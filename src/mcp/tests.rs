//! Tests for the MCP server: protocol handshake, the tool dispatch end to end,
//! the intruder anomaly filter, intercept/rules/scope/codec, and the HTTP transport.
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;

use crate::automation::openapi::{self, J};
use crate::proxy;

use super::attack::anomalies;
use super::helpers::{n, obj, s, strs};
use super::{Ctx, TOOLS, handle, start};

fn ctx() -> Ctx {
    Ctx {
        state: proxy::Shared::new(),
        tasks: Default::default(),
        scope: Default::default(),
    }
}

/// tools/call and back: (text, isError).
fn tool(c: &Ctx, name: &str, args: &str) -> (J, bool) {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{args}}}}}"#
    );
    let r = openapi::parse(&handle(&body, c).unwrap()).unwrap();
    let res = r.get("result").unwrap();
    let J::Arr(content) = res.get("content").unwrap() else {
        panic!()
    };
    let J::Str(t) = content[0].get("text").unwrap() else {
        panic!()
    };
    let err = res.get("isError") == Some(&J::Bool(true));
    (
        if err {
            J::Str(t.clone())
        } else {
            openapi::parse(t).unwrap()
        },
        err,
    )
}

/// Local HTTP server answering every request with its own request line in the body.
fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let mut r = BufReader::new(c.try_clone().unwrap());
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let mut h = String::new();
            while r.read_line(&mut h).is_ok_and(|n| n > 2) {
                h.clear();
            }
            let body = line.trim().to_string();
            let mut c = c;
            let _ = write!(
                c,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
        }
    });
    port
}

#[test]
fn protocol() {
    let c = ctx();
    let init = handle(r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#, &c).unwrap();
    assert!(init.contains(r#""protocolVersion":"2025-03-26""#) && init.contains("burpcraft"));
    assert_eq!(
        handle(
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &c
        ),
        None
    );
    assert!(
        handle(r#"{"jsonrpc":"2.0","id":2,"method":"nope"}"#, &c)
            .unwrap()
            .contains("-32601")
    );
    assert!(handle("{bad", &c).unwrap().contains("-32700"));
    // every schema parses and every listed tool is implemented
    let list =
        openapi::parse(&handle(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#, &c).unwrap())
            .unwrap();
    let J::Arr(tools) = list.get("result").unwrap().get("tools").unwrap() else {
        panic!()
    };
    assert_eq!(tools.len(), TOOLS.len());
    for (name, _, _) in TOOLS {
        let (j, err) = tool(&c, name, "{}");
        assert!(
            !(err && matches!(&j, J::Str(e) if e.starts_with("unknown tool"))),
            "{name}"
        );
    }
    assert!(tool(&c, "nope", "{}").1);
}

#[test]
fn send_history_intruder() {
    let c = ctx();
    let port = echo_server();
    let t = format!("http://127.0.0.1:{port}");
    let (r, err) = tool(
        &c,
        "send",
        &format!(r#"{{"request":"POST /a HTTP/1.1\nHost: x\n\nhi","target":"{t}"}}"#),
    );
    assert!(!err, "{r:?}");
    assert_eq!(r.get("status"), Some(&J::Num("200".into())));
    assert!(matches!(r.get("response"), Some(J::Str(s)) if s.ends_with("POST /a HTTP/1.1")));
    // logged in Logger, readable back
    let (l, _) = tool(
        &c,
        "history_list",
        r#"{"source":"logger","grep":"POST /a"}"#,
    );
    let J::Arr(rows) = l else { panic!() };
    assert_eq!(rows.len(), 1);
    let (g, _) = tool(&c, "history_get", r#"{"source":"logger","id":1}"#);
    assert!(matches!(g.get("request"), Some(J::Str(s)) if s.contains("Content-Length: 2\n\nhi")));
    let (rows, err) = tool(
        &c,
        "intruder",
        &format!(
            r#"{{"request":"GET /§x§ HTTP/1.1\nHost: x\n\n","target":"{t}","payloads":[["a","b","c"]],"grep":"/[a-z]"}}"#
        ),
    );
    assert!(!err, "{rows:?}");
    let J::Arr(rows) = rows else { panic!() };
    let m: Vec<_> = rows
        .iter()
        .map(|r| r.get("match").cloned().unwrap())
        .collect();
    assert_eq!(m, ["/a", "/b", "/c"].map(|x| J::Str(x.into())));
    assert!(tool(&c, "send", r#"{"request":"GET / HTTP/1.1\n\n"}"#).1); // no Host, no target
}

fn row(status: u16, length: usize, ms: u64, m: Option<&str>) -> J {
    obj(vec![
        ("payloads", J::Arr(vec![s("p")])),
        ("status", n(status)),
        ("length", n(length)),
        ("ms", n(ms)),
        ("match", m.map_or(J::Null, s)),
    ])
}

fn err_row() -> J {
    obj(vec![
        ("payloads", J::Arr(vec![s("p")])),
        ("error", s("boom")),
    ])
}

fn reasons(out: &J) -> Vec<Vec<String>> {
    let Some(J::Arr(a)) = out.get("anomalies") else {
        panic!("{out:?}")
    };
    a.iter().map(|r| strs(r.get("reasons").unwrap())).collect()
}

fn why(r: &[&str]) -> Vec<String> {
    r.iter().map(|x| x.to_string()).collect()
}

#[test]
fn anomalies_filter() {
    // every reason, the error row, baseline ties resolved by the first row
    let out = anomalies(vec![
        row(200, 1000, 10, None),
        row(200, 1000, 10, None),
        row(200, 1000, 10, None),
        row(404, 1000, 10, None),
        row(200, 2000, 10, None),
        row(200, 1000, 10, Some("x")),
        err_row(),
        row(200, 1000, 500, None),
        row(500, 5000, 10, None),
    ]);
    assert_eq!(out.get("total"), Some(&n(9)));
    let b = out.get("baseline").unwrap();
    assert_eq!(b.get("status"), Some(&n(200)));
    assert_eq!(b.get("length"), Some(&n(1000)));
    assert_eq!(b.get("count"), Some(&n(5)));
    assert_eq!(b.get("median_ms"), Some(&n(10)));
    assert_eq!(
        reasons(&out),
        vec![
            why(&["status"]),
            why(&["length"]),
            why(&["grep"]),
            why(&["error"]),
            why(&["time"]),
            why(&["status", "length"]),
        ]
    );
    // original fields are kept, in original order
    let J::Arr(a) = out.get("anomalies").unwrap() else {
        panic!()
    };
    assert_eq!(a[0].get("status"), Some(&n(404)));
    assert_eq!(a[2].get("match"), Some(&s("x")));
    assert_eq!(a[3].get("error"), Some(&s("boom")));

    // 2% tolerance above 200 bytes: 1029 is within 21 of 1050, 1028 is not
    let out = anomalies(vec![
        row(200, 1050, 10, None),
        row(200, 1050, 10, None),
        row(200, 1050, 10, None),
        row(200, 1029, 10, None),
        row(200, 1028, 10, None),
    ]);
    assert_eq!(out.get("baseline").unwrap().get("count"), Some(&n(4)));
    assert_eq!(reasons(&out), vec![why(&["length"])]);
    // small responses must match exactly
    let out = anomalies(vec![row(200, 100, 1, None), row(200, 101, 1, None)]);
    assert_eq!(reasons(&out), vec![why(&["length"])]);

    // time: strictly above 3x median AND at least 100 ms over it
    let out = anomalies(vec![
        row(200, 10, 10, None),
        row(200, 10, 10, None),
        row(200, 10, 10, None),
        row(200, 10, 109, None),
        row(200, 10, 110, None),
    ]);
    assert_eq!(reasons(&out), vec![why(&["time"])]);
    assert_eq!(
        out.get("anomalies").and_then(|a| match a {
            J::Arr(v) => v[0].get("ms").cloned(),
            _ => None,
        }),
        Some(n(110))
    );
    let out = anomalies(vec![
        row(200, 10, 100, None),
        row(200, 10, 100, None),
        row(200, 10, 100, None),
        row(200, 10, 300, None),
        row(200, 10, 301, None),
    ]);
    assert_eq!(reasons(&out), vec![why(&["time"])]);

    // all rows failed: no baseline, everything is anomalous
    let out = anomalies(vec![err_row(), err_row()]);
    assert_eq!(out.get("total"), Some(&n(2)));
    assert_eq!(out.get("baseline"), Some(&J::Null));
    assert_eq!(reasons(&out), vec![why(&["error"]), why(&["error"])]);
}

#[test]
fn intruder_anomalies_option() {
    let c = ctx();
    let port = echo_server();
    let args = |extra: &str| {
        format!(
            r#"{{"request":"GET /§x§ HTTP/1.1\nHost: x\n\n","target":"http://127.0.0.1:{port}","payloads":[["a","b","c","long-payload"]]{extra}}}"#
        )
    };
    let (r, err) = tool(&c, "intruder", &args(r#","anomalies":true"#));
    assert!(!err, "{r:?}");
    assert_eq!(r.get("total"), Some(&n(4)));
    assert_eq!(r.get("baseline").unwrap().get("count"), Some(&n(3)));
    assert_eq!(reasons(&r), vec![why(&["length"])]);
    let J::Arr(a) = r.get("anomalies").unwrap() else {
        panic!()
    };
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].get("payloads"), Some(&J::Arr(vec![s("long-payload")])));
    // off by default: the plain row list
    let (r, _) = tool(&c, "intruder", &args(""));
    assert!(matches!(r, J::Arr(v) if v.len() == 4));
}

#[test]
fn scan_start_openapi_with_auth() {
    let c = ctx();
    let port = echo_server();
    let doc = r#"{\"openapi\":\"3.0.0\",\"paths\":{\"/op\":{\"get\":{\"parameters\":[{\"name\":\"q\",\"in\":\"query\"}]}}}}"#;
    let (r, err) = tool(
        &c,
        "scan_start",
        &format!(
            r#"{{"urls":["http://127.0.0.1:{port}"],"openapi":"{doc}","headers":"X-T: 1","login":"POST /login HTTP/1.1\nHost: x\n\n"}}"#
        ),
    );
    assert!(!err, "{r:?}");
    let task = c.tasks.lock().unwrap().pop().unwrap();
    for _ in 0..500 {
        if task.done.load(Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let st = c.state.lock().unwrap();
    let sent: Vec<String> = st
        .logger
        .iter()
        .map(|e| String::from_utf8_lossy(&e.req).into_owned())
        .collect();
    assert!(
        sent.len() > 1 && sent[0].starts_with("POST /login "),
        "{sent:?}"
    );
    // the definition's operation, not a crawl of the base URL, with the extra header
    assert!(
        sent.iter()
            .skip(1)
            .all(|r| r.starts_with("GET /op?q=") && r.contains("\r\nX-T: 1\r\n"))
    );
    let (r, err) = tool(&c, "scan_start", r#"{"openapi":"{}"}"#);
    assert!(err, "{r:?}");
}

#[test]
fn scan_start_refuses_out_of_scope() {
    let c = ctx();
    c.scope
        .lock()
        .unwrap()
        .push((true, true, "http://in.test/".into()));
    let (r, err) = tool(&c, "scan_start", r#"{"urls":["http://out.test/"]}"#);
    assert!(
        err && format!("{r:?}").contains("outside the scan scope"),
        "{r:?}"
    );
    assert!(c.tasks.lock().unwrap().is_empty());
}

#[test]
fn forward_all_releases_queue() {
    let c = ctx();
    let mut held = Vec::new();
    for (id, req) in [
        (1, b"GET /a HTTP/1.1\r\n\r\n".to_vec()),
        (2, b"GET /b HTTP/1.1\r\n\r\n".to_vec()),
    ] {
        let (tx, rx) = std::sync::mpsc::channel();
        c.state.lock().unwrap().queue.push_back(proxy::Pending {
            id,
            host: "h".into(),
            port: 80,
            tls: false,
            req: req.clone(),
            response: false,
            reply: tx,
        });
        held.push((rx, req));
    }
    c.state.lock().unwrap().forward_all();
    for (rx, req) in held {
        assert_eq!(rx.recv().unwrap().unwrap(), req);
    }
    assert!(c.state.lock().unwrap().queue.is_empty());
}

#[test]
fn intercept_rules_scope_codec() {
    let c = ctx();
    let (tx, rx) = std::sync::mpsc::channel();
    c.state.lock().unwrap().queue.push_back(proxy::Pending {
        id: 7,
        host: "h".into(),
        port: 80,
        tls: false,
        req: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
        response: false,
        reply: tx,
    });
    let (q, _) = tool(&c, "intercept_queue", "{}");
    assert!(matches!(&q, J::Arr(v) if v.len() == 1));
    let (_, err) = tool(
        &c,
        "intercept_forward",
        r#"{"id":7,"message":"POST /x HTTP/1.1\n\nab"}"#,
    );
    assert!(!err);
    assert_eq!(
        rx.recv().unwrap().unwrap(),
        b"POST /x HTTP/1.1\r\nContent-Length: 2\r\n\r\nab"
    );
    assert!(tool(&c, "intercept_drop", r#"{"id":7}"#).1); // already gone
    let (i, _) = tool(&c, "intercept", r#"{"enabled":true,"host":"ex"}"#);
    assert_eq!(i.get("enabled"), Some(&J::Bool(true)));
    assert!(c.state.lock().unwrap().intercept);

    let (r, _) = tool(
        &c,
        "rules",
        r#"{"set":[{"kind":"request_header","pattern":"","replace":"X-A: 1"}]}"#,
    );
    assert!(matches!(&r, J::Arr(v) if v.len() == 1));
    assert!(
        tool(
            &c,
            "rules",
            r#"{"set":[{"kind":"bogus","pattern":"","replace":""}]}"#
        )
        .1
    );
    assert!(
        tool(
            &c,
            "rules",
            r#"{"set":[{"kind":"request_body","pattern":"(","replace":""}]}"#
        )
        .1
    );
    assert_eq!(c.state.lock().unwrap().rules.len(), 1);

    tool(
        &c,
        "scope",
        r#"{"set":[{"prefix":"https://a/"},{"prefix":"https://a/x","include":false}]}"#,
    );
    assert_eq!(
        c.scope.lock().unwrap()[1],
        (true, false, "https://a/x".to_string())
    );

    assert_eq!(
        tool(&c, "codec", r#"{"op":"base64_encode","data":"hi"}"#).0,
        J::Str("aGk=".into())
    );
    assert_eq!(
        tool(&c, "codec", r#"{"op":"url_decode","data":"a%20b"}"#).0,
        J::Str("a b".into())
    );
    assert!(tool(&c, "codec", r#"{"op":"rot13","data":""}"#).1);
}

#[test]
fn http_transport() {
    let port = start(0, "t0k".into(), ctx()).unwrap();
    let post = |extra: &str, body: &str| {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            s,
            "POST /mcp HTTP/1.1\r\nHost: x\r\n{extra}Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut r = BufReader::new(s);
        let mut first = String::new();
        r.read_line(&mut first).unwrap();
        first
    };
    let ping = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    assert!(post("", ping).contains("401"));
    assert!(
        post(
            "Authorization: Bearer t0k\r\nOrigin: https://evil.test\r\n",
            ping
        )
        .contains("403")
    );
    assert!(
        post(
            "Authorization: Bearer t0k\r\nOrigin: http://localhost:3000\r\n",
            ping
        )
        .contains("200")
    );
    assert!(
        post(
            "Authorization: Bearer t0k\r\n",
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        )
        .contains("202")
    );
}
