//! Active scanner (Pro): crawls a target, finds insertion points in each request and sends attack
//! payloads to them, reporting issues next to the passive ones. Runs as Dashboard tasks.
//!
//! Insertion points are byte ranges in the raw request (query/body/cookie/JSON values and a few
//! headers); a payload replaces the range, encoded for its context.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::proxy::{self, State};
use crate::security::scanner::Severity;

mod checks;
mod config;
mod crawl;
mod ctx;
mod points;

pub(crate) use checks::*;
pub(crate) use config::*;
pub(crate) use crawl::*;
pub(crate) use ctx::*;
pub(crate) use points::*;

// ------------------------------------------------------------ entry points

/// Starts a scan task: crawl (optional) and audit `urls`, plus `extra` raw requests (from history or an API definition).
pub fn start(
    id: usize,
    urls: Vec<String>,
    extra: Vec<(Target, String)>,
    cfg: Config,
    state: State,
) -> Task {
    let name = urls
        .first()
        .cloned()
        .or_else(|| {
            extra.first().map(|(t, r)| {
                format!(
                    "{}{}",
                    host_header(t),
                    r.split_whitespace().nth(1).unwrap_or("")
                )
            })
        })
        .unwrap_or_default();
    let origin = |t: &Target| {
        format!(
            "{}://{}",
            if t.tls { "https" } else { "http" },
            host_header(t)
        )
    };
    let mut origins: Vec<String> = urls
        .iter()
        .filter_map(|u| parse_url(u.trim()))
        .map(|(t, _)| origin(&t))
        .chain(extra.iter().map(|(t, _)| origin(t)))
        .collect();
    origins.dedup();
    let task = Task {
        origins,
        name: format!(
            "{}. {} {name}",
            id,
            if cfg.crawl && !urls.is_empty() {
                "Crawl and audit of"
            } else {
                "Audit of"
            }
        ),
        status: Arc::new(Mutex::new("Starting".into())),
        requests: Default::default(),
        issues: Default::default(),
        stop: Default::default(),
        done: Default::default(),
    };
    let (status, requests, issues, stop, done) = (
        task.status.clone(),
        task.requests.clone(),
        task.issues.clone(),
        task.stop.clone(),
        task.done.clone(),
    );
    std::thread::spawn(move || {
        let mut work: Vec<(Target, String)> = extra;
        let mut ctxs: Vec<Arc<Ctx>> = vec![];
        let ctx_for = |t: &Target, ctxs: &mut Vec<Arc<Ctx>>| -> Arc<Ctx> {
            if let Some(c) = ctxs.iter().find(|c| {
                c.target.host == t.host && c.target.port == t.port && c.target.tls == t.tls
            }) {
                return c.clone();
            }
            let c = Arc::new(Ctx {
                target: t.clone(),
                cfg: cfg.clone(),
                state: state.clone(),
                task: id,
                requests: requests.clone(),
                issues: issues.clone(),
                stop: stop.clone(),
                cookies: Mutex::default(),
                oob: Mutex::default(),
                pages: Mutex::default(),
                stored_left: AtomicUsize::new(STORED_REFETCH_BUDGET),
            });
            if !cfg.login.trim().is_empty() {
                *status.lock().unwrap() = "Logging in".into();
                let login = crate::tools::fix_content_length(
                    &cfg.login.replace("\r\n", "\n").replace('\n', "\r\n"),
                );
                if let Some((resp, _)) = c.send(&login) {
                    let set: Vec<String> = String::from_utf8_lossy(proxy::head(&resp))
                        .lines()
                        .filter_map(|l| {
                            l.split_once(':')
                                .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
                                .map(|(_, v)| v.trim().split(';').next().unwrap_or("").to_string())
                        })
                        .collect();
                    *c.cookies.lock().unwrap() = set.join("; ");
                }
            }
            ctxs.push(c.clone());
            c
        };
        for u in &urls {
            let Some((t, path)) = parse_url(u.trim()) else {
                continue;
            };
            let c = ctx_for(&t, &mut ctxs);
            if cfg.crawl {
                work.extend(
                    crawl(&c, &path, &status)
                        .into_iter()
                        .map(|r| (t.clone(), r)),
                );
            } else {
                work.push((t, get_request(&c.target, &path)));
            }
        }
        // one context (session) per target, shared by the worker pool
        for (t, _) in work.iter() {
            ctx_for(t, &mut ctxs);
        }
        for c in &ctxs {
            c.host_bchecks();
            c.host_smuggle();
        }
        let total = work.len();
        let (next, work, shared) = (
            Arc::new(AtomicUsize::new(0)),
            Arc::new(work),
            Arc::new(ctxs),
        );
        let pool: Vec<_> = (0..cfg.threads.max(1))
            .map(|_| {
                let (work, next, status, shared) =
                    (work.clone(), next.clone(), status.clone(), shared.clone());
                std::thread::spawn(move || {
                    while let Some((t, req)) = work.get(next.fetch_add(1, Ordering::SeqCst)) {
                        let Some(c) = shared.iter().find(|c| {
                            c.target.host == t.host
                                && c.target.port == t.port
                                && c.target.tls == t.tls
                        }) else {
                            continue;
                        };
                        *status.lock().unwrap() = format!(
                            "Auditing {} of {total}: {}",
                            next.load(Ordering::SeqCst).min(total),
                            req.lines().next().unwrap_or("")
                        );
                        audit(c, req);
                    }
                })
            })
            .collect();
        pool.into_iter().for_each(|h| {
            let _ = h.join();
        });
        let used = shared;
        // out-of-band: give the target a moment, then poll and match labels
        let pending: Vec<(Arc<Ctx>, (String, &'static str, String, String))> = used
            .iter()
            .flat_map(|c| {
                c.oob
                    .lock()
                    .unwrap()
                    .drain(..)
                    .map(|o| (c.clone(), o))
                    .collect::<Vec<_>>()
            })
            .collect();
        if !pending.is_empty() && !stop.load(Ordering::SeqCst) {
            *status.lock().unwrap() = "Waiting for out-of-band interactions".into();
            for _ in 0..3 {
                std::thread::sleep(Duration::from_secs(2));
                let _ = crate::security::collab::poll();
            }
            let hits = crate::security::collab::interactions_for(&format!("Scan {id} "));
            for (c, (label, issue, detail, req)) in pending {
                if let Some((it, _)) = hits.iter().find(|(_, l)| *l == label) {
                    c.report(
                        issue,
                        Severity::High,
                        "Certain",
                        format!(
                            "{detail} The server made a {} request from {}.",
                            it.protocol, it.client_ip
                        ),
                        &req,
                        &it.raw,
                    );
                }
            }
        }
        *status.lock().unwrap() = if stop.load(Ordering::SeqCst) {
            "Stopped".into()
        } else {
            format!(
                "Finished: {} requests, {} issues",
                requests.load(Ordering::SeqCst),
                issues.load(Ordering::SeqCst)
            )
        };
        done.store(true, Ordering::SeqCst);
        if let Some(ctx) = state.lock().unwrap().ctx.clone() {
            ctx.request_repaint();
        }
    });
    task
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};

    #[test]
    fn insertion_points() {
        let req = "POST /a?x=1&y=two HTTP/1.1\r\nHost: h\r\nCookie: s=abc; t=1\r\nUser-Agent: UA\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nu=a&p=b";
        let ps = points(req);
        let names: Vec<(Kind, &str, &str)> = ps
            .iter()
            .map(|p| (p.kind, p.name.as_str(), &req[p.start..p.end]))
            .collect();
        assert_eq!(
            names,
            [
                (Kind::Query, "x", "1"),
                (Kind::Query, "y", "two"),
                (Kind::Cookie, "s", "abc"),
                (Kind::Cookie, "t", "1"),
                (Kind::Header, "User-Agent", "UA"),
                (Kind::Body, "u", "a"),
                (Kind::Body, "p", "b")
            ]
        );
        let r = inject(req, &ps[1], "a b'&");
        assert!(r.starts_with("POST /a?x=1&y=a%20b'%26 HTTP/1.1"));
        let r = inject(req, &ps[5], "<x>");
        assert!(r.ends_with("\r\n\r\nu=%3Cx%3E&p=b") && r.contains("Content-Length: 13"));
        let json = "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"bob\",\"age\":30}";
        let jp = points(json);
        assert_eq!(
            jp.iter().map(|p| &json[p.start..p.end]).collect::<Vec<_>>(),
            ["bob", "30"]
        );
        assert!(inject(json, &jp[0], "a\"b").contains("{\"name\":\"a\\\"b\",\"age\":30}"));
        assert!(inject(json, &jp[1], "1'").contains("\"age\":\"1'\""));
        let xml = "POST /x HTTP/1.1\r\nContent-Type: application/xml\r\nContent-Length: 42\r\n\r\n<?xml version=\"1.0\"?><data><n>bob</n></data>";
        let xp = points(xml);
        assert_eq!(
            xp.iter()
                .map(|p| (p.kind, &xml[p.start..p.end]))
                .collect::<Vec<_>>(),
            [(Kind::Xml, "bob")]
        );
        assert!(inject(xml, &xp[0], "a<b>&c").contains("<n>a&lt;b&gt;&amp;c</n>"));
        let (t, path) = parse_url("http://127.0.0.1:9/x?y=1").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.tls, path.as_str()),
            ("127.0.0.1", 9, false, "/x?y=1")
        );
    }

    #[test]
    fn xxe_probe_substitutes_entity() {
        let xml = "POST /x HTTP/1.1\r\nContent-Type: application/xml\r\nContent-Length: 42\r\n\r\n<?xml version=\"1.0\"?><data><n>bob</n></data>";
        let p = &points(xml)[0];
        let r = xxe_inject(xml, p, "file:///etc/passwd");
        let body = r.split_once("\r\n\r\n").unwrap().1;
        assert_eq!(
            body,
            "<?xml version=\"1.0\"?><!DOCTYPE bc [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><data><n>&xxe;</n></data>"
        );
        assert_eq!(crate::tools::fix_content_length(&r), r); // Content-Length already correct
    }

    /// A deliberately vulnerable web app: one endpoint per issue class plus a safe control.
    fn vulnerable_app() -> u16 {
        let srv = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = srv.local_addr().unwrap().port();
        let store: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(vec![])); // stored-XSS sink
        std::thread::spawn(move || {
            for c in srv.incoming().flatten() {
                let store = store.clone();
                std::thread::spawn(move || {
                    let mut r = BufReader::new(c.try_clone().unwrap());
                    let mut head = String::new();
                    let mut line = String::new();
                    let mut len = 0;
                    while r.read_line(&mut line).is_ok_and(|n| n > 2) {
                        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap_or(0);
                        }
                        head += &line;
                        line.clear();
                    }
                    let mut body = vec![0; len];
                    let _ = r.read_exact(&mut body);
                    let target = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let (path, q) = target.split_once('?').unwrap_or((&target, ""));
                    let all = format!("{q}&{}", String::from_utf8_lossy(&body));
                    let arg = |k: &str| {
                        all.split('&')
                            .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
                            .map(|v| {
                                String::from_utf8_lossy(&crate::http::codec::url_decode(
                                    &v.replace('+', " "),
                                ))
                                .into_owned()
                            })
                            .unwrap_or_default()
                    };
                    let html =
                        |b: String| ("200 OK", vec![("Content-Type", "text/html".to_string())], b);
                    let (status, headers, body) = match path {
                        "/" => html("<a href=\"/search?q=hi\">s</a> <a href='/item?id=1'>i</a> <a href=\"/file?name=a.txt\">f</a> <a href=\"/go?url=/home\">g</a> <a href=\"/tpl?name=x\">t</a> <a href=\"/fetch?u=http://x/\">fetch</a> <a href=\"/safe?q=1\">safe</a> <a href=\"/comment?c=hi\">add</a> <a href=\"/comments\">list</a> <img src=\"/logo.png\"> <a href=\"https://other.example/\">ext</a> <form method=post action=/login><input name=user><input type=password name=pass></form>".into()),
                        "/search" => html(format!("Results for {}", arg("q"))),
                        "/safe" => html(format!("Results for {}", crate::http::codec::html_encode(arg("q").as_bytes(), false))),
                        "/item" => {
                            let id = arg("id");
                            if id.contains('\'') {
                                html("<b>Warning</b>: You have an error in your SQL syntax; check the manual".into())
                            } else if id == "1" || id.ends_with("AND 1=1") {
                                html("Item 1: a red chair, comfortable and cheap, in stock".into())
                            } else {
                                html("No such item".into())
                            }
                        }
                        "/file" => html(if arg("name").contains("etc/passwd") { "root:x:0:0:root:/root:/bin/bash".into() } else { "file contents".into() }),
                        "/go" => ("302 Found", vec![("Location", arg("url"))], String::new()),
                        "/tpl" => {
                            // evaluates `{{a*b}}` like a real engine, so a wrong expected product fails
                            let n = arg("name");
                            let v = n.strip_prefix("{{").and_then(|e| e.strip_suffix("}}")).and_then(|e| e.split_once('*')).and_then(|(a, b)| Some(a.parse::<u64>().ok()? * b.parse::<u64>().ok()?));
                            html(format!("Hello {}", v.map_or(n, |v| v.to_string())))
                        }
                        "/fetch" => {
                            // SSRF: fetches http URLs given in `u`
                            if let Some(rest) = arg("u").strip_prefix("http://") {
                                let (hp, p) = rest.split_once('/').unwrap_or((rest, ""));
                                if let Ok(mut s) = std::net::TcpStream::connect(hp) {
                                    let _ = write!(s, "GET /{p} HTTP/1.1\r\nHost: {hp}\r\nConnection: close\r\n\r\n");
                                    let mut sink = vec![];
                                    let _ = s.read_to_end(&mut sink);
                                }
                            }
                            html("fetched".into())
                        }
                        "/comment" => {
                            store.lock().unwrap().push(arg("c"));
                            html("saved".into())
                        }
                        // stored input rendered unescaped on another page
                        "/comments" => html(store.lock().unwrap().join(" | ")),
                        // XXE: discloses the file only when the external-entity declaration is present
                        "/xml" => {
                            let b = String::from_utf8_lossy(&body);
                            html(if b.contains("file:///etc/passwd") {
                                "root:x:0:0:root:/root:/bin/bash".into()
                            } else {
                                "ok".into()
                            })
                        }
                        "/.git/HEAD" => ("200 OK", vec![], "ref: refs/heads/main\n".into()),
                        "/login" => html(format!("Welcome {}", crate::http::codec::html_encode(arg("user").as_bytes(), false))),
                        _ => ("404 Not Found", vec![], "nope".into()),
                    };
                    let mut c = c;
                    let extra: String = headers
                        .iter()
                        .map(|(k, v)| format!("{k}: {v}\r\n"))
                        .collect();
                    let _ = write!(
                        c,
                        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                });
            }
        });
        port
    }

    #[test]
    fn crawls_and_finds_each_issue_class() {
        let _g = crate::security::collab::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let collab = burpcraft_server::start(burpcraft_server::Config::default()).unwrap();
        {
            let mut c = crate::security::collab::client().lock().unwrap();
            (c.server, c.domain, c.secret) = (
                format!("127.0.0.1:{}", collab.http_port),
                String::new(),
                String::new(),
            );
        }
        let port = vulnerable_app();
        {
            let mut b = crate::security::bcheck::checks().lock().unwrap();
            b.0.push(crate::security::bcheck::parse(crate::security::bcheck::TEMPLATE).unwrap());
            b.0.push(crate::security::bcheck::parse("metadata:\n name: \"Echoed marker\"\ngiven query insertion point then\n send payload:\n  replacing: \"bcmark42\"\n if \"bcmark42\" in {latest.response.body} then\n  report issue:\n   severity: info\n end if").unwrap());
        }
        let state = proxy::Shared::new();
        let xml_body = "<?xml version=\"1.0\"?><data><name>test</name></data>";
        let xml_req = format!(
            "POST /xml HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml_body}",
            xml_body.len()
        );
        let task = start(
            1,
            vec![format!("http://127.0.0.1:{port}/")],
            vec![(
                Target {
                    host: "127.0.0.1".into(),
                    port,
                    tls: false,
                },
                xml_req,
            )],
            Config::fast(),
            state.clone(),
        );
        for _ in 0..600 {
            if task.done.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            task.done.load(Ordering::SeqCst),
            "scan did not finish: {}",
            task.status.lock().unwrap()
        );
        let s = state.lock().unwrap();
        let mut found: Vec<(String, &str)> =
            s.issues.iter().map(|i| (i.path.clone(), i.name)).collect();
        found.sort();
        found.dedup();
        let expect = [
            ("/fetch", "External service interaction"),
            ("/file", "File path traversal"),
            ("/go", "Open redirection"),
            ("/item", "SQL injection"),
            ("/search", "Cross-site scripting (reflected)"),
            ("/tpl", "Server-side template injection"),
            ("/.git/HEAD", "Exposed git repository"),
            ("/search", "Echoed marker"),
            ("/comment", "Cross-site scripting (stored)"),
            ("/xml", "XML external entity injection"),
        ];
        for (p, n) in expect {
            assert!(
                found.iter().any(|(fp, fn_)| fp == p && *fn_ == n),
                "missing {n} on {p}; found {found:?}"
            );
        }
        // negative controls: escaped reflection and the login form have no active finding
        // (passive header findings from the scanner's own traffic are expected there)
        let active: Vec<&str> = expect.iter().map(|(_, n)| *n).collect();
        assert!(
            !found.iter().any(|(p, n)| (p == "/safe" || p == "/login")
                && *n != "Echoed marker"
                && active.contains(n)),
            "false positive: {found:?}"
        );
        // scanner traffic is passively scanned too
        assert!(found.contains(&("/search".into(), "No Content-Security-Policy")));
        // crawler stayed on the origin and skipped static files
        assert!(
            s.history
                .iter()
                .filter(|e| e.tool == "Crawler")
                .all(|e| e.port == port && !e.url.ends_with(".png"))
        );
        assert!(task.status.lock().unwrap().starts_with("Finished"));
    }
}
