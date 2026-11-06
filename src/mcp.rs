//! MCP server: lets AI agents drive the running app (traffic, send, intercept/MITM, rules, scope, scans,
//! Collaborator). JSON-RPC 2.0 over Streamable HTTP, plain JSON replies (no SSE), on 127.0.0.1 only.
//!
//!   BURPCRAFT_MCP=1338[:token] burpcraft
//!   claude mcp add --transport http burpcraft http://127.0.0.1:1338/mcp [--header "Authorization: Bearer <token>"]
//!
//! The tool descriptions in `TOOLS` are the documentation agents read: keep them short and exact.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crate::openapi::{self, J};
use crate::proxy::{self, Entry, Rule, State};
use crate::rest::Tasks;
use crate::target::Scope;
use crate::{codec, collab, intruder, net, scan, tools};

/// Everything the tools can reach.
#[derive(Clone)]
pub struct Ctx {
    pub state: State,
    pub tasks: Tasks,
    pub scope: Scope,
}

const INSTRUCTIONS: &str = "BurpCraft MCP: full control of the running BurpCraft proxy.
Messages are raw HTTP text; line endings may be \\n (sent as CRLF, Content-Length fixed for you).
`target` = scheme://host[:port] (default: https + the Host header). Request line `... HTTP/2` sends HTTP/2.
Typical loop: history_list -> history_get -> send (edit and replay) -> intruder / scan_start.
MITM: intercept {enabled:true} -> intercept_queue -> intercept_forward (optionally edited) / intercept_drop.
Bodies are decoded (chunked/gzip) and cut at max_bytes (default 20000). All calls return JSON.";

/// (name, description, JSON schema of the arguments).
const TOOLS: &[(&str, &str, &str)] = &[
    (
        "status",
        "Proxy listener, intercept state, counts (history, logger, websockets, issues, queue), CA cert path, Collaborator.",
        r#"{"type":"object","properties":{}}"#,
    ),
    (
        "history_list",
        "List captured requests (oldest first). source: proxy (default) or logger (all tools). Filters combine. Returns id, method, url, status, length, mime, tool.",
        r#"{"type":"object","properties":{"source":{"enum":["proxy","logger"]},"host":{"type":"string","description":"substring of host"},"method":{"type":"string"},"status":{"type":"integer"},"grep":{"type":"string","description":"regex over request+response"},"after_id":{"type":"integer","description":"only ids greater than this (poll for new traffic)"},"limit":{"type":"integer","description":"default 50, newest kept"}}}"#,
    ),
    (
        "history_get",
        "Full request and response of one history/logger item.",
        r#"{"type":"object","properties":{"id":{"type":"integer"},"source":{"enum":["proxy","logger"]},"max_bytes":{"type":"integer"}},"required":["id"]}"#,
    ),
    (
        "ws_list",
        "WebSocket messages seen by the proxy. direction: to_server true/false.",
        r#"{"type":"object","properties":{"grep":{"type":"string"},"after_id":{"type":"integer"},"limit":{"type":"integer"},"max_bytes":{"type":"integer"}}}"#,
    ),
    (
        "send",
        "Send one raw HTTP request (Repeater) and return the response. Logged in Logger as tool MCP.",
        r#"{"type":"object","properties":{"request":{"type":"string","description":"raw HTTP request"},"target":{"type":"string","description":"scheme://host[:port]"},"max_bytes":{"type":"integer"}},"required":["request"]}"#,
    ),
    (
        "intruder",
        "Run an attack synchronously. Mark positions with §value§. attack: sniper (default), battering_ram, pitchfork, cluster_bomb. payloads: one list per position (sniper/battering_ram use the first). Max 1000 requests. Returns status/length/ms per request and grep match. anomalies=true returns only the odd rows (error, status or length unlike the commonest response, ms > 3x median and >= 100 ms over it, grep match), each with `reasons`, plus total and baseline.",
        r#"{"type":"object","properties":{"request":{"type":"string"},"target":{"type":"string"},"attack":{"enum":["sniper","battering_ram","pitchfork","cluster_bomb"]},"payloads":{"type":"array","items":{"type":"array","items":{"type":"string"}}},"threads":{"type":"integer","description":"default 8"},"grep":{"type":"string","description":"regex; first match per response"},"anomalies":{"type":"boolean","description":"only anomalous rows, default false"}},"required":["request","payloads"]}"#,
    ),
    (
        "intercept",
        "Read or change intercept settings (only given fields change). Turning it off forwards everything queued. Returns settings and queue size.",
        r#"{"type":"object","properties":{"enabled":{"type":"boolean"},"responses":{"type":"boolean","description":"also hold responses"},"host":{"type":"string","description":"only hosts containing this ('' = all)"},"skip_ext":{"type":"string","description":"regex of file extensions not intercepted"}}}"#,
    ),
    (
        "intercept_queue",
        "Messages held by intercept, waiting for intercept_forward/intercept_drop. response=true means a held response.",
        r#"{"type":"object","properties":{"max_bytes":{"type":"integer"}}}"#,
    ),
    (
        "intercept_forward",
        "Release a held message by id, optionally replaced with an edited raw message.",
        r#"{"type":"object","properties":{"id":{"type":"integer"},"message":{"type":"string"}},"required":["id"]}"#,
    ),
    (
        "intercept_drop",
        "Drop a held message by id (the client gets an error).",
        r#"{"type":"object","properties":{"id":{"type":"integer"}},"required":["id"]}"#,
    ),
    (
        "rules",
        "Proxy match-and-replace rules. Without `set` returns them; `set` replaces the whole list. kind: request_header, request_body, response_header, response_body, request_first_line. Regex pattern; empty pattern on a header rule adds `replace` as a header.",
        r#"{"type":"object","properties":{"set":{"type":"array","items":{"type":"object","properties":{"enabled":{"type":"boolean"},"kind":{"type":"string"},"pattern":{"type":"string"},"replace":{"type":"string"},"comment":{"type":"string"}},"required":["kind","pattern","replace"]}}}}"#,
    ),
    (
        "scope",
        "Target scope (URL prefixes). Without `set` returns it; `set` replaces it. include=false excludes.",
        r#"{"type":"object","properties":{"set":{"type":"array","items":{"type":"object","properties":{"prefix":{"type":"string"},"include":{"type":"boolean"},"enabled":{"type":"boolean"}},"required":["prefix"]}}}}"#,
    ),
    (
        "scan_start",
        "Start an active scan in the background. Either urls (crawl + audit), one raw request + target (audit its parameters), or openapi (audit every operation; urls[0] overrides its server). headers/login authenticate every request. Returns task_id for scan_status.",
        r#"{"type":"object","properties":{"urls":{"type":"array","items":{"type":"string"}},"request":{"type":"string"},"target":{"type":"string"},"openapi":{"type":"string","description":"OpenAPI 3 / Swagger 2 definition, JSON or YAML text"},"headers":{"type":"string","description":"extra `Name: value` lines on every request"},"login":{"type":"string","description":"raw login request sent first; its cookies join every request"},"thorough":{"type":"boolean"},"crawl":{"type":"boolean","description":"default true"}}}"#,
    ),
    (
        "scan_status",
        "Scan progress and the issues it found. stop=true stops it.",
        r#"{"type":"object","properties":{"task_id":{"type":"integer"},"stop":{"type":"boolean"}},"required":["task_id"]}"#,
    ),
    (
        "issues",
        "All issues found so far (passive and active).",
        r#"{"type":"object","properties":{}}"#,
    ),
    (
        "codec",
        "Encode, decode or hash text. op: base64_encode, base64_decode, url_encode, url_decode, html_encode, html_decode, hex_encode, hex_decode, md5, sha1, sha256, sha384, sha512.",
        r#"{"type":"object","properties":{"op":{"type":"string"},"data":{"type":"string"}},"required":["op","data"]}"#,
    ),
    (
        "collaborator",
        "Out-of-band testing. builtin=true starts a local server; or configure server/domain/secret. payloads=n mints n payloads. Always polls and returns interactions.",
        r#"{"type":"object","properties":{"builtin":{"type":"boolean"},"server":{"type":"string"},"domain":{"type":"string"},"secret":{"type":"string"},"payloads":{"type":"integer"}}}"#,
    ),
    (
        "open_in",
        "Show a history/logger item in a UI tool for the human: repeater, intruder, organizer, sequencer, decoder, comparer.",
        r#"{"type":"object","properties":{"id":{"type":"integer"},"tool":{"type":"string"},"source":{"enum":["proxy","logger"]}},"required":["id","tool"]}"#,
    ),
    (
        "events",
        "App event log (proxy errors, extension output, ...), newest last.",
        r#"{"type":"object","properties":{"limit":{"type":"integer"}}}"#,
    ),
];

const RULE_KINDS: [&str; 5] = [
    "request_header",
    "request_body",
    "response_header",
    "response_body",
    "request_first_line",
];

pub fn start(port: u16, key: String, ctx: Ctx) -> std::io::Result<u16> {
    let l = TcpListener::bind(("127.0.0.1", port))?;
    let port = l.local_addr()?.port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let (ctx, key) = (ctx.clone(), key.clone());
            std::thread::spawn(move || serve(c, &key, &ctx));
        }
    });
    Ok(port)
}

/// One keep-alive connection: POST /mcp carries a JSON-RPC message.
fn serve(c: TcpStream, key: &str, ctx: &Ctx) {
    let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(300)));
    let _ = c.set_nodelay(true);
    let Ok(rc) = c.try_clone() else { return };
    let (mut r, mut w) = (BufReader::new(rc), c);
    loop {
        let mut first = String::new();
        if r.read_line(&mut first).unwrap_or(0) == 0 {
            return;
        }
        let (mut len, mut auth, mut origin, mut line) =
            (0usize, String::new(), String::new(), String::new());
        while r.read_line(&mut line).is_ok_and(|n| n > 2) {
            if let Some((k, v)) = line.split_once(':') {
                let v = v.trim().to_string();
                match k.trim().to_ascii_lowercase().as_str() {
                    "content-length" => len = v.parse().unwrap_or(0),
                    "authorization" => auth = v,
                    "origin" => origin = v,
                    _ => {}
                }
            }
            line.clear();
        }
        if len > 16 << 20 {
            return;
        }
        let mut body = vec![0; len];
        if r.read_exact(&mut body).is_err() {
            return;
        }
        let mut parts = first.split_whitespace();
        let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        // browsers on other sites must not drive the proxy (DNS rebinding / CSRF)
        let local = origin.is_empty()
            || [
                "http://127.0.0.1",
                "http://localhost",
                "https://127.0.0.1",
                "https://localhost",
            ]
            .iter()
            .any(|o| origin == *o || origin.starts_with(&format!("{o}:")));
        let (status, out) = if !key.is_empty() && auth != format!("Bearer {key}") {
            ("401 Unauthorized", String::new())
        } else if !local {
            ("403 Forbidden", String::new())
        } else if path.split('?').next() != Some("/mcp") {
            ("404 Not Found", String::new())
        } else if method != "POST" {
            ("405 Method Not Allowed", String::new())
        } else {
            match handle(&String::from_utf8_lossy(&body), ctx) {
                Some(j) => ("200 OK", j),
                None => ("202 Accepted", String::new()),
            }
        };
        let ok = write!(
            w,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{out}",
            out.len()
        );
        if ok.is_err() {
            return;
        }
    }
}

fn obj(v: Vec<(&str, J)>) -> J {
    J::Obj(v.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}
fn s(v: impl Into<String>) -> J {
    J::Str(v.into())
}
fn n(v: impl ToString) -> J {
    J::Num(v.to_string())
}

/// One JSON-RPC message in, the reply out (None for notifications).
pub fn handle(body: &str, ctx: &Ctx) -> Option<String> {
    let req = match openapi::parse(body) {
        Ok(j) => j,
        Err(e) => return Some(rpc_err(J::Null, -32700, &format!("parse error: {e}"))),
    };
    let id = req.get("id").cloned()?; // no id: notification, nothing to answer
    let params = req.get("params").cloned().unwrap_or(J::Obj(vec![]));
    let result = match req.get("method") {
        Some(J::Str(m)) if m == "initialize" => {
            let v = match params.get("protocolVersion") {
                Some(J::Str(v))
                    if ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]
                        .contains(&v.as_str()) =>
                {
                    v.clone()
                }
                _ => "2025-06-18".into(),
            };
            obj(vec![
                ("protocolVersion", s(v)),
                ("capabilities", obj(vec![("tools", obj(vec![]))])),
                (
                    "serverInfo",
                    obj(vec![
                        ("name", s("burpcraft")),
                        ("version", s(env!("CARGO_PKG_VERSION"))),
                    ]),
                ),
                ("instructions", s(INSTRUCTIONS)),
            ])
        }
        Some(J::Str(m)) if m == "ping" => obj(vec![]),
        Some(J::Str(m)) if m == "tools/list" => obj(vec![(
            "tools",
            J::Arr(
                TOOLS
                    .iter()
                    .map(|(name, desc, schema)| {
                        obj(vec![
                            ("name", s(*name)),
                            ("description", s(*desc)),
                            ("inputSchema", openapi::parse(schema).expect("tool schema")),
                        ])
                    })
                    .collect(),
            ),
        )]),
        Some(J::Str(m)) if m == "tools/call" => {
            let name = str_arg(&params, "name").unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(J::Obj(vec![]));
            let (text, err) = match call(name, &args, ctx) {
                Ok(j) => (j.to_json(), false),
                Err(e) => (e, true),
            };
            obj(vec![
                (
                    "content",
                    J::Arr(vec![obj(vec![("type", s("text")), ("text", s(text))])]),
                ),
                ("isError", J::Bool(err)),
            ])
        }
        _ => return Some(rpc_err(id, -32601, "method not found")),
    };
    Some(obj(vec![("jsonrpc", s("2.0")), ("id", id), ("result", result)]).to_json())
}

fn rpc_err(id: J, code: i32, msg: &str) -> String {
    obj(vec![
        ("jsonrpc", s("2.0")),
        ("id", id),
        ("error", obj(vec![("code", n(code)), ("message", s(msg))])),
    ])
    .to_json()
}

fn str_arg<'a>(a: &'a J, k: &str) -> Option<&'a str> {
    match a.get(k) {
        Some(J::Str(v)) => Some(v),
        _ => None,
    }
}
fn num_arg(a: &J, k: &str) -> Option<i64> {
    match a.get(k) {
        Some(J::Num(v)) => v.parse::<f64>().ok().map(|f| f as i64),
        _ => None,
    }
}
fn bool_arg(a: &J, k: &str) -> Option<bool> {
    match a.get(k) {
        Some(J::Bool(b)) => Some(*b),
        _ => None,
    }
}
fn strs(j: &J) -> Vec<String> {
    match j {
        J::Arr(v) => v
            .iter()
            .filter_map(|x| {
                if let J::Str(s) = x {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect(),
        _ => vec![],
    }
}

/// Message text for agents: decoded body, `\n` line endings, cut at `max` bytes.
fn text(msg: &[u8], max: usize) -> String {
    let t = proxy::display(msg).replace("\r\n", "\n");
    if t.len() <= max {
        return t;
    }
    let mut cut = max;
    while !t.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}\n…[truncated {} bytes]", &t[..cut], t.len() - cut)
}

/// Raw message from an agent: CRLF line endings in the head, Content-Length fixed.
fn raw(msg: &str) -> String {
    tools::fix_content_length(&msg.replace("\r\n", "\n").replace('\n', "\r\n"))
}

/// `target` argument, else https + the request's Host header.
fn target(a: &J, req: &str) -> Result<scan::Target, String> {
    let t = match str_arg(a, "target") {
        Some(t) => t.to_string(),
        None => format!(
            "https://{}",
            net::header(req, "host").ok_or("no `target` and no Host header")?
        ),
    };
    scan::parse_url(&t)
        .map(|(t, _)| t)
        .ok_or_else(|| format!("bad target {t:?}: use scheme://host[:port]"))
}

fn source<'a>(a: &J, st: &'a proxy::Shared) -> &'a [Entry] {
    if str_arg(a, "source") == Some("logger") {
        &st.logger
    } else {
        &st.history
    }
}

fn call(name: &str, a: &J, ctx: &Ctx) -> Result<J, String> {
    let max = num_arg(a, "max_bytes").unwrap_or(20_000).max(0) as usize;
    let limit = num_arg(a, "limit").unwrap_or(50).max(1) as usize;
    let grep = match str_arg(a, "grep") {
        Some(g) => Some(regex::Regex::new(g).map_err(|e| format!("bad grep regex: {e}"))?),
        None => None,
    };
    match name {
        "status" => {
            let st = ctx.state.lock().unwrap();
            let c = collab::client().lock().unwrap();
            Ok(obj(vec![
                (
                    "proxy_listener",
                    st.listener.map_or(J::Null, |p| s(format!("127.0.0.1:{p}"))),
                ),
                ("intercept", J::Bool(st.intercept)),
                ("intercept_responses", J::Bool(st.intercept_responses)),
                ("history", n(st.history.len())),
                ("logger", n(st.logger.len())),
                ("websockets", n(st.ws.len())),
                ("issues", n(st.issues.len())),
                ("queue", n(st.queue.len())),
                ("scans", n(ctx.tasks.lock().unwrap().len())),
                (
                    "ca_cert",
                    s(net::data_dir().join("ca.pem").display().to_string()),
                ),
                (
                    "collaborator",
                    if c.configured() {
                        s(c.server.clone())
                    } else {
                        J::Null
                    },
                ),
            ]))
        }
        "history_list" => {
            let st = ctx.state.lock().unwrap();
            let (host, method) = (str_arg(a, "host"), str_arg(a, "method"));
            let (status, after) = (num_arg(a, "status"), num_arg(a, "after_id").unwrap_or(0));
            let rows: Vec<&Entry> = source(a, &st)
                .iter()
                .filter(|e| e.id as i64 > after)
                .filter(|e| host.is_none_or(|h| e.host.contains(h)))
                .filter(|e| method.is_none_or(|m| e.method.eq_ignore_ascii_case(m)))
                .filter(|e| status.is_none_or(|x| e.status as i64 == x))
                .filter(|e| {
                    grep.as_ref().is_none_or(|g| {
                        g.is_match(&String::from_utf8_lossy(&e.req))
                            || g.is_match(&proxy::display(&e.resp))
                    })
                })
                .collect();
            let skip = rows.len().saturating_sub(limit);
            Ok(J::Arr(
                rows[skip..]
                    .iter()
                    .map(|e| {
                        obj(vec![
                            ("id", n(e.id)),
                            ("method", s(e.method.clone())),
                            ("url", s(format!("{}{}", e.origin(), e.url))),
                            ("status", n(e.status)),
                            ("length", n(e.resp.len())),
                            ("mime", s(e.mime())),
                            ("tool", s(e.tool)),
                        ])
                    })
                    .collect(),
            ))
        }
        "history_get" => {
            let id = num_arg(a, "id").ok_or("`id` required")? as usize;
            let st = ctx.state.lock().unwrap();
            let e = source(a, &st)
                .iter()
                .find(|e| e.id == id)
                .ok_or("no such id")?;
            Ok(obj(vec![
                ("id", n(e.id)),
                ("target", s(e.origin())),
                ("status", n(e.status)),
                ("time", s(e.time.clone())),
                ("comment", s(e.comment.clone())),
                ("request", s(text(&e.req, max))),
                ("response", s(text(&e.resp, max))),
            ]))
        }
        "ws_list" => {
            let st = ctx.state.lock().unwrap();
            let after = num_arg(a, "after_id").unwrap_or(0);
            let rows: Vec<_> = st
                .ws
                .iter()
                .filter(|m| m.id as i64 > after)
                .filter(|m| {
                    grep.as_ref()
                        .is_none_or(|g| g.is_match(&String::from_utf8_lossy(&m.data)))
                })
                .collect();
            let skip = rows.len().saturating_sub(limit);
            Ok(J::Arr(
                rows[skip..]
                    .iter()
                    .map(|m| {
                        let mut d = String::from_utf8_lossy(&m.data).into_owned();
                        if d.len() > max {
                            let mut c = max;
                            while !d.is_char_boundary(c) {
                                c -= 1;
                            }
                            d.truncate(c);
                        }
                        obj(vec![
                            ("id", n(m.id)),
                            ("url", s(m.url.clone())),
                            ("to_server", J::Bool(m.to_server)),
                            ("opcode", n(m.opcode)),
                            ("time", s(m.time.clone())),
                            ("data", s(d)),
                        ])
                    })
                    .collect(),
            ))
        }
        "send" => {
            let req = raw(str_arg(a, "request").ok_or("`request` required")?);
            let t = target(a, &req)?;
            let t0 = Instant::now();
            let resp = net::send(&t.host, t.port, t.tls, req.as_bytes())
                .map_err(|e| format!("send failed: {e}"))?;
            let ms = t0.elapsed().as_millis();
            ctx.state.lock().unwrap().log_tool(
                "MCP",
                &t.host,
                t.port,
                t.tls,
                req.as_bytes(),
                &resp,
            );
            Ok(obj(vec![
                ("status", n(proxy::status_of(&resp))),
                ("ms", n(ms)),
                ("response", s(text(&resp, max))),
            ]))
        }
        "intruder" => intruder_attack(a, ctx, grep),
        "intercept" => {
            let mut st = ctx.state.lock().unwrap();
            if let Some(b) = bool_arg(a, "responses") {
                st.intercept_responses = b;
            }
            if let Some(h) = str_arg(a, "host") {
                st.intercept_host = h.into();
            }
            if let Some(x) = str_arg(a, "skip_ext") {
                st.intercept_skip_ext = x.into();
            }
            if let Some(b) = bool_arg(a, "enabled") {
                st.intercept = b;
                if !b {
                    st.forward_all();
                }
            }
            if !matches!(a, J::Obj(v) if v.is_empty()) {
                st.event("MCP", "Intercept settings changed");
            }
            Ok(obj(vec![
                ("enabled", J::Bool(st.intercept)),
                ("responses", J::Bool(st.intercept_responses)),
                ("host", s(st.intercept_host.clone())),
                ("skip_ext", s(st.intercept_skip_ext.clone())),
                ("queue", n(st.queue.len())),
            ]))
        }
        "intercept_queue" => {
            let st = ctx.state.lock().unwrap();
            Ok(J::Arr(
                st.queue
                    .iter()
                    .map(|p| {
                        obj(vec![
                            ("id", n(p.id)),
                            (
                                "target",
                                s(format!(
                                    "{}://{}:{}",
                                    if p.tls { "https" } else { "http" },
                                    p.host,
                                    p.port
                                )),
                            ),
                            ("response", J::Bool(p.response)),
                            ("message", s(text(&p.req, max))),
                        ])
                    })
                    .collect(),
            ))
        }
        "intercept_forward" | "intercept_drop" => {
            let id = num_arg(a, "id").ok_or("`id` required")? as usize;
            let mut st = ctx.state.lock().unwrap();
            let i = st
                .queue
                .iter()
                .position(|p| p.id == id)
                .ok_or("no held message with that id")?;
            let p = st.queue.remove(i).expect("index from position");
            let reply = match (name, str_arg(a, "message")) {
                ("intercept_drop", _) => None,
                // responses keep their bytes as-is (bodies may be binary); requests get Content-Length fixed
                (_, Some(m)) if p.response => {
                    Some(m.replace("\r\n", "\n").replace('\n', "\r\n").into_bytes())
                }
                (_, Some(m)) => Some(raw(m).into_bytes()),
                _ => Some(p.req),
            };
            let _ = p.reply.send(reply);
            Ok(obj(vec![
                ("ok", J::Bool(true)),
                ("queue", n(st.queue.len())),
            ]))
        }
        "rules" => {
            let mut st = ctx.state.lock().unwrap();
            if let Some(J::Arr(v)) = a.get("set") {
                let mut rules = vec![];
                for r in v {
                    let kind = str_arg(r, "kind").unwrap_or("");
                    rules.push(Rule {
                        enabled: bool_arg(r, "enabled").unwrap_or(true),
                        kind: RULE_KINDS
                            .iter()
                            .position(|k| *k == kind)
                            .ok_or_else(|| format!("bad kind {kind:?}: one of {RULE_KINDS:?}"))?,
                        pattern: str_arg(r, "pattern").unwrap_or("").into(),
                        replace: str_arg(r, "replace").unwrap_or("").into(),
                        comment: str_arg(r, "comment").unwrap_or("").into(),
                    });
                }
                if let Some(bad) = rules
                    .iter()
                    .find(|r| regex::Regex::new(&r.pattern).is_err())
                {
                    return Err(format!("bad regex {:?}", bad.pattern));
                }
                st.rules = rules;
                st.event("MCP", "Match and replace rules replaced");
            }
            Ok(J::Arr(
                st.rules
                    .iter()
                    .map(|r| {
                        obj(vec![
                            ("enabled", J::Bool(r.enabled)),
                            ("kind", s(RULE_KINDS[r.kind])),
                            ("pattern", s(r.pattern.clone())),
                            ("replace", s(r.replace.clone())),
                            ("comment", s(r.comment.clone())),
                        ])
                    })
                    .collect(),
            ))
        }
        "scope" => {
            let mut sc = ctx.scope.lock().unwrap();
            if let Some(J::Arr(v)) = a.get("set") {
                *sc = v
                    .iter()
                    .filter_map(|r| {
                        let p = str_arg(r, "prefix")?;
                        Some((
                            bool_arg(r, "enabled").unwrap_or(true),
                            bool_arg(r, "include").unwrap_or(true),
                            p.to_string(),
                        ))
                    })
                    .collect();
                ctx.state
                    .lock()
                    .unwrap()
                    .event("MCP", "Target scope replaced");
            }
            Ok(J::Arr(
                sc.iter()
                    .map(|(on, inc, p)| {
                        obj(vec![
                            ("prefix", s(p.clone())),
                            ("include", J::Bool(*inc)),
                            ("enabled", J::Bool(*on)),
                        ])
                    })
                    .collect(),
            ))
        }
        "scan_start" => {
            let mut urls = a.get("urls").map(strs).unwrap_or_default();
            if urls.iter().any(|u| scan::parse_url(u).is_none()) {
                return Err("`urls` must be absolute http(s) URLs".into());
            }
            let mut extra = match str_arg(a, "request") {
                Some(r) => {
                    let r = raw(r);
                    vec![(target(a, &r)?, r)]
                }
                None => vec![],
            };
            if let Some(doc) = str_arg(a, "openapi") {
                // as in the New scan dialog: the URL is the API base, not a crawl start
                let base = urls.first().cloned();
                extra.extend(openapi::requests(
                    &openapi::parse_any(doc)?,
                    base.as_deref(),
                )?);
                urls.clear();
            }
            if urls.is_empty() && extra.is_empty() {
                return Err("give `urls` or `request`".into());
            }
            let mut cfg = if bool_arg(a, "thorough") == Some(true) {
                scan::Config::thorough()
            } else {
                scan::Config::fast()
            };
            cfg.crawl = bool_arg(a, "crawl").unwrap_or(extra.is_empty());
            cfg.headers = str_arg(a, "headers").unwrap_or("").into();
            cfg.login = str_arg(a, "login").unwrap_or("").into();
            let mut t = ctx.tasks.lock().unwrap();
            let id = t.len() + 1;
            t.push(scan::start(id, urls, extra, cfg, ctx.state.clone()));
            Ok(obj(vec![("task_id", n(id))]))
        }
        "scan_status" => {
            let id = num_arg(a, "task_id").ok_or("`task_id` required")?;
            if bool_arg(a, "stop") == Some(true) {
                let t = ctx.tasks.lock().unwrap();
                let task = (id as usize)
                    .checked_sub(1)
                    .and_then(|i| t.get(i))
                    .ok_or("no such task")?;
                task.stop.store(true, Ordering::SeqCst);
            }
            rest_get(&format!("/v0.1/scan/{id}"), ctx)
        }
        "issues" => rest_get("/v0.1/issues", ctx),
        "codec" => {
            let d = str_arg(a, "data").ok_or("`data` required")?;
            let b = d.as_bytes();
            let lossy = |v: Vec<u8>| String::from_utf8_lossy(&v).into_owned();
            let out = match str_arg(a, "op").unwrap_or("") {
                "base64_encode" => codec::base64_encode(b),
                "base64_decode" => lossy(codec::base64_decode(d).ok_or("invalid base64")?),
                "url_encode" => codec::url_encode(b, false),
                "url_decode" => lossy(codec::url_decode(d)),
                "html_encode" => codec::html_encode(b, false),
                "html_decode" => codec::html_decode(d),
                "hex_encode" => codec::hex_encode(b),
                "hex_decode" => lossy(codec::hex_decode(d).ok_or("invalid hex")?),
                "md5" => codec::hash("MD5", b),
                "sha1" => codec::hash("SHA-1", b),
                "sha256" => codec::hash("SHA-256", b),
                "sha384" => codec::hash("SHA-384", b),
                "sha512" => codec::hash("SHA-512", b),
                op => return Err(format!("unknown op {op:?}")),
            };
            Ok(s(out))
        }
        "collaborator" => {
            if bool_arg(a, "builtin") == Some(true) {
                collab::start_builtin()?;
            } else if let Some(srv) = str_arg(a, "server") {
                let mut c = collab::client().lock().unwrap();
                c.server = srv.trim().into();
                c.domain = str_arg(a, "domain").unwrap_or("").trim().into();
                c.secret = str_arg(a, "secret").unwrap_or("").into();
            }
            let payloads: Vec<J> = {
                let mut c = collab::client().lock().unwrap();
                if !c.configured() {
                    return Err("no Collaborator server: pass builtin=true or server".into());
                }
                (0..num_arg(a, "payloads").unwrap_or(0).clamp(0, 1000))
                    .filter_map(|_| c.payload("MCP").map(s))
                    .collect()
            };
            let poll_error = collab::poll().err();
            let inter = collab::interactions_for("")
                .into_iter()
                .map(|(i, used_by)| {
                    obj(vec![
                        ("id", s(i.id)),
                        ("protocol", s(i.protocol)),
                        ("client_ip", s(i.client_ip)),
                        ("time_ms", n(i.time_ms)),
                        ("used_by", s(used_by)),
                        ("raw", s(text(&i.raw, max))),
                    ])
                })
                .collect();
            Ok(obj(vec![
                ("payloads", J::Arr(payloads)),
                ("interactions", J::Arr(inter)),
                ("poll_error", poll_error.map_or(J::Null, s)),
            ]))
        }
        "open_in" => {
            const UI: [&str; 6] = [
                "repeater",
                "intruder",
                "organizer",
                "sequencer",
                "decoder",
                "comparer",
            ];
            let tool = str_arg(a, "tool").unwrap_or("");
            let tool = *UI
                .iter()
                .find(|t| **t == tool)
                .ok_or(format!("tool must be one of {UI:?}"))?;
            let id = num_arg(a, "id").ok_or("`id` required")? as usize;
            let mut st = ctx.state.lock().unwrap();
            let e = source(a, &st)
                .iter()
                .find(|e| e.id == id)
                .cloned()
                .ok_or("no such id")?;
            st.ui_cmds
                .push((if tool == "comparer" { "cmp_req" } else { tool }, e));
            st.event("MCP", format!("Sent item {id} to {tool}"));
            Ok(obj(vec![("ok", J::Bool(true))]))
        }
        "events" => {
            let st = ctx.state.lock().unwrap();
            let skip = st.events.len().saturating_sub(limit);
            Ok(J::Arr(
                st.events[skip..]
                    .iter()
                    .map(|(t, src, m)| {
                        obj(vec![
                            ("time", s(t.clone())),
                            ("source", s(src.clone())),
                            ("message", s(m.clone())),
                        ])
                    })
                    .collect(),
            ))
        }
        _ => Err(format!("unknown tool {name:?}")),
    }
}

/// Reuses the REST API's JSON for scans and issues.
fn rest_get(path: &str, ctx: &Ctx) -> Result<J, String> {
    let (status, _, body) = crate::rest::route("GET", path, "", "", &ctx.tasks, &ctx.state);
    let j = openapi::parse(&body).map_err(|e| e.to_string())?;
    if status.starts_with("200") {
        Ok(j)
    } else {
        Err(body)
    }
}

fn intruder_attack(a: &J, ctx: &Ctx, grep: Option<regex::Regex>) -> Result<J, String> {
    let template = raw(str_arg(a, "request").ok_or("`request` required")?);
    let t = target(a, &template.replace('§', ""))?;
    let attack = match str_arg(a, "attack").unwrap_or("sniper") {
        "sniper" => 0,
        "battering_ram" => 1,
        "pitchfork" => 2,
        "cluster_bomb" => 3,
        x => return Err(format!("bad attack {x:?}")),
    };
    let sets: Vec<Vec<String>> = match a.get("payloads") {
        Some(J::Arr(v)) => v.iter().map(strs).collect(),
        _ => return Err("`payloads` must be a list of string lists".into()),
    };
    let reqs = intruder::generate(&template, attack, &sets);
    if reqs.is_empty() {
        return Err("no requests: mark positions with §value§ and give payloads".into());
    }
    // ponytail: hard cap keeps one call fast; split bigger attacks into several calls
    if reqs.len() > 1000 {
        return Err(format!("{} requests: max 1000 per call", reqs.len()));
    }
    let threads = num_arg(a, "threads").unwrap_or(8).clamp(1, 32) as usize;
    let next = AtomicUsize::new(0);
    let rows: Mutex<Vec<(usize, J)>> = Mutex::new(vec![]);
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| {
                loop {
                    let k = next.fetch_add(1, Ordering::SeqCst);
                    let Some((payloads, req)) = reqs.get(k) else {
                        break;
                    };
                    let req = tools::fix_content_length(req);
                    let t0 = Instant::now();
                    let res = net::send(&t.host, t.port, t.tls, req.as_bytes());
                    let ms = t0.elapsed().as_millis();
                    let row = match &res {
                        Ok(resp) => {
                            ctx.state.lock().unwrap().log_tool(
                                "MCP",
                                &t.host,
                                t.port,
                                t.tls,
                                req.as_bytes(),
                                resp,
                            );
                            let body = proxy::display(resp);
                            let m = grep
                                .as_ref()
                                .and_then(|g| g.find(&body))
                                .map(|m| s(m.as_str()));
                            obj(vec![
                                (
                                    "payloads",
                                    J::Arr(payloads.iter().cloned().map(s).collect()),
                                ),
                                ("status", n(proxy::status_of(resp))),
                                ("length", n(resp.len())),
                                ("ms", n(ms)),
                                ("match", m.unwrap_or(J::Null)),
                            ])
                        }
                        Err(e) => obj(vec![
                            (
                                "payloads",
                                J::Arr(payloads.iter().cloned().map(s).collect()),
                            ),
                            ("error", s(e.to_string())),
                        ]),
                    };
                    rows.lock().unwrap().push((k, row));
                }
            });
        }
    });
    let mut rows = rows.into_inner().unwrap();
    rows.sort_by_key(|r| r.0);
    let rows: Vec<J> = rows.into_iter().map(|r| r.1).collect();
    Ok(if bool_arg(a, "anomalies") == Some(true) {
        anomalies(rows)
    } else {
        J::Arr(rows)
    })
}

/// Only the odd intruder rows. Baseline = the commonest (status, length) among rows without `error`;
/// length matches within the `soft_404` tolerance (exact, or 2% above 200 bytes). A row is anomalous
/// for `error`, `status`, `length`, `time` (ms > 3x median and >= 100 ms over it) or `grep` (match set).
fn anomalies(rows: Vec<J>) -> J {
    fn nu(r: &J, k: &str) -> i64 {
        num_arg(r, k).unwrap_or(0)
    }
    let compat = |a: i64, b: i64| b == a || (a > 200 && a.abs_diff(b) <= (a / 50) as u64);
    let ok: Vec<&J> = rows.iter().filter(|r| r.get("error").is_none()).collect();
    // ponytail: O(n^2) baseline search, fine for the 1000-request cap; bucket by status if the cap grows
    let mut base: Option<(i64, i64, usize)> = None;
    for r in &ok {
        let (st, len) = (nu(r, "status"), nu(r, "length"));
        let c = ok
            .iter()
            .filter(|o| nu(o, "status") == st && compat(len, nu(o, "length")))
            .count();
        if base.is_none_or(|(_, _, bc)| c > bc) {
            base = Some((st, len, c));
        }
    }
    let mut ms: Vec<i64> = ok.iter().map(|r| nu(r, "ms")).collect();
    ms.sort_unstable();
    let med = ms.get(ms.len() / 2).copied().unwrap_or(0);
    let mut out = vec![];
    for r in &rows {
        let mut why = vec![];
        if r.get("error").is_some() {
            why.push("error");
        } else if let Some((bs, bl, _)) = base {
            if nu(r, "status") != bs {
                why.push("status");
            }
            if !compat(bl, nu(r, "length")) {
                why.push("length");
            }
            let t = nu(r, "ms");
            if t > 3 * med && t - med >= 100 {
                why.push("time");
            }
            if !matches!(r.get("match"), None | Some(J::Null)) {
                why.push("grep");
            }
        }
        if let (false, J::Obj(mut v)) = (why.is_empty(), r.clone()) {
            v.push(("reasons".into(), J::Arr(why.into_iter().map(s).collect())));
            out.push(J::Obj(v));
        }
    }
    obj(vec![
        ("total", n(rows.len())),
        (
            "baseline",
            base.map_or(J::Null, |(st, len, c)| {
                obj(vec![
                    ("status", n(st)),
                    ("length", n(len)),
                    ("count", n(c)),
                    ("median_ms", n(med)),
                ])
            }),
        ),
        ("anomalies", J::Arr(out)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let list = openapi::parse(
            &handle(r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#, &c).unwrap(),
        )
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
        assert!(
            matches!(g.get("request"), Some(J::Str(s)) if s.contains("Content-Length: 2\n\nhi"))
        );
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
}
