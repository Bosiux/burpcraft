//! The individual tool handlers: the `call` dispatch over every tool name
//! (history/logger/websockets, send, intruder, intercept queue, match-and-replace,
//! scope, scans, collaborator, decoder, open_in/events) and the REST bridge for
//! scans and issues.
use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::openapi::{self, J};
use crate::proxy::{self, Entry, Rule};
use crate::{codec, collab, net, scan};

use super::Ctx;
use super::attack::intruder_attack;
use super::helpers::{bool_arg, n, num_arg, obj, raw, s, source, str_arg, strs, target, text};

const RULE_KINDS: [&str; 5] = [
    "request_header",
    "request_body",
    "response_header",
    "response_body",
    "request_first_line",
];

pub(crate) fn call(name: &str, a: &J, ctx: &Ctx) -> Result<J, String> {
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
