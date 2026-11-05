//! REST API (Pro): start scans and read their results from scripts or CI, on localhost.
//! Burp-style routes under `/v0.1/`; an optional key goes in the path (`/<key>/v0.1/...`).
//!
//!   POST /v0.1/scan            {"urls": ["http://t/"], "scan_configurations": [{"name": "thorough"}], "crawl": true}
//!                              -> 201 Created, Location: <task id>
//!   GET  /v0.1/scan/<id>       -> {"task_id", "scan_status", "scan_metrics": {...}, "issue_events": [...]}
//!   GET  /v0.1/issues          -> every issue found so far (passive and active)
//!   GET  /v0.1/                -> API info
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use crate::openapi::J;
use crate::proxy::State;
use crate::scan::{self, Task};

pub type Tasks = Arc<Mutex<Vec<Task>>>;

pub fn start(port: u16, key: String, tasks: Tasks, state: State) -> std::io::Result<u16> {
    let l = TcpListener::bind(("127.0.0.1", port))?;
    let port = l.local_addr()?.port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let (tasks, state, key) = (tasks.clone(), state.clone(), key.clone());
            std::thread::spawn(move || handle(c, &key, &tasks, &state));
        }
    });
    Ok(port)
}

fn s(v: impl Into<String>) -> J {
    J::Str(v.into())
}
fn n(v: usize) -> J {
    J::Num(v.to_string())
}
fn obj(v: Vec<(&str, J)>) -> J {
    J::Obj(v.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn issues_json(state: &State, origin_filter: Option<&dyn Fn(&crate::scanner::Issue) -> bool>) -> J {
    let st = state.lock().unwrap();
    J::Arr(
        st.issues
            .iter()
            .filter(|i| origin_filter.is_none_or(|f| f(i)))
            .map(|i| {
                obj(vec![(
                    "issue",
                    obj(vec![
                        ("name", s(i.name)),
                        ("severity", s(i.severity.label().to_ascii_lowercase())),
                        ("confidence", s(i.confidence.to_ascii_lowercase())),
                        ("origin", s(i.origin.clone())),
                        ("path", s(i.path.clone())),
                        ("description", s(i.detail.clone())),
                    ]),
                )])
            })
            .collect(),
    )
}

/// Routes one request; returns (status line, extra headers, JSON body).
pub fn route(
    method: &str,
    path: &str,
    body: &str,
    key: &str,
    tasks: &Tasks,
    state: &State,
) -> (&'static str, String, String) {
    let path = if key.is_empty() {
        path
    } else {
        match path.strip_prefix(&format!("/{key}")) {
            Some(p) => p,
            None => {
                return (
                    "401 Unauthorized",
                    String::new(),
                    obj(vec![(
                        "error",
                        s("API key required in the path: /<key>/v0.1/..."),
                    )])
                    .to_json(),
                );
            }
        }
    };
    let path = path.split('?').next().unwrap_or("");
    match (method, path.trim_end_matches('/')) {
        ("GET", "/v0.1") => (
            "200 OK",
            String::new(),
            obj(vec![
                ("product", s("BurpCraft")),
                ("version", s(env!("CARGO_PKG_VERSION"))),
            ])
            .to_json(),
        ),
        ("GET", "/v0.1/issues") => ("200 OK", String::new(), issues_json(state, None).to_json()),
        ("POST", "/v0.1/scan") => {
            let req = match crate::openapi::parse(body) {
                Ok(j) => j,
                Err(e) => {
                    return (
                        "400 Bad Request",
                        String::new(),
                        obj(vec![("error", s(format!("invalid JSON: {e}")))]).to_json(),
                    );
                }
            };
            let urls: Vec<String> = match req.get("urls") {
                Some(J::Arr(v)) => v
                    .iter()
                    .filter_map(|u| {
                        if let J::Str(u) = u {
                            Some(u.clone())
                        } else {
                            None
                        }
                    })
                    .collect(),
                _ => vec![],
            };
            if urls.is_empty() || urls.iter().any(|u| scan::parse_url(u).is_none()) {
                return (
                    "400 Bad Request",
                    String::new(),
                    obj(vec![(
                        "error",
                        s("\"urls\" must list absolute http(s) URLs"),
                    )])
                    .to_json(),
                );
            }
            let thorough = matches!(req.get("scan_configurations"), Some(J::Arr(v)) if v.iter().any(|c| matches!(c.get("name"), Some(J::Str(n)) if n.to_ascii_lowercase().contains("thorough"))));
            let mut cfg = if thorough {
                scan::Config::thorough()
            } else {
                scan::Config::fast()
            };
            if let Some(J::Bool(b)) = req.get("crawl") {
                cfg.crawl = *b;
            }
            let mut t = tasks.lock().unwrap();
            let id = t.len() + 1;
            t.push(scan::start(id, urls, vec![], cfg, state.clone()));
            ("201 Created", format!("Location: {id}\r\n"), String::new())
        }
        ("GET", p) if p.starts_with("/v0.1/scan/") => {
            let Some(id) = p.rsplit('/').next().and_then(|i| i.parse::<usize>().ok()) else {
                return ("404 Not Found", String::new(), String::new());
            };
            let t = tasks.lock().unwrap();
            let Some(task) = id.checked_sub(1).and_then(|i| t.get(i)) else {
                return (
                    "404 Not Found",
                    String::new(),
                    obj(vec![("error", s("no such task"))]).to_json(),
                );
            };
            let status = if !task.done.load(Ordering::SeqCst) {
                "running"
            } else if task.stop.load(Ordering::SeqCst) {
                "paused"
            } else {
                "succeeded"
            };
            let body = obj(vec![
                ("task_id", s(id.to_string())),
                ("scan_status", s(status)),
                ("message", s(task.status.lock().unwrap().clone())),
                (
                    "scan_metrics",
                    obj(vec![
                        ("requests_made", n(task.requests.load(Ordering::SeqCst))),
                        ("issue_events", n(task.issues.load(Ordering::SeqCst))),
                    ]),
                ),
                (
                    "issue_events",
                    issues_json(
                        state,
                        Some(&|i: &crate::scanner::Issue| task.origins.contains(&i.origin)),
                    ),
                ),
            ]);
            ("200 OK", String::new(), body.to_json())
        }
        _ => (
            "404 Not Found",
            String::new(),
            obj(vec![("error", s("unknown endpoint"))]).to_json(),
        ),
    }
}

fn handle(mut c: TcpStream, key: &str, tasks: &Tasks, state: &State) {
    let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let Ok(rc) = c.try_clone() else { return };
    let mut r = BufReader::new(rc);
    let (mut first, mut line, mut len) = (String::new(), String::new(), 0usize);
    if r.read_line(&mut first).is_err() {
        return;
    }
    while r.read_line(&mut line).is_ok_and(|n| n > 2) {
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
        line.clear();
    }
    let mut body = vec![0; len.min(1 << 20)];
    let _ = r.read_exact(&mut body);
    let mut parts = first.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
    let (status, extra, body) = route(
        method,
        path,
        &String::from_utf8_lossy(&body),
        key,
        tasks,
        state,
    );
    let _ = write!(
        c,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        let (tasks, state): (Tasks, State) = (Default::default(), crate::proxy::Shared::new());
        assert_eq!(route("GET", "/v0.1/", "", "", &tasks, &state).0, "200 OK");
        assert_eq!(
            route("GET", "/v0.1/", "", "k3y", &tasks, &state).0,
            "401 Unauthorized"
        );
        assert_eq!(
            route("GET", "/k3y/v0.1/", "", "k3y", &tasks, &state).0,
            "200 OK"
        );
        assert_eq!(
            route("POST", "/v0.1/scan", "{nope", "", &tasks, &state).0,
            "400 Bad Request"
        );
        assert_eq!(
            route(
                "POST",
                "/v0.1/scan",
                r#"{"urls": ["ftp://x"]}"#,
                "",
                &tasks,
                &state
            )
            .0,
            "400 Bad Request"
        );
        // a closed port: the task finishes quickly with no issues
        let (st, loc, _) = route(
            "POST",
            "/v0.1/scan",
            r#"{"urls": ["http://127.0.0.1:9/"], "crawl": false}"#,
            "",
            &tasks,
            &state,
        );
        assert_eq!((st, loc.as_str()), ("201 Created", "Location: 1\r\n"));
        let mut body = String::new();
        for _ in 0..100 {
            body = route("GET", "/v0.1/scan/1", "", "", &tasks, &state).2;
            if body.contains("\"succeeded\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let j = crate::openapi::parse(&body).unwrap();
        assert_eq!(j.get("scan_status"), Some(&J::Str("succeeded".into())));
        assert_eq!(j.get("issue_events"), Some(&J::Arr(vec![])));
        assert_eq!(
            route("GET", "/v0.1/scan/9", "", "", &tasks, &state).0,
            "404 Not Found"
        );
    }
}
