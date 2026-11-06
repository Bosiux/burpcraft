//! Extension protocol runtime: the `Ext` process (JSON-lines over stdin/stdout), the registry,
//! the request/response hooks, and process lifecycle (load/start/unload/init).
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::Duration;

use crate::http::codec::{base64_decode, base64_encode};
use crate::openapi::{J, parse};
use crate::proxy::{Entry, State};

pub struct Ext {
    pub path: String,
    pub name: String,
    pub hooks: Vec<String>,
    pub loaded: bool,
    pub output: Vec<String>,
    stdin: Option<ChildStdin>,
    child: Option<Child>,
    replies: HashMap<u64, mpsc::Sender<Option<Vec<u8>>>>,
}

type Shared = Arc<Mutex<Ext>>;

pub(super) fn registry() -> &'static Mutex<Vec<Shared>> {
    static R: OnceLock<Mutex<Vec<Shared>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

fn state_cell() -> &'static Mutex<Option<State>> {
    static S: OnceLock<Mutex<Option<State>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

fn list_file() -> std::path::PathBuf {
    crate::http::net::data_dir().join("extensions.txt")
}

pub(super) fn save_list() {
    let paths: Vec<String> = registry()
        .lock()
        .unwrap()
        .iter()
        .map(|e| e.lock().unwrap().path.clone())
        .collect();
    let _ = std::fs::create_dir_all(crate::http::net::data_dir());
    let _ = std::fs::write(list_file(), paths.join("\n"));
}

fn send_line(e: &mut Ext, j: &J) -> bool {
    match e.stdin.as_mut() {
        Some(w) => writeln!(w, "{}", j.to_json())
            .and_then(|_| w.flush())
            .is_ok(),
        None => false,
    }
}

fn obj(v: Vec<(&str, J)>) -> J {
    J::Obj(v.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

fn text(j: &J, k: &str) -> String {
    match j.get(k) {
        Some(J::Str(s)) => s.clone(),
        Some(J::Num(n)) => n.clone(),
        _ => String::new(),
    }
}

/// Handles one line written by an extension.
fn on_message(ext: &Shared, line: &str) {
    let Ok(j) = parse(line) else {
        ext.lock().unwrap().output.push(line.to_string());
        return;
    };
    let mut e = ext.lock().unwrap();
    match text(&j, "type").as_str() {
        "register" => {
            e.name = text(&j, "name");
            e.hooks = match j.get("hooks") {
                Some(J::Arr(v)) => v
                    .iter()
                    .filter_map(|h| {
                        if let J::Str(s) = h {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
                    .collect(),
                _ => vec![],
            };
        }
        "log" => e.output.push(text(&j, "message")),
        "request" | "continue" => {
            let id = text(&j, "id").parse().unwrap_or(0);
            if let Some(tx) = e.replies.remove(&id) {
                let _ = tx.send(
                    base64_decode(&text(&j, "request")).filter(|_| text(&j, "type") == "request"),
                );
            }
        }
        "issue" => {
            let name = e.name.clone();
            drop(e);
            report(&j, &name);
        }
        other => e.output.push(format!("unknown message type {other:?}")),
    }
}

fn report(j: &J, ext_name: &str) {
    let Some(state) = state_cell().lock().unwrap().clone() else {
        return;
    };
    let url = text(j, "url");
    let (target, path) = crate::scan::parse_url(&url)
        .map(|(t, p)| (Some(t), p))
        .unwrap_or((None, "/".into()));
    let origin = target
        .map(|t| {
            format!(
                "{}://{}{}",
                if t.tls { "https" } else { "http" },
                t.host,
                if (t.tls && t.port == 443) || (!t.tls && t.port == 80) {
                    String::new()
                } else {
                    format!(":{}", t.port)
                }
            )
        })
        .unwrap_or_default();
    use crate::security::scanner::Severity;
    let severity = match text(j, "severity").to_ascii_lowercase().as_str() {
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    };
    let mut s = state.lock().unwrap();
    let name: &'static str = Box::leak(text(j, "name").into_boxed_str());
    let detail = format!("{} (reported by extension {ext_name})", text(j, "detail"));
    let path = path.split('?').next().unwrap_or("/").to_string();
    if s.issues
        .iter()
        .any(|x| x.name == name && x.origin == origin && x.path == path)
    {
        return;
    }
    let id = s.issues.len() + 1;
    s.issues.push(crate::security::scanner::Issue {
        id,
        name,
        severity,
        confidence: "Tentative",
        origin,
        path,
        detail,
        background: "",
        remediation: "",
        entry_id: 0,
    });
    s.event("Extensions", format!("{ext_name}: {name}"));
}

/// Starts an extension process (path may include arguments, e.g. `python3 /x/ext.py`).
pub fn load(path: &str) -> Shared {
    let ext = Arc::new(Mutex::new(Ext {
        path: path.into(),
        name: path.rsplit('/').next().unwrap_or(path).into(),
        hooks: vec![],
        loaded: false,
        output: vec![],
        stdin: None,
        child: None,
        replies: HashMap::new(),
    }));
    start(&ext);
    registry().lock().unwrap().push(ext.clone());
    save_list();
    ext
}

pub(super) fn start(ext: &Shared) {
    let path = ext.lock().unwrap().path.clone();
    let mut parts = path.split_whitespace();
    let Some(prog) = parts.next() else { return };
    match Command::new(prog)
        .args(parts)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            let (out, err) = (child.stdout.take(), child.stderr.take());
            {
                let mut e = ext.lock().unwrap();
                e.stdin = child.stdin.take();
                e.child = Some(child);
                e.loaded = true;
                send_line(
                    &mut e,
                    &obj(vec![
                        ("type", J::Str("hello".into())),
                        ("api", J::Str("burpcraft-ext/1".into())),
                    ]),
                );
            }
            if let Some(out) = out {
                let ext = ext.clone();
                std::thread::spawn(move || {
                    for line in BufReader::new(out).lines().map_while(Result::ok) {
                        on_message(&ext, &line);
                    }
                    let mut e = ext.lock().unwrap();
                    e.loaded = false;
                    e.output.push("extension exited".into());
                });
            }
            if let Some(err) = err {
                let ext = ext.clone();
                std::thread::spawn(move || {
                    for line in BufReader::new(err).lines().map_while(Result::ok) {
                        ext.lock().unwrap().output.push(format!("stderr: {line}"));
                    }
                });
            }
        }
        Err(e) => ext
            .lock()
            .unwrap()
            .output
            .push(format!("failed to start: {e}")),
    }
}

pub(super) fn unload(ext: &Shared) {
    let mut e = ext.lock().unwrap();
    e.stdin = None; // closing stdin asks a well-behaved extension to exit
    if let Some(mut c) = e.child.take() {
        let _ = c.kill();
        let _ = c.wait();
    }
    e.loaded = false;
}

/// Loads the extensions saved last time; called once at startup.
pub fn init(state: State) {
    *state_cell().lock().unwrap() = Some(state);
    for p in std::fs::read_to_string(list_file())
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
    {
        let ext = Arc::new(Mutex::new(Ext {
            path: p.into(),
            name: p.rsplit('/').next().unwrap_or(p).into(),
            hooks: vec![],
            loaded: false,
            output: vec![],
            stdin: None,
            child: None,
            replies: HashMap::new(),
        }));
        start(&ext);
        registry().lock().unwrap().push(ext);
    }
}

fn with_hook(hook: &str) -> Vec<Shared> {
    registry()
        .lock()
        .unwrap()
        .iter()
        .filter(|e| {
            e.lock()
                .map(|e| e.loaded && e.hooks.iter().any(|h| h == hook))
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// Proxy request hook: each extension may replace the request (2 s timeout per extension).
pub fn on_request(host: &str, port: u16, tls: bool, mut req: Vec<u8>) -> Vec<u8> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    for ext in with_hook("request") {
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        {
            let mut e = ext.lock().unwrap();
            e.replies.insert(id, tx);
            let msg = obj(vec![
                ("type", J::Str("request".into())),
                ("id", J::Num(id.to_string())),
                ("host", J::Str(host.into())),
                ("port", J::Num(port.to_string())),
                ("tls", J::Bool(tls)),
                ("request", J::Str(base64_encode(&req))),
            ]);
            if !send_line(&mut e, &msg) {
                e.replies.remove(&id);
                continue;
            }
        }
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(Some(new)) => req = new,
            Ok(None) => {}
            Err(_) => {
                let mut e = ext.lock().unwrap();
                e.replies.remove(&id);
                e.output
                    .push(format!("request hook timed out for request {id}"));
            }
        }
    }
    req
}

/// Proxy response hook (fire and forget).
pub fn on_response(e: &Entry) {
    for ext in with_hook("response") {
        let msg = obj(vec![
            ("type", J::Str("response".into())),
            ("url", J::Str(format!("{}{}", e.origin(), e.url))),
            ("request", J::Str(base64_encode(&e.req))),
            ("response", J::Str(base64_encode(&e.resp))),
        ]);
        send_line(&mut ext.lock().unwrap(), &msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXT: &str = r#"
import sys, json, base64
print(json.dumps({"type": "register", "name": "Tagger", "hooks": ["request", "response"]}), flush=True)
for line in sys.stdin:
    m = json.loads(line)
    if m["type"] == "request":
        req = base64.b64decode(m["request"]).replace(b"\r\n\r\n", b"\r\nX-Tagged: 1\r\n\r\n", 1)
        print(json.dumps({"type": "request", "id": m["id"], "request": base64.b64encode(req).decode()}), flush=True)
    elif m["type"] == "response" and b"secret" in base64.b64decode(m["response"]):
        print(json.dumps({"type": "issue", "name": "Secret in response", "severity": "low", "url": m["url"], "detail": "found 'secret'"}), flush=True)
        print(json.dumps({"type": "log", "message": "reported " + m["url"]}), flush=True)
"#;

    #[test]
    fn process_extension_protocol() {
        if Command::new("python3").arg("-V").output().is_err() {
            return; // no interpreter on this machine
        }
        let dir = std::env::temp_dir().join(format!("burpcraft-ext-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("tagger.py");
        std::fs::write(&script, EXT).unwrap();
        let state = crate::proxy::Shared::new();
        *state_cell().lock().unwrap() = Some(state.clone());
        let ext = Arc::new(Mutex::new(Ext {
            path: format!("python3 {}", script.display()),
            name: String::new(),
            hooks: vec![],
            loaded: false,
            output: vec![],
            stdin: None,
            child: None,
            replies: HashMap::new(),
        }));
        start(&ext);
        registry().lock().unwrap().push(ext.clone());
        // the Windows CI runner can take several seconds to spawn python3 and complete the
        // handshake; poll generously (breaks early on success, so it's only slow on real failure)
        for _ in 0..400 {
            if !ext.lock().unwrap().hooks.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        {
            let e = ext.lock().unwrap();
            assert_eq!((e.name.as_str(), e.hooks.len()), ("Tagger", 2));
        }
        let out = on_request(
            "a.test",
            443,
            true,
            b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec(),
        );
        assert_eq!(
            out,
            b"GET / HTTP/1.1\r\nHost: a.test\r\nX-Tagged: 1\r\n\r\n"
        );
        let t = crate::scan::Target {
            host: "a.test".into(),
            port: 443,
            tls: true,
        };
        let e = crate::scan::entry_of(
            &t,
            "GET /x HTTP/1.1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nthe secret is 42",
            "Proxy",
        );
        on_response(&e);
        for _ in 0..100 {
            if !state.lock().unwrap().issues.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        let s = state.lock().unwrap();
        assert_eq!(
            (
                s.issues[0].name,
                s.issues[0].origin.as_str(),
                s.issues[0].path.as_str()
            ),
            ("Secret in response", "https://a.test", "/x")
        );
        drop(s);
        unload(&ext);
        registry().lock().unwrap().retain(|x| !Arc::ptr_eq(x, &ext));
        // an unloaded extension no longer sees requests
        assert_eq!(on_request("a.test", 443, true, b"X".to_vec()), b"X");
        let _ = std::fs::remove_dir_all(dir);
    }
}
