//! Extensions (Pro-style): out-of-process plugins in any language, a BApp Store served by a
//! self-hosted `burpcraft-server`, and the BChecks editor.
//!
//! Extension protocol: the extension is an executable started with piped stdin/stdout; every
//! message is one JSON object per line. BurpCraft sends:
//!   {"type":"hello","api":"burpcraft-ext/1"}
//!   {"type":"request","id":7,"host":"a.test","port":443,"tls":true,"request":"<base64>"}
//!       (only if the extension registered the "request" hook; reply within 2 s with
//!        {"type":"request","id":7,"request":"<base64>"} to replace it, or {"type":"continue","id":7})
//!   {"type":"response","url":"https://a.test/x","request":"<base64>","response":"<base64>"}
//! The extension may send at any time:
//!   {"type":"register","name":"My extension","hooks":["request","response"]}
//!   {"type":"issue","name":"...","severity":"high|medium|low|info","url":"https://...","detail":"..."}
//!   {"type":"log","message":"..."}
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::Duration;

use eframe::egui::{self, RichText};

use crate::codec::{base64_decode, base64_encode};
use crate::openapi::{J, parse};
use crate::proxy::{Entry, State};
use crate::theme;

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

fn registry() -> &'static Mutex<Vec<Shared>> {
    static R: OnceLock<Mutex<Vec<Shared>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

fn state_cell() -> &'static Mutex<Option<State>> {
    static S: OnceLock<Mutex<Option<State>>> = OnceLock::new();
    S.get_or_init(Default::default)
}

fn list_file() -> std::path::PathBuf {
    crate::net::data_dir().join("extensions.txt")
}

fn save_list() {
    let paths: Vec<String> = registry()
        .lock()
        .unwrap()
        .iter()
        .map(|e| e.lock().unwrap().path.clone())
        .collect();
    let _ = std::fs::create_dir_all(crate::net::data_dir());
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
    use crate::scanner::Severity;
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
    s.issues.push(crate::scanner::Issue {
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

fn start(ext: &Shared) {
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

fn unload(ext: &Shared) {
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

// ------------------------------------------------------------ BApp Store client

/// Catalogue entry: (name, version, description, file).
pub type BApp = (String, String, String, String);

fn http_get(server: &str, path: &str) -> Result<Vec<u8>, String> {
    let (host, port) = server
        .rsplit_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(80)))
        .unwrap_or((server.to_string(), 80));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {server}\r\nConnection: close\r\n\r\n");
    let resp = crate::net::send(&host, port, false, req.as_bytes()).map_err(|e| e.to_string())?;
    if !String::from_utf8_lossy(crate::proxy::head(&resp)).starts_with("HTTP/1.1 200") {
        return Err(String::from_utf8_lossy(crate::proxy::head(&resp))
            .lines()
            .next()
            .unwrap_or("")
            .to_string());
    }
    Ok(crate::proxy::body_bytes(&resp))
}

pub fn store_list(server: &str) -> Result<Vec<BApp>, String> {
    let body = http_get(server, "/burpcraft/bapps")?;
    Ok(String::from_utf8_lossy(&body)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() == 4).then(|| (f[0].into(), f[1].into(), f[2].into(), f[3].into()))
        })
        .collect())
}

/// Downloads a BApp into ~/.burpcraft/bapps and loads it; returns the command line used.
pub fn install(server: &str, app: &BApp) -> Result<String, String> {
    if app.3.contains('/') || app.3.contains("..") {
        return Err("invalid file name in catalogue".into());
    }
    let data = http_get(server, &format!("/burpcraft/bapps/{}", app.3))?;
    let dir = crate::net::data_dir().join("bapps");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let file = dir.join(&app.3);
    std::fs::write(&file, &data).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755));
    }
    // scripts run through their interpreter so no shebang/exec bit is needed
    let cmd = match file.extension().and_then(|e| e.to_str()) {
        Some("py") => format!("python3 {}", file.display()),
        Some("js") => format!("node {}", file.display()),
        Some("sh") => format!("sh {}", file.display()),
        _ => file.display().to_string(),
    };
    load(&cmd);
    Ok(cmd)
}

// ------------------------------------------------------------ UI

#[derive(Default)]
pub struct Tab {
    tab: usize,
    selected: Option<usize>,
    new_path: String,
    store_server: String,
    store: Vec<BApp>,
    store_msg: String,
    bcheck_sel: Option<usize>,
    bcheck_text: String,
    bcheck_msg: String,
}

impl Tab {
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        theme::frame_chrome().show(ui, |ui| {
            ui.horizontal(|ui| {
                for (i, t) in ["Installed", "BApp Store", "BChecks", "APIs"]
                    .iter()
                    .enumerate()
                {
                    if theme::sub_tab(ui, self.tab == i, t).clicked() {
                        self.tab = i;
                    }
                }
            });
        });
        ui.add_space(4.0);
        match self.tab {
            0 => self.installed(ui),
            1 => self.store(ui),
            2 => self.bchecks(ui),
            _ => {
                ui.label("Extensions are separate programs that talk to BurpCraft with one JSON object per line on stdin/stdout:");
                let doc: String = include_str!("ext.rs")
                    .lines()
                    .take_while(|l| l.starts_with("//!"))
                    .map(|l| l.trim_start_matches("//!"))
                    .collect::<Vec<_>>()
                    .join("\n");
                let mut d = doc;
                ui.add(
                    egui::TextEdit::multiline(&mut d)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .interactive(false),
                );
            }
        }
    }

    fn installed(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.new_path)
                    .hint_text("command, e.g. python3 /path/to/extension.py")
                    .desired_width(360.0),
            );
            if ui.button("Add").clicked() && !self.new_path.trim().is_empty() {
                load(self.new_path.trim());
                self.new_path.clear();
            }
            if let Some(i) = self.selected {
                if ui.button("Remove").clicked() {
                    let ext = registry().lock().unwrap().remove(i);
                    unload(&ext);
                    save_list();
                    self.selected = None;
                } else if ui.button("Reload").clicked() {
                    let ext = registry().lock().unwrap()[i].clone();
                    unload(&ext);
                    start(&ext);
                }
            }
        });
        ui.separator();
        let exts = registry().lock().unwrap().clone();
        if exts.is_empty() {
            ui.label(
                RichText::new(
                    "No extensions. Add a command above, or install one from the BApp Store.",
                )
                .color(theme::muted()),
            );
        }
        egui::Grid::new("exts")
            .striped(true)
            .num_columns(4)
            .show(ui, |ui| {
                for h in ["Loaded", "Name", "Hooks", "Command"] {
                    ui.strong(h);
                }
                ui.end_row();
                for (i, e) in exts.iter().enumerate() {
                    let e = e.lock().unwrap();
                    let mut on = e.loaded;
                    ui.add_enabled(false, egui::Checkbox::without_text(&mut on));
                    if ui
                        .selectable_label(self.selected == Some(i), &e.name)
                        .clicked()
                    {
                        self.selected = Some(i);
                    }
                    ui.label(e.hooks.join(", "));
                    ui.monospace(&e.path);
                    ui.end_row();
                }
            });
        if let Some(e) = self.selected.and_then(|i| exts.get(i)) {
            ui.separator();
            ui.strong("Output");
            let mut out = e.lock().unwrap().output.join("\n");
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut out)
                            .code_editor()
                            .desired_width(f32::INFINITY)
                            .interactive(false),
                    );
                });
        }
    }

    fn store(&mut self, ui: &mut egui::Ui) {
        if self.store_server.is_empty() {
            self.store_server = crate::collab::client().lock().unwrap().server.clone();
        }
        ui.label("BApps are served by a self-hosted burpcraft-server started with --bapps <dir>.");
        ui.horizontal(|ui| {
            ui.label("Server:");
            ui.add(
                egui::TextEdit::singleline(&mut self.store_server)
                    .hint_text("host:port")
                    .desired_width(220.0),
            );
            if ui.button("Refresh").clicked() {
                match store_list(self.store_server.trim()) {
                    Ok(l) => (self.store, self.store_msg) = (l, String::new()),
                    Err(e) => self.store_msg = format!("Failed to load the catalogue: {e}"),
                }
            }
        });
        if !self.store_msg.is_empty() {
            ui.label(RichText::new(&self.store_msg).color(theme::muted()));
        }
        ui.separator();
        let installed: Vec<String> = registry()
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.lock().unwrap().path.clone())
            .collect();
        let mut chosen = None;
        egui::Grid::new("bapps")
            .striped(true)
            .num_columns(4)
            .show(ui, |ui| {
                for h in ["Name", "Version", "Description", ""] {
                    ui.strong(h);
                }
                ui.end_row();
                for (i, app) in self.store.iter().enumerate() {
                    ui.label(&app.0);
                    ui.label(&app.1);
                    ui.label(&app.2);
                    if installed.iter().any(|p| p.ends_with(&app.3)) {
                        ui.label("Installed");
                    } else if ui.button("Install").clicked() {
                        chosen = Some(i);
                    }
                    ui.end_row();
                }
            });
        if let Some(i) = chosen {
            self.store_msg = match install(self.store_server.trim(), &self.store[i]) {
                Ok(c) => format!("Installed and loaded: {c}"),
                Err(e) => format!("Install failed: {e}"),
            };
        }
    }

    fn bchecks(&mut self, ui: &mut egui::Ui) {
        ui.label(format!("BChecks in {} (*.bcheck). Enabled checks run in active scans and on proxied responses.", crate::bcheck::dir().display()));
        ui.horizontal(|ui| {
            if ui.button("New").clicked() {
                (self.bcheck_sel, self.bcheck_text) = (None, crate::bcheck::TEMPLATE.to_string());
            }
            if ui.button("Reload from disk").clicked() {
                *crate::bcheck::checks().lock().unwrap() =
                    crate::bcheck::load_dir(&crate::bcheck::dir());
            }
        });
        let (list, errs) = crate::bcheck::checks().lock().unwrap().clone();
        for e in &errs {
            ui.colored_label(egui::Color32::from_rgb(0xC0, 0x30, 0x30), e);
        }
        egui::Grid::new("bchecks")
            .striped(true)
            .num_columns(3)
            .show(ui, |ui| {
                for h in ["Enabled", "Name", "Given"] {
                    ui.strong(h);
                }
                ui.end_row();
                for (i, b) in list.iter().enumerate() {
                    let mut on = b.enabled;
                    if ui.checkbox(&mut on, "").changed() {
                        crate::bcheck::checks().lock().unwrap().0[i].enabled = on;
                    }
                    if ui
                        .selectable_label(self.bcheck_sel == Some(i), &b.name)
                        .clicked()
                    {
                        (self.bcheck_sel, self.bcheck_text) = (Some(i), b.source.clone());
                    }
                    ui.label(format!("{:?}", b.given));
                    ui.end_row();
                }
            });
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Validate").clicked() {
                self.bcheck_msg = match crate::bcheck::parse(&self.bcheck_text) {
                    Ok(b) => format!("OK: \"{}\"", b.name),
                    Err(e) => e,
                };
            }
            if ui.button("Save").clicked() {
                self.bcheck_msg = match crate::bcheck::parse(&self.bcheck_text) {
                    Ok(b) => {
                        let file: String = b
                            .name
                            .chars()
                            .map(|c| {
                                if c.is_ascii_alphanumeric() {
                                    c.to_ascii_lowercase()
                                } else {
                                    '-'
                                }
                            })
                            .collect();
                        let path = crate::bcheck::dir().join(format!("{file}.bcheck"));
                        let _ = std::fs::create_dir_all(crate::bcheck::dir());
                        match std::fs::write(&path, &self.bcheck_text) {
                            Ok(()) => {
                                *crate::bcheck::checks().lock().unwrap() =
                                    crate::bcheck::load_dir(&crate::bcheck::dir());
                                format!("Saved {}", path.display())
                            }
                            Err(e) => format!("Save failed: {e}"),
                        }
                    }
                    Err(e) => format!("Not saved: {e}"),
                };
            }
            ui.label(RichText::new(&self.bcheck_msg).color(theme::muted()));
        });
        ui.label(RichText::new("Syntax: metadata, optional `run for each:` (name = \"a\", \"b\") and `define:` (name = \"value\", used as {name}; {random_str(8)}), `given ... then`, `send ...`, `if ... then` / `else if ... then` / `else` / `end if`, `report issue:`. New starts from an example.").color(theme::muted()));
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut self.bcheck_text)
                    .code_editor()
                    .desired_rows(16)
                    .desired_width(f32::INFINITY),
            );
        });
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
        for _ in 0..100 {
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
