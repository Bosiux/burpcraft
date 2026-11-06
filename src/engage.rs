//! Engagement tools (Pro): analyze target, discover content, find comments / scripts / references,
//! generate CSRF PoC. Reached from the history context menu; results open in one window.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use eframe::egui;

use crate::proxy::{self, Entry};

pub const TOOLS: [&str; 6] = [
    "Analyze target",
    "Discover content",
    "Find comments",
    "Find scripts",
    "Find references",
    "Generate CSRF PoC",
];

/// Responses of the same origin as `e`.
fn same_origin<'a>(history: &'a [Entry], e: &Entry) -> impl Iterator<Item = &'a Entry> {
    let o = e.origin();
    history.iter().filter(move |x| x.origin() == o)
}

fn text(e: &Entry) -> String {
    String::from_utf8_lossy(&proxy::body_bytes(&e.resp)).into_owned()
}

/// HTML comments in HTML responses, `/* */` and whole-line `//` comments in scripts.
pub fn comments(history: &[Entry], e: &Entry) -> Vec<(String, String)> {
    let html = regex::Regex::new(r"(?s)<!--(.*?)-->").unwrap();
    let block = regex::Regex::new(r"(?s)/\*(.*?)\*/").unwrap();
    let mut out = vec![];
    for x in same_origin(history, e) {
        let (t, mime) = (text(x), x.mime());
        let url = format!("{}{}", x.origin(), x.url);
        let mut push = |c: &str| {
            let c = c.trim();
            if !c.is_empty()
                && !out
                    .iter()
                    .any(|(u, v): &(String, String)| *u == url && v == c)
            {
                out.push((url.clone(), c.chars().take(300).collect()));
            }
        };
        if mime == "HTML" {
            html.captures_iter(&t).for_each(|c| push(&c[1]));
        }
        if mime == "script" || mime == "HTML" {
            block.captures_iter(&t).for_each(|c| push(&c[1]));
            t.lines()
                .filter_map(|l| l.trim().strip_prefix("//"))
                .for_each(&mut push);
        }
    }
    out
}

/// External script URLs and inline script blocks.
pub fn scripts(history: &[Entry], e: &Entry) -> Vec<(String, String)> {
    let re = regex::Regex::new(r#"(?is)<script\b([^>]*)>(.*?)</script>"#).unwrap();
    let src = regex::Regex::new(r#"(?i)\bsrc\s*=\s*["']?([^"'\s>]+)"#).unwrap();
    let mut out = vec![];
    for x in same_origin(history, e).filter(|x| x.mime() == "HTML") {
        let url = format!("{}{}", x.origin(), x.url);
        for c in re.captures_iter(&text(x)) {
            let item = match src.captures(&c[1]) {
                Some(s) => format!("external: {}", &s[1]),
                None => format!(
                    "inline, {} bytes: {}",
                    c[2].len(),
                    c[2].trim()
                        .chars()
                        .take(120)
                        .collect::<String>()
                        .replace('\n', " ")
                ),
            };
            out.push((url.clone(), item));
        }
    }
    out
}

/// Items anywhere in the history whose response mentions the selected URL's path.
pub fn references(history: &[Entry], e: &Entry) -> Vec<(String, String)> {
    let path = e.path();
    if path.len() < 2 {
        return vec![];
    }
    history
        .iter()
        .filter(|x| x.id != e.id && text(x).contains(path))
        .map(|x| {
            (
                format!("{}{}", x.origin(), x.url),
                format!("references {path}"),
            )
        })
        .collect()
}

/// Origin summary: URLs, static vs dynamic, parameters and their names.
pub fn analyze(history: &[Entry], e: &Entry) -> String {
    let mut urls = std::collections::BTreeSet::new();
    let mut dynamic = std::collections::BTreeSet::new();
    let mut params = std::collections::BTreeMap::<String, usize>::new();
    for x in same_origin(history, e) {
        urls.insert(x.path().to_string());
        let query = x
            .url
            .split_once('?')
            .map(|(_, q)| q.to_string())
            .unwrap_or_default();
        let body = if proxy::body(&x.req).is_some_and(|b| !b.is_empty()) {
            String::from_utf8_lossy(proxy::body(&x.req).unwrap()).into_owned()
        } else {
            String::new()
        };
        let mut any = false;
        for kv in query
            .split('&')
            .chain(body.split('&'))
            .filter(|kv| kv.contains('='))
        {
            *params
                .entry(kv.split('=').next().unwrap_or("").to_string())
                .or_default() += 1;
            any = true;
        }
        if any {
            dynamic.insert(x.path().to_string());
        }
    }
    let mut out = format!(
        "Target: {}\nTotal URLs: {}\nDynamic URLs (with parameters): {}\nStatic URLs: {}\nUnique parameter names: {}\n\nParameters (name: occurrences)\n",
        e.origin(),
        urls.len(),
        dynamic.len(),
        urls.len() - dynamic.len(),
        params.len()
    );
    for (k, n) in &params {
        out += &format!("  {k}: {n}\n");
    }
    out += "\nDynamic URLs\n";
    dynamic.iter().for_each(|u| out += &format!("  {u}\n"));
    out
}

fn attr(s: &str) -> String {
    crate::http::codec::html_encode(s.as_bytes(), false)
}

/// Auto-submitting HTML form that replays the request cross-site.
pub fn csrf_poc(e: &Entry) -> String {
    let req = String::from_utf8_lossy(&e.req);
    let head = String::from_utf8_lossy(proxy::head(&e.req)).into_owned();
    let ct = crate::http::net::header(&head, "content-type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let body = req
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    let (path, query) = e.url.split_once('?').unwrap_or((&e.url, ""));
    let get = e.method.eq_ignore_ascii_case("GET");
    let action = format!("{}{}", e.origin(), if get { path } else { &e.url });
    let field = |k: &str, v: &str| {
        let d = |s: &str| {
            String::from_utf8_lossy(&crate::http::codec::url_decode(&s.replace('+', " "))).into_owned()
        };
        format!(
            "      <input type=\"hidden\" name=\"{}\" value=\"{}\" />\n",
            attr(&d(k)),
            attr(&d(v))
        )
    };
    let pairs = |s: &str| {
        s.split('&')
            .filter(|p| !p.is_empty())
            .map(|p| p.split_once('=').unwrap_or((p, "")))
            .map(|(k, v)| field(k, v))
            .collect::<String>()
    };
    let (enctype, fields) = if get {
        (String::new(), pairs(query))
    } else if ct.is_empty() || ct.contains("x-www-form-urlencoded") {
        (String::new(), pairs(&body))
    } else {
        // non-form bodies (JSON, XML): text/plain sends `name=value`; the whole body as the name arrives as `body=`
        (
            " enctype=\"text/plain\"".into(),
            format!(
                "      <input type=\"hidden\" name=\"{}\" value=\"\" />\n",
                attr(&body)
            ),
        )
    };
    format!(
        "<html>\n  <!-- CSRF PoC - generated by BurpCraft -->\n  <body>\n    <form action=\"{}\" method=\"{}\"{}>\n{}      <input type=\"submit\" value=\"Submit request\" />\n    </form>\n    <script>history.pushState('', '', '/');document.forms[0].submit();</script>\n  </body>\n</html>\n",
        attr(&action),
        if get { "GET" } else { "POST" },
        enctype,
        fields
    )
}

const WORDS: &[&str] = &[
    "admin",
    "administrator",
    "login",
    "logout",
    "api",
    "v1",
    "v2",
    "backup",
    "backups",
    "config",
    "conf",
    "uploads",
    "upload",
    "images",
    "img",
    "js",
    "css",
    "static",
    "assets",
    ".git/HEAD",
    ".env",
    ".DS_Store",
    "robots.txt",
    "sitemap.xml",
    "test",
    "dev",
    "debug",
    "old",
    "tmp",
    "private",
    "phpinfo.php",
    "server-status",
    "console",
    "dashboard",
    "panel",
    "wp-admin",
    "wp-login.php",
    "user",
    "users",
    "account",
    "register",
    "signup",
    "docs",
    "swagger",
    "swagger.json",
    "openapi.json",
    "graphql",
    "health",
    "status",
    "metrics",
    "actuator",
    "index.php",
    "index.html",
    "web.config",
    "crossdomain.xml",
    ".well-known/security.txt",
];

/// Content discovery state: words tried against the selected item's directory, hits listed as they arrive.
pub struct Discovery {
    pub found: Arc<Mutex<Vec<(u16, usize, String)>>>,
    pub done: Arc<AtomicUsize>,
    pub total: usize,
    pub stop: Arc<AtomicBool>,
}

/// Body with the requested path removed: many "not found" pages echo it back.
fn normalize(body: &[u8], path: &str) -> String {
    String::from_utf8_lossy(body).replace(path, "")
}

/// A response that looks like the server's "not found" page for a random path: same status and
/// the same body once the path is removed; big pages may also differ by a few % (dynamic tokens).
pub fn soft_404(baseline: (u16, &str), got: (u16, &str)) -> bool {
    let (a, b) = (baseline.1.len(), got.1.len());
    got.0 == 404
        || (got.0 == baseline.0 && (got.1 == baseline.1 || (a > 200 && a.abs_diff(b) <= a / 50)))
}

fn get(e: &Entry, path: &str) -> Option<(u16, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let host = if (e.tls && e.port == 443) || (!e.tls && e.port == 80) {
        e.host.clone()
    } else {
        format!("{}:{}", e.host, e.port)
    };
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 BurpCraft\r\nAccept: */*\r\nConnection: close\r\n\r\n").into_bytes();
    let resp = crate::http::net::send(&e.host, e.port, e.tls, &req).ok()?;
    let status = String::from_utf8_lossy(proxy::head(&resp))
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some((status, proxy::body_bytes(&resp), req, resp))
}

pub fn discover(e: &Entry, extra: &str, state: &proxy::State) -> Discovery {
    let dir = match e.path().rfind('/') {
        Some(i) => e.path()[..=i].to_string(),
        None => "/".into(),
    };
    let words: Vec<String> = WORDS
        .iter()
        .map(|w| w.to_string())
        .chain(
            extra
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from),
        )
        .collect();
    let d = Discovery {
        found: Default::default(),
        done: Default::default(),
        total: words.len(),
        stop: Default::default(),
    };
    let (found, done, stop, e, state) = (
        d.found.clone(),
        d.done.clone(),
        d.stop.clone(),
        e.clone(),
        state.clone(),
    );
    std::thread::spawn(move || {
        let probe = format!("{dir}burpcraft-{}-missing", std::process::id());
        let baseline = Arc::new(get(&e, &probe).map_or((404, String::new()), |(s, b, ..)| {
            (s, normalize(&b, &probe))
        }));
        let (words, next) = (Arc::new(words), Arc::new(AtomicUsize::new(0)));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let (words, next, found, done, stop, e, state, dir, baseline) = (
                    words.clone(),
                    next.clone(),
                    found.clone(),
                    done.clone(),
                    stop.clone(),
                    e.clone(),
                    state.clone(),
                    dir.clone(),
                    baseline.clone(),
                );
                std::thread::spawn(move || {
                    while let Some(w) = words.get(next.fetch_add(1, Ordering::SeqCst)) {
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        let path = format!("{dir}{w}");
                        if let Some((status, body, req, resp)) = get(&e, &path) {
                            state.lock().unwrap().log_tool(
                                "Discover content",
                                &e.host,
                                e.port,
                                e.tls,
                                &req,
                                &resp,
                            );
                            if status != 0
                                && !soft_404(
                                    (baseline.0, &baseline.1),
                                    (status, &normalize(&body, &path)),
                                )
                            {
                                found.lock().unwrap().push((
                                    status,
                                    body.len(),
                                    format!("{}{path}", e.origin()),
                                ));
                            }
                        }
                        done.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        workers.into_iter().for_each(|w| {
            let _ = w.join();
        });
        if let Some(ctx) = state.lock().unwrap().ctx.clone() {
            ctx.request_repaint();
        }
    });
    d
}

#[derive(Default)]
pub struct Engage {
    pub open: bool,
    title: String,
    rows: Vec<(String, String)>,
    text: String,
    discovery: Option<Discovery>,
    wordlist: String,
    target: Option<Entry>,
}

impl Engage {
    pub fn start(&mut self, tool: usize, e: Entry, state: &proxy::State) {
        let history = state.lock().unwrap().history.clone();
        self.title = format!("{}: {}{}", TOOLS[tool], e.origin(), e.url);
        (self.rows, self.text, self.discovery) = (vec![], String::new(), None);
        match tool {
            0 => self.text = analyze(&history, &e),
            1 => self.discovery = Some(discover(&e, &self.wordlist, state)),
            2 => self.rows = comments(&history, &e),
            3 => self.rows = scripts(&history, &e),
            4 => self.rows = references(&history, &e),
            _ => self.text = csrf_poc(&e),
        }
        self.target = Some(e);
        self.open = true;
    }

    pub fn window(&mut self, ctx: &egui::Context) {
        if !self.open {
            return;
        }
        let mut open = true;
        crate::ui::theme::window(ctx, "Engagement tools", [820.0, 520.0], &mut open, |ui| {
            ui.strong(&self.title);
            ui.separator();
            if let Some(d) = &self.discovery {
                let done = d.done.load(Ordering::SeqCst);
                ui.horizontal(|ui| {
                    ui.add(
                        egui::ProgressBar::new(done as f32 / d.total.max(1) as f32)
                            .text(format!("{done} of {} requests", d.total))
                            .desired_width(300.0),
                    );
                    if done < d.total && ui.button("Stop").clicked() {
                        d.stop.store(true, Ordering::SeqCst);
                    }
                });
                ui.label("Extra words (one per line, used on the next run):");
                ui.add(
                    egui::TextEdit::multiline(&mut self.wordlist)
                        .desired_rows(2)
                        .desired_width(400.0),
                );
                let found = d.found.lock().unwrap();
                ui.label(format!(
                    "{} found (soft-404 responses filtered out)",
                    found.len()
                ));
                egui::ScrollArea::vertical().show(ui, |ui| {
                    egui::Grid::new("disc")
                        .striped(true)
                        .num_columns(3)
                        .show(ui, |ui| {
                            for (s, l, u) in found.iter() {
                                ui.label(s.to_string());
                                ui.label(l.to_string());
                                ui.monospace(u);
                                ui.end_row();
                            }
                        });
                });
                if done < d.total {
                    ui.ctx()
                        .request_repaint_after(std::time::Duration::from_millis(200));
                }
            } else if !self.text.is_empty() {
                let csrf = self.text.starts_with("<html>");
                if csrf {
                    ui.horizontal(|ui| {
                        if ui.button("Copy HTML").clicked() {
                            ui.ctx().copy_text(self.text.clone());
                        }
                        if ui.button("Test in browser").clicked() {
                            let _ = crate::render::open_in_browser(&self.text, None);
                        }
                    });
                }
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.text)
                            .code_editor()
                            .desired_width(f32::INFINITY),
                    );
                });
            } else {
                ui.label(format!(
                    "{} result{}",
                    self.rows.len(),
                    if self.rows.len() == 1 { "" } else { "s" }
                ));
                egui::ScrollArea::vertical().show(ui, |ui| {
                    egui::Grid::new("eng")
                        .striped(true)
                        .num_columns(2)
                        .show(ui, |ui| {
                            for (u, v) in &self.rows {
                                ui.monospace(u);
                                ui.label(v);
                                ui.end_row();
                            }
                        });
                });
            }
        });
        self.open = open;
        if !open && let Some(d) = &self.discovery {
            d.stop.store(true, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn entry(id: usize, method: &str, url: &str, req_extra: &str, resp: &str) -> Entry {
        Entry {
            id,
            host: "a.test".into(),
            port: 443,
            tls: true,
            method: method.into(),
            url: url.into(),
            status: 200,
            req: format!("{method} {url} HTTP/1.1\r\nHost: a.test\r\n{req_extra}").into_bytes(),
            resp: resp.as_bytes().to_vec(),
            edited: false,
            time: String::new(),
            ip: String::new(),
            listener: 8080,
            comment: String::new(),
            highlight: None,
            tool: "Proxy",
        }
    }

    #[test]
    fn engagement() {
        let page = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!-- TODO remove debug --><script src=\"/app.js\"></script><script>var k=1;</script><a href=\"/account/settings\">";
        let js = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n/* api key below */\n// internal endpoint\nvar u='http://x';";
        let h = vec![
            entry(1, "GET", "/home?lang=en", "\r\n", page),
            entry(2, "GET", "/app.js", "\r\n", js),
            entry(
                3,
                "POST",
                "/account/settings",
                "Content-Type: application/x-www-form-urlencoded\r\n\r\nemail=a%40b.c&role=admin+user",
                "HTTP/1.1 200 OK\r\n\r\n",
            ),
        ];
        let c: Vec<String> = comments(&h, &h[0]).into_iter().map(|x| x.1).collect();
        assert_eq!(
            c,
            ["TODO remove debug", "api key below", "internal endpoint"]
        );
        let s = scripts(&h, &h[0]);
        assert_eq!(
            (s[0].1.as_str(), s[1].1.starts_with("inline, 8 bytes")),
            ("external: /app.js", true)
        );
        assert_eq!(
            references(&h, &h[2]),
            [(
                "https://a.test/home?lang=en".to_string(),
                "references /account/settings".to_string()
            )]
        );
        let a = analyze(&h, &h[0]);
        assert!(
            a.contains("Total URLs: 3")
                && a.contains("Dynamic URLs (with parameters): 2")
                && a.contains("  role: 1")
        );
        let poc = csrf_poc(&h[2]);
        assert!(poc.contains("action=\"https://a.test/account/settings\" method=\"POST\""));
        assert!(
            poc.contains("name=\"email\" value=\"a@b.c\"")
                && poc.contains("name=\"role\" value=\"admin user\"")
        );
        let get_poc = csrf_poc(&h[0]);
        assert!(
            get_poc.contains("method=\"GET\"")
                && get_poc.contains("name=\"lang\" value=\"en\"")
                && get_poc.contains("action=\"https://a.test/home\"")
        );
        let big = "x".repeat(1000);
        assert!(
            soft_404((200, &big), (200, &"x".repeat(1010)))
                && soft_404((200, "nf"), (404, "a"))
                && soft_404((200, "Not found: "), (200, "Not found: "))
        );
        assert!(
            !soft_404((200, "Not here"), (200, "Disallow: /x"))
                && !soft_404((200, &big), (200, &"x".repeat(4000)))
                && !soft_404((404, "a"), (403, "a"))
        );
        assert_eq!(normalize(b"No page /admin here", "/admin"), "No page  here");
    }
}

#[cfg(test)]
mod net_tests {
    use super::tests::entry;
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn discovers_content_against_local_server() {
        // soft-404 server: every unknown path is "200 Not here", only /admin and /robots.txt exist
        let srv = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = srv.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut c in srv.incoming().flatten() {
                let mut buf = [0u8; 2048];
                let n = c.read(&mut buf).unwrap_or(0);
                let line = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                let body = if line.contains(" /admin ") {
                    "admin panel ".repeat(40)
                } else if line.contains(" /robots.txt ") {
                    "Disallow: /x".into()
                } else {
                    "Not here".into()
                };
                let _ = write!(
                    c,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let mut e = entry(1, "GET", "/index.html", "\r\n", "");
        (e.host, e.port, e.tls) = ("127.0.0.1".into(), port, false);
        let state = crate::proxy::Shared::new();
        let d = discover(&e, "custom-word", &state);
        for _ in 0..200 {
            if d.done.load(Ordering::SeqCst) == d.total {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(d.total, WORDS.len() + 1);
        let mut found: Vec<String> = d
            .found
            .lock()
            .unwrap()
            .iter()
            .map(|f| f.2.clone())
            .collect();
        found.sort();
        assert_eq!(
            found,
            [
                format!("http://127.0.0.1:{port}/admin"),
                format!("http://127.0.0.1:{port}/robots.txt")
            ]
        );
        assert_eq!(state.lock().unwrap().logger.len(), d.total);
    }
}
