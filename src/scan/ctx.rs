use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::proxy::{self, Entry, State};
use crate::security::scanner::{Issue, Severity};
use crate::tools::target::{Scope, url_in_scope};

// ------------------------------------------------------------ task

pub struct Task {
    pub name: String,
    /// Origins this task scans (`https://host[:port]`), to pick its issues.
    pub origins: Vec<String>,
    pub status: Arc<Mutex<String>>,
    pub requests: Arc<AtomicUsize>,
    pub issues: Arc<AtomicUsize>,
    pub stop: Arc<AtomicBool>,
    pub done: Arc<AtomicBool>,
}

/// What a scan request goes to: origin parts, as in history entries.
#[derive(Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

pub(crate) struct Ctx {
    pub(crate) target: Target,
    pub(crate) cfg: Config,
    pub(crate) state: State,
    pub(crate) task: usize,
    pub(crate) requests: Arc<AtomicUsize>,
    pub(crate) issues: Arc<AtomicUsize>,
    pub(crate) stop: Arc<AtomicBool>,
    /// Session cookies from the login request.
    pub(crate) cookies: Mutex<String>,
    /// Collaborator payload label -> (issue context) for out-of-band findings.
    pub(crate) oob: Mutex<Vec<(String, &'static str, String, String)>>, // label, issue name, detail, request
    /// Crawled in-scope paths, re-fetched when looking for stored input (stored XSS).
    pub(crate) pages: Mutex<Vec<String>>,
    /// Shared ceiling on total stored-XSS re-fetches, so point count can't explode traffic.
    pub(crate) stored_left: AtomicUsize,
    /// Target scope rules; with no include rule the scan's own origins are the scope.
    pub(crate) scope: Scope,
    /// Requests not sent because they were out of scope.
    pub(crate) skipped: Arc<AtomicUsize>,
    /// Compiled `cfg.logged_out`, and consecutive re-logins that did not help (serialises them).
    pub(crate) logged_out: Option<regex::Regex>,
    pub(crate) relogins: Mutex<usize>,
}

/// Consecutive useless re-logins before giving up: a login that never sticks, or endpoints that
/// answer 401 even when logged in, must not double the traffic for the whole scan.
pub(crate) const MAX_RELOGINS: usize = 20;

pub fn parse_url(url: &str) -> Option<(Target, String)> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else {
        (false, url.strip_prefix("http://")?)
    };
    let (hostport, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".into()));
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse().unwrap()),
        _ => (hostport.to_string(), if tls { 443 } else { 80 }),
    };
    (!host.is_empty()).then_some((Target { host, port, tls }, path))
}

pub fn origin_of(t: &Target) -> String {
    format!(
        "{}://{}",
        if t.tls { "https" } else { "http" },
        host_header(t)
    )
}

pub(crate) fn host_header(t: &Target) -> String {
    if (t.tls && t.port == 443) || (!t.tls && t.port == 80) {
        t.host.clone()
    } else {
        format!("{}:{}", t.host, t.port)
    }
}

pub fn get_request(t: &Target, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (BurpCraft Scanner)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        host_header(t)
    )
}

pub fn entry_of(t: &Target, req: &str, resp: &[u8], tool: &'static str) -> Entry {
    let mut line = req.lines().next().unwrap_or("").split(' ');
    Entry {
        id: 0,
        host: t.host.clone(),
        port: t.port,
        tls: t.tls,
        method: line.next().unwrap_or("").into(),
        url: line.next().unwrap_or("").into(),
        status: proxy::status_of(resp),
        req: req.as_bytes().to_vec(),
        resp: resp.to_vec(),
        edited: false,
        time: proxy::now(),
        ip: String::new(),
        listener: 0,
        comment: String::new(),
        highlight: None,
        tool,
    }
}

impl Ctx {
    /// Whether `path` on this target is in the Target scope (exclude rules always apply).
    pub(crate) fn in_scope(&self, path: &str) -> bool {
        let url = format!("{}{path}", origin_of(&self.target));
        url_in_scope(&self.scope.lock().unwrap(), &url, true)
    }

    /// Sends the login request and keeps its Set-Cookie values for every later request.
    pub(crate) fn login(&self) {
        let login = crate::tools::fix_content_length(
            &self.cfg.login.replace("\r\n", "\n").replace('\n', "\r\n"),
        );
        if let Some((resp, _)) = self.send_once("Scanner", &login) {
            let set: Vec<String> = String::from_utf8_lossy(proxy::head(&resp))
                .lines()
                .filter_map(|l| {
                    l.split_once(':')
                        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
                        .map(|(_, v)| v.trim().split(';').next().unwrap_or("").to_string())
                })
                .collect();
            *self.cookies.lock().unwrap() = set.join("; ");
        }
    }

    fn is_logged_out(&self, resp: &[u8]) -> bool {
        if let Some(re) = &self.logged_out {
            return re.is_match(&String::from_utf8_lossy(resp));
        }
        let status = proxy::status_of(resp);
        let loc = crate::http::net::header(&String::from_utf8_lossy(proxy::head(resp)), "location")
            .unwrap_or_default()
            .to_ascii_lowercase();
        status == 401
            || ((300..400).contains(&status) && (loc.contains("login") || loc.contains("signin")))
    }

    /// Like `send_once`, but when a login is configured and the response says the session
    /// expired, logs in again (once for all threads) and retries the request.
    pub(crate) fn send(&self, req: &str) -> Option<(Vec<u8>, Duration)> {
        self.send_as("Scanner", req)
    }

    /// `send` with the tool name the exchange is logged under: "Crawler" responses are passively
    /// scanned, "Scanner" (audit payload) responses are not, as each payload is a new URL.
    pub(crate) fn send_as(&self, tool: &'static str, req: &str) -> Option<(Vec<u8>, Duration)> {
        let sent_with = self.cookies.lock().unwrap().clone();
        let r = self.send_once(tool, req)?;
        if self.cfg.login.trim().is_empty() || !self.is_logged_out(&r.0) {
            return Some(r);
        }
        {
            let mut n = self.relogins.lock().unwrap();
            // another thread may have refreshed the session meanwhile: just retry
            if *self.cookies.lock().unwrap() == sent_with {
                if *n >= MAX_RELOGINS {
                    return Some(r);
                }
                *n += 1;
                self.login();
                self.state.lock().unwrap().event(
                    "Scanner",
                    format!("Task {}: session expired, logged in again", self.task),
                );
            }
        }
        let retry = self.send_once(tool, req);
        if retry.as_ref().is_some_and(|(b, _)| !self.is_logged_out(b)) {
            // a real expiry: the budget only counts re-logins that did not help
            *self.relogins.lock().unwrap() = 0;
        }
        retry.or(Some(r))
    }

    /// Adds auth headers/cookies, sends, logs; None when stopped, out of scope or on a network error.
    pub(crate) fn send_once(&self, tool: &'static str, req: &str) -> Option<(Vec<u8>, Duration)> {
        if self.stop.load(Ordering::SeqCst) {
            return None;
        }
        if !self.in_scope(req.split(' ').nth(1).unwrap_or("/")) {
            self.skipped.fetch_add(1, Ordering::SeqCst);
            return None;
        }
        let mut req = req.to_string();
        let extra: String = self
            .cfg
            .headers
            .lines()
            .map(str::trim)
            .filter(|l| l.contains(':'))
            .map(|l| format!("{l}\r\n"))
            .collect();
        let cookies = self.cookies.lock().unwrap().clone();
        if let Some(i) = req.find("\r\n") {
            let mut add = extra;
            if !cookies.is_empty() {
                add += &format!("Cookie: {cookies}\r\n");
            }
            req.insert_str(i + 2, &add);
        }
        if self.cfg.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(self.cfg.delay_ms));
        }
        let t0 = Instant::now();
        let resp = crate::http::net::send(
            &self.target.host,
            self.target.port,
            self.target.tls,
            req.as_bytes(),
        )
        .ok()?;
        let took = t0.elapsed();
        self.requests.fetch_add(1, Ordering::SeqCst);
        self.state.lock().unwrap().log_tool(
            tool,
            &self.target.host,
            self.target.port,
            self.target.tls,
            req.as_bytes(),
            &resp,
        );
        Some((resp, took))
    }

    pub(crate) fn report(
        &self,
        name: &'static str,
        severity: Severity,
        confidence: &'static str,
        detail: String,
        req: &str,
        resp: &[u8],
    ) {
        let (background, remediation) = advice(name);
        let e = entry_of(&self.target, req, resp, "Scanner");
        let issue = Issue {
            id: 0,
            name,
            severity,
            confidence,
            origin: e.origin(),
            path: e.path().to_string(),
            detail,
            background,
            remediation,
            entry_id: 0,
        };
        self.report_issue(issue, e);
    }

    /// Records an issue (once per name/location/detail) with its request/response as evidence.
    pub(crate) fn report_issue(&self, mut issue: Issue, mut e: Entry) {
        let mut s = self.state.lock().unwrap();
        if s.issues.iter().any(|x| {
            x.name == issue.name
                && x.origin == issue.origin
                && x.path == issue.path
                && x.detail == issue.detail
        }) {
            return;
        }
        e.id = s.next_id;
        s.next_id += 1;
        issue.entry_id = e.id;
        s.history.push(e);
        issue.id = s.issues.len() + 1;
        s.event(
            "Scanner",
            format!("Task {}: {} found", self.task, issue.name),
        );
        s.issues.push(issue);
        self.issues.fetch_add(1, Ordering::SeqCst);
    }

    /// BChecks: `given host` once per target.
    pub(crate) fn host_bchecks(&self) {
        for b in crate::security::bcheck::enabled(|g| *g == crate::security::bcheck::Given::Host) {
            let crate::security::bcheck::Action::Request { method, path } = &b.action else {
                continue;
            };
            let req = get_request(&self.target, path).replacen("GET ", &format!("{method} "), 1);
            if let Some((resp, _)) = self.send(&req)
                && let Some(m) = b.matched(&crate::security::bcheck::Responses {
                    latest: &resp,
                    base: None,
                })
            {
                let e = entry_of(&self.target, &req, &resp, "Scanner");
                self.report_issue(m.issue(e.origin(), e.path().to_string(), 0), e);
            }
        }
    }

    /// Timing-based request smuggling (CL.TE / TE.CL), once per target.
    pub(crate) fn host_smuggle(&self) {
        if self.stop.load(Ordering::SeqCst)
            || !self.cfg.on("HTTP request smuggling (timing)")
            || !self.in_scope("/")
        {
            return;
        }
        if let Some(f) = crate::security::smuggle::detect(&self.target, Duration::from_secs(10)) {
            self.report(
                "HTTP request smuggling",
                Severity::High,
                "Tentative",
                f.detail,
                &f.req,
                &[],
            );
        }
    }
}

fn advice(name: &str) -> (&'static str, &'static str) {
    match name {
        "SQL injection" => (
            "User input is placed into a database query without proper handling, so it can change the query's meaning: read or modify data, bypass logins, sometimes run commands.",
            "Use parameterized queries (prepared statements) for every query; never build SQL by concatenating input.",
        ),
        "Cross-site scripting (reflected)" => (
            "Input is copied into the response unescaped, so an attacker's link can run script in a victim's browser in the context of this site.",
            "Encode output for its HTML context, validate input strictly, and add a Content-Security-Policy.",
        ),
        "OS command injection" => (
            "Input reaches an operating-system command, letting an attacker run arbitrary commands on the server.",
            "Avoid shell commands with user input; use APIs that take argument lists, and allow-list values.",
        ),
        "File path traversal" => (
            "Input is used in a file path, so `../` sequences reach files outside the intended directory.",
            "Do not pass input to file APIs; map identifiers to files server-side, or canonicalize and check the base directory.",
        ),
        "Server-side template injection" => (
            "Input is evaluated as template code on the server, which often leads to remote code execution.",
            "Never build templates from input; pass input only as template data, and use a sandboxed engine.",
        ),
        "Open redirection" => (
            "The application redirects to a URL taken from the request, which helps phishing and can chain into other attacks.",
            "Redirect only to relative paths or an allow-list of destinations.",
        ),
        "HTTP response header injection" => (
            "Input containing CR/LF ends up in a response header, so an attacker can add headers or split the response.",
            "Reject or strip CR and LF in anything copied into headers.",
        ),
        "External service interaction" => (
            "The server made a network request (DNS/HTTP) to a domain supplied in the input, a sign of SSRF or blind injection.",
            "Do not fetch URLs or resolve hosts from input; if needed, use a strict allow-list and block internal addresses.",
        ),
        "HTTP request smuggling" => (
            "A front-end and back-end server interpret request boundaries differently (Content-Length vs Transfer-Encoding), so part of one request can be treated as the start of the next, letting an attacker poison other users' requests.",
            "Make the whole chain agree on request parsing: reject messages that carry both Content-Length and Transfer-Encoding, normalise framing at the front-end, and prefer HTTP/2 end to end.",
        ),
        "Cross-site scripting (stored)" => (
            "Input submitted on one request is saved and later copied unescaped into a page served to other users, so an attacker's script runs in every visitor's browser in this site's context.",
            "Encode output for its HTML context wherever stored data is rendered, validate input on the way in, and add a Content-Security-Policy.",
        ),
        "XML external entity injection" => (
            "The XML parser resolves external entities declared in the document, so attacker-supplied XML can read local files or make the server issue network requests (SSRF).",
            "Disable external entity and DTD processing in the XML parser (set it to not resolve external entities, and reject DOCTYPE declarations).",
        ),
        _ => ("", ""),
    }
}
