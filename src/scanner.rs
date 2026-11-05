//! Passive scanner: inspects traffic the proxy already captured (no extra requests) and reports issues.
use crate::net;
use crate::proxy::{self, Entry};

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Information",
        }
    }
}

#[derive(Clone)]
pub struct Issue {
    pub id: usize,
    pub name: &'static str,
    pub severity: Severity,
    pub confidence: &'static str,
    pub origin: String,
    pub path: String,
    pub detail: String,
    pub background: &'static str,
    pub remediation: &'static str,
    pub entry_id: usize,
}

fn headers(msg: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(proxy::head(msg))
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

/// Runs every passive check against one request/response pair.
pub fn passive(e: &Entry) -> Vec<Issue> {
    let mut out = vec![];
    let mut add = |name, severity, confidence, detail: String, background, remediation| {
        out.push(Issue {
            id: 0,
            name,
            severity,
            confidence,
            origin: e.origin(),
            path: e.path().to_string(),
            detail,
            background,
            remediation,
            entry_id: e.id,
        })
    };
    if e.resp.is_empty() {
        return out;
    }
    let rh = headers(&e.resp);
    let get = |k: &str| rh.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let html = e.mime() == "HTML";
    let body = String::from_utf8_lossy(&proxy::body_bytes(&e.resp)).into_owned();

    for (_, v) in rh.iter().filter(|(k, _)| k == "set-cookie") {
        let name = v.split('=').next().unwrap_or("").trim().to_string();
        let flags = v.to_ascii_lowercase();
        if e.tls && !flags.contains("secure") {
            add(
                "Cookie missing Secure attribute",
                Severity::Medium,
                "Firm",
                format!("The cookie '{name}' was issued over HTTPS without the Secure attribute."),
                "Without the Secure attribute the browser will also send this cookie over unencrypted HTTP connections to the same host, where an attacker on the network path can read it.",
                "Add the Secure attribute to every cookie issued over HTTPS, especially session tokens.",
            );
        }
        if !flags.contains("httponly") {
            add(
                "Cookie missing HttpOnly attribute",
                Severity::Low,
                "Firm",
                format!("The cookie '{name}' does not have the HttpOnly attribute."),
                "Cookies readable from JavaScript can be stolen through any cross-site scripting flaw in the application.",
                "Set HttpOnly on cookies that client-side scripts do not need to read.",
            );
        }
    }
    if e.tls && get("strict-transport-security").is_none() && e.status / 100 == 2 {
        add(
            "HSTS header missing",
            Severity::Low,
            "Certain",
            "The HTTPS response does not include a Strict-Transport-Security header.".into(),
            "Without HSTS a user who types the bare domain or follows an http:// link makes a first unencrypted request that a network attacker can intercept and downgrade.",
            "Return Strict-Transport-Security with a long max-age (and includeSubDomains where possible) on all HTTPS responses.",
        );
    }
    if html && e.status / 100 == 2 {
        let csp = get("content-security-policy").unwrap_or("");
        if get("x-frame-options").is_none() && !csp.contains("frame-ancestors") {
            add(
                "Page can be framed by other sites",
                Severity::Info,
                "Firm",
                "The HTML response can be embedded in a frame on another site.".into(),
                "Pages that perform actions can be framed invisibly by a malicious site that tricks users into clicking them.",
                "Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY / SAMEORIGIN).",
            );
        }
        if csp.is_empty() {
            add(
                "No Content-Security-Policy",
                Severity::Info,
                "Certain",
                "The HTML response has no Content-Security-Policy header.".into(),
                "A content security policy limits where scripts and other resources may load from, reducing the impact of injection flaws.",
                "Define a restrictive Content-Security-Policy and tighten it over time.",
            );
        }
        let lower = body.to_ascii_lowercase();
        if !e.tls && lower.contains("type=\"password\"")
            || !e.tls && lower.contains("type=password")
        {
            add(
                "Password form served over HTTP",
                Severity::High,
                "Certain",
                "A page served over plain HTTP contains a password field.".into(),
                "Credentials entered on an unencrypted page can be read or altered by anyone on the network path.",
                "Serve login pages and their form targets exclusively over HTTPS.",
            );
        }
    }
    if get("x-content-type-options").is_none_or(|v| !v.eq_ignore_ascii_case("nosniff"))
        && !body.is_empty()
        && e.status / 100 == 2
    {
        add(
            "MIME sniffing not prevented",
            Severity::Info,
            "Firm",
            "The response does not include X-Content-Type-Options: nosniff.".into(),
            "Browsers may guess the content type of a response and treat user-supplied data as script or HTML.",
            "Send X-Content-Type-Options: nosniff on all responses.",
        );
    }
    for h in ["server", "x-powered-by", "x-aspnet-version"] {
        if let Some(v) = get(h).filter(|v| v.chars().any(|c| c.is_ascii_digit())) {
            add(
                "Server software version exposed",
                Severity::Info,
                "Firm",
                format!("The {h} header reveals: {v}"),
                "Exact product versions help an attacker pick known vulnerabilities to try.",
                "Remove or genericise version information in response headers.",
            );
        }
    }
    if let Some(acao) = get("access-control-allow-origin") {
        let creds =
            get("access-control-allow-credentials").is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let req_origin = net::header(&String::from_utf8_lossy(&e.req), "origin");
        if acao == "*" && creds || req_origin.as_deref() == Some(acao) && creds {
            add(
                "Permissive CORS with credentials",
                Severity::Medium,
                "Tentative",
                format!(
                    "Access-Control-Allow-Origin is '{acao}' together with Access-Control-Allow-Credentials: true."
                ),
                "Reflecting arbitrary origins while allowing credentials lets other websites read authenticated responses.",
                "Only allow a fixed list of trusted origins when credentials are permitted.",
            );
        }
    }
    let textual = !matches!(e.mime().as_str(), "image" | "font" | "");
    let emails: Vec<String> = if textual { find_emails(&body) } else { vec![] };
    if !emails.is_empty() {
        add(
            "Email addresses in response",
            Severity::Info,
            "Certain",
            format!("The response contains: {}", emails.join(", ")),
            "Published addresses can be targeted by phishing or used as usernames in guessing attacks.",
            "Review whether these addresses need to appear in responses.",
        );
    }
    out
}

fn find_emails(body: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for (i, _) in body.match_indices('@') {
        let is_local = |c: char| c.is_ascii_alphanumeric() || "._%+-".contains(c);
        let start = body[..i]
            .char_indices()
            .rev()
            .find(|(_, c)| !is_local(*c))
            .map(|(p, c)| p + c.len_utf8())
            .unwrap_or(0);
        let end = body[i + 1..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || ".-".contains(c)))
            .map(|p| i + 1 + p)
            .unwrap_or(body.len());
        let (local, domain) = (&body[start..i], body[i + 1..end].trim_end_matches('.'));
        if !local.is_empty()
            && domain.contains('.')
            && domain
                .rsplit('.')
                .next()
                .is_some_and(|t| t.len() >= 2 && t.chars().all(|c| c.is_ascii_alphabetic()))
        {
            let m = format!("{local}@{domain}");
            if !out.contains(&m) && out.len() < 10 {
                out.push(m);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tls: bool, resp: &str) -> Entry {
        Entry {
            id: 1,
            host: "a.test".into(),
            port: if tls { 443 } else { 80 },
            tls,
            method: "GET".into(),
            url: "/login".into(),
            status: 200,
            req: b"GET /login HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec(),
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
    fn checks() {
        let r = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx/1.18.0\r\nSet-Cookie: sid=1; Path=/\r\n\r\n<form><input type=\"password\"></form> mail admin@a.test";
        let names: Vec<&str> = passive(&entry(false, r)).iter().map(|i| i.name).collect();
        for n in [
            "Cookie missing HttpOnly attribute",
            "Password form served over HTTP",
            "Server software version exposed",
            "Email addresses in response",
            "Page can be framed by other sites",
        ] {
            assert!(names.contains(&n), "missing {n}: {names:?}");
        }
        assert!(!names.contains(&"Cookie missing Secure attribute"));
        let secure = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nStrict-Transport-Security: max-age=1\r\nX-Content-Type-Options: nosniff\r\nSet-Cookie: s=1; Secure; HttpOnly\r\n\r\n{}";
        assert!(passive(&entry(true, secure)).is_empty());
        assert_eq!(find_emails("x a.b@c.io, @bad, n@x.y1"), ["a.b@c.io"]);
        // multibyte characters right before '@' (e.g. lossy-decoded binary) must not split a char
        assert_eq!(find_emails("\u{fffd}@x.io é@y.io"), Vec::<String>::new());
    }
}
