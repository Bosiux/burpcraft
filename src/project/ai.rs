//! BurpCraft AI (the original's "Burp AI"): asks Claude to explain an issue and suggest follow-up
//! tests, from the issue and its request/response evidence. Opt-in per click: the data leaves the
//! machine for the Anthropic API, over certificate-verified HTTPS, with the user's own API key
//! (ANTHROPIC_API_KEY, or one typed in the UI and kept only in memory).
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::openapi::J;

pub const MODEL: &str = "claude-opus-5-5";
/// Evidence above this size is cut, and the prompt says so (never silently).
const MAX_EVIDENCE: usize = 60_000;

const SYSTEM: &str = "You are a senior web application penetration tester helping a colleague inside an authorized security testing tool. \
Given a scanner finding and the HTTP request/response that evidences it: say whether it looks like a true or false positive and why, \
explain the impact concretely for this application, and list the next manual tests to confirm or exploit it safely in this authorized engagement \
(exact requests or payloads to try in Repeater). Then give the fix. Be concise and specific to the evidence; use short sections.";

/// Key typed in the UI (memory only); falls back to the environment.
pub fn key() -> &'static Mutex<String> {
    static K: OnceLock<Mutex<String>> = OnceLock::new();
    K.get_or_init(|| Mutex::new(std::env::var("ANTHROPIC_API_KEY").unwrap_or_default()))
}

/// Answers by issue id: None while a request is running.
pub fn answers() -> &'static Mutex<HashMap<usize, Option<Result<String, String>>>> {
    static A: OnceLock<Mutex<HashMap<usize, Option<Result<String, String>>>>> = OnceLock::new();
    A.get_or_init(Default::default)
}

fn evidence(label: &str, msg: &[u8]) -> String {
    let t = crate::proxy::display(msg);
    if t.len() > MAX_EVIDENCE {
        format!(
            "{label} (first {MAX_EVIDENCE} of {} bytes; the rest was cut):\n{}",
            t.len(),
            &t[..t.floor_char_boundary(MAX_EVIDENCE)]
        )
    } else {
        format!("{label}:\n{t}")
    }
}

/// Messages API request body (non-streaming; refusals fall back server-side to another model).
pub fn request_body(issue: &crate::security::scanner::Issue, req: &[u8], resp: &[u8]) -> String {
    let user = format!(
        "Finding: {}\nSeverity: {} / confidence: {}\nLocation: {}{}\nScanner detail: {}\n\n{}\n\n{}",
        issue.name,
        issue.severity.label(),
        issue.confidence,
        issue.origin,
        issue.path,
        issue.detail,
        evidence("Request", req),
        evidence("Response", resp)
    );
    let obj = |v: Vec<(&str, J)>| J::Obj(v.into_iter().map(|(k, v)| (k.to_string(), v)).collect());
    obj(vec![
        ("model", J::Str(MODEL.into())),
        ("max_tokens", J::Num("16000".into())),
        // medium is this model's default; set explicitly so a model change doesn't silently shift it
        (
            "output_config",
            obj(vec![("effort", J::Str("medium".into()))]),
        ),
        ("fallbacks", J::Str("default".into())),
        ("system", J::Str(SYSTEM.into())),
        (
            "messages",
            J::Arr(vec![obj(vec![
                ("role", J::Str("user".into())),
                ("content", J::Str(user)),
            ])]),
        ),
    ])
    .to_json()
}

/// Text of a Messages API response body, or a readable error (API error, refusal, truncation).
pub fn parse_response(status: u16, body: &str) -> Result<String, String> {
    let j = crate::openapi::parse(body)
        .map_err(|e| format!("unreadable API response ({status}): {e}"))?;
    let s = |j: Option<&J>| {
        if let Some(J::Str(v)) = j {
            v.clone()
        } else {
            String::new()
        }
    };
    if status != 200 {
        let err = j.get("error");
        return Err(format!(
            "Anthropic API error {status}: {} {}",
            s(err.and_then(|e| e.get("type"))),
            s(err.and_then(|e| e.get("message")))
        ));
    }
    let stop = s(j.get("stop_reason"));
    if stop == "refusal" {
        let d = j.get("stop_details");
        return Err(format!(
            "Claude declined this request ({}): {}",
            s(d.and_then(|d| d.get("category"))),
            s(d.and_then(|d| d.get("explanation")))
        ));
    }
    let text: Vec<String> = match j.get("content") {
        Some(J::Arr(blocks)) => blocks
            .iter()
            .filter(|b| s(b.get("type")) == "text")
            .map(|b| s(b.get("text")))
            .collect(),
        _ => vec![],
    };
    let mut out = text.join("\n");
    if stop == "max_tokens" {
        out += "\n\n[answer cut at the token limit]";
    }
    if out.trim().is_empty() {
        Err(format!("empty answer (stop reason {stop})"))
    } else {
        Ok(out)
    }
}

fn call(body: &str, api_key: &str) -> Result<String, String> {
    let req = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nx-api-key: {api_key}\r\nanthropic-version: 2023-06-01\r\nanthropic-beta: server-side-fallback-2026-07-01\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = crate::http::net::send_verified("api.anthropic.com", req.as_bytes())
        .map_err(|e| format!("Could not reach the Anthropic API: {e}"))?;
    let status = String::from_utf8_lossy(crate::proxy::head(&resp))
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    parse_response(
        status,
        &String::from_utf8_lossy(&crate::proxy::body_bytes(&resp)),
    )
}

/// Starts an explanation in the background; the result appears in `answers()`.
pub fn explain(
    issue: crate::security::scanner::Issue,
    req: Vec<u8>,
    resp: Vec<u8>,
    ctx: eframe::egui::Context,
) {
    let api_key = key().lock().unwrap().trim().to_string();
    let id = issue.id;
    if api_key.is_empty() {
        answers().lock().unwrap().insert(
            id,
            Some(Err(
                "Set ANTHROPIC_API_KEY or enter an API key first.".into()
            )),
        );
        return;
    }
    answers().lock().unwrap().insert(id, None);
    std::thread::spawn(move || {
        let r = call(&request_body(&issue, &req, &resp), &api_key);
        answers().lock().unwrap().insert(id, Some(r));
        ctx.request_repaint();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::scanner::{Issue, Severity};

    #[test]
    fn request_and_response_shapes() {
        let issue = Issue {
            id: 3,
            name: "SQL injection",
            severity: Severity::High,
            confidence: "Firm",
            origin: "https://a.test".into(),
            path: "/item".into(),
            detail: "quote → \"error\"".into(),
            background: "",
            remediation: "",
            entry_id: 1,
        };
        let big = vec![b'x'; MAX_EVIDENCE + 10];
        let body = crate::openapi::parse(&request_body(
            &issue,
            b"GET /item?id=1' HTTP/1.1\r\n\r\n",
            &big,
        ))
        .unwrap();
        assert_eq!(body.get("model"), Some(&J::Str("claude-opus-5-5".into())));
        assert_eq!(body.get("fallbacks"), Some(&J::Str("default".into())));
        let J::Arr(msgs) = body.get("messages").unwrap() else {
            panic!()
        };
        let J::Str(user) = msgs[0].get("content").unwrap() else {
            panic!()
        };
        assert!(
            user.contains("Finding: SQL injection")
                && user.contains("id=1'")
                && user.contains(&format!(
                    "first {MAX_EVIDENCE} of {} bytes",
                    MAX_EVIDENCE + 10
                ))
        );

        let ok = r#"{"content":[{"type":"thinking","thinking":""},{"type":"text","text":"Likely true positive."}],"stop_reason":"end_turn"}"#;
        assert_eq!(parse_response(200, ok).unwrap(), "Likely true positive.");
        let cut = r#"{"content":[{"type":"text","text":"Part"}],"stop_reason":"max_tokens"}"#;
        assert!(
            parse_response(200, cut)
                .unwrap()
                .ends_with("[answer cut at the token limit]")
        );
        let refusal = r#"{"content":[],"stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":"x"}}"#;
        assert!(
            parse_response(200, refusal)
                .unwrap_err()
                .contains("declined this request (cyber)")
        );
        let err = r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#;
        assert_eq!(
            parse_response(401, err).unwrap_err(),
            "Anthropic API error 401: authentication_error invalid x-api-key"
        );
    }

    /// Network check (run with `cargo test -- --ignored`): verified TLS to the real API and error parsing.
    #[test]
    #[ignore]
    fn live_rejects_bad_key() {
        let issue = Issue {
            id: 1,
            name: "x",
            severity: Severity::Info,
            confidence: "Firm",
            origin: String::new(),
            path: String::new(),
            detail: String::new(),
            background: "",
            remediation: "",
            entry_id: 0,
        };
        let err = call(&request_body(&issue, b"", b""), "sk-ant-invalid").unwrap_err();
        assert!(
            err.starts_with("Anthropic API error 401: authentication_error"),
            "{err}"
        );
    }
}
