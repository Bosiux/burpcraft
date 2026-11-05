//! BChecks: custom scan checks in a small declarative language (a subset of the original's syntax).
//!
//! ```text
//! metadata:
//!     name: "Exposed git HEAD"
//!     description: "The .git directory is served"
//! given host then
//!     send request called check:
//!         method: "GET"
//!         path: "/.git/HEAD"
//!     if "ref: refs/" in {check.response.body} then
//!         report issue:
//!             severity: medium
//!             confidence: firm
//!             detail: "Found /.git/HEAD"
//!             remediation: "Do not deploy the .git directory"
//!     end if
//! ```
//! `given`: `response` (passive, every proxied response), `host` (once per scanned origin),
//! `[query|body|cookie|json|header] insertion point` (active, per parameter, with `send payload:`
//! `appending: "..."` or `replacing: "..."`). Conditions: `<value> matches "re"`, `"text" in <value>`,
//! `<value> is "text"`, joined with `and` / `or`, each optionally prefixed by `not`. Values:
//! `{latest.response}`, `{latest.response.body}`, `{latest.response.headers}`,
//! `{latest.response.status_code}`, `{base.response...}` (the unmodified request's response);
//! `{check.response...}` is `latest` for a `send request called check`.
use std::sync::{Mutex, OnceLock};

use crate::scanner::Severity;

#[derive(Clone, Debug, PartialEq)]
pub enum Given {
    Response,
    Host,
    /// Insertion point, optionally limited to one kind (`query`, `body`, `cookie`, `json`, `header`).
    Point(Option<String>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    None,
    Append(String),
    Replace(String),
    Request { method: String, path: String },
}

#[derive(Clone, Debug, PartialEq)]
enum Test {
    Matches(String, String),
    In(String, String),
    Is(String, String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct BCheck {
    pub name: String,
    pub description: String,
    pub given: Given,
    pub action: Action,
    /// Disjunction of conjunctions of (negated?, test).
    cond: Vec<Vec<(bool, Test)>>,
    pub severity: Severity,
    pub confidence: String,
    pub detail: String,
    pub remediation: String,
    pub enabled: bool,
    pub source: String,
}

fn quoted(s: &str) -> Option<String> {
    let s = s.trim();
    let inner = s.strip_prefix('"')?.strip_suffix('"')?;
    Some(
        inner
            .replace("\\\"", "\"")
            .replace("\\n", "\n")
            .replace("\\\\", "\\"),
    )
}

fn kv(line: &str) -> Option<(String, String)> {
    let (k, v) = line.split_once(':')?;
    Some((k.trim().to_ascii_lowercase(), v.trim().to_string()))
}

fn parse_test(t: &str) -> Result<(bool, Test), String> {
    let t = t.trim();
    let (neg, t) = match t.strip_prefix("not ") {
        Some(r) => (true, r.trim()),
        None => (false, t),
    };
    let err = || format!("cannot read condition `{t}`");
    if let Some((l, r)) = t.split_once(" matches ") {
        return Ok((
            neg,
            Test::Matches(l.trim().into(), quoted(r).ok_or_else(err)?),
        ));
    }
    if let Some((l, r)) = t.split_once(" in ") {
        return Ok((neg, Test::In(quoted(l).ok_or_else(err)?, r.trim().into())));
    }
    if let Some((l, r)) = t.split_once(" is ") {
        return Ok((neg, Test::Is(l.trim().into(), quoted(r).ok_or_else(err)?)));
    }
    Err(err())
}

pub fn parse(src: &str) -> Result<BCheck, String> {
    let mut b = BCheck {
        name: String::new(),
        description: String::new(),
        given: Given::Response,
        action: Action::None,
        cond: vec![],
        severity: Severity::Info,
        confidence: "Tentative".into(),
        detail: String::new(),
        remediation: String::new(),
        enabled: true,
        source: src.to_string(),
    };
    let (mut given, mut method, mut path) = (false, "GET".to_string(), None);
    for raw in src.lines() {
        let line = raw.split(" #").next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let low = line.to_ascii_lowercase();
        if let Some(g) = low
            .strip_prefix("given ")
            .and_then(|g| g.strip_suffix(" then"))
        {
            given = true;
            b.given = match g.trim() {
                "response" => Given::Response,
                "host" => Given::Host,
                "insertion point" | "any insertion point" => Given::Point(None),
                other => match other.strip_suffix(" insertion point") {
                    Some(k) if ["query", "body", "cookie", "json", "header"].contains(&k) => {
                        Given::Point(Some(k.into()))
                    }
                    _ => return Err(format!("unknown `given {g}`")),
                },
            };
            continue;
        }
        if let Some(c) = line
            .strip_prefix("if ")
            .and_then(|c| c.strip_suffix(" then"))
        {
            b.cond = c
                .split(" or ")
                .map(|conj| {
                    conj.split(" and ")
                        .map(parse_test)
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<_, _>>()?;
            continue;
        }
        let Some((k, v)) = kv(line) else { continue };
        let q = || quoted(&v).ok_or_else(|| format!("`{k}` needs a quoted value"));
        match k.as_str() {
            "name" => b.name = q()?,
            "description" => b.description = q()?,
            "appending" => b.action = Action::Append(q()?),
            "replacing" => b.action = Action::Replace(q()?),
            "method" => method = q()?,
            "path" => path = Some(q()?),
            "severity" => {
                b.severity = match v.to_ascii_lowercase().trim_matches('"') {
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    "info" | "information" => Severity::Info,
                    s => return Err(format!("unknown severity `{s}`")),
                }
            }
            "confidence" => {
                let c = v.trim_matches('"').to_ascii_lowercase();
                b.confidence = match c.as_str() {
                    "certain" | "firm" | "tentative" => {
                        format!("{}{}", c[..1].to_ascii_uppercase(), &c[1..])
                    }
                    _ => return Err(format!("unknown confidence `{c}`")),
                };
            }
            "detail" => b.detail = q()?,
            "remediation" => b.remediation = q()?,
            _ => {}
        }
    }
    if let Some(p) = path {
        b.action = Action::Request { method, path: p };
    }
    if b.name.is_empty() {
        return Err("missing `name` in metadata".into());
    }
    if !given {
        return Err("missing `given ... then`".into());
    }
    if b.cond.is_empty() {
        return Err("missing `if ... then` condition".into());
    }
    if matches!(b.given, Given::Point(_))
        && !matches!(b.action, Action::Append(_) | Action::Replace(_))
    {
        return Err(
            "an insertion point check needs `send payload:` with `appending` or `replacing`".into(),
        );
    }
    if b.given == Given::Host && !matches!(b.action, Action::Request { .. }) {
        return Err("a host check needs `send request` with a `path`".into());
    }
    Ok(b)
}

/// Responses a check reads its values from.
pub struct Responses<'a> {
    pub latest: &'a [u8],
    pub base: Option<&'a [u8]>,
}

fn value(name: &str, r: &Responses) -> String {
    let name = name.trim().trim_start_matches('{').trim_end_matches('}');
    let (which, part) = name.split_once(".response").unwrap_or((name, ""));
    let msg = if which == "base" {
        r.base.unwrap_or(r.latest)
    } else {
        r.latest
    };
    match part {
        ".body" => String::from_utf8_lossy(&crate::proxy::body_bytes(msg)).into_owned(),
        ".headers" => String::from_utf8_lossy(crate::proxy::head(msg)).into_owned(),
        ".status_code" => String::from_utf8_lossy(crate::proxy::head(msg))
            .split_whitespace()
            .nth(1)
            .unwrap_or("")
            .to_string(),
        _ => crate::proxy::display(msg),
    }
}

impl BCheck {
    pub fn holds(&self, r: &Responses) -> bool {
        self.cond.iter().any(|conj| {
            conj.iter().all(|(neg, t)| {
                let ok = match t {
                    Test::Matches(v, re) => {
                        regex::Regex::new(re).is_ok_and(|re| re.is_match(&value(v, r)))
                    }
                    Test::In(text, v) => value(v, r).contains(text.as_str()),
                    Test::Is(v, text) => value(v, r) == *text,
                };
                ok != *neg
            })
        })
    }
    /// Issue for a match (name/description leaked once per load: issues hold `&'static str`).
    pub fn issue(&self, origin: String, path: String, entry_id: usize) -> crate::scanner::Issue {
        crate::scanner::Issue {
            id: 0,
            name: Box::leak(self.name.clone().into_boxed_str()),
            severity: self.severity,
            confidence: Box::leak(self.confidence.clone().into_boxed_str()),
            origin,
            path,
            detail: if self.detail.is_empty() {
                format!("Reported by BCheck \"{}\".", self.name)
            } else {
                self.detail.clone()
            },
            background: Box::leak(self.description.clone().into_boxed_str()),
            remediation: Box::leak(self.remediation.clone().into_boxed_str()),
            entry_id,
        }
    }
}

pub fn dir() -> std::path::PathBuf {
    crate::net::data_dir().join("bchecks")
}

/// Loaded checks (from ~/.burpcraft/bchecks/*.bcheck) with any parse errors.
pub fn checks() -> &'static Mutex<(Vec<BCheck>, Vec<String>)> {
    static C: OnceLock<Mutex<(Vec<BCheck>, Vec<String>)>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(load_dir(&dir())))
}

pub fn load_dir(d: &std::path::Path) -> (Vec<BCheck>, Vec<String>) {
    let (mut ok, mut errs) = (vec![], vec![]);
    let mut files: Vec<_> = std::fs::read_dir(d)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "bcheck"))
        .collect();
    files.sort();
    for f in files {
        match std::fs::read_to_string(&f)
            .map_err(|e| e.to_string())
            .and_then(|s| parse(&s))
        {
            Ok(b) => ok.push(b),
            Err(e) => errs.push(format!("{}: {e}", f.display())),
        }
    }
    (ok, errs)
}

pub fn enabled(given: impl Fn(&Given) -> bool) -> Vec<BCheck> {
    checks()
        .lock()
        .unwrap()
        .0
        .iter()
        .filter(|b| b.enabled && given(&b.given))
        .cloned()
        .collect()
}

/// Passive `given response` checks for one proxied item.
pub fn passive(e: &crate::proxy::Entry) -> Vec<crate::scanner::Issue> {
    enabled(|g| *g == Given::Response)
        .iter()
        .filter(|b| {
            b.holds(&Responses {
                latest: &e.resp,
                base: None,
            })
        })
        .map(|b| b.issue(e.origin(), e.path().to_string(), e.id))
        .collect()
}

pub const TEMPLATE: &str = "metadata:
    name: \"Exposed git repository\"
    description: \"The web root serves the .git directory, which leaks source code and history.\"

given host then
    send request called check:
        method: \"GET\"
        path: \"/.git/HEAD\"
    if \"ref: refs/\" in {check.response.body} then
        report issue:
            severity: medium
            confidence: firm
            detail: \"/.git/HEAD is readable.\"
            remediation: \"Remove the .git directory from the deployed site or deny access to it.\"
    end if
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_evaluate() {
        let b = parse(TEMPLATE).unwrap();
        assert_eq!(
            (
                b.given.clone(),
                b.action.clone(),
                b.severity,
                b.confidence.as_str()
            ),
            (
                Given::Host,
                Action::Request {
                    method: "GET".into(),
                    path: "/.git/HEAD".into()
                },
                Severity::Medium,
                "Firm"
            )
        );
        let hit = b"HTTP/1.1 200 OK\r\n\r\nref: refs/heads/main";
        assert!(b.holds(&Responses {
            latest: hit,
            base: None
        }));
        assert!(!b.holds(&Responses {
            latest: b"HTTP/1.1 404 Not Found\r\n\r\nnope",
            base: None
        }));

        let p = parse(
            "metadata:\n name: \"Debug error\"\ngiven query insertion point then\n send payload:\n  appending: \"'\\\"\"\n if {latest.response} matches \"(?i)stack trace\" and not {base.response.body} matches \"(?i)stack trace\" or {latest.response.status_code} is \"500\" then\n  report issue:\n   severity: high\n   confidence: tentative\n end if",
        )
        .unwrap();
        assert_eq!(
            (p.given.clone(), p.action.clone()),
            (
                Given::Point(Some("query".into())),
                Action::Append("'\"".into())
            )
        );
        let base = b"HTTP/1.1 200 OK\r\n\r\nok";
        assert!(p.holds(&Responses {
            latest: b"HTTP/1.1 200 OK\r\n\r\nStack trace: at x",
            base: Some(base)
        }));
        assert!(!p.holds(&Responses {
            latest: b"HTTP/1.1 200 OK\r\n\r\nStack trace",
            base: Some(b"HTTP/1.1 200 OK\r\n\r\nstack trace")
        }));
        assert!(p.holds(&Responses {
            latest: b"HTTP/1.1 500 Oops\r\n\r\n",
            base: Some(base)
        }));
        assert_eq!(
            p.issue("https://a".into(), "/".into(), 1).detail,
            "Reported by BCheck \"Debug error\"."
        );

        for (bad, why) in [
            (
                "given response then\n if \"x\" in {latest.response} then",
                "missing `name`",
            ),
            (
                "metadata:\n name: \"n\"\n if \"x\" in {latest.response} then",
                "missing `given",
            ),
            (
                "metadata:\n name: \"n\"\ngiven insertion point then\n if \"x\" in {latest.response} then",
                "needs `send payload",
            ),
            (
                "metadata:\n name: \"n\"\ngiven response then\n if x in y then",
                "cannot read condition",
            ),
            (
                "metadata:\n name: \"n\"\ngiven response then\n if \"x\" in {latest.response} then\n severity: urgent",
                "unknown severity",
            ),
        ] {
            let e = parse(bad).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
    }
}
