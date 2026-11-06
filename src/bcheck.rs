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
//!
//! Variables: a `define:` block of `name = "value"` lines, and a `run for each:` block with one
//! `name = "a", "b", "c"` line, which runs the whole check once per value. `{name}` is replaced in
//! the rest of the file (values may use earlier ones); `{random_str(8)}` is a fresh random string.
//! Branches: `if ... then`, any number of `else if ... then`, an optional `else`, then `end if`;
//! the first branch whose condition holds reports its `report issue:` (in an if/else chain a
//! branch without one reports nothing; a plain `if` always reports).
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
    /// This branch has a `report issue:`.
    reports: bool,
    /// `else if` / `else` branches (an `else` has one empty conjunction, which always holds).
    orelse: Vec<BCheck>,
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

fn condition(c: &str) -> Result<Vec<Vec<(bool, Test)>>, String> {
    c.split(" or ")
        .map(|conj| {
            conj.split(" and ")
                .map(parse_test)
                .collect::<Result<Vec<_>, _>>()
        })
        .collect()
}

/// Comma-separated quoted values, still escaped (so they can be substituted into other literals).
fn list(v: &str) -> Option<Vec<String>> {
    let (mut out, mut rest) = (vec![], v.trim());
    loop {
        let r = rest.strip_prefix('"')?;
        let mut esc = false;
        let end = r.char_indices().find_map(|(i, c)| {
            let close = c == '"' && !esc;
            esc = c == '\\' && !esc;
            close.then_some(i)
        })?;
        out.push(r[..end].to_string());
        rest = r[end + 1..].trim_start();
        if rest.is_empty() {
            return Some(out);
        }
        rest = rest.strip_prefix(',')?.trim_start();
    }
}

fn random_str(n: usize) -> String {
    use std::hash::BuildHasher;
    // ponytail: SipHash of a fresh RandomState, fine for markers, not for secrets
    (0..n)
        .map(|_| {
            let h = std::hash::RandomState::new().hash_one(0u8);
            b"abcdefghijklmnopqrstuvwxyz0123456789"[(h % 36) as usize] as char
        })
        .collect()
}

fn subst(s: &str, vars: &[(String, String)]) -> Result<String, String> {
    let mut s = vars
        .iter()
        .fold(s.to_string(), |s, (k, v)| s.replace(&format!("{{{k}}}"), v));
    while let Some(i) = s.find("{random_str(") {
        let rest = &s[i + 12..];
        let j = rest.find(")}").ok_or("unclosed `{random_str(`")?;
        let n: usize = rest[..j]
            .trim()
            .parse()
            .map_err(|_| format!("bad length in `random_str({})`", &rest[..j]))?;
        s.replace_range(i..i + 12 + j + 2, &random_str(n.min(256)));
    }
    Ok(s)
}

/// Takes out the `define:` and `run for each:` blocks and returns the rest of the check once per
/// loop value (once without a loop), with the variables substituted.
fn expand(src: &str) -> Result<Vec<String>, String> {
    let (mut defs, mut each, mut body, mut block) = (vec![], None, String::new(), "");
    for raw in src.lines() {
        let line = raw.split(" #").next().unwrap_or("").trim();
        let low = line.to_ascii_lowercase();
        if low == "define:" || low == "run for each:" {
            block = if low == "define:" { "define" } else { "each" };
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && !block.is_empty()
            && !k.trim().is_empty()
            && k.trim()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            let k = k.trim().to_string();
            let mut vals = list(v).ok_or_else(|| format!("`{k}` needs quoted values"))?;
            match block {
                "define" if vals.len() == 1 => defs.push((k, vals.remove(0))),
                "define" => return Err(format!("`{k}` in `define:` takes one value")),
                _ if each.is_some() => return Err("`run for each:` takes one variable".into()),
                _ => each = Some((k, vals)),
            }
            continue;
        }
        if !line.is_empty() && !line.starts_with('#') {
            block = "";
        }
        body.push_str(raw);
        body.push('\n');
    }
    let runs: Vec<Vec<(String, String)>> = match each {
        Some((k, vals)) => vals.into_iter().map(|v| vec![(k.clone(), v)]).collect(),
        None => vec![vec![]],
    };
    runs.into_iter()
        .map(|mut vars| {
            for (k, raw) in &defs {
                let v = subst(raw, &vars)?;
                vars.push((k.clone(), v));
            }
            subst(&body, &vars)
        })
        .collect()
}

/// The check once per `run for each:` value.
fn instances(src: &str) -> Result<Vec<BCheck>, String> {
    expand(src)?
        .iter()
        .map(|body| {
            parse_body(body).map(|b| BCheck {
                source: src.to_string(),
                ..b
            })
        })
        .collect()
}

/// Parses a check (its first `run for each:` value; `enabled` runs every value).
pub fn parse(src: &str) -> Result<BCheck, String> {
    Ok(instances(src)?.remove(0))
}

/// The branch report fields go to: the last `else`, or the `if`.
fn branch(b: &mut BCheck) -> &mut BCheck {
    if b.orelse.is_empty() {
        b
    } else {
        b.orelse.last_mut().unwrap()
    }
}

fn parse_body(src: &str) -> Result<BCheck, String> {
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
        reports: false,
        orelse: vec![],
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
            b.cond = condition(c)?;
            continue;
        }
        // ponytail: one flat if/else chain, no nested ifs; add a statement tree if checks need them
        let alt = match low.as_str() {
            "else" | "else then" => Some(vec![vec![]]),
            _ => match line
                .strip_prefix("else if ")
                .and_then(|c| c.strip_suffix(" then"))
            {
                Some(c) => Some(condition(c)?),
                None => None,
            },
        };
        if let Some(cond) = alt {
            if b.cond.is_empty() {
                return Err("`else` without `if`".into());
            }
            b.orelse.push(BCheck {
                cond,
                severity: Severity::Info,
                confidence: "Tentative".into(),
                detail: String::new(),
                remediation: String::new(),
                reports: false,
                orelse: vec![],
                ..b.clone()
            });
            continue;
        }
        let Some((k, v)) = kv(line) else { continue };
        let q = || quoted(&v).ok_or_else(|| format!("`{k}` needs a quoted value"));
        match k.as_str() {
            "report issue" => branch(&mut b).reports = true,
            "name" => b.name = q()?,
            "description" => b.description = q()?,
            "appending" => b.action = Action::Append(q()?),
            "replacing" => b.action = Action::Replace(q()?),
            "method" => method = q()?,
            "path" => path = Some(q()?),
            "severity" => {
                branch(&mut b).severity = match v.to_ascii_lowercase().trim_matches('"') {
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    "info" | "information" => Severity::Info,
                    s => return Err(format!("unknown severity `{s}`")),
                }
            }
            "confidence" => {
                let c = v.trim_matches('"').to_ascii_lowercase();
                branch(&mut b).confidence = match c.as_str() {
                    "certain" | "firm" | "tentative" => {
                        format!("{}{}", c[..1].to_ascii_uppercase(), &c[1..])
                    }
                    _ => return Err(format!("unknown confidence `{c}`")),
                };
            }
            "detail" => branch(&mut b).detail = q()?,
            "remediation" => branch(&mut b).remediation = q()?,
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
    // checks written before `else` existed may omit `report issue:`; a plain `if` still reports
    if b.orelse.is_empty() {
        b.reports = true;
    } else if !b.reports && !b.orelse.iter().any(|o| o.reports) {
        return Err("missing `report issue:`".into());
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
    /// The first branch whose condition holds, if that branch reports an issue.
    pub fn matched(&self, r: &Responses) -> Option<&BCheck> {
        std::iter::once(self)
            .chain(&self.orelse)
            .find(|b| b.holds(r))
            .filter(|b| b.reports)
    }
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
    crate::http::net::data_dir().join("bchecks")
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

/// Enabled checks, once per `run for each:` value (re-expanded so `random_str` is fresh per run).
pub fn enabled(given: impl Fn(&Given) -> bool) -> Vec<BCheck> {
    let src: Vec<String> = checks()
        .lock()
        .unwrap()
        .0
        .iter()
        .filter(|b| b.enabled && given(&b.given))
        .map(|b| b.source.clone())
        .collect();
    src.iter()
        .flat_map(|s| instances(s).unwrap_or_default())
        .collect()
}

/// Passive `given response` checks for one proxied item.
pub fn passive(e: &crate::proxy::Entry) -> Vec<crate::scanner::Issue> {
    enabled(|g| *g == Given::Response)
        .iter()
        .filter_map(|b| {
            b.matched(&Responses {
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

run for each:
    file = \"HEAD\", \"config\"

define:
    git = \"/.git/{file}\"

given host then
    send request called check:
        method: \"GET\"
        path: \"{git}\"
    if \"ref: refs/\" in {check.response.body} or \"[core]\" in {check.response.body} then
        report issue:
            severity: medium
            confidence: firm
            detail: \"{git} is readable.\"
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

    fn resp(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\n\r\n{body}").into_bytes()
    }

    #[test]
    fn loop_reports_per_value() {
        let all = instances(TEMPLATE).unwrap();
        let paths: Vec<_> = all.iter().map(|b| b.action.clone()).collect();
        assert_eq!(
            paths,
            ["/.git/HEAD", "/.git/config"].map(|p| Action::Request {
                method: "GET".into(),
                path: p.into()
            })
        );
        let hit = resp("[core]\nbare = false");
        let details: Vec<_> = all
            .iter()
            .filter_map(|b| {
                b.matched(&Responses {
                    latest: &hit,
                    base: None,
                })
            })
            .map(|b| b.issue("https://a".into(), "/".into(), 0).detail)
            .collect();
        assert_eq!(
            details,
            ["/.git/HEAD is readable.", "/.git/config is readable."]
        );
    }

    #[test]
    fn define_and_interpolation() {
        let src = "metadata:\n name: \"Marker\"\ndefine:\n tag = \"bc\\\"x\"\n mark = \"<{tag}{random_str(6)}>\"\ngiven body insertion point then\n send payload:\n  replacing: \"{mark}\"\n if \"{mark}\" in {latest.response.body} then\n  report issue:\n   detail: \"echoed {mark}\"\n end if";
        let b = parse(src).unwrap();
        let Action::Replace(p) = &b.action else {
            panic!("{:?}", b.action)
        };
        assert!(
            p.starts_with("<bc\"x") && p.ends_with('>') && p.len() == 12,
            "{p}"
        );
        assert_eq!(
            b.issue(String::new(), String::new(), 0).detail,
            format!("echoed {p}")
        );
        assert!(
            b.matched(&Responses {
                latest: &resp(&format!("..{p}..")),
                base: None
            })
            .is_some()
        );
        // random_str is fresh per expansion
        let Action::Replace(q) = parse(src).unwrap().action else {
            unreachable!()
        };
        assert_ne!(*p, q);
        for (bad, why) in [
            ("define:\n a = x", "needs quoted values"),
            ("define:\n a = \"1\", \"2\"", "takes one value"),
            ("run for each:\n a = \"1\"\n b = \"2\"", "one variable"),
            ("define:\n a = \"{random_str(z)}\"", "bad length"),
        ] {
            let e = parse(bad).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
    }

    #[test]
    fn else_branches() {
        let b = parse("metadata:\n name: \"Status\"\ngiven response then\n if {latest.response.status_code} is \"500\" then\n  report issue:\n   severity: high\n else if \"debug\" in {latest.response.body} then\n  report issue:\n   severity: low\n   detail: \"debug\"\n else if {latest.response.status_code} is \"404\" then\n  # nothing to report\n else\n  report issue:\n   detail: \"other\"\n end if").unwrap();
        let sev = |raw: &[u8]| {
            b.matched(&Responses {
                latest: raw,
                base: None,
            })
            .map(|m| (m.severity, m.issue(String::new(), String::new(), 0).detail))
        };
        assert_eq!(
            sev(b"HTTP/1.1 500 X\r\n\r\ndebug").unwrap().0,
            Severity::High
        );
        assert_eq!(sev(&resp("debug")), Some((Severity::Low, "debug".into())));
        assert_eq!(sev(b"HTTP/1.1 404 X\r\n\r\ndebu"), None);
        assert_eq!(sev(&resp("ok")), Some((Severity::Info, "other".into())));
        assert_eq!(b.issue(String::new(), String::new(), 0).name, "Status");
        for (bad, why) in [
            (
                "metadata:\n name: \"n\"\ngiven response then\n else\n  report issue:",
                "`else` without `if`",
            ),
            (
                "metadata:\n name: \"n\"\ngiven response then\n if \"x\" in {latest.response} then\n else\n end if",
                "missing `report issue:`",
            ),
        ] {
            let e = parse(bad).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
        // a plain `if` without `report issue:` (pre-`else` checks) still reports
        let old = parse("metadata:\n name: \"n\"\ngiven response then\n if \"x\" in {latest.response} then\n  detail: \"d\"\n end if").unwrap();
        assert!(
            old.matched(&Responses {
                latest: &resp("x"),
                base: None
            })
            .is_some()
        );
    }
}
