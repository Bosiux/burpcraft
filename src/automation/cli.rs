//! `burpcraft scan`: the scanner without the GUI, for CI. Same engine and arguments as REST
//! `POST /v0.1/scan` and MCP `scan_start`; waits for the scan, writes reports, sets the exit code.
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::security::scanner::Severity;

const USAGE: &str = "usage: burpcraft scan <url>... | '<json>' [--thorough] [--sarif FILE] [--xml FILE] [--html FILE] [--fail-on high|medium|low|info|none]
  <json> takes the REST/MCP scan fields: urls, request, target, openapi, headers, login, logged_out, threads, delay_ms, scope, crawl
  exit status: 0 no issue at or above --fail-on (default high), 1 issues found, 2 usage or scan error";

/// Runs a scan to completion; returns the process exit status.
pub fn scan(args: &[String]) -> i32 {
    match run(args) {
        Ok(found) => i32::from(found),
        Err(e) => {
            eprintln!("burpcraft scan: {e}\n{USAGE}");
            2
        }
    }
}

fn run(args: &[String]) -> Result<bool, String> {
    use crate::automation::openapi::{J, parse};
    let (mut urls, mut json, mut thorough) = (vec![], None, false);
    let (mut outputs, mut fail_on) = (vec![], Some(Severity::High));
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--thorough" => thorough = true,
            "--sarif" | "--xml" | "--html" => outputs.push((a.clone(), val()?)),
            "--fail-on" => {
                fail_on = match val()?.to_ascii_lowercase().as_str() {
                    "high" => Some(Severity::High),
                    "medium" => Some(Severity::Medium),
                    "low" => Some(Severity::Low),
                    "info" => Some(Severity::Info),
                    "none" => None,
                    v => return Err(format!("unknown --fail-on {v}")),
                }
            }
            j if j.trim_start().starts_with('{') => json = Some(parse(j)?),
            u if !u.starts_with("--") => urls.push(J::Str(u.into())),
            f => return Err(format!("unknown option {f}")),
        }
    }
    let mut req = json.unwrap_or(J::Obj(vec![]));
    if let J::Obj(fields) = &mut req {
        if !urls.is_empty() {
            fields.push(("urls".into(), J::Arr(urls)));
        }
        if thorough {
            fields.push(("thorough".into(), J::Bool(true)));
        }
    }
    let (tasks, state) = (Default::default(), crate::proxy::Shared::new());
    let id = crate::mcp::start_scan(&req, &tasks, &state, &Default::default())?;
    let task = {
        let t = tasks.lock().unwrap();
        let t = &t[id - 1];
        (t.status.clone(), t.done.clone(), t.requests.clone())
    };
    let mut last = String::new();
    while !task.1.load(Ordering::SeqCst) {
        let now = task.0.lock().unwrap().clone();
        if now != last {
            eprintln!("{now}");
            last = now;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let s = state.lock().unwrap();
    for (flag, path) in outputs {
        let body = match flag.as_str() {
            "--sarif" => crate::project::report::sarif(&s.issues),
            "--xml" => crate::project::report::xml(&s.issues, &s.history),
            _ => crate::project::report::html(&s.issues, &s.history, "BurpCraft scan report"),
        };
        std::fs::write(&path, body).map_err(|e| format!("{path}: {e}"))?;
    }
    let mut issues: Vec<_> = s.issues.iter().collect();
    issues.sort_by_key(|i| i.severity);
    for i in &issues {
        println!(
            "{:<11} {:<9} {}{}  {}",
            i.severity.label(),
            i.confidence,
            i.origin,
            i.path,
            i.name
        );
    }
    eprintln!(
        "{} issue(s), {} request(s)",
        issues.len(),
        task.2.load(Ordering::SeqCst)
    );
    Ok(fail_on.is_some_and(|f| issues.iter().any(|i| i.severity <= f)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_errors() {
        let a = |v: &[&str]| scan(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(a(&[]), 2); // nothing to scan
        assert_eq!(a(&["ftp://x"]), 2);
        assert_eq!(a(&["http://127.0.0.1:9/", "--fail-on", "sometimes"]), 2);
        assert_eq!(a(&["http://127.0.0.1:9/", "--sarif"]), 2);
        assert_eq!(a(&["--bogus"]), 2);
    }
}
