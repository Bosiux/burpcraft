// ------------------------------------------------------------ configuration

pub const CHECKS: [&str; 12] = [
    "SQL injection",
    "Cross-site scripting (reflected)",
    "OS command injection",
    "File path traversal",
    "Server-side template injection",
    "Open redirection",
    "HTTP response header injection",
    "Out-of-band interactions (Collaborator)",
    "Time-based checks (slow)",        // index 8 (disabled by fast())
    "HTTP request smuggling (timing)", // index 9 (disabled by fast())
    // append new checks after the fast()-disabled ones so their indices stay fixed
    "Cross-site scripting (stored)",
    "XML external entity injection",
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
        checks[8] = false; // time-based checks (slow)
        checks[9] = false; // request smuggling (slow, timing-based)
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
    pub(crate) fn on(&self, name: &str) -> bool {
        CHECKS
            .iter()
            .position(|c| *c == name)
            .is_some_and(|i| self.checks[i])
    }
}
