//! Timing-based detection of HTTP request smuggling (CL.TE / TE.CL), non-destructive.
//!
//! The classic PortSwigger timing probes: a request whose Content-Length and Transfer-Encoding
//! disagree makes a vulnerable front-end/back-end pair hang, waiting for a chunk or body that never
//! arrives. We never smuggle a real second request, so nothing is poisoned - we only measure the
//! hang. Raw sockets are required because the normal client rewrites the framing before sending.
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use crate::http::net;
use crate::scan::Target;

pub struct Finding {
    pub detail: String,
    pub req: String,
}

fn baseline(t: &Target) -> String {
    format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\n\r\n",
        crate::scan::host_header(t)
    )
}

/// Front-end uses Content-Length (forwards `1\r\nA`, drops `X`), back-end uses chunked and waits
/// for the next chunk that never comes.
fn clte_probe(t: &Target) -> String {
    format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX",
        crate::scan::host_header(t)
    )
}

/// Front-end uses chunked (sees the terminating `0` chunk, forwards nothing more), back-end uses
/// Content-Length and waits for the body byte that never comes.
fn tecl_probe(t: &Target) -> String {
    format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX",
        crate::scan::host_header(t)
    )
}

/// Sends `req` on a fresh connection and returns how long until the first response byte, or `None`
/// if nothing arrived within `timeout` (the connection hung).
fn send_timed(t: &Target, req: &[u8], timeout: Duration) -> io::Result<Option<Duration>> {
    let mut s = net::connect(&t.host, t.port, t.tls)?;
    s.set_timeout(Some(timeout));
    let start = Instant::now();
    s.write_all(req)?;
    s.flush()?;
    let mut buf = [0u8; 1];
    match s.read(&mut buf) {
        Ok(_) => Ok(Some(start.elapsed())),
        Err(ref e)
            if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Probes one HTTP/1.1 origin for CL.TE and TE.CL smuggling. Returns a finding only when a probe
/// hangs twice while a normal request keeps answering quickly, to avoid flagging merely slow hosts.
/// `hang` is the per-request timeout (how long a hang must last to count); keep it generous in
/// production and small in tests.
pub fn detect(t: &Target, hang: Duration) -> Option<Finding> {
    // Needs a responsive HTTP/1.1 baseline; skip HTTP/2-only or slow/unreachable hosts.
    let base = match send_timed(t, baseline(t).as_bytes(), hang) {
        Ok(Some(d)) if d < hang / 2 => d,
        _ => return None,
    };
    let hung = |p: &str| matches!(send_timed(t, p.as_bytes(), hang), Ok(None));
    let responds = || matches!(send_timed(t, baseline(t).as_bytes(), hang), Ok(Some(_)));
    for (variant, probe) in [("CL.TE", clte_probe(t)), ("TE.CL", tecl_probe(t))] {
        if hung(&probe) && responds() && hung(&probe) {
            return Some(Finding {
                detail: format!(
                    "A {variant} request smuggling probe got no response within {}s (confirmed twice), while a normal request answered in {}ms. The front-end and back-end disagree on where the request ends (Content-Length vs Transfer-Encoding).",
                    hang.as_secs().max(1),
                    base.as_millis()
                ),
                req: probe,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::thread;

    /// A server that answers normal requests at once but, if `vulnerable`, hangs whenever a request
    /// carries both Content-Length and Transfer-Encoding - mimicking a back-end left waiting.
    fn mock_server(vulnerable: bool) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            for c in l.incoming().flatten() {
                thread::spawn(move || {
                    let mut c = c;
                    let mut r = BufReader::new(c.try_clone().unwrap());
                    let (mut te, mut cl, mut line) = (false, 0usize, String::new());
                    while r.read_line(&mut line).is_ok_and(|n| n > 0) {
                        if line == "\r\n" || line == "\n" {
                            break;
                        }
                        let low = line.to_ascii_lowercase();
                        if low.starts_with("transfer-encoding:") && low.contains("chunked") {
                            te = true;
                        }
                        if let Some(v) = low.strip_prefix("content-length:") {
                            cl = v.trim().parse().unwrap_or(0);
                        }
                        line.clear();
                    }
                    if vulnerable && te && cl > 0 {
                        thread::sleep(Duration::from_secs(30)); // client times out long before this
                        return;
                    }
                    let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                });
            }
        });
        port
    }

    fn target(port: u16) -> Target {
        Target {
            host: "127.0.0.1".into(),
            port,
            tls: false,
        }
    }

    #[test]
    fn probes_are_well_formed() {
        let t = target(1);
        let p = clte_probe(&t);
        assert!(p.contains("Content-Length: 4") && p.contains("Transfer-Encoding: chunked"));
        assert!(p.ends_with("\r\n\r\n1\r\nA\r\nX"));
        let p = tecl_probe(&t);
        assert!(p.contains("Content-Length: 6") && p.ends_with("\r\n\r\n0\r\n\r\nX"));
    }

    #[test]
    fn flags_vulnerable_and_clears_safe() {
        let hang = Duration::from_millis(400);
        let vuln = detect(&target(mock_server(true)), hang);
        assert!(vuln.is_some(), "vulnerable server not flagged");
        assert!(vuln.unwrap().detail.contains("CL.TE"));
        assert!(
            detect(&target(mock_server(false)), hang).is_none(),
            "responsive server flagged"
        );
    }

    #[test]
    fn skips_unresponsive_host() {
        // nothing listening -> connection refused -> no baseline -> no finding
        assert!(detect(&target(1), Duration::from_millis(200)).is_none());
    }
}
