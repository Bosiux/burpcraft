//! Automation surfaces: REST control API and OpenAPI import.
pub mod openapi;
pub mod rest;

/// Local control servers (REST, MCP) only answer requests that are not from a web page on another site:
/// `Host` must name the loopback (DNS rebinding) and `Origin`, when a browser sends one, too (CSRF).
/// An empty `Host` is accepted: browsers always send one, raw local clients may not.
pub fn is_local(host: &str, origin: &str) -> bool {
    let loopback = |h: &str| {
        let h = h
            .rsplit_once(':')
            .filter(|(_, p)| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            .map_or(h, |(h, _)| h);
        ["127.0.0.1", "localhost", "[::1]"].contains(&h.to_ascii_lowercase().as_str())
    };
    let origin_ok = origin.is_empty()
        || ["http://", "https://"]
            .iter()
            .any(|s| origin.strip_prefix(s).is_some_and(loopback));
    (host.is_empty() || loopback(host)) && origin_ok
}

#[cfg(test)]
mod tests {
    #[test]
    fn is_local() {
        use super::is_local;
        for (host, origin) in [
            ("127.0.0.1:1337", ""),
            ("localhost:1338", "http://localhost:3000"),
            ("[::1]:1337", "https://127.0.0.1"),
            ("LOCALHOST", "http://[::1]:8080"),
            ("", ""),
        ] {
            assert!(is_local(host, origin), "{host} {origin}");
        }
        for (host, origin) in [
            ("evil.test:1337", ""), // DNS rebinding
            ("127.0.0.1:1337", "https://evil.test"),
            ("127.0.0.1", "http://localhost.evil.test"),
            ("127.0.0.1", "null"), // sandboxed iframe / file://
            ("127.0.0.1.evil.test", ""),
            ("localhost:", ""),
        ] {
            assert!(!is_local(host, origin), "{host} {origin}");
        }
    }
}
