//! Intercepting proxy: listener, HTTPS MITM, intercept queue and HTTP history.
mod entry;
mod listener;
mod message;
mod rules;
mod state;
mod ws;

pub use entry::*;
pub use listener::*;
pub use message::*;
pub use rules::*;
pub use state::*;
pub use ws::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack() {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"hello").unwrap();
        let z = gz.finish().unwrap();
        let mut m = format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n", z.len()).into_bytes();
        m.extend_from_slice(&z);
        m.extend_from_slice(b"\r\n0\r\n\r\n");
        assert!(display(&m).ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn tool_traffic_is_passively_scanned() {
        let state = Shared::new();
        let resp = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\nhi";
        let mut s = state.lock().unwrap();
        for _ in 0..2 {
            s.log_tool(
                "Repeater",
                "a.test",
                80,
                false,
                b"GET /x HTTP/1.1\r\n\r\n",
                resp,
            );
        }
        let i = s
            .issues
            .iter()
            .find(|i| i.name == "Server software version exposed")
            .expect("passive issue from Repeater traffic");
        assert_eq!(
            (i.origin.as_str(), i.path.as_str()),
            ("http://a.test", "/x")
        );
        // reported once, with the Repeater exchange kept as evidence
        let ev: Vec<_> = s.history.iter().filter(|e| e.id == i.entry_id).collect();
        assert!(ev.len() == 1 && ev[0].tool == "Repeater" && ev[0].resp == resp);
        assert_eq!(s.history.len(), 1);
    }

    #[test]
    fn websocket_frames() {
        // masked "Hi" from client, then unmasked "ok" from server, then a partial frame
        let mut b = vec![
            0x81,
            0x82,
            1,
            2,
            3,
            4,
            b'H' ^ 1,
            b'i' ^ 2,
            0x81,
            0x02,
            b'o',
            b'k',
            0x81,
        ];
        let f = ws_frames(&mut b);
        assert_eq!(f, vec![(1, b"Hi".to_vec()), (1, b"ok".to_vec())]);
        assert_eq!(b, vec![0x81]);
    }

    #[test]
    fn intercept_rules() {
        let ext = "^(png|css)$";
        assert!(should_intercept(ext, "", "a.com", "/login?x=1"));
        assert!(!should_intercept(ext, "", "a.com", "/s/app.css?v=2"));
        assert!(!should_intercept(ext, "b.com", "a.com", "/"));
        assert!(should_intercept(ext, "a.com", "api.a.com", "/x.json"));
    }

    #[test]
    fn rules() {
        let mut r = default_rules();
        r[1].enabled = true;
        let out = apply_rules(
            &r,
            b"GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\n\r\n",
            true,
        );
        assert_eq!(out, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        let add = Rule {
            enabled: true,
            kind: 0,
            pattern: String::new(),
            replace: "X-Test: 1".into(),
            comment: String::new(),
        };
        let body = Rule {
            enabled: true,
            kind: 3,
            pattern: "foo".into(),
            replace: "bar".into(),
            comment: String::new(),
        };
        assert_eq!(
            apply_rules(&[add], b"GET / HTTP/1.1\r\n\r\n", true),
            b"GET / HTTP/1.1\r\nX-Test: 1\r\n\r\n"
        );
        assert_eq!(
            apply_rules(&[body], b"HTTP/1.1 200 OK\r\n\r\nfoo foo", false),
            b"HTTP/1.1 200 OK\r\n\r\nbar bar"
        );
    }

    #[test]
    fn urls() {
        assert_eq!(
            split_url("http://a.com/x?y"),
            Some((false, "a.com".into(), 80, "/x?y".into()))
        );
        assert_eq!(
            split_url("https://a.com:8443"),
            Some((true, "a.com".into(), 8443, "/".into()))
        );
        assert_eq!(split_host_port("[::1]:8080", 80), ("::1".into(), 8080));
        assert_eq!(
            split_host_port("example.com", 443),
            ("example.com".into(), 443)
        );
    }
}
