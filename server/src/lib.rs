//! Self-hosted Collaborator server for BurpCraft (std only).
//!
//! Captures out-of-band interactions over DNS (UDP), HTTP and SMTP. Every payload carries an id:
//! `<client id (12 chars)><counter>` either as the first DNS label (`abc...123.oast.example`)
//! or, when no domain/DNS is available (local testing), as the first HTTP path segment
//! (`http://server:port/abc...123`). Clients fetch their interactions with
//! `GET /burpcraft/poll?biid=<client id>[&secret=...]` on the HTTP port.
//!
//! Poll response: one interaction per line, tab-separated:
//! `time_ms  protocol  client_ip  payload_id  base64(raw)`.
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Length of the client id prefix of a payload id.
pub const BIID_LEN: usize = 12;
const MAX_PER_CLIENT: usize = 1000;

#[derive(Clone, Debug)]
pub struct Config {
    /// Payload domain, e.g. `oast.example.com` (empty: path-based payloads only).
    pub domain: String,
    /// Address A queries for the domain resolve to (the server's public IP).
    pub public_ip: Ipv4Addr,
    pub bind: IpAddr,
    pub dns_port: Option<u16>,
    pub http_port: u16,
    pub smtp_port: Option<u16>,
    /// Required on poll requests when non-empty.
    pub secret: String,
    /// BApp Store directory: `catalog.tsv` (name, version, description, file per line) plus the files.
    pub bapps: Option<std::path::PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            domain: String::new(),
            public_ip: Ipv4Addr::LOCALHOST,
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dns_port: None,
            http_port: 0,
            smtp_port: None,
            secret: String::new(),
            bapps: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Interaction {
    pub time_ms: u128,
    pub protocol: String,
    pub client_ip: String,
    pub id: String,
    pub raw: Vec<u8>,
}

/// Interactions waiting to be polled, by client id.
#[derive(Default)]
pub struct Store(Mutex<HashMap<String, Vec<Interaction>>>);

impl Store {
    fn record(&self, protocol: &str, client: SocketAddr, id: &str, raw: &[u8]) {
        if id.len() <= BIID_LEN || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return;
        }
        let it = Interaction {
            time_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            protocol: protocol.into(),
            client_ip: client.ip().to_string(),
            id: id.to_ascii_lowercase(),
            raw: raw[..raw.len().min(64 * 1024)].to_vec(),
        };
        let mut m = self.0.lock().unwrap();
        let list = m.entry(it.id[..BIID_LEN].to_string()).or_default();
        if list.len() < MAX_PER_CLIENT {
            list.push(it);
        }
    }
    /// Removes and returns a client's interactions.
    pub fn take(&self, biid: &str) -> Vec<Interaction> {
        self.0
            .lock()
            .unwrap()
            .remove(&biid.to_ascii_lowercase())
            .unwrap_or_default()
    }
}

/// Running server: actual bound ports (useful with port 0) and the shared store.
pub struct Running {
    pub http_port: u16,
    pub dns_port: Option<u16>,
    pub smtp_port: Option<u16>,
    pub store: Arc<Store>,
}

pub fn start(cfg: Config) -> std::io::Result<Running> {
    let store = Arc::new(Store::default());
    let cfg = Arc::new(cfg);
    let http = TcpListener::bind((cfg.bind, cfg.http_port))?;
    let http_port = http.local_addr()?.port();
    let dns_port = match cfg.dns_port {
        Some(p) => {
            let sock = UdpSocket::bind((cfg.bind, p))?;
            let port = sock.local_addr()?.port();
            let (cfg, store) = (cfg.clone(), store.clone());
            std::thread::spawn(move || dns_loop(sock, &cfg, &store));
            Some(port)
        }
        None => None,
    };
    let smtp_port = match cfg.smtp_port {
        Some(p) => {
            let l = TcpListener::bind((cfg.bind, p))?;
            let port = l.local_addr()?.port();
            let (cfg, store) = (cfg.clone(), store.clone());
            std::thread::spawn(move || {
                for c in l.incoming().flatten() {
                    let (cfg, store) = (cfg.clone(), store.clone());
                    std::thread::spawn(move || smtp_conn(c, &cfg, &store));
                }
            });
            Some(port)
        }
        None => None,
    };
    {
        let (cfg, store) = (cfg.clone(), store.clone());
        std::thread::spawn(move || {
            for c in http.incoming().flatten() {
                let (cfg, store) = (cfg.clone(), store.clone());
                std::thread::spawn(move || http_conn(c, &cfg, &store));
            }
        });
    }
    Ok(Running {
        http_port,
        dns_port,
        smtp_port,
        store,
    })
}

/// Payload id found in a host name under `domain` (its first label), if any.
pub fn id_from_host(host: &str, domain: &str) -> Option<String> {
    let host = host
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        return None;
    }
    let sub = host.strip_suffix(&domain)?.strip_suffix('.')?;
    // payload may be nested (`x.<id>.domain`): the label right above the domain is the id
    sub.rsplit('.').next().map(String::from)
}

// ------------------------------------------------------------ DNS

/// Parses the question of a DNS query: (qname, qtype, end offset of the question).
pub fn dns_question(q: &[u8]) -> Option<(String, u16, usize)> {
    if q.len() < 12 || u16::from_be_bytes([q[4], q[5]]) == 0 {
        return None;
    }
    let mut i = 12;
    let mut labels = vec![];
    loop {
        let len = *q.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None; // compression pointers never appear in a question we answer
        }
        labels.push(String::from_utf8_lossy(q.get(i..i + len)?).into_owned());
        i += len;
    }
    let qtype = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    Some((labels.join("."), qtype, i + 4))
}

/// Authoritative answer: an A record with `ip` for names under the domain (type A or ANY), empty otherwise.
pub fn dns_answer(q: &[u8], domain: &str, ip: Ipv4Addr) -> Option<Vec<u8>> {
    let (name, qtype, end) = dns_question(q)?;
    let ours = name.eq_ignore_ascii_case(domain) || id_from_host(&name, domain).is_some();
    let answer = ours && (qtype == 1 || qtype == 255);
    let mut r = q[..end].to_vec();
    r[2] = 0x84 | (q[2] & 0x01); // response, authoritative, keep RD
    r[3] = if ours { 0x00 } else { 0x05 }; // NOERROR / REFUSED
    r[6..12].copy_from_slice(&[0, answer as u8, 0, 0, 0, 0]);
    if answer {
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]); // name ptr, A, IN, TTL 60, len 4
        r.extend_from_slice(&ip.octets());
    }
    Some(r)
}

fn dns_loop(sock: UdpSocket, cfg: &Config, store: &Store) {
    let mut buf = [0u8; 1500];
    while let Ok((n, from)) = sock.recv_from(&mut buf) {
        let q = &buf[..n];
        if let Some((name, ..)) = dns_question(q)
            && let Some(id) = id_from_host(&name, &cfg.domain)
        {
            store.record("DNS", from, &id, q);
        }
        if let Some(r) = dns_answer(q, &cfg.domain, cfg.public_ip) {
            let _ = sock.send_to(&r, from);
        }
    }
}

// ------------------------------------------------------------ HTTP

fn query_param<'a>(target: &'a str, key: &str) -> Option<&'a str> {
    target
        .split_once('?')?
        .1
        .split('&')
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
}

fn http_conn(mut c: TcpStream, cfg: &Config, store: &Store) {
    let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
    let peer = c.peer_addr().unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut raw = vec![];
    let mut r = BufReader::new(&mut c);
    let mut line = String::new();
    let mut len = 0usize;
    while r.read_line(&mut line).is_ok_and(|n| n > 0) && raw.len() < 64 * 1024 {
        raw.extend_from_slice(line.as_bytes());
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }
    let mut body = vec![0u8; len.min(64 * 1024)];
    let _ = r.read_exact(&mut body);
    raw.extend_from_slice(&body);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let target = text.split_whitespace().nth(1).unwrap_or("/").to_string();
    let host = text
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.trim().to_string())
        })
        .unwrap_or_default();

    if target.starts_with("/burpcraft/poll") {
        let ok =
            cfg.secret.is_empty() || query_param(&target, "secret") == Some(cfg.secret.as_str());
        let body = if ok {
            let biid = query_param(&target, "biid").unwrap_or("");
            store
                .take(biid)
                .iter()
                .map(|i| {
                    format!(
                        "{}\t{}\t{}\t{}\t{}\n",
                        i.time_ms,
                        i.protocol,
                        i.client_ip,
                        i.id,
                        b64(&i.raw)
                    )
                })
                .collect::<String>()
        } else {
            String::new()
        };
        let status = if ok { "200 OK" } else { "403 Forbidden" };
        let _ = write!(
            c,
            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        return;
    }
    if let Some(rest) = target.strip_prefix("/burpcraft/bapps") {
        let (status, body) = bapp(cfg, rest);
        let _ = write!(
            c,
            "HTTP/1.1 {status}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = c.write_all(&body);
        return;
    }
    let path_id = target
        .trim_start_matches('/')
        .split(['/', '?', '.'])
        .next()
        .unwrap_or("")
        .to_string();
    let id = id_from_host(&host, &cfg.domain).unwrap_or(path_id);
    store.record("HTTP", peer, &id, &raw);
    // like the original, the body contains a token so reflected responses can be recognised
    let body = format!(
        "<html><body>{}</body></html>",
        id.chars().rev().collect::<String>()
    );
    let _ = write!(
        c,
        "HTTP/1.1 200 OK\r\nServer: BurpCraft Collaborator\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// BApp Store: `/burpcraft/bapps` is the catalogue, `/burpcraft/bapps/<file>` a listed file.
fn bapp(cfg: &Config, rest: &str) -> (&'static str, Vec<u8>) {
    let Some(dir) = &cfg.bapps else {
        return ("404 Not Found", b"no BApp Store on this server".to_vec());
    };
    let catalog = std::fs::read_to_string(dir.join("catalog.tsv")).unwrap_or_default();
    match rest.trim_start_matches('/') {
        "" => ("200 OK", catalog.into_bytes()),
        // only files the catalogue lists, so no path tricks reach the filesystem
        file if catalog.lines().any(|l| l.split('\t').nth(3) == Some(file)) => {
            match std::fs::read(dir.join(file)) {
                Ok(b) => ("200 OK", b),
                Err(_) => ("404 Not Found", vec![]),
            }
        }
        _ => ("404 Not Found", vec![]),
    }
}

// ------------------------------------------------------------ SMTP

fn smtp_conn(mut c: TcpStream, cfg: &Config, store: &Store) {
    let _ = c.set_read_timeout(Some(Duration::from_secs(30)));
    let peer = c.peer_addr().unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
    let _ = c.write_all(b"220 BurpCraft Collaborator ESMTP\r\n");
    let Ok(rc) = c.try_clone() else { return };
    let mut r = BufReader::new(rc);
    let (mut session, mut line, mut data) = (Vec::new(), String::new(), false);
    while r.read_line(&mut line).is_ok_and(|n| n > 0) && session.len() < 64 * 1024 {
        session.extend_from_slice(line.as_bytes());
        let cmd = line.trim_end().to_ascii_uppercase();
        let reply: &[u8] = if data {
            if line.trim_end() == "." {
                data = false;
                b"250 OK\r\n"
            } else {
                b""
            }
        } else if cmd.starts_with("DATA") {
            data = true;
            b"354 End data with <CR><LF>.<CR><LF>\r\n"
        } else if cmd.starts_with("QUIT") {
            let _ = c.write_all(b"221 Bye\r\n");
            break;
        } else if cmd.starts_with("EHLO")
            || cmd.starts_with("HELO")
            || cmd.starts_with("MAIL")
            || cmd.starts_with("RCPT")
            || cmd.starts_with("RSET")
            || cmd.starts_with("NOOP")
        {
            b"250 OK\r\n"
        } else {
            b"502 Command not implemented\r\n"
        };
        let _ = c.write_all(reply);
        line.clear();
    }
    // every address under the domain in the session counts (RCPT TO:<x@id.domain>)
    let text = String::from_utf8_lossy(&session).into_owned();
    let mut seen = vec![];
    for host in text
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '-'))
        .filter(|w| w.contains('.'))
    {
        if let Some(id) = id_from_host(host, &cfg.domain)
            && !seen.contains(&id)
        {
            store.record("SMTP", peer, &id, &session);
            seen.push(id);
        }
    }
}

// ------------------------------------------------------------ poll format

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() {
                T[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn unb64(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let (mut out, mut acc, mut bits) = (vec![], 0u32, 0);
    for v in s.bytes().filter_map(val) {
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// Parses a poll response body.
pub fn parse_poll(body: &str) -> Vec<Interaction> {
    body.lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            Some(Interaction {
                time_ms: f.next()?.parse().ok()?,
                protocol: f.next()?.into(),
                client_ip: f.next()?.into(),
                id: f.next()?.into(),
                raw: unb64(f.next()?),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, (qtype >> 8) as u8, qtype as u8, 0, 1]);
        q
    }

    fn get(port: u16, req: &str) -> String {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.write_all(req.as_bytes()).unwrap();
        let mut s = String::new();
        c.read_to_string(&mut s).unwrap();
        s
    }

    #[test]
    fn parsing() {
        assert_eq!(
            id_from_host("abcdefghijkl0001.oast.test:80", "oast.test").as_deref(),
            Some("abcdefghijkl0001")
        );
        assert_eq!(
            id_from_host("x.abcdefghijkl0001.OAST.test.", "oast.test").as_deref(),
            Some("abcdefghijkl0001")
        );
        assert_eq!(id_from_host("evil-oast.test", "oast.test"), None);
        assert_eq!(id_from_host("a.b", ""), None);
        let q = query("abcdefghijkl0001.oast.test", 1);
        assert_eq!(
            dns_question(&q),
            Some(("abcdefghijkl0001.oast.test".into(), 1, q.len()))
        );
        let a = dns_answer(&q, "oast.test", Ipv4Addr::new(10, 1, 2, 3)).unwrap();
        assert_eq!(
            (&a[..4], a[7], &a[a.len() - 4..]),
            (&[0x12, 0x34, 0x85, 0x00][..], 1, &[10, 1, 2, 3][..])
        );
        let other = dns_answer(&query("example.com", 1), "oast.test", Ipv4Addr::LOCALHOST).unwrap();
        assert_eq!((other[3], other[7]), (0x05, 0));
        assert!(dns_question(&[0; 5]).is_none());
        let raw = b"\x00\xffbinary\r\n".to_vec();
        assert_eq!(unb64(&b64(&raw)), raw);
        assert_eq!(b64(b"Ma"), "TWE=");
    }

    #[test]
    fn captures_dns_http_smtp_and_polls() {
        let cfg = Config {
            domain: "oast.test".into(),
            dns_port: Some(0),
            smtp_port: Some(0),
            secret: "s3".into(),
            ..Default::default()
        };
        let srv = start(cfg).unwrap();
        let biid = "abcdefghijkl";
        // HTTP by Host header and by path (no DNS needed)
        get(
            srv.http_port,
            &format!("GET / HTTP/1.1\r\nHost: {biid}0001.oast.test\r\n\r\n"),
        );
        let resp = get(
            srv.http_port,
            &format!(
                "POST /{biid}0002/x HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\nbody"
            ),
        );
        assert!(resp.starts_with("HTTP/1.1 200") && resp.contains(&"2000lkjihgfedcba".to_string()));
        // DNS
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sock.send_to(
            &query(&format!("{biid}0003.oast.test"), 1),
            ("127.0.0.1", srv.dns_port.unwrap()),
        )
        .unwrap();
        let mut buf = [0u8; 512];
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[n - 4..n], &[127, 0, 0, 1]);
        // SMTP
        let mut m = TcpStream::connect(("127.0.0.1", srv.smtp_port.unwrap())).unwrap();
        m.write_all(format!("EHLO x\r\nMAIL FROM:<a@b.c>\r\nRCPT TO:<u@{biid}0004.oast.test>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n").as_bytes()).unwrap();
        let mut s = String::new();
        m.read_to_string(&mut s).unwrap();
        assert!(s.contains("354") && s.ends_with("221 Bye\r\n"));

        // wrong secret: nothing, and nothing consumed
        assert!(
            get(
                srv.http_port,
                &format!("GET /burpcraft/poll?biid={biid}&secret=no HTTP/1.1\r\n\r\n")
            )
            .starts_with("HTTP/1.1 403")
        );
        let body = get(
            srv.http_port,
            &format!("GET /burpcraft/poll?biid={biid}&secret=s3 HTTP/1.1\r\n\r\n"),
        );
        let mut got = parse_poll(body.split("\r\n\r\n").nth(1).unwrap());
        got.sort_by(|a, b| a.id.cmp(&b.id));
        let summary: Vec<(String, String)> = got
            .iter()
            .map(|i| (i.protocol.clone(), i.id.clone()))
            .collect();
        assert_eq!(
            summary,
            [
                ("HTTP", "0001"),
                ("HTTP", "0002"),
                ("DNS", "0003"),
                ("SMTP", "0004")
            ]
            .map(|(p, n)| (p.to_string(), format!("{biid}{n}")))
        );
        assert!(String::from_utf8_lossy(&got[1].raw).ends_with("body"));
        // no BApp Store configured
        assert!(
            get(srv.http_port, "GET /burpcraft/bapps HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 404")
        );
        // polling consumes
        assert_eq!(
            parse_poll(
                get(
                    srv.http_port,
                    &format!("GET /burpcraft/poll?biid={biid}&secret=s3 HTTP/1.1\r\n\r\n")
                )
                .split("\r\n\r\n")
                .nth(1)
                .unwrap()
            ),
            vec![]
        );
    }

    #[test]
    fn bapp_store() {
        let dir = std::env::temp_dir().join(format!("bcs-bapps-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("catalog.tsv"),
            "Tagger\t1.0\tTags requests\ttagger.py\n",
        )
        .unwrap();
        std::fs::write(dir.join("tagger.py"), "print('hi')").unwrap();
        std::fs::write(dir.join("secret.txt"), "nope").unwrap();
        let srv = start(Config {
            bapps: Some(dir.clone()),
            ..Default::default()
        })
        .unwrap();
        assert!(
            get(srv.http_port, "GET /burpcraft/bapps HTTP/1.1\r\n\r\n")
                .ends_with("Tagger\t1.0\tTags requests\ttagger.py\n")
        );
        assert!(
            get(
                srv.http_port,
                "GET /burpcraft/bapps/tagger.py HTTP/1.1\r\n\r\n"
            )
            .ends_with("print('hi')")
        );
        for bad in ["secret.txt", "../catalog.tsv", "%2e%2e/etc/passwd"] {
            assert!(
                get(
                    srv.http_port,
                    &format!("GET /burpcraft/bapps/{bad} HTTP/1.1\r\n\r\n")
                )
                .starts_with("HTTP/1.1 404"),
                "{bad}"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
