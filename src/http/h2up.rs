//! HTTP/2 towards servers. The UI keeps editing HTTP/1-style text ("GET / HTTP/2" + headers);
//! this module turns it into h2 frames and serialises the answer back as "HTTP/2 200 OK" text.
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;

use crate::proxy;

/// Headers that are connection-specific in HTTP/1 and forbidden in HTTP/2.
const HOP: [&str; 7] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "host",
];

pub struct Parsed {
    pub method: String,
    pub path: String,
    pub authority: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn parse(req: &[u8]) -> Option<Parsed> {
    let head = String::from_utf8_lossy(proxy::head(req)).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let (method, path) = (first.next()?.to_string(), first.next()?.to_string());
    let mut headers = vec![];
    let mut authority = None;
    let mut chunked = false;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
        match k.as_str() {
            "host" => authority = Some(v),
            "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
            _ if HOP.contains(&k.as_str()) => {}
            _ => headers.push((k, v)),
        }
    }
    let raw = proxy::body(req).unwrap_or_default();
    let body = if chunked {
        proxy::dechunk(raw)
    } else {
        raw.to_vec()
    };
    Some(Parsed {
        method,
        path,
        authority,
        headers,
        body,
    })
}

/// HTTP/1.1 request as the original displays it once upgraded: `HTTP/2` version, lowercase headers.
pub fn to_h2_text(req: &[u8]) -> Option<Vec<u8>> {
    let p = parse(req)?;
    let mut s = format!("{} {} HTTP/2\r\n", p.method, p.path);
    if let Some(a) = &p.authority {
        s += &format!("Host: {a}\r\n");
    }
    for (k, v) in &p.headers {
        if k != "content-length" || !p.body.is_empty() {
            s += &format!("{k}: {v}\r\n");
        }
    }
    let mut out = (s + "\r\n").into_bytes();
    out.extend_from_slice(&p.body);
    Some(out)
}

/// "HTTP/2 200 OK" response text → HTTP/1.1 bytes a browser on the HTTP/1 side understands.
pub fn to_h1_response(resp: &[u8], head_request: bool) -> Vec<u8> {
    let head = String::from_utf8_lossy(proxy::head(resp)).into_owned();
    let body = proxy::body(resp).unwrap_or_default();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("").replacen("HTTP/2", "HTTP/1.1", 1);
    let mut out = status + "\r\n";
    for l in lines {
        let k = l
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if k == "transfer-encoding" || (k == "content-length" && !head_request) {
            continue;
        }
        out += l;
        out += "\r\n";
    }
    if !head_request {
        out += &format!("content-length: {}\r\n", body.len());
    }
    let mut v = (out + "\r\n").into_bytes();
    v.extend_from_slice(body);
    v
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn not_h2() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "server did not negotiate HTTP/2",
    )
}

/// Remembers which origins refused h2 so the proxy does not retry the ALPN handshake every time.
fn no_h2() -> &'static Mutex<HashMap<String, ()>> {
    static M: OnceLock<Mutex<HashMap<String, ()>>> = OnceLock::new();
    M.get_or_init(Default::default)
}

pub fn known_unsupported(host: &str, port: u16) -> bool {
    no_h2()
        .lock()
        .unwrap()
        .contains_key(&format!("{host}:{port}"))
}

/// Sends `req` (HTTP/1-style text) over HTTP/2 and returns the response as "HTTP/2 …" text.
/// Fails with `ErrorKind::Unsupported` when the server does not pick h2 via ALPN.
pub fn send(host: &str, port: u16, req: &[u8]) -> io::Result<Vec<u8>> {
    let p = parse(req).ok_or_else(|| io_err("malformed request"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let res = rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), exchange(host, port, p)).await
    });
    match res {
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "HTTP/2 request timed out",
        )),
        Ok(Err(e)) if e.kind() == io::ErrorKind::Unsupported => {
            no_h2().lock().unwrap().insert(format!("{host}:{port}"), ());
            Err(e)
        }
        Ok(r) => r,
    }
}

async fn exchange(host: &str, port: u16, p: Parsed) -> io::Result<Vec<u8>> {
    let tcp = tokio::net::TcpStream::connect((host, port)).await?;
    tcp.set_nodelay(true).ok();
    let mut cfg = (*crate::http::net::client_config()).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(io_err)?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(not_h2());
    }
    let (client, conn) = h2::client::handshake(tls).await.map_err(io_err)?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut client = client.ready().await.map_err(io_err)?;
    let default = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let authority = p.authority.unwrap_or(default);
    let mut b = http::Request::builder()
        .method(p.method.as_str())
        .uri(format!("https://{authority}{}", p.path));
    for (k, v) in p.headers.iter().filter(|(k, _)| k != "content-length") {
        b = b.header(k.as_str(), v.as_str());
    }
    if !p.body.is_empty() {
        b = b.header("content-length", p.body.len());
    }
    let request = b.body(()).map_err(io_err)?;
    let end = p.body.is_empty();
    let (fut, mut stream) = client.send_request(request, end).map_err(io_err)?;
    if !end {
        stream
            .send_data(Bytes::from(p.body), true)
            .map_err(io_err)?;
    }
    let resp = fut.await.map_err(io_err)?;
    let (parts, mut body) = resp.into_parts();
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(io_err)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        data.extend_from_slice(&chunk);
        if data.len() > crate::http::net::max_message() {
            return Err(crate::http::net::too_large(crate::http::net::max_message()));
        }
    }
    let mut out = format!(
        "HTTP/2 {} {}\r\n",
        parts.status.as_u16(),
        parts.status.canonical_reason().unwrap_or("")
    );
    for (k, v) in &parts.headers {
        out += &format!("{}: {}\r\n", k, String::from_utf8_lossy(v.as_bytes()));
    }
    let mut out = (out + "\r\n").into_bytes();
    out.extend_from_slice(&data);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Local TLS server signed by our CA; speaks h2 when `h2` is true, else only advertises http/1.1.
    fn local_server(h2: bool) -> u16 {
        let ca = crate::http::net::Ca::load_or_create().unwrap();
        let mut cfg = (*ca.server_config("localhost").unwrap()).clone();
        cfg.alpn_protocols = vec![if h2 {
            b"h2".to_vec()
        } else {
            b"http/1.1".to_vec()
        }];
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        l.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let l = tokio::net::TcpListener::from_std(l).unwrap();
                let (tcp, _) = l.accept().await.unwrap();
                let Ok(tls) = tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
                    .accept(tcp)
                    .await
                else {
                    return;
                };
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let (parts, mut body) = req.into_parts();
                    let mut got = Vec::new();
                    while let Some(Ok(c)) = body.data().await {
                        got.extend_from_slice(&c);
                    }
                    let msg = format!(
                        "{} {} {}",
                        parts.method,
                        parts.uri.path(),
                        String::from_utf8_lossy(&got)
                    );
                    let resp = http::Response::builder()
                        .status(201)
                        .header("x-test", "yes")
                        .body(())
                        .unwrap();
                    let mut s = respond.send_response(resp, false).unwrap();
                    s.send_data(Bytes::from(msg), true).unwrap();
                }
            });
        });
        port
    }

    #[test]
    fn h2_roundtrip_and_fallback() {
        let port = local_server(true);
        let r = send(
            "localhost",
            port,
            b"POST /echo HTTP/2\r\nHost: localhost\r\ncontent-type: text/plain\r\n\r\nping",
        )
        .unwrap();
        let r = String::from_utf8(r).unwrap();
        assert!(r.starts_with("HTTP/2 201 Created\r\n"), "{r}");
        assert!(r.contains("x-test: yes"));
        assert!(r.ends_with("POST /echo ping"));
        let port = local_server(false);
        let e = send(
            "localhost",
            port,
            b"GET / HTTP/2\r\nHost: localhost\r\n\r\n",
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
        assert!(known_unsupported("localhost", port));
    }

    #[test]
    fn conversions() {
        let r = b"POST /a?b=1 HTTP/1.1\r\nHost: x.com\r\nConnection: keep-alive\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi";
        let t = String::from_utf8(to_h2_text(r).unwrap()).unwrap();
        assert_eq!(
            t,
            "POST /a?b=1 HTTP/2\r\nHost: x.com\r\ncontent-type: text/plain\r\ncontent-length: 2\r\n\r\nhi"
        );
        let h1 = to_h1_response(
            b"HTTP/2 200 OK\r\ncontent-type: text/html\r\ncontent-length: 99\r\n\r\nabc",
            false,
        );
        assert_eq!(
            h1,
            b"HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: 3\r\n\r\nabc"
        );
    }
}
