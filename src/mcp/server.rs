//! Streamable-HTTP transport: the TCP accept loop, one keep-alive connection per
//! thread, auth/origin checks, and handing each POST /mcp body to `handle`.
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

use super::{Ctx, handle};

pub fn start(port: u16, key: String, ctx: Ctx) -> std::io::Result<u16> {
    let l = TcpListener::bind(("127.0.0.1", port))?;
    let port = l.local_addr()?.port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            let (ctx, key) = (ctx.clone(), key.clone());
            std::thread::spawn(move || serve(c, &key, &ctx));
        }
    });
    Ok(port)
}

/// One keep-alive connection: POST /mcp carries a JSON-RPC message.
fn serve(c: TcpStream, key: &str, ctx: &Ctx) {
    let _ = c.set_read_timeout(Some(std::time::Duration::from_secs(300)));
    let _ = c.set_nodelay(true);
    let Ok(rc) = c.try_clone() else { return };
    let (mut r, mut w) = (BufReader::new(rc), c);
    loop {
        let mut first = String::new();
        if r.read_line(&mut first).unwrap_or(0) == 0 {
            return;
        }
        let (mut len, mut auth, mut origin, mut host, mut line) = (
            0usize,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        );
        while r.read_line(&mut line).is_ok_and(|n| n > 2) {
            if let Some((k, v)) = line.split_once(':') {
                let v = v.trim().to_string();
                match k.trim().to_ascii_lowercase().as_str() {
                    "content-length" => len = v.parse().unwrap_or(0),
                    "authorization" => auth = v,
                    "origin" => origin = v,
                    "host" => host = v,
                    _ => {}
                }
            }
            line.clear();
        }
        if len > 16 << 20 {
            return;
        }
        let mut body = vec![0; len];
        if r.read_exact(&mut body).is_err() {
            return;
        }
        let mut parts = first.split_whitespace();
        let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        // browsers on other sites must not drive the proxy (DNS rebinding / CSRF)
        let local = crate::automation::is_local(&host, &origin);
        let (status, out) = if !key.is_empty() && auth != format!("Bearer {key}") {
            ("401 Unauthorized", String::new())
        } else if !local {
            ("403 Forbidden", String::new())
        } else if path.split('?').next() != Some("/mcp") {
            ("404 Not Found", String::new())
        } else if method != "POST" {
            ("405 Method Not Allowed", String::new())
        } else {
            match handle(&String::from_utf8_lossy(&body), ctx) {
                Some(j) => ("200 OK", j),
                None => ("202 Accepted", String::new()),
            }
        };
        let ok = write!(
            w,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{out}",
            out.len()
        );
        if ok.is_err() {
            return;
        }
    }
}
