//! TCP listener, HTTPS MITM/CONNECT handling and the per-connection serve loop.
use std::io::{self, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, mpsc};

use super::*;
use crate::http::net::{self, Ca, Stream};

static LISTEN_PORT: AtomicU16 = AtomicU16::new(0);

/// The proxy's port, for code without the shared state (Chromium render); None until it listens.
pub fn listen_port() -> Option<u16> {
    Some(LISTEN_PORT.load(Ordering::Relaxed)).filter(|&p| p != 0)
}

pub fn start(state: State, ca: Arc<Ca>, port: u16) {
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            state.lock().unwrap().event(
                "Proxy",
                format!("Failed to start proxy service on 127.0.0.1:{port}. {e}"),
            );
            return;
        }
    };
    // port 0 asks the OS for a free port
    let port = listener.local_addr().map_or(port, |a| a.port());
    LISTEN_PORT.store(port, Ordering::Relaxed);
    {
        let mut s = state.lock().unwrap();
        s.listener = Some(port);
        s.event(
            "Proxy",
            format!("Proxy service started on 127.0.0.1:{port}"),
        );
    }
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let (state, ca) = (state.clone(), ca.clone());
            std::thread::spawn(move || {
                let _ = handle(conn, state, ca, port);
            });
        }
    });
}

fn handle(tcp: TcpStream, state: State, ca: Arc<Ca>, listener: u16) -> io::Result<()> {
    let mut r = BufReader::new(tcp.try_clone()?);
    let first = net::read_message(&mut r, false, false)?;
    let line = String::from_utf8_lossy(head(&first))
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    let mut parts = line.split_whitespace();
    if parts.next() == Some("CONNECT") {
        let target = parts.next().unwrap_or("").to_string();
        let (host, port) = split_host_port(&target, 443);
        let mut tcp = tcp;
        tcp.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
        // TLS ClientHello starts with 0x16; anything else is a plain tunnel (e.g. ws:// via CONNECT)
        let mut first = [0u8; 1];
        if tcp.peek(&mut first)? == 0 {
            return Ok(());
        }
        if first[0] != 0x16 {
            return serve(
                BufReader::new(tcp),
                None,
                Some((host, port, false)),
                state,
                listener,
            );
        }
        let cfg = ca.server_config(&host)?;
        let conn = rustls::ServerConnection::new(cfg).map_err(io::Error::other)?;
        let tls = rustls::StreamOwned::new(conn, tcp);
        return serve(
            BufReader::new(tls),
            None,
            Some((host, port, true)),
            state,
            listener,
        );
    }
    drop(r);
    // plain HTTP: the first message was already consumed, replay it through the same loop
    serve(BufReader::new(tcp), Some(first), None, state, listener)
}

pub fn split_host_port(s: &str, default: u16) -> (String, u16) {
    match s.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || s.starts_with('[') => match p.parse() {
            Ok(p) => (h.trim_matches(['[', ']']).to_string(), p),
            Err(_) => (s.to_string(), default),
        },
        _ => (s.to_string(), default),
    }
}

/// Splits `http://host:port/path` into (tls, host, port, path).
pub fn split_url(url: &str) -> Option<(bool, String, u16, String)> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else {
        (false, url.strip_prefix("http://")?)
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path
    };
    let (host, port) = split_host_port(authority, if tls { 443 } else { 80 });
    Some((tls, host, port, path))
}

fn serve<S: Stream>(
    mut r: BufReader<S>,
    mut first: Option<Vec<u8>>,
    tunnel: Option<(String, u16, bool)>,
    state: State,
    listener: u16,
) -> io::Result<()> {
    loop {
        let msg = match first.take() {
            Some(m) => m,
            None => net::read_message(&mut r, false, false)?,
        };
        let text = String::from_utf8_lossy(head(&msg)).into_owned();
        let line = text.lines().next().unwrap_or("").to_string();
        let mut parts = line.splitn(3, ' ');
        let (method, target, version) = (
            parts.next().unwrap_or("").to_string(),
            parts.next().unwrap_or("/").to_string(),
            parts.next().unwrap_or("HTTP/1.1"),
        );
        let (tls, host, port, path) = match (&tunnel, split_url(&target)) {
            (Some((h, p, t)), _) => (*t, h.clone(), *p, target.clone()),
            (None, Some(u)) => u,
            (None, None) => {
                let (h, p) = split_host_port(&net::header(&text, "host").unwrap_or_default(), 80);
                (false, h, p, target.clone())
            }
        };
        // DOM Invader reports from "Open browser" end here instead of going upstream
        if host == crate::domi::REPORT_HOST {
            let found = crate::domi::parse_findings(&String::from_utf8_lossy(
                body(&msg).unwrap_or_default(),
            ));
            crate::domi::record(&state, &found);
            r.get_mut().write_all(b"HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 0\r\n\r\n")?;
            continue;
        }
        // origin-form towards the server, as browsers send it to a non-proxy
        let mut req = format!("{method} {path} {version}").into_bytes();
        req.extend_from_slice(&msg[line.len()..]);

        let id = {
            let mut s = state.lock().unwrap();
            s.next_id += 1;
            s.next_id - 1
        };
        let original = req.clone();
        let (rules, intercepting, intercept_resp) = {
            let s = state.lock().unwrap();
            let on = s.intercept
                && should_intercept(&s.intercept_skip_ext, &s.intercept_host, &host, &path);
            (s.rules.clone(), on, on && s.intercept_responses)
        };
        req = apply_rules(&rules, &req, true);
        req = crate::ext::on_request(&host, port, tls, req);
        if intercepting {
            match hold(&state, id, &host, port, tls, req.clone(), false) {
                Some(edited) => req = edited,
                None => return Ok(()), // dropped
            }
        }
        let edited = req != original;
        let mut h2_resp: Option<Vec<u8>> = None;
        let upgrade = net::header(&String::from_utf8_lossy(head(&req)), "upgrade")
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
        let mut upstream = None;
        let mut resp = if upgrade {
            match net::send_keep(&host, port, tls, &req) {
                Ok((r, up)) => {
                    upstream = Some(up);
                    r
                }
                Err(e) => error_page(&format!("Error connecting to {host}:{port}: {e}")),
            }
        } else {
            let use_h2 =
                tls && state.lock().unwrap().http2 && !crate::http::h2up::known_unsupported(&host, port);
            let h2_req = if use_h2 {
                crate::http::h2up::to_h2_text(&req)
            } else {
                None
            };
            let first = match &h2_req {
                Some(r2) => net::send(&host, port, tls, r2),
                None => Err(io::Error::new(io::ErrorKind::Unsupported, "")),
            };
            match first {
                Ok(r) => {
                    // history shows the HTTP/2 exchange; the browser side stays HTTP/1.1
                    req = h2_req.unwrap();
                    h2_resp = Some(apply_rules(&rules, &r, false));
                    crate::http::h2up::to_h1_response(h2_resp.as_ref().unwrap(), method == "HEAD")
                }
                Err(e) if e.kind() != io::ErrorKind::Unsupported => {
                    error_page(&format!("Error connecting to {host}:{port}: {e}"))
                }
                Err(_) => match net::send(&host, port, tls, &req) {
                    Ok(r) => apply_rules(&rules, &r, false),
                    Err(e) => error_page(&format!("Error connecting to {host}:{port}: {e}")),
                },
            }
        };
        if intercept_resp {
            match hold(&state, id, &host, port, tls, resp.clone(), true) {
                Some(edited) => resp = edited,
                None => return Ok(()),
            }
        }
        let ip = format!("{host}:{port}")
            .parse::<std::net::SocketAddr>()
            .map(|a| a.ip().to_string())
            .ok()
            .or_else(|| {
                std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), port))
                    .ok()?
                    .next()
                    .map(|a| a.ip().to_string())
            })
            .unwrap_or_default();
        r.get_mut().write_all(&resp)?;
        r.get_mut().flush()?;
        let status = String::from_utf8_lossy(head(&resp))
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let rline = String::from_utf8_lossy(head(&req))
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        let mut rp = rline.splitn(3, ' ');
        let entry = Entry {
            id,
            host,
            port,
            tls,
            method: rp.next().unwrap_or("").into(),
            url: rp.next().unwrap_or("").into(),
            status,
            edited,
            req,
            resp: h2_resp.clone().unwrap_or_else(|| resp.clone()),
            time: now(),
            ip,
            listener,
            comment: String::new(),
            highlight: None,
            tool: "Proxy",
        };
        let mut found = crate::scanner::passive(&entry);
        found.extend(crate::bcheck::passive(&entry));
        crate::ext::on_response(&entry);
        if !found.is_empty() {
            let mut s = state.lock().unwrap();
            for mut i in found {
                if !s
                    .issues
                    .iter()
                    .any(|x| x.name == i.name && x.origin == i.origin && x.path == i.path)
                {
                    i.id = s.issues.len() + 1;
                    s.issues.push(i);
                }
            }
        }
        if entry.mime() == "image" || entry.mime() == "SVG" {
            images().lock().unwrap().insert(
                format!("{}{}", entry.origin(), entry.url),
                body_bytes(&entry.resp),
            );
        }
        {
            let mut s = state.lock().unwrap();
            let mut l = entry.clone();
            l.id = s.logger.len() + 1;
            s.logger.push(l);
            let pos = s.history.partition_point(|e| e.id < id);
            s.history.insert(pos, entry);
            s.repaint();
        }
        if status == 101
            && let Some(up) = upstream
        {
            let scheme = if tls { "wss" } else { "ws" };
            let url = format!("{scheme}://{}{}", entry_host_port(&state, id), path);
            return relay_ws(&mut r, up, &state, &url);
        }
        let close_delimited = {
            let h = String::from_utf8_lossy(head(&resp)).into_owned();
            net::header(&h, "content-length").is_none()
                && !net::header(&h, "transfer-encoding").is_some_and(|v| v.contains("chunked"))
                && !(status == 204 || status == 304 || method == "HEAD")
        };
        if close_delimited
            || net::header(&text, "connection").is_some_and(|v| v.eq_ignore_ascii_case("close"))
        {
            return Ok(());
        }
    }
}

fn entry_host_port(state: &State, id: usize) -> String {
    let s = state.lock().unwrap();
    s.history
        .iter()
        .find(|e| e.id == id)
        .map(|e| {
            let def = if e.tls { 443 } else { 80 };
            if e.port == def {
                e.host.clone()
            } else {
                format!("{}:{}", e.host, e.port)
            }
        })
        .unwrap_or_default()
}

pub fn should_intercept(skip_ext: &str, host_filter: &str, host: &str, path: &str) -> bool {
    let file = path
        .split('?')
        .next()
        .unwrap_or("")
        .rsplit('/')
        .next()
        .unwrap_or("");
    let ext = file
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    let skip = !ext.is_empty()
        && !skip_ext.is_empty()
        && regex::Regex::new(skip_ext).is_ok_and(|r| r.is_match(&ext));
    !skip && (host_filter.is_empty() || host.contains(host_filter))
}

/// Parks a message in the intercept queue until the UI forwards (maybe edited) or drops it.
fn hold(
    state: &State,
    id: usize,
    host: &str,
    port: u16,
    tls: bool,
    msg: Vec<u8>,
    response: bool,
) -> Option<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    {
        let mut s = state.lock().unwrap();
        s.queue.push_back(Pending {
            id,
            host: host.into(),
            port,
            tls,
            req: msg,
            response,
            reply: tx,
        });
        s.repaint();
    }
    rx.recv().ok().flatten()
}

pub fn error_page(msg: &str) -> Vec<u8> {
    let body = format!(
        "<html><head><title>BurpCraft Error</title></head><body><h1>BurpCraft Error</h1><p>{}</p></body></html>",
        crate::http::codec::html_encode(msg.as_bytes(), false)
    );
    format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
