//! Intercepting proxy: listener, HTTPS MITM, intercept queue and HTTP history.
use std::collections::VecDeque;
use std::io::{self, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};

use crate::net::{self, Ca, Stream};

#[derive(Clone)]
pub struct Entry {
    pub id: usize,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub method: String,
    pub url: String,
    pub status: u16,
    pub req: Vec<u8>,
    pub resp: Vec<u8>,
    pub edited: bool,
    pub time: String,
    pub ip: String,
    pub listener: u16,
    pub comment: String,
    pub highlight: Option<usize>,
    pub tool: &'static str,
}

impl Entry {
    pub fn origin(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            format!("{scheme}://{}", self.host)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }
    pub fn path(&self) -> &str {
        self.url.split('?').next().unwrap_or("")
    }
    pub fn params(&self) -> bool {
        self.url.contains('?') || body(&self.req).is_some_and(|b| !b.is_empty())
    }
    pub fn mime(&self) -> String {
        let ct = net::header(&String::from_utf8_lossy(head(&self.resp)), "content-type")
            .unwrap_or_default();
        mime_label(&ct, &self.resp)
    }
    pub fn extension(&self) -> &str {
        let p = self.path();
        let last = p.rsplit('/').next().unwrap_or("");
        last.rsplit_once('.').map(|(_, e)| e).unwrap_or("")
    }
    pub fn title(&self) -> String {
        let s = String::from_utf8_lossy(&self.resp);
        let low = s.to_ascii_lowercase();
        let Some(a) = low.find("<title") else {
            return String::new();
        };
        let Some(gt) = low[a..].find('>') else {
            return String::new();
        };
        let start = a + gt + 1;
        let end = low[start..]
            .find("</title")
            .map(|e| start + e)
            .unwrap_or(start);
        s.get(start..end).unwrap_or("").trim().to_string()
    }
    pub fn cookies(&self) -> String {
        String::from_utf8_lossy(head(&self.resp))
            .lines()
            .filter_map(|l| l.split_once(':'))
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, v)| v.trim().split(';').next().unwrap_or("").to_string())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

pub fn mime_label(content_type: &str, resp: &[u8]) -> String {
    let ct = content_type.to_ascii_lowercase();
    let label = [
        ("html", "HTML"),
        ("json", "JSON"),
        ("javascript", "script"),
        ("ecmascript", "script"),
        ("css", "CSS"),
        ("xml", "XML"),
        ("image/svg", "SVG"),
        ("image/", "image"),
        ("font", "font"),
        ("text/plain", "text"),
    ]
    .iter()
    .find(|(k, _)| ct.contains(k))
    .map(|(_, v)| *v);
    match label {
        Some(l) => l.into(),
        None if ct.is_empty() && body(resp).is_none_or(|b| b.is_empty()) => String::new(),
        None => "text".into(),
    }
}

/// Body with transfer and content encodings removed (chunked, gzip, deflate).
pub fn body_bytes(msg: &[u8]) -> Vec<u8> {
    let Some(b) = body(msg) else { return vec![] };
    let h = String::from_utf8_lossy(head(msg)).into_owned();
    let mut data = b.to_vec();
    if net::header(&h, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        data = dechunk(&data);
    }
    let enc = net::header(&h, "content-encoding")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let mut out = Vec::new();
    use std::io::Read;
    let ok = match enc.as_str() {
        "gzip" | "x-gzip" => flate2::read::MultiGzDecoder::new(&data[..])
            .read_to_end(&mut out)
            .is_ok(),
        "deflate" => {
            flate2::read::ZlibDecoder::new(&data[..])
                .read_to_end(&mut out)
                .is_ok()
                || {
                    out.clear();
                    flate2::read::DeflateDecoder::new(&data[..])
                        .read_to_end(&mut out)
                        .is_ok()
                }
        }
        _ => false,
    };
    if ok { out } else { data }
}

/// Text for read-only message panes: chunked and gzip/deflate bodies are unpacked, like the original's default display.
pub fn display(msg: &[u8]) -> String {
    let Some(b) = body(msg) else {
        return String::from_utf8_lossy(msg).into_owned();
    };
    let data = body_bytes(msg);
    if data == b {
        return String::from_utf8_lossy(msg).into_owned();
    }
    format!(
        "{}\r\n\r\n{}",
        String::from_utf8_lossy(head(msg)),
        String::from_utf8_lossy(&data)
    )
}

/// Images seen by the proxy, by full URL, so the Render tab can show them without new requests.
// ponytail: unbounded map; cap or evict if image-heavy sessions grow memory too much
pub fn images() -> &'static Mutex<std::collections::HashMap<String, Vec<u8>>> {
    static M: std::sync::OnceLock<Mutex<std::collections::HashMap<String, Vec<u8>>>> =
        std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

pub fn dechunk(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(nl) = find(&b[i..], b"\r\n") {
        let line = String::from_utf8_lossy(&b[i..i + nl]).into_owned();
        let Ok(size) = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
        else {
            break;
        };
        i += nl + 2;
        if size == 0 || i + size > b.len() {
            break;
        }
        out.extend_from_slice(&b[i..i + size]);
        i += size + 2;
    }
    out
}

pub fn head(msg: &[u8]) -> &[u8] {
    match find(msg, b"\r\n\r\n") {
        Some(i) => &msg[..i],
        None => msg,
    }
}

pub fn body(msg: &[u8]) -> Option<&[u8]> {
    find(msg, b"\r\n\r\n").map(|i| &msg[i + 4..])
}

pub fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

pub struct Pending {
    pub id: usize,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub req: Vec<u8>,
    pub response: bool,
    pub reply: mpsc::Sender<Option<Vec<u8>>>,
}

pub const RULE_KINDS: [&str; 5] = [
    "Request header",
    "Request body",
    "Response header",
    "Response body",
    "Request first line",
];

#[derive(Clone)]
pub struct Rule {
    pub enabled: bool,
    pub kind: usize,
    pub pattern: String,
    pub replace: String,
    pub comment: String,
}

/// Applies enabled match-and-replace rules for one direction. Header rules work line by line;
/// an empty pattern on a header rule adds the replacement as a new header.
pub fn apply_rules(rules: &[Rule], msg: &[u8], request: bool) -> Vec<u8> {
    let mut text = String::from_utf8_lossy(msg).into_owned();
    if std::str::from_utf8(msg).is_err() {
        return msg.to_vec(); // binary bodies are left untouched
    }
    for r in rules
        .iter()
        .filter(|r| r.enabled && (r.kind == 4 || (r.kind < 2) == request))
    {
        let (h, b) = match text.split_once("\r\n\r\n") {
            Some((h, b)) => (h.to_string(), b.to_string()),
            None => (text.clone(), String::new()),
        };
        let re = match regex::Regex::new(&r.pattern) {
            Ok(re) => re,
            Err(_) => continue,
        };
        text = match r.kind {
            0 | 2 => {
                let mut lines: Vec<String> = h.split("\r\n").map(String::from).collect();
                if r.pattern.is_empty() {
                    lines.push(r.replace.clone());
                } else {
                    for l in lines.iter_mut().skip(1) {
                        *l = re.replace_all(l, r.replace.as_str()).into_owned();
                    }
                    lines.retain(|l| !l.is_empty());
                }
                format!("{}\r\n\r\n{b}", lines.join("\r\n"))
            }
            4 => {
                let (first, rest) = h.split_once("\r\n").unwrap_or((&h, ""));
                let first = re.replace_all(first, r.replace.as_str());
                if rest.is_empty() {
                    format!("{first}\r\n\r\n{b}")
                } else {
                    format!("{first}\r\n{rest}\r\n\r\n{b}")
                }
            }
            _ if r.pattern.is_empty() => text,
            _ => format!("{h}\r\n\r\n{}", re.replace_all(&b, r.replace.as_str())),
        };
    }
    text.into_bytes()
}

pub fn default_rules() -> Vec<Rule> {
    let r = |kind, pattern: &str, replace: &str, comment: &str| Rule {
        enabled: false,
        kind,
        pattern: pattern.into(),
        replace: replace.into(),
        comment: comment.into(),
    };
    vec![
        r(
            0,
            "^User-Agent.*$",
            "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
            "Emulate iOS",
        ),
        r(0, "^Accept-Encoding.*$", "", "Remove Accept-Encoding"),
        r(
            0,
            "^If-Modified-Since.*$",
            "",
            "Require non-cached response",
        ),
        r(0, "^If-None-Match.*$", "", "Require non-cached response"),
        r(2, "^Strict-Transport-Security.*$", "", "Remove HSTS"),
        r(2, "^Content-Security-Policy.*$", "", "Remove CSP"),
    ]
}

#[derive(Clone)]
pub struct WsMsg {
    pub id: usize,
    pub url: String,
    pub to_server: bool,
    pub opcode: u8,
    pub data: Vec<u8>,
    pub time: String,
}

/// Pops complete WebSocket frames (opcode, unmasked payload) off the front of `buf`.
pub fn ws_frames(buf: &mut Vec<u8>) -> Vec<(u8, Vec<u8>)> {
    let mut out = vec![];
    loop {
        if buf.len() < 2 {
            break;
        }
        let (op, masked, l7) = (buf[0] & 0x0f, buf[1] & 0x80 != 0, (buf[1] & 0x7f) as usize);
        let (len, mut i) = match l7 {
            126 if buf.len() >= 4 => (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4),
            127 if buf.len() >= 10 => (
                u64::from_be_bytes(buf[2..10].try_into().unwrap()) as usize,
                10,
            ),
            126 | 127 => break,
            n => (n, 2),
        };
        let key = if masked {
            if buf.len() < i + 4 {
                break;
            }
            i += 4;
            Some([buf[i - 4], buf[i - 3], buf[i - 2], buf[i - 1]])
        } else {
            None
        };
        if buf.len() < i + len {
            break;
        }
        let mut data = buf[i..i + len].to_vec();
        if let Some(k) = key {
            data.iter_mut()
                .enumerate()
                .for_each(|(j, b)| *b ^= k[j % 4]);
        }
        buf.drain(..i + len);
        out.push((op, data));
    }
    out
}

pub struct Shared {
    pub history: Vec<Entry>,
    pub logger: Vec<Entry>,
    pub ws: Vec<WsMsg>,
    pub issues: Vec<crate::scanner::Issue>,
    pub intercept: bool,
    pub intercept_responses: bool,
    /// Intercept rules: skip URLs whose file extension matches this regex; only hosts containing `intercept_host`.
    pub intercept_skip_ext: String,
    pub intercept_host: String,
    /// "Default to HTTP/2 if the server supports it"
    pub http2: bool,
    pub rules: Vec<Rule>,
    pub queue: VecDeque<Pending>,
    pub events: Vec<(String, String, String)>, // time, source, message
    pub listener: Option<u16>,
    pub ctx: Option<eframe::egui::Context>,
    pub next_id: usize,
}

pub type State = Arc<Mutex<Shared>>;

pub fn now() -> String {
    chrono::Local::now()
        .format("%H:%M:%S %-d %b %Y")
        .to_string()
}

impl Shared {
    pub fn new() -> State {
        Arc::new(Mutex::new(Shared {
            history: Vec::new(),
            logger: Vec::new(),
            ws: Vec::new(),
            issues: Vec::new(),
            intercept: false,
            intercept_responses: false,
            intercept_skip_ext: "^(gif|jpg|png|css|js|ico|svg|eot|woff|woff2|ttf)$".into(),
            intercept_host: String::new(),
            http2: true,
            rules: default_rules(),
            queue: VecDeque::new(),
            events: Vec::new(),
            listener: None,
            ctx: None,
            next_id: 1,
        }))
    }
    pub fn event(&mut self, source: &str, msg: impl Into<String>) {
        self.events.push((now(), source.into(), msg.into()));
        self.repaint();
    }
    /// Records traffic from any tool for the Logger tab.
    pub fn log_tool(
        &mut self,
        tool: &'static str,
        host: &str,
        port: u16,
        tls: bool,
        req: &[u8],
        resp: &[u8],
    ) {
        let line = String::from_utf8_lossy(head(req))
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        let mut p = line.splitn(3, ' ');
        let status = String::from_utf8_lossy(head(resp))
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let id = self.logger.len() + 1;
        self.logger.push(Entry {
            id,
            host: host.into(),
            port,
            tls,
            method: p.next().unwrap_or("").into(),
            url: p.next().unwrap_or("").into(),
            status,
            req: req.to_vec(),
            resp: resp.to_vec(),
            edited: false,
            time: now(),
            ip: String::new(),
            listener: 0,
            comment: String::new(),
            highlight: None,
            tool,
        });
        self.repaint();
    }
    fn repaint(&self) {
        if let Some(c) = &self.ctx {
            c.request_repaint();
        }
    }
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
                tls && state.lock().unwrap().http2 && !crate::h2up::known_unsupported(&host, port);
            let h2_req = if use_h2 {
                crate::h2up::to_h2_text(&req)
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
                    crate::h2up::to_h1_response(h2_resp.as_ref().unwrap(), method == "HEAD")
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

/// Shuttles bytes both ways after a 101, logging every frame to the WebSockets history.
fn relay_ws<S: Stream>(
    client: &mut BufReader<S>,
    mut up: BufReader<Box<dyn Stream>>,
    state: &State,
    url: &str,
) -> io::Result<()> {
    use std::io::Read;
    let tick = Some(std::time::Duration::from_millis(30));
    client.get_ref().set_timeout(tick);
    up.get_ref().set_timeout(tick);
    let mut bufs = [Vec::new(), Vec::new()];
    let mut tmp = vec![0u8; 16 * 1024];
    loop {
        for to_server in [true, false] {
            let n = if to_server {
                client.read(&mut tmp)
            } else {
                up.read(&mut tmp)
            };
            let n = match n {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => return Ok(()),
            };
            if to_server {
                up.get_mut().write_all(&tmp[..n])?;
                up.get_mut().flush()?;
            } else {
                client.get_mut().write_all(&tmp[..n])?;
                client.get_mut().flush()?;
            }
            let buf = &mut bufs[to_server as usize];
            buf.extend_from_slice(&tmp[..n]);
            let frames = ws_frames(buf);
            if !frames.is_empty() {
                let mut s = state.lock().unwrap();
                for (opcode, data) in frames {
                    let id = s.ws.len() + 1;
                    s.ws.push(WsMsg {
                        id,
                        url: url.into(),
                        to_server,
                        opcode,
                        data,
                        time: now(),
                    });
                }
                s.repaint();
            }
        }
    }
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
        crate::codec::html_encode(msg.as_bytes(), false)
    );
    format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

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
