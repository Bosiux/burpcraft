//! Raw HTTP message framing and body decoding helpers.
use std::sync::Mutex;

use crate::http::net;

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
    // sizes come from the peer: a huge or truncated chunk ends the body instead of overflowing
    while let Some(nl) = b.get(i..).and_then(|r| find(r, b"\r\n")) {
        let line = String::from_utf8_lossy(&b[i..i + nl]).into_owned();
        let Ok(size) = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
        else {
            break;
        };
        i += nl + 2;
        let Some(end) = i.checked_add(size).filter(|&e| size > 0 && e <= b.len()) else {
            break;
        };
        out.extend_from_slice(&b[i..end]);
        i = end + 2;
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

/// HTTP status code from a raw response, or 0 if absent/unparseable.
pub fn status_of(resp: &[u8]) -> u16 {
    String::from_utf8_lossy(head(resp))
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

pub fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}
