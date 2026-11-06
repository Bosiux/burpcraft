// ------------------------------------------------------------ insertion points

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Query,
    Body,
    Cookie,
    Json,
    Header,
    Xml,
    Path,
    Multipart,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Point {
    pub kind: Kind,
    pub name: String,
    pub start: usize,
    pub end: usize,
}

impl Point {
    pub fn label(&self) -> String {
        let k = match self.kind {
            Kind::Query => "URL parameter",
            Kind::Body => "body parameter",
            Kind::Cookie => "cookie",
            Kind::Json => "JSON parameter",
            Kind::Header => "HTTP header",
            Kind::Xml => "XML element",
            Kind::Path => "URL path segment",
            Kind::Multipart => "multipart part",
        };
        format!("{k} {}", self.name)
    }
}

/// `k=v&k=v` value ranges inside `s`, offset by `base`.
fn pairs(s: &str, base: usize, sep: char, kind: Kind, out: &mut Vec<Point>) {
    let mut pos = 0;
    for part in s.split(sep) {
        if let Some(eq) = part.find('=') {
            let name = part[..eq].trim().to_string();
            if !name.is_empty() {
                out.push(Point {
                    kind,
                    name,
                    start: base + pos + eq + 1,
                    end: base + pos + part.len(),
                });
            }
        }
        pos += part.len() + sep.len_utf8();
    }
}

pub fn points(req: &str) -> Vec<Point> {
    let mut out = vec![];
    let head_end = req.find("\r\n\r\n").unwrap_or(req.len());
    let first_end = req.find("\r\n").unwrap_or(head_end);
    let first = &req[..first_end];
    // path segments between the method and the query/version: /api/users/42 -> api, users, 42
    if let Some(sp) = first.find(" /") {
        let start = sp + 1;
        let end = first[start..]
            .find(['?', ' '])
            .map_or(first.len(), |e| start + e);
        let mut pos = start + 1;
        for seg in first[start + 1..end].split('/') {
            if !seg.is_empty() {
                out.push(Point {
                    kind: Kind::Path,
                    name: seg.to_string(),
                    start: pos,
                    end: pos + seg.len(),
                });
            }
            pos += seg.len() + 1;
        }
    }
    if let Some(q) = first.find('?') {
        let end = first
            .rfind(" HTTP/")
            .filter(|&e| e > q)
            .unwrap_or(first.len());
        pairs(&first[q + 1..end], q + 1, '&', Kind::Query, &mut out);
    }
    let mut pos = first_end + 2;
    let mut json = false;
    let mut form = false;
    let mut xml = false;
    let mut boundary: Option<String> = None;
    while pos < head_end {
        let end = req[pos..head_end]
            .find("\r\n")
            .map_or(head_end, |e| pos + e);
        let line = &req[pos..end];
        if let Some((k, v)) = line.split_once(':') {
            let vstart = pos + k.len() + 1 + (v.len() - v.trim_start().len());
            match k.trim().to_ascii_lowercase().as_str() {
                "cookie" => pairs(&req[vstart..end], vstart, ';', Kind::Cookie, &mut out),
                "content-type" => {
                    let lv = v.to_ascii_lowercase();
                    json = lv.contains("json");
                    form = lv.contains("x-www-form-urlencoded");
                    xml = lv.contains("xml");
                    if lv.contains("multipart/form-data") {
                        boundary = v
                            .split(';')
                            .find_map(|p| p.trim().strip_prefix("boundary="))
                            .map(|b| b.trim_matches('"').to_string());
                    }
                }
                // framing and routing headers: changing them breaks the request, not the app
                "host" | "content-length" | "transfer-encoding" | "connection" | "upgrade"
                | "accept" | "accept-encoding" | "accept-language" | "te" => {}
                _ => out.push(Point {
                    kind: Kind::Header,
                    name: k.trim().into(),
                    start: vstart,
                    end,
                }),
            }
        }
        pos = end + 2;
    }
    let bstart = (head_end + 4).min(req.len());
    let body = &req[bstart..];
    if let Some(b) = boundary {
        // each non-file part's value: --b\r\n<part headers>\r\n\r\n<value>\r\n--b
        let delim = format!("--{b}");
        let mut pos = 0;
        while let Some(i) = body[pos..].find(&delim) {
            let part = pos + i + delim.len();
            let Some(next) = body[part..].find(&delim).map(|n| part + n) else {
                break;
            };
            let chunk = &body[part..next];
            if let Some(h) = chunk.find("\r\n\r\n")
                && !chunk[..h].contains("filename=")
                && let Some(name) = chunk[..h]
                    .split("name=\"")
                    .nth(1)
                    .and_then(|n| n.split('"').next())
            {
                let vstart = part + h + 4;
                let vend = next.saturating_sub(2).max(vstart); // CRLF before the delimiter
                out.push(Point {
                    kind: Kind::Multipart,
                    name: name.to_string(),
                    start: bstart + vstart,
                    end: bstart + vend,
                });
            }
            pos = next;
        }
    } else if json || body.trim_start().starts_with('{') {
        let re = regex::Regex::new(
            r#""([^"\\]+)"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(-?\d+(?:\.\d+)?|true|false))"#,
        )
        .unwrap();
        for c in re.captures_iter(body) {
            let v = c.get(2).or(c.get(3)).unwrap();
            out.push(Point {
                kind: Kind::Json,
                name: c[1].to_string(),
                start: bstart + v.start(),
                end: bstart + v.end(),
            });
        }
    } else if xml || (!form && body.trim_start().starts_with('<')) {
        // element text between tags, bounded; enough to carry an XXE entity reference
        let re = regex::Regex::new(r"(?s)>([^<>]+)<").unwrap();
        for c in re.captures_iter(body).take(5) {
            let v = c.get(1).unwrap();
            if v.as_str().trim().is_empty() {
                continue;
            }
            out.push(Point {
                kind: Kind::Xml,
                name: v.as_str().trim().to_string(),
                start: bstart + v.start(),
                end: bstart + v.end(),
            });
        }
    } else if form || body.contains('=') {
        pairs(body, bstart, '&', Kind::Body, &mut out);
    }
    out
}

/// Request with `value` in place of the point, encoded for its context and Content-Length fixed.
pub fn inject(req: &str, p: &Point, value: &str) -> String {
    let enc = match p.kind {
        Kind::Query | Kind::Body | Kind::Path => value
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-_.~!*'()/:".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect(),
        Kind::Cookie => value
            .replace(';', "%3b")
            .replace(' ', "%20")
            .replace('\r', "%0d")
            .replace('\n', "%0a"),
        Kind::Json => value.replace('\\', "\\\\").replace('"', "\\\""),
        Kind::Header => value.replace(['\r', '\n'], ""),
        Kind::Multipart => value.to_string(),
        Kind::Xml => value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;"),
    };
    let quoted = p.kind == Kind::Json && !req[..p.start].ends_with('"');
    let enc = if quoted { format!("\"{enc}\"") } else { enc };
    crate::tools::fix_content_length(&format!("{}{enc}{}", &req[..p.start], &req[p.end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn got(req: &str, kind: Kind) -> Vec<(String, &str)> {
        points(req)
            .into_iter()
            .filter(|p| p.kind == kind)
            .map(|p| (p.name, &req[p.start..p.end]))
            .collect()
    }

    #[test]
    fn path_headers_and_multipart() {
        let req = "GET /api/users/42?x=1 HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer t\r\nX-Tenant: acme\r\nAccept: */*\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            got(req, Kind::Path),
            [
                ("api".into(), "api"),
                ("users".into(), "users"),
                ("42".into(), "42")
            ]
        );
        assert_eq!(
            got(req, Kind::Header),
            [
                ("Authorization".into(), "Bearer t"),
                ("X-Tenant".into(), "acme")
            ]
        );
        let p = &points(req)[2];
        assert!(inject(req, p, "1 or/x?").starts_with("GET /api/users/1%20or/x%3F?x=1 "));

        let body = "--XY\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--XY\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nfile\r\n--XY\r\nContent-Disposition: form-data; name=\"n\"\r\n\r\n7\r\n--XY--\r\n";
        let req = format!(
            "POST /up HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=XY\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        assert_eq!(
            got(&req, Kind::Multipart),
            [("title".into(), "hello"), ("n".into(), "7")]
        );
        let p = points(&req)
            .into_iter()
            .find(|p| p.name == "title")
            .unwrap();
        let r = inject(&req, &p, "<svg>");
        assert!(r.contains("name=\"title\"\r\n\r\n<svg>\r\n--XY"));
        assert!(r.contains(&format!("Content-Length: {}", body.len())));
    }
}
