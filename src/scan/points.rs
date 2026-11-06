// ------------------------------------------------------------ insertion points

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Query,
    Body,
    Cookie,
    Json,
    Header,
    Xml,
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
    while pos < head_end {
        let end = req[pos..head_end]
            .find("\r\n")
            .map_or(head_end, |e| pos + e);
        let line = &req[pos..end];
        if let Some((k, v)) = line.split_once(':') {
            let vstart = pos + k.len() + 1 + (v.len() - v.trim_start().len());
            match k.trim().to_ascii_lowercase().as_str() {
                "cookie" => pairs(&req[vstart..end], vstart, ';', Kind::Cookie, &mut out),
                "user-agent" | "referer" => out.push(Point {
                    kind: Kind::Header,
                    name: k.trim().into(),
                    start: vstart,
                    end,
                }),
                "content-type" => {
                    let v = v.to_ascii_lowercase();
                    json = v.contains("json");
                    form = v.contains("x-www-form-urlencoded");
                    xml = v.contains("xml");
                }
                _ => {}
            }
        }
        pos = end + 2;
    }
    let bstart = (head_end + 4).min(req.len());
    let body = &req[bstart..];
    if json || body.trim_start().starts_with('{') {
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
        Kind::Query | Kind::Body => value
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
        Kind::Xml => value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;"),
    };
    let quoted = p.kind == Kind::Json && !req[..p.start].ends_with('"');
    let enc = if quoted { format!("\"{enc}\"") } else { enc };
    crate::tools::fix_content_length(&format!("{}{enc}{}", &req[..p.start], &req[p.end..]))
}
