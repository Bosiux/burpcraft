//! Match-and-replace rules applied to proxied requests and responses.

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
