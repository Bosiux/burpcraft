//! Shared helpers for the tool handlers: JSON builders, argument extractors, and
//! message formatting (decoded display text, raw CRLF conversion, target/source).
use crate::automation::openapi::J;
use crate::proxy::{self, Entry};
use crate::{http::net, scan, tools};

pub(crate) fn obj(v: Vec<(&str, J)>) -> J {
    J::Obj(v.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}
pub(crate) fn s(v: impl Into<String>) -> J {
    J::Str(v.into())
}
pub(crate) fn n(v: impl ToString) -> J {
    J::Num(v.to_string())
}

pub(crate) fn str_arg<'a>(a: &'a J, k: &str) -> Option<&'a str> {
    match a.get(k) {
        Some(J::Str(v)) => Some(v),
        _ => None,
    }
}
pub(crate) fn num_arg(a: &J, k: &str) -> Option<i64> {
    match a.get(k) {
        Some(J::Num(v)) => v.parse::<f64>().ok().map(|f| f as i64),
        _ => None,
    }
}
pub(crate) fn bool_arg(a: &J, k: &str) -> Option<bool> {
    match a.get(k) {
        Some(J::Bool(b)) => Some(*b),
        _ => None,
    }
}
pub(crate) fn strs(j: &J) -> Vec<String> {
    match j {
        J::Arr(v) => v
            .iter()
            .filter_map(|x| {
                if let J::Str(s) = x {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect(),
        _ => vec![],
    }
}

/// Message text for agents: decoded body, `\n` line endings, cut at `max` bytes.
pub(crate) fn text(msg: &[u8], max: usize) -> String {
    let t = proxy::display(msg).replace("\r\n", "\n");
    if t.len() <= max {
        return t;
    }
    let mut cut = max;
    while !t.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}\n…[truncated {} bytes]", &t[..cut], t.len() - cut)
}

/// Raw message from an agent: CRLF line endings in the head, Content-Length fixed.
pub(crate) fn raw(msg: &str) -> String {
    tools::fix_content_length(&msg.replace("\r\n", "\n").replace('\n', "\r\n"))
}

/// `target` argument, else https + the request's Host header.
pub(crate) fn target(a: &J, req: &str) -> Result<scan::Target, String> {
    let t = match str_arg(a, "target") {
        Some(t) => t.to_string(),
        None => format!(
            "https://{}",
            net::header(req, "host").ok_or("no `target` and no Host header")?
        ),
    };
    scan::parse_url(&t)
        .map(|(t, _)| t)
        .ok_or_else(|| format!("bad target {t:?}: use scheme://host[:port]"))
}

pub(crate) fn source<'a>(a: &J, st: &'a proxy::Shared) -> &'a [Entry] {
    if str_arg(a, "source") == Some("logger") {
        &st.logger
    } else {
        &st.history
    }
}
