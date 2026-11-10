use super::*;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use crate::proxy;

// ------------------------------------------------------------ crawler

/// Same-origin links, form targets (as ready requests) found in a page.
pub fn links(base_path: &str, html: &str, t: &Target) -> (Vec<String>, Vec<String>) {
    let href = regex::Regex::new(r#"(?i)(?:href|src)\s*=\s*["']([^"'#]+)"#).unwrap();
    let form = regex::Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form>"#).unwrap();
    let attr = |s: &str, a: &str| {
        regex::Regex::new(&format!(r#"(?i)\b{a}\s*=\s*["']([^"']*)["']"#))
            .unwrap()
            .captures(s)
            .map(|c| c[1].to_string())
    };
    let input = regex::Regex::new(r#"(?is)<(?:input|textarea|select)\b([^>]*)>"#).unwrap();
    let origin = origin_of(t);
    let resolve = |u: &str| -> Option<String> {
        let u = crate::http::codec::html_decode(u.trim());
        if let Some(rest) = u.strip_prefix(&origin) {
            return Some(if rest.is_empty() {
                "/".into()
            } else {
                rest.to_string()
            });
        }
        // another origin or scheme (http:, javascript:, mailto:...): only a prefix counts, not "?u=http://" in a query
        let scheme = u.split(['/', '?', '#']).next().unwrap_or("").contains(':');
        if scheme || u.starts_with("//") {
            return None;
        }
        Some(if u.starts_with('/') {
            u
        } else {
            format!(
                "{}{u}",
                base_path[..base_path.rfind('/').map_or(0, |i| i + 1)]
                    .trim_end_matches(|c| c != '/')
            )
        })
    };
    let static_ext = regex::Regex::new(
        r"(?i)\.(png|jpe?g|gif|ico|svg|css|woff2?|ttf|eot|mp4|webp|pdf|zip)(\?|$)",
    )
    .unwrap();
    let mut pages: Vec<String> = href
        .captures_iter(html)
        .filter_map(|c| resolve(&c[1]))
        .filter(|u| !static_ext.is_match(u))
        .collect();
    let mut forms = vec![];
    for f in form.captures_iter(html) {
        let action = attr(&f[1], "action")
            .and_then(|a| resolve(&a))
            .unwrap_or_else(|| base_path.to_string());
        let method = attr(&f[1], "method")
            .unwrap_or_else(|| "get".into())
            .to_ascii_uppercase();
        let fields: Vec<String> = input
            .captures_iter(&f[2])
            .filter_map(|i| {
                let name = attr(&i[1], "name")?;
                let value = attr(&i[1], "value")
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| "test".into());
                Some(format!(
                    "{}={}",
                    crate::http::codec::url_encode(name.as_bytes(), false),
                    crate::http::codec::url_encode(value.as_bytes(), false)
                ))
            })
            .collect();
        let qs = fields.join("&");
        if method == "POST" {
            let path = action.clone();
            forms.push(format!(
                "POST {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (BurpCraft Scanner)\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{qs}",
                host_header(t),
                qs.len()
            ));
        } else {
            let sep = if action.contains('?') { '&' } else { '?' };
            pages.push(if qs.is_empty() {
                action
            } else {
                format!("{action}{sep}{qs}")
            });
        }
    }
    pages.dedup();
    (pages, forms)
}

/// Breadth-first crawl from `start`; returns the requests worth auditing (with insertion points).
pub(crate) fn crawl(c: &Ctx, start: &str, status: &Mutex<String>) -> Vec<String> {
    let mut queue = std::collections::VecDeque::from([start.to_string()]);
    let mut seen = std::collections::HashSet::new();
    let mut audit = vec![];
    let shape = |path: &str| {
        // one page per path + parameter names, not per value
        let (p, q) = path.split_once('?').unwrap_or((path, ""));
        let mut names: Vec<&str> = q
            .split('&')
            .map(|kv| kv.split('=').next().unwrap_or(""))
            .collect();
        names.sort();
        format!("{p}?{}", names.join("&"))
    };
    while let Some(path) = queue.pop_front() {
        if seen.len() >= c.cfg.max_pages || c.stop.load(Ordering::SeqCst) {
            break;
        }
        // out-of-scope pages neither count toward max_pages nor get fetched
        if !c.in_scope(&path) || !seen.insert(shape(&path)) {
            continue;
        }
        *status.lock().unwrap() = format!("Crawling: {} pages, {path}", seen.len());
        let req = get_request(&c.target, &path);
        let Some((resp, _)) = c.send_as("Crawler", &req) else {
            continue;
        };
        {
            let mut s = c.state.lock().unwrap();
            let mut e = entry_of(&c.target, &req, &resp, "Crawler");
            e.id = s.next_id;
            s.next_id += 1;
            s.history.push(e);
        }
        c.pages.lock().unwrap().push(path.clone());
        if path.contains('?') {
            audit.push(req);
        }
        let ct =
            crate::http::net::header(&String::from_utf8_lossy(proxy::head(&resp)), "content-type")
                .unwrap_or_default();
        if !ct.contains("html") {
            continue;
        }
        let (pages, forms) = links(&path, &body_text(&resp), &c.target);
        for f in forms {
            if seen.insert(shape(&format!(
                "POST {}",
                f.split_whitespace().nth(1).unwrap_or("")
            ))) {
                audit.push(f);
            }
        }
        queue.extend(pages);
    }
    audit
}
