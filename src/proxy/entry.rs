//! The `Entry` record for one request/response exchange in history and the logger.
use super::*;
use crate::net;

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
