//! Shared application state store and the intercept queue item.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, mpsc};

use super::*;

pub struct Pending {
    pub id: usize,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub req: Vec<u8>,
    pub response: bool,
    pub reply: mpsc::Sender<Option<Vec<u8>>>,
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
    /// Items the MCP server asked the UI to open: (entry action, item).
    pub ui_cmds: Vec<(&'static str, Entry)>,
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
            ui_cmds: Vec::new(),
        }))
    }
    /// Releases every held message unchanged.
    pub fn forward_all(&mut self) {
        for p in self.queue.drain(..) {
            let _ = p.reply.send(Some(p.req));
        }
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
    pub(crate) fn repaint(&self) {
        if let Some(c) = &self.ctx {
            c.request_repaint();
        }
    }
}
