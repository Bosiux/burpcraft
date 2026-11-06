use std::sync::mpsc;
use std::time::Instant;

use eframe::egui::{self, RichText};

use crate::{ui::editor, http::net, proxy, ui::theme};

pub struct RepeaterTab {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub req: String,
    pub resp: String,
    status: String,
    rx: Option<mpsc::Receiver<(Result<Vec<u8>, String>, u128)>>,
    started: Option<Instant>,
    hist: Vec<(String, String)>,
    pos: usize,
}

impl RepeaterTab {
    pub fn new(name: String, host: String, port: u16, tls: bool, req: String) -> Self {
        Self {
            name,
            host,
            port,
            tls,
            req,
            resp: String::new(),
            status: String::new(),
            rx: None,
            started: None,
            hist: vec![],
            pos: 0,
        }
    }
    fn target(&self) -> String {
        let def = if self.tls { 443 } else { 80 };
        let scheme = if self.tls { "https" } else { "http" };
        if self.port == def {
            format!("{scheme}://{}", self.host)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }
}

#[derive(Default)]
pub struct Repeater {
    pub tabs: Vec<RepeaterTab>,
    pub current: usize,
    counter: usize,
    editing_target: Option<(String, String, bool)>,
}

impl Repeater {
    pub fn add(&mut self, host: String, port: u16, tls: bool, req: String) {
        self.counter += 1;
        self.tabs.push(RepeaterTab::new(
            self.counter.to_string(),
            host,
            port,
            tls,
            req,
        ));
        self.current = self.tabs.len() - 1;
    }

    pub fn send_current(&mut self, ctx: &egui::Context) {
        if let Some(t) = self.tabs.get_mut(self.current)
            && t.rx.is_none()
            && !t.host.is_empty()
        {
            send(t, ctx.clone());
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, state: &proxy::State) {
        if self.tabs.is_empty() {
            self.add(String::new(), 80, false, String::new());
        }
        // tab strip: "1 ×  2 ×  +"
        ui.horizontal(|ui| {
            let mut close = None;
            for (i, t) in self.tabs.iter().enumerate() {
                if theme::sub_tab(ui, i == self.current, &t.name).clicked() {
                    self.current = i;
                }
                if ui.small_button("×").on_hover_text("Close tab").clicked() {
                    close = Some(i);
                }
            }
            if ui.button("+").on_hover_text("New tab").clicked() {
                self.add(String::new(), 80, false, String::new());
            }
            if let Some(i) = close {
                self.tabs.remove(i);
                self.current = self.current.min(self.tabs.len().saturating_sub(1));
            }
        });
        if self.tabs.is_empty() {
            return;
        }
        ui.separator();
        let t = &mut self.tabs[self.current];

        if let Some(rx) = &t.rx
            && let Ok((res, ms)) = rx.try_recv()
        {
            match res {
                Ok(bytes) => {
                    t.resp = proxy::display(&bytes);
                    t.status = format!("{} bytes | {} millis", bytes.len(), ms);
                    let mut s = state.lock().unwrap();
                    s.log_tool("Repeater", &t.host, t.port, t.tls, t.req.as_bytes(), &bytes);
                }
                Err(e) => {
                    t.resp = String::new();
                    t.status = e;
                }
            }
            t.rx = None;
            t.hist.truncate(t.pos);
            t.hist.push((t.req.clone(), t.resp.clone()));
            t.pos = t.hist.len();
        }

        // toolbar
        ui.horizontal(|ui| {
            let busy = t.rx.is_some();
            if theme::primary_button(ui, "Send").clicked() && !busy && !t.host.is_empty() {
                send(t, ui.ctx().clone());
            }
            if ui.add_enabled(busy, egui::Button::new("Cancel")).clicked() {
                t.rx = None;
                t.status = "Cancelled".into();
            }
            if ui
                .add_enabled(t.pos > 1, egui::Button::new("<"))
                .on_hover_text("Previous request")
                .clicked()
            {
                t.pos -= 1;
                (t.req, t.resp) = t.hist[t.pos - 1].clone();
            }
            if ui
                .add_enabled(t.pos < t.hist.len(), egui::Button::new(">"))
                .on_hover_text("Next request")
                .clicked()
            {
                t.pos += 1;
                (t.req, t.resp) = t.hist[t.pos - 1].clone();
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let h2 = net::is_h2(t.req.as_bytes());
                let proto = if h2 { "HTTP/2" } else { "HTTP/1" };
                if ui
                    .button(proto)
                    .on_hover_text("Request protocol: click to switch HTTP/1 / HTTP/2")
                    .clicked()
                {
                    t.req = set_protocol(&t.req, !h2);
                }
                if ui
                    .button("Edit")
                    .on_hover_text("Configure target details")
                    .clicked()
                {
                    self.editing_target = Some((t.host.clone(), t.port.to_string(), t.tls));
                }
                let target = if t.host.is_empty() {
                    "Not specified".into()
                } else {
                    t.target()
                };
                ui.label(RichText::new(format!("Target: {target}")).strong());
            });
        });

        if let Some((h, p, tls)) = &mut self.editing_target {
            let mut open = true;
            let mut done = false;
            theme::window(
                ui.ctx(),
                "Configure target details",
                [420.0, 200.0],
                &mut open,
                |ui| {
                    ui.label(
                        "Specify the details of the server to which the request will be sent.",
                    );
                    egui::Grid::new("tgt").num_columns(2).show(ui, |ui| {
                        ui.label("Host:");
                        ui.text_edit_singleline(h);
                        ui.end_row();
                        ui.label("Port:");
                        ui.text_edit_singleline(p);
                        ui.end_row();
                    });
                    ui.checkbox(tls, "Use HTTPS");
                    ui.horizontal(|ui| {
                        if theme::primary_button(ui, "OK").clicked() {
                            done = true;
                        }
                    });
                },
            );
            if done {
                t.host = h.trim().to_string();
                t.port = p.trim().parse().unwrap_or(if *tls { 443 } else { 80 });
                t.tls = *tls;
            }
            if done || !open {
                self.editing_target = None;
            }
        }

        let t = &mut self.tabs[self.current];
        egui::Panel::bottom("rep_status").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(if t.rx.is_some() { "Waiting…" } else { "Done" });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(&t.status)
                });
            });
        });
        egui::Panel::right("rep_inspector")
            .default_size(260.0)
            .resizable(true)
            .show(ui, |ui| {
                editor::inspector(ui, &t.req, Some(&t.resp));
            });
        let base = format!(
            "{}{}",
            t.target(),
            t.req.split_whitespace().nth(1).unwrap_or("/")
        );
        crate::ui::editor::split(
            ui,
            ("rep_req", t.name.as_str()),
            &mut t.req,
            true,
            &mut t.resp,
            Some(&base),
        );
    }
}

fn send(t: &mut RepeaterTab, ctx: egui::Context) {
    let (tx, rx) = mpsc::channel();
    // keep Content-Length honest after edits, like the original's default "Update Content-Length"
    let req = fix_content_length(&t.req.replace("\r\n", "\n").replace('\n', "\r\n"));
    t.req = req.clone();
    let (host, port, tls) = (t.host.clone(), t.port, t.tls);
    t.rx = Some(rx);
    t.started = Some(Instant::now());
    std::thread::spawn(move || {
        let start = Instant::now();
        let r = net::send(&host, port, tls, req.as_bytes()).map_err(|e| e.to_string());
        let _ = tx.send((r, start.elapsed().as_millis()));
        ctx.request_repaint();
    });
}

/// Rewrites the request line version (and converts headers) when toggling HTTP/1 <-> HTTP/2.
pub fn set_protocol(req: &str, h2: bool) -> String {
    if h2 {
        return crate::http::h2up::to_h2_text(req.as_bytes())
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|| req.into());
    }
    let (first, rest) = req.split_once("\r\n").unwrap_or((req, ""));
    let first = first
        .strip_suffix(" HTTP/2")
        .map(|f| format!("{f} HTTP/1.1"))
        .unwrap_or_else(|| first.to_string());
    format!("{first}\r\n{rest}")
}

pub fn fix_content_length(req: &str) -> String {
    let Some((head, body)) = req.split_once("\r\n\r\n") else {
        return format!("{}\r\n\r\n", req.trim_end());
    };
    let mut out: Vec<String> = Vec::new();
    let mut had = false;
    for l in head.lines() {
        if l.split(':')
            .next()
            .is_some_and(|k| k.trim().eq_ignore_ascii_case("content-length"))
        {
            had = true;
            out.push(format!("Content-Length: {}", body.len()));
        } else {
            out.push(l.to_string());
        }
    }
    if !had && !body.is_empty() {
        out.push(format!("Content-Length: {}", body.len()));
    }
    format!("{}\r\n\r\n{body}", out.join("\r\n"))
}
