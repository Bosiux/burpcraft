//! Collaborator client: generates out-of-band payloads, polls a self-hosted `burpcraft-server`
//! (or one started inside the app) and lists the DNS/HTTP/SMTP interactions they triggered.
//! Global so Intruder and the scanner can mint payloads too.
use std::sync::{Mutex, OnceLock};

use burpcraft_server::{BIID_LEN, Interaction};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};

use crate::theme;

pub struct Client {
    /// Polling address `host:port` of the server's HTTP listener.
    pub server: String,
    /// Payload domain; empty means path-based payloads (`http://server/<id>`), fine for local tests.
    pub domain: String,
    pub secret: String,
    biid: String,
    counter: u64,
    /// (payload id, where it was used)
    issued: Vec<(String, String)>,
    pub interactions: Vec<Interaction>,
    pub error: String,
    embedded: Option<burpcraft_server::Running>,
    poller: bool,
}

/// Tests that configure the global client run one at a time.
#[cfg(test)]
pub static TEST_LOCK: Mutex<()> = Mutex::new(());

pub fn client() -> &'static Mutex<Client> {
    static C: OnceLock<Mutex<Client>> = OnceLock::new();
    C.get_or_init(|| {
        let mut b = [0u8; 8];
        let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
        let biid = base36(u64::from_le_bytes(b), BIID_LEN);
        Mutex::new(Client {
            server: String::new(),
            domain: String::new(),
            secret: String::new(),
            biid,
            counter: 0,
            issued: vec![],
            interactions: vec![],
            error: String::new(),
            embedded: None,
            poller: false,
        })
    })
}

fn base36(mut n: u64, width: usize) -> String {
    let mut s = vec![b'0'; width];
    for c in s.iter_mut().rev() {
        *c = b"0123456789abcdefghijklmnopqrstuvwxyz"[(n % 36) as usize];
        n /= 36;
    }
    String::from_utf8(s).unwrap()
}

impl Client {
    pub fn configured(&self) -> bool {
        !self.server.is_empty()
    }
    /// A fresh payload host (`<id>.<domain>`) or URL path (`<server>/<id>`); `used_by` labels its interactions.
    pub fn payload(&mut self, used_by: &str) -> Option<String> {
        if !self.configured() {
            return None;
        }
        self.counter += 1;
        let id = format!("{}{}", self.biid, base36(self.counter, 6));
        self.issued.push((id.clone(), used_by.to_string()));
        Some(if self.domain.is_empty() {
            format!("{}/{id}", self.server)
        } else {
            format!("{id}.{}", self.domain)
        })
    }
    pub fn used_by(&self, id: &str) -> &str {
        self.issued
            .iter()
            .find(|(i, _)| i == id)
            .map_or("", |(_, u)| u)
    }
}

/// Fetches new interactions; returns how many arrived.
/// Starts burpcraft-server inside the app on localhost (HTTP, path-based payloads) and points the client at it.
pub fn start_builtin() -> Result<String, String> {
    let mut c = client().lock().unwrap();
    if let Some(r) = &c.embedded {
        return Ok(format!("127.0.0.1:{}", r.http_port));
    }
    let r = burpcraft_server::start(burpcraft_server::Config {
        http_port: 0,
        ..Default::default()
    })
    .map_err(|e| format!("Failed to start server: {e}"))?;
    (c.server, c.domain, c.secret) = (
        format!("127.0.0.1:{}", r.http_port),
        String::new(),
        String::new(),
    );
    c.embedded = Some(r);
    Ok(c.server.clone())
}

pub fn poll() -> Result<usize, String> {
    let (server, biid, secret) = {
        let c = client().lock().unwrap();
        if !c.configured() {
            return Err("No Collaborator server configured".into());
        }
        (c.server.clone(), c.biid.clone(), c.secret.clone())
    };
    let (host, port) = server
        .rsplit_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(80)))
        .unwrap_or((server.clone(), 80));
    let req = format!(
        "GET /burpcraft/poll?biid={biid}&secret={} HTTP/1.1\r\nHost: {server}\r\nConnection: close\r\n\r\n",
        crate::codec::url_encode(secret.as_bytes(), false)
    );
    let resp = crate::net::send(&host, port, false, req.as_bytes())
        .map_err(|e| format!("Poll failed: {e}"))?;
    let text = String::from_utf8_lossy(&resp);
    if !text.starts_with("HTTP/1.1 200") && !text.starts_with("HTTP/1.0 200") {
        return Err(format!(
            "Poll refused: {}",
            text.lines().next().unwrap_or("")
        ));
    }
    let got = burpcraft_server::parse_poll(text.split_once("\r\n\r\n").map_or("", |(_, b)| b));
    let n = got.len();
    client().lock().unwrap().interactions.extend(got);
    Ok(n)
}

/// Polls every 5 seconds once a server is configured (like the original's background polling).
fn ensure_poller(ctx: &egui::Context) {
    let mut c = client().lock().unwrap();
    if c.poller {
        return;
    }
    c.poller = true;
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            if client().lock().unwrap().configured() {
                let r = poll();
                let mut c = client().lock().unwrap();
                c.error = r.err().unwrap_or_default();
                ctx.request_repaint();
            }
        }
    });
}

/// Interactions whose payload id was issued for `used_by` (scanner and Intruder look theirs up here).
pub fn interactions_for(used_by_prefix: &str) -> Vec<(Interaction, String)> {
    let c = client().lock().unwrap();
    c.interactions
        .iter()
        .filter_map(|i| {
            Some((i.clone(), c.used_by(&i.id).to_string()))
                .filter(|(_, u)| u.starts_with(used_by_prefix))
        })
        .collect()
}

#[derive(Default)]
pub struct Tab {
    selected: Option<usize>,
    server: String,
    domain: String,
    secret: String,
    loaded: bool,
}

impl Tab {
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        ensure_poller(ui.ctx());
        if !self.loaded {
            let c = client().lock().unwrap();
            (self.server, self.domain, self.secret, self.loaded) =
                (c.server.clone(), c.domain.clone(), c.secret.clone(), true);
        }
        theme::heading(ui, "Collaborator");
        ui.label("Detects out-of-band interactions (DNS, HTTP, SMTP) triggered by your payloads, through a self-hosted burpcraft-server.");
        ui.add_space(6.0);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            egui::Grid::new("collab_cfg").num_columns(2).show(ui, |ui| {
                ui.label("Server (polling host:port):");
                ui.add(egui::TextEdit::singleline(&mut self.server).hint_text("oast.example.com:80 or 127.0.0.1:8053").desired_width(280.0));
                ui.end_row();
                ui.label("Payload domain:");
                ui.add(egui::TextEdit::singleline(&mut self.domain).hint_text("empty: path-based payloads").desired_width(280.0));
                ui.end_row();
                ui.label("Poll secret:");
                ui.add(egui::TextEdit::singleline(&mut self.secret).password(true).desired_width(280.0));
                ui.end_row();
            });
            ui.horizontal(|ui| {
                if ui.button("Apply").clicked() {
                    let mut c = client().lock().unwrap();
                    (c.server, c.domain, c.secret) = (self.server.trim().into(), self.domain.trim().into(), self.secret.clone());
                }
                let running = client().lock().unwrap().embedded.as_ref().map(|r| r.http_port);
                match running {
                    Some(p) => {
                        ui.label(RichText::new(format!("Built-in server running on 127.0.0.1:{p}")).color(theme::muted()));
                    }
                    None => {
                        if ui.button("Start built-in server").on_hover_text("Runs burpcraft-server inside the app on localhost (HTTP, path-based payloads) for testing").clicked() {
                            match start_builtin() {
                                Ok(srv) => (self.server, self.domain, self.secret) = (srv, String::new(), String::new()),
                                Err(e) => client().lock().unwrap().error = e,
                            }
                        }
                    }
                }
            });
        });
        ui.add_space(6.0);
        let configured = client().lock().unwrap().configured();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(configured, egui::Button::new("Copy to clipboard"))
                .on_hover_text("Copies a new payload")
                .clicked()
                && let Some(p) = client().lock().unwrap().payload("Manual")
            {
                ui.ctx().copy_text(p);
            }
            if ui
                .add_enabled(configured, egui::Button::new("Poll now"))
                .clicked()
            {
                let r = poll();
                client().lock().unwrap().error = r.err().unwrap_or_default();
            }
            let err = client().lock().unwrap().error.clone();
            if !err.is_empty() {
                ui.colored_label(egui::Color32::from_rgb(0xC0, 0x30, 0x30), err);
            } else if !configured {
                ui.label(
                    RichText::new(
                        "Configure a server, or start the built-in one, to generate payloads.",
                    )
                    .color(theme::muted()),
                );
            }
        });
        ui.add_space(6.0);
        let c = client().lock().unwrap();
        let rows: Vec<(usize, &Interaction)> = c.interactions.iter().enumerate().rev().collect();
        let h = ui.available_height();
        egui::Panel::top("collab_tbl")
            .resizable(true)
            .default_size(h * 0.5)
            .show(ui, |ui| {
                TableBuilder::new(ui)
                    .id_salt("collab")
                    .striped(true)
                    .sense(egui::Sense::click())
                    .column(Column::initial(50.0))
                    .column(Column::initial(170.0))
                    .column(Column::initial(70.0))
                    .column(Column::initial(240.0))
                    .column(Column::initial(120.0))
                    .column(Column::remainder())
                    .header(22.0, |mut r| {
                        for h in ["#", "Time", "Type", "Payload", "Source IP", "Comment"] {
                            r.col(|ui| {
                                ui.strong(h);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(20.0, rows.len(), |mut row| {
                            let (i, it) = rows[row.index()];
                            row.set_selected(self.selected == Some(i));
                            let time = chrono::DateTime::from_timestamp_millis(it.time_ms as i64)
                                .map(|t| {
                                    t.with_timezone(&chrono::Local)
                                        .format("%H:%M:%S %-d %b")
                                        .to_string()
                                })
                                .unwrap_or_default();
                            for v in [
                                (i + 1).to_string(),
                                time,
                                it.protocol.clone(),
                                it.id.clone(),
                                it.client_ip.clone(),
                                c.used_by(&it.id).to_string(),
                            ] {
                                row.col(|ui| {
                                    ui.label(v);
                                });
                            }
                            if row.response().clicked() {
                                self.selected = Some(i);
                            }
                        });
                    });
            });
        if let Some(it) = self.selected.and_then(|i| c.interactions.get(i)) {
            ui.strong(format!("{} interaction from {}", it.protocol, it.client_ip));
            let mut raw = if it.protocol == "DNS" {
                crate::codec::hexdump_rows(&it.raw)
                    .map(|(o, h, a)| format!("{o:08x}  {h}  {a}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                String::from_utf8_lossy(&it.raw).into_owned()
            };
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut raw)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .interactive(false),
                );
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_and_polling_against_built_in_server() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(base36(35, 3), "00z");
        let srv = burpcraft_server::start(burpcraft_server::Config {
            http_port: 0,
            secret: "k".into(),
            ..Default::default()
        })
        .unwrap();
        let url = {
            let mut c = client().lock().unwrap();
            (c.server, c.secret) = (format!("127.0.0.1:{}", srv.http_port), "k".into());
            format!("http://{}/", c.payload("Scanner: SSRF test").unwrap())
        };
        // the "target" fetches the payload URL
        let path = url.trim_start_matches("http://").split_once('/').unwrap().1;
        crate::net::send(
            "127.0.0.1",
            srv.http_port,
            false,
            format!("GET /{path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
        )
        .unwrap();
        assert_eq!(poll().unwrap(), 1);
        let hits = interactions_for("Scanner:");
        assert_eq!(hits.len(), 1);
        assert_eq!(
            (hits[0].0.protocol.as_str(), hits[0].1.as_str()),
            ("HTTP", "Scanner: SSRF test")
        );
        assert!(url.trim_end_matches('/').ends_with(&hits[0].0.id));
        assert!(interactions_for("Intruder").is_empty());
    }
}
