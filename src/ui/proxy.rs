//! Proxy tab: the sub-tab bar and its screens — Intercept, WebSockets history,
//! Match and replace, and Proxy settings. HTTP history lives in `history.rs`.

use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};

use crate::{App, PROXY_TABS, http::codec, http::net, open_browser, proxy, ui::editor, ui::theme};

impl App {
    pub(crate) fn proxy(&mut self, ui: &mut egui::Ui) {
        theme::frame_chrome().show(ui, |ui| {
            ui.horizontal(|ui| {
                for t in PROXY_TABS {
                    if theme::sub_tab(ui, self.proxy_tab == t, t).clicked() {
                        self.proxy_tab = t;
                    }
                }
            });
        });
        match self.proxy_tab {
            "Intercept" => self.intercept(ui),
            "HTTP history" => self.history(ui),
            "Proxy settings" => self.proxy_settings(ui),
            "WebSockets history" => self.ws_history(ui),
            _ => self.match_replace(ui),
        }
    }
    fn intercept(&mut self, ui: &mut egui::Ui) {
        let (on, front) = {
            let s = self.state.lock().unwrap();
            (
                s.intercept,
                s.queue.front().map(|p| {
                    (
                        p.id * 2 + p.response as usize,
                        p.host.clone(),
                        p.port,
                        p.tls,
                        String::from_utf8_lossy(&p.req).into_owned(),
                    )
                }),
            )
        };
        if let Some((id, _, _, _, req)) = &front
            && self.intercept_text.as_ref().is_none_or(|(i, _)| i != id)
        {
            self.intercept_text = Some((*id, req.clone()));
        }
        let mut decision: Option<Option<Vec<u8>>> = None;
        let mut forward_all = false;
        ui.horizontal(|ui| {
            let has = front.is_some();
            let fwd = theme::split_button(ui, "Forward", has, |ui| {
                if ui
                    .button("Forward all")
                    .on_hover_text("Release every held message; intercept stays on")
                    .clicked()
                {
                    // the message on screen goes as edited, the rest unchanged
                    decision = Some(
                        self.intercept_text
                            .as_ref()
                            .map(|(_, t)| t.clone().into_bytes()),
                    );
                    forward_all = true;
                }
            });
            if fwd.clicked() {
                decision = Some(
                    self.intercept_text
                        .as_ref()
                        .map(|(_, t)| t.clone().into_bytes()),
                );
            }
            if ui.add_enabled(has, egui::Button::new("Drop")).clicked() {
                decision = Some(None);
            }
            let label = if on {
                "Intercept is on"
            } else {
                "Intercept is off"
            };
            let btn = egui::Button::new(RichText::new(label).strong()).selected(on);
            if ui.add(btn).clicked() {
                let mut s = self.state.lock().unwrap();
                s.intercept = !on;
                if on {
                    // turning intercept off releases everything queued unchanged
                    s.forward_all();
                }
            }
            ui.menu_button("Action ...", |ui| {
                if ui.button("Send to Repeater").clicked()
                    && let Some((_, host, port, tls, _)) = &front
                {
                    let txt = self
                        .intercept_text
                        .as_ref()
                        .map(|t| t.1.clone())
                        .unwrap_or_default();
                    self.repeater.add(host.clone(), *port, *tls, txt);
                    self.flash = Some("Repeater");
                }
                if ui.button("Send to Intruder").clicked()
                    && let Some((_, host, port, tls, _)) = &front
                {
                    let txt = self
                        .intercept_text
                        .as_ref()
                        .map(|t| t.1.clone())
                        .unwrap_or_default();
                    self.intruder.add(host.clone(), *port, *tls, txt);
                    self.flash = Some("Intruder");
                }
                if ui.button("Send to Comparer").clicked()
                    && let Some((_, t)) = &self.intercept_text
                {
                    self.comparer.add(t.clone());
                }
            });
            if ui.button("Open browser").clicked() {
                open_browser(&self.state);
            }
            if let Some((_, host, port, tls, _)) = &front {
                let scheme = if *tls { "https" } else { "http" };
                let what = if self
                    .intercept_text
                    .as_ref()
                    .is_some_and(|(id, _)| id % 2 == 1)
                {
                    "Response from"
                } else {
                    "Request to"
                };
                ui.label(
                    RichText::new(format!("{what} {scheme}://{host}:{port}")).color(theme::muted()),
                );
            }
        });
        ui.separator();
        if let Some(d) = decision {
            let mut s = self.state.lock().unwrap();
            if let Some(p) = s.queue.pop_front() {
                let _ = p.reply.send(d);
            }
            if forward_all {
                s.forward_all();
            }
            self.intercept_text = None;
            return;
        }
        match (&front, &mut self.intercept_text) {
            (Some(_), Some((id, text))) => {
                let text_ref: &str = text;
                let req = text_ref.to_owned();
                egui::Panel::right("int_insp")
                    .default_size(260.0)
                    .resizable(true)
                    .show(ui, |ui| editor::inspector(ui, &req, None));
                egui::CentralPanel::default().show(ui, |ui| {
                    let title = if *id % 2 == 1 { "Response" } else { "Request" };
                    editor::message(ui, ("intercept", *id), title, text, true);
                });
            }
            _ => {
                ui.vertical_centered(|ui| {
                    ui.add_space(80.0);
                    let msg = if on { "Waiting for requests…" } else { "Intercept is off" };
                    ui.label(RichText::new(msg).size(18.0).color(theme::muted()));
                    if !on {
                        ui.label(RichText::new("Turn intercept on to hold requests here for inspection and editing.").color(theme::muted()));
                    }
                });
            }
        }
    }
    fn ws_history(&mut self, ui: &mut egui::Ui) {
        let msgs = self.state.lock().unwrap().ws.clone();
        let h = ui.available_height();
        let sel = self.ws_sel;
        let mut clicked = None;
        egui::Panel::top("ws_tbl")
            .resizable(true)
            .default_size(h * 0.5)
            .show(ui, |ui| {
                TableBuilder::new(ui)
                    .id_salt("ws")
                    .striped(true)
                    .sense(egui::Sense::click())
                    .resizable(true)
                    .stick_to_bottom(true)
                    .column(Column::initial(50.0))
                    .column(Column::initial(320.0).clip(true))
                    .column(Column::initial(110.0))
                    .column(Column::initial(60.0))
                    .column(Column::initial(70.0))
                    .column(Column::initial(150.0))
                    .column(Column::remainder())
                    .header(22.0, |mut r| {
                        for c in [
                            "#",
                            "URL",
                            "Direction",
                            "Edited",
                            "Length",
                            "Time",
                            "Message",
                        ] {
                            r.col(|ui| {
                                ui.strong(c);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(20.0, msgs.len(), |mut row| {
                            let m = &msgs[row.index()];
                            row.set_selected(sel == Some(m.id));
                            let preview: String = String::from_utf8_lossy(&m.data)
                                .chars()
                                .take(200)
                                .map(|c| if c.is_control() { ' ' } else { c })
                                .collect();
                            let dir = if m.to_server {
                                "-> To server"
                            } else {
                                "<- To client"
                            };
                            for v in [
                                m.id.to_string(),
                                m.url.clone(),
                                dir.into(),
                                String::new(),
                                m.data.len().to_string(),
                                m.time.clone(),
                                preview,
                            ] {
                                row.col(|ui| {
                                    ui.add(egui::Label::new(v).truncate().selectable(false));
                                });
                            }
                            if row.response().clicked() {
                                clicked = Some(m.id);
                            }
                        });
                    });
            });
        if clicked.is_some() {
            self.ws_sel = clicked;
        }
        if let Some(m) = self.ws_sel.and_then(|id| msgs.iter().find(|m| m.id == id)) {
            let mut text = if m.opcode == 1 {
                String::from_utf8_lossy(&m.data).into_owned()
            } else {
                codec::hexdump_rows(&m.data)
                    .map(|(o, h, a)| format!("{o:08x}  {h:<47}  {a}\n"))
                    .collect()
            };
            egui::CentralPanel::default().show(ui, |ui| {
                editor::message(ui, ("ws", m.id), "Message", &mut text, false);
            });
        } else if msgs.is_empty() {
            ui.label(RichText::new("No WebSockets messages captured yet").color(theme::muted()));
        }
    }
    fn match_replace(&mut self, ui: &mut egui::Ui) {
        theme::heading(ui, "HTTP match and replace rules");
        ui.label("Use these settings to automatically replace parts of requests and responses passing through the Proxy. Patterns are regular expressions.");
        ui.add_space(6.0);
        let mut s = self.state.lock().unwrap();
        let mut remove = None;
        let mut swap = None;
        ui.horizontal(|ui| {
            if ui.button("Add").clicked() {
                s.rules.push(proxy::Rule {
                    enabled: true,
                    kind: 0,
                    pattern: String::new(),
                    replace: String::new(),
                    comment: String::new(),
                });
            }
            if ui.button("Clear").clicked() {
                s.rules.clear();
            }
        });
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("rules")
                .striped(true)
                .num_columns(7)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    for h in ["Enabled", "Item", "Match", "Replace", "Comment", "", ""] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    let n = s.rules.len();
                    for (i, r) in s.rules.iter_mut().enumerate() {
                        ui.checkbox(&mut r.enabled, "");
                        egui::ComboBox::from_id_salt(("kind", i))
                            .selected_text(proxy::RULE_KINDS[r.kind])
                            .width(150.0)
                            .show_ui(ui, |ui| {
                                for (k, name) in proxy::RULE_KINDS.iter().enumerate() {
                                    ui.selectable_value(&mut r.kind, k, *name);
                                }
                            });
                        let bad = !r.pattern.is_empty() && regex::Regex::new(&r.pattern).is_err();
                        let te = egui::TextEdit::singleline(&mut r.pattern)
                            .code_editor()
                            .desired_width(260.0);
                        ui.add(if bad {
                            te.text_color(egui::Color32::RED)
                        } else {
                            te
                        });
                        ui.add(
                            egui::TextEdit::singleline(&mut r.replace)
                                .code_editor()
                                .desired_width(260.0),
                        );
                        ui.add(egui::TextEdit::singleline(&mut r.comment).desired_width(180.0));
                        ui.horizontal(|ui| {
                            if ui.add_enabled(i > 0, egui::Button::new("Up")).clicked() {
                                swap = Some(i - 1);
                            }
                            if ui
                                .add_enabled(i + 1 < n, egui::Button::new("Down"))
                                .clicked()
                            {
                                swap = Some(i);
                            }
                        });
                        if ui.button("Remove").clicked() {
                            remove = Some(i);
                        }
                        ui.end_row();
                    }
                });
        });
        if let Some(i) = swap {
            s.rules.swap(i, i + 1);
        }
        if let Some(i) = remove {
            s.rules.remove(i);
        }
    }
    fn proxy_settings(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            theme::heading(ui, "Proxy listeners");
            ui.label("BurpCraft uses listeners to receive incoming HTTP requests from your browser. You will need to configure your browser to use one of the listeners as its proxy server.");
            let listener = self.state.lock().unwrap().listener;
            egui::Grid::new("listeners").striped(true).num_columns(5).spacing([16.0, 4.0]).show(ui, |ui| {
                for h in ["Running", "Interface", "Invisible", "Redirect", "Certificate"] {
                    ui.strong(h);
                }
                ui.end_row();
                let mut running = listener.is_some();
                ui.add_enabled(false, egui::Checkbox::without_text(&mut running));
                ui.label(format!("127.0.0.1:{}", listener.unwrap_or(8080)));
                ui.label("");
                ui.label("");
                ui.label("Per-host");
                ui.end_row();
            });
            ui.add_space(12.0);
            ui.label("Each installation of BurpCraft generates its own CA certificate that Proxy listeners can use when negotiating TLS connections.");
            if let Some(ca) = &self.ca {
                let path = net::data_dir().join("ca.pem");
                ui.horizontal(|ui| {
                    ui.label("CA certificate (PEM):");
                    ui.monospace(path.display().to_string());
                });
                ui.horizontal(|ui| {
                    if ui.button("Export certificate in DER format").clicked() {
                        let der = net::data_dir().join("cacert.der");
                        let msg = match std::fs::write(&der, &*ca.cert_der) {
                            Ok(()) => format!("CA certificate exported to {}", der.display()),
                            Err(e) => format!("Failed to export CA certificate: {e}"),
                        };
                        self.state.lock().unwrap().event("Proxy", msg);
                    }
                    if ui.button("Copy PEM").clicked() {
                        ui.ctx().copy_text(ca.cert_pem.clone());
                    }
                });
            }
            ui.add_space(12.0);
            theme::heading(ui, "HTTP/2");
            {
                let mut s = self.state.lock().unwrap();
                ui.checkbox(&mut s.http2, "Default to HTTP/2 if the server supports it");
            }
            ui.add_space(12.0);
            theme::heading(ui, "Request interception rules");
            let mut s = self.state.lock().unwrap();
            ui.checkbox(&mut s.intercept, "Intercept requests based on the following rules:");
            egui::Grid::new("irules").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
                ui.label("And URL file extension does not match:");
                let bad = regex::Regex::new(&s.intercept_skip_ext).is_err();
                let te = egui::TextEdit::singleline(&mut s.intercept_skip_ext).code_editor().desired_width(420.0);
                ui.add(if bad { te.text_color(egui::Color32::RED) } else { te });
                ui.end_row();
                ui.label("And domain name contains:");
                ui.add(egui::TextEdit::singleline(&mut s.intercept_host).hint_text("(any host)").desired_width(420.0));
                ui.end_row();
            });
            ui.add_space(8.0);
            theme::heading(ui, "Response interception rules");
            ui.checkbox(&mut s.intercept_responses, "Intercept responses based on the following rules: (all responses)");
        });
    }
}
