//! Dashboard tab: task list, issue activity table, event log, advisory panel,
//! and the "New scan" dialog launched from it.

use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};

use crate::{ai, misc, next_time, openapi, report, scan, scanner, theme, App};

impl App {
    pub(crate) fn scan_window(&mut self, ctx: &egui::Context) {
        let Some((mut urls, mut cfg, mut api, mut at, mut every)) = self.scan_dlg.take() else {
            return;
        };
        let (mut open, mut go) = (true, false);
        theme::window(ctx, "New scan", [560.0, 640.0], &mut open, |ui| {
            ui.label("URLs to scan (one per line):");
            ui.add(
                egui::TextEdit::multiline(&mut urls)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY)
                    .hint_text("https://target.example/"),
            );
            ui.horizontal(|ui| {
                ui.label("Scan configuration:");
                if ui.button("Fast").clicked() {
                    cfg = scan::Config {
                        headers: cfg.headers.clone(),
                        login: cfg.login.clone(),
                        ..scan::Config::fast()
                    };
                }
                if ui
                    .button("Thorough")
                    .on_hover_text("Adds time-based checks and crawls up to 500 pages")
                    .clicked()
                {
                    cfg = scan::Config {
                        headers: cfg.headers.clone(),
                        login: cfg.login.clone(),
                        ..scan::Config::thorough()
                    };
                }
            });
            ui.checkbox(
                &mut cfg.crawl,
                "Crawl from the URLs (otherwise audit them only)",
            );
            egui::Grid::new("checks").num_columns(3).show(ui, |ui| {
                for (i, name) in scan::CHECKS.iter().enumerate() {
                    ui.checkbox(&mut cfg.checks[i], *name);
                    if i % 3 == 2 {
                        ui.end_row();
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("Max pages:");
                ui.add(egui::DragValue::new(&mut cfg.max_pages).range(1..=10_000));
                ui.label("Threads:");
                ui.add(egui::DragValue::new(&mut cfg.threads).range(1..=32));
                ui.label("Delay (ms):");
                ui.add(egui::DragValue::new(&mut cfg.delay_ms).range(0..=10_000));
            });
            ui.collapsing("Authentication", |ui| {
                ui.label("Extra headers on every request (e.g. Authorization: Bearer ...):");
                ui.add(egui::TextEdit::multiline(&mut cfg.headers).desired_rows(2).desired_width(f32::INFINITY));
                ui.label("Login request (raw HTTP, sent first; its Set-Cookie values join every request):");
                ui.add(egui::TextEdit::multiline(&mut cfg.login).code_editor().desired_rows(4).desired_width(f32::INFINITY));
            });
            ui.collapsing("API definition", |ui| {
                ui.label("OpenAPI / Swagger file (JSON or YAML) to audit every operation of:");
                ui.add(
                    egui::TextEdit::singleline(&mut api)
                        .hint_text("/path/to/openapi.yaml")
                        .desired_width(f32::INFINITY),
                );
            });
            ui.collapsing("Schedule", |ui| {
                ui.horizontal(|ui| {
                    ui.label("Start at (HH:MM, empty = now):");
                    ui.add(egui::TextEdit::singleline(&mut at).desired_width(60.0));
                    ui.label("Repeat every");
                    ui.add(egui::DragValue::new(&mut every).range(0..=720));
                    ui.label("hours (0 = once)");
                });
            });
            go = theme::primary_button(
                ui,
                if at.trim().is_empty() {
                    "Scan"
                } else {
                    "Schedule scan"
                },
            )
            .clicked();
        });
        if go {
            let list: Vec<String> = urls
                .lines()
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .map(String::from)
                .collect();
            let mut extra = vec![];
            if !api.trim().is_empty() {
                match openapi::load(api.trim(), list.first().map(String::as_str)) {
                    Ok(reqs) => extra = reqs,
                    Err(e) => self
                        .state
                        .lock()
                        .unwrap()
                        .event("Scanner", format!("API definition: {e}")),
                }
            }
            if let Some(when) = next_time(at.trim()) {
                if !list.is_empty() {
                    self.state.lock().unwrap().event(
                        "Scanner",
                        format!(
                            "Scan of {} scheduled for {}",
                            list.join(", "),
                            when.format("%H:%M %-d %b")
                        ),
                    );
                    self.schedules.push((when, every, list, cfg));
                    return;
                }
            } else if !list.is_empty() || !extra.is_empty() {
                let list = if extra.is_empty() { list } else { vec![] };
                self.start_scan(list, extra, cfg);
                return;
            }
        }
        if open {
            self.scan_dlg = Some((urls, cfg, api, at, every));
        }
    }

    pub(crate) fn dashboard(&mut self, ui: &mut egui::Ui) {
        let h = ui.available_height() / 2.0;
        egui::Panel::top("dash_top").exact_size(h).show(ui, |ui| {
            ui.columns(2, |c| {
                theme::heading(&mut c[0], "Tasks");
                c[0].horizontal(|ui| {
                    if ui.button("New scan").clicked() {
                        self.scan_dlg = Some((String::new(), scan::Config::fast(), String::new(), String::new(), 0));
                    }
                    let live = if self.live_active { "Stop live active audit" } else { "New live task" };
                    if ui.button(live).on_hover_text("Actively audits every new in-scope proxied request that has parameters").clicked() {
                        self.live_active = !self.live_active;
                        self.live_seen = self.state.lock().unwrap().next_id;
                    }
                });
                c[0].separator();
                egui::ScrollArea::vertical().id_salt("tasks").max_height(c[0].available_height() * 0.6).show(&mut c[0], |ui| {
                    for (when, every, urls, _) in &self.schedules {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(format!("Scheduled scan of {}", urls.join(", "))).strong());
                            let rep = if *every > 0 { format!(", then every {every} h") } else { String::new() };
                            ui.label(RichText::new(format!("Next run {}{rep}", when.format("%H:%M %-d %b"))).color(theme::muted()));
                        });
                    }
                    let scans = self.scans.lock().unwrap();
                    for t in scans.iter().rev() {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&t.name).strong());
                                if !t.done.load(std::sync::atomic::Ordering::SeqCst) && ui.small_button("Stop").clicked() {
                                    t.stop.store(true, std::sync::atomic::Ordering::SeqCst);
                                }
                            });
                            ui.label(RichText::new(t.status.lock().unwrap().as_str()).color(theme::muted()));
                            ui.label(format!(
                                "{} requests, {} issues",
                                t.requests.load(std::sync::atomic::Ordering::SeqCst),
                                t.issues.load(std::sync::atomic::Ordering::SeqCst)
                            ));
                        });
                    }
                });
                if self.scans.lock().unwrap().iter().any(|t| !t.done.load(std::sync::atomic::Ordering::SeqCst)) {
                    c[0].ctx().request_repaint_after(std::time::Duration::from_millis(500));
                }
                for (n, (name, desc)) in [
                    ("Live passive crawl from Proxy (all traffic)", "Capturing: adds every proxied item to the site map"),
                    ("Live audit from Proxy (all traffic)", "Passive checks on every proxied response; results appear in Issue activity"),
                    (
                        if self.live_active { "Live active audit from Proxy (in scope): on" } else { "Live active audit from Proxy (in scope): off" },
                        "Attack payloads against every new in-scope request with parameters (New live task)",
                    ),
                ]
                .iter()
                .enumerate()
                {
                    egui::Frame::group(c[0].style()).show(&mut c[0], |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new(format!("{}. {name}", n + 1)).strong());
                        ui.label(RichText::new(*desc).color(theme::muted()));
                    });
                }
                c[1].horizontal(|ui| {
                    theme::heading(ui, "Issue activity");
                    for (html, label) in [(true, "Report (HTML)"), (false, "Export (XML)")] {
                        if ui.button(label).clicked() {
                            let mut s = self.state.lock().unwrap();
                            let msg = match report::write(&s.issues, &s.history, html) {
                                Ok(p) => {
                                    if html {
                                        let _ = misc::open_external(&p);
                                    }
                                    format!("Report written to {}", p.display())
                                }
                                Err(e) => format!("Failed to write report: {e}"),
                            };
                            s.event("Report", msg);
                        }
                    }
                });
                c[1].separator();
                self.issue_table(&mut c[1]);
            });
        });
        ui.columns(2, |c| {
            theme::heading(&mut c[0], "Event log");
            c[0].separator();
            let events = self.state.lock().unwrap().events.clone();
            TableBuilder::new(&mut c[0])
                .id_salt("events")
                .striped(true)
                .column(Column::initial(150.0))
                .column(Column::initial(60.0))
                .column(Column::initial(70.0))
                .column(Column::remainder())
                .header(22.0, |mut r| {
                    for h in ["Time", "Type", "Source", "Message"] {
                        r.col(|ui| {
                            ui.strong(h);
                        });
                    }
                })
                .body(|body| {
                    body.rows(20.0, events.len(), |mut row| {
                        let (t, s, m) = &events[events.len() - 1 - row.index()];
                        let typ = if m.starts_with("Failed") {
                            "Error"
                        } else {
                            "Info"
                        };
                        for v in [t.as_str(), typ, s, m] {
                            row.col(|ui| {
                                ui.label(v);
                            });
                        }
                    });
                });
            theme::heading(&mut c[1], "Advisory");
            c[1].separator();
            self.advisory(&mut c[1]);
        });
    }

    fn issue_table(&mut self, ui: &mut egui::Ui) {
        let mut issues = self.state.lock().unwrap().issues.clone();
        if issues.is_empty() {
            ui.label(
                RichText::new(
                    "No issues. The passive scanner reports issues in proxied traffic here.",
                )
                .color(theme::muted()),
            );
            return;
        }
        issues.sort_by(|a, b| a.severity.cmp(&b.severity).then(b.id.cmp(&a.id)));
        let sel = self.issue_sel;
        let mut clicked = None;
        TableBuilder::new(ui)
            .id_salt("issues")
            .striped(true)
            .sense(egui::Sense::click())
            .resizable(true)
            .column(Column::initial(36.0))
            .column(Column::initial(210.0).clip(true))
            .column(Column::initial(150.0).clip(true))
            .column(Column::initial(110.0).clip(true))
            .column(Column::initial(85.0))
            .column(Column::remainder().at_least(80.0).clip(true))
            .header(22.0, |mut r| {
                for h in ["#", "Issue type", "Host", "Path", "Severity", "Confidence"] {
                    r.col(|ui| {
                        ui.strong(h);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, issues.len(), |mut row| {
                    let i = &issues[row.index()];
                    row.set_selected(sel == Some(i.id));
                    let sev_color = match i.severity {
                        scanner::Severity::High => egui::Color32::from_rgb(0xD0, 0x21, 0x21),
                        scanner::Severity::Medium => theme::ORANGE_DARK,
                        scanner::Severity::Low => egui::Color32::from_rgb(0xB0, 0x8A, 0x00),
                        scanner::Severity::Info => theme::muted(),
                    };
                    row.col(|ui| {
                        ui.label(i.id.to_string());
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(i.name).truncate());
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(&i.origin).truncate());
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(&i.path).truncate());
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(i.severity.label()).color(sev_color).strong());
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(i.confidence).truncate());
                    });
                    if row.response().clicked() {
                        clicked = Some(i.id);
                    }
                });
            });
        if clicked.is_some() {
            self.issue_sel = clicked;
        }
    }

    fn advisory(&mut self, ui: &mut egui::Ui) {
        let issue = self.issue_sel.and_then(|id| {
            self.state
                .lock()
                .unwrap()
                .issues
                .iter()
                .find(|i| i.id == id)
                .cloned()
        });
        let Some(i) = issue else {
            ui.label(RichText::new("No issue selected").color(theme::muted()));
            return;
        };
        egui::ScrollArea::vertical().id_salt("advisory").show(ui, |ui| {
            ui.label(RichText::new(i.name).size(16.0).strong());
            egui::Grid::new("adv").num_columns(2).spacing([12.0, 2.0]).show(ui, |ui| {
                for (k, v) in [("Issue", i.name.to_string()), ("Severity", i.severity.label().into()), ("Confidence", i.confidence.into()), ("Host", i.origin.clone()), ("Path", i.path.clone())] {
                    ui.strong(k);
                    ui.label(v);
                    ui.end_row();
                }
            });
            ui.add_space(6.0);
            for (title, text) in [("Issue detail", i.detail.as_str()), ("Issue background", i.background), ("Issue remediation", i.remediation)] {
                ui.label(RichText::new(title).strong().color(theme::ORANGE_DARK));
                ui.label(text);
                ui.add_space(4.0);
            }
            let evidence = self.state.lock().unwrap().history.iter().find(|e| e.id == i.entry_id).cloned();
            let (ev_req, ev_resp) = evidence.as_ref().map(|e| (e.req.clone(), e.resp.clone())).unwrap_or_default();
            match evidence {
                // scanner evidence is not in the Proxy history: open it in Repeater instead
                Some(e) if e.tool != "Proxy" => {
                    if ui.button("Send evidence request to Repeater").clicked() {
                        self.send_to_repeater(&e);
                        self.tab = "Repeater";
                    }
                }
                _ => {
                    if ui.button("Show request in HTTP history").clicked() {
                        self.tab = "Proxy";
                        self.proxy_tab = "HTTP history";
                        self.selected = Some(i.entry_id);
                    }
                }
            }
            ui.add_space(6.0);
            theme::heading(ui, "BurpCraft AI");
            ui.horizontal(|ui| {
                if std::env::var_os("ANTHROPIC_API_KEY").is_none() {
                    ui.add(egui::TextEdit::singleline(&mut *ai::key().lock().unwrap()).password(true).hint_text("Anthropic API key (kept in memory)").desired_width(220.0));
                }
                let busy = matches!(ai::answers().lock().unwrap().get(&i.id), Some(None));
                if ui
                    .add_enabled(!busy, egui::Button::new("Explain with Claude"))
                    .on_hover_text(format!("Sends this issue and its request/response to the Anthropic API ({})", ai::MODEL))
                    .clicked()
                {
                    ai::explain(i.clone(), ev_req, ev_resp, ui.ctx().clone());
                }
                if busy {
                    ui.spinner();
                }
            });
            match ai::answers().lock().unwrap().get(&i.id) {
                Some(Some(Ok(text))) => {
                    ui.label(text.as_str());
                }
                Some(Some(Err(e))) => {
                    ui.colored_label(egui::Color32::from_rgb(0xC0, 0x30, 0x30), e.as_str());
                }
                _ => {
                    ui.label(RichText::new("Opt-in: the issue and its evidence are sent to Anthropic only when you click.").color(theme::muted()));
                }
            }
        });
    }
}
