//! The Intruder tab UI, tab state, and the threaded attack runner.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use eframe::egui::{self, RichText};

use crate::{editor, net, proxy, theme, tools};

use super::*;

pub struct IntruderTab {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub template: String,
    attack: usize,
    payload_set: usize,
    payloads: Vec<Payload>,
    list_input: String,
    url_encode: bool,
    threads: usize,
    /// Payload processing rules: (rule, argument, replacement).
    processing: Vec<(usize, String, String)>,
    new_rule: (usize, String, String),
    grep_match: String,
    grep_extract: String,
    grep_payloads: bool,
}

#[derive(Default)]
pub struct Intruder {
    pub tabs: Vec<IntruderTab>,
    current: usize,
    counter: usize,
    pub attacks: Vec<Attack>,
}

impl Intruder {
    pub fn add(&mut self, host: String, port: u16, tls: bool, req: String) {
        self.counter += 1;
        let template = auto_positions(&req);
        self.tabs.push(IntruderTab {
            name: self.counter.to_string(),
            host,
            port,
            tls,
            template,
            attack: 0,
            payload_set: 0,
            payloads: vec![Payload::List(vec![])],
            list_input: String::new(),
            url_encode: true,
            threads: 4,
            processing: vec![],
            new_rule: (0, String::new(), String::new()),
            grep_match: String::new(),
            grep_extract: String::new(),
            grep_payloads: false,
        });
        self.current = self.tabs.len() - 1;
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, state: &proxy::State) {
        if self.tabs.is_empty() {
            self.add(String::new(), 80, false, String::new());
        }
        ui.horizontal(|ui| {
            let mut close = None;
            for (i, t) in self.tabs.iter().enumerate() {
                if theme::sub_tab(ui, i == self.current, &t.name).clicked() {
                    self.current = i;
                }
                if ui.small_button("×").clicked() {
                    close = Some(i);
                }
            }
            if ui.button("+").clicked() {
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
        let (_, defs) = split_positions(&t.template);
        let npos = defs.len();
        let nsets = if t.attack < 2 { 1 } else { npos.max(1) };
        t.payloads.resize(nsets, Payload::List(vec![]));
        t.payload_set = t.payload_set.min(nsets - 1);

        let mut start = false;
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("attack_type")
                .selected_text(ATTACKS[t.attack])
                .width(190.0)
                .show_ui(ui, |ui| {
                    for (i, a) in ATTACKS.iter().enumerate() {
                        ui.selectable_value(&mut t.attack, i, *a);
                    }
                });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                start = theme::primary_button(ui, "Start attack").clicked();
                ui.add(
                    egui::TextEdit::singleline(&mut t.host)
                        .desired_width(200.0)
                        .hint_text("host"),
                );
                ui.label("Target:");
                ui.checkbox(&mut t.tls, "HTTPS");
                let mut p = t.port.to_string();
                if ui
                    .add(egui::TextEdit::singleline(&mut p).desired_width(50.0))
                    .changed()
                {
                    t.port = p.parse().unwrap_or(t.port);
                }
                ui.label("Port:");
            });
        });
        ui.separator();

        egui::Panel::right("payloads").default_size(380.0).resizable(true).show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                theme::heading(ui, "Payloads");
                ui.horizontal(|ui| {
                    ui.label("Payload position:");
                    egui::ComboBox::from_id_salt("pset").selected_text(format!("{}", t.payload_set + 1)).show_ui(ui, |ui| {
                        for i in 0..nsets {
                            ui.selectable_value(&mut t.payload_set, i, format!("{}", i + 1));
                        }
                    });
                });
                let req_count = generate(&t.template, t.attack, &t.payloads.iter().map(|p| p.values()).collect::<Vec<_>>()).len();
                let p = &mut t.payloads[t.payload_set];
                ui.horizontal(|ui| {
                    ui.label("Payload type:");
                    let kind = p.kind();
                    egui::ComboBox::from_id_salt("ptype").selected_text(PAYLOAD_TYPES[kind]).show_ui(ui, |ui| {
                        for (k, name) in PAYLOAD_TYPES.iter().enumerate() {
                            if ui.selectable_label(k == kind, *name).clicked() && k != kind {
                                *p = Payload::of_kind(k);
                            }
                        }
                    });
                });
                let count = p.values().len();
                ui.label(format!("Payload count: {count}    Request count: {}", req_count));
                ui.separator();
                ui.strong("Payload configuration");
                match p {
                    Payload::List(items) => {
                        ui.horizontal_top(|ui| {
                            ui.vertical(|ui| {
                                if ui.add_sized([80.0, 22.0], egui::Button::new("Paste")).clicked() {
                                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                                }
                                if ui.add_sized([80.0, 22.0], egui::Button::new("Remove")).clicked() {
                                    items.pop();
                                }
                                if ui.add_sized([80.0, 22.0], egui::Button::new("Clear")).clicked() {
                                    items.clear();
                                }
                            });
                            egui::Frame::new().stroke(egui::Stroke::new(1.0, theme::border())).inner_margin(4).show(ui, |ui| {
                                ui.set_min_size(egui::vec2(240.0, 160.0));
                                egui::ScrollArea::vertical().id_salt("plist").max_height(160.0).show(ui, |ui| {
                                    for it in items.iter() {
                                        ui.monospace(it);
                                    }
                                });
                            });
                        });
                        ui.horizontal(|ui| {
                            if ui.add_sized([80.0, 22.0], egui::Button::new("Add")).clicked() && !t.list_input.is_empty() {
                                // multi-line input adds one payload per line
                                items.extend(t.list_input.lines().filter(|l| !l.is_empty()).map(String::from));
                                t.list_input.clear();
                            }
                            ui.add(egui::TextEdit::singleline(&mut t.list_input).hint_text("Enter a new item").desired_width(240.0));
                        });
                        ui.menu_button("Add from list ...", |ui| {
                            for (name, vals) in builtin_lists() {
                                if ui.button(name).clicked() {
                                    items.extend(vals.iter().map(|s| s.to_string()));
                                    ui.close();
                                }
                            }
                        });
                    }
                    Payload::Numbers { from, to, step } => {
                        egui::Grid::new("nums").num_columns(2).show(ui, |ui| {
                            ui.label("From:");
                            ui.add(egui::DragValue::new(from));
                            ui.end_row();
                            ui.label("To:");
                            ui.add(egui::DragValue::new(to));
                            ui.end_row();
                            ui.label("Step:");
                            ui.add(egui::DragValue::new(step).range(1..=i64::MAX));
                            ui.end_row();
                        });
                    }
                    Payload::RuntimeFile(path) => {
                        ui.label("File (one payload per line, read when the attack starts):");
                        ui.add(egui::TextEdit::singleline(path).hint_text("/path/to/wordlist.txt").desired_width(320.0));
                    }
                    Payload::BruteForce { charset, min, max } => {
                        egui::Grid::new("brute").num_columns(2).show(ui, |ui| {
                            ui.label("Character set:");
                            ui.add(egui::TextEdit::singleline(charset).desired_width(240.0));
                            ui.end_row();
                            ui.label("Min length:");
                            ui.add(egui::DragValue::new(min).range(0..=8));
                            ui.end_row();
                            ui.label("Max length:");
                            ui.add(egui::DragValue::new(max).range(0..=8));
                            ui.end_row();
                        });
                    }
                    Payload::Collaborator(n) => {
                        ui.horizontal(|ui| {
                            ui.label("Generate");
                            ui.add(egui::DragValue::new(n).range(1..=10_000));
                            ui.label("unique Collaborator payloads");
                        });
                        if !crate::collab::client().lock().unwrap().configured() {
                            ui.label(RichText::new("No Collaborator server configured (see the Collaborator tab)").color(theme::muted()));
                        }
                    }
                    Payload::Null(n) => {
                        ui.horizontal(|ui| {
                            ui.label("Generate");
                            ui.add(egui::DragValue::new(n).range(1..=MAX_PAYLOADS));
                            ui.label("payloads");
                        });
                    }
                    Payload::CharBlocks { base, from, to, step } => {
                        egui::Grid::new("blocks").num_columns(2).show(ui, |ui| {
                            ui.label("Base string:");
                            ui.add(egui::TextEdit::singleline(base).desired_width(120.0));
                            ui.end_row();
                            ui.label("Min length:");
                            ui.add(egui::DragValue::new(from));
                            ui.end_row();
                            ui.label("Max length:");
                            ui.add(egui::DragValue::new(to));
                            ui.end_row();
                            ui.label("Step:");
                            ui.add(egui::DragValue::new(step).range(1..=usize::MAX));
                            ui.end_row();
                        });
                    }
                }
                ui.separator();
                ui.strong("Payload processing");
                let mut remove = None;
                for (i, (k, a, b)) in t.processing.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if ui.small_button("×").clicked() {
                            remove = Some(i);
                        }
                        let arg = if *k == 2 { format!("{a} → {b}") } else { a.clone() };
                        ui.label(format!("{}{}", RULES[*k], if arg.is_empty() { String::new() } else { format!(": {arg}") }));
                    });
                }
                if let Some(i) = remove {
                    t.processing.remove(i);
                }
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("prule").selected_text(RULES[t.new_rule.0]).width(170.0).show_ui(ui, |ui| {
                        for (i, r) in RULES.iter().enumerate() {
                            ui.selectable_value(&mut t.new_rule.0, i, *r);
                        }
                    });
                    let hint = match t.new_rule.0 {
                        6 => "MD5",
                        0..=2 | 10 => "value / regex",
                        _ => "",
                    };
                    if !hint.is_empty() {
                        ui.add(egui::TextEdit::singleline(&mut t.new_rule.1).hint_text(hint).desired_width(90.0));
                    }
                    if t.new_rule.0 == 2 {
                        ui.add(egui::TextEdit::singleline(&mut t.new_rule.2).hint_text("replace").desired_width(70.0));
                    }
                    if ui.button("Add").clicked() {
                        let kind = t.new_rule.0;
                        t.processing.push(std::mem::replace(&mut t.new_rule, (kind, String::new(), String::new())));
                    }
                });
                ui.separator();
                ui.strong("Payload encoding");
                ui.checkbox(&mut t.url_encode, "URL-encode these characters: ./\\=<>?+&*;:\"{}|^`#");
                ui.separator();
                theme::heading(ui, "Grep - Match");
                ui.label(RichText::new("Flag responses containing these terms (one per line, case-insensitive)").color(theme::muted()));
                ui.add(egui::TextEdit::multiline(&mut t.grep_match).desired_rows(3).desired_width(320.0).hint_text("error\nexception\nsql syntax"));
                theme::heading(ui, "Grep - Extract");
                ui.label(RichText::new("Show the first capture group of each regex (one per line)").color(theme::muted()));
                ui.add(egui::TextEdit::multiline(&mut t.grep_extract).desired_rows(2).desired_width(320.0).hint_text("<title>(.*?)</title>"));
                theme::heading(ui, "Grep - Payloads");
                ui.checkbox(&mut t.grep_payloads, "Flag responses that reflect the payload");
                ui.separator();
                theme::heading(ui, "Resource pool");
                ui.horizontal(|ui| {
                    ui.label("Maximum concurrent requests:");
                    ui.add(egui::DragValue::new(&mut t.threads).range(1..=50));
                });
            });
        });

        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal(|ui| {
                theme::heading(ui, "Positions");
                ui.label(
                    RichText::new(format!(
                        "{npos} payload position{}",
                        if npos == 1 { "" } else { "s" }
                    ))
                    .color(theme::muted()),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Auto §").clicked() {
                        t.template = auto_positions(&t.template.replace(MARK, ""));
                    }
                    if ui.button("Clear §").clicked() {
                        t.template = t.template.replace(MARK, "");
                    }
                    if ui
                        .button("Add §")
                        .on_hover_text("Wraps the selection, or inserts a marker at the cursor")
                        .clicked()
                    {
                        let id = ui
                            .make_persistent_id(("intr_tpl", t.name.as_str()))
                            .with("te");
                        if let Some(st) = egui::TextEdit::load_state(ui.ctx(), id)
                            && let Some(r) = st.cursor.char_range()
                        {
                            let (a, b) = (
                                r.primary.index.0.min(r.secondary.index.0),
                                r.primary.index.0.max(r.secondary.index.0),
                            );
                            let chars: Vec<char> = t.template.chars().collect();
                            // the saved cursor can outlive a shorter template (Clear §, paste)
                            let (a, b) = (a.min(chars.len()), b.min(chars.len()));
                            let mut s: String = chars[..a].iter().collect();
                            s.push(MARK);
                            s.extend(&chars[a..b]);
                            s.push(MARK);
                            s.extend(&chars[b..]);
                            t.template = s;
                        }
                    }
                });
            });
            editor::message(ui, ("intr_tpl", t.name.as_str()), "", &mut t.template, true);
        });

        if start {
            let t = &self.tabs[self.current];
            let sets: Vec<Vec<String>> = t
                .payloads
                .iter()
                .map(|p| {
                    p.resolve()
                        .into_iter()
                        .filter_map(|v| process(&t.processing, &v))
                        .map(|v| if t.url_encode { intruder_encode(&v) } else { v })
                        .collect()
                })
                .collect();
            let grep = Arc::new(Grep {
                matches: t
                    .grep_match
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(String::from)
                    .collect(),
                extracts: t
                    .grep_extract
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .filter_map(|l| regex::Regex::new(l).ok())
                    .collect(),
                payloads: t.grep_payloads,
            });
            let grep_cols = grep.columns();
            let jobs = generate(&t.template, t.attack, &sets);
            let base = t.template.replace(MARK, "");
            let mut jobs: Vec<(Vec<String>, String)> = jobs;
            jobs.insert(0, (vec![], base));
            let rows = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let total = jobs.len();
            let jobs = Arc::new(jobs);
            let next = Arc::new(AtomicUsize::new(0));
            for _ in 0..t.threads {
                let (jobs, next, rows, stop, grep) = (
                    jobs.clone(),
                    next.clone(),
                    rows.clone(),
                    stop.clone(),
                    grep.clone(),
                );
                let (host, port, tls, ctx, state) = (
                    t.host.clone(),
                    t.port,
                    t.tls,
                    ui.ctx().clone(),
                    state.clone(),
                );
                std::thread::spawn(move || {
                    loop {
                        let i = next.fetch_add(1, Ordering::SeqCst);
                        if i >= jobs.len() || stop.load(Ordering::SeqCst) {
                            break;
                        }
                        let (payloads, req) = &jobs[i];
                        let req = tools::fix_content_length(
                            &req.replace("\r\n", "\n").replace('\n', "\r\n"),
                        );
                        let t0 = Instant::now();
                        let res = net::send(&host, port, tls, req.as_bytes());
                        let millis = t0.elapsed().as_millis();
                        let (resp, error) = match res {
                            Ok(b) => (b, false),
                            Err(e) => (e.to_string().into_bytes(), true),
                        };
                        if !error {
                            state.lock().unwrap().log_tool(
                                "Intruder",
                                &host,
                                port,
                                tls,
                                req.as_bytes(),
                                &resp,
                            );
                        }
                        let status = if error {
                            0
                        } else {
                            String::from_utf8_lossy(proxy::head(&resp))
                                .split_whitespace()
                                .nth(1)
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0)
                        };
                        let text = proxy::display(&resp);
                        let grep = if error {
                            vec![String::new(); grep.columns().len()]
                        } else {
                            grep.cells(&text, payloads)
                        };
                        let row = Row {
                            n: i,
                            payloads: payloads.clone(),
                            status,
                            millis,
                            error,
                            len: if error { 0 } else { resp.len() },
                            req,
                            resp: text,
                            grep,
                        };
                        let mut r = rows.lock().unwrap();
                        let pos = r.partition_point(|x: &Row| x.n < i);
                        r.insert(pos, row);
                        ctx.request_repaint();
                    }
                });
            }
            let title = format!(
                "{} {} to {}",
                self.attacks.len() + 1,
                ATTACKS[t.attack],
                t.host
            );
            self.attacks.push(Attack {
                title,
                rows,
                total,
                stop,
                open: true,
                grep_cols,
                selected: None,
                sort: None,
            });
        }
    }
    /// Pasted text goes into the current payload list (multi-line = many payloads).
    pub fn paste(&mut self, text: &str) {
        if let Some(t) = self.tabs.get_mut(self.current)
            && let Some(Payload::List(items)) = t.payloads.get_mut(t.payload_set)
        {
            items.extend(text.lines().filter(|l| !l.is_empty()).map(String::from));
        }
    }
}
