//! Intruder: § positions, four attack types, payload sets, attack results windows.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};

use crate::{editor, net, proxy, theme, tools};

pub const MARK: char = '§';
const ATTACKS: [&str; 4] = [
    "Sniper attack",
    "Battering ram attack",
    "Pitchfork attack",
    "Cluster bomb attack",
];

#[derive(Clone, PartialEq)]
pub enum Payload {
    List(Vec<String>),
    Numbers {
        from: i64,
        to: i64,
        step: i64,
    },
    /// One payload per line of a file, read when the attack starts.
    RuntimeFile(String),
    /// Every string over `charset` with length min..=max.
    BruteForce {
        charset: String,
        min: usize,
        max: usize,
    },
    /// N empty payloads: repeats the base request.
    Null(usize),
    /// `base` repeated from..=to times (step), for length/overflow tests.
    CharBlocks {
        base: String,
        from: usize,
        to: usize,
        step: usize,
    },
    /// N unique Collaborator payloads, minted when the attack starts.
    Collaborator(usize),
}

pub const PAYLOAD_TYPES: [&str; 7] = [
    "Simple list",
    "Runtime file",
    "Numbers",
    "Brute forcer",
    "Null payloads",
    "Character blocks",
    "Collaborator payloads",
];
const MAX_PAYLOADS: usize = 1_000_000;

impl Payload {
    fn kind(&self) -> usize {
        match self {
            Payload::List(_) => 0,
            Payload::RuntimeFile(_) => 1,
            Payload::Numbers { .. } => 2,
            Payload::BruteForce { .. } => 3,
            Payload::Null(_) => 4,
            Payload::CharBlocks { .. } => 5,
            Payload::Collaborator(_) => 6,
        }
    }
    fn of_kind(k: usize) -> Self {
        match k {
            1 => Payload::RuntimeFile(String::new()),
            2 => Payload::Numbers {
                from: 1,
                to: 10,
                step: 1,
            },
            3 => Payload::BruteForce {
                charset: "abcdefghijklmnopqrstuvwxyz0123456789".into(),
                min: 1,
                max: 3,
            },
            4 => Payload::Null(10),
            5 => Payload::CharBlocks {
                base: "A".into(),
                from: 1,
                to: 1000,
                step: 100,
            },
            6 => Payload::Collaborator(10),
            _ => Payload::List(vec![]),
        }
    }
    /// Values for an attack: like `values`, but Collaborator payloads are minted for real.
    pub fn resolve(&self) -> Vec<String> {
        match self {
            Payload::Collaborator(n) => {
                let mut c = crate::collab::client().lock().unwrap();
                (0..(*n).min(10_000))
                    .filter_map(|_| c.payload("Intruder"))
                    .collect()
            }
            _ => self.values(),
        }
    }
    pub fn values(&self) -> Vec<String> {
        match self {
            Payload::List(v) => v.clone(),
            Payload::RuntimeFile(path) => std::fs::read_to_string(path.trim())
                .map(|t| {
                    t.lines()
                        .filter(|l| !l.is_empty())
                        .take(MAX_PAYLOADS)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default(),
            Payload::Null(n) => vec![String::new(); (*n).min(MAX_PAYLOADS)],
            // placeholders for counting; `resolve` mints the real ones
            Payload::Collaborator(n) => vec!["<collaborator payload>".into(); (*n).min(10_000)],
            Payload::CharBlocks {
                base,
                from,
                to,
                step,
            } => (*from..=*to)
                .step_by((*step).max(1))
                .take(MAX_PAYLOADS)
                .map(|n| base.repeat(n))
                .collect(),
            Payload::BruteForce { charset, min, max } => {
                let chars: Vec<char> = charset.chars().collect();
                let mut out = vec![];
                if chars.is_empty() {
                    return out;
                }
                for len in *min..=*max {
                    // odometer over `len` digits in base chars.len()
                    let mut idx = vec![0usize; len];
                    loop {
                        if out.len() >= MAX_PAYLOADS {
                            return out;
                        }
                        out.push(idx.iter().map(|&i| chars[i]).collect());
                        let Some(i) = (0..len).rev().find(|&i| idx[i] + 1 < chars.len()) else {
                            break;
                        };
                        idx[i] += 1;
                        idx[i + 1..].iter_mut().for_each(|x| *x = 0);
                    }
                }
                out
            }
            Payload::Numbers { from, to, step } => {
                let step = (*step).max(1);
                let mut out = vec![];
                let mut n = *from;
                while (from <= to && n <= *to) || (from > to && n >= *to) {
                    out.push(n.to_string());
                    n += if from <= to { step } else { -step };
                    if out.len() > 1_000_000 {
                        break;
                    }
                }
                out
            }
        }
    }
}

pub const RULES: [&str; 11] = [
    "Add prefix",
    "Add suffix",
    "Match/replace (regex)",
    "URL-encode all characters",
    "Base64-encode",
    "HTML-encode",
    "Hash (MD5, SHA-1, SHA-256)",
    "Reverse",
    "Convert to lower case",
    "Convert to upper case",
    "Skip if matches regex",
];

/// Applies payload processing rules in order; None means the payload is skipped.
pub fn process(rules: &[(usize, String, String)], v: &str) -> Option<String> {
    let mut v = v.to_string();
    for (kind, a, b) in rules {
        v = match kind {
            0 => format!("{a}{v}"),
            1 => format!("{v}{a}"),
            2 => regex::Regex::new(a)
                .map(|re| re.replace_all(&v, b.as_str()).into_owned())
                .unwrap_or(v),
            3 => crate::codec::url_encode(v.as_bytes(), true),
            4 => crate::codec::base64_encode(v.as_bytes()),
            5 => crate::codec::html_encode(v.as_bytes(), false),
            6 => crate::codec::hash(
                if a.trim().is_empty() { "MD5" } else { a.trim() },
                v.as_bytes(),
            ),
            7 => v.chars().rev().collect(),
            8 => v.to_lowercase(),
            9 => v.to_uppercase(),
            _ if regex::Regex::new(a).is_ok_and(|re| re.is_match(&v)) => return None,
            _ => v,
        };
    }
    Some(v)
}

/// Grep settings applied to every response: match terms, extract regexes, reflected payloads.
pub struct Grep {
    pub matches: Vec<String>,
    pub extracts: Vec<regex::Regex>,
    pub payloads: bool,
}

impl Grep {
    pub fn columns(&self) -> Vec<String> {
        let mut c: Vec<String> = self.matches.clone();
        c.extend(self.extracts.iter().map(|r| r.as_str().to_string()));
        if self.payloads {
            c.push("Payload reflected".into());
        }
        c
    }
    /// One cell per column: Yes for a (case-insensitive) match, the first capture group for an extract.
    pub fn cells(&self, resp: &str, payloads: &[String]) -> Vec<String> {
        let low = resp.to_lowercase();
        let mut out: Vec<String> = self
            .matches
            .iter()
            .map(|m| {
                if low.contains(&m.to_lowercase()) {
                    "Yes".into()
                } else {
                    String::new()
                }
            })
            .collect();
        for re in &self.extracts {
            out.push(
                re.captures(resp)
                    .and_then(|c| c.get(1).or_else(|| c.get(0)))
                    .map(|m| m.as_str().chars().take(200).collect())
                    .unwrap_or_default(),
            );
        }
        if self.payloads {
            // payloads are sent URL-encoded; look for the decoded value
            let hit = payloads.iter().any(|p| {
                let raw = String::from_utf8_lossy(&crate::codec::url_decode(p)).into_owned();
                !raw.is_empty() && resp.contains(&raw)
            });
            out.push(if hit { "Yes".into() } else { String::new() });
        }
        out
    }
}

/// Splits a template on § markers: returns literal chunks (positions.len() + 1) and the default value of each position.
pub fn split_positions(t: &str) -> (Vec<String>, Vec<String>) {
    let parts: Vec<&str> = t.split(MARK).collect();
    if parts.len().is_multiple_of(2) {
        return (vec![t.to_string()], vec![]); // unbalanced markers: treat as no positions
    }
    let lits = parts.iter().step_by(2).map(|s| s.to_string()).collect();
    let defs = parts
        .iter()
        .skip(1)
        .step_by(2)
        .map(|s| s.to_string())
        .collect();
    (lits, defs)
}

fn build(lits: &[String], vals: &[String]) -> String {
    let mut s = lits[0].clone();
    for (v, l) in vals.iter().zip(&lits[1..]) {
        s.push_str(v);
        s.push_str(l);
    }
    s
}

/// Generates (payloads shown in the results table, request) for every attack request.
pub fn generate(template: &str, attack: usize, sets: &[Vec<String>]) -> Vec<(Vec<String>, String)> {
    let (lits, defs) = split_positions(template);
    let n = defs.len();
    let mut out = vec![];
    if n == 0 {
        return out;
    }
    let set = |i: usize| sets.get(i).cloned().unwrap_or_default();
    match attack {
        0 => {
            for p in 0..n {
                for v in set(0) {
                    let mut vals = defs.clone();
                    vals[p] = v.clone();
                    out.push((vec![v], build(&lits, &vals)));
                }
            }
        }
        1 => {
            for v in set(0) {
                out.push((vec![v.clone()], build(&lits, &vec![v; n])));
            }
        }
        2 => {
            let len = (0..n).map(|i| set(i).len()).min().unwrap_or(0);
            for k in 0..len {
                let vals: Vec<String> = (0..n).map(|i| set(i)[k].clone()).collect();
                out.push((vals.clone(), build(&lits, &vals)));
            }
        }
        _ => {
            let lists: Vec<Vec<String>> = (0..n).map(set).collect();
            if lists.iter().any(|l| l.is_empty()) {
                return out;
            }
            let mut idx = vec![0usize; n];
            loop {
                let vals: Vec<String> = (0..n).map(|i| lists[i][idx[i]].clone()).collect();
                out.push((vals.clone(), build(&lits, &vals)));
                // first position iterates fastest, like the original
                let mut i = 0;
                loop {
                    if i == n {
                        return out;
                    }
                    idx[i] += 1;
                    if idx[i] < lists[i].len() {
                        break;
                    }
                    idx[i] = 0;
                    i += 1;
                }
            }
        }
    }
    out
}

pub struct Row {
    pub n: usize,
    pub payloads: Vec<String>,
    pub status: u16,
    pub millis: u128,
    pub error: bool,
    pub len: usize,
    pub req: String,
    pub resp: String,
    /// Grep column values.
    pub grep: Vec<String>,
}

pub struct Attack {
    pub title: String,
    pub rows: Arc<Mutex<Vec<Row>>>,
    pub total: usize,
    pub stop: Arc<AtomicBool>,
    pub open: bool,
    grep_cols: Vec<String>,
    selected: Option<usize>,
    sort: Option<(usize, bool)>,
}

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

    /// Results windows; shown from any main tab, like the original's separate attack windows.
    pub fn windows(&mut self, ctx: &egui::Context) {
        for (k, a) in self.attacks.iter_mut().enumerate() {
            if !a.open {
                continue;
            }
            let mut open = true;
            egui::Window::new(format!("Intruder attack {}", a.title)).id(egui::Id::unique(("attack", k))).open(&mut open).default_size([1000.0, 700.0]).show(ctx, |ui| {
                let rows = a.rows.lock().unwrap();
                let done = rows.len();
                ui.horizontal(|ui| {
                    let finished = done >= a.total || a.stop.load(Ordering::SeqCst);
                    if ui.add_enabled(!finished, egui::Button::new("Pause / stop")).clicked() {
                        a.stop.store(true, Ordering::SeqCst);
                    }
                    ui.label(if finished { "Finished".to_string() } else { "Attack running".into() });
                    ui.add(egui::ProgressBar::new(done as f32 / a.total.max(1) as f32).text(format!("{done} of {}", a.total)).desired_width(300.0));
                });
                ui.separator();
                let npay = rows.iter().map(|r| r.payloads.len()).max().unwrap_or(1).max(1);
                let mut order: Vec<usize> = (0..rows.len()).collect();
                if let Some((col, asc)) = a.sort {
                    order.sort_by(|&x, &y| {
                        let (x, y) = (&rows[x], &rows[y]);
                        let o = match col {
                            0 => x.n.cmp(&y.n),
                            1 => x.status.cmp(&y.status),
                            2 => x.millis.cmp(&y.millis),
                            3 => x.len.cmp(&y.len),
                            c => x.grep.get(c - 4).cmp(&y.grep.get(c - 4)),
                        };
                        if asc { o } else { o.reverse() }
                    });
                }
                let sel = a.selected.and_then(|n| rows.iter().find(|r| r.n == n));
                let (req, resp) = sel.map(|r| (r.req.clone(), r.resp.clone())).unwrap_or_default();
                let h = ui.available_height();
                egui::Panel::top(("res_tbl", k)).resizable(true).default_size(h * 0.5).show(ui, |ui| {
                    let mut tb = TableBuilder::new(ui).id_salt(("res", k)).striped(true).sense(egui::Sense::click()).resizable(true);
                    tb = tb.column(Column::initial(70.0));
                    for _ in 0..npay {
                        tb = tb.column(Column::initial(140.0).clip(true));
                    }
                    for _ in 0..5 {
                        tb = tb.column(Column::initial(100.0));
                    }
                    for _ in &a.grep_cols {
                        tb = tb.column(Column::initial(110.0).clip(true));
                    }
                    tb.header(22.0, |mut r| {
                        let sortable = |r: &mut egui_extras::TableRow, name: &str, col: usize, sort: &mut Option<(usize, bool)>| {
                            r.col(|ui| {
                                if ui.add(egui::Label::new(RichText::new(name).strong()).sense(egui::Sense::click())).clicked() {
                                    *sort = Some((col, sort.is_none_or(|(c, asc)| c != col || !asc)));
                                }
                            });
                        };
                        sortable(&mut r, "Request", 0, &mut a.sort);
                        for i in 0..npay {
                            r.col(|ui| {
                                ui.strong(if npay == 1 { "Payload".into() } else { format!("Payload {}", i + 1) });
                            });
                        }
                        sortable(&mut r, "Status code", 1, &mut a.sort);
                        sortable(&mut r, "Response received", 2, &mut a.sort);
                        r.col(|ui| {
                            ui.strong("Error");
                        });
                        r.col(|ui| {
                            ui.strong("Timeout");
                        });
                        sortable(&mut r, "Length", 3, &mut a.sort);
                        for (i, c) in a.grep_cols.iter().enumerate() {
                            sortable(&mut r, c, 4 + i, &mut a.sort);
                        }
                    })
                    .body(|body| {
                        body.rows(20.0, order.len(), |mut row| {
                            let r = &rows[order[row.index()]];
                            row.set_selected(a.selected == Some(r.n));
                            row.col(|ui| {
                                ui.label(r.n.to_string());
                            });
                            for i in 0..npay {
                                row.col(|ui| {
                                    ui.label(r.payloads.get(i).cloned().unwrap_or_default());
                                });
                            }
                            for v in [
                                if r.status == 0 { String::new() } else { r.status.to_string() },
                                r.millis.to_string(),
                                if r.error { "Yes".into() } else { String::new() },
                                String::new(),
                                r.len.to_string(),
                            ]
                            .into_iter()
                            .chain(r.grep.iter().cloned())
                            {
                                row.col(|ui| {
                                    ui.label(v);
                                });
                            }
                            if row.response().clicked() {
                                a.selected = Some(r.n);
                            }
                        });
                    });
                });
                drop(rows);
                let (mut req, mut resp) = (req, resp);
                crate::editor::split(ui, ("ares_req", k), &mut req, false, &mut resp, None);
            });
            if !open {
                a.open = false;
                a.stop.store(true, Ordering::SeqCst);
            }
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

fn intruder_encode(v: &str) -> String {
    v.chars()
        .map(|c| {
            if "./\\=<>?+&*;:\"{}|^`# ".contains(c) {
                format!("%{:02x}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// "Auto §": marks every query/body/cookie parameter value.
pub fn auto_positions(req: &str) -> String {
    let mark = |s: &str, sep: char| -> String {
        s.split(sep)
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) => format!("{k}={MARK}{v}{MARK}"),
                None => kv.to_string(),
            })
            .collect::<Vec<_>>()
            .join(&sep.to_string())
    };
    let (head, body) = match req.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), Some(b.to_string())),
        None => (req.to_string(), None),
    };
    let mut lines: Vec<String> = head.split("\r\n").map(String::from).collect();
    if let Some(first) = lines.first_mut()
        && let Some(q) = first.find('?')
    {
        let end = first[q..].find(' ').map(|e| q + e).unwrap_or(first.len());
        let marked = mark(&first[q + 1..end], '&');
        *first = format!("{}{}{}", &first[..=q], marked, &first[end..]);
    }
    for l in lines.iter_mut().skip(1) {
        if let Some(v) = l.strip_prefix("Cookie: ") {
            *l = format!("Cookie: {}", mark(v, ';'));
        }
    }
    let mut out = lines.join("\r\n");
    if let Some(b) = body {
        out.push_str("\r\n\r\n");
        let form = !b.trim_start().starts_with(['{', '[', '<']) && b.contains('=');
        out.push_str(&if form { mark(&b, '&') } else { b });
    }
    out
}

fn builtin_lists() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "Usernames",
            vec![
                "admin",
                "administrator",
                "root",
                "test",
                "guest",
                "user",
                "info",
                "adm",
                "mysql",
                "oracle",
            ],
        ),
        (
            "Passwords",
            vec![
                "password",
                "123456",
                "12345678",
                "admin",
                "qwerty",
                "letmein",
                "welcome",
                "monkey",
                "password1",
                "abc123",
            ],
        ),
        (
            "Fuzzing - quick",
            vec![
                "'",
                "\"",
                "<",
                ">",
                "'--",
                "\" or 1=1--",
                "<script>alert(1)</script>",
                "../../../../etc/passwd",
                "${7*7}",
                "{{7*7}}",
                "%00",
                "|id",
            ],
        ),
        (
            "Directories - short",
            vec![
                "admin", "login", "api", "backup", "config", "uploads", "images", "js", "css",
                ".git", "test", "dev",
            ],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_types() {
        let t = "a=§1§&b=§2§";
        let s = vec![
            vec!["x".into(), "y".into()],
            vec!["p".into(), "q".into(), "r".into()],
        ];
        let sn: Vec<String> = generate(t, 0, &s).into_iter().map(|j| j.1).collect();
        assert_eq!(sn, ["a=x&b=2", "a=y&b=2", "a=1&b=x", "a=1&b=y"]);
        let br: Vec<String> = generate(t, 1, &s).into_iter().map(|j| j.1).collect();
        assert_eq!(br, ["a=x&b=x", "a=y&b=y"]);
        let pf: Vec<String> = generate(t, 2, &s).into_iter().map(|j| j.1).collect();
        assert_eq!(pf, ["a=x&b=p", "a=y&b=q"]);
        assert_eq!(generate(t, 3, &s).len(), 6);
        assert_eq!(
            Payload::Numbers {
                from: 3,
                to: 1,
                step: 1
            }
            .values(),
            ["3", "2", "1"]
        );
        assert_eq!(
            auto_positions("GET /?a=1&b=2 HTTP/1.1\r\nHost: h\r\n\r\n"),
            "GET /?a=§1§&b=§2§ HTTP/1.1\r\nHost: h\r\n\r\n"
        );
    }

    #[test]
    fn pro_payloads_processing_grep() {
        assert_eq!(
            Payload::BruteForce {
                charset: "ab".into(),
                min: 1,
                max: 2
            }
            .values(),
            ["a", "b", "aa", "ab", "ba", "bb"]
        );
        assert_eq!(Payload::Null(3).values(), ["", "", ""]);
        assert_eq!(
            Payload::CharBlocks {
                base: "A".into(),
                from: 1,
                to: 5,
                step: 2
            }
            .values(),
            ["A", "AAA", "AAAAA"]
        );
        assert!(
            Payload::RuntimeFile("/nonexistent".into())
                .values()
                .is_empty()
        );
        let rules = vec![
            (0, "<".into(), String::new()),
            (2, "b+".into(), "X".into()),
            (9, String::new(), String::new()),
        ];
        assert_eq!(process(&rules, "abbc").as_deref(), Some("<AXC"));
        assert_eq!(
            process(&[(6, "SHA-256".into(), String::new())], "a")
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            process(&[(10, "^skip".into(), String::new())], "skip me"),
            None
        );
        let g = Grep {
            matches: vec!["SQL syntax".into()],
            extracts: vec![regex::Regex::new("<title>(.*?)</title>").unwrap()],
            payloads: true,
        };
        assert_eq!(
            g.columns(),
            ["SQL syntax", "<title>(.*?)</title>", "Payload reflected"]
        );
        assert_eq!(
            g.cells(
                "<title>Err</title> You have an error in your sql syntax near '<x>'",
                &["%3cx%3e".into()]
            ),
            ["Yes", "Err", "Yes"]
        );
        assert_eq!(g.cells("ok", &["zz".into()]), ["", "", ""]);
    }
}
