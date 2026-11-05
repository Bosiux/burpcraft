//! Repeater, Decoder and Comparer.
use std::sync::mpsc;
use std::time::Instant;

use eframe::egui::{self, Color32, RichText};

use crate::{codec, editor, net, proxy, theme};

// ------------------------------------------------------------------ Repeater

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
            egui::Window::new("Configure target details")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ui.ctx(), |ui| {
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
                });
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
        crate::editor::split(
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
        return crate::h2up::to_h2_text(req.as_bytes())
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

// ------------------------------------------------------------------ Decoder

const DECODE: [&str; 6] = ["URL", "HTML", "Base64", "ASCII hex", "Hex", "Gzip"];
const ENCODE: [&str; 8] = [
    "URL",
    "HTML",
    "Base64",
    "ASCII hex",
    "Hex",
    "Octal",
    "Binary",
    "Gzip",
];
const HASHES: [&str; 5] = ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"];

pub struct Decoder {
    pub panes: Vec<(String, bool)>, // (text, hex view)
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            panes: vec![(String::new(), false)],
        }
    }
}

impl Decoder {
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        let mut action: Option<(usize, String)> = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for (i, (text, hexv)) in self.panes.iter_mut().enumerate() {
                    ui.horizontal_top(|ui| {
                        let w = ui.available_width() - 200.0;
                        egui::Frame::new()
                            .stroke(egui::Stroke::new(1.0, theme::border()))
                            .inner_margin(4)
                            .show(ui, |ui| {
                                ui.set_width(w);
                                ui.set_height(150.0);
                                egui::ScrollArea::vertical()
                                    .id_salt(("dec", i))
                                    .show(ui, |ui| {
                                        if *hexv {
                                            editor::hex(ui, text.as_bytes());
                                        } else {
                                            ui.add(
                                                egui::TextEdit::multiline(text)
                                                    .code_editor()
                                                    .frame(egui::Frame::NONE)
                                                    .desired_width(w)
                                                    .desired_rows(9),
                                            );
                                        }
                                    });
                            });
                        ui.vertical(|ui| {
                            ui.set_width(185.0);
                            ui.horizontal(|ui| {
                                ui.radio_value(hexv, false, "Text");
                                ui.radio_value(hexv, true, "Hex");
                            });
                            let mut pick =
                                |ui: &mut egui::Ui, label: &str, items: &[&str], prefix: &str| {
                                    egui::ComboBox::from_id_salt((label, i))
                                        .selected_text(label)
                                        .width(175.0)
                                        .show_ui(ui, |ui| {
                                            for it in items {
                                                if ui.selectable_label(false, *it).clicked() {
                                                    action = Some((i, format!("{prefix}{it}")));
                                                }
                                            }
                                        });
                                };
                            pick(ui, "Decode as ...", &DECODE, "d:");
                            pick(ui, "Encode as ...", &ENCODE, "e:");
                            pick(ui, "Hash ...", &HASHES, "h:");
                            if ui
                                .add_sized([175.0, 24.0], egui::Button::new("Smart decode"))
                                .clicked()
                            {
                                action = Some((i, "smart".into()));
                            }
                        });
                    });
                    ui.add_space(8.0);
                }
            });
        if let Some((i, op)) = action {
            let input = self.panes[i].0.clone();
            let out = apply(&op, &input);
            self.panes.truncate(i + 1);
            self.panes.push((out, false));
        }
    }
}

pub fn apply(op: &str, s: &str) -> String {
    let b = s.as_bytes();
    let lossy = |v: Vec<u8>| String::from_utf8_lossy(&v).into_owned();
    match op {
        "d:URL" => lossy(codec::url_decode(s)),
        "d:HTML" => codec::html_decode(s),
        "d:Base64" => codec::base64_decode(s.trim())
            .map(lossy)
            .unwrap_or_else(|| s.into()),
        "d:ASCII hex" | "d:Hex" => codec::hex_decode(s).map(lossy).unwrap_or_else(|| s.into()),
        "d:Gzip" => {
            use std::io::Read;
            let mut out = Vec::new();
            // Decoder text is lossy UTF-8, so gzip input is accepted as hex (the Hex view) or raw bytes
            let raw = codec::hex_decode(s).unwrap_or_else(|| b.to_vec());
            match flate2::read::MultiGzDecoder::new(&raw[..]).read_to_end(&mut out) {
                Ok(_) => lossy(out),
                Err(_) => s.into(),
            }
        }
        "e:Gzip" => {
            use std::io::Write;
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let _ = gz.write_all(b);
            codec::hex_encode(&gz.finish().unwrap_or_default())
        }
        "e:URL" => codec::url_encode(b, true),
        "e:HTML" => codec::html_encode(b, true),
        "e:Base64" => codec::base64_encode(b),
        "e:ASCII hex" | "e:Hex" => codec::hex_encode(b),
        "e:Octal" => codec::octal_encode(b),
        "e:Binary" => codec::binary_encode(b),
        "smart" => smart_decode(s),
        h => codec::hash(h.trim_start_matches("h:"), b),
    }
}

/// Repeatedly peels URL / HTML / Base64 layers while each one changes the text into something printable.
pub fn smart_decode(s: &str) -> String {
    let mut cur = s.to_string();
    for _ in 0..10 {
        let t = cur.trim();
        let next = if t.contains('%') && codec::url_decode(t) != t.as_bytes() {
            String::from_utf8_lossy(&codec::url_decode(t)).into_owned()
        } else if t.contains('&') && t.contains(';') && codec::html_decode(t) != t {
            codec::html_decode(t)
        } else if t.len() >= 4
            && t.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"+/=-_".contains(&c))
            && let Some(d) = codec::base64_decode(t).filter(|d| {
                !d.is_empty()
                    && d.iter()
                        .all(|&c| c >= 0x20 || c == b'\n' || c == b'\r' || c == b'\t')
            })
            && let Ok(d) = String::from_utf8(d)
        {
            d
        } else {
            break;
        };
        cur = next;
    }
    cur
}

// ------------------------------------------------------------------ Comparer

#[derive(Default)]
pub struct Comparer {
    pub items: Vec<String>,
    sel: [Option<usize>; 2],
    result: Option<(bool, Vec<(Tag, String)>, Vec<(Tag, String)>)>,
    paste: String,
}

#[derive(Clone, Copy, PartialEq)]
enum Tag {
    Same,
    Modified,
    Deleted,
    Added,
}

impl Comparer {
    pub fn add(&mut self, s: String) {
        self.items.push(s);
        let n = self.items.len() - 1;
        if self.sel[0].is_none() {
            self.sel[0] = Some(n);
        } else {
            self.sel[1] = Some(n);
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        for k in 0..2 {
            ui.horizontal(|ui| {
                theme::heading(ui, &format!("Select item {}:", k + 1));
            });
            ui.horizontal_top(|ui| {
                let w = ui.available_width() - 130.0;
                egui::Frame::new()
                    .stroke(egui::Stroke::new(1.0, theme::border()))
                    .show(ui, |ui| {
                        ui.set_width(w);
                        ui.set_height(
                            ui.available_height() / if k == 0 { 2.2 } else { 1.0 } - 30.0,
                        );
                        egui::Grid::new(("cmp", k))
                            .striped(true)
                            .num_columns(3)
                            .min_col_width(40.0)
                            .show(ui, |ui| {
                                for h in ["#", "Length", "Data"] {
                                    ui.label(RichText::new(h).strong());
                                }
                                ui.end_row();
                                for (i, it) in self.items.iter().enumerate() {
                                    let sel = self.sel[k] == Some(i);
                                    if ui.selectable_label(sel, (i + 1).to_string()).clicked() {
                                        self.sel[k] = Some(i);
                                    }
                                    ui.label(it.len().to_string());
                                    let preview: String = it
                                        .chars()
                                        .take(120)
                                        .map(|c| if c.is_control() { ' ' } else { c })
                                        .collect();
                                    if ui.selectable_label(sel, preview).clicked() {
                                        self.sel[k] = Some(i);
                                    }
                                    ui.end_row();
                                }
                            });
                    });
                ui.vertical(|ui| {
                    if k == 0 {
                        if ui
                            .add_sized([120.0, 24.0], egui::Button::new("Paste"))
                            .clicked()
                        {
                            self.paste = String::new();
                        }
                        ui.add(
                            egui::TextEdit::singleline(&mut self.paste)
                                .hint_text("paste text or file path")
                                .desired_width(120.0),
                        );
                        if ui
                            .add_sized([120.0, 24.0], egui::Button::new("Add"))
                            .clicked()
                            && !self.paste.is_empty()
                        {
                            let p = std::mem::take(&mut self.paste);
                            self.add(p);
                        }
                        if ui
                            .add_sized([120.0, 24.0], egui::Button::new("Load"))
                            .on_hover_text("Load the file whose path is typed above")
                            .clicked()
                        {
                            match std::fs::read(self.paste.trim()) {
                                Ok(b) => {
                                    self.paste.clear();
                                    self.add(String::from_utf8_lossy(&b).into_owned());
                                }
                                Err(e) => self.paste = format!("error: {e}"),
                            }
                        }
                        if ui
                            .add_sized([120.0, 24.0], egui::Button::new("Remove"))
                            .clicked()
                            && let Some(i) = self.sel[0]
                        {
                            self.items.remove(i);
                            self.sel = [None, None];
                        }
                        if ui
                            .add_sized([120.0, 24.0], egui::Button::new("Clear"))
                            .clicked()
                        {
                            self.items.clear();
                            self.sel = [None, None];
                        }
                    } else {
                        ui.label("Compare ...");
                        for (words, label) in [(true, "Words"), (false, "Bytes")] {
                            if ui
                                .add_sized([120.0, 24.0], egui::Button::new(label))
                                .clicked()
                                && let [Some(a), Some(b)] = self.sel
                                && let (Some(a), Some(b)) = (self.items.get(a), self.items.get(b))
                            {
                                let (l, r) = diff(a, b, words);
                                self.result = Some((words, l, r));
                            }
                        }
                    }
                });
            });
        }
        if let Some((words, l, r)) = &self.result {
            let mut open = true;
            egui::Window::new(if *words {
                "Word compare"
            } else {
                "Byte compare"
            })
            .open(&mut open)
            .default_size([900.0, 600.0])
            .show(ui.ctx(), |ui| {
                ui.horizontal(|ui| {
                    ui.label("Key:");
                    for (t, n) in [
                        (Tag::Modified, "Modified"),
                        (Tag::Deleted, "Deleted"),
                        (Tag::Added, "Added"),
                    ] {
                        ui.label(RichText::new(format!(" {n} ")).background_color(tag_color(t)));
                    }
                });
                ui.columns(2, |cols| {
                    for (c, side) in cols.iter_mut().zip([l, r]) {
                        egui::ScrollArea::both()
                            .id_salt(c.scope_id())
                            .show(c, |ui| {
                                let mut job = egui::text::LayoutJob::default();
                                for (t, s) in side {
                                    job.append(
                                        s,
                                        0.0,
                                        egui::TextFormat {
                                            font_id: egui::FontId::monospace(13.0),
                                            color: theme::text(),
                                            background: tag_color(*t),
                                            ..Default::default()
                                        },
                                    );
                                }
                                ui.label(job);
                            });
                    }
                });
            });
            if !open {
                self.result = None;
            }
        }
    }
}

fn tag_color(t: Tag) -> Color32 {
    match t {
        Tag::Same => Color32::TRANSPARENT,
        Tag::Modified => Color32::from_rgb(0xFF, 0xD7, 0x80),
        Tag::Deleted => Color32::from_rgb(0xFF, 0xA0, 0xA0),
        Tag::Added => Color32::from_rgb(0xFF, 0xFF, 0x90),
    }
}

fn tokens(s: &str, words: bool) -> Vec<String> {
    if !words {
        return s.chars().map(String::from).collect();
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if c.is_alphanumeric() == cur.chars().next().is_some_and(char::is_alphanumeric)
            && !cur.is_empty()
            && !c.is_whitespace()
        {
            cur.push(c);
        } else {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// LCS-based diff. Unmatched runs present on both sides become "modified".
// ponytail: O(n*m) table capped at 4M cells; switch to Myers diff if huge comparisons matter
fn diff(a: &str, b: &str, words: bool) -> (Vec<(Tag, String)>, Vec<(Tag, String)>) {
    let (x, y) = (tokens(a, words), tokens(b, words));
    if x.len() * y.len() > 4_000_000 {
        let tag = if a == b { Tag::Same } else { Tag::Modified };
        return (vec![(tag, a.into())], vec![(tag, b.into())]);
    }
    let (n, m) = (x.len(), y.len());
    let mut t = vec![0u32; (n + 1) * (m + 1)];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            t[i * (m + 1) + j] = if x[i] == y[j] {
                t[(i + 1) * (m + 1) + j + 1] + 1
            } else {
                t[(i + 1) * (m + 1) + j].max(t[i * (m + 1) + j + 1])
            };
        }
    }
    let (mut l, mut r) = (vec![], vec![]);
    let (mut i, mut j) = (0, 0);
    let (mut dl, mut dr) = (String::new(), String::new());
    let flush = |l: &mut Vec<(Tag, String)>,
                 r: &mut Vec<(Tag, String)>,
                 dl: &mut String,
                 dr: &mut String| {
        let both = !dl.is_empty() && !dr.is_empty();
        if !dl.is_empty() {
            l.push((
                if both { Tag::Modified } else { Tag::Deleted },
                std::mem::take(dl),
            ));
        }
        if !dr.is_empty() {
            r.push((
                if both { Tag::Modified } else { Tag::Added },
                std::mem::take(dr),
            ));
        }
    };
    while i < n || j < m {
        if i < n && j < m && x[i] == y[j] {
            flush(&mut l, &mut r, &mut dl, &mut dr);
            l.push((Tag::Same, x[i].clone()));
            r.push((Tag::Same, y[j].clone()));
            i += 1;
            j += 1;
        } else if j < m && (i == n || t[i * (m + 1) + j + 1] >= t[(i + 1) * (m + 1) + j]) {
            dr.push_str(&y[j]);
            j += 1;
        } else {
            dl.push_str(&x[i]);
            i += 1;
        }
    }
    flush(&mut l, &mut r, &mut dl, &mut dr);
    (l, r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_and_decode() {
        assert_eq!(
            fix_content_length("POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\nabc"),
            "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"
        );
        assert_eq!(
            fix_content_length("GET / HTTP/1.1\r\nHost: a"),
            "GET / HTTP/1.1\r\nHost: a\r\n\r\n"
        );
        assert_eq!(smart_decode("JTNDYSUzRQ=="), "<a>");
        let h2 = set_protocol(
            "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
            true,
        );
        assert_eq!(h2, "GET / HTTP/2\r\nHost: a\r\n\r\n");
        assert_eq!(
            set_protocol(&h2, false),
            "GET / HTTP/1.1\r\nHost: a\r\n\r\n"
        );
        assert_eq!(apply("d:Gzip", &apply("e:Gzip", "hello")), "hello");
        assert_eq!(apply("h:MD5", ""), "d41d8cd98f00b204e9800998ecf8427e");
        let (l, r) = diff("a b c", "a x c", true);
        assert!(l.iter().any(|(t, s)| *t == Tag::Modified && s == "b"));
        assert!(r.iter().any(|(t, s)| *t == Tag::Modified && s == "x"));
    }
}
