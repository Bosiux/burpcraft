//! Sequencer: capture session tokens live (or paste them) and estimate their randomness.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use eframe::egui::{self, RichText};

use crate::{ui::editor, http::net, proxy, ui::theme};

pub struct Sequencer {
    tab: &'static str,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub req: String,
    cookie: String,
    start: String,
    end: String,
    use_cookie: bool,
    tokens: Arc<Mutex<Vec<String>>>,
    running: Arc<AtomicBool>,
    manual: String,
    report: Option<Report>,
    report_tab: &'static str,
}

impl Default for Sequencer {
    fn default() -> Self {
        Self {
            tab: "Live capture",
            host: String::new(),
            port: 80,
            tls: false,
            req: String::new(),
            cookie: String::new(),
            start: String::new(),
            end: String::new(),
            use_cookie: true,
            tokens: Default::default(),
            running: Default::default(),
            manual: String::new(),
            report: None,
            report_tab: "Summary",
        }
    }
}

pub struct Report {
    pub count: usize,
    pub entropy_bits: f64,
    pub quality: &'static str,
    /// per character position: (distinct chars, entropy bits)
    pub chars: Vec<(usize, f64)>,
    /// per bit position: (share of ones, passes)
    pub bits: Vec<(f64, bool)>,
}

/// Character- and bit-level analysis. Entropy per position is Shannon entropy capped by log2(sample size).
pub fn analyze(tokens: &[String]) -> Option<Report> {
    let n = tokens.len();
    if n < 2 {
        return None;
    }
    let maxlen = tokens.iter().map(|t| t.len()).max()?;
    let cap = (n as f64).log2();
    let mut chars = vec![];
    for pos in 0..maxlen {
        let mut counts = std::collections::HashMap::new();
        for t in tokens {
            *counts
                .entry(t.as_bytes().get(pos).copied())
                .or_insert(0usize) += 1;
        }
        let h: f64 = counts
            .values()
            .map(|&c| c as f64 / n as f64)
            .map(|p| -p * p.log2())
            .sum();
        chars.push((counts.len(), h.min(cap)));
    }
    let nbits = maxlen * 8;
    let tol = 3.0 * 0.5 / (n as f64).sqrt(); // ~3 sigma for a fair coin
    let bits = (0..nbits)
        .map(|b| {
            let ones = tokens
                .iter()
                .filter(|t| {
                    t.as_bytes()
                        .get(b / 8)
                        .is_some_and(|c| c >> (7 - b % 8) & 1 == 1)
                })
                .count();
            let p = ones as f64 / n as f64;
            (p, (p - 0.5).abs() <= tol)
        })
        .collect();
    let entropy_bits: f64 = chars.iter().map(|c| c.1).sum();
    let quality = match entropy_bits {
        e if e >= 64.0 => "excellent",
        e if e >= 32.0 => "reasonable",
        e if e >= 16.0 => "poor",
        _ => "extremely poor",
    };
    Some(Report {
        count: n,
        entropy_bits,
        quality,
        chars,
        bits,
    })
}

/// Pulls a token from a response: a Set-Cookie value, or the text between two delimiters.
pub fn extract(resp: &str, cookie: Option<&str>, start: &str, end: &str) -> Option<String> {
    if let Some(name) = cookie {
        let head = resp.split("\r\n\r\n").next()?;
        return head
            .lines()
            .filter_map(|l| l.split_once(':'))
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .find_map(|(_, v)| {
                let (k, val) = v.trim().split(';').next()?.split_once('=')?;
                (k.trim() == name).then(|| val.trim().to_string())
            });
    }
    let i = resp.find(start)? + start.len();
    let j = if end.is_empty() {
        resp[i..]
            .find(['\r', '\n', '"', '\'', '<', ';', '&'])
            .unwrap_or(resp.len() - i)
    } else {
        resp[i..].find(end)?
    };
    Some(resp[i..i + j].to_string())
}

impl Sequencer {
    pub fn load(&mut self, host: String, port: u16, tls: bool, req: String, resp: &str) {
        (self.host, self.port, self.tls, self.req) = (host, port, tls, req);
        if let Some(name) = cookie_names(resp).first() {
            self.cookie = name.clone();
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, state: &proxy::State) {
        theme::frame_chrome().show(ui, |ui| {
            ui.horizontal(|ui| {
                for t in ["Live capture", "Manual load", "Analysis options"] {
                    if theme::sub_tab(ui, self.tab == t, t).clicked() {
                        self.tab = t;
                    }
                }
            });
        });
        if self.report.is_some() {
            self.report_window(ui.ctx());
        }
        match self.tab {
            "Live capture" => self.live(ui, state),
            "Manual load" => {
                ui.label("Paste tokens below, one per line, then click Analyze now.");
                ui.horizontal(|ui| {
                    if theme::primary_button(ui, "Analyze now").clicked() {
                        let toks: Vec<String> = self
                            .manual
                            .lines()
                            .map(str::trim)
                            .filter(|l| !l.is_empty())
                            .map(String::from)
                            .collect();
                        self.report = analyze(&toks);
                    }
                    if ui.button("Clear").clicked() {
                        self.manual.clear();
                    }
                    ui.label(format!(
                        "Tokens loaded: {}",
                        self.manual.lines().filter(|l| !l.trim().is_empty()).count()
                    ));
                });
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.manual)
                            .code_editor()
                            .desired_width(f32::INFINITY)
                            .desired_rows(30),
                    );
                });
            }
            _ => {
                theme::heading(ui, "Token handling");
                ui.label("Tokens are analyzed as captured: character positions are compared across the sample, and each byte is split into 8 bits for the bit-level tests.");
                theme::heading(ui, "Token analysis");
                ui.label("Character-level: Shannon entropy per position. Bit-level: monobit test per bit at a 3-sigma tolerance.");
            }
        }
    }

    fn live(&mut self, ui: &mut egui::Ui, state: &proxy::State) {
        let running = self.running.load(Ordering::SeqCst);
        let count = self.tokens.lock().unwrap().len();
        ui.horizontal(|ui| {
            theme::heading(ui, "Select live capture request");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = if running {
                    "Stop capture"
                } else {
                    "Start live capture"
                };
                if theme::primary_button(ui, label).clicked() {
                    if running {
                        self.running.store(false, Ordering::SeqCst);
                    } else if !self.host.is_empty() {
                        self.start_capture(ui.ctx().clone(), state.clone());
                    }
                }
                if ui
                    .add_enabled(count >= 2, egui::Button::new("Analyze now"))
                    .clicked()
                {
                    self.report = analyze(&self.tokens.lock().unwrap());
                }
                if ui.button("Clear tokens").clicked() {
                    self.tokens.lock().unwrap().clear();
                }
                ui.label(format!("Tokens captured: {count}"));
            });
        });
        ui.label(
            RichText::new(if self.host.is_empty() {
                "Send a request here from any tool's context menu (Send to Sequencer).".into()
            } else {
                format!(
                    "Target: {}://{}:{}",
                    if self.tls { "https" } else { "http" },
                    self.host,
                    self.port
                )
            })
            .color(theme::muted()),
        );
        ui.separator();
        theme::heading(ui, "Token location within response");
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.use_cookie, true, "Cookie:");
            ui.add_enabled(
                self.use_cookie,
                egui::TextEdit::singleline(&mut self.cookie)
                    .desired_width(200.0)
                    .hint_text("cookie name"),
            );
        });
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.use_cookie, false, "Custom location: start after");
            ui.add_enabled(
                !self.use_cookie,
                egui::TextEdit::singleline(&mut self.start).desired_width(160.0),
            );
            ui.label("end at");
            ui.add_enabled(
                !self.use_cookie,
                egui::TextEdit::singleline(&mut self.end)
                    .desired_width(120.0)
                    .hint_text("(delimiter)"),
            );
        });
        ui.separator();
        egui::CentralPanel::default().show(ui, |ui| {
            editor::message(ui, "seq_req", "Request", &mut self.req, true);
        });
    }

    fn start_capture(&mut self, ctx: egui::Context, state: proxy::State) {
        self.running.store(true, Ordering::SeqCst);
        let (running, tokens) = (self.running.clone(), self.tokens.clone());
        let (host, port, tls) = (self.host.clone(), self.port, self.tls);
        let req =
            crate::tools::fix_content_length(&self.req.replace("\r\n", "\n").replace('\n', "\r\n"));
        let cookie = self.use_cookie.then(|| self.cookie.clone());
        let (start, end) = (self.start.clone(), self.end.clone());
        std::thread::spawn(move || {
            let mut errors = 0;
            while running.load(Ordering::SeqCst) && tokens.lock().unwrap().len() < 20_000 {
                match net::send(&host, port, tls, req.as_bytes()) {
                    Ok(r) => match extract(
                        &String::from_utf8_lossy(&r),
                        cookie.as_deref(),
                        &start,
                        &end,
                    ) {
                        Some(t) => tokens.lock().unwrap().push(t),
                        None => errors += 1,
                    },
                    Err(_) => errors += 1,
                }
                if errors > 20 {
                    state.lock().unwrap().event(
                        "Sequencer",
                        "Live capture stopped: token not found in responses",
                    );
                    break;
                }
                ctx.request_repaint();
            }
            running.store(false, Ordering::SeqCst);
            ctx.request_repaint();
        });
    }

    fn report_window(&mut self, ctx: &egui::Context) {
        let mut open = true;
        let Some(r) = &self.report else { return };
        let tab = &mut self.report_tab;
        theme::window(ctx, "Sequencer analysis", [800.0, 560.0], &mut open, |ui| {
            ui.horizontal(|ui| {
                for t in ["Summary", "Character-level analysis", "Bit-level analysis"] {
                    if theme::sub_tab(ui, *tab == t, t).clicked() {
                        *tab = t;
                    }
                }
            });
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| match *tab {
                "Summary" => {
                    theme::heading(ui, "Overall result");
                    ui.label(format!("The overall quality of randomness within the sample is estimated to be: {}.", r.quality));
                    ui.label(format!("The effective entropy is estimated to be: {:.0} bits.", r.entropy_bits));
                    ui.add_space(8.0);
                    theme::heading(ui, "Sample");
                    ui.label(format!("The analysis was based on a sample of {} tokens.", r.count));
                    bar_chart(ui, "Effective entropy per character position", &r.chars.iter().map(|c| c.1).collect::<Vec<_>>(), (r.count as f64).log2().max(1.0));
                }
                "Character-level analysis" => {
                    egui::Grid::new("chars").striped(true).num_columns(3).show(ui, |ui| {
                        ui.strong("Position");
                        ui.strong("Distinct characters");
                        ui.strong("Entropy (bits)");
                        ui.end_row();
                        for (i, (d, h)) in r.chars.iter().enumerate() {
                            ui.label(i.to_string());
                            ui.label(d.to_string());
                            ui.label(format!("{h:.2}"));
                            ui.end_row();
                        }
                    });
                }
                _ => {
                    let pass = r.bits.iter().filter(|b| b.1).count();
                    ui.label(format!("{pass} of {} bits passed the monobit test.", r.bits.len()));
                    bar_chart(ui, "Proportion of ones per bit (0.5 is ideal)", &r.bits.iter().map(|b| b.0).collect::<Vec<_>>(), 1.0);
                }
            });
        });
        if !open {
            self.report = None;
        }
    }
}

fn bar_chart(ui: &mut egui::Ui, title: &str, vals: &[f64], max: f64) {
    ui.strong(title);
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 180.0),
        egui::Sense::hover(),
    );
    let p = ui.painter();
    p.rect_stroke(
        rect,
        0.0,
        egui::Stroke::new(1.0, theme::border()),
        egui::StrokeKind::Inside,
    );
    let w = rect.width() / vals.len().max(1) as f32;
    for (i, v) in vals.iter().enumerate() {
        let h = (v / max).clamp(0.0, 1.0) as f32 * (rect.height() - 4.0);
        let x = rect.left() + i as f32 * w;
        p.rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(x + 1.0, rect.bottom() - h),
                egui::pos2(x + w - 1.0, rect.bottom()),
            ),
            0.0,
            theme::ORANGE,
        );
    }
}

pub fn cookie_names(resp: &str) -> Vec<String> {
    resp.split("\r\n\r\n")
        .next()
        .unwrap_or("")
        .lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, v)| v.trim().split('=').next().map(|s| s.trim().to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extraction_and_analysis() {
        let r = "HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc123; Path=/\r\n\r\n{\"token\":\"xyz\"}";
        assert_eq!(extract(r, Some("sid"), "", "").as_deref(), Some("abc123"));
        assert_eq!(
            extract(r, None, "\"token\":\"", "\"").as_deref(),
            Some("xyz")
        );
        let same: Vec<String> = vec!["aaaa".into(); 50];
        assert_eq!(analyze(&same).unwrap().entropy_bits, 0.0);
        let varied: Vec<String> = (0..256)
            .map(|i| format!("{i:02x}{:02x}", (i * 37) % 256))
            .collect();
        assert!(analyze(&varied).unwrap().entropy_bits > 8.0);
    }
}
