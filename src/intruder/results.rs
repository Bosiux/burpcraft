//! Attack results model (Row/Attack), response grep, and the results windows.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};

use crate::theme;

use super::*;

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
    pub(crate) grep_cols: Vec<String>,
    pub(crate) selected: Option<usize>,
    pub(crate) sort: Option<(usize, bool)>,
}

impl Intruder {
    /// Results windows; shown from any main tab, like the original's separate attack windows.
    pub fn windows(&mut self, ctx: &egui::Context) {
        for (k, a) in self.attacks.iter_mut().enumerate() {
            if !a.open {
                continue;
            }
            let mut open = true;
            theme::window(
                ctx,
                &format!("Intruder attack {}", a.title),
                [1000.0, 700.0],
                &mut open,
                |ui| {
                    let rows = a.rows.lock().unwrap();
                    let done = rows.len();
                    ui.horizontal(|ui| {
                        let finished = done >= a.total || a.stop.load(Ordering::SeqCst);
                        if ui
                            .add_enabled(!finished, egui::Button::new("Pause / stop"))
                            .clicked()
                        {
                            a.stop.store(true, Ordering::SeqCst);
                        }
                        ui.label(if finished {
                            "Finished".to_string()
                        } else {
                            "Attack running".into()
                        });
                        ui.add(
                            egui::ProgressBar::new(done as f32 / a.total.max(1) as f32)
                                .text(format!("{done} of {}", a.total))
                                .desired_width(300.0),
                        );
                    });
                    ui.separator();
                    let npay = rows
                        .iter()
                        .map(|r| r.payloads.len())
                        .max()
                        .unwrap_or(1)
                        .max(1);
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
                    let (req, resp) = sel
                        .map(|r| (r.req.clone(), r.resp.clone()))
                        .unwrap_or_default();
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
                },
            );
            if !open {
                a.open = false;
                a.stop.store(true, Ordering::SeqCst);
            }
        }
    }
}
