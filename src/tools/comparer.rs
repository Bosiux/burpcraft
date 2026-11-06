use eframe::egui::{self, Color32, RichText};

use crate::ui::theme;

#[derive(Default)]
pub struct Comparer {
    pub items: Vec<String>,
    sel: [Option<usize>; 2],
    result: Option<(bool, Vec<(Tag, String)>, Vec<(Tag, String)>)>,
    paste: String,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Tag {
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
            theme::window(
                ui.ctx(),
                if *words {
                    "Word compare"
                } else {
                    "Byte compare"
                },
                [900.0, 600.0],
                &mut open,
                |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Key:");
                        for (t, n) in [
                            (Tag::Modified, "Modified"),
                            (Tag::Deleted, "Deleted"),
                            (Tag::Added, "Added"),
                        ] {
                            ui.label(
                                RichText::new(format!(" {n} ")).background_color(tag_color(t)),
                            );
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
                },
            );
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
pub(crate) fn diff(a: &str, b: &str, words: bool) -> (Vec<(Tag, String)>, Vec<(Tag, String)>) {
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
