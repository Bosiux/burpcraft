//! HTTP history and Logger tables: the shared sortable table with its context
//! menu, the history filter popup, and the `curl` export helper.

use super::history_table::history_table;
use crate::proxy::Entry;
use crate::{App, proxy, target, theme};
use eframe::egui;

impl App {
    pub(crate) fn history(&mut self, ui: &mut egui::Ui) {
        let rows: Vec<Entry> = {
            let s = self.state.lock().unwrap();
            let f = self.filter.to_ascii_lowercase();
            s.history
                .iter()
                // crawler and scanner evidence live in the site map, not the Proxy history
                .filter(|e| e.tool == "Proxy")
                .filter(|e| self.hfilter.keep(e, &self.target))
                .filter(|e| {
                    f.is_empty() || e.host.contains(&f) || e.url.to_ascii_lowercase().contains(&f)
                })
                .cloned()
                .collect()
        };
        ui.horizontal(|ui| {
            if ui
                .button(format!("Filter settings: {}", self.hfilter.describe()))
                .clicked()
            {
                self.hfilter_open = !self.hfilter_open;
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Search")
                    .desired_width(220.0),
            );
        });
        if self.hfilter_open {
            let mut open = true;
            theme::window(
                ui.ctx(),
                "HTTP history filter",
                [640.0, 420.0],
                &mut open,
                |ui| self.hfilter.ui(ui),
            );
            self.hfilter_open = open;
        }
        let sel = self
            .selected
            .and_then(|id| rows.iter().find(|e| e.id == id).cloned());
        let h = ui.available_height();
        let mut action: Option<(&'static str, Entry)> = None;
        egui::Panel::top("hist_table")
            .resizable(true)
            .default_size(h * 0.45)
            .show(ui, |ui| {
                action = history_table(ui, "history", &rows, &mut self.selected, false);
            });
        if let Some(e) = sel {
            let mut req = String::from_utf8_lossy(&e.req).into_owned();
            let mut resp = proxy::display(&e.resp);
            crate::editor::split(
                ui,
                ("hreq", e.id),
                &mut req,
                false,
                &mut resp,
                Some(&format!("{}{}", e.origin(), e.url)),
            );
        }
        if let Some((what, e)) = action {
            self.entry_action(what, e, false);
        }
        if let Some((id, text)) = &mut self.comment_edit {
            let mut open = true;
            let mut ok = false;
            theme::window(ui.ctx(), "Add comment", [360.0, 110.0], &mut open, |ui| {
                ui.text_edit_singleline(text);
                ok = theme::primary_button(ui, "OK").clicked();
            });
            if ok {
                let mut s = self.state.lock().unwrap();
                if let Some(e) = s.history.iter_mut().find(|e| e.id == *id) {
                    e.comment = text.clone();
                }
            }
            if ok || !open {
                self.comment_edit = None;
            }
        }
    }

    pub(crate) fn logger(&mut self, ui: &mut egui::Ui) {
        let rows = self.state.lock().unwrap().logger.clone();
        let sel = self
            .logger_sel
            .and_then(|id| rows.iter().find(|e| e.id == id).cloned());
        let h = ui.available_height();
        let mut action = None;
        egui::Panel::top("log_table")
            .resizable(true)
            .default_size(h * 0.5)
            .show(ui, |ui| {
                action = history_table(ui, "logger", &rows, &mut self.logger_sel, true);
            });
        if let Some(e) = sel {
            let mut req = String::from_utf8_lossy(&e.req).into_owned();
            let mut resp = proxy::display(&e.resp);
            crate::editor::split(
                ui,
                ("lreq", e.id),
                &mut req,
                false,
                &mut resp,
                Some(&format!("{}{}", e.origin(), e.url)),
            );
        }
        if let Some((what, e)) = action {
            self.entry_action(what, e, true);
        }
    }
}

const MIME_GROUPS: [&str; 8] = [
    "HTML",
    "Script",
    "XML",
    "CSS",
    "Other text",
    "Images",
    "Flash",
    "Other binary",
];

/// The HTTP history "Filter settings" popup state.
pub(crate) struct HistFilter {
    in_scope: bool,
    hide_no_response: bool,
    only_params: bool,
    mime: [bool; 8],
    status: [bool; 4],
    hide_ext: bool,
    exts: String,
}

impl Default for HistFilter {
    fn default() -> Self {
        Self {
            in_scope: false,
            hide_no_response: false,
            only_params: false,
            mime: [true, true, true, false, true, false, false, false],
            status: [true; 4],
            hide_ext: false,
            exts: "js,gif,jpg,png,css".into(),
        }
    }
}

impl HistFilter {
    fn group(e: &Entry) -> usize {
        match e.mime().as_str() {
            "HTML" => 0,
            "script" | "JSON" => 1,
            "XML" | "SVG" => 2,
            "CSS" => 3,
            "image" => 5,
            "font" => 7,
            "" | "text" => 4,
            _ => 7,
        }
    }

    fn keep(&self, e: &Entry, target: &target::Target) -> bool {
        let ext = e.extension().to_ascii_lowercase();
        let st = (e.status / 100) as usize;
        (!self.in_scope || target.in_scope(e))
            && (!self.hide_no_response || !e.resp.is_empty())
            && (!self.only_params || e.params())
            && (self.mime[Self::group(e)] || (Self::group(e) == 4 && e.mime().is_empty()))
            && !(self.hide_ext && !ext.is_empty() && self.exts.split(',').any(|x| x.trim() == ext))
            && (!(2..=5).contains(&st) || self.status[st - 2])
    }

    fn describe(&self) -> String {
        let mut parts = vec![];
        if self.in_scope {
            parts.push("Showing only in-scope items".to_string());
        }
        let hidden: Vec<&str> = MIME_GROUPS
            .iter()
            .zip(self.mime)
            .filter(|(_, on)| !on)
            .map(|(m, _)| *m)
            .collect();
        if hidden.is_empty() && parts.is_empty() {
            return "Showing all items".into();
        }
        if hidden == ["CSS", "Images", "Flash", "Other binary"] {
            parts.push("Hiding CSS, image and general binary content".into());
        } else if !hidden.is_empty() {
            parts.push(format!("Hiding {}", hidden.join(", ")));
        }
        parts.join("; ")
    }

    fn ui(&mut self, ui: &mut egui::Ui) {
        ui.columns(3, |c| {
            c[0].strong("Filter by request type");
            c[0].checkbox(&mut self.in_scope, "Show only in-scope items");
            c[0].checkbox(&mut self.hide_no_response, "Hide items without responses");
            c[0].checkbox(&mut self.only_params, "Show only parameterized requests");
            c[1].strong("Filter by MIME type");
            for (i, m) in MIME_GROUPS.iter().enumerate() {
                c[1].checkbox(&mut self.mime[i], *m);
            }
            c[2].strong("Filter by status code");
            for (i, m) in [
                "2xx [success]",
                "3xx [redirection]",
                "4xx [request error]",
                "5xx [server error]",
            ]
            .iter()
            .enumerate()
            {
                c[2].checkbox(&mut self.status[i], *m);
            }
            c[2].add_space(8.0);
            c[2].strong("Filter by file extension");
            c[2].checkbox(&mut self.hide_ext, "Hide:");
            c[2].text_edit_singleline(&mut self.exts);
        });
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Show all").clicked() {
                *self = HistFilter {
                    mime: [true; 8],
                    ..Default::default()
                };
            }
            if ui.button("Revert changes").clicked() {
                *self = HistFilter::default();
            }
        });
    }
}
