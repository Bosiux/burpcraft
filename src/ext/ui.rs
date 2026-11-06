//! Extensions tab egui UI: Installed, BApp Store, BChecks editor and the protocol reference.
use eframe::egui::{self, RichText};

use super::runtime::{load, registry, save_list, start, unload};
use super::store::{BApp, install, store_list};
use crate::theme;

// ------------------------------------------------------------ UI

#[derive(Default)]
pub struct Tab {
    tab: usize,
    selected: Option<usize>,
    new_path: String,
    store_server: String,
    store: Vec<BApp>,
    store_msg: String,
    bcheck_sel: Option<usize>,
    bcheck_text: String,
    bcheck_msg: String,
}

impl Tab {
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        theme::frame_chrome().show(ui, |ui| {
            ui.horizontal(|ui| {
                for (i, t) in ["Installed", "BApp Store", "BChecks", "APIs"]
                    .iter()
                    .enumerate()
                {
                    if theme::sub_tab(ui, self.tab == i, t).clicked() {
                        self.tab = i;
                    }
                }
            });
        });
        ui.add_space(4.0);
        match self.tab {
            0 => self.installed(ui),
            1 => self.store(ui),
            2 => self.bchecks(ui),
            _ => {
                ui.label("Extensions are separate programs that talk to BurpCraft with one JSON object per line on stdin/stdout:");
                let doc: String = include_str!("mod.rs")
                    .lines()
                    .take_while(|l| l.starts_with("//!"))
                    .map(|l| l.trim_start_matches("//!"))
                    .collect::<Vec<_>>()
                    .join("\n");
                let mut d = doc;
                ui.add(
                    egui::TextEdit::multiline(&mut d)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .interactive(false),
                );
            }
        }
    }

    fn installed(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.new_path)
                    .hint_text("command, e.g. python3 /path/to/extension.py")
                    .desired_width(360.0),
            );
            if ui.button("Add").clicked() && !self.new_path.trim().is_empty() {
                load(self.new_path.trim());
                self.new_path.clear();
            }
            if let Some(i) = self.selected {
                if ui.button("Remove").clicked() {
                    let ext = registry().lock().unwrap().remove(i);
                    unload(&ext);
                    save_list();
                    self.selected = None;
                } else if ui.button("Reload").clicked() {
                    let ext = registry().lock().unwrap()[i].clone();
                    unload(&ext);
                    start(&ext);
                }
            }
        });
        ui.separator();
        let exts = registry().lock().unwrap().clone();
        if exts.is_empty() {
            ui.label(
                RichText::new(
                    "No extensions. Add a command above, or install one from the BApp Store.",
                )
                .color(theme::muted()),
            );
        }
        egui::Grid::new("exts")
            .striped(true)
            .num_columns(4)
            .show(ui, |ui| {
                for h in ["Loaded", "Name", "Hooks", "Command"] {
                    ui.strong(h);
                }
                ui.end_row();
                for (i, e) in exts.iter().enumerate() {
                    let e = e.lock().unwrap();
                    let mut on = e.loaded;
                    ui.add_enabled(false, egui::Checkbox::without_text(&mut on));
                    if ui
                        .selectable_label(self.selected == Some(i), &e.name)
                        .clicked()
                    {
                        self.selected = Some(i);
                    }
                    ui.label(e.hooks.join(", "));
                    ui.monospace(&e.path);
                    ui.end_row();
                }
            });
        if let Some(e) = self.selected.and_then(|i| exts.get(i)) {
            ui.separator();
            ui.strong("Output");
            let mut out = e.lock().unwrap().output.join("\n");
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut out)
                            .code_editor()
                            .desired_width(f32::INFINITY)
                            .interactive(false),
                    );
                });
        }
    }

    fn store(&mut self, ui: &mut egui::Ui) {
        if self.store_server.is_empty() {
            self.store_server = crate::security::collab::client().lock().unwrap().server.clone();
        }
        ui.label("BApps are served by a self-hosted burpcraft-server started with --bapps <dir>.");
        ui.horizontal(|ui| {
            ui.label("Server:");
            ui.add(
                egui::TextEdit::singleline(&mut self.store_server)
                    .hint_text("host:port")
                    .desired_width(220.0),
            );
            if ui.button("Refresh").clicked() {
                match store_list(self.store_server.trim()) {
                    Ok(l) => (self.store, self.store_msg) = (l, String::new()),
                    Err(e) => self.store_msg = format!("Failed to load the catalogue: {e}"),
                }
            }
        });
        if !self.store_msg.is_empty() {
            ui.label(RichText::new(&self.store_msg).color(theme::muted()));
        }
        ui.separator();
        let installed: Vec<String> = registry()
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.lock().unwrap().path.clone())
            .collect();
        let mut chosen = None;
        egui::Grid::new("bapps")
            .striped(true)
            .num_columns(4)
            .show(ui, |ui| {
                for h in ["Name", "Version", "Description", ""] {
                    ui.strong(h);
                }
                ui.end_row();
                for (i, app) in self.store.iter().enumerate() {
                    ui.label(&app.0);
                    ui.label(&app.1);
                    ui.label(&app.2);
                    if installed.iter().any(|p| p.ends_with(&app.3)) {
                        ui.label("Installed");
                    } else if ui.button("Install").clicked() {
                        chosen = Some(i);
                    }
                    ui.end_row();
                }
            });
        if let Some(i) = chosen {
            self.store_msg = match install(self.store_server.trim(), &self.store[i]) {
                Ok(c) => format!("Installed and loaded: {c}"),
                Err(e) => format!("Install failed: {e}"),
            };
        }
    }

    fn bchecks(&mut self, ui: &mut egui::Ui) {
        ui.label(format!("BChecks in {} (*.bcheck). Enabled checks run in active scans and on proxied responses.", crate::security::bcheck::dir().display()));
        ui.horizontal(|ui| {
            if ui.button("New").clicked() {
                (self.bcheck_sel, self.bcheck_text) = (None, crate::security::bcheck::TEMPLATE.to_string());
            }
            if ui.button("Reload from disk").clicked() {
                *crate::security::bcheck::checks().lock().unwrap() =
                    crate::security::bcheck::load_dir(&crate::security::bcheck::dir());
            }
        });
        let (list, errs) = crate::security::bcheck::checks().lock().unwrap().clone();
        for e in &errs {
            ui.colored_label(egui::Color32::from_rgb(0xC0, 0x30, 0x30), e);
        }
        egui::Grid::new("bchecks")
            .striped(true)
            .num_columns(3)
            .show(ui, |ui| {
                for h in ["Enabled", "Name", "Given"] {
                    ui.strong(h);
                }
                ui.end_row();
                for (i, b) in list.iter().enumerate() {
                    let mut on = b.enabled;
                    if ui.checkbox(&mut on, "").changed() {
                        crate::security::bcheck::checks().lock().unwrap().0[i].enabled = on;
                    }
                    if ui
                        .selectable_label(self.bcheck_sel == Some(i), &b.name)
                        .clicked()
                    {
                        (self.bcheck_sel, self.bcheck_text) = (Some(i), b.source.clone());
                    }
                    ui.label(format!("{:?}", b.given));
                    ui.end_row();
                }
            });
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Validate").clicked() {
                self.bcheck_msg = match crate::security::bcheck::parse(&self.bcheck_text) {
                    Ok(b) => format!("OK: \"{}\"", b.name),
                    Err(e) => e,
                };
            }
            if ui.button("Save").clicked() {
                self.bcheck_msg = match crate::security::bcheck::parse(&self.bcheck_text) {
                    Ok(b) => {
                        let file: String = b
                            .name
                            .chars()
                            .map(|c| {
                                if c.is_ascii_alphanumeric() {
                                    c.to_ascii_lowercase()
                                } else {
                                    '-'
                                }
                            })
                            .collect();
                        let path = crate::security::bcheck::dir().join(format!("{file}.bcheck"));
                        let _ = std::fs::create_dir_all(crate::security::bcheck::dir());
                        match std::fs::write(&path, &self.bcheck_text) {
                            Ok(()) => {
                                *crate::security::bcheck::checks().lock().unwrap() =
                                    crate::security::bcheck::load_dir(&crate::security::bcheck::dir());
                                format!("Saved {}", path.display())
                            }
                            Err(e) => format!("Save failed: {e}"),
                        }
                    }
                    Err(e) => format!("Not saved: {e}"),
                };
            }
            ui.label(RichText::new(&self.bcheck_msg).color(theme::muted()));
        });
        ui.label(RichText::new("Syntax: metadata, optional `run for each:` (name = \"a\", \"b\") and `define:` (name = \"value\", used as {name}; {random_str(8)}), `given ... then`, `send ...`, `if ... then` / `else if ... then` / `else` / `end if`, `report issue:`. New starts from an example.").color(theme::muted()));
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut self.bcheck_text)
                    .code_editor()
                    .desired_rows(16)
                    .desired_width(f32::INFINITY),
            );
        });
    }
}
