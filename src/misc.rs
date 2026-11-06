//! Organizer, Collaborator, Extensions, Learn and the Settings window.
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};

use crate::proxy::Entry;
use crate::theme;

/// Opens a file or URL with the OS default handler.
pub fn open_external(target: impl AsRef<std::ffi::OsStr>) -> std::io::Result<()> {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    std::process::Command::new(opener)
        .arg(target)
        .spawn()
        .map(|_| ())
}

const STATUSES: [&str; 3] = ["New", "In progress", "Done"];

#[derive(Default)]
pub struct Organizer {
    pub items: Vec<(Entry, usize, String)>, // entry, status index, notes
    selected: Option<usize>,
}

impl Organizer {
    pub fn add(&mut self, mut e: Entry) {
        e.id = self.items.len() + 1;
        self.items.push((e, 0, String::new()));
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            theme::heading(ui, "Organizer");
            ui.label(RichText::new(format!("{} items", self.items.len())).color(theme::muted()));
        });
        let h = ui.available_height();
        let sel = self.selected;
        let mut clicked = None;
        egui::Panel::top("org_tbl")
            .resizable(true)
            .default_size(h * 0.45)
            .show(ui, |ui| {
                TableBuilder::new(ui)
                    .id_salt("organizer")
                    .striped(true)
                    .sense(egui::Sense::click())
                    .resizable(true)
                    .column(Column::initial(40.0))
                    .column(Column::initial(140.0))
                    .column(Column::initial(90.0))
                    .column(Column::initial(70.0))
                    .column(Column::initial(200.0))
                    .column(Column::initial(260.0).clip(true))
                    .column(Column::initial(80.0))
                    .column(Column::remainder())
                    .header(22.0, |mut r| {
                        for c in [
                            "#",
                            "Time",
                            "Status",
                            "Method",
                            "Host",
                            "URL",
                            "Status code",
                            "Notes",
                        ] {
                            r.col(|ui| {
                                ui.strong(c);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(24.0, self.items.len(), |mut row| {
                            let i = row.index();
                            row.set_selected(sel == Some(i));
                            let (e, status, notes) = &mut self.items[i];
                            row.col(|ui| {
                                ui.label(e.id.to_string());
                            });
                            row.col(|ui| {
                                ui.label(&e.time);
                            });
                            row.col(|ui| {
                                egui::ComboBox::from_id_salt(("org_st", i))
                                    .selected_text(STATUSES[*status])
                                    .width(80.0)
                                    .show_ui(ui, |ui| {
                                        for (k, s) in STATUSES.iter().enumerate() {
                                            ui.selectable_value(status, k, *s);
                                        }
                                    });
                            });
                            for v in [
                                e.method.clone(),
                                e.origin(),
                                e.url.clone(),
                                e.status.to_string(),
                            ] {
                                row.col(|ui| {
                                    ui.label(v);
                                });
                            }
                            row.col(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(notes)
                                        .hint_text("Add notes")
                                        .frame(egui::Frame::NONE),
                                );
                            });
                            if row.response().clicked() {
                                clicked = Some(i);
                            }
                        });
                    });
            });
        if clicked.is_some() {
            self.selected = clicked;
        }
        if let Some((e, _, _)) = self.selected.and_then(|i| self.items.get(i)) {
            let mut req = String::from_utf8_lossy(&e.req).into_owned();
            let mut resp = crate::proxy::display(&e.resp);
            crate::editor::split(
                ui,
                ("oreq", e.id),
                &mut req,
                false,
                &mut resp,
                Some(&format!("{}{}", e.origin(), e.url)),
            );
        } else if self.items.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label(RichText::new("Send requests here from any tool's context menu (Send to Organizer) to keep track of them.").color(theme::muted()));
            });
        }
    }
}

pub fn learn(ui: &mut egui::Ui) {
    theme::heading(ui, "Learn");
    ui.label("Quick guides for getting started with BurpCraft.");
    ui.add_space(8.0);
    let guides = [
        (
            "Proxy your browser",
            "Click Proxy > Intercept > Open browser, or set your browser's HTTP and HTTPS proxy to 127.0.0.1:8080 (or the BURPCRAFT_PROXY port) and install ~/.burpcraft/ca.pem as a trusted CA.",
        ),
        (
            "Intercept and modify",
            "Turn intercept on, edit the held request, then Forward or Drop it. Enable response interception in Proxy settings.",
        ),
        (
            "Replay requests",
            "Right-click any request and choose Send to Repeater (Ctrl+R). Edit and press Send (Ctrl+Space).",
        ),
        (
            "Automate attacks",
            "Send a request to Intruder (Ctrl+I), mark positions with Add §, choose an attack type and payloads, then Start attack.",
        ),
        (
            "Analyze tokens",
            "Send a request that issues a session token to Sequencer, pick the token location and start live capture.",
        ),
        (
            "Decode and compare",
            "Decoder chains encodings and hashes; Comparer shows word- or byte-level differences between two items.",
        ),
    ];
    for (t, d) in guides {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(t).strong().size(14.0));
            ui.label(d);
        });
    }
}

pub struct Settings {
    pub open: bool,
    pub dark: bool,
    pub font_size: f32,
    pub section: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            open: false,
            dark: false,
            font_size: 13.0,
            section: 0,
        }
    }
}

impl Settings {
    /// Returns true when the theme must be re-applied.
    pub fn window(&mut self, ctx: &egui::Context, state: &crate::proxy::State) -> bool {
        let mut changed = false;
        let mut open = self.open;
        theme::window(ctx, "Settings", [760.0, 480.0], &mut open, |ui| {
            egui::Panel::left("settings_nav")
                .default_size(180.0)
                .show(ui, |ui| {
                    for (i, s) in ["User interface", "Proxy", "Network", "Sessions"]
                        .iter()
                        .enumerate()
                    {
                        if ui.selectable_label(self.section == i, *s).clicked() {
                            self.section = i;
                        }
                    }
                });
            egui::CentralPanel::default().show(ui, |ui| match self.section {
                0 => {
                    theme::heading(ui, "Appearance");
                    ui.horizontal(|ui| {
                        ui.label("Theme:");
                        changed |= ui.radio_value(&mut self.dark, false, "Light").changed();
                        changed |= ui.radio_value(&mut self.dark, true, "Dark").changed();
                    });
                    ui.horizontal(|ui| {
                        ui.label("Font size:");
                        changed |= ui
                            .add(egui::Slider::new(&mut self.font_size, 10.0..=20.0).step_by(1.0))
                            .changed();
                    });
                    ui.add_space(8.0);
                    crate::update::settings(ui);
                    ui.add_space(8.0);
                    theme::heading(ui, "Hotkeys");
                    egui::Grid::new("hotkeys").striped(true).show(ui, |ui| {
                        for (a, k) in [
                            ("Send to Repeater", "Ctrl+R"),
                            ("Send to Intruder", "Ctrl+I"),
                            ("Issue Repeater request", "Ctrl+Space"),
                            ("Forward intercepted message", "Ctrl+F"),
                            ("Toggle intercept", "Ctrl+T"),
                            (
                                "Switch to Dashboard / Target / Proxy / Intruder / Repeater",
                                "Ctrl+Shift+D / T / P / I / R",
                            ),
                        ] {
                            ui.label(a);
                            ui.monospace(k);
                            ui.end_row();
                        }
                    });
                }
                1 => {
                    let s = state.lock().unwrap();
                    theme::heading(ui, "Proxy listeners");
                    ui.label(format!(
                        "127.0.0.1:{} (running: {})",
                        s.listener.unwrap_or(8080),
                        s.listener.is_some()
                    ));
                    ui.label(format!(
                        "{} match and replace rules ({} enabled)",
                        s.rules.len(),
                        s.rules.iter().filter(|r| r.enabled).count()
                    ));
                }
                2 => {
                    theme::heading(ui, "Connections");
                    ui.label("Timeouts: 30 seconds for connect and read.");
                    ui.label("Upstream TLS: certificates are not verified (testing proxy).");
                }
                _ => {
                    theme::heading(ui, "Session handling rules");
                    ui.label(RichText::new("No session handling rules.").color(theme::muted()));
                }
            });
        });
        self.open = open;
        changed
    }
}
