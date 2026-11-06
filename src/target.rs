//! Target tab: Site map tree built from proxied traffic, and the Scope rules.
use std::collections::BTreeMap;

use eframe::egui::{self, RichText};

use crate::proxy::{Entry, State};
use crate::ui::theme;

#[derive(Default)]
struct Node(BTreeMap<String, Node>);

/// Scope rules (enabled, include, url prefix), shared with the MCP server.
pub type Scope = std::sync::Arc<std::sync::Mutex<Vec<(bool, bool, String)>>>;

pub struct Target {
    pub tab: &'static str,
    pub scope: Scope,
    selected: Vec<String>, // origin followed by path segments
    selected_item: Option<usize>,
    only_in_scope: bool,
    new_rule: String,
}

impl Default for Target {
    fn default() -> Self {
        Self {
            tab: "Site map",
            scope: Default::default(),
            selected: vec![],
            selected_item: None,
            only_in_scope: false,
            new_rule: String::new(),
        }
    }
}

impl Target {
    pub fn in_scope(&self, e: &Entry) -> bool {
        let url = format!("{}{}", e.origin(), e.url);
        let m = |inc: bool| {
            self.scope
                .lock()
                .unwrap()
                .iter()
                .any(|(on, i, p)| *on && *i == inc && url.starts_with(p.as_str()))
        };
        m(true) && !m(false)
    }

    pub fn add_to_scope(&mut self, e: &Entry) {
        let p = format!("{}/", e.origin());
        let mut scope = self.scope.lock().unwrap();
        if !scope.iter().any(|(_, i, x)| *i && *x == p) {
            scope.push((true, true, p));
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, state: &State) -> Option<(&'static str, Entry)> {
        theme::frame_chrome().show(ui, |ui| {
            ui.horizontal(|ui| {
                for t in ["Site map", "Scope", "Issue definitions"] {
                    if theme::sub_tab(ui, self.tab == t, t).clicked() {
                        self.tab = t;
                    }
                }
            });
        });
        match self.tab {
            "Site map" => self.site_map(ui, state),
            "Scope" => {
                self.scope_ui(ui);
                None
            }
            _ => {
                ui.add_space(20.0);
                ui.label(
                    RichText::new(
                        "Issue definitions are listed here once scanning issues are available.",
                    )
                    .color(theme::muted()),
                );
                None
            }
        }
    }

    fn site_map(&mut self, ui: &mut egui::Ui, state: &State) -> Option<(&'static str, Entry)> {
        let entries: Vec<Entry> = state
            .lock()
            .unwrap()
            .history
            .iter()
            .filter(|e| !self.only_in_scope || self.in_scope(e))
            .cloned()
            .collect();
        let mut root = Node::default();
        for e in &entries {
            let mut n = root.0.entry(e.origin()).or_default();
            for seg in e.path().split('/').filter(|s| !s.is_empty()) {
                n = n.0.entry(seg.to_string()).or_default();
            }
        }
        ui.horizontal(|ui| {
            let desc = if self.only_in_scope {
                "Showing only in-scope items"
            } else {
                "Hiding not found items; hiding CSS, image and general binary content"
            };
            if ui
                .button(format!("Filter: {desc}"))
                .on_hover_text("Click to toggle in-scope filter")
                .clicked()
            {
                self.only_in_scope = !self.only_in_scope;
            }
        });
        let mut action = None;
        egui::Panel::left("sitemap_tree")
            .default_size(320.0)
            .resizable(true)
            .show(ui, |ui| {
                egui::ScrollArea::both()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        for (origin, node) in &root.0 {
                            let path = vec![origin.clone()];
                            let in_scope =
                                self.scope.lock().unwrap().iter().any(|(on, inc, p)| {
                                    *on && *inc && p.starts_with(origin.as_str())
                                });
                            self.tree(ui, origin, node, path, in_scope, &mut action, &entries);
                        }
                    });
            });
        let items: Vec<Entry> = entries.into_iter().filter(|e| self.matches(e)).collect();
        let h = ui.available_height();
        egui::Panel::top("sitemap_items")
            .resizable(true)
            .default_size(h * 0.4)
            .show(ui, |ui| {
                if let Some(a) =
                    crate::ui::history_table(ui, "sitemap", &items, &mut self.selected_item, false)
                {
                    action = Some(a);
                }
            });
        if let Some(e) = self
            .selected_item
            .and_then(|id| items.iter().find(|e| e.id == id))
        {
            let mut req = String::from_utf8_lossy(&e.req).into_owned();
            let mut resp = crate::proxy::display(&e.resp);
            crate::ui::editor::split(
                ui,
                ("smreq", e.id),
                &mut req,
                false,
                &mut resp,
                Some(&format!("{}{}", e.origin(), e.url)),
            );
        }
        action
    }

    fn matches(&self, e: &Entry) -> bool {
        let Some((origin, segs)) = self.selected.split_first() else {
            return true;
        };
        if e.origin() != *origin {
            return false;
        }
        let path: Vec<&str> = e.path().split('/').filter(|s| !s.is_empty()).collect();
        path.len() >= segs.len() && path.iter().zip(segs).all(|(a, b)| a == b)
    }

    #[allow(clippy::too_many_arguments)]
    fn tree(
        &mut self,
        ui: &mut egui::Ui,
        label: &str,
        node: &Node,
        path: Vec<String>,
        in_scope: bool,
        action: &mut Option<(&'static str, Entry)>,
        entries: &[Entry],
    ) {
        let selected = self.selected == path;
        let color = if in_scope || self.scope.lock().unwrap().is_empty() {
            theme::text()
        } else {
            theme::muted()
        };
        let text = RichText::new(label).color(color);
        let resp = if node.0.is_empty() {
            ui.horizontal(|ui| {
                ui.add_space(18.0);
                ui.selectable_label(selected, text)
            })
            .inner
        } else {
            let id = ui.make_persistent_id(("sm", &path));
            let (_, header, _) = egui::collapsing_header::CollapsingState::load_with_default_open(
                ui.ctx(),
                id,
                false,
            )
            .show_header(ui, |ui| ui.selectable_label(selected, text))
            .body(|ui| {
                for (seg, child) in &node.0 {
                    let mut p = path.clone();
                    p.push(seg.clone());
                    self.tree(ui, seg, child, p, in_scope, action, entries);
                }
            });
            header.inner
        };
        if resp.clicked() {
            self.selected = path.clone();
            self.selected_item = None;
        }
        if path.len() == 1 {
            resp.context_menu(|ui| {
                if ui.button("Add to scope").clicked() {
                    if let Some(e) = entries.iter().find(|e| e.origin() == path[0]) {
                        self.add_to_scope(e);
                    }
                    ui.close();
                }
                if ui.button("Remove from scope").clicked() {
                    self.scope
                        .lock()
                        .unwrap()
                        .retain(|(_, _, p)| !p.starts_with(path[0].as_str()));
                    ui.close();
                }
                if ui.button("Copy URL").clicked() {
                    ui.ctx().copy_text(path[0].clone());
                    ui.close();
                }
                if ui.button("Delete host").clicked() {
                    *action = Some((
                        "delete_host",
                        entries
                            .iter()
                            .find(|e| e.origin() == path[0])
                            .cloned()
                            .unwrap(),
                    ));
                    ui.close();
                }
            });
        }
    }

    fn scope_ui(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            theme::heading(ui, "Target scope");
            ui.label("Define the in-scope targets for your current work. This configuration affects the behavior of tools throughout the suite.");
            ui.add_space(8.0);
            for include in [true, false] {
                ui.strong(if include { "Include in scope" } else { "Exclude from scope" });
                ui.horizontal_top(|ui| {
                    ui.vertical(|ui| {
                        ui.set_width(90.0);
                        if ui.add_sized([85.0, 24.0], egui::Button::new("Add")).clicked() && !self.new_rule.trim().is_empty() {
                            self.scope.lock().unwrap().push((true, include, self.new_rule.trim().to_string()));
                            self.new_rule.clear();
                        }
                        if ui.add_sized([85.0, 24.0], egui::Button::new("Clear")).clicked() {
                            self.scope.lock().unwrap().retain(|(_, i, _)| *i != include);
                        }
                    });
                    egui::Frame::new().stroke(egui::Stroke::new(1.0, theme::border())).inner_margin(4).show(ui, |ui| {
                        ui.set_min_size(egui::vec2(600.0, 120.0));
                        egui::Grid::new(("scope", include)).striped(true).num_columns(3).spacing([16.0, 4.0]).show(ui, |ui| {
                            ui.strong("Enabled");
                            ui.strong("Prefix");
                            ui.label("");
                            ui.end_row();
                            let mut remove = None;
                            let mut scope = self.scope.lock().unwrap();
                            for (i, (on, inc, p)) in scope.iter_mut().enumerate().filter(|(_, r)| r.1 == include) {
                                let _ = inc;
                                ui.checkbox(on, "");
                                ui.monospace(p.as_str());
                                if ui.small_button("Remove").clicked() {
                                    remove = Some(i);
                                }
                                ui.end_row();
                            }
                            if let Some(i) = remove {
                                scope.remove(i);
                            }
                        });
                    });
                });
                ui.add_space(10.0);
            }
            ui.horizontal(|ui| {
                ui.label("URL prefix for new rule:");
                ui.add(egui::TextEdit::singleline(&mut self.new_rule).hint_text("https://example.com/").desired_width(400.0));
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_rules() {
        let mut t = Target::default();
        let e = Entry {
            id: 1,
            host: "a.com".into(),
            port: 443,
            tls: true,
            method: "GET".into(),
            url: "/admin/x".into(),
            status: 200,
            req: vec![],
            resp: vec![],
            edited: false,
            time: String::new(),
            ip: String::new(),
            listener: 8080,
            comment: String::new(),
            highlight: None,
            tool: "Proxy",
        };
        assert!(!t.in_scope(&e));
        t.add_to_scope(&e);
        assert!(t.in_scope(&e));
        t.scope
            .lock()
            .unwrap()
            .push((true, false, "https://a.com/admin".into()));
        assert!(!t.in_scope(&e));
        t.selected = vec!["https://a.com".into(), "admin".into()];
        assert!(t.matches(&e));
    }
}
