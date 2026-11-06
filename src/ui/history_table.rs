//! The sortable HTTP-history / Logger table widget and its right-click menu,
//! shared by the Proxy history and Logger screens, plus the `curl` exporter.

use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};

use crate::proxy::Entry;
use crate::{engage, ui::theme};

/// Shared HTTP history / Logger table with the original's columns and context menu.
pub(crate) fn history_table(
    ui: &mut egui::Ui,
    id: &str,
    rows: &[Entry],
    selected: &mut Option<usize>,
    logger: bool,
) -> Option<(&'static str, Entry)> {
    let cols: &[(&str, f32)] = if logger {
        &[
            ("#", 50.0),
            ("Time", 140.0),
            ("Tool", 80.0),
            ("Method", 60.0),
            ("Host", 200.0),
            ("Path", 260.0),
            ("Status code", 80.0),
            ("Length", 70.0),
            ("MIME type", 70.0),
        ]
    } else {
        &[
            ("#", 50.0),
            ("Host", 200.0),
            ("Method", 60.0),
            ("URL", 280.0),
            ("Params", 55.0),
            ("Edited", 55.0),
            ("Status code", 80.0),
            ("Length", 70.0),
            ("MIME type", 70.0),
            ("Extension", 70.0),
            ("Title", 160.0),
            ("Notes", 120.0),
            ("TLS", 40.0),
            ("IP", 110.0),
            ("Cookies", 160.0),
            ("Time", 140.0),
            ("Listener port", 90.0),
        ]
    };
    let check = |b: bool| if b { "\u{2713}" } else { "" }.to_string();
    // ponytail: all cells are rebuilt every frame; cache per entry if histories reach 100k+ rows
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|e| {
            if logger {
                vec![
                    e.id.to_string(),
                    e.time.clone(),
                    e.tool.into(),
                    e.method.clone(),
                    e.origin(),
                    e.url.clone(),
                    e.status.to_string(),
                    e.resp.len().to_string(),
                    e.mime(),
                ]
            } else {
                vec![
                    e.id.to_string(),
                    e.origin(),
                    e.method.clone(),
                    e.url.clone(),
                    check(e.params()),
                    check(e.edited),
                    if e.status == 0 {
                        String::new()
                    } else {
                        e.status.to_string()
                    },
                    e.resp.len().to_string(),
                    e.mime(),
                    e.extension().into(),
                    e.title(),
                    e.comment.clone(),
                    check(e.tls),
                    e.ip.clone(),
                    e.cookies(),
                    e.time.clone(),
                    e.listener.to_string(),
                ]
            }
        })
        .collect();
    let sort_id = ui.make_persistent_id((id, "sort"));
    let mut sort: Option<(usize, bool)> = ui.data(|d| d.get_temp(sort_id));
    let mut order: Vec<usize> = (0..rows.len()).collect();
    if let Some((c, asc)) = sort {
        order.sort_by(|&a, &b| {
            let (x, y) = (&cells[a][c], &cells[b][c]);
            let o = match (x.parse::<f64>(), y.parse::<f64>()) {
                (Ok(p), Ok(q)) => p.total_cmp(&q),
                _ => x.cmp(y),
            };
            if asc { o } else { o.reverse() }
        });
    }
    let mut action = None;
    let mut tb = TableBuilder::new(ui)
        .id_salt(id)
        .striped(true)
        .sense(egui::Sense::click())
        .resizable(true)
        .stick_to_bottom(sort.is_none());
    for (_, w) in cols {
        tb = tb.column(Column::initial(*w).clip(true));
    }
    tb.header(22.0, |mut r| {
        for (i, (h, _)) in cols.iter().enumerate() {
            r.col(|ui| {
                let arrow = match sort {
                    Some((c, true)) if c == i => " ^",
                    Some((c, false)) if c == i => " v",
                    _ => "",
                };
                if ui
                    .add(
                        egui::Label::new(RichText::new(format!("{h}{arrow}")).strong())
                            .sense(egui::Sense::click()),
                    )
                    .clicked()
                {
                    // ascending -> descending -> unsorted, like the original
                    sort = match sort {
                        Some((c, true)) if c == i => Some((i, false)),
                        Some((c, false)) if c == i => None,
                        _ => Some((i, true)),
                    };
                }
            });
        }
    })
    .body(|body| {
        body.rows(20.0, rows.len(), |mut row| {
            let k = order[row.index()];
            let e = &rows[k];
            row.set_selected(*selected == Some(e.id));
            let vals = cells[k].clone();
            let hl = e.highlight.map(|i| theme::HIGHLIGHTS[i].1);
            for v in vals {
                row.col(|ui| {
                    if let Some(c) = hl {
                        ui.painter().rect_filled(
                            ui.max_rect().expand2(egui::vec2(4.0, 2.0)),
                            0.0,
                            c,
                        );
                    }
                    if v == "\u{2713}" {
                        // default fonts lack a check glyph, so paint the tick
                        let c = ui.max_rect().left_center() + egui::vec2(8.0, 0.0);
                        let pts = [
                            c + egui::vec2(-4.0, 0.0),
                            c + egui::vec2(-1.0, 3.5),
                            c + egui::vec2(5.0, -4.0),
                        ];
                        ui.painter()
                            .line(pts.to_vec(), egui::Stroke::new(1.8, theme::text()));
                    } else {
                        ui.add(egui::Label::new(v).truncate().selectable(false));
                    }
                });
            }
            let resp = row.response();
            if resp.clicked() {
                *selected = Some(e.id);
            }
            resp.context_menu(|ui| {
                *selected = Some(e.id);
                ui.label(RichText::new(format!("{}{}", e.origin(), e.url)).color(theme::muted()));
                ui.separator();
                let mut item = |ui: &mut egui::Ui, label: &str, key: &'static str| {
                    if ui.button(label).clicked() {
                        action = Some((key, e.clone()));
                        ui.close();
                    }
                };
                item(ui, "Add to scope", "scope");
                item(ui, "Do active scan", "scan");
                item(ui, "DOM Invader scan", "domi");
                ui.separator();
                item(ui, "Send to Intruder", "intruder");
                item(ui, "Send to Repeater", "repeater");
                item(ui, "Send to Sequencer", "sequencer");
                item(ui, "Send to Decoder", "decoder");
                item(ui, "Send to Organizer", "organizer");
                ui.menu_button("Send to Comparer", |ui| {
                    item(ui, "Request", "cmp_req");
                    item(ui, "Response", "cmp_resp");
                });
                ui.menu_button("Engagement tools", |ui| {
                    for (i, t) in engage::TOOLS.iter().enumerate() {
                        let key: &'static str =
                            ["eng:0", "eng:1", "eng:2", "eng:3", "eng:4", "eng:5"][i];
                        item(ui, t, key);
                    }
                });
                ui.separator();
                if ui.button("Copy URL").clicked() {
                    ui.ctx().copy_text(format!("{}{}", e.origin(), e.url));
                    ui.close();
                }
                if ui.button("Copy as curl command").clicked() {
                    ui.ctx().copy_text(curl_command(e));
                    ui.close();
                }
                ui.menu_button("Highlight", |ui| {
                    item(ui, "None", "hl:none");
                    for (i, (n, _)) in theme::HIGHLIGHTS.iter().enumerate() {
                        let key: &'static str = [
                            "hl:0", "hl:1", "hl:2", "hl:3", "hl:4", "hl:5", "hl:6", "hl:7",
                        ][i];
                        item(ui, n, key);
                    }
                });
                if !logger {
                    item(ui, "Add comment", "comment");
                }
                ui.separator();
                item(ui, "Delete item", "delete");
                item(
                    ui,
                    if logger { "Clear log" } else { "Clear history" },
                    "clear",
                );
            });
        });
    });
    ui.data_mut(|d| d.insert_temp(sort_id, sort));
    action
}

/// `curl` invocation reproducing a request (headers curl manages itself are skipped).
fn curl_command(e: &Entry) -> String {
    let q = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let text = String::from_utf8_lossy(&e.req).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut cmd = format!("curl -i -s -k -X {} \\\n", q(&e.method));
    for l in head.lines().skip(1) {
        if let Some((k, _)) = l.split_once(':')
            && !["host", "content-length", "connection"]
                .contains(&k.trim().to_ascii_lowercase().as_str())
        {
            cmd += &format!("    -H {} \\\n", q(l));
        }
    }
    if !body.is_empty() {
        cmd += &format!("    --data-binary {} \\\n", q(body));
    }
    cmd + &format!("    {}", q(&format!("{}{}", e.origin(), e.url)))
}
