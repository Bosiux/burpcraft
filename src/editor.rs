//! HTTP message editor (Pretty / Raw / Hex) with syntax colouring, and the Inspector side panel.
use eframe::egui::{self, Color32, FontId, RichText, TextFormat, text::LayoutJob};

use crate::codec;
use crate::theme;

#[derive(Clone, Copy, PartialEq, Default)]
enum View {
    #[default]
    Pretty,
    Raw,
    Hex,
    Render,
}

/// Indents a JSON body for the read-only Pretty view (strings are copied verbatim).
pub fn pretty_json(s: &str) -> String {
    let mut out = String::new();
    let (mut depth, mut in_str, mut esc) = (0usize, false, false);
    let nl = |out: &mut String, d: usize| {
        out.push('\n');
        out.push_str(&"  ".repeat(d));
    };
    for c in s.chars() {
        if in_str {
            out.push(c);
            match (esc, c) {
                (true, _) => esc = false,
                (_, '\\') => esc = true,
                (_, '"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
            }
            '{' | '[' => {
                depth += 1;
                out.push(c);
                nl(&mut out, depth);
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                let trimmed = out.trim_end().len();
                if out[..trimmed].ends_with(['{', '[']) {
                    out.truncate(trimmed); // empty object/array stays on one line
                } else {
                    nl(&mut out, depth);
                }
                out.push(c);
            }
            ',' => {
                out.push(c);
                nl(&mut out, depth);
            }
            ':' => out.push_str(": "),
            c if c.is_whitespace() => {}
            c => out.push(c),
        }
    }
    out
}

/// Burp-like colouring: request/status line, header names, query params, body.
pub fn highlight(text: &str, wrap: f32) -> LayoutJob {
    let font = FontId::monospace(13.0);
    let fmt = |c: Color32| TextFormat {
        font_id: font.clone(),
        color: c,
        ..Default::default()
    };
    let mut job = LayoutJob::default();
    job.wrap.max_width = wrap;
    if text.contains('§') {
        // Intruder template: shade payload positions like the original
        for (i, part) in text.split('§').enumerate() {
            if i > 0 {
                job.append(
                    "§",
                    0.0,
                    TextFormat {
                        background: theme::select(),
                        ..fmt(theme::ORANGE_DARK)
                    },
                );
            }
            let f = if i % 2 == 1 {
                TextFormat {
                    background: theme::select(),
                    ..fmt(theme::text())
                }
            } else {
                fmt(theme::text())
            };
            job.append(part, 0.0, f);
        }
        return job;
    }
    // ponytail: colour only the first 256 KiB, the rest is plain to keep frames fast
    let cut = text
        .char_indices()
        .nth(256 * 1024)
        .map(|(i, _)| i)
        .unwrap_or(text.len());
    let (text, rest) = text.split_at(cut);
    let (head, body) = match text.find("\r\n\r\n").or_else(|| text.find("\n\n")) {
        Some(i) => text.split_at(i),
        None => (text, ""),
    };
    for (n, line) in head.split_inclusive('\n').enumerate() {
        if n == 0 {
            let mut it = line.splitn(3, ' ');
            let (a, b, c) = (it.next().unwrap_or(""), it.next(), it.next());
            job.append(a, 0.0, fmt(theme::text()));
            if let Some(b) = b {
                job.append(" ", 0.0, fmt(theme::text()));
                params(&mut job, b, &fmt);
            }
            if let Some(c) = c {
                job.append(" ", 0.0, fmt(theme::text()));
                job.append(c, 0.0, fmt(theme::text()));
            }
        } else if let Some((k, v)) = line.split_once(':') {
            job.append(k, 0.0, fmt(theme::hdr_name()));
            job.append(":", 0.0, fmt(theme::text()));
            job.append(v, 0.0, fmt(theme::hdr_value()));
        } else {
            job.append(line, 0.0, fmt(theme::text()));
        }
    }
    let trimmed = body.trim_start();
    if !trimmed.contains('<')
        && !trimmed.starts_with(['{', '['])
        && trimmed.contains('=')
        && !trimmed.contains('\n')
    {
        let lead = body.len() - trimmed.len();
        job.append(&body[..lead], 0.0, fmt(theme::text()));
        params(&mut job, trimmed, &fmt);
    } else {
        job.append(body, 0.0, fmt(theme::text()));
    }
    job.append(rest, 0.0, fmt(theme::text()));
    job
}

/// Colours `a=1&b=2` (optionally after a `path?`).
fn params(job: &mut LayoutJob, s: &str, fmt: &dyn Fn(Color32) -> TextFormat) {
    let (path, query) = match s.split_once('?') {
        Some((p, q)) => (Some(p), q),
        None if s.starts_with('/') || s.starts_with("http") => (Some(s), ""),
        None => (None, s),
    };
    if let Some(p) = path {
        job.append(p, 0.0, fmt(theme::text()));
        if s.contains('?') {
            job.append("?", 0.0, fmt(theme::text()));
        }
    }
    for (i, kv) in query
        .split('&')
        .enumerate()
        .filter(|(_, kv)| !kv.is_empty() || query.is_empty())
    {
        if query.is_empty() {
            break;
        }
        if i > 0 {
            job.append("&", 0.0, fmt(theme::text()));
        }
        match kv.split_once('=') {
            Some((k, v)) => {
                job.append(k, 0.0, fmt(theme::PARAM_NAME));
                job.append("=", 0.0, fmt(theme::text()));
                job.append(v, 0.0, fmt(theme::param_value()));
            }
            None => job.append(kv, 0.0, fmt(theme::PARAM_NAME)),
        }
    }
}

/// Small "Pretty Raw Hex" switcher like the one above each message pane.
fn view_tabs(ui: &mut egui::Ui, view: &mut View, response: bool) {
    let tabs = [
        (View::Pretty, "Pretty"),
        (View::Raw, "Raw"),
        (View::Hex, "Hex"),
        (View::Render, "Render"),
    ];
    for (v, name) in &tabs[..if response { 4 } else { 3 }] {
        let v = *v;
        if theme::sub_tab(ui, *view == v, name).clicked() {
            *view = v;
        }
    }
}

/// Full message pane: title row, view tabs and the editor body. Returns true if edited.
pub fn message(
    ui: &mut egui::Ui,
    id: impl egui::AsIdSalt,
    title: &str,
    text: &mut String,
    editable: bool,
) -> bool {
    message_at(ui, id, title, text, editable, None)
}

/// Like [`message`], with the page URL so the Render view can resolve relative links and images.
pub fn message_at(
    ui: &mut egui::Ui,
    id: impl egui::AsIdSalt,
    title: &str,
    text: &mut String,
    editable: bool,
    base: Option<&str>,
) -> bool {
    let id = ui.make_persistent_id(id);
    // dev hook: BURPCRAFT_VIEW=Render opens response panes on that view (screenshots)
    let start =
        if title == "Response" && std::env::var("BURPCRAFT_VIEW").is_ok_and(|v| v == "Render") {
            View::Render
        } else {
            View::Pretty
        };
    let mut view: View = ui.data_mut(|d| *d.get_temp_mut_or_insert_with(id, || start));
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).strong().size(14.0));
        ui.add_space(8.0);
        view_tabs(ui, &mut view, title == "Response");
    });
    ui.separator();
    match view {
        View::Hex => hex(ui, text.as_bytes()),
        View::Render => {
            let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
            let engine_id = ui.make_persistent_id("render-engine");
            let mut chromium: bool = ui.data_mut(|d| {
                *d.get_persisted_mut_or_insert_with(engine_id, || {
                    crate::render::chromium_path().is_some()
                })
            });
            ui.horizontal(|ui| {
                ui.label("Engine:");
                ui.selectable_value(&mut chromium, true, "Chromium");
                ui.selectable_value(&mut chromium, false, "Native");
                if ui.button("Show response in browser").clicked() {
                    let _ = crate::render::open_in_browser(body, base);
                }
            });
            ui.data_mut(|d| d.insert_persisted(engine_id, chromium));
            egui::ScrollArea::both().id_salt(id.with("render")).auto_shrink([false; 2]).show(ui, |ui| {
                if !chromium {
                    crate::render::show(ui, body);
                    return;
                }
                // round the width so resizing the pane does not re-render on every pixel
                let width = ((ui.available_width() as u32).max(320) / 64) * 64;
                let (ppp, max_px) = (ui.ctx().pixels_per_point(), ui.ctx().input(|i| i.max_texture_side) as u32);
                match crate::render::chromium_shot(ui.ctx(), body, base, width, ppp, max_px) {
                    crate::render::Shot::Pending => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label("Rendering with Chromium...");
                        });
                    }
                    crate::render::Shot::Done(png) => match crate::render::shot_texture(ui.ctx(), &png) {
                        Some(tex) => {
                            ui.add(egui::Image::new(egui::load::SizedTexture::new(tex.id(), tex.size_vec2() / ppp.max(1.0))));
                        }
                        None => {
                            ui.label("Chromium produced an unreadable screenshot; showing the native render.");
                            crate::render::show(ui, body);
                        }
                    },
                    crate::render::Shot::Failed(msg) => {
                        ui.label(RichText::new(format!("{msg}. Showing the native render.")).color(theme::muted()));
                        crate::render::show(ui, body);
                    }
                }
            });
        }
        _ => {
            let pretty = view == View::Pretty;
            egui::ScrollArea::both()
                .id_salt(id)
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    let mut layouter = |ui: &egui::Ui, buf: &dyn egui::TextBuffer, wrap: f32| {
                        let job = if pretty {
                            highlight(buf.as_str(), wrap)
                        } else {
                            let mut j = LayoutJob::simple(
                                buf.as_str().to_owned(),
                                FontId::monospace(13.0),
                                theme::text(),
                                wrap,
                            );
                            j.wrap.max_width = wrap;
                            j
                        };
                        ui.fonts_mut(|f| f.layout_job(job))
                    };
                    let w = ui.available_width();
                    let mut ro = match text.split_once("\r\n\r\n") {
                        Some((h, b))
                            if pretty && !editable && b.trim_start().starts_with(['{', '[']) =>
                        {
                            format!("{h}\r\n\r\n{}", pretty_json(b))
                        }
                        _ => text.clone(),
                    };
                    let buf: &mut String = if editable { text } else { &mut ro };
                    let out = egui::TextEdit::multiline(buf)
                        .id(id.with("te"))
                        .code_editor()
                        .frame(egui::Frame::NONE)
                        .desired_width(w)
                        .desired_rows(30)
                        .layouter(&mut layouter)
                        .show(ui);
                    changed = editable && out.response.changed();
                });
        }
    }
    ui.data_mut(|d| d.insert_temp(id, view));
    changed
}

/// Side-by-side Request | Response panes with a draggable divider; both use the same frame so headers line up.
pub fn split(
    ui: &mut egui::Ui,
    id: impl egui::AsIdSalt + Clone,
    req: &mut String,
    req_editable: bool,
    resp: &mut String,
    base: Option<&str>,
) {
    let frame = egui::Frame::new().inner_margin(egui::Margin::symmetric(6, 4));
    let w = ui.available_width();
    egui::Panel::left(("split", id.clone()))
        .frame(frame)
        .default_size(w / 2.0)
        .resizable(true)
        .show(ui, |ui| {
            message(ui, ("req", id.clone()), "Request", req, req_editable);
        });
    egui::CentralPanel::default().frame(frame).show(ui, |ui| {
        message_at(ui, ("resp", id), "Response", resp, false, base);
    });
}

pub fn hex(ui: &mut egui::Ui, data: &[u8]) {
    let row_h = 18.0;
    let rows = data.len().div_ceil(16);
    let mono = |s: String| RichText::new(s).monospace().color(theme::text());
    egui::ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show_rows(ui, row_h, rows, |ui, range| {
            for (off, hex, asc) in
                codec::hexdump_rows(&data[range.start * 16..(range.end * 16).min(data.len())])
            {
                ui.horizontal(|ui| {
                    ui.label(mono(format!("{:08x}", off + range.start * 16)).color(theme::muted()));
                    ui.label(mono(format!("{hex:<47}")));
                    ui.label(mono(asc));
                });
            }
        });
}

/// Inspector panel content for a request (and optional response).
pub fn inspector(ui: &mut egui::Ui, req: &str, resp: Option<&str>) {
    ui.label(RichText::new("Inspector").strong().size(15.0));
    ui.separator();
    egui::ScrollArea::vertical()
        .id_salt("inspector")
        .show(ui, |ui| {
            let head = req.split("\r\n\r\n").next().unwrap_or("");
            let first = head.lines().next().unwrap_or("");
            let mut parts = first.split_whitespace();
            let (method, path, proto) = (
                parts.next().unwrap_or(""),
                parts.next().unwrap_or(""),
                parts.next().unwrap_or(""),
            );
            section(ui, "Request attributes", 3, |ui| {
                kv_grid(
                    ui,
                    "attrs",
                    &[
                        ("Method".into(), method.into()),
                        ("Path".into(), path.split('?').next().unwrap_or("").into()),
                        ("Protocol".into(), proto.into()),
                    ],
                );
            });
            let query: Vec<(String, String)> = path
                .split_once('?')
                .map(|(_, q)| split_params(q, '&'))
                .unwrap_or_default();
            section(ui, "Request query parameters", query.len(), |ui| {
                kv_grid(ui, "query", &query)
            });
            let body = req.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
            let ct = crate::net::header(req, "content-type").unwrap_or_default();
            let bparams = if ct.contains("x-www-form-urlencoded") {
                split_params(body, '&')
            } else {
                vec![]
            };
            section(ui, "Request body parameters", bparams.len(), |ui| {
                kv_grid(ui, "body", &bparams)
            });
            let cookies: Vec<(String, String)> = crate::net::header(req, "cookie")
                .map(|c| split_params(&c.replace("; ", ";"), ';'))
                .unwrap_or_default();
            section(ui, "Request cookies", cookies.len(), |ui| {
                kv_grid(ui, "cookies", &cookies)
            });
            let headers = header_list(head);
            section(ui, "Request headers", headers.len(), |ui| {
                kv_grid(ui, "rh", &headers)
            });
            if let Some(resp) = resp.filter(|r| !r.is_empty()) {
                let h = header_list(resp.split("\r\n\r\n").next().unwrap_or(""));
                section(ui, "Response headers", h.len(), |ui| {
                    kv_grid(ui, "resph", &h)
                });
            }
        });
}

fn split_params(s: &str, sep: char) -> Vec<(String, String)> {
    s.split(sep)
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (
                k.trim().to_string(),
                String::from_utf8_lossy(&codec::url_decode(v)).into_owned(),
            )
        })
        .collect()
}

fn header_list(head: &str) -> Vec<(String, String)> {
    head.lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.into(), v.trim().into()))
        .collect()
}

fn section(ui: &mut egui::Ui, title: &str, count: usize, add: impl FnOnce(&mut egui::Ui)) {
    egui::CollapsingHeader::new(RichText::new(format!("{title}   {count}")).strong())
        .id_salt(title)
        .show(ui, add);
}

fn kv_grid(ui: &mut egui::Ui, id: &str, rows: &[(String, String)]) {
    if rows.is_empty() {
        ui.label(RichText::new("No items").color(theme::muted()));
        return;
    }
    egui::Grid::new(id)
        .striped(true)
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            ui.label(RichText::new("Name").color(theme::muted()));
            ui.label(RichText::new("Value").color(theme::muted()));
            ui.end_row();
            for (k, v) in rows {
                ui.label(RichText::new(k).monospace().color(theme::hdr_name()));
                ui.label(RichText::new(v).monospace());
                ui.end_row();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_and_render() {
        assert_eq!(
            pretty_json(r#"{"e":{},"f":[]}"#),
            "{\n  \"e\": {},\n  \"f\": []\n}"
        );
        assert_eq!(
            pretty_json(r#"{"a":[1,2],"b":"x,{y}"}"#),
            "{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": \"x,{y}\"\n}"
        );
    }
}
