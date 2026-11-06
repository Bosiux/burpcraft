//! Native egui rendering: block/inline flow (`walk`), row/box-model layout and the `show` entry point.
use std::cell::RefCell;

use eframe::egui::{self, Color32, RichText, Stroke, text::LayoutJob};
use scraper::node::Node;

use super::css::{
    BoxCss, Track, css_decls, grid_tracks, inline_style, parse_color, parse_css, place,
};
use super::{INK, NodeRef, Style};

const SKIP: [&str; 9] = [
    "script", "style", "head", "template", "noscript", "svg", "iframe", "object", "meta",
];
const BLOCKS: [&str; 22] = [
    "p",
    "div",
    "section",
    "article",
    "header",
    "footer",
    "nav",
    "main",
    "aside",
    "form",
    "fieldset",
    "figure",
    "figcaption",
    "address",
    "dl",
    "dt",
    "dd",
    "center",
    "details",
    "summary",
    "body",
    "html",
];
const LINK: Color32 = Color32::from_rgb(0x1A, 0x0D, 0xAB);

type Widget = Box<dyn FnOnce(&mut egui::Ui)>;

struct Flow<'a> {
    rules: &'a [(scraper::Selector, String)],
    job: LayoutJob,
    /// Inline run of text and form controls waiting to be laid out on wrapped lines.
    items: Vec<Result<LayoutJob, Widget>>,
    space: bool, // last emitted char was whitespace (for collapsing)
    budget: usize,
}

impl Flow<'_> {
    fn text(&mut self, t: &str, st: &Style) {
        if st.pre {
            self.job.append(t, 0.0, st.format());
            self.space = t.ends_with(char::is_whitespace);
            return;
        }
        let mut out = String::new();
        for c in t.chars() {
            if c.is_whitespace() {
                if !self.space && !(self.job.text.is_empty() && out.is_empty()) {
                    out.push(' ');
                }
                self.space = true;
            } else {
                out.push(c);
                self.space = false;
            }
        }
        if !out.is_empty() {
            self.job.append(&out, 0.0, st.format());
        }
    }

    /// Inline form control: keeps flowing on the same line as the surrounding text.
    fn widget(&mut self, w: impl FnOnce(&mut egui::Ui) + 'static) {
        let job = std::mem::take(&mut self.job);
        if !job.text.is_empty() {
            self.items.push(Ok(job));
        }
        self.items.push(Err(Box::new(w)));
        self.space = false;
    }

    fn flush(&mut self, ui: &mut egui::Ui) {
        let job = std::mem::take(&mut self.job);
        if self.items.is_empty() {
            if !job.text.trim().is_empty() {
                let mut job = job;
                job.wrap.max_width = ui.available_width();
                ui.label(job);
            }
        } else {
            if !job.text.trim().is_empty() {
                self.items.push(Ok(job));
            }
            let items = std::mem::take(&mut self.items);
            ui.horizontal_wrapped(|ui| {
                for it in items {
                    match it {
                        Ok(j) => {
                            ui.label(j);
                        }
                        Err(w) => w(ui),
                    }
                }
            });
        }
        self.space = false;
    }
}

fn inner_text(n: NodeRef) -> String {
    let mut s = String::new();
    for d in n.descendants() {
        if let Node::Text(t) = d.value() {
            s.push_str(t);
        }
    }
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Lays out `cells` side by side at `place` (x, width) offsets; the row is as tall as its tallest cell.
fn row(ui: &mut egui::Ui, cells: &[Vec<NodeRef>], place: &[(f32, f32)], s: &Style, f: &mut Flow) {
    let top = ui.cursor().min;
    let mut bottom = top.y;
    for (cell, &(x, w)) in cells.iter().zip(place) {
        let rect =
            egui::Rect::from_min_size(top + egui::vec2(x, 0.0), egui::vec2(w, f32::INFINITY));
        let mut ui = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(rect)
                .layout(egui::Layout::top_down(egui::Align::LEFT)),
        );
        ui.set_width(w);
        for c in cell {
            walk(&mut ui, *c, s, f);
        }
        f.flush(&mut ui);
        bottom = bottom.max(ui.min_rect().bottom());
    }
    let width = place.last().map_or(0.0, |&(x, w)| x + w);
    ui.advance_cursor_after_rect(egui::Rect::from_min_size(
        top,
        egui::vec2(width, bottom - top.y),
    ));
}

fn walk(ui: &mut egui::Ui, n: NodeRef, st: &Style, f: &mut Flow) {
    if f.budget == 0 {
        return;
    }
    f.budget -= 1;
    let el = match n.value() {
        Node::Text(t) => return f.text(t, st),
        Node::Element(e) => e,
        Node::Document | Node::Fragment => {
            for c in n.children() {
                walk(ui, c, st, f);
            }
            return;
        }
        _ => return,
    };
    let name = el.name();
    if SKIP.contains(&name) || el.attr("hidden").is_some() {
        return;
    }
    let mut s = st.clone();
    let decls = css_decls(n, f.rules);
    for d in &decls {
        if !inline_style(d, &mut s) {
            return;
        }
    }
    let bx = BoxCss::parse(&decls, s.size);
    if let Some(c) = el.attr("color").and_then(parse_color) {
        s.color = c;
    }
    let kids = |ui: &mut egui::Ui, s: &Style, f: &mut Flow| {
        for c in n.children() {
            walk(ui, c, s, f);
        }
    };
    match name {
        "br" => {
            f.job.append("\n", 0.0, s.format());
            f.space = true;
        }
        "hr" => {
            f.flush(ui);
            ui.separator();
        }
        "a" => {
            s.color = LINK;
            s.underline = true;
            kids(ui, &s, f);
        }
        "b" | "strong" | "th" => {
            s.bold = true;
            kids(ui, &s, f);
        }
        "i" | "em" | "cite" | "var" | "dfn" => {
            s.italic = true;
            kids(ui, &s, f);
        }
        "u" | "ins" => {
            s.underline = true;
            kids(ui, &s, f);
        }
        "s" | "strike" | "del" => {
            s.strike = true;
            kids(ui, &s, f);
        }
        "small" => {
            s.size *= 0.85;
            kids(ui, &s, f);
        }
        "big" => {
            s.size *= 1.2;
            kids(ui, &s, f);
        }
        "mark" => {
            s.bg = Color32::from_rgb(255, 255, 0);
            kids(ui, &s, f);
        }
        "code" | "kbd" | "samp" | "tt" => {
            s.mono = true;
            s.size *= 0.92;
            s.bg = Color32::from_rgb(0xF0, 0xF0, 0xF0);
            kids(ui, &s, f);
        }
        "img" => {
            let src = el.attr("src").unwrap_or("");
            let size_attr = |a: &str| {
                el.attr(a)
                    .and_then(|v| v.trim_end_matches("px").parse::<f32>().ok())
            };
            if let Some(tex) = texture(ui.ctx(), src) {
                let natural = tex.size_vec2();
                let (w, h) = match (size_attr("width"), size_attr("height")) {
                    (Some(w), Some(h)) => (w, h),
                    (Some(w), None) => (w, natural.y * w / natural.x),
                    (None, Some(h)) => (natural.x * h / natural.y, h),
                    _ => (natural.x, natural.y),
                };
                let max = ui.available_width().max(50.0);
                let size = if w > max {
                    egui::vec2(max, h * max / w)
                } else {
                    egui::vec2(w, h)
                };
                f.widget(move |ui| {
                    ui.add(egui::Image::new(egui::load::SizedTexture::new(
                        tex.id(),
                        size,
                    )));
                });
            } else {
                let alt = el
                    .attr("alt")
                    .filter(|a| !a.is_empty())
                    .unwrap_or_else(|| src.rsplit('/').next().unwrap_or("image"));
                let mut p = s.clone();
                p.color = Color32::from_rgb(0x70, 0x70, 0x70);
                p.bg = Color32::from_rgb(0xEE, 0xEE, 0xEE);
                f.text(&format!(" [image: {alt}] "), &p);
            }
        }
        h if h.len() == 2 && h.starts_with('h') && h.as_bytes()[1].is_ascii_digit() => {
            let level = (h.as_bytes()[1] - b'0') as usize;
            f.flush(ui);
            ui.add_space(6.0);
            s.bold = true;
            s.size = [32.0, 24.0, 18.7, 16.0, 13.3, 10.7]
                .get(level - 1)
                .copied()
                .unwrap_or(16.0);
            kids(ui, &s, f);
            f.flush(ui);
            ui.add_space(4.0);
        }
        "pre" => {
            f.flush(ui);
            s.pre = true;
            s.mono = true;
            egui::Frame::new()
                .fill(Color32::from_rgb(0xF6, 0xF6, 0xF6))
                .inner_margin(6)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    kids(ui, &s, f);
                    f.flush(ui);
                });
        }
        "blockquote" => {
            f.flush(ui);
            ui.indent(n.id(), |ui| {
                kids(ui, &s, f);
                f.flush(ui);
            });
        }
        "ul" | "ol" | "menu" => {
            f.flush(ui);
            let ordered = name == "ol";
            let mut k = el
                .attr("start")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1);
            ui.indent(n.id(), |ui| {
                for c in n.children() {
                    let is_li = matches!(c.value(), Node::Element(e) if e.name() == "li");
                    if !is_li {
                        walk(ui, c, &s, f);
                        continue;
                    }
                    let marker = if ordered {
                        format!("{k}. ")
                    } else {
                        "\u{2022} ".to_string()
                    };
                    k += 1;
                    f.job.append(&marker, 0.0, s.format());
                    f.space = true;
                    for g in c.children() {
                        walk(ui, g, &s, f);
                    }
                    f.flush(ui);
                }
            });
            ui.add_space(4.0);
        }
        "table" => {
            f.flush(ui);
            table(ui, n, &s, f);
            ui.add_space(6.0);
        }
        "input" => {
            let kind = el.attr("type").unwrap_or("text").to_ascii_lowercase();
            if kind == "hidden" {
                return;
            }
            let val = el.attr("value").unwrap_or("").to_string();
            match kind.as_str() {
                "submit" | "button" | "reset" | "image" => {
                    let label = if val.is_empty() {
                        "Submit".to_string()
                    } else {
                        val
                    };
                    f.widget(move |ui| {
                        let _ = ui.add(
                            egui::Button::new(RichText::new(label).color(INK))
                                .fill(Color32::from_rgb(0xEF, 0xEF, 0xEF)),
                        );
                    });
                }
                "checkbox" | "radio" => {
                    let mut on = el.attr("checked").is_some();
                    f.widget(move |ui| {
                        ui.add_enabled(false, egui::Checkbox::without_text(&mut on));
                    });
                }
                _ => {
                    let mut text = if kind == "password" {
                        "\u{2022}".repeat(val.chars().count())
                    } else {
                        val
                    };
                    let hint = el.attr("placeholder").unwrap_or("").to_string();
                    f.widget(move |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut text)
                                .hint_text(hint)
                                .desired_width(220.0)
                                .interactive(false),
                        );
                    });
                }
            }
        }
        "button" => {
            let label = inner_text(n);
            f.widget(move |ui| {
                let _ = ui.add(
                    egui::Button::new(RichText::new(label).color(INK))
                        .fill(Color32::from_rgb(0xEF, 0xEF, 0xEF)),
                );
            });
        }
        "select" => {
            let first = n
                .descendants()
                .filter_map(|d| match d.value() {
                    Node::Element(e) if e.name() == "option" => {
                        Some((d, e.attr("selected").is_some()))
                    }
                    _ => None,
                })
                .fold(None, |acc: Option<(NodeRef, bool)>, (d, sel)| match acc {
                    Some((_, true)) => acc,
                    _ if sel || acc.is_none() => Some((d, sel)),
                    _ => acc,
                });
            let label = first.map(|(d, _)| inner_text(d)).unwrap_or_default();
            let id = n.id();
            f.widget(move |ui| {
                ui.add_enabled_ui(false, |ui| {
                    egui::ComboBox::from_id_salt(id)
                        .selected_text(label)
                        .show_ui(ui, |_| {})
                });
            });
        }
        "textarea" => {
            let mut t = inner_text(n);
            f.widget(move |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut t)
                        .desired_rows(3)
                        .interactive(false),
                );
            });
        }
        "li" => {
            // a stray <li> outside a list
            f.flush(ui);
            f.job.append("\u{2022} ", 0.0, s.format());
            kids(ui, &s, f);
            f.flush(ui);
        }
        _ if BLOCKS.contains(&name)
            || matches!(
                bx.display.as_str(),
                "block" | "flex" | "grid" | "inline-block" | "list-item"
            ) =>
        {
            f.flush(ui);
            let px = |v: f32| v.clamp(0.0, 127.0) as i8;
            ui.add_space(bx.margin[0]);
            let frame = egui::Frame::new()
                .fill(bx.bg.unwrap_or(Color32::TRANSPARENT))
                .inner_margin(egui::Margin::symmetric(px(bx.pad[1]), px(bx.pad[0])))
                .outer_margin(egui::Margin::symmetric(px(bx.margin[1]), 0))
                .stroke(bx.border.map_or(Stroke::NONE, |(w, c)| Stroke::new(w, c)))
                .corner_radius(bx.radius.clamp(0.0, 255.0) as u8);
            frame.show(ui, |ui| {
                if bx.bg.is_some() || bx.border.is_some() {
                    ui.set_width(ui.available_width());
                }
                // visible children that take part in a flex/grid/float layout, with their own box CSS
                let items: Vec<(NodeRef, BoxCss)> = n
                    .children()
                    .filter_map(|c| match c.value() {
                        Node::Element(e)
                            if !SKIP.contains(&e.name()) && e.attr("hidden").is_none() =>
                        {
                            let d = css_decls(c, f.rules);
                            let mut tmp = Style::default();
                            d.iter()
                                .all(|d| inline_style(d, &mut tmp))
                                .then(|| (c, BoxCss::parse(&d, s.size)))
                        }
                        Node::Text(t) if !t.trim().is_empty() => Some((c, BoxCss::default())),
                        _ => None,
                    })
                    .collect();
                let avail = ui.available_width();
                let gap = bx.gap[1].max(ui.spacing().item_spacing.x);
                let flex_row = matches!(bx.display.as_str(), "flex" | "inline-flex") && !bx.column;
                let grid = matches!(bx.display.as_str(), "grid" | "inline-grid")
                    .then(|| grid_tracks(&bx.grid, s.size, avail, gap))
                    .unwrap_or_default();
                let floats = !flex_row
                    && grid.is_empty()
                    && items
                        .iter()
                        .any(|(_, b)| matches!(b.float.as_str(), "left" | "right"));
                // ponytail: no flex-wrap, align-items, order or grid spans/rows; position:absolute/fixed
                // elements stay in place in document order (overlays and banners still show their content)
                if flex_row && items.len() > 1 {
                    let tracks: Vec<Track> = items
                        .iter()
                        .map(|(c, b)| flex_track(*c, b, s.size))
                        .collect();
                    let cells: Vec<Vec<NodeRef>> = items.iter().map(|(c, _)| vec![*c]).collect();
                    row(ui, &cells, &place(&tracks, avail, gap, &bx.justify), &s, f);
                } else if grid.len() > 1 {
                    for (i, chunk) in items.chunks(grid.len()).enumerate() {
                        if i > 0 {
                            ui.add_space(bx.gap[0]);
                        }
                        let cells: Vec<Vec<NodeRef>> =
                            chunk.iter().map(|(c, _)| vec![*c]).collect();
                        row(
                            ui,
                            &cells,
                            &place(&grid[..chunk.len()], avail, gap, &bx.justify),
                            &s,
                            f,
                        );
                    }
                } else if floats {
                    // ponytail: floats become side columns (left floats, the rest of the content, right floats);
                    // text does not wrap under a float that ends early
                    let (mut left, mut mid, mut right) = (vec![], vec![], vec![]);
                    for (c, b) in &items {
                        match b.float.as_str() {
                            "left" => left.push((vec![*c], float_track(*c, b))),
                            "right" => right.push((vec![*c], float_track(*c, b))),
                            _ => mid.push(*c),
                        }
                    }
                    let (cells, tracks): (Vec<_>, Vec<_>) = left
                        .into_iter()
                        .chain([(mid, Track::Fr(1.0))])
                        .chain(right)
                        .unzip();
                    row(ui, &cells, &place(&tracks, avail, gap, ""), &s, f);
                } else {
                    kids(ui, &s, f);
                    f.flush(ui);
                }
            });
            ui.add_space(bx.margin[0]);
            if name == "p" || name == "dl" || name == "figure" {
                ui.add_space(8.0);
            }
            if name == "dd" {
                ui.add_space(2.0);
            }
        }
        _ => kids(ui, &s, f),
    }
}

/// Width of a flex item: flex-grow, then width/flex-basis, else an estimate of its text width.
fn flex_track(n: NodeRef, b: &BoxCss, font: f32) -> Track {
    if b.grow > 0.0 {
        return Track::Fr(b.grow);
    }
    if let Some(w) = b.width {
        return w;
    }
    // ponytail: content width guessed from the character count (~0.6em each, plus slack for button padding); text-less items share the rest
    let chars = inner_text(n).chars().count();
    if chars == 0 {
        Track::Fr(1.0)
    } else {
        Track::Px(chars as f32 * font * 0.6 + 2.0 * b.pad[1] + 24.0)
    }
}

/// Width of a float's side column: its CSS width, an `<img width>`, else a third of the row.
fn float_track(n: NodeRef, b: &BoxCss) -> Track {
    let attr = match n.value() {
        Node::Element(e) => e
            .attr("width")
            .and_then(|w| w.trim_end_matches("px").parse().ok()),
        _ => None,
    };
    b.width.or(attr.map(Track::Px)).unwrap_or(Track::Pct(33.0))
}

/// Image bytes for an `<img src>`: data: URIs, or an image the proxy already captured (matched by URL suffix).
pub fn image_bytes(src: &str) -> Option<Vec<u8>> {
    if let Some(rest) = src.strip_prefix("data:") {
        let (meta, data) = rest.split_once(',')?;
        return if meta.ends_with(";base64") {
            crate::codec::base64_decode(data)
        } else {
            Some(crate::codec::url_decode(data))
        };
    }
    if src.is_empty() {
        return None;
    }
    let store = crate::proxy::images().lock().unwrap();
    if let Some(b) = store.get(src) {
        return Some(b.clone());
    }
    // relative or root-relative src: base URL is unknown here, so match on the path suffix
    let tail = src.trim_start_matches("./");
    let tail = if tail.starts_with('/') {
        tail.to_string()
    } else {
        format!("/{tail}")
    };
    store
        .iter()
        .find(|(k, _)| k.ends_with(&tail))
        .map(|(_, v)| v.clone())
}

/// Decoded texture for `src`, cached in egui memory (failures are cached too).
fn texture(ctx: &egui::Context, src: &str) -> Option<egui::TextureHandle> {
    let id = egui::Id::unique(("render-img", src));
    if let Some(t) = ctx.data(|d| d.get_temp::<Option<egui::TextureHandle>>(id)) {
        return t;
    }
    let tex = image_bytes(src)
        .and_then(|b| image::load_from_memory(&b).ok())
        .map(|img| {
            let rgba = img.to_rgba8();
            let ci = egui::ColorImage::from_rgba_unmultiplied(
                [rgba.width() as usize, rgba.height() as usize],
                &rgba,
            );
            ctx.load_texture(
                src.chars().take(80).collect::<String>(),
                ci,
                egui::TextureOptions::LINEAR,
            )
        });
    // only remember a miss for data: URIs; proxied images may still arrive later
    if tex.is_some() || src.starts_with("data:") {
        ctx.data_mut(|d| d.insert_temp(id, tex.clone()));
    }
    tex
}

fn table(ui: &mut egui::Ui, n: NodeRef, st: &Style, f: &mut Flow) {
    let is = |d: &NodeRef, tag: &str| matches!(d.value(), Node::Element(e) if e.name() == tag);
    // own rows only: a table nested in a cell is drawn by that cell
    let rows: Vec<NodeRef> = n
        .descendants()
        .filter(|d| {
            is(d, "tr") && d.ancestors().find(|a| is(a, "table")).map(|a| a.id()) == Some(n.id())
        })
        .collect();
    let cols = rows.iter().map(|r| r.children().filter(|c| matches!(c.value(), Node::Element(e) if e.name() == "td" || e.name() == "th")).count()).max().unwrap_or(0);
    if cols == 0 {
        return;
    }
    egui::Frame::new()
        .stroke(Stroke::new(1.0, Color32::from_rgb(0xCC, 0xCC, 0xCC)))
        .inner_margin(4)
        .show(ui, |ui| {
            egui::Grid::new(n.id())
                .striped(true)
                .num_columns(cols)
                .spacing([14.0, 4.0])
                .show(ui, |ui| {
                    for r in rows {
                        for c in r.children() {
                            let Node::Element(e) = c.value() else {
                                continue;
                            };
                            if e.name() != "td" && e.name() != "th" {
                                continue;
                            }
                            let mut s = st.clone();
                            s.bold = e.name() == "th";
                            if let Some(style) = e.attr("style") {
                                inline_style(style, &mut s);
                            }
                            // full cell content: images, links and form controls, not just the text
                            ui.vertical(|ui| {
                                for g in c.children() {
                                    walk(ui, g, &s, f);
                                }
                                f.flush(ui);
                            });
                        }
                        ui.end_row();
                    }
                });
        });
}

type Parsed = (u64, scraper::Html, Vec<(scraper::Selector, String)>);

thread_local! {
    // ponytail: one-entry parse cache; the pane re-renders every frame with the same body
    static CACHE: RefCell<Option<Parsed>> = const { RefCell::new(None) };
}

/// Draws `html` as a page. Returns the document title, if any.
pub fn show(ui: &mut egui::Ui, html: &str) -> Option<String> {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    html.hash(&mut h);
    let key = h.finish();
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c.as_ref().is_none_or(|(k, _, _)| *k != key) {
            let doc = scraper::Html::parse_document(html);
            let css: String = doc
                .tree
                .root()
                .descendants()
                .filter(|d| matches!(d.value(), Node::Element(e) if e.name() == "style"))
                .map(|d| {
                    d.children()
                        .filter_map(|t| {
                            if let Node::Text(t) = t.value() {
                                Some(t.to_string())
                            } else {
                                None
                            }
                        })
                        .collect::<String>()
                })
                .collect();
            let rules = parse_css(&css);
            *c = Some((key, doc, rules));
        }
        let (_, doc, rules) = c.as_ref().unwrap();
        let title = doc
            .tree
            .root()
            .descendants()
            .find(|d| matches!(d.value(), Node::Element(e) if e.name() == "title"))
            .map(inner_text);
        let body_bg = doc
            .tree
            .root()
            .descendants()
            .find_map(|d| match d.value() {
                Node::Element(e) if e.name() == "body" => e.attr("bgcolor").and_then(parse_color),
                _ => None,
            })
            .unwrap_or(Color32::WHITE);
        egui::Frame::new()
            .fill(body_bg)
            .inner_margin(12)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.style_mut().visuals.override_text_color = None;
                let mut f = Flow {
                    rules,
                    job: LayoutJob::default(),
                    items: vec![],
                    space: false,
                    budget: 20_000,
                };
                walk(ui, doc.tree.root(), &Style::default(), &mut f);
                f.flush(ui);
            });
        title
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_sources() {
        // 1x1 PNG
        let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==";
        let bytes = image_bytes(&format!("data:image/png;base64,{png}")).unwrap();
        assert_eq!(image::load_from_memory(&bytes).unwrap().width(), 1);
        crate::proxy::images()
            .lock()
            .unwrap()
            .insert("https://a.test/img/logo.png".into(), bytes.clone());
        assert_eq!(image_bytes("/img/logo.png"), Some(bytes.clone()));
        assert_eq!(image_bytes("img/logo.png"), Some(bytes));
        assert_eq!(image_bytes("/nope.png"), None);
    }

    #[test]
    fn renders_without_panicking() {
        // headless egui pass over a page that exercises every element branch
        let html = r##"<html><head><title>Test page</title><style>p{}</style></head><body bgcolor="#fafafa">
            <h1>Title</h1><p>Hello <b>bold</b> <i>it</i> <a href="/x">link</a> <code>x</code><br>next</p>
            <ul><li>one</li><li>two<ol start="3"><li>three</li></ol></li></ul><hr>
            <table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table>
            <form><input type="text" value="v"><input type="password" value="pw"><input type="checkbox" checked>
            <select><option>a</option><option selected>b</option></select><textarea>t</textarea>
            <input type="submit" value="Go"><button>Btn</button><input type="hidden" value="h"></form>
            <pre>  pre  text</pre><blockquote>q</blockquote><img alt="logo"><div style="display:none">x</div>
            <div style="display:flex;background:#eee;padding:8px;border:1px solid #ccc;border-radius:4px"><span>a</span><b>b</b></div>
            <section style="display:grid;grid-template-columns:repeat(2,1fr)"><div>1</div><div>2</div><div>3</div></section>
            <div style="display:flex;justify-content:space-between"><b style="flex:1">a</b><i style="width:20%">b</i><span>c</span><p style="display:none">x</p></div>
            <div><img src="x.png" width="80" style="float:left"><div style="float:right;width:100px">r</div><p>text</p></div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(100px,1fr));gap:8px"><div>1</div><div>2</div></div>
            <table><tr><td><img src="x.png" alt="i"><a href="/">l</a><table><tr><td>nested</td></tr></table></td></tr></table>
            <script>alert(1)</script></body></html>"##;
        let ctx = egui::Context::default();
        let mut title = None;
        let mut out = ctx.run_ui(Default::default(), |ui| {
            title = show(ui, html);
        });
        out.textures_delta.clear(); // no renderer in tests to upload font atlases to
        assert_eq!(title.as_deref(), Some("Test page"));
    }
}
