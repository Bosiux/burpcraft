//! Render tab: lays out an HTML response natively in egui (block/inline flow, lists, tables, forms,
//! inline colours), on a white page like a browser. Parsing is html5ever via `scraper`.
// ponytail: no scripts, floats or positioning; the Chromium engine covers full fidelity
use std::cell::RefCell;

use eframe::egui::{
    self, Color32, FontFamily, FontId, RichText, Stroke, TextFormat, text::LayoutJob,
};
use scraper::node::Node;

type NodeRef<'a> = ego_tree::NodeRef<'a, Node>;

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
const INK: Color32 = Color32::from_rgb(0x11, 0x11, 0x11);

#[derive(Clone)]
struct Style {
    size: f32,
    bold: bool,
    italic: bool,
    mono: bool,
    pre: bool,
    underline: bool,
    strike: bool,
    color: Color32,
    bg: Color32,
}

impl Default for Style {
    fn default() -> Self {
        Self {
            size: 14.0,
            bold: false,
            italic: false,
            mono: false,
            pre: false,
            underline: false,
            strike: false,
            color: INK,
            bg: Color32::TRANSPARENT,
        }
    }
}

impl Style {
    fn format(&self) -> TextFormat {
        let family = if self.mono {
            FontFamily::Monospace
        } else {
            FontFamily::Proportional
        };
        // egui's default fonts have no bold face: emulate it with a slightly darker, larger run
        let size = if self.bold {
            self.size + 0.5
        } else {
            self.size
        };
        let color = if self.bold && self.color == INK {
            Color32::BLACK
        } else {
            self.color
        };
        TextFormat {
            font_id: FontId::new(size, family),
            color,
            background: self.bg,
            italics: self.italic,
            underline: if self.underline {
                Stroke::new(1.0, color)
            } else {
                Stroke::NONE
            },
            strikethrough: if self.strike {
                Stroke::new(1.0, color)
            } else {
                Stroke::NONE
            },
            ..Default::default()
        }
    }
}

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

/// Parses `color:`/`background:` and `display:none` out of a style attribute.
fn inline_style(style: &str, st: &mut Style) -> bool {
    for decl in style.split(';') {
        let Some((k, v)) = decl.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_ascii_lowercase());
        match k.as_str() {
            "display" if v == "none" => return false,
            "visibility" if v == "hidden" => return false,
            "color" => st.color = parse_color(&v).unwrap_or(st.color),
            "background" | "background-color" => st.bg = parse_color(&v).unwrap_or(st.bg),
            "font-weight" => st.bold = v == "bold" || v.parse::<u32>().is_ok_and(|w| w >= 600),
            "font-style" => st.italic = v == "italic",
            "text-decoration" => st.underline = v.contains("underline"),
            "font-size" => {
                if let Some(px) = v
                    .strip_suffix("px")
                    .and_then(|n| n.trim().parse::<f32>().ok())
                {
                    st.size = px.clamp(8.0, 48.0);
                } else if let Some(em) = v
                    .strip_suffix("em")
                    .and_then(|n| n.trim().parse::<f32>().ok())
                {
                    st.size = (st.size * em).clamp(8.0, 48.0);
                }
            }
            _ => {}
        }
    }
    true
}

/// Per-element (not inherited) box properties: the block's own background, spacing, border and layout.
#[derive(Default)]
struct BoxCss {
    bg: Option<Color32>,
    pad: [f32; 2],    // vertical, horizontal
    margin: [f32; 2], // vertical, horizontal
    border: Option<(f32, Color32)>,
    radius: f32,
    display: String,
    column: bool, // flex-direction: column
    cols: usize,  // grid-template-columns track count
}

/// A CSS length in px; % and auto are not resolvable here.
fn css_len(v: &str, font: f32) -> Option<f32> {
    let v = v.trim();
    let num = |s: &str| s.trim().parse::<f32>().ok();
    if v == "0" {
        Some(0.0)
    } else if let Some(n) = v.strip_suffix("px") {
        num(n)
    } else if let Some(n) = v.strip_suffix("rem") {
        num(n).map(|n| n * 16.0)
    } else if let Some(n) = v.strip_suffix("em") {
        num(n).map(|n| n * font)
    } else {
        None
    }
}

/// Top-level tokens of a value: spaces inside parentheses (repeat(3, 1fr), rgb(…)) do not split.
fn css_tokens(v: &str) -> Vec<&str> {
    let (mut out, mut depth, mut start) = (vec![], 0, None);
    for (i, c) in v.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            c if c.is_whitespace() && depth == 0 => {
                if let Some(s) = start.take() {
                    out.push(&v[s..i]);
                }
                continue;
            }
            _ => {}
        }
        start.get_or_insert(i);
    }
    if let Some(s) = start {
        out.push(&v[s..]);
    }
    out
}

impl BoxCss {
    fn parse(decls: &[&str], font: f32) -> Self {
        let mut b = Self::default();
        // "10px" -> all sides, "10px 20px" -> vertical, horizontal
        let pair = |v: &str| {
            let t: Vec<f32> = css_tokens(v)
                .iter()
                .map(|t| css_len(t, font).unwrap_or(0.0))
                .collect();
            [
                t.first().copied().unwrap_or(0.0),
                t.get(1).or(t.first()).copied().unwrap_or(0.0),
            ]
        };
        for decl in decls.iter().flat_map(|d| d.split(';')) {
            let Some((k, v)) = decl.split_once(':') else {
                continue;
            };
            let (k, v) = (
                k.trim().to_ascii_lowercase(),
                v.trim()
                    .trim_end_matches("!important")
                    .trim()
                    .to_ascii_lowercase(),
            );
            match k.as_str() {
                "background" | "background-color" => {
                    b.bg = parse_color(&v)
                        .or_else(|| css_tokens(&v).into_iter().find_map(parse_color))
                        .or(b.bg)
                }
                "padding" => b.pad = pair(&v),
                "margin" => b.margin = pair(&v),
                "border" => {
                    let t = css_tokens(&v);
                    b.border = (v != "none" && v != "0").then(|| {
                        let w = t.iter().find_map(|t| css_len(t, font)).unwrap_or(1.0);
                        (
                            w,
                            t.iter()
                                .find_map(|t| parse_color(t))
                                .unwrap_or(Color32::from_rgb(0xCC, 0xCC, 0xCC)),
                        )
                    });
                }
                "border-radius" => {
                    b.radius = css_tokens(&v)
                        .first()
                        .and_then(|t| css_len(t, font))
                        .unwrap_or(0.0)
                }
                "display" => b.display = v,
                "flex-direction" => b.column = v.starts_with("column"),
                "grid-template-columns" => {
                    b.cols = match v.strip_prefix("repeat(").and_then(|r| r.split(',').next()) {
                        Some(n) => n.trim().parse().unwrap_or(1),
                        None => css_tokens(&v).len(),
                    }
                }
                _ => {}
            }
        }
        b
    }
}

pub fn parse_color(v: &str) -> Option<Color32> {
    let v = v.trim();
    if let Some(h) = v.strip_prefix('#') {
        let h: String = if h.len() == 3 {
            h.chars().flat_map(|c| [c, c]).collect()
        } else {
            h.to_string()
        };
        let n = u32::from_str_radix(h.get(..6)?, 16).ok()?;
        return Some(Color32::from_rgb((n >> 16) as u8, (n >> 8) as u8, n as u8));
    }
    if let Some(args) = v.strip_prefix("rgb(").or_else(|| v.strip_prefix("rgba(")) {
        let p: Vec<u8> = args
            .trim_end_matches(')')
            .split(',')
            .take(3)
            .filter_map(|x| x.trim().parse().ok())
            .collect();
        return (p.len() == 3).then(|| Color32::from_rgb(p[0], p[1], p[2]));
    }
    Some(match v {
        "black" => Color32::BLACK,
        "white" => Color32::WHITE,
        "red" => Color32::from_rgb(255, 0, 0),
        "green" => Color32::from_rgb(0, 128, 0),
        "blue" => Color32::from_rgb(0, 0, 255),
        "gray" | "grey" => Color32::from_rgb(128, 128, 128),
        "orange" => Color32::from_rgb(255, 165, 0),
        "yellow" => Color32::from_rgb(255, 255, 0),
        "purple" => Color32::from_rgb(128, 0, 128),
        "navy" => Color32::from_rgb(0, 0, 128),
        "maroon" => Color32::from_rgb(128, 0, 0),
        "silver" => Color32::from_rgb(192, 192, 192),
        _ => return None,
    })
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
    // stylesheet rules in document order, then the inline style wins
    // ponytail: no specificity or inheritance rules beyond "later wins"; enough for most app pages
    let rules = f.rules;
    let mut decls: Vec<&str> = vec![];
    if !rules.is_empty()
        && let Some(er) = scraper::ElementRef::wrap(n)
    {
        decls.extend(
            rules
                .iter()
                .filter(|(sel, _)| sel.matches(&er))
                .map(|(_, d)| d.as_str()),
        );
    }
    decls.extend(el.attr("style"));
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
                // children that take part in a flex/grid layout
                let items: Vec<NodeRef> = n
                    .children()
                    .filter(|c| match c.value() {
                        Node::Element(e) => !SKIP.contains(&e.name()),
                        Node::Text(t) => !t.trim().is_empty(),
                        _ => false,
                    })
                    .collect();
                // ponytail: flex row and grid both become equal-width columns; no justify/align, spans or fr ratios
                let per_row = match bx.display.as_str() {
                    "flex" | "inline-flex" if !bx.column => items.len(),
                    "grid" | "inline-grid" => bx.cols.max(1),
                    _ => 0,
                };
                if per_row > 1 {
                    for row in items.chunks(per_row) {
                        ui.columns(per_row, |cols| {
                            for (ui, c) in cols.iter_mut().zip(row) {
                                walk(ui, *c, &s, f);
                                f.flush(ui);
                            }
                        });
                    }
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

/// Parses `<style>` text into (selector, declarations); @-rules (media queries, fonts…) are skipped.
pub fn parse_css(css: &str) -> Vec<(scraper::Selector, String)> {
    let mut clean = String::new();
    let mut rest = css;
    while let Some(i) = rest.find("/*") {
        clean.push_str(&rest[..i]);
        rest = rest[i..]
            .find("*/")
            .map(|j| &rest[i + j + 2..])
            .unwrap_or("");
    }
    clean.push_str(rest);
    let mut out = vec![];
    let mut s = clean.as_str();
    while let Some(open) = s.find('{') {
        let sel = s[..open].trim();
        if sel.starts_with('@') {
            // skip the whole block, including nested braces
            let mut depth = 0;
            let mut end = s.len();
            for (i, c) in s[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            s = &s[end..];
            continue;
        }
        let Some(close) = s[open..].find('}').map(|c| open + c) else {
            break;
        };
        if let Ok(selector) = scraper::Selector::parse(sel) {
            out.push((selector, s[open + 1..close].to_string()));
        }
        s = &s[close + 1..];
    }
    out
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

// ------------------------------------------------------------ Chromium engine

/// A Chromium-family browser for headless rendering: $BURPCRAFT_CHROME, then common install paths.
pub fn chromium_path() -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("BURPCRAFT_CHROME") {
        return Some(p.into());
    }
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        // Chrome for Testing first: built for headless use (Brave 156 hangs on --headless)
        &[
            "/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            "~/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ]
    } else if cfg!(windows) {
        &[
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        ]
    } else {
        &[
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
        ]
    };
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    candidates
        .iter()
        .map(|c| {
            c.strip_prefix("~/")
                .map_or_else(|| std::path::PathBuf::from(c), |rest| home.join(rest))
        })
        .find(|p| p.exists())
}

#[derive(Clone)]
pub enum Shot {
    Pending,
    Done(std::path::PathBuf),
    Failed(String),
}

fn shots() -> &'static std::sync::Mutex<std::collections::HashMap<u64, Shot>> {
    static M: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u64, Shot>>> =
        std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// Page written to disk for Chromium: a <base> makes relative links resolve against the real URL.
pub fn page_with_base(html: &str, base: Option<&str>) -> String {
    match base {
        Some(b) => format!(
            "<base href=\"{}\">{html}",
            crate::codec::html_encode(b.as_bytes(), false)
        ),
        None => html.to_string(),
    }
}

/// Command-line arguments for a headless run; `out` is `--screenshot=<png>` or `--dump-dom`.
/// Sub-resources go through the BurpCraft proxy.
pub fn chromium_args(
    profile: &std::path::Path,
    out: &str,
    page: &std::path::Path,
    width: u32,
    height: u32,
    scale: f32,
) -> Vec<String> {
    vec![
        "--headless=new".into(),
        "--disable-gpu".into(),
        "--hide-scrollbars".into(),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--use-mock-keychain".into(),
        "--proxy-server=127.0.0.1:8080".into(),
        // Chrome skips the proxy for localhost by default; local targets must show up too
        "--proxy-bypass-list=<-loopback>".into(),
        "--ignore-certificate-errors".into(),
        // keep Chrome's own update/telemetry requests out of the proxy history
        "--disable-background-networking".into(),
        "--disable-component-update".into(),
        "--disable-sync".into(),
        "--disable-domain-reliability".into(),
        "--no-pings".into(),
        // network-time and "AI Mode" eligibility checks still go out without these (verified on Chrome 157)
        "--disable-features=NetworkTimeServiceQuerying,AimServerEligibility,AimEnabled,AiMode"
            .into(),
        format!("--user-data-dir={}", profile.display()),
        format!("--window-size={width},{height}"),
        // HiDPI screens: capture at the screen's pixel density so the shot is sharp at full pane width
        format!("--force-device-scale-factor={scale}"),
        // lets scripts run and timers settle before the capture
        "--virtual-time-budget=3000".into(),
        out.into(),
        format!("file://{}", page.display()),
    ]
}

/// Appended to the page for the measuring pass: after load (images sized), records the document height.
const MEASURE: &str = "<script>addEventListener('load',()=>setTimeout(()=>{const d=document.documentElement;\
d.setAttribute('data-bc-h',Math.ceil(Math.max(d.scrollHeight,document.body?document.body.scrollHeight:0)))},0))</script>";

/// Page height in CSS px recorded by MEASURE in a `--dump-dom` output.
pub fn measured_height(dom: &str) -> Option<u32> {
    let rest = &dom[dom.find("data-bc-h=\"")? + 11..];
    rest[..rest.find('"')?].parse().ok()
}

/// Runs Chromium until `done()` or until it exits; gives up after 25 seconds.
pub fn run_chromium(
    cmd: &mut std::process::Command,
    done: impl Fn() -> bool,
) -> Result<(), String> {
    let mut child = cmd
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start {}: {e}", cmd.get_program().display()))?;
    let start = std::time::Instant::now();
    loop {
        // some builds keep running after writing the file, so the output appearing also counts as done
        if done() {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let _ = child.kill();
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            return if done() {
                Ok(())
            } else {
                Err(format!("Chromium exited ({status}) without output"))
            };
        }
        if start.elapsed() > std::time::Duration::from_secs(25) {
            let _ = child.kill();
            return Err("Chromium did not finish rendering within 25 seconds".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Starts (once per page+width+scale) a full-page headless Chromium screenshot and reports its state.
/// `max_px` is the tallest texture the GPU accepts; longer pages are cut there.
// ponytail: two Chromium runs (measure with --dump-dom, then shoot at that height) instead of a DevTools
// session; 100vh layouts grow with the taller window, use CDP's captureBeyondViewport if that matters
pub fn chromium_shot(
    ctx: &egui::Context,
    html: &str,
    base: Option<&str>,
    width: u32,
    scale: f32,
    max_px: u32,
) -> Shot {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (html, base, width, scale.to_bits(), max_px).hash(&mut h);
    let key = h.finish();
    if let Some(s) = shots().lock().unwrap().get(&key) {
        return s.clone();
    }
    let Some(bin) = chromium_path() else {
        return Shot::Failed(
            "No Chromium-based browser found (set BURPCRAFT_CHROME to its path)".into(),
        );
    };
    shots().lock().unwrap().insert(key, Shot::Pending);
    let dir = std::env::temp_dir().join("burpcraft-render");
    let page = page_with_base(html, base);
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        // one profile per render: concurrent renders on a shared profile exit with status 21 (profile in use)
        let profile = dir.join(format!("{key:x}-profile"));
        let result = (|| -> Result<std::path::PathBuf, String> {
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let path = |ext: &str| dir.join(format!("{key:x}.{ext}"));
            let (file, png, dom) = (path("html"), path("png"), path("dom"));
            // pass 1: measure the laid-out page height
            std::fs::write(&file, format!("{page}{MEASURE}")).map_err(|e| e.to_string())?;
            let out = std::fs::File::create(&dom).map_err(|e| e.to_string())?;
            run_chromium(
                std::process::Command::new(&bin)
                    .args(chromium_args(
                        &profile,
                        "--dump-dom",
                        &file,
                        width,
                        600,
                        scale,
                    ))
                    .stdout(out),
                || std::fs::read_to_string(&dom).is_ok_and(|d| d.contains("</html>")),
            )?;
            let limit = ((max_px as f32 / scale) as u32).max(600);
            let height = std::fs::read_to_string(&dom)
                .ok()
                .as_deref()
                .and_then(measured_height)
                .unwrap_or(2400)
                .clamp(200, limit);
            // pass 2: screenshot at that height (the PNG of an earlier run must not count as done)
            std::fs::write(&file, &page).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&png);
            let shot = format!("--screenshot={}", png.display());
            run_chromium(
                std::process::Command::new(&bin)
                    .args(chromium_args(&profile, &shot, &file, width, height, scale))
                    .stdout(std::process::Stdio::null()),
                || std::fs::metadata(&png).is_ok_and(|m| m.len() > 0),
            )?;
            Ok(png)
        })();
        let _ = std::fs::remove_dir_all(&profile);
        shots()
            .lock()
            .unwrap()
            .insert(key, result.map(Shot::Done).unwrap_or_else(Shot::Failed));
        ctx.request_repaint();
    });
    Shot::Pending
}

/// Texture for a finished Chromium screenshot (cached per file).
pub fn shot_texture(ctx: &egui::Context, png: &std::path::Path) -> Option<egui::TextureHandle> {
    let id = egui::Id::unique(("chromium-shot", png));
    if let Some(t) = ctx.data(|d| d.get_temp::<egui::TextureHandle>(id)) {
        return Some(t);
    }
    let img = image::load_from_memory(&std::fs::read(png).ok()?)
        .ok()?
        .to_rgba8();
    let ci = egui::ColorImage::from_rgba_unmultiplied(
        [img.width() as usize, img.height() as usize],
        &img,
    );
    let tex = ctx.load_texture(png.display().to_string(), ci, egui::TextureOptions::LINEAR);
    ctx.data_mut(|d| d.insert_temp(id, tex.clone()));
    Some(tex)
}

/// "Show response in browser": writes the body to a temp file (with a <base> for relative links) and opens it.
pub fn open_in_browser(html: &str, base: Option<&str>) -> std::io::Result<()> {
    let path = std::env::temp_dir().join(format!("burpcraft-render-{}.html", std::process::id()));
    let mut page = String::new();
    if let Some(b) = base {
        page += &format!(
            "<base href=\"{}\">",
            crate::codec::html_encode(b.as_bytes(), false)
        );
    }
    page += html;
    std::fs::write(&path, page)?;
    crate::misc::open_external(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colors_and_styles() {
        assert_eq!(parse_color("#f00"), Some(Color32::from_rgb(255, 0, 0)));
        assert_eq!(
            parse_color("rgb(1, 2, 3)"),
            Some(Color32::from_rgb(1, 2, 3))
        );
        assert_eq!(parse_color("nonsense"), None);
        let mut s = Style::default();
        assert!(inline_style("color: #00ff00; font-weight: 700", &mut s));
        assert!(s.bold && s.color == Color32::from_rgb(0, 255, 0));
        assert!(!inline_style("display:none", &mut s));
    }

    #[test]
    fn chromium_command() {
        let a = chromium_args(
            std::path::Path::new("/p"),
            "--dump-dom",
            std::path::Path::new("/x.html"),
            800,
            2400,
            2.0,
        );
        assert!(
            a.contains(&"--headless=new".to_string())
                && a.contains(&"--window-size=800,2400".to_string())
        );
        assert!(
            a.contains(&"--force-device-scale-factor=2".to_string())
                && a.contains(&"--dump-dom".to_string())
        );
        assert_eq!(
            measured_height(r#"<html data-bc-h="3187"><body>"#),
            Some(3187)
        );
        assert_eq!(measured_height("<html><body>"), None);
        assert!(a.contains(&"--proxy-server=127.0.0.1:8080".to_string()));
        assert!(
            a.contains(&"--disable-background-networking".to_string())
                && a.contains(&"--proxy-bypass-list=<-loopback>".to_string())
        );
        assert_eq!(a.last().unwrap(), "file:///x.html");
        assert_eq!(
            page_with_base("<p>", Some("https://a.test/x?y=\"1\"")),
            "<base href=\"https://a.test/x?y=&quot;1&quot;\"><p>"
        );
        // without a browser the request fails cleanly instead of hanging
        unsafe { std::env::set_var("BURPCRAFT_CHROME", "/nonexistent/chrome") };
        let ctx = egui::Context::default();
        let mut shot = chromium_shot(&ctx, "<p>t</p>", None, 640, 1.0, 8192);
        for _ in 0..50 {
            if !matches!(shot, Shot::Pending) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            shot = chromium_shot(&ctx, "<p>t</p>", None, 640, 1.0, 8192);
        }
        assert!(matches!(shot, Shot::Failed(ref m) if m.contains("Failed to start")));
        unsafe { std::env::remove_var("BURPCRAFT_CHROME") };
    }

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
    fn stylesheet() {
        let rules = parse_css(
            "/* c */ @media print { p { color: red } } .warn, #x { color: #c00 } p.hide { display: none }",
        );
        assert_eq!(rules.len(), 2);
        let doc = scraper::Html::parse_document(r#"<p class="warn hide">x</p>"#);
        let p = doc
            .select(&scraper::Selector::parse("p").unwrap())
            .next()
            .unwrap();
        let mut s = Style::default();
        assert!(rules[0].0.matches(&p) && inline_style(&rules[0].1, &mut s));
        assert_eq!(s.color, Color32::from_rgb(0xCC, 0, 0));
        assert!(rules[1].0.matches(&p) && !inline_style(&rules[1].1, &mut s));
    }

    #[test]
    fn box_model() {
        assert_eq!(
            css_tokens("repeat(3, 1fr) 2px  rgb(1, 2, 3)"),
            ["repeat(3, 1fr)", "2px", "rgb(1, 2, 3)"]
        );
        assert_eq!(css_len("1.5em", 10.0), Some(15.0));
        assert_eq!(css_len("50%", 10.0), None);
        let b = BoxCss::parse(
            &[
                "padding: 4px 8px; margin: 0 auto; border: 2px solid #f00",
                "background: #fff url(x.png); display: grid; grid-template-columns: repeat(3, 1fr)",
            ],
            16.0,
        );
        assert_eq!(
            (b.pad, b.margin, b.border),
            (
                [4.0, 8.0],
                [0.0, 0.0],
                Some((2.0, Color32::from_rgb(255, 0, 0)))
            )
        );
        assert_eq!(
            (b.bg, b.display.as_str(), b.cols),
            (Some(Color32::WHITE), "grid", 3)
        );
        assert_eq!(
            BoxCss::parse(
                &[
                    "grid-template-columns: 200px 1fr",
                    "display:flex;flex-direction:column"
                ],
                16.0
            )
            .cols,
            2
        );
        assert!(BoxCss::parse(&["display:flex;flex-direction:column"], 16.0).column);
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
