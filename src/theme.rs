//! Light theme modelled on the observable look of the original: white panels, grey chrome, orange accent.
use std::sync::atomic::{AtomicBool, Ordering};

use eframe::egui::{self, Color32, CornerRadius, FontFamily, FontId, RichText, Stroke, TextStyle};

pub const ORANGE: Color32 = Color32::from_rgb(0xFF, 0x66, 0x33);
pub const ORANGE_DARK: Color32 = Color32::from_rgb(0xE0, 0x52, 0x22);
pub const PARAM_NAME: Color32 = Color32::from_rgb(0xC4, 0x4B, 0x00);

static DARK: AtomicBool = AtomicBool::new(false);

fn pick(light: (u8, u8, u8), dark: (u8, u8, u8)) -> Color32 {
    let (r, g, b) = if DARK.load(Ordering::Relaxed) {
        dark
    } else {
        light
    };
    Color32::from_rgb(r, g, b)
}

pub fn select() -> Color32 {
    pick((0xFF, 0xD8, 0xC6), (0x6A, 0x36, 0x22))
}
pub fn text() -> Color32 {
    pick((0x1E, 0x1E, 0x1E), (0xDD, 0xDD, 0xDD))
}
pub fn muted() -> Color32 {
    pick((0x80, 0x80, 0x80), (0x96, 0x96, 0x96))
}
pub fn chrome() -> Color32 {
    pick((0xF2, 0xF2, 0xF2), (0x2B, 0x2D, 0x30))
}
pub fn border() -> Color32 {
    pick((0xD0, 0xD0, 0xD0), (0x4A, 0x4C, 0x50))
}
pub fn hdr_name() -> Color32 {
    pick((0x1F, 0x4F, 0x9C), (0x7A, 0xA7, 0xF0))
}
pub fn hdr_value() -> Color32 {
    text()
}
pub fn param_value() -> Color32 {
    hdr_name()
}
fn bg() -> Color32 {
    pick((0xFF, 0xFF, 0xFF), (0x1E, 0x1F, 0x22))
}

/// Row highlight colours offered by the "Highlight" context menu.
pub const HIGHLIGHTS: [(&str, Color32); 8] = [
    ("Red", Color32::from_rgb(0xFF, 0x64, 0x64)),
    ("Orange", Color32::from_rgb(0xFF, 0xC8, 0x64)),
    ("Yellow", Color32::from_rgb(0xFF, 0xFF, 0x64)),
    ("Green", Color32::from_rgb(0x64, 0xFF, 0x64)),
    ("Cyan", Color32::from_rgb(0x64, 0xFF, 0xFF)),
    ("Blue", Color32::from_rgb(0x64, 0x64, 0xFF)),
    ("Pink", Color32::from_rgb(0xFF, 0xC8, 0xC8)),
    ("Magenta", Color32::from_rgb(0xFF, 0x64, 0xFF)),
];

pub fn apply(ctx: &egui::Context, dark: bool, size: f32) {
    DARK.store(dark, Ordering::Relaxed);
    let mut style = (*ctx.global_style()).clone();
    style.text_styles = [
        (
            TextStyle::Small,
            FontId::new(size - 2.0, FontFamily::Proportional),
        ),
        (TextStyle::Body, FontId::new(size, FontFamily::Proportional)),
        (
            TextStyle::Button,
            FontId::new(size, FontFamily::Proportional),
        ),
        (
            TextStyle::Heading,
            FontId::new(size + 4.0, FontFamily::Proportional),
        ),
        (
            TextStyle::Monospace,
            FontId::new(size, FontFamily::Monospace),
        ),
    ]
    .into();
    style.spacing.item_spacing = egui::vec2(6.0, 4.0);
    style.spacing.button_padding = egui::vec2(10.0, 3.0);
    style.spacing.interact_size.y = 24.0;
    let v = &mut style.visuals;
    *v = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    v.panel_fill = bg();
    v.window_fill = bg();
    v.extreme_bg_color = bg();
    v.faint_bg_color = pick((0xF7, 0xF7, 0xF7), (0x26, 0x27, 0x2A));
    v.override_text_color = Some(text());
    v.selection.bg_fill = select();
    v.selection.stroke = Stroke::new(1.0, ORANGE_DARK);
    v.hyperlink_color = ORANGE_DARK;
    v.window_corner_radius = CornerRadius::same(4);
    v.window_stroke = Stroke::new(1.0, border());
    for (w, fill) in [
        (&mut v.widgets.inactive, bg()),
        (
            &mut v.widgets.hovered,
            pick((0xF4, 0xF4, 0xF4), (0x33, 0x35, 0x38)),
        ),
        (
            &mut v.widgets.active,
            pick((0xE8, 0xE8, 0xE8), (0x3C, 0x3E, 0x42)),
        ),
        (
            &mut v.widgets.open,
            pick((0xF0, 0xF0, 0xF0), (0x36, 0x38, 0x3B)),
        ),
    ] {
        w.bg_fill = fill;
        w.weak_bg_fill = fill;
        w.corner_radius = CornerRadius::same(3);
        w.bg_stroke = Stroke::new(1.0, border());
        w.fg_stroke.color = text();
    }
    v.widgets.noninteractive.bg_stroke =
        Stroke::new(1.0, pick((0xE2, 0xE2, 0xE2), (0x3A, 0x3C, 0x40)));
    v.widgets.noninteractive.fg_stroke.color = text();
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, pick((0xA8, 0xA8, 0xA8), (0x6A, 0x6C, 0x70)));
    ctx.set_global_style(style);
}

/// Primary-tab look: plain text, orange + underline when selected, orange fill when flagged.
pub fn main_tab(ui: &mut egui::Ui, selected: bool, flagged: bool, label: &str) -> egui::Response {
    tab(ui, selected, flagged, label, 14.0, 10.0)
}

pub fn sub_tab(ui: &mut egui::Ui, selected: bool, label: &str) -> egui::Response {
    tab(ui, selected, false, label, 13.0, 7.0)
}

fn tab(
    ui: &mut egui::Ui,
    selected: bool,
    flagged: bool,
    label: &str,
    size: f32,
    pad: f32,
) -> egui::Response {
    let color = if selected { ORANGE_DARK } else { text() };
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), FontId::proportional(size), color);
    let desired = galley.size() + egui::vec2(pad * 2.0, 10.0);
    let (rect, resp) = ui.allocate_exact_size(desired, egui::Sense::click());
    let p = ui.painter();
    if flagged {
        p.rect_filled(rect, 2.0, ORANGE);
    } else if resp.hovered() && !selected {
        p.rect_filled(rect, 2.0, pick((0xEC, 0xEC, 0xEC), (0x36, 0x38, 0x3B)));
    }
    let text_color = if flagged { Color32::WHITE } else { color };
    p.galley_with_override_text_color(rect.center() - galley.size() / 2.0, galley, text_color);
    if selected {
        let y = rect.bottom() - 1.0;
        p.line_segment(
            [
                egui::pos2(rect.left() + 2.0, y),
                egui::pos2(rect.right() - 2.0, y),
            ],
            Stroke::new(2.5, ORANGE),
        );
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// The orange call-to-action button (Send, Forward when intercepting, Start attack…).
pub fn primary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(label).color(Color32::WHITE).strong())
            .fill(ORANGE)
            .stroke(Stroke::new(1.0, ORANGE_DARK))
            .corner_radius(3),
    )
}

pub fn bg_color() -> Color32 {
    bg()
}

pub fn frame_chrome() -> egui::Frame {
    egui::Frame::new()
        .fill(chrome())
        .inner_margin(egui::Margin::symmetric(8, 2))
}

pub fn heading(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(15.0).strong().color(ORANGE_DARK));
}
