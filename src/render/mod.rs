//! Render tab: lays out an HTML response natively in egui (block/inline flow, lists, tables, forms,
//! inline colours), on a white page like a browser. Parsing is html5ever via `scraper`.
// ponytail: no scripts and approximate flex/grid/float layout; the Chromium engine covers full fidelity
use eframe::egui::{Color32, FontFamily, FontId, Stroke, TextFormat};
use scraper::node::Node;

mod chromium;
mod css;
mod native;

pub use chromium::{
    Shot, chromium_path, chromium_shot, open_in_browser, run_chromium, shot_texture,
};
pub use native::show;

pub(crate) type NodeRef<'a> = ego_tree::NodeRef<'a, Node>;

const INK: Color32 = Color32::from_rgb(0x11, 0x11, 0x11);

#[derive(Clone)]
pub(crate) struct Style {
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
