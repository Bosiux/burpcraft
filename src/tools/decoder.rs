use eframe::egui;

use crate::{http::codec, ui::editor, ui::theme};

const DECODE: [&str; 6] = ["URL", "HTML", "Base64", "ASCII hex", "Hex", "Gzip"];
const ENCODE: [&str; 8] = [
    "URL",
    "HTML",
    "Base64",
    "ASCII hex",
    "Hex",
    "Octal",
    "Binary",
    "Gzip",
];
const HASHES: [&str; 5] = ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"];

pub struct Decoder {
    pub panes: Vec<(String, bool)>, // (text, hex view)
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            panes: vec![(String::new(), false)],
        }
    }
}

impl Decoder {
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        let mut action: Option<(usize, String)> = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for (i, (text, hexv)) in self.panes.iter_mut().enumerate() {
                    ui.horizontal_top(|ui| {
                        let w = ui.available_width() - 200.0;
                        egui::Frame::new()
                            .stroke(egui::Stroke::new(1.0, theme::border()))
                            .inner_margin(4)
                            .show(ui, |ui| {
                                ui.set_width(w);
                                ui.set_height(150.0);
                                egui::ScrollArea::vertical()
                                    .id_salt(("dec", i))
                                    .show(ui, |ui| {
                                        if *hexv {
                                            editor::hex(ui, text.as_bytes());
                                        } else {
                                            ui.add(
                                                egui::TextEdit::multiline(text)
                                                    .code_editor()
                                                    .frame(egui::Frame::NONE)
                                                    .desired_width(w)
                                                    .desired_rows(9),
                                            );
                                        }
                                    });
                            });
                        ui.vertical(|ui| {
                            ui.set_width(185.0);
                            ui.horizontal(|ui| {
                                ui.radio_value(hexv, false, "Text");
                                ui.radio_value(hexv, true, "Hex");
                            });
                            let mut pick =
                                |ui: &mut egui::Ui, label: &str, items: &[&str], prefix: &str| {
                                    egui::ComboBox::from_id_salt((label, i))
                                        .selected_text(label)
                                        .width(175.0)
                                        .show_ui(ui, |ui| {
                                            for it in items {
                                                if ui.selectable_label(false, *it).clicked() {
                                                    action = Some((i, format!("{prefix}{it}")));
                                                }
                                            }
                                        });
                                };
                            pick(ui, "Decode as ...", &DECODE, "d:");
                            pick(ui, "Encode as ...", &ENCODE, "e:");
                            pick(ui, "Hash ...", &HASHES, "h:");
                            if ui
                                .add_sized([175.0, 24.0], egui::Button::new("Smart decode"))
                                .clicked()
                            {
                                action = Some((i, "smart".into()));
                            }
                        });
                    });
                    ui.add_space(8.0);
                }
            });
        if let Some((i, op)) = action {
            let input = self.panes[i].0.clone();
            let out = apply(&op, &input);
            self.panes.truncate(i + 1);
            self.panes.push((out, false));
        }
    }
}

pub fn apply(op: &str, s: &str) -> String {
    let b = s.as_bytes();
    let lossy = |v: Vec<u8>| String::from_utf8_lossy(&v).into_owned();
    match op {
        "d:URL" => lossy(codec::url_decode(s)),
        "d:HTML" => codec::html_decode(s),
        "d:Base64" => codec::base64_decode(s.trim())
            .map(lossy)
            .unwrap_or_else(|| s.into()),
        "d:ASCII hex" | "d:Hex" => codec::hex_decode(s).map(lossy).unwrap_or_else(|| s.into()),
        "d:Gzip" => {
            use std::io::Read;
            let mut out = Vec::new();
            // Decoder text is lossy UTF-8, so gzip input is accepted as hex (the Hex view) or raw bytes
            let raw = codec::hex_decode(s).unwrap_or_else(|| b.to_vec());
            match flate2::read::MultiGzDecoder::new(&raw[..]).read_to_end(&mut out) {
                Ok(_) => lossy(out),
                Err(_) => s.into(),
            }
        }
        "e:Gzip" => {
            use std::io::Write;
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let _ = gz.write_all(b);
            codec::hex_encode(&gz.finish().unwrap_or_default())
        }
        "e:URL" => codec::url_encode(b, true),
        "e:HTML" => codec::html_encode(b, true),
        "e:Base64" => codec::base64_encode(b),
        "e:ASCII hex" | "e:Hex" => codec::hex_encode(b),
        "e:Octal" => codec::octal_encode(b),
        "e:Binary" => codec::binary_encode(b),
        "smart" => smart_decode(s),
        h => codec::hash(h.trim_start_matches("h:"), b),
    }
}

/// Repeatedly peels URL / HTML / Base64 layers while each one changes the text into something printable.
pub fn smart_decode(s: &str) -> String {
    let mut cur = s.to_string();
    for _ in 0..10 {
        let t = cur.trim();
        let next = if t.contains('%') && codec::url_decode(t) != t.as_bytes() {
            String::from_utf8_lossy(&codec::url_decode(t)).into_owned()
        } else if t.contains('&') && t.contains(';') && codec::html_decode(t) != t {
            codec::html_decode(t)
        } else if t.len() >= 4
            && t.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"+/=-_".contains(&c))
            && let Some(d) = codec::base64_decode(t).filter(|d| {
                !d.is_empty()
                    && d.iter()
                        .all(|&c| c >= 0x20 || c == b'\n' || c == b'\r' || c == b'\t')
            })
            && let Ok(d) = String::from_utf8(d)
        {
            d
        } else {
            break;
        };
        cur = next;
    }
    cur
}
