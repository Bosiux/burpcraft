//! Global search (Burp's "Search" window): text or regex across HTTP history, Logger, WebSockets,
//! Repeater tabs and issues, with a snippet per hit and a jump to the matching item.
use crate::App;

#[derive(Clone, PartialEq)]
pub enum Place {
    History(usize),
    Logger(usize),
    WebSocket(usize),
    Repeater(usize),
    Issue(usize),
}

pub struct Hit {
    pub place: Place,
    pub label: String,
    pub snippet: String,
}

pub struct Query {
    pub text: String,
    pub regex: bool,
    pub case: bool,
}

#[derive(Default)]
pub struct Search {
    pub open: bool,
    text: String,
    regex: bool,
    case: bool,
    hits: Vec<Hit>,
    error: String,
}

const MAX_HITS: usize = 5000;

impl Query {
    /// Byte offset of the first match in `hay`, or a regex error.
    fn matcher(&self) -> Result<impl Fn(&str) -> Option<(usize, usize)>, String> {
        let pat = if self.regex {
            self.text.clone()
        } else {
            regex::escape(&self.text)
        };
        let re = regex::RegexBuilder::new(&pat)
            .case_insensitive(!self.case)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(move |hay: &str| re.find(hay).map(|m| (m.start(), m.end())))
    }
}

/// ~80 characters of context around a match, on one line.
fn snippet(hay: &str, (a, b): (usize, usize)) -> String {
    let start = hay.floor_char_boundary(a.saturating_sub(40));
    let end = hay.ceil_char_boundary((b + 40).min(hay.len()));
    hay[start..end].replace(['\r', '\n', '\t'], " ")
}

/// Searches every tool; `items` lists (place, label, text) so the matching itself stays testable.
pub fn find(
    q: &Query,
    items: impl Iterator<Item = (Place, String, String)>,
) -> Result<Vec<Hit>, String> {
    if q.text.is_empty() {
        return Ok(vec![]);
    }
    let m = q.matcher()?;
    Ok(items
        .filter_map(|(place, label, text)| {
            m(&text).map(|r| Hit {
                place,
                label,
                snippet: snippet(&text, r),
            })
        })
        .take(MAX_HITS)
        .collect())
}

fn corpus(
    state: &crate::proxy::State,
    repeater: &crate::tools::Repeater,
) -> Vec<(Place, String, String)> {
    let s = state.lock().unwrap();
    let msg = |req: &[u8], resp: &[u8]| {
        format!(
            "{}\r\n\r\n{}",
            crate::proxy::display(req),
            crate::proxy::display(resp)
        )
    };
    let mut out = vec![];
    for e in &s.history {
        out.push((
            Place::History(e.id),
            format!("Proxy #{} {} {}{}", e.id, e.method, e.origin(), e.url),
            msg(&e.req, &e.resp),
        ));
    }
    for e in &s.logger {
        out.push((
            Place::Logger(e.id),
            format!(
                "Logger #{} {} {} {}{}",
                e.id,
                e.tool,
                e.method,
                e.origin(),
                e.url
            ),
            msg(&e.req, &e.resp),
        ));
    }
    for m in &s.ws {
        out.push((
            Place::WebSocket(m.id),
            format!("WebSocket #{} {}", m.id, m.url),
            String::from_utf8_lossy(&m.data).into_owned(),
        ));
    }
    for (i, t) in repeater.tabs.iter().enumerate() {
        out.push((
            Place::Repeater(i),
            format!("Repeater tab {}", t.name),
            format!("{}\r\n\r\n{}", t.req, t.resp),
        ));
    }
    for i in &s.issues {
        out.push((
            Place::Issue(i.id),
            format!("Issue: {} {}{}", i.name, i.origin, i.path),
            format!("{} {} {}", i.name, i.detail, i.path),
        ));
    }
    out
}

impl App {
    /// Search window; clicking a hit selects that item in its tool.
    pub fn search_window(&mut self, ctx: &eframe::egui::Context) {
        use eframe::egui;
        if !self.search.open {
            return;
        }
        let mut open = true;
        let mut go = None;
        egui::Window::new("Search")
            .open(&mut open)
            .default_size([760.0, 480.0])
            .show(ctx, |ui| {
                let sr = &mut self.search;
                let mut run = false;
                ui.horizontal(|ui| {
                    run |= ui
                        .add(
                            egui::TextEdit::singleline(&mut sr.text)
                                .hint_text("search all tools")
                                .desired_width(360.0),
                        )
                        .lost_focus()
                        && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    ui.checkbox(&mut sr.case, "Case sensitive");
                    ui.checkbox(&mut sr.regex, "Regex");
                    run |= ui.button("Search").clicked();
                });
                if run {
                    let q = Query {
                        text: sr.text.clone(),
                        regex: sr.regex,
                        case: sr.case,
                    };
                    (sr.hits, sr.error) = (vec![], String::new());
                    match find(&q, corpus(&self.state, &self.repeater).into_iter()) {
                        Ok(h) => self.search.hits = h,
                        Err(e) => self.search.error = e,
                    }
                }
                let sr = &self.search;
                if !sr.error.is_empty() {
                    ui.colored_label(egui::Color32::from_rgb(0xC0, 0x30, 0x30), &sr.error);
                }
                ui.label(format!(
                    "{} result{}",
                    sr.hits.len(),
                    if sr.hits.len() == 1 { "" } else { "s" }
                ));
                egui::ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        for h in &sr.hits {
                            let r = ui.add(
                                egui::Label::new(egui::RichText::new(&h.label).strong())
                                    .sense(egui::Sense::click()),
                            );
                            ui.label(egui::RichText::new(&h.snippet).monospace().small());
                            if r.clicked() {
                                go = Some(h.place.clone());
                            }
                            ui.separator();
                        }
                    });
            });
        self.search.open = open;
        match go {
            Some(Place::History(id)) => {
                (self.tab, self.proxy_tab, self.selected) = ("Proxy", "HTTP history", Some(id));
            }
            Some(Place::Logger(id)) => (self.tab, self.logger_sel) = ("Logger", Some(id)),
            Some(Place::WebSocket(id)) => {
                (self.tab, self.proxy_tab, self.ws_sel) = ("Proxy", "WebSockets history", Some(id));
            }
            Some(Place::Repeater(i)) => (self.tab, self.repeater.current) = ("Repeater", i),
            Some(Place::Issue(id)) => (self.tab, self.issue_sel) = ("Dashboard", Some(id)),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search() {
        let items = || {
            vec![
                (
                    Place::History(1),
                    "a".into(),
                    "GET /login HTTP/1.1\r\nCookie: SESSION=abc".into(),
                ),
                (Place::Issue(2), "b".into(), "nothing".into()),
            ]
            .into_iter()
        };
        let q = |text: &str, regex, case| Query {
            text: text.into(),
            regex,
            case,
        };
        let hits = find(&q("session=", false, false), items()).unwrap();
        assert_eq!(hits.len(), 1);
        assert!(
            hits[0].place == Place::History(1)
                && hits[0].snippet.contains("Cookie: SESSION=abc")
                && !hits[0].snippet.contains('\n')
        );
        assert!(
            find(&q("session=", false, true), items())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            find(&q(r"SESSION=\w+", true, true), items()).unwrap().len(),
            1
        );
        assert_eq!(find(&q("a.c", false, false), items()).unwrap().len(), 0); // literal, not regex
        assert!(find(&q("(", true, false), items()).is_err());
        assert_eq!(snippet("ééé match ééé", (7, 12)), "ééé match ééé");
    }
}
