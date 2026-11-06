//! CSS parsing, selector matching and the box-model/flex/grid/float layout math.
use eframe::egui::Color32;

use super::{NodeRef, Style};

/// Parses `color:`/`background:` and `display:none` out of a style attribute.
pub(crate) fn inline_style(style: &str, st: &mut Style) -> bool {
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
pub(crate) struct BoxCss {
    pub(crate) bg: Option<Color32>,
    pub(crate) pad: [f32; 2],    // vertical, horizontal
    pub(crate) margin: [f32; 2], // vertical, horizontal
    pub(crate) border: Option<(f32, Color32)>,
    pub(crate) radius: f32,
    pub(crate) display: String,
    pub(crate) column: bool,  // flex-direction: column
    pub(crate) grid: String,  // grid-template-columns, resolved against the width at layout time
    pub(crate) gap: [f32; 2], // row, column
    pub(crate) justify: String,
    pub(crate) width: Option<Track>, // width / flex-basis
    pub(crate) grow: f32,
    pub(crate) float: String,
}

/// One column of a flex row, grid or float layout.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Track {
    Px(f32),
    Pct(f32),
    Fr(f32),
}

/// A width track: px/em/rem, %, fr; anything else (auto, min-content…) is 1fr.
fn track(v: &str, font: f32) -> Track {
    let num = |s: &str| s.trim().parse::<f32>().ok();
    if let Some(args) = v.strip_prefix("minmax(").and_then(|a| a.strip_suffix(')')) {
        // ponytail: minmax keeps only its max (fr or fixed); the min is ignored
        return track(args.rsplit(',').next().unwrap_or("1fr").trim(), font);
    }
    if let Some(n) = v.strip_suffix("fr").and_then(num) {
        Track::Fr(n.max(0.0))
    } else if let Some(n) = v.strip_suffix('%').and_then(num) {
        Track::Pct(n)
    } else {
        css_len(v, font).map_or(Track::Fr(1.0), Track::Px)
    }
}

/// grid-template-columns as tracks; repeat(auto-fill|auto-fit, minmax(Npx, …)) fits as many N px columns as `avail` holds.
pub(crate) fn grid_tracks(v: &str, font: f32, avail: f32, gap: f32) -> Vec<Track> {
    let mut out = vec![];
    for t in css_tokens(v) {
        let Some((n, list)) = t
            .strip_prefix("repeat(")
            .and_then(|r| r.strip_suffix(')'))
            .and_then(|r| r.split_once(','))
        else {
            out.push(track(t, font));
            continue;
        };
        let list = css_tokens(list.trim());
        let n = n.trim().parse::<usize>().unwrap_or_else(|_| {
            // auto-fill/auto-fit: minimum column width from minmax(min, …) or a fixed track
            let min = list
                .first()
                .and_then(|l| l.strip_prefix("minmax("))
                .and_then(|a| a.split(',').next())
                .and_then(|m| css_len(m, font))
                .or_else(|| list.first().and_then(|l| css_len(l, font)))
                .unwrap_or(200.0)
                .max(1.0);
            ((avail + gap) / (min + gap)).floor().max(1.0) as usize
        });
        for _ in 0..n.min(24) {
            out.extend(list.iter().map(|l| track(l, font)));
        }
    }
    out
}

/// (x, width) of each track in a row `avail` wide: fixed and % tracks first, fr tracks share the rest,
/// fixed tracks shrink proportionally when they overflow, and leftover space follows justify-content.
pub(crate) fn place(tracks: &[Track], avail: f32, gap: f32, justify: &str) -> Vec<(f32, f32)> {
    let n = tracks.len().max(1) as f32;
    let space = (avail - gap * (n - 1.0)).max(0.0);
    let fixed = |t: &Track| match *t {
        Track::Px(v) => v.max(0.0),
        Track::Pct(p) => avail * p / 100.0,
        Track::Fr(_) => 0.0,
    };
    let fixed_sum: f32 = tracks.iter().map(fixed).sum();
    let fr_sum: f32 = tracks
        .iter()
        .map(|t| if let Track::Fr(g) = t { *g } else { 0.0 })
        .sum();
    let shrink = if fixed_sum > space {
        space / fixed_sum
    } else {
        1.0
    };
    let free = (space - fixed_sum * shrink).max(0.0);
    let widths: Vec<f32> = tracks
        .iter()
        .map(|t| match t {
            Track::Fr(g) if fr_sum > 0.0 => free * g / fr_sum,
            t => fixed(t) * shrink,
        })
        .collect();
    let left = if fr_sum > 0.0 { 0.0 } else { free };
    let (mut x, step) = match justify {
        "center" => (left / 2.0, 0.0),
        "flex-end" | "end" | "right" => (left, 0.0),
        "space-between" if n > 1.0 => (0.0, left / (n - 1.0)),
        "space-around" => (left / n / 2.0, left / n),
        "space-evenly" => (left / (n + 1.0), left / (n + 1.0)),
        _ => (0.0, 0.0),
    };
    widths
        .into_iter()
        .map(|w| {
            let at = (x, w);
            x += w + gap + step;
            at
        })
        .collect()
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
    pub(crate) fn parse(decls: &[&str], font: f32) -> Self {
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
                "grid-template-columns" => b.grid = v,
                "gap" | "grid-gap" => b.gap = pair(&v),
                "column-gap" => b.gap[1] = css_len(&v, font).unwrap_or(0.0),
                "justify-content" => b.justify = v,
                "width" | "flex-basis" if v != "auto" && !v.contains('(') => {
                    b.width = Some(track(&v, font))
                }
                "flex-grow" => b.grow = v.parse().unwrap_or(0.0),
                // flex: none | auto | <grow> [<shrink>] [<basis>]
                "flex" => {
                    let t = css_tokens(&v);
                    b.grow = match v.as_str() {
                        "none" => 0.0,
                        "auto" => 1.0,
                        _ => t.first().and_then(|g| g.parse().ok()).unwrap_or(0.0),
                    };
                    // a zero basis (flex: 1 1 0) means "no fixed width"
                    if let Some(basis) = t
                        .iter()
                        .skip(1)
                        .find_map(|x| css_len(x, font).filter(|&px| px > 0.0))
                    {
                        b.width = Some(Track::Px(basis));
                    }
                }
                "float" => b.float = v,
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

/// Declarations that apply to `n`: stylesheet rules in document order, then the inline style wins.
// ponytail: no specificity or inheritance rules beyond "later wins"; enough for most app pages
pub(crate) fn css_decls<'a>(
    n: NodeRef<'a>,
    rules: &'a [(scraper::Selector, String)],
) -> Vec<&'a str> {
    let mut out: Vec<&str> = vec![];
    if let Some(er) = scraper::ElementRef::wrap(n) {
        out.extend(
            rules
                .iter()
                .filter(|(sel, _)| sel.matches(&er))
                .map(|(_, d)| d.as_str()),
        );
        out.extend(er.value().attr("style"));
    }
    out
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
            (b.bg, b.display.as_str(), b.grid.as_str()),
            (Some(Color32::WHITE), "grid", "repeat(3, 1fr)")
        );
        assert!(BoxCss::parse(&["display:flex;flex-direction:column"], 16.0).column);
    }

    #[test]
    fn flex_and_float_css() {
        let b = |d: &str| BoxCss::parse(&[d], 10.0);
        assert_eq!((b("flex: 1").grow, b("flex: 1").width), (1.0, None));
        assert_eq!(b("flex: 1 1 0").width, None);
        let fixed = b("flex: 0 0 200px");
        assert_eq!((fixed.grow, fixed.width), (0.0, Some(Track::Px(200.0))));
        assert_eq!((b("flex: none").grow, b("flex: auto").grow), (0.0, 1.0));
        assert_eq!(b("flex-grow: 2").grow, 2.0);
        assert_eq!(b("width: 25%").width, Some(Track::Pct(25.0)));
        assert_eq!(b("width: 2em").width, Some(Track::Px(20.0)));
        assert_eq!(b("width: auto").width, None);
        assert_eq!(b("gap: 4px 8px").gap, [4.0, 8.0]);
        assert_eq!(b("float: right").float, "right");
        assert_eq!(b("justify-content: center").justify, "center");
    }

    #[test]
    fn grid_columns() {
        use Track::*;
        assert_eq!(
            grid_tracks("200px 1fr 2fr", 16.0, 800.0, 0.0),
            [Px(200.0), Fr(1.0), Fr(2.0)]
        );
        assert_eq!(
            grid_tracks("repeat(3, 1fr)", 16.0, 800.0, 0.0),
            [Fr(1.0); 3]
        );
        assert_eq!(
            grid_tracks("repeat(2, 10% 1fr)", 16.0, 800.0, 0.0),
            [Pct(10.0), Fr(1.0), Pct(10.0), Fr(1.0)]
        );
        assert_eq!(
            grid_tracks("repeat(3, minmax(0, 1fr))", 16.0, 800.0, 0.0),
            [Fr(1.0); 3]
        );
        assert_eq!(grid_tracks("auto 1fr", 16.0, 800.0, 0.0), [Fr(1.0); 2]);
        // 4 columns of >= 180px fit in 800px with 10px gaps (4*180 + 3*10 = 750)
        assert_eq!(
            grid_tracks("repeat(auto-fill, minmax(180px, 1fr))", 16.0, 800.0, 10.0).len(),
            4
        );
        assert_eq!(
            grid_tracks("repeat(auto-fit, minmax(900px, 1fr))", 16.0, 800.0, 10.0).len(),
            1
        );
    }

    #[test]
    fn placement() {
        use Track::*;
        // fixed sidebar + fr ratios share the rest
        assert_eq!(
            place(&[Px(200.0), Fr(1.0), Fr(3.0)], 1000.0, 0.0, ""),
            [(0.0, 200.0), (200.0, 200.0), (400.0, 600.0)]
        );
        // % of the row, gap counted between tracks
        assert_eq!(
            place(&[Pct(25.0), Fr(1.0)], 400.0, 10.0, ""),
            [(0.0, 100.0), (110.0, 290.0)]
        );
        // overflowing fixed tracks shrink proportionally
        assert_eq!(
            place(&[Px(300.0), Px(100.0)], 200.0, 0.0, ""),
            [(0.0, 150.0), (150.0, 50.0)]
        );
        // justify-content distributes leftover space when nothing grows
        let two = [Px(100.0), Px(100.0)];
        assert_eq!(
            place(&two, 400.0, 0.0, "center"),
            [(100.0, 100.0), (200.0, 100.0)]
        );
        assert_eq!(
            place(&two, 400.0, 0.0, "flex-end"),
            [(200.0, 100.0), (300.0, 100.0)]
        );
        assert_eq!(
            place(&two, 400.0, 0.0, "space-between"),
            [(0.0, 100.0), (300.0, 100.0)]
        );
        assert_eq!(
            place(&two, 400.0, 0.0, "space-around"),
            [(50.0, 100.0), (250.0, 100.0)]
        );
        // a growing track leaves nothing to justify
        assert_eq!(
            place(&[Px(100.0), Fr(1.0)], 400.0, 0.0, "center"),
            [(0.0, 100.0), (100.0, 300.0)]
        );
    }
}
