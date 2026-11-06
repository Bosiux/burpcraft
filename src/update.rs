//! Startup check for a newer BurpCraft release on GitHub; notify only, never installs.
use std::cmp::Ordering;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, RichText};

use crate::openapi::J;
use crate::theme;

const REPO: &str = "Bosiux/burpcraft";
const CHECK_EVERY: Duration = Duration::from_secs(24 * 3600);
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// Persisted in `~/.burpcraft/update.txt` as `key=value` lines.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Prefs {
    pub disabled: bool,
    pub checked: u64,
    pub latest: String,
    pub skipped: String,
}

impl Prefs {
    fn parse(s: &str) -> Self {
        let mut p = Self::default();
        for (k, v) in s.lines().filter_map(|l| l.split_once('=')) {
            match k {
                "disabled" => p.disabled = v == "1",
                "checked" => p.checked = v.parse().unwrap_or(0),
                "latest" => p.latest = v.into(),
                "skipped" => p.skipped = v.into(),
                _ => {}
            }
        }
        p
    }

    fn to_text(&self) -> String {
        format!(
            "disabled={}\nchecked={}\nlatest={}\nskipped={}\n",
            self.disabled as u8, self.checked, self.latest, self.skipped
        )
    }

    /// The release to announce, if newer than this build and not skipped.
    pub fn pending(&self) -> Option<&str> {
        let tag = self.latest.as_str();
        (!self.disabled && tag != self.skipped && newer(tag, CURRENT)).then_some(tag)
    }
}

fn prefs_file() -> PathBuf {
    crate::net::data_dir().join("update.txt")
}

fn prefs() -> &'static Mutex<Prefs> {
    static P: OnceLock<Mutex<Prefs>> = OnceLock::new();
    P.get_or_init(|| {
        Mutex::new(Prefs::parse(
            &std::fs::read_to_string(prefs_file()).unwrap_or_default(),
        ))
    })
}

fn save(p: &Prefs) {
    let _ = std::fs::create_dir_all(crate::net::data_dir());
    let _ = std::fs::write(prefs_file(), p.to_text());
}

fn update_prefs(f: impl FnOnce(&mut Prefs)) {
    let mut p = prefs().lock().unwrap();
    f(&mut p);
    save(&p);
}

/// Checks GitHub in the background, at most once a day; opt out with BURPCRAFT_NO_UPDATE_CHECK.
pub fn start(ctx: egui::Context) {
    let now = unix_now();
    let due = {
        let p = prefs().lock().unwrap();
        !p.disabled && now.saturating_sub(p.checked) >= CHECK_EVERY.as_secs()
    };
    if !due || std::env::var_os("BURPCRAFT_NO_UPDATE_CHECK").is_some() {
        return;
    }
    std::thread::spawn(move || {
        // ponytail: failures stay silent (offline labs are normal); retried on the next start
        let Ok(releases) = fetch_releases() else {
            return;
        };
        let latest = newest(&releases, CURRENT).unwrap_or_default();
        update_prefs(|p| {
            p.checked = now;
            p.latest = latest;
        });
        ctx.request_repaint();
    });
}

fn fetch_releases() -> Result<J, String> {
    let req = format!(
        "GET /repos/{REPO}/releases?per_page=20 HTTP/1.1\r\nHost: api.github.com\r\nUser-Agent: BurpCraft/{CURRENT}\r\nAccept: application/vnd.github+json\r\nX-GitHub-Api-Version: 2022-11-28\r\nConnection: close\r\n\r\n"
    );
    let resp =
        crate::net::send_verified("api.github.com", req.as_bytes()).map_err(|e| e.to_string())?;
    let head = String::from_utf8_lossy(crate::proxy::head(&resp)).into_owned();
    if head.split_whitespace().nth(1) != Some("200") {
        return Err(head.lines().next().unwrap_or_default().to_string());
    }
    crate::openapi::parse(&String::from_utf8_lossy(&crate::proxy::body_bytes(&resp)))
}

/// Highest published tag above `current`; pre-releases only when `current` is one.
pub fn newest(releases: &J, current: &str) -> Option<String> {
    let wants_pre = current.contains('-');
    releases
        .items()
        .iter()
        .filter(|r| !matches!(r.get("draft"), Some(J::Bool(true))))
        .filter(|r| wants_pre || !matches!(r.get("prerelease"), Some(J::Bool(true))))
        .filter_map(|r| r.get("tag_name")?.str())
        .filter(|t| newer(t, current))
        .max_by(|a, b| compare(a, b).unwrap_or(Ordering::Equal))
        .map(str::to_string)
}

fn newer(tag: &str, current: &str) -> bool {
    compare(tag, current) == Some(Ordering::Greater)
}

/// SemVer precedence of two versions (a leading `v` is ignored); None if either is malformed.
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    let (a, b) = (parse_version(a)?, parse_version(b)?);
    Some(
        a.0.cmp(&b.0)
            .then_with(|| match (a.1.is_empty(), b.1.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => compare_pre(&a.1, &b.1),
            }),
    )
}

fn parse_version(v: &str) -> Option<([u64; 3], Vec<&str>)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let v = v.split('+').next()?;
    let (core, pre) = v.split_once('-').unwrap_or((v, ""));
    let mut n = core.split('.').map(|x| x.parse::<u64>().ok());
    let core = [n.next()??, n.next()??, n.next()??];
    if n.next().is_some() {
        return None;
    }
    let pre: Vec<&str> = if pre.is_empty() {
        vec![]
    } else {
        pre.split('.').collect()
    };
    // tags end up in a URL handed to the OS opener
    let valid =
        |id: &&str| !id.is_empty() && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-');
    pre.iter().all(valid).then_some((core, pre))
}

fn compare_pre(a: &[&str], b: &[&str]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        let o = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => x.cmp(y),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    a.len().cmp(&b.len())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Banner under the tab bar while a newer release is pending; `dismissed` hides it until restart.
pub fn banner(ui: &mut egui::Ui, dismissed: &mut bool) {
    let Some(tag) = prefs().lock().unwrap().pending().map(str::to_string) else {
        return;
    };
    if *dismissed {
        return;
    }
    egui::Panel::top("update_banner")
        .frame(theme::frame_chrome())
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!(
                    "BurpCraft {} is available (you have {CURRENT}).",
                    tag.trim_start_matches('v')
                )));
                if ui.button("Release notes").clicked() {
                    let _ = crate::misc::open_external(format!(
                        "https://github.com/{REPO}/releases/tag/{tag}"
                    ));
                }
                if ui.button("Skip this version").clicked() {
                    update_prefs(|p| p.skipped = tag.clone());
                }
                if ui.button("Later").clicked() {
                    *dismissed = true;
                }
            });
        });
}

/// Settings > User interface section.
pub fn settings(ui: &mut egui::Ui) {
    theme::heading(ui, "Updates");
    let mut enabled = !prefs().lock().unwrap().disabled;
    if ui
        .checkbox(
            &mut enabled,
            "Check GitHub for new releases on startup (once a day)",
        )
        .changed()
    {
        update_prefs(|p| p.disabled = !enabled);
    }
    ui.label(RichText::new(format!("Version {CURRENT}")).color(theme::muted()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_precedence() {
        let order = [
            "0.0.1-beta.1",
            "v0.0.1-beta.2",
            "0.0.1-beta.10",
            "0.0.1-rc.1",
            "0.0.1",
            "0.0.2-beta.1",
            "0.1.0",
            "0.10.0",
            "1.0.0",
        ];
        for w in order.windows(2) {
            assert_eq!(
                compare(w[0], w[1]),
                Some(Ordering::Less),
                "{} < {}",
                w[0],
                w[1]
            );
        }
        assert_eq!(compare("1.0.0+build.5", "v1.0.0"), Some(Ordering::Equal));
        assert_eq!(compare("1.0", "1.0.0"), None);
        assert_eq!(compare("latest", "1.0.0"), None);
        assert_eq!(compare("1.0.0-a&calc", "1.0.0"), None);
        assert_eq!(compare("1.0.0-beta..1", "1.0.0"), None);
    }

    fn releases() -> J {
        crate::openapi::parse(
            r#"[
              {"tag_name":"v0.3.0","draft":true,"prerelease":false},
              {"tag_name":"v0.2.1-beta.1","draft":false,"prerelease":true},
              {"tag_name":"v0.2.0","draft":false,"prerelease":false},
              {"tag_name":"nightly","draft":false,"prerelease":false},
              {"tag_name":"v0.1.0","draft":false,"prerelease":false}
            ]"#,
        )
        .unwrap()
    }

    #[test]
    fn channel_rules() {
        // stable users never see betas or drafts
        assert_eq!(newest(&releases(), "0.1.0").as_deref(), Some("v0.2.0"));
        // beta users see the newest of either
        assert_eq!(
            newest(&releases(), "0.2.0-beta.3").as_deref(),
            Some("v0.2.1-beta.1")
        );
        // nothing newer, nothing announced
        assert_eq!(newest(&releases(), "0.2.0"), None);
        assert_eq!(newest(&J::Arr(vec![]), "0.1.0"), None);
    }

    #[test]
    fn prefs_round_trip_and_pending() {
        let p = Prefs {
            disabled: false,
            checked: 1_700_000_000,
            latest: "v99.0.0".into(),
            skipped: String::new(),
        };
        assert_eq!(Prefs::parse(&p.to_text()), p);
        assert_eq!(p.pending(), Some("v99.0.0"));
        let skipped = Prefs {
            skipped: "v99.0.0".into(),
            ..p.clone()
        };
        assert_eq!(skipped.pending(), None);
        let off = Prefs {
            disabled: true,
            ..p.clone()
        };
        assert_eq!(off.pending(), None);
        let old = Prefs {
            latest: "v0.0.0".into(),
            ..p
        };
        assert_eq!(old.pending(), None);
        assert_eq!(Prefs::parse("garbage\nchecked=x"), Prefs::default());
    }

    #[test]
    #[ignore = "network: queries the live GitHub API"]
    fn live_github() {
        let releases = fetch_releases().expect("GitHub reachable");
        let tag = newest(&releases, "0.0.0-alpha").expect("at least one release");
        assert!(compare(&tag, "0.0.0").is_some(), "{tag}");
    }
}
