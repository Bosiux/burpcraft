//! macOS keeps the application menu in the system menu bar at the top of the screen,
//! so there it replaces the in-window egui menu that Windows and Linux use.
use super::{Cmd, MAIN_TABS};
use eframe::egui;
use muda::accelerator::{Accelerator, Code, Modifiers};
use muda::{AboutMetadata, CheckMenuItem, Menu, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use std::sync::mpsc;

pub struct NativeMenu {
    _menu: Menu,
    rx: mpsc::Receiver<MenuId>,
    rest: MenuItem,
    mcp: MenuItem,
    intercept: CheckMenuItem,
    synced: Option<(Option<u16>, Option<u16>, bool)>,
}

fn item(id: &str, text: &str, acc: Option<(Modifiers, Code)>) -> MenuItem {
    MenuItem::with_id(
        id,
        text,
        true,
        acc.map(|(m, c)| Accelerator::new(Some(m), c)),
    )
}

/// Menu item id → command. Ids are the `Cmd` variant names; tabs are `tab:<name>`.
fn cmd(id: &str) -> Option<Cmd> {
    Some(match id {
        "settings" => Cmd::Settings,
        "rest" => Cmd::StartRest,
        "mcp" => Cmd::StartMcp,
        "quit" => Cmd::Exit,
        "open" => Cmd::OpenProject,
        "save" => Cmd::SaveProject,
        "save_as" => Cmd::SaveProjectAs,
        "intercept" => Cmd::Intercept,
        "repeater" => Cmd::NewRepeater,
        "search" => Cmd::Search,
        _ => Cmd::Tab(
            MAIN_TABS
                .into_iter()
                .find(|t| id.strip_prefix("tab:") == Some(*t))?,
        ),
    })
}

impl NativeMenu {
    pub fn new(ctx: &egui::Context) -> Self {
        let cmd_key = Modifiers::SUPER;
        let rest = item("rest", "Start REST API (127.0.0.1:1337)", None);
        let mcp = item("mcp", "Start MCP server (127.0.0.1:1338)", None);
        let intercept = CheckMenuItem::with_id("intercept", "Intercept", true, false, None);
        let sep = PredefinedMenuItem::separator;
        let about = AboutMetadata {
            name: Some("BurpCraft".into()),
            version: Some(env!("CARGO_PKG_VERSION").into()),
            comments: Some("A Rust/egui web security testing proxy".into()),
            ..Default::default()
        };
        let tabs: Vec<MenuItem> = MAIN_TABS
            .iter()
            .map(|t| item(&format!("tab:{t}"), t, None))
            .collect();
        let tab_refs: Vec<&dyn muda::IsMenuItem> = tabs.iter().map(|t| t as _).collect();
        let window = Submenu::with_items(
            "Window",
            true,
            &[
                &PredefinedMenuItem::minimize(None),
                &PredefinedMenuItem::fullscreen(None),
            ],
        )
        .unwrap();
        let help = Submenu::with_items(
            "Help",
            true,
            &[&MenuItem::new(
                "BurpCraft — a Rust/egui web security testing proxy",
                false,
                None,
            )],
        )
        .unwrap();
        // ponytail: no Edit menu; its Cmd+C/V items would swallow the keys egui reads for copy/paste
        let menu = Menu::with_items(&[
            // the first submenu becomes the application menu, titled by the app name
            &Submenu::with_items(
                "BurpCraft",
                true,
                &[
                    &PredefinedMenuItem::about(Some("About BurpCraft"), Some(about)),
                    &sep(),
                    &item("settings", "Settings...", Some((cmd_key, Code::Comma))),
                    &rest,
                    &mcp,
                    &sep(),
                    &PredefinedMenuItem::services(None),
                    &sep(),
                    &PredefinedMenuItem::hide(Some("Hide BurpCraft")),
                    &PredefinedMenuItem::hide_others(None),
                    &PredefinedMenuItem::show_all(None),
                    &sep(),
                    // not PredefinedMenuItem::quit: that terminates without eframe's shutdown
                    &item("quit", "Quit BurpCraft", Some((cmd_key, Code::KeyQ))),
                ],
            )
            .unwrap(),
            &Submenu::with_items(
                "Project",
                true,
                &[
                    &item("open", "Open project...", None),
                    &item("save", "Save project", Some((cmd_key, Code::KeyS))),
                    &item("save_as", "Save project as...", None),
                    &sep(),
                    &intercept,
                ],
            )
            .unwrap(),
            &Submenu::with_items(
                "Intruder",
                true,
                &[&MenuItem::new("Start attack", false, None)],
            )
            .unwrap(),
            &Submenu::with_items("Repeater", true, &[&item("repeater", "New tab", None)]).unwrap(),
            &Submenu::with_items(
                "Search",
                true,
                &[&item(
                    "search",
                    "Search all tools",
                    Some((cmd_key | Modifiers::SHIFT, Code::KeyF)),
                )],
            )
            .unwrap(),
            &Submenu::with_items("View", true, &tab_refs).unwrap(),
            &window,
            &help,
        ])
        .unwrap();
        menu.init_for_nsapp();
        window.set_as_windows_menu_for_nsapp();
        help.set_as_help_menu_for_nsapp();
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        muda::MenuEvent::set_event_handler(Some(move |e: muda::MenuEvent| {
            let _ = tx.send(e.id);
            ctx.request_repaint();
        }));
        Self {
            _menu: menu,
            rx,
            rest,
            mcp,
            intercept,
            synced: None,
        }
    }

    /// Commands clicked since the last frame.
    pub fn poll(&self) -> Vec<Cmd> {
        self.rx
            .try_iter()
            .filter_map(|id| cmd(id.as_ref()))
            .collect()
    }

    /// Mirror app state into the item labels; only touches AppKit when something changed.
    pub fn sync(&mut self, rest: Option<u16>, mcp: Option<u16>, intercept: bool) {
        let now = Some((rest, mcp, intercept));
        if self.synced == now {
            return;
        }
        self.synced = now;
        if let Some(p) = rest {
            self.rest
                .set_text(format!("REST API on http://127.0.0.1:{p}/v0.1/"));
            self.rest.set_enabled(false);
        }
        if let Some(p) = mcp {
            self.mcp
                .set_text(format!("MCP server on http://127.0.0.1:{p}/mcp"));
            self.mcp.set_enabled(false);
        }
        self.intercept.set_checked(intercept);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ids_map_to_commands() {
        use super::{Cmd, cmd};
        assert!(matches!(cmd("save"), Some(Cmd::SaveProject)));
        assert!(matches!(cmd("tab:Proxy"), Some(Cmd::Tab("Proxy"))));
        assert!(cmd("tab:Nope").is_none() && cmd("bogus").is_none());
    }
}
