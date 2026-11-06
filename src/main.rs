// release builds are a GUI app on Windows: no console window
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
mod ai;
mod editor;
mod engage;
mod ext;
mod http;
mod intruder;
#[cfg(target_os = "macos")]
mod macmenu;
mod mcp;
mod misc;
mod openapi;
mod project;
mod proxy;
mod render;
mod report;
mod rest;
mod scan;
mod search;
mod security;
mod sequencer;
mod target;
mod theme;
mod tools;
mod ui;
mod update;

use std::sync::Arc;

use eframe::egui::{self, RichText};

use http::net;
use proxy::{Entry, State};
use security::{collab, domi};
use ui::HistFilter;

const MAIN_TABS: [&str; 13] = [
    "Dashboard",
    "Target",
    "Proxy",
    "Intruder",
    "Repeater",
    "Collaborator",
    "Sequencer",
    "Decoder",
    "Comparer",
    "Logger",
    "Organizer",
    "Extensions",
    "Learn",
];
/// Menu commands, shared by the in-window menu and the macOS system menu bar.
#[derive(Clone, Copy)]
enum Cmd {
    Settings,
    StartRest,
    StartMcp,
    Exit,
    OpenProject,
    SaveProject,
    SaveProjectAs,
    Intercept,
    NewRepeater,
    Search,
    Tab(&'static str),
}
const PROXY_TABS: [&str; 5] = [
    "Intercept",
    "HTTP history",
    "WebSockets history",
    "Match and replace",
    "Proxy settings",
];

struct App {
    state: State,
    ca: Option<Arc<net::Ca>>,
    tab: &'static str,
    proxy_tab: &'static str,
    selected: Option<usize>,
    filter: String,
    hfilter: HistFilter,
    hfilter_open: bool,
    intercept_text: Option<(usize, String)>,
    target: target::Target,
    repeater: tools::Repeater,
    intruder: intruder::Intruder,
    sequencer: sequencer::Sequencer,
    organizer: misc::Organizer,
    extensions: ext::Tab,
    settings: misc::Settings,
    decoder: tools::Decoder,
    comparer: tools::Comparer,
    logger_sel: Option<usize>,
    ws_sel: Option<usize>,
    issue_sel: Option<usize>,
    flash: Option<&'static str>,
    update_dismissed: bool,
    comment_edit: Option<(usize, String)>,
    frames: u32,
    /// Open project file: Ctrl+S and exit save here.
    project: Option<std::path::PathBuf>,
    /// Project dialog: (saving?, typed path, status message).
    project_dlg: Option<(bool, String, String)>,
    autosave: project::Autosave,
    search: search::Search,
    engage: engage::Engage,
    collab: collab::Tab,
    scans: rest::Tasks,
    /// REST API port while it runs.
    rest_port: Option<u16>,
    /// MCP server port while it runs.
    mcp_port: Option<u16>,
    /// macOS: the menu in the system menu bar (elsewhere it is drawn inside the window).
    #[cfg(target_os = "macos")]
    native_menu: Option<macmenu::NativeMenu>,
    /// New scan dialog: (URLs, config, API definition path, schedule "HH:MM" or empty, repeat hours).
    scan_dlg: Option<(String, scan::Config, String, String, u32)>,
    /// Scheduled scans: (next run, repeat hours (0 = once), URLs, config).
    schedules: Vec<(
        chrono::DateTime<chrono::Local>,
        u32,
        Vec<String>,
        scan::Config,
    )>,
    /// Live active audit of in-scope proxy traffic, and the last history id it looked at.
    live_active: bool,
    live_seen: usize,
}

impl App {
    fn new(cc: &eframe::CreationContext) -> Self {
        let dark = std::env::var_os("BURPCRAFT_DARK").is_some();
        theme::apply(&cc.egui_ctx, dark, 13.0);
        let state = proxy::Shared::new();
        state.lock().unwrap().ctx = Some(cc.egui_ctx.clone());
        let ca = match net::Ca::load_or_create() {
            Ok(ca) => Some(Arc::new(ca)),
            Err(e) => {
                state
                    .lock()
                    .unwrap()
                    .event("Proxy", format!("Failed to load CA certificate: {e}"));
                None
            }
        };
        if let Some(ca) = &ca {
            // BURPCRAFT_PROXY=port moves the listener off 8080 (0 = any free port)
            match std::env::var("BURPCRAFT_PROXY").map(|v| (v.parse::<u16>(), v)) {
                Err(_) => proxy::start(state.clone(), ca.clone(), 8080),
                Ok((Ok(port), _)) => proxy::start(state.clone(), ca.clone(), port),
                // not 8080: the user set the variable to stay off it
                Ok((Err(_), v)) => state.lock().unwrap().event(
                    "Proxy",
                    format!("Proxy not started: BURPCRAFT_PROXY={v:?} is not a port number"),
                ),
            }
        }
        // dev hooks: BURPCRAFT_TAB / BURPCRAFT_PROXY_TAB pick the start screen (used with BURPCRAFT_SHOT)
        let pick = |var: &str, list: &[&'static str], def: &'static str| {
            std::env::var(var)
                .ok()
                .and_then(|v| list.iter().find(|t| **t == v).copied())
                .unwrap_or(def)
        };
        let mut app = Self {
            ca,
            tab: pick("BURPCRAFT_TAB", &MAIN_TABS, "Dashboard"),
            proxy_tab: pick("BURPCRAFT_PROXY_TAB", &PROXY_TABS, "Intercept"),
            ..Self::blank(state)
        };
        app.settings.dark = dark;
        #[cfg(target_os = "macos")]
        {
            app.native_menu = Some(macmenu::NativeMenu::new(&cc.egui_ctx));
        }
        ext::init(app.state.clone());
        update::start(cc.egui_ctx.clone());
        // BURPCRAFT_API=port[:key] starts the REST API (e.g. for CI)
        if let Ok(v) = std::env::var("BURPCRAFT_API") {
            let (port, key) = v.split_once(':').unwrap_or((&v, ""));
            app.start_rest(port.parse().unwrap_or(1337), key.to_string());
        }
        // BURPCRAFT_MCP=port[:token] starts the MCP server for AI agents
        if let Ok(v) = std::env::var("BURPCRAFT_MCP") {
            let (port, key) = v.split_once(':').unwrap_or((&v, ""));
            app.start_mcp(port.parse().unwrap_or(1338), key.to_string());
        }
        // `burpcraft <file.burpcraft>` opens a project
        if let Some(path) = std::env::args_os().nth(1).map(std::path::PathBuf::from) {
            match project::open(&mut app, &path) {
                Ok(()) => app.project = Some(path),
                // a new path starts a new project there, autosaved and saved on exit
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => app.project = Some(path),
                Err(e) => app
                    .state
                    .lock()
                    .unwrap()
                    .event("Project", format!("Failed to open {}: {e}", path.display())),
            }
        }
        app
    }

    /// App state without a window or proxy listener (also used by tests).
    fn blank(state: State) -> Self {
        Self {
            state,
            ca: None,
            tab: "Dashboard",
            proxy_tab: "Intercept",
            selected: None,
            filter: String::new(),
            hfilter: HistFilter::default(),
            hfilter_open: false,
            intercept_text: None,
            target: Default::default(),
            repeater: Default::default(),
            intruder: Default::default(),
            sequencer: Default::default(),
            organizer: Default::default(),
            extensions: Default::default(),
            settings: Default::default(),
            decoder: Default::default(),
            comparer: Default::default(),
            logger_sel: None,
            ws_sel: None,
            issue_sel: None,
            flash: None,
            update_dismissed: false,
            comment_edit: None,
            frames: 0,
            project: None,
            project_dlg: None,
            autosave: Default::default(),
            search: Default::default(),
            engage: Default::default(),
            collab: Default::default(),
            scans: Default::default(),
            rest_port: None,
            mcp_port: None,
            #[cfg(target_os = "macos")]
            native_menu: None,
            scan_dlg: None,
            schedules: vec![],
            live_active: false,
            live_seen: 0,
        }
    }

    fn start_rest(&mut self, port: u16, key: String) {
        let msg = match rest::start(port, key, self.scans.clone(), self.state.clone()) {
            Ok(p) => {
                self.rest_port = Some(p);
                format!("REST API listening on http://127.0.0.1:{p}/v0.1/")
            }
            Err(e) => format!("Failed to start REST API on port {port}: {e}"),
        };
        self.state.lock().unwrap().event("REST API", msg);
    }

    fn start_mcp(&mut self, port: u16, key: String) {
        let ctx = mcp::Ctx {
            state: self.state.clone(),
            tasks: self.scans.clone(),
            scope: self.target.scope.clone(),
        };
        let msg = match mcp::start(port, key, ctx) {
            Ok(p) => {
                self.mcp_port = Some(p);
                format!("MCP server listening on http://127.0.0.1:{p}/mcp")
            }
            Err(e) => format!("Failed to start MCP server on port {port}: {e}"),
        };
        self.state.lock().unwrap().event("MCP", msg);
    }

    fn start_scan(
        &mut self,
        urls: Vec<String>,
        extra: Vec<(scan::Target, String)>,
        cfg: scan::Config,
    ) {
        let mut scans = self.scans.lock().unwrap();
        let id = scans.len() + 1;
        scans.push(scan::start(id, urls, extra, cfg, self.state.clone()));
        self.tab = "Dashboard";
    }

    /// Starts scheduled scans whose time has come; repeating ones are re-armed.
    fn run_schedules(&mut self, ctx: &egui::Context) {
        let now = chrono::Local::now();
        let due: Vec<usize> = (0..self.schedules.len())
            .filter(|&i| self.schedules[i].0 <= now)
            .collect();
        for i in due.into_iter().rev() {
            let (when, every, urls, cfg) = self.schedules.remove(i);
            self.start_scan(urls.clone(), vec![], cfg.clone());
            if every > 0 {
                self.schedules.push((
                    when + chrono::Duration::hours(every as i64),
                    every,
                    urls,
                    cfg,
                ));
            }
        }
        if !self.schedules.is_empty() {
            ctx.request_repaint_after(std::time::Duration::from_secs(20));
        }
    }

    /// Audits new in-scope proxy items with parameters while the live task is on.
    fn live_audit(&mut self) {
        if !self.live_active {
            return;
        }
        let fresh: Vec<Entry> = {
            let s = self.state.lock().unwrap();
            s.history
                .iter()
                .filter(|e| e.id >= self.live_seen && e.tool == "Proxy")
                .cloned()
                .collect()
        };
        for e in fresh {
            self.live_seen = self.live_seen.max(e.id + 1);
            let req = String::from_utf8_lossy(&e.req).into_owned();
            if self.target.in_scope(&e) && !scan::points(&req).is_empty() {
                let mut cfg = scan::Config::fast();
                cfg.crawl = false;
                let mut scans = self.scans.lock().unwrap();
                let id = scans.len() + 1;
                scans.push(scan::start(
                    id,
                    vec![],
                    vec![(
                        scan::Target {
                            host: e.host,
                            port: e.port,
                            tls: e.tls,
                        },
                        req,
                    )],
                    cfg,
                    self.state.clone(),
                ));
            }
        }
    }

    fn save_project(&mut self, path: std::path::PathBuf) -> Result<(), String> {
        project::save(self, &path)
            .map_err(|e| format!("Failed to save {}: {e}", path.display()))?;
        self.state
            .lock()
            .unwrap()
            .event("Project", format!("Project saved to {}", path.display()));
        self.project = Some(path);
        Ok(())
    }

    fn project_window(&mut self, ctx: &egui::Context) {
        let Some((saving, mut path, mut msg)) = self.project_dlg.take() else {
            return;
        };
        let mut open = true;
        let mut done = false;
        theme::window(
            ctx,
            if saving {
                "Save project"
            } else {
                "Open project"
            },
            [460.0, 160.0],
            &mut open,
            |ui| {
                ui.label("Project file:");
                ui.add(egui::TextEdit::singleline(&mut path).desired_width(420.0));
                if !msg.is_empty() {
                    ui.label(RichText::new(&msg).color(theme::muted()));
                }
                if ui.button(if saving { "Save" } else { "Open" }).clicked() {
                    let p = std::path::PathBuf::from(path.trim());
                    let result = if saving {
                        self.save_project(p)
                    } else {
                        project::open(self, &p)
                            .map(|()| self.project = Some(p))
                            .map_err(|e| format!("Failed to open: {e}"))
                    };
                    match result {
                        Ok(()) => done = true,
                        Err(e) => msg = e,
                    }
                }
            },
        );
        if open && !done {
            self.project_dlg = Some((saving, path, msg));
        }
    }

    fn send_to_repeater(&mut self, e: &Entry) {
        self.repeater.add(
            e.host.clone(),
            e.port,
            e.tls,
            String::from_utf8_lossy(&e.req).into_owned(),
        );
        self.flash = Some("Repeater");
    }

    fn run(&mut self, ctx: &egui::Context, cmd: Cmd) {
        let current = || {
            self.project
                .clone()
                .unwrap_or_else(project::default_path)
                .display()
                .to_string()
        };
        match cmd {
            Cmd::Settings => self.settings.open = true,
            Cmd::StartRest => self.start_rest(1337, String::new()),
            Cmd::StartMcp => self.start_mcp(1338, String::new()),
            Cmd::Exit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Cmd::OpenProject => self.project_dlg = Some((false, current(), String::new())),
            Cmd::SaveProject => match self.project.clone() {
                Some(p) => {
                    if let Err(e) = self.save_project(p) {
                        self.state.lock().unwrap().event("Project", e);
                    }
                }
                None => self.project_dlg = Some((true, current(), String::new())),
            },
            Cmd::SaveProjectAs => self.project_dlg = Some((true, current(), String::new())),
            Cmd::Intercept => {
                let mut s = self.state.lock().unwrap();
                s.intercept = !s.intercept;
            }
            Cmd::NewRepeater => {
                self.repeater.add(String::new(), 80, false, String::new());
                self.tab = "Repeater";
            }
            Cmd::Search => self.search.open = true,
            Cmd::Tab(t) => self.tab = t,
        }
    }

    /// In-window menu bar (Windows/Linux); macOS uses `macmenu` in the system menu bar.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    fn menu(&mut self, ui: &mut egui::Ui) {
        let mut cmd = None;
        egui::MenuBar::new().ui(ui, |ui| {
            let mut pick = |r: egui::Response, c: Cmd| {
                if r.clicked() {
                    cmd = Some(c);
                }
            };
            ui.menu_button("BurpCraft", |ui| {
                pick(ui.button("Settings"), Cmd::Settings);
                match self.rest_port {
                    Some(p) => {
                        ui.label(format!("REST API on http://127.0.0.1:{p}/v0.1/"));
                    }
                    None => pick(ui.button("Start REST API (127.0.0.1:1337)"), Cmd::StartRest),
                }
                match self.mcp_port {
                    Some(p) => {
                        ui.label(format!("MCP server on http://127.0.0.1:{p}/mcp"));
                    }
                    None => {
                        pick(
                            ui.button("Start MCP server (127.0.0.1:1338)")
                                .on_hover_text("Lets AI agents control BurpCraft: claude mcp add --transport http burpcraft http://127.0.0.1:1338/mcp"),
                            Cmd::StartMcp,
                        );
                    }
                }
                ui.separator();
                pick(ui.button("Exit"), Cmd::Exit);
            });
            ui.menu_button("Project", |ui| {
                pick(ui.button("Open project..."), Cmd::OpenProject);
                pick(ui.button("Save project  (Ctrl+S)"), Cmd::SaveProject);
                pick(ui.button("Save project as..."), Cmd::SaveProjectAs);
                ui.separator();
                let label = if self.state.lock().unwrap().intercept {
                    "Intercept is on"
                } else {
                    "Intercept is off"
                };
                pick(ui.button(label), Cmd::Intercept);
            });
            ui.menu_button("Intruder", |ui| {
                ui.add_enabled(false, egui::Button::new("Start attack"));
            });
            ui.menu_button("Repeater", |ui| pick(ui.button("New tab"), Cmd::NewRepeater));
            ui.menu_button("Search", |ui| {
                pick(ui.button("Search all tools  (Ctrl+Shift+F)"), Cmd::Search)
            });
            ui.menu_button("View", |ui| {
                for t in MAIN_TABS {
                    pick(ui.button(t), Cmd::Tab(t));
                }
            });
            ui.menu_button("Help", |ui| {
                ui.label("BurpCraft — a Rust/egui web security testing proxy");
            });
        });
        if let Some(c) = cmd {
            self.run(ui.ctx(), c);
        }
    }

    fn main_tabs(&mut self, ui: &mut egui::Ui) {
        let pending = !self.state.lock().unwrap().queue.is_empty();
        ui.horizontal(|ui| {
            for t in MAIN_TABS {
                let flagged = (t == "Proxy" && pending && self.tab != "Proxy")
                    || (self.flash == Some(t) && self.tab != t);
                if theme::main_tab(ui, self.tab == t, flagged, t).clicked() {
                    self.tab = t;
                    if self.flash == Some(t) {
                        self.flash = None;
                    }
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Settings").clicked() {
                    self.settings.open = true;
                }
                if let Some(p) = &self.project {
                    ui.label(
                        RichText::new(&self.autosave.status)
                            .small()
                            .color(theme::muted()),
                    )
                    .on_hover_text(format!(
                        "Autosaved every {} s to {}",
                        project::AUTOSAVE.as_secs(),
                        p.display()
                    ));
                }
            });
        });
    }

    fn entry_action(&mut self, what: &str, e: Entry, logger: bool) {
        match what {
            "repeater" => {
                self.send_to_repeater(&e);
            }
            "intruder" => {
                self.intruder.add(
                    e.host.clone(),
                    e.port,
                    e.tls,
                    String::from_utf8_lossy(&e.req).into_owned(),
                );
                self.flash = Some("Intruder");
            }
            "sequencer" => {
                self.sequencer.load(
                    e.host.clone(),
                    e.port,
                    e.tls,
                    String::from_utf8_lossy(&e.req).into_owned(),
                    &String::from_utf8_lossy(&e.resp),
                );
                self.flash = Some("Sequencer");
            }
            "organizer" => {
                self.organizer.add(e);
                self.flash = Some("Organizer");
            }
            "cmp_req" => self
                .comparer
                .add(String::from_utf8_lossy(&e.req).into_owned()),
            "cmp_resp" => self
                .comparer
                .add(String::from_utf8_lossy(&e.resp).into_owned()),
            "decoder" => {
                self.decoder.panes = vec![(String::from_utf8_lossy(&e.req).into_owned(), false)];
                self.flash = Some("Decoder");
            }
            "comment" => self.comment_edit = Some((e.id, e.comment.clone())),
            "clear" => {
                let mut s = self.state.lock().unwrap();
                if logger {
                    s.logger.clear()
                } else {
                    s.history.clear()
                }
            }
            "delete" => {
                let mut s = self.state.lock().unwrap();
                let list = if logger {
                    &mut s.logger
                } else {
                    &mut s.history
                };
                list.retain(|x| x.id != e.id);
            }
            "domi" => {
                let (url, state) = (format!("{}{}", e.origin(), e.url), self.state.clone());
                state.lock().unwrap().event(
                    "DOM Invader",
                    format!("Scanning {url} in a headless browser"),
                );
                std::thread::spawn(move || {
                    let msg = match domi::scan(&url, &state, true) {
                        Ok(f) => format!("Finished {url}: {} finding(s)", f.len()),
                        Err(e) => format!("Failed on {url}: {e}"),
                    };
                    state.lock().unwrap().event("DOM Invader", msg);
                });
            }
            "scan" => {
                let mut cfg = scan::Config::fast();
                cfg.crawl = false;
                let req = String::from_utf8_lossy(&e.req).into_owned();
                self.start_scan(
                    vec![],
                    vec![(
                        scan::Target {
                            host: e.host.clone(),
                            port: e.port,
                            tls: e.tls,
                        },
                        req,
                    )],
                    cfg,
                );
            }
            w if w.starts_with("eng:") => {
                let tool = w[4..].parse().unwrap_or(0);
                self.engage.start(tool, e, &self.state);
            }
            w if w.starts_with("hl:") => {
                let idx = w[3..].parse::<usize>().ok();
                let mut s = self.state.lock().unwrap();
                let list = if logger {
                    &mut s.logger
                } else {
                    &mut s.history
                };
                if let Some(x) = list.iter_mut().find(|x| x.id == e.id) {
                    x.highlight = idx.filter(|&i| i < theme::HIGHLIGHTS.len());
                }
            }
            "scope" => self.target.add_to_scope(&e),
            "delete_host" => {
                let origin = e.origin();
                self.state
                    .lock()
                    .unwrap()
                    .history
                    .retain(|x| x.origin() != origin);
            }
            _ => {}
        }
    }
}

/// Next occurrence of a local "HH:MM" (today, or tomorrow if already past); None for empty/invalid input.
fn next_time(hhmm: &str) -> Option<chrono::DateTime<chrono::Local>> {
    let t = chrono::NaiveTime::parse_from_str(hhmm, "%H:%M").ok()?;
    let now = chrono::Local::now();
    let today = now
        .date_naive()
        .and_time(t)
        .and_local_timezone(chrono::Local)
        .earliest()?;
    Some(if today > now {
        today
    } else {
        today + chrono::Duration::days(1)
    })
}

/// Launches a Chromium-based browser pre-configured to use the proxy, like the original's embedded browser.
fn open_browser(state: &State) {
    let port = state.lock().unwrap().listener;
    let Some(port) = port else {
        state.lock().unwrap().event(
            "Proxy",
            "Failed to launch browser: the proxy is not running",
        );
        return;
    };
    let dir = net::data_dir().join("browser-profile");
    let args = [
        format!("--proxy-server=127.0.0.1:{port}"),
        "--ignore-certificate-errors".into(),
        "--proxy-bypass-list=<-loopback>".into(),
        format!("--user-data-dir={}", dir.display()),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
    ];
    // DOM Invader rides along (Chrome for Testing / Chromium; branded Chrome ignores --load-extension)
    let mut args = args.to_vec();
    if let Ok(dir) = domi::extension_dir() {
        args.push(format!("--load-extension={}", dir.display()));
    }
    let ok = render::chromium_path()
        .is_some_and(|c| std::process::Command::new(c).args(&args).spawn().is_ok());
    let msg = if ok {
        format!("Browser launched with proxy 127.0.0.1:{port}")
    } else {
        "Failed to launch browser: no Chromium-based browser found".to_string()
    };
    state.lock().unwrap().event("Proxy", msg);
}

impl eframe::App for App {
    fn on_exit(&mut self) {
        // like a disk-based project: closing the app keeps the work
        if let Some(p) = self.project.clone() {
            let _ = project::save(self, &p);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.dev_screenshot(ui.ctx());
        if self.tab == "Intruder" {
            let pasted: Vec<String> = ui.input(|i| {
                i.events
                    .iter()
                    .filter_map(|e| {
                        if let egui::Event::Paste(t) = e {
                            Some(t.clone())
                        } else {
                            None
                        }
                    })
                    .collect()
            });
            // ponytail: only the Payloads "Paste" button should land here; a focused text field also gets the paste
            if ui.ctx().memory(|m| m.focused().is_none()) {
                for t in pasted {
                    self.intruder.paste(&t);
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        egui::Panel::top("menu")
            .frame(theme::frame_chrome())
            .show(ui, |ui| self.menu(ui));
        #[cfg(target_os = "macos")]
        {
            let cmds = self
                .native_menu
                .as_ref()
                .map(|m| m.poll())
                .unwrap_or_default();
            for c in cmds {
                self.run(ui.ctx(), c);
            }
            let intercept = self.state.lock().unwrap().intercept;
            if let Some(m) = &mut self.native_menu {
                m.sync(self.rest_port, self.mcp_port, intercept);
            }
        }
        egui::Panel::top("tabs")
            .frame(
                egui::Frame::new()
                    .fill(theme::chrome())
                    .inner_margin(egui::Margin::symmetric(6, 0)),
            )
            .show(ui, |ui| self.main_tabs(ui));
        update::popup(ui.ctx(), &mut self.update_dismissed);
        self.intruder.windows(ui.ctx());
        self.project_window(ui.ctx());
        self.search_window(ui.ctx());
        self.engage.window(ui.ctx());
        self.scan_window(ui.ctx());
        self.live_audit();
        let cmds = std::mem::take(&mut self.state.lock().unwrap().ui_cmds);
        for (what, e) in cmds {
            self.entry_action(what, e, false);
        }
        self.run_schedules(ui.ctx());
        project::autosave(self, ui.ctx());
        if ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::S)) {
            self.run(ui.ctx(), Cmd::SaveProject);
        }
        if self.settings.open && self.settings.window(ui.ctx(), &self.state) {
            theme::apply(ui.ctx(), self.settings.dark, self.settings.font_size);
        }
        self.shortcuts(ui.ctx());
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme::bg_color()).inner_margin(6))
            .show(ui, |ui| match self.tab {
                "Dashboard" => self.dashboard(ui),
                "Proxy" => self.proxy(ui),
                "Repeater" => self.repeater.ui(ui, &self.state),
                "Decoder" => self.decoder.ui(ui),
                "Comparer" => self.comparer.ui(ui),
                "Logger" => self.logger(ui),
                "Intruder" => self.intruder.ui(ui, &self.state),
                "Sequencer" => self.sequencer.ui(ui, &self.state),
                "Organizer" => self.organizer.ui(ui),
                "Collaborator" => self.collab.ui(ui),
                "Extensions" => self.extensions.ui(ui),
                "Learn" => misc::learn(ui),
                "Target" => {
                    if let Some((what, e)) = self.target.ui(ui, &self.state) {
                        self.entry_action(what, e, false);
                    }
                }
                other => {
                    ui.vertical_centered(|ui| {
                        ui.add_space(80.0);
                        ui.label(RichText::new(other).size(20.0).color(theme::muted()));
                        ui.label(RichText::new("Not implemented yet").color(theme::muted()));
                    });
                }
            });
    }
}

impl App {
    /// Global hotkeys (Ctrl on Linux/Windows, Cmd on macOS).
    fn shortcuts(&mut self, ctx: &egui::Context) {
        use egui::{Key, KeyboardShortcut as K, Modifiers as M};
        let hit = |m: M, k: Key| ctx.input_mut(|i| i.consume_shortcut(&K::new(m, k)));
        let cs = M::COMMAND | M::SHIFT;
        if hit(cs, Key::F) {
            self.search.open = true;
        }
        for (k, tab) in [
            (Key::D, "Dashboard"),
            (Key::T, "Target"),
            (Key::P, "Proxy"),
            (Key::I, "Intruder"),
            (Key::R, "Repeater"),
        ] {
            if hit(cs, k) {
                self.tab = tab;
            }
        }
        let selected = match self.tab {
            "Proxy" if self.proxy_tab == "HTTP history" => self.selected.and_then(|id| {
                self.state
                    .lock()
                    .unwrap()
                    .history
                    .iter()
                    .find(|e| e.id == id)
                    .cloned()
            }),
            "Logger" => self.logger_sel.and_then(|id| {
                self.state
                    .lock()
                    .unwrap()
                    .logger
                    .iter()
                    .find(|e| e.id == id)
                    .cloned()
            }),
            _ => None,
        };
        if let Some(e) = selected {
            if hit(M::COMMAND, Key::R) {
                self.entry_action("repeater", e.clone(), false);
            }
            if hit(M::COMMAND, Key::I) {
                self.entry_action("intruder", e, false);
            }
        }
        if hit(M::COMMAND, Key::T) {
            let mut s = self.state.lock().unwrap();
            s.intercept = !s.intercept;
            if !s.intercept {
                s.forward_all();
            }
        }
        if self.tab == "Proxy" && self.proxy_tab == "Intercept" && hit(M::COMMAND, Key::F) {
            let mut s = self.state.lock().unwrap();
            if let Some(p) = s.queue.pop_front() {
                let msg = self
                    .intercept_text
                    .take()
                    .map(|t| t.1.into_bytes())
                    .unwrap_or(p.req.clone());
                let _ = p.reply.send(Some(msg));
            }
        }
        if self.tab == "Repeater" && hit(M::COMMAND, Key::Space) {
            self.repeater.send_current(ctx);
        }
    }

    /// Dev hook: BURPCRAFT_SHOT=/path.bmp saves a window screenshot after a few frames, then quits.
    fn dev_screenshot(&mut self, ctx: &egui::Context) {
        let Ok(path) = std::env::var("BURPCRAFT_SHOT") else {
            return;
        };
        self.frames += 1;
        // first entry: sub-resources fetched by the Chromium render land after it (and may be filtered out)
        self.selected = self
            .state
            .lock()
            .unwrap()
            .history
            .first()
            .map(|e| e.id)
            .or(self.selected);
        self.issue_sel = self
            .state
            .lock()
            .unwrap()
            .issues
            .iter()
            .min_by_key(|i| i.severity)
            .map(|i| i.id)
            .or(self.issue_sel);
        let first = if self.frames == 200 {
            self.state.lock().unwrap().history.first().cloned()
        } else {
            None
        };
        if let Some(e) = first {
            match self.tab {
                "Intruder" => self.intruder.add(
                    e.host.clone(),
                    e.port,
                    e.tls,
                    String::from_utf8_lossy(&e.req).into_owned(),
                ),
                "Repeater" => self.send_to_repeater(&e),
                _ => {}
            }
        }
        if self.frames
            == std::env::var("BURPCRAFT_SHOT_FRAMES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30)
        {
            let c = ctx.clone();
            ctx.request_screenshot(move |img| {
                let _ = std::fs::write(&path, bmp(&img));
                c.send_viewport_cmd(egui::ViewportCommand::Close);
            });
        }
        ctx.request_repaint();
    }
}

fn bmp(img: &egui::ColorImage) -> Vec<u8> {
    let [w, h] = img.size;
    let size = 54 + w * h * 4;
    let mut b = Vec::with_capacity(size);
    b.extend_from_slice(b"BM");
    for v in [
        size as u32,
        0,
        54,
        40,
        w as u32,
        (h as i32).wrapping_neg() as u32,
    ] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&32u16.to_le_bytes());
    b.extend_from_slice(&[0; 24]);
    for p in &img.pixels {
        b.extend_from_slice(&[p.b(), p.g(), p.r(), 255]);
    }
    b
}

/// App/window icon (the crab logo), decoded from the embedded PNG.
fn app_icon() -> egui::IconData {
    let png = include_bytes!("../assets/app-icon/window-icon.png");
    match image::load_from_memory(png) {
        Ok(img) => {
            let rgba = img.to_rgba8();
            let (width, height) = rgba.dimensions();
            egui::IconData {
                rgba: rgba.into_raw(),
                width,
                height,
            }
        }
        Err(_) => egui::IconData::default(),
    }
}

fn main() -> eframe::Result {
    let opts = eframe::NativeOptions {
        renderer: eframe::Renderer::Wgpu,
        viewport: egui::ViewportBuilder::default()
            .with_title("BurpCraft Community Edition")
            .with_inner_size([1400.0, 900.0])
            .with_icon(app_icon()),
        ..Default::default()
    };
    eframe::run_native("BurpCraft", opts, Box::new(|cc| Ok(Box::new(App::new(cc)))))
}

#[cfg(test)]
mod tests {
    #[test]
    fn schedule_times() {
        assert!(super::next_time("").is_none() && super::next_time("25:00").is_none());
        let t = super::next_time("03:15").unwrap();
        let now = chrono::Local::now();
        assert!(t > now && t - now <= chrono::Duration::days(1));
        assert_eq!(t.format("%H:%M").to_string(), "03:15");
    }
}
