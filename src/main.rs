// release builds are a GUI app on Windows: no console window
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
mod ai;
mod bcheck;
mod codec;
mod collab;
mod domi;
mod editor;
mod engage;
mod ext;
mod h2up;
mod intruder;
#[cfg(target_os = "macos")]
mod macmenu;
mod mcp;
mod misc;
mod net;
mod openapi;
mod project;
mod proxy;
mod render;
mod report;
mod rest;
mod scan;
mod scanner;
mod search;
mod sequencer;
mod target;
mod theme;
mod tools;
mod update;

use std::sync::Arc;

use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};

use proxy::{Entry, State};

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
                // a new path starts a new project there, saved on exit
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

    fn scan_window(&mut self, ctx: &egui::Context) {
        let Some((mut urls, mut cfg, mut api, mut at, mut every)) = self.scan_dlg.take() else {
            return;
        };
        let (mut open, mut go) = (true, false);
        theme::window(ctx, "New scan", [560.0, 640.0], &mut open, |ui| {
            ui.label("URLs to scan (one per line):");
            ui.add(
                egui::TextEdit::multiline(&mut urls)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY)
                    .hint_text("https://target.example/"),
            );
            ui.horizontal(|ui| {
                ui.label("Scan configuration:");
                if ui.button("Fast").clicked() {
                    cfg = scan::Config {
                        headers: cfg.headers.clone(),
                        login: cfg.login.clone(),
                        ..scan::Config::fast()
                    };
                }
                if ui
                    .button("Thorough")
                    .on_hover_text("Adds time-based checks and crawls up to 500 pages")
                    .clicked()
                {
                    cfg = scan::Config {
                        headers: cfg.headers.clone(),
                        login: cfg.login.clone(),
                        ..scan::Config::thorough()
                    };
                }
            });
            ui.checkbox(
                &mut cfg.crawl,
                "Crawl from the URLs (otherwise audit them only)",
            );
            egui::Grid::new("checks").num_columns(3).show(ui, |ui| {
                for (i, name) in scan::CHECKS.iter().enumerate() {
                    ui.checkbox(&mut cfg.checks[i], *name);
                    if i % 3 == 2 {
                        ui.end_row();
                    }
                }
            });
            ui.horizontal(|ui| {
                ui.label("Max pages:");
                ui.add(egui::DragValue::new(&mut cfg.max_pages).range(1..=10_000));
                ui.label("Threads:");
                ui.add(egui::DragValue::new(&mut cfg.threads).range(1..=32));
                ui.label("Delay (ms):");
                ui.add(egui::DragValue::new(&mut cfg.delay_ms).range(0..=10_000));
            });
            ui.collapsing("Authentication", |ui| {
                ui.label("Extra headers on every request (e.g. Authorization: Bearer ...):");
                ui.add(egui::TextEdit::multiline(&mut cfg.headers).desired_rows(2).desired_width(f32::INFINITY));
                ui.label("Login request (raw HTTP, sent first; its Set-Cookie values join every request):");
                ui.add(egui::TextEdit::multiline(&mut cfg.login).code_editor().desired_rows(4).desired_width(f32::INFINITY));
            });
            ui.collapsing("API definition", |ui| {
                ui.label("OpenAPI / Swagger JSON file to audit every operation of:");
                ui.add(
                    egui::TextEdit::singleline(&mut api)
                        .hint_text("/path/to/openapi.json")
                        .desired_width(f32::INFINITY),
                );
            });
            ui.collapsing("Schedule", |ui| {
                ui.horizontal(|ui| {
                    ui.label("Start at (HH:MM, empty = now):");
                    ui.add(egui::TextEdit::singleline(&mut at).desired_width(60.0));
                    ui.label("Repeat every");
                    ui.add(egui::DragValue::new(&mut every).range(0..=720));
                    ui.label("hours (0 = once)");
                });
            });
            go = theme::primary_button(
                ui,
                if at.trim().is_empty() {
                    "Scan"
                } else {
                    "Schedule scan"
                },
            )
            .clicked();
        });
        if go {
            let list: Vec<String> = urls
                .lines()
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .map(String::from)
                .collect();
            let mut extra = vec![];
            if !api.trim().is_empty() {
                match openapi::load(api.trim(), list.first().map(String::as_str)) {
                    Ok(reqs) => extra = reqs,
                    Err(e) => self
                        .state
                        .lock()
                        .unwrap()
                        .event("Scanner", format!("API definition: {e}")),
                }
            }
            if let Some(when) = next_time(at.trim()) {
                if !list.is_empty() {
                    self.state.lock().unwrap().event(
                        "Scanner",
                        format!(
                            "Scan of {} scheduled for {}",
                            list.join(", "),
                            when.format("%H:%M %-d %b")
                        ),
                    );
                    self.schedules.push((when, every, list, cfg));
                    return;
                }
            } else if !list.is_empty() || !extra.is_empty() {
                let list = if extra.is_empty() { list } else { vec![] };
                self.start_scan(list, extra, cfg);
                return;
            }
        }
        if open {
            self.scan_dlg = Some((urls, cfg, api, at, every));
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
            });
        });
    }

    // ------------------------------------------------------------ Dashboard

    fn dashboard(&mut self, ui: &mut egui::Ui) {
        let h = ui.available_height() / 2.0;
        egui::Panel::top("dash_top").exact_size(h).show(ui, |ui| {
            ui.columns(2, |c| {
                theme::heading(&mut c[0], "Tasks");
                c[0].horizontal(|ui| {
                    if ui.button("New scan").clicked() {
                        self.scan_dlg = Some((String::new(), scan::Config::fast(), String::new(), String::new(), 0));
                    }
                    let live = if self.live_active { "Stop live active audit" } else { "New live task" };
                    if ui.button(live).on_hover_text("Actively audits every new in-scope proxied request that has parameters").clicked() {
                        self.live_active = !self.live_active;
                        self.live_seen = self.state.lock().unwrap().next_id;
                    }
                });
                c[0].separator();
                egui::ScrollArea::vertical().id_salt("tasks").max_height(c[0].available_height() * 0.6).show(&mut c[0], |ui| {
                    for (when, every, urls, _) in &self.schedules {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(format!("Scheduled scan of {}", urls.join(", "))).strong());
                            let rep = if *every > 0 { format!(", then every {every} h") } else { String::new() };
                            ui.label(RichText::new(format!("Next run {}{rep}", when.format("%H:%M %-d %b"))).color(theme::muted()));
                        });
                    }
                    let scans = self.scans.lock().unwrap();
                    for t in scans.iter().rev() {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&t.name).strong());
                                if !t.done.load(std::sync::atomic::Ordering::SeqCst) && ui.small_button("Stop").clicked() {
                                    t.stop.store(true, std::sync::atomic::Ordering::SeqCst);
                                }
                            });
                            ui.label(RichText::new(t.status.lock().unwrap().as_str()).color(theme::muted()));
                            ui.label(format!(
                                "{} requests, {} issues",
                                t.requests.load(std::sync::atomic::Ordering::SeqCst),
                                t.issues.load(std::sync::atomic::Ordering::SeqCst)
                            ));
                        });
                    }
                });
                if self.scans.lock().unwrap().iter().any(|t| !t.done.load(std::sync::atomic::Ordering::SeqCst)) {
                    c[0].ctx().request_repaint_after(std::time::Duration::from_millis(500));
                }
                for (n, (name, desc)) in [
                    ("Live passive crawl from Proxy (all traffic)", "Capturing: adds every proxied item to the site map"),
                    ("Live audit from Proxy (all traffic)", "Passive checks on every proxied response; results appear in Issue activity"),
                    (
                        if self.live_active { "Live active audit from Proxy (in scope): on" } else { "Live active audit from Proxy (in scope): off" },
                        "Attack payloads against every new in-scope request with parameters (New live task)",
                    ),
                ]
                .iter()
                .enumerate()
                {
                    egui::Frame::group(c[0].style()).show(&mut c[0], |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(RichText::new(format!("{}. {name}", n + 1)).strong());
                        ui.label(RichText::new(*desc).color(theme::muted()));
                    });
                }
                c[1].horizontal(|ui| {
                    theme::heading(ui, "Issue activity");
                    for (html, label) in [(true, "Report (HTML)"), (false, "Export (XML)")] {
                        if ui.button(label).clicked() {
                            let mut s = self.state.lock().unwrap();
                            let msg = match report::write(&s.issues, &s.history, html) {
                                Ok(p) => {
                                    if html {
                                        let _ = misc::open_external(&p);
                                    }
                                    format!("Report written to {}", p.display())
                                }
                                Err(e) => format!("Failed to write report: {e}"),
                            };
                            s.event("Report", msg);
                        }
                    }
                });
                c[1].separator();
                self.issue_table(&mut c[1]);
            });
        });
        ui.columns(2, |c| {
            theme::heading(&mut c[0], "Event log");
            c[0].separator();
            let events = self.state.lock().unwrap().events.clone();
            TableBuilder::new(&mut c[0])
                .id_salt("events")
                .striped(true)
                .column(Column::initial(150.0))
                .column(Column::initial(60.0))
                .column(Column::initial(70.0))
                .column(Column::remainder())
                .header(22.0, |mut r| {
                    for h in ["Time", "Type", "Source", "Message"] {
                        r.col(|ui| {
                            ui.strong(h);
                        });
                    }
                })
                .body(|body| {
                    body.rows(20.0, events.len(), |mut row| {
                        let (t, s, m) = &events[events.len() - 1 - row.index()];
                        let typ = if m.starts_with("Failed") {
                            "Error"
                        } else {
                            "Info"
                        };
                        for v in [t.as_str(), typ, s, m] {
                            row.col(|ui| {
                                ui.label(v);
                            });
                        }
                    });
                });
            theme::heading(&mut c[1], "Advisory");
            c[1].separator();
            self.advisory(&mut c[1]);
        });
    }

    fn issue_table(&mut self, ui: &mut egui::Ui) {
        let mut issues = self.state.lock().unwrap().issues.clone();
        if issues.is_empty() {
            ui.label(
                RichText::new(
                    "No issues. The passive scanner reports issues in proxied traffic here.",
                )
                .color(theme::muted()),
            );
            return;
        }
        issues.sort_by(|a, b| a.severity.cmp(&b.severity).then(b.id.cmp(&a.id)));
        let sel = self.issue_sel;
        let mut clicked = None;
        TableBuilder::new(ui)
            .id_salt("issues")
            .striped(true)
            .sense(egui::Sense::click())
            .resizable(true)
            .column(Column::initial(36.0))
            .column(Column::initial(210.0).clip(true))
            .column(Column::initial(150.0).clip(true))
            .column(Column::initial(110.0).clip(true))
            .column(Column::initial(85.0))
            .column(Column::remainder().at_least(80.0).clip(true))
            .header(22.0, |mut r| {
                for h in ["#", "Issue type", "Host", "Path", "Severity", "Confidence"] {
                    r.col(|ui| {
                        ui.strong(h);
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, issues.len(), |mut row| {
                    let i = &issues[row.index()];
                    row.set_selected(sel == Some(i.id));
                    let sev_color = match i.severity {
                        scanner::Severity::High => egui::Color32::from_rgb(0xD0, 0x21, 0x21),
                        scanner::Severity::Medium => theme::ORANGE_DARK,
                        scanner::Severity::Low => egui::Color32::from_rgb(0xB0, 0x8A, 0x00),
                        scanner::Severity::Info => theme::muted(),
                    };
                    row.col(|ui| {
                        ui.label(i.id.to_string());
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(i.name).truncate());
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(&i.origin).truncate());
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(&i.path).truncate());
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(i.severity.label()).color(sev_color).strong());
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(i.confidence).truncate());
                    });
                    if row.response().clicked() {
                        clicked = Some(i.id);
                    }
                });
            });
        if clicked.is_some() {
            self.issue_sel = clicked;
        }
    }

    fn advisory(&mut self, ui: &mut egui::Ui) {
        let issue = self.issue_sel.and_then(|id| {
            self.state
                .lock()
                .unwrap()
                .issues
                .iter()
                .find(|i| i.id == id)
                .cloned()
        });
        let Some(i) = issue else {
            ui.label(RichText::new("No issue selected").color(theme::muted()));
            return;
        };
        egui::ScrollArea::vertical().id_salt("advisory").show(ui, |ui| {
            ui.label(RichText::new(i.name).size(16.0).strong());
            egui::Grid::new("adv").num_columns(2).spacing([12.0, 2.0]).show(ui, |ui| {
                for (k, v) in [("Issue", i.name.to_string()), ("Severity", i.severity.label().into()), ("Confidence", i.confidence.into()), ("Host", i.origin.clone()), ("Path", i.path.clone())] {
                    ui.strong(k);
                    ui.label(v);
                    ui.end_row();
                }
            });
            ui.add_space(6.0);
            for (title, text) in [("Issue detail", i.detail.as_str()), ("Issue background", i.background), ("Issue remediation", i.remediation)] {
                ui.label(RichText::new(title).strong().color(theme::ORANGE_DARK));
                ui.label(text);
                ui.add_space(4.0);
            }
            let evidence = self.state.lock().unwrap().history.iter().find(|e| e.id == i.entry_id).cloned();
            let (ev_req, ev_resp) = evidence.as_ref().map(|e| (e.req.clone(), e.resp.clone())).unwrap_or_default();
            match evidence {
                // scanner evidence is not in the Proxy history: open it in Repeater instead
                Some(e) if e.tool != "Proxy" => {
                    if ui.button("Send evidence request to Repeater").clicked() {
                        self.send_to_repeater(&e);
                        self.tab = "Repeater";
                    }
                }
                _ => {
                    if ui.button("Show request in HTTP history").clicked() {
                        self.tab = "Proxy";
                        self.proxy_tab = "HTTP history";
                        self.selected = Some(i.entry_id);
                    }
                }
            }
            ui.add_space(6.0);
            theme::heading(ui, "BurpCraft AI");
            ui.horizontal(|ui| {
                if std::env::var_os("ANTHROPIC_API_KEY").is_none() {
                    ui.add(egui::TextEdit::singleline(&mut *ai::key().lock().unwrap()).password(true).hint_text("Anthropic API key (kept in memory)").desired_width(220.0));
                }
                let busy = matches!(ai::answers().lock().unwrap().get(&i.id), Some(None));
                if ui
                    .add_enabled(!busy, egui::Button::new("Explain with Claude"))
                    .on_hover_text(format!("Sends this issue and its request/response to the Anthropic API ({})", ai::MODEL))
                    .clicked()
                {
                    ai::explain(i.clone(), ev_req, ev_resp, ui.ctx().clone());
                }
                if busy {
                    ui.spinner();
                }
            });
            match ai::answers().lock().unwrap().get(&i.id) {
                Some(Some(Ok(text))) => {
                    ui.label(text.as_str());
                }
                Some(Some(Err(e))) => {
                    ui.colored_label(egui::Color32::from_rgb(0xC0, 0x30, 0x30), e.as_str());
                }
                _ => {
                    ui.label(RichText::new("Opt-in: the issue and its evidence are sent to Anthropic only when you click.").color(theme::muted()));
                }
            }
        });
    }

    // ------------------------------------------------------------ Proxy

    fn proxy(&mut self, ui: &mut egui::Ui) {
        theme::frame_chrome().show(ui, |ui| {
            ui.horizontal(|ui| {
                for t in PROXY_TABS {
                    if theme::sub_tab(ui, self.proxy_tab == t, t).clicked() {
                        self.proxy_tab = t;
                    }
                }
            });
        });
        match self.proxy_tab {
            "Intercept" => self.intercept(ui),
            "HTTP history" => self.history(ui),
            "Proxy settings" => self.proxy_settings(ui),
            "WebSockets history" => self.ws_history(ui),
            _ => self.match_replace(ui),
        }
    }

    fn intercept(&mut self, ui: &mut egui::Ui) {
        let (on, front) = {
            let s = self.state.lock().unwrap();
            (
                s.intercept,
                s.queue.front().map(|p| {
                    (
                        p.id * 2 + p.response as usize,
                        p.host.clone(),
                        p.port,
                        p.tls,
                        String::from_utf8_lossy(&p.req).into_owned(),
                    )
                }),
            )
        };
        if let Some((id, _, _, _, req)) = &front
            && self.intercept_text.as_ref().is_none_or(|(i, _)| i != id)
        {
            self.intercept_text = Some((*id, req.clone()));
        }
        let mut decision: Option<Option<Vec<u8>>> = None;
        let mut forward_all = false;
        ui.horizontal(|ui| {
            let has = front.is_some();
            let fwd = theme::split_button(ui, "Forward", has, |ui| {
                if ui
                    .button("Forward all")
                    .on_hover_text("Release every held message; intercept stays on")
                    .clicked()
                {
                    // the message on screen goes as edited, the rest unchanged
                    decision = Some(
                        self.intercept_text
                            .as_ref()
                            .map(|(_, t)| t.clone().into_bytes()),
                    );
                    forward_all = true;
                }
            });
            if fwd.clicked() {
                decision = Some(
                    self.intercept_text
                        .as_ref()
                        .map(|(_, t)| t.clone().into_bytes()),
                );
            }
            if ui.add_enabled(has, egui::Button::new("Drop")).clicked() {
                decision = Some(None);
            }
            let label = if on {
                "Intercept is on"
            } else {
                "Intercept is off"
            };
            let btn = egui::Button::new(RichText::new(label).strong()).selected(on);
            if ui.add(btn).clicked() {
                let mut s = self.state.lock().unwrap();
                s.intercept = !on;
                if on {
                    // turning intercept off releases everything queued unchanged
                    s.forward_all();
                }
            }
            ui.menu_button("Action ...", |ui| {
                if ui.button("Send to Repeater").clicked()
                    && let Some((_, host, port, tls, _)) = &front
                {
                    let txt = self
                        .intercept_text
                        .as_ref()
                        .map(|t| t.1.clone())
                        .unwrap_or_default();
                    self.repeater.add(host.clone(), *port, *tls, txt);
                    self.flash = Some("Repeater");
                }
                if ui.button("Send to Intruder").clicked()
                    && let Some((_, host, port, tls, _)) = &front
                {
                    let txt = self
                        .intercept_text
                        .as_ref()
                        .map(|t| t.1.clone())
                        .unwrap_or_default();
                    self.intruder.add(host.clone(), *port, *tls, txt);
                    self.flash = Some("Intruder");
                }
                if ui.button("Send to Comparer").clicked()
                    && let Some((_, t)) = &self.intercept_text
                {
                    self.comparer.add(t.clone());
                }
            });
            if ui.button("Open browser").clicked() {
                open_browser(&self.state);
            }
            if let Some((_, host, port, tls, _)) = &front {
                let scheme = if *tls { "https" } else { "http" };
                let what = if self
                    .intercept_text
                    .as_ref()
                    .is_some_and(|(id, _)| id % 2 == 1)
                {
                    "Response from"
                } else {
                    "Request to"
                };
                ui.label(
                    RichText::new(format!("{what} {scheme}://{host}:{port}")).color(theme::muted()),
                );
            }
        });
        ui.separator();
        if let Some(d) = decision {
            let mut s = self.state.lock().unwrap();
            if let Some(p) = s.queue.pop_front() {
                let _ = p.reply.send(d);
            }
            if forward_all {
                s.forward_all();
            }
            self.intercept_text = None;
            return;
        }
        match (&front, &mut self.intercept_text) {
            (Some(_), Some((id, text))) => {
                let text_ref: &str = text;
                let req = text_ref.to_owned();
                egui::Panel::right("int_insp")
                    .default_size(260.0)
                    .resizable(true)
                    .show(ui, |ui| editor::inspector(ui, &req, None));
                egui::CentralPanel::default().show(ui, |ui| {
                    let title = if *id % 2 == 1 { "Response" } else { "Request" };
                    editor::message(ui, ("intercept", *id), title, text, true);
                });
            }
            _ => {
                ui.vertical_centered(|ui| {
                    ui.add_space(80.0);
                    let msg = if on { "Waiting for requests…" } else { "Intercept is off" };
                    ui.label(RichText::new(msg).size(18.0).color(theme::muted()));
                    if !on {
                        ui.label(RichText::new("Turn intercept on to hold requests here for inspection and editing.").color(theme::muted()));
                    }
                });
            }
        }
    }

    fn history(&mut self, ui: &mut egui::Ui) {
        let rows: Vec<Entry> = {
            let s = self.state.lock().unwrap();
            let f = self.filter.to_ascii_lowercase();
            s.history
                .iter()
                // crawler and scanner evidence live in the site map, not the Proxy history
                .filter(|e| e.tool == "Proxy")
                .filter(|e| self.hfilter.keep(e, &self.target))
                .filter(|e| {
                    f.is_empty() || e.host.contains(&f) || e.url.to_ascii_lowercase().contains(&f)
                })
                .cloned()
                .collect()
        };
        ui.horizontal(|ui| {
            if ui
                .button(format!("Filter settings: {}", self.hfilter.describe()))
                .clicked()
            {
                self.hfilter_open = !self.hfilter_open;
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Search")
                    .desired_width(220.0),
            );
        });
        if self.hfilter_open {
            let mut open = true;
            theme::window(
                ui.ctx(),
                "HTTP history filter",
                [640.0, 420.0],
                &mut open,
                |ui| self.hfilter.ui(ui),
            );
            self.hfilter_open = open;
        }
        let sel = self
            .selected
            .and_then(|id| rows.iter().find(|e| e.id == id).cloned());
        let h = ui.available_height();
        let mut action: Option<(&'static str, Entry)> = None;
        egui::Panel::top("hist_table")
            .resizable(true)
            .default_size(h * 0.45)
            .show(ui, |ui| {
                action = history_table(ui, "history", &rows, &mut self.selected, false);
            });
        if let Some(e) = sel {
            let mut req = String::from_utf8_lossy(&e.req).into_owned();
            let mut resp = proxy::display(&e.resp);
            crate::editor::split(
                ui,
                ("hreq", e.id),
                &mut req,
                false,
                &mut resp,
                Some(&format!("{}{}", e.origin(), e.url)),
            );
        }
        if let Some((what, e)) = action {
            self.entry_action(what, e, false);
        }
        if let Some((id, text)) = &mut self.comment_edit {
            let mut open = true;
            let mut ok = false;
            theme::window(ui.ctx(), "Add comment", [360.0, 110.0], &mut open, |ui| {
                ui.text_edit_singleline(text);
                ok = theme::primary_button(ui, "OK").clicked();
            });
            if ok {
                let mut s = self.state.lock().unwrap();
                if let Some(e) = s.history.iter_mut().find(|e| e.id == *id) {
                    e.comment = text.clone();
                }
            }
            if ok || !open {
                self.comment_edit = None;
            }
        }
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

    fn ws_history(&mut self, ui: &mut egui::Ui) {
        let msgs = self.state.lock().unwrap().ws.clone();
        let h = ui.available_height();
        let sel = self.ws_sel;
        let mut clicked = None;
        egui::Panel::top("ws_tbl")
            .resizable(true)
            .default_size(h * 0.5)
            .show(ui, |ui| {
                TableBuilder::new(ui)
                    .id_salt("ws")
                    .striped(true)
                    .sense(egui::Sense::click())
                    .resizable(true)
                    .stick_to_bottom(true)
                    .column(Column::initial(50.0))
                    .column(Column::initial(320.0).clip(true))
                    .column(Column::initial(110.0))
                    .column(Column::initial(60.0))
                    .column(Column::initial(70.0))
                    .column(Column::initial(150.0))
                    .column(Column::remainder())
                    .header(22.0, |mut r| {
                        for c in [
                            "#",
                            "URL",
                            "Direction",
                            "Edited",
                            "Length",
                            "Time",
                            "Message",
                        ] {
                            r.col(|ui| {
                                ui.strong(c);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(20.0, msgs.len(), |mut row| {
                            let m = &msgs[row.index()];
                            row.set_selected(sel == Some(m.id));
                            let preview: String = String::from_utf8_lossy(&m.data)
                                .chars()
                                .take(200)
                                .map(|c| if c.is_control() { ' ' } else { c })
                                .collect();
                            let dir = if m.to_server {
                                "-> To server"
                            } else {
                                "<- To client"
                            };
                            for v in [
                                m.id.to_string(),
                                m.url.clone(),
                                dir.into(),
                                String::new(),
                                m.data.len().to_string(),
                                m.time.clone(),
                                preview,
                            ] {
                                row.col(|ui| {
                                    ui.add(egui::Label::new(v).truncate().selectable(false));
                                });
                            }
                            if row.response().clicked() {
                                clicked = Some(m.id);
                            }
                        });
                    });
            });
        if clicked.is_some() {
            self.ws_sel = clicked;
        }
        if let Some(m) = self.ws_sel.and_then(|id| msgs.iter().find(|m| m.id == id)) {
            let mut text = if m.opcode == 1 {
                String::from_utf8_lossy(&m.data).into_owned()
            } else {
                codec::hexdump_rows(&m.data)
                    .map(|(o, h, a)| format!("{o:08x}  {h:<47}  {a}\n"))
                    .collect()
            };
            egui::CentralPanel::default().show(ui, |ui| {
                editor::message(ui, ("ws", m.id), "Message", &mut text, false);
            });
        } else if msgs.is_empty() {
            ui.label(RichText::new("No WebSockets messages captured yet").color(theme::muted()));
        }
    }

    fn match_replace(&mut self, ui: &mut egui::Ui) {
        theme::heading(ui, "HTTP match and replace rules");
        ui.label("Use these settings to automatically replace parts of requests and responses passing through the Proxy. Patterns are regular expressions.");
        ui.add_space(6.0);
        let mut s = self.state.lock().unwrap();
        let mut remove = None;
        let mut swap = None;
        ui.horizontal(|ui| {
            if ui.button("Add").clicked() {
                s.rules.push(proxy::Rule {
                    enabled: true,
                    kind: 0,
                    pattern: String::new(),
                    replace: String::new(),
                    comment: String::new(),
                });
            }
            if ui.button("Clear").clicked() {
                s.rules.clear();
            }
        });
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("rules")
                .striped(true)
                .num_columns(7)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    for h in ["Enabled", "Item", "Match", "Replace", "Comment", "", ""] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    let n = s.rules.len();
                    for (i, r) in s.rules.iter_mut().enumerate() {
                        ui.checkbox(&mut r.enabled, "");
                        egui::ComboBox::from_id_salt(("kind", i))
                            .selected_text(proxy::RULE_KINDS[r.kind])
                            .width(150.0)
                            .show_ui(ui, |ui| {
                                for (k, name) in proxy::RULE_KINDS.iter().enumerate() {
                                    ui.selectable_value(&mut r.kind, k, *name);
                                }
                            });
                        let bad = !r.pattern.is_empty() && regex::Regex::new(&r.pattern).is_err();
                        let te = egui::TextEdit::singleline(&mut r.pattern)
                            .code_editor()
                            .desired_width(260.0);
                        ui.add(if bad {
                            te.text_color(egui::Color32::RED)
                        } else {
                            te
                        });
                        ui.add(
                            egui::TextEdit::singleline(&mut r.replace)
                                .code_editor()
                                .desired_width(260.0),
                        );
                        ui.add(egui::TextEdit::singleline(&mut r.comment).desired_width(180.0));
                        ui.horizontal(|ui| {
                            if ui.add_enabled(i > 0, egui::Button::new("Up")).clicked() {
                                swap = Some(i - 1);
                            }
                            if ui
                                .add_enabled(i + 1 < n, egui::Button::new("Down"))
                                .clicked()
                            {
                                swap = Some(i);
                            }
                        });
                        if ui.button("Remove").clicked() {
                            remove = Some(i);
                        }
                        ui.end_row();
                    }
                });
        });
        if let Some(i) = swap {
            s.rules.swap(i, i + 1);
        }
        if let Some(i) = remove {
            s.rules.remove(i);
        }
    }

    fn proxy_settings(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            theme::heading(ui, "Proxy listeners");
            ui.label("BurpCraft uses listeners to receive incoming HTTP requests from your browser. You will need to configure your browser to use one of the listeners as its proxy server.");
            let listener = self.state.lock().unwrap().listener;
            egui::Grid::new("listeners").striped(true).num_columns(5).spacing([16.0, 4.0]).show(ui, |ui| {
                for h in ["Running", "Interface", "Invisible", "Redirect", "Certificate"] {
                    ui.strong(h);
                }
                ui.end_row();
                let mut running = listener.is_some();
                ui.add_enabled(false, egui::Checkbox::without_text(&mut running));
                ui.label(format!("127.0.0.1:{}", listener.unwrap_or(8080)));
                ui.label("");
                ui.label("");
                ui.label("Per-host");
                ui.end_row();
            });
            ui.add_space(12.0);
            ui.label("Each installation of BurpCraft generates its own CA certificate that Proxy listeners can use when negotiating TLS connections.");
            if let Some(ca) = &self.ca {
                let path = net::data_dir().join("ca.pem");
                ui.horizontal(|ui| {
                    ui.label("CA certificate (PEM):");
                    ui.monospace(path.display().to_string());
                });
                ui.horizontal(|ui| {
                    if ui.button("Export certificate in DER format").clicked() {
                        let der = net::data_dir().join("cacert.der");
                        let msg = match std::fs::write(&der, &*ca.cert_der) {
                            Ok(()) => format!("CA certificate exported to {}", der.display()),
                            Err(e) => format!("Failed to export CA certificate: {e}"),
                        };
                        self.state.lock().unwrap().event("Proxy", msg);
                    }
                    if ui.button("Copy PEM").clicked() {
                        ui.ctx().copy_text(ca.cert_pem.clone());
                    }
                });
            }
            ui.add_space(12.0);
            theme::heading(ui, "HTTP/2");
            {
                let mut s = self.state.lock().unwrap();
                ui.checkbox(&mut s.http2, "Default to HTTP/2 if the server supports it");
            }
            ui.add_space(12.0);
            theme::heading(ui, "Request interception rules");
            let mut s = self.state.lock().unwrap();
            ui.checkbox(&mut s.intercept, "Intercept requests based on the following rules:");
            egui::Grid::new("irules").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
                ui.label("And URL file extension does not match:");
                let bad = regex::Regex::new(&s.intercept_skip_ext).is_err();
                let te = egui::TextEdit::singleline(&mut s.intercept_skip_ext).code_editor().desired_width(420.0);
                ui.add(if bad { te.text_color(egui::Color32::RED) } else { te });
                ui.end_row();
                ui.label("And domain name contains:");
                ui.add(egui::TextEdit::singleline(&mut s.intercept_host).hint_text("(any host)").desired_width(420.0));
                ui.end_row();
            });
            ui.add_space(8.0);
            theme::heading(ui, "Response interception rules");
            ui.checkbox(&mut s.intercept_responses, "Intercept responses based on the following rules: (all responses)");
        });
    }

    fn logger(&mut self, ui: &mut egui::Ui) {
        let rows = self.state.lock().unwrap().logger.clone();
        let sel = self
            .logger_sel
            .and_then(|id| rows.iter().find(|e| e.id == id).cloned());
        let h = ui.available_height();
        let mut action = None;
        egui::Panel::top("log_table")
            .resizable(true)
            .default_size(h * 0.5)
            .show(ui, |ui| {
                action = history_table(ui, "logger", &rows, &mut self.logger_sel, true);
            });
        if let Some(e) = sel {
            let mut req = String::from_utf8_lossy(&e.req).into_owned();
            let mut resp = proxy::display(&e.resp);
            crate::editor::split(
                ui,
                ("lreq", e.id),
                &mut req,
                false,
                &mut resp,
                Some(&format!("{}{}", e.origin(), e.url)),
            );
        }
        if let Some((what, e)) = action {
            self.entry_action(what, e, true);
        }
    }
}

const MIME_GROUPS: [&str; 8] = [
    "HTML",
    "Script",
    "XML",
    "CSS",
    "Other text",
    "Images",
    "Flash",
    "Other binary",
];

/// The HTTP history "Filter settings" popup state.
struct HistFilter {
    in_scope: bool,
    hide_no_response: bool,
    only_params: bool,
    mime: [bool; 8],
    status: [bool; 4],
    hide_ext: bool,
    exts: String,
}

impl Default for HistFilter {
    fn default() -> Self {
        Self {
            in_scope: false,
            hide_no_response: false,
            only_params: false,
            mime: [true, true, true, false, true, false, false, false],
            status: [true; 4],
            hide_ext: false,
            exts: "js,gif,jpg,png,css".into(),
        }
    }
}

impl HistFilter {
    fn group(e: &Entry) -> usize {
        match e.mime().as_str() {
            "HTML" => 0,
            "script" | "JSON" => 1,
            "XML" | "SVG" => 2,
            "CSS" => 3,
            "image" => 5,
            "font" => 7,
            "" | "text" => 4,
            _ => 7,
        }
    }

    fn keep(&self, e: &Entry, target: &target::Target) -> bool {
        let ext = e.extension().to_ascii_lowercase();
        let st = (e.status / 100) as usize;
        (!self.in_scope || target.in_scope(e))
            && (!self.hide_no_response || !e.resp.is_empty())
            && (!self.only_params || e.params())
            && (self.mime[Self::group(e)] || (Self::group(e) == 4 && e.mime().is_empty()))
            && !(self.hide_ext && !ext.is_empty() && self.exts.split(',').any(|x| x.trim() == ext))
            && (!(2..=5).contains(&st) || self.status[st - 2])
    }

    fn describe(&self) -> String {
        let mut parts = vec![];
        if self.in_scope {
            parts.push("Showing only in-scope items".to_string());
        }
        let hidden: Vec<&str> = MIME_GROUPS
            .iter()
            .zip(self.mime)
            .filter(|(_, on)| !on)
            .map(|(m, _)| *m)
            .collect();
        if hidden.is_empty() && parts.is_empty() {
            return "Showing all items".into();
        }
        if hidden == ["CSS", "Images", "Flash", "Other binary"] {
            parts.push("Hiding CSS, image and general binary content".into());
        } else if !hidden.is_empty() {
            parts.push(format!("Hiding {}", hidden.join(", ")));
        }
        parts.join("; ")
    }

    fn ui(&mut self, ui: &mut egui::Ui) {
        ui.columns(3, |c| {
            c[0].strong("Filter by request type");
            c[0].checkbox(&mut self.in_scope, "Show only in-scope items");
            c[0].checkbox(&mut self.hide_no_response, "Hide items without responses");
            c[0].checkbox(&mut self.only_params, "Show only parameterized requests");
            c[1].strong("Filter by MIME type");
            for (i, m) in MIME_GROUPS.iter().enumerate() {
                c[1].checkbox(&mut self.mime[i], *m);
            }
            c[2].strong("Filter by status code");
            for (i, m) in [
                "2xx [success]",
                "3xx [redirection]",
                "4xx [request error]",
                "5xx [server error]",
            ]
            .iter()
            .enumerate()
            {
                c[2].checkbox(&mut self.status[i], *m);
            }
            c[2].add_space(8.0);
            c[2].strong("Filter by file extension");
            c[2].checkbox(&mut self.hide_ext, "Hide:");
            c[2].text_edit_singleline(&mut self.exts);
        });
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Show all").clicked() {
                *self = HistFilter {
                    mime: [true; 8],
                    ..Default::default()
                };
            }
            if ui.button("Revert changes").clicked() {
                *self = HistFilter::default();
            }
        });
    }
}

/// Shared HTTP history / Logger table with the original's columns and context menu.
fn history_table(
    ui: &mut egui::Ui,
    id: &str,
    rows: &[Entry],
    selected: &mut Option<usize>,
    logger: bool,
) -> Option<(&'static str, Entry)> {
    let cols: &[(&str, f32)] = if logger {
        &[
            ("#", 50.0),
            ("Time", 140.0),
            ("Tool", 80.0),
            ("Method", 60.0),
            ("Host", 200.0),
            ("Path", 260.0),
            ("Status code", 80.0),
            ("Length", 70.0),
            ("MIME type", 70.0),
        ]
    } else {
        &[
            ("#", 50.0),
            ("Host", 200.0),
            ("Method", 60.0),
            ("URL", 280.0),
            ("Params", 55.0),
            ("Edited", 55.0),
            ("Status code", 80.0),
            ("Length", 70.0),
            ("MIME type", 70.0),
            ("Extension", 70.0),
            ("Title", 160.0),
            ("Notes", 120.0),
            ("TLS", 40.0),
            ("IP", 110.0),
            ("Cookies", 160.0),
            ("Time", 140.0),
            ("Listener port", 90.0),
        ]
    };
    let check = |b: bool| if b { "\u{2713}" } else { "" }.to_string();
    // ponytail: all cells are rebuilt every frame; cache per entry if histories reach 100k+ rows
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|e| {
            if logger {
                vec![
                    e.id.to_string(),
                    e.time.clone(),
                    e.tool.into(),
                    e.method.clone(),
                    e.origin(),
                    e.url.clone(),
                    e.status.to_string(),
                    e.resp.len().to_string(),
                    e.mime(),
                ]
            } else {
                vec![
                    e.id.to_string(),
                    e.origin(),
                    e.method.clone(),
                    e.url.clone(),
                    check(e.params()),
                    check(e.edited),
                    if e.status == 0 {
                        String::new()
                    } else {
                        e.status.to_string()
                    },
                    e.resp.len().to_string(),
                    e.mime(),
                    e.extension().into(),
                    e.title(),
                    e.comment.clone(),
                    check(e.tls),
                    e.ip.clone(),
                    e.cookies(),
                    e.time.clone(),
                    e.listener.to_string(),
                ]
            }
        })
        .collect();
    let sort_id = ui.make_persistent_id((id, "sort"));
    let mut sort: Option<(usize, bool)> = ui.data(|d| d.get_temp(sort_id));
    let mut order: Vec<usize> = (0..rows.len()).collect();
    if let Some((c, asc)) = sort {
        order.sort_by(|&a, &b| {
            let (x, y) = (&cells[a][c], &cells[b][c]);
            let o = match (x.parse::<f64>(), y.parse::<f64>()) {
                (Ok(p), Ok(q)) => p.total_cmp(&q),
                _ => x.cmp(y),
            };
            if asc { o } else { o.reverse() }
        });
    }
    let mut action = None;
    let mut tb = TableBuilder::new(ui)
        .id_salt(id)
        .striped(true)
        .sense(egui::Sense::click())
        .resizable(true)
        .stick_to_bottom(sort.is_none());
    for (_, w) in cols {
        tb = tb.column(Column::initial(*w).clip(true));
    }
    tb.header(22.0, |mut r| {
        for (i, (h, _)) in cols.iter().enumerate() {
            r.col(|ui| {
                let arrow = match sort {
                    Some((c, true)) if c == i => " ^",
                    Some((c, false)) if c == i => " v",
                    _ => "",
                };
                if ui
                    .add(
                        egui::Label::new(RichText::new(format!("{h}{arrow}")).strong())
                            .sense(egui::Sense::click()),
                    )
                    .clicked()
                {
                    // ascending -> descending -> unsorted, like the original
                    sort = match sort {
                        Some((c, true)) if c == i => Some((i, false)),
                        Some((c, false)) if c == i => None,
                        _ => Some((i, true)),
                    };
                }
            });
        }
    })
    .body(|body| {
        body.rows(20.0, rows.len(), |mut row| {
            let k = order[row.index()];
            let e = &rows[k];
            row.set_selected(*selected == Some(e.id));
            let vals = cells[k].clone();
            let hl = e.highlight.map(|i| theme::HIGHLIGHTS[i].1);
            for v in vals {
                row.col(|ui| {
                    if let Some(c) = hl {
                        ui.painter().rect_filled(
                            ui.max_rect().expand2(egui::vec2(4.0, 2.0)),
                            0.0,
                            c,
                        );
                    }
                    if v == "\u{2713}" {
                        // default fonts lack a check glyph, so paint the tick
                        let c = ui.max_rect().left_center() + egui::vec2(8.0, 0.0);
                        let pts = [
                            c + egui::vec2(-4.0, 0.0),
                            c + egui::vec2(-1.0, 3.5),
                            c + egui::vec2(5.0, -4.0),
                        ];
                        ui.painter()
                            .line(pts.to_vec(), egui::Stroke::new(1.8, theme::text()));
                    } else {
                        ui.add(egui::Label::new(v).truncate().selectable(false));
                    }
                });
            }
            let resp = row.response();
            if resp.clicked() {
                *selected = Some(e.id);
            }
            resp.context_menu(|ui| {
                *selected = Some(e.id);
                ui.label(RichText::new(format!("{}{}", e.origin(), e.url)).color(theme::muted()));
                ui.separator();
                let mut item = |ui: &mut egui::Ui, label: &str, key: &'static str| {
                    if ui.button(label).clicked() {
                        action = Some((key, e.clone()));
                        ui.close();
                    }
                };
                item(ui, "Add to scope", "scope");
                item(ui, "Do active scan", "scan");
                item(ui, "DOM Invader scan", "domi");
                ui.separator();
                item(ui, "Send to Intruder", "intruder");
                item(ui, "Send to Repeater", "repeater");
                item(ui, "Send to Sequencer", "sequencer");
                item(ui, "Send to Decoder", "decoder");
                item(ui, "Send to Organizer", "organizer");
                ui.menu_button("Send to Comparer", |ui| {
                    item(ui, "Request", "cmp_req");
                    item(ui, "Response", "cmp_resp");
                });
                ui.menu_button("Engagement tools", |ui| {
                    for (i, t) in engage::TOOLS.iter().enumerate() {
                        let key: &'static str =
                            ["eng:0", "eng:1", "eng:2", "eng:3", "eng:4", "eng:5"][i];
                        item(ui, t, key);
                    }
                });
                ui.separator();
                if ui.button("Copy URL").clicked() {
                    ui.ctx().copy_text(format!("{}{}", e.origin(), e.url));
                    ui.close();
                }
                if ui.button("Copy as curl command").clicked() {
                    ui.ctx().copy_text(curl_command(e));
                    ui.close();
                }
                ui.menu_button("Highlight", |ui| {
                    item(ui, "None", "hl:none");
                    for (i, (n, _)) in theme::HIGHLIGHTS.iter().enumerate() {
                        let key: &'static str = [
                            "hl:0", "hl:1", "hl:2", "hl:3", "hl:4", "hl:5", "hl:6", "hl:7",
                        ][i];
                        item(ui, n, key);
                    }
                });
                if !logger {
                    item(ui, "Add comment", "comment");
                }
                ui.separator();
                item(ui, "Delete item", "delete");
                item(
                    ui,
                    if logger { "Clear log" } else { "Clear history" },
                    "clear",
                );
            });
        });
    });
    ui.data_mut(|d| d.insert_temp(sort_id, sort));
    action
}

/// `curl` invocation reproducing a request (headers curl manages itself are skipped).
fn curl_command(e: &Entry) -> String {
    let q = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let text = String::from_utf8_lossy(&e.req).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut cmd = format!("curl -i -s -k -X {} \\\n", q(&e.method));
    for l in head.lines().skip(1) {
        if let Some((k, _)) = l.split_once(':')
            && !["host", "content-length", "connection"]
                .contains(&k.trim().to_ascii_lowercase().as_str())
        {
            cmd += &format!("    -H {} \\\n", q(l));
        }
    }
    if !body.is_empty() {
        cmd += &format!("    --data-binary {} \\\n", q(body));
    }
    cmd + &format!("    {}", q(&format!("{}{}", e.origin(), e.url)))
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
