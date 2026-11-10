//! Project files: saves and reopens the session state (history, logger, WebSockets, issues, scope,
//! match-and-replace rules, Repeater/Intruder tabs, Organizer, Comparer) as one gzip file.
//! Format: magic line, then length-prefixed fields in a fixed order (no serde dependency).
//! While a project file is open it is autosaved in the background every `AUTOSAVE` when it changed.
// ponytail: whole-file rewrite, not Burp's incremental disk project; a crash loses at most AUTOSAVE of work, add a write-ahead log if that is too much
use std::hash::Hasher;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use eframe::egui;

use crate::App;
use crate::proxy::{Entry, Rule, WsMsg};
use crate::security::scanner::{Issue, Severity};

const MAGIC: &[u8] = b"BURPCRAFT-PROJECT 1\n";

#[derive(Default)]
struct W(Vec<u8>);

impl W {
    fn n(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn b(&mut self, v: &[u8]) {
        self.n(v.len() as u64);
        self.0.extend_from_slice(v);
    }
    fn s(&mut self, v: &str) {
        self.b(v.as_bytes());
    }
    fn entry(&mut self, e: &Entry) {
        self.n(e.id as u64);
        self.s(&e.host);
        self.n(e.port as u64);
        self.n(e.tls as u64);
        self.s(&e.method);
        self.s(&e.url);
        self.n(e.status as u64);
        self.b(&e.req);
        self.b(&e.resp);
        self.n(e.edited as u64);
        self.s(&e.time);
        self.s(&e.ip);
        self.n(e.listener as u64);
        self.s(&e.comment);
        self.n(e.highlight.map_or(0, |h| h as u64 + 1));
        self.s(e.tool);
    }
}

struct R<'a>(&'a [u8]);

fn bad() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "truncated or corrupt project file",
    )
}

impl R<'_> {
    fn n(&mut self) -> io::Result<u64> {
        let (v, rest) = self.0.split_first_chunk::<8>().ok_or_else(bad)?;
        self.0 = rest;
        Ok(u64::from_le_bytes(*v))
    }
    fn b(&mut self) -> io::Result<Vec<u8>> {
        let len = usize::try_from(self.n()?).map_err(|_| bad())?;
        if len > self.0.len() {
            return Err(bad());
        }
        let (v, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(v.to_vec())
    }
    fn s(&mut self) -> io::Result<String> {
        String::from_utf8(self.b()?).map_err(|_| bad())
    }
    /// Fields typed `&'static str` in memory; a project is opened rarely, so leaking them is fine.
    fn st(&mut self) -> io::Result<&'static str> {
        Ok(self.s()?.leak())
    }
    fn count(&mut self) -> io::Result<usize> {
        // every item takes at least 8 bytes, so a larger count means a corrupt file (and no huge allocation)
        let n = usize::try_from(self.n()?).map_err(|_| bad())?;
        if n > self.0.len() / 8 {
            Err(bad())
        } else {
            Ok(n)
        }
    }
    fn entry(&mut self) -> io::Result<Entry> {
        Ok(Entry {
            id: self.n()? as usize,
            host: self.s()?,
            port: self.n()? as u16,
            tls: self.n()? != 0,
            method: self.s()?,
            url: self.s()?,
            status: self.n()? as u16,
            req: self.b()?,
            resp: self.b()?,
            edited: self.n()? != 0,
            time: self.s()?,
            ip: self.s()?,
            listener: self.n()? as u16,
            comment: self.s()?,
            highlight: self.n()?.checked_sub(1).map(|h| h as usize),
            tool: self.st()?,
        })
    }
}

const SEVERITIES: [Severity; 4] = [
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

/// Serialises the project-worthy parts of the app.
pub fn encode(app: &App) -> Vec<u8> {
    let mut w = W::default();
    let s = app.state.lock().unwrap();
    for list in [&s.history, &s.logger] {
        w.n(list.len() as u64);
        list.iter().for_each(|e| w.entry(e));
    }
    w.n(s.ws.len() as u64);
    for m in &s.ws {
        w.n(m.id as u64);
        w.s(&m.url);
        w.n(m.to_server as u64);
        w.n(m.opcode as u64);
        w.b(&m.data);
        w.s(&m.time);
    }
    w.n(s.issues.len() as u64);
    for i in &s.issues {
        w.n(i.id as u64);
        w.s(i.name);
        w.n(SEVERITIES
            .iter()
            .position(|v| *v == i.severity)
            .unwrap_or(3) as u64);
        w.s(i.confidence);
        w.s(&i.origin);
        w.s(&i.path);
        w.s(&i.detail);
        w.s(i.background);
        w.s(i.remediation);
        w.n(i.entry_id as u64);
    }
    w.n(s.rules.len() as u64);
    for r in &s.rules {
        w.n(r.enabled as u64);
        w.n(r.kind as u64);
        w.s(&r.pattern);
        w.s(&r.replace);
        w.s(&r.comment);
    }
    let scope = app.target.scope.lock().unwrap();
    w.n(scope.len() as u64);
    for (enabled, include, prefix) in scope.iter() {
        w.n(*enabled as u64);
        w.n(*include as u64);
        w.s(prefix);
    }
    w.n(app.repeater.tabs.len() as u64);
    for t in &app.repeater.tabs {
        w.s(&t.name);
        w.s(&t.host);
        w.n(t.port as u64);
        w.n(t.tls as u64);
        w.s(&t.req);
        w.s(&t.resp);
    }
    w.n(app.intruder.tabs.len() as u64);
    for t in &app.intruder.tabs {
        w.s(&t.host);
        w.n(t.port as u64);
        w.n(t.tls as u64);
        w.s(&t.template);
    }
    w.n(app.organizer.items.len() as u64);
    for (e, status, notes) in &app.organizer.items {
        w.entry(e);
        w.n(*status as u64);
        w.s(notes);
    }
    w.n(app.comparer.items.len() as u64);
    app.comparer.items.iter().for_each(|i| w.s(i));
    w.0
}

/// Replaces the app's project state with the decoded file; on error nothing is changed.
pub fn decode(app: &mut App, data: &[u8]) -> io::Result<()> {
    let mut r = R(data);
    let mut lists = [vec![], vec![]];
    for list in &mut lists {
        for _ in 0..r.count()? {
            list.push(r.entry()?);
        }
    }
    let mut ws = vec![];
    for _ in 0..r.count()? {
        ws.push(WsMsg {
            id: r.n()? as usize,
            url: r.s()?,
            to_server: r.n()? != 0,
            opcode: r.n()? as u8,
            data: r.b()?,
            time: r.s()?,
        });
    }
    let mut issues = vec![];
    for _ in 0..r.count()? {
        issues.push(Issue {
            id: r.n()? as usize,
            name: r.st()?,
            severity: SEVERITIES
                .get(r.n()? as usize)
                .copied()
                .unwrap_or(Severity::Info),
            confidence: r.st()?,
            origin: r.s()?,
            path: r.s()?,
            detail: r.s()?,
            background: r.st()?,
            remediation: r.st()?,
            entry_id: r.n()? as usize,
        });
    }
    let mut rules = vec![];
    for _ in 0..r.count()? {
        rules.push(Rule {
            enabled: r.n()? != 0,
            kind: r.n()? as usize,
            pattern: r.s()?,
            replace: r.s()?,
            comment: r.s()?,
        });
    }
    let mut scope = vec![];
    for _ in 0..r.count()? {
        scope.push((r.n()? != 0, r.n()? != 0, r.s()?));
    }
    let mut repeater = vec![];
    for _ in 0..r.count()? {
        repeater.push((r.s()?, r.s()?, r.n()? as u16, r.n()? != 0, r.s()?, r.s()?));
    }
    let mut intruder = vec![];
    for _ in 0..r.count()? {
        intruder.push((r.s()?, r.n()? as u16, r.n()? != 0, r.s()?));
    }
    let mut organizer = vec![];
    for _ in 0..r.count()? {
        organizer.push((r.entry()?, r.n()? as usize, r.s()?));
    }
    let mut comparer = vec![];
    for _ in 0..r.count()? {
        comparer.push(r.s()?);
    }

    // everything decoded: now swap it in
    let [history, logger] = lists;
    {
        let mut s = app.state.lock().unwrap();
        s.next_id = history.iter().map(|e| e.id).max().unwrap_or(0) + 1;
        (s.history, s.logger, s.ws, s.issues, s.rules) = (history, logger, ws, issues, rules);
    }
    *app.target.scope.lock().unwrap() = scope;
    app.repeater = Default::default();
    for (name, host, port, tls, req, resp) in repeater {
        app.repeater.add(host, port, tls, req);
        let t = app.repeater.tabs.last_mut().unwrap();
        (t.name, t.resp) = (name, resp);
    }
    app.intruder = Default::default();
    for (host, port, tls, template) in intruder {
        app.intruder.add(host, port, tls, String::new());
        app.intruder.tabs.last_mut().unwrap().template = template;
    }
    app.organizer.items = organizer;
    app.comparer.items = comparer;
    app.selected = None;
    Ok(())
}

pub const AUTOSAVE: Duration = Duration::from_secs(30);

/// Autosave state: when it last ran, a hash of what is on disk, the running background save.
#[derive(Default)]
pub struct Autosave {
    last: Option<Instant>,
    saved: u64,
    job: Option<std::thread::JoinHandle<io::Result<Option<u64>>>>,
    /// "Saved HH:MM:SS" or the last error, shown next to Settings.
    pub status: String,
}

fn hash(body: &[u8]) -> u64 {
    let mut h = std::hash::DefaultHasher::new();
    h.write(body);
    h.finish()
}

/// Gzips `body` into `<path>.tmp`, fsyncs and renames it over `path`, so a crash mid-save
/// leaves the previous project intact.
fn write(path: &Path, body: &[u8]) -> io::Result<()> {
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(dir) = dir {
        std::fs::create_dir_all(dir)?;
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(MAGIC)?;
    gz.write_all(body)?;
    let data = gz.finish()?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let res = std::fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(&data).and_then(|()| f.sync_all()))
        .and_then(|()| std::fs::rename(&tmp, path));
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    // the rename itself is durable once the directory is synced (best effort: not possible on Windows)
    let _ = std::fs::File::open(dir.unwrap_or(Path::new("."))).and_then(|d| d.sync_all());
    res
}

/// Waits for a running background save, so saves never race on the same file.
fn settle(a: &mut Autosave) {
    if let Some(Ok(Ok(Some(h)))) = a.job.take().map(|j| j.join()) {
        a.saved = h;
    }
}

pub fn save(app: &mut App, path: &Path) -> io::Result<()> {
    settle(&mut app.autosave);
    let body = encode(app);
    write(path, &body)?;
    app.autosave.saved = hash(&body);
    app.autosave.status = format!("Saved {}", chrono::Local::now().format("%H:%M:%S"));
    Ok(())
}

pub fn open(app: &mut App, path: &Path) -> io::Result<()> {
    let mut data = vec![];
    flate2::read::GzDecoder::new(std::fs::File::open(path)?).read_to_end(&mut data)?;
    let body = data.strip_prefix(MAGIC).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "not a BurpCraft project file")
    })?;
    decode(app, body)?;
    settle(&mut app.autosave);
    // decode/encode round-trips, so this is the hash of the reopened state
    (app.autosave.saved, app.autosave.status) = (hash(body), String::new());
    Ok(())
}

/// Called every frame: collects a finished background save and, every AUTOSAVE while a project
/// file is open, snapshots the state here and hashes/compresses/writes it on a thread if it changed.
pub fn autosave(app: &mut App, ctx: &egui::Context) {
    let a = &mut app.autosave;
    if let Some(job) = a.job.take_if(|j| j.is_finished()) {
        match job.join() {
            Ok(Ok(Some(h))) => {
                a.saved = h;
                a.status = format!("Saved {}", chrono::Local::now().format("%H:%M:%S"));
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => {
                a.status = format!("Autosave failed: {e}");
                let msg = a.status.clone();
                app.state.lock().unwrap().event("Project", msg);
            }
            Err(_) => a.status = "Autosave failed".into(),
        }
    }
    let Some(path) = app.project.clone() else {
        return;
    };
    let a = &mut app.autosave;
    ctx.request_repaint_after(if a.job.is_some() {
        Duration::from_secs(1)
    } else {
        AUTOSAVE
    });
    if a.job.is_some() || a.last.is_some_and(|t| t.elapsed() < AUTOSAVE) {
        return;
    }
    a.last = Some(Instant::now());
    let (body, saved) = (encode(app), app.autosave.saved);
    app.autosave.job = Some(std::thread::spawn(move || {
        let h = hash(&body);
        if h == saved {
            return Ok(None);
        }
        write(&path, &body).map(|()| Some(h))
    }));
}

pub fn default_path() -> std::path::PathBuf {
    crate::http::net::data_dir()
        .join("projects")
        .join("project.burpcraft")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: usize) -> Entry {
        Entry {
            id,
            host: "a.test".into(),
            port: 443,
            tls: true,
            method: "POST".into(),
            url: "/login?x=1".into(),
            status: 302,
            req: b"POST /login HTTP/1.1\r\n\r\nu=a&p=\xff".to_vec(),
            resp: b"HTTP/1.1 302 Found\r\n\r\n".to_vec(),
            edited: true,
            time: "12:00:00".into(),
            ip: "127.0.0.1".into(),
            listener: 8080,
            comment: "creds".into(),
            highlight: Some(2),
            tool: "Proxy",
        }
    }

    /// A project touching every saved section; also the content of the format fixtures.
    fn sample() -> App {
        let mut a = App::blank(crate::proxy::Shared::new());
        {
            let mut s = a.state.lock().unwrap();
            s.history = vec![entry(1), entry(7)];
            s.issues.push(Issue {
                id: 1,
                name: "Cookie without Secure flag",
                severity: Severity::Low,
                confidence: "Firm",
                origin: "https://a.test".into(),
                path: "/".into(),
                detail: "d".into(),
                background: "b",
                remediation: "r",
                entry_id: 7,
            });
            s.rules[0].enabled = true;
        }
        a.target
            .scope
            .lock()
            .unwrap()
            .push((true, true, "https://a.test/".into()));
        a.repeater
            .add("a.test".into(), 443, true, "GET / HTTP/1.1\r\n\r\n".into());
        a.repeater.tabs[0].resp = "HTTP/1.1 200 OK".into();
        a.intruder.add(
            "a.test".into(),
            443,
            true,
            "GET /?q=1 HTTP/1.1\r\n\r\n".into(),
        );
        a.organizer.items.push((entry(3), 1, "todo".into()));
        a.comparer.items.push("one".into());
        a
    }

    #[test]
    fn round_trip() {
        let mut a = sample();
        let dir =
            std::env::temp_dir().join(format!("burpcraft-project-test-{}", std::process::id()));
        let path = dir.join("p.burpcraft");
        save(&mut a, &path).unwrap();

        let mut b = App::blank(crate::proxy::Shared::new());
        open(&mut b, &path).unwrap();
        assert_eq!(encode(&a), encode(&b));
        let s = b.state.lock().unwrap();
        assert_eq!(
            (s.history[1].req.clone(), s.history[1].highlight, s.next_id),
            (entry(7).req, Some(2), 8)
        );
        assert_eq!(
            (s.issues[0].name, s.issues[0].severity),
            ("Cookie without Secure flag", Severity::Low)
        );
        assert_eq!(
            (
                b.repeater.tabs[0].resp.as_str(),
                b.intruder.tabs[0].template.as_str()
            ),
            ("HTTP/1.1 200 OK", a.intruder.tabs[0].template.as_str())
        );
        drop(s);

        // nothing changed since the save: autosave writes nothing; a new comment is written
        let ctx = egui::Context::default();
        b.project = Some(path.clone());
        let run = |b: &mut App| {
            b.autosave.last = None;
            autosave(b, &ctx);
            b.autosave.job.take().unwrap().join().unwrap().unwrap()
        };
        assert_eq!(run(&mut b), None);
        b.state.lock().unwrap().history[0].comment = "edited".into();
        let h = run(&mut b).unwrap();
        b.autosave.saved = h;
        assert_eq!(run(&mut b), None);
        let mut c = App::blank(crate::proxy::Shared::new());
        open(&mut c, &path).unwrap();
        assert_eq!(c.state.lock().unwrap().history[0].comment, "edited");

        // a failed save (here: the temp file cannot be created) leaves the previous file intact
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        std::fs::create_dir(&tmp).unwrap();
        c.state.lock().unwrap().history.clear();
        assert!(save(&mut c, &path).is_err());
        open(&mut c, &path).unwrap();
        assert_eq!(c.state.lock().unwrap().history.len(), 2);
        std::fs::remove_dir(&tmp).unwrap();

        // corrupt or foreign files are rejected without touching the open project
        std::fs::write(&path, b"not gzip").unwrap();
        assert!(open(&mut b, &path).is_err());
        let truncated = &encode(&a)[..40];
        assert!(decode(&mut b, truncated).is_err());
        assert_eq!(b.state.lock().unwrap().history.len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Files saved by released versions must keep opening to the same state. A format change adds
    /// migration code, never edits these fixtures; each release adds its own
    /// (`BURPCRAFT_WRITE_FIXTURE=1 cargo test fixtures` writes the current version's).
    #[test]
    fn fixtures_from_released_versions_open() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let current = dir.join(format!("project-{}.burpcraft", env!("CARGO_PKG_VERSION")));
        if std::env::var_os("BURPCRAFT_WRITE_FIXTURE").is_some() {
            save(&mut sample(), &current).unwrap();
        }
        let mut seen = 0;
        for f in std::fs::read_dir(&dir).unwrap().flatten() {
            let mut b = App::blank(crate::proxy::Shared::new());
            open(&mut b, &f.path()).unwrap_or_else(|e| panic!("{}: {e}", f.path().display()));
            assert!(
                encode(&b) == encode(&sample()),
                "{} decodes differently",
                f.path().display()
            );
            seen += 1;
        }
        assert!(seen > 0, "no fixtures in {}", dir.display());
    }
}
