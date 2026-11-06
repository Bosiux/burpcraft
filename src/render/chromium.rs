//! Chromium headless render path: browser discovery, process spawn, measuring pass and screenshot.
use eframe::egui;

/// A Chromium-family browser for headless rendering: $BURPCRAFT_CHROME, then common install paths.
pub fn chromium_path() -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("BURPCRAFT_CHROME") {
        return Some(p.into());
    }
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        // Chrome for Testing first: built for headless use (Brave 156 hangs on --headless)
        &[
            "/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            "~/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ]
    } else if cfg!(windows) {
        &[
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        ]
    } else {
        &[
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
        ]
    };
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();
    candidates
        .iter()
        .map(|c| {
            c.strip_prefix("~/")
                .map_or_else(|| std::path::PathBuf::from(c), |rest| home.join(rest))
        })
        .find(|p| p.exists())
}

#[derive(Clone)]
pub enum Shot {
    Pending,
    Done(std::path::PathBuf),
    Failed(String),
}

fn shots() -> &'static std::sync::Mutex<std::collections::HashMap<u64, Shot>> {
    static M: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u64, Shot>>> =
        std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// Page written to disk for Chromium: a <base> makes relative links resolve against the real URL.
pub fn page_with_base(html: &str, base: Option<&str>) -> String {
    match base {
        Some(b) => format!(
            "<base href=\"{}\">{html}",
            crate::http::codec::html_encode(b.as_bytes(), false)
        ),
        None => html.to_string(),
    }
}

/// Command-line arguments for a headless run; `out` is `--screenshot=<png>` or `--dump-dom`.
/// Sub-resources go through the BurpCraft proxy when it listens on `proxy_port`.
pub fn chromium_args(
    profile: &std::path::Path,
    out: &str,
    page: &std::path::Path,
    width: u32,
    height: u32,
    scale: f32,
    proxy_port: Option<u16>,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "--headless=new".into(),
        "--disable-gpu".into(),
        "--hide-scrollbars".into(),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--use-mock-keychain".into(),
        "--ignore-certificate-errors".into(),
        // keep Chrome's own update/telemetry requests out of the proxy history
        "--disable-background-networking".into(),
        "--disable-component-update".into(),
        "--disable-sync".into(),
        "--disable-domain-reliability".into(),
        "--no-pings".into(),
        // network-time and "AI Mode" eligibility checks still go out without these (verified on Chrome 157)
        "--disable-features=NetworkTimeServiceQuerying,AimServerEligibility,AimEnabled,AiMode"
            .into(),
        format!("--user-data-dir={}", profile.display()),
        format!("--window-size={width},{height}"),
        // HiDPI screens: capture at the screen's pixel density so the shot is sharp at full pane width
        format!("--force-device-scale-factor={scale}"),
        // lets scripts run and timers settle before the capture
        "--virtual-time-budget=3000".into(),
    ];
    if let Some(port) = proxy_port {
        args.extend([
            format!("--proxy-server=127.0.0.1:{port}"),
            // Chrome skips the proxy for localhost by default; local targets must show up too
            "--proxy-bypass-list=<-loopback>".into(),
        ]);
    }
    args.extend([out.into(), format!("file://{}", page.display())]);
    args
}

/// Appended to the page for the measuring pass: after load (images sized), records the document height.
const MEASURE: &str = "<script>addEventListener('load',()=>setTimeout(()=>{const d=document.documentElement;\
d.setAttribute('data-bc-h',Math.ceil(Math.max(d.scrollHeight,document.body?document.body.scrollHeight:0)))},0))</script>";

/// Page height in CSS px recorded by MEASURE in a `--dump-dom` output.
pub fn measured_height(dom: &str) -> Option<u32> {
    let rest = &dom[dom.find("data-bc-h=\"")? + 11..];
    rest[..rest.find('"')?].parse().ok()
}

/// Runs Chromium until `done()` or until it exits; gives up after 25 seconds.
pub fn run_chromium(
    cmd: &mut std::process::Command,
    done: impl Fn() -> bool,
) -> Result<(), String> {
    let mut child = cmd
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start {}: {e}", cmd.get_program().display()))?;
    let start = std::time::Instant::now();
    loop {
        // some builds keep running after writing the file, so the output appearing also counts as done
        if done() {
            std::thread::sleep(std::time::Duration::from_millis(200));
            let _ = child.kill();
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            return if done() {
                Ok(())
            } else {
                Err(format!("Chromium exited ({status}) without output"))
            };
        }
        if start.elapsed() > std::time::Duration::from_secs(25) {
            let _ = child.kill();
            return Err("Chromium did not finish rendering within 25 seconds".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Starts (once per page+width+scale) a full-page headless Chromium screenshot and reports its state.
/// `max_px` is the tallest texture the GPU accepts; longer pages are cut there.
// ponytail: two Chromium runs (measure with --dump-dom, then shoot at that height) instead of a DevTools
// session; 100vh layouts grow with the taller window, use CDP's captureBeyondViewport if that matters
pub fn chromium_shot(
    ctx: &egui::Context,
    html: &str,
    base: Option<&str>,
    width: u32,
    scale: f32,
    max_px: u32,
) -> Shot {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (html, base, width, scale.to_bits(), max_px).hash(&mut h);
    let key = h.finish();
    if let Some(s) = shots().lock().unwrap().get(&key) {
        return s.clone();
    }
    let Some(bin) = chromium_path() else {
        return Shot::Failed(
            "No Chromium-based browser found (set BURPCRAFT_CHROME to its path)".into(),
        );
    };
    shots().lock().unwrap().insert(key, Shot::Pending);
    let dir = std::env::temp_dir().join("burpcraft-render");
    let page = page_with_base(html, base);
    let ctx = ctx.clone();
    let proxy_port = crate::proxy::listen_port();
    std::thread::spawn(move || {
        // one profile per render: concurrent renders on a shared profile exit with status 21 (profile in use)
        let profile = dir.join(format!("{key:x}-profile"));
        let result = (|| -> Result<std::path::PathBuf, String> {
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let path = |ext: &str| dir.join(format!("{key:x}.{ext}"));
            let (file, png, dom) = (path("html"), path("png"), path("dom"));
            // pass 1: measure the laid-out page height
            std::fs::write(&file, format!("{page}{MEASURE}")).map_err(|e| e.to_string())?;
            let out = std::fs::File::create(&dom).map_err(|e| e.to_string())?;
            run_chromium(
                std::process::Command::new(&bin)
                    .args(chromium_args(
                        &profile,
                        "--dump-dom",
                        &file,
                        width,
                        600,
                        scale,
                        proxy_port,
                    ))
                    .stdout(out),
                || std::fs::read_to_string(&dom).is_ok_and(|d| d.contains("</html>")),
            )?;
            let limit = ((max_px as f32 / scale) as u32).max(600);
            let height = std::fs::read_to_string(&dom)
                .ok()
                .as_deref()
                .and_then(measured_height)
                .unwrap_or(2400)
                .clamp(200, limit);
            // pass 2: screenshot at that height (the PNG of an earlier run must not count as done)
            std::fs::write(&file, &page).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&png);
            let shot = format!("--screenshot={}", png.display());
            run_chromium(
                std::process::Command::new(&bin)
                    .args(chromium_args(
                        &profile, &shot, &file, width, height, scale, proxy_port,
                    ))
                    .stdout(std::process::Stdio::null()),
                || std::fs::metadata(&png).is_ok_and(|m| m.len() > 0),
            )?;
            Ok(png)
        })();
        let _ = std::fs::remove_dir_all(&profile);
        shots()
            .lock()
            .unwrap()
            .insert(key, result.map(Shot::Done).unwrap_or_else(Shot::Failed));
        ctx.request_repaint();
    });
    Shot::Pending
}

/// Texture for a finished Chromium screenshot (cached per file).
pub fn shot_texture(ctx: &egui::Context, png: &std::path::Path) -> Option<egui::TextureHandle> {
    let id = egui::Id::unique(("chromium-shot", png));
    if let Some(t) = ctx.data(|d| d.get_temp::<egui::TextureHandle>(id)) {
        return Some(t);
    }
    let img = image::load_from_memory(&std::fs::read(png).ok()?)
        .ok()?
        .to_rgba8();
    let ci = egui::ColorImage::from_rgba_unmultiplied(
        [img.width() as usize, img.height() as usize],
        &img,
    );
    let tex = ctx.load_texture(png.display().to_string(), ci, egui::TextureOptions::LINEAR);
    ctx.data_mut(|d| d.insert_temp(id, tex.clone()));
    Some(tex)
}

/// "Show response in browser": writes the body to a temp file (with a <base> for relative links) and opens it.
pub fn open_in_browser(html: &str, base: Option<&str>) -> std::io::Result<()> {
    let path = std::env::temp_dir().join(format!("burpcraft-render-{}.html", std::process::id()));
    let mut page = String::new();
    if let Some(b) = base {
        page += &format!(
            "<base href=\"{}\">",
            crate::http::codec::html_encode(b.as_bytes(), false)
        );
    }
    page += html;
    std::fs::write(&path, page)?;
    crate::misc::open_external(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromium_command() {
        let a = chromium_args(
            std::path::Path::new("/p"),
            "--dump-dom",
            std::path::Path::new("/x.html"),
            800,
            2400,
            2.0,
            Some(8090),
        );
        assert!(
            a.contains(&"--headless=new".to_string())
                && a.contains(&"--window-size=800,2400".to_string())
        );
        assert!(
            a.contains(&"--force-device-scale-factor=2".to_string())
                && a.contains(&"--dump-dom".to_string())
        );
        assert_eq!(
            measured_height(r#"<html data-bc-h="3187"><body>"#),
            Some(3187)
        );
        assert_eq!(measured_height("<html><body>"), None);
        assert!(a.contains(&"--proxy-server=127.0.0.1:8090".to_string()));
        // proxy not running: straight to the network, never to whatever holds 8080
        let direct = chromium_args(
            std::path::Path::new("/p"),
            "--dump-dom",
            std::path::Path::new("/x.html"),
            800,
            600,
            1.0,
            None,
        );
        assert!(!direct.iter().any(|x| x.starts_with("--proxy")));
        assert_eq!(direct.last().unwrap(), "file:///x.html");
        assert!(
            a.contains(&"--disable-background-networking".to_string())
                && a.contains(&"--proxy-bypass-list=<-loopback>".to_string())
        );
        assert_eq!(a.last().unwrap(), "file:///x.html");
        assert_eq!(
            page_with_base("<p>", Some("https://a.test/x?y=\"1\"")),
            "<base href=\"https://a.test/x?y=&quot;1&quot;\"><p>"
        );
        // without a browser the request fails cleanly instead of hanging
        unsafe { std::env::set_var("BURPCRAFT_CHROME", "/nonexistent/chrome") };
        let ctx = egui::Context::default();
        let mut shot = chromium_shot(&ctx, "<p>t</p>", None, 640, 1.0, 8192);
        for _ in 0..50 {
            if !matches!(shot, Shot::Pending) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            shot = chromium_shot(&ctx, "<p>t</p>", None, 640, 1.0, 8192);
        }
        assert!(matches!(shot, Shot::Failed(ref m) if m.contains("Failed to start")));
        unsafe { std::env::remove_var("BURPCRAFT_CHROME") };
    }
}
