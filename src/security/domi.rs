//! DOM Invader: a Chromium extension (written to ~/.burpcraft/dom-invader) that runs in the page's
//! own JavaScript world, wraps dangerous sinks and reports when a canary string from the URL reaches
//! one (DOM-based XSS), or when `__proto__[...]` parameters pollute Object.prototype.
//!
//! Reports go two ways: into the page as a `data-bcdi` attribute (read back by the headless scan via
//! `--dump-dom`), and as a POST to a reserved host that the BurpCraft proxy turns into issues while
//! you browse with "Open browser".
use crate::proxy::State;
use crate::security::scanner::{Issue, Severity};

pub const REPORT_HOST: &str = "burpcraft-dom-invader.invalid";
pub const CANARY: &str = "bcdi7q3x";

const MANIFEST: &str = r#"{
  "manifest_version": 3,
  "name": "BurpCraft DOM Invader",
  "version": "1.0",
  "description": "Finds DOM-based XSS sinks and client-side prototype pollution for BurpCraft.",
  "content_scripts": [{"matches": ["<all_urls>"], "js": ["invader.js"], "run_at": "document_start", "world": "MAIN", "all_frames": true}]
}"#;

const SCRIPT: &str = r#"(() => {
  const CANARY = '__CANARY__';
  const found = [];
  const flush = () => {
    try { document.documentElement.setAttribute('data-bcdi', JSON.stringify(found)); } catch (e) {}
  };
  const report = (kind, sink, value) => {
    const f = { kind, sink, value: String(value).slice(0, 300), url: location.href };
    if (found.some(x => x.kind === kind && x.sink === sink)) return;
    found.push(f);
    flush();
    try { navigator.sendBeacon('http://__HOST__/report', JSON.stringify(f)); } catch (e) {}
  };
  const check = (sink, v) => { if (typeof v === 'string' && v.includes(CANARY)) report('dom-xss', sink, v); };
  const wrapSetter = (proto, prop, name) => {
    const d = Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.set) return;
    Object.defineProperty(proto, prop, { ...d, set(v) { check(name, v); return d.set.call(this, v); } });
  };
  const wrapFn = (obj, prop, name, argIndex = 0) => {
    const orig = obj[prop];
    if (typeof orig !== 'function') return;
    obj[prop] = function (...a) { check(name, a[argIndex]); return orig.apply(this, a); };
  };
  wrapSetter(Element.prototype, 'innerHTML', 'element.innerHTML');
  wrapSetter(Element.prototype, 'outerHTML', 'element.outerHTML');
  wrapSetter(HTMLIFrameElement.prototype, 'srcdoc', 'iframe.srcdoc');
  wrapFn(Element.prototype, 'insertAdjacentHTML', 'element.insertAdjacentHTML', 1);
  wrapFn(Document.prototype, 'write', 'document.write');
  wrapFn(Document.prototype, 'writeln', 'document.writeln');
  wrapFn(window, 'eval', 'eval');
  wrapFn(window, 'setTimeout', 'setTimeout');
  wrapFn(window, 'setInterval', 'setInterval');
  wrapFn(Range.prototype, 'createContextualFragment', 'range.createContextualFragment');
  const F = window.Function;
  window.Function = function (...a) { a.forEach(x => check('Function', x)); return F.apply(this, a); };
  window.Function.prototype = F.prototype;
  const setAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (n, v) {
    if (/^(href|src|action|formaction|srcdoc)$/i.test(n) || /^on/i.test(n)) check('element.setAttribute(' + n + ')', v);
    return setAttr.call(this, n, v);
  };
  for (const [proto, prop] of [[HTMLAnchorElement.prototype, 'href'], [HTMLScriptElement.prototype, 'src'], [HTMLIFrameElement.prototype, 'src']]) {
    wrapSetter(proto, prop, proto.constructor.name.replace('HTML', '').replace('Element', '').toLowerCase() + '.' + prop);
  }
  const check_pollution = () => {
    if (({}).bcpp === 'polluted') report('prototype-pollution', 'Object.prototype.bcpp', 'polluted');
  };
  addEventListener('DOMContentLoaded', () => { check_pollution(); flush(); });
  addEventListener('load', () => setTimeout(() => { check_pollution(); flush(); }, 0));
})();"#;

/// Writes the extension (fresh each time, so updates apply) and returns its directory.
pub fn extension_dir() -> std::io::Result<std::path::PathBuf> {
    let dir = crate::http::net::data_dir().join("dom-invader");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("manifest.json"), MANIFEST)?;
    std::fs::write(
        dir.join("invader.js"),
        SCRIPT
            .replace("__CANARY__", CANARY)
            .replace("__HOST__", REPORT_HOST),
    )?;
    Ok(dir)
}

#[derive(Debug, PartialEq, Clone)]
pub struct Finding {
    pub kind: String,
    pub sink: String,
    pub value: String,
    pub url: String,
}

/// Findings in a `data-bcdi` attribute of a dumped DOM, or a report body (one JSON object).
pub fn parse_findings(text: &str) -> Vec<Finding> {
    let json = if let Some(i) = text.find("data-bcdi=\"") {
        let rest = &text[i + 11..];
        crate::http::codec::html_decode(&rest[..rest.find('"').unwrap_or(0)])
    } else {
        text.to_string()
    };
    let field = |j: &crate::openapi::J, k: &str| match j.get(k) {
        Some(crate::openapi::J::Str(s)) => s.clone(),
        _ => String::new(),
    };
    let items = match crate::openapi::parse(json.trim()) {
        Ok(crate::openapi::J::Arr(v)) => v,
        Ok(o @ crate::openapi::J::Obj(_)) => vec![o],
        _ => vec![],
    };
    items
        .iter()
        .map(|j| Finding {
            kind: field(j, "kind"),
            sink: field(j, "sink"),
            value: field(j, "value"),
            url: field(j, "url"),
        })
        .filter(|f| !f.kind.is_empty())
        .collect()
}

/// Adds findings as issues (deduplicated by type, page and sink).
pub fn record(state: &State, found: &[Finding]) -> usize {
    let mut s = state.lock().unwrap();
    let mut added = 0;
    for f in found {
        let Some((t, path)) = crate::scan::parse_url(&f.url) else {
            continue;
        };
        let origin = format!(
            "{}://{}{}",
            if t.tls { "https" } else { "http" },
            t.host,
            if (t.tls && t.port == 443) || (!t.tls && t.port == 80) {
                String::new()
            } else {
                format!(":{}", t.port)
            }
        );
        let path = path.split(['?', '#']).next().unwrap_or("/").to_string();
        let (name, severity, detail, background, remediation) = if f.kind == "prototype-pollution" {
            (
                "Client-side prototype pollution",
                Severity::Medium,
                format!(
                    "Loading {} set Object.prototype.bcpp: the page merges URL input into objects without blocking __proto__.",
                    f.url
                ),
                "Attacker-controlled keys such as __proto__ reach an object merge, polluting every object's prototype; with a suitable gadget this becomes DOM XSS.",
                "Reject __proto__, constructor and prototype keys when parsing input, or use Object.create(null) / Map for parsed data.",
            )
        } else {
            (
                "DOM-based cross-site scripting",
                Severity::High,
                format!(
                    "The canary from the URL reached the sink {}: {}",
                    f.sink, f.value
                ),
                "Client-side JavaScript reads attacker-controlled data (URL, fragment) and passes it to a sink that can execute script, so a crafted link runs code in the victim's session.",
                "Do not pass URL-derived data to HTML or script sinks; use textContent, setAttribute on safe attributes, or sanitize with a trusted library.",
            )
        };
        if s.issues.iter().any(|x| {
            x.name == name && x.origin == origin && x.path == path && x.detail.contains(&f.sink)
        }) {
            continue;
        }
        let id = s.issues.len() + 1;
        s.issues.push(Issue {
            id,
            name,
            severity,
            confidence: "Firm",
            origin,
            path,
            detail,
            background,
            remediation,
            entry_id: 0,
        });
        s.event("DOM Invader", format!("{name} via {}", f.sink));
        added += 1;
    }
    added
}

/// URL variants that put the canary (or a pollution probe) into each source.
pub fn variants(url: &str) -> Vec<String> {
    let (base, frag) = url
        .split_once('#')
        .map(|(b, f)| (b.to_string(), Some(f.to_string())))
        .unwrap_or((url.to_string(), None));
    let (path, query) = base
        .split_once('?')
        .map(|(p, q)| (p.to_string(), q.to_string()))
        .unwrap_or((base.clone(), String::new()));
    let mut out = vec![];
    let params: Vec<&str> = query.split('&').filter(|p| !p.is_empty()).collect();
    for i in 0..params.len() {
        let q: Vec<String> = params
            .iter()
            .enumerate()
            .map(|(j, p)| {
                if i == j {
                    format!("{}={CANARY}", p.split('=').next().unwrap_or(""))
                } else {
                    p.to_string()
                }
            })
            .collect();
        out.push(format!("{path}?{}", q.join("&")));
    }
    let sep = if query.is_empty() { "?" } else { "&" };
    let q = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    out.push(format!("{base}{sep}bcdi={CANARY}"));
    out.push(format!(
        "{path}{q}#{}{CANARY}",
        frag.map(|f| format!("{f}&")).unwrap_or_default()
    ));
    out.push(format!(
        "{base}{sep}__proto__[bcpp]=polluted&constructor[prototype][bcpp]=polluted"
    ));
    out.push(format!("{path}{q}#__proto__[bcpp]=polluted"));
    out
}

/// Loads every variant in headless Chromium with the extension and records what it reports.
/// `proxy`: route through the BurpCraft proxy (false in tests, where none runs).
pub fn scan(url: &str, state: &State, proxy: bool) -> Result<Vec<Finding>, String> {
    let bin = crate::render::chromium_path().ok_or("No Chromium-based browser found (set BURPCRAFT_CHROME); Chrome for Testing or Chromium is needed to load extensions")?;
    let ext = extension_dir().map_err(|e| e.to_string())?;
    let mut all = vec![];
    for (n, v) in variants(url).into_iter().enumerate() {
        let profile =
            std::env::temp_dir().join(format!("burpcraft-domi-{}-{n}", std::process::id()));
        let dom = profile.with_extension("dom");
        let out = std::fs::File::create(&dom).map_err(|e| e.to_string())?;
        let mut args = vec![
            "--headless=new".to_string(),
            "--disable-gpu".into(),
            "--no-first-run".into(),
            "--use-mock-keychain".into(),
            "--disable-background-networking".into(),
            "--disable-features=NetworkTimeServiceQuerying,AimServerEligibility,AimEnabled,AiMode"
                .into(),
            format!("--user-data-dir={}", profile.display()),
            format!("--load-extension={}", ext.display()),
            "--virtual-time-budget=3000".into(),
            "--dump-dom".into(),
        ];
        if proxy {
            let port = state
                .lock()
                .unwrap()
                .listener
                .ok_or("The proxy is not running")?;
            args.extend([
                format!("--proxy-server=127.0.0.1:{port}"),
                "--proxy-bypass-list=<-loopback>".into(),
                "--ignore-certificate-errors".into(),
            ]);
        }
        args.push(v.clone());
        let r = crate::render::run_chromium(
            std::process::Command::new(&bin).args(&args).stdout(out),
            || std::fs::read_to_string(&dom).is_ok_and(|d| d.contains("</html>")),
        );
        let text = std::fs::read_to_string(&dom).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&profile);
        let _ = std::fs::remove_file(&dom);
        r?;
        all.extend(parse_findings(&text));
    }
    record(state, &all);
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};

    #[test]
    fn variants_and_parsing() {
        let v = variants("http://a.test/p?x=1&y=2#frag");
        assert_eq!(v[0], format!("http://a.test/p?x={CANARY}&y=2"));
        assert_eq!(v[2], format!("http://a.test/p?x=1&y=2&bcdi={CANARY}"));
        assert_eq!(v[3], format!("http://a.test/p?x=1&y=2#frag&{CANARY}"));
        assert!(v.iter().any(|u| u.ends_with("#__proto__[bcpp]=polluted")));
        let dom = format!(
            "<html data-bcdi=\"[{{&quot;kind&quot;:&quot;dom-xss&quot;,&quot;sink&quot;:&quot;element.innerHTML&quot;,&quot;value&quot;:&quot;{CANARY}&quot;,&quot;url&quot;:&quot;http://a.test/p?q=1&quot;}}]\"><body></body></html>"
        );
        let f = parse_findings(&dom);
        assert_eq!((f.len(), f[0].sink.as_str()), (1, "element.innerHTML"));
        let state = crate::proxy::Shared::new();
        assert_eq!(record(&state, &f), 1);
        assert_eq!(record(&state, &f), 0);
        assert_eq!(state.lock().unwrap().issues[0].path, "/p");
        assert_eq!(
            parse_findings(
                r#"{"kind":"prototype-pollution","sink":"s","value":"v","url":"http://a/"}"#
            )
            .len(),
            1
        );
    }

    /// Pages with a DOM XSS (query -> innerHTML), a pollution-prone query parser, and a safe one.
    fn app() -> u16 {
        let srv = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = srv.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut c in srv.incoming().flatten() {
                let mut line = String::new();
                let _ = BufReader::new(c.try_clone().unwrap()).read_line(&mut line);
                let body = if line.contains(" /xss") {
                    "<html><body><div id=o></div><script>document.getElementById('o').innerHTML = 'Hi ' + new URLSearchParams(location.search).get('name');</script></body></html>"
                } else if line.contains(" /pp") {
                    // naive deep-merge of `a[b][c]=v` query keys, the classic pollution source
                    "<html><body><script>const o={};for(const [k,v] of new URLSearchParams(location.search)){const p=k.split(/\\[|\\]\\[|\\]/).filter(Boolean);let t=o;p.slice(0,-1).forEach(x=>{t[x]=t[x]||{};t=t[x]});t[p[p.length-1]]=v;}</script></body></html>"
                } else {
                    "<html><body><div id=o></div><script>document.getElementById('o').textContent = new URLSearchParams(location.search).get('name');</script></body></html>"
                };
                let _ = write!(
                    c,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        port
    }

    #[test]
    fn finds_dom_xss_and_pollution_in_headless_chromium() {
        if crate::render::chromium_path()
            .is_none_or(|p| !p.to_string_lossy().contains("for Testing"))
        {
            return; // needs Chrome for Testing / Chromium (branded Chrome ignores --load-extension)
        }
        let port = app();
        let state = crate::proxy::Shared::new();
        let xss = scan(
            &format!("http://127.0.0.1:{port}/xss?name=bob"),
            &state,
            false,
        )
        .unwrap();
        assert!(
            xss.iter()
                .any(|f| f.kind == "dom-xss" && f.sink == "element.innerHTML"),
            "{xss:?}"
        );
        let pp = scan(&format!("http://127.0.0.1:{port}/pp?a=1"), &state, false).unwrap();
        assert!(pp.iter().any(|f| f.kind == "prototype-pollution"), "{pp:?}");
        let safe = scan(
            &format!("http://127.0.0.1:{port}/safe?name=bob"),
            &state,
            false,
        )
        .unwrap();
        assert!(safe.is_empty(), "{safe:?}");
        let names: Vec<&str> = state
            .lock()
            .unwrap()
            .issues
            .iter()
            .map(|i| i.name)
            .collect();
        assert!(
            names.contains(&"DOM-based cross-site scripting")
                && names.contains(&"Client-side prototype pollution")
        );
    }
}
