# BurpCraft roadmap

A Rust (eframe/egui + wgpu) recreation of the observable features and look of Burp Suite.
Built only from observable behaviour, no reverse engineering. Own name, no original logos/assets.

Workspace: the app plus `server/` (`burpcraft-server`, self-hosted Collaborator + BApp Store, std only).
Dev loop: `cargo test --workspace`, `python3 e2e.py` (local HTTP + WebSocket servers through the running proxy), `python3 e2e_scan.py --launch target/debug/burpcraft` (vulnerable local app with safe twins; scanner, OpenAPI, auth, passive, Intruder, Collaborator, send and intercept over REST/MCP; PASS/FAIL table), then `OUT=/path/shot ./shot.sh <MainTab> [ProxyTab]` to render a screen
into `<OUT>.png` with sample traffic (uses the BURPCRAFT_SHOT / BURPCRAFT_TAB dev hooks).

## Done (iteration 1)
- [x] Window, menu bar, 13 main tabs, orange light theme, flagged-tab highlight
- [x] Proxy listener 127.0.0.1:8080, HTTP + HTTPS MITM (CA in ~/.burpcraft/ca.pem)
- [x] Intercept: Forward / Drop / toggle / Action / Open browser (system Chromium with proxy)
- [x] HTTP history: full column set, filter toggle, search, context menu (Repeater, Decoder, Comparer, highlight, comment, delete, clear)
- [x] Message editor: Pretty (highlighted) / Raw / Hex, Inspector panel
- [x] Repeater: numbered tabs, Send/Cancel/</>, target dialog, Content-Length fix, timing
- [x] Decoder: chained panes, decode/encode/hash, smart decode
- [x] Comparer: item lists, word/byte diff window
- [x] Logger: all tools' traffic
- [x] Dashboard: Tasks, Issue activity, Event log, Advisory

## Done (iterations 2-3)
- [x] Target: Site map tree + contents table, Scope include/exclude, Add to scope
- [x] Intruder: § positions (Add/Clear/Auto), Sniper / Battering ram / Pitchfork / Cluster bomb, Simple list + Numbers payloads, built-in lists, URL-encoding, resource pool, sortable results window
- [x] Sequencer: live capture (cookie or delimiters), manual load, summary / character / bit-level analysis
- [x] Proxy: regex Match and replace (with defaults), response interception, WebSockets relay + history, gzip/deflate/chunked unpacking in viewers
- [x] Editor: JSON pretty print, Render tab (text), § highlighting
- [x] HTTP history: sortable columns, full Filter settings dialog, Copy as curl command, Send to Sequencer/Organizer
- [x] Organizer (status + notes), Collaborator (no server), Extensions, Learn
- [x] Settings window: light/dark theme, font size, hotkeys (Ctrl+R/I/T/F/Space, Ctrl+Shift+D/T/P/I/R)
- [x] Decoder: Gzip encode/decode, MD5
- [x] Plain-vs-TLS sniffing after CONNECT; WebSocket relay verified end-to-end (e2e.py)
- [x] Shared Request|Response split pane (aligned headers)

- [x] Intercept rules (skip static extensions, domain filter), Comparer Load from file, local-server send test

- [x] HTTP/2 upstream (ALPN h2 with HTTP/1.1 fallback), HTTP/2 shown in history, Repeater HTTP/1 <-> HTTP/2 switch, "Default to HTTP/2" setting; tested with a local h2 server
- [x] Render: native egui HTML layout (html5ever parse; headings, paragraphs, links, lists, tables, inline form controls, pre/code, inline colours), "Show response in browser"
- [x] Render: <style> stylesheets via real CSS selector matching (later rules win), images from data: URIs and from images already captured by the proxy
- [x] Passive scanner (Pro-style): checks every proxied response (cookie flags, HSTS, framing, CSP, cleartext password forms, MIME sniffing, version headers, permissive CORS, emails); Dashboard Issue activity + Advisory with own wording
- [x] Render engine selector: Chromium headless (full CSS, JavaScript via V8, images; sub-resources through the proxy, <base> = page URL) with native egui fallback; BURPCRAFT_CHROME overrides the browser path
- [x] Fix: passive scanner panicked on binary bodies (char boundary in email finder)
- [x] Chromium render verified on macOS with Chrome for Testing 157 (CSS flex/grid, JS, image sub-resource via the proxy). Fixes: Chrome for Testing searched first (Brave 156 hangs headless), loopback targets forced through the proxy (`<-loopback>`), Chrome's own update/time/AI-Mode traffic kept out of the history, one profile per render (shared profile -> exit 21), stale PNG from a previous run no longer reused
- [x] Chromium render: full-page capture (measure pass with --dump-dom, then screenshot at that height, capped at the GPU texture limit) and HiDPI-sharp at full pane width (device scale factor = pixels per point)
- [x] Native render: box model (background, padding, margin, border, radius), display:flex rows and display:grid columns, full content inside table cells (images, links, form controls, nested tables)

## Not covered (larger efforts, decide before starting)
- [ ] Native fallback render: no JavaScript (needs a JS engine + DOM; the Chromium engine covers it), no floats/positioning, flex/grid are equal-width columns only
- [ ] Scanner: no stored XSS, DOM checks only via DOM Invader, no HTTP request smuggling / deserialization / XXE checks
- [ ] BChecks: subset of the original syntax (no loops, variables, `run for each`)
- [ ] BurpCraft AI: a live answer was not exercised on the dev machine (no Anthropic API key there)
- [ ] Project files are written on save/exit, not continuously like a disk-based project
- [ ] Scanner: crawler/audit responses are not passively scanned (only proxied traffic is); header insertion points are only User-Agent and Referer
- [ ] Scanner: Target scope is not applied (a scan stays on the origins it is given; the crawler is same-origin); delay/rate limit only in the New scan dialog, not over REST/MCP
- [ ] REST API `/v0.1/scan`: no API definition, authentication, threads or delay fields (MCP `scan_start` has openapi/headers/login)
- [ ] HTTP client buffers whole bodies in memory (no size cap on a real multi-GB response)

## Done (iteration 4): Pro features
Everything in the table below is implemented; see the per-row notes. Self-hosting:
`cargo run -p burpcraft-server -- --domain oast.example.com --public-ip <ip> --bind 0.0.0.0 --dns 53 --http 80 --smtp 25 --secret <s> --bapps server/bapps`
(local testing: `--http 8053`, or "Start built-in server" in the Collaborator tab). REST API: `BURPCRAFT_API=1337 burpcraft`.

## Pro features (vs Community), by infrastructure need
From PortSwigger's public docs, recalled 2026-11-04 (not re-checked; the edition split changes over time).
Status: ✅ done · 🟡 partial · ❌ missing

### Needs an external server
| Feature | What it does | BurpCraft |
|---|---|---|
| Burp Collaborator | Public server (DNS, HTTP/S, SMTP) on its own domain that receives out-of-band interactions from the target; finds blind SSRF/SQLi/XXE, DNS injection. Can be self-hosted | ✅ `server/` crate `burpcraft-server` (DNS/HTTP/SMTP + poll API, std only); Collaborator tab: configure, built-in local server, payloads, background polling, interactions |
| Collaborator payloads in Intruder/Scanner | Inserts unique Collaborator addresses and links each interaction to the request that caused it | ✅ Intruder "Collaborator payloads" type; scanner OOB checks (SSRF, blind command injection) |
| Burp AI | AI-assisted explanations/testing on PortSwigger's servers (credits) | ✅ "Explain with Claude" in the issue advisory: Anthropic Messages API (claude-opus-5-5, server-side refusal fallback), opt-in per click, own key (ANTHROPIC_API_KEY or in-memory), certificate-verified TLS. Live answer not exercised here (no key on the dev machine); request shape, parsing and a real 401 round trip are tested |
| BApp Store | Download/update extensions from a remote catalogue (some Pro-only) | ✅ served by `burpcraft-server --bapps DIR` (catalog.tsv + files, example BApps in server/bapps); Extensions → BApp Store installs and loads |

### Local only (no server)
| Feature | What it does | BurpCraft |
|---|---|---|
| Passive scanner | Analyses proxied traffic without sending anything | ✅ |
| Active scanner | Sends attack payloads to parameters: SQLi (error/boolean/time), reflected & stored XSS, path traversal, command injection, header injection, open redirect... | ✅ query/body/cookie/JSON/header points; SQLi error/boolean/time, reflected XSS, path traversal, SSTI, open redirect, header injection, command injection (time/OOB), SSRF (OOB). No stored XSS yet |
| Crawler | Explores the site following links and forms, fills the site map | ✅ BFS, same origin, GET/POST forms, static files skipped |
| Scan configurations | Fast/thorough profiles, chosen checks, rate limits | ✅ New scan dialog: Fast/Thorough, per-check toggles, pages, threads, delay |
| Live tasks | Automatic audit (passive or active) of traffic as it passes the proxy | ✅ passive always; "New live task" = active audit of in-scope proxied requests |
| BChecks | Custom scan checks in a small declarative language | ✅ subset of the syntax: given response/host/insertion point, send payload/request, matches/in/is with and/or/not; editor in Extensions → BChecks |
| API-definition scanning | Import OpenAPI/Swagger and scan the endpoints | ✅ OpenAPI 3 / Swagger 2, JSON or YAML |
| Authenticated scanning | Recorded login or credentials used during crawl/audit | ✅ extra headers + raw login request whose cookies join every request |
| Reports | Export issues as HTML/XML | ✅ Dashboard "Report (HTML)" / "Export (XML)", with request/response evidence, in ~/.burpcraft/reports |
| Project files | Save/reopen all state on disk: history, site map, Repeater, issues, settings | ✅ Project menu Open/Save/Save as, Ctrl+S, `burpcraft <file>`, saved on exit (gzip, own format) |
| Unthrottled Intruder | Community is throttled; Pro adds payload processing, grep match/extract, more payload types | ✅ unthrottled; runtime file, brute forcer, null, character blocks; 11 processing rules; Grep match/extract/payloads columns |
| Global search | Text/regex search across all tools | ✅ Search menu / Ctrl+Shift+F: history, Logger, WebSockets, Repeater, issues; click jumps to the item |
| Engagement tools | Target analyzer, content discovery (file/dir brute force), find comments/scripts/references, CSRF PoC generator, simulate manual testing | ✅ history context menu: analyze, discover content (soft-404 aware), comments, scripts, references, CSRF PoC (form/GET/text-plain). Skipped "simulate manual testing" (fake traffic only) |
| Scheduled tasks | Start/pause scans and tasks at set times | ✅ New scan → Schedule: start at HH:MM, repeat every N hours |
| REST API | HTTP API on localhost to start scans and read results from scripts/CI | ✅ /v0.1/scan, /v0.1/scan/<id>, /v0.1/issues; BurpCraft menu or BURPCRAFT_API=port[:key] |
| MCP server | (no Burp equivalent) AI agents control the app over MCP | ✅ in-process Streamable HTTP on 127.0.0.1 (BurpCraft menu or BURPCRAFT_MCP=port[:token]): history, logger, WebSockets, send, Intruder, intercept queue (forward/edit/drop), match-and-replace, scope, scans, issues, Collaborator, Decoder, open in UI tools |
| DOM Invader | Embedded-browser extension finding DOM XSS and prototype pollution | ✅ MV3 extension (main world, sink hooks + canary, __proto__ probes) loaded into "Open browser"; history context menu "DOM Invader scan" runs URL variants in headless Chrome for Testing; verified on Chrome 157 |
| Extension API | Third-party plugins (Burp: Java, Montoya API); extension management exists in Community too, Pro adds scanner hooks and some BApps | ✅ out-of-process plugins in any language, JSON lines on stdin/stdout: request rewrite hook, response hook, issues, log |

Note: the active scanner is local, but without Collaborator it misses blind vulnerabilities.
