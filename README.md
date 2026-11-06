<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/banner-dark.svg">
    <img alt="BurpCraft: web security testing, built in pure Rust" src="docs/brand/banner-light.svg" width="100%">
  </picture>
</p>

<p align="center">
  <b>An open-source intercepting proxy, scanner and attack toolkit for web security testing, built in pure Rust.</b>
</p>

<p align="center">
  <a href="https://github.com/Bosiux/burpcraft/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Bosiux/burpcraft/ci.yml?branch=main&style=flat-square&label=CI"></a>
  <a href="https://github.com/Bosiux/burpcraft/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/Bosiux/burpcraft?include_prereleases&sort=semver&style=flat-square&color=e8590c"></a>
  <img alt="Status: early development" src="https://img.shields.io/badge/status-early%20development-f26b1d?style=flat-square">
  <img alt="Written in Rust" src="https://img.shields.io/badge/written%20in-Rust-b7410e?style=flat-square&logo=rust&logoColor=white">
  <img alt="Runs on macOS, Windows and Linux" src="https://img.shields.io/badge/runs%20on-macOS%20%C2%B7%20Windows%20%C2%B7%20Linux-e8590c?style=flat-square">
  <img alt="Self-hosted Collaborator" src="https://img.shields.io/badge/collaborator-self--hosted-d9480f?style=flat-square">
  <img alt="REST API" src="https://img.shields.io/badge/REST%20API-v0.1-ff8a3d?style=flat-square">
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#how-it-fits-together">How it fits together</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#self-hosting-the-collaborator-and-bapp-store">Collaborator</a> ·
  <a href="#rest-api">REST API</a> ·
  <a href="#mcp-server-ai-agents">MCP</a> ·
  <a href="#releases">Releases</a>
</p>

<p align="center">
  Intercept and edit HTTP/1.1, HTTP/2 and WebSocket traffic, replay it in Repeater, automate attacks in Intruder,
  crawl and actively scan targets, catch blind bugs with a self-hosted Collaborator, and drive scans from CI
  through a REST API. Native egui + wgpu desktop app; extensions in any language.
</p>

<p align="center">
  <img src="docs/screenshots/proxy-history.png" width="92%" alt="BurpCraft Proxy HTTP history: three captured requests, the selected one shown as a highlighted request and response">
  <br><sub>Proxy → HTTP history, with live traffic through the local CA</sub>
</p>

> [!IMPORTANT]
> BurpCraft is an independent project built from the observable behaviour of Burp Suite. It is not affiliated with,
> endorsed by, or using any code or assets of PortSwigger. Use it only against systems you are authorized to test.

## Features

| Area | What you get |
|---|---|
| **Proxy** | HTTPS MITM with a local CA, intercept (requests and responses), match and replace, HTTP history with filters, WebSockets history, HTTP/2 upstream |
| **Repeater / Intruder** | Tabs, HTTP/1 ↔ HTTP/2, § positions, four attack types, 7 payload types, payload processing rules, Grep match / extract / payloads |
| **Scanner** | Passive checks on all traffic; active crawl and audit (SQLi, XSS, path traversal, SSTI, open redirect, header and command injection, SSRF via Collaborator); OpenAPI/Swagger import; authenticated scans; scheduled and live tasks |
| **DOM Invader** | Browser extension that tracks a canary into DOM sinks and probes prototype pollution, headless or while you browse |
| **Collaborator** | `burpcraft-server`: DNS, HTTP and SMTP interaction capture with a polling API, or a built-in local server for testing |
| **Extensions** | Out-of-process plugins in any language (JSON lines over stdin/stdout), BChecks, and a BApp Store served by your own server |
| **More** | Target site map and scope, Decoder, Comparer, Sequencer, Logger, Organizer, engagement tools, global search, HTML/XML reports, project files, Chromium page rendering, an opt-in AI explainer |

## How it fits together

```mermaid
flowchart LR
  B([Browser]) -->|127.0.0.1:8080| P[Proxy<br/>intercept · history · rewrite]
  P <-->|HTTP/1.1 · HTTP/2 · WS| T[(Target)]
  P --> R[Repeater] & I[Intruder] & S[Scanner]
  R & I & S --> T
  S -. OAST payloads .-> C{{burpcraft-server<br/>Collaborator}}
  T -. DNS / HTTP / SMTP .-> C
  CI([CI pipeline]) -->|REST API :1337| S
```

## Quick start

```sh
cargo run --release                     # starts the app; the proxy listens on 127.0.0.1:8080
BURPCRAFT_PROXY=8090 cargo run --release   # another proxy port
cargo run --release -- my.burpcraft     # open or create a project file
BURPCRAFT_API=1337 cargo run --release  # also start the REST API on 127.0.0.1:1337
```

Point your browser at `127.0.0.1:8080` and trust `~/.burpcraft/ca.pem`, or use **Proxy → Intercept → Open browser**.

## Self-hosting the Collaborator and BApp Store

```sh
cargo run -p burpcraft-server -- --http 8053                    # local, path-based payloads
cargo run -p burpcraft-server -- --domain oast.example.com --public-ip 203.0.113.7 \
  --bind 0.0.0.0 --dns 53 --http 80 --smtp 25 --secret s3cret --bapps server/bapps
```

Then set the server in the **Collaborator** tab (or click **Start built-in server**).

## REST API

```sh
curl -i -X POST -d '{"urls":["http://target.example/"]}' http://127.0.0.1:1337/v0.1/scan   # 201, Location: 1
curl http://127.0.0.1:1337/v0.1/scan/1                                                     # status and issues
```

## MCP server (AI agents)

Agents drive the running app over [MCP](https://modelcontextprotocol.io): read traffic, send and fuzz requests,
intercept and edit live (MITM), change rules and scope, scan, use the Collaborator. In-process, localhost only, <1 ms per call.

```sh
BURPCRAFT_MCP=1338 cargo run --release          # or BurpCraft menu → Start MCP server; 1338:<token> requires a bearer token
claude mcp add --transport http burpcraft http://127.0.0.1:1338/mcp   # + --header "Authorization: Bearer <token>"
```

| Tool | Does |
|---|---|
| `status` | listener, intercept state, counts, CA path |
| `history_list` / `history_get` | proxy or logger items: filter (host, method, status, regex, `after_id`), full request/response |
| `ws_list` | WebSocket messages |
| `send` | raw HTTP/1.1 or HTTP/2 request → response (Repeater) |
| `intruder` | `§`-marked attack: sniper, battering_ram, pitchfork, cluster_bomb; grep per response; `anomalies` returns only the odd rows |
| `intercept` · `intercept_queue` · `intercept_forward` · `intercept_drop` | MITM: hold, read, edit-and-forward or drop live requests/responses |
| `rules` · `scope` | match-and-replace rules, target scope (get, or replace with `set`) |
| `scan_start` · `scan_status` · `issues` | active scan of URLs or one request, progress, findings |
| `collaborator` | built-in or remote OAST server, payloads, interactions |
| `codec` | base64 / url / html / hex, md5 / sha* |
| `open_in` · `events` | show an item in a UI tool for the human, app event log |

Messages are plain HTTP text (`\n` is fine: CRLF and `Content-Length` are fixed for you). Each tool's own description is the reference.

## Development

```sh
cargo test --workspace     # unit and local end-to-end tests (vulnerable test apps, headless Chromium)
python3 e2e.py             # proxy end-to-end checks against local HTTP and WebSocket servers
```

See [ROADMAP.md](ROADMAP.md) for what is done and what is not covered yet.

## Releases

Downloads for macOS (universal `.dmg`), Windows (`.zip`) and Linux x86_64/aarch64 (`.tar.gz`) are on the
[Releases](../../releases) page, with `SHA256SUMS.txt` and build provenance (`gh attestation verify <file> -R Bosiux/burpcraft`).

Once a day at startup the app asks the GitHub Releases API whether a newer version exists and shows a popup; it
never downloads or installs anything and sends nothing beyond that request. Beta builds also see betas. Turn it off in
*Settings → User interface → Updates*, or set `BURPCRAFT_NO_UPDATE_CHECK=1`.

- **Stable**: bump `version` in `Cargo.toml`, merge to `main`, then `git tag vX.Y.Z && git push origin vX.Y.Z`.
- **Beta**: *Actions → Release → Run workflow* on any branch publishes `vX.Y.Z-beta.N` as a pre-release (never `latest`).

---

<p align="center">
  <img src="docs/brand/logo.svg" width="48" height="48" alt="">
  <br>
  <sub>Built in Rust, for people who read raw HTTP for fun. Test only what you are allowed to test.</sub>
</p>
