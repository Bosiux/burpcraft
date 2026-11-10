# ADR 0001: Threat model

Date: 2026-11-10 · Status: accepted · Scope: `burpcraft` desktop app and `burpcraft-server`

## Context

BurpCraft is an intercepting proxy: the user installs its CA as a trusted root, routes their browser through it and
points it at systems that may be hostile. That makes the tool itself a high-value target. This ADR fixes what we
protect, from whom, and which control covers each path, so new features can be checked against it.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| CA private key | `~/.burpcraft/ca.key` | trusted by the user's browser for **every** site: whoever reads it can MITM all their TLS |
| Captured traffic | memory, project files, `~/.burpcraft` | credentials, sessions and data of systems the tester was trusted with |
| API keys | `ANTHROPIC_API_KEY` / in-memory, REST/MCP tokens | spend and control |
| Execution on the tester's machine | BApps, plugins, BChecks, Chromium | full compromise |
| Scan reach | scanner, Intruder, REST/MCP | an attacker steering scans attacks third parties from the tester's IP |

## Adversaries and entry points

| Adversary | Entry point | Controls |
|---|---|---|
| **Hostile target server / WebSocket peer** | every byte of responses and frames: HTTP/1 framing, chunked, gzip, h2, WS, HTML/CSS render, passive checks | message size cap (#22); parsers fuzzed in every `cargo test` and nightly (#38) — five panics fixed; native renderer has no JS; Chromium render runs headless, sandboxed, one profile per render |
| **Malicious web page in the tester's browser** | `127.0.0.1` REST (1337) and MCP (1338): CSRF with CORS-simple requests, DNS rebinding | `Host` and `Origin` must be loopback (#30); servers bind 127.0.0.1 only; optional tokens |
| **Other local user / process** | `~/.burpcraft` files; unauthenticated REST/MCP | CA key `0600`, folder `0700` (#28), crash log `0600` (#34); **open:** tokens are opt-in, so any local process can drive REST/MCP |
| **On-path attacker / compromised store** | BApp Store download, update check, Anthropic API | BApp SHA-256 per file + `https://` store over verified TLS (#32); update check is notify-only over verified TLS; Anthropic API over verified TLS |
| **Malicious BApp, plugin or BCheck author** | out-of-process plugins run with the user's privileges | explicit install only, hash-checked; **accepted risk:** no sandbox — documented, same model as Burp extensions |
| **Malicious project file** (shared by a colleague) | `project::decode` | length-checked reader, counts bounded by remaining bytes, fuzzed (#38); decoding never executes content |
| **Supply chain** | crates, GitHub Actions, release pipeline | `cargo deny` (advisories, licenses, sources), `--locked` builds, Actions pinned by SHA (#31), build provenance attestations + SHA256SUMS on releases, Dependabot |
| **Data leaving to third parties** | AI explainer | opt-in per click; `Authorization`/`Cookie`/token headers redacted (#35); bodies sent as captured (stated in the UI) |
| **Tester error** | scanning out-of-scope hosts | Target scope enforced on every scan request and on REST/MCP scan starts (#20) |

## Decisions

1. Parsers of untrusted bytes must not panic: new parsers get a target in `src/fuzz.rs`.
2. Anything that executes downloaded code verifies its integrity first.
3. Local control surfaces assume a hostile browser on the same machine (Host/Origin), and should assume a hostile
   local process once tokens become mandatory (open decision: breaking for existing MCP client configs).
4. Files holding secrets or captured data are owner-only.
5. Nothing leaves the machine without an explicit user action, and credentials are redacted when it does.

## Open items

- Mandatory random REST/MCP token (shown in the UI) — breaking change, needs a decision.
- Plugin sandboxing (OS-level) — large; accepted risk for now.
- Project-file encryption at rest — optional, for shared machines.
- Publisher signatures for BApp catalogues (ed25519, pinned key) if stores are shared between teams.
