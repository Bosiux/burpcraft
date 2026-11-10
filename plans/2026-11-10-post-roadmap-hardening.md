# Post-roadmap plan: stable, secure, faster

Date: 2026-11-10 · Baseline: `main` @ 00fe0ea · Status updated 2026-11-10 (see *Progress*) (0.1.0, 26 PRs, ~20.8k lines of Rust, 76 `#[test]`)

Goal: once the ROADMAP power-ups are done, turn BurpCraft from "feature-complete" into a project people can
trust with a CA in their browser trust store. Order: governance → security → stability → performance → features.
Every item is one small PR (< 400 changed lines) with an exit criterion someone else can check.

## Baseline (what is already good, what is missing)

Good: CI on 3 OSes (fmt, clippy `-D warnings`, tests, `cargo audit`, single `CI OK` gate), Dependabot for cargo +
actions, release builds with build-provenance attestations and SHA256SUMS, MCP server checks `Origin`,
update checker notifies only (never installs), scan scope enforced.

Missing / found while reading the code:

| # | Finding | Where | Severity |
|---|---|---|---|
| F1 | No `LICENSE` file: the repo is public but not legally open source (no one may reuse or contribute safely) | repo root | blocker |
| F2 | ~~`main` is not protected~~ — false positive: a `main` ruleset already requires a PR, `CI OK` (strict) and blocks force-push/deletion; the legacy branch-protection API returned 404 | GitHub settings | — |
| F3 | CA private key written with default umask (usually 0644): any local user/process can read the key the user's browser trusts and MITM all their TLS | `src/http/net.rs:356` | high |
| F4 | BApp Store installs executables (`chmod 0755`) with no hash/signature check | `src/ext/store.rs:51` | high |
| F5 | MCP / REST run unauthenticated when no token is given; MCP checks `Origin` but not `Host` (DNS rebinding with no Origin is still possible from non-browser clients; any local process can drive the proxy) | `src/mcp/server.rs`, `src/automation/rest.rs` | medium |
| F6 | No fuzzing of parsers that read attacker-controlled bytes (HTTP/1, chunked, gzip, h2, WebSocket, HTML/CSS, OpenAPI/YAML, BCheck, project file) | — | medium |
| F7 | `e2e.py` / `e2e_scan.py` are not run in CI; ~181 `unwrap/expect` outside tests (panic = dropped connection or crashed UI) | `.github/workflows/ci.yml` | medium |
| F8 | No SECURITY.md, CONTRIBUTING.md, PR template, CHANGELOG, MSRV, benchmarks | repo root | low |

## Phase 0 — Governance (1–2 days, unblocks everything)

- [ ] Add `LICENSE` (decide: Apache-2.0 OR MIT dual license is the Rust norm; GPL-3.0 if forks must stay open). Set `license` in both `Cargo.toml`.
- [ ] `SECURITY.md` + enable GitHub private vulnerability reporting; supported versions = latest minor.
- [ ] `CONTRIBUTING.md` (dev loop from ROADMAP, PR size limit, "only test what you are authorised to test"), `.github/pull_request_template.md` (goal, scope, test plan, AI disclosure, rollback), `CODEOWNERS`.
- [ ] Repository ruleset on `main`: require PR, require `CI OK`, linear history, block force-push and deletion, dismiss stale approvals.
- [ ] Enable secret scanning + push protection, Dependabot security updates.
- [ ] `CHANGELOG.md` (Keep a Changelog), generated from PR titles at release time (`git-cliff`).
- [ ] `rust-version` (MSRV) in `Cargo.toml` + an MSRV CI job.

Exit: `gh api repos/Bosiux/burpcraft/rulesets` shows the rule; OpenSSF Scorecard ≥ 6 on first run.

## Phase 1 — Security hardening

1. **CA key perms (F3)** — write `ca.key` with `0o600` (`OpenOptions::mode` on Unix), fix existing installs on load, `~/.burpcraft` at `0o700`. Test: create CA in a temp dir, assert mode. (S)
2. **BApp integrity (F4)** — catalog carries `sha256` per file; refuse install on mismatch. Next step: ed25519 signature over `catalog.tsv` (`ring` is already a dependency), public key pinned in the app. (S→M)
3. **Local control plane (F5)** — generate a random token when none is given and show it in the UI / log; validate `Host` is `127.0.0.1`/`localhost`; bind loopback only (assert). Test: request with wrong Host / no token → 403. (S)
4. **Fuzzing (F6)** — `cargo-fuzz` targets: HTTP/1 request+response parser, chunked + gzip decode (with size cap), h2 frames, WebSocket frames, BCheck parser, OpenAPI JSON/YAML, project file loader, native HTML/CSS render. Nightly workflow, 5 min per target, corpus cached; crashes become regression tests. (M)
5. **Panic policy (F7)** — `clippy::unwrap_used` / `expect_used` = warn in trust-boundary modules (`http/`, `proxy/`, `mcp/`, `automation/`, `project/`, `ext/`), ratchet to deny module by module; panic hook writes `~/.burpcraft/crash-<ts>.log`. (M, several PRs)
6. **Supply chain** — replace `cargo audit` with `cargo-deny` (advisories + licenses + banned/duplicate crates + allowed sources); pin GitHub Actions by SHA (Dependabot keeps them updated); add OpenSSF Scorecard and CodeQL (Rust) workflows. (S)
7. **Threat model** — one ADR in `docs` branch: assets (CA key, captured credentials, project files, API key), adversaries (hostile target server, malicious web page, local process, malicious BApp/plugin/project file), mitigations mapped to the items above. (S)
8. **Privacy** — AI explainer: preview exactly what is sent, strip `Authorization`/`Cookie` by default. Project files contain credentials: document it, optional encryption later. (S)

Exit: fuzzers run 7 nights with no new crash; Scorecard ≥ 7; `cargo deny check` green; F3–F5 have tests.

## Phase 2 — Stability (tests, releases, compatibility)

- [ ] **e2e in CI (F7)**: run `e2e.py` and `e2e_scan.py --launch` on Linux under `xvfb-run` (or a headless mode, see Phase 4). Requires the e2e scripts to exit non-zero on any FAIL.
- [ ] **Coverage ratchet**: `cargo llvm-cov` in CI, publish the number, fail if it drops > 1 point. Prioritise tests for `http/`, `proxy/`, `scan/ctx.rs`, `project/`.
- [ ] **Property tests** (`proptest`, dev-dependency only): HTTP parse∘serialize round trip, Decoder encode∘decode, chunked framing, Intruder position parsing.
- [ ] **Project-file compatibility**: format version field + golden fixture per release under `tests/fixtures/`; CI opens every older fixture. Breaking the format = migration code or a major bump.
- [ ] **Release train**: SemVer, monthly minor, patch on demand; release checklist (CHANGELOG, fixtures, e2e green, notes). macOS notarization and Windows signing so users are not trained to bypass OS warnings.
- [ ] **Flake budget**: any flaky test is quarantined with an issue within 24 h, never retried silently.

Exit: 3 consecutive releases with no hotfix; e2e PASS table attached to every release.

## Phase 3 — Performance (measure first)

Benchmarks live in-repo and run on PRs with deterministic counters (`gungraun`/iai-callgrind: instruction counts, no runner noise); wall-clock load tests run nightly.

| Scenario | Tool | Target to set after the first measurement |
|---|---|---|
| Proxy throughput / added latency (HTTP, HTTPS MITM, h2) | `oha` through 127.0.0.1:8080 vs direct | p99 overhead |
| Passive scan cost per entry | bench on recorded corpus | µs/entry |
| History with 100k entries: filter, sort, search, frame time | bench + egui frame timing | < 16 ms/frame |
| Project save/load 100k entries | bench | seconds, RSS |
| Peak RAM on large responses | `dhat` | bounded by the message cap |

Likely work items (only after numbers): incremental append-only project log (already in ROADMAP), history index for search, leaf-cert cache bounds, tokio multi-thread runtime for the proxy if one core saturates.

Exit: published baseline table in `docs/`; CI fails on > 10 % instruction-count regression.

## Phase 4 — Features (after the ROADMAP list)

Keep the ROADMAP rule: depth over width. Candidates, in order:
1. **Headless CLI** (`burpcraft scan --target … --report sarif`) — no GUI, exits non-zero on findings; unlocks CI use and e2e in CI. (M)
2. **SARIF report** — findings land in GitHub code scanning. (S)
3. **Docker image** for `burpcraft-server` (Collaborator + BApp Store) with a hardening guide. (S)
4. Remaining ROADMAP big bets (browser crawl, FP confirmation, GraphQL, JWT, WS fuzzing), then HTTP/3 and gRPC/protobuf only if issues ask for them.

New features enter through an issue with acceptance criteria; nothing speculative.

## Working rhythm ("more commits" done right)

The goal is frequent, small, reviewed merges, not commit count: one PR per checklist item, < 400 lines, CI green, a test that fails without the change. Dependabot weekly, release monthly, ROADMAP updated in the same PR that closes an item.

## How someone else verifies this plan worked

- `gh api repos/Bosiux/burpcraft/rulesets`, `LICENSE`, `SECURITY.md` exist.
- OpenSSF Scorecard badge ≥ 7; `cargo deny check` and CI `CI OK` green on `main`.
- `stat -f %Lp ~/.burpcraft/ca.key` → `600` after a fresh start.
- Fuzz workflow history: nightly runs, zero open crash issues.
- Coverage and benchmark numbers in CI logs, trend not decreasing.
- Every release has the e2e PASS table and opens all older project fixtures.

## Progress (2026-11-10)

| Item | PR | State |
|---|---|---|
| F1 license (MIT) | #27 | merged |
| F3 CA key 0600 / dir 0700 | #28 | merged |
| SECURITY.md, CONTRIBUTING.md, PR template | #29, #36 | merged |
| F5 REST/MCP Host + Origin check (REST had none: CSRF-able scans) | #30 | merged |
| Actions pinned by SHA, cargo-deny | #31 | merged |
| F4 BApp SHA-256 + https store | #32 | merged |
| Crash log (panic hook) | #34 | merged |
| AI explainer redacts credentials | #35 | merged |
| e2e suites in CI (Linux, xvfb) | #33 | queued |
| MSRV 1.95 + CI job | #37 | queued |
| Parser fuzzing; 5 panics on hostile input fixed (dechunk, ws_frames, multipart points, hex/html decode) | #38 | queued |
| Project-file fixture per release | #39 | queued |
| Docker image for burpcraft-server | #40 | queued |
| Performance baseline test | #41 | queued |
| Repo settings: private vulnerability reporting, secret scanning + push protection, Dependabot alerts + security fixes, auto-merge | — | done |

Still open: mandatory REST/MCP tokens (breaking: needs a decision), `unwrap` reduction in trust-boundary modules,
coverage ratchet, threat-model ADR, CHANGELOG, macOS notarization / Windows signing (need signing secrets),
headless CLI + SARIF, publishing the Docker image, remaining ROADMAP big bets.

## Performance baseline (Apple Silicon, release, `cargo test --release perf -- --ignored --nocapture`)

| Scenario | Result |
|---|---|
| proxy, 1 client | 59 µs direct → 193 µs proxied (+134 µs), 5 191 req/s |
| proxy, 8 clients | 210 µs → 702 µs, 11 404 req/s |
| passive scan | 4.3 µs/entry |
| project, 100k entries | encode 6 ms, decode 24 ms, 57.2 MB before gzip |
