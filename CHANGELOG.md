# Changelog

All notable changes to BurpCraft. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/). Each entry links its pull request.

## [Unreleased]

### Security
- Proxy CA private key is owner-only (`0600`, `~/.burpcraft` `0700`); existing installs are tightened on start (#28).
  On a shared machine, delete `~/.burpcraft/ca.key` + `ca.pem` and reinstall the CA: an older key may have been readable.
- REST API and MCP server refuse requests whose `Host` or `Origin` is not loopback: a web page could start scans
  through the REST API (CSRF) or reach either through DNS rebinding (#30).
- BApp Store verifies each file's SHA-256 from the catalogue before installing or running it, and accepts an
  `https://` store over certificate-verified TLS (#32). **Self-hosted catalogues need a fifth column (sha256).**
- *Explain with Claude* redacts `Authorization`, `Cookie`, `Set-Cookie` and token/key/secret/session header values
  before sending evidence (#35).
- Five panics on hostile input fixed (chunked bodies, WebSocket frame lengths, multipart insertion points, hex and
  HTML decoding), found by the new parser fuzzer (#38).

### Added
- `burpcraft scan`: headless scans for CI with SARIF 2.1.0 / XML / HTML reports and `--fail-on` exit status (#43).
- Docker image for `burpcraft-server` (distroless, unprivileged) (#40).
- Panics are logged with a backtrace to `~/.burpcraft/crash.log` (#34).

### Fixed
- Passive findings were repeated once per audit payload (path-segment payloads make every request a new URL);
  passive checks now run on crawled pages, not on audit payload responses (#42).

### Project
- MIT license (#27); SECURITY.md with private vulnerability reporting, CONTRIBUTING.md, PR template (#29, #36).
- CI: GitHub Actions pinned by commit SHA, `cargo deny` (advisories, licenses, sources) (#31); end-to-end suites on
  Linux (#33); MSRV 1.95 (#37); coverage floor (#44); nightly long fuzz run (#38).
- Tests: parser fuzzing (#38), Decoder round-trip properties (#45), a project-file fixture per release (#39),
  performance baseline (#41).

## [0.1.0] - 2026-11-09

First stable release. Feature list and known gaps: [ROADMAP.md](ROADMAP.md).
