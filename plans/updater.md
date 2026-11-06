# Updater

Release pipeline today: `release.yml` publishes `.dmg` / `.zip` / `.tar.gz`, `SHA256SUMS.txt` and build provenance.
Stable tags are `vX.Y.Z` (marked latest), betas `vX.Y.Z-beta.N` (pre-release).

## Principles

- Notify first; installing is optional and later.
- Trust a signing key, not GitHub alone: HTTPS + SHA256SUMS does not survive a compromised account or workflow.
- Opt-out, at most one request a day, nothing sent beyond the GET, silent when offline.
- Channel: stable sees stable; beta sees beta and newer stable; never downgrade.
- Never self-replace an install the app doesn't own (package manager, read-only path).

## Phases

1. **Notify** (PR #8): GitHub Releases API at startup, corner popup with Release notes / Skip / Later, Settings toggle,
   `BURPCRAFT_NO_UPDATE_CHECK`.
2. **Signed manifest**: CI signs `SHA256SUMS.txt` with Ed25519 (`UPDATE_SIGNING_KEY` secret); the app embeds the
   public key and verifies with `ring`.
3. **In-app install** (only if asked for): raw per-platform binaries as release assets; download, check against the
   signed manifest, atomic replace (rename on Linux, `.old` swap on Windows, re-sign the `.app` on macOS), restart on
   user action, keep the previous binary for rollback.

## Rejected for now

- `self_update` / `axoupdater` (cargo-dist) / Velopack: new dependency trees or a replacement release pipeline.
- Static `latest.json` on `releases/latest`: excludes pre-releases, so no beta channel.

Package managers (Homebrew cask, winget, Scoop) cover auto-update with less code and risk than phase 3.
