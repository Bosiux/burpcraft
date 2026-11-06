# Audit — 2026-11-06 — src/

Summary: the code itself is clean (no dead code, no commented-out blocks, no narrating/changelog comments, clippy -D warnings green); the real problems are structural — one flat `src/` with 30 files, several 1000+ line logic files (main.rs 2316, render.rs ~1466, intruder.rs ~1121, mcp.rs ~1008, scan.rs ~1246), and two small duplicate helpers.

| Area | Count | Worst offenders |
|---|---|---|
| Long files (logic, excl. in-file tests) | 22 >300 | main.rs 2316, render.rs ~1466, scan.rs ~1246, intruder.rs ~1121, mcp.rs ~1008, proxy.rs ~1012 |
| Long functions / closures | several | egui UI closures in main.rs (history_table, per-tab panels), render.rs walk(), mcp call() |
| Crowded folders | 1 | src/ — 30 files, no sub-folders |
| Duplicates | 2 | `status_of` (scan.rs:307 + mcp.rs:376); `host_header` (scan.rs:292 + smuggle.rs:18) |
| Comment noise | ~0 | none found (disciplined; `ponytail:` notes are intentional) |
| Dead code | ~0 | only 1 platform-gated `allow(dead_code)` in main.rs:585 (legit) |
| Over-engineering | ~0 | ponytail already applied throughout |

Note: in-file `#[cfg(test)]` modules inflate raw line counts (render.rs 1724→~1466 logic, scan.rs 1509→~1246). Tests staying next to their code is idiomatic Rust, not slop — splits target logic size, and tests move with the code they cover.

## Plan (each item = one small PR, < ~300 lines of real change)
- [ ] 1. `/deslop-dupes` src/ — merge `status_of` and `host_header` into one shared home (proxy.rs / net.rs); both callers use it (~small, deletion)
- [ ] 2. `/deslop-split` src/main.rs — extract per-tab UI panels and `history_table` into `src/ui/` submodules; main.rs keeps bootstrap + App + egui loop (biggest win; do in sub-steps, one tab group per commit)
- [ ] 3. `/deslop-split` src/render.rs — separate CSS/box-model/layout from the egui walk and the Chromium path into a `render/` module
- [ ] 4. `/deslop-split` src/scan.rs — separate insertion points, per-class checks, crawler and OOB into a `scan/` module
- [ ] 5. `/deslop-split` src/mcp.rs + src/intruder.rs — group tool handlers (mcp) and attack-type/payload/results (intruder) into submodules
- [ ] 6. `/deslop-split` remaining >300-line files (proxy, tools, ext, openapi, engage, project, editor, sequencer, net, domi, scanner, collab, target, update, h2up, theme)
- [ ] 7. `/deslop-structure` src/ — group modules by domain: `http/` (net, h2up, codec), `proxy/`, `scan/` (scan, scanner, bcheck, smuggle, collab, domi), `tools/` (repeater, intruder, sequencer, comparer, decoder, editor, target, search, engage), `render/`, `automation/` (mcp, rest, openapi, ext), `project/` (project, report, update, ai), `ui/` (theme, macmenu) — group by group, each commit compiling
