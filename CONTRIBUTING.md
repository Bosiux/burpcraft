# Contributing

Thanks for helping. Only test systems you are authorised to test, including while developing checks.

## Before you start

- Bugs and small fixes: open a PR directly.
- New features or large changes: open an issue first so we agree on the approach. [ROADMAP.md](ROADMAP.md) lists
  what is planned; the direction is depth and accuracy over new surface area.
- Security vulnerabilities: follow [SECURITY.md](SECURITY.md), never a public issue.

## Pull requests

- One change per PR, under ~400 changed lines (lockfiles excluded); split larger work.
- Every behaviour change comes with a test that fails without it.
- CI must be green: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked`, `cargo deny check`. Run the end-to-end scripts from the README *Development*
  section when you touch the proxy or the scanner.
- Fill in the PR template, including the AI-assistance disclosure.
- Visible changes: add a screenshot (`OUT=/path/shot ./shot.sh <MainTab>` renders one).
- Update ROADMAP.md in the same PR when you close or add an item.

## License

By contributing you agree that your contribution is licensed under the [MIT license](LICENSE).
