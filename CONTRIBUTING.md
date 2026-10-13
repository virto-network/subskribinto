# Contributing to Subskribinto

Thanks for taking the time to contribute! Bug reports, fixes, docs and new features are all welcome.

## Before you start

- **Bugs and features**: open an [issue](https://github.com/virto-network/subskribinto/issues/new/choose) first
  for anything bigger than a small fix, so we can agree on the approach before you write the code.
- **Security issues**: please don't open a public issue. Follow [SECURITY.md](SECURITY.md) instead.
- By participating you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

You need a recent stable Rust toolchain (the crate uses the 2024 edition):

```bash
rustup toolchain install stable --component rustfmt clippy
git clone https://github.com/virto-network/subskribinto.git
cd subskribinto
cargo build
```

The first build takes a while: Subxt generates the Kreivo API from `metadata/kreivo.scale` at compile time.

## Checks

CI runs the following on every pull request; please run them locally before pushing:

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo deny check advisories   # needs `cargo install cargo-deny`
scripts/license-headers.sh    # every .rs file starts with the license header
```

New Rust files need the license header below; `scripts/license-headers.sh --fix` adds it for you.

```rust
// Copyright (c) Virto Network
// SPDX-License-Identifier: MIT
```

Tests must not need a network connection or touch real keys. Use the throwaway accounts in
[`fixtures/`](fixtures) (password `testacct`) or generate fresh ones.

## Pull requests

- Keep each pull request focused on one change, and describe *why* it is needed, not only what it does.
- Add or update tests for behaviour changes, and update the [README](README.md) when users would
  notice the change.
- **Title the pull request in the [Conventional Commits](https://www.conventionalcommits.org/) style**
  (see below). CI checks it.
- Never commit real secrets: mnemonics, seeds, key files or passwords of accounts that hold value.

### Pull request titles

Pull requests are squash-merged, so **the PR title becomes the commit on `main`, the line in the
changelog and the input to the next version bump.**

| Title | Next release | Changelog section |
| --- | --- | --- |
| `feat!: rename --call-file to --call-data-file` | **breaking** | ⚠ Breaking changes |
| `feat(mcp): add a tool to list pending requests` | feature | Added |
| `fix(keyfile): accept hex-encoded key files` | patch | Fixed |
| `perf(...)`, `refactor(...)`, `docs(...)`, `chore(...)` | patch | Performance / Changed / Documentation / Other |
| `test(...)`, `ci(...)`, `style(...)` | patch | *(not listed)* |

The description is imperative and lowercase, and reads well as a changelog entry. `!` marks a
breaking change: a removed or renamed flag or subcommand, or an incompatible policy or keystore
format. Explain in the PR description what users have to do.

## Updating the metadata

When Kreivo's runtime changes, refresh the bundled metadata with
[`subxt-cli`](https://crates.io/crates/subxt-cli):

```bash
subxt metadata --url wss://kreivo.io --format bytes > metadata/kreivo.scale
```

## Changelog

`CHANGELOG.md` has one section per release and is written by the release workflow, from the
titles of the pull requests merged since the last release, so you **don't edit it in feature PRs**.
A maintainer curates each section before releasing; see [RELEASING.md](RELEASING.md).

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
