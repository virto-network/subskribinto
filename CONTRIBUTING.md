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
- Add or update tests for behaviour changes, and update the [README](README.md) and
  [CHANGELOG](CHANGELOG.md) (under *Unreleased*) when users would notice the change.
- Write commit messages in the [Conventional Commits](https://www.conventionalcommits.org/) style used in
  the history (`feat:`, `fix:`, `chore:`, `docs:` …).
- Never commit real secrets: mnemonics, seeds, key files or passwords of accounts that hold value.

## Updating the metadata

When Kreivo's runtime changes, refresh the bundled metadata with
[`subxt-cli`](https://crates.io/crates/subxt-cli):

```bash
subxt metadata --url wss://kreivo.io --format bytes > metadata/kreivo.scale
```

## Releasing

Releases are automated with [release-plz](https://release-plz.dev) (`.github/workflows/release.yml`):

1. On every push to `main`, release-plz opens or updates a **release PR** that bumps the version in
   `Cargo.toml` according to the Conventional Commits since the last release.
2. In that PR, move the entries under *Unreleased* in `CHANGELOG.md` to a section for the new version.
3. Merging it publishes the crate to crates.io, tags `vX.Y.Z` and creates a GitHub release. Nothing is
   published from ordinary pushes.

One-time setup, done by a maintainer:

- **First publish by hand**: crates.io only accepts trusted publishing for crates that already exist, so
  publish the first version with `cargo publish` from a clean checkout of `main`.
- **Trusted publishing**: on crates.io, under the crate's *Settings → Trusted Publishing*, add the GitHub
  repository `virto-network/subskribinto` with workflow `release.yml`. No registry token is stored in the
  repository.
- **Optional**: add a `RELEASE_PLZ_TOKEN` secret (GitHub App or fine-grained token with contents and
  pull-requests write access), so CI runs on release PRs. Pull requests opened with the default
  `GITHUB_TOKEN` don't trigger workflows.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
