# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `--key-file` to sign with a JSON key file exported by polkadot{.js} (extension, apps or keyring).
- `--scheme sr25519|ed25519` for `--phrase` and `--seed`.
- `--call-data` and `--call-data-file` as aliases of `--call` and `--call-file`.
- Transactions are followed until finalization, printing their block and events.

### Fixed

- 64-byte `--seed` values exported by polkadot{.js} are read in schnorrkel's ed25519 layout. They were
  rejected before, or for some keys silently resolved to a different account.

### Security

- Updated dependencies with published advisories (`anyhow`, `rustls`, `rustls-webpki`, `bytes`, `time`, `rand`,
  `keccak`, `tracing-subscriber`). CI now checks advisories on every pull request.

### Removed

- `jsubskribinto` (the Deno port) and the `pjs_decode` script: the Rust CLI covers both now.

## [0.1.0] - 2025-05-26

### Added

- Interactive and non-interactive signing of Kreivo extrinsics from a mnemonic or a hex seed.

[Unreleased]: https://github.com/virto-network/subskribinto/compare/438f17f...HEAD
[0.1.0]: https://github.com/virto-network/subskribinto/commit/438f17f
