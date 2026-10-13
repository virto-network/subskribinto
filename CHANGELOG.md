# Changelog

All notable changes to this project are documented in this file. See
[CONTRIBUTING.md](./CONTRIBUTING.md#changelog) for how this file is maintained.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/virto-network/subskribinto/releases/tag/v0.2.0)

The first release published to crates.io (`cargo install subskribinto`).

### Added

- Stored accounts in the system keystore (`subskribinto accounts add|list|show|policy|remove`), each with a
  policy that pins its endpoint, lists the calls it may sign (with caps and recipient allowlists, checked
  through nested calls) and can sign as a proxy of another account.
- `subskribinto mcp`: a stdio MCP server that lets AI assistants list stored accounts, build and inspect calls,
  and submit them after the policy allows them and the user approves (MCP elicitation, plus Touch ID or the
  account password on macOS).
- `--account <name>` to sign with a stored account from the command line, under the same policy and approval.
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

## [0.1.0](https://github.com/virto-network/subskribinto/commit/438f17f) - 2025-05-26

Not published.

### Added

- Interactive and non-interactive signing of Kreivo extrinsics from a mnemonic or a hex seed.
