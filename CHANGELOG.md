# Changelog

All notable changes to this project are documented in this file. See
[CONTRIBUTING.md](./CONTRIBUTING.md#changelog) for how this file is maintained.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.3](https://github.com/virto-network/subskribinto/releases/tag/v0.2.3) - 2026-10-26

### Fixed

- *(mcp)* Reconnect when the chain connection dies or the runtime changes ([#26](https://github.com/virto-network/subskribinto/pull/26))

### Other

- *(deps)* Update crates with new security advisories ([#27](https://github.com/virto-network/subskribinto/pull/27))

## [0.2.2](https://github.com/virto-network/subskribinto/releases/tag/v0.2.2) - 2026-10-13

### Changed

- Updated dependencies: `scrypt` 0.12 ([#15](https://github.com/virto-network/subskribinto/pull/15)), `bip39` 3
  ([#14](https://github.com/virto-network/subskribinto/pull/14)), `inquire` 0.9, which draws the interactive prompts
  ([#13](https://github.com/virto-network/subskribinto/pull/13)), `base64` 0.23
  ([#16](https://github.com/virto-network/subskribinto/pull/16)), and minor and patch updates of `clap`, `tokio`,
  `serde_json`, `schnorrkel`, `scale-value` and `zeroize` ([#12](https://github.com/virto-network/subskribinto/pull/12)).
  Key files, stored accounts and policies work as before.

## [0.2.1](https://github.com/virto-network/subskribinto/releases/tag/v0.2.1) - 2026-10-13

### Added

- Unattended policy rules for signing without approval ([#19](https://github.com/virto-network/subskribinto/pull/19)):
  - `unattended = true` on a rule signs the calls it allows without asking, when every call in the
    transaction (nested ones included) is allowed by an unattended rule. Anything else still needs
    your approval.
  - `call = "*"` allows any other call, only with your approval: one policy can run routine
    operations unattended and keep transfers behind Touch ID.
  - `decode_call` and `encode_call` report whether a call will be signed unattended or needs approval.
  - Every signature made with a stored account is recorded in a local audit log
    (`audit.jsonl` in the local data directory); nothing is signed if it can't be recorded.

### Documentation

- Add a policy reference, `docs/policy.md` ([#17](https://github.com/virto-network/subskribinto/pull/17))

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
