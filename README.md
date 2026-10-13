# Subskribinto

[![CI](https://github.com/virto-network/subskribinto/actions/workflows/ci.yml/badge.svg)](https://github.com/virto-network/subskribinto/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Interactively (or non-interactively) sign **Kreivo** extrinsics and submit them to a node over **WS/WSS**.  
The tool walks you through four steps:

1. **Endpoint** – choose the WebSocket RPC URL.
2. **Signing Material** – supply a **BIP-39 mnemonic**, a raw **hex seed** (32 bytes) *or* a
   **polkadot{.js} JSON key file**.  
   Optionally add a derivation path like `//soft` or `/polkadot/0`.
3. **Call Data** – paste a hex-encoded, SCALE-encoded call (variant-index + fields).  
   The tool can decode and preview the pallet/variant with metadata.
4. **Sign & Submit** – the extrinsic is signed locally and submitted; the tool follows it until
   finalization and prints the block and the events it emitted.

---

## ✨ Features

* **Interactive wizard** powered by [`inquire`](https://docs.rs/inquire) – prompts only for missing args.
* Fast, script-friendly **CLI options** via [`clap`](https://docs.rs/clap) – skip prompts entirely.
* Supports **`sr25519`** and **`ed25519`** keys (`--scheme`, defaults to `sr25519`) from:
  * *Mnemonic phrase* (`--phrase`)
  * *Raw seed* (`--seed 0x…`): a 32-byte seed, or a 64-byte sr25519 secret key as polkadot{.js}
    stores it
  * *polkadot{.js} key file* (`--key-file account.json`): the JSON exported by the extension,
    apps or `@polkadot/keyring`. The password is asked interactively, and the unlocked key is
    checked against the file's address
  * Optional *derivation path* (`--derive-path "//hard/soft"`, mnemonic only; ed25519 supports
    hard junctions only)
* **Mnemonic checksum validation** with [`bip39`](https://docs.rs/bip39).
* Uses **Subxt 0.42** for submission.
* Decodes and prints the call using the node’s **runtime metadata** (helpful preview).

---

## 🛠 Prerequisites

| Tool           | Version                         | Notes                                    |
|----------------|---------------------------------|------------------------------------------|
| Rust toolchain | recent stable (2024 edition)    | `rustup default stable`                  |
| Node endpoint  | Kreivo, or another Substrate chain | Reached over `ws://` or `wss://`      |

---

## 📦 Installation

From [crates.io](https://crates.io/crates/subskribinto):

```bash
cargo install --locked subskribinto
```

Or the latest `main`:

```bash
cargo install --locked --git https://github.com/virto-network/subskribinto.git
```

---

## 🚀 Quick Start

### Fully interactive

```bash
subskribinto                 # prompts for everything
```

### Non-interactive

```bash
subskribinto --endpoint wss://rpc.polkadot.io   --phrase "conduct stadium suggest ..."   --derive-path "//0"   --call 0x0400ffd1
```

### Mix & match (some prompts)

```bash
subskribinto --endpoint wss://kusama-rpc.polkadot.io --seed 0x1efe…
# will still ask for call-data

subskribinto --endpoint wss://kreivo.io --key-file ./5H6Huzcc….json --call-file call.bin
# asks for the key file password
```

---

## 🤖 Stored accounts and AI assistants (MCP)

Subskribinto can keep accounts in your system keystore (macOS Keychain, Windows Credential Manager,
Secret Service on Linux) and expose them to AI assistants such as Claude through a local
[MCP](https://modelcontextprotocol.io) server, so an assistant can prepare and submit transactions
**without ever seeing a key, and without being able to sign anything you didn't approve**.

Three guards stand between the assistant and a signature:

1. **A policy per account**, stored in the keystore next to the key (so editing files can't loosen
   it). It pins the endpoint and lists the calls the account may sign, with optional caps
   (`max`) and recipient allowlists (`to`). Calls nested in batches or proxies are checked too;
   anything not allowed is rejected before you're asked.
2. **Your approval for every signature**, shown in the MCP client and, on macOS, through Touch ID
   or your account password: something the assistant can't provide. Changing or removing an
   account needs the same approval.
3. **Signing as a restricted proxy** (recommended): store a fresh key, make it a proxy of the
   account that holds funds with `Proxy.add_proxy` and a narrow `ProxyType`, and set `[proxy]` in
   its policy. Every call is then wrapped in `Proxy.proxy`, so even an approved mistake is bounded
   on-chain, and you can revoke the proxy at any time.

### Setting it up

```bash
# 1. Write a policy (see examples/policy.toml), then store the account with it.
subskribinto accounts add ops --key-file ./ops.json --policy ./policy.toml

# 2. Check what's stored. Secrets are never printed.
subskribinto accounts list
subskribinto accounts show ops

# 3. Register the MCP server with Claude Code…
claude mcp add subskribinto -- subskribinto mcp
```

…or with Claude Desktop, in `claude_desktop_config.json` (use the full path to the binary):

```json
{
  "mcpServers": {
    "subskribinto": { "command": "/Users/you/.cargo/bin/subskribinto", "args": ["mcp"] }
  }
}
```

The server offers four tools: `list_accounts`, `encode_call` (build a call from pallet, call and
arguments), `decode_call` (inspect hex call data and check it against the policy), and
`sign_and_submit`.

You can also sign with a stored account yourself, under the same policy and approval:
`subskribinto --account ops --call 0x…`. To change a policy, use
`subskribinto accounts policy ops ./policy.toml`; to delete an account,
`subskribinto accounts remove ops`.

### Platform notes

| Platform | Keystore | Other programs can read the key? | Approval |
|---|---|---|---|
| macOS | Keychain | No: only the `subskribinto` binary that stored it; anything else needs your login password | MCP client prompt, plus Touch ID / account password |
| Linux | Secret Service (GNOME Keyring, KWallet) | Yes, any program running as you, once the keyring is unlocked | MCP client prompt; CLI changes ask in the terminal |
| Windows | Credential Manager | Yes, any program running as you | MCP client prompt; CLI changes ask in the terminal |

**On Linux and Windows, these guards hold against an assistant that only has the MCP tools (such
as Claude Desktop), not against one that can also run commands as you (such as Claude Code with
shell access): it could read the key from the keystore, or imitate a terminal approval.** There,
store only restricted proxy keys, so the chain itself limits what a leaked key can do. If the MCP
client can't ask you (no elicitation support), signing is refused.

On macOS, the Keychain ties each entry to the binary that created it: after reinstalling or
rebuilding `subskribinto`, macOS asks for your login password before it can read stored
accounts again. Approve only binaries you built or installed yourself.

---

## 🔍 What counts as *call data*?

* Raw **SCALE-encoded** bytes of a `pallet::Call` variant.
* First byte(s) = *pallet/variant index*, followed by field SCALE encoding.
* You can copy it from logs (`system.extrinsic`) or generate it with this same crate (conveniently exported as part of the library):

```rust
let call = kreivo::tx().balances().transfer_keep_alive(dest, value);
let bytes = call.encode();
```

---

## 🧩 Project Structure

| Path / Module | Description |
|---------------|-------------|
| `src/main.rs` | CLI entry point, argument parsing, wizard logic |
| `src/tx.rs`   | `sign_and_submit()` implementation (connect, sign, submit, watch) |
| `src/config.rs` | Kreivo's Subxt configuration (transaction extensions) |
| `src/lib.rs`  | The Kreivo API, generated by Subxt from `metadata/kreivo.scale` |
| `src/signer.rs` | `PairSigner`: sr25519 / ed25519 signer for Subxt |
| `src/keyfile.rs` | Decrypting polkadot{.js} JSON key files (scrypt + xsalsa20-poly1305, PKCS#8) |
| `src/store.rs` | Accounts in the system keystore |
| `src/policy.rs`, `src/call.rs` | Policies, and decoding / checking calls (including nested ones) against them |
| `src/guard.rs` | The one path stored accounts sign through: policy, proxy wrapping, approval text |
| `src/presence.rs` | Asking for the user's approval (Touch ID on macOS, terminal elsewhere) |
| `src/mcp.rs`  | The stdio MCP server |
| `src/accounts.rs` | `accounts` subcommands and `--account` signing |
| `examples/policy.toml` | An annotated example policy |
| `fixtures/`   | Throwaway test accounts exported by polkadot{.js} (password `testacct`) |
| `metadata/`   | Kreivo runtime metadata, used at compile time |

---

## ✈️ Cross compilation

Pure Rust all the way down, so the usual Rust targets work. For example, a static Linux binary:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

---

## 🤝 Contributing

Issues and pull requests are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for how to build,
test and propose changes, the [CHANGELOG](CHANGELOG.md) for what changed recently, and
[RELEASING.md](RELEASING.md) for how releases are cut. Everyone taking
part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## 🔒 Security

This tool handles private keys. Please report vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md), never in a public issue.

---

## 📝 License

[MIT](LICENSE) © 2025 Virto Network
