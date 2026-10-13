# Subskribinto

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

| Tool               | Version (tested) | Notes                               |
|--------------------|------------------|-------------------------------------|
| Rust toolchain     | `1.76+`          | `rustup default stable`             |
| Cargo features     | `tokio`, `ws`    | Pulled automatically by `--features`|
| Node endpoint      | Any Substrate-based chain with metadata (Polkadot, Kusama, local dev) |

---

## 📦 Installation

```bash
# 1. Clone
cargo install --git https://github.com/virto-network/subskribinto.git
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
| `src/config.rs` | Chain-specific constants or type aliases (placeholder) |
| `src/signer.rs` | `PairSigner`: sr25519 / ed25519 signer for Subxt |
| `src/keyfile.rs` | Decrypting polkadot{.js} JSON key files (scrypt + xsalsa20-poly1305, PKCS#8) |
| `fixtures/`   | Throwaway test accounts exported by polkadot{.js} (password `testacct`) |
| `metadata/`   | Optional pre-fetched `.scale` metadata blobs |

---

## ✈️ Cross compilation

The binary is **`no-std` friendly** except for `tokio`; to cross-compile:

```bash
rustup target add x86_64-unknown-linux-musl
aarch64-linux-android

# Example (static Linux, musl)
cargo build --release --target x86_64-unknown-linux-musl
```

---

## 📝 License

MIT © 2025 Virto Network
