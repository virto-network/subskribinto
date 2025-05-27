# Subskribinto

Interactively (or non-interactively) sign **Kreivo** extrinsics and submit them to a node over **WS/WSS**.  
The tool walks you through four steps:

1. **Endpoint** – choose the WebSocket RPC URL.
2. **Signing Material** – supply a **BIP-39 mnemonic** *or* a raw **hex seed** (32 bytes).  
   Optionally add a derivation path like `//soft` or `/polkadot/0`.
3. **Call Data** – paste a hex-encoded, SCALE-encoded call (variant-index + fields).  
   The tool can decode and preview the pallet/variant with metadata.
4. **Sign & Submit** – the extrinsic is signed locally and submitted; you get the hash and inclusion events.

---

## ✨ Features

* **Interactive wizard** powered by [`inquire`](https://docs.rs/inquire) – prompts only for missing args.
* Fast, script-friendly **CLI options** via [`clap`](https://docs.rs/clap) – skip prompts entirely.
* Supports **`sr25519` keys** from:
  * *Mnemonic phrase* (`--phrase`)
  * *Raw seed* (`--seed 0x…`)
  * Optional *derivation path* (`--derive-path "//hard/soft"`)
* **Mnemonic checksum validation** with [`bip39`](https://docs.rs/bip39).
* Uses **Subxt 0.42** + **subxt-signer** for submission.
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
subscribinto                 # prompts for everything
```

### Non-interactive

```bash
subscribinto --endpoint wss://rpc.polkadot.io   --phrase "conduct stadium suggest ..."   --derive-path "//0"   --call-data 0x0400ffd1
```

### Mix & match (some prompts)

```bash
subscribinto --endpoint wss://kusama-rpc.polkadot.io --seed 0x1efe…
# will still ask for call-data
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
| `src/signer.rs` | Re-export helpers for `PairSigner` (placeholder) |
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
