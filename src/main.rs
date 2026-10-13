// Copyright (c) Virto Network
// SPDX-License-Identifier: MIT

use ::sp_core::{Pair as _, crypto::Ss58Codec, ed25519, sr25519};
use bip39::Mnemonic;
use clap::{Args, Parser, Subcommand};
use inquire::{Password, Text};
use std::path::PathBuf;

mod accounts;
mod audit;
mod call;
pub(crate) mod config;
mod guard;
pub(crate) mod keyfile;
mod mcp;
mod policy;
mod presence;
pub(crate) mod signer;
mod store;
mod tx;

use call::DecodedCall;
use keyfile::KeyFile;
use signer::{PairSigner, Scheme};
use store::{Accounts, OsKeystore};

#[derive(Debug, Parser)]
#[command(author, version, about = "Step‑based extrinsic signer & submitter", long_about = None)]
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// WebSocket endpoint (e.g. wss://rpc.polkadot.io)
    #[arg(long, short = 'e')]
    endpoint: Option<String>,

    #[command(flatten)]
    signing: SigningArgs,

    /// Sign with an account stored with `subskribinto accounts add`, subject to its policy and
    /// your approval
    #[arg(long, value_name = "NAME", conflicts_with_all = ["phrase", "seed", "key_file", "path"])]
    account: Option<String>,

    /// Hex‑encoded call data (0x…)
    #[arg(long, alias = "call-data", value_name = "HEX")]
    call: Option<String>,

    /// A file containing the SCALE-encoded call data in raw format
    #[arg(long, alias = "call-data-file", value_name = "FILE")]
    call_file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage accounts kept in the system keystore (Keychain, Credential Manager, Secret Service)
    #[command(subcommand)]
    Accounts(accounts::AccountsCommand),
    /// Serve the stored accounts to AI assistants as an MCP server over stdio
    Mcp,
}

#[derive(Debug, Args)]
pub(crate) struct SigningArgs {
    /// BIP‑39 mnemonic phrase (will supersede --seed and --key-file if supplied)
    #[arg(long)]
    phrase: Option<String>,

    /// Raw 0x‑prefixed hex seed (32 bytes), or a 64-byte sr25519 secret key as exported by
    /// polkadot{.js}
    #[arg(long)]
    seed: Option<String>,

    /// A JSON key file exported by polkadot{.js} (extension, apps or keyring). The password is
    /// asked interactively
    #[arg(long, value_name = "FILE")]
    key_file: Option<PathBuf>,

    /// Optional derivation path (e.g. "/polkadot/0")
    #[arg(long = "derive-path")]
    path: Option<String>,

    /// Signature scheme for --phrase and --seed (key files declare their own)
    #[arg(long, value_enum, default_value_t = Scheme::Sr25519)]
    scheme: Scheme,
}

#[derive(Debug)]
pub(crate) enum SigningChoice {
    Mnemonic {
        phrase: String,
        derive_path: Option<String>,
        scheme: Scheme,
    },
    Seed {
        hex_seed: String,
        scheme: Scheme,
    },
    KeyFile {
        file: KeyFile,
        password: String,
    },
}

impl SigningChoice {
    /// Convert `SigningChoice` into a signer ready for signing extrinsics.
    pub(crate) fn try_into_signer(&self) -> anyhow::Result<PairSigner> {
        match self {
            SigningChoice::Mnemonic {
                phrase,
                derive_path,
                scheme,
            } => {
                // Validate mnemonic checksum & wordlist first
                ensure_valid_mnemonic(phrase)?;

                // Build `secret_uri` understood by sp‑core, e.g. "<mnemonic>//hard/soft"
                let uri = match derive_path {
                    Some(dp) => format!("{}{}", phrase, dp),
                    None => phrase.clone(),
                };
                let invalid = |e| anyhow::anyhow!("Invalid mnemonic or derivation path: {e}");
                Ok(match scheme {
                    Scheme::Sr25519 => sr25519::Pair::from_string(&uri, None)
                        .map_err(invalid)?
                        .into(),
                    Scheme::Ed25519 => ed25519::Pair::from_string(&uri, None)
                        .map_err(invalid)?
                        .into(),
                })
            }
            SigningChoice::Seed { hex_seed, scheme } => {
                let bytes = hex::decode(hex_seed.trim_start_matches("0x"))?;
                Ok(match scheme {
                    Scheme::Sr25519 => keyfile::sr25519_from_secret(&bytes)?.into(),
                    Scheme::Ed25519 => ed25519::Pair::from_seed_slice(&bytes)
                        .map_err(|e| anyhow::anyhow!("Seed: {e}"))?
                        .into(),
                })
            }
            SigningChoice::KeyFile { file, password } => file.unlock(password),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Accounts(command)) => {
            return accounts::run(&Accounts::new(OsKeystore), command).await;
        }
        Some(Command::Mcp) => return mcp::serve(Accounts::new(OsKeystore)).await,
        None => {}
    }

    if let Some(name) = cli.account {
        let call_bytes = read_call(cli.call, cli.call_file)?;
        let accounts = Accounts::new(OsKeystore);
        return accounts::sign_with_stored(&accounts, &name, cli.endpoint.as_deref(), &call_bytes)
            .await;
    }

    let endpoint = match cli.endpoint {
        Some(ep) => ep,
        None => Text::new("WebSocket endpoint URL?").prompt()?,
    };

    let signer = resolve_signing_choice(cli.signing)?.try_into_signer()?;
    let call_bytes = read_call(cli.call, cli.call_file)?;

    println!("Signing as {}", signer.account_id().to_ss58check());
    let api = tx::connect(&endpoint).await?;
    let call = DecodedCall::decode(&api.metadata(), &call_bytes)?;
    println!("Submitting {}", call.describe());

    let outcome = tx::sign_and_submit(&api, &call, &signer, accounts::print_progress).await?;
    accounts::print_outcome(&outcome);

    Ok(())
}

/// The call data, from `--call`, `--call-file` or a prompt.
fn read_call(call: Option<String>, call_file: Option<PathBuf>) -> anyhow::Result<Vec<u8>> {
    let call_hex = match (call, call_file) {
        (Some(data), _) => data,
        (_, Some(path)) => std::fs::read(path).map(hex::encode)?,
        (_, _) => Text::new("Hex‑encoded call data (0x…)?").prompt()?,
    };

    Ok(hex::decode(call_hex.trim_start_matches("0x"))?)
}

/// Validate a BIP‑39 mnemonic; returns error if checksum / wordlist mismatch
fn ensure_valid_mnemonic(phrase: &str) -> anyhow::Result<()> {
    Mnemonic::parse(phrase)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("Invalid BIP‑39 mnemonic: {e}"))
}

pub(crate) fn resolve_signing_choice(args: SigningArgs) -> anyhow::Result<SigningChoice> {
    let scheme = args.scheme;
    match (args.phrase, args.seed, args.key_file) {
        (Some(phrase), _, _) => Ok(SigningChoice::Mnemonic {
            phrase,
            derive_path: ask_optional_derive_path(args.path)?,
            scheme,
        }),
        (None, Some(hex_seed), _) => Ok(SigningChoice::Seed { hex_seed, scheme }),
        (None, None, Some(path)) => key_file_choice(path),
        (None, None, None) => {
            // Ask interactively using inquire Select
            use inquire::Select;
            let opts = vec!["Mnemonic phrase", "Hex seed", "polkadot{.js} key file"];
            let choice = Select::new("Choose signing material", opts).prompt()?;
            match choice {
                "Mnemonic phrase" => Ok(SigningChoice::Mnemonic {
                    phrase: Text::new("Enter mnemonic phrase:").prompt()?,
                    derive_path: ask_optional_derive_path(args.path)?,
                    scheme,
                }),
                "Hex seed" => Ok(SigningChoice::Seed {
                    hex_seed: Text::new("Enter 0x‑prefixed hex seed:").prompt()?,
                    scheme,
                }),
                _ => key_file_choice(Text::new("Key file location:").prompt()?.into()),
            }
        }
    }
}

/// Load a polkadot{.js} key file, asking for its password if it is encrypted.
fn key_file_choice(path: PathBuf) -> anyhow::Result<SigningChoice> {
    let file = KeyFile::from_path(&path)?;
    let password = if file.is_encrypted() {
        Password::new(&format!("Password for {}:", file.describe()))
            .without_confirmation()
            .prompt()?
    } else {
        String::new()
    };
    Ok(SigningChoice::KeyFile { file, password })
}

/// Prompt helper: ask for an optional derivation path when not supplied on the CLI
fn ask_optional_derive_path(maybe_derive_path: Option<String>) -> anyhow::Result<Option<String>> {
    if maybe_derive_path.is_some() {
        return Ok(maybe_derive_path);
    }

    let path = Text::new("Derivation path (leave blank to skip):")
        .with_help_message("Example: /polkadot/0 or //hard/soft")
        .prompt()?;
    if path.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(path))
    }
}
