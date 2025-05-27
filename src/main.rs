use ::sp_core::{Pair as _, sr25519};
use bip39::Mnemonic;
use clap::{Args, Parser};
use inquire::Text;

pub(crate) mod config;
pub(crate) mod signer;
mod tx;

#[derive(Debug, Parser)]
#[command(author, version, about = "Step‑based extrinsic signer & submitter", long_about = None)]
struct Cli {
    /// WebSocket endpoint (e.g. wss://rpc.polkadot.io)
    #[arg(long, short = 'e')]
    endpoint: Option<String>,

    #[command(flatten)]
    signing: SigningArgs,

    /// Hex‑encoded call data (0x…)
    #[arg(long, value_name = "HEX")]
    call_data: Option<String>,
}

#[derive(Debug, Args)]
struct SigningArgs {
    /// BIP‑39 mnemonic phrase (will supersede --seed if both supplied)
    #[arg(long)]
    phrase: Option<String>,

    /// Raw 0x‑prefixed hex seed (32‑byte)
    #[arg(long)]
    seed: Option<String>,

    /// Optional derivation path (e.g. "/polkadot/0")
    #[arg(long = "derive-path")]
    path: Option<String>,
}

#[derive(Debug)]
enum SigningChoice {
    Mnemonic {
        phrase: String,
        derive_path: Option<String>,
    },
    Seed {
        hex_seed: String,
    },
}

impl SigningChoice {
    /// Convert `SigningChoice` into an sr25519 `KeyPair` ready for signing extrinsics.
    fn try_into_keypair(&self) -> anyhow::Result<sr25519::Pair> {
        match self {
            SigningChoice::Mnemonic {
                phrase,
                derive_path,
            } => {
                // Validate mnemonic checksum & wordlist first
                ensure_valid_mnemonic(phrase)?;

                // Build `secret_uri` understood by sp‑core, e.g. "<mnemonic>//hard/soft"
                let uri = match derive_path {
                    Some(dp) => format!("{}{}", phrase, dp),
                    None => phrase.clone(),
                };
                sr25519::Pair::from_string(&uri, None)
                    .map_err(|e| anyhow::anyhow!("Invalid mnemonic or derivation path: {e}"))
            }
            SigningChoice::Seed { hex_seed, .. } => {
                let bytes = hex::decode(hex_seed.trim_start_matches("0x"))?;
                sr25519::Pair::from_seed_slice(&bytes).map_err(|e| anyhow::anyhow!("Seed: {e}"))
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // 1️⃣ Gather endpoint
    let endpoint = match cli.endpoint {
        Some(ep) => ep,
        None => Text::new("WebSocket endpoint URL?").prompt()?,
    };

    // 2️⃣ Determine signing choice
    let signing_choice = resolve_signing_choice(cli.signing)?;

    // 3️⃣ Get call data
    let call_data_hex = match cli.call_data {
        Some(data) => data,
        None => Text::new("Hex‑encoded call data (0x…)?").prompt()?,
    };

    // 4️⃣ Sign & submit (stub)
    tx::sign_and_submit(signing_choice, call_data_hex, &endpoint).await?;

    Ok(())
}

/// Convert `SigningChoice` into an sr25519 `KeyPair` ready for signing extrinsics.
/// Validate a BIP‑39 mnemonic; returns error if checksum / wordlist mismatch
fn ensure_valid_mnemonic(phrase: &str) -> anyhow::Result<()> {
    Mnemonic::parse(phrase)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("Invalid BIP‑39 mnemonic: {e}"))
}

fn resolve_signing_choice(args: SigningArgs) -> anyhow::Result<SigningChoice> {
    match (args.phrase, args.seed) {
        (Some(phrase), _) => Ok(SigningChoice::Mnemonic {
            phrase,
            derive_path: ask_optional_derive_path(args.path)?,
        }),
        (None, Some(hex_seed)) => Ok(SigningChoice::Seed { hex_seed }),
        (None, None) => {
            // Ask interactively using inquire Select
            use inquire::Select;
            let opts = vec!["Mnemonic phrase", "Hex seed"];
            let choice = Select::new("Choose signing material", opts).prompt()?;
            match choice {
                "Mnemonic phrase" => Ok(SigningChoice::Mnemonic {
                    phrase: Text::new("Enter mnemonic phrase:").prompt()?,
                    derive_path: ask_optional_derive_path(args.path)?,
                }),
                _ => Ok(SigningChoice::Seed {
                    hex_seed: Text::new("Enter 0x‑prefixed hex seed:").prompt()?,
                }),
            }
        }
    }
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
