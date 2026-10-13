// Copyright (c) Virto Network
// SPDX-License-Identifier: MIT

//! `subskribinto accounts …` and `subskribinto --account <name>`: managing accounts in the system
//! keystore, and signing with them from the command line.
//!
//! Anything that changes an account, or signs with one, needs the user's approval through
//! [`presence::confirm`]; signing also needs the account's policy to allow the call.

use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use clap::Subcommand;

use crate::{
    SigningArgs,
    guard::Request,
    policy::Policy,
    presence, resolve_signing_choice,
    store::{AccountRecord, Accounts},
    tx::{self, Progress},
};

#[derive(Debug, Subcommand)]
pub enum AccountsCommand {
    /// Store an account in the system keystore
    Add {
        /// A name for the account (letters, digits, `-` and `_`)
        name: String,

        #[command(flatten)]
        signing: SigningArgs,

        /// A policy file (TOML) with the endpoint, proxy and allowed calls
        #[arg(long, value_name = "FILE", required_unless_present = "endpoint")]
        policy: Option<PathBuf>,

        /// The only endpoint this account will use. Without `--policy`, nothing can be signed
        /// until a policy is set with `accounts policy`
        #[arg(long, conflicts_with = "policy")]
        endpoint: Option<String>,
    },
    /// List stored accounts
    List,
    /// Print an account's address and policy
    Show { name: String },
    /// Replace an account's policy
    Policy {
        name: String,
        /// The new policy (TOML)
        file: PathBuf,
    },
    /// Delete an account from the system keystore
    Remove { name: String },
}

pub async fn run(accounts: &Accounts, command: AccountsCommand) -> anyhow::Result<()> {
    match command {
        AccountsCommand::Add {
            name,
            signing,
            policy,
            endpoint,
        } => {
            let policy = match (policy, endpoint) {
                (Some(path), _) => read_policy(&path)?,
                (None, Some(endpoint)) => Policy::deny_all(endpoint)?,
                (None, None) => unreachable!("clap requires one of them"),
            };
            let signer = resolve_signing_choice(signing)?.try_into_signer()?;
            let record = AccountRecord::new(name, &signer, policy)?;
            ensure!(
                !accounts.names()?.contains(&record.name),
                "An account named `{}` already exists",
                record.name
            );

            presence::confirm(&format!(
                "store the account `{}` ({})",
                record.name, record.address
            ))
            .await?;
            accounts.insert(&record)?;
            println!("Stored `{}` ({})", record.name, record.address);
            if record.policy.allow.is_empty() {
                println!(
                    "Its policy allows no calls yet: set one with `subskribinto accounts policy`."
                );
            }
        }
        AccountsCommand::List => {
            let names = accounts.names()?;
            if names.is_empty() {
                println!("No stored accounts.");
            }
            for name in names {
                let record = accounts.get(&name)?;
                let proxy = record
                    .policy
                    .proxy
                    .as_ref()
                    .map(|proxy| format!(", proxy of {}", proxy.real))
                    .unwrap_or_default();
                println!(
                    "{name}\t{} ({}) on {}{proxy}, {} rule(s)",
                    record.address,
                    record.scheme,
                    record.policy.endpoint,
                    record.policy.allow.len()
                );
            }
        }
        AccountsCommand::Show { name } => {
            let record = accounts.get(&name)?;
            println!(
                "# {} ({}, {})\n",
                record.name, record.address, record.scheme
            );
            print!("{}", record.policy.to_toml());
        }
        AccountsCommand::Policy { name, file } => {
            let policy = read_policy(&file)?;
            let record = accounts.get(&name)?;
            presence::confirm(&format!(
                "replace the policy of `{}` with {}",
                record.name,
                file.display()
            ))
            .await?;
            accounts.set_policy(&name, policy)?;
            println!("Updated the policy of `{name}`");
        }
        AccountsCommand::Remove { name } => {
            let record = accounts.get(&name)?;
            presence::confirm(&format!(
                "delete the account `{}` ({})",
                record.name, record.address
            ))
            .await?;
            accounts.remove(&name)?;
            println!("Removed `{name}`");
        }
    }
    Ok(())
}

/// Sign `call` with a stored account from the command line: same policy and approval as over MCP.
pub async fn sign_with_stored(
    accounts: &Accounts,
    name: &str,
    endpoint: Option<&str>,
    call: &[u8],
) -> anyhow::Result<()> {
    let record = accounts.get(name)?;
    if let Some(endpoint) = endpoint {
        ensure!(
            endpoint == record.policy.endpoint,
            "`{name}` only uses {}, not {endpoint}",
            record.policy.endpoint
        );
    }
    let api = tx::connect(&record.policy.endpoint).await?;
    let request = Request::new(record, &api.metadata(), call)?;
    request.check()?;

    println!("{}\n", request.summary());
    presence::confirm(&request.reason()).await?;

    let signer = request.account.signer()?;
    let outcome = tx::sign_and_submit(&api, &request.signed, &signer, print_progress).await?;
    print_outcome(&outcome);
    Ok(())
}

pub fn print_progress(progress: Progress<'_>) {
    match progress {
        Progress::Submitted { tx_hash } => println!("Transaction submitted with hash {tx_hash}"),
        Progress::InBlock { block_hash } => println!("Transaction included in block {block_hash}"),
    }
}

pub fn print_outcome(outcome: &tx::Outcome) {
    println!(
        "Transaction finalized in block {} (extrinsic #{})",
        outcome.block_hash, outcome.extrinsic_index
    );
    for event in &outcome.events {
        println!("  {event}");
    }
}

fn read_policy(path: &Path) -> anyhow::Result<Policy> {
    let toml =
        std::fs::read_to_string(path).with_context(|| format!("Cannot read {}", path.display()))?;
    Policy::from_toml(&toml).with_context(|| format!("In {}", path.display()))
}
