// Copyright (c) Virto Network
// SPDX-License-Identifier: MIT

//! Connecting to a chain, and signing, submitting and following transactions.

use anyhow::{anyhow, bail, ensure};
use schemars::JsonSchema;
use serde::Serialize;
use std::time::Duration;

use subxt::{OnlineClient, tx::TxStatus};

use crate::{call::DecodedCall, config::KreivoConfig, signer::PairSigner};

pub type Api = OnlineClient<KreivoConfig>;

pub async fn connect(endpoint: &str) -> anyhow::Result<Api> {
    Api::from_url(endpoint)
        .await
        .map_err(|e| anyhow!("Cannot connect to {endpoint}: {e}"))
}

/// How long [`is_current`] waits for the node before giving up on a connection.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether a client from [`connect`] can still be used: its connection answers, and it was built
/// for the runtime the chain runs now. After a runtime upgrade its metadata and transaction
/// version are outdated, and the chain would reject what it signs.
pub async fn is_current(api: &Api) -> bool {
    let built = api.runtime_version();
    match tokio::time::timeout(
        HEALTH_CHECK_TIMEOUT,
        api.backend().current_runtime_version(),
    )
    .await
    {
        Ok(Ok(now)) => {
            now.spec_version == built.spec_version
                && now.transaction_version == built.transaction_version
        }
        _ => false,
    }
}

/// Intermediate steps of a submission, for callers that report progress.
pub enum Progress<'a> {
    Submitted { tx_hash: &'a str },
    InBlock { block_hash: &'a str },
}

/// A finalized transaction.
#[derive(Debug, Serialize, JsonSchema)]
pub struct Outcome {
    pub tx_hash: String,
    pub block_hash: String,
    pub extrinsic_index: u32,
    /// The events the transaction emitted, as `Pallet.Event { fields }`.
    pub events: Vec<String>,
}

/// Sign `call` exactly as decoded, submit it, and follow it until it is finalized.
/// Fails if it is invalid, dropped, or dispatched with an error.
pub async fn sign_and_submit(
    api: &Api,
    call: &DecodedCall,
    signer: &PairSigner,
    mut progress: impl FnMut(Progress<'_>),
) -> anyhow::Result<Outcome> {
    let payload = call.payload()?;
    ensure!(
        api.tx().call_data(&payload)? == call.bytes(),
        "The call would not be signed exactly as decoded; refusing to sign it"
    );

    let mut tx = api
        .tx()
        .sign_and_submit_then_watch_default(&payload, signer)
        .await?;
    let tx_hash = format!("{:?}", tx.extrinsic_hash());
    progress(Progress::Submitted { tx_hash: &tx_hash });

    while let Some(status) = tx.next().await {
        match status? {
            TxStatus::InBestBlock(block) => {
                progress(Progress::InBlock {
                    block_hash: &format!("{:?}", block.block_hash()),
                });
            }
            TxStatus::InFinalizedBlock(block) => {
                let events = block.wait_for_success().await?;
                let mut descriptions = Vec::new();
                for event in events.iter() {
                    let event = event?;
                    descriptions.push(format!(
                        "{}.{} {}",
                        event.pallet_name(),
                        event.variant_name(),
                        call.describe_fields(event.field_values()?)
                    ));
                }
                return Ok(Outcome {
                    tx_hash,
                    block_hash: format!("{:?}", block.block_hash()),
                    extrinsic_index: events.extrinsic_index(),
                    events: descriptions,
                });
            }
            TxStatus::Error { message }
            | TxStatus::Invalid { message }
            | TxStatus::Dropped { message } => bail!("Transaction failed: {message}"),
            _ => {}
        }
    }

    bail!("Lost track of the transaction before it was finalized")
}

#[cfg(test)]
mod tests {
    //! Against a local dev chain: run `polkadot --dev --tmp --rpc-port 19944` (or point
    //! `SUBSKRIBINTO_DEV_NODE` at another dev node), then `cargo test -- --ignored`.

    use sp_core::{Pair as _, sr25519};

    use super::*;
    use crate::{
        audit::AuditLog,
        guard::Request,
        policy::{
            Approval, Policy,
            tests::{ALICE, BOB, CHARLIE},
        },
        store::AccountRecord,
    };

    fn dev(name: &str) -> PairSigner {
        sr25519::Pair::from_string(&format!("//{name}"), None)
            .unwrap()
            .into()
    }

    fn endpoint() -> String {
        std::env::var("SUBSKRIBINTO_DEV_NODE").unwrap_or_else(|_| "ws://127.0.0.1:19944".into())
    }

    #[tokio::test]
    #[ignore = "needs a local dev chain"]
    async fn signs_through_a_proxy_on_a_dev_chain() {
        let api = connect(&endpoint()).await.unwrap();
        let metadata = api.metadata();

        // Alice makes Bob her proxy.
        let add_proxy = DecodedCall::encode(
            &metadata,
            "Proxy",
            "add_proxy",
            Some(&format!(
                "{{ delegate: Id({BOB}), proxy_type: Any(), delay: 0 }}"
            )),
        )
        .unwrap();
        // Already a proxy if the test ran before against the same chain.
        if let Err(e) = sign_and_submit(&api, &add_proxy, &dev("Alice"), |_| {}).await {
            assert!(format!("{e:#}").contains("Duplicate"), "{e:#}");
        }

        // Bob is stored with a policy that only allows small transfers to Charlie, for Alice, and
        // signs them without asking.
        let record = || {
            let policy = Policy::from_toml(&format!(
                "endpoint = \"{}\"\n\
                 [proxy]\nreal = \"{ALICE}\"\ntype = \"Any\"\n\
                 [[allow]]\ncall = \"Balances.transfer_keep_alive\"\nunattended = true\n\
                 max = {{ value = 1000000000000 }}\nto = {{ dest = [\"{CHARLIE}\"] }}",
                endpoint()
            ))
            .unwrap();
            AccountRecord::new("bob".into(), &dev("Bob"), policy).unwrap()
        };
        let transfer = |value: u128| {
            DecodedCall::encode(
                &metadata,
                "Balances",
                "transfer_keep_alive",
                Some(&format!("{{ dest: Id({CHARLIE}), value: {value} }}")),
            )
            .unwrap()
        };

        let too_much =
            Request::new(record(), &metadata, transfer(2_000_000_000_000).bytes()).unwrap();
        assert!(too_much.check().is_err());

        let request = Request::new(record(), &metadata, transfer(1_000_000_000).bytes()).unwrap();
        let approval = request.check().unwrap();
        assert_eq!(approval, Approval::Unattended);

        let log_path = std::env::temp_dir()
            .join(format!("subskribinto-devchain-{}", std::process::id()))
            .join("audit.jsonl");
        let audit = AuditLog::at(log_path.clone());
        let outcome = request.sign(&api, approval, &audit, |_| {}).await.unwrap();

        let log = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(log.lines().count(), 2, "{log}");
        assert!(log.contains(&outcome.tx_hash), "{log}");
        std::fs::remove_dir_all(log_path.parent().unwrap()).unwrap();

        println!("{outcome:#?}");
        assert!(
            outcome
                .events
                .iter()
                .any(|e| e.starts_with("Proxy.ProxyExecuted") && e.contains("Ok")),
            "{outcome:#?}"
        );
        assert!(
            outcome
                .events
                .iter()
                .any(|e| e.starts_with("Balances.Transfer")
                    && e.contains(ALICE)
                    && e.contains(CHARLIE)),
            "the transfer must come from Alice: {outcome:#?}"
        );
    }
}
