// Copyright (c) Virto Network
// SPDX-License-Identifier: MIT

use super::*;

use ::sp_core::crypto::Ss58Codec;
use subxt::{
    dynamic::Value,
    ext::{
        scale_decode::DecodeAsType,
        scale_value::{Composite, ValueDef, Variant},
    },
    tx::{DefaultPayload, TxStatus},
};

pub async fn sign_and_submit(
    signing: SigningChoice,
    call_bytes: Vec<u8>,
    endpoint: &str,
) -> anyhow::Result<()> {
    let signer = signing.try_into_signer()?;
    println!("Signing as {}", signer.account_id().to_ss58check());
    let api = subxt::OnlineClient::<config::KreivoConfig>::from_url(endpoint).await?;

    // Now we decode using metadata.
    let metadata = api.metadata();
    let call_ty = metadata.outer_enums().call_enum_ty();
    let call_value = Value::decode_as_type(&mut call_bytes.as_ref(), call_ty, metadata.types())?;
    let ValueDef::Variant(Variant {
        name: pallet_name,
        values: Composite::Unnamed(v),
    }) = call_value.value
    else {
        Err(anyhow::Error::msg(
            "It was not possible to parse value as pallet enum",
        ))?
    };
    let Some(ValueDef::Variant(Variant {
        name: call_name,
        values: fields,
    })) = v.first().map(|v| v.clone().value)
    else {
        Err(anyhow::Error::msg(
            "It was not possible to parse value as call enum",
        ))?
    };

    let call = DefaultPayload::new(&pallet_name, &call_name, fields);

    println!("Submitting {pallet_name}::{call_name}(<stripped>)");

    let mut progress = api
        .tx()
        .sign_and_submit_then_watch_default(&call, &signer)
        .await?;

    println!(
        "Transaction submitted with hash {:?}",
        progress.extrinsic_hash()
    );

    while let Some(status) = progress.next().await {
        match status? {
            TxStatus::InBestBlock(block) => {
                println!("Transaction included in block {:?}", block.block_hash());
            }
            TxStatus::InFinalizedBlock(block) => {
                let events = block.wait_for_success().await?;
                println!(
                    "Transaction finalized in block {:?} (extrinsic #{})",
                    block.block_hash(),
                    events.extrinsic_index()
                );
                for event in events.iter() {
                    let event = event?;
                    println!(
                        "  {}::{} {}",
                        event.pallet_name(),
                        event.variant_name(),
                        event.field_values()?
                    );
                }
                return Ok(());
            }
            TxStatus::Error { message }
            | TxStatus::Invalid { message }
            | TxStatus::Dropped { message } => {
                anyhow::bail!("Transaction failed: {message}")
            }
            _ => {}
        }
    }

    anyhow::bail!("Lost track of the transaction before it was finalized")
}
