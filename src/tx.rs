use super::*;

use signer::PairSigner;
use subxt::{
    dynamic::Value,
    ext::{
        scale_decode::DecodeAsType,
        scale_value::{Composite, ValueDef, Variant},
    },
    tx::DefaultPayload,
};

pub async fn sign_and_submit(
    signing: SigningChoice,
    call_hex: String,
    endpoint: &str,
) -> anyhow::Result<()> {
    let signer: PairSigner = signing.try_into_keypair()?.into();
    let api = subxt::OnlineClient::<config::KreivoConfig>::from_url(endpoint).await?;

    let call_bytes = hex::decode(call_hex.trim_start_matches("0x"))?;

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

    let tx_hash = api.tx().sign_and_submit_default(&call, &signer).await?;

    println!("Transaction submitted with hash {tx_hash}");

    Ok(())
}
