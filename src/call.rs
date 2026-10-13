// Copyright (c) Virto Network
// SPDX-License-Identifier: MIT

//! Decoding, describing and wrapping runtime calls with a chain's metadata.
//!
//! Calls are decoded keeping each value's type id, which is what lets the policy find calls nested
//! inside other calls (`Utility.batch`, `Proxy.proxy`, …) and tell accounts apart from other 32-byte
//! values such as hashes.

use std::{collections::HashSet, fmt, fmt::Write as _};

use anyhow::{Context, anyhow, bail, ensure};
use scale_info::TypeDef;
use sp_core::crypto::{AccountId32, Ss58AddressFormat, Ss58Codec};
use subxt::{
    Metadata,
    ext::scale_value::{
        self, Composite, Primitive, ValueDef,
        stringify::{
            custom_formatters::format_hex,
            custom_parsers::{parse_hex, parse_ss58},
        },
    },
    tx::DefaultPayload,
};

use crate::policy::{ProxyConfig, parse_account};

/// A decoded value, annotated with the id of its type in the chain's metadata.
pub type Value = scale_value::Value<u32>;

const DEFAULT_SS58_PREFIX: u16 = 42;

/// A runtime call decoded with a chain's metadata.
pub struct DecodedCall {
    bytes: Vec<u8>,
    value: Value,
    call_ty: u32,
    account_tys: HashSet<u32>,
    ss58_prefix: u16,
}

/// One call inside a [`DecodedCall`]: the call itself, or one nested in it.
pub struct CallRef<'a> {
    pub pallet: &'a str,
    pub call: &'a str,
    args: &'a Composite<u32>,
    account_tys: &'a HashSet<u32>,
}

impl DecodedCall {
    pub fn decode(metadata: &Metadata, bytes: &[u8]) -> anyhow::Result<Self> {
        let call_ty = metadata.outer_enums().call_enum_ty();
        let mut cursor = bytes;
        let value = scale_value::scale::decode_as_type(&mut cursor, call_ty, metadata.types())
            .map_err(|e| anyhow!("Not a valid call for this chain: {e}"))?;
        ensure!(
            cursor.is_empty(),
            "Not a valid call for this chain: {} trailing bytes",
            cursor.len()
        );

        let account_tys = metadata
            .types()
            .types
            .iter()
            .filter(|ty| {
                ty.ty
                    .path
                    .segments
                    .last()
                    .is_some_and(|name| name == "AccountId32")
            })
            .map(|ty| ty.id)
            .collect();
        let ss58_prefix = metadata
            .pallet_by_name("System")
            .and_then(|pallet| pallet.constant_by_name("SS58Prefix"))
            .and_then(|constant| <[u8; 2]>::try_from(constant.value()).ok())
            .map(u16::from_le_bytes)
            .unwrap_or(DEFAULT_SS58_PREFIX);

        Ok(Self {
            bytes: bytes.to_vec(),
            value,
            call_ty,
            account_tys,
            ss58_prefix,
        })
    }

    /// Build `Pallet.call(args)` with the chain's metadata. `args` uses scale-value syntax, e.g.
    /// `{ dest: Id(5FHneW46…), value: 1_000 }`, with SS58 addresses and `0x…` hex accepted, and
    /// variants without data written `Variant()`.
    pub fn encode(
        metadata: &Metadata,
        pallet: &str,
        call: &str,
        args: Option<&str>,
    ) -> anyhow::Result<Self> {
        let fields = match args.map(str::trim).filter(|args| !args.is_empty()) {
            Some(args) => {
                let (value, rest) = scale_value::stringify::from_str_custom()
                    .add_custom_parser(parse_hex)
                    .add_custom_parser(parse_ss58)
                    .parse(args);
                let value = value.map_err(|e| anyhow!("Cannot parse the arguments: {e}"))?;
                ensure!(
                    rest.trim().is_empty(),
                    "Cannot parse the arguments from: {rest}"
                );
                match value.value {
                    ValueDef::Composite(fields) => fields,
                    _ => bail!("The arguments must be `{{ name: value, … }}` or `(value, …)`"),
                }
            }
            None => Composite::Unnamed(Vec::new()),
        };
        let value = scale_value::Value::unnamed_variant(
            pallet,
            [scale_value::Value::variant(call, fields)],
        );

        let mut bytes = Vec::new();
        scale_value::scale::encode_as_type(
            &value,
            metadata.outer_enums().call_enum_ty(),
            metadata.types(),
            &mut bytes,
        )
        .map_err(|e| anyhow!("Cannot encode `{pallet}.{call}`: {e}"))?;
        Self::decode(metadata, &bytes)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The call and every call nested in it, outermost first.
    pub fn calls(&self) -> anyhow::Result<Vec<CallRef<'_>>> {
        let mut calls = Vec::new();
        self.walk(&self.value, &mut calls)?;
        Ok(calls)
    }

    fn walk<'a>(&'a self, value: &'a Value, calls: &mut Vec<CallRef<'a>>) -> anyhow::Result<()> {
        if value.context == self.call_ty {
            let ValueDef::Variant(pallet) = &value.value else {
                bail!("Unexpected shape for a call");
            };
            let mut inner = pallet.values.values();
            let (Some(call), None) = (inner.next(), inner.next()) else {
                bail!("Unexpected shape for a `{}` call", pallet.name);
            };
            let ValueDef::Variant(call) = &call.value else {
                bail!("Unexpected shape for a `{}` call", pallet.name);
            };
            calls.push(CallRef {
                pallet: &pallet.name,
                call: &call.name,
                args: &call.values,
                account_tys: &self.account_tys,
            });
            return call.values.values().try_for_each(|v| self.walk(v, calls));
        }
        match &value.value {
            ValueDef::Composite(composite) => {
                composite.values().try_for_each(|v| self.walk(v, calls))
            }
            ValueDef::Variant(variant) => variant
                .values
                .values()
                .try_for_each(|v| self.walk(v, calls)),
            _ => Ok(()),
        }
    }

    /// A readable rendering of the call, with accounts in SS58 and bytes in hex.
    pub fn describe(&self) -> String {
        describe(&self.value, &self.account_tys, self.ss58_prefix, true)
    }

    /// Render decoded fields (e.g. an event's) like [`DecodedCall::describe`], on one line.
    pub fn describe_fields(&self, fields: Composite<u32>) -> String {
        let value = Value {
            value: ValueDef::Composite(fields),
            context: u32::MAX,
        };
        describe(&value, &self.account_tys, self.ss58_prefix, false)
    }

    /// Render an account the way [`DecodedCall::describe`] does.
    pub fn format_account(&self, account: &AccountId32) -> String {
        account.to_ss58check_with_version(Ss58AddressFormat::custom(self.ss58_prefix))
    }

    /// The same call, wrapped in `Proxy.proxy(real, force_proxy_type, call)`.
    pub fn wrap_in_proxy(&self, metadata: &Metadata, proxy: &ProxyConfig) -> anyhow::Result<Self> {
        let real = parse_account(&proxy.real)?;
        let variant = metadata
            .pallet_by_name("Proxy")
            .and_then(|pallet| pallet.call_variant_by_name("proxy"))
            .context("This chain has no `Proxy.proxy` call")?;
        let real_ty = variant
            .fields
            .iter()
            .find(|field| field.name.as_deref() == Some("real"))
            .context("Unexpected `Proxy.proxy` signature")?
            .ty
            .id;

        let real = scale_value::Value::from_bytes(real);
        let real = match metadata.types().resolve(real_ty).map(|ty| &ty.type_def) {
            Some(TypeDef::Variant(lookup)) if lookup.variants.iter().any(|v| v.name == "Id") => {
                scale_value::Value::unnamed_variant("Id", [real])
            }
            _ => real,
        };
        let force_proxy_type = match &proxy.proxy_type {
            Some(name) => scale_value::Value::unnamed_variant(
                "Some",
                [scale_value::Value::unnamed_variant(name.clone(), [])],
            ),
            None => scale_value::Value::unnamed_variant("None", []),
        };
        let wrapped = scale_value::Value::unnamed_variant(
            "Proxy",
            [scale_value::Value::named_variant(
                "proxy",
                [
                    ("real", real),
                    ("force_proxy_type", force_proxy_type),
                    ("call", self.value.clone().remove_context()),
                ],
            )],
        );

        let mut bytes = Vec::new();
        scale_value::scale::encode_as_type(&wrapped, self.call_ty, metadata.types(), &mut bytes)
            .map_err(|e| anyhow!("Cannot wrap the call in `Proxy.proxy`: {e}"))?;
        Self::decode(metadata, &bytes)
    }

    /// The payload Subxt signs. Callers should check `call_data(&payload) == bytes()`.
    pub fn payload(&self) -> anyhow::Result<DefaultPayload<Composite<()>>> {
        let root = self.calls()?.into_iter().next().context("No call found")?;
        Ok(DefaultPayload::new(
            root.pallet.to_owned(),
            root.call.to_owned(),
            root.args.clone().map_context(|_| ()),
        ))
    }
}

impl<'a> CallRef<'a> {
    /// A named argument of the call.
    pub fn field(&self, name: &str) -> Option<&'a Value> {
        match self.args {
            Composite::Named(fields) => fields.iter().find(|(n, _)| n == name).map(|(_, v)| v),
            Composite::Unnamed(_) => None,
        }
    }

    /// Every account found in a value, judged by its type (not by its length).
    pub fn accounts_in(&self, value: &Value) -> Vec<AccountId32> {
        let mut accounts = Vec::new();
        collect_accounts(value, self.account_tys, &mut accounts);
        accounts
    }
}

impl fmt::Display for CallRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.pallet, self.call)
    }
}

/// A numeric value, looking through single-field wrappers such as `Compact` or newtypes.
pub fn as_u128(value: &Value) -> Option<u128> {
    match &value.value {
        ValueDef::Primitive(Primitive::U128(n)) => Some(*n),
        ValueDef::Primitive(Primitive::I128(n)) => u128::try_from(*n).ok(),
        ValueDef::Composite(composite) => {
            let mut values = composite.values();
            match (values.next(), values.next()) {
                (Some(value), None) => as_u128(value),
                _ => None,
            }
        }
        _ => None,
    }
}

fn collect_accounts(value: &Value, account_tys: &HashSet<u32>, accounts: &mut Vec<AccountId32>) {
    if account_tys.contains(&value.context) {
        if let Some(bytes) = flatten_bytes(value).and_then(|b| <[u8; 32]>::try_from(b).ok()) {
            accounts.push(AccountId32::new(bytes));
        }
        return;
    }
    match &value.value {
        ValueDef::Composite(composite) => composite
            .values()
            .for_each(|v| collect_accounts(v, account_tys, accounts)),
        ValueDef::Variant(variant) => variant
            .values
            .values()
            .for_each(|v| collect_accounts(v, account_tys, accounts)),
        _ => {}
    }
}

/// The bytes of a value made only of `u8`s, through any nesting (e.g. `AccountId32([u8; 32])`).
fn flatten_bytes<T>(value: &scale_value::Value<T>) -> Option<Vec<u8>> {
    match &value.value {
        ValueDef::Primitive(Primitive::U128(n)) => u8::try_from(*n).ok().map(|b| vec![b]),
        ValueDef::Composite(composite) => {
            let mut bytes = Vec::new();
            for value in composite.values() {
                bytes.extend(flatten_bytes(value)?);
            }
            Some(bytes)
        }
        _ => None,
    }
}

fn describe(value: &Value, account_tys: &HashSet<u32>, ss58_prefix: u16, pretty: bool) -> String {
    let account_tys = account_tys.clone();
    let mut out = String::new();
    let writer = scale_value::stringify::to_writer_custom();
    let writer = if pretty { writer.pretty() } else { writer };
    writer
        .add_custom_formatter(move |value: &Value, writer: &mut &mut String| {
            if !account_tys.contains(&value.context) {
                return None;
            }
            let bytes = flatten_bytes(value).and_then(|b| <[u8; 32]>::try_from(b).ok())?;
            let account = AccountId32::new(bytes)
                .to_ss58check_with_version(Ss58AddressFormat::custom(ss58_prefix));
            Some(writer.write_str(&account))
        })
        .add_custom_formatter(|value, writer| format_hex(value, writer))
        .write(value, &mut out)
        .expect("writing to a String never fails");
    out
}
