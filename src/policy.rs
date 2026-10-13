// Copyright (c) Virto Network
// SPDX-License-Identifier: MIT

//! What a stored account may sign.
//!
//! A [`Policy`] is a fail-closed allowlist: every call in a transaction, including the ones nested
//! inside `Utility.batch`, `Proxy.proxy` and the like, must match a [`Rule`], and every constraint
//! of that rule must hold. Anything the checker can't read is a rejection.

use std::{collections::BTreeMap, fmt};

use anyhow::{Context, anyhow, ensure};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sp_core::crypto::{AccountId32, Ss58Codec};

use crate::call::{CallRef, Value, as_u128};

/// The settings and permissions stored next to an account's key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The only node this account talks to (`ws://` or `wss://`).
    pub endpoint: String,
    /// Sign every call as a proxy of another account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyConfig>,
    /// The calls this account may sign. Empty means none.
    #[serde(default)]
    pub allow: Vec<Rule>,
}

/// Wrap every call in `Proxy.proxy(real, type, call)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// The proxied account (SS58).
    pub real: String,
    /// The `ProxyType` variant to force, e.g. `"Any"`. The chain picks one when absent.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub proxy_type: Option<String>,
}

/// One allowed call, with optional constraints on its arguments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// `"Pallet.call"`, `"Pallet.*"` for any call of a pallet, or `"*"` for any call at all (only
    /// in rules that need approval).
    pub call: String,
    /// Sign without asking the user, when every call in the transaction matches an unattended rule.
    /// Otherwise the user approves each signature.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unattended: bool,
    /// Upper bounds for numeric arguments, by argument name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[schemars(with = "BTreeMap<String, String>")]
    pub max: BTreeMap<String, Amount>,
    /// Allowed accounts (SS58) for account arguments, by argument name. Every account found in the
    /// argument must be listed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub to: BTreeMap<String, Vec<String>>,
}

/// How a transaction the policy allows gets signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Approval {
    /// Every call matches an unattended rule: signed without asking.
    Unattended,
    /// The user approves it first.
    Required,
}

/// An unsigned amount, written as an integer or a string (TOML integers stop at 2^63).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Amount(pub u128);

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Int(u64),
            Str(String),
        }
        match Repr::deserialize(deserializer)? {
            Repr::Int(n) => Ok(Self(n.into())),
            Repr::Str(s) => {
                s.replace('_', "").parse().map(Self).map_err(|_| {
                    serde::de::Error::custom(format!("`{s}` is not an unsigned integer"))
                })
            }
        }
    }
}

impl Policy {
    pub fn from_toml(toml: &str) -> anyhow::Result<Self> {
        let policy: Self = toml::from_str(toml).context("Invalid policy")?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("policies always serialize")
    }

    /// A policy that only pins the endpoint: nothing can be signed until rules are added.
    pub fn deny_all(endpoint: String) -> anyhow::Result<Self> {
        let policy = Self {
            endpoint,
            proxy: None,
            allow: Vec::new(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.endpoint.starts_with("wss://") || self.endpoint.starts_with("ws://"),
            "`endpoint` must be a ws:// or wss:// URL"
        );
        if let Some(proxy) = &self.proxy {
            parse_account(&proxy.real).context("Invalid `proxy.real`")?;
        }
        for rule in &self.allow {
            if rule.call == ANY_CALL {
                ensure!(
                    !rule.unattended,
                    "`call = \"*\"` can't be unattended: list the calls to sign without approval"
                );
                ensure!(
                    rule.max.is_empty() && rule.to.is_empty(),
                    "`call = \"*\"` can't have `max` or `to` limits"
                );
                continue;
            }
            let (pallet, call) = rule
                .call
                .split_once('.')
                .filter(|(pallet, call)| !pallet.is_empty() && !call.is_empty())
                .ok_or_else(|| {
                    anyhow!(
                        "Rule `{}` must look like `Pallet.call`, `Pallet.*` or `*`",
                        rule.call
                    )
                })?;
            ensure!(
                pallet != "*" && !call.contains('.'),
                "Rule `{}` must look like `Pallet.call`, `Pallet.*` or `*`",
                rule.call
            );
            for (field, accounts) in &rule.to {
                ensure!(
                    !accounts.is_empty(),
                    "Rule `{}`: `to.{field}` is empty",
                    rule.call
                );
                for account in accounts {
                    parse_account(account).with_context(|| {
                        format!("Rule `{}`: invalid account in `to.{field}`", rule.call)
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Check that every call (top-level and nested) is allowed, and whether the transaction can be
    /// signed without asking: only when every call is allowed by an unattended rule.
    pub fn check(&self, calls: &[CallRef<'_>]) -> anyhow::Result<Approval> {
        ensure!(!calls.is_empty(), "No call found");
        let mut approval = Approval::Unattended;
        for call in calls {
            let matched: Vec<&Rule> = self.allow.iter().filter(|r| r.matches(call)).collect();
            ensure!(
                !matched.is_empty(),
                "`{call}` is not allowed by this account's policy"
            );
            let (mut allowed, mut unattended, mut failures) = (false, false, Vec::new());
            for rule in matched {
                match rule.check(call) {
                    Ok(()) => {
                        allowed = true;
                        unattended |= rule.unattended;
                    }
                    Err(e) => failures.push(e.to_string()),
                }
            }
            ensure!(allowed, "`{call}` is not allowed: {}", failures.join("; "));
            if !unattended {
                approval = Approval::Required;
            }
        }
        Ok(approval)
    }
}

impl Rule {
    fn matches(&self, call: &CallRef<'_>) -> bool {
        if self.call == ANY_CALL {
            return true;
        }
        match self.call.split_once('.') {
            Some((pallet, name)) => pallet == call.pallet && (name == "*" || name == call.call),
            None => false,
        }
    }

    fn check(&self, call: &CallRef<'_>) -> anyhow::Result<()> {
        for (field, max) in &self.max {
            let value = field_of(call, field)?;
            let amount = as_u128(value).ok_or_else(|| anyhow!("`{field}` is not a number"))?;
            ensure!(
                amount <= max.0,
                "`{field}` is {amount}, above the maximum of {max}"
            );
        }
        for (field, allowed) in &self.to {
            let value = field_of(call, field)?;
            let allowed: Vec<AccountId32> = allowed
                .iter()
                .filter_map(|a| parse_account(a).ok())
                .collect();
            let found = call.accounts_in(value);
            ensure!(
                !found.is_empty(),
                "`{field}` holds no account this policy can check"
            );
            for account in found {
                ensure!(
                    allowed.contains(&account),
                    "`{field}` includes {}, which is not in the allowed list",
                    account.to_ss58check()
                );
            }
        }
        Ok(())
    }
}

/// The rule that matches every call.
const ANY_CALL: &str = "*";

fn field_of<'a>(call: &CallRef<'a>, field: &str) -> anyhow::Result<&'a Value> {
    call.field(field)
        .ok_or_else(|| anyhow!("`{call}` has no argument named `{field}`"))
}

pub fn parse_account(ss58: &str) -> anyhow::Result<AccountId32> {
    AccountId32::from_ss58check_with_version(ss58)
        .map(|(account, _)| account)
        .map_err(|e| anyhow!("`{ss58}` is not an SS58 address: {e:?}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use codec::Decode;
    use subxt::Metadata;

    use super::*;
    use crate::call::DecodedCall;

    pub const ALICE: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
    pub const BOB: &str = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty";
    pub const CHARLIE: &str = "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y";

    pub fn metadata() -> Metadata {
        let bytes = include_bytes!("../metadata/kreivo.scale");
        Metadata::decode(&mut &bytes[..]).unwrap()
    }

    pub fn call(metadata: &Metadata, pallet: &str, call: &str, args: &str) -> DecodedCall {
        DecodedCall::encode(metadata, pallet, call, Some(args)).unwrap()
    }

    pub fn policy(rules: &str) -> Policy {
        Policy::from_toml(&format!("endpoint = \"wss://kreivo.io\"\n{rules}")).unwrap()
    }

    fn transfer(metadata: &Metadata, to: &str, value: u128) -> DecodedCall {
        call(
            metadata,
            "Balances",
            "transfer_keep_alive",
            &format!("{{ dest: Id({to}), value: {value} }}"),
        )
    }

    fn check(policy: &Policy, call: &DecodedCall) -> anyhow::Result<Approval> {
        policy.check(&call.calls()?)
    }

    const TRANSFERS_TO_BOB: &str = r#"
        [[allow]]
        call = "Balances.transfer_keep_alive"
        max = { value = 10 }
        to = { dest = ["5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"] }
    "#;

    #[test]
    fn allows_listed_calls_within_limits() {
        let metadata = metadata();
        assert!(check(&policy(TRANSFERS_TO_BOB), &transfer(&metadata, BOB, 10)).is_ok());
    }

    #[test]
    fn enforces_max_and_to() {
        let metadata = metadata();
        let policy = policy(TRANSFERS_TO_BOB);

        let err = check(&policy, &transfer(&metadata, BOB, 11)).unwrap_err();
        assert!(err.to_string().contains("above the maximum"), "{err}");

        let err = check(&policy, &transfer(&metadata, CHARLIE, 1)).unwrap_err();
        assert!(err.to_string().contains("not in the allowed list"), "{err}");
    }

    #[test]
    fn rejects_unlisted_calls_and_empty_policies() {
        let metadata = metadata();
        let remark = call(&metadata, "System", "remark", "{ remark: 0x00 }");

        let err = check(&policy(TRANSFERS_TO_BOB), &remark).unwrap_err();
        assert!(err.to_string().contains("not allowed"), "{err}");
        assert!(check(&policy(""), &transfer(&metadata, BOB, 1)).is_err());
        assert!(check(&policy("[[allow]]\ncall = \"System.*\""), &remark).is_ok());
    }

    #[test]
    fn checks_nested_calls() {
        let metadata = metadata();
        let batch = call(
            &metadata,
            "Utility",
            "batch_all",
            &format!(
                "{{ calls: (Balances(transfer_keep_alive {{ dest: Id({BOB}), value: 1 }}), \
                 Balances(transfer_keep_alive {{ dest: Id({CHARLIE}), value: 1 }})) }}"
            ),
        );
        assert_eq!(
            batch
                .calls()
                .unwrap()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [
                "Utility.batch_all",
                "Balances.transfer_keep_alive",
                "Balances.transfer_keep_alive"
            ]
        );

        // The batch itself must be allowed…
        assert!(check(&policy(TRANSFERS_TO_BOB), &batch).is_err());
        // …and so must every call in it: Charlie isn't listed.
        let with_batch = format!("{TRANSFERS_TO_BOB}\n[[allow]]\ncall = \"Utility.batch_all\"");
        let err = check(&policy(&with_batch), &batch).unwrap_err();
        assert!(err.to_string().contains("not in the allowed list"), "{err}");

        let both = with_batch.replace(
            r#"dest = ["5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"]"#,
            &format!(r#"dest = ["{BOB}", "{CHARLIE}"]"#),
        );
        assert!(check(&policy(&both), &batch).is_ok());
    }

    #[test]
    fn hashes_are_not_accounts() {
        let metadata = metadata();
        let announce = call(
            &metadata,
            "Proxy",
            "announce",
            &format!("{{ real: Id({BOB}), call_hash: 0x{} }}", "11".repeat(32)),
        );
        let rules =
            format!("[[allow]]\ncall = \"Proxy.announce\"\nto = {{ call_hash = [\"{BOB}\"] }}");
        let err = check(&policy(&rules), &announce).unwrap_err();
        assert!(err.to_string().contains("holds no account"), "{err}");
    }

    #[test]
    fn example_policy_is_valid() {
        let example = Policy::from_toml(include_str!("../examples/policy.toml")).unwrap();
        assert!(example.proxy.is_some());
        assert_eq!(example.allow.len(), 3);
    }

    #[test]
    fn documented_policy_is_valid() {
        let doc = include_str!("../docs/policy.md");
        let example = doc
            .split("```toml\n")
            .nth(1)
            .and_then(|block| block.split("```").next())
            .expect("docs/policy.md starts with a TOML example");
        let policy = Policy::from_toml(example).unwrap();
        assert_eq!(
            policy.proxy.unwrap().proxy_type.as_deref(),
            Some("NonTransfer")
        );
        assert_eq!(policy.allow[0].max["value"], Amount(10_000_000_000_000));
    }

    /// `examples/unattended.toml`: admin operations unattended, everything else approved.
    fn unattended_policy() -> Policy {
        Policy::from_toml(include_str!("../examples/unattended.toml")).unwrap()
    }

    #[test]
    fn unattended_rules_skip_approval() {
        let metadata = metadata();
        let policy = unattended_policy();

        let add_member = call(
            &metadata,
            "Communities",
            "add_member",
            &format!("{{ who: Id({BOB}) }}"),
        );
        assert_eq!(check(&policy, &add_member).unwrap(), Approval::Unattended);

        let batch = call(
            &metadata,
            "Utility",
            "batch",
            "{ calls: (System(remark { remark: 0x01 }), Preimage(note_preimage { bytes: 0x02 })) }",
        );
        assert_eq!(check(&policy, &batch).unwrap(), Approval::Unattended);
    }

    #[test]
    fn anything_else_needs_approval() {
        let metadata = metadata();
        let policy = unattended_policy();

        // Allowed by the catch-all `*` rule, which isn't unattended.
        assert_eq!(
            check(&policy, &transfer(&metadata, BOB, 1)).unwrap(),
            Approval::Required
        );

        // One attended call is enough to need approval for the whole transaction…
        let mixed = call(
            &metadata,
            "Utility",
            "batch",
            &format!(
                "{{ calls: (System(remark {{ remark: 0x01 }}), \
                 Balances(transfer_keep_alive {{ dest: Id({BOB}), value: 1 }})) }}"
            ),
        );
        assert_eq!(check(&policy, &mixed).unwrap(), Approval::Required);

        // …including a transfer hidden in a community's `dispatch_as_account`.
        let dispatch = call(
            &metadata,
            "Communities",
            "dispatch_as_account",
            &format!("{{ call: Balances(transfer_keep_alive {{ dest: Id({BOB}), value: 1 }}) }}"),
        );
        assert_eq!(check(&policy, &dispatch).unwrap(), Approval::Required);

        // A call not allowed at all stays rejected.
        assert!(
            check(
                &self::policy(
                    r#"[[allow]]
call = "System.remark"
unattended = true"#
                ),
                &transfer(&metadata, BOB, 1)
            )
            .is_err()
        );
    }

    #[test]
    fn unattended_limits_fall_back_to_approval() {
        let metadata = metadata();
        let policy = policy(
            "[[allow]]\ncall = \"Balances.transfer_keep_alive\"\nunattended = true\n\
             max = { value = 10 }\n[[allow]]\ncall = \"*\"",
        );
        assert_eq!(
            check(&policy, &transfer(&metadata, BOB, 10)).unwrap(),
            Approval::Unattended
        );
        assert_eq!(
            check(&policy, &transfer(&metadata, BOB, 11)).unwrap(),
            Approval::Required
        );
    }

    #[test]
    fn validates_policies() {
        for bad in [
            "endpoint = \"https://kreivo.io\"",
            "endpoint = \"wss://kreivo.io\"\n[[allow]]\ncall = \"Balances\"",
            "endpoint = \"wss://kreivo.io\"\n[[allow]]\ncall = \"*.*\"",
            "endpoint = \"wss://kreivo.io\"\n[[allow]]\ncall = \"A.b\"\nto = { dest = [] }",
            "endpoint = \"wss://kreivo.io\"\n[[allow]]\ncall = \"A.b\"\nto = { dest = [\"nope\"] }",
            "endpoint = \"wss://kreivo.io\"\n[proxy]\nreal = \"nope\"",
            "endpoint = \"wss://kreivo.io\"\nunknown = 1",
            "endpoint = \"wss://kreivo.io\"\n[[allow]]\ncall = \"*\"\nunattended = true",
            "endpoint = \"wss://kreivo.io\"\n[[allow]]\ncall = \"*\"\nmax = { value = 1 }",
        ] {
            assert!(Policy::from_toml(bad).is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn amounts_beyond_toml_integers() {
        let policy = policy(
            "[[allow]]\ncall = \"Balances.transfer_keep_alive\"\nmax = { value = \"100_000_000_000_000_000_000\" }",
        );
        assert_eq!(
            policy.allow[0].max["value"],
            Amount(100_000_000_000_000_000_000)
        );
        // And they round-trip through TOML.
        assert_eq!(Policy::from_toml(&policy.to_toml()).unwrap(), policy);
    }

    #[test]
    fn wraps_calls_for_proxies() {
        let metadata = metadata();
        let proxy = ProxyConfig {
            real: ALICE.into(),
            proxy_type: None,
        };
        let wrapped = transfer(&metadata, BOB, 1)
            .wrap_in_proxy(&metadata, &proxy)
            .unwrap();
        let calls = wrapped.calls().unwrap();
        assert_eq!(
            calls.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["Proxy.proxy", "Balances.transfer_keep_alive"]
        );
        let real = calls[0].field("real").unwrap();
        assert_eq!(calls[0].accounts_in(real), [parse_account(ALICE).unwrap()]);

        let bad_type = ProxyConfig {
            real: ALICE.into(),
            proxy_type: Some("NoSuchProxyType".into()),
        };
        assert!(
            transfer(&metadata, BOB, 1)
                .wrap_in_proxy(&metadata, &bad_type)
                .is_err()
        );
    }

    #[test]
    fn describes_accounts_in_ss58() {
        let metadata = metadata();
        let call = transfer(&metadata, BOB, 42);
        let description = call.describe();
        assert!(
            description.contains(&call.format_account(&parse_account(BOB).unwrap())),
            "{description}"
        );
        assert!(description.contains("42"), "{description}");
    }
}
