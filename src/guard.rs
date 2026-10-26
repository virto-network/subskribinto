// Copyright (c) Virto Network
// SPDX-License-Identifier: MIT

//! The single path through which a stored account signs anything, from the CLI or over MCP:
//! decode the call with the chain's metadata, check it against the account's policy, wrap it for
//! the configured proxy, and describe exactly what will be signed so a human can approve it.

use subxt::Metadata;

use crate::{
    audit::AuditLog,
    call::DecodedCall,
    policy::{Approval, ProxyConfig, parse_account},
    store::AccountRecord,
    tx::{self, Api, Failure, Outcome, Progress},
};

/// Longest call description put in an operating-system approval dialog.
const MAX_REASON_LEN: usize = 400;

pub struct Request {
    pub account: AccountRecord,
    /// The call as requested.
    pub call: DecodedCall,
    /// The call as it will be signed: `call`, or `call` wrapped in `Proxy.proxy`.
    pub signed: DecodedCall,
}

impl Request {
    pub fn new(account: AccountRecord, metadata: &Metadata, call: &[u8]) -> anyhow::Result<Self> {
        let call = DecodedCall::decode(metadata, call)?;
        let signed = match &account.policy.proxy {
            Some(proxy) => call.wrap_in_proxy(metadata, proxy)?,
            None => DecodedCall::decode(metadata, call.bytes())?,
        };
        Ok(Self {
            account,
            call,
            signed,
        })
    }

    /// Check the requested call, and every call nested in it, against the account's policy, and
    /// whether it needs the user's approval.
    pub fn check(&self) -> anyhow::Result<Approval> {
        self.account.policy.check(&self.call.calls()?)
    }

    /// Sign and submit the request, recording it in the audit log before and after. Call only
    /// once the policy allowed it and, when required, the user approved it.
    pub async fn sign(
        &self,
        api: &Api,
        approval: Approval,
        audit: &AuditLog,
        progress: impl FnMut(Progress<'_>),
    ) -> anyhow::Result<Outcome> {
        audit.signing(self, approval)?;
        let outcome = match self.account.signer() {
            Ok(signer) => tx::sign_and_submit(api, &self.signed, &signer, progress).await,
            Err(error) => Err(Failure {
                tx_hash: None,
                error,
            }),
        };
        if let Err(e) = audit.finished(self, approval, &outcome) {
            eprintln!("warning: {e:#}");
        }
        Ok(outcome?)
    }

    /// `Pallet.call` of the requested call and of every call nested in it.
    pub fn call_names(&self) -> anyhow::Result<Vec<String>> {
        Ok(self.call.calls()?.iter().map(ToString::to_string).collect())
    }

    pub fn proxy(&self) -> Option<&ProxyConfig> {
        self.account.policy.proxy.as_ref()
    }

    /// Everything a human needs to approve the request.
    pub fn summary(&self) -> String {
        let account = &self.account;
        let mut summary = format!(
            "Sign and submit as `{}` ({}) on {}",
            account.name, account.address, account.policy.endpoint
        );
        if let Some(proxy) = self.proxy() {
            summary.push_str(&format!("\nas a proxy of {}", self.format_real(proxy)));
            if let Some(proxy_type) = &proxy.proxy_type {
                summary.push_str(&format!(" (type {proxy_type})"));
            }
        }
        summary.push_str(":\n\n");
        summary.push_str(&self.call.describe());
        summary
    }

    /// A one-line reason for the operating system's approval dialog.
    pub fn reason(&self) -> String {
        let mut call = self
            .call
            .describe()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if call.len() > MAX_REASON_LEN {
            let cut = (0..=MAX_REASON_LEN)
                .rev()
                .find(|&i| call.is_char_boundary(i))
                .unwrap_or(0);
            call.truncate(cut);
            call.push('…');
        }
        let proxy = self
            .proxy()
            .map(|proxy| format!(" for {}", self.format_real(proxy)))
            .unwrap_or_default();
        format!(
            "sign as `{}`{proxy} on {}: {call}",
            self.account.name, self.account.policy.endpoint
        )
    }

    fn format_real(&self, proxy: &ProxyConfig) -> String {
        parse_account(&proxy.real)
            .map(|real| self.call.format_account(&real))
            .unwrap_or_else(|_| proxy.real.clone())
    }
}

#[cfg(test)]
mod tests {
    use sp_core::{Pair as _, sr25519};

    use super::*;
    use crate::{
        policy::tests::{ALICE, BOB, metadata, policy},
        signer::PairSigner,
    };

    const PHRASE: &str =
        "exact step odor long figure buffalo cereal army shallow social similar shaft";

    fn record(rules: &str) -> AccountRecord {
        let signer: PairSigner = sr25519::Pair::from_string(PHRASE, None).unwrap().into();
        AccountRecord::new("ops".into(), &signer, policy(rules)).unwrap()
    }

    fn transfer(metadata: &Metadata) -> Vec<u8> {
        DecodedCall::encode(
            metadata,
            "Balances",
            "transfer_keep_alive",
            Some(&format!("{{ dest: Id({BOB}), value: 7 }}")),
        )
        .unwrap()
        .bytes()
        .to_vec()
    }

    #[test]
    fn checks_the_requested_call_and_signs_the_wrapped_one() {
        let metadata = metadata();
        let rules = format!(
            "[proxy]\nreal = \"{ALICE}\"\n[[allow]]\ncall = \"Balances.transfer_keep_alive\""
        );
        let request = Request::new(record(&rules), &metadata, &transfer(&metadata)).unwrap();

        // The policy applies to what was asked for, not to the `Proxy.proxy` wrapper.
        request.check().unwrap();
        assert_eq!(
            request.call_names().unwrap(),
            ["Balances.transfer_keep_alive"]
        );
        assert_eq!(
            request.signed.calls().unwrap()[0].to_string(),
            "Proxy.proxy",
            "signed call must be wrapped"
        );

        let summary = request.summary();
        assert!(summary.contains("as a proxy of"), "{summary}");
        assert!(summary.contains("transfer_keep_alive"), "{summary}");
        let reason = request.reason();
        assert!(reason.starts_with("sign as `ops` for "), "{reason}");
        assert!(!reason.contains('\n'), "{reason}");
    }

    #[test]
    fn without_proxy_signs_the_call_as_is() {
        let metadata = metadata();
        let call = transfer(&metadata);
        let request = Request::new(record(""), &metadata, &call).unwrap();
        assert_eq!(request.signed.bytes(), call);
        assert!(request.check().is_err(), "an empty policy allows nothing");
    }
}
