// Copyright (c) Virto Network
// SPDX-License-Identifier: MIT

//! An append-only log of every signature made with a stored account, as JSON lines.
//!
//! Each signature writes a `signing` entry before anything is submitted, and a `finalized` or
//! `failed` entry after. If the first entry can't be written, nothing is signed: unattended
//! signatures must always leave a trace.

use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::Serialize;

use crate::{
    guard::Request,
    policy::Approval,
    tx::{Failure, Outcome},
};

pub struct AuditLog {
    path: PathBuf,
}

#[derive(Serialize)]
struct Entry<'a> {
    /// Seconds since the Unix epoch.
    time: u64,
    event: &'a str,
    account: &'a str,
    address: &'a str,
    endpoint: &'a str,
    approval: Approval,
    calls: &'a [String],
    call_data: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_hash: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

impl AuditLog {
    /// The log in the user's local data directory, e.g.
    /// `~/Library/Application Support/subskribinto/audit.jsonl` on macOS.
    pub fn default_location() -> anyhow::Result<Self> {
        let dir = dirs::data_local_dir()
            .context("Cannot find the local data directory for the audit log")?;
        Ok(Self::at(dir.join("subskribinto").join("audit.jsonl")))
    }

    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record a signature about to happen. Callers must not sign if this fails.
    pub fn signing(&self, request: &Request, approval: Approval) -> anyhow::Result<()> {
        self.write(request, approval, "signing", None, None, None)
    }

    /// Record how a signature ended.
    pub fn finished(
        &self,
        request: &Request,
        approval: Approval,
        outcome: &Result<Outcome, Failure>,
    ) -> anyhow::Result<()> {
        match outcome {
            Ok(outcome) => self.write(
                request,
                approval,
                "finalized",
                Some(&outcome.tx_hash),
                Some(&outcome.block_hash),
                None,
            ),
            Err(failure) => self.write(
                request,
                approval,
                "failed",
                failure.tx_hash.as_deref(),
                None,
                Some(&format!("{:#}", failure.error)),
            ),
        }
    }

    fn write(
        &self,
        request: &Request,
        approval: Approval,
        event: &str,
        tx_hash: Option<&str>,
        block_hash: Option<&str>,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        let calls = request.call_names()?;
        let entry = Entry {
            time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
            event,
            account: &request.account.name,
            address: &request.account.address,
            endpoint: &request.account.policy.endpoint,
            approval,
            calls: &calls,
            call_data: &format!("0x{}", hex::encode(request.call.bytes())),
            tx_hash,
            block_hash,
            error,
        };

        let mut line = serde_json::to_vec(&entry)?;
        line.push(b'\n');
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("Cannot create {}", dir.display()))?;
        }
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut file| file.write_all(&line))
            .with_context(|| format!("Cannot write the audit log at {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use sp_core::{Pair as _, sr25519};

    use super::*;
    use crate::{
        call::DecodedCall,
        policy::tests::{BOB, metadata, policy},
        signer::PairSigner,
        store::AccountRecord,
    };

    #[test]
    fn records_intent_and_outcome() {
        let metadata = metadata();
        let signer: PairSigner = sr25519::Pair::from_string("//Alice", None).unwrap().into();
        let record = AccountRecord::new("ops".into(), &signer, policy("")).unwrap();
        let call = DecodedCall::encode(
            &metadata,
            "Balances",
            "transfer_keep_alive",
            Some(&format!("{{ dest: Id({BOB}), value: 1 }}")),
        )
        .unwrap();
        let request = Request::new(record, &metadata, call.bytes()).unwrap();

        let path = std::env::temp_dir()
            .join(format!("subskribinto-audit-{}", std::process::id()))
            .join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        let log = AuditLog::at(path.clone());

        log.signing(&request, Approval::Required).unwrap();
        log.finished(
            &request,
            Approval::Required,
            &Err(Failure {
                tx_hash: Some("0xabc".into()),
                error: anyhow::anyhow!("dropped"),
            }),
        )
        .unwrap();

        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["event"], "signing");
        assert_eq!(lines[0]["account"], "ops");
        assert_eq!(lines[0]["approval"], "required");
        assert_eq!(lines[0]["calls"][0], "Balances.transfer_keep_alive");
        assert_eq!(lines[1]["event"], "failed");
        assert_eq!(lines[1]["error"], "dropped");
        assert_eq!(
            lines[1]["tx_hash"], "0xabc",
            "a submitted transaction keeps its hash"
        );
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
