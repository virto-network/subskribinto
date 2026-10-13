// Copyright (c) Virto Network
// SPDX-License-Identifier: MIT

//! Accounts kept in the operating system's secure store (macOS Keychain, Windows Credential
//! Manager, Secret Service on Linux).
//!
//! Each account is one entry holding its secret together with its [`Policy`]: keeping the policy
//! in the keystore, rather than in a file, means editing files can't loosen it. A separate entry
//! lists the account names, since keystores can't be enumerated portably.

use anyhow::{Context, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use sp_core::{Pair as _, crypto::Ss58Codec, ed25519, sr25519};
use zeroize::Zeroizing;

use crate::{
    policy::Policy,
    signer::{PairSigner, Scheme},
};

const SERVICE: &str = "subskribinto";
const INDEX: &str = "index";
const ACCOUNT_PREFIX: &str = "account:";

/// A minimal key-value view of a secure store.
pub trait Keystore: Send + Sync {
    fn get(&self, key: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>>;
    fn set(&self, key: &str, value: &[u8]) -> anyhow::Result<()>;
    fn delete(&self, key: &str) -> anyhow::Result<()>;
}

/// The operating system's secure store.
pub struct OsKeystore;

impl OsKeystore {
    fn entry(key: &str) -> anyhow::Result<keyring::Entry> {
        keyring::Entry::new(SERVICE, key)
            .map_err(|e| anyhow!("The system keystore is not available: {e}"))
    }
}

impl Keystore for OsKeystore {
    fn get(&self, key: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        match Self::entry(key)?.get_secret() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!("Cannot read `{key}` from the system keystore: {e}")),
        }
    }

    fn set(&self, key: &str, value: &[u8]) -> anyhow::Result<()> {
        Self::entry(key)?
            .set_secret(value)
            .map_err(|e| anyhow!("Cannot write `{key}` to the system keystore: {e}"))
    }

    fn delete(&self, key: &str) -> anyhow::Result<()> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!(
                "Cannot delete `{key}` from the system keystore: {e}"
            )),
        }
    }
}

/// An account as stored: its key and its policy.
#[derive(Serialize, Deserialize)]
pub struct AccountRecord {
    pub name: String,
    pub scheme: Scheme,
    pub address: String,
    /// Hex of `Pair::to_raw_vec()`: the 64-byte canonical sr25519 secret key, or the ed25519 seed.
    secret: Zeroizing<String>,
    pub policy: Policy,
}

impl AccountRecord {
    pub fn new(name: String, signer: &PairSigner, policy: Policy) -> anyhow::Result<Self> {
        validate_name(&name)?;
        policy.validate()?;
        let raw = Zeroizing::new(match signer {
            PairSigner::Sr25519(pair) => pair.to_raw_vec(),
            PairSigner::Ed25519(pair) => pair.to_raw_vec(),
        });
        Ok(Self {
            name,
            scheme: signer.scheme(),
            address: signer.account_id().to_ss58check(),
            secret: Zeroizing::new(hex::encode(&*raw)),
            policy,
        })
    }

    /// Rebuild the signer, checking it still matches the stored address.
    pub fn signer(&self) -> anyhow::Result<PairSigner> {
        let raw = Zeroizing::new(hex::decode(&*self.secret).context("Corrupted secret")?);
        let invalid = |e| anyhow!("Corrupted secret for `{}`: {e}", self.name);
        let signer: PairSigner = match self.scheme {
            Scheme::Sr25519 => sr25519::Pair::from_seed_slice(&raw)
                .map_err(invalid)?
                .into(),
            Scheme::Ed25519 => ed25519::Pair::from_seed_slice(&raw)
                .map_err(invalid)?
                .into(),
        };
        ensure!(
            signer.account_id().to_ss58check() == self.address,
            "Stored key for `{}` does not match its address",
            self.name
        );
        Ok(signer)
    }
}

/// The accounts in a [`Keystore`].
pub struct Accounts {
    store: Box<dyn Keystore>,
}

impl Accounts {
    pub fn new(store: impl Keystore + 'static) -> Self {
        Self {
            store: Box::new(store),
        }
    }

    pub fn names(&self) -> anyhow::Result<Vec<String>> {
        match self.store.get(INDEX)? {
            Some(index) => serde_json::from_slice(&index).context("Corrupted account index"),
            None => Ok(Vec::new()),
        }
    }

    pub fn get(&self, name: &str) -> anyhow::Result<AccountRecord> {
        validate_name(name)?;
        let record = self
            .store
            .get(&key(name))?
            .ok_or_else(|| anyhow!("No account named `{name}`"))?;
        serde_json::from_slice(&record).with_context(|| format!("Corrupted record for `{name}`"))
    }

    pub fn insert(&self, record: &AccountRecord) -> anyhow::Result<()> {
        let mut names = self.names()?;
        if names.contains(&record.name) || self.store.get(&key(&record.name))?.is_some() {
            bail!("An account named `{}` already exists", record.name);
        }
        self.write(record)?;
        names.push(record.name.clone());
        names.sort();
        self.write_index(&names)
    }

    pub fn set_policy(&self, name: &str, policy: Policy) -> anyhow::Result<()> {
        policy.validate()?;
        let mut record = self.get(name)?;
        record.policy = policy;
        self.write(&record)
    }

    pub fn remove(&self, name: &str) -> anyhow::Result<()> {
        validate_name(name)?;
        let names = self.names()?;
        ensure!(
            names.iter().any(|n| n == name) || self.store.get(&key(name))?.is_some(),
            "No account named `{name}`"
        );
        self.store.delete(&key(name))?;
        let names: Vec<_> = names.into_iter().filter(|n| n != name).collect();
        self.write_index(&names)
    }

    fn write(&self, record: &AccountRecord) -> anyhow::Result<()> {
        let json = Zeroizing::new(serde_json::to_vec(record)?);
        self.store.set(&key(&record.name), &json)
    }

    fn write_index(&self, names: &[String]) -> anyhow::Result<()> {
        self.store.set(INDEX, &serde_json::to_vec(names)?)
    }
}

fn key(name: &str) -> String {
    format!("{ACCOUNT_PREFIX}{name}")
}

fn validate_name(name: &str) -> anyhow::Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "Account names use 1 to 64 letters, digits, `-` or `_` (got `{name}`)"
    );
    Ok(())
}

#[cfg(test)]
pub mod memory {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;

    /// An in-memory [`Keystore`] for tests.
    #[derive(Default)]
    pub struct MemoryKeystore(Mutex<HashMap<String, Vec<u8>>>);

    impl Keystore for MemoryKeystore {
        fn get(&self, key: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
            Ok(self.0.lock().unwrap().get(key).cloned().map(Zeroizing::new))
        }

        fn set(&self, key: &str, value: &[u8]) -> anyhow::Result<()> {
            self.0
                .lock()
                .unwrap()
                .insert(key.to_owned(), value.to_vec());
            Ok(())
        }

        fn delete(&self, key: &str) -> anyhow::Result<()> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{memory::MemoryKeystore, *};

    const PHRASE: &str =
        "exact step odor long figure buffalo cereal army shallow social similar shaft";

    fn policy() -> Policy {
        Policy::deny_all("wss://kreivo.io".into()).unwrap()
    }

    #[test]
    fn round_trips_both_schemes() {
        let accounts = Accounts::new(MemoryKeystore::default());
        let sr: PairSigner = sr25519::Pair::from_string(PHRASE, None).unwrap().into();
        let ed: PairSigner = ed25519::Pair::from_string(PHRASE, None).unwrap().into();

        accounts
            .insert(&AccountRecord::new("sr".into(), &sr, policy()).unwrap())
            .unwrap();
        accounts
            .insert(&AccountRecord::new("ed".into(), &ed, policy()).unwrap())
            .unwrap();

        assert_eq!(accounts.names().unwrap(), ["ed", "sr"]);
        assert_eq!(
            accounts.get("sr").unwrap().signer().unwrap().account_id(),
            sr.account_id()
        );
        assert_eq!(
            accounts.get("ed").unwrap().signer().unwrap().account_id(),
            ed.account_id()
        );
        assert!(matches!(
            accounts.get("ed").unwrap().scheme,
            Scheme::Ed25519
        ));
    }

    #[test]
    fn refuses_duplicates_and_bad_names() {
        let accounts = Accounts::new(MemoryKeystore::default());
        let signer: PairSigner = sr25519::Pair::from_string(PHRASE, None).unwrap().into();

        accounts
            .insert(&AccountRecord::new("ops".into(), &signer, policy()).unwrap())
            .unwrap();
        let again = AccountRecord::new("ops".into(), &signer, policy()).unwrap();
        assert!(accounts.insert(&again).is_err());
        assert!(AccountRecord::new("no spaces".into(), &signer, policy()).is_err());
        assert!(accounts.get("missing").is_err());
    }

    #[test]
    fn updates_policy_and_removes() {
        let accounts = Accounts::new(MemoryKeystore::default());
        let signer: PairSigner = sr25519::Pair::from_string(PHRASE, None).unwrap().into();
        accounts
            .insert(&AccountRecord::new("ops".into(), &signer, policy()).unwrap())
            .unwrap();

        let updated = Policy::from_toml(
            "endpoint = \"wss://kreivo.io\"\n[[allow]]\ncall = \"System.remark\"\n",
        )
        .unwrap();
        accounts.set_policy("ops", updated.clone()).unwrap();
        assert_eq!(accounts.get("ops").unwrap().policy, updated);

        accounts.remove("ops").unwrap();
        assert!(accounts.names().unwrap().is_empty());
        assert!(accounts.get("ops").is_err());
    }

    #[test]
    fn rejects_tampered_records() {
        let store = MemoryKeystore::default();
        let accounts = Accounts::new(store);
        let signer: PairSigner = sr25519::Pair::from_string(PHRASE, None).unwrap().into();
        let mut record = AccountRecord::new("ops".into(), &signer, policy()).unwrap();
        record.address = "5F99BTMyMj5szz7zvhHpSi5QC5uj4DCtTszoHz8m1oer65gA".into();
        accounts.insert(&record).unwrap();
        assert!(accounts.get("ops").unwrap().signer().is_err());
    }
}
