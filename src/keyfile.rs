//! Decoding of JSON key files exported by polkadot{.js} (extension, apps, keyring).
//!
//! The `encoded` field holds, for the current (v3) format:
//!
//! ```text
//! salt (32) | N (u32 LE) | p (u32 LE) | r (u32 LE) | nonce (24) | secretbox(pkcs8)
//! ```
//!
//! where the secretbox key is the first 32 bytes of `scrypt(password, salt, N, r, p)`.
//! The decrypted PKCS#8 body is `header (16) | secret key | divider (5) | public key (32)`.
//!
//! sr25519 secret keys are stored as 64 bytes in schnorrkel's *ed25519 layout* (the secret
//! scalar multiplied by the cofactor), so they must be read with
//! [`schnorrkel::SecretKey::from_ed25519_bytes`], not with `sr25519::Pair::from_seed_slice`.

use std::path::Path;

use anyhow::{Context, anyhow, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use crypto_secretbox::{KeyInit, XSalsa20Poly1305, aead::Aead};
use serde::Deserialize;
use sp_core::{
    Pair as _,
    crypto::{AccountId32, Ss58Codec},
    ed25519, sr25519,
};

use crate::signer::PairSigner;

const PKCS8_HEADER: [u8; 16] = [48, 83, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32];
const PKCS8_DIVIDER: [u8; 5] = [161, 35, 3, 33, 0];
const PUBLIC_KEY_LENGTH: usize = 32;
const SECRET_KEY_LENGTH: usize = 64;
const SEED_LENGTH: usize = 32;

const SALT_LENGTH: usize = 32;
const SCRYPT_LENGTH: usize = SALT_LENGTH + 3 * 4;
const NONCE_LENGTH: usize = 24;
/// `(N, p, r)` presets accepted by polkadot{.js}; anything else is rejected, like it does.
const ALLOWED_SCRYPT_PARAMS: [(u32, u32, u32); 6] = [
    (1 << 13, 10, 8),
    (1 << 14, 5, 8),
    (1 << 15, 3, 8),
    (1 << 15, 1, 8),
    (1 << 16, 2, 8),
    (1 << 17, 1, 8),
];

#[derive(Debug, Deserialize)]
pub struct KeyFile {
    encoded: String,
    encoding: Encoding,
    address: String,
    #[serde(default)]
    meta: Meta,
}

#[derive(Debug, Deserialize)]
struct Encoding {
    content: OneOrMany,
    #[serde(rename = "type")]
    kind: OneOrMany,
}

#[derive(Debug, Default, Deserialize)]
struct Meta {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn contains(&self, value: &str) -> bool {
        match self {
            Self::One(v) => v == value,
            Self::Many(vs) => vs.iter().any(|v| v == value),
        }
    }
}

impl KeyFile {
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read key file {}", path.display()))?;
        Self::from_json(&json)
    }

    pub fn from_json(json: &str) -> anyhow::Result<Self> {
        serde_json::from_str(json).context("Not a polkadot{.js} key file")
    }

    /// The address and (if any) name of the account, for display purposes.
    pub fn describe(&self) -> String {
        match &self.meta.name {
            Some(name) => format!("{} ({name})", self.address),
            None => self.address.clone(),
        }
    }

    /// Whether unlocking the file requires a password.
    pub fn is_encrypted(&self) -> bool {
        self.encoding.kind.contains("xsalsa20-poly1305")
    }

    /// Decrypt the key and check it matches the file's `address`.
    pub fn unlock(&self, password: &str) -> anyhow::Result<PairSigner> {
        let pkcs8 = self.decrypt(password)?;
        let (secret, public) = decode_pkcs8(&pkcs8)?;

        // Same rule as polkadot{.js}: `["pkcs8", <type>]`, anything else is a legacy ed25519 key.
        let key_type = match &self.encoding.content {
            OneOrMany::Many(content) => content.get(1).map(String::as_str).unwrap_or("ed25519"),
            OneOrMany::One(_) => "ed25519",
        };
        let signer = match key_type {
            "sr25519" => PairSigner::Sr25519(sr25519_from_secret(secret)?),
            "ed25519" => PairSigner::Ed25519(
                ed25519::Pair::from_seed_slice(&secret[..SEED_LENGTH])
                    .map_err(|e| anyhow!("Invalid ed25519 secret key: {e}"))?,
            ),
            other => bail!("Unsupported key type `{other}` (only sr25519 and ed25519 are)"),
        };

        let account = signer.account_id();
        ensure!(
            <AccountId32 as AsRef<[u8]>>::as_ref(&account) == public,
            "Decrypted secret key does not match the public key stored in the file"
        );
        let (expected, _) = AccountId32::from_ss58check_with_version(&self.address)
            .map_err(|e| anyhow!("Invalid address `{}` in key file: {e:?}", self.address))?;
        ensure!(
            account == expected,
            "Decrypted key belongs to {}, but the file is for {}",
            account.to_ss58check(),
            self.address
        );

        Ok(signer)
    }

    fn decrypt(&self, password: &str) -> anyhow::Result<Vec<u8>> {
        let encoded = match self.encoded.strip_prefix("0x").map(hex::decode) {
            Some(Ok(bytes)) => bytes,
            _ => BASE64
                .decode(&self.encoded)
                .context("`encoded` is neither hex nor base64")?,
        };

        if !self.is_encrypted() {
            return Ok(encoded);
        }
        ensure!(!password.is_empty(), "A password is required to unlock this key file");

        let mut data = encoded.as_slice();
        let mut key = [0u8; 32];
        if self.encoding.kind.contains("scrypt") {
            ensure!(data.len() >= SCRYPT_LENGTH, "Key file is too short");
            let (scrypt_header, rest) = data.split_at(SCRYPT_LENGTH);
            derive_scrypt_key(password, scrypt_header, &mut key)?;
            data = rest;
        } else {
            // Legacy files use the raw password, truncated or zero-padded to 32 bytes.
            let bytes = password.as_bytes();
            let len = bytes.len().min(key.len());
            key[..len].copy_from_slice(&bytes[..len]);
        }

        ensure!(data.len() > NONCE_LENGTH, "Key file is too short");
        let (nonce, ciphertext) = data.split_at(NONCE_LENGTH);
        XSalsa20Poly1305::new(&key.into())
            .decrypt(nonce.into(), ciphertext)
            .map_err(|_| anyhow!("Unable to decrypt key file: wrong password?"))
    }
}

fn derive_scrypt_key(password: &str, header: &[u8], out: &mut [u8; 32]) -> anyhow::Result<()> {
    let (salt, params) = header.split_at(SALT_LENGTH);
    let read_u32 = |i: usize| u32::from_le_bytes(params[i * 4..i * 4 + 4].try_into().unwrap());
    let (n, p, r) = (read_u32(0), read_u32(1), read_u32(2));
    ensure!(
        ALLOWED_SCRYPT_PARAMS.contains(&(n, p, r)),
        "Unsupported scrypt parameters (N = {n}, p = {p}, r = {r})"
    );

    // polkadot{.js} derives 64 bytes and keeps the first 32, which is what deriving 32 yields.
    let params = scrypt::Params::new(n.trailing_zeros() as u8, r, p, out.len())
        .map_err(|e| anyhow!("Invalid scrypt parameters: {e}"))?;
    scrypt::scrypt(password.as_bytes(), salt, &params, out)
        .map_err(|e| anyhow!("scrypt failed: {e}"))
}

/// Split a decrypted PKCS#8 body into `(secret key, public key)`.
fn decode_pkcs8(pkcs8: &[u8]) -> anyhow::Result<(&[u8], &[u8])> {
    let body = pkcs8
        .strip_prefix(PKCS8_HEADER.as_slice())
        .context("Invalid PKCS#8 header in decrypted key")?;

    // Current format stores a 64-byte secret key, older ones a 32-byte seed.
    for secret_len in [SECRET_KEY_LENGTH, SEED_LENGTH] {
        let Some((secret, rest)) = body.split_at_checked(secret_len) else {
            continue;
        };
        if let Some(public) = rest.strip_prefix(PKCS8_DIVIDER.as_slice()) {
            ensure!(public.len() >= PUBLIC_KEY_LENGTH, "Truncated public key in decrypted key");
            return Ok((secret, &public[..PUBLIC_KEY_LENGTH]));
        }
    }
    bail!("Invalid PKCS#8 divider in decrypted key")
}

/// Build an sr25519 pair from a secret as polkadot{.js} stores and exports it: either a 32-byte
/// mini secret (seed) or a 64-byte secret key in schnorrkel's ed25519 layout.
pub fn sr25519_from_secret(secret: &[u8]) -> anyhow::Result<sr25519::Pair> {
    match secret.len() {
        SEED_LENGTH => sr25519::Pair::from_seed_slice(secret)
            .map_err(|e| anyhow!("Invalid sr25519 seed: {e}")),
        SECRET_KEY_LENGTH => schnorrkel::SecretKey::from_ed25519_bytes(secret)
            .map(sr25519::Pair::from)
            .map_err(|e| anyhow!("Invalid sr25519 secret key: {e}")),
        len => bail!("sr25519 secrets must be 32 or 64 bytes (got {len})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SR25519_FILE: &str = include_str!("../fixtures/pjs-sr25519.json");
    const ED25519_FILE: &str = include_str!("../fixtures/pjs-ed25519.json");
    // Throwaway test account, created only for these fixtures.
    const PHRASE: &str = "exact step odor long figure buffalo cereal army shallow social similar shaft";
    const PASSWORD: &str = "testacct";

    #[test]
    fn unlocks_sr25519_file() {
        let file = KeyFile::from_json(SR25519_FILE).unwrap();
        let signer = file.unlock(PASSWORD).unwrap();
        let expected = sr25519::Pair::from_string(PHRASE, None).unwrap();

        assert!(matches!(signer, PairSigner::Sr25519(_)));
        assert_eq!(
            signer.account_id().to_ss58check(),
            "5H6HuzccfPDestVUFEeaNBbRCT9tCbGH1Cp1XT1DDzj3Yeq3"
        );
        assert_eq!(signer.account_id(), AccountId32::from(expected.public()));

        let PairSigner::Sr25519(pair) = signer else { unreachable!() };
        let signature = pair.sign(b"payload");
        assert!(sr25519::Pair::verify(&signature, b"payload", &expected.public()));
    }

    #[test]
    fn unlocks_ed25519_file() {
        let file = KeyFile::from_json(ED25519_FILE).unwrap();
        let signer = file.unlock(PASSWORD).unwrap();
        let expected = ed25519::Pair::from_string(PHRASE, None).unwrap();

        assert!(matches!(signer, PairSigner::Ed25519(_)));
        assert_eq!(
            signer.account_id().to_ss58check(),
            "5F99BTMyMj5szz7zvhHpSi5QC5uj4DCtTszoHz8m1oer65gA"
        );
        assert_eq!(signer.account_id(), AccountId32::from(expected.public()));
    }

    #[test]
    fn rejects_wrong_password() {
        let file = KeyFile::from_json(SR25519_FILE).unwrap();
        let err = file.unlock("not-the-password").unwrap_err();
        assert!(err.to_string().contains("wrong password"), "{err}");
        assert!(file.unlock("").is_err());
    }

    #[test]
    fn rejects_mismatched_address() {
        let json = SR25519_FILE.replace(
            "5H6HuzccfPDestVUFEeaNBbRCT9tCbGH1Cp1XT1DDzj3Yeq3",
            "5F99BTMyMj5szz7zvhHpSi5QC5uj4DCtTszoHz8m1oer65gA",
        );
        let err = KeyFile::from_json(&json).unwrap().unlock(PASSWORD).unwrap_err();
        assert!(err.to_string().contains("but the file is for"), "{err}");
    }

    #[test]
    fn sr25519_secret_in_ed25519_layout() {
        // What `pjs_decode` used to print for the fixture: the raw 64-byte secret key.
        let secret = hex::decode(
            "48b3552099c31059d3fa93465fbd38f4160781db0d3012d0381684682ba3db4b\
             09b2701244b4f9987cfe9c566cb82c7282515e3c26f41c9c25e0a5979775166c",
        )
        .unwrap();
        let pair = sr25519_from_secret(&secret).unwrap();
        let expected = sr25519::Pair::from_string(PHRASE, None).unwrap();
        assert_eq!(pair.public(), expected.public());

        // `from_seed_slice` reads it as a canonical scalar, which is the original bug.
        assert!(sr25519::Pair::from_seed_slice(&secret).is_err());
    }
}
