use sp_core::{
    Pair,
    crypto::{AccountId32, Ss58Codec},
    ed25519, sr25519,
};
use subxt::{Config, tx::Signer, utils::MultiSignature};

pub enum PairSigner {
    Sr25519(sr25519::Pair),
    Ed25519(ed25519::Pair),
}

impl From<sr25519::Pair> for PairSigner {
    fn from(value: sr25519::Pair) -> Self {
        Self::Sr25519(value)
    }
}

impl From<ed25519::Pair> for PairSigner {
    fn from(value: ed25519::Pair) -> Self {
        Self::Ed25519(value)
    }
}

impl PairSigner {
    pub fn account_id(&self) -> AccountId32 {
        match self {
            Self::Sr25519(pair) => pair.public().into(),
            Self::Ed25519(pair) => pair.public().into(),
        }
    }
}

// Shows the scheme and address only, never key material.
impl std::fmt::Debug for PairSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = match self {
            Self::Sr25519(_) => "Sr25519",
            Self::Ed25519(_) => "Ed25519",
        };
        write!(f, "PairSigner::{scheme}({})", self.account_id().to_ss58check())
    }
}

impl<T> Signer<T> for PairSigner
where
    T: Config<AccountId = AccountId32, Signature = MultiSignature>,
{
    fn account_id(&self) -> <T as Config>::AccountId {
        PairSigner::account_id(self)
    }

    fn sign(&self, signer_payload: &[u8]) -> <T as Config>::Signature {
        match self {
            Self::Sr25519(pair) => MultiSignature::Sr25519(pair.sign(signer_payload).0),
            Self::Ed25519(pair) => MultiSignature::Ed25519(pair.sign(signer_payload).0),
        }
    }
}
