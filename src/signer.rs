use sp_core::{Pair, crypto::AccountId32, sr25519};
use subxt::{Config, tx::Signer, utils::MultiSignature};

pub struct PairSigner(sr25519::Pair);
impl From<sr25519::Pair> for PairSigner {
    fn from(value: sr25519::Pair) -> Self {
        Self(value)
    }
}

impl<T> Signer<T> for PairSigner
where
    T: Config<AccountId = AccountId32, Signature = MultiSignature>,
{
    fn account_id(&self) -> <T as Config>::AccountId {
        AccountId32::new(self.0.public().0)
    }

    fn sign(&self, signer_payload: &[u8]) -> <T as Config>::Signature {
        MultiSignature::Sr25519(self.0.sign(signer_payload).0)
    }
}
