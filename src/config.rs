use codec::Encode;
use scale_info::PortableRegistry;
use sp_core::crypto::AccountId32;
use subxt::{
    Config,
    config::{
        ExtrinsicParams, ExtrinsicParamsEncoder, TransactionExtension,
        substrate::{DynamicHasher256, SubstrateHeader},
        transaction_extensions,
    },
    utils::{MultiAddress, MultiSignature},
};

pub struct PassAuthenticate(Option<u32>);

impl ExtrinsicParamsEncoder for PassAuthenticate {
    fn encode_value_to(&self, v: &mut Vec<u8>) {
        self.0.encode_to(v)
    }
}

impl<T: Config> ExtrinsicParams<T> for PassAuthenticate {
    type Params = ();

    fn new(
        _: &subxt::client::ClientState<T>,
        _params: Self::Params,
    ) -> Result<Self, subxt::config::ExtrinsicParamsError> {
        Ok(Self(None))
    }
}

impl<T: Config> TransactionExtension<T> for PassAuthenticate {
    // The actual type is obviosuly more complex, but this
    // implementation will just completely ignore it for the sake
    // of simplicity, since we don't actually use it.
    type Decoded = Option<u32>;

    fn matches(identifier: &str, _type_id: u32, _types: &PortableRegistry) -> bool {
        identifier == "PassAuthenticate"
    }
}

pub type KreivoExtrinsicParams<T> = transaction_extensions::AnyOf<
    T,
    (
        PassAuthenticate,
        transaction_extensions::CheckSpecVersion,
        transaction_extensions::CheckTxVersion,
        transaction_extensions::CheckNonce,
        transaction_extensions::CheckGenesis<T>,
        transaction_extensions::CheckMortality<T>,
        transaction_extensions::ChargeAssetTxPayment<T>,
        transaction_extensions::ChargeTransactionPayment,
        transaction_extensions::CheckMetadataHash,
    ),
>;

pub struct KreivoConfig;

impl Config for KreivoConfig {
    type AccountId = AccountId32;
    type Address = MultiAddress<Self::AccountId, u32>;
    type Signature = MultiSignature;
    type Hasher = DynamicHasher256;
    type Header = SubstrateHeader<u32, DynamicHasher256>;
    type ExtrinsicParams = KreivoExtrinsicParams<Self>;
    type AssetId = u32;
}
