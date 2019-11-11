#[macro_export]
/// implement parity codec for type
macro_rules! impl_codec_for {
    ($type:ty) => {
        impl codec::Encode for $type {
            fn encode(&self) -> Vec<u8> {
                let encoded = bincode::serialize(&self).unwrap();
                codec::Encode::encode(&encoded)
            }
        }

        impl codec::Decode for $type {
            fn decode<I: codec::Input>(value: &mut I) -> std::result::Result<Self, codec::Error> {
                let decoded: Vec<u8> = codec::Decode::decode(value)?;
                bincode::deserialize(decoded.as_slice()).map_err(|_| {
                    codec::Error::from("parity-scale-codec decode error in threshold_crypto")
                })
            }
        }
    };
}

use crate::{Ciphertext, DecryptionShare, PublicKey, PublicKeySet, Signature};

impl_codec_for!(PublicKey);
impl_codec_for!(Signature);
impl_codec_for!(DecryptionShare);
impl_codec_for!(PublicKeySet);
impl_codec_for!(Ciphertext);
