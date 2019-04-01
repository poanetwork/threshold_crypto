//! Serialization and deserialization implementations for group and field elements.

pub use self::field_vec::FieldWrap;

use std::borrow::Cow;
use std::ops::Deref;

use crate::G1;
use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::poly::{coeff_pos, BivarCommitment};
use crate::serde_impl::serialize_secret_internal::SerializeSecret;

const ERR_DEG: &str = "commitment degree does not match coefficients";

mod serialize_secret_internal {
    use serde::Serializer;

    /// To avoid deriving [`Serialize`] automatically for structs containing secret keys this trait
    /// should be implemented instead. It only enables explicit serialization through
    /// [`::serde_impls::SerdeSecret`].
    pub trait SerializeSecret {
        fn serialize_secret<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>;
    }

    impl<T: SerializeSecret> SerializeSecret for &T {
        fn serialize_secret<S: Serializer>(
            &self,
            serializer: S,
        ) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> {
            (*self).serialize_secret(serializer)
        }
    }
}

/// `SerdeSecret` is a wrapper struct for serializing and deserializing secret keys. Due to security
/// concerns serialize shouldn't be implemented for secret keys to avoid accidental leakage.
///
/// Whenever this struct is used the integrity of security boundaries should be checked carefully.
pub struct SerdeSecret<T>(pub T);

impl<T> Deref for SerdeSecret<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner()
    }
}

impl<T> SerdeSecret<T> {
    /// Returns the actual secret from the wrapper
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Returns a reference to the actual secret contained in the wrapper
    pub fn inner(&self) -> &T {
        &self.0
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for SerdeSecret<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(SerdeSecret(Deserialize::deserialize(deserializer)?))
    }
}

impl<T: SerializeSecret> Serialize for SerdeSecret<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize_secret(serializer)
    }
}

impl<'de> Deserialize<'de> for crate::SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use crate::{Fr, FrRepr};
        use pairing::PrimeField;
        use serde::de;

        let mut fr = match Fr::from_repr(FrRepr(Deserialize::deserialize(deserializer)?)) {
            Ok(x) => x,
            Err(pairing::PrimeFieldDecodingError::NotInField(_)) => {
                return Err(de::Error::invalid_value(
                    de::Unexpected::Other(&"Number outside of prime field."),
                    &"Valid prime field element.",
                ));
            }
        };

        Ok(crate::SecretKey::from_mut(&mut fr))
    }
}

impl SerializeSecret for crate::SecretKey {
    fn serialize_secret<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use pairing::PrimeField;

        Serialize::serialize(&self.0.into_repr().0, serializer)
    }
}

impl<'de> Deserialize<'de> for crate::SecretKeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(crate::SecretKeyShare(Deserialize::deserialize(
            deserializer,
        )?))
    }
}

impl SerializeSecret for crate::SecretKeyShare {
    fn serialize_secret<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize_secret(serializer)
    }
}

/// A type with the same content as `BivarCommitment`, but that has not been validated yet.
#[derive(Serialize, Deserialize)]
struct WireBivarCommitment<'a> {
    /// The polynomial's degree in each of the two variables.
    degree: usize,
    /// The commitments to the coefficients.
    #[serde(with = "projective_vec")]
    coeff: Cow<'a, [G1]>,
}

impl Serialize for BivarCommitment {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        WireBivarCommitment {
            degree: self.degree,
            coeff: Cow::Borrowed(&self.coeff),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for BivarCommitment {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let WireBivarCommitment { degree, coeff } = Deserialize::deserialize(d)?;
        if coeff_pos(degree, degree).and_then(|l| l.checked_add(1)) != Some(coeff.len()) {
            return Err(D::Error::custom(ERR_DEG));
        }
        Ok(BivarCommitment {
            degree,
            coeff: coeff.into(),
        })
    }
}

/// Serialization and deserialization of a group element's compressed representation.
pub(crate) mod projective {
    use std::fmt;
    use std::marker::PhantomData;

    use pairing::{CurveAffine, CurveProjective, EncodedPoint};
    use serde::de::{Error as DeserializeError, SeqAccess, Visitor};
    use serde::{ser::SerializeTuple, Deserializer, Serializer};

    const ERR_CODE: &str = "deserialized bytes don't encode a group element";

    pub fn serialize<S, C>(c: &C, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        C: CurveProjective,
    {
        let len = <C::Affine as CurveAffine>::Compressed::size();
        let mut tup = s.serialize_tuple(len)?;
        for byte in c.into_affine().into_compressed().as_ref() {
            tup.serialize_element(byte)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D, C>(d: D) -> Result<C, D::Error>
    where
        D: Deserializer<'de>,
        C: CurveProjective,
    {
        struct TupleVisitor<C> {
            _ph: PhantomData<C>,
        }

        impl<'de, C: CurveProjective> Visitor<'de> for TupleVisitor<C> {
            type Value = C;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let len = <C::Affine as CurveAffine>::Compressed::size();
                write!(f, "a tuple of size {}", len)
            }

            #[inline]
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<C, A::Error> {
                let mut compressed = <C::Affine as CurveAffine>::Compressed::empty();
                for (i, byte) in compressed.as_mut().iter_mut().enumerate() {
                    let len_err = || DeserializeError::invalid_length(i, &self);
                    *byte = seq.next_element()?.ok_or_else(len_err)?;
                }
                let to_err = |_| DeserializeError::custom(ERR_CODE);
                Ok(compressed.into_affine().map_err(to_err)?.into_projective())
            }
        }

        let len = <C::Affine as CurveAffine>::Compressed::size();
        d.deserialize_tuple(len, TupleVisitor { _ph: PhantomData })
    }
}

/// Serialization and deserialization of vectors of projective curve elements.
pub(crate) mod projective_vec {
    use std::borrow::Borrow;
    use std::iter::FromIterator;
    use std::marker::PhantomData;

    use pairing::CurveProjective;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::projective;

    /// A wrapper type to facilitate serialization and deserialization of group elements.
    struct CurveWrap<C, B>(B, PhantomData<C>);

    impl<C, B> CurveWrap<C, B> {
        fn new(c: B) -> Self {
            CurveWrap(c, PhantomData)
        }
    }

    impl<C: CurveProjective, B: Borrow<C>> Serialize for CurveWrap<C, B> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            projective::serialize(self.0.borrow(), s)
        }
    }

    impl<'de, C: CurveProjective> Deserialize<'de> for CurveWrap<C, C> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            Ok(CurveWrap::new(projective::deserialize(d)?))
        }
    }

    pub fn serialize<S, C, T>(vec: T, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        C: CurveProjective,
        T: AsRef<[C]>,
    {
        let wrap_vec: Vec<CurveWrap<C, &C>> = vec.as_ref().iter().map(CurveWrap::new).collect();
        wrap_vec.serialize(s)
    }

    pub fn deserialize<'de, D, C, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        C: CurveProjective,
        T: FromIterator<C>,
    {
        let wrap_vec = <Vec<CurveWrap<C, C>>>::deserialize(d)?;
        Ok(wrap_vec.into_iter().map(|CurveWrap(c, _)| c).collect())
    }
}

/// Serialization and deserialization of vectors of field elements.
pub(crate) mod field_vec {
    use std::borrow::Borrow;

    use pairing::PrimeField;
    use serde::de::Error as DeserializeError;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::{Fr, FrRepr};

    /// A wrapper type to facilitate serialization and deserialization of field elements.
    pub struct FieldWrap<B>(pub B);

    impl FieldWrap<Fr> {
        /// Returns the wrapped field element.
        pub fn into_inner(self) -> Fr {
            self.0
        }
    }

    impl<B: Borrow<Fr>> Serialize for FieldWrap<B> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            self.0.borrow().into_repr().0.serialize(s)
        }
    }

    impl<'de> Deserialize<'de> for FieldWrap<Fr> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let repr = FrRepr(Deserialize::deserialize(d)?);
            Ok(FieldWrap(Fr::from_repr(repr).map_err(|_| {
                D::Error::custom("invalid field element representation")
            })?))
        }
    }

    pub fn serialize<S: Serializer>(vec: &[Fr], s: S) -> Result<S::Ok, S::Error> {
        let wrap_vec: Vec<FieldWrap<&Fr>> = vec.iter().map(FieldWrap).collect();
        wrap_vec.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Fr>, D::Error> {
        let wrap_vec = <Vec<FieldWrap<Fr>>>::deserialize(d)?;
        Ok(wrap_vec.into_iter().map(FieldWrap::into_inner).collect())
    }
}

#[cfg(test)]
mod tests {
    use bincode;
    use rand;
    use rand04_compat::RngExt;
    use serde::{Deserialize, Serialize};

    use crate::poly::BivarPoly;
    use crate::{Fr, G1};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Vecs {
        #[serde(with = "super::projective_vec")]
        curve_points: Vec<G1>,
        #[serde(with = "super::field_vec")]
        field_elements: Vec<Fr>,
    }

    impl PartialEq for Vecs {
        fn eq(&self, other: &Self) -> bool {
            self.curve_points == other.curve_points && self.field_elements == other.field_elements
        }
    }

    #[test]
    fn vecs() {
        let mut rng = rand::thread_rng();
        let vecs = Vecs {
            curve_points: rng.gen_iter04().take(10).collect(),
            field_elements: rng.gen_iter04().take(10).collect(),
        };
        let ser_vecs = bincode::serialize(&vecs).expect("serialize vecs");
        let de_vecs = bincode::deserialize(&ser_vecs).expect("deserialize vecs");
        assert_eq!(vecs, de_vecs);
    }

    #[test]
    fn bivar_commitment() {
        let mut rng = rand::thread_rng();
        for deg in 1..8 {
            let poly = BivarPoly::random(deg, &mut rng);
            let comm = poly.commitment();
            let ser_comm = bincode::serialize(&comm).expect("serialize commitment");
            let de_comm = bincode::deserialize(&ser_comm).expect("deserialize commitment");
            assert_eq!(comm, de_comm);
        }
    }

    #[test]
    #[cfg(not(feature = "use-insecure-test-only-mock-crypto"))]
    fn serde_secret_key() {
        use crate::serde_impl::SerdeSecret;
        use crate::SecretKey;
        use rand::{thread_rng, Rng};

        let mut rng = thread_rng();
        for _ in 0..2048 {
            let sk: SecretKey = rng.gen();
            let ser_ref = bincode::serialize(&SerdeSecret(&sk)).expect("serialize secret key");

            let de = bincode::deserialize(&ser_ref).expect("deserialize secret key");
            assert_eq!(sk, de);

            let de_serde_secret: SerdeSecret<SecretKey> =
                bincode::deserialize(&ser_ref).expect("deserialize secret key");
            assert_eq!(sk, de_serde_secret.into_inner());

            let ser_val = bincode::serialize(&SerdeSecret(sk)).expect("serialize secret key");
            assert_eq!(ser_ref, ser_val);
        }
    }

    #[test]
    fn serde_secret_key_share() {
        use crate::serde_impl::SerdeSecret;
        use crate::SecretKeyShare;
        use rand::{thread_rng, Rng};

        let mut rng = thread_rng();
        for _ in 0..2048 {
            let sk: SecretKeyShare = rng.gen();
            let ser_ref = bincode::serialize(&SerdeSecret(&sk)).expect("serialize secret key");

            let de = bincode::deserialize(&ser_ref).expect("deserialize secret key");
            assert_eq!(sk, de);

            let de_serde_secret: SerdeSecret<SecretKeyShare> =
                bincode::deserialize(&ser_ref).expect("deserialize secret key");
            assert_eq!(sk, de_serde_secret.into_inner());

            let ser_val = bincode::serialize(&SerdeSecret(sk)).expect("serialize secret key");
            assert_eq!(ser_ref, ser_val);

            #[cfg(not(feature = "use-insecure-test-only-mock-crypto"))]
            assert_eq!(ser_val.len(), 32);
        }
    }
}
