//! Mock cryptography implementation of a `pairing` engine.
//!
//! Affectionately known as *mocktography*, the `mock` module implements a valid `pairing::Engine`
//! on top of simpler cryptographic primitives; instead of elliptic curves, a simple finite field of
//! Mersenne prime order is used. The resulting engine is trivially breakable (the key space is
//! smaller than 2^31), but should not produce accidental collisions at an unacceptable rate.
//!
//! As a result, all "cryptographic" operations can be carried out much faster. This module is
//! intended to be used during unit-tests of applications that build on top of `threshold_crypto`;
//! enabling this in production code of any application will immediately break its cryptographic
//! security.

pub mod ms8;

use std::{fmt, mem, slice};

use ff::{Field, PrimeField, ScalarEngine};
use group::{CurveAffine, CurveProjective, EncodedPoint, GroupDecodingError};

use super::Engine;

pub use self::ms8::Mersenne8;

/// The size of a key's representation in bytes.
pub const PK_SIZE: usize = 4;
/// The size of a signature's representation in bytes.
pub const SIG_SIZE: usize = 4;

/// A `pairing` Engine based on `Mersenne8` prime fields.
#[derive(Clone, Debug)]
pub struct Mocktography;

/// Affine type for `Mersenne8`.
#[derive(Copy, Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ms8Affine(Mersenne8);

/// Projective type for `Mersenne8`.
#[derive(Copy, Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ms8Projective(Mersenne8);

impl fmt::Display for Ms8Affine {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Display for Ms8Projective {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Ms8Affine {
    fn random<R: rand::Rng>(rng: &mut R) -> Self {
        Ms8Affine(rng.gen())
    }
}

impl Ms8Projective {
    fn random<R: rand::Rng>(rng: &mut R) -> Self {
        Ms8Projective(rng.gen())
    }
}

impl From<Ms8Projective> for Ms8Affine {
    fn from(Ms8Projective(x): Ms8Projective) -> Ms8Affine {
        Ms8Affine(x)
    }
}

impl From<Ms8Affine> for Ms8Projective {
    fn from(Ms8Affine(x): Ms8Affine) -> Ms8Projective {
        Ms8Projective(x)
    }
}

impl ScalarEngine for Mocktography {
    type Fr = Mersenne8;
}

impl Engine for Mocktography {
    type G1 = Ms8Projective;
    type G1Affine = Ms8Affine;
    type G2 = Ms8Projective;
    type G2Affine = Ms8Affine;
    type Fq = Mersenne8;
    type Fqe = Mersenne8;
    type Fqk = Mersenne8;

    fn pairing<G1, G2>(p: G1, q: G2) -> Self::Fqk
    where
        G1: Into<Self::G1Affine>,
        G2: Into<Self::G2Affine>,
    {
        p.into().0 * q.into().0
    }
}

impl AsRef<[u64]> for Mersenne8 {
    #[inline]
    fn as_ref(&self) -> &[u64] {
        panic!("Not supported: AsRef<[u64]>")
    }
}

impl AsRef<[u8]> for Mersenne8 {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(&self.0 as *const u32 as *const u8, 4) }
    }
}

impl AsMut<[u64]> for Mersenne8 {
    #[inline]
    fn as_mut(&mut self) -> &mut [u64] {
        panic!("Not supported: AsMut<[u64]>")
    }
}

impl AsMut<[u8]> for Mersenne8 {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(&mut self.0 as *mut u32 as *mut u8, 4) }
    }
}

impl AsRef<[u8]> for Ms8Affine {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for Ms8Affine {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl CurveAffine for Ms8Affine {
    type Engine = Mocktography;
    type Scalar = Mersenne8;
    type Base = Mersenne8;
    type Projective = Ms8Projective;
    type Uncompressed = Ms8Affine;
    type Compressed = Ms8Affine;

    fn zero() -> Self {
        Ms8Affine(Mersenne8::zero())
    }

    fn one() -> Self {
        Ms8Affine(Mersenne8::one())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    fn negate(&mut self) {
        self.0.negate();
    }

    fn mul<S: Into<<Self::Scalar as PrimeField>::Repr>>(&self, other: S) -> Self::Projective {
        // FIXME: Is this correct?
        let s = other.into();

        Ms8Projective(self.0 * s)
    }

    fn into_projective(&self) -> Self::Projective {
        Ms8Projective(self.0)
    }
}

impl CurveProjective for Ms8Projective {
    type Engine = Mocktography;
    type Scalar = Mersenne8;
    type Base = Mersenne8;
    type Affine = Ms8Affine;

    fn zero() -> Self {
        Ms8Projective(Mersenne8::zero())
    }

    fn one() -> Self {
        Ms8Projective(Mersenne8::one())
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    fn batch_normalization(_v: &mut [Self]) {
        // We just assume all values as already normalized. See `is_normalized()`.
    }

    fn is_normalized(&self) -> bool {
        true
    }

    fn double(&mut self) {
        self.0.double()
    }

    fn add_assign(&mut self, other: &Self) {
        self.0.add_assign(&other.0);
    }

    fn add_assign_mixed(&mut self, other: &Self::Affine) {
        self.0.add_assign(&other.0);
    }

    fn negate(&mut self) {
        self.0.negate();
    }

    fn mul_assign<S: Into<<Self::Scalar as PrimeField>::Repr>>(&mut self, other: S) {
        self.0 *= other.into();
    }

    fn into_affine(&self) -> Self::Affine {
        Ms8Affine(self.0)
    }

    fn recommended_wnaf_for_scalar(_scalar: <Self::Scalar as PrimeField>::Repr) -> usize {
        2
    }

    fn recommended_wnaf_for_num_scalars(_num_scalars: usize) -> usize {
        2
    }
}

impl EncodedPoint for Ms8Affine {
    type Affine = Ms8Affine;

    fn empty() -> Self {
        // FIXME: Ensure we are not violating any assumptions here.
        Self::default()
    }

    fn size() -> usize {
        mem::size_of::<Self>()
    }

    fn into_affine(&self) -> Result<Self::Affine, GroupDecodingError> {
        Ok(*self)
    }

    fn into_affine_unchecked(&self) -> Result<Self::Affine, GroupDecodingError> {
        Ok(*self)
    }

    fn from_affine(affine: Self::Affine) -> Self {
        affine
    }
}

#[cfg(test)]
mod test {
    // There are copy & pasted results of calculations from external programs in these tests.
    #![allow(clippy::unreadable_literal)]

    use super::{EncodedPoint, Mersenne8, Mocktography, Ms8Affine, PK_SIZE, SIG_SIZE};
    use pairing::Engine;

    #[test]
    fn example_pairings() {
        let pqs: Vec<(u32, u32, u32)> = vec![
            (0, 0, 0),
            (123, 0, 0),
            (1, 1, 1),
            (123, 1, 123),
            (4, 5, 20),
            (123456789, 987654321, 2137109934),
            (456789123, 456789123, 1405297315),
        ];

        for (p, q, res) in pqs {
            let p = Ms8Affine(p.into());
            let q = Ms8Affine(q.into());
            println!("P, Q: {}, {}", p, q);
            println!("Checking e({}, {}) = {}", p, q, res);
            assert_eq!(Mocktography::pairing(p, q), Mersenne8::new(res));

            // Our pairing is bilinear.
            println!("Checking e({}, {}) = {}", q, p, res);
            assert_eq!(Mocktography::pairing(q, p), Mersenne8::new(res));
        }
    }

    #[test]
    fn size() {
        assert_eq!(<Ms8Affine as EncodedPoint>::size(), PK_SIZE);
        assert_eq!(<Ms8Affine as EncodedPoint>::size(), SIG_SIZE);
    }
}
