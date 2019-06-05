//! A pairing-based threshold cryptosystem for collaborative decryption and signatures.

// Clippy warns that it's dangerous to derive `PartialEq` and explicitly implement `Hash`, but the
// `pairing::bls12_381` types don't implement `Hash`, so we can't derive it.
#![allow(clippy::derive_hash_xor_eq)]
// When using the mocktography, the resulting field elements become wrapped `u32`s, suddenly
// triggering pass-by-reference warnings. They are conditionally disabled for this reason:
#![cfg_attr(
    feature = "use-insecure-test-only-mock-crypto",
    allow(clippy::trivially_copy_pass_by_ref)
)]
#![warn(missing_docs)]

pub use pairing;

mod cmp_pairing;
mod into_fr;
mod secret;

pub mod error;
pub mod poly;
pub mod serde_impl;

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ptr::copy_nonoverlapping;

use hex_fmt::HexFmt;
use log::debug;
use pairing::{CurveAffine, CurveProjective, EncodedPoint, Engine, Field};
use rand::distributions::{Distribution, Standard};
use rand::{rngs::OsRng, Rng, SeedableRng};
use rand04_compat::RngExt;
use rand_chacha::ChaChaRng;
use serde::{Deserialize, Serialize};
use tiny_keccak::sha3_256;

use crate::cmp_pairing::cmp_projective;
use crate::error::{Error, FromBytesError, FromBytesResult, Result};
use crate::poly::{Commitment, Poly};
use crate::secret::{clear_fr, ContainsSecret, MemRange, FR_SIZE};

pub use crate::into_fr::IntoFr;

#[cfg(not(feature = "use-insecure-test-only-mock-crypto"))]
pub use pairing::bls12_381::{Bls12 as PEngine, Fr, FrRepr, G1Affine, G2Affine, G1, G2};

#[cfg(feature = "use-insecure-test-only-mock-crypto")]
mod mock;

#[cfg(feature = "use-insecure-test-only-mock-crypto")]
pub use crate::mock::{
    Mersenne8 as Fr, Mersenne8 as FrRepr, Mocktography as PEngine, Ms8Affine as G1Affine,
    Ms8Affine as G2Affine, Ms8Projective as G1, Ms8Projective as G2, PK_SIZE, SIG_SIZE,
};

/// The size of a key's representation in bytes.
#[cfg(not(feature = "use-insecure-test-only-mock-crypto"))]
pub const PK_SIZE: usize = 48;

/// The size of a signature's representation in bytes.
#[cfg(not(feature = "use-insecure-test-only-mock-crypto"))]
pub const SIG_SIZE: usize = 96;

const ERR_OS_RNG: &str = "could not initialize the OS random number generator";

/// A public key.
#[derive(Deserialize, Serialize, Copy, Clone, PartialEq, Eq)]
pub struct PublicKey(#[serde(with = "serde_impl::projective")] G1);

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uncomp = self.0.into_affine().into_uncompressed();
        write!(f, "PublicKey({:0.10})", HexFmt(uncomp))
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_projective(&self.0, &other.0)
    }
}

impl PublicKey {
    /// Returns `true` if the signature matches the element of `G2`.
    pub fn verify_g2<H: Into<G2Affine>>(&self, sig: &Signature, hash: H) -> bool {
        PEngine::pairing(self.0, hash) == PEngine::pairing(G1Affine::one(), sig.0)
    }

    /// Returns `true` if the signature matches the message.
    ///
    /// This is equivalent to `verify_g2(sig, hash_g2(msg))`.
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &Signature, msg: M) -> bool {
        self.verify_g2(sig, hash_g2(msg))
    }

    /// Encrypts the message using the OS random number generator.
    ///
    /// Uses the `OsRng` by default. To pass in a custom random number generator, use
    /// `encrypt_with_rng()`.
    pub fn encrypt<M: AsRef<[u8]>>(&self, msg: M) -> Ciphertext {
        self.encrypt_with_rng(&mut OsRng::new().expect(ERR_OS_RNG), msg)
    }

    /// Encrypts the message.
    pub fn encrypt_with_rng<R: Rng, M: AsRef<[u8]>>(&self, rng: &mut R, msg: M) -> Ciphertext {
        let r: Fr = rng.gen04();
        let u = G1Affine::one().mul(r);
        let v: Vec<u8> = {
            let g = self.0.into_affine().mul(r);
            xor_with_hash(g, msg.as_ref())
        };
        let w = hash_g1_g2(u, &v).into_affine().mul(r);
        Ciphertext(u, v, w)
    }

    /// Returns the key with the given representation, if valid.
    pub fn from_bytes<B: Borrow<[u8; PK_SIZE]>>(bytes: B) -> FromBytesResult<Self> {
        let mut compressed: <G1Affine as CurveAffine>::Compressed = EncodedPoint::empty();
        compressed.as_mut().copy_from_slice(bytes.borrow());
        let opt_affine = compressed.into_affine().ok();
        let projective = opt_affine.ok_or(FromBytesError::Invalid)?.into_projective();
        Ok(PublicKey(projective))
    }

    /// Returns a byte string representation of the public key.
    pub fn to_bytes(&self) -> [u8; PK_SIZE] {
        let mut bytes = [0u8; PK_SIZE];
        bytes.copy_from_slice(self.0.into_affine().into_compressed().as_ref());
        bytes
    }
}

/// A public key share.
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct PublicKeyShare(PublicKey);

impl fmt::Debug for PublicKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uncomp = (self.0).0.into_affine().into_uncompressed();
        write!(f, "PublicKeyShare({:0.10})", HexFmt(uncomp))
    }
}

impl PublicKeyShare {
    /// Returns `true` if the signature matches the element of `G2`.
    pub fn verify_g2<H: Into<G2Affine>>(&self, sig: &SignatureShare, hash: H) -> bool {
        self.0.verify_g2(&sig.0, hash)
    }

    /// Returns `true` if the signature matches the message.
    ///
    /// This is equivalent to `verify_g2(sig, hash_g2(msg))`.
    pub fn verify<M: AsRef<[u8]>>(&self, sig: &SignatureShare, msg: M) -> bool {
        self.verify_g2(sig, hash_g2(msg))
    }

    /// Returns `true` if the decryption share matches the ciphertext.
    pub fn verify_decryption_share(&self, share: &DecryptionShare, ct: &Ciphertext) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *ct;
        let hash = hash_g1_g2(*u, v);
        PEngine::pairing(share.0, hash) == PEngine::pairing((self.0).0, *w)
    }

    /// Returns the key share with the given representation, if valid.
    pub fn from_bytes<B: Borrow<[u8; PK_SIZE]>>(bytes: B) -> FromBytesResult<Self> {
        Ok(PublicKeyShare(PublicKey::from_bytes(bytes)?))
    }

    /// Returns a byte string representation of the public key share.
    pub fn to_bytes(&self) -> [u8; PK_SIZE] {
        self.0.to_bytes()
    }
}

/// A signature.
// Note: Random signatures can be generated for testing.
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Signature(#[serde(with = "serde_impl::projective")] G2);

impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for Signature {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_projective(&self.0, &other.0)
    }
}

impl Distribution<Signature> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Signature {
        Signature(rng.gen04())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uncomp = self.0.into_affine().into_uncompressed();
        write!(f, "Signature({:0.10})", HexFmt(uncomp))
    }
}

impl Hash for Signature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl Signature {
    /// Returns `true` if the signature contains an odd number of ones.
    pub fn parity(&self) -> bool {
        let uncomp = self.0.into_affine().into_uncompressed();
        let xor_bytes: u8 = uncomp.as_ref().iter().fold(0, |result, byte| result ^ byte);
        let parity = 0 != xor_bytes.count_ones() % 2;
        debug!("Signature: {:0.10}, parity: {}", HexFmt(uncomp), parity);
        parity
    }

    /// Returns the signature with the given representation, if valid.
    pub fn from_bytes<B: Borrow<[u8; SIG_SIZE]>>(bytes: B) -> FromBytesResult<Self> {
        let mut compressed: <G2Affine as CurveAffine>::Compressed = EncodedPoint::empty();
        compressed.as_mut().copy_from_slice(bytes.borrow());
        let opt_affine = compressed.into_affine().ok();
        let projective = opt_affine.ok_or(FromBytesError::Invalid)?.into_projective();
        Ok(Signature(projective))
    }

    /// Returns a byte string representation of the signature.
    pub fn to_bytes(&self) -> [u8; SIG_SIZE] {
        let mut bytes = [0u8; SIG_SIZE];
        bytes.copy_from_slice(self.0.into_affine().into_compressed().as_ref());
        bytes
    }
}

/// A signature share.
// Note: Random signature shares can be generated for testing.
#[derive(Deserialize, Serialize, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct SignatureShare(pub Signature);

impl Distribution<SignatureShare> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SignatureShare {
        SignatureShare(rng.gen())
    }
}

impl fmt::Debug for SignatureShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uncomp = (self.0).0.into_affine().into_uncompressed();
        write!(f, "SignatureShare({:0.10})", HexFmt(uncomp))
    }
}

impl SignatureShare {
    /// Returns the signature share with the given representation, if valid.
    pub fn from_bytes<B: Borrow<[u8; SIG_SIZE]>>(bytes: B) -> FromBytesResult<Self> {
        Ok(SignatureShare(Signature::from_bytes(bytes)?))
    }

    /// Returns a byte string representation of the signature share.
    pub fn to_bytes(&self) -> [u8; SIG_SIZE] {
        self.0.to_bytes()
    }
}

/// A secret key; wraps a single prime field element. The field element is
/// heap allocated to avoid any stack copying that result when passing
/// `SecretKey`s between stack frames.
///
/// # Serde integration
/// `SecretKey` implements `Deserialize` but not `Serialize` to avoid accidental
/// serialization in insecure contexts. To enable both use the `::serde_impl::SerdeSecret`
/// wrapper which implements both `Deserialize` and `Serialize`.
#[derive(PartialEq, Eq)]
pub struct SecretKey(Box<Fr>);

/// Creates a `SecretKey` containing the zero prime field element.
impl Default for SecretKey {
    fn default() -> Self {
        let mut fr = Fr::zero();
        SecretKey::from_mut(&mut fr)
    }
}

impl Distribution<SecretKey> for Standard {
    /// Creates a new random instance of `SecretKey`. If you do not need to specify your own RNG,
    /// you should use the [`SecretKey::random()`](struct.SecretKey.html#method.random) constructor,
    /// which uses [`rand::thread_rng()`](https://docs.rs/rand/0.6.1/rand/fn.thread_rng.html)
    /// internally as its RNG.
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SecretKey {
        SecretKey(Box::new(rng.gen04()))
    }
}

/// Creates a new `SecretKey` by cloning another `SecretKey`'s prime field element.
impl Clone for SecretKey {
    fn clone(&self) -> Self {
        let mut fr = *self.0;
        SecretKey::from_mut(&mut fr)
    }
}

/// Zeroes out the memory allocated from the `SecretKey`'s field element.
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zero_secret();
    }
}
/// A debug statement where the secret prime field element is redacted.
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretKey").field(&"...").finish()
    }
}

impl ContainsSecret for SecretKey {
    fn secret_memory(&self) -> MemRange {
        MemRange {
            ptr: &*self.0 as *const Fr as *mut u8,
            n_bytes: FR_SIZE,
        }
    }
}

impl SecretKey {
    /// Creates a new `SecretKey` from a mutable reference to a field element. This constructor
    /// takes a reference to avoid any unnecessary stack copying/moving of secrets (i.e. the field
    /// element). The field element is copied bytewise onto the heap, the resulting `Box` is
    /// stored in the returned `SecretKey`.
    ///
    /// *WARNING* this constructor will overwrite the referenced `Fr` element with zeros after it
    /// has been copied onto the heap.
    pub fn from_mut(fr: &mut Fr) -> Self {
        let fr_ptr = fr as *mut Fr;
        let mut boxed_fr = Box::new(Fr::zero());
        unsafe {
            copy_nonoverlapping(fr_ptr, &mut *boxed_fr as *mut Fr, 1);
        }
        clear_fr(fr_ptr);
        SecretKey(boxed_fr)
    }

    /// Creates a new random instance of `SecretKey`. If you want to use/define your own random
    /// number generator, you should use the constructor:
    /// [`SecretKey::sample()`](struct.SecretKey.html#impl-Distribution<SecretKey>). If you do not
    /// need to specify your own RNG, you should use the
    /// [`SecretKey::random()`](struct.SecretKey.html#method.random) constructor, which uses
    /// [`rand::thread_rng()`](https://docs.rs/rand/0.6.1/rand/fn.thread_rng.html) internally as its
    /// RNG.
    pub fn random() -> Self {
        rand::random()
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(G1Affine::one().mul(*self.0))
    }

    /// Signs the given element of `G2`.
    pub fn sign_g2<H: Into<G2Affine>>(&self, hash: H) -> Signature {
        Signature(hash.into().mul(*self.0))
    }

    /// Signs the given message.
    ///
    /// This is equivalent to `sign_g2(hash_g2(msg))`.
    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> Signature {
        self.sign_g2(hash_g2(msg))
    }

    /// Returns the decrypted text, or `None`, if the ciphertext isn't valid.
    pub fn decrypt(&self, ct: &Ciphertext) -> Option<Vec<u8>> {
        if !ct.verify() {
            return None;
        }
        let Ciphertext(ref u, ref v, _) = *ct;
        let g = u.into_affine().mul(*self.0);
        Some(xor_with_hash(g, v))
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field element.
    pub fn reveal(&self) -> String {
        let uncomp = self.public_key().0.into_affine().into_uncompressed();
        format!("SecretKey({:0.10})", HexFmt(uncomp))
    }
}

/// A secret key share.
///
/// # Serde integration
/// `SecretKeyShare` implements `Deserialize` but not `Serialize` to avoid accidental
/// serialization in insecure contexts. To enable both use the `::serde_impl::SerdeSecret`
/// wrapper which implements both `Deserialize` and `Serialize`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretKeyShare(SecretKey);

/// Can be used to create a new random instance of `SecretKeyShare`. This is only useful for testing
/// purposes as such a key has not been derived from a `SecretKeySet`.
impl Distribution<SecretKeyShare> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SecretKeyShare {
        SecretKeyShare(rng.gen())
    }
}

impl fmt::Debug for SecretKeyShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretKeyShare").field(&"...").finish()
    }
}

impl SecretKeyShare {
    /// Creates a new `SecretKeyShare` from a mutable reference to a field element. This
    /// constructor takes a reference to avoid any unnecessary stack copying/moving of secrets
    /// field elements. The field element will be copied bytewise onto the heap, the resulting
    /// `Box` is stored in the `SecretKey` which is then wrapped in a `SecretKeyShare`.
    ///
    /// *WARNING* this constructor will overwrite the pointed to `Fr` element with zeros once it
    /// has been copied into a new `SecretKeyShare`.
    pub fn from_mut(fr: &mut Fr) -> Self {
        SecretKeyShare(SecretKey::from_mut(fr))
    }

    /// Returns the matching public key share.
    pub fn public_key_share(&self) -> PublicKeyShare {
        PublicKeyShare(self.0.public_key())
    }

    /// Signs the given element of `G2`.
    pub fn sign_g2<H: Into<G2Affine>>(&self, hash: H) -> SignatureShare {
        SignatureShare(self.0.sign_g2(hash))
    }

    /// Signs the given message.
    pub fn sign<M: AsRef<[u8]>>(&self, msg: M) -> SignatureShare {
        SignatureShare(self.0.sign(msg))
    }

    /// Returns a decryption share, or `None`, if the ciphertext isn't valid.
    pub fn decrypt_share(&self, ct: &Ciphertext) -> Option<DecryptionShare> {
        if !ct.verify() {
            return None;
        }
        Some(self.decrypt_share_no_verify(ct))
    }

    /// Returns a decryption share, without validating the ciphertext.
    pub fn decrypt_share_no_verify(&self, ct: &Ciphertext) -> DecryptionShare {
        DecryptionShare(ct.0.into_affine().mul(*(self.0).0))
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field element.
    pub fn reveal(&self) -> String {
        let uncomp = self.0.public_key().0.into_affine().into_uncompressed();
        format!("SecretKeyShare({:0.10})", HexFmt(uncomp))
    }
}

/// An encrypted message.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext(
    #[serde(with = "serde_impl::projective")] G1,
    Vec<u8>,
    #[serde(with = "serde_impl::projective")] G2,
);

impl Hash for Ciphertext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let Ciphertext(ref u, ref v, ref w) = *self;
        u.into_affine().into_compressed().as_ref().hash(state);
        v.hash(state);
        w.into_affine().into_compressed().as_ref().hash(state);
    }
}

impl PartialOrd for Ciphertext {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(&other))
    }
}

impl Ord for Ciphertext {
    fn cmp(&self, other: &Self) -> Ordering {
        let Ciphertext(ref u0, ref v0, ref w0) = self;
        let Ciphertext(ref u1, ref v1, ref w1) = other;
        cmp_projective(u0, u1)
            .then(v0.cmp(v1))
            .then(cmp_projective(w0, w1))
    }
}

impl Ciphertext {
    /// Returns `true` if this is a valid ciphertext. This check is necessary to prevent
    /// chosen-ciphertext attacks.
    pub fn verify(&self) -> bool {
        let Ciphertext(ref u, ref v, ref w) = *self;
        let hash = hash_g1_g2(*u, v);
        PEngine::pairing(G1Affine::one(), *w) == PEngine::pairing(*u, hash)
    }
}

/// A decryption share. A threshold of decryption shares can be used to decrypt a message.
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct DecryptionShare(#[serde(with = "serde_impl::projective")] G1);

impl Distribution<DecryptionShare> for Standard {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> DecryptionShare {
        DecryptionShare(rng.gen04())
    }
}

impl Hash for DecryptionShare {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.into_affine().into_compressed().as_ref().hash(state);
    }
}

/// A public key and an associated set of public key shares.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct PublicKeySet {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    commit: Commitment,
}

impl Hash for PublicKeySet {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.commit.hash(state);
    }
}

impl From<Commitment> for PublicKeySet {
    fn from(commit: Commitment) -> PublicKeySet {
        PublicKeySet { commit }
    }
}

impl PublicKeySet {
    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.commit.degree()
    }

    /// Returns the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.commit.coeff[0])
    }

    /// Returns the `i`-th public key share.
    pub fn public_key_share<T: IntoFr>(&self, i: T) -> PublicKeyShare {
        let value = self.commit.evaluate(into_fr_plus_1(i));
        PublicKeyShare(PublicKey(value))
    }

    /// Combines the shares into a signature that can be verified with the main public key.
    ///
    /// The validity of the shares is not checked: If one of them is invalid, the resulting
    /// signature also is. Only returns an error if there is a duplicate index or too few shares.
    ///
    /// Validity of signature shares should be checked beforehand, or validity of the result
    /// afterwards:
    ///
    /// ```
    /// # extern crate rand;
    /// #
    /// # use std::collections::BTreeMap;
    /// # use threshold_crypto::SecretKeySet;
    /// #
    /// let sk_set = SecretKeySet::random(3, &mut rand::thread_rng());
    /// let sk_shares: Vec<_> = (0..6).map(|i| sk_set.secret_key_share(i)).collect();
    /// let pk_set = sk_set.public_keys();
    /// let msg = "Happy birthday! If this is signed, at least four people remembered!";
    ///
    /// // Create four signature shares for the message.
    /// let sig_shares: BTreeMap<_, _> = (0..4).map(|i| (i, sk_shares[i].sign(msg))).collect();
    ///
    /// // Validate the signature shares.
    /// for (i, sig_share) in &sig_shares {
    ///     assert!(pk_set.public_key_share(*i).verify(sig_share, msg));
    /// }
    ///
    /// // Combine them to produce the main signature.
    /// let sig = pk_set.combine_signatures(&sig_shares).expect("not enough shares");
    ///
    /// // Validate the main signature. If the shares were valid, this can't fail.
    /// assert!(pk_set.public_key().verify(&sig, msg));
    /// ```
    pub fn combine_signatures<'a, T, I>(&self, shares: I) -> Result<Signature>
    where
        I: IntoIterator<Item = (T, &'a SignatureShare)>,
        T: IntoFr,
    {
        let samples = shares.into_iter().map(|(i, share)| (i, &(share.0).0));
        Ok(Signature(interpolate(self.commit.degree(), samples)?))
    }

    /// Combines the shares to decrypt the ciphertext.
    pub fn decrypt<'a, T, I>(&self, shares: I, ct: &Ciphertext) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = (T, &'a DecryptionShare)>,
        T: IntoFr,
    {
        let samples = shares.into_iter().map(|(i, share)| (i, &share.0));
        let g = interpolate(self.commit.degree(), samples)?;
        Ok(xor_with_hash(g, &ct.1))
    }
}

/// A secret key and an associated set of secret key shares.
pub struct SecretKeySet {
    /// The coefficients of a polynomial whose value at `0` is the "master key", and value at
    /// `i + 1` is key share number `i`.
    poly: Poly,
}

impl From<Poly> for SecretKeySet {
    fn from(poly: Poly) -> SecretKeySet {
        SecretKeySet { poly }
    }
}

impl SecretKeySet {
    /// Creates a set of secret key shares, where any `threshold + 1` of them can collaboratively
    /// sign and decrypt. This constructor is identical to the `SecretKeySet::try_random()` in every
    /// way except that this constructor panics if the other returns an error.
    ///
    /// # Panic
    ///
    /// Panics if the `threshold` is too large for the coefficients to fit into a `Vec`.
    pub fn random<R: Rng>(threshold: usize, rng: &mut R) -> Self {
        SecretKeySet::try_random(threshold, rng)
            .unwrap_or_else(|e| panic!("Failed to create random `SecretKeySet`: {}", e))
    }

    /// Creates a set of secret key shares, where any `threshold + 1` of them can collaboratively
    /// sign and decrypt. This constructor is identical to the `SecretKeySet::random()` in every
    /// way except that this constructor returns an `Err` where the `random` would panic.
    pub fn try_random<R: Rng>(threshold: usize, rng: &mut R) -> Result<Self> {
        Poly::try_random(threshold, rng).map(SecretKeySet::from)
    }

    /// Returns the threshold `t`: any set of `t + 1` signature shares can be combined into a full
    /// signature.
    pub fn threshold(&self) -> usize {
        self.poly.degree()
    }

    /// Returns the `i`-th secret key share.
    pub fn secret_key_share<T: IntoFr>(&self, i: T) -> SecretKeyShare {
        let mut fr = self.poly.evaluate(into_fr_plus_1(i));
        SecretKeyShare::from_mut(&mut fr)
    }

    /// Returns the corresponding public key set. That information can be shared publicly.
    pub fn public_keys(&self) -> PublicKeySet {
        PublicKeySet {
            commit: self.poly.commitment(),
        }
    }

    /// Returns the secret master key.
    #[cfg(test)]
    fn secret_key(&self) -> SecretKey {
        let mut fr = self.poly.evaluate(0);
        SecretKey::from_mut(&mut fr)
    }
}

/// Returns a hash of the given message in `G2`.
pub fn hash_g2<M: AsRef<[u8]>>(msg: M) -> G2 {
    let digest = sha3_256(msg.as_ref());
    ChaChaRng::from_seed(digest).gen04()
}

/// Returns a hash of the group element and message, in the second group.
fn hash_g1_g2<M: AsRef<[u8]>>(g1: G1, msg: M) -> G2 {
    // If the message is large, hash it, otherwise copy it.
    // TODO: Benchmark and optimize the threshold.
    let mut msg = if msg.as_ref().len() > 64 {
        sha3_256(msg.as_ref()).to_vec()
    } else {
        msg.as_ref().to_vec()
    };
    msg.extend(g1.into_affine().into_compressed().as_ref());
    hash_g2(&msg)
}

/// Returns the bitwise xor of `bytes` with a sequence of pseudorandom bytes determined by `g1`.
fn xor_with_hash(g1: G1, bytes: &[u8]) -> Vec<u8> {
    let digest = sha3_256(g1.into_affine().into_compressed().as_ref());
    let mut rng = ChaChaRng::from_seed(digest);
    let xor = |(a, b): (u8, &u8)| a ^ b;
    rng.sample_iter(&Standard).zip(bytes).map(xor).collect()
}

use std::borrow::Borrow;

/// Given a list of `t + 1` samples `(i - 1, f(i) * g)` for a polynomial `f` of degree `t`, and a
/// group generator `g`, returns `f(0) * g`.
fn interpolate<C, B, T, I>(t: usize, items: I) -> Result<C>
where
    C: CurveProjective<Scalar = Fr>,
    I: IntoIterator<Item = (T, B)>,
    T: IntoFr,
    B: Borrow<C>,
{
    let samples: Vec<_> = items
        .into_iter()
        .take(t + 1)
        .map(|(i, sample)| (into_fr_plus_1(i), sample))
        .collect();
    if samples.len() <= t {
        return Err(Error::NotEnoughShares);
    }

    if t == 0 {
        return Ok(*samples[0].1.borrow());
    }

    // Compute the products `x_prod[i]` of all but the `i`-th entry.
    let mut x_prod: Vec<C::Scalar> = Vec::with_capacity(t);
    let mut tmp = C::Scalar::one();
    x_prod.push(tmp);
    for (x, _) in samples.iter().take(t) {
        tmp.mul_assign(x);
        x_prod.push(tmp);
    }
    tmp = C::Scalar::one();
    for (i, (x, _)) in samples[1..].iter().enumerate().rev() {
        tmp.mul_assign(x);
        x_prod[i].mul_assign(&tmp);
    }

    let mut result = C::zero();
    for (mut l0, (x, sample)) in x_prod.into_iter().zip(&samples) {
        // Compute the value at 0 of the Lagrange polynomial that is `0` at the other data
        // points but `1` at `x`.
        let mut denom = C::Scalar::one();
        for (x0, _) in samples.iter().filter(|(x0, _)| x0 != x) {
            let mut diff = *x0;
            diff.sub_assign(x);
            denom.mul_assign(&diff);
        }
        l0.mul_assign(&denom.inverse().ok_or(Error::DuplicateEntry)?);
        result.add_assign(&sample.borrow().into_affine().mul(l0));
    }
    Ok(result)
}

fn into_fr_plus_1<I: IntoFr>(x: I) -> Fr {
    let mut result = Fr::one();
    result.add_assign(&x.into_fr());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use rand::{self, distributions::Standard, random, Rng};
    use rand04_compat::rand04::random as random04;

    #[test]
    fn test_interpolate() {
        let mut rng = rand::thread_rng();
        for deg in 0..5 {
            println!("deg = {}", deg);
            let comm = Poly::random(deg, &mut rng).commitment();
            let mut values = Vec::new();
            let mut x = 0;
            for _ in 0..=deg {
                x += rng.gen_range(1, 5);
                values.push((x - 1, comm.evaluate(x)));
            }
            let actual = interpolate(deg, values).expect("wrong number of values");
            assert_eq!(comm.evaluate(0), actual);
        }
    }

    #[test]
    fn test_simple_sig() {
        let sk0 = SecretKey::random();
        let sk1 = SecretKey::random();
        let pk0 = sk0.public_key();
        let msg0 = b"Real news";
        let msg1 = b"Fake news";
        assert!(pk0.verify(&sk0.sign(msg0), msg0));
        assert!(!pk0.verify(&sk1.sign(msg0), msg0)); // Wrong key.
        assert!(!pk0.verify(&sk0.sign(msg1), msg0)); // Wrong message.
    }

    #[test]
    fn test_threshold_sig() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let pk_master = pk_set.public_key();

        // Make sure the keys are different, and the first coefficient is the main key.
        assert_ne!(pk_master, pk_set.public_key_share(0).0);
        assert_ne!(pk_master, pk_set.public_key_share(1).0);
        assert_ne!(pk_master, pk_set.public_key_share(2).0);

        // Make sure we don't hand out the main secret key to anyone.
        let sk_master = sk_set.secret_key();
        let sk_share_0 = sk_set.secret_key_share(0).0;
        let sk_share_1 = sk_set.secret_key_share(1).0;
        let sk_share_2 = sk_set.secret_key_share(2).0;
        assert_ne!(sk_master, sk_share_0);
        assert_ne!(sk_master, sk_share_1);
        assert_ne!(sk_master, sk_share_2);

        let msg = "Totally real news";

        // The threshold is 3, so 4 signature shares will suffice to recreate the share.
        let sigs: BTreeMap<_, _> = [5, 8, 7, 10]
            .iter()
            .map(|&i| {
                let sig = sk_set.secret_key_share(i).sign(msg);
                (i, sig)
            })
            .collect();

        // Each of the shares is a valid signature matching its public key share.
        for (i, sig) in &sigs {
            assert!(pk_set.public_key_share(*i).verify(sig, msg));
        }

        // Combined, they produce a signature matching the main public key.
        let sig = pk_set.combine_signatures(&sigs).expect("signatures match");
        assert!(pk_set.public_key().verify(&sig, msg));

        // A different set of signatories produces the same signature.
        let sigs2: BTreeMap<_, _> = [42, 43, 44, 45]
            .iter()
            .map(|&i| {
                let sig = sk_set.secret_key_share(i).sign(msg);
                (i, sig)
            })
            .collect();
        let sig2 = pk_set.combine_signatures(&sigs2).expect("signatures match");
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_simple_enc() {
        let sk_bob: SecretKey = random();
        let sk_eve: SecretKey = random();
        let pk_bob = sk_bob.public_key();
        let msg = b"Muffins in the canteen today! Don't tell Eve!";
        let ciphertext = pk_bob.encrypt(&msg[..]);
        assert!(ciphertext.verify());

        // Bob can decrypt the message.
        let decrypted = sk_bob.decrypt(&ciphertext).expect("invalid ciphertext");
        assert_eq!(msg[..], decrypted[..]);

        // Eve can't.
        let decrypted_eve = sk_eve.decrypt(&ciphertext).expect("invalid ciphertext");
        assert_ne!(msg[..], decrypted_eve[..]);

        // Eve tries to trick Bob into decrypting `msg` xor `v`, but it doesn't validate.
        let Ciphertext(u, v, w) = ciphertext;
        let fake_ciphertext = Ciphertext(u, vec![0; v.len()], w);
        assert!(!fake_ciphertext.verify());
        assert_eq!(None, sk_bob.decrypt(&fake_ciphertext));
    }

    #[test]
    fn test_random_extreme_thresholds() {
        let mut rng = rand::thread_rng();
        let sks = SecretKeySet::random(0, &mut rng);
        assert_eq!(0, sks.threshold());
        assert!(SecretKeySet::try_random(usize::max_value(), &mut rng).is_err());
    }

    #[test]
    fn test_threshold_enc() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let msg = b"Totally real news";
        let ciphertext = pk_set.public_key().encrypt(&msg[..]);

        // The threshold is 3, so 4 signature shares will suffice to decrypt.
        let shares: BTreeMap<_, _> = [5, 8, 7, 10]
            .iter()
            .map(|&i| {
                let dec_share = sk_set
                    .secret_key_share(i)
                    .decrypt_share(&ciphertext)
                    .expect("ciphertext is invalid");
                (i, dec_share)
            })
            .collect();

        // Each of the shares is valid matching its public key share.
        for (i, share) in &shares {
            pk_set
                .public_key_share(*i)
                .verify_decryption_share(share, &ciphertext);
        }

        // Combined, they can decrypt the message.
        let decrypted = pk_set
            .decrypt(&shares, &ciphertext)
            .expect("decryption shares match");
        assert_eq!(msg[..], decrypted[..]);
    }

    /// Some basic sanity checks for the `hash_g2` function.
    #[test]
    fn test_hash_g2() {
        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = rng.sample_iter(&Standard).take(1000).collect();
        let msg_end0: Vec<u8> = msg.iter().chain(b"end0").cloned().collect();
        let msg_end1: Vec<u8> = msg.iter().chain(b"end1").cloned().collect();

        assert_eq!(hash_g2(&msg), hash_g2(&msg));
        assert_ne!(hash_g2(&msg), hash_g2(&msg_end0));
        assert_ne!(hash_g2(&msg_end0), hash_g2(&msg_end1));
    }

    /// Some basic sanity checks for the `hash_g1_g2` function.
    #[test]
    fn test_hash_g1_g2() {
        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = rng.sample_iter(&Standard).take(1000).collect();
        let msg_end0: Vec<u8> = msg.iter().chain(b"end0").cloned().collect();
        let msg_end1: Vec<u8> = msg.iter().chain(b"end1").cloned().collect();
        let g0 = random04();
        let g1 = random04();

        assert_eq!(hash_g1_g2(g0, &msg), hash_g1_g2(g0, &msg));
        assert_ne!(hash_g1_g2(g0, &msg), hash_g1_g2(g0, &msg_end0));
        assert_ne!(hash_g1_g2(g0, &msg_end0), hash_g1_g2(g0, &msg_end1));
        assert_ne!(hash_g1_g2(g0, &msg), hash_g1_g2(g1, &msg));
    }

    /// Some basic sanity checks for the `hash_bytes` function.
    #[test]
    fn test_xor_with_hash() {
        let g0 = random04();
        let g1 = random04();
        let xwh = xor_with_hash;
        assert_eq!(xwh(g0, &[0; 5]), xwh(g0, &[0; 5]));
        assert_ne!(xwh(g0, &[0; 5]), xwh(g1, &[0; 5]));
        assert_eq!(5, xwh(g0, &[0; 5]).len());
        assert_eq!(6, xwh(g0, &[0; 6]).len());
        assert_eq!(20, xwh(g0, &[0; 20]).len());
    }

    #[test]
    fn test_from_to_bytes() {
        let sk: SecretKey = random();
        let sig = sk.sign("Please sign here: ______");
        let pk = sk.public_key();
        let pk2 = PublicKey::from_bytes(pk.to_bytes()).expect("invalid pk representation");
        assert_eq!(pk, pk2);
        let sig2 = Signature::from_bytes(sig.to_bytes()).expect("invalid sig representation");
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_serde() {
        use bincode;

        let sk: SecretKey = random();
        let sig = sk.sign("Please sign here: ______");
        let pk = sk.public_key();
        let ser_pk = bincode::serialize(&pk).expect("serialize public key");
        let deser_pk = bincode::deserialize(&ser_pk).expect("deserialize public key");
        assert_eq!(ser_pk.len(), PK_SIZE);
        assert_eq!(pk, deser_pk);
        let ser_sig = bincode::serialize(&sig).expect("serialize signature");
        let deser_sig = bincode::deserialize(&ser_sig).expect("deserialize signature");
        assert_eq!(ser_sig.len(), SIG_SIZE);
        assert_eq!(sig, deser_sig);
    }

    #[test]
    fn test_size() {
        assert_eq!(<G1Affine as CurveAffine>::Compressed::size(), PK_SIZE);
        assert_eq!(<G2Affine as CurveAffine>::Compressed::size(), SIG_SIZE);
    }
}
