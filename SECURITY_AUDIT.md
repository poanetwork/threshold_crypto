% POA Network threshold crypto audit
% Jean-Philippe Aumasson
% 20181024

# Introduction

We reviewed <https://github.com/poanetwork/threshold_crypto> for security defects (branch master, e28b77d).

This implements the pairing-based threshold signature and encryption schemes, based on the [Boneh-Lynn-Shacham](https://www.iacr.org/archive/asiacrypt2001/22480516.pdf) pairing-based signature scheme, on its extension to threshold signatures using Lagrange interpolation by [Boldyreva](https://eprint.iacr.org/2002/118.pdf), and on the composition with an IND-CCA encryption construction as described by [Baek and Zheng](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.119.1717&rep=rep1&type=pdf) (a.k.a. "signcryption").

The elliptic-curve arithmetic and pairings are over the BLS12 elliptic curve, and is based on Sean Bowe's `pairing` crate (also used in Zcash), which we have audited in the past months.

We reviewed the source code by manual inspection, and used modified versions of the unit tests in order to perform more testing of edge cases, malformed inputs, and so on. 
We have checked the following points (non-exhaustive list):

* Primitives (curve, hash) and their implementation
* Use of rand? OsRng used for secret stuff
* Exploitable panics
* Unsafe unwraps
* Memory zeroizing completeness
* Equivalent keys using signed/unsigned indices
* Leakage from ciphertext data structure
* Incomplete/insufficient verification
* Threshold enforcement and edge cases
* Dependencies security/versions

We did not find any exploitable security issue in the logic nor implementation of the threshold schemes, but only report potential improvements in the section Observations below.

The audit work took approximately 6h30, including the review of
literature related to the threshold cryptosystems implemented, and the
review of patches following our initial observations.

# Observations

## Impossible error?

```
impl IntoFr for u64 {
    fn into_fr(self) -> Fr {
        Fr::from_repr(self.into()).expect("modulus is greater than u64::MAX")
    }
}
```
Can this really fail, since the trait is only defined for `u64` types, which cant be greater than `u64::MAX`?
(We noticed this when trying to overflow the value / crash decryption.)

### Status

Failure is indeed impossible, but the `expect()` is meant as an
clarification for the reader that the Result obtained must be less than
`u64::MAX`.

## Set a threshold threshold?

Threshold value in SecretKeySet::random() is unlimited (but to `usize`), high values can panic,
e.g. with `2^64-1` we get `thread 'tests::test_threshold_sig' panicked at 'capacity overflow', liballoc/raw_vec.rs:754:5`.

Another panic occurs if calling `SecretKeySet::random(0, &mut rng);`.

### Status

The overflow was fixed, and we reviewed the patch.

## Xored buffers length check

The xor function does not check that input slices have an equal length, which is ok in the current context, since this function is always called with same-length slices.

```
fn xor_vec(x: &[u8], y: &[u8]) -> Vec<u8> {
    x.iter().zip(y).map(|(a, b)| a ^ b).collect()
}
```

### Status

This was addressed by integrating this operation in the hashing logic.

## Outdated dependencies

* byteorder (1.2.3 instead of 1.2.6)
* log (0.4.1 instead of 0.4.5)
* rand (0.4.2 instead of 0.5.5); however note that 0.5 and above have made API changes breaking backward compatibility
* rand_derive (0.3.1 instead of 0.5.0)
* serde (1.0.55 instead of 1.0.79)
* serde_derive (1.0.55 instead of 1.0.79)

### Status

The versions had not been updated at the time of our second review, but
should be before the next release.

