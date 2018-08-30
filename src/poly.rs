//! Utilities for distributed key generation: uni- and bivariate polynomials and commitments.
//!
//! If `G` is a group of prime order `r` (written additively), and `g` is a generator, then
//! multiplication by integers factors through `r`, so the map `x -> x * g` (the sum of `x`
//! copies of `g`) is a homomorphism from the field `Fr` of integers modulo `r` to `G`. If the
//! _discrete logarithm_ is hard, i.e. it is infeasible to reverse this map, then `x * g` can be
//! considered a _commitment_ to `x`: By publishing it, you can guarantee to others that you won't
//! change your mind about the value `x`, without revealing it.
//!
//! This concept extends to polynomials: If you have a polynomial `f` over `Fr`, defined as
//! `a * X * X + b * X + c`, you can publish `a * g`, `b * g` and `c * g`. Then others will be able
//! to verify any single value `f(x)` of the polynomial without learning the original polynomial,
//! because `f(x) * g == x * x * (a * g) + x * (b * g) + (c * g)`. Only after learning three (in
//! general `degree + 1`) values, they can interpolate `f` itself.
//!
//! This module defines univariate polynomials (in one variable) and _symmetric_ bivariate
//! polynomials (in two variables) over a field `Fr`, as well as their _commitments_ in `G`.

use std::borrow::Borrow;
use std::fmt::{self, Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::mem::{size_of, size_of_val};
use std::{cmp, iter, ops};

use errno::errno;
use ff::Field;
use memsec::{memzero, mlock, munlock};
use pairing::bls12_381::{Fr, G1, G1Affine};
use pairing::{CurveAffine, CurveProjective};
use rand::Rng;

use super::{ContainsSecret, Error, IntoFr, Result, SHOULD_MLOCK_SECRETS};

/// A univariate polynomial in the prime field.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct Poly {
    /// The coefficients of a polynomial.
    #[serde(with = "super::serde_impl::field_vec")]
    pub(super) coeff: Vec<Fr>,
}

/// Creates a new `Poly` with the same coefficients as another polynomial.
///
/// # Panics
///
/// Panics if we have hit the system's locked memory limit when `mlock`ing the new instance of
/// `Poly`.
impl Clone for Poly {
    fn clone(&self) -> Self {
        match Poly::new(self.coeff.clone()) {
            Ok(poly) => poly,
            Err(e) => panic!("Failed to clone `Poly`: {}", e),
        }
    }
}

/// A debug statement where the `coeff` vector of prime field elements has been redacted.
impl Debug for Poly {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "Poly {{ coeff: ... }}")
    }
}

/// # Panics
///
/// Panics if we hit the system's locked memory limit or if we fail to unlock memory that has been
/// truncated from the `coeff` vector.
#[cfg_attr(feature = "cargo-clippy", allow(suspicious_op_assign_impl))]
impl<B: Borrow<Poly>> ops::AddAssign<B> for Poly {
    fn add_assign(&mut self, rhs: B) {
        let len = self.coeff.len();
        let rhs_len = rhs.borrow().coeff.len();
        if rhs_len > len {
            self.coeff.resize(rhs_len, Fr::zero());
            let n_coeffs_added = rhs_len - len;
            if let Err(e) = self.extend_mlock(n_coeffs_added) {
                panic!(
                    "Failed to extend `Poly` memory lock during add-assign: {}",
                    e
                );
            }
        }
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.add_assign(rhs_c);
        }
        if let Err(e) = self.remove_zeros() {
            panic!("Failed to unlock `Poly` memory during add-assign: {}", e);
        }
    }
}

impl<'a, B: Borrow<Poly>> ops::Add<B> for &'a Poly {
    type Output = Poly;

    fn add(self, rhs: B) -> Poly {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Poly>> ops::Add<B> for Poly {
    type Output = Poly;

    fn add(mut self, rhs: B) -> Poly {
        self += rhs;
        self
    }
}

/// # Panics
///
/// Panics if we hit the system's locked memory limit or if we fail to unlock memory that has been
/// truncated from the `coeff` vector.
impl<'a> ops::Add<Fr> for Poly {
    type Output = Poly;

    fn add(mut self, rhs: Fr) -> Self::Output {
        if self.coeff.is_empty() {
            if !rhs.is_zero() {
                self.coeff.push(rhs);
                if let Err(e) = self.extend_mlock(1) {
                    panic!("Failed to extend `Poly` memory lock during add: {}", e);
                }
            }
        } else {
            self.coeff[0].add_assign(&rhs);
            if let Err(e) = self.remove_zeros() {
                panic!("Failed to unlock `Poly` memory during add: {}", e);
            }
        }
        self
    }
}

impl<'a> ops::Add<u64> for Poly {
    type Output = Poly;

    fn add(self, rhs: u64) -> Self::Output {
        self + rhs.into_fr()
    }
}

/// # Panics
///
/// Panics if we hit the system's locked memory limit or if we fail to unlock memory that has been
/// truncated from the `coeff` vector.
impl<B: Borrow<Poly>> ops::SubAssign<B> for Poly {
    fn sub_assign(&mut self, rhs: B) {
        let len = self.coeff.len();
        let rhs_len = rhs.borrow().coeff.len();
        if rhs_len > len {
            self.coeff.resize(rhs_len, Fr::zero());
            let n_coeffs_added = rhs_len - len;
            if let Err(e) = self.extend_mlock(n_coeffs_added) {
                panic!(
                    "Failed to extend `Poly` memory lock during sub-assign: {}",
                    e
                );
            }
        }
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.sub_assign(rhs_c);
        }
        if let Err(e) = self.remove_zeros() {
            panic!("Failed to unlock `Poly` memory during sub-assign: {}", e);
        }
    }
}

impl<'a, B: Borrow<Poly>> ops::Sub<B> for &'a Poly {
    type Output = Poly;

    fn sub(self, rhs: B) -> Poly {
        (*self).clone() - rhs
    }
}

impl<B: Borrow<Poly>> ops::Sub<B> for Poly {
    type Output = Poly;

    fn sub(mut self, rhs: B) -> Poly {
        self -= rhs;
        self
    }
}

// Clippy thinks using `+` in a `Sub` implementation is suspicious.
#[cfg_attr(feature = "cargo-clippy", allow(suspicious_arithmetic_impl))]
impl<'a> ops::Sub<Fr> for Poly {
    type Output = Poly;

    fn sub(self, mut rhs: Fr) -> Self::Output {
        rhs.negate();
        self + rhs
    }
}

impl<'a> ops::Sub<u64> for Poly {
    type Output = Poly;

    fn sub(self, rhs: u64) -> Self::Output {
        self - rhs.into_fr()
    }
}

/// # Panics
///
/// Panics if we hit the system's locked memory limit or if we fail to unlock memory that has been
/// truncated from the `coeff` vector.
// Clippy thinks using any `+` and `-` in a `Mul` implementation is suspicious.
#[cfg_attr(feature = "cargo-clippy", allow(suspicious_arithmetic_impl))]
impl<'a, B: Borrow<Poly>> ops::Mul<B> for &'a Poly {
    type Output = Poly;

    fn mul(self, rhs: B) -> Self::Output {
        let coeff: Vec<Fr> = (0..(self.coeff.len() + rhs.borrow().coeff.len() - 1))
            .map(|i| {
                // TODO: clear these secrets from the stack.
                let mut c = Fr::zero();
                for j in i.saturating_sub(rhs.borrow().degree())..(1 + cmp::min(i, self.degree())) {
                    let mut s = self.coeff[j];
                    s.mul_assign(&rhs.borrow().coeff[i - j]);
                    c.add_assign(&s);
                }
                c
            })
            .collect();

        match Poly::new(coeff) {
            Ok(poly) => poly,
            Err(e) => panic!("Failed to create a new `Poly` duing muliplication: {}", e),
        }
    }
}

impl<B: Borrow<Poly>> ops::Mul<B> for Poly {
    type Output = Poly;

    fn mul(self, rhs: B) -> Self::Output {
        &self * rhs
    }
}

impl<B: Borrow<Self>> ops::MulAssign<B> for Poly {
    fn mul_assign(&mut self, rhs: B) {
        *self = &*self * rhs;
    }
}

/// # Panics
///
/// This operation may panic if: when multiplying the polynomial by a zero field element, we fail
/// to munlock the cleared `coeff` vector.
impl<'a> ops::Mul<Fr> for Poly {
    type Output = Poly;

    fn mul(mut self, rhs: Fr) -> Self::Output {
        if rhs.is_zero() {
            self.zero_secret_memory();
            if let Err(e) = self.munlock_secret_memory() {
                panic!("Failed to unlock `Poly` during multiplication: {}", e);
            }
            self.coeff.clear();
        } else {
            self.coeff.iter_mut().for_each(|c| c.mul_assign(&rhs));
        }
        self
    }
}

impl<'a> ops::Mul<u64> for Poly {
    type Output = Poly;

    fn mul(self, rhs: u64) -> Self::Output {
        self * rhs.into_fr()
    }
}

/// # Panics
///
/// Panics if we fail to munlock the `coeff` vector.
impl Drop for Poly {
    fn drop(&mut self) {
        self.zero_secret_memory();
        if let Err(e) = self.munlock_secret_memory() {
            panic!("Failed to munlock `Poly` during drop: {}", e);
        }
    }
}

impl ContainsSecret for Poly {
    fn mlock_secret_memory(&self) -> Result<()> {
        if !*SHOULD_MLOCK_SECRETS {
            return Ok(());
        }
        let ptr = self.coeff.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.coeff.as_slice());
        if n_bytes == 0 {
            return Ok(());
        }
        let mlock_succeeded = unsafe { mlock(ptr, n_bytes) };
        if mlock_succeeded {
            Ok(())
        } else {
            let e = Error::MlockFailed {
                errno: errno(),
                addr: format!("{:?}", ptr),
                n_bytes,
            };
            Err(e)
        }
    }

    fn munlock_secret_memory(&self) -> Result<()> {
        if !*SHOULD_MLOCK_SECRETS {
            return Ok(());
        }
        let ptr = self.coeff.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.coeff.as_slice());
        if n_bytes == 0 {
            return Ok(());
        }
        let munlock_succeeded = unsafe { munlock(ptr, n_bytes) };
        if munlock_succeeded {
            Ok(())
        } else {
            let e = Error::MunlockFailed {
                errno: errno(),
                addr: format!("{:?}", ptr),
                n_bytes,
            };
            Err(e)
        }
    }

    fn zero_secret_memory(&self) {
        let ptr = self.coeff.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.coeff.as_slice());
        unsafe {
            memzero(ptr, n_bytes);
        }
    }
}

impl Poly {
    /// Creates a new `Poly` instance from a vector of prime field elements representing the
    /// coefficients of the polynomial. The `mlock` system call is applied to the region of the
    /// heap where the field elements are allocated.
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we have reached the systems's locked memory limit.
    pub fn new(coeff: Vec<Fr>) -> Result<Self> {
        let poly = Poly { coeff };
        poly.mlock_secret_memory()?;
        Ok(poly)
    }

    /// Creates a random polynomial.
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we have reached the systems's locked memory limit.
    pub fn random<R: Rng>(degree: usize, rng: &mut R) -> Result<Self> {
        let coeff: Vec<Fr> = (0..=degree).map(|_| rng.gen()).collect();
        Poly::new(coeff)
    }

    /// Returns the polynomial with constant value `0`.
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we have reached the systems's locked memory limit.
    pub fn zero() -> Result<Self> {
        Poly::new(vec![])
    }

    /// Returns the polynomial with constant value `1`.
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we have reached the systems's locked memory limit.
    pub fn one() -> Result<Self> {
        Self::monomial(0)
    }

    /// Returns the polynomial with constant value `c`.
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we have reached the systems's locked memory limit.
    pub fn constant(c: Fr) -> Result<Self> {
        let ptr = &c as *const Fr as *mut u8;
        let res = Poly::new(vec![c]);
        unsafe {
            memzero(ptr, size_of::<Fr>());
        }
        res
    }

    /// Returns the identity function, i.e. the polynomial "`x`".
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we have reached the systems's locked memory limit.
    pub fn identity() -> Result<Self> {
        Self::monomial(1)
    }

    /// Returns the (monic) monomial "`x.pow(degree)`"
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we have reached the systems's locked memory limit.
    pub fn monomial(degree: usize) -> Result<Self> {
        let coeff: Vec<Fr> = iter::repeat(Fr::zero())
            .take(degree)
            .chain(iter::once(Fr::one()))
            .collect();
        Poly::new(coeff)
    }

    /// Returns the unique polynomial `f` of degree `samples.len() - 1` with the given values
    /// `(x, f(x))`.
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we have reached the systems's locked memory limit.
    pub fn interpolate<T, U, I>(samples_repr: I) -> Result<Self>
    where
        I: IntoIterator<Item = (T, U)>,
        T: IntoFr,
        U: IntoFr,
    {
        let convert = |(x, y): (T, U)| (x.into_fr(), y.into_fr());
        let samples: Vec<(Fr, Fr)> = samples_repr.into_iter().map(convert).collect();
        Self::compute_interpolation(&samples)
    }

    /// Returns the degree.
    pub fn degree(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the value at the point `i`.
    pub fn evaluate<T: IntoFr>(&self, i: T) -> Fr {
        let mut result = match self.coeff.last() {
            None => return Fr::zero(),
            Some(c) => *c,
        };
        let x = i.into_fr();
        for c in self.coeff.iter().rev().skip(1) {
            result.mul_assign(&x);
            result.add_assign(c);
        }
        result
    }

    /// Returns the corresponding commitment.
    pub fn commitment(&self) -> Commitment {
        let to_g1 = |c: &Fr| G1Affine::one().mul(*c);
        Commitment {
            coeff: self.coeff.iter().map(to_g1).collect(),
        }
    }

    /// Removes all trailing zero coefficients.
    ///
    /// # Errors
    ///
    /// An `Error::MunlockFailed` is returned if we failed to `munlock` the truncated portion of
    /// the `coeff` vector.
    fn remove_zeros(&mut self) -> Result<()> {
        let zeros = self.coeff.iter().rev().take_while(|c| c.is_zero()).count();
        let len = self.coeff.len() - zeros;
        self.coeff.truncate(len);
        self.truncate_mlock(zeros)
    }

    /// Returns the unique polynomial `f` of degree `samples.len() - 1` with the given values
    /// `(x, f(x))`.
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we hit the system's locked memory limit and failed to
    /// `mlock` the new `Poly` instance.
    fn compute_interpolation(samples: &[(Fr, Fr)]) -> Result<Self> {
        if samples.is_empty() {
            return Poly::zero();
        } else if samples.len() == 1 {
            return Poly::constant(samples[0].1);
        }
        // The degree is at least 1 now.
        let degree = samples.len() - 1;
        // Interpolate all but the last sample.
        let prev = Self::compute_interpolation(&samples[..degree])?;
        let (x, mut y) = samples[degree]; // The last sample.
        y.sub_assign(&prev.evaluate(x));
        let step = Self::lagrange(x, &samples[..degree])?;
        Self::constant(y).map(|poly| poly * step + prev)
    }

    /// Returns the Lagrange base polynomial that is `1` in `p` and `0` in every `samples[i].0`.
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we hit the system's locked memory limit.
    fn lagrange(p: Fr, samples: &[(Fr, Fr)]) -> Result<Self> {
        let mut result = Self::one()?;
        for &(sx, _) in samples {
            let mut denom = p;
            denom.sub_assign(&sx);
            denom = denom.inverse().expect("sample points must be distinct");
            result *= (Self::identity()? - Self::constant(sx)?) * Self::constant(denom)?;
        }
        Ok(result)
    }

    // Removes the `mlock` for `len` elements that have been truncated from the `coeff` vector.
    fn truncate_mlock(&self, len: usize) -> Result<()> {
        if !*SHOULD_MLOCK_SECRETS {
            return Ok(());
        }
        let n_bytes_truncated = len * size_of::<Fr>();
        if n_bytes_truncated == 0 {
            return Ok(());
        }
        unsafe {
            let ptr = self.coeff.as_ptr().offset(self.coeff.len() as isize) as *mut u8;
            let munlock_succeeded = munlock(ptr, n_bytes_truncated);
            if munlock_succeeded {
                Ok(())
            } else {
                let e = Error::MunlockFailed {
                    errno: errno(),
                    addr: format!("{:?}", ptr),
                    n_bytes: n_bytes_truncated,
                };
                Err(e)
            }
        }
    }

    // Extends the `mlock` on the `coeff` vector when `len` new elements are added.
    fn extend_mlock(&self, len: usize) -> Result<()> {
        if !*SHOULD_MLOCK_SECRETS {
            return Ok(());
        }
        let n_bytes_extended = len * size_of::<Fr>();
        if n_bytes_extended == 0 {
            return Ok(());
        }
        let offset = (self.coeff.len() - len) as isize;
        unsafe {
            let ptr = self.coeff.as_ptr().offset(offset) as *mut u8;
            let mlock_succeeded = mlock(ptr, n_bytes_extended);
            if mlock_succeeded {
                Ok(())
            } else {
                let e = Error::MunlockFailed {
                    errno: errno(),
                    addr: format!("{:?}", ptr),
                    n_bytes: n_bytes_extended,
                };
                Err(e)
            }
        }
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field elements.
    pub fn reveal(&self) -> String {
        format!("Poly {{ coeff: {:?} }}", self.coeff)
    }
}

/// A commitment to a univariate polynomial.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Commitment {
    /// The coefficients of the polynomial.
    #[serde(with = "super::serde_impl::projective_vec")]
    pub(super) coeff: Vec<G1>,
}

impl Hash for Commitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.coeff.len().hash(state);
        for c in &self.coeff {
            c.into_affine().into_compressed().as_ref().hash(state);
        }
    }
}

impl<B: Borrow<Commitment>> ops::AddAssign<B> for Commitment {
    fn add_assign(&mut self, rhs: B) {
        let len = cmp::max(self.coeff.len(), rhs.borrow().coeff.len());
        self.coeff.resize(len, G1::zero());
        for (self_c, rhs_c) in self.coeff.iter_mut().zip(&rhs.borrow().coeff) {
            self_c.add_assign(rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Commitment>> ops::Add<B> for &'a Commitment {
    type Output = Commitment;

    fn add(self, rhs: B) -> Commitment {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Commitment>> ops::Add<B> for Commitment {
    type Output = Commitment;

    fn add(mut self, rhs: B) -> Commitment {
        self += rhs;
        self
    }
}

impl Commitment {
    /// Returns the polynomial's degree.
    pub fn degree(&self) -> usize {
        self.coeff.len() - 1
    }

    /// Returns the `i`-th public key share.
    pub fn evaluate<T: IntoFr>(&self, i: T) -> G1 {
        let mut result = match self.coeff.last() {
            None => return G1::zero(),
            Some(c) => *c,
        };
        let x = i.into_fr();
        for c in self.coeff.iter().rev().skip(1) {
            result.mul_assign(x);
            result.add_assign(c);
        }
        result
    }

    /// Removes all trailing zero coefficients.
    fn remove_zeros(&mut self) {
        let zeros = self.coeff.iter().rev().take_while(|c| c.is_zero()).count();
        let len = self.coeff.len() - zeros;
        self.coeff.truncate(len)
    }
}

/// A symmetric bivariate polynomial in the prime field.
///
/// This can be used for Verifiable Secret Sharing and Distributed Key Generation. See the module
/// documentation for details.
pub struct BivarPoly {
    /// The polynomial's degree in each of the two variables.
    degree: usize,
    /// The coefficients of the polynomial. Coefficient `(i, j)` for `i <= j` is in position
    /// `j * (j + 1) / 2 + i`.
    coeff: Vec<Fr>,
}

/// # Panics
///
/// Panics if we have hit the system's locked memory limit when `mlock`ing the new instance of
/// `BivarPoly`.
impl Clone for BivarPoly {
    fn clone(&self) -> Self {
        let poly = BivarPoly {
            degree: self.degree,
            coeff: self.coeff.clone(),
        };
        if let Err(e) = poly.mlock_secret_memory() {
            panic!("Failed to clone `BivarPoly`: {}", e);
        }
        poly
    }
}

/// # Panics
///
/// Panics if we fail to munlock the `coeff` vector.
impl Drop for BivarPoly {
    fn drop(&mut self) {
        self.zero_secret_memory();
        if let Err(e) = self.munlock_secret_memory() {
            panic!("Failed to munlock `BivarPoly` during drop: {}", e);
        }
    }
}

/// A debug statement where the `coeff` vector has been redacted.
impl Debug for BivarPoly {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "BivarPoly {{ degree: {}, coeff: ... }}", self.degree)
    }
}

impl ContainsSecret for BivarPoly {
    fn mlock_secret_memory(&self) -> Result<()> {
        if !*SHOULD_MLOCK_SECRETS {
            return Ok(());
        }
        let ptr = self.coeff.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.coeff.as_slice());
        if n_bytes == 0 {
            return Ok(());
        }
        let mlock_succeeded = unsafe { mlock(ptr, n_bytes) };
        if mlock_succeeded {
            Ok(())
        } else {
            let e = Error::MlockFailed {
                errno: errno(),
                addr: format!("{:?}", ptr),
                n_bytes,
            };
            Err(e)
        }
    }

    fn munlock_secret_memory(&self) -> Result<()> {
        if !*SHOULD_MLOCK_SECRETS {
            return Ok(());
        }
        let ptr = self.coeff.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.coeff.as_slice());
        if n_bytes == 0 {
            return Ok(());
        }
        let munlock_succeeded = unsafe { munlock(ptr, n_bytes) };
        if munlock_succeeded {
            Ok(())
        } else {
            let e = Error::MunlockFailed {
                errno: errno(),
                addr: format!("{:?}", ptr),
                n_bytes,
            };
            Err(e)
        }
    }

    fn zero_secret_memory(&self) {
        let ptr = self.coeff.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.coeff.as_slice());
        unsafe {
            memzero(ptr, n_bytes);
        }
    }
}

impl BivarPoly {
    /// Creates a random polynomial.
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we have reached the systems's locked memory limit.
    pub fn random<R: Rng>(degree: usize, rng: &mut R) -> Result<Self> {
        let poly = BivarPoly {
            degree,
            coeff: (0..coeff_pos(degree + 1, 0)).map(|_| rng.gen()).collect(),
        };
        poly.mlock_secret_memory()?;
        Ok(poly)
    }

    /// Returns the polynomial's degree; which is the same in both variables.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the polynomial's value at the point `(x, y)`.
    pub fn evaluate<T: IntoFr>(&self, x: T, y: T) -> Fr {
        let x_pow = self.powers(x);
        let y_pow = self.powers(y);
        // TODO: Can we save a few multiplication steps here due to the symmetry?
        let mut result = Fr::zero();
        for (i, x_pow_i) in x_pow.into_iter().enumerate() {
            for (j, y_pow_j) in y_pow.iter().enumerate() {
                let mut summand = self.coeff[coeff_pos(i, j)];
                summand.mul_assign(&x_pow_i);
                summand.mul_assign(y_pow_j);
                result.add_assign(&summand);
            }
        }
        result
    }

    /// Returns the `x`-th row, as a univariate polynomial.
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we have reached the systems's locked memory limit when
    /// creating the new `Poly` instance.
    pub fn row<T: IntoFr>(&self, x: T) -> Result<Poly> {
        let x_pow = self.powers(x);
        let coeff: Vec<Fr> = (0..=self.degree)
            .map(|i| {
                // TODO: clear these secrets from the stack.
                let mut result = Fr::zero();
                for (j, x_pow_j) in x_pow.iter().enumerate() {
                    let mut summand = self.coeff[coeff_pos(i, j)];
                    summand.mul_assign(x_pow_j);
                    result.add_assign(&summand);
                }
                result
            })
            .collect();
        Poly::new(coeff)
    }

    /// Returns the corresponding commitment. That information can be shared publicly.
    pub fn commitment(&self) -> BivarCommitment {
        let to_pub = |c: &Fr| G1Affine::one().mul(*c);
        BivarCommitment {
            degree: self.degree,
            coeff: self.coeff.iter().map(to_pub).collect(),
        }
    }

    /// Returns the `0`-th to `degree`-th power of `x`.
    fn powers<T: IntoFr>(&self, x: T) -> Vec<Fr> {
        powers(x, self.degree)
    }

    /// Generates a non-redacted debug string. This method differs from the
    /// `Debug` implementation in that it *does* leak the the struct's
    /// internal state.
    pub fn reveal(&self) -> String {
        format!(
            "BivarPoly {{ degree: {}, coeff: {:?} }}",
            self.degree, self.coeff
        )
    }
}

/// A commitment to a symmetric bivariate polynomial.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct BivarCommitment {
    /// The polynomial's degree in each of the two variables.
    degree: usize,
    /// The commitments to the coefficients.
    #[serde(with = "super::serde_impl::projective_vec")]
    coeff: Vec<G1>,
}

impl Hash for BivarCommitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.degree.hash(state);
        for c in &self.coeff {
            c.into_affine().into_compressed().as_ref().hash(state);
        }
    }
}

impl BivarCommitment {
    /// Returns the polynomial's degree: It is the same in both variables.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Returns the commitment's value at the point `(x, y)`.
    pub fn evaluate<T: IntoFr>(&self, x: T, y: T) -> G1 {
        let x_pow = self.powers(x);
        let y_pow = self.powers(y);
        // TODO: Can we save a few multiplication steps here due to the symmetry?
        let mut result = G1::zero();
        for (i, x_pow_i) in x_pow.into_iter().enumerate() {
            for (j, y_pow_j) in y_pow.iter().enumerate() {
                let mut summand = self.coeff[coeff_pos(i, j)];
                summand.mul_assign(x_pow_i);
                summand.mul_assign(*y_pow_j);
                result.add_assign(&summand);
            }
        }
        result
    }

    /// Returns the `x`-th row, as a commitment to a univariate polynomial.
    pub fn row<T: IntoFr>(&self, x: T) -> Commitment {
        let x_pow = self.powers(x);
        let coeff: Vec<G1> = (0..=self.degree)
            .map(|i| {
                let mut result = G1::zero();
                for (j, x_pow_j) in x_pow.iter().enumerate() {
                    let mut summand = self.coeff[coeff_pos(i, j)];
                    summand.mul_assign(*x_pow_j);
                    result.add_assign(&summand);
                }
                result
            })
            .collect();
        Commitment { coeff }
    }

    /// Returns the `0`-th to `degree`-th power of `x`.
    fn powers<T: IntoFr>(&self, x: T) -> Vec<Fr> {
        powers(x, self.degree)
    }
}

/// Returns the `0`-th to `degree`-th power of `x`.
fn powers<T: IntoFr>(into_x: T, degree: usize) -> Vec<Fr> {
    let x = into_x.into_fr();
    let mut x_pow_i = Fr::one();
    iter::once(x_pow_i)
        .chain((0..degree).map(|_| {
            x_pow_i.mul_assign(&x);
            x_pow_i
        }))
        .collect()
}

/// Returns the position of coefficient `(i, j)` in the vector describing a symmetric bivariate
/// polynomial.
fn coeff_pos(i: usize, j: usize) -> usize {
    // Since the polynomial is symmetric, we can order such that `j >= i`.
    if j >= i {
        j * (j + 1) / 2 + i
    } else {
        i * (i + 1) / 2 + j
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{coeff_pos, BivarPoly, IntoFr, Poly};

    use ff::Field;
    use pairing::bls12_381::{Fr, G1Affine};
    use pairing::CurveAffine;
    use rand;

    #[test]
    fn test_coeff_pos() {
        let mut i = 0;
        let mut j = 0;
        for n in 0..100 {
            assert_eq!(n, coeff_pos(i, j));
            if i >= j {
                j += 1;
                i = 0;
            } else {
                i += 1;
            }
        }
    }

    #[test]
    fn poly() {
        // The polynomial 5 X³ + X - 2.
        let x_pow_3 = Poly::monomial(3).expect("Failed to create monic polynomial of degree 3");
        let x_pow_1 = Poly::monomial(1).expect("Failed to create monic polynomial of degree 1");
        let poly = x_pow_3 * 5 + x_pow_1 - 2;

        let coeff: Vec<_> = [-2, 1, 0, 5].into_iter().map(IntoFr::into_fr).collect();
        assert_eq!(Poly { coeff }, poly);
        let samples = vec![(-1, -8), (2, 40), (3, 136), (5, 628)];
        for &(x, y) in &samples {
            assert_eq!(y.into_fr(), poly.evaluate(x));
        }
        let interp = Poly::interpolate(samples).expect("Failed to interpolate `Poly`");
        assert_eq!(interp, poly);
    }

    #[test]
    fn distributed_key_generation() {
        let mut rng = rand::thread_rng();
        let dealer_num = 3;
        let node_num = 5;
        let faulty_num = 2;

        // For distributed key generation, a number of dealers, only one of who needs to be honest,
        // generates random bivariate polynomials and publicly commits to them. In partice, the
        // dealers can e.g. be any `faulty_num + 1` nodes.
        let bi_polys: Vec<BivarPoly> = (0..dealer_num)
            .map(|_| {
                BivarPoly::random(faulty_num, &mut rng)
                    .expect("Failed to create random `BivarPoly`")
            })
            .collect();
        let pub_bi_commits: Vec<_> = bi_polys.iter().map(BivarPoly::commitment).collect();

        let mut sec_keys = vec![Fr::zero(); node_num];

        // Each dealer sends row `m` to node `m`, where the index starts at `1`. Don't send row `0`
        // to anyone! The nodes verify their rows, and send _value_ `s` on to node `s`. They again
        // verify the values they received, and collect them.
        for (bi_poly, bi_commit) in bi_polys.iter().zip(&pub_bi_commits) {
            for m in 1..=node_num {
                // Node `m` receives its row and verifies it.
                let row_poly = bi_poly
                    .row(m)
                    .unwrap_or_else(|_| panic!("Failed to create row #{}", m));
                let row_commit = bi_commit.row(m);
                assert_eq!(row_poly.commitment(), row_commit);
                // Node `s` receives the `s`-th value and verifies it.
                for s in 1..=node_num {
                    let val = row_poly.evaluate(s);
                    let val_g1 = G1Affine::one().mul(val);
                    assert_eq!(bi_commit.evaluate(m, s), val_g1);
                    // The node can't verify this directly, but it should have the correct value:
                    assert_eq!(bi_poly.evaluate(m, s), val);
                }

                // A cheating dealer who modified the polynomial would be detected.
                let x_pow_2 =
                    Poly::monomial(2).expect("Failed to create monic polynomial of degree 2");
                let five = Poly::constant(5.into_fr())
                    .expect("Failed to create polynomial with constant 5");
                let wrong_poly = row_poly.clone() + x_pow_2 * five;
                assert_ne!(wrong_poly.commitment(), row_commit);

                // If `2 * faulty_num + 1` nodes confirm that they received a valid row, then at
                // least `faulty_num + 1` honest ones did, and sent the correct values on to node
                // `s`. So every node received at least `faulty_num + 1` correct entries of their
                // column/row (remember that the bivariate polynomial is symmetric). They can
                // reconstruct the full row and in particular value `0` (which no other node knows,
                // only the dealer). E.g. let's say nodes `1`, `2` and `4` are honest. Then node
                // `m` received three correct entries from that row:
                let received: BTreeMap<_, _> = [1, 2, 4]
                    .iter()
                    .map(|&i| (i, bi_poly.evaluate(m, i)))
                    .collect();
                let my_row =
                    Poly::interpolate(received).expect("Failed to create `Poly` via interpolation");
                assert_eq!(bi_poly.evaluate(m, 0), my_row.evaluate(0));
                assert_eq!(row_poly, my_row);

                // The node sums up all values number `0` it received from the different dealer. No
                // dealer and no other node knows the sum in the end.
                sec_keys[m - 1].add_assign(&my_row.evaluate(Fr::zero()));
            }
        }

        // Each node now adds up all the first values of the rows it received from the different
        // dealers (excluding the dealers where fewer than `2 * faulty_num + 1` nodes confirmed).
        // The whole first column never gets added up in practice, because nobody has all the
        // information. We do it anyway here; entry `0` is the secret key that is not known to
        // anyone, neither a dealer, nor a node:
        let mut sec_key_set = Poly::zero().expect("Failed to create empty `Poly`");
        for bi_poly in &bi_polys {
            sec_key_set += bi_poly
                .row(0)
                .expect("Failed to create `Poly` from row #0 for `BivarPoly`");
        }
        for m in 1..=node_num {
            assert_eq!(sec_key_set.evaluate(m), sec_keys[m - 1]);
        }

        // The sum of the first rows of the public commitments is the commitment to the secret key
        // set.
        let mut sum_commit = Poly::zero()
            .expect("Failed to create empty `Poly`")
            .commitment();
        for bi_commit in &pub_bi_commits {
            sum_commit += bi_commit.row(0);
        }
        assert_eq!(sum_commit, sec_key_set.commitment());
    }
}
