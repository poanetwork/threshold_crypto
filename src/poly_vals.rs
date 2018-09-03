use std::borrow::Borrow;
use std::fmt::{self, Debug, Formatter};
use std::mem::size_of_val;
use std::ops;

use errno::errno;
use memsec::{memzero, mlock, munlock};
use pairing::bls12_381::Fr;
use pairing::{Field, PrimeField};

use super::{ContainsSecret, Error, IntoFr, Poly, Result, SHOULD_MLOCK_SECRETS};

/// A univariate polynomial in the prime field, represented by its values on the roots of unity.
/// This is the Fourier transform of the original polynomial.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct PolyVals {
    /// The binary logarithm of the number of values.
    log_n: usize,
    /// The values of the polynomial, on `w.pow(0)`, `w.pow(1)`, ..., where `w` is the canonical
    /// primitive `2.pow(log_n)`-th root of unity.
    #[serde(with = "super::serde_impl::field_vec")]
    vals: Vec<Fr>,
}

/// Creates a new `PolyVals` with the same values as another polynomial.
///
/// # Panics
///
/// Panics if we have hit the system's locked memory limit when `mlock`ing the new instance of
/// `PolyVals`.
impl Clone for PolyVals {
    fn clone(&self) -> Self {
        let poly_v = PolyVals {
            log_n: self.log_n,
            vals: self.vals.clone(),
        };
        poly_v
            .mlock_secret_memory()
            .expect("Failed to clone `PolyVals`");
        poly_v
    }
}

/// A debug statement where the `vals` vector of prime field elements has been redacted.
impl Debug for PolyVals {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "PolyVals {{ log_n: {}, vals: ... }}", self.log_n)
    }
}

/// # Panics
///
/// Panics if the dimensions of the summands disagree.
#[cfg_attr(feature = "cargo-clippy", allow(suspicious_op_assign_impl))]
impl<B: Borrow<PolyVals>> ops::AddAssign<B> for PolyVals {
    fn add_assign(&mut self, rhs: B) {
        let rhs = rhs.borrow();
        if self.log_n != rhs.log_n {
            panic!(
                "Tried to add a PolyVals of size {} to one of size {}.",
                1 << rhs.log_n,
                1 << self.log_n
            );
        }
        for (self_c, rhs_c) in self.vals.iter_mut().zip(&rhs.borrow().vals) {
            self_c.add_assign(rhs_c);
        }
    }
}

impl<'a, B: Borrow<PolyVals>> ops::Add<B> for &'a PolyVals {
    type Output = PolyVals;

    fn add(self, rhs: B) -> PolyVals {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<PolyVals>> ops::Add<B> for PolyVals {
    type Output = PolyVals;

    fn add(mut self, rhs: B) -> PolyVals {
        self += rhs;
        self
    }
}

/// # Panics
///
/// Panics if we hit the system's locked memory limit or if we fail to unlock memory that has been
/// truncated from the `vals` vector.
impl<'a> ops::Add<Fr> for PolyVals {
    type Output = PolyVals;

    fn add(mut self, rhs: Fr) -> Self::Output {
        for val in &mut self.vals {
            val.add_assign(&rhs);
        }
        self
    }
}

impl<'a> ops::Add<u64> for PolyVals {
    type Output = PolyVals;

    fn add(self, rhs: u64) -> Self::Output {
        self + rhs.into_fr()
    }
}

/// # Panics
///
/// Panics if the dimensions of the two `PolyVals`' disagree.
// Clippy thinks using `<<` in a `Sub` implementation is suspicious.
#[cfg_attr(feature = "cargo-clippy", allow(suspicious_op_assign_impl))]
impl<B: Borrow<PolyVals>> ops::SubAssign<B> for PolyVals {
    fn sub_assign(&mut self, rhs: B) {
        let rhs = rhs.borrow();
        if self.log_n != rhs.log_n {
            panic!(
                "Tried to subtract a PolyVals of size {} from one of size {}.",
                1 << rhs.log_n,
                1 << self.log_n
            );
        }
        for (self_c, rhs_c) in self.vals.iter_mut().zip(&rhs.borrow().vals) {
            self_c.sub_assign(rhs_c);
        }
    }
}

impl<'a, B: Borrow<PolyVals>> ops::Sub<B> for &'a PolyVals {
    type Output = PolyVals;

    fn sub(self, rhs: B) -> PolyVals {
        (*self).clone() - rhs
    }
}

impl<B: Borrow<PolyVals>> ops::Sub<B> for PolyVals {
    type Output = PolyVals;

    fn sub(mut self, rhs: B) -> PolyVals {
        self -= rhs;
        self
    }
}

// Clippy thinks using `+` in a `Sub` implementation is suspicious.
#[cfg_attr(feature = "cargo-clippy", allow(suspicious_arithmetic_impl))]
impl<'a> ops::Sub<Fr> for PolyVals {
    type Output = PolyVals;

    fn sub(self, mut rhs: Fr) -> Self::Output {
        rhs.negate();
        self + rhs
    }
}

impl<'a> ops::Sub<u64> for PolyVals {
    type Output = PolyVals;

    fn sub(self, rhs: u64) -> Self::Output {
        self - rhs.into_fr()
    }
}

/// # Panics
///
/// Panics if the dimensions of the two `PolyVals`' disagree.
// Clippy thinks using `<<` in a `MulAssign` implementation is suspicious.
#[cfg_attr(feature = "cargo-clippy", allow(suspicious_op_assign_impl))]
impl<B: Borrow<Self>> ops::MulAssign<B> for PolyVals {
    fn mul_assign(&mut self, rhs: B) {
        let rhs = rhs.borrow();
        if self.log_n != rhs.log_n {
            panic!(
                "Tried to multiply a PolyVals of size {} with one of size {}.",
                1 << rhs.log_n,
                1 << self.log_n
            );
        }
        for (self_v, rhs_v) in self.vals.iter_mut().zip(&rhs.borrow().vals) {
            self_v.mul_assign(rhs_v);
        }
    }
}

impl<B: Borrow<PolyVals>> ops::Mul<B> for PolyVals {
    type Output = PolyVals;

    fn mul(mut self, rhs: B) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<'a, B: Borrow<PolyVals>> ops::Mul<B> for &'a PolyVals {
    type Output = PolyVals;

    fn mul(self, rhs: B) -> Self::Output {
        self.clone() * rhs
    }
}

impl<'a> ops::Mul<Fr> for PolyVals {
    type Output = PolyVals;

    fn mul(mut self, rhs: Fr) -> Self::Output {
        self.vals.iter_mut().for_each(|c| c.mul_assign(&rhs));
        self
    }
}

impl<'a> ops::Mul<u64> for PolyVals {
    type Output = PolyVals;

    fn mul(self, rhs: u64) -> Self::Output {
        self * rhs.into_fr()
    }
}

/// # Panics
///
/// Panics if we fail to munlock the `vals` vector.
impl Drop for PolyVals {
    fn drop(&mut self) {
        self.zero_secret_memory();
        if let Err(e) = self.munlock_secret_memory() {
            panic!("Failed to munlock `PolyVals` during drop: {}", e);
        }
    }
}

impl ContainsSecret for PolyVals {
    fn mlock_secret_memory(&self) -> Result<()> {
        if !*SHOULD_MLOCK_SECRETS {
            return Ok(());
        }
        let ptr = self.vals.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.vals.as_slice());
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
        let ptr = self.vals.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.vals.as_slice());
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
        let ptr = self.vals.as_ptr() as *mut u8;
        let n_bytes = size_of_val(self.vals.as_slice());
        unsafe {
            memzero(ptr, n_bytes);
        }
    }
}

impl PolyVals {
    /// Creates a new `Poly` instance from a vector of prime field elements representing the
    /// coefficients of the polynomial. The `mlock` system call is applied to the region of the
    /// heap where the field elements are allocated.
    ///
    /// # Errors
    ///
    /// Returns an `Error::MlockFailed` if we have reached the systems's locked memory limit.
    pub fn new(log_n: usize, vals: Vec<Fr>) -> Result<Self> {
        if vals.len() != 1 << log_n {
            panic!("PolyVals must have exactly n values."); // TODO: Return an error.
        }
        let p_vals = PolyVals { vals, log_n };
        p_vals.mlock_secret_memory()?;
        Ok(p_vals)
    }

    /// Applies the inverse Fourier transform to convert this back into a `Poly`.
    pub fn inverse_fourier_transform(&self) -> Result<Poly> {
        // The canonical primitive `n`-th root of unity.
        let mut root = Fr::root_of_unity();
        // Roots of unity always have an inverse.
        root = root.inverse().expect("failed to invert root of unity");
        for _ in self.log_n..(Fr::S as usize) {
            root.square();
        }
        let poly = Poly::new(fourier_transform(self.log_n, &self.vals, &root))?;
        // Any non-zero usize value is smaller than `Fr`'s modulus and can be inverted.
        Ok(poly
            * (1 << self.log_n)
                .into_fr()
                .inverse()
                .expect("could not invert n"))
    }

    /// Generates a non-redacted debug string. This method differs from
    /// the `Debug` implementation in that it *does* leak the secret prime
    /// field elements.
    pub fn reveal(&self) -> String {
        format!("PolyVals {{ vals: {:?} }}", self.vals)
    }
}

/// Returns the Fourier transform of the polynomial with the given coefficients.
// TODO: This implementation involves a lot of cloning and recursive method calls.
//       See whether it can be optimized and/or made more readable.
//       Make sure no secrets can be leaked: zero (and mlock?) temporary variables.
//       Replace some of the panics with errors.
pub(crate) fn fourier_transform(log_n: usize, coeff: &[Fr], root: &Fr) -> Vec<Fr> {
    if log_n == 0 {
        return vec![coeff.get(0).cloned().unwrap_or_else(Fr::zero)];
    }
    if log_n > Fr::S as usize {
        panic!("Polynomial degree too large: no root of unity exists.");
    }
    let n = 1 << log_n;
    if coeff.len() > n {
        panic!("Polynomial degree must be at most the dimension.");
    }

    let mut even = false;
    let (even_coeff, odd_coeff): (Vec<_>, Vec<_>) = coeff.iter().cloned().partition(|_| {
        even = !even;
        even
    });
    let mut root_sq = *root;
    root_sq.square();
    let even_tf = fourier_transform(log_n - 1, &even_coeff, &root_sq);
    let mut odd_tf = fourier_transform(log_n - 1, &odd_coeff, &root_sq);
    let mut root_pow_i = *root;
    for val in odd_tf.iter_mut().skip(1) {
        val.mul_assign(&root_pow_i);
        root_pow_i.mul_assign(root);
    }
    let n2 = n >> 1;
    let mut result: Vec<Fr> = even_tf.iter().chain(&even_tf).cloned().collect();
    for i in 0..n2 {
        result[i].add_assign(&odd_tf[i]);
        result[i + n2].sub_assign(&odd_tf[i]);
    }
    result
}

#[cfg(test)]
mod tests {
    use poly::Poly;

    fn x_pow(exp: usize) -> Poly {
        Poly::monomial(exp).expect("failed to create monic polynomial")
    }

    #[test]
    fn test_fourier_transform() {
        let poly = x_pow(5) * 3 + x_pow(3) * 5 + x_pow(1) - 2;
        let result = poly
            .fourier_transform(3)
            .expect("failed to apply Fourier transform")
            .inverse_fourier_transform()
            .expect("failed to apply inverse Fourier transform");
        assert_eq!(poly, result);
    }

    #[test]
    fn test_arithmetic() {
        // The polynomials 5 X³ + X - 2 and 3 X² + 2 X - 1.
        let poly_0 = x_pow(3) * 5 + x_pow(1) - 2;
        let poly_1 = x_pow(2) * 3 + x_pow(1) * 2 - 1;

        // Product has degree 5. Next pow of 2 is 8 == 1 << 3.
        let p0_fft = poly_0
            .fourier_transform(3)
            .expect("failed to apply Fourier transform");
        let p1_fft = poly_1
            .fourier_transform(3)
            .expect("failed to apply Fourier transform");

        let prod_fft = &p0_fft * &p1_fft;
        let prod = prod_fft
            .inverse_fourier_transform()
            .expect("failed to apply inverse Fourier transform");
        assert_eq!((&poly_0 * &poly_1), prod);

        let sum_fft = p0_fft + p1_fft;
        let sum = sum_fft
            .inverse_fourier_transform()
            .expect("failed to apply inverse Fourier transform");
        assert_eq!((poly_0 + poly_1), sum);
    }
}
