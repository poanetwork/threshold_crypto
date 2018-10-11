//! Eigth Mersenne prime field
//!
//! The eighth [Mersenne Prime](https://en.wikipedia.org/wiki/Mersenne_prime) (`MS8 := 2^31-1) can
//! be used to construct a finite field supporting addition and multiplication. This module provides
//! a wrapper type around `u32` to implement this functionality.
//!
//! The resulting type also implements the `Field`, `PrimeField` and `SqrtField` traits. For
//! convenience, `PrimeFieldRepr` is also implemented.

use std::io::{self, Read, Write};
use std::{fmt, mem, ops};

use byteorder::{BigEndian, ByteOrder};
use pairing::{
    Field, LegendreSymbol, PrimeField, PrimeFieldDecodingError, PrimeFieldRepr, SqrtField,
};
use rand;

/// Modular exponentiation
///
/// Warning: Only tested using bases and exponents `< MS8`.
#[inline]
fn modular_pow(base: u32, mut exp: u32, modulus: u32) -> u32 {
    // Source: https://en.wikipedia.org/wiki/Modular_exponentiation#Right-to-left_binary_method
    if modulus == 1 {
        return 0;
    }

    // Need to use 64 bits to ensure the assert from Schneier's algorithm:
    // (modulus - 1) * (modulus - 1) does not overflow base
    let mut result: u64 = 1;
    let md: u64 = u64::from(modulus);
    let mut base = u64::from(base) % md;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % md;
        }
        exp >>= 1;
        base = (base * base) % md;
    }

    result as u32
}

/// Eigth Mersenne prime, aka `i32::MAX`.
pub const MS8: u32 = 0x7fff_ffff;

/// Eighth Mersenne prime field element
///
/// Finite field of order `2^31-1`.
#[derive(Copy, Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Mersenne8(pub u32);

// We opt to implement the same variants the standard library implements as well:
//
// FooAssign: `lhs .= rhs, lhs .= &rhs`.
// Foo: `lhs . rhs, &lhs . rhs, &lhs . &rhs, lhs . &rhs`
macro_rules! generate_op_impls {
    ($t:ty, $op_name:ident, $op_name_assign:ident, $op_method:ident, $op_method_assign:ident) => {
        // Supplied by caller: `lhs .= rhs`

        // `lhs . rhs`
        impl ops::$op_name for $t {
            type Output = Self;

            #[inline]
            fn $op_method(mut self, rhs: $t) -> Self {
                self.$op_method_assign(&rhs);
                self
            }
        }

        // lhs .= &rhs
        impl<'a> ops::$op_name_assign<&'a $t> for $t {
            #[inline]
            fn $op_method_assign(&mut self, rhs: &'a $t) {
                ops::$op_name_assign::$op_method_assign(self, *rhs)
            }
        }

        // `&lhs . rhs`
        impl<'a> ops::$op_name<$t> for &'a $t {
            type Output = $t;

            #[inline]
            fn $op_method(self, other: $t) -> Self::Output {
                let mut tmp = *self;
                tmp.$op_method_assign(&other);
                tmp
            }
        }

        // `&lhs . &rhs`
        impl<'a, 'b> ops::$op_name<&'b $t> for &'a $t {
            type Output = $t;

            #[inline]
            fn $op_method(self, other: &'b $t) -> Self::Output {
                let mut tmp = *self;
                tmp.$op_method_assign(other);
                tmp
            }
        }

        // `lhs . &rhs`
        impl<'a> ops::$op_name<&'a $t> for $t {
            type Output = $t;

            #[inline]
            fn $op_method(mut self, other: &'a $t) -> Self::Output {
                self.$op_method_assign(other);
                self
            }
        }
    };
}

impl ops::SubAssign<Mersenne8> for Mersenne8 {
    #[inline]
    fn sub_assign(&mut self, rhs: Mersenne8) {
        // Since `self.0` is < 2^31-1, `self.0 + 2^31-1` is still smaller than `u32::MAX`.
        self.0 = (self.0 + MS8 - rhs.0) % MS8;
    }
}
generate_op_impls!(Mersenne8, Sub, SubAssign, sub, sub_assign);

impl ops::AddAssign<Mersenne8> for Mersenne8 {
    #[inline]
    fn add_assign(&mut self, rhs: Mersenne8) {
        self.0 = (self.0 + rhs.0) % MS8;
    }
}
generate_op_impls!(Mersenne8, Add, AddAssign, add, add_assign);

impl ops::MulAssign for Mersenne8 {
    #[inline]
    fn mul_assign(&mut self, rhs: Mersenne8) {
        // Usually, Schrage's method would be a good way to implement the multiplication;
        // however, since we will mostly be running the code on 64-bit machines and
        // `(2^31-1)^2 < 2^64`, we can cheat and do this fairly fast in 64 bits.
        self.0 = (u64::from(self.0) * u64::from(rhs.0) % u64::from(MS8)) as u32;
    }
}

generate_op_impls!(Mersenne8, Mul, MulAssign, mul, mul_assign);

impl Mersenne8 {
    #[inline]
    pub fn new(v: u32) -> Mersenne8 {
        Mersenne8(v % MS8)
    }

    #[inline]
    pub fn pow(self, exp: u32) -> Mersenne8 {
        Mersenne8(modular_pow(self.0, exp, MS8))
    }
}

impl From<u32> for Mersenne8 {
    #[inline]
    fn from(v: u32) -> Mersenne8 {
        Mersenne8::new(v)
    }
}

impl From<u64> for Mersenne8 {
    #[inline]
    fn from(v: u64) -> Mersenne8 {
        Mersenne8((v % u64::from(MS8)) as u32)
    }
}

impl From<Mersenne8> for u32 {
    fn from(v: Mersenne8) -> u32 {
        v.0
    }
}

impl PartialEq<u32> for Mersenne8 {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl fmt::Display for Mersenne8 {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl rand::Rand for Mersenne8 {
    #[inline]
    fn rand<R: rand::Rng>(rng: &mut R) -> Self {
        Mersenne8::from(<u32 as rand::Rand>::rand(rng))
    }
}

impl Field for Mersenne8 {
    #[inline]
    fn zero() -> Self {
        Mersenne8(0)
    }

    #[inline]
    fn one() -> Self {
        Mersenne8(1)
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0 == 0
    }

    #[inline]
    fn square(&mut self) {
        self.0 = (*self * *self).0;
    }

    #[inline]
    fn double(&mut self) {
        // MS8 fits at least twice into a single u32.
        self.0 = (self.0 * 2) % MS8;
    }

    #[inline]
    fn negate(&mut self) {
        self.0 = (Self::zero() - *self).0;
    }

    #[inline]
    fn add_assign(&mut self, other: &Self) {
        *self += other;
    }

    #[inline]
    fn sub_assign(&mut self, other: &Self) {
        *self -= other;
    }

    #[inline]
    fn mul_assign(&mut self, other: &Self) {
        *self *= other;
    }

    #[inline]
    fn inverse(&self) -> Option<Self> {
        let (d, _s, t) = ext_euclid(MS8, self.0);

        // MS8 is prime, so the gcd should always be 1, unless the number itself is 0.
        if d != 1 {
            debug_assert_eq!(d, MS8);
            return None;
        }

        Some(Mersenne8::new(
            ((t + i64::from(MS8)) % i64::from(MS8)) as u32,
        ))
    }

    #[inline]
    fn frobenius_map(&mut self, _power: usize) {
        // Does nothing, the frobenius endomorphism is the identity function in every finite field
        // of prime order.
    }
}

impl PrimeField for Mersenne8 {
    type Repr = Self;

    const NUM_BITS: u32 = 32;
    const CAPACITY: u32 = 30;

    // Not actually used.
    const S: u32 = 0;

    #[inline]
    fn from_repr(v: Self::Repr) -> Result<Self, PrimeFieldDecodingError> {
        Ok(v)
    }

    #[inline]
    fn into_repr(&self) -> Self::Repr {
        *self
    }

    #[inline]
    fn char() -> Self::Repr {
        // Awkward. We cannot return the characteristic itself, since it's not an element of field,
        // but equal to its order. Instead, we panic.
        //
        // Note: The return type of this function should probably be `usize`.
        panic!("Cannot return characteristic of Mersenne8 as an element of Mersenne8.");
    }

    #[inline]
    fn multiplicative_generator() -> Self {
        // Any element of a finite field of prime order is a generator, but 3 is the smallest one
        // that is a quadratic non-residue.
        Mersenne8::new(3)
    }

    #[inline]
    fn root_of_unity() -> Self {
        // Still unclaer what's supposed to be implemented here, missing at least an `n`?.
        unimplemented!()
    }
}

impl SqrtField for Mersenne8 {
    fn legendre(&self) -> LegendreSymbol {
        // Uses Euler's criteria: `(a/p) === a^((p-1)/2).
        let exp = (MS8 - 1) / 2;

        match (*self).pow(exp).0 {
            1 => LegendreSymbol::QuadraticResidue,
            n if n == MS8 - 1 => LegendreSymbol::QuadraticNonResidue,
            0 => LegendreSymbol::Zero,
            _ => panic!("Euler's criteria did not return correct Legendre symbol"),
        }
    }

    fn sqrt(&self) -> Option<Self> {
        unimplemented!() // FIXME, could use Tonelli-Shanks algorithm
    }
}

impl PrimeFieldRepr for Mersenne8 {
    #[inline]
    fn sub_noborrow(&mut self, other: &Self) {
        *self -= other;
    }

    #[inline]
    fn add_nocarry(&mut self, other: &Self) {
        *self += other;
    }

    #[inline]
    fn num_bits(&self) -> u32 {
        8 * mem::size_of::<Self>() as u32
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0 == 0
    }

    #[inline]
    fn is_odd(&self) -> bool {
        self.0 % 2 == 1
    }

    // #[inline]
    fn is_even(&self) -> bool {
        !self.is_odd()
    }

    #[inline]
    fn div2(&mut self) {
        self.shr(1);
    }

    #[inline]
    fn shr(&mut self, amt: u32) {
        self.0 >>= amt;
    }

    #[inline]
    fn mul2(&mut self) {
        *self *= Mersenne8::new(2);
    }

    #[inline]
    fn shl(&mut self, amt: u32) {
        // FIXME: is this correct?
        self.0 <<= amt;
        self.0 %= MS8;
    }

    fn write_be<W: Write>(&self, mut writer: W) -> io::Result<()> {
        let mut buf = [0u8; 4];
        BigEndian::write_u32(&mut buf, self.0);
        writer.write_all(&buf)?;
        Ok(())
    }

    fn read_be<R: Read>(&mut self, mut reader: R) -> io::Result<()> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        self.0 = BigEndian::read_u32(&buf);
        Ok(())
    }
}

/// Extended Euclidean algorithm
///
/// Returns the `gcd(a,b)`, as well as the
/// [Bézout coefficients](https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity) `s` and `t` (with
/// `sa + tb = gcd(a,b)`).
///
/// The function will neither panic nor overflow; however passing in `0` as either `a` or `b`
/// will not give useful results for `s` and `t`.
///
/// Note: A non-recurring implementation will probably be faster, but the recursion is simpler
///       to write.
#[inline]
fn ext_euclid(a: u32, b: u32) -> (u32, i64, i64) {
    // Bézout coefficients (`s` and `t`) are bound by `|s| <= |b/d|` and `|t| <= |a/d|`
    // (`d` being `gdc(a,b)`). (See https://en.wikipedia.org/wiki/B%C3%A9zout%27s_identity)
    //
    // FIXME: Find out of there are any larger than i32::MAX. For now, we are using an `i64` to
    //        avoid problems, at the expense of some runtime performance on 32 bit systems.

    if b == 0 {
        return (a, 1, 0);
    }

    let res = ext_euclid(b, a % b);
    let s = res.2;
    let t = res.1 - i64::from(a / b) * res.2;
    (res.0, s, t)
}

#[cfg(test)]
mod tests {
    // There are copy & pasted results of calculations from external programs in these tests.
    #![cfg_attr(feature = "cargo-clippy", allow(unreadable_literal))]
    #![cfg_attr(feature = "cargo-clippy", allow(op_ref))]
    // We test a few mathematical identities, including `c - c = 0`. Clippy complains about these
    // otherwise unusual expressions, so the lint is disabled.
    #![cfg_attr(feature = "cargo-clippy", allow(eq_op))]

    use super::{ext_euclid, modular_pow, Mersenne8};
    use pairing::Field;

    #[test]
    fn ext_euclid_simple() {
        assert_eq!(ext_euclid(56, 15), (1, -4, 15));
        assert_eq!(ext_euclid(128, 44), (4, -1, 3));
        assert_eq!(ext_euclid(44, 128), (4, 3, -1));
        assert_eq!(ext_euclid(7, 0), (7, 1, 0));
        assert_eq!(ext_euclid(0, 7), (7, 0, 1));
    }

    #[test]
    fn modular_pow_simple() {
        assert_eq!(modular_pow(2, 8, 1024), 256);

        let mods: &[u64] = &[2, 7, 256, 32000, 4294967295];

        for exp in 0..20u32 {
            for base in 2..8u64 {
                for &m in mods {
                    assert_eq!(
                        modular_pow(base as u32, exp, m as u32),
                        (base.pow(exp) % m) as u32
                    )
                }
            }
        }
    }

    #[test]
    fn construction() {
        let a: Mersenne8 = 0u32.into();
        let b: Mersenne8 = 1u32.into();
        let c: Mersenne8 = 2147483649u32.into();
        let d: Mersenne8 = 1099511627776u64.into();

        assert_eq!(a, 0);
        assert_eq!(b, 1);
        assert_eq!(c, 2);
        assert_eq!(d, 512);

        assert_eq!(a, Mersenne8::new(0));
        assert_eq!(b, Mersenne8::new(1));
        assert_eq!(c, Mersenne8::new(2));
        assert_eq!(d, Mersenne8::new(512));
    }

    #[test]
    fn addition() {
        let a = Mersenne8::new(0);
        let b = Mersenne8::new(1);
        let c = Mersenne8::new(127);
        let d = Mersenne8::new(1073741824);
        let e = Mersenne8::new(2147483646);

        // lhs . rhs
        assert_eq!(a + b, Mersenne8::new(1));
        assert_eq!(c + c, Mersenne8::new(254));
        assert_eq!(d + c, Mersenne8::new(1073741951));
        assert_eq!(d + e, Mersenne8::new(3221225470));
        assert_eq!(d + e, 1073741823);
        assert_eq!(e + e, Mersenne8::new(4294967292));

        // &lhs . rhs
        assert_eq!(a + &b, Mersenne8::new(1));
        assert_eq!(c + &c, Mersenne8::new(254));
        assert_eq!(d + &c, Mersenne8::new(1073741951));
        assert_eq!(d + &e, Mersenne8::new(3221225470));
        assert_eq!(e + &e, Mersenne8::new(4294967292));

        // lhs . &rhs
        assert_eq!(&a + b, Mersenne8::new(1));
        assert_eq!(&c + c, Mersenne8::new(254));
        assert_eq!(&d + c, Mersenne8::new(1073741951));
        assert_eq!(&d + e, Mersenne8::new(3221225470));
        assert_eq!(&e + e, Mersenne8::new(4294967292));

        // &lhs . &rhs
        assert_eq!(&a + &b, Mersenne8::new(1));
        assert_eq!(&c + &c, Mersenne8::new(254));
        assert_eq!(&d + &c, Mersenne8::new(1073741951));
        assert_eq!(&d + &e, Mersenne8::new(3221225470));
        assert_eq!(&e + &e, Mersenne8::new(4294967292));

        // lhs .= rhs
        let mut x = Mersenne8::new(8);
        assert_eq!(x, Mersenne8::new(8));
        x += a;
        assert_eq!(x, Mersenne8::new(8));
        x += b;
        assert_eq!(x, Mersenne8::new(9));
        x += c;
        assert_eq!(x, Mersenne8::new(136));
        x += d;
        assert_eq!(x, Mersenne8::new(1073741960));
        x += e;
        assert_eq!(x, Mersenne8::new(1073741959));

        // lhs .= &rhs
        let mut y = Mersenne8::new(8);
        assert_eq!(y, Mersenne8::new(8));
        y += &a;
        assert_eq!(y, Mersenne8::new(8));
        y += &b;
        assert_eq!(y, Mersenne8::new(9));
        y += &c;
        assert_eq!(y, Mersenne8::new(136));
        y += &d;
        assert_eq!(y, Mersenne8::new(1073741960));
        y += &e;
        assert_eq!(y, Mersenne8::new(1073741959));
    }

    #[test]
    fn subtraction() {
        let a = Mersenne8::new(0);
        let b = Mersenne8::new(1);
        let c = Mersenne8::new(127);
        let d = Mersenne8::new(1073741824);
        let e = Mersenne8::new(2147483646);

        // lhs . rhs
        assert_eq!(a - b, Mersenne8::new(2147483646));
        assert_eq!(c - c, Mersenne8::new(0));
        assert_eq!(d - c, Mersenne8::new(1073741697));
        assert_eq!(d - e, Mersenne8::new(1073741825));

        // &lhs . rhs
        assert_eq!(&a - b, Mersenne8::new(2147483646));
        assert_eq!(&c - c, Mersenne8::new(0));
        assert_eq!(&d - c, Mersenne8::new(1073741697));
        assert_eq!(&d - e, Mersenne8::new(1073741825));

        // lhs . &rhs
        assert_eq!(a - &b, Mersenne8::new(2147483646));
        assert_eq!(c - &c, Mersenne8::new(0));
        assert_eq!(d - &c, Mersenne8::new(1073741697));
        assert_eq!(d - &e, Mersenne8::new(1073741825));

        // &lhs . &rhs
        assert_eq!(&a - &b, Mersenne8::new(2147483646));
        assert_eq!(&c - &c, Mersenne8::new(0));
        assert_eq!(&d - &c, Mersenne8::new(1073741697));
        assert_eq!(&d - &e, Mersenne8::new(1073741825));

        // lhs .= rhs
        let mut x = Mersenne8::new(17);
        assert_eq!(x, Mersenne8::new(17));
        x -= a;
        assert_eq!(x, Mersenne8::new(17));
        x -= b;
        assert_eq!(x, Mersenne8::new(16));
        x -= c;
        assert_eq!(x, Mersenne8::new(2147483536));
        x -= d;
        assert_eq!(x, Mersenne8::new(1073741712));
        x -= e;
        assert_eq!(x, Mersenne8::new(1073741713));

        // lhs .= &rhs
        let mut y = Mersenne8::new(17);
        assert_eq!(y, Mersenne8::new(17));
        y -= &a;
        assert_eq!(y, Mersenne8::new(17));
        y -= &b;
        assert_eq!(y, Mersenne8::new(16));
        y -= &c;
        assert_eq!(y, Mersenne8::new(2147483536));
        y -= &d;
        assert_eq!(y, Mersenne8::new(1073741712));
        y -= &e;
        assert_eq!(y, Mersenne8::new(1073741713));
    }

    #[test]
    fn multiplication() {
        let a = Mersenne8::new(0);
        let b = Mersenne8::new(1);
        let c = Mersenne8::new(127);
        let d = Mersenne8::new(1073741824);
        let e = Mersenne8::new(384792341);

        // lhs . rhs
        assert_eq!(a * a, Mersenne8::new(0));
        assert_eq!(a * b, Mersenne8::new(0));
        assert_eq!(b * b, Mersenne8::new(1));
        assert_eq!(c * c, Mersenne8::new(16129));
        assert_eq!(d * c, Mersenne8::new(1073741887));
        assert_eq!(d * e, Mersenne8::new(1266137994));

        // &lhs . rhs
        assert_eq!(&a * a, Mersenne8::new(0));
        assert_eq!(&a * b, Mersenne8::new(0));
        assert_eq!(&b * b, Mersenne8::new(1));
        assert_eq!(&c * c, Mersenne8::new(16129));
        assert_eq!(&d * c, Mersenne8::new(1073741887));
        assert_eq!(&d * e, Mersenne8::new(1266137994));

        // lhs . &rhs
        assert_eq!(a * &a, Mersenne8::new(0));
        assert_eq!(a * &b, Mersenne8::new(0));
        assert_eq!(b * &b, Mersenne8::new(1));
        assert_eq!(c * &c, Mersenne8::new(16129));
        assert_eq!(d * &c, Mersenne8::new(1073741887));
        assert_eq!(d * &e, Mersenne8::new(1266137994));

        // &lhs . &rhs
        assert_eq!(&a * &a, Mersenne8::new(0));
        assert_eq!(&a * &b, Mersenne8::new(0));
        assert_eq!(&b * &b, Mersenne8::new(1));
        assert_eq!(&c * &c, Mersenne8::new(16129));
        assert_eq!(&d * &c, Mersenne8::new(1073741887));
        assert_eq!(&d * &e, Mersenne8::new(1266137994));

        // lhs .= rhs
        let mut x = Mersenne8::new(17);
        x *= b;
        assert_eq!(x, Mersenne8::new(17));
        x *= c;
        assert_eq!(x, Mersenne8::new(2159));
        x *= d;
        assert_eq!(x, Mersenne8::new(1073742903));
        x *= e;
        assert_eq!(x, Mersenne8::new(1992730062));

        // // lhs .= &rhs
        let mut y = Mersenne8::new(17);
        y *= &b;
        assert_eq!(y, Mersenne8::new(17));
        y *= &c;
        assert_eq!(y, Mersenne8::new(2159));
        y *= &d;
        assert_eq!(y, Mersenne8::new(1073742903));
        y *= &e;
        assert_eq!(y, Mersenne8::new(1992730062));
    }

    #[test]
    fn square() {
        let a = Mersenne8::new(7);
        let b = Mersenne8::new(1073729479);

        let mut a_sq = a;
        a_sq.square();
        assert_eq!(a_sq, a * a);
        assert_eq!(a_sq, 49);

        let mut b_sq = b;
        b_sq.square();
        assert_eq!(b_sq, b * b);
        assert_eq!(b_sq, 689257592);
    }

    #[test]
    fn double() {
        let mut a = Mersenne8::new(0);
        let mut b = Mersenne8::new(1);
        let mut c = Mersenne8::new(9);
        let mut d = Mersenne8::new(2147483646);

        a.double();
        b.double();
        c.double();
        d.double();

        assert_eq!(a, 0);
        assert_eq!(b, 2);
        assert_eq!(c, 18);
        assert_eq!(d, 2147483645);
    }

    #[test]
    fn negate() {
        let mut a = Mersenne8::new(0);
        let mut b = Mersenne8::new(1);
        let mut c = Mersenne8::new(9);
        let mut d = Mersenne8::new(17);
        let mut e = Mersenne8::new(16441);
        let mut f = Mersenne8::new(1073754169);

        a.negate();
        b.negate();
        c.negate();
        d.negate();
        e.negate();
        f.negate();

        assert_eq!(a, 0);
        assert_eq!(b, 2147483646);
        assert_eq!(c, 2147483638);
        assert_eq!(d, 2147483630);
        assert_eq!(e, 2147467206);
        assert_eq!(f, 1073729478);
    }

    #[test]
    fn inverse() {
        let a = Mersenne8::new(0);
        let b = Mersenne8::new(1);
        let c = Mersenne8::new(2);
        let d = Mersenne8::new(1234);
        let e = Mersenne8::new(1073741823);
        let f = Mersenne8::new(46341);
        let g = Mersenne8::new(2147483646);
        let h = Mersenne8::new(923042);

        assert_eq!(a.inverse(), None);
        assert_eq!(b.inverse(), Some(Mersenne8::new(1)));
        assert_eq!(c.inverse(), Some(Mersenne8::new(1073741824)));
        assert_eq!(d.inverse(), Some(Mersenne8::new(158363867)));
        assert_eq!(e.inverse(), Some(Mersenne8::new(2147483645)));
        assert_eq!(f.inverse(), Some(Mersenne8::new(2147020238)));
        assert_eq!(g.inverse(), Some(Mersenne8::new(2147483646)));
        assert_eq!(h.inverse(), Some(Mersenne8::new(1271194309)));

        assert_eq!(b.inverse().unwrap().inverse().unwrap(), b);
        assert_eq!(c.inverse().unwrap().inverse().unwrap(), c);
        assert_eq!(d.inverse().unwrap().inverse().unwrap(), d);
        assert_eq!(e.inverse().unwrap().inverse().unwrap(), e);
        assert_eq!(f.inverse().unwrap().inverse().unwrap(), f);
        assert_eq!(g.inverse().unwrap().inverse().unwrap(), g);
        assert_eq!(g.inverse().unwrap().inverse().unwrap(), g);
        assert_eq!(h.inverse().unwrap().inverse().unwrap(), h);
    }

    #[test]
    fn frobenius_map() {
        let a = Mersenne8::new(0);
        let b = Mersenne8::new(1);
        let c = Mersenne8::new(2);
        let d = Mersenne8::new(1234);
        let e = Mersenne8::new(1073741823);
        let f = Mersenne8::new(46341);
        let g = Mersenne8::new(2147483646);
        let h = Mersenne8::new(923042);

        let mut a_fm = a;
        let mut b_fm = b;
        let mut c_fm = c;
        let mut d_fm = d;
        let mut e_fm = e;
        let mut f_fm = f;
        let mut g_fm = g;
        let mut h_fm = h;

        a_fm.frobenius_map(1);
        a_fm.frobenius_map(2);
        a_fm.frobenius_map(3);
        b_fm.frobenius_map(1);
        b_fm.frobenius_map(2);
        b_fm.frobenius_map(3);
        c_fm.frobenius_map(1);
        c_fm.frobenius_map(2);
        c_fm.frobenius_map(3);
        d_fm.frobenius_map(1);
        d_fm.frobenius_map(2);
        d_fm.frobenius_map(3);
        e_fm.frobenius_map(1);
        e_fm.frobenius_map(2);
        e_fm.frobenius_map(3);
        f_fm.frobenius_map(1);
        f_fm.frobenius_map(2);
        f_fm.frobenius_map(3);
        g_fm.frobenius_map(1);
        g_fm.frobenius_map(2);
        g_fm.frobenius_map(3);
        h_fm.frobenius_map(1);
        h_fm.frobenius_map(2);
        h_fm.frobenius_map(3);

        assert_eq!(a_fm, a);
        assert_eq!(b_fm, b);
        assert_eq!(c_fm, c);
        assert_eq!(d_fm, d);
        assert_eq!(e_fm, e);
        assert_eq!(f_fm, f);
        assert_eq!(g_fm, g);
        assert_eq!(h_fm, h);
    }
}
