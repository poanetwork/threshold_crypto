#[macro_use]
extern crate criterion;
extern crate pairing;
extern crate rand;
extern crate threshold_crypto;

use criterion::Criterion;
use pairing::bls12_381::Fr;
use threshold_crypto::poly::Poly;

const TEST_DEGREES: [usize; 4] = [5, 10, 20, 40];
const TEST_THRESHOLDS: [usize; 4] = [5, 10, 20, 40];
const RNG_SEED: [u32; 4] = [1, 2, 3, 4];

mod poly_benches {
    use super::*;
    use rand::{Rng, SeedableRng, XorShiftRng};

    /// Benchmarks multiplication of two polynomials.
    fn multiplication(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        c.bench_function_over_inputs(
            "Polynomial multiplication",
            move |b, &&deg| {
                let rand_factors = || {
                    let lhs = Poly::random(deg, &mut rng);
                    let rhs = Poly::random(deg, &mut rng);
                    (lhs, rhs)
                };
                b.iter_with_setup(rand_factors, |(lhs, rhs)| &lhs * &rhs)
            },
            &TEST_DEGREES,
        );
    }

    /// Benchmarks subtraction of two polynomials
    fn subtraction(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        c.bench_function_over_inputs(
            "Polynomial subtraction",
            move |b, &&deg| {
                let rand_factors = || {
                    let lhs = Poly::random(deg, &mut rng);
                    let rhs = Poly::random(deg, &mut rng);
                    (lhs, rhs)
                };
                b.iter_with_setup(rand_factors, |(lhs, rhs)| &lhs - &rhs)
            },
            &TEST_DEGREES,
        );
    }

    /// Benchmarks addition of two polynomials
    fn addition(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        c.bench_function_over_inputs(
            "Polynomial addition",
            move |b, &&deg| {
                let rand_factors = || {
                    let lhs = Poly::random(deg, &mut rng);
                    let rhs = Poly::random(deg, &mut rng);
                    (lhs, rhs)
                };
                b.iter_with_setup(rand_factors, |(lhs, rhs)| &lhs + &rhs)
            },
            &TEST_DEGREES,
        );
    }

    /// Benchmarks Lagrange interpolation for a polynomial.
    fn interpolate(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        c.bench_function_over_inputs(
            "Polynomial interpolation",
            move |b, &&deg| {
                let rand_samples = || (0..=deg).map(|i| (i, rng.gen::<Fr>())).collect::<Vec<_>>();
                b.iter_with_setup(rand_samples, Poly::interpolate)
            },
            &TEST_DEGREES,
        );
    }

    criterion_group!{
        name = poly_benches;
        config = Criterion::default();
        targets = multiplication, interpolate, addition, subtraction,
    }
}

mod public_key_set_benches {
    use super::*;
    use rand::{SeedableRng, XorShiftRng};
    use std::collections::BTreeMap;
    use threshold_crypto::SecretKeySet;

    /// Benchmarks combining signatures
    fn combine_signatures(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let msg = "Test message";
        c.bench_function_over_inputs(
            "Combine Signatures",
            move |b, &&threshold| {
                let sk_set = SecretKeySet::random(threshold, &mut rng);
                let pk_set = sk_set.public_keys();
                let mut sig_parts: Vec<usize> = (0..threshold + 1).collect();
                let pieces: &mut [usize] = &mut sig_parts;
                let sigs: BTreeMap<_, _> = pieces
                    .iter()
                    .map(|&i| {
                        let sig = sk_set.secret_key_share(i).sign(msg);
                        (i, sig)
                    }).collect();
                b.iter(|| {
                    pk_set
                        .combine_signatures(&sigs)
                        .expect("could not combine signatures");
                })
            },
            &TEST_THRESHOLDS,
        );
    }

    criterion_group!{
        name = public_key_set_benches;
        config = Criterion::default();
        targets = combine_signatures,
    }
}

criterion_main!(
    poly_benches::poly_benches,
    public_key_set_benches::public_key_set_benches
);
