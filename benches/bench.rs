#[macro_use]
extern crate criterion;
extern crate pairing;
extern crate rand;
extern crate threshold_crypto;

use criterion::Criterion;
use pairing::bls12_381::Fr;
use threshold_crypto::poly::Poly;

mod poly_benches {
    use super::*;
    use rand::Rng;

    // Benchmarks multiplication of two polynomials.
    fn multiplication(c: &mut Criterion) {
        let mut rng = rand::thread_rng();
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
            &[5, 10, 20, 40],
        );
    }

    // Benchmarks Lagrange interpolation for a polynomial.
    fn interpolate(c: &mut Criterion) {
        let mut rng = rand::thread_rng();
        c.bench_function_over_inputs(
            "Polynomial interpolation",
            move |b, &&deg| {
                let rand_samples = || (0..=deg).map(|i| (i, rng.gen::<Fr>())).collect::<Vec<_>>();
                b.iter_with_setup(rand_samples, Poly::interpolate)
            },
            &[5, 10, 20, 40],
        );
    }

    criterion_group!{
        name = poly_benches;
        config = Criterion::default();
        targets = multiplication, interpolate,
    }
}

criterion_main!(poly_benches::poly_benches);
