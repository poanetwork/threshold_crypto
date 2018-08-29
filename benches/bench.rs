#[macro_use]
extern crate criterion;
extern crate rand;
extern crate threshold_crypto;

use criterion::Criterion;
use threshold_crypto::poly::Poly;

mod poly_benches {
    use super::*;

    // Benchmarks multiplication of two degree 3 polynomials.
    fn multiplication(c: &mut Criterion) {
        let mut rng = rand::thread_rng();
        let lhs = Poly::random(3, &mut rng).unwrap();
        let rhs = Poly::random(3, &mut rng).unwrap();
        c.bench_function("Polynomial multiplication", move |b| b.iter(|| &lhs * &rhs));
    }

    // Benchmarks Lagrange interpolation for a degree 3 polynomial.
    fn interpolate(c: &mut Criterion) {
        // Points from the the polynomial: `y(x) = 5x^3 + 0x^2 + x - 2`.
        let sample_points = vec![(-1, -8), (2, 40), (3, 136), (5, 628)];
        c.bench_function("Polynomial interpolation", move |b| {
            b.iter(|| Poly::interpolate(sample_points.clone()).unwrap())
        });
    }

    criterion_group!{
        name = poly_benches;
        config = Criterion::default();
        targets = multiplication, interpolate,
    }
}

criterion_main!(poly_benches::poly_benches);
