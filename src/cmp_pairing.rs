use std::cmp::Ordering;

use group::{CurveAffine, CurveProjective};

/// Compares two curve elements and returns their `Ordering`.
pub fn cmp_projective<G: CurveProjective>(x: &G, y: &G) -> Ordering {
    let xc = x.into_affine().into_compressed();
    let yc = y.into_affine().into_compressed();
    xc.as_ref().cmp(yc.as_ref())
}
