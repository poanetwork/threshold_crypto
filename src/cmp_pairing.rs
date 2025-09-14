use std::cmp::Ordering;

// TODO: this may be in group::cofactor::CofactorCurveAffine etc now
use group::GroupEncoding;

/// Compares two curve elements and returns their `Ordering`.
pub fn cmp_projective<G: GroupEncoding>(x: &G, y: &G) -> Ordering {
    let xc = x.to_bytes();
    let yc = y.to_bytes();
    xc.as_ref().cmp(yc.as_ref())
}
