//! Utilities for working with secret values. This module includes functionality for overwriting
//! memory with zeros.

use pairing::PrimeField;
use zeroize::Zeroize;

use crate::Fr;

/// Overwrites a single field element with zeros.
pub(crate) fn clear_fr(fr: &mut Fr) {
    let mut repr = fr.into_repr();
    repr.0.zeroize();
}
