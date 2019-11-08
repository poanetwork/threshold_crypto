//! Utilities for working with secret values. This module includes functionality for overwriting
//! memory with zeros.

use zeroize::Zeroize;

use crate::{Fr, FrRepr};

/// Overwrites a single field element with zeros.
pub(crate) fn clear_fr(fr: &mut Fr) {
    let fr_repr_ptr = unsafe { &mut *(fr as *mut Fr as *mut FrRepr) };
    fr_repr_ptr.0.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::Field;
    use rand::thread_rng;
    use rand04_compat::RngExt;

    #[test]
    fn test_clear() {
        let mut rng = thread_rng();

        let mut fr: Fr = rng.gen04();
        assert_ne!(fr, Fr::zero());

        clear_fr(&mut fr);
        assert_eq!(fr, Fr::zero());
    }
}
