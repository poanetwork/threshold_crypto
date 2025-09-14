use super::Scalar;

// TODO rename all funcions and traits from Fr to Sc

/// A conversion into an element of the field `Fr`.
pub trait IntoFr: Copy {
    /// Converts `self` to a field element.
    fn into_fr(self) -> Scalar;
}

impl IntoFr for Scalar {
    fn into_fr(self) -> Scalar {
        self
    }
}

impl IntoFr for u64 {
    fn into_fr(self) -> Scalar {
        Scalar::from(self)
    }
}

impl IntoFr for usize {
    fn into_fr(self) -> Scalar {
        (self as u64).into_fr()
    }
}

impl IntoFr for i32 {
    fn into_fr(self) -> Scalar {
        if self >= 0 {
            (self as u64).into_fr()
        } else {
            let mut result = ((-self) as u64).into_fr();
            result.neg()
        }
    }
}

impl IntoFr for i64 {
    fn into_fr(self) -> Scalar {
        if self >= 0 {
            (self as u64).into_fr()
        } else {
            let mut result = ((-self) as u64).into_fr();
            result.neg()
        }
    }
}

impl<'a, T: IntoFr> IntoFr for &'a T {
    fn into_fr(self) -> Scalar {
        (*self).into_fr()
    }
}
