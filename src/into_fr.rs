use super::Scalar;

// TODO rename all funcions and traits from Fr to Sc

/// A conversion into an element of the field `Fr`.
pub trait IntoScalar: Copy {
    /// Converts `self` to a field element.
    fn into_scalar(self) -> Scalar;
}

impl IntoScalar for Scalar {
    fn into_scalar(self) -> Scalar {
        self
    }
}

impl IntoScalar for u64 {
    fn into_scalar(self) -> Scalar {
        Scalar::from(self)
    }
}

impl IntoScalar for usize {
    fn into_scalar(self) -> Scalar {
        (self as u64).into_scalar()
    }
}

impl IntoScalar for i32 {
    fn into_scalar(self) -> Scalar {
        if self >= 0 {
            (self as u64).into_scalar()
        } else {
            let result = ((-self) as u64).into_scalar();
            result.neg()
        }
    }
}

impl IntoScalar for i64 {
    fn into_scalar(self) -> Scalar {
        if self >= 0 {
            (self as u64).into_scalar()
        } else {
            let result = ((-self) as u64).into_scalar();
            result.neg()
        }
    }
}

impl<'a, T: IntoScalar> IntoScalar for &'a T {
    fn into_scalar(self) -> Scalar {
        (*self).into_scalar()
    }
}
