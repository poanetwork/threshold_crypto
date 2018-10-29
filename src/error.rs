//! Crypto errors.

use failure::Fail;

/// A crypto error.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "Not enough signature shares")]
    NotEnoughShares,
    #[fail(display = "Signature shares contain a duplicated index")]
    DuplicateEntry,
    #[fail(display = "The degree is too high for the coefficients to be indexed by usize.")]
    DegreeTooHigh,
}

/// A crypto result.
pub type Result<T> = ::std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;

    /// No-op function that compiles only if its argument is `Send + Sync`.
    fn is_send_and_sync<T: Send + Sync>(_: T) {}

    #[test]
    fn errors_are_send_and_sync() {
        is_send_and_sync(Error::NotEnoughShares);
    }
}
