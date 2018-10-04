//! Crypto errors.

use errno::Errno;

/// A crypto error.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    #[fail(display = "Not enough signature shares")]
    NotEnoughShares,
    #[fail(display = "Signature shares contain a duplicated index")]
    DuplicateEntry,
    #[fail(display = "The degree is too high for the coefficients to be indexed by usize.")]
    DegreeTooHigh,
    #[fail(
        display = "Failed to `mlock` {} bytes starting at address: {}",
        n_bytes,
        addr
    )]
    MlockFailed {
        // The errno set by the failed `mlock` syscall.
        errno: Errno,
        // The address for the first byte in the range of memory that was attempted to be locked.
        addr: String,
        // The number of bytes that were attempted to be locked.
        n_bytes: usize,
    },
    #[fail(
        display = "Failed to `munlock` {} bytes starting at address: {}",
        n_bytes,
        addr
    )]
    MunlockFailed {
        // The errno set by the failed `munlock` syscall.
        errno: Errno,
        // The address for the first byte in the range of memory that was attempted to be unlocked.
        addr: String,
        // The number of bytes that were attempted to be unlocked.
        n_bytes: usize,
    },
}

unsafe impl Send for Error {}
unsafe impl Sync for Error {}

/// A crypto result.
pub type Result<T> = ::std::result::Result<T, Error>;
