//! Utilities for working with secret values. This module includes functionality for locking (and
//! unlocking) memory into RAM and overwriting memory with zeros.

use std::env;
use std::mem::{size_of, size_of_val};
use std::ops::{Deref, DerefMut};

use errno::errno;
use memsec::{memzero, mlock, munlock};
use pairing::bls12_381::Fr;

use error::{Error, Result};

lazy_static! {
    /// Sets whether or not `mlock`ing is enabled. Memory locking is enabled by default; it can be
    /// disabled by setting the environment variable `MLOCK_SECRETS=false`. This is useful when you
    /// are running on a system where you do not have the ability to increase the systems locked
    /// memory limit (which can be found using the Unix command: `ulimit -l`). For example, we
    /// disable `mlock`ing of secrets when testing crates that depend on `threshold_crypto` when
    /// running in Travis CI because Travis has a locked memory limit of 64kb, which we may exceed
    /// while running `cargo test`. Disabling `mlock`ing for secret values allows secret keys to
    /// be swapped/core-dumped to disk, resulting in unmanaged copies of secrets to hang around in
    /// memory; this is significantly less secure than enabling memory locking (the default). Only
    /// set `MLOCK_SECRETS=false` in development/testing.
    pub(crate) static ref SHOULD_MLOCK_SECRETS: bool = match env::var("MLOCK_SECRETS") {
        Ok(s) => s.parse().unwrap_or(true),
        _ => true,
    };

    /// The size in bytes of a single field element.
    pub(crate) static ref FR_SIZE: usize = size_of::<Fr>();
}

/// Overwrites a single field element with zeros.
pub(crate) fn clear_fr(fr_ptr: *mut u8) {
    unsafe { memzero(fr_ptr, *FR_SIZE) };
}

pub(crate) struct MemRange {
    pub ptr: *mut u8,
    pub n_bytes: usize,
}

/// Marks a type as containing some secret value.
pub(crate) trait ContainsSecret {
    /// Returns the range of memory marked as secret.
    fn secret_memory(&self) -> MemRange;

    /// Locks a region of memory marked as secret into RAM.
    ///
    /// The region of memory marked as secret will not be copied to disk, for example, during a
    /// swap-to-disk or core dump. This method should be called upon instantiation of every type
    /// that implements `ContainsSecret`.
    ///
    /// Operating systems set a limit on the ammount of memory that a process may lock into RAM.
    /// Due to this limitation, this method returns a `Result` in the event that memory locking
    /// fails.
    ///
    /// # Errors
    ///
    /// An `Error::MlockFailed` is returned if we reach the system's locked memory limit or if  we
    /// attempt to lock an invalid region of memory.
    fn mlock_secret(&self) -> Result<()> {
        if !*SHOULD_MLOCK_SECRETS {
            return Ok(());
        }
        let MemRange { ptr, n_bytes } = self.secret_memory();
        if n_bytes == 0 {
            return Ok(());
        }
        let mlock_succeeded = unsafe { mlock(ptr, n_bytes) };
        if mlock_succeeded {
            Ok(())
        } else {
            let e = Error::MlockFailed {
                errno: errno(),
                addr: format!("{:?}", ptr),
                n_bytes,
            };
            Err(e)
        }
    }

    /// Unlocks the memory lock for a region of memory marked as secret. If the secret region of
    /// memory had not previosly been locked via the `.mlock_secret()` method, then this method
    /// does nothing.
    ///
    /// Once this method has been called, the secret region of memory will no longer be protected
    /// from being copied to disk. This method should be called upon destruction of every type that
    /// implements `ContainsSecret`.
    ///
    /// # Errors
    ///
    /// An `Error::MlockFailed` is returned if we attempt to lock an invalid region memory.
    fn munlock_secret(&self) -> Result<()> {
        if !*SHOULD_MLOCK_SECRETS {
            return Ok(());
        }
        let MemRange { ptr, n_bytes } = self.secret_memory();
        if n_bytes == 0 {
            return Ok(());
        }
        let munlock_succeeded = unsafe { munlock(ptr, n_bytes) };
        if munlock_succeeded {
            Ok(())
        } else {
            let e = Error::MunlockFailed {
                errno: errno(),
                addr: format!("{:?}", ptr),
                n_bytes,
            };
            Err(e)
        }
    }

    /// Overwrites the secret region of memory with zeros.
    ///
    /// This method should be called upon destruction of every type that implements `ContainsSecret`.
    fn zero_secret(&self) {
        let MemRange { ptr, n_bytes } = self.secret_memory();
        unsafe { memzero(ptr, n_bytes) };
    }
}

/// A wrapper around temporary values to ensuer that they are locked into RAM and cleared on drop.
///
/// `Safe<T>` is meant to be used a wrapper around `T`, where `T` is  either an `&mut U` or
/// `Box<U>`.
pub(crate) struct Safe<T: DerefMut>(T);

impl<T> Deref for Safe<T>
where
    T: DerefMut,
{
    type Target = T::Target;

    fn deref(&self) -> &Self::Target {
        &*(self.0)
    }
}

impl<T> DerefMut for Safe<T>
where
    T: DerefMut,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *(self.0)
    }
}

impl<T> Drop for Safe<T>
where
    T: DerefMut,
{
    fn drop(&mut self) {
        self.zero_secret();
        if let Err(e) = self.munlock_secret() {
            panic!("Failed to drop `Safe`: {}", e);
        }
    }
}

impl<T> ContainsSecret for Safe<T>
where
    T: DerefMut,
{
    fn secret_memory(&self) -> MemRange {
        let ptr = &*self.0 as *const T::Target as *mut u8;
        let n_bytes = size_of_val(&*self.0);
        MemRange { ptr, n_bytes }
    }
}

impl<T> Safe<T>
where
    T: DerefMut,
{
    pub(crate) fn new(x: T) -> Self {
        Safe::try_new(x).unwrap_or_else(|e| panic!("Failed to create `Safe`: {}", e))
    }

    pub(crate) fn try_new(x: T) -> Result<Self> {
        let safe = Safe(x);
        safe.mlock_secret()?;
        Ok(safe)
    }
}
