//! Utilities for working with secret values. This module includes functionality for locking (and
//! unlocking) memory into RAM and overwriting memory with zeros.

use std::collections::HashMap;
use std::env;
use std::mem::{size_of, size_of_val};
use std::ops::{Deref, DerefMut};
use std::sync::Mutex;

use errno::errno;
use memsec::{memzero, mlock, munlock};
use page_size;
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
    static ref SHOULD_MLOCK_SECRETS: bool = env::var("MLOCK_SECRETS")
        .map(|s| s.parse().expect("invalid value for `MLOCK_SECRETS`"))
        .unwrap_or(true);

    /// The size in bytes of a single field element.
    pub(crate) static ref FR_SIZE: usize = size_of::<Fr>();

    /// Counts the number of secrets allocated in each page of memory.
    static ref MLOCK_MANAGER: Mutex<MlockManager> = Mutex::new(MlockManager::new());

    /// The size in bytes of each page in memory.
    static ref PAGE_SIZE: usize = get_page_size();
}

fn get_page_size() -> usize {
    page_size::get()
}

/// Overwrites a single field element with zeros.
pub(crate) fn clear_fr(fr_ptr: *mut u8) {
    unsafe { memzero(fr_ptr, *FR_SIZE) };
}

/// Round `ptr` down to the nearest page boundry (i.e returns the first address in the page that
/// contains `ptr`).
fn get_page_addr(ptr: *const u8) -> *const u8 {
    let offset = ptr as usize % *PAGE_SIZE;
    unsafe { ptr.sub(offset) }
}

/// Manages when each page in memory is locked and unlocked from RAM based on how many secrets are
/// allocated in each page.
///
/// The `MlockManager` contains a `HashMap` counter, each key in the counter is the address for a
/// page in memory, each value is the number of secret values currently allocated in the
/// corresponding page. The first secret that is allocated in a page, results in a call to the
/// `mlock` syscall for that page. The final secret to be deallocated from a page, results in the
/// `munlock` syscall being called for that page.
///
/// The `MlockManager` ensures that no pages are unlocked from RAM until all secrets from the
/// corresponding page have been dropped. The `MlockManager` also prevents unnecessary calls to
/// the `mlock` and `munlock` syscalls.
#[derive(Debug, Default)]
struct MlockManager(HashMap<usize, u8>);

impl MlockManager {
    fn new() -> Self {
        MlockManager::default()
    }

    /// Checks if the page that contains the value that `ptr` points to should be locked into RAM,
    /// if so, the `mlock` syscall is called for that page.
    fn mlock(&mut self, ptr: *const u8) -> bool {
        let page_addr = get_page_addr(ptr);
        let should_mlock_page = {
            let n_allocs = self.0.entry(page_addr as usize).or_insert(0);
            let should_mlock = *n_allocs == 0;
            *n_allocs += 1;
            should_mlock
        };
        if should_mlock_page {
            unsafe { mlock(ptr as *mut u8, 1) }
        } else {
            true
        }
    }

    /// Checks if the page that contains the value that `ptr` points to should be unlocked from
    /// RAM, if so, the `munlock` syscall is called for that page.
    fn munlock(&mut self, ptr: *const u8) -> bool {
        let page_addr = get_page_addr(ptr);
        let should_munlock_page = {
            let n_allocs = self.0.entry(page_addr as usize).or_insert(0);
            let should_munlock = *n_allocs == 1;
            *n_allocs = n_allocs.saturating_sub(1);
            should_munlock
        };
        if should_munlock_page {
            unsafe { munlock(ptr as *mut u8, 1) }
        } else {
            true
        }
    }

    /// Returns the total number of pages currently locked into RAM.
    #[cfg(test)]
    fn n_pages_locked(&self) -> usize {
        self.0.values().filter(|count| **count > 0).count()
    }

    /// Returns the number of secrets allocated in a given page.
    #[cfg(test)]
    fn alloc_count(&self, page_ptr: *const u8) -> u8 {
        let page_ptr = page_ptr as usize;
        if let Some(n_allocs) = self.0.get(&page_ptr) {
            *n_allocs
        } else {
            0
        }
    }
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
    /// We do not attempt to lock zero-sized types into RAM because zero-sized types may not
    /// contain a valid pointer.
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
        let mlock_succeeded = MLOCK_MANAGER.lock().unwrap().mlock(ptr);
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
    /// We do not attempt to unlock zero-sized types from RAM because zero-sized types may not
    /// contain a valid pointer.
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
        let munlock_succeeded = MLOCK_MANAGER.lock().unwrap().munlock(ptr);
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

#[cfg(test)]
mod tests {
    use super::{get_page_addr, MlockManager, PAGE_SIZE};

    #[test]
    fn test_manager() {
        let mut manager = MlockManager::new();

        // We create a single `u64` on the stack; we then check that calling `mlock` on its
        // address results in a call to the `mlock` syscall. We check this by asserting that the
        // total number of locked pages is incremented from 0 (the default for each page) to 1.
        let x = 5u64;
        let x_ptr = &x as *const u64 as *mut u8;
        let first_page = get_page_addr(x_ptr);
        assert!(manager.mlock(x_ptr));
        assert_eq!(manager.n_pages_locked(), 1);
        assert_eq!(manager.alloc_count(first_page), 1);

        // Check that allocating a second secret in the first page of memory does not result in a
        // call to the `mlock` syscall. We check this by asserting that the total number of locked
        // pages has not changed.
        assert!(manager.mlock(first_page));
        assert_eq!(manager.n_pages_locked(), 1);
        assert_eq!(manager.alloc_count(first_page), 2);

        // Check that locking the first address in the page following `first_page`, results in a
        // call to the `mlock` syscall. We check this by asserting that the total number of locked
        // pages is incremented from 1 to 2.
        let second_page = unsafe { first_page.offset(*PAGE_SIZE as isize) as *mut u8 };
        assert!(manager.mlock(second_page));
        assert_eq!(manager.n_pages_locked(), 2);
        assert_eq!(manager.alloc_count(second_page), 1);

        // Check that calling `munlock` on the second page, which holds only a single secret,
        // results in a call to the `munlock` syscall. We check this by asserting that the total
        // number of locked pages is decremented from 2 (as asserted above) to 1.
        assert!(manager.munlock(second_page));
        assert_eq!(manager.n_pages_locked(), 1);
        assert_eq!(manager.alloc_count(second_page), 0);

        // We check that calling `munlock` on the page that contains `x` (i.e. the first page),
        // does not result in a call to the `munlock` syscall, because there still exists secrets
        // that are allocated in the first page. We do this by asserting that the allocation
        // counter for the first page has not been decremented from 2 (as asserted above) to 0
        // (which would result in a call to the syscall).
        assert!(manager.munlock(x_ptr));
        assert_eq!(manager.n_pages_locked(), 1);
        assert_eq!(manager.alloc_count(first_page), 1);

        // Check that unlocking the remaining secret in the first page of memory results in a call
        // to the `munlock` syscall. We do this by asserting that the number of locked pages has
        // been decremented from 1 (as asserted above) to 0.
        assert!(manager.munlock(first_page));
        assert_eq!(manager.n_pages_locked(), 0);
        assert_eq!(manager.alloc_count(first_page), 0);
    }
}
