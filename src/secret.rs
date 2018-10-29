//! Utilities for working with secret values. This module includes functionality for overwriting
//! memory with zeros.

use std::mem::{size_of, size_of_val};
use std::ops::{Deref, DerefMut};

use lazy_static::lazy_static;
use memsec::memzero;

use Fr;

lazy_static! {
    /// The size in bytes of a single field element.
    pub(crate) static ref FR_SIZE: usize = size_of::<Fr>();
}

/// Overwrites a single field element with zeros.
pub(crate) fn clear_fr(fr_ptr: *const Fr) {
    unsafe { memzero(fr_ptr as *mut u8, *FR_SIZE) };
}

pub(crate) struct MemRange {
    pub ptr: *mut u8,
    pub n_bytes: usize,
}

/// Marks a type as containing some secret value.
pub(crate) trait ContainsSecret {
    /// Returns the range of memory marked as secret.
    fn secret_memory(&self) -> MemRange;

    /// Overwrites the secret region of memory with zeros.
    ///
    /// This method should be called upon destruction of every type that implements `ContainsSecret`.
    fn zero_secret(&self) {
        let MemRange { ptr, n_bytes } = self.secret_memory();
        unsafe { memzero(ptr, n_bytes) };
    }
}

/// A wrapper around temporary values to ensuer that they are cleared on drop.
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
        Safe(x)
    }
}
