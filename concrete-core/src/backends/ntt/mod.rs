//! A module containing the NTT backend implementation.
//!
//! This module contains a single threaded CPU implementation of part of the concrete scheme,
//! using an NTT to perform polynomial multiplications

#[doc(hidden)]
pub mod private;

mod implementation;

pub use implementation::{engines, entities};
