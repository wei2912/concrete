//! A module containing the [engines](crate::specification::engines) exposed by the NTT backend.

use concrete_commons::parameters::{GlweSize, PolynomialSize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::backends::core::private::crypto::bootstrap::FourierBskBuffers;
use crate::prelude::{FourierLweBootstrapKey32, FourierLweBootstrapKey64, LweBootstrapKeyEntity};
use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::AbstractEngine;

/// The error which can occur in the execution of FHE operations, due to the ntt implementation.
///
/// # Note:
///
/// There is currently no such case, as the core implementation is not expected to undergo some
/// major issues unrelated to FHE.
#[derive(Debug)]
pub enum NttError {
    UnsupportedPolynomialSize,
}

impl Display for NttError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NttError::UnsupportedPolynomialSize => {
                write!(
                    f,
                    "The NTT backend only supports polynomials of size X Y Z."
                )
            }
        }
    }
}

impl Error for NttError {}

/// The main engine exposed by the NTT backend.
pub struct NttEngine {}

impl AbstractEngineSeal for NttEngine {}

impl AbstractEngine for NttEngine {
    type EngineError = NttError;

    fn new() -> Result<Self, Self::EngineError> {
        Ok(NttEngine {})
    }
}

mod lwe_ciphertext_discarding_bootstrap;
