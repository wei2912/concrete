use concrete_commons::parameters::GlweSize;

use crate::backends::core::engines::CoreEngine;
use crate::backends::core::entities::{GlweCiphertext32, GlweCiphertext64};
use crate::backends::core::private::crypto::glwe::GlweCiphertext as ImplGlweCiphertext;
use crate::prelude::{AbstractEngine, GlweCiphertextRelinearizationEngine,
                     GlweCiphertextRelinearizationError};
use crate::specification::entities::GlweCiphertextEntity;

/// # Description:
/// Implementation of [`GlweRelinearizationEngine`] for [`CoreEngine`] that operates on 32-bit
/// integer Glwe Ciphertexts.
impl GlweCiphertextRelinearizationEngine<GlweCiphertext32, GlweCiphertext32>
for CoreEngine{

    // TODO: self only (?) (i.e. no input)
    fn relinearize_glwe_ciphertext(&mut self,
                                      input: &GlweCiphertext32) -> Result<GlweCiphertext32,
        GlweCiphertextRelinearizationError<Self::EngineError>> {
        GlweCiphertextRelinearizationError::perform_generic_checks(input)?;
        Ok(unsafe { self.tensor_product_glwe_ciphertext_unchecked(input)})
    }



    unsafe fn relinearize_glwe_ciphertext_unchecked(&mut self,
                                                       input: &GlweCiphertext32) -> GlweCiphertext32
    {
        let mut ciphertext = ImplGlweCiphertext::allocate(
            0u32,
            input1.polynomial_size(),
            GlweSize(input.glwe_dimension().0),
        );

        // TBA
    }
}

/// # Description:
/// Implementation of [`GlweTensorRelinearizationEngine`] for [`CoreEngine`] that operates on 64-bit
/// integer Glwe Ciphertexts.
impl GlweCiphertextRelinearizationEngine<GlweCiphertext64, GlweCiphertext64>
for CoreEngine{
    // TODO: self only (?) (i.e. no input)
    fn relinearize_glwe_ciphertext(&mut self,
                                      input: &GlweCiphertext64) -> Result<GlweCiphertext64,
        GlweCiphertextRelinearizationError<Self::EngineError>> {
        GlweCiphertextRelinearizationError::perform_generic_checks(input)?;
        Ok(unsafe { self.relinearize_glwe_ciphertext_unchecked(input1)})
    }


    unsafe fn relinearize_glwe_ciphertext_unchecked(&mut self,
                                                       input1: &GlweCiphertext64)
        -> GlweCiphertext64 {

        let mut ciphertext = ImplGlweCiphertext::allocate(
            0u32,
            input1.polynomial_size(),
            GlweSize(input1.glwe_dimension().0 * (3 + input1.glwe_dimension().0) * (1/2)),
        );

      // TBA
    }
}




