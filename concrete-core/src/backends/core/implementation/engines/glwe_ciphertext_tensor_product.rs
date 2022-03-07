use concrete_commons::parameters::GlweSize;

use crate::backends::core::engines::CoreEngine;
use crate::backends::core::entities::{FourierGlweCiphertext64, GlweCiphertext32, GlweCiphertext64, FourierGlweCiphertext32};
use crate::backends::core::private::crypto::glwe::GlweCiphertext as ImplGlweCiphertext;
use crate::backends::core::private::crypto::glwe::FourierGlweCiphertext as ImplFourierGlweCiphertext;
use crate::prelude::{AbstractEngine, GlweCiphertextTensorProductEngine, GlweCiphertextTensorProductError};
use crate::specification::entities::GlweCiphertextEntity;

/// # Description:
/// Implementation of [`GlweTensorProductEngine`] for [`CoreEngine`] that operates on 32-bit
/// integer Glwe Ciphertexts.
impl GlweCiphertextTensorProductEngine<GlweCiphertext32, GlweCiphertext32, GlweCiphertext32>
    for CoreEngine{

    fn tensor_product_glwe_ciphertext(&mut self,
                                      input1: &GlweCiphertext32,
                                      input2: &GlweCiphertext32) -> Result<GlweCiphertext32,
        GlweCiphertextTensorProductError<Self::EngineError>> {
        GlweCiphertextTensorProductError::perform_generic_checks(input1, input2)?;
        Ok(unsafe { self.tensor_product_glwe_ciphertext_unchecked(input1, input2)})
    }



    unsafe fn tensor_product_glwe_ciphertext_unchecked(&mut self,
                                                       input1: &GlweCiphertext32,
                                                       input2: &GlweCiphertext32) -> GlweCiphertext32 {

        let mut ciphertext = ImplGlweCiphertext::allocate(
            0u32,
            input1.polynomial_size(),
            GlweSize(input1.glwe_dimension().0 * (3 + input1.glwe_dimension().0) * (1/2)),
        );

        let fft_buffer1 = &mut buffers.fft_buffers.first_buffer;
        let fft_buffer2 = &mut buffers.fft_buffers.second_buffer;

        // convert the two GLWE ciphertexts of interest to the fourier domain
        let mut fourier_1 = ImplFourierGlweCiphertext::allocate(
            Complex64::Zero,
            input1.polynomial_size(),
            GlweSize(input1.glwe_dimension().0),
        );

        let mut fourier_2 = ImplFourierGlweCiphertext::allocate(
            Complex64::Zero,
            input1.polynomial_size(),
            GlweSize(input1.glwe_dimension().0),
        );

        fourier_1.fill_with_forward_fourier(self, fft_buffer1);
        fourier_2.fill_with_forward_fourier(input1, fft_buffer2);

        // perform the tensor product (in the fourier domain)
        fourier_1.0.tensor_product(fourier_2);

        // convert the result back to the coefficient domain
        ciphertext.convert_glwe_ciphertext(fourier_1.0);
    }
}

/// # Description:
/// Implementation of [`GlweTensorProductEngine`] for [`CoreEngine`] that operates on 64-bit
/// integer Glwe Ciphertexts.
impl GlweCiphertextTensorProductEngine<GlweCiphertext64, GlweCiphertext64, GlweCiphertext64>
for CoreEngine{

    fn tensor_product_glwe_ciphertext(&mut self,
                                      input1: &GlweCiphertext64,
                                      input2: &GlweCiphertext64) -> Result<GlweCiphertext64,
        GlweCiphertextTensorProductError<Self::EngineError>> {
        GlweCiphertextTensorProductError::perform_generic_checks(input1, input2)?;
        Ok(unsafe { self.tensor_product_glwe_ciphertext_unchecked(input1, input2)})
    }


    unsafe fn tensor_product_glwe_ciphertext_unchecked(&mut self,
                                                       input1: &GlweCiphertext64,
                                                       input2: &GlweCiphertext64) -> GlweCiphertext64 {

        let mut ciphertext = ImplGlweCiphertext::allocate(
            0u32,
            input1.polynomial_size(),
            GlweSize(input1.glwe_dimension().0 * (3 + input1.glwe_dimension().0) * (1/2)),
        );

        let fft_buffer1 = &mut buffers.fft_buffers.first_buffer;
        let fft_buffer2 = &mut buffers.fft_buffers.second_buffer;

        // convert the two GLWE ciphertexts of interest to the fourier domain
        let mut fourier_1 = ImplFourierGlweCiphertext::allocate(
            Complex64::Zero,
            input1.polynomial_size(),
            GlweSize(input1.glwe_dimension().0),
        );

        let mut fourier_2 = ImplFourierGlweCiphertext::allocate(
            Complex64::Zero,
            input1.polynomial_size(),
            GlweSize(input1.glwe_dimension().0),
        );

        fourier_1.fill_with_forward_fourier(self, fft_buffer1);
        fourier_2.fill_with_forward_fourier(input1, fft_buffer2);

        // perform the tensor product (in the fourier domain)
        fourier_1.0.tensor_product(fourier_2);

        // convert the result back to the coefficient domain
        ciphertext.convert_glwe_ciphertext(fourier_1.0);
    }
}




