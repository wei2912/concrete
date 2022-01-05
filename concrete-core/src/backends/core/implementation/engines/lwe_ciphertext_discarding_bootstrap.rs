use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    FourierLweBootstrapKey32, FourierLweBootstrapKey64, GlweCiphertext32, GlweCiphertext64,
    LweCiphertext32, LweCiphertext64,
};
use crate::specification::engines::{
    LweCiphertextDiscardingBootstrapEngine, LweCiphertextDiscardingBootstrapError,
};
use crate::specification::entities::{
    GlweCiphertextEntity, LweBootstrapKeyEntity, LweCiphertextEntity,
};

/// # Description:
/// Implementation of [`LweCiphertextDiscardingBootstrapEngine`] for [`CoreEngine`] that operates on
/// 32 bits integers.
impl
    LweCiphertextDiscardingBootstrapEngine<
        FourierLweBootstrapKey32,
        GlweCiphertext32,
        LweCiphertext32,
        LweCiphertext32,
    > for CoreEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// use concrete_commons::key_kinds::BinaryKeyKind;
    /// use concrete_commons::numeric::CastInto;
    /// use concrete_core::backends::core::entities::LweSecretKey32;
    /// use concrete_core::backends::core::private::crypto::secret::LweSecretKey;
    /// use concrete_core::backends::core::private::math::tensor::{AsRefSlice, AsRefTensor};
    /// use concrete_core::backends::core::private::math::tensor::{AsMutTensor, AsMutSlice};
    /// # use std::error::Error;
    ///
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// // DISCLAIMER: the parameters used here are only for test purpose, and are not secure.
    /// use concrete_core::backends::core::private::math::tensor::{AsRefSlice, AsRefTensor};
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(130),
    ///     LweDimension(512),
    ///     GlweDimension(1),
    ///     PolynomialSize(512),
    /// );
    /// let log_degree = f64::log2(poly_size.0 as f64) as i32;
    /// let input: u32 = (poly_size.0 as f64 / 2. * 2_f64.powi(32 - log_degree - 1)) as u32;
    /// let noise = Variance(2_f64.powf(-29.));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(7));
    ///
    /// let mut engine = CoreEngine::new()?;
    /// let lwe_sk: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 = engine.create_glwe_secret_key(glwe_dim, poly_size)?;
    /// let mut lut: GlweCiphertext32 =
    ///     engine.zero_encrypt_glwe_ciphertext(&glwe_sk, noise)?;
    /// let mut mask = lut.0.get_mut_mask();
    /// for mut mask_elt in mask.mask_element_iter_mut() {
    ///    mask_elt.as_mut_tensor().fill_with_element(0);
    /// }
    /// let mut body = lut.0.get_mut_body();
    ///   body.as_mut_tensor()
    ///   .iter_mut()
    ///   .enumerate()
    ///   .for_each(|(i, a)| {
    ///   *a = (i << (32 - log_degree - 1)) as u32;
    ///   });
    /// //panic!("lut {:?}", lut);
    /// let bsk: FourierLweBootstrapKey32 =
    ///     engine.create_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)?;
    /// let lwe_sk_output: LweSecretKey32 = engine.create_lwe_secret_key(lwe_dim_output)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    /// let input = engine.encrypt_lwe_ciphertext(&lwe_sk, &plaintext, noise)?;
    /// let mut output = engine.zero_encrypt_lwe_ciphertext(&lwe_sk_output, noise)?;
    ///
    /// engine.discard_bootstrap_lwe_ciphertext(&mut output, &input, &lut, &bsk)?;
    /// #
    /// // now the LWE is encrypted using a flatten of the GLWE encryption key
    /// let flattened_key = LweSecretKey32(LweSecretKey::binary_from_container(
    ///     glwe_sk.0.as_tensor().as_slice().to_vec(),
    /// ));
    /// let output_plaintext =
    ///     engine.decrypt_lwe_ciphertext(&flattened_key, &output)?;
    ///
    /// // test that the drift remains within the bound of the theoretical drift
    /// let delta_max: i64 =
    ///     ((5. * f64::sqrt((lwe_dim.0 as f64) / 16.0)) * 2_f64.powi(32 - log_degree - 1)) as i64;
    /// assert!(
    ///     (engine.retrieve_plaintext(&output_plaintext)? as i32
    ///         - engine.retrieve_plaintext(&plaintext)? as i32)
    ///         .abs() as u32
    ///         <= delta_max as u32,
    ///     "{:?} != {:?} +- {:?}",
    ///     engine.retrieve_plaintext(&plaintext)?,
    ///     engine.retrieve_plaintext(&output_plaintext)?,
    ///     delta_max
    /// );
    /// assert_eq!(output.lwe_dimension(), lwe_dim_output);
    ///
    /// engine.destroy(lwe_sk)?;
    /// engine.destroy(glwe_sk)?;
    /// engine.destroy(lut)?;
    /// engine.destroy(bsk)?;
    /// engine.destroy(lwe_sk_output)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(input)?;
    /// engine.destroy(output)?;
    /// engine.destroy(output_plaintext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
        acc: &GlweCiphertext32,
        bsk: &FourierLweBootstrapKey32,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<Self::EngineError>> {
        if input.lwe_dimension() != bsk.input_lwe_dimension() {
            return Err(LweCiphertextDiscardingBootstrapError::InputLweDimensionMismatch);
        }
        if acc.polynomial_size() != bsk.polynomial_size() {
            return Err(LweCiphertextDiscardingBootstrapError::AccumulatorPolynomialSizeMismatch);
        }
        if acc.glwe_dimension() != bsk.glwe_dimension() {
            return Err(LweCiphertextDiscardingBootstrapError::AccumulatorGlweDimensionMismatch);
        }
        if output.lwe_dimension() != bsk.output_lwe_dimension() {
            return Err(LweCiphertextDiscardingBootstrapError::OutputLweDimensionMismatch);
        }
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
        acc: &GlweCiphertext32,
        bsk: &FourierLweBootstrapKey32,
    ) {
        let buffers = self.get_fourier_bootstrap_u32_buffer(bsk);
        bsk.0.bootstrap(&mut output.0, &input.0, &acc.0, buffers);
    }
}

/// # Description:
/// Implementation of [`LweCiphertextDiscardingBootstrapEngine`] for [`CoreEngine`] that operates on
/// 64 bits integers.
impl
    LweCiphertextDiscardingBootstrapEngine<
        FourierLweBootstrapKey64,
        GlweCiphertext64,
        LweCiphertext64,
        LweCiphertext64,
    > for CoreEngine
{
    fn discard_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        acc: &GlweCiphertext64,
        bsk: &FourierLweBootstrapKey64,
    ) -> Result<(), LweCiphertextDiscardingBootstrapError<Self::EngineError>> {
        if input.lwe_dimension() != bsk.input_lwe_dimension() {
            return Err(LweCiphertextDiscardingBootstrapError::InputLweDimensionMismatch);
        }
        if acc.polynomial_size() != bsk.polynomial_size() {
            return Err(LweCiphertextDiscardingBootstrapError::AccumulatorPolynomialSizeMismatch);
        }
        if acc.glwe_dimension() != bsk.glwe_dimension() {
            return Err(LweCiphertextDiscardingBootstrapError::AccumulatorGlweDimensionMismatch);
        }
        if output.lwe_dimension() != bsk.output_lwe_dimension() {
            return Err(LweCiphertextDiscardingBootstrapError::OutputLweDimensionMismatch);
        }
        unsafe { self.discard_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn discard_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        acc: &GlweCiphertext64,
        bsk: &FourierLweBootstrapKey64,
    ) {
        let buffers = self.get_fourier_bootstrap_u64_buffer(bsk);

        bsk.0.bootstrap(&mut output.0, &input.0, &acc.0, buffers);
    }
}
