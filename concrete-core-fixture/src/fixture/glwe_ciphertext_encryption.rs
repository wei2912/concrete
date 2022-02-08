use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesGlweCiphertext, PrototypesGlweSecretKey, PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{
    SynthesizesGlweCiphertext, SynthesizesGlweSecretKey, SynthesizesPlaintextVector,
};
use crate::generation::{IntegerPrecision, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use crate::SampleSize;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
use concrete_core::prelude::{
    GlweCiphertextEncryptionEngine, GlweCiphertextEntity, GlweSecretKeyEntity,
    PlaintextVectorEntity,
};

/// A fixture for the types implementing the `GlweCiphertextEncryptionEngine` trait.
pub struct GlweCiphertextEncryptionFixture;

#[derive(Debug)]
pub struct GlweCiphertextEncryptionParameters {
    pub noise: Variance,
    pub glwe_dimension: GlweDimension,
    pub polynomial_size: PolynomialSize,
}

impl<Precision, Engine, PlaintextVector, SecretKey, Ciphertext>
    Fixture<Precision, Engine, (PlaintextVector, SecretKey, Ciphertext)>
    for GlweCiphertextEncryptionFixture
where
    Precision: IntegerPrecision,
    Engine: GlweCiphertextEncryptionEngine<SecretKey, PlaintextVector, Ciphertext>,
    PlaintextVector: PlaintextVectorEntity,
    SecretKey: GlweSecretKeyEntity,
    Ciphertext: GlweCiphertextEntity<KeyDistribution = SecretKey::KeyDistribution>,
    Maker: SynthesizesPlaintextVector<Precision, PlaintextVector>
        + SynthesizesGlweSecretKey<Precision, SecretKey>
        + SynthesizesGlweCiphertext<Precision, Ciphertext>,
{
    type Parameters = GlweCiphertextEncryptionParameters;
    type RawInputs = (Vec<Precision::Raw>,);
    type RawOutputs = (Vec<Precision::Raw>,);
    type Bypass = (<Maker as PrototypesGlweSecretKey<Precision, Ciphertext::KeyDistribution>>::GlweSecretKeyProto, );
    type PreExecutionContext = (PlaintextVector, SecretKey);
    type PostExecutionContext = (PlaintextVector, SecretKey, Ciphertext);
    type Prediction = (Vec<Precision::Raw>, Variance);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![GlweCiphertextEncryptionParameters {
                noise: Variance(0.00000001),
                glwe_dimension: GlweDimension(200),
                polynomial_size: PolynomialSize(200),
            }]
            .into_iter(),
        )
    }

    fn generate_random_raw_inputs(parameters: &Self::Parameters) -> Self::RawInputs {
        (Precision::Raw::uniform_vec(parameters.polynomial_size.0),)
    }

    fn compute_prediction(
        parameters: &Self::Parameters,
        raw_inputs: &Self::RawInputs,
        sample_size: SampleSize,
    ) -> Self::Prediction {
        let (raw_plaintext,) = raw_inputs;
        let output = (0..sample_size.0)
            .flat_map(|_| raw_plaintext.iter())
            .copied()
            .collect::<Vec<Precision::Raw>>();
        (output, parameters.noise)
    }

    fn check_prediction(
        _parameters: &Self::Parameters,
        forecast: &Self::Prediction,
        actual: &[Self::RawOutputs],
    ) -> bool {
        let (means, noise) = forecast;
        let actual = actual
            .iter()
            .flat_map(|r| r.0.iter())
            .copied()
            .collect::<Vec<_>>();
        assert_noise_distribution(&actual, means.as_slice(), *noise)
    }

    fn prepare_context(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        raw_inputs: &Self::RawInputs,
    ) -> (Self::Bypass, Self::PreExecutionContext) {
        let (raw_plaintext_vector,) = raw_inputs;
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector);
        let proto_secret_key =
            maker.new_glwe_secret_key(parameters.glwe_dimension, parameters.polynomial_size);
        let synth_plaintext_vector = maker.synthesize_plaintext_vector(&proto_plaintext_vector);
        let synth_secret_key = maker.synthesize_glwe_secret_key(&proto_secret_key);
        (
            (proto_secret_key,),
            (synth_plaintext_vector, synth_secret_key),
        )
    }

    fn execute_engine(
        parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (plaintext_vector, secret_key) = context;
        let ciphertext = unsafe {
            engine.encrypt_glwe_ciphertext_unchecked(
                &secret_key,
                &plaintext_vector,
                parameters.noise,
            )
        };
        (plaintext_vector, secret_key, ciphertext)
    }

    fn process_context(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        bypass: Self::Bypass,
        context: Self::PostExecutionContext,
    ) -> Self::RawOutputs {
        let (plaintext_vector, secret_key, ciphertext) = context;
        let (proto_secret_key,) = bypass;
        let proto_output_ciphertext = maker.unsynthesize_glwe_ciphertext(&ciphertext);
        let proto_plaintext_vector = maker.decrypt_glwe_ciphertext_to_plaintext_vector(
            &proto_secret_key,
            &proto_output_ciphertext,
        );
        maker.destroy_plaintext_vector(plaintext_vector);
        maker.destroy_glwe_secret_key(secret_key);
        maker.destroy_glwe_ciphertext(ciphertext);
        (maker.transform_plaintext_vector_to_raw_vec(&proto_plaintext_vector),)
    }
}
