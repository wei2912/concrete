use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesLweCiphertextVector, PrototypesLweSecretKey, PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{
    SynthesizesLweCiphertextVector, SynthesizesLweSecretKey, SynthesizesPlaintextVector,
};
use crate::generation::{IntegerPrecision, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use crate::SampleSize;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
use concrete_core::prelude::{
    LweCiphertextVectorDecryptionEngine, LweCiphertextVectorEntity, LweSecretKeyEntity,
    PlaintextVectorEntity,
};
use std::ops::BitAnd;

/// A fixture for the types implementing the `LweCiphertextVectorDecryptionEngine` trait.
pub struct LweCiphertextVectorDecryptionFixture;

#[derive(Debug)]
pub struct LweCiphertextVectorDecryptionParameters {
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
    pub lwe_ciphertext_count: LweCiphertextCount,
}

impl<Precision, Engine, PlaintextVector, SecretKey, CiphertextVector>
    Fixture<Precision, Engine, (PlaintextVector, SecretKey, CiphertextVector)>
    for LweCiphertextVectorDecryptionFixture
where
    Precision: IntegerPrecision,
    Engine: LweCiphertextVectorDecryptionEngine<SecretKey, CiphertextVector, PlaintextVector>,
    PlaintextVector: PlaintextVectorEntity,
    SecretKey: LweSecretKeyEntity,
    CiphertextVector: LweCiphertextVectorEntity<KeyDistribution = SecretKey::KeyDistribution>,
    Maker: SynthesizesPlaintextVector<Precision, PlaintextVector>
        + SynthesizesLweSecretKey<Precision, SecretKey>
        + SynthesizesLweCiphertextVector<Precision, CiphertextVector>,
{
    type Parameters = LweCiphertextVectorDecryptionParameters;
    type RawInputs = (Vec<Precision::Raw>,);
    type RawOutputs = (Vec<Precision::Raw>,);
    type Bypass = ();
    type PreExecutionContext = (CiphertextVector, SecretKey);
    type PostExecutionContext = (CiphertextVector, SecretKey, PlaintextVector);
    type Prediction = Vec<(Vec<Precision::Raw>, Variance)>;

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextVectorDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(100),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextVectorDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(300),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextVectorDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(600),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextVectorDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(1000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextVectorDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(3000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
                LweCiphertextVectorDecryptionParameters {
                    noise: Variance(0.00000001),
                    lwe_dimension: LweDimension(6000),
                    lwe_ciphertext_count: LweCiphertextCount(100),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_raw_inputs(parameters: &Self::Parameters) -> Self::RawInputs {
        (Precision::Raw::uniform_vec(
            parameters.lwe_ciphertext_count.0,
        ),)
    }

    fn compute_prediction(
        parameters: &Self::Parameters,
        raw_inputs: &Self::RawInputs,
        sample_size: SampleSize,
    ) -> Self::Prediction {
        let (raws,) = raw_inputs;
        raws.iter()
            .map(|raw| (vec![*raw; sample_size.0], parameters.noise))
            .collect()
    }

    fn check_prediction(
        parameters: &Self::Parameters,
        forecast: &Self::Prediction,
        actual: &[Self::RawOutputs],
    ) -> bool {
        let transposed_outputs: Vec<Vec<Precision::Raw>> = (0..parameters.lwe_ciphertext_count.0)
            .map(|i| actual.iter().map(|v| v.0[i]).collect())
            .collect();
        transposed_outputs
            .iter()
            .zip(forecast.iter())
            .map(|(output, (means, noise))| {
                assert_noise_distribution(output, means.as_slice(), *noise)
            })
            .reduce(BitAnd::bitand)
            .unwrap()
    }

    fn prepare_context(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        raw_inputs: &Self::RawInputs,
    ) -> (Self::Bypass, Self::PreExecutionContext) {
        let (raw_plaintext_vector,) = raw_inputs;
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector);
        let proto_secret_key = maker.new_lwe_secret_key(parameters.lwe_dimension);
        let proto_ciphertext_vector = maker.encrypt_plaintext_vector_to_lwe_ciphertext_vector(
            &proto_secret_key,
            &proto_plaintext_vector,
            parameters.noise,
        );
        let synth_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(&proto_ciphertext_vector);
        let synth_secret_key = maker.synthesize_lwe_secret_key(&proto_secret_key);
        ((), (synth_ciphertext_vector, synth_secret_key))
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (ciphertext_vector, secret_key) = context;
        let plaintext_vector = unsafe {
            engine.decrypt_lwe_ciphertext_vector_unchecked(&secret_key, &ciphertext_vector)
        };
        (ciphertext_vector, secret_key, plaintext_vector)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        _bypass: Self::Bypass,
        context: Self::PostExecutionContext,
    ) -> Self::RawOutputs {
        let (ciphertext_vector, secret_key, plaintext_vector) = context;
        let proto_output_plaintext_vector = maker.unsynthesize_plaintext_vector(&plaintext_vector);
        maker.destroy_lwe_ciphertext_vector(ciphertext_vector);
        maker.destroy_lwe_secret_key(secret_key);
        maker.destroy_plaintext_vector(plaintext_vector);
        (maker.transform_plaintext_vector_to_raw_vec(&proto_output_plaintext_vector),)
    }
}
