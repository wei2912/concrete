use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesCleartextVector, PrototypesLweCiphertext, PrototypesLweCiphertextVector,
    PrototypesLweSecretKey, PrototypesPlaintext, PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{
    SynthesizesCleartextVector, SynthesizesLweCiphertext, SynthesizesLweCiphertextVector,
    SynthesizesPlaintext,
};
use crate::generation::{IntegerPrecision, Maker};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use crate::SampleSize;
use concrete_commons::dispersion::{DispersionParameter, LogStandardDev, Variance};
use concrete_commons::numeric::UnsignedInteger;
use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
use concrete_core::prelude::{
    CleartextVectorEntity, LweCiphertextEntity,
    LweCiphertextVectorDiscardingAffineTransformationEngine, LweCiphertextVectorEntity,
    PlaintextEntity,
};

/// A fixture for the types implementing the `LweCiphertextVectorDiscardingAffineTransformationEngine` trait.
pub struct LweCiphertextVectorDiscardingAffineTransformationFixture;

#[derive(Debug)]
pub struct LweCiphertextVectorDiscardingAffineTransformationParameters {
    pub nb_ct: LweCiphertextCount,
    pub noise: Variance,
    pub lwe_dimension: LweDimension,
}

impl<Precision, Engine, CiphertextVector, CleartextVector, Plaintext, OutputCiphertext>
    Fixture<
        Precision,
        Engine,
        (
            CiphertextVector,
            CleartextVector,
            Plaintext,
            OutputCiphertext,
        ),
    > for LweCiphertextVectorDiscardingAffineTransformationFixture
where
    Precision: IntegerPrecision,
    Engine: LweCiphertextVectorDiscardingAffineTransformationEngine<
        CiphertextVector,
        CleartextVector,
        Plaintext,
        OutputCiphertext,
    >,
    CiphertextVector: LweCiphertextVectorEntity,
    CleartextVector: CleartextVectorEntity,
    Plaintext: PlaintextEntity,
    OutputCiphertext: LweCiphertextEntity<KeyDistribution = CiphertextVector::KeyDistribution>,
    Maker: SynthesizesLweCiphertextVector<Precision, CiphertextVector>
        + SynthesizesCleartextVector<Precision, CleartextVector>
        + SynthesizesPlaintext<Precision, Plaintext>
        + SynthesizesLweCiphertext<Precision, OutputCiphertext>,
{
    type Parameters = LweCiphertextVectorDiscardingAffineTransformationParameters;
    type RawInputs = (Vec<Precision::Raw>, Vec<Precision::Raw>, Precision::Raw);
    type RawOutputs = (Precision::Raw,);
    type Bypass = (<Maker as PrototypesLweSecretKey<Precision, CiphertextVector::KeyDistribution>>::LweSecretKeyProto, );
    type PreExecutionContext = (
        OutputCiphertext,
        CiphertextVector,
        CleartextVector,
        Plaintext,
    );
    type PostExecutionContext = (
        OutputCiphertext,
        CiphertextVector,
        CleartextVector,
        Plaintext,
    );
    type Prediction = (Vec<Precision::Raw>, Variance);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextVectorDiscardingAffineTransformationParameters {
                    nb_ct: LweCiphertextCount(100),
                    noise: Variance(LogStandardDev::from_log_standard_dev(-25.).get_variance()),
                    lwe_dimension: LweDimension(1000),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_raw_inputs(_parameters: &Self::Parameters) -> Self::RawInputs {
        (
            Precision::Raw::uniform_vec(_parameters.nb_ct.0),
            Precision::Raw::uniform_zero_centered_vec(512, _parameters.nb_ct.0),
            Precision::Raw::uniform_between(0..1024usize),
        )
    }

    fn compute_prediction(
        parameters: &Self::Parameters,
        raw_inputs: &Self::RawInputs,
        sample_size: SampleSize,
    ) -> Self::Prediction {
        let (raw_plaintext_vector, raw_weight_vector, raw_bias) = raw_inputs;
        let predicted_mean = raw_plaintext_vector
            .iter()
            .zip(raw_weight_vector.iter())
            .fold(*raw_bias, |a, (c, w)| a.wrapping_add(c.wrapping_mul(*w)));
        let predicted_variance: Variance =
            concrete_npe::estimate_weighted_sum_noise::<Precision::Raw, _>(
                &vec![parameters.noise; parameters.nb_ct.0],
                raw_weight_vector,
            );
        (vec![predicted_mean; sample_size.0], predicted_variance)
    }

    fn check_prediction(
        _parameters: &Self::Parameters,
        prediction: &Self::Prediction,
        actual: &[Self::RawOutputs],
    ) -> bool {
        let (means, noise) = prediction;
        let actual = actual.iter().map(|r| r.0).collect::<Vec<_>>();
        assert_noise_distribution(&actual, means.as_slice(), *noise)
    }

    fn prepare_context(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        raw_inputs: &Self::RawInputs,
    ) -> (Self::Bypass, Self::PreExecutionContext) {
        let (raw_plaintext_vector, raw_weight_vector, raw_bias) = raw_inputs;
        let proto_plaintext_vector =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector);
        let proto_weight_vector = maker.transform_raw_vec_to_cleartext_vector(raw_weight_vector);
        let proto_bias = maker.transform_raw_to_plaintext(raw_bias);
        let proto_secret_key = maker.new_lwe_secret_key(parameters.lwe_dimension);
        let proto_ciphertext_vector = maker.encrypt_plaintext_vector_to_lwe_ciphertext_vector(
            &proto_secret_key,
            &proto_plaintext_vector,
            parameters.noise,
        );
        let proto_output_ciphertext =
            maker.trivial_encrypt_zero_to_lwe_ciphertext(parameters.lwe_dimension.to_lwe_size());
        let synth_output_ciphertext = maker.synthesize_lwe_ciphertext(&proto_output_ciphertext);
        let synth_ciphertext_vector =
            maker.synthesize_lwe_ciphertext_vector(&proto_ciphertext_vector);
        let synth_weight_vector = maker.synthesize_cleartext_vector(&proto_weight_vector);
        let synth_bias = maker.synthesize_plaintext(&proto_bias);
        (
            (proto_secret_key,),
            (
                synth_output_ciphertext,
                synth_ciphertext_vector,
                synth_weight_vector,
                synth_bias,
            ),
        )
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (mut output_ciphertext, ciphertext_vector, weights, bias) = context;
        unsafe {
            engine.discard_affine_transform_lwe_ciphertext_vector_unchecked(
                &mut output_ciphertext,
                &ciphertext_vector,
                &weights,
                &bias,
            )
        };
        (output_ciphertext, ciphertext_vector, weights, bias)
    }

    fn process_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        bypass: Self::Bypass,
        context: Self::PostExecutionContext,
    ) -> Self::RawOutputs {
        let (output_ciphertext, ciphertext_vector, weights, bias) = context;
        let (proto_secret_key,) = bypass;
        let proto_output_ciphertext = maker.unsynthesize_lwe_ciphertext(&output_ciphertext);
        let proto_plaintext =
            maker.decrypt_lwe_ciphertext_to_plaintext(&proto_secret_key, &proto_output_ciphertext);
        maker.destroy_lwe_ciphertext(output_ciphertext);
        maker.destroy_lwe_ciphertext_vector(ciphertext_vector);
        maker.destroy_cleartext_vector(weights);
        maker.destroy_plaintext(bias);
        (maker.transform_plaintext_to_raw(&proto_plaintext),)
    }
}
