use crate::generation::prototyping::{
    PrototypesLweCiphertext, PrototypesLweKeyswitchKey, PrototypesLweSecretKey, PrototypesPlaintext,
};
use crate::generation::synthesizing::{
    SynthesizeGlweCiphertext, SynthesizeLweBootstrapKey, SynthesizeLweCiphertext,
    SynthesizeLweKeyswitchKey,
};
use crate::generation::{IntegerPrecision, Maker};
use crate::harness::Harness;
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use crate::SampleSize;
use concrete_commons::dispersion::{DispersionParameter, LogStandardDev, Variance};
use concrete_commons::key_kinds::{BinaryKeyKind, GaussianKeyKind, TernaryKeyKind};
use concrete_commons::numeric::{Numeric, UnsignedInteger};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use concrete_core::prelude::markers::{
    BinaryKeyDistribution, GaussianKeyDistribution, KeyDistributionMarker, TernaryKeyDistribution,
};
use concrete_core::prelude::{
    GlweCiphertextEntity, GlweSecretKeyEntity, LweBootstrapKeyEntity,
    LweCiphertextDiscardingBootstrapEngine, LweCiphertextDiscardingKeyswitchEngine,
    LweCiphertextEntity, LweKeyswitchKeyEntity,
};
use std::any::TypeId;

/// A fixture for the types implementing the `LweCiphertextDiscardingBootstrapEngine` trait.
pub struct LweCiphertextDiscardingBootstrapHarness;

#[derive(Debug)]
pub struct LweCiphertextDiscardingBootstrapParameters {
    pub poly_size: PolynomialSize,
    pub glwe_dimension: GlweDimension,
    pub lwe_dimension: LweDimension,
    pub decomp_level_count: DecompositionLevelCount,
    pub decomp_base_log: DecompositionBaseLog,
    pub noise: Variance,
}

impl<Precision, Engine, BootstrapKey, Accumulator, InputCiphertext, OutputCiphertext>
    Harness<Precision, Engine, (BootstrapKey, Accumulator, InputCiphertext, OutputCiphertext)>
    for LweCiphertextDiscardingBootstrapHarness
where
    Precision: IntegerPrecision,
    Engine: LweCiphertextDiscardingBootstrapEngine<
        BootstrapKey,
        Accumulator,
        InputCiphertext,
        OutputCiphertext,
    >,
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity,
    Accumulator: GlweCiphertextEntity<KeyDistribution = OutputCiphertext::KeyDistribution>,
    BootstrapKey: LweBootstrapKeyEntity<
        InputKeyDistribution = InputCiphertext::KeyDistribution,
        OutputKeyDistribution = OutputCiphertext::KeyDistribution,
    >,
    Maker: SynthesizeLweBootstrapKey<Precision, BootstrapKey>
        + SynthesizeLweCiphertext<Precision, InputCiphertext>
        + SynthesizeLweCiphertext<Precision, OutputCiphertext>
        + SynthesizeGlweCiphertext<Precision, Accumulator>,
{
    type Parameters = LweCiphertextDiscardingBootstrapParameters;
    type RawInputs = (Precision::Raw, Vec<Precision::Raw>);
    type RawOutputs = (Precision::Raw,);
    type Keys = ();
    type EngineInputs = (BootstrapKey, Accumulator, InputCiphertext, OutputCiphertext);
    type EngineOutputs = (BootstrapKey, Accumulator, InputCiphertext, OutputCiphertext);
    type Prediction = (Vec<Precision::Raw>, Variance);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                LweCiphertextDiscardingBootstrapParameters {
                    poly_size: PolynomialSize(512),
                    glwe_dimension: GlweDimension(1),
                    lwe_dimension: LweDimension(630),
                    decomp_level_count: DecompositionLevelCount(3),
                    decomp_base_log: DecompositionBaseLog(7),
                    noise: Variance(LogStandardDev::from_log_standard_dev(-29.).get_variance()),
                },
                LweCiphertextDiscardingBootstrapParameters {
                    poly_size: PolynomialSize(1024),
                    glwe_dimension: GlweDimension(1),
                    lwe_dimension: LweDimension(630),
                    decomp_level_count: DecompositionLevelCount(3),
                    decomp_base_log: DecompositionBaseLog(7),
                    noise: Variance(LogStandardDev::from_log_standard_dev(-29.).get_variance()),
                },
                LweCiphertextDiscardingBootstrapParameters {
                    poly_size: PolynomialSize(2048),
                    glwe_dimension: GlweDimension(1),
                    lwe_dimension: LweDimension(630),
                    decomp_level_count: DecompositionLevelCount(3),
                    decomp_base_log: DecompositionBaseLog(7),
                    noise: Variance(LogStandardDev::from_log_standard_dev(-29.).get_variance()),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_raw_inputs(parameters: &Self::Parameters) -> Self::RawInputs {
        let random = Precision::Raw::uniform();
        let message = random
            & (((Precision::Raw::ONE << 3) - Precision::Raw::ONE) << (Precision::Raw::BITS - 4));
        let cst =
        (message,)
    }

    fn prepare_inputs(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        raw_inputs: &Self::RawInputs,
    ) -> (Self::Keys, Self::EngineInputs) {
        let (raw_plaintext,) = raw_inputs;
        let proto_plaintext = maker.transform_raw_to_plaintext(raw_plaintext);
        let proto_output_secret_key = <Maker as PrototypesLweSecretKey<
            Precision,
            OutputCiphertext::KeyDistribution,
        >>::new_lwe_secret_key(
            maker, parameters.output_lwe_dimension
        );
        let proto_input_secret_key = <Maker as PrototypesLweSecretKey<
            Precision,
            InputCiphertext::KeyDistribution,
        >>::new_lwe_secret_key(
            maker, parameters.input_lwe_dimension
        );
        let proto_keyswitch_key = maker.new_lwe_keyswitch_key(
            &proto_input_secret_key,
            &proto_output_secret_key,
            parameters.decomp_level_count,
            parameters.decomp_base_log,
            parameters.ksk_noise,
        );
        let proto_input_ciphertext = <Maker as PrototypesLweCiphertext<
            Precision,
            InputCiphertext::KeyDistribution,
        >>::encrypt_plaintext_to_lwe_ciphertext(
            maker,
            &proto_input_secret_key,
            &proto_plaintext,
            parameters.input_noise,
        );
        let proto_output_ciphertext = <Maker as PrototypesLweCiphertext<
            Precision,
            OutputCiphertext::KeyDistribution,
        >>::trivial_encrypt_zero_to_lwe_ciphertext(
            maker,
            parameters.output_lwe_dimension.to_lwe_size(),
        );
        let synth_keywsitch_key = maker.synthesize_lwe_keyswitch_key(&proto_keyswitch_key);
        let synth_input_ciphertext = maker.synthesize_lwe_ciphertext(&proto_input_ciphertext);
        let synth_output_ciphertext = maker.synthesize_lwe_ciphertext(&proto_output_ciphertext);
        (
            (proto_output_secret_key, proto_input_secret_key),
            (
                synth_keywsitch_key,
                synth_input_ciphertext,
                synth_output_ciphertext,
            ),
        )
    }

    fn ignite_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        inputs: Self::EngineInputs,
    ) -> Self::EngineOutputs {
        let (keyswitch_key, input_ciphertext, mut output_ciphertext) = inputs;
        unsafe {
            engine.discard_keyswitch_lwe_ciphertext_unchecked(
                &mut output_ciphertext,
                &input_ciphertext,
                &keyswitch_key,
            )
        };
        (keyswitch_key, input_ciphertext, output_ciphertext)
    }

    fn process_outputs(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        keys: Self::Keys,
        outputs: Self::EngineOutputs,
    ) -> Self::RawOutputs {
        let (keyswitch_key, input_ciphertext, output_ciphertext) = outputs;
        let (proto_secret_key, _) = keys;
        let proto_output_ciphertext = maker.unsynthesize_lwe_ciphertext(&output_ciphertext);
        let proto_plaintext = <Maker as PrototypesLweCiphertext<
            Precision,
            OutputCiphertext::KeyDistribution,
        >>::decrypt_lwe_ciphertext_to_plaintext(
            maker, &proto_secret_key, &proto_output_ciphertext
        );
        maker.destroy_lwe_ciphertext(input_ciphertext);
        maker.destroy_lwe_ciphertext(output_ciphertext);
        maker.destroy_lwe_keyswitch_key(keyswitch_key);
        (maker.transform_plaintext_to_raw(&proto_plaintext),)
    }

    fn compute_prediction(
        parameters: &Self::Parameters,
        raw_inputs: &Self::RawInputs,
        sample_size: SampleSize,
    ) -> Self::Prediction {
        let (raw_plaintext,) = raw_inputs;
        let predicted_variance: Variance =
            fix_estimate_keyswitch_noise_lwe_to_glwe_with_constant_terms::<
                Precision::Raw,
                _,
                _,
                OutputCiphertext::KeyDistribution,
            >(
                parameters.input_lwe_dimension,
                parameters.input_noise,
                parameters.ksk_noise,
                parameters.decomp_base_log,
                parameters.decomp_level_count,
            );
        (vec![*raw_plaintext; sample_size.0], predicted_variance)
    }

    fn check_prediction(
        _parameters: &Self::Parameters,
        forecast: &Self::Prediction,
        actual: &[Self::RawOutputs],
    ) -> bool {
        let (means, noise) = forecast;
        let actual = actual.iter().map(|r| r.0).collect::<Vec<_>>();
        assert_noise_distribution(&actual, means.as_slice(), *noise)
    }
}

// The current NPE does not use the key distribution markers of concrete-core. This function makes the
// mapping. This function should be removed as soon as the npe uses the types of concrete-core.
fn fix_estimate_keyswitch_noise_lwe_to_glwe_with_constant_terms<T, D1, D2, K>(
    lwe_mask_size: LweDimension,
    dispersion_lwe: D1,
    dispersion_ksk: D2,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
) -> Variance
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
    K: KeyDistributionMarker,
{
    let k_type_id = TypeId::of::<K>();
    if k_type_id == TypeId::of::<BinaryKeyDistribution>() {
        concrete_npe::estimate_keyswitch_noise_lwe_to_glwe_with_constant_terms::<
            T,
            D1,
            D2,
            BinaryKeyKind,
        >(
            lwe_mask_size,
            dispersion_lwe,
            dispersion_ksk,
            base_log,
            level,
        )
    } else if k_type_id == TypeId::of::<TernaryKeyDistribution>() {
        concrete_npe::estimate_keyswitch_noise_lwe_to_glwe_with_constant_terms::<
            T,
            D1,
            D2,
            TernaryKeyKind,
        >(
            lwe_mask_size,
            dispersion_lwe,
            dispersion_ksk,
            base_log,
            level,
        )
    } else if k_type_id == TypeId::of::<GaussianKeyDistribution>() {
        concrete_npe::estimate_keyswitch_noise_lwe_to_glwe_with_constant_terms::<
            T,
            D1,
            D2,
            GaussianKeyKind,
        >(
            lwe_mask_size,
            dispersion_lwe,
            dispersion_ksk,
            base_log,
            level,
        )
    } else {
        panic!("Unknown key distribution encountered.")
    }
}
