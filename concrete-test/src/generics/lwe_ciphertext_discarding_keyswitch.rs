use crate::integers::RawUnsignedIntegers;
use crate::synthesizing::precisions::IntegerPrecision;
use crate::synthesizing::prototyper::Prototyper;
use crate::synthesizing::synthesizers::{
    SynthesizableBinaryBinaryLweKeyswitchKey, SynthesizableBinaryLweCiphertext,
    SynthesizableBinaryLweSecretKey, SynthesizablePlaintext,
};
use crate::synthesizing::Synthesizer;
use crate::utils::assert_noise_distribution;
use concrete_commons::dispersion::{DispersionParameter, LogStandardDev, Variance};
use concrete_commons::key_kinds::BinaryKeyKind;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, LweCiphertextCount, LweDimension,
};
use concrete_core::prelude::markers::BinaryKeyDistribution;
use concrete_core::prelude::{
    LweCiphertextDiscardingKeyswitchEngine, LweCiphertextEncryptionEngine, LweCiphertextEntity,
    LweSecretKeyEntity, PlaintextEntity,
};
use lazy_static::lazy_static;

pub fn test_binary_binary<Precision, Engine, KeyswitchKey, InputCiphertext, OutputCiphertext>()
where
    Precision: IntegerPrecision,
    Synthesizer: Prototyper<Precision>,
    Engine: LweCiphertextDiscardingKeyswitchEngine<KeyswitchKey, InputCiphertext, OutputCiphertext>,
    KeyswitchKey: SynthesizableBinaryBinaryLweKeyswitchKey<Precision>,
    InputCiphertext: SynthesizableBinaryLweCiphertext<Precision>,
    OutputCiphertext: SynthesizableBinaryLweCiphertext<Precision>,
{
    let mut synthesizer = Synthesizer::default();
    let mut engine = Engine::new().unwrap();

    for p in &*PARAMETERS {
        for _ in 0..crate::REPETITIONS.0 {
            let expected =
                Precision::Raw::uniform_n_msb_vec(p.n_bit_message.0, crate::SAMPLE_SIZE.0);
            let mut achieved = Precision::Raw::one_vec(crate::SAMPLE_SIZE.0);

            for i in 0..crate::SAMPLE_SIZE.0 {
                // Creating prototypes
                let proto_input_key = synthesizer.new_binary_lwe_secret_key(p.input_dimension);
                let proto_output_key = synthesizer.new_binary_lwe_secret_key(p.output_dimension);
                let proto_ks_key = synthesizer.new_binary_binary_lwe_keyswitch_key(
                    &proto_input_key,
                    &proto_output_key,
                    p.decomposition_level,
                    p.decomposition_base_log,
                    p.ksk_noise,
                );
                let proto_plaintext = synthesizer.transform_raw_to_plaintext(&expected[i]);
                let proto_input = synthesizer.encrypt_plaintext_to_binary_lwe_ciphertext(
                    &proto_input_key,
                    &proto_plaintext,
                    p.input_noise,
                );
                let proto_zero = synthesizer.transform_raw_to_plaintext(&Precision::Raw::zero());
                let proto_output = synthesizer.encrypt_plaintext_to_binary_lwe_ciphertext(
                    &proto_output_key,
                    &proto_zero,
                    p.input_noise,
                );

                // Performing keyswitch
                let ksk = KeyswitchKey::from_prototype(&mut synthesizer, &proto_ks_key);
                let input = InputCiphertext::from_prototype(&mut synthesizer, &proto_input);
                let mut output = OutputCiphertext::from_prototype(&mut synthesizer, &proto_output);
                engine
                    .discard_keyswitch_lwe_ciphertext(&mut output, &input, &ksk)
                    .unwrap();

                // Recovering result
                let proto_output = OutputCiphertext::into_prototype(&mut synthesizer, &output);
                let proto_recovered = synthesizer
                    .decrypt_binary_lwe_ciphertext_to_plaintext(&proto_output_key, &proto_output);
                let raw_recovered = synthesizer.transform_plaintext_to_raw(&proto_recovered);
                achieved[i] = raw_recovered;
            }

            let expected_variance =
                concrete_npe::estimate_keyswitch_noise_lwe_to_glwe_with_constant_terms::<
                    Precision::Raw,
                    _,
                    _,
                    BinaryKeyKind,
                >(
                    p.input_dimension,
                    p.input_noise,
                    p.ksk_noise,
                    p.decomposition_base_log,
                    p.decomposition_level,
                );
            assert_noise_distribution(expected.as_slice(), achieved.as_slice(), expected_variance);
        }
    }
}

pub struct MessageBitCount(pub usize);
pub struct Parameters {
    pub n_bit_message: MessageBitCount,
    pub decomposition_level: DecompositionLevelCount,
    pub decomposition_base_log: DecompositionBaseLog,
    pub input_noise: Variance,
    pub ksk_noise: Variance,
    pub input_dimension: LweDimension,
    pub output_dimension: LweDimension,
}

lazy_static! {
    static ref PARAMETERS: Vec<Parameters> = vec![Parameters {
        n_bit_message: MessageBitCount(8),
        decomposition_level: DecompositionLevelCount(8),
        decomposition_base_log: DecompositionBaseLog(3),
        input_noise: Variance(LogStandardDev::from_log_standard_dev(-10.).get_variance()),
        ksk_noise: Variance(LogStandardDev::from_log_standard_dev(-25.).get_variance()),
        input_dimension: LweDimension(1024),
        output_dimension: LweDimension(600)
    }];
}
