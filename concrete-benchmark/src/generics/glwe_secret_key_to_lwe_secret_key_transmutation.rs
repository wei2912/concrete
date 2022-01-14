use crate::synthesizer::{SynthesizableGlweSecretKeyEntity, Synthesizer};
use crate::utils::benchmark_name;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
use concrete_core::prelude::*;
use criterion::{black_box, BenchmarkId, Criterion};

pub fn bench<Engine, GlweSecretKey, LweSecretKey>(c: &mut Criterion)
where
    Engine: GlweToLweSecretKeyTransmutationEngine<GlweSecretKey, LweSecretKey>,
    GlweSecretKey: SynthesizableGlweSecretKeyEntity + Clone,
    LweSecretKey: LweSecretKeyEntity<KeyDistribution = GlweSecretKey::KeyDistribution>,
{
    let mut group = c.benchmark_group(benchmark_name!(
        impl GlweToLweSecretKeyTransmutationEngine<
            GlweSecretKey,
            LweSecretKey
        > for Engine
    ));

    let mut synthesizer = Synthesizer::default();
    let mut engine = Engine::new().unwrap();

    for param in PARAMETERS {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", param)),
            &param,
            |b, param| {
                let (glwe_dimension, polynomial_size) = *param;
                let glwe_secret_key =
                    GlweSecretKey::synthesize(&mut synthesizer, polynomial_size, glwe_dimension);

                b.iter(|| {
                    let glwe_secret_key = glwe_secret_key.clone();
                    black_box(
                        engine
                            .transmute_glwe_secret_key_to_lwe_secret_key(glwe_secret_key)
                            .unwrap(),
                    );
                })
            },
        );
    }
}

/// The parameters the benchmark is executed against.
const PARAMETERS: [(GlweDimension, PolynomialSize); 8] = [
    (GlweDimension(1), PolynomialSize(256)),
    (GlweDimension(1), PolynomialSize(512)),
    (GlweDimension(1), PolynomialSize(1024)),
    (GlweDimension(1), PolynomialSize(2048)),
    (GlweDimension(1), PolynomialSize(4096)),
    (GlweDimension(2), PolynomialSize(256)),
    (GlweDimension(2), PolynomialSize(512)),
    (GlweDimension(2), PolynomialSize(1024)),
];
