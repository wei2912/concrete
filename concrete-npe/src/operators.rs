//! Noise Propagation Estimator Module
///
/// * Contains material needed to estimate the growth of the noise when performing homomorphic
///   computation
use super::*;
use concrete_commons::dispersion::{DispersionParameter, Variance};
use concrete_commons::key_kinds::KeyKind;
use concrete_commons::numeric::{CastInto, SignedInteger, UnsignedInteger};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, LweSize,
    PolynomialSize,
};

/// Computes the dispersion of the error distribution after the addition of two
/// uncorrelated ciphertexts
/// # Example:
/// ```rust
/// use concrete_commons::dispersion::*;
/// use concrete_npe::*;
///
/// let var1 = Variance::from_variance(2_f64.powf(-25.));
/// let var2 = Variance::from_variance(2_f64.powf(-25.));
/// let var_out = variance_add::<u64, _, _>(var1, var2);
/// println!("Expect Variance (2^24) =  {}", f64::powi(2., -24));
/// println!("Output Variance {}", var_out.get_variance());
/// assert!((f64::powi(2., -24) - var_out.get_variance()).abs() < 0.0001);
/// ```
pub fn variance_add<T, D1, D2>(dispersion_ct1: D1, dispersion_ct2: D2) -> Variance
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
{
    // The result variance is equal to the sum of the input variances
    let var_res: f64 =
        dispersion_ct1.get_modular_variance::<T>() + dispersion_ct2.get_modular_variance::<T>();
    Variance::from_modular_variance::<T>(var_res)
}

/// Computes the dispersion of the error distribution after the addition of
/// several uncorrelated ciphertexts
/// # Example:
/// ```rust
/// use concrete_commons::dispersion::*;
/// use concrete_npe::*;
///
/// let var1 = Variance::from_variance(2_f64.powf(-25.));
/// let var2 = Variance::from_variance(2_f64.powf(-25.));
/// let var3 = Variance::from_variance(2_f64.powf(-24.));
/// let var_in = [var1, var2, var3];
/// let var_out = variance_add_several::<u64, _>(&var_in);
/// println!("Expect Variance (2^24) =  {}", f64::powi(2., -23));
/// println!("Output Variance {}", var_out.get_variance());
/// assert!((f64::powi(2., -23) - var_out.get_variance()).abs() < 0.0001);
/// ```
pub fn variance_add_several<T, D>(dispersion_cts: &[D]) -> Variance
where
    T: UnsignedInteger,
    D: DispersionParameter,
{
    let mut var_res: f64 = 0.;
    // The result variance is equal to the sum of the input variances
    for dispersion in dispersion_cts.iter() {
        var_res += dispersion.get_modular_variance::<T>();
    }
    Variance::from_modular_variance::<T>(var_res)
}

//TODO: CHECK THE PRECISION !
/// Return the variance of the external product given a set of parameters.
/// # Example:
/// ```rust
/// use concrete_commons::dispersion::*;
/// use concrete_commons::parameters::{
///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
/// };
/// use concrete_npe::*;
/// use concrete_commons::key_kinds::BinaryKeyKind;
/// let dimension = GlweDimension(3);
/// let polynomial_size = PolynomialSize(1024);
/// let base_log = DecompositionBaseLog(7);
/// let l_gadget = DecompositionLevelCount(4);
/// //Variance::from_variance(f64::powi(2., -38));
/// let dispersion_rgsw = Variance::from_modular_variance::<u64>(f64::powi(2., 26));
/// //Variance::from_variance(f64::powi(2., -40));
/// let dispersion_rlwe = Variance::from_modular_variance::<u64>(f64::powi(2., 24));
/// // Computing the noise
/// let var_external_product = variance_external_product::<u64, _, _, BinaryKeyKind>(
///     dimension,
///     polynomial_size,
///     base_log,
///     l_gadget,
///     dispersion_rgsw,
///     dispersion_rlwe,
/// );
/// println!(
///     "Out. {}",
///     var_external_product.get_modular_variance::<u64>()
/// );
///
/// println!("Exp. {}", 3.66209842969680e35);
/// assert!(
///     (3.66209842969680e35 - var_external_product.get_modular_variance::<u64>()).abs()
///         < f64::powi(10., 10)
/// );
/// ```
pub fn variance_external_product<T, D1, D2, K>(
    dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    base_log: DecompositionBaseLog,
    l_gadget: DecompositionLevelCount,
    dispersion_ggsw: D1,
    dispersion_glwe: D2,
) -> Variance
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
    K: KeyDispersion,
{
    // norm 2 of the integer polynomial hidden in the RGSW
    // for an external product inside a bootstrap, the integer polynomial is in fact
    // a constant polynomial equal to 0 or 1
    let norm_2_msg_ggsw = 1.;
    let b_g = 1 << base_log.0;
    let q_square = f64::powi(2., (2 * T::BITS) as i32);
    let res_1: f64 = ((dimension.0 + 1) * l_gadget.0 * polynomial_size.0 * (b_g * b_g + 2)) as f64
        / 12.
        * dispersion_ggsw.get_modular_variance::<T>();
    println!("Res1. {}", res_1);
    println!("var_rgsw. {}", dispersion_ggsw.get_modular_variance::<T>());

    let res_2: f64 = square(norm_2_msg_ggsw)
        * (dispersion_glwe.get_modular_variance::<T>()
            + (q_square - f64::powi(b_g as f64, 2 * l_gadget.0 as i32))
                / (12. * f64::powi(b_g as f64, 2 * l_gadget.0 as i32))
                * (1.
                    + dimension.0 as f64
                        * polynomial_size.0 as f64
                        * (K::variance_key_coefficient::<T>().get_variance()
                            + square(K::expectation_key_coefficient())))
            + dimension.0 as f64 * polynomial_size.0 as f64 / 4.
                * K::variance_key_coefficient::<T>().get_variance());

    Variance::from_modular_variance::<T>(res_1 + res_2)
}
//TODO: End this test
/// Return the variance of the CMUX given a set of parameters.
/// # Warning
/// * Only correct for the CMUX inside a bootstrap
/// # Example
/// ```rust
/// use concrete_commons::dispersion::{DispersionParameter, Variance};
/// use concrete_commons::parameters::{
///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
/// };
/// use concrete_npe::*;
/// use concrete_commons::key_kinds::BinaryKeyKind;
/// let dimension = GlweDimension(3);
/// let l_gadget = DecompositionLevelCount(4);
/// let base_log = DecompositionBaseLog(7);
/// let polynomial_size = PolynomialSize(1024);
/// let dispersion_rgsw = Variance::from_modular_variance::<u64>(f64::powi(2., 26));
/// let dispersion_rlwe_0 = Variance::from_modular_variance::<u64>(f64::powi(2., 25));
/// let dispersion_rlwe_1 = Variance::from_modular_variance::<u64>(f64::powi(2., 25));
/// // Computing the noise
/// let var_cmux = variance_cmux::<u64, _, _, _,BinaryKeyKind>(
///     dimension,
///     polynomial_size,
///     base_log,
///     l_gadget,
///     dispersion_rlwe_0,
///     dispersion_rlwe_1,
///     dispersion_rgsw,
/// );
/// let expected_variance = 6.04856441848937e23 + dispersion_rlwe_0.get_modular_variance::<u64>();
/// println!(
///     "Out. {}",
///     var_cmux.get_modular_variance::<u64>()
/// );
///
/// println!("Exp. {}", expected_variance);
///
/// let var_external_product = variance_external_product::<u64, _, _, BinaryKeyKind> (
///         dimension,
///         polynomial_size,
///         base_log,
///         l_gadget,
///        dispersion_rgsw,
///         variance_add::<u64, _, _>(dispersion_rlwe_0, dispersion_rlwe_1),
/// );
///  println!("External_Product. {}", var_external_product.get_modular_variance::<u64>());
/// assert!(
///     (expected_variance - var_cmux.get_modular_variance::<u64>()).abs()
///         < f64::powi(10., 10)
/// );
/// ```
pub fn variance_cmux<T, D1, D2, D3, K>(
    dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    base_log: DecompositionBaseLog,
    l_gadget: DecompositionLevelCount,
    dispersion_rlwe_0: D1,
    dispersion_rlwe_1: D2,
    dispersion_rgsw: D3,
) -> Variance
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
    D3: DispersionParameter,
    K: KeyDispersion,
{
    let var_external_product = variance_external_product::<T, _, _, K>(
        dimension,
        polynomial_size,
        base_log,
        l_gadget,
        dispersion_rgsw,
        variance_add::<T, _, _>(dispersion_rlwe_0, dispersion_rlwe_1),
    );
    let var_cmux = variance_add::<T, _, _>(var_external_product, dispersion_rlwe_0);
    var_cmux
}

/// Computes the variance of the error distribution after a multiplication
/// of a ciphertext by a scalar
/// # Example
/// ```rust
/// use concrete_commons::dispersion::*;
/// use concrete_npe::*;
/// let variance = Variance::from_variance(f64::powi(2., -48));
/// let n: u64 = 543;
/// // noise computation
/// let var_out = variance_scalar_mul::<u64, _>(variance, n);
/// println!("Out. {}", var_out.get_modular_variance::<u64>());
/// ```
pub fn variance_scalar_mul<T, D>(variance: D, n: T) -> Variance
where
    T: UnsignedInteger,
    D: DispersionParameter,
{
    let sn = n.into_signed();
    let product: f64 = (sn * sn).cast_into();
    return Variance::from_variance(variance.get_modular_variance::<T>() * product);
}

/// Computes the variance of the error distribution after a multisum between
/// uncorrelated ciphertexts and scalar weights i.e. sigma_out^2 <-
/// \Sum_i weight_i^2 * sigma_i^2 Arguments
/// # Example
/// ```rust
/// use concrete_commons::dispersion::Variance;
/// use concrete_npe::variance_scalar_weighted_sum;
/// let variances = vec![
///     Variance::from_variance(f64::powi(2., -30)),
///     Variance::from_variance(f64::powi(2., -32)),
/// ];
/// let weights: Vec<u64> = vec![20, 10];
/// let var_out = variance_scalar_weighted_sum(&variances, &weights);
/// ```
pub fn variance_scalar_weighted_sum<T, D>(dispersion_list: &[D], weights: &[T]) -> Variance
where
    T: UnsignedInteger,
    D: DispersionParameter,
{
    let mut var_res: f64 = 0.;

    for (dispersion, &w) in dispersion_list.iter().zip(weights) {
        var_res += variance_scalar_mul(*dispersion, w).get_modular_variance::<T>();
    }
    Variance::from_variance(var_res)
}

/// Noise formulas for the RLWE operations considering that all slot have the
/// same error variance

/// Computes the variance of the error distribution after a multiplication
/// between an RLWE ciphertext and a scalar polynomial
/// sigma_out^2 <- \Sum_i weight_i^2 * sigma^2
/// # Example
/// ```rust
/// use concrete_commons::dispersion::Variance;
/// use concrete_commons::parameters::PolynomialSize;
/// use concrete_npe::*;
/// let polynomial_size = PolynomialSize(1024);
/// let dispersion_rlwe = Variance::from_variance(f64::powi(2., -40));
/// let scalar_polynomial = vec![10, 15, 18];
/// // Computing the noise
/// let var_out = variance_scalar_polynomial_mul::<u64, _>(dispersion_rlwe, &scalar_polynomial);
/// ```
pub fn variance_scalar_polynomial_mul<T, D>(dispersion: D, scalar_polynomial: &[T]) -> Variance
where
    T: UnsignedInteger,
    D: DispersionParameter,
{
    variance_scalar_weighted_sum(
        &vec![dispersion; scalar_polynomial.len()],
        scalar_polynomial,
    )
}

//TODO: IS THIS REALLY THE GET VARIANCE OR GET_VARIANCE_MODULAR ?
/// Return the variance of the tensor product between two independent GLWE given
/// a set of parameters
/// /// # Example:
/// ```rust
/// use concrete_commons::dispersion::*;
/// use concrete_commons::parameters::{
///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
/// };
/// use concrete_npe::*;
/// use concrete_commons::key_kinds::BinaryKeyKind;
/// let dimension = GlweDimension(3);
/// let polynomial_size = PolynomialSize(1024);
/// //Variance::from_variance(f64::powi(2., -38));
/// let dispersion_rlwe_0 = Variance::from_modular_variance::<u64>(f64::powi(2., 24));
/// let dispersion_rlwe_1 = Variance::from_modular_variance::<u64>(f64::powi(2., 24));
/// let delta_1 = f64::powi(2., 40);
/// let delta_2 = f64::powi(2., 42);
/// let max_msg_1 = 15.;
/// let max_msg_2 = 7.;
/// let var_out = variance_glwe_tensor_product_rescale_round::<u64, _, _, BinaryKeyKind>(
///     polynomial_size,
///     dimension,
///     dispersion_rlwe_0,
///     dispersion_rlwe_1,
///     delta_1,
///     delta_2,
///     max_msg_1,
///     max_msg_2,
/// );
/// ```
pub fn variance_glwe_tensor_product_rescale_round<T, D1, D2, K>(
    poly_size: PolynomialSize,
    rlwe_dimension: GlweDimension,
    dispersion_glwe1: D1,
    dispersion_glwe2: D2,
    delta_1: f64,
    delta_2: f64,
    max_msg_1: f64,
    max_msg_2: f64,
) -> Variance
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
    K: KeyDispersion,
{
    // constants
    let big_n = poly_size.0 as f64; //TODO: polysize is defined as N+1
    let k = rlwe_dimension.0 as f64;
    let delta = f64::min(delta_1, delta_2);
    let delta_square = square(delta);
    let q_square = f64::powi(2., (2 * T::BITS) as i32);
    // #1
    let res_1 = big_n / delta_square
        * (dispersion_glwe1.get_variance() * square(delta_2) * square(max_msg_2)
            + dispersion_glwe2.get_variance() * square(delta_1) * square(max_msg_1)
            + dispersion_glwe1.get_variance() * dispersion_glwe2.get_variance());

    // #2
    let res_2 = (
        // 1ere parenthese
        (q_square - 1.) / 12.
            * (1.
                + k * big_n * K::variance_key_coefficient::<T>().get_variance()
                + k * big_n * square(K::expectation_key_coefficient()))
            + k * big_n / 4. * K::variance_key_coefficient::<T>().get_variance()
            + 1. / 4. * square(1. + k * big_n * K::expectation_key_coefficient())
    ) * (
        // 2e parenthese
        dispersion_glwe1.get_modular_variance::<T>() + dispersion_glwe2.get_modular_variance::<T>()
    ) * big_n
        / delta_square;

    // #3
    let res_3 = 1. / 12.
        + k * big_n / (12. * delta_square)
            * ((delta_square - 1.)
                * (K::variance_key_coefficient::<T>().get_modular_variance::<T>()
                    + square(K::expectation_key_coefficient()))
                + 3. * K::variance_key_coefficient::<T>().get_modular_variance::<T>())
        + k * (k - 1.) * big_n / (24. * delta_square)
            * ((delta_square - 1.)
                * (K::variance_coefficient_in_polynomial_key_times_key::<T>(poly_size)
                    .get_modular_variance::<T>()
                    + K::square_expectation_mean_in_polynomial_key_times_key(poly_size))
                + 3. * K::variance_coefficient_in_polynomial_key_times_key::<T>(poly_size)
                    .get_modular_variance::<T>())
        + k * big_n / (24. * delta_square)
            * ((delta_square - 1.)
                * (K::variance_odd_coefficient_in_polynomial_key_squared::<T>(poly_size)
                    .get_modular_variance::<T>()
                    + K::variance_even_coefficient_in_polynomial_key_squared::<T>(poly_size)
                        .get_modular_variance::<T>()
                    + 2. * K::squared_expectation_mean_in_polynomial_key_squared::<T>(poly_size))
                + 3. * (K::variance_odd_coefficient_in_polynomial_key_squared::<T>(poly_size)
                    .get_modular_variance::<T>()
                    + K::variance_even_coefficient_in_polynomial_key_squared::<T>(poly_size)
                        .get_modular_variance::<T>()));

    Variance::from_variance(res_2 + res_1 + res_3)
}

/// Return the variance of the GLWE after relinearization given
/// a set of parameters
/// # Example
/// ```rust
/// use concrete_commons::dispersion::Variance;
/// use concrete_commons::parameters::{
///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
/// };
/// use concrete_npe::*;
/// use concrete_commons::key_kinds::BinaryKeyKind;
/// let dimension = GlweDimension(3);
/// let l_gadget = DecompositionLevelCount(4);
/// let base_log = DecompositionBaseLog(7);
/// let polynomial_size = PolynomialSize(1024);
/// let dispersion_rlk = Variance::from_variance(f64::powi(2., -38));
/// let var_cmux = variance_glwe_relinearization::<u64, _, BinaryKeyKind>(
///     polynomial_size,
///     dimension,
///     dispersion_rlk,
///     base_log,
///     l_gadget,
/// );
/// ```
pub fn variance_glwe_relinearization<T, D, K>(
    poly_size: PolynomialSize,
    mask_size: GlweDimension,
    dispersion_rlk: D,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
) -> Variance
where
    T: UnsignedInteger,
    D: DispersionParameter,
    K: KeyDispersion,
{
    // constants
    let big_n = poly_size.0 as f64;
    let k = mask_size.0 as f64;
    let b = f64::powi(2., base_log.0 as i32);
    let q_square = f64::powi(2., (2 * T::BITS) as i32);

    // first term
    let res_1 =
        k * (level.0 as f64) * big_n * dispersion_rlk.get_modular_variance::<T>() * (k + 1.) / 2.
            * (square(b) + 2.)
            / 12.;

    // second term
    let res_2 = k * big_n / 2.
        * (q_square / (12. * f64::powi(b, (2 * level.0) as i32)) - 1. / 12.)
        * ((k - 1.)
            * (K::variance_coefficient_in_polynomial_key_times_key::<T>(poly_size)
                .get_modular_variance::<T>()
                + K::square_expectation_mean_in_polynomial_key_times_key(poly_size))
            + K::variance_odd_coefficient_in_polynomial_key_squared::<T>(poly_size)
                .get_modular_variance::<T>()
            + K::variance_even_coefficient_in_polynomial_key_squared::<T>(poly_size)
                .get_modular_variance::<T>()
            + 2. * K::square_expectation_mean_in_polynomial_key_times_key(poly_size));

    // third term
    let res_3 = k * big_n / 8.
        * ((k - 1.)
            * K::variance_coefficient_in_polynomial_key_times_key::<T>(poly_size)
                .get_modular_variance::<T>()
            + K::variance_odd_coefficient_in_polynomial_key_squared::<T>(poly_size)
                .get_modular_variance::<T>()
            + K::variance_even_coefficient_in_polynomial_key_squared::<T>(poly_size)
                .get_modular_variance::<T>());

    Variance::from_variance(res_1 + res_2 + res_3)
}

/// Return a variance when computing an GLWE multiplication (i.e., tensor product and
/// relinearization)
/// # Example
/// ```rust
/// use concrete_commons::dispersion::*;
/// use concrete_commons::parameters::{
///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
/// };
/// use concrete_npe::*;
/// use concrete_commons::key_kinds::BinaryKeyKind;
/// let dimension = GlweDimension(3);
/// let polynomial_size = PolynomialSize(1024);
/// //Variance::from_variance(f64::powi(2., -38));
/// let dispersion_rlwe_0 = Variance::from_modular_variance::<u64>(f64::powi(2., 24));
/// let dispersion_rlwe_1 = Variance::from_modular_variance::<u64>(f64::powi(2., 24));
/// let delta_1 = f64::powi(2., 40);
/// let delta_2 = f64::powi(2., 42);
/// let max_msg_1 = 15.;
/// let max_msg_2 = 7.;
/// let l_gadget = DecompositionLevelCount(4);
/// let base_log = DecompositionBaseLog(7);
/// let dispersion_rlk = Variance::from_variance(f64::powi(2., -38));
/// let var_out = variance_glwe_mul_with_relinearization::<u64, _, _, _, BinaryKeyKind>(
///     polynomial_size,
///     dimension,
///     dispersion_rlwe_0,
///     dispersion_rlwe_1,
///     delta_1,
///     delta_2,
///     max_msg_1,
///     max_msg_2,
///     dispersion_rlk,
///     base_log,
///     l_gadget,
/// );
/// ```
pub fn variance_glwe_mul_with_relinearization<T, D1, D2, D3, K>(
    poly_size: PolynomialSize,
    mask_size: GlweDimension,
    dispersion_glwe1: D1,
    dispersion_glwe2: D2,
    delta_1: f64,
    delta_2: f64,
    max_msg_1: f64,
    max_msg_2: f64,
    dispersion_rlk: D3,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
) -> Variance
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
    D3: DispersionParameter,
    K: KeyDispersion,
{
    // res 1
    let res_1: Variance = variance_glwe_tensor_product_rescale_round::<T, _, _, K>(
        poly_size,
        mask_size,
        dispersion_glwe1,
        dispersion_glwe2,
        delta_1,
        delta_2,
        max_msg_1,
        max_msg_2,
    );

    // res 2
    let res_2: Variance = variance_glwe_relinearization::<T, _, K>(
        poly_size,
        mask_size,
        dispersion_rlk,
        base_log,
        level,
    );

    // return
    Variance::from_variance(res_1.get_variance() + res_2.get_variance())
}

/// Returns the variance of the drift of the PBS with binary keys
/// # Example
/// ```rust
/// use concrete_commons::dispersion::Variance;
/// use concrete_commons::parameters::LweDimension;
/// use concrete_npe::*;
/// let lwe_mask_size = LweDimension(630);
/// let number_of_most_significant_bit: usize = 4;
/// let dispersion_input = Variance::from_variance(f64::powi(2., -40));
/// let var_out = variance_lwe_drift_pbs_with_binary_key::<u64, _>(
///     lwe_mask_size,
///     number_of_most_significant_bit,
///     dispersion_input,
/// );
/// ```
pub fn variance_lwe_drift_pbs_with_binary_key<T, D>(
    lwe_mask_size: LweDimension,
    nb_msb: usize,
    var_in: D,
) -> Variance
where
    T: UnsignedInteger,
    D: DispersionParameter,
{
    let w = (1 << nb_msb) as f64;
    let n = lwe_mask_size.0 as f64;
    let q_square = f64::powi(2., (2 * T::BITS) as i32);
    Variance::from_variance(
        square(w) * var_in.get_modular_variance::<T>() / q_square + 1. / 12.
            - square(w) / (12. * q_square)
            + n / 24.
            + n * square(w) / (48. * q_square),
    )
}

/// Returns the variance of the constant term of the GLWE after an LWE to GLWE keyswitch
/// # Example
/// ```rust
/// use concrete_commons::dispersion::Variance;
/// use concrete_commons::parameters::{
///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
/// };
/// use concrete_npe::{variance_keyswitch_lwe_to_glwe_constant_term, *};
/// use concrete_commons::key_kinds::BinaryKeyKind;
/// let lwe_mask_size = LweDimension(630);
/// let l_ks = DecompositionLevelCount(4);
/// let base_log = DecompositionBaseLog(7);
/// let dispersion_lwe = Variance::from_variance(f64::powi(2., -38));
/// let dispersion_ks = Variance::from_variance(f64::powi(2., -40));
/// let var_ks = variance_keyswitch_lwe_to_glwe_constant_term::<u64, _, _, BinaryKeyKind>(
///     lwe_mask_size,
///     dispersion_lwe,
///     dispersion_ks,
///     base_log,
///     l_ks,
/// );
/// ```
pub fn variance_keyswitch_lwe_to_glwe_constant_term<T, D1, D2, K>(
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
    K: KeyDispersion,
{
    let n = lwe_mask_size.0 as f64;
    let base = (1 << base_log.0) as f64;
    let q_square = f64::powi(2., (2 * T::BITS) as i32);

    // res 1
    let res_1 = dispersion_lwe;

    // res 2
    let res_2 = n
        * (q_square / (12. * f64::powi(base, 2 * level.0 as i32)) - 1. / 12.)
        * (K::variance_key_coefficient::<T>().get_variance()
            + square(K::expectation_key_coefficient()));

    // res 3
    let res_3 = n / 4. * K::variance_key_coefficient::<T>().get_variance();

    // res 4
    let res_4 = n * (level.0 as f64) * dispersion_ksk.get_variance() * (square(base) + 2.) / 12.;

    // return
    Variance::from_variance(res_1.get_variance() + res_2 + res_3 + res_4)
}

/// Return the variance of the non constant GLWE after an LWE to GLWE keyswitch
/// # Example
/// ```rust
/// use concrete_commons::dispersion::Variance;
/// use concrete_commons::parameters::{
///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
/// };
/// use concrete_npe::{variance_keyswitch_lwe_to_glwe_constant_term, *};
/// let lwe_mask_size = LweDimension(630);
/// let l_ks = DecompositionLevelCount(4);
/// let base_log = DecompositionBaseLog(7);
/// let dispersion_ks = Variance::from_variance(f64::powi(2., -40));
/// // Computing the noise
/// let var_ks = variance_keyswitch_lwe_to_glwe_non_constant_terms(
///     lwe_mask_size,
///     dispersion_ks,
///     base_log,
///     l_ks,
/// );
/// ```
pub fn variance_keyswitch_lwe_to_glwe_non_constant_terms<D>(
    lwe_mask_size: LweDimension,
    dispersion_ksk: D,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
) -> Variance
where
    D: DispersionParameter,
{
    let n = lwe_mask_size.0 as f64;
    let base = (1 << base_log.0) as f64;

    let res = n * (level.0 as f64) * dispersion_ksk.get_variance() * (square(base) + 2.) / 12.;

    Variance::from_variance(res)
}
//TODO: THIS HAS TO BE RENAMED
/// Returns a variance of U when doing a modulus switching
/// # Example
/// ```rust
/// use concrete_commons::dispersion::Variance;
/// use concrete_commons::parameters::PolynomialSize;
/// use concrete_npe::{variance_rlwe_k_1_var_u_mod_switch, *};
/// use std::fmt::Binary;
/// use concrete_commons::key_kinds::BinaryKeyKind;
/// let rlwe_mask_size = PolynomialSize(1024);
/// ///
/// let var_out = variance_rlwe_k_1_var_u_mod_switch::<u64, BinaryKeyKind>(rlwe_mask_size);
/// ```
pub fn variance_rlwe_k_1_var_u_mod_switch<T, K>(poly_size: PolynomialSize) -> Variance
where
    T: UnsignedInteger,
    K: KeyDispersion,
{
    let q_square = f64::powi(2., (2 * T::BITS) as i32);

    Variance::from_variance(
        1. / q_square
            * ((q_square - 1.) / 12.
                * (1.
                    + (poly_size.0 as f64) * K::variance_key_coefficient::<T>().get_variance()
                    + (poly_size.0 as f64) * square(K::expectation_key_coefficient()))
                + (poly_size.0 as f64) / 4. * K::variance_key_coefficient::<T>().get_variance()),
    )
}

/// Return the variance when computing a relinarization of an RLWE resulting from
/// a tensor product.
/// # Example
/// ```rust
/// use concrete_commons::dispersion::Variance;
/// use concrete_commons::parameters::{
///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
/// };
/// use concrete_npe::{variance_keyswitch_lwe_to_glwe_constant_term, *};
/// use concrete_commons::key_kinds::BinaryKeyKind;
/// let poly_size = PolynomialSize(1024);
/// let mask_size = GlweDimension(2);
/// let level = DecompositionLevelCount(4);
/// let dispersion_rlk = Variance::from_variance(f64::powi(2., -40));
/// let base_log = DecompositionBaseLog(7);
/// let var_ks = variance_rlwe_relinearization::<u64, _, BinaryKeyKind>(
///     poly_size,
///     mask_size,
///     dispersion_rlk,
///     base_log,
///     level,
/// );
/// ```
pub fn variance_rlwe_relinearization<T, D, K>(
    poly_size: PolynomialSize,
    mask_size: GlweDimension,
    dispersion_rlk: D,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
) -> Variance
where
    T: UnsignedInteger,
    D: DispersionParameter,
    K: KeyDispersion,
{
    let basis: f64 = (1 << base_log.0) as f64;
    let big_n: f64 = poly_size.0 as f64;
    let k = mask_size.0 as f64;
    let q_square = f64::powi(2., (2 * T::BITS) as i32);

    // res 1
    let res_1: f64 = k
        * (level.0 as f64)
        * big_n
        * dispersion_rlk.get_variance()
        * (square(basis) + 2.)
        * (k + 1.)
        / 24.;

    // res 2
    let res_2: f64 = k * big_n / 2.
        * (K::variance_odd_coefficient_in_polynomial_key_squared::<T>(poly_size).get_variance()
            + K::variance_even_coefficient_in_polynomial_key_squared::<T>(poly_size)
                .get_variance()
            + 2. * K::square_expectation_mean_in_polynomial_key_times_key(poly_size)
            + (k - 1.)
                * (K::variance_coefficient_in_polynomial_key_times_key::<T>(poly_size)
                    .get_variance()
                    + K::square_expectation_mean_in_polynomial_key_times_key(poly_size)))
        * (q_square / (12. * f64::powi(basis, 2 * level.0 as i32)) - 1. / 12.)
        + k * big_n / 8.
            * (K::variance_odd_coefficient_in_polynomial_key_squared::<T>(poly_size)
                .get_variance()
                + K::variance_even_coefficient_in_polynomial_key_squared::<T>(poly_size)
                    .get_variance()
                + (k - 1.)
                    * K::variance_coefficient_in_polynomial_key_times_key::<T>(poly_size)
                        .get_variance());

    // return
    Variance::from_variance(res_1 + res_2)
}
/*

/// returns a variance when computing the cmux
pub fn cmux(
    poly_size: usize,
    rlwe_mask_size: usize,
    var_rlwe: f64,
    var_rgsw: f64,
    base_log: usize,
    level: usize,
    q: f64,
    key_kind: char,
) -> f64 {
    let res = external_product(
        poly_size,
        rlwe_mask_size,
        2. * var_rlwe,
        var_rgsw,
        base_log,
        level,
        q,
        key_kind,
    ) + var_rlwe;
    res
}
*/

/// Return the variance when computing an external product as in TFHE's PBS
/// # Example
/// ```rust
/// use concrete_commons::dispersion::Variance;
/// use concrete_commons::parameters::{
///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize,
/// };
/// use concrete_npe::{variance_keyswitch_lwe_to_glwe_constant_term, *};
/// use concrete_commons::key_kinds::BinaryKeyKind;
/// let poly_size = PolynomialSize(1024);
/// let mask_size = GlweDimension(2);
/// let level = DecompositionLevelCount(4);
/// let dispersion_rlwe = Variance::from_variance(f64::powi(2., -40));
/// let dispersion_rgsw = Variance::from_variance(f64::powi(2., -40));
/// let base_log = DecompositionBaseLog(7);
/// let var_ks = variance_external_product_binary_ggsw::<u64, _, _, BinaryKeyKind>(
///     poly_size,
///     mask_size,
///     dispersion_rlwe,
///     dispersion_rgsw,
///     base_log,
///     level,
/// );
/// ```
pub fn variance_external_product_binary_ggsw<T, D1, D2, K>(
    poly_size: PolynomialSize,
    rlwe_mask_size: GlweDimension,
    var_glwe: D1,
    var_ggsw: D2,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
) -> Variance
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
    K: KeyDispersion,
{
    let l = level.0 as f64;
    let k = rlwe_mask_size.0 as f64;
    let big_n = poly_size.0 as f64;
    let b = (1 << base_log.0) as f64;
    let b2l = f64::powf(b, 2. * l);

    let res_1 =
        l * (k + 1.) * big_n * var_ggsw.get_modular_variance::<T>() * (square(b) + 2.) / 12.;
    let res_2 = var_glwe.get_modular_variance::<T>() / 2.;
    let res_3 = (square(T::BITS) as f64 - b2l) / (24. * b2l)
        * (1.
            + k * big_n
                * (K::variance_key_coefficient::<T>().get_variance()
                    + square(K::expectation_key_coefficient())));
    let res_4 = k * big_n / 8. * K::variance_key_coefficient::<T>().get_variance();
    let res_5 = 1. / 16. * square(1. - k * big_n * K::expectation_key_coefficient());
    Variance::from_variance(res_1 + res_2 + res_3 + res_4 + res_5)
}

/// Return the variance when computing TFHE's PBS
/// # Example
/// ```rust
/// use concrete_commons::dispersion::Variance;
/// use concrete_commons::parameters::{
///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
/// };
/// use concrete_npe::{variance_keyswitch_lwe_to_glwe_constant_term, *};
/// use concrete_commons::key_kinds::BinaryKeyKind;
/// let poly_size = PolynomialSize(1024);
/// let mask_size = LweDimension(2);
/// let rlwe_mask_size = GlweDimension(2);
/// let level = DecompositionLevelCount(4);
/// let dispersion_rgsw = Variance::from_variance(f64::powi(2., -40));
/// let base_log = DecompositionBaseLog(7);
/// let var_ks = variance_tfhe_pbs::<u64, _, BinaryKeyKind>(
///     mask_size,
///     poly_size,
///     rlwe_mask_size,
///     dispersion_rgsw,
///     base_log,
///     level,
/// );
/// ```
pub fn variance_tfhe_pbs<T, D, K>(
    lwe_mask_size: LweDimension,
    poly_size: PolynomialSize,
    rlwe_mask_size: GlweDimension,
    var_rgsw: D,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
) -> Variance
where
    T: UnsignedInteger,
    D: DispersionParameter,
    K: KeyDispersion,
{
    let var_rlwe = Variance::from_modular_variance::<T>(0.);
    Variance::from_variance(
        lwe_mask_size.0 as f64
            * variance_external_product_binary_ggsw::<T, _, _, K>(
                poly_size,
                rlwe_mask_size,
                var_rlwe,
                var_rgsw,
                base_log,
                level,
            )
            .get_modular_variance::<T>(),
    )
}

/*
/// Return the variance of output of a bootstrap given a set of parameters.
/// To see how to use it, please refer to the test of the bootstrap.
/// Arguments
/// * `lwe_dimension` - size of the LWE mask
/// * `rlwe_dimension` - size of the RLWE mask
/// * `polynomial_size` - number of coefficients of the polynomial e.g. degree +
///   1
/// * `base_log` - decomposition base of the gadget matrix
/// * `l_gadget` - number of elements for the decomposition
/// * `dispersion_bsk` - dispersion of the bootstrapping key
/// # Output
/// * Returns the variance of the output RLWE
/// # Example
/// ```rust
/// use concrete_commons::dispersion::{DispersionParameter, Variance};
/// use concrete_commons::parameters::{
///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
/// };
/// use concrete_npe::bootstrap;
/// let rlwe_dimension = GlweDimension(3);
/// let lwe_dimension = LweDimension(630);
/// let polynomial_size = PolynomialSize(1024);
/// let base_log = DecompositionBaseLog(7);
/// let l_gadget = DecompositionLevelCount(4);
/// let var_bsk = Variance::from_variance(f64::powi(2., -38));
/// // Computing the noise
/// let var_bootstrap = bootstrap::<u64, _>(
///     lwe_dimension,
///     rlwe_dimension,
///     polynomial_size,
///     base_log,
///     l_gadget,
///     var_bsk,
/// );
/// ```
//TODO: WHAT IS THIS FORMULA ?
pub fn variance_bootstrap<T, D>(
    lwe_dimension: LweDimension,
    rlwe_dimension: GlweDimension,
    polynomial_size: PolynomialSize,
    base_log: DecompositionBaseLog,
    l_gadget: DecompositionLevelCount,
    var_bsk: D,
) -> Variance
where
    T: UnsignedInteger,
    D: DispersionParameter,
{
    let b_g = 1 << base_log.0;
    let q_square = f64::powi(2., (2 * T::BITS) as i32);
    let var_res_1: f64 = (lwe_dimension.0
        * (rlwe_dimension.0 + 1)
        * l_gadget.0
        * polynomial_size.0
        * (b_g * b_g + 2)) as f64
        / 12.
        * var_bsk.get_modular_variance::<T>();

    let var_res_2: f64 = lwe_dimension.0 as f64
        * ((rlwe_dimension.0 * polynomial_size.0 + 2) as f64
            / (24. * f64::powi(b_g as f64, 2 * l_gadget.0 as i32)) as f64
            + lwe_dimension.0 as f64 * (rlwe_dimension.0 * polynomial_size.0 / 48 - 1 / 12) as f64
                / q_square);

    Variance::from_variance(var_res_1 + var_res_2)
}
*/

/*
/// Return the variance of the keyswitch on a LWE ciphertext given a set of
/// parameters. To see how to use it, please refer to the test of the
/// keyswitch # Warning
/// * This function compute the noise of the keyswitch without functional
///   evaluation
/// # Arguments
/// `dimension_before` - size of the input LWE mask
/// `l_ks` - number of level max for the torus decomposition
/// `base_log` - number of bits for the base B (B=2^base_log)
/// `dispersion_ks` - dispersion of the keyswitching key
/// `dispersion_input` - dispersion of the input LWE
/// # Example
/// ```rust
/// use concrete_commons::dispersion::Variance;
/// use concrete_commons::parameters::{
///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
/// };
/// use concrete_npe::key_switch;
/// let dimension_before = LweDimension(630);
/// let l_ks = DecompositionLevelCount(4);
/// let base_log = DecompositionBaseLog(7);
/// let dispersion_ks = Variance::from_variance(f64::powi(2., -38));
/// let dispersion_input = Variance::from_variance(f64::powi(2., -40));
/// // Computing the noise
/// let var_ks = key_switch::<u64, _, _>(
///     dimension_before,
///     l_ks,
///     base_log,
///     dispersion_ks,
///     dispersion_input,
/// );
/// ```
pub fn variance_key_switch_lwe_to_lwe<T, D1, D2>(
    dimension_before: LweDimension,
    l_ks: DecompositionLevelCount,
    base_log: DecompositionBaseLog,
    dispersion_ks: D1,
    dispersion_input: D2,
) -> Variance
    where
        T: UnsignedInteger,
        D1: DispersionParameter,
        D2: DispersionParameter,
{
    let q_square = f64::powi(2., (2 * T::BITS * 8) as i32);
    let var_res_1: f64 = dimension_before.0 as f64
        * (1. / 24. * f64::powi(2.0, -2 * (base_log.0 * l_ks.0) as i32) + 1. / (48. * q_square));
    let var_res_2: f64 = dimension_before.0 as f64
        * l_ks.0 as f64
        * (f64::powi(2., 2 * base_log.0 as i32) / 12. + 1. / 6.)
        * dispersion_ks.get_modular_variance::<T>();

    let var_res: f64 = dispersion_input.get_modular_variance::<T>() + var_res_1 + var_res_2;
    Variance::from_variance(var_res)
}
*/

/*
/// returns a variance when computing a relinarization of an RLWE resulting from
/// a tensor product: with k=2, and the secret key is (-S^2(X),S(X))
/// input -> var_1 = 2^22 <=> std_dev lwe estimator 2^-53
pub fn variance_rlwe_k_2_relinearization<T, D>(
    poly_size: PolynomialSize,
    dispersion_rlk: D,
    base_log: DecompositionBaseLog,
    level: DecompositionLevelCount,
    key_type: KeyType,
) -> Variance
    where
        T: UnsignedInteger,
        D: DispersionParameter,
{
    let basis: f64 = (1 << base_log.0) as f64;
    let big_n: f64 = poly_size.0 as f64;
    let q_square = f64::powi(2., (2 * T::BITS) as i32);

    // res 1
    let res_1: f64 =
        (level.0 as f64) * big_n * dispersion_rlk.get_variance() * (square(basis) + 2.) / 12.;

    // res 2
    let res_2: f64 = big_n / 2.
        * (variance_odd_coefficient_in_polynomial_key_squared(poly_size, key_type)
        + variance_even_coefficient_in_polynomial_key_squared(poly_size, key_type)
        + 2. * square_expectation_mean_in_polynomial_key_times_key(poly_size, key_type))
        * (q_square / (12. * f64::powi(basis, 2 * level.0 as i32)) - 1. / 12.)
        + big_n / 8.
        * (variance_odd_coefficient_in_polynomial_key_squared(poly_size, key_type)
        + variance_even_coefficient_in_polynomial_key_squared(poly_size, key_type));

    // return
    Variance::from_variance(res_1 + res_2)
}
*/