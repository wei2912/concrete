//! A module containing generic testing functions.
//!
//! Every submodule here is expected to contain a generic `test` function which can be instantiated
//! with different engine types to verify the correctness of an operation.

pub mod lwe_ciphertext_cleartext_discarding_multiplication;
pub mod lwe_ciphertext_discarding_keyswitch;
pub mod lwe_ciphertext_encryption;
