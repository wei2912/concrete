//! Hardware specific implementation of AES encryptors
//!
//! The availability of these encryptors depends on the CPU architecture
//! and its supported features

#[cfg(target_arch = "x86_64")]
pub(crate) mod x86_64;

/// Re-export of the hardware encryptor for the current arch
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::Encryptor;
