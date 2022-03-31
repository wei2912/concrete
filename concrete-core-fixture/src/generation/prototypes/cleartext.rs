use crate::generation::{IntegerPrecision, Precision32, Precision64};
use concrete_core::prelude::{Cleartext32, Cleartext64, FloatCleartext32, FloatCleartext64};

/// A trait implemented by cleartext prototypes.
pub trait CleartextPrototype {
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 32 bit cleartext entity.
pub struct ProtoCleartext32(pub(crate) Cleartext32);
impl CleartextPrototype for ProtoCleartext32 {
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit cleartext entity.
pub struct ProtoCleartext64(pub(crate) Cleartext64);
impl CleartextPrototype for ProtoCleartext64 {
    type Precision = Precision64;
}

pub trait FloatCleartextPrototype {
    type Precision: IntegerPrecision;
}

/// A type representing the prototype of a 64 bit float cleartext entity
/// used together with 32-bits integer modulus.
pub struct ProtoFloatCleartext32(pub(crate) FloatCleartext32);
impl FloatCleartextPrototype for ProtoFloatCleartext32 {
    type Precision = Precision32;
}

/// A type representing the prototype of a 64 bit float cleartext entity
/// used together with 64-bits integer modulus.
pub struct ProtoFloatCleartext64(pub(crate) FloatCleartext64);
impl FloatCleartextPrototype for ProtoFloatCleartext64 {
    type Precision = Precision64;
}
