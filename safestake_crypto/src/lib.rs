pub mod blst_utils;
pub mod define;
pub mod elgamal;
pub mod generic_threshold;
pub mod impls;
pub mod math;
pub mod rand_utils;
pub mod secp;
pub mod secret;

macro_rules! define_mod {
    ($name: ident, $mod: path) => {
        pub mod $name {
            use $mod as bls_variant;

            use crate::generic_threshold::*;

            pub type ThresholdSignature =
                GenericThresholdSignature<bls_variant::ThresholdSignature>;
        }
    };
}

define_mod!(blst_threshold_implementations, crate::impls::blst::types);
pub use blst_threshold_implementations::*;
