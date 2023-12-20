use crate::*;
use ark_r1cs_std::{groups::curves::twisted_edwards::AffineVar, fields::fp::FpVar};

use crate::constraints::FqVar;

/// A variable that is the R1CS equivalent of `crate::EdwardsAffine`.
pub type EdwardsVar = AffineVar<EdwardsParameters, FqVar>;
pub type EdwardsFVar<F> = AffineVar<EdwardsParameters, FpVar<F>>;

#[test]
fn test() {
    ark_curve_constraint_tests::curves::te_test::<_, EdwardsVar>().unwrap();
}
