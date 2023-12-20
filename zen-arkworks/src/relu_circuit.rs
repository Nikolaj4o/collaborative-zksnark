use crate::*;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::boolean::Boolean;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{println, vec, vec::Vec, test_rng};
use ark_ed_on_bls12_381::{constraints::FqVar, Fq, Fr};
use ark_ff::*;
use mpc_algebra::Reveal;


#[derive(Debug, Clone)]
pub(crate) struct ReLUCircuitOp3<F: PrimeField> {
    pub(crate) y_in: Vec<FpVar<F>>,
    pub(crate) y_out: Vec<FpVar<F>>,
    pub(crate) y_zeropoint: F,
    pub(crate) cmp_res: Vec<bool>,
}

impl <F: PrimeField>ConstraintSynthesizer<F> for ReLUCircuitOp3<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        //println!("ReLU zero point {}", self.y_zeropoint);
        let zero_var = FpVar::<F>::Constant(self.y_zeropoint);
        //zero point is constant wire in the circuit

        for i in 0..self.y_in.len() {
            let cmp =
                Boolean::new_witness(ark_relations::ns!(cs, "relu"), || {
                    Ok(self.cmp_res[i])
                })
                .unwrap();
            self.y_out[i]
                .enforce_equal(&cmp.select(&self.y_in[i], &zero_var).unwrap())
                .unwrap();

        }
        Ok(())
    }
}

pub(crate) struct ReLUCircuitOp3MPC<MFr: PrimeField + Reveal> {
    pub(crate) y_in: Vec<FpVar<MFr>>,
    pub(crate) y_out: Vec<FpVar<MFr>>,
    pub(crate) y_zeropoint: u8,
    pub(crate) cmp_res: Vec<bool>,
}

impl <F: PrimeField, MFr: PrimeField + Reveal<Base = F>>ConstraintSynthesizer<MFr> for ReLUCircuitOp3MPC<MFr>{
    fn generate_constraints(self, cs: ConstraintSystemRef<MFr>) -> Result<(), SynthesisError> {
        //println!("ReLU zero point {}", self.y_zeropoint);
        let zero: F = self.y_zeropoint.into();
        //zero point is constant wire in the circuit
        let rng = &mut test_rng();
        let zero_shares = MFr::king_share(zero, rng);
        let zero_var = FpVar::<MFr>::Constant(zero_shares);

        for i in 0..self.y_in.len() {
            let cmp =
                Boolean::new_witness(ark_relations::ns!(cs, "relu"), || {
                    Ok(self.cmp_res[i])
                })
                .unwrap();
            self.y_out[i]
                .enforce_equal(&cmp.select(&self.y_in[i], &zero_var).unwrap())
                .unwrap();

        }
        Ok(())
    }
}
