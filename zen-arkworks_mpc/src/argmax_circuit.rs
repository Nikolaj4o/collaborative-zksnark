use crate::*;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::boolean::Boolean;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{println, vec, vec::Vec, test_rng};
use ark_ed_on_bls12_381::{constraints::FqVar, Fq, Fr};
use ark_ff::*;
use core::cmp::Ordering;
use ark_r1cs_std::fields::fp::FpVar;
use mpc_algebra::Reveal;


//used in mnist and cifar10 classification problem
#[derive(Debug, Clone)]
pub struct ArgmaxCircuitU8<F: PrimeField> {
    pub input: Vec<FpVar<F>>,
    pub argmax_res: FpVar<F>,
}

impl <F: PrimeField> ConstraintSynthesizer<F> for ArgmaxCircuitU8<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // This is NOT using the argmax (index) but the max input value (input[argmax])
        let _cir_number = cs.num_constraints();
        // let argmax_var =
        //     FpVar::<F>::new_witness(ark_relations::ns!(cs, "argmax var"), || Ok(self.argmax_res)).unwrap();
        // let classification_res: F = (self.argmax_res as u8).into();
        // let classification_res_var = FpVar::<F>::new_input(ark_relations::ns!(cs, "class var"), || Ok(argmax_fq)).unwrap();
        
        for i in 0..self.input.len() {
            // let tmp = FpVar::<F>::new_witness(ark_relations::ns!(cs, "argmax tmp var"), || Ok(self.input[i]))
            //     .unwrap();
            //the argmax result should be larger or equal than all the input values.
            self.argmax_res
                .enforce_cmp(&self.input[i], Ordering::Greater, true)
                .unwrap();
        }

        println!(
            "Number of constraints for ArgmaxCircuitU8 Circuit {}, Accumulated constraints {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ArgmaxCircuitU8MPC {
    pub input: Vec<u8>,
    pub argmax_res: usize,
}

impl <F: PrimeField, MFr: PrimeField + Reveal<Base = F>> ConstraintSynthesizer<MFr> for ArgmaxCircuitU8MPC{
    fn generate_constraints(self, cs: ConstraintSystemRef<MFr>) -> Result<(), SynthesisError> {
        let _cir_number = cs.num_constraints();
        let argmax_fq: F = self.input[self.argmax_res].into();
        let rng = &mut test_rng();
        let argmax_share = MFr::king_share(argmax_fq, rng);
        let argmax_var =
            FpVar::<MFr>::new_witness(ark_relations::ns!(cs, "argmax var"), || Ok(argmax_share)).unwrap();

        for i in 0..self.input.len() {
            let tmp_fq: F = self.input[i].into();
            let rng = &mut test_rng();
            let tmp_share = MFr::king_share(tmp_fq, rng);
            let tmp = FpVar::<MFr>::new_witness(ark_relations::ns!(cs, "argmax tmp var"), || Ok(tmp_share))
                .unwrap();
            //the argmax result should be larger or equal than all the input values.
            argmax_var
                .enforce_cmp(&tmp, Ordering::Greater, true)
                .unwrap();
        }

        println!(
            "Number of constraints for ArgmaxCircuitU8 Circuit {}, Accumulated constraints {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        Ok(())
    }
}
