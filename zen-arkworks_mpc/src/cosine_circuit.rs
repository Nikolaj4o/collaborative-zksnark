use crate::*;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::boolean::*;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{println, vec, vec::Vec};
use ark_ed_on_bls12_381::{constraints::FqVar, Fq};
use ark_ff::*;
use core::cmp::Ordering;

//used in ORL face recognition problem
#[derive(Debug, Clone)]
pub struct CosineSimilarityCircuitU8<F: PrimeField> {
    pub vec1: Vec<F>,
    pub vec2: Vec<F>,
    pub threshold: F,
    pub result: bool,
}

impl <F: PrimeField> ConstraintSynthesizer<F> for CosineSimilarityCircuitU8<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let _cir_number = cs.num_constraints();

        let res = Boolean::<F>::constant(self.result);

        let norm1 = scala_cs_helper_f(cs.clone(), &self.vec1.clone(), &self.vec1.clone());
        let norm2 = scala_cs_helper_f(cs.clone(), &self.vec2.clone(), &self.vec2.clone());
        let numerator = scala_cs_helper_f(cs.clone(), &self.vec1.clone(), &self.vec2.clone());
        let ten_thousand: F = (10000u64).into();
        let ten_thousand_const = FpVar::<F>::Constant(ten_thousand);

        let threshold_fq: F = self.threshold.into();
        let threshold_const = FpVar::<F>::Constant(threshold_fq);
        let left = ten_thousand_const * numerator.clone() * numerator.clone();
        let right = threshold_const.clone() * threshold_const.clone() * norm2 * norm1;

        if res.value().unwrap_or_default() == true {
            left.enforce_cmp(&right, Ordering::Greater, false).unwrap();
        } else {
            left.enforce_cmp(&right, Ordering::Less, true).unwrap();
        }
        println!(
            "Number of constraints for CosineSimilarity Circuit {}, Accumulated constraints {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        Ok(())
    }
}

fn mul_cs_helper_u8(cs: ConstraintSystemRef<Fq>, a: u8, c: u8) -> FqVar {
    let aa: Fq = a.into();
    let cc: Fq = c.into();
    let a_var = FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "a gadget"), || Ok(aa)).unwrap();
    let c_var = FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "c gadget"), || Ok(cc)).unwrap();
    a_var * c_var
}

fn mul_cs_helper_f<F: PrimeField>(cs: ConstraintSystemRef<F>, a: F, c: F) -> FpVar<F> {
    let aa: F = a.into();
    let cc: F = c.into();
    let a_var = FpVar::<F>::new_witness(ark_relations::ns!(cs, "a gadget"), || Ok(aa)).unwrap();
    let c_var = FpVar::<F>::new_witness(ark_relations::ns!(cs, "c gadget"), || Ok(cc)).unwrap();
    a_var * c_var
}


fn scala_cs_helper_u8(cs: ConstraintSystemRef<Fq>, vec1: &[u8], vec2: &[u8]) -> FqVar {
    let _no_cs = cs.num_constraints();
    if vec1.len() != vec2.len() {
        panic!("scala mul: length not equal");
    }
    let mut res =
        FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "q1*q2 gadget"), || Ok(Fq::zero())).unwrap();

    for i in 0..vec1.len() {
        res += mul_cs_helper_u8(cs.clone(), vec1[i], vec2[i]);
    }

    res
}

fn scala_cs_helper_f<F: PrimeField>(cs: ConstraintSystemRef<F>, vec1: &[F], vec2: &[F]) -> FpVar<F> {
    let _no_cs = cs.num_constraints();
    if vec1.len() != vec2.len() {
        panic!("scala mul: length not equal");
    }
    let mut res =
        FpVar::<F>::new_witness(ark_relations::ns!(cs, "q1*q2 gadget"), || Ok(F::zero())).unwrap();

    for i in 0..vec1.len() {
        res += mul_cs_helper_f(cs.clone(), vec1[i], vec2[i]);
    }

    res
}