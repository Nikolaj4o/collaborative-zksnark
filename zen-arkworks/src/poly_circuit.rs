use ark_ec::{bls12::{Bls12, G1Prepared, G2Prepared, Bls12Parameters}, bw6::BW6};
use ark_ff::PrimeField;
use ark_ec::PairingEngine;
use ark_r1cs_std::{groups::bls12::{G1PreparedVar, G2PreparedVar}, alloc::AllocVar, fields::{fp::FpVar, FieldVar}, pairing::{bls12::PairingVar}, eq::EqGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[derive(Clone)]
pub struct PolyCircuit {
    pub vector_beta_ip: Vec<FpVar<BwSF>>,
    pub beta_qr: Vec<(FpVar<BwSF>, FpVar<BwSF>)>,
    pub cum_sum_qr: Vec<(FpVar<BwSF>, FpVar<BwSF>)>,
    pub rho: FpVar<BwSF>,
    pub bls_mod: FpVar<BwSF>,
}

type BwSF = <BW6<ark_bw6_761::Parameters> as PairingEngine>::Fr;
impl ConstraintSynthesizer<BwSF> for PolyCircuit{
    fn generate_constraints(self, cs: ConstraintSystemRef<BwSF>) -> Result<(), SynthesisError> {
        let mut _cir_number = cs.num_constraints();
        let modulus = self.bls_mod;
        let lhs_beta: Vec<FpVar<BwSF>> = self.beta_qr.iter()
            .map(|(a, b)| a * modulus.clone() + b).collect();
        println!(
            "Number of constraints for PolyCircuit Circuit 1 {}, Accumulated constraints {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();
        for idx in 0..lhs_beta.len() {
            lhs_beta[idx].enforce_equal(&self.vector_beta_ip[idx]).unwrap();
            println!(
                "Number of constraints for PolyCircuit Circuit 1 {}, Accumulated constraints {}",
                cs.num_constraints() - _cir_number,
                cs.num_constraints()
            );
            _cir_number = cs.num_constraints();
            self.beta_qr[idx].1.enforce_cmp_unchecked(&modulus, std::cmp::Ordering::Less, false).unwrap();
            println!(
                "Number of constraints for PolyCircuit Circuit 1 {}, Accumulated constraints {}",
                cs.num_constraints() - _cir_number,
                cs.num_constraints()
            );
            _cir_number = cs.num_constraints();
        }
        println!(
            "Number of constraints for PolyCircuit Circuit 2 {}, Accumulated constraints {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();
        let mut curr = FpVar::<BwSF>::zero();
        for idx in 0..self.cum_sum_qr.len() {
            curr += self.vector_beta_ip[idx].clone();
            let (q, r) = self.cum_sum_qr[idx].clone();
            let lhs = q * modulus.clone() + r;
            lhs.enforce_equal(&curr).unwrap();
            self.cum_sum_qr[idx].1.enforce_cmp(&modulus, std::cmp::Ordering::Less, false).unwrap();
        }
        println!(
            "Number of constraints for PolyCircuit Circuit 3 {}, Accumulated constraints {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();
        self.rho.enforce_equal(&self.cum_sum_qr.last().unwrap().1).unwrap();
        println!(
            "Number of constraints for PolyCircuit Circuit 4 {}, Accumulated constraints {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        Ok(())
    }
}

