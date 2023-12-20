use ark_ec::{bls12::{Bls12, G1Prepared, G2Prepared, Bls12Parameters}, bw6::BW6};
use ark_ff::PrimeField;
use ark_ec::PairingEngine;
use ark_r1cs_std::{groups::bls12::{G1PreparedVar, G2PreparedVar}, alloc::AllocVar, fields::fp::FpVar, pairing::{bls12::PairingVar}, eq::EqGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

#[derive(Clone)]
pub struct KZGCommitCircuit {
    pub g1_l: G1PreparedVar<ark_bls12_377::Parameters>,
    pub g2_l: G2PreparedVar<ark_bls12_377::Parameters>,
    pub g1_r: G1PreparedVar<ark_bls12_377::Parameters>,
    pub g2_r: G2PreparedVar<ark_bls12_377::Parameters>,
}
type BwSF = <BW6<ark_bw6_761::Parameters> as PairingEngine>::Fr;
impl ConstraintSynthesizer<BwSF> for KZGCommitCircuit{
    fn generate_constraints(self, cs: ConstraintSystemRef<BwSF>) -> Result<(), SynthesisError> {
        let _cir_number = cs.num_constraints();
        let pairing_l = <PairingVar<ark_bls12_377::Parameters> as ark_r1cs_std::pairing::PairingVar<Bls12<ark_bls12_377::Parameters>>>::pairing(self.g1_l, self.g2_l.clone()).unwrap();
        let pairing_r = <PairingVar<ark_bls12_377::Parameters> as ark_r1cs_std::pairing::PairingVar<Bls12<ark_bls12_377::Parameters>>>::pairing(self.g1_r, self.g2_r.clone()).unwrap();
        pairing_l.enforce_equal(&pairing_r).unwrap();
        println!(
            "Number of constraints for KZGCommitCircuit Circuit {}, Accumulated constraints {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        Ok(())
    }
}

