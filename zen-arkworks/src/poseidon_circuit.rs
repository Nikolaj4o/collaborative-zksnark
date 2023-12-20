use ark_bls12_381::Bls12_381;
use ark_ff::UniformRand;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::SynthesisError;
use ark_sponge::CryptographicSponge;
use ark_sponge::FieldBasedCryptographicSponge;

use ark_sponge::constraints::*;

//use ark_relations::r1cs::ConstraintSystem;
use ark_std::test_rng;
//use ark_test_curves::bls12_381::Fq;

//use ark_sponge::*;
//use ark_sponge::poseidon::*;
use ark_sponge::poseidon::{PoseidonSponge, PoseidonParameters};
use ark_sponge::poseidon::constraints::*;

use ark_ff::PrimeField;
use ark_crypto_primitives::SNARK;

use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::ConstraintSystem;
use ark_relations::*;
use ark_groth16::*;
use crate::*;
use ark_std::{rand::SeedableRng,vec::Vec};


//pub type CRHOutput = [u8; 32];

#[derive(Clone)]
pub struct PosedionCircuit<F: PrimeField> {
	pub param: PoseidonParameters<F>,
	pub input: Vec<FpVar<F>>,
	pub output: Vec<F>
}


impl <F: PrimeField>ConstraintSynthesizer<F> for PosedionCircuit<F>{
	/// Input a circuit, build the constraint system and add it to `cs`
	fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError>{
        println!("input len: {} ", self.input.len());
        let _cir_number = cs.num_constraints();
        let pos_param_var =  PoseidonSpongeVar::<F>::new(cs.clone(),&self.param);      

        let mut constraint_sponge = pos_param_var;
        constraint_sponge.absorb(&self.input).unwrap();

        let squeeze = constraint_sponge.squeeze_field_elements(1).unwrap();
        let outputvar: Vec<_> = self.output.iter()
            .map(|v| FpVar::new_input(ns!(cs, "absorb1"), || Ok(*v)).unwrap())
            .collect();
        squeeze.enforce_equal(&outputvar).unwrap();
        println!(
            "Number of constraints for PoseidonCircuit Circuit {}, Accumulated constraints {} avg per input {}, ",
            cs.num_constraints() - _cir_number,
            cs.num_constraints(),
            (cs.num_constraints() - _cir_number) / self.input.len()
        );
		Ok(())
	}
}

