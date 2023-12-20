use crate::argmax_circuit::*;
use crate::fc_circuit::*;
use crate::kzgcom_circuit::*;
use crate::poly_circuit::PolyCircuit;
use crate::poseidon_circuit::PosedionCircuit;
use crate::poseidon_circuit::PosedionCircuitU8;
use crate::psponge::SPNGCircuit;
use crate::psponge::SPNGOutput;
use crate::psponge::SPNGParam;
use crate::relu_circuit::*;
use crate::vanilla::*;
use crate::*;
use ark_ec::PairingEngine;
use ark_ec::ProjectiveCurve;
use ark_ec::bls12::Bls12;
use ark_ec::bls12::G1Prepared;
use ark_ec::bls12::G2Prepared;
use ark_ec::bw6::BW6;
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::bls12::G1PreparedVar;
use ark_r1cs_std::groups::bls12::G2PreparedVar;
use ark_r1cs_std::poly::polynomial::univariate::dense::DensePolynomialVar;
use ark_sponge::CryptographicSponge;
use ark_sponge::constraints::CryptographicSpongeVar;
use ark_sponge::poseidon::PoseidonSponge;
use ark_sponge::poseidon::constraints::PoseidonSpongeVar;
use mpc_algebra::AffProjShare;
use mpc_algebra::com;
use std::cmp::*;
use ark_ff::*;
use ark_std::test_rng;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_ed_on_bls12_381::{constraints::FqVar, Fq};
use mpc_algebra::{channel, MpcPairingEngine, PairingShare, Reveal};



pub fn convert_2d_vector_into_1d<T: Clone>(vec: Vec<Vec<T>>) -> Vec<T> {
    let mut res = Vec::new();
    for i in 0..vec.len() {
        res.extend(vec[i].clone());
    }
    res
}

pub fn convert_2d_vector_into_fq(vec: Vec<Vec<u8>>) -> Vec<Fq> {
    let mut res = vec![Fq::zero(); vec[0].len() * vec.len()];
    for i in 0..vec.len() {
        for j in 0..vec[0].len() {
            let tmp: Fq = vec[i][j].into();
            res[i * vec[0].len() + j] = tmp;
        }
    }
    res
}

fn generate_fqvar<F: PrimeField>(cs: ConstraintSystemRef<F>, input: Vec<u8>) -> Vec<FpVar<F>> {
    let mut res: Vec<FpVar<F>> = Vec::new();
    for i in 0..input.len() {
        let fq: F = input[i].into();
        let tmp = FpVar::<F>::new_witness(ark_relations::ns!(cs, "tmp"), || Ok(fq)).unwrap();
        res.push(tmp);
    }
    res
}

fn generate_fqvar_share<F: PrimeField, MFr: PrimeField + Reveal<Base = F>>(cs: ConstraintSystemRef<MFr>, input: Vec<u8>) -> Vec<FpVar<MFr>> {
    let mut res: Vec<FpVar<MFr>> = Vec::new();
    for i in 0..input.len() {
        let fq: F = input[i].into();
        let rng = &mut test_rng();
        let fq_share = MFr::king_share(fq, rng);
        let tmp = FpVar::<MFr>::new_witness(ark_relations::ns!(cs, "tmp"), || Ok(fq_share)).unwrap();
        res.push(tmp);
    }
    println!("FQVAR IPT LEN: {}", res.len());
    res
}

fn generate_fqvar_ipt<F: PrimeField>(cs: ConstraintSystemRef<F>, input: Vec<u8>) -> Vec<FpVar<F>> {
    let mut res: Vec<FpVar<F>> = Vec::new();
    for i in 0..input.len() {
        let fq: F = input[i].into();
        let tmp = FpVar::<F>::new_input(ark_relations::ns!(cs, "tmp"), || Ok(fq)).unwrap();
        res.push(tmp);
    }
    println!("FQVAR IPT LEN: {}", res.len());
    res
}

fn generate_fqvar_ipt_share<F: PrimeField, MFr: PrimeField + Reveal<Base = F>>(cs: ConstraintSystemRef<MFr>, input: Vec<u8>) -> Vec<FpVar<MFr>> {
    let mut res: Vec<FpVar<MFr>> = Vec::new();
    let fq_vec: Vec<F> = input.iter().map(|f| (*f).into()).collect();
    let rng = &mut test_rng();
    println!("LENGTH:{}", fq_vec.len());
    let fq_share = MFr::king_share_batch(fq_vec, rng);

    for i in 0..input.len() {
        let tmp = FpVar::<MFr>::new_input(ark_relations::ns!(cs, "tmp"), || Ok(fq_share[i])).unwrap();
        res.push(tmp);
    }
    println!("FQVAR IPT LEN: {}", res.len());
    res
}

fn generate_fqvar_witness2D<F: PrimeField>(cs: ConstraintSystemRef<F>, input: Vec<Vec<u8>>) -> Vec<Vec<FpVar<F>>> {
    let zero_var = FpVar::<F>::Constant(F::zero());
    let mut res: Vec<Vec<FpVar<F>>> = vec![vec![zero_var; input[0].len()]; input.len()];
    for i in 0..input.len() {
        for j in 0..input[i].len() {
            let fq: F = input[i][j].into();
            let tmp = FpVar::<F>::new_witness(ark_relations::ns!(cs, "tmp"), || Ok(fq)).unwrap();
            res[i][j] = tmp;
        }
    }
    res
}

fn generate_fqvar_witness2D_share<F: PrimeField, MFr: PrimeField + Reveal<Base = F>>(cs: ConstraintSystemRef<MFr>, input: Vec<Vec<u8>>) -> Vec<Vec<FpVar<MFr>>> {

    let zero_var = FpVar::<MFr>::Constant(MFr::zero());
    let mut res: Vec<Vec<FpVar<MFr>>> = vec![vec![zero_var; input[0].len()]; input.len()];
    for i in 0..input.len() {
        for j in 0..input[i].len() {
            let fq: F = input[i][j].into();
            let rng = &mut test_rng();
            let fq_share = MFr::king_share(fq, rng);        
            let tmp = FpVar::<MFr>::new_witness(ark_relations::ns!(cs, "tmp"), || Ok(fq_share)).unwrap();
            res[i][j] = tmp;
        }
    }
    res
}
fn generate_fvar_ipt<F: PrimeField>(cs: ConstraintSystemRef<F>, input: Vec<F>) -> Vec<FpVar<F>> {
    let res = input.iter().map(|x| FpVar::<F>::new_input(ark_relations::ns!(cs, "tmp"), || Ok(*x)).unwrap()).collect(); 
    res
}
fn generate_fvar<F: PrimeField>(cs: ConstraintSystemRef<F>, input: Vec<F>) -> Vec<FpVar<F>> {
    let res = input.iter().map(|x| FpVar::<F>::new_witness(ark_relations::ns!(cs, "tmp"), || Ok(*x)).unwrap()).collect(); 
    res
}

fn generate_fvar2d<F: PrimeField>(cs: ConstraintSystemRef<F>, input: Vec<Vec<F>>) -> Vec<Vec<FpVar<F>>> {
    let res = input.iter().map(|x| generate_fvar(cs.clone(), (*x).clone())).collect();
    res
}
#[derive(Clone)]
pub struct FullCircuitOpLv3PoseidonClassificationU8<F: PrimeField> {
    pub x: Vec<F>,
    pub l1: Vec<Vec<F>>,
    pub l2: Vec<Vec<F>>,
    pub y: Vec<F>,
    pub z: Vec<F>,
    pub x_u8: Vec<u8>,
    pub l1_u8: Vec<Vec<u8>>,
    pub l2_u8: Vec<Vec<u8>>,
    pub z_u8: Vec<u8>,
    pub argmax_res: F,
    pub relu_output1: Vec<F>,
    pub remainder1: Vec<F>,
    pub remainder2: Vec<F>,
    pub div1: Vec<F>,
    pub div2: Vec<F>,
    pub cmp_res: Vec<bool>,
    pub y_0_converted: Vec<F>,
    pub z_0_converted: Vec<F>,
    pub x_0: F,
    pub y_0: F,
    pub z_0: F,
    pub l1_mat_0: F,
    pub l2_mat_0: F,
    pub multiplier_l1: Vec<F>,
    pub multiplier_l2: Vec<F>,
    pub two_power_8: F,
    pub m_exp: F,
    pub zero: F,

    pub params: <PoseidonSponge<F> as CryptographicSponge>::Parameters,
    pub x_squeeze: Vec<F>,
    pub l1_squeeze: Vec<F>,
    pub l2_squeeze: Vec<F>,
    pub z_squeeze: Vec<F>,
}

impl <F: PrimeField>ConstraintSynthesizer<F> for FullCircuitOpLv3PoseidonClassificationU8<F>{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_fvar = generate_fvar_ipt(cs.clone(), self.x.clone());
        let l1_fvar = generate_fvar2d(cs.clone(), self.l1.clone());
        let l2_fvar = generate_fvar2d(cs.clone(), self.l2.clone());
        let y_fvar = generate_fvar(cs.clone(), self.y.clone());
        let l1_1d_fvar = convert_2d_vector_into_1d(l1_fvar.clone());
        let l2_1d_fvar = convert_2d_vector_into_1d(l2_fvar.clone());

        //let l1_1d_fvar = generate_fvar(cs.clone(), self.l1_1d_f.clone());
        //let l2_1d_fvar = generate_fvar(cs.clone(), self.l2_1d_f.clone());
        let z_fvar = generate_fvar_ipt(cs.clone(), self.z.clone());
        let relu_output1_fvar = generate_fvar(cs.clone(), self.relu_output1.clone());
        let argmax_fvar = FpVar::<F>::new_witness(ark_relations::ns!(cs, "argmax var"), || Ok(self.argmax_res)).unwrap();
        //let param_var = PoseidonSpongeVar::<F>::new(cs.clone(),&self.params);
        
        let full_circuit = FullCircuitOpLv3 {
            x: x_fvar.clone(),
            l1: l1_fvar,
            l2: l2_fvar,
            z: z_fvar.clone(),
            y: y_fvar,
            relu_output1: relu_output1_fvar,
            remainder1: self.remainder1,
            remainder2: self.remainder2,
            div1: self.div1,
            div2: self.div2,
            cmp_res: self.cmp_res,
            y_0_converted: self.y_0_converted,
            z_0_converted: self.z_0_converted,
            x_0: self.x_0,
            y_0: self.y_0,
            z_0: self.z_0,
            l1_mat_0: self.l1_mat_0,
            l2_mat_0: self.l2_mat_0,
            multiplier_l1: self.multiplier_l1,
            multiplier_l2: self.multiplier_l2,
            two_power_8: self.two_power_8,
            m_exp: self.m_exp,
            zero: self.zero,
        };

        let argmax_circuit = ArgmaxCircuitU8 {
            input: z_fvar.clone(),
            argmax_res: argmax_fvar,
        };

        let x_com_circuit = PosedionCircuit {
            param: self.params.clone(),
            input: x_fvar.clone(),
            output: self.x_squeeze.clone()
        };

        let l1_com_circuit = PosedionCircuit {
            param: self.params.clone(),
            input: l1_1d_fvar,
            output: self.l1_squeeze.clone()
        };

        let l2_com_circuit = PosedionCircuit {
            param: self.params.clone(),
            input: l2_1d_fvar,
            output: self.l2_squeeze.clone()
        };

        let z_com_circuit = PosedionCircuit {
            param: self.params.clone(),
            input: z_fvar,
            output: self.z_squeeze.clone()
        };

        full_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        argmax_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        x_com_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        l1_com_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        l2_com_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        z_com_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        Ok(())
    }
}

#[derive(Clone)]
pub struct FullCircuitOpLv3PoseidonClassification<F: PrimeField> {
    pub x: Vec<F>,
    pub l1: Vec<Vec<F>>,
    pub l2: Vec<Vec<F>>,
    pub y: Vec<F>,
    pub z: Vec<F>,
    pub argmax_res: F,
    pub relu_output1: Vec<F>,
    pub remainder1: Vec<F>,
    pub remainder2: Vec<F>,
    pub div1: Vec<F>,
    pub div2: Vec<F>,
    pub cmp_res: Vec<bool>,
    pub y_0_converted: Vec<F>,
    pub z_0_converted: Vec<F>,
    pub x_0: F,
    pub y_0: F,
    pub z_0: F,
    pub l1_mat_0: F,
    pub l2_mat_0: F,
    pub multiplier_l1: Vec<F>,
    pub multiplier_l2: Vec<F>,
    pub two_power_8: F,
    pub m_exp: F,
    pub zero: F,

    pub params: <PoseidonSponge<F> as CryptographicSponge>::Parameters,
    pub commit: Vec<F>,
    pub commit_u8: Vec<u8>,
    pub is_u8: bool,
}

impl <F: PrimeField>ConstraintSynthesizer<F> for FullCircuitOpLv3PoseidonClassification<F>{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_fvar = generate_fvar_ipt(cs.clone(), self.x.clone());
        let l1_fvar = generate_fvar2d(cs.clone(), self.l1.clone());
        let l2_fvar = generate_fvar2d(cs.clone(), self.l2.clone());
        let y_fvar = generate_fvar(cs.clone(), self.y.clone());
        let l1_1d_fvar = convert_2d_vector_into_1d(l1_fvar.clone());
        let l2_1d_fvar = convert_2d_vector_into_1d(l2_fvar.clone());
        //let l1_1d_fvar = generate_fvar(cs.clone(), self.l1_1d_f.clone());
        //let l2_1d_fvar = generate_fvar(cs.clone(), self.l2_1d_f.clone());
        let z_fvar = generate_fvar_ipt(cs.clone(), self.z.clone());
        let mut commit_ipt_fvar = Vec::<FpVar<F>>::new();
        commit_ipt_fvar.extend(x_fvar.clone());
        commit_ipt_fvar.extend(l1_1d_fvar);
        commit_ipt_fvar.extend(l2_1d_fvar);
        commit_ipt_fvar.extend(z_fvar.clone());
        let relu_output1_fvar = generate_fvar(cs.clone(), self.relu_output1.clone());
        let argmax_fvar = FpVar::<F>::new_witness(ark_relations::ns!(cs, "argmax var"), || Ok(self.argmax_res)).unwrap();
        //let param_var = PoseidonSpongeVar::<F>::new(cs.clone(),&self.params);
        
        let full_circuit = FullCircuitOpLv3 {
            x: x_fvar,
            l1: l1_fvar,
            l2: l2_fvar,
            z: z_fvar.clone(),
            y: y_fvar,
            relu_output1: relu_output1_fvar,
            remainder1: self.remainder1,
            remainder2: self.remainder2,
            div1: self.div1,
            div2: self.div2,
            cmp_res: self.cmp_res,
            y_0_converted: self.y_0_converted,
            z_0_converted: self.z_0_converted,
            x_0: self.x_0,
            y_0: self.y_0,
            z_0: self.z_0,
            l1_mat_0: self.l1_mat_0,
            l2_mat_0: self.l2_mat_0,
            multiplier_l1: self.multiplier_l1,
            multiplier_l2: self.multiplier_l2,
            two_power_8: self.two_power_8,
            m_exp: self.m_exp,
            zero: self.zero,
        };

        let argmax_circuit = ArgmaxCircuitU8 {
            input: z_fvar.clone(),
            argmax_res: argmax_fvar,
        };

        let com_circuit = PosedionCircuit {
                param: self.params.clone(),
                input: commit_ipt_fvar.clone(),
                output: self.commit.clone()
        };
        let com_circuit_u8 = PosedionCircuitU8 {
                param: self.params.clone(),
                input: self.commit_u8,
                output: self.commit.clone()
        };
    


        // let l1_com_circuit = PosedionCircuit {
        //     param: self.params.clone(),
        //     input: l1_1d_fvar,
        //     output: self.l1_squeeze.clone()
        // };

        // let l2_com_circuit = PosedionCircuit {
        //     param: self.params.clone(),
        //     input: l2_1d_fvar,
        //     output: self.l2_squeeze.clone()
        // };

        // let z_com_circuit = PosedionCircuit {
        //     param: self.params.clone(),
        //     input: z_fvar,
        //     output: self.z_squeeze.clone()
        // };

        full_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        argmax_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        if self.is_u8 {
            com_circuit_u8
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        } else {
            com_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        }

        // l1_com_circuit
        //     .clone()
        //     .generate_constraints(cs.clone())
        //     .unwrap();
        // l2_com_circuit
        //     .clone()
        //     .generate_constraints(cs.clone())
        //     .unwrap();
        // z_com_circuit
        //     .clone()
        //     .generate_constraints(cs.clone())
        //     .unwrap();
        Ok(())
    }
}

type BwSF = <BW6<ark_bw6_761::Parameters> as PairingEngine>::Fr;
#[derive(Clone)]
pub struct FullCircuitOpLv3KZGPolyClassification<F: PrimeField> {
    pub x: Vec<F>,
    pub l1: Vec<Vec<F>>,
    pub l2: Vec<Vec<F>>,
    pub y: Vec<F>,
    pub z: Vec<F>,
    pub argmax_res: F,
    pub relu_output1: Vec<F>,
    pub remainder1: Vec<F>,
    pub remainder2: Vec<F>,
    pub div1: Vec<F>,
    pub div2: Vec<F>,
    pub cmp_res: Vec<bool>,
    pub y_0_converted: Vec<F>,
    pub z_0_converted: Vec<F>,
    pub x_0: F,
    pub y_0: F,
    pub z_0: F,
    pub l1_mat_0: F,
    pub l2_mat_0: F,
    pub multiplier_l1: Vec<F>,
    pub multiplier_l2: Vec<F>,
    pub two_power_8: F,
    pub m_exp: F,
    pub zero: F,

    pub powers_of_beta: Vec<F>,
    pub rho: F,
}

impl <F: PrimeField> ConstraintSynthesizer<F> for FullCircuitOpLv3KZGPolyClassification<F>{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let x_fvar = generate_fvar_ipt(cs.clone(), self.x.clone());
        let l1_fvar = generate_fvar2d(cs.clone(), self.l1.clone());
        let l2_fvar = generate_fvar2d(cs.clone(), self.l2.clone());
        let y_fvar = generate_fvar(cs.clone(), self.y.clone());
        let l1_1d_fvar = convert_2d_vector_into_1d(l1_fvar.clone());
        let l2_1d_fvar = convert_2d_vector_into_1d(l2_fvar.clone());

        //let l1_1d_fvar = generate_fvar(cs.clone(), self.l1_1d_f.clone());
        //let l2_1d_fvar = generate_fvar(cs.clone(), self.l2_1d_f.clone());
        let z_fvar = generate_fvar_ipt(cs.clone(), self.z.clone());
        let mut commit_ipt_fvar = Vec::<FpVar<F>>::new();
        commit_ipt_fvar.extend(x_fvar.clone());
        commit_ipt_fvar.extend(l1_1d_fvar);
        commit_ipt_fvar.extend(l2_1d_fvar);
        commit_ipt_fvar.extend(z_fvar.clone());
        let relu_output1_fvar = generate_fvar(cs.clone(), self.relu_output1.clone());
        let argmax_fvar = FpVar::<F>::new_witness(ark_relations::ns!(cs, "argmax var"), || Ok(self.argmax_res)).unwrap();
        // KZG stuff 
        // Ensure rho = Bls_SF(sum(w_i * beta^i))

        let _cir_number = cs.num_constraints();
        let com_len = commit_ipt_fvar.len();
        let beta_fvar = FpVar::<F>::new_input(ark_relations::ns!(cs, "beta var"), || Ok(self.powers_of_beta[0])).unwrap();
        let poly = DensePolynomialVar::<F>::from_coefficients_vec(commit_ipt_fvar);
        let rho_fvar = FpVar::<F>::new_input(ark_relations::ns!(cs, "rho var"), || Ok(self.rho)).unwrap();
        let rho_circ = poly.evaluate(&beta_fvar).unwrap();
        rho_circ.enforce_equal(&rho_fvar).unwrap();
        println!(
            "Number of constraints for Poly {}, avg {}",
            cs.num_constraints() - _cir_number,
            ((cs.num_constraints() - _cir_number) as f64) / (com_len as f64)
        );

        let full_circuit = FullCircuitOpLv3 {
            x: x_fvar,
            l1: l1_fvar,
            l2: l2_fvar,
            z: z_fvar.clone(),
            y: y_fvar,
            relu_output1: relu_output1_fvar,
            remainder1: self.remainder1,
            remainder2: self.remainder2,
            div1: self.div1,
            div2: self.div2,
            cmp_res: self.cmp_res,
            y_0_converted: self.y_0_converted,
            z_0_converted: self.z_0_converted,
            x_0: self.x_0,
            y_0: self.y_0,
            z_0: self.z_0,
            l1_mat_0: self.l1_mat_0,
            l2_mat_0: self.l2_mat_0,
            multiplier_l1: self.multiplier_l1,
            multiplier_l2: self.multiplier_l2,
            two_power_8: self.two_power_8,
            m_exp: self.m_exp,
            zero: self.zero,
        };
        let argmax_circuit = ArgmaxCircuitU8 {
            input: z_fvar,
            argmax_res: argmax_fvar,
        };
        full_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        argmax_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        Ok(())
    }
}
#[derive(Clone)]
pub struct FullCircuitOpLv3KZGClassification<F: PrimeField> {
    pub x: Vec<F>,
    pub l1: Vec<Vec<F>>,
    pub l2: Vec<Vec<F>>,
    pub y: Vec<F>,
    pub z: Vec<F>,
    pub argmax_res: F,
    pub relu_output1: Vec<F>,
    pub remainder1: Vec<F>,
    pub remainder2: Vec<F>,
    pub div1: Vec<F>,
    pub div2: Vec<F>,
    pub cmp_res: Vec<bool>,
    pub y_0_converted: Vec<F>,
    pub z_0_converted: Vec<F>,
    pub x_0: F,
    pub y_0: F,
    pub z_0: F,
    pub l1_mat_0: F,
    pub l2_mat_0: F,
    pub multiplier_l1: Vec<F>,
    pub multiplier_l2: Vec<F>,
    pub two_power_8: F,
    pub m_exp: F,
    pub zero: F,

    pub powers_of_beta: Vec<F>,
    pub bls_modulus: BwSF,
    pub l1_rho: F,
    pub l2_rho: F,
    pub l1_beta_qr: Vec<(BwSF, BwSF)>,
    pub l2_beta_qr: Vec<(BwSF, BwSF)>,
    pub l1_cum_sum_qr: Vec<(BwSF, BwSF)>,
    pub l2_cum_sum_qr: Vec<(BwSF, BwSF)>,

    pub g1_l1_l: G1Prepared<ark_bls12_377::Parameters>,
    pub g1_l2_l: G1Prepared<ark_bls12_377::Parameters>,
    pub g1_l1_r: G1Prepared<ark_bls12_377::Parameters>,
    pub g1_l2_r: G1Prepared<ark_bls12_377::Parameters>, 
    pub g2_l: G2Prepared<ark_bls12_377::Parameters>,
    pub g2_r: G2Prepared<ark_bls12_377::Parameters>,
}
impl ConstraintSynthesizer<BwSF> for FullCircuitOpLv3KZGClassification<BwSF>{
    fn generate_constraints(self, cs: ConstraintSystemRef<BwSF>) -> Result<(), SynthesisError> {

        let x_fvar = generate_fvar_ipt(cs.clone(), self.x.clone());
        let l1_fvar = generate_fvar2d(cs.clone(), self.l1.clone());
        let l2_fvar = generate_fvar2d(cs.clone(), self.l2.clone());
        let y_fvar = generate_fvar(cs.clone(), self.y.clone());
        let l1_1d_fvar = convert_2d_vector_into_1d(l1_fvar.clone());
        let l2_1d_fvar = convert_2d_vector_into_1d(l2_fvar.clone());

        //let l1_1d_fvar = generate_fvar(cs.clone(), self.l1_1d_f.clone());
        //let l2_1d_fvar = generate_fvar(cs.clone(), self.l2_1d_f.clone());
        let z_fvar = generate_fvar_ipt(cs.clone(), self.z.clone());
        let relu_output1_fvar = generate_fvar(cs.clone(), self.relu_output1.clone());
        let argmax_fvar = FpVar::<BwSF>::new_witness(ark_relations::ns!(cs, "argmax var"), || Ok(self.argmax_res)).unwrap();
        // KZG stuff 
        // Ensure rho = Bls_SF(sum(w_i * beta^i))
        let beta_fvar = generate_fvar(cs.clone(), self.powers_of_beta.clone());
        let l1_beta_fvar: Vec<FpVar<BwSF>> = l1_1d_fvar.iter().zip(beta_fvar.iter())
            .map(|(a,b)| a * b).collect();

        let l2_beta_fvar: Vec<FpVar<BwSF>> = l2_1d_fvar.iter().zip(beta_fvar.iter())
            .map(|(a,b)| a * b).collect();

        let l1_beta_qr_fvar: Vec<(FpVar<BwSF>, FpVar<BwSF>)> = self.l1_beta_qr.iter()
            .map(|(a,b)| (
                FpVar::<BwSF>::new_witness(ark_relations::ns!(cs, "l1_q"), || Ok(*a)).unwrap(),
                FpVar::<BwSF>::new_witness(ark_relations::ns!(cs, "l1_r"), || Ok(*b)).unwrap(),
            )).collect();

        let l2_beta_qr_fvar: Vec<(FpVar<BwSF>, FpVar<BwSF>)> = self.l2_beta_qr.iter()
            .map(|(a,b)| (
                FpVar::<BwSF>::new_witness(ark_relations::ns!(cs, "l2_q"), || Ok(*a)).unwrap(),
                FpVar::<BwSF>::new_witness(ark_relations::ns!(cs, "l2_r"), || Ok(*b)).unwrap(),
            )).collect();
        
        let l1_cum_sum_qr_fvar: Vec<(FpVar<BwSF>, FpVar<BwSF>)> = self.l1_cum_sum_qr.iter()
            .map(|(a,b)| (
                FpVar::<BwSF>::new_witness(ark_relations::ns!(cs, "l1_q"), || Ok(*a)).unwrap(),
                FpVar::<BwSF>::new_witness(ark_relations::ns!(cs, "l1_r"), || Ok(*b)).unwrap(),
            )).collect();

        let l2_cum_sum_qr_fvar: Vec<(FpVar<BwSF>, FpVar<BwSF>)> = self.l2_cum_sum_qr.iter()
            .map(|(a,b)| (
                FpVar::<BwSF>::new_witness(ark_relations::ns!(cs, "l2_q"), || Ok(*a)).unwrap(),
                FpVar::<BwSF>::new_witness(ark_relations::ns!(cs, "l2_r"), || Ok(*b)).unwrap(),
            )).collect();
        // let l1_poly = DensePolynomialVar::<BwSF>::from_coefficients_vec(l1_1d_fvar);
        // let l2_poly = DensePolynomialVar::<BwSF>::from_coefficients_vec(l2_1d_fvar);
        // let beta_fvar = FpVar::<BwSF>::new_input(ark_relations::ns!(cs, "beta var"), || Ok(self.powers_of_beta[0])).unwrap();
        let l1_rho_fvar = FpVar::<BwSF>::new_input(ark_relations::ns!(cs, "l1 rho var"), || Ok(self.l1_rho)).unwrap();
        let l2_rho_fvar = FpVar::<BwSF>::new_input(ark_relations::ns!(cs, "l2 rho var"), || Ok(self.l2_rho)).unwrap();
        // let l1_rho_circ = l1_poly.evaluate(&beta_fvar).unwrap();
        // let l2_rho_circ = l2_poly.evaluate(&beta_fvar).unwrap();
        // l1_rho_circ.enforce_equal(&l1_rho_fvar).unwrap();
        // l2_rho_circ.enforce_equal(&l2_rho_fvar).unwrap();
        let bls_mod_fvar = FpVar::<BwSF>::new_constant(ark_relations::ns!(cs, "bls modulus"), self.bls_modulus).unwrap();

        let g1_l1_l_var = G1PreparedVar::<ark_bls12_377::Parameters>::new_input(cs.clone(), || Ok(self.g1_l1_l.clone())).unwrap();
        let g1_l1_r_var = G1PreparedVar::<ark_bls12_377::Parameters>::new_input(cs.clone(), || Ok(self.g1_l1_r.clone())).unwrap();  
        let g1_l2_l_var = G1PreparedVar::<ark_bls12_377::Parameters>::new_input(cs.clone(), || Ok(self.g1_l2_l.clone())).unwrap();
        let g1_l2_r_var = G1PreparedVar::<ark_bls12_377::Parameters>::new_input(cs.clone(), || Ok(self.g1_l2_r.clone())).unwrap();  
        let g2_l_var = G2PreparedVar::<ark_bls12_377::Parameters>::new_input(cs.clone(), || Ok(self.g2_l.clone())).unwrap();
        let g2_r_var = G2PreparedVar::<ark_bls12_377::Parameters>::new_input(cs.clone(), || Ok(self.g2_r.clone())).unwrap();  


        let full_circuit = FullCircuitOpLv3 {
            x: x_fvar,
            l1: l1_fvar,
            l2: l2_fvar,
            z: z_fvar.clone(),
            y: y_fvar,
            relu_output1: relu_output1_fvar,
            remainder1: self.remainder1,
            remainder2: self.remainder2,
            div1: self.div1,
            div2: self.div2,
            cmp_res: self.cmp_res,
            y_0_converted: self.y_0_converted,
            z_0_converted: self.z_0_converted,
            x_0: self.x_0,
            y_0: self.y_0,
            z_0: self.z_0,
            l1_mat_0: self.l1_mat_0,
            l2_mat_0: self.l2_mat_0,
            multiplier_l1: self.multiplier_l1,
            multiplier_l2: self.multiplier_l2,
            two_power_8: self.two_power_8,
            m_exp: self.m_exp,
            zero: self.zero,
        };

        let argmax_circuit = ArgmaxCircuitU8 {
            input: z_fvar,
            argmax_res: argmax_fvar,
        };

        let poly_circuit_l1 = PolyCircuit {
            vector_beta_ip: l1_beta_fvar,
            beta_qr: l1_beta_qr_fvar,
            cum_sum_qr: l1_cum_sum_qr_fvar,
            rho: l1_rho_fvar,
            bls_mod: bls_mod_fvar.clone(),
        };

        let poly_circuit_l2 = PolyCircuit {
            vector_beta_ip: l2_beta_fvar,
            beta_qr: l2_beta_qr_fvar,
            cum_sum_qr: l2_cum_sum_qr_fvar,
            rho: l2_rho_fvar,
            bls_mod: bls_mod_fvar.clone(),
        };

        let commit_circuit_l1 = KZGCommitCircuit {
            g2_l: g2_l_var.clone(),
            g2_r: g2_r_var.clone(),
            g1_l: g1_l1_l_var.clone(),
            g1_r: g1_l1_r_var.clone(),
        };

        let commit_circuit_l2 = KZGCommitCircuit {
            g2_l: g2_l_var,
            g2_r: g2_r_var,
            g1_l: g1_l2_l_var.clone(),
            g1_r: g1_l2_r_var.clone(),
        };

        full_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        argmax_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        poly_circuit_l1
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        poly_circuit_l2
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        commit_circuit_l1
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        commit_circuit_l2
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        Ok(())
    }
}

#[derive(Clone)]
pub struct FullCircuitOpLv3<F: PrimeField> {
    pub x: Vec<FpVar<F>>,
    pub l1: Vec<Vec<FpVar<F>>>,
    pub l2: Vec<Vec<FpVar<F>>>,
    pub z: Vec<FpVar<F>>,
    pub y: Vec<FpVar<F>>,
    
    pub relu_output1: Vec<FpVar<F>>,

    pub remainder1: Vec<F>,
    pub div1: Vec<F>,
    pub remainder2: Vec<F>,
    pub div2: Vec<F>,
    
    pub cmp_res: Vec<bool>,
    pub x_0: F,
    pub y_0: F,
    pub y_0_converted: Vec<F>,
    pub z_0: F,
    pub z_0_converted: Vec<F>,    
    pub l1_mat_0: F,
    pub l2_mat_0: F,
    pub multiplier_l1: Vec<F>,
    pub multiplier_l2: Vec<F>,
    pub two_power_8: F,
    pub m_exp: F,
    pub zero: F,
}

impl <F: PrimeField> ConstraintSynthesizer<F> for FullCircuitOpLv3<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut _cir_number = cs.num_constraints();
        // CIRCUITS

        let l1_circuit = FCCircuitOp3 {
            x: self.x.clone(),
            l1_mat: self.l1.clone(),
            y: self.y.clone(),
            remainder: self.remainder1,
            div: self.div1,

            x_0: self.x_0,
            l1_mat_0: self.l1_mat_0,
            y_0: self.y_0_converted,

            multiplier: self.multiplier_l1,

            two_power_8: self.two_power_8,
            m_exp: self.m_exp,
            zero: self.zero,
        };

        l1_circuit.generate_constraints(cs.clone())?;
        println!(
            "Number of constraints for FC1 {} accumulated constraints {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();

        let relu_circuit = ReLUCircuitOp3 {
            y_in: self.y,
            y_out: self.relu_output1.clone(),
            y_zeropoint: self.y_0,
            cmp_res: self.cmp_res.clone(),
        };
        relu_circuit.generate_constraints(cs.clone())?;

        println!(
            "Number of constraints for ReLU1 {} accumulated constraints {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );

        _cir_number = cs.num_constraints();

        let l2_circuit = FCCircuitOp3 {
            x: self.relu_output1.clone(),
            l1_mat: self.l2,
            y: self.z,
            remainder: self.remainder2,
            div: self.div2,

            x_0: self.y_0,
            l1_mat_0: self.l2_mat_0,
            y_0: self.z_0_converted,

            multiplier: self.multiplier_l2,

            two_power_8: self.two_power_8,
            m_exp: self.m_exp,
            zero: self.zero,
        };
        l2_circuit.generate_constraints(cs.clone())?;
        println!(
            "Number of constraints for FC2 {} accumulated constraints {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();

        println!(
            "Total number of FullCircuit inference constraints {}",
            cs.num_constraints()
        );
        Ok(())
    }
}

