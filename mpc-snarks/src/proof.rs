#![allow(dead_code)]
#![allow(unused_imports)]
use ark_ec::PairingEngine;
use ark_groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use ark_std::test_rng;
use ark_std::{end_timer, start_timer};
use blake2::Blake2s;
use clap::arg_enum;
use log::debug;
use mpc_algebra::{channel, MpcPairingEngine, PairingShare, Reveal};
use mpc_net::{MpcMultiNet, MpcNet, MpcTwoNet};
use structopt::StructOpt;
use zen_arkworks::*;
use std::path::PathBuf;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Polynomial, UVPolynomial};
use zen_arkworks::full_circuit::*;
use zen_arkworks::vanilla::*;
use ark_poly_commit::kzg10::{Powers, Commitment, UniversalParams, Proof};
use ark_ff::{PrimeField, Field, UniformRand, One};
use std::borrow::Cow;
use std::ops::{Deref, Div};
use ark_ec::bls12::Bls12;
mod groth;
mod marlin;
mod silly;

const TIMED_SECTION_LABEL: &str = "timed section";

trait SnarkBench {
    fn local<E: PairingEngine>(n: usize, timer_label: &str);
    fn ark_local<E: PairingEngine>(_n: usize, _timer_label: &str) {
        unimplemented!("ark benchmark for {}", std::any::type_name::<Self>())
    }
    fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str);
}

mod squarings {
    use super::*;
    const M_EXP: u32 = 22;
    fn kzg_proof<F: PrimeField, E: PairingEngine<Fr = F>>(
        poly: DensePolynomial<F>,
        //pp: ark_poly_commit::kzg10::UniversalParams<E>,
        powers: Powers<E>,
        x: F,
    ) -> (F, ark_poly_commit::kzg10::Commitment<E>, ark_poly_commit::kzg10::Commitment<E>)  {
        let rng = &mut ark_std::test_rng();

        let (commit, rand) =
        ark_poly_commit::kzg10::KZG10::commit(&powers, &poly, None, None).unwrap();
        let eval = poly.evaluate(&x);
        let eval_poly = DensePolynomial::<F>::from_coefficients_vec(vec![-eval]);
        let divisor_poly = DensePolynomial::<F>::from_coefficients_vec(vec![-x, E::Fr::one()]);
        let wintess_poly = (poly + eval_poly).div(&divisor_poly);
        let (witness_commit, rand) = 
        ark_poly_commit::kzg10::KZG10::commit(&powers, &wintess_poly, None, None).unwrap();

        (eval, commit, witness_commit)
    }

    fn gen_circ_full_kzg_poly<E: PairingEngine>(    
        x: Vec<u8>,
        l1: Vec<Vec<u8>>,
        l2: Vec<Vec<u8>>,
        z: Vec<u8>,
        argmax_res: usize,
    
        x_0: u8,
        y_0: u8,
        z_0: u8,
        l1_mat_0: u8,
        l2_mat_0: u8,
        multiplier_l1: Vec<f32>,
        multiplier_l2: Vec<f32>,
    ) -> (FullCircuitOpLv3KZGPolyClassification<E::Fr>, Commitment<E>, Commitment<E>, UniversalParams<E>, <E as PairingEngine>::Fr, <E as PairingEngine>::Fr) {
        // KZG commit to NN
        let mut y = vec![0u8; l1.len()];
        let l1_mat_ref: Vec<&[u8]> = l1.iter().map(|x| x.as_ref()).collect();

        let (remainder1, div1) = vec_mat_mul_with_remainder_u8(
            &x,
            l1_mat_ref[..].as_ref(),
            &mut y,
            x_0,
            l1_mat_0,
            y_0,
            &multiplier_l1,
        );

        let mut y_out = y.clone();
        let cmp_res = relu_u8(&mut y_out, y_0);

        // y_0 and multiplier_l1 are both constants.
        let mut y_0_converted: Vec<u64> = Vec::new();
        let mut multiplier_l1_f: Vec<E::Fr> = Vec::new();
        for i in 0..multiplier_l1.len() {
            let m = (multiplier_l1[i] * (2u64.pow(M_EXP)) as f32) as u64;
            multiplier_l1_f.push(m.into());
            y_0_converted.push((y_0 as u64 * 2u64.pow(M_EXP)) / m);
        }

        let l2_mat_ref: Vec<&[u8]> = l2.iter().map(|x| x.as_ref()).collect();
        let mut zz = vec![0u8; l2.len()];
        let (remainder2, div2) = vec_mat_mul_with_remainder_u8(
            &y_out,
            l2_mat_ref[..].as_ref(),
            &mut zz,
            y_0,
            l2_mat_0,
            z_0,
            &multiplier_l2,
        );

        // z_0 and multiplier_l2 are both constants.

        let mut z_0_converted: Vec<u64> = Vec::new();
        let mut multiplier_l2_f: Vec<E::Fr> = Vec::new();
        for i in 0..multiplier_l2.len() {
            let m = (multiplier_l2[i] * (2u64.pow(M_EXP)) as f32) as u64;
            multiplier_l2_f.push(m.into());
            z_0_converted.push((z_0 as u64 * 2u64.pow(M_EXP)) / m);
        }

        // To Field Elements
        let x_f:Vec<E::Fr> = x.iter().map(|x| (*x).into()).collect();
        let remainder1_f:Vec<E::Fr> = remainder1.iter().map(|x| (*x).into()).collect();
        let div1_f:Vec<E::Fr> = div1.iter().map(|x| (*x).into()).collect();
        let remainder2_f:Vec<E::Fr> = remainder2.iter().map(|x| (*x).into()).collect();
        let div2_f:Vec<E::Fr> = div2.iter().map(|x| (*x).into()).collect();
        let y_f: Vec<E::Fr> = y.iter().map(|x| (*x).into()).collect();
        let l1_f: Vec<Vec<E::Fr>> = l1.iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect();
        let y_0_converted_f: Vec<E::Fr> = y_0_converted.iter().map(|x| (*x).into()).collect();
        let relu_output_f: Vec<E::Fr> = y_out.iter().map(|x| (*x).into()).collect();
        let z_f: Vec<E::Fr> = zz.iter().map(|x| (*x).into()).collect();
        let z_max = z_f[argmax_res];
        let l2_f: Vec<Vec<E::Fr>> = l2.iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect();
        let z_0_converted_f: Vec<E::Fr> = z_0_converted.iter().map(|x| (*x).into()).collect();
        let x_0_f: E::Fr = x_0.into();
        let y_0_f: E::Fr = y_0.into();
        let z_0_f: E::Fr = z_0.into();
        let l1_mat_0_f: E::Fr = l1_mat_0.into();
        let l2_mat_0_f: E::Fr = l2_mat_0.into();
                
        let two_power_8: E::Fr = (2u64.pow(8)).into();
        let m_exp: E::Fr = (2u64.pow(M_EXP)).into();
        let zero: E::Fr = 0u64.into();
        // KZG Commit to NN

        let l1_bls: Vec<E::Fr> = convert_2d_vector_into_1d(l1).iter().map(|x| (*x).into()).collect();
        let l2_bls: Vec<E::Fr> = convert_2d_vector_into_1d(l2).iter().map(|x| (*x).into()).collect();

        let mut commit_vec = Vec::<E::Fr>::new();
        commit_vec.extend(x_f.clone());
        commit_vec.extend(l1_bls.clone());
        commit_vec.extend(l2_bls.clone());
        commit_vec.extend(z_f.clone());
        let commit_poly = DensePolynomial::<E::Fr>::from_coefficients_slice(&commit_vec);

        let rng = &mut ark_std::test_rng();
        let pp = ark_poly_commit::kzg10::KZG10::<
            E,
            DensePolynomial<E::Fr>,
        >::setup(commit_vec.len() - 1, true, rng)
        .unwrap();

        let powers_of_gamma_g = (0..commit_vec.len())
            .map(|i| pp.powers_of_gamma_g[&i])
            .collect::<Vec<_>>();

        let powers = ark_poly_commit::kzg10::Powers::<E> {
            powers_of_g: Cow::Borrowed(&pp.powers_of_g),
            powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
        };

        let beta = E::Fr::rand(rng);
        let mut powers_of_beta: Vec<E::Fr> = vec![1u8.into()];
        let mut cur = beta;

        for _ in 0..commit_vec.len() {
            powers_of_beta.push(cur);
            cur *= &beta;
        } 

        let (rho, c, pi) = kzg_proof(commit_poly, powers.clone(), beta);

        let full_circuit = FullCircuitOpLv3KZGPolyClassification {
            x: x_f,
            l1: l1_f,
            l2: l2_f, 
            y: y_f,
            z: z_f,
            argmax_res: z_max,
            relu_output1: relu_output_f,
            remainder1: remainder1_f,
            remainder2: remainder2_f,
            div1: div1_f,
            div2: div2_f,
            cmp_res,
            y_0_converted: y_0_converted_f,
            z_0_converted: z_0_converted_f,
            x_0: x_0_f,
            y_0: y_0_f,
            z_0: z_0_f,
            l1_mat_0: l1_mat_0_f,
            l2_mat_0: l2_mat_0_f,
            multiplier_l1: multiplier_l1_f,
            multiplier_l2: multiplier_l2_f,
            two_power_8,
            m_exp,
            zero,
            
            //KZG stuff
            powers_of_beta: powers_of_beta,
            rho: rho,
        };
        (full_circuit, c, pi, pp, beta, rho)
    }

    fn gen_circ_full_mpc<F: PrimeField, MF: PrimeField + Reveal<Base = F>>(    
        full_circuit: FullCircuitOpLv3KZGPolyClassification<F>
    ) -> FullCircuitOpLv3KZGPolyClassification<MF> {

        let rng = &mut test_rng();

        let full_circuit_mpc = FullCircuitOpLv3KZGPolyClassification {
            x: MF::king_share_batch(full_circuit.x, rng),
            l1: Vec::<MF>::king_share_batch(full_circuit.l1, rng),
            l2: Vec::<MF>::king_share_batch(full_circuit.l2, rng),
            y: MF::king_share_batch(full_circuit.y, rng),
            z: MF::king_share_batch(full_circuit.z, rng),
            argmax_res: MF::king_share(full_circuit.argmax_res, rng),
            relu_output1: MF::king_share_batch(full_circuit.relu_output1, rng),
            remainder1: MF::king_share_batch(full_circuit.remainder1, rng),
            remainder2: MF::king_share_batch(full_circuit.remainder2, rng),
            div1: MF::king_share_batch(full_circuit.div1, rng),
            div2: MF::king_share_batch(full_circuit.div2, rng),
            cmp_res: bool::king_share_batch(full_circuit.cmp_res, rng),
            y_0_converted: MF::king_share_batch(full_circuit.y_0_converted, rng),
            z_0_converted: MF::king_share_batch(full_circuit.z_0_converted, rng),
            x_0: MF::king_share(full_circuit.x_0, rng),
            y_0: MF::king_share(full_circuit.y_0, rng),
            z_0: MF::king_share(full_circuit.z_0, rng),
            l1_mat_0: MF::king_share(full_circuit.l1_mat_0, rng),
            l2_mat_0: MF::king_share(full_circuit.l2_mat_0, rng),
            multiplier_l1: MF::king_share_batch(full_circuit.multiplier_l1, rng),
            multiplier_l2: MF::king_share_batch(full_circuit.multiplier_l2, rng),
            two_power_8: MF::king_share(full_circuit.two_power_8, rng),
            m_exp: MF::king_share(full_circuit.m_exp, rng),
            zero: MF::king_share(full_circuit.zero, rng),

            powers_of_beta: MF::king_share_batch(full_circuit.powers_of_beta.clone(), rng),
            rho: MF::king_share(full_circuit.rho.clone(), rng),
        };
        full_circuit_mpc
    }
    pub mod groth {
        use super::*;
        use crate::ark_groth16::{generate_random_parameters, prepare_verifying_key, verify_proof};
        use crate::groth::prover::create_random_proof;

        pub struct Groth16Bench;

        impl SnarkBench for Groth16Bench {
            fn local<E: PairingEngine>(n: usize, timer_label: &str) {
                let mut rng = &mut test_rng();
                //let (x, l1_mat, l2_mat): (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) = read_shallownet_inputs_u8();
                let x: Vec<u8> = read_vector1d("pretrained_model/shallownet/X_q.txt".to_string(), 784); // only read one image
                let l1_mat: Vec<Vec<u8>> = read_vector2d(
                    "pretrained_model/shallownet/l1_weight_q.txt".to_string(),
                    128,
                    784,
                );
                let l2_mat: Vec<Vec<u8>> = read_vector2d(
                    "pretrained_model/shallownet/l2_weight_q.txt".to_string(),
                    10,
                    128,
                );
                let x_0: Vec<u8> = read_vector1d("pretrained_model/shallownet/X_z.txt".to_string(), 1);
                let l1_output_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l1_output_z.txt".to_string(), 1);
                let l2_output_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l2_output_z.txt".to_string(), 1);
                let l1_mat_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l1_weight_z.txt".to_string(), 1);
                let l2_mat_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l2_weight_z.txt".to_string(), 1);
            
                let l1_mat_multiplier: Vec<f32> = read_vector1d_f32(
                    "pretrained_model/shallownet/l1_weight_s.txt".to_string(),
                    128,
                );
                let l2_mat_multiplier: Vec<f32> = read_vector1d_f32(
                    "pretrained_model/shallownet/l2_weight_s.txt".to_string(),
                    10,
                );
            
                //println!("zero points x_0 {}  l1_out_0 {} l2_out_0 {}, l1_mat_0 {}, l2_mat_0 {}", x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0]);
            
                let z: Vec<u8> = full_circuit_forward_u8(
                    x.clone(),
                    l1_mat.clone(),
                    l2_mat.clone(),
                    x_0[0],
                    l1_output_0[0],
                    l2_output_0[0],
                    l1_mat_0[0],
                    l2_mat_0[0],
                    l1_mat_multiplier.clone(),
                    l2_mat_multiplier.clone(),
                );
            
                // let end = Instant::now();
                // println!("commit time {:?}", end.duration_since(begin));
                let classification_res = argmax_u8(z.clone());

                let (circ_data, c, pi, pp, beta, rho) = gen_circ_full_kzg_poly::<E>(x, l1_mat, l2_mat, z, classification_res, x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0], l1_mat_multiplier, l2_mat_multiplier);

                let params = generate_random_parameters::<E, _, _>(circ_data.clone(), rng).unwrap();

                let pvk = prepare_verifying_key::<E>(&params.vk);

                let timer = start_timer!(|| timer_label);
                let proof = create_random_proof::<E, _, _>(circ_data.clone(), &params, rng).unwrap();
 
                let zk_timer = start_timer!(|| "ZKP verification");
                let public_inputs = vec![circ_data.powers_of_beta[1], circ_data.rho];
                let _ = verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap();
                end_timer!(zk_timer);
                let kzg_timer = start_timer!(|| "KZG verification");
                let vk = ark_poly_commit::kzg10::VerifierKey::<E> {
                    g: pp.powers_of_g[0],
                    gamma_g: pp.powers_of_gamma_g[&0],
                    h: pp.h,
                    beta_h: pp.beta_h,
                    prepared_h: pp.prepared_h,
                    prepared_beta_h: pp.prepared_beta_h,
                };
                let _ = ark_poly_commit::kzg10::KZG10::<
                    E,
                    ark_poly::univariate::DensePolynomial<E::Fr>,
                >::check(&vk, &c, beta, rho, &Proof{w: pi.0, random_v: None})
                .unwrap();
                end_timer!(kzg_timer);
            }

            fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str) {
                let mut rng = &mut test_rng();
                //let (x, l1_mat, l2_mat): (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) = read_shallownet_inputs_u8();
                let x: Vec<u8> = read_vector1d("pretrained_model/shallownet/X_q.txt".to_string(), 784); // only read one image
                let l1_mat: Vec<Vec<u8>> = read_vector2d(
                    "pretrained_model/shallownet/l1_weight_q.txt".to_string(),
                    128,
                    784,
                );
                let l2_mat: Vec<Vec<u8>> = read_vector2d(
                    "pretrained_model/shallownet/l2_weight_q.txt".to_string(),
                    10,
                    128,
                );
                let x_0: Vec<u8> = read_vector1d("pretrained_model/shallownet/X_z.txt".to_string(), 1);
                let l1_output_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l1_output_z.txt".to_string(), 1);
                let l2_output_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l2_output_z.txt".to_string(), 1);
                let l1_mat_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l1_weight_z.txt".to_string(), 1);
                let l2_mat_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l2_weight_z.txt".to_string(), 1);
            
                let l1_mat_multiplier: Vec<f32> = read_vector1d_f32(
                    "pretrained_model/shallownet/l1_weight_s.txt".to_string(),
                    128,
                );
                let l2_mat_multiplier: Vec<f32> = read_vector1d_f32(
                    "pretrained_model/shallownet/l2_weight_s.txt".to_string(),
                    10,
                );
            
                //println!("zero points x_0 {}  l1_out_0 {} l2_out_0 {}, l1_mat_0 {}, l2_mat_0 {}", x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0]);
            
                let z: Vec<u8> = full_circuit_forward_u8(
                    x.clone(),
                    l1_mat.clone(),
                    l2_mat.clone(),
                    x_0[0],
                    l1_output_0[0],
                    l2_output_0[0],
                    l1_mat_0[0],
                    l2_mat_0[0],
                    l1_mat_multiplier.clone(),
                    l2_mat_multiplier.clone(),
                );
            
                // let end = Instant::now();
                // println!("commit time {:?}", end.duration_since(begin));
                let classification_res = argmax_u8(z.clone());

                let (circ_data, c, pi, pp, beta, rho) = gen_circ_full_kzg_poly::<E>(x, l1_mat, l2_mat, z, classification_res, x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0], l1_mat_multiplier, l2_mat_multiplier);

                let params = generate_random_parameters::<E, _, _>(circ_data.clone(), rng).unwrap();

                let pvk = prepare_verifying_key::<E>(&params.vk);
                let mpc_params = Reveal::from_public(params);

                let computation_timer = start_timer!(|| "do the mpc (cheat)");
                let circ_data = gen_circ_full_mpc(circ_data.clone());

                end_timer!(computation_timer);
                MpcMultiNet::reset_stats();
                let timer = start_timer!(|| timer_label);
                let proof = channel::without_cheating(|| {
                    let pf = create_random_proof::<MpcPairingEngine<E, S>, _, _>(circ_data.clone(), &mpc_params, rng)
                        .unwrap();
                    let reveal_timer = start_timer!(|| "reveal");
                    let pf = pf.reveal();
                    end_timer!(reveal_timer);
                    pf
                });
                end_timer!(timer);
                let zk_timer = start_timer!(|| "ZKP verification");
                let public_inputs = vec![circ_data.powers_of_beta[0], circ_data.rho].reveal();
                
                let _ = verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap();
                end_timer!(zk_timer);
                let kzg_timer = start_timer!(|| "KZG verification");
                let vk = ark_poly_commit::kzg10::VerifierKey::<E> {
                    g: pp.powers_of_g[0],
                    gamma_g: pp.powers_of_gamma_g[&0],
                    h: pp.h,
                    beta_h: pp.beta_h,
                    prepared_h: pp.prepared_h,
                    prepared_beta_h: pp.prepared_beta_h,
                };
                let res = ark_poly_commit::kzg10::KZG10::<
                    E,
                    ark_poly::univariate::DensePolynomial<E::Fr>,
                >::check(&vk, &c, beta, rho, &Proof{w: pi.0, random_v: None})
                .unwrap();
                end_timer!(kzg_timer);
            }
        }
    }

    pub mod marlin {
        use super::*;
        use ark_marlin::Marlin;
        use ark_marlin::*;
        use ark_poly::univariate::DensePolynomial;
        use ark_poly_commit::marlin::marlin_pc::MarlinKZG10;

        type KzgMarlin<Fr, E> = Marlin<Fr, MarlinKZG10<E, DensePolynomial<Fr>>, Blake2s>;

        pub struct MarlinBench;

        impl SnarkBench for MarlinBench {
            fn local<E: PairingEngine>(n: usize, timer_label: &str) {
                let mut rng = &mut test_rng();
                //let (x, l1_mat, l2_mat): (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) = read_shallownet_inputs_u8();
                let x: Vec<u8> = read_vector1d("pretrained_model/shallownet/X_q.txt".to_string(), 784); // only read one image
                let l1_mat: Vec<Vec<u8>> = read_vector2d(
                    "pretrained_model/shallownet/l1_weight_q.txt".to_string(),
                    128,
                    784,
                );
                let l2_mat: Vec<Vec<u8>> = read_vector2d(
                    "pretrained_model/shallownet/l2_weight_q.txt".to_string(),
                    10,
                    128,
                );
                let x_0: Vec<u8> = read_vector1d("pretrained_model/shallownet/X_z.txt".to_string(), 1);
                let l1_output_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l1_output_z.txt".to_string(), 1);
                let l2_output_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l2_output_z.txt".to_string(), 1);
                let l1_mat_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l1_weight_z.txt".to_string(), 1);
                let l2_mat_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l2_weight_z.txt".to_string(), 1);
            
                let l1_mat_multiplier: Vec<f32> = read_vector1d_f32(
                    "pretrained_model/shallownet/l1_weight_s.txt".to_string(),
                    128,
                );
                let l2_mat_multiplier: Vec<f32> = read_vector1d_f32(
                    "pretrained_model/shallownet/l2_weight_s.txt".to_string(),
                    10,
                );
            
                //println!("zero points x_0 {}  l1_out_0 {} l2_out_0 {}, l1_mat_0 {}, l2_mat_0 {}", x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0]);
            
                let z: Vec<u8> = full_circuit_forward_u8(
                    x.clone(),
                    l1_mat.clone(),
                    l2_mat.clone(),
                    x_0[0],
                    l1_output_0[0],
                    l2_output_0[0],
                    l1_mat_0[0],
                    l2_mat_0[0],
                    l1_mat_multiplier.clone(),
                    l2_mat_multiplier.clone(),
                );
            
                // let end = Instant::now();
                // println!("commit time {:?}", end.duration_since(begin));
                let classification_res = argmax_u8(z.clone());
                let (circ_data, c, pi, pp, beta, rho) = gen_circ_full_kzg_poly::<E>(x, l1_mat, l2_mat, z, classification_res, x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0], l1_mat_multiplier, l2_mat_multiplier);
                let srs = KzgMarlin::<E::Fr, E>::universal_setup(1000000, 1000000, 1000000, rng).unwrap();

                let (pk, vk) = KzgMarlin::<E::Fr, E>::index(&srs, circ_data.clone()).unwrap();

                let a = E::Fr::rand(rng);
                //let circ_data = RepeatedSquaringCircuit::from_start(a, n);
                let public_inputs = vec![circ_data.powers_of_beta[1], circ_data.rho];
                let timer = start_timer!(|| "Marlin Proof");
                let zk_rng = &mut test_rng();
                let proof = KzgMarlin::<E::Fr, E>::prove(&pk, circ_data, zk_rng).unwrap();
                end_timer!(timer);
                assert!(KzgMarlin::<E::Fr, E>::verify(&vk, &public_inputs, &proof, rng).unwrap());
            }

            fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str) {
                let mut rng = &mut test_rng();
                //let (x, l1_mat, l2_mat): (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) = read_shallownet_inputs_u8();
                let x: Vec<u8> = read_vector1d("pretrained_model/shallownet/X_q.txt".to_string(), 784); // only read one image
                let l1_mat: Vec<Vec<u8>> = read_vector2d(
                    "pretrained_model/shallownet/l1_weight_q.txt".to_string(),
                    128,
                    784,
                );
                let l2_mat: Vec<Vec<u8>> = read_vector2d(
                    "pretrained_model/shallownet/l2_weight_q.txt".to_string(),
                    10,
                    128,
                );
                let x_0: Vec<u8> = read_vector1d("pretrained_model/shallownet/X_z.txt".to_string(), 1);
                let l1_output_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l1_output_z.txt".to_string(), 1);
                let l2_output_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l2_output_z.txt".to_string(), 1);
                let l1_mat_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l1_weight_z.txt".to_string(), 1);
                let l2_mat_0: Vec<u8> =
                    read_vector1d("pretrained_model/shallownet/l2_weight_z.txt".to_string(), 1);
            
                let l1_mat_multiplier: Vec<f32> = read_vector1d_f32(
                    "pretrained_model/shallownet/l1_weight_s.txt".to_string(),
                    128,
                );
                let l2_mat_multiplier: Vec<f32> = read_vector1d_f32(
                    "pretrained_model/shallownet/l2_weight_s.txt".to_string(),
                    10,
                );
            
                //println!("zero points x_0 {}  l1_out_0 {} l2_out_0 {}, l1_mat_0 {}, l2_mat_0 {}", x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0]);
            
                let z: Vec<u8> = full_circuit_forward_u8(
                    x.clone(),
                    l1_mat.clone(),
                    l2_mat.clone(),
                    x_0[0],
                    l1_output_0[0],
                    l2_output_0[0],
                    l1_mat_0[0],
                    l2_mat_0[0],
                    l1_mat_multiplier.clone(),
                    l2_mat_multiplier.clone(),
                );
            
                // let end = Instant::now();
                // println!("commit time {:?}", end.duration_since(begin));
                let classification_res = argmax_u8(z.clone());
                let (circ_data, c, pi, pp, beta, rho) = gen_circ_full_kzg_poly::<E>(x, l1_mat, l2_mat, z, classification_res, x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0], l1_mat_multiplier, l2_mat_multiplier);
                let srs = KzgMarlin::<E::Fr, E>::universal_setup(1000000, 1000000, 1000000, rng).unwrap();
                let (pk, vk) = KzgMarlin::<E::Fr, E>::index(&srs, circ_data.clone()).unwrap();
                let mpc_pk = IndexProverKey::from_public(pk);

                let a = E::Fr::rand(rng);
                let computation_timer = start_timer!(|| "do the mpc (cheat)");
                let circ_data = gen_circ_full_mpc(circ_data.clone());
                let public_inputs = vec![circ_data.clone().powers_of_beta[0], circ_data.clone().rho].reveal();
                end_timer!(computation_timer);

                MpcMultiNet::reset_stats();
                let timer = start_timer!(|| timer_label);
                let zk_rng = &mut test_rng();
                let proof = channel::without_cheating(|| {
                    KzgMarlin::<
                        <MpcPairingEngine<E, S> as PairingEngine>::Fr,
                        MpcPairingEngine<E, S>,
                    >::prove(&mpc_pk, circ_data, zk_rng)
                    .unwrap()
                    .reveal()
                });
                end_timer!(timer);
                assert!(KzgMarlin::<E::Fr, E>::verify(&vk, &public_inputs, &proof, rng).unwrap());
            }
        }
    }


   

    // fn mpc_squaring_circuit<Fr: Field, MFr: Field + Reveal<Base = Fr>>(
    //     start: Fr,
    //     squarings: usize,
    // ) -> RepeatedSquaringCircuit<MFr> {
    //     let raw_chain: Vec<Fr> = std::iter::successors(Some(start), |a| Some(a.square()))
    //         .take(squarings + 1)
    //         .collect();
    //     let rng = &mut test_rng();
    //     let chain_shares = MFr::king_share_batch(raw_chain, rng);
    //     RepeatedSquaringCircuit {
    //         chain: chain_shares.into_iter().map(Some).collect(),
    //     }
    // }

    // impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF>
    //     for RepeatedSquaringCircuit<ConstraintF>
    // {
    //     fn generate_constraints(
    //         self,
    //         cs: ConstraintSystemRef<ConstraintF>,
    //     ) -> Result<(), SynthesisError> {
    //         let mut vars: Vec<Variable> = self
    //             .chain
    //             .iter()
    //             .take(self.squarings())
    //             .map(|o| cs.new_witness_variable(|| o.ok_or(SynthesisError::AssignmentMissing)))
    //             .collect::<Result<_, _>>()?;
    //         vars.push(cs.new_input_variable(|| {
    //             self.chain
    //                 .last()
    //                 .unwrap()
    //                 .ok_or(SynthesisError::AssignmentMissing)
    //         })?);

    //         for i in 0..self.squarings() {
    //             cs.enforce_constraint(lc!() + vars[i], lc!() + vars[i], lc!() + vars[i + 1])?;
    //         }

    //         Ok(())
    //     }
    // }
}

#[derive(Debug, StructOpt)]
struct ShareInfo {
    /// File with list of hosts
    #[structopt(long, parse(from_os_str))]
    hosts: PathBuf,

    /// Which party are you? 0 or 1?
    #[structopt(long, default_value = "0")]
    party: u8,

    /// Use spdz?
    #[structopt(long)]
    alg: MpcAlg,
}

impl ShareInfo {
    fn setup(&self) {
        MpcMultiNet::init_from_file(self.hosts.to_str().unwrap(), self.party as usize)
    }
    fn teardown(&self) {
        debug!("Stats: {:#?}", MpcMultiNet::stats());
        MpcMultiNet::deinit();
    }
    fn run<E: PairingEngine, B: SnarkBench>(
        &self,
        computation: Computation,
        computation_size: usize,
        _b: B,
        timed_label: &str,
    ) {
        match computation {
            Computation::Squaring => match self.alg {
                MpcAlg::Spdz => B::mpc::<E, mpc_algebra::share::spdz::SpdzPairingShare<E>>(
                    computation_size,
                    timed_label,
                ),
                MpcAlg::Hbc => B::mpc::<E, mpc_algebra::share::add::AdditivePairingShare<E>>(
                    computation_size,
                    timed_label,
                ),
                MpcAlg::Gsz => B::mpc::<E, mpc_algebra::share::gsz20::GszPairingShare<E>>(
                    computation_size,
                    timed_label,
                ),
            },
        }
    }
}

arg_enum! {
    #[derive(PartialEq, Debug, Clone, Copy)]
    pub enum MpcAlg {
        Spdz,
        Hbc,
        Gsz,
    }
}

arg_enum! {
    #[derive(PartialEq, Debug, Clone, Copy)]
    pub enum Computation {
        Squaring,
    }
}

arg_enum! {
    #[derive(PartialEq, Debug, Clone, Copy)]
    pub enum ProofSystem {
        Groth16,
        Marlin
    }
}

#[derive(Debug, StructOpt)]
enum FieldOpt {
    Mpc {
        #[structopt(flatten)]
        party_info: ShareInfo,
    },
    Local,
}

impl FieldOpt {
    fn setup(&self) {
        match self {
            FieldOpt::Mpc { party_info, .. } => party_info.setup(),
            _ => {}
        }
    }
    fn teardown(&self) {
        match self {
            FieldOpt::Mpc { party_info, .. } => party_info.teardown(),
            _ => {}
        }
        println!("Stats: {:#?}", MpcMultiNet::stats());
    }
    fn run<E: PairingEngine, B: SnarkBench>(
        &self,
        computation: Computation,
        computation_size: usize,
        b: B,
        timed_label: &str,
    ) {
        self.setup();
        match self {
            FieldOpt::Mpc { party_info, .. } => {
                party_info.run::<E, B>(computation, computation_size, b, timed_label)
            }
            FieldOpt::Local => B::local::<E>(computation_size, timed_label),
        }
        self.teardown();
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "proof", about = "Standard and MPC proofs")]
struct Opt {
    /// Computation to perform
    #[structopt(short = "c")]
    computation: Computation,

    /// Proof system to use
    #[structopt(short = "p")]
    proof_system: ProofSystem,

    /// Computation to perform
    #[structopt(long, default_value = "10")]
    computation_size: usize,

    #[structopt(subcommand)]
    field: FieldOpt,
}

impl Opt {}

fn main() {
    let opt = Opt::from_args();
    env_logger::init();
    /*let timer = start_timer!(|| "kzg param");
    let mut rng = &mut ark_std::test_rng();
    let pp = ark_poly_commit::kzg10::KZG10::<
        ark_bls12_377::Bls12_377,
        DensePolynomial<<ark_bls12_377::Bls12_377 as PairingEngine>::Fr>,
    >::setup(102425, true, rng)
    .unwrap();
    end_timer!(timer);*/
    match opt.proof_system {
        ProofSystem::Groth16 => opt.field.run::<ark_bls12_377::Bls12_377, _>(
            opt.computation,
            opt.computation_size,
            squarings::groth::Groth16Bench,
            TIMED_SECTION_LABEL,
        ),
        ProofSystem::Marlin => opt.field.run::<ark_bls12_377::Bls12_377, _>(
            opt.computation,
            opt.computation_size,
            squarings::marlin::MarlinBench,
            TIMED_SECTION_LABEL,
        ),
    }
}
