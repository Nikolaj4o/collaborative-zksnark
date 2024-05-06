#![allow(dead_code)]
#![allow(unused_imports)]
use ark_ec::PairingEngine;
use ark_groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use ark_std::{test_rng, PubUniformRand};
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
use zen_arkworks::util::*;
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

mod shallownet {
    use mpc_algebra::{FieldShare, MpcField};

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
        x_0: u8,
        y_0: u8,
        z_0: u8,
        l1_mat_0: u8,
        l2_mat_0: u8,
        multiplier_l1: Vec<f32>,
        multiplier_l2: Vec<f32>,
    ) -> (FullCircuitOpLv3KZGPolyClassification<E::Fr>) {//, Commitment<E>, Commitment<E>, UniversalParams<E>, <E as PairingEngine>::Fr, <E as PairingEngine>::Fr) {
        // y_0 and multiplier_l1 are both constants.
        let mut y_0_converted: Vec<u64> = Vec::new();
        let mut multiplier_l1_f: Vec<E::Fr> = Vec::new();
        for i in 0..multiplier_l1.len() {
            let m = (multiplier_l1[i] * (2u64.pow(M_EXP)) as f32) as u64;
            multiplier_l1_f.push(m.into());
            y_0_converted.push((y_0 as u64 * 2u64.pow(M_EXP)) / m);
        }
        let mut z_0_converted: Vec<u64> = Vec::new();
        let mut multiplier_l2_f: Vec<E::Fr> = Vec::new();
        for i in 0..multiplier_l2.len() {
            let m = (multiplier_l2[i] * (2u64.pow(M_EXP)) as f32) as u64;
            multiplier_l2_f.push(m.into());
            z_0_converted.push((z_0 as u64 * 2u64.pow(M_EXP)) / m);
        }

        // To Field Elements
        let x_f:Vec<E::Fr> = x.iter().map(|x| (*x).into()).collect();
        let l1_f: Vec<Vec<E::Fr>> = l1.iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect();
        let y_0_converted_f: Vec<E::Fr> = y_0_converted.iter().map(|x| (*x).into()).collect();
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

        let mut y_f = vec![(0 as u64).into(); l1_f.len()];
        let (remainder1_f, div1_f) = vec_mat_mul_with_remainder_f(
            &x_f,
            l1_f.clone(),
            &mut y_f,
            x_0_f,
            l1_mat_0_f,
            y_0_f,
            &multiplier_l1_f,
        );

        let mut y_out_f = y_f.clone();
        let cmp_res = relu_f(&mut y_out_f, y_0_f);
        let mut z_f = vec![(0 as u64).into(); l2_f.len()];
        let (remainder2_f, div2_f) = vec_mat_mul_with_remainder_f(
            &y_out_f,
            l2_f.clone(),
            &mut z_f,
            y_0_f,
            l2_mat_0_f,
            z_0_f,
            &multiplier_l2_f,
        );
        let argmax_res = argmax_f(z_f.clone());
        let z_max = z_f[argmax_res];

        let mut commit_vec = Vec::<E::Fr>::new();
        commit_vec.extend(x_f.clone());
        commit_vec.extend(l1_bls.clone());
        commit_vec.extend(l2_bls.clone());
        //commit_vec.extend(z_f.clone());
        let commit_poly = DensePolynomial::<E::Fr>::from_coefficients_slice(&commit_vec);

        let rng = &mut ark_std::test_rng();
        // let pp = ark_poly_commit::kzg10::KZG10::<
        //     E,
        //     DensePolynomial<E::Fr>,
        // >::setup(commit_vec.len() - 1, true, rng)
        // .unwrap();

        // let powers_of_gamma_g = (0..commit_vec.len())
        //     .map(|i| pp.powers_of_gamma_g[&i])
        //     .collect::<Vec<_>>();

        // let powers = ark_poly_commit::kzg10::Powers::<E> {
        //     powers_of_g: Cow::Borrowed(&pp.powers_of_g),
        //     powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
        // };

        let beta = E::Fr::rand(rng);
        let rho = E::Fr::rand(rng);
        let mut powers_of_beta: Vec<E::Fr> = vec![1u8.into()];
        let mut cur = beta;

        for _ in 0..commit_vec.len() {
            powers_of_beta.push(cur);
            cur *= &beta;
        } 

        // let (rho, c, pi) = kzg_proof(commit_poly, powers.clone(), beta);

        let full_circuit = FullCircuitOpLv3KZGPolyClassification {
            x: x_f,
            l1: l1_f,
            l2: l2_f, 
            y: y_f,
            z: z_f,
            argmax_res: z_max,
            relu_output1: y_out_f,
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
        full_circuit//, c, pi, pp, beta, rho)
    }

    fn gen_circ_full_mpc<F: PrimeField, S: FieldShare<F>>(    
        full_circuit: FullCircuitOpLv3KZGPolyClassification<F>
    ) -> FullCircuitOpLv3KZGPolyClassification<MpcField<F, S>> {

        let rng = &mut test_rng();
        let x: Vec<MpcField::<F, S>> = full_circuit.x.iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect();
        let l1: Vec<Vec<MpcField::<F, S>>> = full_circuit.l1.iter().map(|x| x.iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect()).collect();
        let l2: Vec<Vec<MpcField::<F, S>>> = full_circuit.l2.iter().map(|x| x.iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect()).collect();
        let x_0 = MpcField::<F, S>::from_public(full_circuit.x_0);
        let y_0 = MpcField::<F, S>::from_public(full_circuit.y_0);
        let z_0 = MpcField::<F, S>::from_public(full_circuit.z_0);
        let l1_mat_0 = MpcField::<F, S>::from_public(full_circuit.l1_mat_0);
        let l2_mat_0 = MpcField::<F, S>::from_public(full_circuit.l2_mat_0);
        let y_0_converted: Vec<MpcField::<F, S>> = full_circuit.y_0_converted.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let z_0_converted: Vec<MpcField::<F, S>> = full_circuit.z_0_converted.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let multiplier_l1: Vec<MpcField::<F, S>> = full_circuit.multiplier_l1.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let multiplier_l2: Vec<MpcField::<F, S>> = full_circuit.multiplier_l2.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let two_power_8 = MpcField::<F, S>::from_public(full_circuit.two_power_8);
        let m_exp = MpcField::<F, S>::from_public(full_circuit.m_exp);
        let zero = MpcField::<F, S>::from_public(full_circuit.zero);
        let mut y = vec![(0 as u64).into(); l1.len()];

        let (remainder1, div1) = vec_mat_mul_with_remainder_f(
            &x,
            l1.clone(),
            &mut y,
            x_0,
            l1_mat_0,
            y_0,
            &multiplier_l1,
        );

        let mut y_out = y.clone();
        let cmp_res = relu_f(&mut y_out, y_0);
        let mut z = vec![(0 as u64).into(); l2.len()];
        let (remainder2, div2) = vec_mat_mul_with_remainder_f(
            &y_out,
            l2.clone(),
            &mut z,
            y_0,
            l2_mat_0,
            z_0,
            &multiplier_l2,
        );
        let argmax_res = argmax_f(z.clone());
        let z_max = z[argmax_res];
        let beta = MpcField::<F, S>::pub_rand(rng);
        let rho = MpcField::<F, S>::pub_rand(rng);
        let mut powers_of_beta: Vec<MpcField::<F, S>> = vec![1u8.into()];
        let mut cur = beta;

        let l1_bls: Vec<MpcField::<F, S>> = convert_2d_vector_into_1d(l1.clone()).iter().map(|x| (*x).into()).collect();
        let l2_bls: Vec<MpcField::<F, S>> = convert_2d_vector_into_1d(l2.clone()).iter().map(|x| (*x).into()).collect();
        let mut commit_vec = Vec::<MpcField::<F, S>>::new();
        commit_vec.extend(x.clone());
        commit_vec.extend(l1_bls.clone());
        commit_vec.extend(l2_bls.clone());
        //commit_vec.extend(z_f.clone());
        let commit_poly = DensePolynomial::<MpcField::<F, S>>::from_coefficients_slice(&commit_vec);

        for _ in 0..commit_vec.len() {
            powers_of_beta.push(cur);
            cur *= &beta;
        } 

        let full_circuit = FullCircuitOpLv3KZGPolyClassification {
            x: x,
            l1: l1,
            l2: l2, 
            y: y,
            z: z,
            argmax_res: z_max,
            relu_output1: y_out,
            remainder1: remainder1,
            remainder2: remainder2,
            div1: div1,
            div2: div2,
            cmp_res,
            y_0_converted: y_0_converted,
            z_0_converted: z_0_converted,
            x_0: x_0,
            y_0: y_0,
            z_0: z_0,
            l1_mat_0: l1_mat_0,
            l2_mat_0: l2_mat_0,
            multiplier_l1: multiplier_l1,
            multiplier_l2: multiplier_l2,
            two_power_8,
            m_exp,
            zero,
            
            //KZG stuff
            powers_of_beta: powers_of_beta,
            rho: rho,
        };
        full_circuit
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
                let shallownet = read_shallownet();
                
                //println!("zero points x_0 {}  l1_out_0 {} l2_out_0 {}, l1_mat_0 {}, l2_mat_0 {}", x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0]);
                let preprocessing_timer = start_timer!(|| "Preprocessing");

                let circ_data = gen_circ_full_kzg_poly::<E>(
                    shallownet.x, 
                    shallownet.l1_mat, 
                    shallownet.l2_mat,
                    shallownet.x_0[0], 
                    shallownet.l1_output_0[0], 
                    shallownet.l2_output_0[0], 
                    shallownet.l1_mat_0[0], 
                    shallownet.l2_mat_0[0], 
                    shallownet.l1_mat_multiplier, 
                    shallownet.l2_mat_multiplier
                );

                end_timer!(preprocessing_timer);
                let params = generate_random_parameters::<E, _, _>(circ_data.clone(), rng).unwrap();

                let pvk = prepare_verifying_key::<E>(&params.vk);

                let timer = start_timer!(|| timer_label);
                let proof = create_random_proof::<E, _, _>(circ_data.clone(), &params, rng).unwrap();
 
                let zk_timer = start_timer!(|| "ZKP verification");
                let public_inputs = vec![circ_data.powers_of_beta[1], circ_data.rho];
                let _ = verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap();
                end_timer!(zk_timer);
                let kzg_timer = start_timer!(|| "KZG verification");
                // let vk = ark_poly_commit::kzg10::VerifierKey::<E> {
                //     g: pp.powers_of_g[0],
                //     gamma_g: pp.powers_of_gamma_g[&0],
                //     h: pp.h,
                //     beta_h: pp.beta_h,
                //     prepared_h: pp.prepared_h,
                //     prepared_beta_h: pp.prepared_beta_h,
                // };
                // let _ = ark_poly_commit::kzg10::KZG10::<
                //     E,
                //     ark_poly::univariate::DensePolynomial<E::Fr>,
                // >::check(&vk, &c, beta, rho, &Proof{w: pi.0, random_v: None})
                // .unwrap();
                end_timer!(kzg_timer);
            }

            fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str) {
                let mut rng = &mut test_rng();
                //let (x, l1_mat, l2_mat): (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) = read_shallownet_inputs_u8();
                let shallownet = read_shallownet();
                
                //println!("zero points x_0 {}  l1_out_0 {} l2_out_0 {}, l1_mat_0 {}, l2_mat_0 {}", x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0]);
                let preprocessing_timer = start_timer!(|| "Preprocessing");
            
                let circ_data = gen_circ_full_kzg_poly::<E>(
                    shallownet.x, 
                    shallownet.l1_mat, 
                    shallownet.l2_mat,
                    shallownet.x_0[0], 
                    shallownet.l1_output_0[0], 
                    shallownet.l2_output_0[0], 
                    shallownet.l1_mat_0[0], 
                    shallownet.l2_mat_0[0], 
                    shallownet.l1_mat_multiplier, 
                    shallownet.l2_mat_multiplier
                );
                
                let params = generate_random_parameters::<E, _, _>(circ_data.clone(), rng).unwrap();

                let pvk = prepare_verifying_key::<E>(&params.vk);
                let mpc_params = Reveal::from_public(params);

                let computation_timer = start_timer!(|| "MPC Proof");
                let preprocessing_timer = start_timer!(|| "Preprocessing");
                let circ_data = gen_circ_full_mpc(circ_data);
                end_timer!(preprocessing_timer);
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
                end_timer!(computation_timer);
                let zk_timer = start_timer!(|| "ZKP verification");
                let public_inputs = vec![circ_data.powers_of_beta[0], circ_data.rho].reveal();
                
                let _ = verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap();
                end_timer!(zk_timer);
                // let kzg_timer = start_timer!(|| "KZG verification");
                // let vk = ark_poly_commit::kzg10::VerifierKey::<E> {
                //     g: pp.powers_of_g[0],
                //     gamma_g: pp.powers_of_gamma_g[&0],
                //     h: pp.h,
                //     beta_h: pp.beta_h,
                //     prepared_h: pp.prepared_h,
                //     prepared_beta_h: pp.prepared_beta_h,
                // };
                // let res = ark_poly_commit::kzg10::KZG10::<
                //     E,
                //     ark_poly::univariate::DensePolynomial<E::Fr>,
                // >::check(&vk, &c, beta, rho, &Proof{w: pi.0, random_v: None})
                // .unwrap();
                // end_timer!(kzg_timer);
            }
        }
    }
}

mod cifar {
    use mpc_algebra::{FieldShare, MpcField};
    use zen_arkworks::lenet_circuit::LeNetCircuitU8OptimizedLv3PolyClassification;

    use super::*;

    fn gen_circ_full_kzg_poly<E: PairingEngine>(    
        x: Vec<Vec<Vec<Vec<u8>>>>,
        conv1_w: Vec<Vec<Vec<Vec<u8>>>>,
        conv2_w: Vec<Vec<Vec<Vec<u8>>>>,
        conv3_w: Vec<Vec<Vec<Vec<u8>>>>,
        fc1_w: Vec<Vec<u8>>,
        fc2_w: Vec<Vec<u8>>,
        x_0: Vec<u8>,
        conv1_output_0: Vec<u8>,
        conv2_output_0: Vec<u8>,
        conv3_output_0: Vec<u8>,
        fc1_output_0: Vec<u8>,
        fc2_output_0: Vec<u8>,
        conv1_weights_0: Vec<u8>,
        conv2_weights_0: Vec<u8>,
        conv3_weights_0: Vec<u8>,
        fc1_weights_0: Vec<u8>,
        fc2_weights_0: Vec<u8>,
        multiplier_conv1: Vec<f32>,
        multiplier_conv2: Vec<f32>,
        multiplier_conv3: Vec<f32>,
        multiplier_fc1: Vec<f32>,
        multiplier_fc2: Vec<f32>,

    ) -> (LeNetCircuitU8OptimizedLv3PolyClassification<E::Fr>) {//, Commitment<E>, Commitment<E>, UniversalParams<E>, <E as PairingEngine>::Fr, <E as PairingEngine>::Fr) {
        // y_0 and multiplier_l1 are both constants.
        let rng = &mut test_rng();
        let x_f: Vec<Vec<Vec<Vec<E::Fr>>>> = x.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect()).collect()).collect();
        let conv1_w_f: Vec<Vec<Vec<Vec<E::Fr>>>> = conv1_w.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect()).collect()).collect();
        let conv2_w_f: Vec<Vec<Vec<Vec<E::Fr>>>> = conv2_w.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect()).collect()).collect();
        let conv3_w_f: Vec<Vec<Vec<Vec<E::Fr>>>> = conv3_w.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect()).collect()).collect();
        let fc1_w_f: Vec<Vec<E::Fr>> = fc1_w.iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect();
        let fc2_w_f: Vec<Vec<E::Fr>> = fc2_w.iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect();
        let x_0_f: Vec<E::Fr> = x_0.iter().map(|x| (*x).into()).collect();
        let conv1_output_0_f: Vec<E::Fr> = conv1_output_0.iter().map(|x| (*x).into()).collect();
        let conv2_output_0_f: Vec<E::Fr> = conv2_output_0.iter().map(|x| (*x).into()).collect();
        let conv3_output_0_f: Vec<E::Fr> = conv3_output_0.iter().map(|x| (*x).into()).collect();
        let fc1_output_0_f: Vec<E::Fr> = fc1_output_0.iter().map(|x| (*x).into()).collect();
        let fc2_output_0_f: Vec<E::Fr> = fc2_output_0.iter().map(|x| (*x).into()).collect();
        let conv1_weights_0_f: Vec<E::Fr> = conv1_weights_0.iter().map(|x| (*x).into()).collect();
        let conv2_weights_0_f: Vec<E::Fr> = conv2_weights_0.iter().map(|x| (*x).into()).collect();
        let conv3_weights_0_f: Vec<E::Fr> = conv3_weights_0.iter().map(|x| (*x).into()).collect();
        let fc1_weights_0_f: Vec<E::Fr> = fc1_weights_0.iter().map(|x| (*x).into()).collect();
        let fc2_weights_0_f: Vec<E::Fr> = fc2_weights_0.iter().map(|x| (*x).into()).collect();
        let multiplier_conv1_f: Vec<E::Fr> = multiplier_conv1.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
        let multiplier_conv2_f: Vec<E::Fr> = multiplier_conv2.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
        let multiplier_conv3_f: Vec<E::Fr> = multiplier_conv3.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
        let multiplier_fc1_f: Vec<E::Fr> = multiplier_fc1.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
        let multiplier_fc2_f: Vec<E::Fr> = multiplier_fc2.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();

        // let (rho, c, pi) = kzg_proof(commit_poly, powers.clone(), beta);


        let z: Vec<Vec<E::Fr>> = lenet_circuit_forward_f(
            x_f.clone(),
            conv1_w_f.clone(),
            conv2_w_f.clone(),
            conv3_w_f.clone(),
            fc1_w_f.clone(),
            fc2_w_f.clone(),
            x_0_f[0],
            conv1_output_0_f[0],
            conv2_output_0_f[0],
            conv3_output_0_f[0],
            fc1_output_0_f[0],
            fc2_output_0_f[0], // which is also lenet output(z) zero point
            conv1_weights_0_f[0],
            conv2_weights_0_f[0],
            conv3_weights_0_f[0],
            fc1_weights_0_f[0],
            fc2_weights_0_f[0],
            multiplier_conv1_f.clone(),
            multiplier_conv2_f.clone(),
            multiplier_conv3_f.clone(),
            multiplier_fc1_f.clone(),
            multiplier_fc2_f.clone(),
        );

        let beta = E::Fr::rand(rng);
        let rho = E::Fr::rand(rng);
        let classification_res = argmax_f(z[0].clone());
        
        let full_circuit = LeNetCircuitU8OptimizedLv3PolyClassification{
            x: x_f.clone(),
            conv1_weights: conv1_w_f.clone(),
    
            conv2_weights: conv2_w_f.clone(),
    
            conv3_weights: conv3_w_f.clone(),
    
            fc1_weights: fc1_w_f.clone(),
    
            fc2_weights: fc2_w_f.clone(),
    
            z: z.clone(),
            rho: rho.clone(),
            beta: beta.clone(),
    
            //zero points for quantization.
            x_0: x_0_f[0],
            conv1_output_0: conv1_output_0_f[0],
            conv2_output_0: conv2_output_0_f[0],
            conv3_output_0: conv3_output_0_f[0],
            fc1_output_0: fc1_output_0_f[0],
            fc2_output_0: fc2_output_0_f[0], // which is also lenet output(z) zero point
    
            conv1_weights_0: conv1_weights_0_f[0],
            conv2_weights_0: conv2_weights_0_f[0],
            conv3_weights_0: conv3_weights_0_f[0],
            fc1_weights_0: fc1_weights_0_f[0],
            fc2_weights_0: fc2_weights_0_f[0],
    
            //multiplier for quantization
            multiplier_conv1: multiplier_conv1_f.clone(),
            multiplier_conv2: multiplier_conv2_f.clone(),
            multiplier_conv3: multiplier_conv3_f.clone(),
            multiplier_fc1: multiplier_fc1_f.clone(),
            multiplier_fc2: multiplier_fc2_f.clone(),
            
            argmax_res: classification_res,
        };

        full_circuit//, c, pi, pp, beta, rho)
    }

    fn gen_circ_full_mpc<F: PrimeField, S: FieldShare<F>>(    
        full_circuit: LeNetCircuitU8OptimizedLv3PolyClassification<F>
    ) -> LeNetCircuitU8OptimizedLv3PolyClassification<MpcField<F, S>> {

        let rng = &mut test_rng();
        let x_f: Vec<Vec<Vec<Vec<MpcField<F, S>>>>> = full_circuit.x.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| MpcField::<F, S>::from_public(*x)).collect()).collect()).collect()).collect();
        let conv1_w_f: Vec<Vec<Vec<Vec<MpcField<F, S>>>>> = full_circuit.conv1_weights.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect()).collect()).collect()).collect();
        let conv2_w_f: Vec<Vec<Vec<Vec<MpcField<F, S>>>>> = full_circuit.conv2_weights.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect()).collect()).collect()).collect();
        let conv3_w_f: Vec<Vec<Vec<Vec<MpcField<F, S>>>>> = full_circuit.conv3_weights.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect()).collect()).collect()).collect();
        let fc1_w_f: Vec<Vec<MpcField<F, S>>> = full_circuit.fc1_weights.iter().map(|x| (*x).iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect()).collect();
        let fc2_w_f: Vec<Vec<MpcField<F, S>>> = full_circuit.fc2_weights.iter().map(|x| (*x).iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect()).collect();
        let x_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.x_0);
        let conv1_output_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.conv1_output_0);
        let conv2_output_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.conv2_output_0);
        let conv3_output_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.conv3_output_0);
        let fc1_output_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.fc1_output_0);
        let fc2_output_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.fc2_output_0);
        let conv1_weights_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.conv1_weights_0);
        let conv2_weights_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.conv2_weights_0);
        let conv3_weights_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.conv3_weights_0);
        let fc1_weights_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.fc1_weights_0);
        let fc2_weights_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.fc2_weights_0);

        let multiplier_conv1_f: Vec<MpcField<F, S>> = full_circuit.multiplier_conv1.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let multiplier_conv2_f: Vec<MpcField<F, S>> = full_circuit.multiplier_conv2.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let multiplier_conv3_f: Vec<MpcField<F, S>> = full_circuit.multiplier_conv3.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let multiplier_fc1_f: Vec<MpcField<F, S>> = full_circuit.multiplier_fc1.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let multiplier_fc2_f: Vec<MpcField<F, S>> = full_circuit.multiplier_fc2.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();

 
        let z = lenet_circuit_forward_f(
            x_f.clone(),
            conv1_w_f.clone(),
            conv2_w_f.clone(),
            conv3_w_f.clone(),
            fc1_w_f.clone(),
            fc2_w_f.clone(),
            x_0_f,
            conv1_output_0_f,
            conv2_output_0_f,
            conv3_output_0_f,
            fc1_output_0_f,
            fc2_output_0_f, // which is also lenet output(z) zero point
            conv1_weights_0_f,
            conv2_weights_0_f,
            conv3_weights_0_f,
            fc1_weights_0_f,
            fc2_weights_0_f,
            multiplier_conv1_f.clone(),
            multiplier_conv2_f.clone(),
            multiplier_conv3_f.clone(),
            multiplier_fc1_f.clone(),
            multiplier_fc2_f.clone(),
        );

        let beta = MpcField::<F, S>::rand(rng);
        let rho = MpcField::<F, S>::rand(rng);
        let classification_res = argmax_f(z[0].clone());

        let full_circuit = LeNetCircuitU8OptimizedLv3PolyClassification {
            x: x_f.clone(),
            conv1_weights: conv1_w_f.clone(),
    
            conv2_weights: conv2_w_f.clone(),
    
            conv3_weights: conv3_w_f.clone(),
    
            fc1_weights: fc1_w_f.clone(),
    
            fc2_weights: fc2_w_f.clone(),
    
            z: z.clone(),
            rho: rho.clone(),
            beta: beta.clone(),
    
            //zero points for quantization.
            x_0: x_0_f,
            conv1_output_0: conv1_output_0_f,
            conv2_output_0: conv2_output_0_f,
            conv3_output_0: conv3_output_0_f,
            fc1_output_0: fc1_output_0_f,
            fc2_output_0: fc2_output_0_f, // which is also lenet output(z) zero point
    
            conv1_weights_0: conv1_weights_0_f,
            conv2_weights_0: conv2_weights_0_f,
            conv3_weights_0: conv3_weights_0_f,
            fc1_weights_0: fc1_weights_0_f,
            fc2_weights_0: fc2_weights_0_f,
    
            //multiplier for quantization
            multiplier_conv1: multiplier_conv1_f.clone(),
            multiplier_conv2: multiplier_conv2_f.clone(),
            multiplier_conv3: multiplier_conv3_f.clone(),
            multiplier_fc1: multiplier_fc1_f.clone(),
            multiplier_fc2: multiplier_fc2_f.clone(),
            
            argmax_res: classification_res,
        };
        full_circuit
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
                let cifar = read_cifar();
                
                //println!("zero points x_0 {}  l1_out_0 {} l2_out_0 {}, l1_mat_0 {}, l2_mat_0 {}", x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0]);
                let preprocessing_timer = start_timer!(|| "Preprocessing");

                let circ_data = gen_circ_full_kzg_poly::<E>(
                    cifar.x,
                    cifar.conv1_w,
                    cifar.conv2_w,
                    cifar.conv3_w,
                    cifar.fc1_w,
                    cifar.fc2_w,
                    cifar.x_0,
                    cifar.conv1_output_0,
                    cifar.conv2_output_0,
                    cifar.conv3_output_0,
                    cifar.fc1_output_0,
                    cifar.fc2_output_0,
                    cifar.conv1_weights_0,
                    cifar.conv2_weights_0,
                    cifar.conv3_weights_0,
                    cifar.fc1_weights_0,
                    cifar.fc2_weights_0,
                    cifar.multiplier_conv1,
                    cifar.multiplier_conv2,
                    cifar.multiplier_conv3,
                    cifar.multiplier_fc1,
                    cifar.multiplier_fc2,
                );

                end_timer!(preprocessing_timer);
                let params = generate_random_parameters::<E, _, _>(circ_data.clone(), rng).unwrap();

                let pvk = prepare_verifying_key::<E>(&params.vk);

                let timer = start_timer!(|| timer_label);
                let proof = create_random_proof::<E, _, _>(circ_data.clone(), &params, rng).unwrap();
 
                let zk_timer = start_timer!(|| "ZKP verification");
                let public_inputs = vec![circ_data.beta, circ_data.rho];
                let _ = verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap();
                end_timer!(zk_timer);
                let kzg_timer = start_timer!(|| "KZG verification");
                // let vk = ark_poly_commit::kzg10::VerifierKey::<E> {
                //     g: pp.powers_of_g[0],
                //     gamma_g: pp.powers_of_gamma_g[&0],
                //     h: pp.h,
                //     beta_h: pp.beta_h,
                //     prepared_h: pp.prepared_h,
                //     prepared_beta_h: pp.prepared_beta_h,
                // };
                // let _ = ark_poly_commit::kzg10::KZG10::<
                //     E,
                //     ark_poly::univariate::DensePolynomial<E::Fr>,
                // >::check(&vk, &c, beta, rho, &Proof{w: pi.0, random_v: None})
                // .unwrap();
                end_timer!(kzg_timer);
            }

            fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str) {
                let mut rng = &mut test_rng();
                //let (x, l1_mat, l2_mat): (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) = read_shallownet_inputs_u8();
                let cifar = read_cifar();
                
                //println!("zero points x_0 {}  l1_out_0 {} l2_out_0 {}, l1_mat_0 {}, l2_mat_0 {}", x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0]);
                let preprocessing_timer = start_timer!(|| "Preprocessing");
            
                let circ_data = gen_circ_full_kzg_poly::<E>(
                    cifar.x,
                    cifar.conv1_w,
                    cifar.conv2_w,
                    cifar.conv3_w,
                    cifar.fc1_w,
                    cifar.fc2_w,
                    cifar.x_0,
                    cifar.conv1_output_0,
                    cifar.conv2_output_0,
                    cifar.conv3_output_0,
                    cifar.fc1_output_0,
                    cifar.fc2_output_0,
                    cifar.conv1_weights_0,
                    cifar.conv2_weights_0,
                    cifar.conv3_weights_0,
                    cifar.fc1_weights_0,
                    cifar.fc2_weights_0,
                    cifar.multiplier_conv1,
                    cifar.multiplier_conv2,
                    cifar.multiplier_conv3,
                    cifar.multiplier_fc1,
                    cifar.multiplier_fc2,
                );
                
                let params = generate_random_parameters::<E, _, _>(circ_data.clone(), rng).unwrap();

                let pvk = prepare_verifying_key::<E>(&params.vk);
                let mpc_params = Reveal::from_public(params);

                let computation_timer = start_timer!(|| "MPC Proof");
                let preprocessing_timer = start_timer!(|| "Preprocessing");
                let circ_data = gen_circ_full_mpc(circ_data);
                end_timer!(preprocessing_timer);
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
                end_timer!(computation_timer);
                let zk_timer = start_timer!(|| "ZKP verification");
                let public_inputs = vec![circ_data.beta, circ_data.rho].reveal();
                
                let _ = verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap();
                end_timer!(zk_timer);
                // let kzg_timer = start_timer!(|| "KZG verification");
                // let vk = ark_poly_commit::kzg10::VerifierKey::<E> {
                //     g: pp.powers_of_g[0],
                //     gamma_g: pp.powers_of_gamma_g[&0],
                //     h: pp.h,
                //     beta_h: pp.beta_h,
                //     prepared_h: pp.prepared_h,
                //     prepared_beta_h: pp.prepared_beta_h,
                // };
                // let res = ark_poly_commit::kzg10::KZG10::<
                //     E,
                //     ark_poly::univariate::DensePolynomial<E::Fr>,
                // >::check(&vk, &c, beta, rho, &Proof{w: pi.0, random_v: None})
                // .unwrap();
                // end_timer!(kzg_timer);
            }
        }
    }
}

mod face {
    use mpc_algebra::{FieldShare, MpcField};
    use zen_arkworks::lenet_circuit::LeNetCircuitU8OptimizedLv3PolyRecognition;

    use super::*;

    fn gen_circ_full_kzg_poly<E: PairingEngine>(    
        x: Vec<Vec<Vec<Vec<u8>>>>,
        conv1_w: Vec<Vec<Vec<Vec<u8>>>>,
        conv2_w: Vec<Vec<Vec<Vec<u8>>>>,
        conv3_w: Vec<Vec<Vec<Vec<u8>>>>,
        fc1_w: Vec<Vec<u8>>,
        fc2_w: Vec<Vec<u8>>,
        x_0: Vec<u8>,
        conv1_output_0: Vec<u8>,
        conv2_output_0: Vec<u8>,
        conv3_output_0: Vec<u8>,
        fc1_output_0: Vec<u8>,
        fc2_output_0: Vec<u8>,
        conv1_weights_0: Vec<u8>,
        conv2_weights_0: Vec<u8>,
        conv3_weights_0: Vec<u8>,
        fc1_weights_0: Vec<u8>,
        fc2_weights_0: Vec<u8>,
        multiplier_conv1: Vec<f32>,
        multiplier_conv2: Vec<f32>,
        multiplier_conv3: Vec<f32>,
        multiplier_fc1: Vec<f32>,
        multiplier_fc2: Vec<f32>,
        person_feature_vector: Vec<u8>

    ) -> (LeNetCircuitU8OptimizedLv3PolyRecognition<E::Fr>) {//, Commitment<E>, Commitment<E>, UniversalParams<E>, <E as PairingEngine>::Fr, <E as PairingEngine>::Fr) {
        // y_0 and multiplier_l1 are both constants.
        let rng = &mut test_rng();
        let x_f: Vec<Vec<Vec<Vec<E::Fr>>>> = x.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect()).collect()).collect();
        let conv1_w_f: Vec<Vec<Vec<Vec<E::Fr>>>> = conv1_w.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect()).collect()).collect();
        let conv2_w_f: Vec<Vec<Vec<Vec<E::Fr>>>> = conv2_w.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect()).collect()).collect();
        let conv3_w_f: Vec<Vec<Vec<Vec<E::Fr>>>> = conv3_w.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect()).collect()).collect();
        let fc1_w_f: Vec<Vec<E::Fr>> = fc1_w.iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect();
        let fc2_w_f: Vec<Vec<E::Fr>> = fc2_w.iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect();
        let x_0_f: Vec<E::Fr> = x_0.iter().map(|x| (*x).into()).collect();
        let conv1_output_0_f: Vec<E::Fr> = conv1_output_0.iter().map(|x| (*x).into()).collect();
        let conv2_output_0_f: Vec<E::Fr> = conv2_output_0.iter().map(|x| (*x).into()).collect();
        let conv3_output_0_f: Vec<E::Fr> = conv3_output_0.iter().map(|x| (*x).into()).collect();
        let fc1_output_0_f: Vec<E::Fr> = fc1_output_0.iter().map(|x| (*x).into()).collect();
        let fc2_output_0_f: Vec<E::Fr> = fc2_output_0.iter().map(|x| (*x).into()).collect();
        let conv1_weights_0_f: Vec<E::Fr> = conv1_weights_0.iter().map(|x| (*x).into()).collect();
        let conv2_weights_0_f: Vec<E::Fr> = conv2_weights_0.iter().map(|x| (*x).into()).collect();
        let conv3_weights_0_f: Vec<E::Fr> = conv3_weights_0.iter().map(|x| (*x).into()).collect();
        let fc1_weights_0_f: Vec<E::Fr> = fc1_weights_0.iter().map(|x| (*x).into()).collect();
        let fc2_weights_0_f: Vec<E::Fr> = fc2_weights_0.iter().map(|x| (*x).into()).collect();
        let multiplier_conv1_f: Vec<E::Fr> = multiplier_conv1.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
        let multiplier_conv2_f: Vec<E::Fr> = multiplier_conv2.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
        let multiplier_conv3_f: Vec<E::Fr> = multiplier_conv3.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
        let multiplier_fc1_f: Vec<E::Fr> = multiplier_fc1.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
        let multiplier_fc2_f: Vec<E::Fr> = multiplier_fc2.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
        let person_feature_vector_f: Vec<E::Fr> = person_feature_vector.iter().map(|x| (*x).into()).collect();
        // let (rho, c, pi) = kzg_proof(commit_poly, powers.clone(), beta);


        let z: Vec<Vec<E::Fr>> = lenet_circuit_forward_f(
            x_f.clone(),
            conv1_w_f.clone(),
            conv2_w_f.clone(),
            conv3_w_f.clone(),
            fc1_w_f.clone(),
            fc2_w_f.clone(),
            x_0_f[0],
            conv1_output_0_f[0],
            conv2_output_0_f[0],
            conv3_output_0_f[0],
            fc1_output_0_f[0],
            fc2_output_0_f[0], // which is also lenet output(z) zero point
            conv1_weights_0_f[0],
            conv2_weights_0_f[0],
            conv3_weights_0_f[0],
            fc1_weights_0_f[0],
            fc2_weights_0_f[0],
            multiplier_conv1_f.clone(),
            multiplier_conv2_f.clone(),
            multiplier_conv3_f.clone(),
            multiplier_fc1_f.clone(),
            multiplier_fc2_f.clone(),
        );

        let beta = E::Fr::rand(rng);
        let rho = E::Fr::rand(rng);
        let is_the_same_person: bool =
        cosine_similarity_f(z[0].clone(), person_feature_vector_f.clone(), E::Fr::from(50 as u8));
        
        let full_circuit = LeNetCircuitU8OptimizedLv3PolyRecognition{
            x: x_f.clone(),
            conv1_weights: conv1_w_f.clone(),
    
            conv2_weights: conv2_w_f.clone(),
    
            conv3_weights: conv3_w_f.clone(),
    
            fc1_weights: fc1_w_f.clone(),
    
            fc2_weights: fc2_w_f.clone(),
    
            z: z.clone(),
            rho: rho.clone(),
            beta: beta.clone(),
    
            //zero points for quantization.
            x_0: x_0_f[0],
            conv1_output_0: conv1_output_0_f[0],
            conv2_output_0: conv2_output_0_f[0],
            conv3_output_0: conv3_output_0_f[0],
            fc1_output_0: fc1_output_0_f[0],
            fc2_output_0: fc2_output_0_f[0], // which is also lenet output(z) zero point
    
            conv1_weights_0: conv1_weights_0_f[0],
            conv2_weights_0: conv2_weights_0_f[0],
            conv3_weights_0: conv3_weights_0_f[0],
            fc1_weights_0: fc1_weights_0_f[0],
            fc2_weights_0: fc2_weights_0_f[0],
    
            //multiplier for quantization
            multiplier_conv1: multiplier_conv1_f.clone(),
            multiplier_conv2: multiplier_conv2_f.clone(),
            multiplier_conv3: multiplier_conv3_f.clone(),
            multiplier_fc1: multiplier_fc1_f.clone(),
            multiplier_fc2: multiplier_fc2_f.clone(),
            
            person_feature_vector: person_feature_vector_f,
            threshold: E::Fr::from(50 as u8),
            result: is_the_same_person
        };

        full_circuit//, c, pi, pp, beta, rho)
    }

    fn gen_circ_full_mpc<F: PrimeField, S: FieldShare<F>>(    
        full_circuit: LeNetCircuitU8OptimizedLv3PolyRecognition<F>
    ) -> LeNetCircuitU8OptimizedLv3PolyRecognition<MpcField<F, S>> {

        let rng = &mut test_rng();
        let x_f: Vec<Vec<Vec<Vec<MpcField<F, S>>>>> = full_circuit.x.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| MpcField::<F, S>::from_public(*x)).collect()).collect()).collect()).collect();
        let conv1_w_f: Vec<Vec<Vec<Vec<MpcField<F, S>>>>> = full_circuit.conv1_weights.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect()).collect()).collect()).collect();
        let conv2_w_f: Vec<Vec<Vec<Vec<MpcField<F, S>>>>> = full_circuit.conv2_weights.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect()).collect()).collect()).collect();
        let conv3_w_f: Vec<Vec<Vec<Vec<MpcField<F, S>>>>> = full_circuit.conv3_weights.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect()).collect()).collect()).collect();
        let fc1_w_f: Vec<Vec<MpcField<F, S>>> = full_circuit.fc1_weights.iter().map(|x| (*x).iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect()).collect();
        let fc2_w_f: Vec<Vec<MpcField<F, S>>> = full_circuit.fc2_weights.iter().map(|x| (*x).iter().map(|x| MpcField::<F, S>::from_add_shared(*x)).collect()).collect();
        let x_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.x_0);
        let conv1_output_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.conv1_output_0);
        let conv2_output_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.conv2_output_0);
        let conv3_output_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.conv3_output_0);
        let fc1_output_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.fc1_output_0);
        let fc2_output_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.fc2_output_0);
        let conv1_weights_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.conv1_weights_0);
        let conv2_weights_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.conv2_weights_0);
        let conv3_weights_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.conv3_weights_0);
        let fc1_weights_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.fc1_weights_0);
        let fc2_weights_0_f: MpcField<F, S> = MpcField::<F, S>::from_public(full_circuit.fc2_weights_0);

        let multiplier_conv1_f: Vec<MpcField<F, S>> = full_circuit.multiplier_conv1.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let multiplier_conv2_f: Vec<MpcField<F, S>> = full_circuit.multiplier_conv2.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let multiplier_conv3_f: Vec<MpcField<F, S>> = full_circuit.multiplier_conv3.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let multiplier_fc1_f: Vec<MpcField<F, S>> = full_circuit.multiplier_fc1.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let multiplier_fc2_f: Vec<MpcField<F, S>> = full_circuit.multiplier_fc2.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
        let person_feature_vector_f: Vec<MpcField<F, S>> = full_circuit.person_feature_vector.iter().map(|x| MpcField::<F, S>::from_public(*x)).collect();
 
        let z = lenet_circuit_forward_f(
            x_f.clone(),
            conv1_w_f.clone(),
            conv2_w_f.clone(),
            conv3_w_f.clone(),
            fc1_w_f.clone(),
            fc2_w_f.clone(),
            x_0_f,
            conv1_output_0_f,
            conv2_output_0_f,
            conv3_output_0_f,
            fc1_output_0_f,
            fc2_output_0_f, // which is also lenet output(z) zero point
            conv1_weights_0_f,
            conv2_weights_0_f,
            conv3_weights_0_f,
            fc1_weights_0_f,
            fc2_weights_0_f,
            multiplier_conv1_f.clone(),
            multiplier_conv2_f.clone(),
            multiplier_conv3_f.clone(),
            multiplier_fc1_f.clone(),
            multiplier_fc2_f.clone(),
        );

        let beta = MpcField::<F, S>::rand(rng);
        let rho = MpcField::<F, S>::rand(rng);
        let is_the_same_person: bool =
        cosine_similarity_f(z[0].clone(), person_feature_vector_f.clone(), MpcField::<F, S>::from(50 as u8));

        let full_circuit = LeNetCircuitU8OptimizedLv3PolyRecognition {
            x: x_f.clone(),
            conv1_weights: conv1_w_f.clone(),
    
            conv2_weights: conv2_w_f.clone(),
    
            conv3_weights: conv3_w_f.clone(),
    
            fc1_weights: fc1_w_f.clone(),
    
            fc2_weights: fc2_w_f.clone(),
    
            z: z.clone(),
            rho: rho.clone(),
            beta: beta.clone(),
    
            //zero points for quantization.
            x_0: x_0_f,
            conv1_output_0: conv1_output_0_f,
            conv2_output_0: conv2_output_0_f,
            conv3_output_0: conv3_output_0_f,
            fc1_output_0: fc1_output_0_f,
            fc2_output_0: fc2_output_0_f, // which is also lenet output(z) zero point
    
            conv1_weights_0: conv1_weights_0_f,
            conv2_weights_0: conv2_weights_0_f,
            conv3_weights_0: conv3_weights_0_f,
            fc1_weights_0: fc1_weights_0_f,
            fc2_weights_0: fc2_weights_0_f,
    
            //multiplier for quantization
            multiplier_conv1: multiplier_conv1_f.clone(),
            multiplier_conv2: multiplier_conv2_f.clone(),
            multiplier_conv3: multiplier_conv3_f.clone(),
            multiplier_fc1: multiplier_fc1_f.clone(),
            multiplier_fc2: multiplier_fc2_f.clone(),
            
            person_feature_vector: person_feature_vector_f,
            threshold: MpcField::<F, S>::from(50 as u8),
            result: is_the_same_person
        };
        full_circuit
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
                let face = read_face();
                
                //println!("zero points x_0 {}  l1_out_0 {} l2_out_0 {}, l1_mat_0 {}, l2_mat_0 {}", x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0]);
                let preprocessing_timer = start_timer!(|| "Preprocessing");

                let circ_data = gen_circ_full_kzg_poly::<E>(
                    face.x,
                    face.conv1_w,
                    face.conv2_w,
                    face.conv3_w,
                    face.fc1_w,
                    face.fc2_w,
                    face.x_0,
                    face.conv1_output_0,
                    face.conv2_output_0,
                    face.conv3_output_0,
                    face.fc1_output_0,
                    face.fc2_output_0,
                    face.conv1_weights_0,
                    face.conv2_weights_0,
                    face.conv3_weights_0,
                    face.fc1_weights_0,
                    face.fc2_weights_0,
                    face.multiplier_conv1,
                    face.multiplier_conv2,
                    face.multiplier_conv3,
                    face.multiplier_fc1,
                    face.multiplier_fc2,
                    face.person_feature_vector,
                );

                end_timer!(preprocessing_timer);
                let params = generate_random_parameters::<E, _, _>(circ_data.clone(), rng).unwrap();

                let pvk = prepare_verifying_key::<E>(&params.vk);

                let timer = start_timer!(|| timer_label);
                let proof = create_random_proof::<E, _, _>(circ_data.clone(), &params, rng).unwrap();
 
                let zk_timer = start_timer!(|| "ZKP verification");
                let public_inputs = vec![circ_data.beta, circ_data.rho];
                let _ = verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap();
                end_timer!(zk_timer);
                let kzg_timer = start_timer!(|| "KZG verification");
                // let vk = ark_poly_commit::kzg10::VerifierKey::<E> {
                //     g: pp.powers_of_g[0],
                //     gamma_g: pp.powers_of_gamma_g[&0],
                //     h: pp.h,
                //     beta_h: pp.beta_h,
                //     prepared_h: pp.prepared_h,
                //     prepared_beta_h: pp.prepared_beta_h,
                // };
                // let _ = ark_poly_commit::kzg10::KZG10::<
                //     E,
                //     ark_poly::univariate::DensePolynomial<E::Fr>,
                // >::check(&vk, &c, beta, rho, &Proof{w: pi.0, random_v: None})
                // .unwrap();
                end_timer!(kzg_timer);
            }

            fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str) {
                let mut rng = &mut test_rng();
                //let (x, l1_mat, l2_mat): (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) = read_shallownet_inputs_u8();
                let face = read_face();
                
                //println!("zero points x_0 {}  l1_out_0 {} l2_out_0 {}, l1_mat_0 {}, l2_mat_0 {}", x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0]);
                let preprocessing_timer = start_timer!(|| "Preprocessing");
            
                let circ_data = gen_circ_full_kzg_poly::<E>(
                    face.x,
                    face.conv1_w,
                    face.conv2_w,
                    face.conv3_w,
                    face.fc1_w,
                    face.fc2_w,
                    face.x_0,
                    face.conv1_output_0,
                    face.conv2_output_0,
                    face.conv3_output_0,
                    face.fc1_output_0,
                    face.fc2_output_0,
                    face.conv1_weights_0,
                    face.conv2_weights_0,
                    face.conv3_weights_0,
                    face.fc1_weights_0,
                    face.fc2_weights_0,
                    face.multiplier_conv1,
                    face.multiplier_conv2,
                    face.multiplier_conv3,
                    face.multiplier_fc1,
                    face.multiplier_fc2,
                    face.person_feature_vector
                );
                
                let params = generate_random_parameters::<E, _, _>(circ_data.clone(), rng).unwrap();

                let pvk = prepare_verifying_key::<E>(&params.vk);
                let mpc_params = Reveal::from_public(params);

                let computation_timer = start_timer!(|| "MPC Proof");
                let preprocessing_timer = start_timer!(|| "Preprocessing");
                let circ_data = gen_circ_full_mpc(circ_data);
                end_timer!(preprocessing_timer);
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
                end_timer!(computation_timer);
                let zk_timer = start_timer!(|| "ZKP verification");
                let public_inputs = vec![circ_data.beta, circ_data.rho].reveal();
                
                let _ = verify_proof(&pvk, &proof, public_inputs.as_slice()).unwrap();
                end_timer!(zk_timer);
                // let kzg_timer = start_timer!(|| "KZG verification");
                // let vk = ark_poly_commit::kzg10::VerifierKey::<E> {
                //     g: pp.powers_of_g[0],
                //     gamma_g: pp.powers_of_gamma_g[&0],
                //     h: pp.h,
                //     beta_h: pp.beta_h,
                //     prepared_h: pp.prepared_h,
                //     prepared_beta_h: pp.prepared_beta_h,
                // };
                // let res = ark_poly_commit::kzg10::KZG10::<
                //     E,
                //     ark_poly::univariate::DensePolynomial<E::Fr>,
                // >::check(&vk, &c, beta, rho, &Proof{w: pi.0, random_v: None})
                // .unwrap();
                // end_timer!(kzg_timer);
            }
        }
    }
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
        match self.alg {
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
        Shallownet,
        Face,
        Cifar
    }
}

arg_enum! {
    #[derive(PartialEq, Debug, Clone, Copy)]
    pub enum ProofSystem {
        Groth16,
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
        ProofSystem::Groth16 => {
            match opt.computation {
                Computation::Shallownet => opt.field.run::<ark_bls12_377::Bls12_377, _>(
                    opt.computation,
                    opt.computation_size,
                    shallownet::groth::Groth16Bench,
                    TIMED_SECTION_LABEL,
                ),
                Computation::Face => opt.field.run::<ark_bls12_377::Bls12_377, _>(
                    opt.computation,
                    opt.computation_size,
                    shallownet::groth::Groth16Bench,
                    TIMED_SECTION_LABEL,
                ),
                Computation::Cifar => opt.field.run::<ark_bls12_377::Bls12_377, _>(
                    opt.computation,
                    opt.computation_size,
                    cifar::groth::Groth16Bench,
                    TIMED_SECTION_LABEL,
                ),
            }
        }
    }
}
