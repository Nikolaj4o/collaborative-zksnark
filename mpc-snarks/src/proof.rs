#![allow(dead_code)]
#![allow(unused_imports)]
use mpc_snarks::*;
use ark_ec::{PairingEngine, AffineCurve};
use ark_ff::{PrimeField, Field, UniformRand};
use ark_groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable, Namespace, ConstraintSystem},
};
use ark_std::test_rng;
use ark_std::{end_timer, start_timer};
use blake2::Blake2s;
use clap::arg_enum;
use log::debug;
use num::bigint::BigUint;
use mpc_algebra::{channel, MpcPairingEngine, PairingShare, Reveal};
use mpc_net::{MpcMultiNet, MpcNet, MpcTwoNet};
use structopt::StructOpt;
use ark_r1cs_std::{prelude::{AllocVar, AllocationMode, Boolean, EqGadget}, R1CSVar, uint8::UInt8, ToBitsGadget};
use ark_sponge::{ CryptographicSponge, FieldBasedCryptographicSponge, poseidon::PoseidonSponge};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Polynomial, UVPolynomial};

use std::path::PathBuf;

mod groth;
mod marlin;
mod silly;

const TIMED_SECTION_LABEL: &str = "timed section";

trait SnarkBench {
    fn local<E: PairingEngine>(n: usize, timer_label: &str);
    fn ark_local<E: PairingEngine>(_n: usize, _timer_label: &str) {
        unimplemented!("ark benchmark for {}", std::any::type_name::<Self>())
    }
    fn mpc<E: PairingEngine, S: PairingShare<E>>(n: usize, timer_label: &str) {
        unimplemented!("mpc benchmark for {}", std::any::type_name::<Self>())
    }
}

// 
mod shallownet_mnist {
    const M_EXP: u32 = 22;
    use super::*;
    pub mod groth {
        use std::borrow::Cow;
        use std::ops::{Deref, Div};

        use super::*;
        use crate::ark_groth16::{generate_random_parameters, prepare_verifying_key, verify_proof};
        use crate::groth::prover::create_random_proof;

        pub struct Groth16Bench;
        use std::time::Instant;
        use ark_ec::ProjectiveCurve;
        use ark_ec::bls12::{Bls12, G1Prepared, G2Prepared};
        use ark_ec::bw6::BW6;
        use ark_ec::group::Group;
        use ark_ec::short_weierstrass_jacobian::GroupAffine;
        use ark_poly_commit::ipa_pc::UniversalParams;
        use ark_poly_commit::kzg10::Powers;
        use ark_sponge::Absorb;
        use mpc_net::multi;
        use num::{BigInt, Integer};
        use zen_arkworks::*;
        use ark_serialize::CanonicalDeserialize;
        use ark_serialize::CanonicalSerialize;
    
        use ark_ff::{UniformRand, BigInteger, BigInteger256, FpParameters};
        // use ark_groth16::*;
        use ark_crypto_primitives::{commitment::pedersen::Randomness, SNARK};
        use ark_bls12_381::Bls12_381;
        use zen_arkworks::full_circuit::*;
        use zen_arkworks::psponge::{poseidon_parameters_for_test_s, SPNGParam, SPNGOutput};
        use zen_arkworks::vanilla::*;
        use ark_std::test_rng;

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

        fn gen_circ_full_poseidon<E: PairingEngine>(    
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
        ) -> FullCircuitOpLv3PoseidonClassification<<E as ark_ec::PairingEngine>::Fr> where <E as ark_ec::PairingEngine>::Fr: Absorb {
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
            let parameter : SPNGParam<E::Fr> = poseidon_parameters_for_test_s();
            let mut commit_sponge = PoseidonSponge::< >::new(&parameter);
            let l1_f_1d = convert_2d_vector_into_1d(l1_f.clone());
            let l2_f_1d = convert_2d_vector_into_1d(l2_f.clone());
            let mut commit_vec = Vec::<E::Fr>::new();
            commit_vec.extend(x_f.clone());
            commit_vec.extend(l1_f_1d);
            commit_vec.extend(l2_f_1d);
            commit_vec.extend(z_f.clone());

            commit_sponge.absorb(&commit_vec);
            //let x_squeeze: Vec<E::Fr> = x_sponge.squeeze_native_field_elements(1);//x.clone().len() / 32 + 1);
            //commit_sponge.absorb(&l1_f_1d);
            //let l1_squeeze: Vec<E::Fr> = l1_sponge.squeeze_native_field_elements(1);//l1_f_1d.len() / 32 + 1);
            //commit_sponge.absorb(&l2_f_1d);
            //let l2_squeeze: Vec<E::Fr> = l2_sponge.squeeze_native_field_elements(1);//l2_f_1d.len() / 32 + 1);
            //commit_sponge.absorb(&z_f);
            let commit_squeeze: Vec<E::Fr> = commit_sponge.squeeze_native_field_elements(1);//z.clone().len() / 32 + 1);

            let full_circuit = FullCircuitOpLv3PoseidonClassification {
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
                
                //poseidon stuff
                params: parameter,
                commit: commit_squeeze,
            };
            full_circuit
        }

        fn gen_circ_full_kzg<E: PairingEngine>(    
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
        ) -> FullCircuitOpLv3KZGClassification<E::Fr> {
            type BlsSF = <ark_bls12_377::Bls12_377 as PairingEngine>::Fr;
            type BwSF = <ark_bw6_761::BW6_761 as PairingEngine>::Fr;
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

            let l1_bls: Vec<BlsSF> = convert_2d_vector_into_1d(l1).iter().map(|x| (*x).into()).collect();
            let l2_bls: Vec<BlsSF> = convert_2d_vector_into_1d(l2).iter().map(|x| (*x).into()).collect();

            let l1_poly = DensePolynomial::<BlsSF>::from_coefficients_slice(&l1_bls);
            let l2_poly = DensePolynomial::<BlsSF>::from_coefficients_slice(&l2_bls);      

            let rng = &mut ark_std::test_rng();
            let pp = ark_poly_commit::kzg10::KZG10::<
                ark_bls12_377::Bls12_377,
                DensePolynomial<BlsSF>,
            >::setup(l1_bls.len() - 1, true, rng)
            .unwrap();

            let powers_of_gamma_g = (0..l1_bls.len())
                .map(|i| pp.powers_of_gamma_g[&i])
                .collect::<Vec<_>>();

            let powers = ark_poly_commit::kzg10::Powers::<ark_bls12_377::Bls12_377> {
                powers_of_g: Cow::Borrowed(&pp.powers_of_g),
                powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
            };

            let beta = BlsSF::rand(rng);
            let mut powers_of_beta: Vec<BlsSF> = vec![1u8.into()];
            let mut cur = beta;

            for _ in 0..l1_bls.len() {
                powers_of_beta.push(cur);
                cur *= &beta;
            }

            let betas_bi: Vec<BigUint> = powers_of_beta.iter().map(|x| BigUint::from_bytes_le((*x).into_repr().to_bytes_le().as_slice())).collect();
            let l1_bi: Vec<BigUint> = l1_bls.iter().map(|x| BigUint::from_bytes_le((*x).into_repr().to_bytes_le().as_slice())).collect();
            let l2_bi: Vec<BigUint> = l2_bls.iter().map(|x| BigUint::from_bytes_le((*x).into_repr().to_bytes_le().as_slice())).collect();  
            
            let l1_beta: Vec<BigUint> = betas_bi.iter().zip(l1_bi.iter()).map(|(a,b)| a*b).collect();
            let l2_beta: Vec<BigUint> = betas_bi.iter().zip(l2_bi.iter()).map(|(a,b)| a*b).collect();
            let bls_modulus: BigInteger256 = <BlsSF as PrimeField>::Params::MODULUS;
            let bls_modulus_bwsf = BwSF::from_le_bytes_mod_order(bls_modulus.to_bytes_le().as_slice());
            let bls_modulus_bi =  BigUint::from_bytes_le(bls_modulus.to_bytes_le().as_slice());

            let l1_beta_qr_bi: Vec<(BigUint, BigUint)> = l1_beta.iter().map(|x| x.div_mod_floor(&bls_modulus_bi)).collect();
            let l2_beta_qr_bi: Vec<(BigUint, BigUint)> = l2_beta.iter().map(|x| x.div_mod_floor(&bls_modulus_bi)).collect();

            let mut l1_cum_sum_qr_bi: Vec<(BigUint, BigUint)> = Vec::new();
            let mut l1_cum_sum: Vec<BigUint> = Vec::new();
            let mut cur = BigUint::from(0u8);
            for idx in 0..l1_beta.len() {
                cur += l1_beta[idx].clone();
                l1_cum_sum.push(cur.clone());
                let (q, r) = cur.div_mod_floor(&bls_modulus_bi);
                l1_cum_sum_qr_bi.push((q, r));
            }

            let mut l2_cum_sum_qr_bi: Vec<(BigUint, BigUint)> = Vec::new();
            let mut l2_cum_sum: Vec<BigUint> = Vec::new();
            let mut cur = BigUint::from(0u8);
            for idx in 0..l2_beta.len() {
                cur += l2_beta[idx].clone();
                l2_cum_sum.push(cur.clone());
                let (q, r) = cur.div_mod_floor(&bls_modulus_bi);
                l2_cum_sum_qr_bi.push((q, r));
            }

            let l1_beta_qr: Vec<(BwSF, BwSF)> = l1_beta_qr_bi.iter()
                .map(|(a, b)| (
                    BwSF::from_le_bytes_mod_order((*a).to_bytes_le().as_slice()),
                    BwSF::from_le_bytes_mod_order((*b).to_bytes_le().as_slice())
                )).collect();

            let l2_beta_qr: Vec<(BwSF, BwSF)> = l2_beta_qr_bi.iter()
                .map(|(a, b)| (
                    BwSF::from_le_bytes_mod_order((*a).to_bytes_le().as_slice()),
                    BwSF::from_le_bytes_mod_order((*b).to_bytes_le().as_slice())
                )).collect();
            
            let l1_cum_sum_qr: Vec<(BwSF, BwSF)> = l1_cum_sum_qr_bi.iter()
                .map(|(a, b)| (
                    BwSF::from_le_bytes_mod_order((*a).to_bytes_le().as_slice()),
                    BwSF::from_le_bytes_mod_order((*b).to_bytes_le().as_slice())
                )).collect(); 

            let l2_cum_sum_qr: Vec<(BwSF, BwSF)> = l2_cum_sum_qr_bi.iter()
                .map(|(a, b)| (
                    BwSF::from_le_bytes_mod_order((*a).to_bytes_le().as_slice()),
                    BwSF::from_le_bytes_mod_order((*b).to_bytes_le().as_slice())
                )).collect();   

            let (l1_rho, l1_c, l1_pi) = kzg_proof(l1_poly, powers.clone(), beta);
            let (l2_rho, l2_c, l2_pi) = kzg_proof(l2_poly, powers.clone(), beta);
            //rhs 
            //print!("1: {}, 2: {}, 3: {}\n", l2_cum_sum[l2_cum_sum.len() - 1], l2_rho.into_repr(), l2_cum_sum_qr[l2_cum_sum.len() - 1].1);
            let taug = pp.beta_h;
            let g2 = pp.h;
            let g2_beta: GroupAffine<ark_bls12_377::g2::Parameters> = g2.scalar_mul(beta).into();
            // this goes into the pairing rhs
            let g2_r = G2Prepared::<ark_bls12_377::Parameters>::from(taug - g2_beta);
            let g1_l1_r = G1Prepared::<ark_bls12_377::Parameters>::from(l1_pi.0);
            let g1_l2_r = G1Prepared::<ark_bls12_377::Parameters>::from(l2_pi.0);
            //lhs
            let g1 = powers.powers_of_g[0];
            let g1_l1_rho: GroupAffine<ark_bls12_377::g1::Parameters> = g1.scalar_mul(l1_rho).into();
            let g1_l2_rho: GroupAffine<ark_bls12_377::g1::Parameters> = g1.scalar_mul(l2_rho).into();
            let g1_l1_c = l1_c.0;
            let g1_l2_c = l2_c.0;
            // this goes into the pairing lhs
            let g2_l = G2Prepared::<ark_bls12_377::Parameters>::from(g2);
            let g1_l1_l = G1Prepared::<ark_bls12_377::Parameters>::from(g1_l1_c - g1_l1_rho);
            let g1_l2_l = G1Prepared::<ark_bls12_377::Parameters>::from(g1_l2_c - g1_l2_rho);
            let l1_rho_bw = E::Fr::from_repr(
                <E::Fr as PrimeField>::BigInt::from_bits_le(&l1_rho.into_repr().to_bits_le())
            ).unwrap();

            let l2_rho_bw = E::Fr::from_repr(
                <E::Fr as PrimeField>::BigInt::from_bits_le(&l2_rho.into_repr().to_bits_le())
            ).unwrap();

            let powers_of_beta_bw = powers_of_beta.iter().map(|x| 
                E::Fr::from_repr(<E::Fr as PrimeField>::BigInt::from_bits_le(&x.into_repr().to_bits_le())).unwrap()).collect();
            //let l1_mat_1d_f:Vec<F> = l1_mat_1d.iter().map(|x| (*x).into()).collect();
            //let l2_mat_1d_f:Vec<F> = l2_mat_1d.iter().map(|x| (*x).into()).collect();

            let full_circuit = FullCircuitOpLv3KZGClassification {
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
                g1_l1_l,
                g1_l1_r,
                g1_l2_l,
                g1_l2_r,
                g2_l,
                g2_r,

                powers_of_beta: powers_of_beta_bw,
                bls_modulus: bls_modulus_bwsf,
                l1_rho: l1_rho_bw,
                l2_rho: l2_rho_bw,
                l1_beta_qr,
                l2_beta_qr,
                l1_cum_sum_qr,
                l2_cum_sum_qr
                // x_squeeze: x_squeeze.clone(),
                // l1_squeeze: l1_squeeze.clone(),
                // l2_squeeze: l2_squeeze.clone(),
                // z_squeeze: z_squeeze.clone(),
                
            };
            full_circuit
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
        ) -> FullCircuitOpLv3KZGPolyClassification<E::Fr> {
            type BlsSF = <ark_bls12_377::Bls12_377 as PairingEngine>::Fr;
            type BwSF = <ark_bw6_761::BW6_761 as PairingEngine>::Fr;
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
            full_circuit
        }

        // fn gen_circ_full_mpc<F: PrimeField, MF: PrimeField + Reveal<Base = F>>(    
        //     full_circuit: FullCircuitOpLv3PedersenClassification<F>
        // ) -> FullCircuitOpLv3PedersenClassification<MF> {

        //     let rng = &mut test_rng();

        //     let full_circuit_mpc = FullCircuitOpLv3PedersenClassification {
        //         x: MF::king_share_batch(full_circuit.x, rng),
        //         l1: Vec::<MF>::king_share_batch(full_circuit.l1, rng),
        //         l2: Vec::<MF>::king_share_batch(full_circuit.l2, rng),
        //         y: MF::king_share_batch(full_circuit.y, rng),
        //         z: MF::king_share_batch(full_circuit.z, rng),
        //         argmax_res: MF::king_share(full_circuit.argmax_res, rng),
        //         relu_output1: MF::king_share_batch(full_circuit.relu_output1, rng),
        //         remainder1: MF::king_share_batch(full_circuit.remainder1, rng),
        //         remainder2: MF::king_share_batch(full_circuit.remainder2, rng),
        //         div1: MF::king_share_batch(full_circuit.div1, rng),
        //         div2: MF::king_share_batch(full_circuit.div2, rng),
        //         cmp_res: bool::king_share_batch(full_circuit.cmp_res, rng),
        //         y_0_converted: MF::king_share_batch(full_circuit.y_0_converted, rng),
        //         z_0_converted: MF::king_share_batch(full_circuit.z_0_converted, rng),
        //         x_0: MF::king_share(full_circuit.x_0, rng),
        //         y_0: MF::king_share(full_circuit.y_0, rng),
        //         z_0: MF::king_share(full_circuit.z_0, rng),
        //         l1_mat_0: MF::king_share(full_circuit.l1_mat_0, rng),
        //         l2_mat_0: MF::king_share(full_circuit.l2_mat_0, rng),
        //         multiplier_l1: MF::king_share_batch(full_circuit.multiplier_l1, rng),
        //         multiplier_l2: MF::king_share_batch(full_circuit.multiplier_l2, rng),
        //         two_power_8: MF::king_share(full_circuit.two_power_8, rng),
        //         m_exp: MF::king_share(full_circuit.m_exp, rng),
        //         zero: MF::king_share(full_circuit.zero, rng),

        //         params: full_circuit.params.share(rng),
        //         l1_1d: full_circuit.l1_1d,
        //         l2_1d: full_circuit.l2_1d,
        //         x_u8: full_circuit.x_u8,
        //         z_u8: full_circuit.z_u8,

        //         x_squeeze: MF::king_share_batch(full_circuit.x_squeeze.clone(), rng),
        //         l1_squeeze: MF::king_share_batch(full_circuit.l1_squeeze.clone(), rng),
        //         l2_squeeze: MF::king_share_batch(full_circuit.l2_squeeze.clone(), rng),
        //         z_squeeze: MF::king_share_batch(full_circuit.z_squeeze.clone(), rng),

        //     };
        //     full_circuit_mpc
        // }
        impl SnarkBench for Groth16Bench {
            fn local<E: PairingEngine>(_n: usize, timer_label: &str) {
                let mut rng = test_rng();
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

                // CIRCS
                
                let full_circuit = gen_circ_full_poseidon::<Bls12<ark_bls12_377::Parameters>>(
                    x.clone(),
                    l1_mat,
                    l2_mat, 
                    z.clone(), 
                    classification_res, 
                    x_0[0], 
                    l1_output_0[0], 
                    l2_output_0[0], 
                    l1_mat_0[0], 
                    l2_mat_0[0], 
                    l1_mat_multiplier, 
                    l2_mat_multiplier
                );

                println!("start generating random parameters");
                let begin = Instant::now();
            
                // pre-computed parameters
                let param =
                    generate_random_parameters::<ark_bls12_377::Bls12_377, _, _>(full_circuit.clone(), &mut rng)
                        .unwrap();
                let end = Instant::now();
                println!("setup time {:?}", end.duration_since(begin));
            
                // let mut buf = vec![];
                // param.serialize(&mut buf).unwrap();
                // println!("crs size: {}", buf.len());
            
                let pvk = prepare_verifying_key(&param.vk);
                println!("random parameters generated!\n");
            
                // prover
                let begin = Instant::now();
                let (ipts, proof) = create_random_proof(full_circuit, &param, &mut rng).unwrap();

                let end = Instant::now();
                println!("prove time {:?}", end.duration_since(begin));

                let begin = Instant::now();
                assert!(verify_proof(&pvk, &proof, &ipts).unwrap());
                let end = Instant::now();
                println!("verification time {:?}", end.duration_since(begin));
            }
            //<ark_bls12_381::Bls12_381, mpc_algebra::share::gsz20::GszPairingShare<ark_bls12_381::Bls12_381>
            // fn mpc<E: PairingEngine, S: PairingShare<E>>(_n: usize, timer_label: &str) {
            //     let mut rng = test_rng();
            //     //let (x, l1_mat, l2_mat): (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) = read_shallownet_inputs_u8();
            //     let x: Vec<u8> = read_vector1d("pretrained_model/shallownet/X_q.txt".to_string(), 784); // only read one image
            //     let l1_mat: Vec<Vec<u8>> = read_vector2d(
            //         "pretrained_model/shallownet/l1_weight_q.txt".to_string(),
            //         128,
            //         784,
            //     );
            //     let l2_mat: Vec<Vec<u8>> = read_vector2d(
            //         "pretrained_model/shallownet/l2_weight_q.txt".to_string(),
            //         10,
            //         128,
            //     );
            //     let x_0: Vec<u8> = read_vector1d("pretrained_model/shallownet/X_z.txt".to_string(), 1);
            //     let l1_output_0: Vec<u8> =
            //         read_vector1d("pretrained_model/shallownet/l1_output_z.txt".to_string(), 1);
            //     let l2_output_0: Vec<u8> =
            //         read_vector1d("pretrained_model/shallownet/l2_output_z.txt".to_string(), 1);
            //     let l1_mat_0: Vec<u8> =
            //         read_vector1d("pretrained_model/shallownet/l1_weight_z.txt".to_string(), 1);
            //     let l2_mat_0: Vec<u8> =
            //         read_vector1d("pretrained_model/shallownet/l2_weight_z.txt".to_string(), 1);
            
            //     let l1_mat_multiplier: Vec<f32> = read_vector1d_f32(
            //         "pretrained_model/shallownet/l1_weight_s.txt".to_string(),
            //         128,
            //     );
            //     let l2_mat_multiplier: Vec<f32> = read_vector1d_f32(
            //         "pretrained_model/shallownet/l2_weight_s.txt".to_string(),
            //         10,
            //     );
            
            //     //println!("zero points x_0 {}  l1_out_0 {} l2_out_0 {}, l1_mat_0 {}, l2_mat_0 {}", x_0[0], l1_output_0[0], l2_output_0[0], l1_mat_0[0], l2_mat_0[0]);
            
            //     let z: Vec<u8> = full_circuit_forward_u8(
            //         x.clone(),
            //         l1_mat.clone(),
            //         l2_mat.clone(),
            //         x_0[0],
            //         l1_output_0[0],
            //         l2_output_0[0],
            //         l1_mat_0[0],
            //         l2_mat_0[0],
            //         l1_mat_multiplier.clone(),
            //         l2_mat_multiplier.clone(),
            //     );
            
            //     let begin = Instant::now();

            //     let classification_res = argmax_u8(z.clone());

            //     // CIRCS
            //     let full_circuit = gen_circ_full::<E::Fr>(
            //         x.clone(),
            //         l1_mat.clone(),
            //         l2_mat.clone(),
            //         z.clone(),
            //         classification_res,
            //         x_0[0],
            //         l1_output_0[0], 
            //         l2_output_0[0],
            //         l1_mat_0[0],
            //         l2_mat_0[0],
            //         l1_mat_multiplier.clone(),
            //         l2_mat_multiplier.clone(),
            //     );

            //     //let computation_timer = start_timer!(|| "do the mpc (cheat)");
            //     println!("start generating random parameters");

            //     let param =
            //         generate_random_parameters::<E, _, _>(full_circuit.clone(), &mut rng)
            //             .unwrap();
            //     let pvk = prepare_verifying_key(&param.vk);
            //     let mpc_params= Reveal::from_public(param);

            //     let end = Instant::now();
            //     println!("setup time {:?}", end.duration_since(begin));
            
            //     println!("random parameters generated!\n");
                
            //     let full_circuit_mpc = gen_circ_full_mpc::<
            //         E::Fr,
            //         <MpcPairingEngine<E, S> as PairingEngine>::Fr,
            //     >(full_circuit);
                
            //     let x_reveal: Vec<<E as PairingEngine>::Fr> = full_circuit_mpc.x.iter().map(|x| (*x).reveal()).collect();
            //     let z_reveal: Vec<<E as PairingEngine>::Fr> = full_circuit_mpc.z.iter().map(|x| (*x).reveal()).collect();
            //     // prover
            //     let begin = Instant::now();
            //     let proof = channel::without_cheating(|| {
            //         let pf = create_random_proof::<MpcPairingEngine<E, S>, _, _>(full_circuit_mpc, &mpc_params, &mut rng)
            //             .unwrap();
            //         let reveal_timer = start_timer!(|| "reveal");
            //         let pf = pf.reveal();
            //         end_timer!(reveal_timer);
            //         pf
            //     });

            //     let end = Instant::now();

            //     println!("prove time {:?}", end.duration_since(begin));

            //     let ipts = [x_reveal, z_reveal].concat();
            //     println!("IPTS LEN {}", ipts.len());

            //     let begin = Instant::now();
            //     assert!(verify_proof(&pvk, &proof, &ipts).unwrap());
            //     let end = Instant::now();
            //     println!("verification time {:?}", end.duration_since(begin));
            // }
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
        //Marlin,
        //Plonk,
    }
}

#[derive(Debug, StructOpt)]
enum FieldOpt {
    Mpc {
        #[structopt(flatten)]
        party_info: ShareInfo,
    },
    Local,
    ArkLocal,
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
            FieldOpt::ArkLocal => B::ark_local::<E>(computation_size, timed_label),
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
    shallownet_mnist::groth::Groth16Bench::local::<ark_bls12_381::Bls12_381>(0, TIMED_SECTION_LABEL);
    // MpcMultiNet::init_from_file( "./data/2", 0);
    // shallownet_mnist::groth::Groth16Bench::mpc::<ark_bls12_381::Bls12_381, mpc_algebra::share::gsz20::GszPairingShare<ark_bls12_381::Bls12_381>>(0, TIMED_SECTION_LABEL);
    // let opt = Opt::from_args();
    // env_logger::init();
    // println!("YOOOOOOOO");
    // match opt.proof_system {
    //     ProofSystem::Groth16 => opt.field.run::<ark_bls12_377::Bls12_377, _>(
    //         opt.computation,
    //         opt.computation_size,
    //         shallownet_mnist::groth::Groth16Bench,
    //         TIMED_SECTION_LABEL,
    //     ),
    //     // ProofSystem::Plonk => opt.field.run::<ark_bls12_377::Bls12_377, _>(
    //     //     opt.computation,
    //     //     opt.computation_size,
    //     //     shallownet_mnist::plonk::PlonkBench,
    //     //     TIMED_SECTION_LABEL,
    //     // ),
    //     // ProofSystem::Marlin => opt.field.run::<ark_bls12_377::Bls12_377, _>(
    //     //     opt.computation,
    //     //     opt.computation_size,
    //     //     squarings::marlin::MarlinBench,
    //     //     TIMED_SECTION_LABEL,
    //     // ),
    // }
}


