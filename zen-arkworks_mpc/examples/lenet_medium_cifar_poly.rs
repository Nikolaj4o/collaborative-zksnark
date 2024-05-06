use std::time::Instant;
use zen_arkworks::lenet_circuit::convert_4d_vector_into_1d;
use zen_arkworks::lenet_circuit::LeNetCircuitU8OptimizedLv3PolyClassification;
use zen_arkworks::*;
use ark_serialize::CanonicalSerialize;

use ark_serialize::CanonicalDeserialize;
use ark_ff::UniformRand;
use ark_groth16::*;
use ark_crypto_primitives::{commitment::pedersen::Randomness, SNARK};
use ark_bls12_377::Bls12_377;
use zen_arkworks::full_circuit::convert_2d_vector_into_1d;
use ark_sponge::{ CryptographicSponge, FieldBasedCryptographicSponge, poseidon::PoseidonSponge};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::kzg10::Powers;
use ark_poly::Polynomial;
use ark_poly::UVPolynomial;
use ark_ff::One;
use ark_std::borrow::Cow;
use std::ops::Div;
use ark_std::test_rng;

fn kzg_proof(
    poly: DensePolynomial<Fq>,
    //pp: ark_poly_commit::kzg10::UniversalParams<E>,
    powers: Powers<Bls12_377>,
    x: Fq,
) -> (Fq, ark_poly_commit::kzg10::Commitment<Bls12_377>, ark_poly_commit::kzg10::Commitment<Bls12_377>)  {
    let rng = &mut ark_std::test_rng();

    let (commit, rand) =
    ark_poly_commit::kzg10::KZG10::commit(&powers, &poly, None, None).unwrap();
    let eval = poly.evaluate(&x);
    let eval_poly = DensePolynomial::<Fq>::from_coefficients_vec(vec![-eval]);
    let divisor_poly = DensePolynomial::<Fq>::from_coefficients_vec(vec![-x, Fq::one()]);
    let wintess_poly = (poly + eval_poly).div(&divisor_poly);
    let (witness_commit, rand) = 
    ark_poly_commit::kzg10::KZG10::commit(&powers, &wintess_poly, None, None).unwrap();

    (eval, commit, witness_commit)
}

fn main() {
    let mut rng = test_rng();

    println!("LeNet optimized medium on CIFAR dataset");

    let x: Vec<Vec<Vec<Vec<u8>>>> = read_vector4d(
        "pretrained_model/LeNet_CIFAR_pretrained/X_q.txt".to_string(),
        1,
        3,
        32,
        32,
    ); // only read one image
    let conv1_w: Vec<Vec<Vec<Vec<u8>>>> = read_vector4d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_conv1_weight_q.txt".to_string(),
        32,
        3,
        5,
        5,
    );
    let conv2_w: Vec<Vec<Vec<Vec<u8>>>> = read_vector4d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_conv2_weight_q.txt".to_string(),
        64,
        32,
        5,
        5,
    );
    let conv3_w: Vec<Vec<Vec<Vec<u8>>>> = read_vector4d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_conv3_weight_q.txt".to_string(),
        256,
        64,
        4,
        4,
    );
    let fc1_w: Vec<Vec<u8>> = read_vector2d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_linear1_weight_q.txt".to_string(),
        128,
        1024,
    );
    let fc2_w: Vec<Vec<u8>> = read_vector2d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_linear2_weight_q.txt".to_string(),
        10,
        128,
    );

    let x_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/X_z.txt".to_string(),
        1,
    );
    let conv1_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_conv1_output_z.txt".to_string(),
        1,
    );
    let conv2_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_conv2_output_z.txt".to_string(),
        1,
    );
    let conv3_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_conv3_output_z.txt".to_string(),
        1,
    );
    let fc1_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_linear1_output_z.txt".to_string(),
        1,
    );
    let fc2_output_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_linear2_output_z.txt".to_string(),
        1,
    );

    let conv1_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_conv1_weight_z.txt".to_string(),
        1,
    );
    let conv2_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_conv2_weight_z.txt".to_string(),
        1,
    );
    let conv3_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_conv3_weight_z.txt".to_string(),
        1,
    );
    let fc1_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_linear1_weight_z.txt".to_string(),
        1,
    );
    let fc2_weights_0: Vec<u8> = read_vector1d(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_linear2_weight_z.txt".to_string(),
        1,
    );

    let multiplier_conv1: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_conv1_weight_s.txt".to_string(),
        32,
    );
    let multiplier_conv2: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_conv2_weight_s.txt".to_string(),
        64,
    );
    let multiplier_conv3: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_conv3_weight_s.txt".to_string(),
        256,
    );

    let multiplier_fc1: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_linear1_weight_s.txt".to_string(),
        128,
    );
    let multiplier_fc2: Vec<f32> = read_vector1d_f32(
        "pretrained_model/LeNet_CIFAR_pretrained/LeNet_Medium_linear2_weight_s.txt".to_string(),
        10,
    );

    println!("finish reading parameters");

    //batch size is only one for faster calculation of total constraints
    let flattened_x3d: Vec<Vec<Vec<u8>>> = x.clone().into_iter().flatten().collect();
    let flattened_x2d: Vec<Vec<u8>> = flattened_x3d.into_iter().flatten().collect();
    let flattened_x1d: Vec<u8> = flattened_x2d.into_iter().flatten().collect();

    //let flattened_z1d: Vec<u8> = z.clone().into_iter().flatten().collect();
    let conv1_weights_1d = convert_4d_vector_into_1d(conv1_w.clone());
    let conv2_weights_1d = convert_4d_vector_into_1d(conv2_w.clone());
    let conv3_weights_1d = convert_4d_vector_into_1d(conv3_w.clone());
    let fc1_weights_1d = convert_2d_vector_into_1d(fc1_w.clone());
    let fc2_weights_1d = convert_2d_vector_into_1d(fc2_w.clone());


    let x_f: Vec<Vec<Vec<Vec<Fq>>>> = x.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect()).collect()).collect();
    let conv1_w_f: Vec<Vec<Vec<Vec<Fq>>>> = conv1_w.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect()).collect()).collect();
    let conv2_w_f: Vec<Vec<Vec<Vec<Fq>>>> = conv2_w.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect()).collect()).collect();
    let conv3_w_f: Vec<Vec<Vec<Vec<Fq>>>> = conv3_w.iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect()).collect()).collect();
    let fc1_w_f: Vec<Vec<Fq>> = fc1_w.iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect();
    let fc2_w_f: Vec<Vec<Fq>> = fc2_w.iter().map(|x| (*x).iter().map(|x| (*x).into()).collect()).collect();
    let x_0_f: Vec<Fq> = x_0.iter().map(|x| (*x).into()).collect();
    let conv1_output_0_f: Vec<Fq> = conv1_output_0.iter().map(|x| (*x).into()).collect();
    let conv2_output_0_f: Vec<Fq> = conv2_output_0.iter().map(|x| (*x).into()).collect();
    let conv3_output_0_f: Vec<Fq> = conv3_output_0.iter().map(|x| (*x).into()).collect();
    let fc1_output_0_f: Vec<Fq> = fc1_output_0.iter().map(|x| (*x).into()).collect();
    let fc2_output_0_f: Vec<Fq> = fc2_output_0.iter().map(|x| (*x).into()).collect();
    let conv1_weights_0_f: Vec<Fq> = conv1_weights_0.iter().map(|x| (*x).into()).collect();
    let conv2_weights_0_f: Vec<Fq> = conv2_weights_0.iter().map(|x| (*x).into()).collect();
    let conv3_weights_0_f: Vec<Fq> = conv3_weights_0.iter().map(|x| (*x).into()).collect();
    let fc1_weights_0_f: Vec<Fq> = fc1_weights_0.iter().map(|x| (*x).into()).collect();
    let fc2_weights_0_f: Vec<Fq> = fc2_weights_0.iter().map(|x| (*x).into()).collect();
    let multiplier_conv1_f: Vec<Fq> = multiplier_conv1.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
    let multiplier_conv2_f: Vec<Fq> = multiplier_conv2.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
    let multiplier_conv3_f: Vec<Fq> = multiplier_conv3.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
    let multiplier_fc1_f: Vec<Fq> = multiplier_fc1.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();
    let multiplier_fc2_f: Vec<Fq> = multiplier_fc2.iter().map(|x| (((*x) * 2u32.pow(22) as f32) as u128).into()).collect();

    let z: Vec<Vec<Fq>> = lenet_circuit_forward_f(
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

    //println!("x outside {:?}", x.clone());
    //println!("z outside {:?}", flattened_z1d.clone());
    let begin = Instant::now();
    let mut commit_vec = Vec::<Fq>::new();
    let mut x_fq: Vec<Fq> = flattened_x1d.clone().iter().map(|x| (*x).into()).collect();
    commit_vec.extend(x_fq.clone());
    let c1_fq: Vec<Fq> = conv1_weights_1d.clone().iter().map(|x| (*x).into()).collect();
    commit_vec.extend(c1_fq);
    let c2_fq: Vec<Fq> = conv2_weights_1d.clone().iter().map(|x| (*x).into()).collect();
    commit_vec.extend(c2_fq);
    let c3_fq: Vec<Fq> = conv3_weights_1d.clone().iter().map(|x| (*x).into()).collect();
    commit_vec.extend(c3_fq);
    let l1_fq: Vec<Fq> = fc1_weights_1d.clone().iter().map(|x| (*x).into()).collect();
    commit_vec.extend(l1_fq);
    let l2_fq: Vec<Fq> = fc2_weights_1d.clone().iter().map(|x| (*x).into()).collect();
    commit_vec.extend(l2_fq);
    //let z_fq: Vec<Fq> = z.clone().iter().map(|x| (*x).into()).collect();
    //commit_vec.extend(z_fq);
    let commit_len: usize = commit_vec.len();

    let mut rng = &mut ark_std::test_rng();
    let pp = ark_poly_commit::kzg10::KZG10::<
        ark_bls12_377::Bls12_377,
        DensePolynomial<Fq>,
    >::setup(commit_len - 1, true, rng)
    .unwrap();

    let powers_of_gamma_g = (0..commit_len)
        .map(|i| pp.powers_of_gamma_g[&i])
        .collect::<Vec<_>>();

    let powers = ark_poly_commit::kzg10::Powers::<ark_bls12_377::Bls12_377> {
        powers_of_g: Cow::Borrowed(&pp.powers_of_g),
        powers_of_gamma_g: Cow::Owned(powers_of_gamma_g),
    };

    let beta = Fq::rand(rng);
    let mut powers_of_beta: Vec<Fq> = vec![1u8.into()];
    let mut cur = beta;

    for _ in 1..commit_len {
        powers_of_beta.push(cur);
        cur *= &beta;
    }
    let commit_poly = DensePolynomial::<Fq>::from_coefficients_vec(commit_vec);
    let (rho, c, pi) = kzg_proof(commit_poly, powers.clone(), beta);

    let end = Instant::now();
    println!("commit time {:?}", end.duration_since(begin));
    //we only do one image in zk proof.
    let classification_res = argmax_f(z[0].clone());

    let full_circuit = LeNetCircuitU8OptimizedLv3PolyClassification::<Fq>{
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



    println!("start generating random parameters");
    let begin = Instant::now();

    // pre-computed parameters
    let param =
        generate_random_parameters::<Bls12_377, _, _>(full_circuit.clone(), &mut rng)
            .unwrap();
    let end = Instant::now();
    println!("setup time {:?}", end.duration_since(begin));



    let pvk = prepare_verifying_key(&param.vk);
    println!("random parameters generated!\n");

    // prover
    let begin = Instant::now();
    let proof = create_random_proof(full_circuit, &param, &mut rng).unwrap();
    let end = Instant::now();
    println!("prove time {:?}", end.duration_since(begin));

    let mut inputs = vec![
        rho.clone(),
        beta.clone(),
    ];
    inputs.append(&mut x_fq);

    let begin = Instant::now();
    assert!(verify_proof(&pvk, &proof, &inputs[..].as_ref()).unwrap());
    let end = Instant::now();
    println!("verification time {:?}", end.duration_since(begin));
}
