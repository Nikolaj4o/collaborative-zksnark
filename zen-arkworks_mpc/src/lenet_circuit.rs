
use crate::argmax_circuit::*;
use crate::avg_pool_circuit::*;
use crate::conv_circuit::*;
use crate::cosine_circuit::*;
use crate::fc_circuit::*;
use crate::relu_circuit::*;
use crate::vanilla::*;
use crate::*;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::poly::polynomial::univariate::dense::DensePolynomialVar;
use num_traits::Pow;
use std::cmp::*;
use ark_ff::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_ed_on_bls12_381::{constraints::FqVar, Fq};

//use ark_sponge::poseidon::PoseidonParameters;




pub fn convert_2d_vector_into_1d<T: Clone>(vec: Vec<Vec<T>>) -> Vec<T> {
    let mut res = Vec::new();
    for i in 0..vec.len() {
        res.extend(vec[i].clone());
    }
    res
}

pub fn convert_4d_vector_into_1d<T: Clone>(vec: Vec<Vec<Vec<Vec<T>>>>) -> Vec<T> {
    let mut res = Vec::new();
    for i in 0..vec.len() {
        for j in 0..vec[0].len() {
            for k in 0..vec[0][0].len() {
                res.extend(vec[i][j][k].clone());
            }
        }
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

pub fn convert_4d_vector_into_fq(vec: Vec<Vec<Vec<Vec<u8>>>>) -> Vec<Fq> {
    let mut res = vec![Fq::zero(); vec[0][0][0].len() * vec[0][0].len() * vec[0].len() * vec.len()];
    let mut counter = 0;
    for i in 0..vec.len() {
        for j in 0..vec[0].len() {
            for k in 0..vec[0][0].len() {
                for m in 0..vec[0][0][0].len() {
                    let tmp: Fq = vec[i][j][k][m].into();
                    res[counter] = tmp;
                    counter += 1;
                }
            }
        }
    }
    res
}

fn generate_fqvar(cs: ConstraintSystemRef<Fq>, input: Vec<u8>) -> Vec<FqVar> {
    let mut res: Vec<FqVar> = Vec::new();
    for i in 0..input.len() {
        let fq: Fq = input[i].into();
        let tmp = FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "tmp"), || Ok(fq)).unwrap();
        res.push(tmp);
    }
    res
}

fn generate_fqvar_f<F: PrimeField>(cs: ConstraintSystemRef<F>, input: Vec<F>) -> Vec<FpVar<F>> {
    let mut res: Vec<FpVar<F>> = Vec::new();
    for i in 0..input.len() {
        let tmp = FpVar::<F>::new_witness(ark_relations::ns!(cs, "tmp"), || Ok(input[i])).unwrap();
        res.push(tmp);
    }
    res
}

fn generate_fqvar4d(
    cs: ConstraintSystemRef<Fq>,
    input: Vec<Vec<Vec<Vec<u8>>>>,
) -> Vec<Vec<Vec<Vec<FqVar>>>> {
    let mut res: Vec<Vec<Vec<Vec<FqVar>>>> =
        vec![
            vec![
                vec![
                    vec![FpVar::<Fq>::Constant(Fq::zero()); input[0][0][0].len()];
                    input[0][0].len()
                ];
                input[0].len()
            ];
            input.len()
        ];
    for i in 0..input.len() {
        for j in 0..input[i].len() {
            for k in 0..input[i][j].len() {
                for l in 0..input[i][j][k].len() {
                    let fq: Fq = input[i][j][k][l].into();
                    let tmp =
                        FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "tmp"), || Ok(fq)).unwrap();
                    res[i][j][k][l] = tmp;
                }
            }
        }
    }
    res
}

fn generate_fqvar4d_f<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    input: Vec<Vec<Vec<Vec<F>>>>,
) -> Vec<Vec<Vec<Vec<FpVar<F>>>>> {
    let mut res: Vec<Vec<Vec<Vec<FpVar<F>>>>> =
        vec![
            vec![
                vec![
                    vec![FpVar::<F>::Constant(F::zero()); input[0][0][0].len()];
                    input[0][0].len()
                ];
                input[0].len()
            ];
            input.len()
        ];
    for i in 0..input.len() {
        for j in 0..input[i].len() {
            for k in 0..input[i][j].len() {
                for l in 0..input[i][j][k].len() {
                    let tmp =
                        FpVar::<F>::new_witness(ark_relations::ns!(cs, "tmp"), || Ok(input[i][j][k][l])).unwrap();
                    res[i][j][k][l] = tmp;
                }
            }
        }
    }
    res
}
fn generate_fqvar4d_ipt(
    cs: ConstraintSystemRef<Fq>,
    input: Vec<Vec<Vec<Vec<u8>>>>,
) -> Vec<Vec<Vec<Vec<FqVar>>>> {
    let mut res: Vec<Vec<Vec<Vec<FqVar>>>> =
        vec![
            vec![
                vec![
                    vec![FpVar::<Fq>::Constant(Fq::zero()); input[0][0][0].len()];
                    input[0][0].len()
                ];
                input[0].len()
            ];
            input.len()
        ];
    for i in 0..input.len() {
        for j in 0..input[i].len() {
            for k in 0..input[i][j].len() {
                for l in 0..input[i][j][k].len() {
                    let fq: Fq = input[i][j][k][l].into();
                    let tmp =
                        FpVar::<Fq>::new_input(ark_relations::ns!(cs, "tmp"), || Ok(fq)).unwrap();
                    res[i][j][k][l] = tmp;
                }
            }
        }
    }
    res
}

fn generate_fqvar4d_ipt_f<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    input: Vec<Vec<Vec<Vec<F>>>>,
) -> Vec<Vec<Vec<Vec<FpVar<F>>>>> {
    let mut res: Vec<Vec<Vec<Vec<FpVar<F>>>>> =
        vec![
            vec![
                vec![
                    vec![FpVar::<F>::Constant(F::zero()); input[0][0][0].len()];
                    input[0][0].len()
                ];
                input[0].len()
            ];
            input.len()
        ];
    for i in 0..input.len() {
        for j in 0..input[i].len() {
            for k in 0..input[i][j].len() {
                for l in 0..input[i][j][k].len() {
                    let tmp =
                        FpVar::<F>::new_input(ark_relations::ns!(cs, "tmp"), || Ok(input[i][j][k][l])).unwrap();
                    res[i][j][k][l] = tmp;
                }
            }
        }
    }
    res
}

fn generate_fqvar_witness2D(cs: ConstraintSystemRef<Fq>, input: Vec<Vec<u8>>) -> Vec<Vec<FqVar>> {
    let zero_var = FpVar::<Fq>::Constant(Fq::zero());
    let mut res: Vec<Vec<FqVar>> = vec![vec![zero_var; input[0].len()]; input.len()];
    for i in 0..input.len() {
        for j in 0..input[i].len() {
            let fq: Fq = input[i][j].into();
            let tmp = FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "tmp"), || Ok(fq)).unwrap();
            res[i][j] = tmp;
        }
    }
    res
}

fn generate_fqvar_witness2D_f<F: PrimeField>(cs: ConstraintSystemRef<F>, input: Vec<Vec<F>>) -> Vec<Vec<FpVar<F>>> {
    let zero_var = FpVar::<F>::Constant(F::zero());
    let mut res: Vec<Vec<FpVar<F>>> = vec![vec![zero_var; input[0].len()]; input.len()];
    for i in 0..input.len() {
        for j in 0..input[i].len() {
            let fq = input[i][j];
            let tmp = FpVar::<F>::new_witness(ark_relations::ns!(cs, "tmp"), || Ok(fq)).unwrap();
            res[i][j] = tmp;
        }
    }
    res
}

fn generate_fqvar_witness4D(
    cs: ConstraintSystemRef<Fq>,
    input: Vec<Vec<Vec<Vec<u8>>>>,
) -> Vec<Vec<Vec<Vec<FqVar>>>> {
    let zero_var = FpVar::<Fq>::Constant(Fq::zero());
    let mut res: Vec<Vec<Vec<Vec<FqVar>>>> =
        vec![
            vec![vec![vec![zero_var; input[0][0][0].len()]; input[0][0].len()]; input[0].len()];
            input.len()
        ];
    for i in 0..input.len() {
        for j in 0..input[i].len() {
            for k in 0..input[i][j].len() {
                for m in 0..input[i][j][k].len() {
                    let fq: Fq = input[i][j][k][m].into();
                    let tmp =
                        FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "tmp"), || Ok(fq)).unwrap();
                    res[i][j][k][m] = tmp;
                }
            }
        }
    }
    res
}

#[derive(Clone)]
pub struct LeNetCircuitU8OptimizedLv3PolyClassification<F: PrimeField> {
    pub x: Vec<Vec<Vec<Vec<F>>>>,

    pub conv1_weights: Vec<Vec<Vec<Vec<F>>>>,

    pub conv2_weights: Vec<Vec<Vec<Vec<F>>>>,

    pub conv3_weights: Vec<Vec<Vec<Vec<F>>>>,

    pub fc1_weights: Vec<Vec<F>>,

    pub fc2_weights: Vec<Vec<F>>,

    pub z: Vec<Vec<F>>,

    pub beta: F,
    pub rho: F,

    //zero points for quantization.
    pub x_0: F,
    pub conv1_output_0: F,
    pub conv2_output_0: F,
    pub conv3_output_0: F,
    pub fc1_output_0: F,
    pub fc2_output_0: F, // which is also lenet output(z) zero point

    pub conv1_weights_0: F,
    pub conv2_weights_0: F,
    pub conv3_weights_0: F,
    pub fc1_weights_0: F,
    pub fc2_weights_0: F,

    //multiplier for quantization
    pub multiplier_conv1: Vec<F>,
    pub multiplier_conv2: Vec<F>,
    pub multiplier_conv3: Vec<F>,
    pub multiplier_fc1: Vec<F>,
    pub multiplier_fc2: Vec<F>,
    //we do not need multiplier in relu and AvgPool layer

    pub argmax_res: usize,
}

impl <F: PrimeField>ConstraintSynthesizer<F> for LeNetCircuitU8OptimizedLv3PolyClassification<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        #[cfg(debug_assertion)]
        println!(
            "LeNetCircuitU8OptimizedLv3PedersenClassification is setup mode: {}",
            cs.is_in_setup_mode()
        );
        let argmax_f: F = (self.argmax_res as u32).into();
        let z_fvar: Vec<Vec<FpVar<F>>> = self.z.clone().iter().map(|x| (*x).iter().map(|x| FpVar::<F>::new_input(ark_relations::ns!(cs, "z var"), || Ok(*x)).unwrap()).collect()).collect();
        let argmax_fvar = FpVar::<F>::new_witness(ark_relations::ns!(cs, "argmax var"), || Ok(argmax_f)).unwrap();
        let full_circuit = LeNetCircuitU8OptimizedLv3Poly{
            x: self.x.clone(),
            conv1_weights: self.conv1_weights.clone(),
            conv2_weights: self.conv2_weights.clone(),
            conv3_weights: self.conv3_weights.clone(),
            fc1_weights: self.fc1_weights.clone(),
            fc2_weights: self.fc2_weights.clone(),
            z: self.z.clone(),
            beta: self.beta,
            rho: self.rho,
            
            //zero points for quantization.
            x_0: self.x_0,
            conv1_output_0: self.conv1_output_0,
            conv2_output_0: self.conv2_output_0,
            conv3_output_0: self.conv3_output_0,
            fc1_output_0: self.fc1_output_0,
            fc2_output_0: self.fc2_output_0, // which is also lenet output(z) zero point

            conv1_weights_0: self.conv1_weights_0,
            conv2_weights_0: self.conv2_weights_0,
            conv3_weights_0: self.conv3_weights_0,
            fc1_weights_0: self.fc1_weights_0,
            fc2_weights_0: self.fc2_weights_0,

            //multiplier for quantization
            multiplier_conv1: self.multiplier_conv1.clone(),
            multiplier_conv2: self.multiplier_conv2.clone(),
            multiplier_conv3: self.multiplier_conv3.clone(),
            multiplier_fc1: self.multiplier_fc1.clone(),
            multiplier_fc2: self.multiplier_fc2.clone(),

        };

        //we only do one image in zk proof.
        let argmax_circuit = ArgmaxCircuitU8 {
            input: z_fvar[0].clone(),
            argmax_res: argmax_fvar.clone(),
        };

        full_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        argmax_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();

        println!(
            "FullCircuit {}",
            cs.num_constraints()
        );

        Ok(())
    }
}


#[derive(Clone)]
pub struct LeNetCircuitU8OptimizedLv3PolyRecognition <F: PrimeField> {
    pub x: Vec<Vec<Vec<Vec<F>>>>,

    pub conv1_weights: Vec<Vec<Vec<Vec<F>>>>,

    pub conv2_weights: Vec<Vec<Vec<Vec<F>>>>,

    pub conv3_weights: Vec<Vec<Vec<Vec<F>>>>,

    pub fc1_weights: Vec<Vec<F>>,

    pub fc2_weights: Vec<Vec<F>>,

    pub z: Vec<Vec<F>>,
    
    pub beta: F,
    pub rho: F,

    //zero points for quantization.
    pub x_0: F,
    pub conv1_output_0: F,
    pub conv2_output_0: F,
    pub conv3_output_0: F,
    pub fc1_output_0: F,
    pub fc2_output_0: F, // which is also lenet output(z) zero point

    pub conv1_weights_0: F,
    pub conv2_weights_0: F,
    pub conv3_weights_0: F,
    pub fc1_weights_0: F,
    pub fc2_weights_0: F,

    //multiplier for quantization
    pub multiplier_conv1: Vec<F>,
    pub multiplier_conv2: Vec<F>,
    pub multiplier_conv3: Vec<F>,
    pub multiplier_fc1: Vec<F>,
    pub multiplier_fc2: Vec<F>,
    //we do not need multiplier in relu and AvgPool layer


    pub person_feature_vector: Vec<F>,
    pub threshold: F,
    pub result: bool,
}

impl <F: PrimeField> ConstraintSynthesizer<F> for LeNetCircuitU8OptimizedLv3PolyRecognition<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        #[cfg(debug_assertion)]
        println!(
            "LeNetCircuitU8OptimizedLv3PedersenRecognition is setup mode: {}",
            cs.is_in_setup_mode()
        );

        let full_circuit = LeNetCircuitU8OptimizedLv3Poly {
            x: self.x.clone(),
            conv1_weights: self.conv1_weights.clone(),
            conv2_weights: self.conv2_weights.clone(),
            conv3_weights: self.conv3_weights.clone(),
            fc1_weights: self.fc1_weights.clone(),
            fc2_weights: self.fc2_weights.clone(),
            z: self.z.clone(),
            beta: self.beta,
            rho: self.rho,
            //zero points for quantization.
            x_0: self.x_0,
            conv1_output_0: self.conv1_output_0,
            conv2_output_0: self.conv2_output_0,
            conv3_output_0: self.conv3_output_0,
            fc1_output_0: self.fc1_output_0,
            fc2_output_0: self.fc2_output_0, // which is also lenet output(z) zero point

            conv1_weights_0: self.conv1_weights_0,
            conv2_weights_0: self.conv2_weights_0,
            conv3_weights_0: self.conv3_weights_0,
            fc1_weights_0: self.fc1_weights_0,
            fc2_weights_0: self.fc2_weights_0,

            //multiplier for quantization
            multiplier_conv1: self.multiplier_conv1.clone(),
            multiplier_conv2: self.multiplier_conv2.clone(),
            multiplier_conv3: self.multiplier_conv3.clone(),
            multiplier_fc1: self.multiplier_fc1.clone(),
            multiplier_fc2: self.multiplier_fc2.clone(),
        };

        //we only do one image in zk proof.
        let similarity_circuit = CosineSimilarityCircuitU8 {
            vec1: self.z[0].clone(),
            vec2: self.person_feature_vector.clone(),
            threshold: self.threshold,
            result: self.result,
        };

        full_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        similarity_circuit
            .clone()
            .generate_constraints(cs.clone())
            .unwrap();
        println!(
            "FullCircuit {}",
            cs.num_constraints()
        );

        Ok(())
    }
}

#[derive(Clone)]
pub struct LeNetCircuitU8OptimizedLv3Poly<F: PrimeField> {
    pub x: Vec<Vec<Vec<Vec<F>>>>,
    pub conv1_weights: Vec<Vec<Vec<Vec<F>>>>,
    pub conv2_weights: Vec<Vec<Vec<Vec<F>>>>,
    pub conv3_weights: Vec<Vec<Vec<Vec<F>>>>,
    pub fc1_weights: Vec<Vec<F>>,
    pub fc2_weights: Vec<Vec<F>>,
    pub z: Vec<Vec<F>>,
    pub beta: F,
    pub rho: F,

    //zero points for quantization.
    pub x_0: F,
    pub conv1_output_0: F,
    pub conv2_output_0: F,
    pub conv3_output_0: F,
    pub fc1_output_0: F,
    pub fc2_output_0: F, // which is also lenet output(z) zero point

    pub conv1_weights_0: F,
    pub conv2_weights_0: F,
    pub conv3_weights_0: F,
    pub fc1_weights_0: F,
    pub fc2_weights_0: F,

    //multiplier for quantization
    pub multiplier_conv1: Vec<F>,
    pub multiplier_conv2: Vec<F>,
    pub multiplier_conv3: Vec<F>,
    pub multiplier_fc1: Vec<F>,
    pub multiplier_fc2: Vec<F>,
    //we do not need multiplier in relu and AvgPool layer

}

impl <F: PrimeField>ConstraintSynthesizer<F> for LeNetCircuitU8OptimizedLv3Poly<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // x commitment
        let rho_var = FpVar::<F>::new_input(ark_relations::ns!(cs, "tmp"), || Ok(self.rho.clone())).unwrap();
        let beta_var = FpVar::<F>::new_input(ark_relations::ns!(cs, "tmp"), || Ok(self.beta.clone())).unwrap();
        let mut _cir_number = cs.num_constraints();
        //conv1
        let mut conv1_output = vec![vec![vec![vec![F::zero(); self.x[0][0][0].len() - self.conv1_weights[0][0][0].len() + 1];  // w - kernel_size  + 1
                                            self.x[0][0].len() - self.conv1_weights[0][0].len() + 1]; // h - kernel_size + 1
                                            self.conv1_weights.len()]; //number of conv kernels
                                            self.x.len()]; //input (image) batch size
        let (remainder_conv1, div_conv1) = vec_conv_with_remainder_f(
            &self.x,
            &self.conv1_weights,
            &mut conv1_output,
            self.x_0,
            self.conv1_weights_0,
            self.conv1_output_0,
            &self.multiplier_conv1,
        );

        let x_fqvar = generate_fqvar4d_ipt_f(cs.clone(), self.x.clone());
        let conv1_output_fqvar = generate_fqvar4d_f(cs.clone(), conv1_output.clone());
        let conv1_weight_fqvar_input =
            generate_fqvar4d_f(cs.clone(), self.conv1_weights.clone());
        // conv1_output_0 and multiplier_conv1 are both constants.
        let mut conv1_output_zeropoint_converted: Vec<F> = Vec::new();
        let f22: F =  2u64.pow(M_EXP).into();
        for i in 0..self.multiplier_conv1.len() {
            let m = self.multiplier_conv1[i];
            conv1_output_zeropoint_converted
                .push((self.conv1_output_0 * f22) / m);
        }

        //use SIMD for reducing constraints
        let conv1_circuit = ConvCircuitOp3 {
            x: x_fqvar.clone(),
            conv_kernel: conv1_weight_fqvar_input.clone(),
            y: conv1_output_fqvar.clone(),
            remainder: remainder_conv1.clone(),
            div: div_conv1.clone(),

            x_0: self.x_0,
            conv_kernel_0: self.conv1_weights_0,
            y_0: conv1_output_zeropoint_converted,

            multiplier: self.multiplier_conv1,
        };
        conv1_circuit.generate_constraints(cs.clone())?;

        println!(
            "Conv1 {} {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();
        //println!("conv1 {:?}", conv1_output);

        //relu1
        let relu1_cmp_res = relu4d_f(&mut conv1_output, self.conv1_output_0);
        let relu1_output_fqvar = generate_fqvar4d_f(cs.clone(), conv1_output.clone());

        let relu1_cmp_res_3d: Vec<Vec<Vec<bool>>> = relu1_cmp_res.into_iter().flatten().collect();
        let relu1_cmp_res_2d: Vec<Vec<bool>> = relu1_cmp_res_3d.into_iter().flatten().collect();
        let relu1_cmp_res_1d: Vec<bool> = relu1_cmp_res_2d.into_iter().flatten().collect();

        let flattened_relu1_input3d: Vec<Vec<Vec<FpVar<F>>>> =
            conv1_output_fqvar.into_iter().flatten().collect();
        let flattened_relu1_input2d: Vec<Vec<FpVar<F>>> =
            flattened_relu1_input3d.into_iter().flatten().collect();
        let flattened_relu1_input1d: Vec<FpVar<F>> =
            flattened_relu1_input2d.into_iter().flatten().collect();

        let flattened_relu1_output3d: Vec<Vec<Vec<FpVar<F>>>> =
            relu1_output_fqvar.clone().into_iter().flatten().collect();
        let flattened_relu1_output2d: Vec<Vec<FpVar<F>>> =
            flattened_relu1_output3d.into_iter().flatten().collect();
        let flattened_relu1_output1d: Vec<FpVar<F>> =
            flattened_relu1_output2d.into_iter().flatten().collect();

        let relu1_circuit = ReLUCircuitOp3 {
            y_in: flattened_relu1_input1d.clone(),
            y_out: flattened_relu1_output1d.clone(),
            y_zeropoint: self.conv1_output_0,
            cmp_res: relu1_cmp_res_1d.clone(),
        };

        relu1_circuit.generate_constraints(cs.clone())?;
        println!(
            "Relu1 {} {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();

        //avg_pool1

        let (avg_pool1_output, avg1_remainder) = avg_pool_with_remainder_scala_f(&conv1_output, 2);
        let avg_pool1_output_fqvar = generate_fqvar4d_f(cs.clone(), avg_pool1_output.clone());
        let avg_pool1_circuit = AvgPoolCircuitLv3 {
            x: relu1_output_fqvar.clone(),
            y: avg_pool1_output_fqvar.clone(),
            kernel_size: 2,
            remainder: avg1_remainder.clone(),
        };
        avg_pool1_circuit.generate_constraints(cs.clone())?;
        println!(
            "AvgPool1 {} {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();

        //layer 2 :
        //Conv2 -> relu -> AvgPool
        let mut conv2_output = vec![vec![vec![vec![F::zero(); avg_pool1_output[0][0][0].len() - self.conv2_weights[0][0][0].len()+ 1];  // w - kernel_size + 1
                                                                        avg_pool1_output[0][0].len() - self.conv2_weights[0][0].len()+ 1]; // h - kernel_size+ 1
                                                                        self.conv2_weights.len()]; //number of conv kernels
                                                                        avg_pool1_output.len()]; //input (image) batch size

        let (remainder_conv2, div_conv2) = vec_conv_with_remainder_f(
            &avg_pool1_output,
            &self.conv2_weights,
            &mut conv2_output,
            self.conv1_output_0,
            self.conv2_weights_0,
            self.conv2_output_0,
            &self.multiplier_conv2,
        );
        //println!("{:?}", self.conv2_weights.clone());
        let conv2_output_fqvar = generate_fqvar4d_f(cs.clone(), conv2_output.clone());
        let conv2_weight_fqvar_input =
            generate_fqvar4d_f(cs.clone(), self.conv2_weights.clone());

        // y_0 and multiplier_l1 are both constants.
        let mut conv2_output_zeropoint_converted: Vec<F> = Vec::new();
        for i in 0..self.multiplier_conv2.len() {
            let m = self.multiplier_conv2[i];
            conv2_output_zeropoint_converted
                .push((self.conv2_output_0 * f22) / m);
        }
        // println!("conv2_output_zeropoint_converted {:?}", conv2_output_zeropoint_converted.clone());
        // println!("conv2 multiplier {:?}", self.multiplier_conv2.clone());
        //use SIMD to reduce the number of constraints
        let conv2_circuit = ConvCircuitOp3 {
            x: avg_pool1_output_fqvar.clone(),
            conv_kernel: conv2_weight_fqvar_input.clone(),
            y: conv2_output_fqvar.clone(),
            remainder: remainder_conv2.clone(),
            div: div_conv2.clone(),

            x_0: self.conv1_output_0,
            conv_kernel_0: self.conv2_weights_0,
            y_0: conv2_output_zeropoint_converted,

            multiplier: self.multiplier_conv2,
        };
        conv2_circuit.generate_constraints(cs.clone())?;

        // #[cfg(debug_assertion)]
        println!(
            "Conv2 {} {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();

        //relu2 layer

        let relu2_cmp_res = relu4d_f(&mut conv2_output, self.conv2_output_0);
        let relu2_output_fqvar = generate_fqvar4d_f(cs.clone(), conv2_output.clone());
        let relu2_cmp_res_3d: Vec<Vec<Vec<bool>>> = relu2_cmp_res.into_iter().flatten().collect();
        let relu2_cmp_res_2d: Vec<Vec<bool>> = relu2_cmp_res_3d.into_iter().flatten().collect();
        let relu2_cmp_res_1d: Vec<bool> = relu2_cmp_res_2d.into_iter().flatten().collect();

        let flattened_relu2_input3d: Vec<Vec<Vec<FpVar<F>>>> =
            conv2_output_fqvar.into_iter().flatten().collect();
        let flattened_relu2_input2d: Vec<Vec<FpVar<F>>> =
            flattened_relu2_input3d.into_iter().flatten().collect();
        let flattened_relu2_input1d: Vec<FpVar<F>> =
            flattened_relu2_input2d.into_iter().flatten().collect();

        let flattened_relu2_output3d: Vec<Vec<Vec<FpVar<F>>>> =
            relu2_output_fqvar.clone().into_iter().flatten().collect();
        let flattened_relu2_output2d: Vec<Vec<FpVar<F>>> =
            flattened_relu2_output3d.into_iter().flatten().collect();
        let flattened_relu2_output1d: Vec<FpVar<F>> =
            flattened_relu2_output2d.into_iter().flatten().collect();

        let relu2_circuit = ReLUCircuitOp3 {
            y_in: flattened_relu2_input1d.clone(),
            y_out: flattened_relu2_output1d.clone(),
            y_zeropoint: self.conv2_output_0,
            cmp_res: relu2_cmp_res_1d.clone(),
        };
        relu2_circuit.generate_constraints(cs.clone())?;

        println!(
            "Relu2 {} {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();

        //avg pool2 layer
        //let avg_pool2_output = avg_pool_scala_u8(&conv2_output, self.conv2_weights.len());
        let (avg_pool2_output, avg2_remainder) = avg_pool_with_remainder_scala_f(&conv2_output, 2);
        let avg_pool2_output_fqvar = generate_fqvar4d_f(cs.clone(), avg_pool2_output.clone());
        let avg_pool2_circuit = AvgPoolCircuitLv3 {
            x: relu2_output_fqvar.clone(),
            y: avg_pool2_output_fqvar.clone(),
            kernel_size: 2,
            remainder: avg2_remainder.clone(),
        };
        avg_pool2_circuit.generate_constraints(cs.clone())?;
        println!(
            "AvgPool2 {} {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();

        //layer 3 :
        //Conv3 -> relu -> reshape output for following FC layer
        let mut conv3_output = vec![vec![vec![vec![F::zero(); avg_pool2_output[0][0][0].len() - self.conv3_weights[0][0][0].len()+ 1];  // w - kernel_size + 1
                                                                            avg_pool2_output[0][0].len() - self.conv3_weights[0][0].len()+ 1]; // h - kernel_size+ 1
                                                                            self.conv3_weights.len()]; //number of conv kernels
                                                                            avg_pool2_output.len()]; //input (image) batch size
                                                                                                     //conv3 layer
        let (remainder_conv3, div_conv3) = vec_conv_with_remainder_f(
            &avg_pool2_output,
            &self.conv3_weights,
            &mut conv3_output,
            self.conv2_output_0,
            self.conv3_weights_0,
            self.conv3_output_0,
            &self.multiplier_conv3,
        );

        let conv3_output_fqvar = generate_fqvar4d_f(cs.clone(), conv3_output.clone());
        let conv3_weight_fqvar_input =
            generate_fqvar4d_f(cs.clone(), self.conv3_weights.clone());

        // y_0 and multiplier_l1 are both constants.
        let mut conv3_output_zeropoint_converted: Vec<F> = Vec::new();
        for i in 0..self.multiplier_conv3.len() {
            let m = self.multiplier_conv3[i];
            conv3_output_zeropoint_converted
                .push((self.conv3_output_0 * f22) / m);
        }

        //use SIMD to reduce the number of constraints
        let conv3_circuit = ConvCircuitOp3 {
            x: avg_pool2_output_fqvar.clone(),
            conv_kernel: conv3_weight_fqvar_input.clone(),
            y: conv3_output_fqvar.clone(),
            remainder: remainder_conv3.clone(),
            div: div_conv3.clone(),

            x_0: self.conv2_output_0,
            conv_kernel_0: self.conv3_weights_0,
            y_0: conv3_output_zeropoint_converted,

            multiplier: self.multiplier_conv3,
        };
        conv3_circuit.generate_constraints(cs.clone())?;

        println!(
            "Conv3 {} {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();

        //relu3 layer

        let relu3_cmp_res = relu4d_f(&mut conv3_output, self.conv3_output_0);
        let relu3_output_fqvar = generate_fqvar4d_f(cs.clone(), conv3_output.clone());
        let relu3_cmp_res_3d: Vec<Vec<Vec<bool>>> = relu3_cmp_res.into_iter().flatten().collect();
        let relu3_cmp_res_2d: Vec<Vec<bool>> = relu3_cmp_res_3d.into_iter().flatten().collect();
        let relu3_cmp_res_1d: Vec<bool> = relu3_cmp_res_2d.into_iter().flatten().collect();

        let flattened_relu3_input3d: Vec<Vec<Vec<FpVar<F>>>> =
            conv3_output_fqvar.into_iter().flatten().collect();
        let flattened_relu3_input2d: Vec<Vec<FpVar<F>>> =
            flattened_relu3_input3d.into_iter().flatten().collect();
        let flattened_relu3_input1d: Vec<FpVar<F>> =
            flattened_relu3_input2d.into_iter().flatten().collect();

        let flattened_relu3_output3d: Vec<Vec<Vec<FpVar<F>>>> =
            relu3_output_fqvar.clone().into_iter().flatten().collect();
        let flattened_relu3_output2d: Vec<Vec<FpVar<F>>> =
            flattened_relu3_output3d.into_iter().flatten().collect();
        let flattened_relu3_output1d: Vec<FpVar<F>> =
            flattened_relu3_output2d.into_iter().flatten().collect();

        let relu3_circuit = ReLUCircuitOp3 {
            y_in: flattened_relu3_input1d.clone(),
            y_out: flattened_relu3_output1d.clone(),
            y_zeropoint: self.conv3_output_0,
            cmp_res: relu3_cmp_res_1d.clone(),
        };
        relu3_circuit.generate_constraints(cs.clone())?;

        println!(
            "Relu3 {} {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();

        //flatten to fit FC layers
        let mut transformed_conv3_output =
            vec![
                vec![
                    F::zero();
                    conv3_output[0].len() * conv3_output[0][0].len() * conv3_output[0][0][0].len()
                ];
                conv3_output.len()
            ];
        let mut transformed_conv3_output_fqvar =
            vec![
                vec![
                    FpVar::<F>::Constant(F::zero());
                    conv3_output[0].len() * conv3_output[0][0].len() * conv3_output[0][0][0].len()
                ];
                conv3_output.len()
            ];
        for i in 0..conv3_output.len() {
            let mut counter = 0;
            for j in 0..conv3_output[0].len() {
                for p in 0..conv3_output[0][0].len() {
                    for q in 0..conv3_output[0][0][0].len() {
                        transformed_conv3_output[i][counter] = conv3_output[i][j][p][q];
                        transformed_conv3_output_fqvar[i][counter] =
                            relu3_output_fqvar[i][j][p][q].clone();
                        counter += 1;
                    }
                }
            }
        }

        //layer 4 :
        //FC1 -> relu
        //assume we only do inference on one image(batch size = 1)
        let mut fc1_output = vec![vec![F::zero(); self.fc1_weights.len()];  // channels
                                            transformed_conv3_output.len()]; //batch size
        //let fc1_weight_ref: Vec<Vec<F>> = self.fc1_weights.iter().map(|x| x).collect();

        //assume we only do inference on one image
        let (remainder_fc1, div_fc1) = vec_mat_mul_with_remainder_f(
            &transformed_conv3_output[0],
            self.fc1_weights.clone(),
            &mut fc1_output[0],
            self.conv3_output_0,
            self.fc1_weights_0,
            self.fc1_output_0,
            &self.multiplier_fc1,
        );

        let fc1_output_fqvar = generate_fqvar_f(cs.clone(), fc1_output[0].clone());
        let mut fc1_output0_converted: Vec<F> = Vec::new();
        for i in 0..self.multiplier_fc1.len() {
            let m = self.multiplier_fc1[i];
            fc1_output0_converted.push((self.fc1_output_0 * f22) / m);
        }
        let fc1_weights_fqvar_input =
            generate_fqvar_witness2D_f(cs.clone(), self.fc1_weights.clone());

        let fc1_circuit = FCCircuitOp3 {
            x: transformed_conv3_output_fqvar[0].clone(),
            l1_mat: fc1_weights_fqvar_input.clone(),
            y: fc1_output_fqvar.clone(),
            remainder: remainder_fc1.clone(),
            div: div_fc1.clone(),
            x_0: self.conv3_output_0,
            l1_mat_0: self.fc1_weights_0,
            y_0: fc1_output0_converted,
            zero: F::zero(),
            two_power_8: (64 as u32).into(),
            m_exp: (2u64.pow(M_EXP)).into(),

            multiplier: self.multiplier_fc1.clone(),
        };
        fc1_circuit.generate_constraints(cs.clone())?;

        println!(
            "FC1 {} {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();

        //relu4 layer
        //assume we only process one image
        let cmp_res = relu_f(&mut fc1_output[0], self.fc1_output_0);
        let relu4_output_fqvar = generate_fqvar_f(cs.clone(), fc1_output[0].clone());
        let relu4_circuit = ReLUCircuitOp3 {
            y_in: fc1_output_fqvar.clone(),
            y_out: relu4_output_fqvar.clone(),
            y_zeropoint: self.fc1_output_0,
            cmp_res: cmp_res.clone(),
        };
        relu4_circuit.generate_constraints(cs.clone())?;
        println!(
            "Relu4 {} {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();

        //layer 5 :
        //FC2 -> output
        let mut fc2_output = vec![vec![F::zero(); self.fc2_weights.len()]; // channels
                                            fc1_output.len()]; //batch size
        //let fc2_weight_ref: Vec<&[u8]> = self.fc2_weights.iter().map(|x| x.as_ref()).collect();

        let (remainder_fc2, div_fc2) = vec_mat_mul_with_remainder_f(
            &fc1_output[0],
            self.fc2_weights.clone(),
            &mut fc2_output[0],
            self.fc1_output_0,
            self.fc2_weights_0,
            self.fc2_output_0,
            &self.multiplier_fc2.clone(),
        );
        //println!("z within circuit {:?}", fc2_output.clone());

        let fc2_output_fqvar = generate_fqvar_f(cs.clone(), fc2_output[0].clone());
        let fc2_weights_fqvar_input =
            generate_fqvar_witness2D_f(cs.clone(), self.fc2_weights.clone());

        let mut fc2_output0_converted: Vec<F> = Vec::new();
        for i in 0..self.multiplier_fc2.len() {
            let m = self.multiplier_fc2[i];
            fc2_output0_converted.push(((self.fc2_output_0 as F * f22)) / m);
        }
        let fc2_circuit = FCCircuitOp3 {
            x: relu4_output_fqvar.clone(),
            l1_mat: fc2_weights_fqvar_input.clone(),
            y: fc2_output_fqvar.clone(),

            remainder: remainder_fc2.clone(),
            div: div_fc2.clone(),

            x_0: self.fc1_output_0,
            l1_mat_0: self.fc2_weights_0,
            y_0: fc2_output0_converted,
            zero: F::zero(),
            two_power_8: (64 as u32).into(),
            m_exp: (2u64.pow(M_EXP)).into(),
            multiplier: self.multiplier_fc2.clone(),
        };
        fc2_circuit.generate_constraints(cs.clone())?;

        println!(
            "FC2 {} {}",
            cs.num_constraints() - _cir_number,
            cs.num_constraints()
        );
        _cir_number = cs.num_constraints();

        let mut commit_vec = Vec::<FpVar<F>>::new();
        commit_vec.extend(convert_4d_vector_into_1d(x_fqvar));
        commit_vec.extend(convert_4d_vector_into_1d(conv1_weight_fqvar_input));
        commit_vec.extend(convert_4d_vector_into_1d(conv2_weight_fqvar_input));
        commit_vec.extend(convert_4d_vector_into_1d(conv3_weight_fqvar_input));
        commit_vec.extend(convert_2d_vector_into_1d(fc1_weights_fqvar_input));
        commit_vec.extend(convert_2d_vector_into_1d(fc2_weights_fqvar_input));
        //commit_vec.extend(z_fqvar);
        let commit_len = commit_vec.len();

        /*let intermediate = commit_vec[0].clone() * beta_vars[0].clone();
        let prev = intermediate.clone();
        for idx in 1..commit_len {
            let intermediatee = commit_vec[idx].clone() * beta_vars[idx].clone();
            let prevv = 
        }
        rho_vec[commit_len - 1].enforce_equal(&rho_var);*/

        //let commit_vec_f: Vec<Fq> = commit_vec.iter().map(|x| x.into()).collect();

        let commit_poly = DensePolynomialVar::<F>::from_coefficients_vec(commit_vec);
        let rho_circ = commit_poly.evaluate(&beta_var)?;
        rho_circ.enforce_equal(&rho_var).unwrap();

        println!("Commit {}", cs.num_constraints() - _cir_number);
        Ok(())
    }
}
