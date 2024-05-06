use crate::*;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::bits::*;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::ConstraintSystem;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{println, vec, vec::Vec};
use ark_ed_on_bls12_381::{constraints::FqVar, Fq, Fr};
use ark_ff::*;



#[derive(Debug, Clone)]
pub struct ConvCircuitOp3<F: PrimeField>{
    pub x: Vec<Vec<Vec<Vec<FpVar<F>>>>>, // [Batch Size, Num Channel, Height, Width]
    pub conv_kernel: Vec<Vec<Vec<Vec<FpVar<F>>>>>, //[Num Kernel, Num Channel, kernel_size, kernel_size]
    pub y: Vec<Vec<Vec<Vec<FpVar<F>>>>>, // [Batch Size, Num Kernel, Height - kernel_size + 1, Width - kernel_size + 1]

    //these two variables are used to restore the real y
    pub remainder: Vec<Vec<Vec<Vec<F>>>>,
    pub div: Vec<Vec<Vec<Vec<F>>>>,

    //zero points for quantization
    pub x_0: F,
    pub conv_kernel_0: F,
    pub y_0: Vec<F>,

    //multiplier for quantization. s1*s2/s3
    pub multiplier: Vec<F>,
}

impl <F: PrimeField>ConstraintSynthesizer<F> for ConvCircuitOp3<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        #[cfg(debug_assertion)]
        println!(
            "ConvCircuitOp3OldSIMD is setup mode: {}",
            cs.is_in_setup_mode()
        );

        let batch_size = self.x.len();
        let num_channels = self.conv_kernel[0].len();
        let input_height = self.x[0][0].len();
        let input_width = self.x[0][0][0].len();
        let num_kernels = self.conv_kernel.len();
        let kernel_size = self.conv_kernel[0][0].len();

        let two_power_8: F = (2u64.pow(8)).into();
        let two_power_8_constant = FpVar::<F>::Constant(two_power_8);
        let m_exp_fq: F = (2u64.pow(M_EXP)).into();
        let m_exp_constant = FpVar::<F>::Constant(m_exp_fq);
        //println!("input size {} {} {} {}", batch_size, num_channels, input_height, input_width);
        //println!("kernel size {} {} {} {}", num_kernels, num_channels, kernel_size, kernel_size);
        if true {
            //we do not use SIMD
            println!("we don't use old SIMD");
            for k in 0..num_kernels {
                //println!("k {} multiplier {}", k, ((self.multiplier[k] * (2u32.pow(M_EXP)) as f32) as u128));
                let multiplier: F = self.multiplier[k];
                let multiplier_var = FpVar::<F>::Constant(multiplier);
                for n in 0..batch_size {
                    for h in 0..(input_height - kernel_size + 1) {
                        for w in 0..(input_width - kernel_size + 1) {
                            let tmp = conv_kernel_helper_fq(
                                cs.clone(),
                                self.x[n].clone(),
                                self.conv_kernel[k].clone(),
                                h,
                                w,
                                self.x_0,
                                self.conv_kernel_0,
                                self.y_0[k],
                            );

                            let tmp = tmp * multiplier_var.clone();

                            let yy_var = self.y[n][k][h][w].clone();
                            let div: F = self.div[n][k][h][w].into();
                            let div_var =
                                FpVar::<F>::new_witness(ark_relations::ns!(cs, "div gadget"), || {
                                    Ok(div)
                                })
                                .unwrap();
                            let remainder: F = self.remainder[n][k][h][w].into();
                            let remainder_var = FpVar::<F>::new_witness(
                                ark_relations::ns!(cs, "remainder gadget"),
                                || Ok(remainder),
                            )
                            .unwrap();
                            let output_var = (yy_var + div_var * two_power_8_constant.clone())
                                * m_exp_constant.clone()
                                + remainder_var;

                            output_var.enforce_equal(&tmp).unwrap();
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn conv_kernel_helper_u8_simd(
    cs: ConstraintSystemRef<Fq>,
    x: Vec<FqVar>,
    kernel: Vec<FqVar>,
    x_zeropoint: u128,
    kernel_zeropoint: u128,

    y_zeropoint_converted: FqVar,
) -> FqVar {
    let _no_cs = cs.num_constraints();

    let length = kernel.len();
    let mut tmp1 =
        FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "q1*q2 gadget"), || Ok(Fq::zero())).unwrap();
    
        let mut tmp2 =
        FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "q1*z2 gadget"), || Ok(Fq::zero())).unwrap();
    let mut tmp3 =
        FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "q2*z1 gadget"), || Ok(Fq::zero())).unwrap();
    let mut tmp4 =
        FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "z1*z2 gadget"), || Ok(Fq::zero())).unwrap();

    let kernel0: Fq = kernel_zeropoint.into();
    let input0: Fq = x_zeropoint.into();
    let kernel0_const = FpVar::Constant(kernel0);
    let input0_const = FpVar::Constant(input0);
    //let mut v = Vec::new();

    for i in 0..length {
        //x_zeropoint, kernel_zeropoints and y_zeropoints are all Constant wires because they are independent of input image
        //let w_fq: Fq = kernel[i].into();
        //let w_const = FpVar::Constant(w_fq);
        //let w_const = FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "w "), || Ok(w_fq)).unwrap();
        let w_const = kernel[i].clone();
        tmp1 += x[i].clone() * w_const.clone();
        //v.push(x[i].clone() * w_const.clone());

        tmp2 += x[i].clone() * kernel0_const.clone();
        tmp3 += w_const.clone() * input0_const.clone();

        tmp4 += input0_const.clone() * kernel0_const.clone();
    }
   //let tmp1 : FpVar<Fq>= v.iter().sum();

    // println!("tmp1 + tmp4 {:?}", (tmp1.clone() + tmp4.clone()).to_bits_le().unwrap().value().unwrap());
    // println!("y_zero {:?}", y_zeropoint_converted.to_bits_le().unwrap().value().unwrap());
    // println!("tmp2 + tmp3 {:?}", (tmp2.clone() + tmp3.clone()).to_bits_le().unwrap().value().unwrap());
    let res = (tmp1 + tmp4 + y_zeropoint_converted) - (tmp2 + tmp3);

    res
}

fn conv_kernel_helper_fq<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    x: Vec<Vec<Vec<FpVar<F>>>>,
    kernel: Vec<Vec<Vec<FpVar<F>>>>,
    h_index: usize,
    w_index: usize,

    x_zeropoint: F,
    kernel_zeropoint: F,

    y_0_converted: F,
) -> FpVar<F> {
    let _no_cs = cs.num_constraints();

    let num_channels = kernel.len();
    let kernel_size = kernel[0].len();
    let mut tmp1 =
        FpVar::<F>::new_witness(ark_relations::ns!(cs, "q1*q2 gadget"), || Ok(F::zero())).unwrap();
    let mut tmp2 =
        FpVar::<F>::new_witness(ark_relations::ns!(cs, "q1*z2 gadget"), || Ok(F::zero())).unwrap();
    let mut tmp3 =
        FpVar::<F>::new_witness(ark_relations::ns!(cs, "q2*z1 gadget"), || Ok(F::zero())).unwrap();
    let mut tmp4 =
        FpVar::<F>::new_witness(ark_relations::ns!(cs, "z1*z2 gadget"), || Ok(F::zero())).unwrap();

    let y_zeropoint_fq: F = y_0_converted.into();
    let y_zeropoint_var = FpVar::<F>::Constant(y_zeropoint_fq);

    let kernel0: F = kernel_zeropoint.into();
    let input0: F = x_zeropoint.into();
    let kernel0_const = FpVar::Constant(kernel0);
    let input0_const = FpVar::Constant(input0);
    for i in 0..num_channels {
        //iterate through all channels
        for j in h_index..(h_index + kernel_size) {
            for k in w_index..(w_index + kernel_size) {
                //let w: Fq = kernel[i][j - h_index][k - w_index].into();
                //let w_const = FpVar::Constant(w);
                //x_zeropoint, kernel_zeropoints and y_zeropoints are all Constant wires because they are independent of input image
                //let w_const = FpVar::<Fq>::new_witness(ark_relations::ns!(cs, "w tmp"), || Ok(w)).unwrap();
                let w_const = kernel[i][j - h_index][k - w_index].clone();
                tmp1 += x[i][j][k].clone() * w_const.clone();
                tmp2 += x[i][j][k].clone() * kernel0_const.clone();
                tmp3 += w_const.clone() * input0_const.clone();

                tmp4 += input0_const.clone() * kernel0_const.clone();
            }
        }
    }

    let res = (tmp1 + tmp4 + y_zeropoint_var) - (tmp2 + tmp3);

    res
}
