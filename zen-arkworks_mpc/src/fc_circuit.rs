use crate::*;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::bits::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{println, vec, vec::Vec, test_rng};
use ark_ed_on_bls12_381::{constraints::FqVar, Fq, Fr};
use ark_ff::*;
use mpc_algebra::Reveal;



#[derive(Debug, Clone)]
pub struct FCCircuitOp3<F: PrimeField> {
     //x and y are already encoded and mapped to FqVar for use.
     pub x: Vec<FpVar<F>>,
     pub l1_mat: Vec<Vec<FpVar<F>>>,
     pub y: Vec<FpVar<F>>, //it is already restored.
 
     //these two variables are used to restore the real y. this happens outside the circuit
     pub remainder: Vec<F>,
     pub div: Vec<F>,
 
     //zero points for quantization
     pub x_0: F,
     pub l1_mat_0: F,
     pub y_0: Vec<F>,
 
     //multiplier for quantization. s1*s2/s3
     pub multiplier: Vec<F>,
     pub two_power_8: F,
     pub m_exp: F,
     pub zero: F,
}

// =============================
// constraints
// =============================
impl <F: PrimeField>ConstraintSynthesizer<F> for FCCircuitOp3<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        #[cfg(debug_assertions)]
        println!("is setup mode?: {}", cs.is_in_setup_mode());
        
        let two_power_8_constant = FpVar::<F>::Constant(self.two_power_8);

        let m_exp_constant = FpVar::<F>::Constant(self.m_exp);

        let zero_var = FpVar::<F>::Constant(self.zero);


        let mut assembled_vec_x = vec![zero_var.clone(); self.x.len()];
        //only implemented 3 and 4 vector SIMD processing
        if true {//self.x.len() < 2u32.pow(SIMD_BOTTLENECK as u32) as usize {
            //we do not use simd because vector length is tooooo short, and we can not benefit from it.
            for i in 0..self.y.len() {
                let multiplier_var = FpVar::<F>::Constant(self.multiplier[i]);

                let tmp = multiplier_var
                    * scala_cs_helper_u8(
                        cs.clone(),
                        &self.x,
                        &self.l1_mat[i],
                        self.x_0,
                        self.l1_mat_0,
                        self.y_0[i],
                    );

                //let div1: F = (self.div[i] as u64).into();
                let div1_var =
                    FpVar::<F>::new_witness(ark_relations::ns!(cs, "div1 gadget"), || Ok(self.div[i]))
                        .unwrap();
                //let remainder1: F = (self.remainder[i] as u64).into();
                let remainder1_var =
                    FpVar::<F>::new_witness(ark_relations::ns!(cs, "remainder1 gadget"), || {
                        Ok(self.remainder[i])
                    })
                    .unwrap();
                let yy1_var = (self.y[i].clone() + div1_var * two_power_8_constant.clone())
                    * m_exp_constant.clone()
                    + remainder1_var;

                tmp.enforce_equal(&yy1_var).unwrap();
            }
        }
        Ok(())
    }
}


//when model is public and image is secret, model parameters should use new_input() instead of new_witness()
fn scala_cs_helper_u8_simd(
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
    for i in 0..length {
        //x_zeropoint, kernel_zeropoints and y_zeropoints are all Constant wires because they are independent of input image
        let w_const = kernel[i].clone();
        //let w_fq: Fq = kernel[i].into();
        //let w_const = FpVar::new_input(ark_relations::ns!(cs, "w "), || Ok(w_fq)).unwrap();

        tmp1 += x[i].clone() * w_const.clone();

        tmp2 += x[i].clone() * kernel0_const.clone();
        tmp3 += w_const.clone() * input0_const.clone();

        tmp4 += input0_const.clone() * kernel0_const.clone();
    }
    // println!("tmp1 + tmp4 {:?}", (tmp1.clone() + tmp4.clone()).to_bits_le().unwrap().value().unwrap());
    // println!("y_zero {:?}", y_zeropoint_converted.to_bits_le().unwrap().value().unwrap());
    // println!("tmp2 + tmp3 {:?}", (tmp2.clone() + tmp3.clone()).to_bits_le().unwrap().value().unwrap());
    let res = (tmp1 + tmp4 + y_zeropoint_converted) - (tmp2 + tmp3);

    res
}

//when model is public and image is secret, model parameters should use new_input() instead of new_witness()
fn scala_cs_helper_u8_mpc<F: PrimeField, MFr: PrimeField + Reveal<Base = F>>(
    cs: ConstraintSystemRef<MFr>,
    input: &[FpVar<MFr>],  //witness
    weight: &[FpVar<MFr>], //constant
    input_zeropoint: u8,
    weight_zeropoint: u8,
    y_zeropoint: u64,
) -> FpVar<MFr> {
    let _no_cs = cs.num_constraints();
    if input.len() != weight.len() {
        panic!("scala mul: length not equal");
    }
    
    let mut tmp1 =
        FpVar::<MFr>::new_witness(ark_relations::ns!(cs, "q1*q2 gadget"), || Ok(MFr::zero())).unwrap();
    let mut tmp2 =
        FpVar::<MFr>::new_witness(ark_relations::ns!(cs, "q1*z2 gadget"), || Ok(MFr::zero())).unwrap();
    let mut tmp3 =
        FpVar::<MFr>::new_witness(ark_relations::ns!(cs, "q2*z1 gadget"), || Ok(MFr::zero())).unwrap();
    let mut tmp4 =
        FpVar::<MFr>::new_witness(ark_relations::ns!(cs, "z1*z2 gadget"), || Ok(MFr::zero())).unwrap();

    //zero points of input, weight and y for quantization are all fixed after training, so they are Constant wires.
    let y0: F = y_zeropoint.into();
    let rng = &mut test_rng();
    let y0_shares = MFr::king_share(y0, rng);
    let y0_const = FpVar::Constant(y0_shares);

    let w0: F = weight_zeropoint.into();
    let input0: F = input_zeropoint.into();

    let rng = &mut test_rng();
    let w0_shares = MFr::king_share(w0, rng);
    let rng = &mut test_rng();
    let input0_shares = MFr::king_share(input0, rng);

    let w0_const = FpVar::Constant(w0_shares);
    let input0_const = FpVar::Constant(input0_shares);
    //println!("input0 {:?}\n\n\n", input[0].clone().to_bits_le().unwrap().value().unwrap());
    //let mut v = Vec::new();
    for i in 0..input.len() {
        let w_const = weight[i].clone();
        //let w_const = FpVar::new_input(ark_relations::ns!(cs, "w tmp"), || Ok(w)).unwrap();
        //v.push(input[i].clone() * w_const.clone());
        tmp1 += input[i].clone() * w_const.clone();
        tmp2 += input[i].clone() * w0_const.clone();
        tmp3 += w_const.clone() * input0_const.clone();
        tmp4 += w0_const.clone() * input0_const.clone();
    }
    //let tmp1 : FpVar<Fq>= v.iter().sum();
    //println!("tmp1 {:?} \n tmp2 {:?} \n tmp3 {:?} \n tmp4 {:?}\n\n\n\n", tmp1.value().unwrap(), tmp2.value().unwrap(), tmp3.value().unwrap(), tmp4.value().unwrap());
    let res = (tmp1.clone() + tmp4.clone() + y0_const) - (tmp2 + tmp3);
    //println!("{:?}\n\n\n", (tmp1.clone() + tmp4.clone()).to_bits_le().unwrap().value().unwrap());
    res
}


//when model is public and image is secret, model parameters should use new_input() instead of new_witness()
fn scala_cs_helper_u8<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    input: &[FpVar<F>],  //witness
    weight: &[FpVar<F>], //constant
    input_zeropoint: F,
    weight_zeropoint: F,
    y_zeropoint: F,
) -> FpVar<F> {
    let _no_cs = cs.num_constraints();
    if input.len() != weight.len() {
        panic!("scala mul: length not equal");
    }
    
    let mut tmp1 =
        FpVar::<F>::new_witness(ark_relations::ns!(cs, "q1*q2 gadget"), || Ok(F::zero())).unwrap();
    let mut tmp2 =
        FpVar::<F>::new_witness(ark_relations::ns!(cs, "q1*z2 gadget"), || Ok(F::zero())).unwrap();
    let mut tmp3 =
        FpVar::<F>::new_witness(ark_relations::ns!(cs, "q2*z1 gadget"), || Ok(F::zero())).unwrap();
    let mut tmp4 =
        FpVar::<F>::new_witness(ark_relations::ns!(cs, "z1*z2 gadget"), || Ok(F::zero())).unwrap();

    //zero points of input, weight and y for quantization are all fixed after training, so they are Constant wires.
    let y0_const = FpVar::Constant(y_zeropoint);
    let w0_const = FpVar::Constant(weight_zeropoint);
    let input0_const = FpVar::Constant(input_zeropoint);
    //println!("input0 {:?}\n\n\n", input[0].clone().to_bits_le().unwrap().value().unwrap());
    //let mut v = Vec::new();
    for i in 0..input.len() {
        let w_const = weight[i].clone();
        //let w_const = FpVar::new_input(ark_relations::ns!(cs, "w tmp"), || Ok(w)).unwrap();
        //v.push(input[i].clone() * w_const.clone());
        tmp1 += input[i].clone() * w_const.clone();
        tmp2 += input[i].clone() * w0_const.clone();
        tmp3 += w_const.clone() * input0_const.clone();
        tmp4 += w0_const.clone() * input0_const.clone();
    }
    //let tmp1 : FpVar<Fq>= v.iter().sum();
    //println!("tmp1 {:?} \n tmp2 {:?} \n tmp3 {:?} \n tmp4 {:?}\n\n\n\n", tmp1.value().unwrap(), tmp2.value().unwrap(), tmp3.value().unwrap(), tmp4.value().unwrap());
    let res = (tmp1.clone() + tmp4.clone() + y0_const) - (tmp2 + tmp3);
    //println!("{:?}\n\n\n", (tmp1.clone() + tmp4.clone()).to_bits_le().unwrap().value().unwrap());
    res
}