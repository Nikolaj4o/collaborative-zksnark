pub type ConstraintF = ark_bls12_377::Fr;

pub mod psponge;
pub mod pedersen;
pub mod r1cs;
pub mod pedersen_params;
pub mod zk_params;
pub mod util;
pub mod fc_circuit;
pub mod conv_circuit;
pub mod read_inputs;
pub mod relu_circuit;
pub mod cosine_circuit;
pub mod avg_pool_circuit;
pub mod argmax_circuit;
pub mod lenet_circuit;
pub mod full_circuit;
pub mod vanilla;
pub mod kzgcom_circuit;
pub mod poly_circuit;
pub mod poseidon_circuit;

pub use pedersen::*;
pub use r1cs::{PedersenComCircuit};
pub use crate::zk_params::ZK_PARAM;
pub use pedersen_params::COMMIT_PARAM;
pub use r1cs::*;
pub use fc_circuit::*;
pub use conv_circuit::*;
pub use read_inputs::*;

pub use conv_circuit::*;
pub use avg_pool_circuit::*;
pub use argmax_circuit::*;

pub use vanilla::*;
//=======================
// dimensions
//=======================
pub(crate) const M: usize = 128;
pub(crate) const N: usize = 10;

//should be consistent
//pub(crate) const SIMD_5VEC_EXTRA_BITS: u32 = 3; //not used in our implementation
pub(crate) const SIMD_4VEC_EXTRA_BITS: u32 = 12; //in case the long vector dot product overflow. 12 can hold at least vector of length 2^12
pub(crate) const SIMD_3VEC_EXTRA_BITS: u32 = 20;
//pub(crate) const SIMD_2VEC_EXTRA_BITS: u32 = 68;
pub(crate) const M_EXP: u32 = 22;

pub(crate) const SIMD_BOTTLENECK: usize = 210;
//=======================
// data
//=======================

pub const FACE_HEIGHT: usize = 46;
pub const FACE_HEIGHT_FC1: usize = 5;
pub const FACE_WIDTH: usize = 56;
pub const FACE_WIDTH_FC1: usize = 8;

use ark_bls12_377::Bls12_377;
pub type CurveTypeG = Bls12_377;
pub use ark_ed_on_bls12_377::*;
pub use ark_ed_on_bls12_377::{constraints::EdwardsVar, *};