use std::str::FromStr;

use ark_ff::{
    biginteger::BigInteger64 as BigInteger, field_new, fields::{FftParameters, Fp64, Fp64Parameters, FpParameters}, Field, PrimeField
};

pub type F2= Fp64<F2Parameters>;

pub struct F2Parameters;

impl Fp64Parameters for F2Parameters {}
impl FftParameters for F2Parameters {
    type BigInt = BigInteger;

    const TWO_ADICITY: u32 = 1;

    #[rustfmt::skip]
    const TWO_ADIC_ROOT_OF_UNITY: BigInteger = BigInteger([1]);
}

impl FpParameters for F2Parameters {
    #[rustfmt::skip]
    const MODULUS: BigInteger = BigInteger([0x2]);

    const MODULUS_BITS: u32 = 2;

    const CAPACITY: u32 = Self::MODULUS_BITS - 1;

    const REPR_SHAVE_BITS: u32 = 1;

    #[rustfmt::skip]
    const R: BigInteger = BigInteger([1]);

    #[rustfmt::skip]
    const R2: BigInteger = BigInteger([1]);

    const INV: u64 = 0xfffffffffffffffe;

    /// GENERATOR = 2
    /// Encoded in Montgomery form, so the value is
    /// 2 * R % q = 2758230843577277949620073511305048635578704962089743514587482222134842183668501798417467556318533664893264801977679
    #[rustfmt::skip]
    const GENERATOR: BigInteger = BigInteger([1]);

    #[rustfmt::skip]
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([1]);

    /// T and T_MINUS_ONE_DIV_TWO, where MODULUS - 1 = 2^S * T
    /// For T coprime to 2
    #[rustfmt::skip]
    const T: BigInteger = BigInteger([1]);

    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([1]);
}

pub const FQ_ONE: F2 = field_new!(F2, "1");
pub const FQ_ZERO: F2 = field_new!(F2, "0");

// pub struct BinField {
//     val: bool,
// }

// impl From<bool> for BinField {
//     fn from(value: bool) -> Self {
//         Self{val: value}
//     }
// }
// impl From<u8> for BinField {
//     fn from(value: u8) -> Self {
//         Self{val: value > 0}
//     } 
// }
// impl From<u16> for BinField {
//     fn from(value: u16) -> Self {
//         Self{val: value > 0}
//     } 
// }
// impl From<u32> for BinField {
//     fn from(value: u32) -> Self {
//         Self{val: value > 0}
//     } 
// }
// impl From<u64> for BinField {
//     fn from(value: u64) -> Self {
//         Self{val: value > 0}
//     }  
// }
// impl From<u128> for BinField {
//     fn from(value: u128) -> Self {
//         Self{val: value > 0}
//     } 
// }

// impl Field for BinField {
//     type BasePrimeField = BinField;

//     fn extension_degree() -> u64 {
//         todo!()
//     }

//     fn from_base_prime_field_elems(elems: &[Self::BasePrimeField]) -> Option<Self> {
//         todo!()
//     }

//     fn double(&self) -> Self {
//         todo!()
//     }

//     fn double_in_place(&mut self) -> &mut Self {
//         todo!()
//     }

//     fn from_random_bytes_with_flags<F: ark_serialize::Flags>(bytes: &[u8]) -> Option<(Self, F)> {
//         todo!()
//     }

//     fn square(&self) -> Self {
//         todo!()
//     }

//     fn square_in_place(&mut self) -> &mut Self {
//         todo!()
//     }

//     fn inverse(&self) -> Option<Self> {
//         todo!()
//     }

//     fn inverse_in_place(&mut self) -> Option<&mut Self> {
//         todo!()
//     }

//     fn frobenius_map(&mut self, power: usize) {
//         todo!()
//     }
    
//     fn characteristic<'a>() -> &'a [u64] {
//         Self::BasePrimeField::characteristic()
//     }
    
//     fn from_random_bytes(bytes: &[u8]) -> Option<Self> {
//         Self::from_random_bytes_with_flags::<ark_serialize::EmptyFlags>(bytes).map(|f| f.0)
//     }
    
//     fn pow<S: AsRef<[u64]>>(&self, exp: S) -> Self {
//         todo!()
//     }
    
//     fn pow_with_table<S: AsRef<[u64]>>(powers_of_2: &[Self], exp: S) -> Option<Self> {
//         todo!()
//     }
    
//     fn batch_product_in_place(selfs: &mut [Self], others: &[Self]) {
//         todo!()
//     }
    
//     fn batch_division_in_place(selfs: &mut [Self], others: &[Self]) {
//         todo!()
//     }
    
//     fn partial_products_in_place(selfs: &mut [Self]) {
//         todo!()
//     }
    
//     fn has_univariate_div_qr() -> bool {
//         false
//     }
    
//     fn univariate_div_qr<'a>(
//         _num: ark_ff::poly_stub::DenseOrSparsePolynomial<'a, Self>,
//         _den: ark_ff::poly_stub::DenseOrSparsePolynomial<'a, Self>,
//     ) -> Option<(
//         ark_ff::poly_stub::DensePolynomial<Self>,
//         ark_ff::poly_stub::DensePolynomial<Self>,
//     )> {
//         panic!("No special division algorithm")
//     }
// }
// impl FromStr for BinField {
//     type Err = ();

//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         if s.is_empty() {
//             return Err(());
//         }
//         if s == "0" {
//             return Ok(Self::zero());
//         } else if s == "1" {
//             return Ok(Self::one());
//         } else {
//             return Ok(Self::one());
//         }
//     }
// }

// impl PrimeField for BinField {
//     type Params = F2Parameters;

//     type BigInt = bool;

//     fn from_repr(repr: Self::BigInt) -> Option<Self> {
//         Some(BinField{val: repr})
//     }

//     fn into_repr(&self) -> Self::BigInt {
//         return self.val
//     }
    
//     fn from_repr_unwrap(repr: Self::BigInt) -> Self {
//         Self::from_repr(repr).unwrap()
//     }
    
//     fn bit_decomp(&self) -> Vec<Self> {
//         todo!()
//     }
    
//     fn trunc (&self, bits: u32) -> Self {
//         todo!()
//     }
    
//     fn modulo (&self, bits: u32) -> Self {
//         todo!()
//     }
    
//     fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
//        todo!()
//     }
    
//     fn from_le_bytes_mod_order(bytes: &[u8]) -> Self {
//         todo!()
//     }
    
//     fn qnr_to_t() -> Self {
//         Self::two_adic_root_of_unity()
//     }
    
//     fn size_in_bits() -> usize {
//         Self::Params::MODULUS_BITS as usize
//     }
    
//     fn trace() -> Self::BigInt {
//         Self::Params::T
//     }
    
//     fn trace_minus_one_div_two() -> Self::BigInt {
//         Self::Params::T_MINUS_ONE_DIV_TWO
//     }
    
//     fn modulus_minus_one_div_two() -> Self::BigInt {
//         Self::Params::MODULUS_MINUS_ONE_DIV_TWO
//     }
// }