use ark_ff::{
    biginteger::BigInteger64 as BigInteger,
    field_new,
    fields::{FftParameters, Fp64, Fp64Parameters, FpParameters},
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
