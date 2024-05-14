//use alloc::collections;
use ark_poly::{domain, EvaluationDomain, GeneralEvaluationDomain};
use ark_std::test_rng;
use derivative::Derivative;
use log::debug;
use rand::Rng;
use zeroize::Zeroize;

use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::{prelude::*, BigInteger64};
use ark_ff::{poly_stub, FftField};
use ark_serialize::{
    CanonicalDeserialize, CanonicalDeserializeWithFlags, CanonicalSerialize,
    CanonicalSerializeWithFlags, Flags, SerializationError,
};
use mpc_trait::MpcWire;
use ark_ff::BitIteratorBE;

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{self, Read, Write};
use std::iter::{Product, Sum};
use std::marker::PhantomData;
use std::{ops::*, vec};

use super::super::share::field::FieldShare;
use super::super::share::BeaverSource;
use crate::bin::F2;
use crate::{Reveal, SpdzFieldShare};
use mpc_net::{MpcNet, MpcMultiNet as Net};

#[derive(Clone, Copy, Hash, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MpcField<F: Field, S: FieldShare<F>> {
    Public(F),
    Shared(S),
}

impl_basics_2!(FieldShare, Field, MpcField);

#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Copy(bound = ""))]
pub struct DummyFieldTripleSource<T, S> {
    _scalar: PhantomData<T>,
    _share: PhantomData<S>,
}

impl<T: Field, S: FieldShare<T>> BeaverSource<S, S, S> for DummyFieldTripleSource<T, S> {
    #[inline]
    fn triple(&mut self) -> (S, S, S) {
        (
            S::from_add_shared(if Net::am_king() {
                T::one()
            } else {
                T::zero()
            }),
            S::from_add_shared(if Net::am_king() {
                T::one()
            } else {
                T::zero()
            }),
            S::from_add_shared(if Net::am_king() {
                T::one()
            } else {
                T::zero()
            }),
        )
    }
    #[inline]
    fn inv_pair(&mut self) -> (S, S) {
        (
            S::from_add_shared(if Net::am_king() {
                T::one()
            } else {
                T::zero()
            }),
            S::from_add_shared(if Net::am_king() {
                T::one()
            } else {
                T::zero()
            }),
        )
    }
    
    fn nbit_val(&mut self, n: u32) -> S {
        let rng = &mut test_rng();
        let val = T::rand(rng);
        let mut modulus = T::from(2u32);
        modulus.pow([n as u64]);
        print!("Modulus: {modulus}, N: {n}\n");
        S::from_add_shared(T::from(val))
    }
}

impl<T: Field, S: FieldShare<T>> MpcField<T, S> {
    #[inline]
    pub fn inv(self) -> Option<Self> {
        match self {
            Self::Public(x) => x.inverse().map(MpcField::Public),
            Self::Shared(x) => Some(MpcField::Shared(
                x.inv(&mut DummyFieldTripleSource::default()),
            )),
        }
    }
    pub fn all_public_or_shared(v: impl IntoIterator<Item = Self>) -> Result<Vec<T>, Vec<S>> {
        let mut out_a = Vec::new();
        let mut out_b = Vec::new();
        for s in v {
            match s {
                Self::Public(x) => out_a.push(x),
                Self::Shared(x) => out_b.push(x),
            }
        }
        if out_a.len() > 0 && out_b.len() > 0 {
            panic!("Heterogeous")
        } else if out_a.len() > 0 {
            Ok(out_a)
        } else {
            Err(out_b)
        }
    }

}
// impl<F: PrimeField, S: FieldShare<F>> MpcField<F, S> {
//     pub fn unbounded_fanin_or(bits: Vec<Self>) -> Self {
//         let rng = &mut test_rng();
//         let A: Self = Self::one() + bits.iter().sum();
//         let bitlen = bits.len();
//         let domain: GeneralEvaluationDomain::<Self> = GeneralEvaluationDomain::<Self>::new(bitlen + 1).unwrap();
//         let mut evals = vec![Self::zero(); bitlen + 1];
//         evals[bitlen] = Self::one();
//         //end_timer!(build_domain_timer);
//         //let ifft_timer = start_timer!(|| "ifft");
//         domain.ifft_in_place(&mut evals);
//         let mut b: Vec<Self> = vec![Self::zero(); bitlen].iter().map(|x| Self::from_add_shared(F::rand(rng))).collect();
//         let b_p: Vec<Self> = vec![Self::zero(); bitlen].iter().map(|x| Self::from_add_shared(F::rand(rng))).collect();
//         let B: Vec<Self> = b.iter().zip(b_p).map(|(a, b)| *a*b).collect();
//         B.iter().map(|x| (*x).publicize());
//         let b_inv = b_p.iter().zip(B).map(|(a, b)| (*a) * b.inv().unwrap());
//         let mut b_shift = b.clone();
//         b_shift.pop();
//         b_shift = vec![Self::one();1].iter().chain(&b_shift).map(|x| *x).collect();
//         let c: Vec<Self> = b_shift.iter().zip(b_inv).map(|(a, b)| A * (*a) * b).collect();
//         c.iter().map(|x| (*x).publicize());
//         let mut A_pows: Vec<Self> = b.iter().enumerate().map(|(i, x)| *x * c[0..i].iter().product()).collect();
//         A_pows = vec![Self::one(); 1].iter().chain(&A_pows).map(|x| *x).collect();
//         let result = vec![Self::one(); 1].iter().chain(&A_pows).zip(evals).map(|(a, b)| *a * b ).sum();
//         result
//     }
//     pub fn prefix_or(bits: Vec<Self>) -> Vec<Self> {
//         let lambda = (bits.len()).sqrt() as u32;
//         let mut x = vec![Self::zero(); lambda];
//         let mut y = vec![Self::zero(); lambda];
//         for i in 0..lambda {
//             x[i] = unbounded_fanin_or(bits[i * lambda..(i + 1)*lambda]);
//         }
//         for i in 0..lambda {
//             y[i] = unbounded_fanin_or(x[0..i]);
//         }
//         let mut f = vec![Self::zero(); lambda];
//         f[0] = x[0];
//         for i in 1..lambda {
//             f[i] = y[i] - y[i - 1];
//         }
//         let mut g = vec![Self::zero(); bits.len()];

//         for i in 0..lambda {
//             for j in 0..lambda {
//                 g[i*lambda + j] = f[i] * a[i*lambda + j];
//             }
//         }

//         for i in 0..lambda {
//             c[i] = g[i * lambda..(i+1)*lambda].iter().sum();
//         }

//         let mut b_p = vec![Self::zero(); lambda];
//         for i in 0..lambda {
//             b_p[i] = unbounded_fanin_or(c[0..i]);
//         }

//         for i in 0..lambda {
//             for j in 0..lambda {
//                 g[i*lambda + j] = f[i] * a[i*lambda + j];
//             }
//         }
//         g
//     }
//     pub fn bitwise_lt () {

//     }
// }
impl<'a, T: Field, S: FieldShare<T>> MulAssign<&'a MpcField<T, S>> for MpcField<T, S> {
    #[inline]
    fn mul_assign(&mut self, other: &Self) {
        match self {
            // for some reason, a two-stage match (rather than a tuple match) avoids moving
            // self
            MpcField::Public(x) => match other {
                MpcField::Public(y) => {
                    *x *= y;
                }
                MpcField::Shared(y) => {
                    let mut t = *y;
                    t.scale(x);
                    *self = MpcField::Shared(t);
                }
            },
            MpcField::Shared(x) => match other {
                MpcField::Public(y) => {
                    x.scale(y);
                }
                MpcField::Shared(y) => {
                    let t = x.mul(*y, &mut DummyFieldTripleSource::default());
                    *self = MpcField::Shared(t);
                }
            },
        }
    }
}
impl<T: Field, S: FieldShare<T>> One for MpcField<T, S> {
    #[inline]
    fn one() -> Self {
        MpcField::Public(T::one())
    }
}
impl<T: Field, S: FieldShare<T>> Product for MpcField<T, S> {
    #[inline]
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), Mul::mul)
    }
}
impl<'a, T: Field, S: FieldShare<T> + 'a> Product<&'a MpcField<T, S>> for MpcField<T, S> {
    #[inline]
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::one(), |x, y| x.mul(y.clone()))
    }
}

impl<'a, T: Field, S: FieldShare<T>> DivAssign<&'a MpcField<T, S>> for MpcField<T, S> {
    #[inline]
    fn div_assign(&mut self, other: &Self) {
        match self {
            // for some reason, a two-stage match (rather than a tuple match) avoids moving
            // self
            MpcField::Public(x) => match other {
                MpcField::Public(y) => {
                    *x /= y;
                }
                MpcField::Shared(y) => {
                    let mut t = y.inv(&mut DummyFieldTripleSource::default());
                    t.scale(&x);
                    *self = MpcField::Shared(t);
                }
            },
            MpcField::Shared(x) => match other {
                MpcField::Public(y) => {
                    x.scale(&y.inverse().unwrap());
                }
                MpcField::Shared(y) => {
                    let src = &mut DummyFieldTripleSource::default();
                    *x = x.div(*y, src);
                }
            },
        }
    }
}

impl_ref_ops!(
    Mul,
    MulAssign,
    mul,
    mul_assign,
    Field,
    FieldShare,
    MpcField
);
impl_ref_ops!(
    Add,
    AddAssign,
    add,
    add_assign,
    Field,
    FieldShare,
    MpcField
);
impl_ref_ops!(
    Div,
    DivAssign,
    div,
    div_assign,
    Field,
    FieldShare,
    MpcField
);
impl_ref_ops!(
    Sub,
    SubAssign,
    sub,
    sub_assign,
    Field,
    FieldShare,
    MpcField
);

impl<T: Field, S: FieldShare<T>> MpcWire for MpcField<T, S> {
    #[inline]
    fn publicize(&mut self) {
        match self {
            MpcField::Shared(s) => {
                *self = MpcField::Public(s.open());
            }
            _ => {}
        }
        debug_assert!({
            let self_val = if let MpcField::Public(s) = self {
                s.clone()
            } else {
                unreachable!()
            };
            super::macros::check_eq(self_val.clone());
            true
        })
    }
    #[inline]
    fn is_shared(&self) -> bool {
        match self {
            MpcField::Shared(_) => true,
            MpcField::Public(_) => false,
        }
    }
}

impl<T: Field, S: FieldShare<T>> Reveal for MpcField<T, S> {
    type Base = T;
    #[inline]
    fn reveal(self) -> Self::Base {
        let result = match self {
            Self::Shared(s) => s.reveal(),
            Self::Public(s) => s,
        };
        super::macros::check_eq(result.clone());
        result
    }
    #[inline]
    fn from_public(b: Self::Base) -> Self {
        MpcField::Public(b)
    }
    #[inline]
    fn from_add_shared(b: Self::Base) -> Self {
        MpcField::Shared(S::from_add_shared(b))
    }
    #[inline]
    fn unwrap_as_public(self) -> Self::Base {
        match self {
            Self::Shared(s) => s.unwrap_as_public(),
            Self::Public(s) => s,
        }
    }
    #[inline]
    fn king_share<R: Rng>(f: Self::Base, rng: &mut R) -> Self {
        Self::Shared(S::king_share(f, rng))
    }
    #[inline]
    fn king_share_batch<R: Rng>(f: Vec<Self::Base>, rng: &mut R) -> Vec<Self> {
        S::king_share_batch(f, rng).into_iter().map(Self::Shared).collect()
    }
    fn init_protocol() {
        S::init_protocol()
    }
    fn deinit_protocol() {
        S::deinit_protocol()
    }
}

from_prim!(bool, Field, FieldShare, MpcField);
from_prim!(u8, Field, FieldShare, MpcField);
from_prim!(u16, Field, FieldShare, MpcField);
from_prim!(u32, Field, FieldShare, MpcField);
from_prim!(u64, Field, FieldShare, MpcField);
from_prim!(u128, Field, FieldShare, MpcField);

impl<T: PrimeField, S: FieldShare<T>> std::str::FromStr for MpcField<T, S> {
    type Err = T::Err;
    #[inline]
    fn from_str(s: &str) -> Result<Self, T::Err> {
        T::from_str(s).map(Self::Public)
    }
}

impl<F: PrimeField, S: FieldShare<F>> Field for MpcField<F, S> {
    type BasePrimeField = Self;

    #[inline]
    fn characteristic<'a>() -> &'a [u64] {
        F::characteristic()
    }

    #[inline]
    fn extension_degree() -> u64 {
        unimplemented!("extension_degree")
    }
    #[inline]
    fn from_base_prime_field_elems(_b: &[<Self as ark_ff::Field>::BasePrimeField]) -> Option<Self> {
        unimplemented!()
        // assert!(b.len() > 0);
        // let shared = b[0].is_shared();
        // assert!(b.iter().all(|e| e.is_shared() == shared));
        // let base_values = b.iter().map(|e| e.unwrap_as_public()).collect::<Vec<_>>();
        // F::from_base_prime_field_elems(&base_values).map(|val| Self::new(val, shared))
    }
    #[inline]
    fn double(&self) -> Self {
        Self::Public(F::from(2u8)) * self
    }
    #[inline]
    fn double_in_place(&mut self) -> &mut Self {
        *self *= Self::Public(F::from(2u8));
        self
    }
    #[inline]
    fn from_random_bytes_with_flags<Fl: Flags>(b: &[u8]) -> Option<(Self, Fl)> {
        F::from_random_bytes_with_flags(b).map(|(val, f)| (Self::Shared(S::from_public(val)), f))
    }
    #[inline]
    fn square(&self) -> Self {
        self.clone() * self
    }
    #[inline]
    fn square_in_place(&mut self) -> &mut Self {
        *self *= self.clone();
        self
    }
    #[inline]
    fn inverse(&self) -> Option<Self> {
        self.inv()
    }
    #[inline]
    fn inverse_in_place(&mut self) -> Option<&mut Self> {
        self.inv().map(|i| {
            *self = i;
            self
        })
    }
    #[inline]
    fn frobenius_map(&mut self, _: usize) {
        unimplemented!("frobenius_map")
    }

    fn batch_product_in_place(selfs: &mut [Self], others: &[Self]) {
        let selfs_shared = selfs[0].is_shared();
        let others_shared = others[0].is_shared();
        assert!(
            selfs.iter().all(|s| s.is_shared() == selfs_shared),
            "Selfs heterogenously shared!"
        );
        assert!(
            others.iter().all(|s| s.is_shared() == others_shared),
            "others heterogenously shared!"
        );
        if selfs_shared && others_shared {
            let sshares = selfs
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => s.clone(),
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            let oshares = others
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => s.clone(),
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            let nshares = S::batch_mul(sshares, oshares, &mut DummyFieldTripleSource::default());
            for (self_, new) in selfs.iter_mut().zip(nshares.into_iter()) {
                *self_ = Self::Shared(new);
            }
        } else {
            for (a, b) in ark_std::cfg_iter_mut!(selfs).zip(others.iter()) {
                *a *= b;
            }
        }
    }
    fn batch_division_in_place(selfs: &mut [Self], others: &[Self]) {
        let selfs_shared = selfs[0].is_shared();
        let others_shared = others[0].is_shared();
        assert!(
            selfs.iter().all(|s| s.is_shared() == selfs_shared),
            "Selfs heterogenously shared!"
        );
        assert!(
            others.iter().all(|s| s.is_shared() == others_shared),
            "others heterogenously shared!"
        );
        if selfs_shared && others_shared {
            let sshares = selfs
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => s.clone(),
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            let oshares = others
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => s.clone(),
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            let nshares = S::batch_div(sshares, oshares, &mut DummyFieldTripleSource::default());
            for (self_, new) in selfs.iter_mut().zip(nshares.into_iter()) {
                *self_ = Self::Shared(new);
            }
        } else {
            for (a, b) in ark_std::cfg_iter_mut!(selfs).zip(others.iter()) {
                *a *= b;
            }
        }
    }
    fn partial_products_in_place(selfs: &mut [Self]) {
        let selfs_shared = selfs[0].is_shared();
        assert!(
            selfs.iter().all(|s| s.is_shared() == selfs_shared),
            "Selfs heterogenously shared!"
        );
        if selfs_shared {
            let sshares = selfs
                .iter()
                .map(|s| match s {
                    Self::Shared(s) => s.clone(),
                    Self::Public(_) => unreachable!(),
                })
                .collect();
            for (self_, new) in selfs.iter_mut().zip(
                S::partial_products(sshares, &mut DummyFieldTripleSource::default()).into_iter(),
            ) {
                *self_ = Self::Shared(new);
            }
        } else {
            for i in 1..selfs.len() {
                let last = selfs[i - 1];
                selfs[i] *= &last;
            }
        }
    }
    fn has_univariate_div_qr() -> bool {
        true
    }
    fn univariate_div_qr<'a>(
        num: poly_stub::DenseOrSparsePolynomial<Self>,
        den: poly_stub::DenseOrSparsePolynomial<Self>,
    ) -> Option<(
        poly_stub::DensePolynomial<Self>,
        poly_stub::DensePolynomial<Self>,
    )> {
        use poly_stub::DenseOrSparsePolynomial::*;
        let shared_num = match num {
            DPolynomial(d) => Ok(d.into_owned().coeffs.into_iter().map(|c| match c {
                MpcField::Shared(s) => s,
                MpcField::Public(_) => panic!("public numerator"),
            }).collect()),
            SPolynomial(d) => Err(d.into_owned().coeffs.into_iter().map(|(i, c)| match c {
                MpcField::Shared(s) => (i, s),
                MpcField::Public(_) => panic!("public numerator"),
            }).collect()),
        };
        let pub_denom = match den {
            DPolynomial(d) => Ok(d.into_owned().coeffs.into_iter().map(|c| match c {
                MpcField::Public(s) => s,
                MpcField::Shared(_) => panic!("shared denominator"),
            }).collect()),
            SPolynomial(d) => Err(d.into_owned().coeffs.into_iter().map(|(i, c)| match c {
                MpcField::Public(s) => (i, s),
                MpcField::Shared(_) => panic!("shared denominator"),
            }).collect()),
        };
        S::univariate_div_qr(shared_num, pub_denom).map(|(q, r)| {
            (
                poly_stub::DensePolynomial {
                    coeffs: q.into_iter().map(|qc| MpcField::Shared(qc)).collect(),
                },
                poly_stub::DensePolynomial {
                    coeffs: r.into_iter().map(|rc| MpcField::Shared(rc)).collect(),
                },
            )
        })
    }
}

impl<F: PrimeField, S: FieldShare<F>> FftField for MpcField<F, S> {
    type FftParams = F::FftParams;
    #[inline]
    fn two_adic_root_of_unity() -> Self {
        Self::from_public(F::two_adic_root_of_unity())
    }
    #[inline]
    fn large_subgroup_root_of_unity() -> Option<Self> {
        F::large_subgroup_root_of_unity().map(Self::from_public)
    }
    #[inline]
    fn multiplicative_generator() -> Self {
        Self::from_public(F::multiplicative_generator())
    }
}

impl<F: PrimeField, S: FieldShare<F>> PrimeField for MpcField<F, S> {
    type Params = F::Params;
    type BigInt = F::BigInt;
    #[inline]
    fn from_repr(_r: <Self as PrimeField>::BigInt) -> Option<Self> {
        //unimplemented!("No BigInt reprs for shared fields! (from_repr)")
        F::from_repr(_r).map(|v| Self::from_public(v))
    }
    // We're assuming that into_repr is linear
    #[inline]
    fn into_repr(&self) -> <Self as PrimeField>::BigInt {
        //unimplemented!("No BigInt reprs for shared fields! (into_repr)")
        self.unwrap_as_public().into_repr()
    }
    // fn modulo (&self, val: u32) -> Self {
        
    // }
    fn trunc (&self, bits: u32) -> Self {
        match self {
             Self::Public(x) => Self::Public(x.trunc(bits)),
             Self::Shared(x) => {
                let rng = &mut test_rng();
                let r_p = Self::from_add_shared(F::rand(rng).modulo(bits));
                let mod_bit_len = Self::Params::MODULUS_BITS;
                let mut r = Self::from_add_shared(F::rand(rng).modulo(mod_bit_len - bits));
                let mut b = Self::from_public(2u128.pow(64).into());
                let scalar = Self::from(2u32.pow(bits));
                b.add(*self);
                b.add(&r_p);
                b.add(r * scalar);
                let c = b.reveal();
                let mut d = Self::from_public(c.modulo(bits));
                d.sub(&r_p);
                let mut a = *self;
                a.sub(&d);
                let inv = scalar.inverse().unwrap();
                a *= inv;
                //print!("Shared trunc protocol");
                a
             }
        }
    }
    fn modulo (&self, bits: u32) -> Self {
        match self {
             Self::Public(x) => Self::Public(x.modulo(bits)),
             Self::Shared(x) => {
                let rng = &mut test_rng();
                let r_p = Self::from_add_shared(F::rand(rng).modulo(bits));
                let mod_bit_len = Self::Params::MODULUS_BITS;
                let mut r = Self::from_add_shared(F::rand(rng).modulo(mod_bit_len - bits));
                let mut b = Self::from_public(2u128.pow(64).into());
                let scalar = Self::from(2u32.pow(bits));
                b.add(self);
                b.add(&r_p);
                b.add(r * scalar);
                //let c = b.reveal();
                b.publicize();     
                let mut d = b.modulo(bits);
                d.sub(&r_p);
                d
             }
        }
    }

    fn bit_decomp(&self) -> Vec<bool> {
        match self {
            Self::Public(x) => x.bit_decomp(),
            Self::Shared(_) => {
                let bitlen = Self::BigInt::NUM_LIMBS * 64;
                let bits = vec![false; bitlen as usize];
                bits
                // let bits_f2: Vec<MpcField<F2, SpdzFieldShare<F2>>> = bits.iter().map(|x| MpcField::<F2, SpdzFieldShare<F2>>::from_add_shared((*x).into())).collect();
                // let bits_f: Vec<Self> = bits.iter().map(|x| (*x).into()).collect();
                // //let r_share_bits: Vec<MpcField<F2, SpdzFieldShare<F2>>> = bits.iter().map(|x| MpcField::<F2, SpdzFieldShare<F2>>::from_add_shared(F2::from(*x))).collect();
                // let mut c: Self = bits_f.iter().enumerate().map(|(i, x)| *x * Self::from(2u64).pow([i as u64])).sum();
                // c -= *self; 
                // c.publicize();
                // let c_bits = c.bit_decomp();
                // let c_bits_f2: Vec<MpcField<F2, SpdzFieldShare<F2>>> = c_bits.iter().map(|x| MpcField::<F2, SpdzFieldShare<F2>>::from_public((*x).into())).collect();
                // let mut carry_i = MpcField::<F2, SpdzFieldShare<F2>>::zero();
                // let mut z: Vec<MpcField<F2, SpdzFieldShare<F2>>> = vec![false.into(); bitlen as usize];
                // for i in 0..bitlen {
                //     z[i as usize] = carry_i + c_bits_f2[i as usize] + bits_f2[i as usize];
                //     carry_i = carry_i * ((bits_f2[i as usize] + carry_i) * (c_bits_f2[i as usize] + carry_i));
                // }
                // //let c = 
                // let res: Vec<bool> = z.iter().map(|x| (*x).into_repr().0 != [0 as u64]).collect();
                // res
            }
        }
    }

    // fn bit_decomp(&self) -> Vec<Self> {
    //     match self {
    //         Self::Public(x) => x.bit_decomp().iter().map(|b| Self::Public(*b)).collect(),
    //         Self::Shared(x) => {
    //             let rng = &mut test_rng();
    //             let r = Self::from_public(F::rand(rng));
    //             let r_bits = r.bit_decomp();
    //             let c = *self - r;
    //             c.publicize();
    //             let c_bits = c.bit_decomp();
    //             let d_bits: Vec<Self> = r_bits.iter().zip(c_bits).map(|(a, b)| *a - b).collect();
    //             let p_bits = BitIteratorBE::new(F::Params::MODULUS).map(|x| Self::from_public(x.into())).collect();
    //             let dxorp: Vec<Self> = d_bits.iter().zip(p_bits).map(|(a, b)| *a + b - (*a*b + *a*b)).collect();
    //             let mut dprefix: Vec<Self> = vec![Self::zero(); dxorp.len()];
    //             for i in 0..dxorp.len() {
    //                 dprefix[i] = predix_or(dxorp[0..i]);
    //             }
    //             let mut l

    //             self
    //         }
    //     }  
    // }
}

impl<F: PrimeField, S: FieldShare<F>> SquareRootField for MpcField<F, S> {
    #[inline]
    fn legendre(&self) -> ark_ff::LegendreSymbol {
        todo!()
    }
    #[inline]
    fn sqrt(&self) -> Option<Self> {
        todo!()
    }
    #[inline]
    fn sqrt_in_place(&mut self) -> Option<&mut Self> {
        todo!()
    }
}

mod poly_impl {

    use crate::share::*;
    use crate::wire::*;
    use crate::Reveal;
    use ark_ff::PrimeField;
    use ark_poly::domain::{EvaluationDomain, GeneralEvaluationDomain};
    use ark_poly::evaluations::univariate::Evaluations;
    use ark_poly::univariate::DensePolynomial;

    impl<E: PrimeField, S: FieldShare<E>> Reveal for DensePolynomial<MpcField<E, S>> {
        type Base = DensePolynomial<E>;
        struct_reveal_simp_impl!(DensePolynomial; coeffs);
    }

    impl<F: PrimeField, S: FieldShare<F>> Reveal for Evaluations<MpcField<F, S>> {
        type Base = Evaluations<F>;

        fn reveal(self) -> Self::Base {
            Evaluations::from_vec_and_domain(
                self.evals.reveal(),
                GeneralEvaluationDomain::new(self.domain.size()).unwrap(),
            )
        }

        fn from_add_shared(b: Self::Base) -> Self {
            Evaluations::from_vec_and_domain(
                Reveal::from_add_shared(b.evals),
                GeneralEvaluationDomain::new(b.domain.size()).unwrap(),
            )
        }

        fn from_public(b: Self::Base) -> Self {
            Evaluations::from_vec_and_domain(
                Reveal::from_public(b.evals),
                GeneralEvaluationDomain::new(b.domain.size()).unwrap(),
            )
        }
    }
}
