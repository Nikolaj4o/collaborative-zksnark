#![macro_use]

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use crate::channel;

use std::fmt::Display;

#[track_caller]
/// Checks that both sides of the channel have the same value.
pub fn check_eq<T: CanonicalSerialize + CanonicalDeserialize + Clone + Eq + Display>(t: T) {
    debug_assert!({
        use log::debug;
        let other = channel::exchange(t.clone());
        if t == other {
            debug!("Consistency check passed");
            true
        } else {
            println!("\nConsistency check failed\n{}\nvs\n{}", t, other);
            false
        }
    })
}

macro_rules! impl_basics_2 {
    ($share:ident, $bound:ident, $wrap:ident) => {
        impl<T: $bound, S: $share<T>> $wrap<T, S> {
            pub fn new(t: T, shared: bool) -> Self {
                if shared {
                    Self::Shared(S::from_public(t))
                } else {
                    Self::Public(t)
                }
            }
            pub fn from_public(t: T) -> Self {
                Self::new(t, false)
            }
            pub fn unwrap_as_public(self) -> T {
                match self {
                    Self::Shared(s) => s.unwrap_as_public(),
                    Self::Public(s) => s,
                }
            }
            pub fn map<TT: $bound, SS: $share<TT>, FT: Fn(T) -> TT, FS: Fn(S) -> SS>(
                self,
                ft: FT,
                fs: FS,
            ) -> $wrap<TT, SS> {
                match self {
                    Self::Shared(s) => $wrap::Shared(fs(s)),
                    Self::Public(s) => $wrap::Public(ft(s)),
                }
            }
        }
        impl<T: $bound, S: $share<T>> Display for $wrap<T, S> {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                match self {
                    $wrap::Public(x) => write!(f, "{} (public)", x),
                    $wrap::Shared(x) => write!(f, "{} (shared)", x),
                }
            }
        }
        impl<T: $bound, S: $share<T>> ToBytes for $wrap<T, S> {
            fn write<W: Write>(&self, writer: W) -> io::Result<()> {
                match self {
                    Self::Public(v) => v.write(writer),
                    Self::Shared(_) => unimplemented!("write share: {}", self),
                }
            }
        }
        impl<T: $bound, S: $share<T>> FromBytes for $wrap<T, S> {
            fn read<R: Read>(_reader: R) -> io::Result<Self> {
                unimplemented!("read")
            }
        }
        impl<T: $bound, S: $share<T>> CanonicalSerialize for $wrap<T, S> {
            fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
                match self {
                    Self::Public(v) => v.serialize(writer),
                    Self::Shared(_) => unimplemented!("serialize share: {}", self),
                }
            }
            fn serialized_size(&self) -> usize {
                match self {
                    Self::Public(v) => v.serialized_size(),
                    Self::Shared(_) => unimplemented!("serialized_size share: {}", self),
                }
            }
        }
        // NB: CanonicalSerializeWithFlags is unimplemented for Group.
        impl<T: $bound, S: $share<T>> CanonicalSerializeWithFlags for $wrap<T, S> {
            fn serialize_with_flags<W: Write, F: Flags>(
                &self,
                _writer: W,
                _flags: F,
            ) -> Result<(), SerializationError> {
                unimplemented!("serialize_with_flags")
            }

            fn serialized_size_with_flags<F: Flags>(&self) -> usize {
                unimplemented!("serialized_size_with_flags")
            }
        }
        impl<T: $bound, S: $share<T>> CanonicalDeserialize for $wrap<T, S> {
            fn deserialize<R: Read>(_reader: R) -> Result<Self, SerializationError> {
                unimplemented!("deserialize")
            }
        }
        impl<T: $bound, S: $share<T>> CanonicalDeserializeWithFlags for $wrap<T, S> {
            fn deserialize_with_flags<R: Read, F: Flags>(
                _reader: R,
            ) -> Result<(Self, F), SerializationError> {
                unimplemented!("deserialize_with_flags")
            }
        }
        impl<T: $bound, S: $share<T>> UniformRand for $wrap<T, S> {
            fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
                Self::Shared(<S as UniformRand>::rand(rng))
            }
        }
        impl<T: $bound, S: $share<T>> Add for $wrap<T, S> {
            type Output = Self;
            fn add(self, other: Self) -> Self::Output {
                match (self, other) {
                    ($wrap::Public(x), $wrap::Public(y)) => $wrap::Public(x + y),
                    ($wrap::Shared(x), $wrap::Public(y)) => $wrap::Shared(x.shift(&y)),
                    ($wrap::Public(x), $wrap::Shared(y)) => $wrap::Shared(y.shift(&x)),
                    ($wrap::Shared(x), $wrap::Shared(y)) => $wrap::Shared(x.add(&y)),
                }
            }
        }
        impl<T: $bound, S: $share<T>> Sum for $wrap<T, S> {
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), Add::add)
            }
        }
        impl<'a, T: $bound, S: $share<T> + 'a> Sum<&'a $wrap<T, S>> for $wrap<T, S> {
            fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::zero(), |x, y| x.add(y.clone()))
            }
        }
        impl<T: $bound, S: $share<T>> Neg for $wrap<T, S> {
            type Output = Self;
            fn neg(self) -> Self::Output {
                match self {
                    $wrap::Public(x) => $wrap::Public(-x),
                    $wrap::Shared(x) => $wrap::Shared(x.neg()),
                }
            }
        }
        impl<T: $bound, S: $share<T>> Sub for $wrap<T, S> {
            type Output = Self;
            fn sub(self, other: Self) -> Self::Output {
                match (self, other) {
                    ($wrap::Public(x), $wrap::Public(y)) => $wrap::Public(x - y),
                    ($wrap::Shared(x), $wrap::Public(y)) => $wrap::Shared(x.shift(&-y)),
                    ($wrap::Public(x), $wrap::Shared(y)) => $wrap::Shared(y.neg().shift(&x)),
                    ($wrap::Shared(x), $wrap::Shared(y)) => $wrap::Shared(x.sub(y)),
                }
            }
        }
        impl<T: $bound, S: $share<T>> Zero for $wrap<T, S> {
            fn zero() -> Self {
                $wrap::Public(T::zero())
            }
            fn is_zero(&self) -> bool {
                match self {
                    $wrap::Public(x) => x.is_zero(),
                    $wrap::Shared(_x) => {
                        debug!("Warning: is_zero on shared data. Returning false");
                        false
                    }
                }
            }
        }
        impl<T: $bound, S: $share<T>> Zeroize for $wrap<T, S> {
            fn zeroize(&mut self) {
                *self = $wrap::Public(T::zero());
            }
        }
        impl<T: $bound, S: $share<T>> Default for $wrap<T, S> {
            fn default() -> Self {
                Self::zero()
            }
        }
    };
}

macro_rules! impl_ref_ops {
    ($op:ident, $assop:ident, $opfn:ident, $assopfn:ident, $bound:ident, $share:ident, $wrap:ident) => {
        impl<'a, T: $bound, S: $share<T>> $op<&'a $wrap<T, S>> for $wrap<T, S> {
            type Output = Self;
            fn $opfn(self, other: &$wrap<T, S>) -> Self::Output {
                self.$opfn(other.clone())
            }
        }
        impl<T: $bound, S: $share<T>> $assop<$wrap<T, S>> for $wrap<T, S> {
            fn $assopfn(&mut self, other: $wrap<T, S>) {
                *self = self.clone().$opfn(other.clone());
            }
        }
        impl<'a, T: $bound, S: $share<T>> $assop<&'a $wrap<T, S>> for $wrap<T, S> {
            fn $assopfn(&mut self, other: &$wrap<T, S>) {
                *self = self.clone().$opfn(other.clone());
            }
        }
    };
}

macro_rules! from_prim {
    ($t:ty, $bound:ident, $share:ident, $wrap:ident) => {
        impl<T: $bound, S: $share<T>> std::convert::From<$t> for $wrap<T, S> {
            fn from(t: $t) -> Self {
                $wrap::from_public(T::from(t))
            }
        }
    };
}
