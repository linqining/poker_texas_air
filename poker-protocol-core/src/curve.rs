use rand_core::{CryptoRng, RngCore};
use std::fmt::Debug;
use std::iter::Sum;
use std::ops::{Add, Mul, Neg, Sub};

/// Scalar operations required by the proof systems.
pub trait CurveScalar:
    Clone
    + Copy
    + Debug
    + PartialEq
    + Eq
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + Sum
    + Send
    + Sync
    + 'static
{
    fn zero() -> Self;
    fn one() -> Self;
    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self;
    fn from_bytes_mod_order(bytes: &[u8]) -> Self;
    fn from_canonical_bytes(bytes: &[u8]) -> Option<Self>;
    fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self;
    fn from_u64(val: u64) -> Self;
    fn as_bytes(&self) -> Vec<u8>;
    fn invert(&self) -> Self;
}

/// Group operations required by the proof systems.
pub trait CurvePoint:
    Clone
    + Copy
    + Debug
    + PartialEq
    + Eq
    + Add<Output = Self>
    + Sub<Output = Self>
    + Sum
    + for<'a> Mul<&'a <Self as CurvePoint>::Scalar, Output = Self>
    + Mul<<Self as CurvePoint>::Scalar, Output = Self>
    + Send
    + Sync
    + 'static
{
    type Scalar: CurveScalar;
    type Compressed: Clone + Debug + Send + Sync + AsRef<[u8]>;

    fn identity() -> Self;
    fn is_identity(&self) -> bool;
    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self;
    fn compress(&self) -> Self::Compressed;
    fn vartime_multiscalar_mul(scalars: &[Self::Scalar], points: &[Self]) -> Self;
    fn from_compressed(bytes: &[u8]) -> Option<Self>;
}

/// Associates a group and scalar field with deterministic generators and
/// hash functions. Concrete implementations live in backend crates.
pub trait Curve: Clone + Debug + PartialEq + Eq + Send + Sync + 'static {
    type Point: CurvePoint<Scalar = Self::Scalar>;
    type Scalar: CurveScalar;

    fn base_g() -> Self::Point;
    fn base_h() -> Self::Point;
    fn hash_to_scalar(digest: &[u8]) -> Self::Scalar;
    fn hash_to_curve(digest: &[u8]) -> Self::Point;

    fn n_cards() -> usize {
        52
    }
}

/// Generic exponential-ElGamal ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElGamalCiphertextGeneric<C: Curve> {
    pub c1: C::Point,
    pub c2: C::Point,
}

impl<C: Curve> ElGamalCiphertextGeneric<C> {
    pub fn encrypt(plaintext: &C::Point, pk: &C::Point, r: &C::Scalar) -> Self {
        Self {
            c1: C::base_g() * r,
            c2: *plaintext + *pk * r,
        }
    }

    pub fn decrypt(&self, sk: &C::Scalar) -> C::Point {
        self.c2 - self.c1 * sk
    }

    pub fn re_encrypt(&self, pk: &C::Point, r_prime: &C::Scalar) -> Self {
        Self {
            c1: self.c1 + C::base_g() * r_prime,
            c2: self.c2 + *pk * r_prime,
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.c1.is_identity() && !self.c2.is_identity()
    }

    pub fn new_placeholder_card() -> Self {
        Self {
            c1: C::Point::identity(),
            c2: C::Point::identity(),
        }
    }

    pub fn gen_reveal_token(&self, sk: &C::Scalar) -> C::Point {
        self.c1 * sk
    }

    pub fn remask(&self, sk: &C::Scalar) -> Self {
        Self {
            c1: self.c1,
            c2: self.c2 + self.c1 * sk,
        }
    }
}
