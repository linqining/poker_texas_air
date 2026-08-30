//! STARK curve backend (Cairo-native, EC_OP builtin compatible).
//!
//! Curve: `y² = x³ + x + β` over `F_P`, `P = 2²⁵¹ + 17·2¹⁹² + 1`,
//! `β = 0x06f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89`,
//! prime group order
//! `n = 0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f`
//! (cofactor 1). Parameters are taken from `starknet-curve::curve_params`,
//! the same constants Cairo's EC_OP builtin uses, so host-side points map
//! 1:1 to on-chain felts.
//!
//! Two fields are in play and must not be confused:
//! - point coordinates live in `F_P` (via `starknet_types_core::felt::Felt`,
//!   Montgomery arithmetic mod P);
//! - scalars live in `Z_n` (the group order). `n < P`, so Felt arithmetic
//!   (mod P) is *not* scalar arithmetic; `StarkScalar` reduces mod n via
//!   `crypto-bigint` instead. Fiat–Shamir challenges, sk/s values and all
//!   residual-coefficient arithmetic stay mod n.
//!
//! Hash discipline: `hash_to_scalar` folds the digest into 31-byte
//! big-endian chunks (each < 2²⁴⁸ < P), hashes with `poseidon_hash_many`
//! (the same Hades permutation as Cairo's Poseidon builtin) and reduces mod
//! n. `hash_to_curve` is try-and-increment over the same poseidon digest
//! with the curve equation checked via `Felt::sqrt`; the encoded
//! representative always uses the odd y coordinate.

use rand_core::{CryptoRng, RngCore};

use starknet_curve::curve_params::{BETA, GENERATOR};
use starknet_crypto::{poseidon_hash_many, Felt};

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Encoding, U256};

use crate::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};

/// Group order as a 256-bit integer, parsed from the same constant the
/// Cairo-side verifier uses. Debug-checked against `starknet_curve`'s
/// `EC_ORDER` in the test suite.
pub const EC_ORDER_U256: U256 =
    U256::from_be_hex("0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f");

/// Montgomery-domain parameters for the group order. Built once; `n` is odd
/// so `DynResidueParams::new` accepts it.
fn residue_params() -> DynResidueParams<{ U256::LIMBS }> {
    static PARAMS: std::sync::OnceLock<DynResidueParams<{ U256::LIMBS }>> = std::sync::OnceLock::new();
    *PARAMS.get_or_init(|| DynResidueParams::new(&EC_ORDER_U256))
}

/// `x mod n` via the Montgomery representation (`DynResidue::new` reduces
/// for arbitrary `x` because the stored form is `x·R² mod n`).
fn reduce_mod_n(x: U256) -> U256 {
    DynResidue::new(&x, residue_params()).retrieve()
}

// ============================================================
// Scalar arithmetic mod n
// ============================================================

/// Scalar in `Z_n`, n = group order of the STARK curve.
///
/// Invariant: the wrapped integer is always `< n`; every operation
/// re-establishes the invariant. Add/sub/neg run on plain integers (safe
/// because `n < 2^252`), mul/invert run in the Montgomery domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StarkScalar(U256);

impl StarkScalar {
    pub fn from_u256(raw: U256) -> Option<Self> {
        (raw < EC_ORDER_U256).then(|| StarkScalar(raw))
    }

    pub fn to_u256(&self) -> U256 {
        self.0
    }
}

impl CurveScalar for StarkScalar {
    fn zero() -> Self {
        StarkScalar(U256::ZERO)
    }

    fn one() -> Self {
        StarkScalar(U256::ONE)
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            let candidate = U256::from_be_slice(&bytes);
            if candidate < EC_ORDER_U256 && candidate != U256::ZERO {
                return StarkScalar(candidate);
            }
        }
    }

    fn from_bytes_mod_order(bytes: &[u8]) -> Self {
        // Right-align into a 32-byte big-endian word (mirrors the secp256k1
        // backend's length tolerance), then reduce mod n.
        let mut repr = [0u8; 32];
        let len = 32.min(bytes.len());
        repr[32 - len..].copy_from_slice(&bytes[..len]);
        StarkScalar(reduce_mod_n(U256::from_be_slice(&repr)))
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let raw = U256::from_be_slice(bytes);
        (raw < EC_ORDER_U256).then(|| StarkScalar(raw))
    }

    fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        // Same discipline as the BLS/secp backends: XOR the two halves down
        // to 32 bytes, then reduce modulo the group order.
        let mut arr = [0u8; 32];
        for i in 0..32 {
            arr[i] = bytes[i] ^ bytes[32 + i];
        }
        StarkScalar(reduce_mod_n(U256::from_be_slice(&arr)))
    }

    fn from_u64(val: u64) -> Self {
        StarkScalar(reduce_mod_n(U256::from_u128(val as u128)))
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }

    fn invert(&self) -> Self {
        if self.0 == U256::ZERO {
            return StarkScalar(U256::ZERO);
        }
        // n is prime and self != 0, so the inverse always exists; the
        // inherent `invert` returns (value, CtChoice) with choice true.
        let (inv, _exists) = DynResidue::new(&self.0, residue_params()).invert();
        StarkScalar(inv.retrieve())
    }
}

impl core::ops::Add for StarkScalar {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let sum = self.0.wrapping_add(&rhs.0);
        StarkScalar(if sum >= EC_ORDER_U256 {
            sum.wrapping_sub(&EC_ORDER_U256)
        } else {
            sum
        })
    }
}

impl core::ops::Add<&StarkScalar> for StarkScalar {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self {
        self + *rhs
    }
}

impl core::ops::Add<StarkScalar> for &StarkScalar {
    type Output = StarkScalar;
    fn add(self, rhs: StarkScalar) -> StarkScalar {
        *self + rhs
    }
}

impl core::ops::Add<&StarkScalar> for &StarkScalar {
    type Output = StarkScalar;
    fn add(self, rhs: &StarkScalar) -> StarkScalar {
        *self + *rhs
    }
}

impl core::ops::AddAssign for StarkScalar {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl core::ops::AddAssign<&StarkScalar> for StarkScalar {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + *rhs;
    }
}

impl core::ops::Sub<&StarkScalar> for StarkScalar {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self {
        self - *rhs
    }
}

impl core::ops::Sub<StarkScalar> for &StarkScalar {
    type Output = StarkScalar;
    fn sub(self, rhs: StarkScalar) -> StarkScalar {
        *self - rhs
    }
}

impl core::ops::Sub<&StarkScalar> for &StarkScalar {
    type Output = StarkScalar;
    fn sub(self, rhs: &StarkScalar) -> StarkScalar {
        *self - *rhs
    }
}

impl core::ops::SubAssign for StarkScalar {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl core::ops::Mul<&StarkScalar> for StarkScalar {
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self {
        self * *rhs
    }
}

impl core::ops::Mul<StarkScalar> for &StarkScalar {
    type Output = StarkScalar;
    fn mul(self, rhs: StarkScalar) -> StarkScalar {
        *self * rhs
    }
}

impl core::ops::Mul<&StarkScalar> for &StarkScalar {
    type Output = StarkScalar;
    fn mul(self, rhs: &StarkScalar) -> StarkScalar {
        *self * *rhs
    }
}

impl core::ops::Neg for &StarkScalar {
    type Output = StarkScalar;
    fn neg(self) -> StarkScalar {
        -*self
    }
}

impl<'a> core::iter::Sum<&'a StarkScalar> for StarkScalar {
    fn sum<I: Iterator<Item = &'a StarkScalar>>(iter: I) -> Self {
        iter.fold(<Self as CurveScalar>::zero(), |acc, x| acc + x)
    }
}

impl Default for StarkScalar {
    fn default() -> Self {
        <Self as CurveScalar>::zero()
    }
}

impl Default for StarkPoint {
    fn default() -> Self {
        <Self as CurvePoint>::identity()
    }
}

impl core::ops::Sub for StarkScalar {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        if self.0 >= rhs.0 {
            StarkScalar(self.0.wrapping_sub(&rhs.0))
        } else {
            // self - rhs ≡ self + (n - rhs) mod n, both < n so no overflow
            StarkScalar(self.0.wrapping_add(&EC_ORDER_U256.wrapping_sub(&rhs.0)))
        }
    }
}

impl core::ops::Mul for StarkScalar {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let prod = DynResidue::new(&self.0, residue_params())
            * DynResidue::new(&rhs.0, residue_params());
        StarkScalar(prod.retrieve())
    }
}

impl core::ops::Neg for StarkScalar {
    type Output = Self;
    fn neg(self) -> Self {
        if self.0 == U256::ZERO {
            self
        } else {
            StarkScalar(EC_ORDER_U256.wrapping_sub(&self.0))
        }
    }
}

impl core::iter::Sum for StarkScalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(<Self as CurveScalar>::zero(), |acc, x| acc + x)
    }
}

// ============================================================
// Jacobian point arithmetic over F_P
// ============================================================

fn felt_is_odd(f: &Felt) -> bool {
    f.to_bytes_be()[31] & 1 == 1
}

/// Point on the STARK curve in Jacobian coordinates
/// (`x_aff = X/Z²`, `y_aff = Y/Z³`). Identity is `(1, 1, 0)`.
///
/// Hand-rolled formulas because `starknet_types_core::curve::ProjectivePoint`
/// is not `Copy` (the trait requires `Copy`). Every operation is
/// oracle-tested against that implementation in this module's tests.
///
/// Equality is *semantic* (cross-multiplied, like the k256/blstrs
/// projective backends), not coordinate-wise: `(X₁Z₂², Y₁Z₂³) ==
/// (X₂Z₁², Y₂Z₁³)`.
#[derive(Clone, Copy, Debug)]
pub struct StarkPoint {
    x: Felt,
    y: Felt,
    z: Felt,
}

impl PartialEq for StarkPoint {
    fn eq(&self, other: &Self) -> bool {
        match (self.is_identity(), other.is_identity()) {
            (true, true) => true,
            (true, false) | (false, true) => false,
            (false, false) => {
                let z1z1 = self.z * self.z;
                let z2z2 = other.z * other.z;
                self.x * z2z2 == other.x * z1z1
                    && self.y * z2z2 * other.z == other.y * z1z1 * self.z
            }
        }
    }
}

impl Eq for StarkPoint {}

impl StarkPoint {
    pub fn from_affine_parts(x: Felt, y: Felt) -> Self {
        StarkPoint { x, y, z: Felt::ONE }
    }

    pub fn to_affine_parts(&self) -> Option<(Felt, Felt)> {
        if self.is_identity() {
            return None;
        }
        let z_inv = self.z.inverse()?;
        let z2 = z_inv * z_inv;
        Some((self.x * z2, self.y * z2 * z_inv))
    }

    fn double(&self) -> Self {
        if self.is_identity() || self.y == Felt::ZERO {
            // y = 0 would mean 2-torsion; the group order is prime and odd,
            // so this only fires for the identity.
            return <Self as CurvePoint>::identity();
        }
        // dbl-2009-l with a = 1
        let a = self.x * self.x;
        let b = self.y * self.y;
        let c = b * b;
        let d = {
            let t = (self.x + b) * (self.x + b) - a - c;
            t + t
        };
        let e = a + a + a + {
            let z2 = self.z * self.z;
            z2 * z2 // a · Z1⁴ with a = 1
        };
        let f = e * e;
        let x3 = f - d - d;
        let c8 = {
            let c2 = c + c;
            let c4 = c2 + c2;
            c4 + c4
        };
        let y3 = e * (d - x3) - c8;
        let z3 = self.y * self.z + self.y * self.z;
        StarkPoint { x: x3, y: y3, z: z3 }
    }
}

impl CurvePoint for StarkPoint {
    type Scalar = StarkScalar;
    type Compressed = StarkCompressedPoint;

    fn identity() -> Self {
        StarkPoint { x: Felt::ONE, y: Felt::ONE, z: Felt::ZERO }
    }

    fn is_identity(&self) -> bool {
        self.z == Felt::ZERO
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        <StarkCurve as Curve>::base_g() * StarkScalar::random(rng)
    }

    fn compress(&self) -> StarkCompressedPoint {
        if self.is_identity() {
            return StarkCompressedPoint([0u8; 32]);
        }
        let (x, y) = self
            .to_affine_parts()
            .expect("non-identity Jacobian point has affine coordinates");
        let x_bytes = x.to_bytes_be();
        debug_assert!(x_bytes[0] <= 0x07, "x coordinate must be below 2^251");
        let mut out = [0u8; 32];
        out.copy_from_slice(&x_bytes);
        // flag bit records the parity of the encoded y. For x = 0 force the
        // odd representative so the encoding of a non-identity point never
        // collides with the all-zero identity encoding.
        let y = if x == Felt::ZERO && !felt_is_odd(&y) {
            Felt::ZERO - y
        } else {
            y
        };
        if felt_is_odd(&y) {
            out[0] |= 0x80;
        }
        StarkCompressedPoint(out)
    }

    fn vartime_multiscalar_mul(scalars: &[StarkScalar], points: &[Self]) -> Self {
        // Straightfold; windowed methods are a measured follow-up (P3).
        let terms = points.iter().zip(scalars.iter());
        terms.map(|(point, scalar)| *point * *scalar).sum()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        if bytes.iter().all(|b| *b == 0) {
            return Some(<Self as CurvePoint>::identity());
        }
        // Canonical layout: byte0 = (0x80 if y odd) | (x >> 244), x < 2^251.
        let y_odd = bytes[0] & 0x80 != 0;
        if bytes[0] & 0x7f > 0x07 {
            return None;
        }
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(bytes);
        x_bytes[0] &= 0x7f;
        let x = Felt::from_bytes_be(&x_bytes);
        let rhs = x * x * x + x + BETA; // a = 1
        let y = rhs.sqrt()?;
        let y = if felt_is_odd(&y) == y_odd { y } else { Felt::ZERO - y };
        Some(StarkPoint::from_affine_parts(x, y))
    }
}

impl core::ops::Add for StarkPoint {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        add_points(self, rhs)
    }
}

impl core::ops::Add<&StarkPoint> for StarkPoint {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self {
        add_points(self, *rhs)
    }
}

impl core::ops::Add<StarkPoint> for &StarkPoint {
    type Output = StarkPoint;
    fn add(self, rhs: StarkPoint) -> StarkPoint {
        add_points(*self, rhs)
    }
}

impl core::ops::Add<&StarkPoint> for &StarkPoint {
    type Output = StarkPoint;
    fn add(self, rhs: &StarkPoint) -> StarkPoint {
        add_points(*self, *rhs)
    }
}

fn add_points(a: StarkPoint, b: StarkPoint) -> StarkPoint {
    if a.is_identity() {
        return b;
    }
    if b.is_identity() {
        return a;
    }
    // add-2007-bl
    let zz1 = a.z * a.z;
    let zz2 = b.z * b.z;
    let u1 = a.x * zz2;
    let u2 = b.x * zz1;
    let s1 = a.y * b.z * zz2;
    let s2 = b.y * a.z * zz1;
    let h = u2 - u1;
    let r = (s2 - s1) + (s2 - s1);
    if h == Felt::ZERO {
        if r == Felt::ZERO {
            return a.double();
        }
        // P + (−P) = identity
        return <StarkPoint as CurvePoint>::identity();
    }
    let i = {
        let h2 = h + h;
        h2 * h2
    };
    let j = h * i;
    let v = u1 * i;
    let x3 = r * r - j - v - v;
    let s1j = s1 * j;
    let y3 = r * (v - x3) - s1j - s1j;
    let z3 = {
        let z12 = a.z + b.z;
        z12 * z12 - zz1 - zz2
    } * h;
    StarkPoint { x: x3, y: y3, z: z3 }
}

impl core::ops::AddAssign for StarkPoint {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl core::ops::AddAssign<&StarkPoint> for StarkPoint {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + *rhs;
    }
}

impl core::ops::Sub for StarkPoint {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self + (-rhs)
    }
}

impl core::ops::Sub<&StarkPoint> for StarkPoint {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self {
        self + (-*rhs)
    }
}

impl core::ops::Sub<StarkPoint> for &StarkPoint {
    type Output = StarkPoint;
    fn sub(self, rhs: StarkPoint) -> StarkPoint {
        *self + (-rhs)
    }
}

impl core::ops::Sub<&StarkPoint> for &StarkPoint {
    type Output = StarkPoint;
    fn sub(self, rhs: &StarkPoint) -> StarkPoint {
        *self + (-*rhs)
    }
}

impl core::ops::SubAssign for StarkPoint {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl core::ops::SubAssign<&StarkPoint> for StarkPoint {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = *self - *rhs;
    }
}

impl core::ops::Neg for StarkPoint {
    type Output = Self;
    fn neg(self) -> Self {
        StarkPoint { x: self.x, y: Felt::ZERO - self.y, z: self.z }
    }
}

impl core::ops::Neg for &StarkPoint {
    type Output = StarkPoint;
    fn neg(self) -> StarkPoint {
        StarkPoint { x: self.x, y: Felt::ZERO - self.y, z: self.z }
    }
}

impl core::iter::Sum for StarkPoint {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(<Self as CurvePoint>::identity(), |acc, p| acc + p)
    }
}

impl<'a> core::iter::Sum<&'a StarkPoint> for StarkPoint {
    fn sum<I: Iterator<Item = &'a StarkPoint>>(iter: I) -> Self {
        iter.fold(<Self as CurvePoint>::identity(), |acc, p| acc + p)
    }
}

impl core::ops::Mul<StarkScalar> for StarkPoint {
    type Output = Self;
    fn mul(self, scalar: StarkScalar) -> Self {
        let bytes = scalar.0.to_be_bytes();
        let mut acc = <Self as CurvePoint>::identity();
        let mut started = false;
        for byte in bytes.iter() {
            for bit in (0..8).rev() {
                let set = (byte >> bit) & 1 == 1;
                if started {
                    acc = acc.double();
                    if set {
                        acc = acc + self;
                    }
                } else if set {
                    acc = self;
                    started = true;
                }
            }
        }
        acc
    }
}

impl core::ops::Mul<&StarkScalar> for StarkPoint {
    type Output = Self;
    fn mul(self, scalar: &StarkScalar) -> Self {
        self * *scalar
    }
}

impl core::ops::Mul<StarkScalar> for &StarkPoint {
    type Output = StarkPoint;
    fn mul(self, scalar: StarkScalar) -> StarkPoint {
        *self * scalar
    }
}

impl core::ops::Mul<&StarkScalar> for &StarkPoint {
    type Output = StarkPoint;
    fn mul(self, scalar: &StarkScalar) -> StarkPoint {
        *self * *scalar
    }
}

/// 32-byte compressed encoding: `byte0 = 0x80 | (x >> 244)`, remaining 31
/// bytes are the low end of x; y is always the odd representative. All-zero
/// bytes encode the identity. Points with x ≥ 2^251 (probability ≈ 2^-59)
/// are outside the canonical range and rejected on decompress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarkCompressedPoint([u8; 32]);

impl AsRef<[u8]> for StarkCompressedPoint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl StarkCompressedPoint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ============================================================
// Curve definition
// ============================================================

/// Folds arbitrary bytes into field elements: 31-byte big-endian chunks
/// (each < 2^248 < P) with a length prefix, hashed by the Cairo-native
/// Poseidon permutation (`poseidon_hash_many`).
fn poseidon_over_bytes(bytes: &[u8]) -> Felt {
    let mut input = Vec::with_capacity(bytes.len() / 31 + 2);
    input.push(Felt::from(bytes.len() as u64));
    for chunk in bytes.chunks(31) {
        let mut buf = [0u8; 32];
        buf[32 - chunk.len()..].copy_from_slice(chunk);
        input.push(Felt::from_bytes_be(&buf));
    }
    poseidon_hash_many(&input)
}

fn stark_hash_to_curve(digest: &[u8]) -> StarkPoint {
    let start = poseidon_over_bytes(digest);
    for i in 0u64..1024 {
        let x = start + Felt::from(i);
        let rhs = x * x * x + x + BETA; // a = 1
        if let Some(y) = rhs.sqrt() {
            let y = if felt_is_odd(&y) { y } else { Felt::ZERO - y };
            return StarkPoint::from_affine_parts(x, y);
        }
    }
    panic!("hash_to_curve: no curve point within 1024 candidates");
}

/// STARK curve (Cairo-native) backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StarkCurve;

impl Curve for StarkCurve {
    type Point = StarkPoint;
    type Scalar = StarkScalar;

    fn base_g() -> StarkPoint {
        StarkPoint::from_affine_parts(GENERATOR.x(), GENERATOR.y())
    }

    fn base_h() -> StarkPoint {
        // Try-and-increment rather than G * hash(label): the latter would
        // publish the discrete-log relation between G and H and invalidate
        // the Pedersen binding assumption used by the Bayer-Groth product
        // argument (same discipline as the secp256k1 backend).
        stark_hash_to_curve(b"texas_poker_independent_base_H_stark_curve")
    }

    fn hash_to_scalar(digest: &[u8]) -> StarkScalar {
        let h = poseidon_over_bytes(digest);
        let raw = U256::from_be_slice(&h.to_bytes_be());
        StarkScalar(reduce_mod_n(raw))
    }

    fn hash_to_curve(digest: &[u8]) -> StarkPoint {
        stark_hash_to_curve(digest)
    }

    fn n_cards() -> usize {
        52
    }
}

/// Exponential-ElGamal ciphertext on the STARK curve.
pub type StarkElGamalCiphertext = ElGamalCiphertextGeneric<StarkCurve>;

// ============================================================
// Hand-batch felt-native transcript helpers（Plan D gas 压缩版）
//
// 实测（snforge l2_gas）：EC_OP 单次 0.08M、poseidon 置换 <0.04M，
// 但逐字节除法序列化（u256_to_be_bytes）与纯 Cairo keccak 占每认可
// ~456M 开销的 ~95%。以下把 Hand-batch 的 challenge/rho 全部改为 felt 直通
// Poseidon：无字节转换、无 keccak，三端（host/wasm/Cairo）共享本文件
// 的同一规范公式。标签取 ASCII 字符串直接作 felt（≤31B，双端逐字节
// 一致派生，无运行时哈希成本）。
// ============================================================

fn ascii_felt(s: &str) -> Felt {
    let bytes = s.as_bytes();
    assert!(bytes.len() <= 31, "ascii label must fit one felt");
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    Felt::from_bytes_be(&buf)
}

/// "poker/hand-batch/proto" 与 "poker/hand-batch/v1" 的 felt 标签。
pub fn handbatch_proto_label() -> Felt {
    ascii_felt("poker/hand-batch/proto")
}

pub fn handbatch_v1_label() -> Felt {
    ascii_felt("poker/hand-batch/v1")
}

fn word_to_felt(w: &[u8; 32]) -> Felt {
    Felt::from_bytes_be(w)
}

/// 认可挑战（gas 压缩版，取代 keccak 域 + 32B 压缩编码的字节流形态）：
/// `c = poseidon([proto_label, hand_binding, Gx, Gy, pk_x, pk_y, R_x, R_y]) mod n`。
/// hand_binding 是 Poseidon 输出（< P），坐标为完整仿射点——单射、无需
/// 奇偶压缩位。Cairo 端 hand_batch_stark.cairo::ownership_terms 复刻同式。
pub fn handbatch_endorsement_challenge(
    hand_binding: &[u8; 32],
    g: &StarkPoint,
    pk: &StarkPoint,
    r: &StarkPoint,
) -> StarkScalar {
    let (gx, gy) = g.to_affine_parts().expect("non-identity G");
    let (pkx, pky) = pk.to_affine_parts().expect("non-identity pk");
    let (rx, ry) = r.to_affine_parts().expect("non-identity R");
    let felts = [
        handbatch_proto_label(),
        word_to_felt(hand_binding),
        gx,
        gy,
        pkx,
        pky,
        rx,
        ry,
    ];
    let h = poseidon_hash_many(&felts);
    StarkScalar(reduce_mod_n(U256::from_be_slice(&h.to_bytes_be())))
}

/// 可折叠 reveal-token 挑战（felt 直通 Poseidon，与 ownership 的
/// `handbatch_endorsement_challenge` 同纪律）：
/// `c = poseidon([reveal_label, hand_binding, pk, c1, c2, token, t1, t2,
///                nonce]) mod n`。
/// 生产 reveal 证明用 FiatShamir(SHA3-256)——Cairo 只有 legacy Keccak
/// syscall，无法逐字节重放；可折叠纪元把挑战改为本式（host/wasm 铸造
/// 与 Cairo 重放三端同构，与 Hand-batch ownership 挑战的迁移同模式）。
/// 方程不变：eq1: s·G − t1 − c·pk = O；eq2: s·c1 − t2 − c·token = O。
pub fn handbatch_reveal_challenge(
    hand_binding: &[u8; 32],
    pk: &StarkPoint,
    c1: &StarkPoint,
    c2: &StarkPoint,
    token: &StarkPoint,
    t1: &StarkPoint,
    t2: &StarkPoint,
    nonce: &StarkScalar,
) -> StarkScalar {
    let (pkx, pky) = pk.to_affine_parts().expect("non-identity pk");
    let (c1x, c1y) = c1.to_affine_parts().expect("non-identity c1");
    let (c2x, c2y) = c2.to_affine_parts().expect("non-identity c2");
    let (tokx, toky) = token.to_affine_parts().expect("non-identity token");
    let (t1x, t1y) = t1.to_affine_parts().expect("non-identity t1");
    let (t2x, t2y) = t2.to_affine_parts().expect("non-identity t2");
    let felts = [
        ascii_felt("poker/reveal-token/fold-v1"),
        word_to_felt(hand_binding),
        pkx, pky, c1x, c1y, c2x, c2y, tokx, toky, t1x, t1y, t2x, t2y,
        Felt::from_bytes_be(&{
            let mut b = [0u8; 32];
            b.copy_from_slice(&nonce.as_bytes());
            b
        }),
    ];
    let h = poseidon_hash_many(&felts);
    StarkScalar(reduce_mod_n(U256::from_be_slice(&h.to_bytes_be())))
}

/// 可折叠 leave/remask 批量 DLEQ 挑战（felt 直通）：
/// `c = poseidon([leave_label, hand_binding, pk, cpk, nonce, n,
///                (in_c1, in_c2, out_c1, out_c2, a_i, d2_i)*]) mod n`，
/// 其中 `d2_i = in_c2_i − out_c2_i`（链上点减重算，进挑战）。
/// 方程：eq0: s·G − cpk − c·pk = O；每卡 eq_i: s·in_c1ᵢ − aᵢ − c·d2ᵢ = O。
pub fn handbatch_leave_challenge(
    hand_binding: &[u8; 32],
    pk: &StarkPoint,
    cpk: &StarkPoint,
    nonce: &StarkScalar,
    cards: &[HandLeaveCardWords],
) -> StarkScalar {
    let (pkx, pky) = pk.to_affine_parts().expect("non-identity pk");
    let (cpkx, cpky) = cpk.to_affine_parts().expect("non-identity cpk");
    let mut felts = Vec::with_capacity(8 + 12 * cards.len());
    felts.push(ascii_felt("poker/leave-fold/v1"));
    felts.push(word_to_felt(hand_binding));
    felts.push(pkx);
    felts.push(pky);
    felts.push(cpkx);
    felts.push(cpky);
    felts.push(Felt::from_bytes_be(&{
        let mut b = [0u8; 32];
        b.copy_from_slice(&nonce.as_bytes());
        b
    }));
    felts.push(Felt::from(cards.len() as u64));
    for card in cards {
        // d2 = in_c2 − out_c2（链上同源重算）。d2 可能是恒等（in==out）
        // ——此时该卡方程退化为 s·in_c1 = a，仍被折叠约束。
        let d2 = card.in_c2 - card.out_c2;
        let (in_c1x, in_c1y) = card.in_c1.to_affine_parts().expect("non-identity in_c1");
        let (in_c2x, in_c2y) = card.in_c2.to_affine_parts().expect("non-identity in_c2");
        let (out_c1x, out_c1y) = card.out_c1.to_affine_parts().expect("non-identity out_c1");
        let (out_c2x, out_c2y) = card.out_c2.to_affine_parts().expect("non-identity out_c2");
        let (ax, ay) = card.a.to_affine_parts().expect("non-identity a");
        // d2 词：若非恒等取仿射坐标，恒等则记 (0, 0)（链上同判）
        let (d2_x, d2_y) = if d2.is_identity() {
            (Felt::ZERO, Felt::ZERO)
        } else {
            let (x, y) = d2.to_affine_parts().unwrap();
            (x, y)
        };
        felts.push(in_c1x);
        felts.push(in_c1y);
        felts.push(in_c2x);
        felts.push(in_c2y);
        felts.push(out_c1x);
        felts.push(out_c1y);
        felts.push(out_c2x);
        felts.push(out_c2y);
        felts.push(ax);
        felts.push(ay);
        felts.push(d2_x);
        felts.push(d2_y);
    }
    let h = poseidon_hash_many(&felts);
    StarkScalar(reduce_mod_n(U256::from_be_slice(&h.to_bytes_be())))
}

/// leave 方程的每卡公开词（点为 StarkPoint）。
pub struct HandLeaveCardWords {
    pub in_c1: StarkPoint,
    pub in_c2: StarkPoint,
    pub out_c1: StarkPoint,
    pub out_c2: StarkPoint,
    pub a: StarkPoint,
}

/// 可折叠 reconstruct（CP-DLEQ）挑战（felt 直通，同上纪律）：
/// `c = poseidon([recon_label, hand_binding, g1, g2, p1, p2, a, b]) mod n`。
/// 方程（与 poker-protocol-proofs/src/reconstruction/chaum_pedersen.rs
/// 的 DLEQ 同形）：
///   eq1: s·G1 − A − c·P1 = O
///   eq2: s·G2 − B − c·P2 = O
pub fn handbatch_reconstruct_challenge(
    hand_binding: &[u8; 32],
    g1: &StarkPoint,
    g2: &StarkPoint,
    p1: &StarkPoint,
    p2: &StarkPoint,
    a: &StarkPoint,
    b: &StarkPoint,
) -> StarkScalar {
    let (g1x, g1y) = g1.to_affine_parts().expect("non-identity g1");
    let (g2x, g2y) = g2.to_affine_parts().expect("non-identity g2");
    let (p1x, p1y) = p1.to_affine_parts().expect("non-identity p1");
    let (p2x, p2y) = p2.to_affine_parts().expect("non-identity p2");
    let (ax, ay) = a.to_affine_parts().expect("non-identity a");
    let (bx, by) = b.to_affine_parts().expect("non-identity b");
    let felts = [
        ascii_felt("poker/reconstruct-fold/v1"),
        word_to_felt(hand_binding),
        g1x, g1y, g2x, g2y, p1x, p1y, p2x, p2y, ax, ay, bx, by,
    ];
    let h = poseidon_hash_many(&felts);
    StarkScalar(reduce_mod_n(U256::from_be_slice(&h.to_bytes_be())))
}

/// 手级 ρ（Horner 折叠版，A 优化）：
/// `rho = poseidon([v1_label, hand_binding, n_eq, (s, pk_x, pk_y, R_x, R_y)*]) mod n`。
/// transcript 绑定每条方程的全部公开输入（s、pk、R；G 是全局常量）。
/// Cairo 端 hand_batch_stark.cairo::hand_rho 复刻同输入集。
/// host 侧返回归约标量（Horner 点乘等价：EC 标量乘对 m 与 m mod n 同结果）；
/// Cairo 端用原始 poseidon felt 作标量，数学等价。
pub fn handbatch_rho(
    hand_binding: &[u8; 32],
    equations: &[HandBatchEquationWords],
) -> StarkScalar {
    // 每方程 3 felt：(kind, s, c)。c 由链上从该方程全部公开输入重算
    //（poseidon 抗碰撞），已整体绑定语句；ρ 只需绑定"哪些方程按序
    // 折叠"，无需重复全部点词。
    let mut felts = Vec::with_capacity(3 + 3 * equations.len());
    felts.push(handbatch_v1_label());
    felts.push(word_to_felt(hand_binding));
    felts.push(Felt::from(equations.len() as u64));
    for eq in equations {
        felts.push(Felt::from(eq.kind as u64));
        felts.push(word_to_felt(&eq.s));
        felts.push(word_to_felt(&eq.c));
    }
    let h = poseidon_hash_many(&felts);
    StarkScalar(reduce_mod_n(U256::from_be_slice(&h.to_bytes_be())))
}

/// 一条参与折叠的方程的 ρ 输入词。
#[derive(Debug, Clone, Copy)]
pub struct HandBatchEquationWords {
    /// 1 = ownership（s·G − c·pk − R）；2 = reveal 两联方程。
    pub kind: u8,
    pub s: [u8; 32],
    /// 挑战 c（ownership: handbatch_endorsement_challenge；reveal:
    /// handbatch_reveal_challenge——链上从公开输入重算同一值）。
    pub c: [u8; 32],
}

/// BG（Bayer-Groth）可折叠纪元的 Poseidon 海绵 transcript：单 felt 状态，
/// 每步一次 `poseidon_hash_many`，可在 Cairo 端逐置换精确重放（无字节
/// 序列化、无 keccak）。
///
/// 规范（三端一致，勿改）：
/// - init:  `state = poseidon([ascii("poker/bg-fold/v1")])`（协议名经
///   `append_message` 进入 transcript，见 BG 的 `bg12_protocol` 步）。
/// - append_message(label, msg):
///   `state = poseidon([state, ascii(label[..31]), felt(msg.len()), felt(msg)])`
///   —— **约束**：msg 必须为 ≤31 字节的短消息（ASCII 标签 / 小端 u64），
///   单 felt 大整数编码；超长消息按 31 字节大端块分多个 felt（BG 证明
///   系统只使用 ≤31 字节消息，最长 `b"poker/bayer-groth-shuffle/v2"`）。
/// - append_point(label, pt):
///   `state = poseidon([state, ascii(label[..31]), x, y])`（仿射坐标，
///   仅对 [`StarkPoint`] 定义；其他曲线后端走压缩字节回退，不可重放）。
/// - append_scalar(label, s):
///   `state = poseidon([state, ascii(label[..31]), felt(s)])`（s < n < P，
///   单 felt 无截断）。
/// - challenge(label):
///   `out = poseidon([state, ascii(label[..31]), ascii("chal")])`；
///   返回 `out mod n`；随后 `state = poseidon([state, out])`。
#[derive(Debug, Clone)]
pub struct PoseidonFeltTranscript {
    state: Felt,
}

/// transcript 域标签（≤31 字节，felt 直通）。
const BG_FOLD_DOMAIN: &str = "poker/bg-fold/v1";

impl PoseidonFeltTranscript {
    /// 规范初始状态（不经 [`CryptoTranscript::new`] 也可直接构造）。
    pub fn new_bg_fold() -> Self {
        Self {
            state: poseidon_hash_many(&[ascii_felt(BG_FOLD_DOMAIN)]),
        }
    }

    /// 当前海绵状态（诊断/向量导出用）。
    pub fn state(&self) -> Felt {
        self.state
    }

    fn absorb_label_and(&mut self, label: &[u8], extra: &[Felt]) {
        let mut input = Vec::with_capacity(2 + extra.len());
        input.push(self.state);
        input.push(ascii_bytes31(label));
        input.extend_from_slice(extra);
        self.state = poseidon_hash_many(&input);
    }
}

/// 任意 ≤31 字节标签 → felt（超长取前 31 字节，规范级截断）。
fn ascii_bytes31(bytes: &[u8]) -> Felt {
    let bytes = &bytes[..bytes.len().min(31)];
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    Felt::from_bytes_be(&buf)
}

/// ≤31 字节消息 → 单 felt；更长消息按 31 字节大端块拆分。
fn message_felts(msg: &[u8]) -> Vec<Felt> {
    msg.chunks(31)
        .map(|chunk| {
            let mut buf = [0u8; 32];
            buf[32 - chunk.len()..].copy_from_slice(chunk);
            Felt::from_bytes_be(&buf)
        })
        .collect()
}

impl crate::CryptoTranscript for PoseidonFeltTranscript {
    fn new(_protocol_name: &[u8]) -> Self {
        // 协议名由调用方 append_message 绑定（BG 的 bg12_protocol 步）；
        // 海绵初始化固定为 BG 折叠纪元域标签，保证 Cairo 重放唯一。
        Self::new_bg_fold()
    }

    fn append_message(&mut self, label: &[u8], message: &[u8]) {
        let mut extra = Vec::with_capacity(2);
        extra.push(Felt::from(message.len() as u64));
        extra.extend(message_felts(message));
        self.absorb_label_and(label, &extra);
    }

    fn append_point<C: crate::Curve>(&mut self, label: &[u8], point: &C::Point) {
        // 仿射 (x, y) 直通路径只对 StarkPoint 定义（Cairo 重放目标）；
        // 其他曲线后端退化为压缩字节块（仅 host 测试可用，不可重放）。
        use std::any::Any;
        let any_point: &dyn Any = point;
        if let Some(p) = any_point.downcast_ref::<StarkPoint>() {
            let (x, y) = p.to_affine_parts().expect("non-identity transcript point");
            self.absorb_label_and(label, &[x, y]);
        } else {
            let compressed = point.compress();
            let bytes = compressed.as_ref();
            let mut extra = Vec::with_capacity(2);
            extra.push(Felt::from(bytes.len() as u64));
            extra.extend(message_felts(bytes));
            self.absorb_label_and(label, &extra);
        }
    }

    fn append_scalar<C: crate::Curve>(&mut self, label: &[u8], scalar: &C::Scalar) {
        let bytes = scalar.as_bytes();
        // StarkScalar 恒 < n < P：单 felt 无截断。其他后端走分块回退。
        if bytes.len() == 32 && bytes[0] <= 0x07 {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&bytes);
            self.absorb_label_and(label, &[Felt::from_bytes_be(&buf)]);
        } else {
            let mut extra = Vec::with_capacity(2);
            extra.push(Felt::from(bytes.len() as u64));
            extra.extend(message_felts(&bytes));
            self.absorb_label_and(label, &extra);
        }
    }

    fn challenge_bytes(&mut self, label: &[u8], dest: &mut [u8]) {
        let out = poseidon_hash_many(&[
            self.state,
            ascii_bytes31(label),
            ascii_felt("chal"),
        ]);
        let bytes = out.to_bytes_be();
        let copy_len = dest.len().min(bytes.len());
        dest[..copy_len].copy_from_slice(&bytes[..copy_len]);
    }

    fn challenge<C: crate::Curve>(&mut self, label: &[u8]) -> crate::Challenge<C> {
        let out = poseidon_hash_many(&[
            self.state,
            ascii_bytes31(label),
            ascii_felt("chal"),
        ]);
        // 与 StarkScalar::from_bytes_mod_order 同一归约（右侧对齐 32B 后
        // mod n）；对 StarkCurve 即 reduce_mod_n(poseidon felt)。
        let scalar = C::Scalar::from_bytes_mod_order(&out.to_bytes_be());
        self.state = poseidon_hash_many(&[self.state, out]);
        crate::Challenge { scalar }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use starknet_curve::curve_params::EC_ORDER;
    use starknet_types_core::curve::ProjectivePoint as CorePoint;

    fn to_core(p: &StarkPoint) -> CorePoint {
        match p.to_affine_parts() {
            Some((x, y)) => CorePoint::from_affine(x, y).expect("valid affine point"),
            None => CorePoint::identity(),
        }
    }

    fn from_core(p: &CorePoint) -> StarkPoint {
        if p.is_identity() {
            return <StarkPoint as CurvePoint>::identity();
        }
        let affine = p.to_affine().expect("non-identity point");
        StarkPoint::from_affine_parts(affine.x(), affine.y())
    }

    fn random_point() -> StarkPoint {
        StarkPoint::random(&mut OsRng)
    }

    #[test]
    fn group_order_matches_starknet_curve_params() {
        let params_be = EC_ORDER.to_bytes_be();
        let ours = EC_ORDER_U256.to_be_bytes();
        assert_eq!(ours.as_slice(), &params_be[..]);
    }

    #[test]
    fn base_points_are_distinct_and_valid() {
        let g = <StarkCurve as Curve>::base_g();
        let h = <StarkCurve as Curve>::base_h();
        assert!(!g.is_identity());
        assert!(!h.is_identity());
        assert_ne!(g, h);
        // G must match the Cairo/EC_OP generator.
        let g_core = to_core(&g);
        assert_eq!(
            g_core.to_affine().expect("affine").x(),
            GENERATOR.x(),
            "base_g must equal the Starknet generator"
        );
    }

    #[test]
    fn scalar_ring_properties() {
        let a = StarkScalar::random(&mut OsRng);
        let b = StarkScalar::random(&mut OsRng);
        let c = StarkScalar::random(&mut OsRng);
        // distributivity: (a + b)·c = a·c + b·c
        assert_eq!((a + b) * c, a * c + b * c);
        // inverse
        assert_eq!(a * a.invert(), StarkScalar::one());
        // negation
        assert_eq!(a + (-a), StarkScalar::zero());
        // sub/add roundtrip
        assert_eq!((a - b) + b, a);
    }

    #[test]
    fn scalar_wide_bytes_matches_secp_discipline() {
        let bytes = [7u8; 64];
        let wide = StarkScalar::from_bytes_mod_order_wide(&bytes);
        let mut xored = [0u8; 32];
        for i in 0..32 {
            xored[i] = 0;
        }
        assert_eq!(wide, StarkScalar::from_bytes_mod_order(&xored));
    }

    #[test]
    fn point_add_matches_types_core_oracle() {
        for _ in 0..16 {
            let p = random_point();
            let q = random_point();
            let mine = p + q;
            let oracle = to_core(&p) + to_core(&q);
            assert_eq!(to_core(&mine), oracle);
        }
    }

    #[test]
    fn point_double_matches_types_core_oracle() {
        for _ in 0..16 {
            let p = random_point();
            let mine = p.double();
            let oracle = to_core(&p) + to_core(&p);
            assert_eq!(to_core(&mine), oracle);
        }
    }

    #[test]
    fn point_scalar_mul_matches_types_core_oracle() {
        for _ in 0..8 {
            let p = random_point();
            let s = StarkScalar::random(&mut OsRng);
            let mine = p * s;
            // interpret the mod-n scalar as a field element mod P (valid:
            // n < P) and compare against the oracle scalar multiplication
            let s_felt = Felt::from_bytes_be_slice(&s.as_bytes());
            let oracle_p = to_core(&p);
            let oracle = &oracle_p * s_felt;
            assert_eq!(to_core(&mine), oracle);
        }
    }

    #[test]
    fn point_sub_and_neg_roundtrip() {
        let p = random_point();
        let q = random_point();
        assert_eq!(p + (-q), p - q);
        assert_eq!((p - q) + q, p);
    }

    #[test]
    fn identity_is_additive_zero() {
        let id = <StarkPoint as CurvePoint>::identity();
        let p = random_point();
        assert!(id.is_identity());
        assert_eq!(id + p, p);
        assert_eq!(p + id, p);
        assert_eq!(p + (-p), id);
    }

    #[test]
    fn multiscalar_matches_sequential_sum() {
        let scalars: Vec<StarkScalar> =
            (0..17).map(|_| StarkScalar::random(&mut OsRng)).collect();
        let points: Vec<StarkPoint> =
            (0..17).map(|_| random_point()).collect();
        let batch = StarkPoint::vartime_multiscalar_mul(&scalars, &points);
        let sequential: StarkPoint =
            points.iter().zip(scalars.iter()).map(|(p, s)| *p * *s).sum();
        assert_eq!(batch, sequential);
    }

    #[test]
    fn compress_decompress_roundtrip() {
        // identity
        let id = <StarkPoint as CurvePoint>::identity();
        let id_bytes = id.compress();
        assert_eq!(
            id_bytes.as_ref().iter().all(|b| *b == 0),
            true,
            "identity compresses to all-zero bytes"
        );
        assert!(<StarkPoint as CurvePoint>::from_compressed(id_bytes.as_ref())
            .expect("identity roundtrip")
            .is_identity());

        for _ in 0..32 {
            let p = random_point();
            let compressed = p.compress();
            assert_eq!(compressed.as_ref().len(), 32);
            let restored = <StarkPoint as CurvePoint>::from_compressed(compressed.as_ref())
                .expect("canonical compressed point parses");
            assert_eq!(restored, p);
        }
    }

    #[test]
    fn hash_to_curve_is_deterministic_and_on_curve() {
        let a = <StarkCurve as Curve>::hash_to_curve(b"deck-card-17");
        let b = <StarkCurve as Curve>::hash_to_curve(b"deck-card-17");
        assert_eq!(a, b);
        assert!(!a.is_identity());
        // on-curve check via affine coords
        let (x, y) = a.to_affine_parts().expect("non-identity");
        assert_eq!(y * y, x * x * x + x + BETA);
        // distinct inputs give distinct points (overwhelming probability)
        let c = <StarkCurve as Curve>::hash_to_curve(b"deck-card-18");
        assert_ne!(a, c);
    }

    #[test]
    fn hash_to_scalar_reduces_mod_group_order() {
        for input in [
            &b"challenge-1"[..],
            &b"texas_poker_batch_rho"[..],
            &[0xffu8; 64][..],
        ] {
            let s = <StarkCurve as Curve>::hash_to_scalar(input);
            assert!(s.to_u256() < EC_ORDER_U256);
        }
        // deterministic
        assert_eq!(
            <StarkCurve as Curve>::hash_to_scalar(b"rho"),
            <StarkCurve as Curve>::hash_to_scalar(b"rho")
        );
    }

    #[test]
    fn elgamal_roundtrip_on_stark_curve() {
        let sk = StarkScalar::random(&mut OsRng);
        let pk = <StarkCurve as Curve>::base_g() * sk;
        let msg = <StarkCurve as Curve>::hash_to_curve(b"card-ace-spades");
        let r = StarkScalar::random(&mut OsRng);
        let ct = StarkElGamalCiphertext::encrypt(&msg, &pk, &r);
        assert!(ct.is_valid());
        assert_eq!(ct.decrypt(&sk), msg);
        // re-encryption keeps the plaintext
        let r2 = StarkScalar::random(&mut OsRng);
        let ct2 = ct.re_encrypt(&pk, &r2);
        assert_ne!(ct, ct2);
        assert_eq!(ct2.decrypt(&sk), msg);
        // reveal token: c1 * sk must decrypt c2 - token
        let token = ct.gen_reveal_token(&sk);
        assert_eq!(ct.c2 - token, msg);
    }
}
