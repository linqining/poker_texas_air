//! STARK curve arithmetic for the hand-verify spike.
//!
//! Curve: `y² = x³ + x + β` over `F_P`, `P = 2²⁵¹ + 17·2¹⁹² + 1` (the felt252
//! prime, handled natively by `starknet_crypto::Felt`), with group order
//! `n = 0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f`,
//! cofactor 1. These are the same constants the Cairo EC_OP builtin uses, so
//! host points map 1:1 to on-chain felts.
//!
//! Points use Jacobian coordinates with an explicit identity (Z = 0):
//! doubling is dbl-2001-b (a = 1 folds its z⁴ term in), addition is the
//! standard case-aware general Jacobian formulas. Performance is not the
//! spike's goal (see `docs/plan_d_perf.md`: the host fold is ~19 µs per
//! scalar mul).
//!
//! Two fields must not be confused (same discipline as
//! `poker-protocol-core::stark_curve`): coordinates live in `F_P`, scalars in
//! `Z_n`. `n < P`, so Felt arithmetic is *not* scalar arithmetic. EC scalars
//! are used as raw felts (valid: multiplying a point of order n by m and by
//! m mod n gives the same point); only the minting side reduces mod n, via
//! `BigUint`.

use std::ops::{Add, Neg, Sub};

use num_bigint::BigUint;
use starknet_crypto::FieldElement as Felt;

fn hex_felt(s: &str) -> Felt {
    Felt::from_hex_be(s).expect("hardcoded hex constant parses")
}

/// `y² = x³ + x + β` — the `β` coefficient (0x06f21413...cee9e89).
pub fn beta() -> Felt {
    use std::sync::OnceLock;
    static B: OnceLock<Felt> = OnceLock::new();
    *B.get_or_init(|| {
        hex_felt("06f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89")
    })
}

/// Group order `n`, decimal form (parsed via `from_dec_str` to avoid hex
/// transcription mistakes; pinned to the on-curve + order tests below).
const EC_ORDER_DEC: &str = "3618502788666131213697322783095070105526743751716087489154079457884512865583";

/// Base point `G`, decimal affine coordinates — byte-for-byte the constants
/// used by the vendored `hand_verify_bench` Cairo programs.
const GENERATOR_X_DEC: &str = "874739451078007766457464989774322083649278607533249481151382481072868806602";
const GENERATOR_Y_DEC: &str = "152666792071518830868575557812948353041420400780739481342941381225525861407";

fn dec_felt(s: &str) -> Felt {
    Felt::from_dec_str(s).expect("hardcoded decimal constant parses")
}

/// Group order as `BigUint` (mint-side mod-n arithmetic only).
pub fn ec_order() -> BigUint {
    use std::sync::OnceLock;
    static N: OnceLock<BigUint> = OnceLock::new();
    N.get_or_init(|| BigUint::from_bytes_be(&dec_felt(EC_ORDER_DEC).to_bytes_be())).clone()

}

/// Felt ↔ BigUint helpers (mint side).
pub fn felt_to_biguint(f: Felt) -> BigUint {
    BigUint::from_bytes_be(&f.to_bytes_be())
}

pub fn biguint_to_felt(v: &BigUint) -> Option<Felt> {
    let bytes = v.to_bytes_be();
    if bytes.len() > 32 {
        return None;
    }
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    Felt::from_bytes_be(&buf).ok()
}

/// `v mod n` (mint side).
pub fn reduce_mod_n(v: &BigUint) -> BigUint {
    v % ec_order()
}

/// A point on the STARK curve (Jacobian coordinates; `z == 0` is identity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    x: Felt,
    y: Felt,
    z: Felt,
}

impl Point {
    pub const fn identity() -> Self {
        Self { x: Felt::ONE, y: Felt::ONE, z: Felt::ZERO }
    }

    pub fn is_identity(&self) -> bool {
        self.z == Felt::ZERO
    }

    /// Affine construction with on-curve validation (mirrors Cairo
    /// `EcPoint::new`): rejects points off the curve.
    pub fn from_affine(x: Felt, y: Felt) -> Option<Self> {
        if y * y != x * x * x + x + beta() {
            return None;
        }
        Some(Self { x, y, z: Felt::ONE })
    }

    pub fn generator() -> Self {
        Self::from_affine(dec_felt(GENERATOR_X_DEC), dec_felt(GENERATOR_Y_DEC))
            .expect("hardcoded generator is on curve")
    }

    pub fn to_affine(&self) -> Option<(Felt, Felt)> {
        if self.is_identity() {
            return None;
        }
        let z_inv = self.z.invert()?;
        let z2 = z_inv * z_inv;
        let z3 = z2 * z_inv;
        Some((self.x * z2, self.y * z3))
    }

    pub fn neg(&self) -> Self {
        if self.is_identity() {
            return *self;
        }
        Self { x: self.x, y: Felt::ZERO - self.y, z: self.z }
    }

    /// dbl-2001-b for a = 1:
    /// S = 4·X·Y², M = 3·X² + Z⁴, X' = M² − 2S, Y' = M·(S − X') − 8·Y⁴,
    /// Z' = 2·Y·Z.
    pub fn double(&self) -> Self {
        if self.is_identity() {
            return *self;
        }
        let y2 = self.y * self.y;
        let s = (self.x * y2).double().double();
        let x2 = self.x * self.x;
        let z2 = self.z * self.z;
        let m = x2.double() + x2 + z2 * z2;
        let x3 = m * m - s.double();
        let y3 = m * (s - x3) - (y2 * y2).double().double().double();
        let z3 = (self.y * self.z).double();
        Self { x: x3, y: y3, z: z3 }
    }

    /// MSB-first double-and-add scalar multiplication.
    pub fn mul(&self, scalar: Felt) -> Self {
        let mut acc = Self::identity();
        for bit in scalar.to_bits_le().iter().rev() {
            acc = acc.double();
            if *bit {
                acc = acc + *self;
            }
        }
        acc
    }
}

impl Add for Point {
    type Output = Point;

    /// Standard case-aware Jacobian addition.
    fn add(self, rhs: Point) -> Point {
        if self.is_identity() {
            return rhs;
        }
        if rhs.is_identity() {
            return self;
        }
        let z1z1 = self.z * self.z;
        let z2z2 = rhs.z * rhs.z;
        let u1 = self.x * z2z2;
        let u2 = rhs.x * z1z1;
        let s1 = self.y * z2z2 * rhs.z;
        let s2 = rhs.y * z1z1 * self.z;
        if u1 == u2 {
            if s1 == s2 {
                return self.double();
            }
            return Point::identity();
        }
        let h = u2 - u1;
        let r = s2 - s1;
        let h2 = h * h;
        let h3 = h2 * h;
        let v = u1 * h2;
        let x3 = r * r - h3 - v.double();
        let y3 = r * (v - x3) - s1 * h3;
        let z3 = self.z * rhs.z * h;
        Point { x: x3, y: y3, z: z3 }
    }
}

impl Sub for Point {
    type Output = Point;

    fn sub(self, rhs: Point) -> Point {
        self + rhs.neg()
    }
}

impl Neg for Point {
    type Output = Point;

    fn neg(self) -> Point {
        Point::neg(&self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_is_on_curve() {
        let g = Point::generator();
        let (x, y) = g.to_affine().unwrap();
        assert_eq!(Point::from_affine(x, y), Some(g));
    }

    #[test]
    fn group_order_times_generator_is_identity() {
        let g = Point::generator();
        let n_felt = dec_felt(EC_ORDER_DEC);
        assert!(g.mul(n_felt).is_identity());
    }

    #[test]
    fn scalar_mul_consistency_small() {
        let g = Point::generator();
        let two_g = g + g;
        let three_g = two_g + g;
        assert_eq!(g.mul(Felt::from(3u32)), three_g);
        assert_eq!(g.mul(Felt::from(2u32)), two_g);
        assert_eq!(g.mul(Felt::from(0u32)), Point::identity());
    }

    #[test]
    fn add_and_sub_roundtrip() {
        let g = Point::generator();
        let two_g = g + g;
        // Jacobian equality is projective: compare in affine coordinates.
        assert_eq!((two_g - g).to_affine(), g.to_affine());
        assert_eq!((g + g.neg()).to_affine(), None);
    }

    #[test]
    fn off_curve_point_rejected() {
        let g = Point::generator();
        let (x, y) = g.to_affine().unwrap();
        assert_eq!(Point::from_affine(x, y + Felt::ONE), None);
    }

    #[test]
    fn group_order_is_the_expected_hex_constant() {
        // n = 0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f
        let n = ec_order();
        let expected = hex_felt(
            "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f",
        );
        assert_eq!(biguint_to_felt(&n).unwrap(), expected);
    }
}
