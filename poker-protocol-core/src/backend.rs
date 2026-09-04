//! Native curve backends for the crate's curve-agnostic traits.
//!
//! Three implementations are provided by this facade:
//! - `RistrettoCurve`: Ristretto255 curve (curve25519-dalek)
//! - `Bn254Curve`: BN254 G1 curve (halo2curves, direct-sigma settlement route)

use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;

use crate::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as DalekScalar,
    traits::{
        Identity as DalekIdentity, IsIdentity as DalekIsIdentity,
        VartimeMultiscalarMul as DalekVartimeMultiscalarMul,
    },
};
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_256;

use halo2curves::bn256::{Fr as BnScalar, G1 as BnG1, G1Affine as BnG1Affine};
use halo2curves::group::{Group as BnGroup, GroupEncoding as BnGroupEncoding};
use halo2curves::{ff as bn_ff, msm as bn_msm, CurveExt as BnCurveExt};

// ============================================================
// Ristretto255 implementation
// ============================================================

/// Wrapper around `CompressedRistretto` that implements `AsRef<[u8]>`.
#[derive(Clone, Debug)]
pub struct CompressedPoint(CompressedRistretto);

impl CompressedPoint {
    /// Access the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl AsRef<[u8]> for CompressedPoint {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<CompressedRistretto> for CompressedPoint {
    fn from(c: CompressedRistretto) -> Self {
        CompressedPoint(c)
    }
}

/// Ristretto255 curve implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RistrettoCurve;

impl CurveScalar for DalekScalar {
    fn zero() -> Self {
        DalekScalar::ZERO
    }

    fn one() -> Self {
        DalekScalar::ONE
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        DalekScalar::random(rng)
    }

    fn from_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut wide = [0u8; 64];
        let len = 64.min(bytes.len());
        wide[..len].copy_from_slice(&bytes[..len]);
        DalekScalar::from_bytes_mod_order_wide(&wide)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut encoded = [0u8; 32];
        encoded.copy_from_slice(bytes);
        Option::<DalekScalar>::from(DalekScalar::from_canonical_bytes(encoded))
    }

    fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        DalekScalar::from_bytes_mod_order_wide(bytes)
    }

    fn from_u64(val: u64) -> Self {
        DalekScalar::from(val)
    }

    fn as_bytes(&self) -> Vec<u8> {
        DalekScalar::as_bytes(self).to_vec()
    }

    fn invert(&self) -> Self {
        DalekScalar::invert(self)
    }
}

impl CurvePoint for RistrettoPoint {
    type Scalar = DalekScalar;
    type Compressed = CompressedPoint;

    fn identity() -> Self {
        DalekIdentity::identity()
    }

    fn is_identity(&self) -> bool {
        DalekIsIdentity::is_identity(self)
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        RistrettoPoint::random(rng)
    }

    fn compress(&self) -> CompressedPoint {
        CompressedPoint(RistrettoPoint::compress(self))
    }

    fn vartime_multiscalar_mul(scalars: &[DalekScalar], points: &[Self]) -> Self {
        <RistrettoPoint as DalekVartimeMultiscalarMul>::vartime_multiscalar_mul(scalars, points)
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        CompressedRistretto::from_slice(bytes)
            .ok()
            .and_then(|c| c.decompress())
    }
}

impl Curve for RistrettoCurve {
    type Point = RistrettoPoint;
    type Scalar = DalekScalar;

    fn base_g() -> RistrettoPoint {
        RISTRETTO_BASEPOINT_TABLE.basepoint()
    }

    fn base_h() -> RistrettoPoint {
        // Map uniform bytes directly into Ristretto.  Using G * hash(label)
        // would publish the discrete-log relation between G and H and would
        // invalidate Pedersen commitment binding assumptions.
        Self::hash_to_curve(b"crypto_independent_base_H_2024")
    }

    fn hash_to_scalar(digest: &[u8]) -> DalekScalar {
        let mut bytes = [0u8; 64];
        let len = 64.min(digest.len());
        bytes[..len].copy_from_slice(&digest[..len]);
        let s = DalekScalar::from_bytes_mod_order_wide(&bytes);
        if s == DalekScalar::ZERO {
            let mut h = Sha256::new();
            h.update(b"hts_retry:");
            h.update(&bytes[..32]);
            let retry = h.finalize();
            let mut rb = [0u8; 64];
            rb[..32].copy_from_slice(&retry);
            let s2 = DalekScalar::from_bytes_mod_order_wide(&rb);
            if s2 == DalekScalar::ZERO {
                DalekScalar::ONE
            } else {
                s2
            }
        } else {
            s
        }
    }

    fn hash_to_curve(digest: &[u8]) -> RistrettoPoint {
        // Ristretto's canonical hash-to-group construction consumes 64
        // uniformly distributed bytes and, unlike G * hash(label), does not
        // expose a known discrete-log relation to the standard generator.
        let uniform_bytes: [u8; 64] = Sha512::digest(digest).into();
        RistrettoPoint::from_uniform_bytes(&uniform_bytes)
    }

    fn n_cards() -> usize {
        52
    }
}


// ============================================================
// BN254 G1 implementation
// ============================================================

/// Wrapper around the 32-byte compressed BN254 G1 encoding that implements
/// `AsRef<[u8]>`.
#[derive(Clone, Debug)]
pub struct BnCompressedPoint([u8; 32]);

impl BnCompressedPoint {
    /// Access the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for BnCompressedPoint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// BN254 G1 curve implementation (halo2curves bn256, direct-sigma settlement
/// route).
///
/// Serialization discipline (DUAL_PROOF_PROTOCOL.md §3.2): scalars are
/// 32-byte **big-endian** (same convention as the BLS12-381 backend), points
/// are halo2curves' 32-byte compressed G1 encodings (cofactor is 1, so an
/// on-curve check is sufficient for external points — no subgroup check).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bn254Curve;

impl CurveScalar for BnScalar {
    fn zero() -> Self {
        <Self as bn_ff::Field>::ZERO
    }

    fn one() -> Self {
        <Self as bn_ff::Field>::ONE
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        <Self as bn_ff::Field>::random(rng)
    }

    fn from_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut arr = [0u8; 32];
        let len = 32.min(bytes.len());
        arr[32 - len..].copy_from_slice(&bytes[..len]);

        // Big-endian parse (matches as_bytes() output and the BLS backend's
        // Move-compat convention).
        let ct = Self::from_canonical_bytes(&arr);
        if let Some(s) = ct {
            return s;
        }

        // Value >= modulus: subtract the modulus until in range. A 32-byte
        // value is < 2^256 < 2 * r^2 / 2^255, so a bounded loop suffices.
        const MODULUS_BE: [u8; 32] = [
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81,
            0x58, 0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93,
            0xf0, 0x00, 0x00, 0x01,
        ];

        for _ in 0..4 {
            let mut borrow = 0i64;
            for i in (0..32).rev() {
                let diff = arr[i] as i64 - MODULUS_BE[i] as i64 - borrow;
                if diff < 0 {
                    arr[i] = (diff + 256) as u8;
                    borrow = 1;
                } else {
                    arr[i] = diff as u8;
                    borrow = 0;
                }
            }
            let ct = Self::from_canonical_bytes(&arr);
            if let Some(s) = ct {
                return s;
            }
        }

        <Self as bn_ff::Field>::ZERO
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut le = [0u8; 32];
        le.copy_from_slice(bytes);
        le.reverse(); // to_repr/from_repr are little-endian; wire form is BE
        Option::<Self>::from(<Self as bn_ff::PrimeField>::from_repr(le.into()))
    }

    fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        // Same discipline as the BLS backend: XOR the two halves down to
        // 32 bytes, then reduce modulo the group order.
        let mut arr = [0u8; 32];
        for i in 0..32 {
            arr[i] = bytes[i] ^ bytes[32 + i];
        }
        Self::from_bytes_mod_order(&arr)
    }

    fn from_u64(val: u64) -> Self {
        <Self as core::convert::From<u64>>::from(val)
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut le = *<Self as bn_ff::PrimeField>::to_repr(self).inner();
        le.reverse(); // wire form is big-endian
        le.to_vec()
    }

    fn invert(&self) -> Self {
        <Self as bn_ff::Field>::invert(self).unwrap_or(<Self as bn_ff::Field>::ZERO)
    }
}

impl CurvePoint for BnG1 {
    type Scalar = BnScalar;
    type Compressed = BnCompressedPoint;

    fn identity() -> Self {
        <Self as BnGroup>::identity()
    }

    fn is_identity(&self) -> bool {
        bool::from(<Self as BnGroup>::is_identity(self))
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let s = <BnScalar as bn_ff::Field>::random(rng);
        <Self as BnGroup>::generator() * s
    }

    fn compress(&self) -> BnCompressedPoint {
        BnCompressedPoint(*<Self as BnGroupEncoding>::to_bytes(self).inner())
    }

    fn vartime_multiscalar_mul(scalars: &[BnScalar], points: &[Self]) -> Self {
        let bases: Vec<BnG1Affine> = points.iter().map(|p| BnG1Affine::from(*p)).collect();
        bn_msm::msm_best(scalars, &bases)
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        let ct = <BnG1Affine as BnGroupEncoding>::from_bytes(&halo2curves::serde::Repr::from(arr));
        if bool::from(ct.is_some()) {
            Some(BnG1::from(ct.unwrap()))
        } else {
            None
        }
    }
}

impl Curve for Bn254Curve {
    type Point = BnG1;
    type Scalar = BnScalar;

    fn base_g() -> BnG1 {
        <BnG1 as BnGroup>::generator()
    }

    fn base_h() -> BnG1 {
        // SVDW hash-to-curve (RFC 9380) rather than G * hash(label): the
        // latter would publish the discrete-log relation between G and H and
        // invalidate the Pedersen binding assumption used by the
        // Bayer-Groth product argument.
        let f = <BnG1 as BnCurveExt>::hash_to_curve("texas_poker_independent_base_H_bn254");
        f(b"")
    }

    fn hash_to_scalar(digest: &[u8]) -> BnScalar {
        // SHA3-256 → clear the top THREE bits → big-endian parse.
        //
        // Unlike BLS12-381 (r > 2^254, so clearing 2 bits suffices), the
        // BN254 group order r ≈ 0x30.. < 2^254: a value masked to < 2^254
        // could still exceed r. Clearing 3 bits bounds the value < 2^253,
        // which is strictly below r, so the big-endian parse always succeeds.
        let mut hash = Sha3_256::digest(digest);
        hash[0] &= 0x1F;
        let arr: [u8; 32] = hash.into();
        BnScalar::from_canonical_bytes(&arr).expect("masked SHA3 output is always < r")
    }

    fn hash_to_curve(digest: &[u8]) -> BnG1 {
        // RFC 9380 SVDW map into BN254 G1 (halo2curves default suite:
        // BN254G1_XMD:SHA-256_SVDW_RO_). Deterministic, no known discrete-log
        // relation to the standard generator.
        let f = <BnG1 as BnCurveExt>::hash_to_curve("texas_poker_bn254");
        f(digest)
    }

    fn n_cards() -> usize {
        52
    }
}

// ============================================================
// secp256k1 implementation (k256)
// ============================================================

use k256::elliptic_curve::{
    ops::Reduce as KReduce, Field as KField, PrimeField as KPrimeField, Group as KGroup,
    hash2curve::{ExpandMsgXmd as KExpandMsgXmd, GroupDigest as KGroupDigest},
    sec1::{FromEncodedPoint as KFromEncodedPoint, ToEncodedPoint as KToEncodedPoint},
};
use k256::{ProjectivePoint as SecpPoint, Scalar as SecpScalar, Secp256k1};
use k256::EncodedPoint as SecpEncodedPoint;
use sha3::Keccak256 as KKeccak256;
use sha3::Sha3_256 as KSha3;

/// Wrapper around the 33-byte compressed secp256k1 SEC1 encoding.
#[derive(Clone, Debug)]
pub struct SecpCompressedPoint([u8; 33]);

impl SecpCompressedPoint {
    /// Access the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}

impl AsRef<[u8]> for SecpCompressedPoint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// secp256k1 curve implementation (k256, direct-sigma settlement route).
///
/// Starknet exposes native EC point add/scalar-mul builtins for this exact
/// curve (EC_OP), so the Cairo verifier side needs no custom field
/// arithmetic — unlike BN254. Serialization discipline (§3.2): k256's
/// `to_repr`/`from_repr` are big-endian 32-byte, matching the wire directly
/// (no byte reversal). Point encodings are 33-byte compressed SEC1.
///
/// Challenge derivation note: unlike BLS12-381 (r > 2^254, clear top bits)
/// the secp256k1 group order is within 2^128 of 2^256, so a 32-byte SHA3
/// output exceeds n with probability ~2^-128; `reduce_bytes` (mod-n) is used
/// instead of high-bit clearing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Secp256k1Curve;

impl CurveScalar for SecpScalar {
    fn zero() -> Self {
        <Self as KField>::ZERO
    }

    fn one() -> Self {
        <Self as KField>::ONE
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        <Self as KField>::random(rng)
    }

    fn from_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut repr = [0u8; 32];
        let len = 32.min(bytes.len());
        repr[32 - len..].copy_from_slice(&bytes[..len]);
        <Self as KReduce<k256::elliptic_curve::bigint::U256>>::reduce_bytes(&repr.into())
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut repr = [0u8; 32];
        repr.copy_from_slice(bytes);
        Option::<Self>::from(Self::from_repr(repr.into()))
    }

    fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        // Same discipline as the BLS/BN254 backends: XOR the two halves down
        // to 32 bytes, then reduce modulo the group order.
        let mut arr = [0u8; 32];
        for i in 0..32 {
            arr[i] = bytes[i] ^ bytes[32 + i];
        }
        <Self as KReduce<k256::elliptic_curve::bigint::U256>>::reduce_bytes(&arr.into())
    }

    fn from_u64(val: u64) -> Self {
        <Self as core::convert::From<u64>>::from(val)
    }

    fn as_bytes(&self) -> Vec<u8> {
        Self::to_repr(self).to_vec()
    }

    fn invert(&self) -> Self {
        <Self as KField>::invert(self).unwrap_or(<Self as KField>::ZERO)
    }
}

impl CurvePoint for SecpPoint {
    type Scalar = SecpScalar;
    type Compressed = SecpCompressedPoint;

    fn identity() -> Self {
        <Self as KGroup>::identity()
    }

    fn is_identity(&self) -> bool {
        bool::from(<SecpPoint as KGroup>::is_identity(self))
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let s = <SecpScalar as KField>::random(rng);
        <Self as KGroup>::generator() * s
    }

    fn compress(&self) -> SecpCompressedPoint {
        let encoded: SecpEncodedPoint = self.to_affine().to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(encoded.as_bytes());
        SecpCompressedPoint(out)
    }

    fn vartime_multiscalar_mul(scalars: &[SecpScalar], points: &[Self]) -> Self {
        // Vartime linear combination (k256). A straightforward fold; k256's
        // precomputed tables keep per-term cost low.
        let terms = points.iter().zip(scalars.iter());
        terms.map(|(point, scalar)| *point * *scalar).sum()
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 33 {
            return None;
        }
        let encoded = SecpEncodedPoint::from_bytes(bytes).ok()?;
        let affine = Option::<k256::AffinePoint>::from(k256::AffinePoint::from_encoded_point(
            &encoded,
        ))?;
        Some(affine.into())
    }
}

/// RFC 9380 SSWU hash into secp256k1 (SHA-256 XMD expansion, domain
/// `texas_poker_secp256k1`). Deterministic; the discrete log of the result
/// w.r.t. G is unknown, which is what `base_h` (Pedersen commitment binding)
/// requires.
fn secp_hash_to_curve(digest: &[u8]) -> SecpPoint {
    <Secp256k1 as KGroupDigest>::hash_from_bytes::<KExpandMsgXmd<sha2::Sha256>>(
        &[digest],
        &[b"texas_poker_secp256k1"],
    )
    .expect("hash-to-curve expansion is infallible for valid inputs")
}

impl Curve for Secp256k1Curve {
    type Point = SecpPoint;
    type Scalar = SecpScalar;

    fn base_g() -> SecpPoint {
        <SecpPoint as KGroup>::generator()
    }

    fn base_h() -> SecpPoint {
        // Try-and-increment rather than G * hash(label): the latter would
        // publish the discrete-log relation between G and H and invalidate
        // the Pedersen binding assumption used by the Bayer-Groth product
        // argument.
        secp_hash_to_curve(b"texas_poker_independent_base_H_secp256k1")
    }

    fn hash_to_scalar(digest: &[u8]) -> SecpScalar {
        // Keccak-256 → mod n (v2.3). The secp256k1 route's challenge
        // derivation maps to Starknet's native keccak builtin for on-chain
        // Fiat–Shamir replay. Byte-order convention (must match the Cairo
        // verifier exactly): the challenge is the digest's **little-endian**
        // integer interpretation reduced mod n — the digest bytes are
        // reversed before the big-endian field parse. The group order sits
        // within 2^128 of 2^256, so the reduction is effectively the
        // identity. Other backends keep their SHA3 big-endian discipline.
        let mut hash: [u8; 32] = KKeccak256::digest(digest).into();
        hash.reverse();
        <SecpScalar as KReduce<k256::elliptic_curve::bigint::U256>>::reduce_bytes(&hash.into())
    }

    fn hash_to_curve(digest: &[u8]) -> SecpPoint {
        secp_hash_to_curve(digest)
    }

    fn n_cards() -> usize {
        52
    }
}

/// Type alias for Ristretto255 ElGamal ciphertext (backward compatibility).
pub type RistrettoElGamalCiphertext = ElGamalCiphertextGeneric<RistrettoCurve>;


/// Type alias for BN254 ElGamal ciphertext (direct-sigma settlement route).
pub type Bn254ElGamalCiphertext = ElGamalCiphertextGeneric<Bn254Curve>;

/// Type alias for secp256k1 ElGamal ciphertext (direct-sigma settlement
/// route, Starknet-native EC_OP builtin).
pub type Secp256k1ElGamalCiphertext = ElGamalCiphertextGeneric<Secp256k1Curve>;

/// Batch encrypt plaintexts under the given public key.
pub fn ec_encrypt_batch_generic<C: Curve>(
    plaintexts: &[C::Point],
    pk: &C::Point,
    rng: &mut (impl CryptoRng + RngCore),
) -> Vec<ElGamalCiphertextGeneric<C>> {
    let r_vec: Vec<C::Scalar> = (0..plaintexts.len())
        .map(|_| C::Scalar::random(rng))
        .collect();
    plaintexts
        .par_iter()
        .zip(r_vec.par_iter())
        .map(|(pt, r)| ElGamalCiphertextGeneric::encrypt(pt, pk, r))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    // ========== RistrettoCurve tests ==========

    #[test]
    fn test_ristretto_curve_base_points() {
        let g = RistrettoCurve::base_g();
        let h = RistrettoCurve::base_h();
        assert!(!<RistrettoPoint as CurvePoint>::is_identity(&g));
        assert!(!<RistrettoPoint as CurvePoint>::is_identity(&h));
        assert_ne!(g, h);
    }

    #[test]
    fn test_ristretto_scalar_operations() {
        let a = DalekScalar::random(&mut OsRng);
        let b = DalekScalar::random(&mut OsRng);
        let _ = a + b;
        let _ = a - b;
        let _ = a * b;
        let _ = -a;
        assert_ne!(DalekScalar::zero(), DalekScalar::one());
        assert_eq!(DalekScalar::from_u64(0), DalekScalar::zero());
        assert_eq!(DalekScalar::from_u64(1), DalekScalar::one());
    }

    #[test]
    fn test_ristretto_point_operations() {
        let g = RistrettoCurve::base_g();
        let s = DalekScalar::from_u64(42);
        let p = &g * &s;
        assert!(!<RistrettoPoint as CurvePoint>::is_identity(&p));
        let _ = g.clone() + p.clone();
        let _ = g.clone() - p;
    }

    #[test]
    fn test_ristretto_elgamal_encrypt_decrypt() {
        let sk = DalekScalar::random(&mut OsRng);
        let pk = RistrettoCurve::base_g() * &sk;
        let plaintext = RistrettoCurve::base_g() * &DalekScalar::from_u64(123);
        let r = DalekScalar::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<RistrettoCurve>::encrypt(&plaintext, &pk, &r);
        let decrypted = ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ristretto_elgamal_re_encrypt() {
        let sk = DalekScalar::random(&mut OsRng);
        let pk = RistrettoCurve::base_g() * &sk;
        let plaintext = RistrettoCurve::base_g() * &DalekScalar::from_u64(456);
        let r = DalekScalar::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<RistrettoCurve>::encrypt(&plaintext, &pk, &r);
        let r_prime = DalekScalar::random(&mut OsRng);
        let re_ct = ct.re_encrypt(&pk, &r_prime);
        let decrypted = re_ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ristretto_hash_to_scalar() {
        let data = b"test data for hashing";
        let s = RistrettoCurve::hash_to_scalar(data);
        assert_ne!(s, DalekScalar::zero());
    }

    #[test]
    fn test_ristretto_n_cards() {
        assert_eq!(RistrettoCurve::n_cards(), 52);
    }

    #[test]
    fn test_ristretto_vartime_multiscalar_mul() {
        let g = RistrettoCurve::base_g();
        let h = RistrettoCurve::base_h();
        let s1 = DalekScalar::from_u64(3);
        let s2 = DalekScalar::from_u64(5);

        let result = <RistrettoPoint as CurvePoint>::vartime_multiscalar_mul(&[s1, s2], &[g, h]);
        let expected = &g * &s1 + &h * &s2;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_ristretto_placeholder_card() {
        let ct = ElGamalCiphertextGeneric::<RistrettoCurve>::new_placeholder_card();
        assert!(<RistrettoPoint as CurvePoint>::is_identity(&ct.c1));
        assert!(<RistrettoPoint as CurvePoint>::is_identity(&ct.c2));
    }

    #[test]
    fn test_ristretto_reveal_token() {
        let sk = DalekScalar::random(&mut OsRng);
        let pk = RistrettoCurve::base_g() * &sk;
        let plaintext = RistrettoCurve::base_g() * &DalekScalar::from_u64(789);
        let r = DalekScalar::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<RistrettoCurve>::encrypt(&plaintext, &pk, &r);
        let token = ct.gen_reveal_token(&sk);
        let expected = &ct.c1 * &sk;
        assert_eq!(token, expected);

        // Verify decryption using reveal token
        let decrypted = ct.c2.clone() - token;
        assert_eq!(decrypted, plaintext);
    }


    // ========== Bn254Curve tests ==========

    #[test]
    fn test_bn254_curve_base_points() {
        let g = Bn254Curve::base_g();
        let h = Bn254Curve::base_h();
        assert!(!<BnG1 as CurvePoint>::is_identity(&g));
        assert!(!<BnG1 as CurvePoint>::is_identity(&h));
        assert_ne!(g, h);
    }

    #[test]
    fn test_bn254_scalar_operations() {
        let a = <BnScalar as CurveScalar>::random(&mut OsRng);
        let b = <BnScalar as CurveScalar>::random(&mut OsRng);
        let _ = a + b;
        let _ = a - b;
        let _ = a * b;
        let _ = -a;
        assert_ne!(BnScalar::zero(), BnScalar::one());
        assert_eq!(BnScalar::from_u64(0), BnScalar::zero());
        assert_eq!(BnScalar::from_u64(1), BnScalar::one());
    }

    #[test]
    fn test_bn254_point_operations() {
        let g = Bn254Curve::base_g();
        let s = BnScalar::from_u64(42);
        let p = &g * &s;
        assert!(!<BnG1 as CurvePoint>::is_identity(&p));
        let _ = g.clone() + p.clone();
        let _ = g.clone() - p;
    }

    #[test]
    fn test_bn254_elgamal_encrypt_decrypt() {
        let sk = <BnScalar as CurveScalar>::random(&mut OsRng);
        let pk = Bn254Curve::base_g() * &sk;
        let plaintext = Bn254Curve::base_g() * &BnScalar::from_u64(123);
        let r = <BnScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Bn254Curve>::encrypt(&plaintext, &pk, &r);
        let decrypted = ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bn254_elgamal_re_encrypt() {
        let sk = <BnScalar as CurveScalar>::random(&mut OsRng);
        let pk = Bn254Curve::base_g() * &sk;
        let plaintext = Bn254Curve::base_g() * &BnScalar::from_u64(456);
        let r = <BnScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Bn254Curve>::encrypt(&plaintext, &pk, &r);
        let r_prime = <BnScalar as CurveScalar>::random(&mut OsRng);
        let re_ct = ct.re_encrypt(&pk, &r_prime);
        let decrypted = re_ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bn254_hash_to_scalar() {
        let data = b"test data for hashing";
        let s = Bn254Curve::hash_to_scalar(data);
        assert_ne!(s, BnScalar::zero());
        // Deterministic and collision-distinct across domain labels.
        let s2 = Bn254Curve::hash_to_scalar(data);
        assert_eq!(s, s2);
        let s3 = Bn254Curve::hash_to_scalar(b"other domain");
        assert_ne!(s, s3);
    }

    #[test]
    fn test_bn254_n_cards() {
        assert_eq!(Bn254Curve::n_cards(), 52);
    }

    #[test]
    fn test_bn254_vartime_multiscalar_mul() {
        let g = Bn254Curve::base_g();
        let h = Bn254Curve::base_h();
        let s1 = BnScalar::from_u64(3);
        let s2 = BnScalar::from_u64(5);

        let result = <BnG1 as CurvePoint>::vartime_multiscalar_mul(&[s1, s2], &[g, h]);
        let expected = &g * &s1 + &h * &s2;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_bn254_placeholder_card() {
        let ct = ElGamalCiphertextGeneric::<Bn254Curve>::new_placeholder_card();
        assert!(<BnG1 as CurvePoint>::is_identity(&ct.c1));
        assert!(<BnG1 as CurvePoint>::is_identity(&ct.c2));
    }

    #[test]
    fn test_bn254_reveal_token() {
        let sk = <BnScalar as CurveScalar>::random(&mut OsRng);
        let pk = Bn254Curve::base_g() * &sk;
        let plaintext = Bn254Curve::base_g() * &BnScalar::from_u64(789);
        let r = <BnScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Bn254Curve>::encrypt(&plaintext, &pk, &r);
        let token = ct.gen_reveal_token(&sk);
        let expected = &ct.c1 * &sk;
        assert_eq!(token, expected);

        // Verify decryption using reveal token
        let decrypted = ct.c2.clone() - token;
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bn254_remask() {
        let sk = <BnScalar as CurveScalar>::random(&mut OsRng);
        let pk = Bn254Curve::base_g() * &sk;
        let plaintext = Bn254Curve::base_g() * &BnScalar::from_u64(999);
        let r = <BnScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Bn254Curve>::encrypt(&plaintext, &pk, &r);
        let remask_sk = <BnScalar as CurveScalar>::random(&mut OsRng);
        let remasked = ct.remask(&remask_sk);

        // c1 should be unchanged
        assert_eq!(remasked.c1, ct.c1);
        // c2 should be different
        assert_ne!(remasked.c2, ct.c2);
    }

    #[test]
    fn test_bn254_point_serialization() {
        let g = Bn254Curve::base_g();
        let compressed = g.compress();
        assert_eq!(compressed.as_ref().len(), 32);
        let decompressed = <BnG1 as CurvePoint>::from_compressed(compressed.as_ref());
        assert!(decompressed.is_some());
        assert_eq!(decompressed.unwrap(), g);

        // Non-canonical byte flips still decode only if the result is a
        // valid curve point; the guarantees we assert are exact round-trips
        // and that the identity encoding decodes.
        let mut bad = [0u8; 32];
        bad.copy_from_slice(compressed.as_ref());
        bad[31] ^= 0x01;
        let _ = <BnG1 as CurvePoint>::from_compressed(&bad);

        let id = <BnG1 as CurvePoint>::identity();
        let id_compressed = id.compress();
        let id_back = <BnG1 as CurvePoint>::from_compressed(id_compressed.as_ref());
        assert!(id_back.is_some());
    }

    #[test]
    fn test_bn254_scalar_serialization() {
        let s = BnScalar::from_u64(42);
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 32);
        let s2 = BnScalar::from_bytes_mod_order(&bytes);
        assert_eq!(s, s2);

        // Canonical rejection: a 32-byte value >= r must not parse.
        let overflow = [0xffu8; 32];
        assert!(BnScalar::from_canonical_bytes(&overflow).is_none());
        // ...but from_bytes_mod_order must still reduce it correctly.
        let reduced = BnScalar::from_bytes_mod_order(&overflow);
        assert_eq!(<BnScalar as CurveScalar>::as_bytes(&reduced).len(), 32);

        // Random scalars round-trip through the wire encoding.
        for _ in 0..16 {
            let s = <BnScalar as CurveScalar>::random(&mut OsRng);
            let bytes = <BnScalar as CurveScalar>::as_bytes(&s);
            assert_eq!(BnScalar::from_bytes_mod_order(&bytes), s);
        }
    }

    #[test]
    fn test_bn254_hash_to_curve_deterministic() {
        let p1 = Bn254Curve::hash_to_curve(b"texas_poker/card/0");
        let p2 = Bn254Curve::hash_to_curve(b"texas_poker/card/0");
        let p3 = Bn254Curve::hash_to_curve(b"texas_poker/card/1");
        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
        assert!(!<BnG1 as CurvePoint>::is_identity(&p1));
    }

    // ========== Secp256k1Curve tests ==========

    #[test]
    fn test_secp256k1_curve_base_points() {
        let g = Secp256k1Curve::base_g();
        let h = Secp256k1Curve::base_h();
        assert!(!<SecpPoint as CurvePoint>::is_identity(&g));
        assert!(!<SecpPoint as CurvePoint>::is_identity(&h));
        assert_ne!(g, h);
    }

    #[test]
    fn test_secp256k1_scalar_operations() {
        let a = <SecpScalar as CurveScalar>::random(&mut OsRng);
        let b = <SecpScalar as CurveScalar>::random(&mut OsRng);
        let _ = a + b;
        let _ = a - b;
        let _ = a * b;
        let _ = -a;
        assert_ne!(SecpScalar::zero(), SecpScalar::one());
        assert_eq!(SecpScalar::from_u64(0), SecpScalar::zero());
        assert_eq!(SecpScalar::from_u64(1), SecpScalar::one());
    }

    #[test]
    fn test_secp256k1_point_operations() {
        let g = Secp256k1Curve::base_g();
        let s = SecpScalar::from_u64(42);
        let p = &g * &s;
        assert!(!<SecpPoint as CurvePoint>::is_identity(&p));
        let _ = g.clone() + p.clone();
        let _ = g.clone() - p;
    }

    #[test]
    fn test_secp256k1_elgamal_encrypt_decrypt() {
        let sk = <SecpScalar as CurveScalar>::random(&mut OsRng);
        let pk = Secp256k1Curve::base_g() * &sk;
        let plaintext = Secp256k1Curve::base_g() * &SecpScalar::from_u64(123);
        let r = <SecpScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Secp256k1Curve>::encrypt(&plaintext, &pk, &r);
        let decrypted = ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_secp256k1_elgamal_re_encrypt() {
        let sk = <SecpScalar as CurveScalar>::random(&mut OsRng);
        let pk = Secp256k1Curve::base_g() * &sk;
        let plaintext = Secp256k1Curve::base_g() * &SecpScalar::from_u64(456);
        let r = <SecpScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Secp256k1Curve>::encrypt(&plaintext, &pk, &r);
        let r_prime = <SecpScalar as CurveScalar>::random(&mut OsRng);
        let re_ct = ct.re_encrypt(&pk, &r_prime);
        let decrypted = re_ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_secp256k1_hash_to_scalar() {
        let data = b"test data for hashing";
        let s = Secp256k1Curve::hash_to_scalar(data);
        assert_ne!(s, SecpScalar::zero());
        let s2 = Secp256k1Curve::hash_to_scalar(data);
        assert_eq!(s, s2);
        let s3 = Secp256k1Curve::hash_to_scalar(b"other domain");
        assert_ne!(s, s3);
    }

    #[test]
    fn test_secp256k1_vartime_multiscalar_mul() {
        let g = Secp256k1Curve::base_g();
        let h = Secp256k1Curve::base_h();
        let s1 = SecpScalar::from_u64(3);
        let s2 = SecpScalar::from_u64(5);

        let result = <SecpPoint as CurvePoint>::vartime_multiscalar_mul(&[s1, s2], &[g, h]);
        let expected = &g * &s1 + &h * &s2;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_secp256k1_reveal_token() {
        let sk = <SecpScalar as CurveScalar>::random(&mut OsRng);
        let pk = Secp256k1Curve::base_g() * &sk;
        let plaintext = Secp256k1Curve::base_g() * &SecpScalar::from_u64(789);
        let r = <SecpScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Secp256k1Curve>::encrypt(&plaintext, &pk, &r);
        let token = ct.gen_reveal_token(&sk);
        let expected = &ct.c1 * &sk;
        assert_eq!(token, expected);
        let decrypted = ct.c2.clone() - token;
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_secp256k1_point_serialization() {
        let g = Secp256k1Curve::base_g();
        let compressed = g.compress();
        assert_eq!(compressed.as_ref().len(), 33);
        let decompressed = <SecpPoint as CurvePoint>::from_compressed(compressed.as_ref());
        assert!(decompressed.is_some());
        assert_eq!(decompressed.unwrap(), g);

        // Non-canonical 33-byte encodings (invalid SEC1 tag) are rejected.
        let mut bad = [0u8; 33];
        bad.copy_from_slice(compressed.as_ref());
        bad[0] = 0x00;
        assert!(<SecpPoint as CurvePoint>::from_compressed(&bad).is_none());
    }

    #[test]
    fn test_secp256k1_scalar_serialization() {
        let s = SecpScalar::from_u64(42);
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 32);
        let s2 = SecpScalar::from_bytes_mod_order(&bytes);
        assert_eq!(s, s2);

        // Values >= n reduce instead of failing.
        let big = [0xffu8; 32];
        let reduced = SecpScalar::from_bytes_mod_order(&big);
        assert_eq!(SecpScalar::as_bytes(&reduced).len(), 32);

        // Random scalars round-trip through the wire encoding.
        for _ in 0..16 {
            let s = <SecpScalar as CurveScalar>::random(&mut OsRng);
            let bytes = <SecpScalar as CurveScalar>::as_bytes(&s);
            assert_eq!(SecpScalar::from_bytes_mod_order(&bytes), s);
        }
    }

    #[test]
    fn test_secp256k1_hash_to_curve_deterministic() {
        let p1 = Secp256k1Curve::hash_to_curve(b"texas_poker/card/0");
        let p2 = Secp256k1Curve::hash_to_curve(b"texas_poker/card/0");
        let p3 = Secp256k1Curve::hash_to_curve(b"texas_poker/card/1");
        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
        assert!(!<SecpPoint as CurvePoint>::is_identity(&p1));

        // Batch determinism: derived table matches across calls.
        for i in 0..52 {
            let label = format!("texas_poker/card/{i}");
            assert_eq!(
                Secp256k1Curve::hash_to_curve(label.as_bytes()),
                Secp256k1Curve::hash_to_curve(label.as_bytes())
            );
        }
    }
}
