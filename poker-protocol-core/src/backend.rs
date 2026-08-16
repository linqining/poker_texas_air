//! Native curve backends for the crate's curve-agnostic traits.
//!
//! Two implementations are provided by this facade:
//! - `RistrettoCurve`: Ristretto255 curve (curve25519-dalek)
//! - `Bls12381Curve`: BLS12-381 G1 curve (blstrs, Sui-compatible)

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

use blstrs::{G1Compressed, G1Projective, Scalar as BlsScalar};
use ff::Field;
use group::{Group, GroupEncoding};

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
// BLS12-381 G1 implementation
// ============================================================

/// Wrapper around `G1Compressed` that implements `AsRef<[u8]>`.
#[derive(Clone, Debug)]
pub struct BlsCompressedPoint(G1Compressed);

impl BlsCompressedPoint {
    /// Access the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsRef<[u8]> for BlsCompressedPoint {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<G1Compressed> for BlsCompressedPoint {
    fn from(c: G1Compressed) -> Self {
        BlsCompressedPoint(c)
    }
}

/// BLS12-381 G1 curve implementation (Sui-compatible).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bls12381Curve;

impl CurveScalar for BlsScalar {
    fn zero() -> Self {
        <Self as Field>::ZERO
    }

    fn one() -> Self {
        <Self as Field>::ONE
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        <Self as Field>::random(rng)
    }

    fn from_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut arr = [0u8; 32];
        let len = 32.min(bytes.len());
        arr[..len].copy_from_slice(&bytes[..len]);

        // 兼容 Move 合约 bls12381::scalar_from_bytes（大端序解析）：
        // 使用 from_bytes_be 而非 from_repr_vartime（小端序），
        // 确保 as_bytes() 的输出能被 from_bytes_mod_order 正确反序列化。

        // Try big-endian deserialization first (works for values < modulus)
        let ct = BlsScalar::from_bytes_be(&arr);
        if bool::from(ct.is_some()) {
            return ct.unwrap();
        }

        // Value >= modulus. Since max 32-byte value < 3 * modulus,
        // subtract modulus until the value is in range.
        // BLS12-381 scalar modulus in big-endian:
        const MODULUS_BE: [u8; 32] = [
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1,
            0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x01,
        ];

        for _ in 0..3 {
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
            let ct = BlsScalar::from_bytes_be(&arr);
            if bool::from(ct.is_some()) {
                return ct.unwrap();
            }
        }

        <Self as Field>::ZERO
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut encoded = [0u8; 32];
        encoded.copy_from_slice(bytes);
        Option::<BlsScalar>::from(BlsScalar::from_bytes_be(&encoded))
    }

    fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        // Combine both halves: XOR low 32 bytes with high 32 bytes,
        // then reduce modulo the curve order.
        let mut arr = [0u8; 32];
        for i in 0..32 {
            arr[i] = bytes[i] ^ bytes[32 + i];
        }
        Self::from_bytes_mod_order(&arr)
    }

    fn from_u64(val: u64) -> Self {
        BlsScalar::from(val)
    }

    fn as_bytes(&self) -> Vec<u8> {
        // 兼容 Move 合约 bls12381::scalar_from_bytes（大端序解析）：
        // 使用 to_bytes_be() 而非 to_repr()（小端序），确保 Rust 端序列化的标量
        // 字节能被 Move 端正确反序列化。
        self.to_bytes_be().to_vec()
    }

    fn invert(&self) -> Self {
        <Self as Field>::invert(self).unwrap_or(<Self as Field>::ZERO)
    }
}

impl CurvePoint for G1Projective {
    type Scalar = BlsScalar;
    type Compressed = BlsCompressedPoint;

    fn identity() -> Self {
        <Self as Group>::identity()
    }

    fn is_identity(&self) -> bool {
        bool::from(<Self as Group>::is_identity(self))
    }

    fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let s = <BlsScalar as Field>::random(rng);
        <Self as Group>::generator() * s
    }

    fn compress(&self) -> BlsCompressedPoint {
        BlsCompressedPoint(<Self as GroupEncoding>::to_bytes(self))
    }

    fn vartime_multiscalar_mul(scalars: &[BlsScalar], points: &[Self]) -> Self {
        G1Projective::multi_exp(points, scalars)
    }

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 48 {
            return None;
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(bytes);
        let ct = G1Projective::from_compressed(&arr);
        if bool::from(ct.is_some()) {
            Some(ct.unwrap())
        } else {
            None
        }
    }
}

impl Curve for Bls12381Curve {
    type Point = G1Projective;
    type Scalar = BlsScalar;

    fn base_g() -> G1Projective {
        <G1Projective as Group>::generator()
    }

    fn base_h() -> G1Projective {
        // 兼容 Move 合约 bls_scalar::base_h()：
        // 使用 hash_to_g1（RFC 9380 hash-to-curve）而非 G * hash(label)。
        // 两者产生不同的点，必须与链上实现保持一致。
        // DST 必须与 Sui `bls12381::hash_to_g1` 一致：`BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`
        const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
        let label = b"texas_poker_independent_base_H";
        G1Projective::hash_to_curve(label, BLS_DST, b"")
    }

    fn hash_to_scalar(digest: &[u8]) -> BlsScalar {
        // 兼容 Move 合约 bls_scalar::hash_to_scalar：
        // SHA3-256(data) → 清除 h[0] 最高2位 → scalar_from_bytes
        //
        // Move 端 bls12381::scalar_from_bytes 使用 blst_scalar_from_bendian（大端序解析），
        // Rust 端必须使用 from_bytes_be（大端序解析）以保持一致。
        // 清位（& 0x3F）确保值 < 2^254 < r，大端序解析必然成功。
        let mut hash = Sha3_256::digest(digest);
        hash[0] &= 0x3F;
        let arr: [u8; 32] = hash.into();
        BlsScalar::from_bytes_be(&arr).unwrap()
    }

    fn hash_to_curve(digest: &[u8]) -> G1Projective {
        // 兼容 Move 合约 bls12381::hash_to_g1：
        // 使用 RFC 9380 hash-to-curve 到 BLS12-381 G1。
        // DST 必须与 Sui `bls12381::hash_to_g1` 一致。
        const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
        G1Projective::hash_to_curve(digest, BLS_DST, b"")
    }

    fn n_cards() -> usize {
        52
    }
}

/// Type alias for Ristretto255 ElGamal ciphertext (backward compatibility).
pub type RistrettoElGamalCiphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

/// Type alias for BLS12-381 ElGamal ciphertext.
pub type Bls12381ElGamalCiphertext = ElGamalCiphertextGeneric<Bls12381Curve>;

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

    // ========== Bls12381Curve tests ==========

    #[test]
    fn test_bls12381_curve_base_points() {
        let g = Bls12381Curve::base_g();
        let h = Bls12381Curve::base_h();
        assert!(!<G1Projective as CurvePoint>::is_identity(&g));
        assert!(!<G1Projective as CurvePoint>::is_identity(&h));
        assert_ne!(g, h);
    }

    #[test]
    fn test_bls12381_scalar_operations() {
        let a = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let b = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let _ = a + b;
        let _ = a - b;
        let _ = a * b;
        let _ = -a;
        assert_ne!(BlsScalar::zero(), BlsScalar::one());
        assert_eq!(BlsScalar::from_u64(0), BlsScalar::zero());
        assert_eq!(BlsScalar::from_u64(1), BlsScalar::one());
    }

    #[test]
    fn test_bls12381_point_operations() {
        let g = Bls12381Curve::base_g();
        let s = BlsScalar::from_u64(42);
        let p = &g * &s;
        assert!(!<G1Projective as CurvePoint>::is_identity(&p));
        let _ = g.clone() + p.clone();
        let _ = g.clone() - p;
    }

    #[test]
    fn test_bls12381_elgamal_encrypt_decrypt() {
        let sk = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let pk = Bls12381Curve::base_g() * &sk;
        let plaintext = Bls12381Curve::base_g() * &BlsScalar::from_u64(123);
        let r = <BlsScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Bls12381Curve>::encrypt(&plaintext, &pk, &r);
        let decrypted = ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bls12381_elgamal_re_encrypt() {
        let sk = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let pk = Bls12381Curve::base_g() * &sk;
        let plaintext = Bls12381Curve::base_g() * &BlsScalar::from_u64(456);
        let r = <BlsScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Bls12381Curve>::encrypt(&plaintext, &pk, &r);
        let r_prime = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let re_ct = ct.re_encrypt(&pk, &r_prime);
        let decrypted = re_ct.decrypt(&sk);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bls12381_hash_to_scalar() {
        let data = b"test data for hashing";
        let s = Bls12381Curve::hash_to_scalar(data);
        assert_ne!(s, BlsScalar::zero());
    }

    #[test]
    fn test_bls12381_n_cards() {
        assert_eq!(Bls12381Curve::n_cards(), 52);
    }

    #[test]
    fn test_bls12381_vartime_multiscalar_mul() {
        let g = Bls12381Curve::base_g();
        let h = Bls12381Curve::base_h();
        let s1 = BlsScalar::from_u64(3);
        let s2 = BlsScalar::from_u64(5);

        let result = <G1Projective as CurvePoint>::vartime_multiscalar_mul(&[s1, s2], &[g, h]);
        let expected = &g * &s1 + &h * &s2;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_bls12381_placeholder_card() {
        let ct = ElGamalCiphertextGeneric::<Bls12381Curve>::new_placeholder_card();
        assert!(<G1Projective as CurvePoint>::is_identity(&ct.c1));
        assert!(<G1Projective as CurvePoint>::is_identity(&ct.c2));
    }

    #[test]
    fn test_bls12381_reveal_token() {
        let sk = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let pk = Bls12381Curve::base_g() * &sk;
        let plaintext = Bls12381Curve::base_g() * &BlsScalar::from_u64(789);
        let r = <BlsScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Bls12381Curve>::encrypt(&plaintext, &pk, &r);
        let token = ct.gen_reveal_token(&sk);
        let expected = &ct.c1 * &sk;
        assert_eq!(token, expected);

        // Verify decryption using reveal token
        let decrypted = ct.c2.clone() - token;
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bls12381_remask() {
        let sk = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let pk = Bls12381Curve::base_g() * &sk;
        let plaintext = Bls12381Curve::base_g() * &BlsScalar::from_u64(999);
        let r = <BlsScalar as CurveScalar>::random(&mut OsRng);

        let ct = ElGamalCiphertextGeneric::<Bls12381Curve>::encrypt(&plaintext, &pk, &r);
        let remask_sk = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let remasked = ct.remask(&remask_sk);

        // c1 should be unchanged
        assert_eq!(remasked.c1, ct.c1);
        // c2 should be different
        assert_ne!(remasked.c2, ct.c2);
    }

    #[test]
    fn test_bls12381_point_serialization() {
        let g = Bls12381Curve::base_g();
        let compressed = g.compress();
        assert_eq!(compressed.as_ref().len(), 48);
        let decompressed = <G1Projective as CurvePoint>::from_compressed(compressed.as_ref());
        assert!(decompressed.is_some());
        assert_eq!(decompressed.unwrap(), g);
    }

    #[test]
    fn test_bls12381_scalar_serialization() {
        let s = BlsScalar::from_u64(42);
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 32);
        let s2 = BlsScalar::from_bytes_mod_order(&bytes);
        assert_eq!(s, s2);
    }
}
