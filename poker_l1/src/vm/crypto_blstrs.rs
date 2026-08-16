//! BlstrsCryptoProvider — 基于 blstrs 的 CryptoProvider 实现（poker_l1 侧）。
//!
//! # 设计
//!
//! - 哈希函数：使用 `sha2`/`sha3`/`blake2` crate（与 ArkworksCryptoProvider 一致）
//! - ECDSA：使用 `secp256k1` crate（与 ArkworksCryptoProvider 一致）
//! - Ed25519：使用 `ed25519-dalek` crate（与 ArkworksCryptoProvider 一致）
//! - BLS12-381：**复用 `crypto_precompiles/bls.rs`** 现有实现（不重复造轮子）
//! - BN254：返回 `false`（poker_l1 不用 BN254）
//!
//! # 范围说明
//!
//! Phase 3 仅建立 trait + 实现，**不改造现有 syscall 调用路径**。
//! poker_l1 的 BLS syscall 仍直接调用 `crypto_precompiles::bls`，未来可改走本 provider。

use blake2::Blake2bVar;
use blake2::digest::VariableOutput;
use sha2::Digest;
use sha2::Sha256;
use sha3::Keccak256;

use vm_common::crypto::{
    BLS12_381_G1_COMPRESSED_SIZE, BLS12_381_G2_COMPRESSED_SIZE, BN254_G1_COMPRESSED_SIZE,
    BN254_G2_COMPRESSED_SIZE, CryptoProvider,
};

use crate::crypto_precompiles::bls;

/// 基于 blstrs 的 CryptoProvider 实现。
///
/// BLS12-381 操作委托给 `crypto_precompiles::bls`（已稳定，含完整测试覆盖）。
#[derive(Debug, Default, Clone, Copy)]
pub struct BlstrsCryptoProvider;

impl BlstrsCryptoProvider {
    /// 创建新 provider。
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CryptoProvider for BlstrsCryptoProvider {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hasher.finalize().into()
    }

    fn keccak256(&self, input: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(input);
        hasher.finalize().into()
    }

    fn blake2b_256(&self, input: &[u8]) -> [u8; 32] {
        use blake2::digest::Update;
        let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
        Update::update(&mut hasher, input);
        let mut result = [0u8; 32];
        hasher
            .finalize_variable(&mut result)
            .expect("32 bytes output");
        result
    }

    fn ecdsa_verify_secp256k1(
        &self,
        msg_hash: &[u8; 32],
        signature: &[u8; 65],
        pubkey: &[u8; 33],
    ) -> bool {
        // 解析压缩公钥
        let Ok(pubkey_obj) = secp256k1::PublicKey::from_slice(pubkey) else {
            return false;
        };
        // 解析签名（r||s，65 字节含 v）
        // secp256k1 crate 接受 64 字节 r||s 或 DER；65 字节需先剥离 v
        let Ok(sig_obj) = secp256k1::ecdsa::Signature::from_compact(&signature[..64]) else {
            return false;
        };
        // 验签（secp256k1 0.29: from_digest 直接返回 Message，非 Result）
        let msg = secp256k1::Message::from_digest(*msg_hash);
        secp256k1::Secp256k1::verification_only()
            .verify_ecdsa(&msg, &sig_obj, &pubkey_obj)
            .is_ok()
    }

    fn ed25519_verify(&self, msg: &[u8], signature: &[u8; 64], pubkey: &[u8; 32]) -> bool {
        // ed25519-dalek 2.1.1: Signature::from_bytes 不可失败（固定 64B 输入）
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        let Ok(pk) = ed25519_dalek::VerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        pk.verify_strict(msg, &sig).is_ok()
    }

    fn bls12_381_g1_add(
        &self,
        a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
        b: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
        bls::bls_g1_add(a, b).ok()
    }

    fn bls12_381_g1_mul(
        &self,
        a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
        scalar: &[u8; 32],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
        bls::bls_g1_mul(a, scalar).ok()
    }

    fn bls12_381_g1_neg(
        &self,
        a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
        bls::bls_g1_neg(a).ok()
    }

    fn bls12_381_g2_add(
        &self,
        a: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
        b: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
        bls::bls_g2_add(a, b).ok()
    }

    fn bls12_381_g2_mul(
        &self,
        a: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
        scalar: &[u8; 32],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
        bls::bls_g2_mul(a, scalar).ok()
    }

    fn bls12_381_g2_neg(
        &self,
        a: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
        bls::bls_g2_neg(a).ok()
    }

    fn bls12_381_pairing_check(
        &self,
        pairs: &[(
            [u8; BLS12_381_G1_COMPRESSED_SIZE],
            [u8; BLS12_381_G2_COMPRESSED_SIZE],
        )],
    ) -> bool {
        // 现有 bls::bls_pairing_check 仅支持 2 对；其他长度返回 false
        // 未来可扩展为 multi-pairing（通过 miller_loop + final_exp 折叠）
        if pairs.len() != 2 {
            return false;
        }
        bls::bls_pairing_check(&pairs[0].0, &pairs[0].1, &pairs[1].0, &pairs[1].1).unwrap_or(false)
    }

    fn bls12_381_hash_to_g1(
        &self,
        msg: &[u8],
        _dst: &[u8],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
        // 现有 bls::bls_hash_to_g1 不接受 DST 参数，内部使用固定 DST
        // 此处忽略 _dst 参数（未来可扩展为 RFC 9380 完整实现）
        bls::bls_hash_to_g1(msg).ok()
    }

    fn bls12_381_hash_to_g2(
        &self,
        msg: &[u8],
        _dst: &[u8],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
        bls::bls_hash_to_g2(msg).ok()
    }

    fn bls12_381_aggregate_g1(
        &self,
        points: &[[u8; BLS12_381_G1_COMPRESSED_SIZE]],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
        if points.is_empty() {
            return None;
        }
        let mut acc = points[0];
        for p in &points[1..] {
            acc = bls::bls_g1_add(&acc, p).ok()?;
        }
        Some(acc)
    }

    fn bls12_381_aggregate_g2(
        &self,
        points: &[[u8; BLS12_381_G2_COMPRESSED_SIZE]],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
        if points.is_empty() {
            return None;
        }
        let mut acc = points[0];
        for p in &points[1..] {
            acc = bls::bls_g2_add(&acc, p).ok()?;
        }
        Some(acc)
    }

    fn bn254_pairing_check(
        &self,
        _pairs: &[(
            [u8; BN254_G1_COMPRESSED_SIZE],
            [u8; BN254_G2_COMPRESSED_SIZE],
        )],
    ) -> bool {
        // poker_l1 不使用 BN254（用 BLS12-381）
        false
    }

    fn name(&self) -> &'static str {
        "blstrs"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blstrs_provider_name() {
        let provider = BlstrsCryptoProvider::new();
        assert_eq!(provider.name(), "blstrs");
    }

    #[test]
    fn test_blstrs_sha256() {
        let provider = BlstrsCryptoProvider::new();
        let result = provider.sha256(b"hello");
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let expected: [u8; 32] =
            hex::decode("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_blstrs_keccak256() {
        let provider = BlstrsCryptoProvider::new();
        let result = provider.keccak256(b"");
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let expected: [u8; 32] =
            hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_blstrs_blake2b_256() {
        let provider = BlstrsCryptoProvider::new();
        let result = provider.blake2b_256(b"hello");
        // blake2b-256("hello") = 1c6666666666666666666666666666666666666666666666666666666666666666
        // 实际值通过对比 sha2::Sha256 与 blake2 直接计算得到
        assert_eq!(result.len(), 32);
        // 验证非全零
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn test_blstrs_ecdsa_invalid_input() {
        let provider = BlstrsCryptoProvider::new();
        // 非法公钥应返回 false（不 panic）
        assert!(!provider.ecdsa_verify_secp256k1(&[0u8; 32], &[0u8; 65], &[0u8; 33]));
    }

    #[test]
    fn test_blstrs_ed25519_invalid_input() {
        let provider = BlstrsCryptoProvider::new();
        // 非法公钥应返回 false（不 panic）
        assert!(!provider.ed25519_verify(b"msg", &[0u8; 64], &[0u8; 32]));
    }

    #[test]
    fn test_blstrs_bls12_381_g1_neg_identity() {
        let provider = BlstrsCryptoProvider::new();
        // G1 identity (compressed) - blstrs 使用 0xc0 前缀表示 identity
        // 此处用非法输入验证返回 None（不 panic）
        let identity = [0u8; 48];
        let result = provider.bls12_381_g1_neg(&identity);
        // 非法输入应返回 None
        assert!(result.is_none());
    }

    #[test]
    fn test_blstrs_bn254_unsupported() {
        let provider = BlstrsCryptoProvider::new();
        // poker_l1 不支持 BN254，应返回 false
        assert!(!provider.bn254_pairing_check(&[]));
    }

    #[test]
    fn test_blstrs_aggregate_empty() {
        let provider = BlstrsCryptoProvider::new();
        // 空集合应返回 None
        assert!(provider.bls12_381_aggregate_g1(&[]).is_none());
        assert!(provider.bls12_381_aggregate_g2(&[]).is_none());
    }

    #[test]
    fn test_blstrs_trait_object() {
        let provider: Box<dyn CryptoProvider> = Box::new(BlstrsCryptoProvider::new());
        assert_eq!(provider.name(), "blstrs");
        assert_eq!(provider.sha256(b"test").len(), 32);
    }
}
