//! CryptoProvider — 跨 VM 密码学原语统一接口（Phase 3 迁入）。
//!
//! # 设计目标
//!
//! - 统一 poker_l1（blstrs）与 poker_zkvm（ark-bn254）的密码学原语接口
//! - **字节级接口**：使用 `[u8; N]` 而非关联类型，保证 trait object 安全
//! - vm-common 不依赖 blstrs/arkworks，仅定义接口
//! - 业务 BLS 用 blstrs（poker_l1），zkvm 电路用 ark-bn254（poker_zkvm），双库共存
//!
//! # 架构
//!
//! ```text
//! vm_common::crypto::CryptoProvider (trait, 字节级接口)
//!     ▲
//!     │ impl
//!     │
//!     ├── poker_l1::vm::crypto_blstrs::BlstrsCryptoProvider
//!     │   └── 复用 crypto_precompiles/bls.rs（不重复造轮子）
//!     │   └── BLS12-381: blstrs / ECDSA: secp256k1 / Ed25519: ed25519-dalek
//!     │
//!     └── poker_zkvm::crypto_arkworks::ArkworksCryptoProvider
//!         └── BN254: ark-bn254 / ECDSA: secp256k1 / Ed25519: ed25519-dalek
//!         └── BLS12-381: 返回 None/false（zkvm 不用 BLS12-381）
//! ```
//!
//! # 一致性保证
//!
//! 哈希函数（sha256/keccak256/blake2b_256）与签名验证（ecdsa/ed25519）使用相同底层
//! crate（sha2/blake2/secp256k1/ed25519-dalek），两个 provider 结果必然一致。
//! BLS12-381 vs BN254 是不同曲线，不做等价断言。
//!
//! # 范围说明
//!
//! Phase 3 仅建立 trait + 双实现 + 一致性测试，**不改造现有 syscall 调用路径**。
//! 让 syscalls 改走 CryptoProvider 是未来增量工作。

/// BLS12-381 G1 点压缩字节数（48 字节）。
pub const BLS12_381_G1_COMPRESSED_SIZE: usize = 48;

/// BLS12-381 G2 点压缩字节数（96 字节）。
pub const BLS12_381_G2_COMPRESSED_SIZE: usize = 96;

/// BN254 G1 点压缩字节数（32 字节）。
pub const BN254_G1_COMPRESSED_SIZE: usize = 32;

/// BN254 G2 点压缩字节数（64 字节）。
pub const BN254_G2_COMPRESSED_SIZE: usize = 64;

/// 跨 VM 密码学原语统一接口。
///
/// 所有方法使用字节级接口，避免暴露曲线点类型（如 `blstrs::G1Projective` 或
/// `ark_bn254::G1Projective`），让 trait object 可用且 vm-common 不依赖具体库。
///
/// # 实现
///
/// - [`BlstrsCryptoProvider`](../../poker_l1/vm/crypto_blstrs/struct.BlstrsCryptoProvider.html)
///   （poker_l1，BLS12-381 用 blstrs）
/// - [`ArkworksCryptoProvider`](../../poker_zkvm/crypto_arkworks/struct.ArkworksCryptoProvider.html)
///   （poker_zkvm，BN254 用 ark-bn254）
pub trait CryptoProvider: Send + Sync {
    // ===== 哈希函数（纯函数，无状态）=====

    /// SHA-256 哈希。
    fn sha256(&self, input: &[u8]) -> [u8; 32];

    /// Keccak-256 哈希（Ethereum 风格）。
    fn keccak256(&self, input: &[u8]) -> [u8; 32];

    /// Blake2b-256 哈希。
    fn blake2b_256(&self, input: &[u8]) -> [u8; 32];

    // ===== 签名验证 =====

    /// ECDSA secp256k1 签名验证。
    ///
    /// # 参数
    /// - `msg_hash`：消息哈希（32 字节）
    /// - `signature`：签名（65 字节 = r||s||v，v 为 recovery ID）
    /// - `pubkey`：压缩公钥（33 字节）
    ///
    /// # 返回
    /// `true` 表示签名有效。
    fn ecdsa_verify_secp256k1(
        &self,
        msg_hash: &[u8; 32],
        signature: &[u8; 65],
        pubkey: &[u8; 33],
    ) -> bool;

    /// Ed25519 签名验证。
    ///
    /// # 参数
    /// - `msg`：原始消息（任意长度）
    /// - `signature`：签名（64 字节）
    /// - `pubkey`：公钥（32 字节）
    fn ed25519_verify(&self, msg: &[u8], signature: &[u8; 64], pubkey: &[u8; 32]) -> bool;

    // ===== BLS12-381（poker_l1 blstrs 实现，zkvm 返回 None/false）=====

    /// BLS12-381 G1 点加法。
    ///
    /// # 返回
    /// `Some([u8; 48])` 表示成功，`None` 表示输入非法或 provider 不支持。
    fn bls12_381_g1_add(
        &self,
        a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
        b: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]>;

    /// BLS12-381 G1 标量乘法。
    fn bls12_381_g1_mul(
        &self,
        a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
        scalar: &[u8; 32],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]>;

    /// BLS12-381 G1 点取负。
    fn bls12_381_g1_neg(
        &self,
        a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]>;

    /// BLS12-381 G2 点加法。
    fn bls12_381_g2_add(
        &self,
        a: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
        b: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]>;

    /// BLS12-381 G2 标量乘法。
    fn bls12_381_g2_mul(
        &self,
        a: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
        scalar: &[u8; 32],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]>;

    /// BLS12-381 G2 点取负。
    fn bls12_381_g2_neg(
        &self,
        a: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]>;

    /// BLS12-381 pairing check。
    ///
    /// 验证 `e(pairs[0].0, pairs[0].1) * e(pairs[1].0, pairs[1].1) * ... == 1`。
    fn bls12_381_pairing_check(
        &self,
        pairs: &[(
            [u8; BLS12_381_G1_COMPRESSED_SIZE],
            [u8; BLS12_381_G2_COMPRESSED_SIZE],
        )],
    ) -> bool;

    /// BLS12-381 hash-to-G1（RFC 9380）。
    fn bls12_381_hash_to_g1(
        &self,
        msg: &[u8],
        dst: &[u8],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]>;

    /// BLS12-381 hash-to-G2（RFC 9380）。
    fn bls12_381_hash_to_g2(
        &self,
        msg: &[u8],
        dst: &[u8],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]>;

    /// BLS12-381 G1 聚合（点加法折叠）。
    fn bls12_381_aggregate_g1(
        &self,
        points: &[[u8; BLS12_381_G1_COMPRESSED_SIZE]],
    ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]>;

    /// BLS12-381 G2 聚合（点加法折叠）。
    fn bls12_381_aggregate_g2(
        &self,
        points: &[[u8; BLS12_381_G2_COMPRESSED_SIZE]],
    ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]>;

    // ===== BN254（zkvm ark-bn254 实现，poker_l1 返回 false）=====

    /// BN254 pairing check。
    ///
    /// 验证 `e(pairs[0].0, pairs[0].1) * e(pairs[1].0, pairs[1].1) * ... == 1`。
    fn bn254_pairing_check(
        &self,
        pairs: &[(
            [u8; BN254_G1_COMPRESSED_SIZE],
            [u8; BN254_G2_COMPRESSED_SIZE],
        )],
    ) -> bool;

    // ===== 元数据 =====

    /// Provider 名称（`"blstrs"` / `"arkworks"`）。
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用 CryptoProvider 实现（所有方法返回默认值，仅用于验证 trait object 可用）。
    struct DummyProvider;

    impl CryptoProvider for DummyProvider {
        fn sha256(&self, _input: &[u8]) -> [u8; 32] {
            [0u8; 32]
        }
        fn keccak256(&self, _input: &[u8]) -> [u8; 32] {
            [0u8; 32]
        }
        fn blake2b_256(&self, _input: &[u8]) -> [u8; 32] {
            [0u8; 32]
        }
        fn ecdsa_verify_secp256k1(
            &self,
            _msg_hash: &[u8; 32],
            _signature: &[u8; 65],
            _pubkey: &[u8; 33],
        ) -> bool {
            false
        }
        fn ed25519_verify(&self, _msg: &[u8], _signature: &[u8; 64], _pubkey: &[u8; 32]) -> bool {
            false
        }
        fn bls12_381_g1_add(
            &self,
            _a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
            _b: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
        ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
            None
        }
        fn bls12_381_g1_mul(
            &self,
            _a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
            _scalar: &[u8; 32],
        ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
            None
        }
        fn bls12_381_g1_neg(
            &self,
            _a: &[u8; BLS12_381_G1_COMPRESSED_SIZE],
        ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
            None
        }
        fn bls12_381_g2_add(
            &self,
            _a: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
            _b: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
        ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
            None
        }
        fn bls12_381_g2_mul(
            &self,
            _a: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
            _scalar: &[u8; 32],
        ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
            None
        }
        fn bls12_381_g2_neg(
            &self,
            _a: &[u8; BLS12_381_G2_COMPRESSED_SIZE],
        ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
            None
        }
        fn bls12_381_pairing_check(
            &self,
            _pairs: &[(
                [u8; BLS12_381_G1_COMPRESSED_SIZE],
                [u8; BLS12_381_G2_COMPRESSED_SIZE],
            )],
        ) -> bool {
            false
        }
        fn bls12_381_hash_to_g1(
            &self,
            _msg: &[u8],
            _dst: &[u8],
        ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
            None
        }
        fn bls12_381_hash_to_g2(
            &self,
            _msg: &[u8],
            _dst: &[u8],
        ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
            None
        }
        fn bls12_381_aggregate_g1(
            &self,
            _points: &[[u8; BLS12_381_G1_COMPRESSED_SIZE]],
        ) -> Option<[u8; BLS12_381_G1_COMPRESSED_SIZE]> {
            None
        }
        fn bls12_381_aggregate_g2(
            &self,
            _points: &[[u8; BLS12_381_G2_COMPRESSED_SIZE]],
        ) -> Option<[u8; BLS12_381_G2_COMPRESSED_SIZE]> {
            None
        }
        fn bn254_pairing_check(
            &self,
            _pairs: &[(
                [u8; BN254_G1_COMPRESSED_SIZE],
                [u8; BN254_G2_COMPRESSED_SIZE],
            )],
        ) -> bool {
            false
        }
        fn name(&self) -> &'static str {
            "dummy"
        }
    }

    #[test]
    fn test_crypto_provider_trait_object() {
        let provider: Box<dyn CryptoProvider> = Box::new(DummyProvider);
        assert_eq!(provider.name(), "dummy");
        assert_eq!(provider.sha256(b"test"), [0u8; 32]);
        assert!(!provider.ecdsa_verify_secp256k1(&[0u8; 32], &[0u8; 65], &[0u8; 33]));
        assert!(provider.bls12_381_g1_add(&[0u8; 48], &[0u8; 48]).is_none());
        assert!(!provider.bn254_pairing_check(&[]));
    }

    #[test]
    fn test_bls12_381_sizes() {
        assert_eq!(BLS12_381_G1_COMPRESSED_SIZE, 48);
        assert_eq!(BLS12_381_G2_COMPRESSED_SIZE, 96);
    }

    #[test]
    fn test_bn254_sizes() {
        assert_eq!(BN254_G1_COMPRESSED_SIZE, 32);
        assert_eq!(BN254_G2_COMPRESSED_SIZE, 64);
    }

    #[test]
    fn test_provider_collection() {
        // 验证多个 provider 可作为 trait object 共存于集合
        let providers: Vec<Box<dyn CryptoProvider>> =
            vec![Box::new(DummyProvider), Box::new(DummyProvider)];
        assert_eq!(providers.len(), 2);
        for p in &providers {
            assert_eq!(p.name(), "dummy");
        }
    }
}
