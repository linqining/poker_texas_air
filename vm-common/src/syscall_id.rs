//! 统一 SyscallId 枚举 — 跨 VM 的 syscall ID 单一事实源。
//!
//! # ID 空间分段
//!
//! | 段 | 用途 | 现有数量 |
//! |---|---|---|
//! | 0x01-0x0F | 原有 zkvm 15 个 syscall（保持现有值不变，向后兼容） | 15 |
//! | 0x10-0x3F | 链上链下共用扩展（新增共用 syscall 用此段） | 0（预留） |
//! | 0x40-0x7F | poker_l1 专属（object_*/get_block_height/verify_signature 等） | 8 |
//! | 0x80-0xFF | BLS12-381 系列（poker_l1 现有 12 个 bls12_381_*） | 12 |
//!
//! # 向后兼容策略
//!
//! **不强制改现有注册机制**：
//! - poker_zkvm 的 `SyscallId`（0x01-0x0F）保留原样使用
//! - poker_l1 的 syscall 通过 `declare_builtin_function!` 宏注册（不依赖枚举）
//! - vm-common 的 `SyscallId` 仅供**新加 syscall** 与 ABI 文档使用，**不破坏现有路由**

/// 统一 SyscallId 枚举 — 跨 VM 的 syscall ID 单一事实源。
///
/// `#[repr(u32)]` 确保 `as u32` 转换得到正确的 ID 值。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum SyscallId {
    // ===== 0x01-0x0F：原有 zkvm 15 个（值不变，向后兼容） =====
    /// `zkvm_read_input(ptr, len)` — 从 host input buffer 读取。
    ReadInput = 0x01,
    /// `zkvm_commit_output(ptr, len)` — 写入 host output buffer。
    CommitOutput = 0x02,
    /// `zkvm_poseidon(ptr, len, out_ptr)` — Poseidon 哈希。
    Poseidon = 0x03,
    /// `zkvm_sha256(ptr, len, out_ptr)` — SHA-256 哈希。
    Sha256 = 0x04,
    /// `zkvm_ecdsa_verify(msg_ptr, msg_len, sig_ptr, pubkey_ptr) -> bool` — ECDSA 验证。
    EcdsaVerify = 0x05,
    /// `zkvm_emit_event(ptr, len)` — 事件进 public_io（绑定 step_index）。
    EmitEvent = 0x06,
    /// `zkvm_log(ptr, len)` — 写入 host event log。
    Log = 0x07,
    /// `zkvm_panic(ptr, len)` — 终止执行。
    Panic = 0x08,
    /// `zkvm_get_randomness(out_ptr)` — 从 host seed 派生（deterministic）。
    GetRandomness = 0x09,
    /// `zkvm_read_state(slot, out_ptr)` — 仅允许白名单 slot。
    ReadState = 0x0A,
    /// `zkvm_keccak256(ptr, len, out_ptr)` — Keccak-256 哈希。
    Keccak256 = 0x0B,
    /// `zkvm_modexp(base_ptr, exp_ptr, mod_ptr, result_ptr, num_bits)` — 大数模幂。
    Modexp = 0x0C,
    /// `zkvm_merkle_verify(leaf, path, indices, root, depth)` — Merkle 路径验证。
    MerkleVerify = 0x0D,
    /// `zkvm_ed25519_verify(msg_ptr, msg_len, sig_ptr, pubkey_ptr) -> bool` — Ed25519 验签。
    Ed25519Verify = 0x0E,
    /// `zkvm_bn254_pairing(a_ptr, b_ptr, c_ptr, d_ptr) -> bool` — BN254 配对等式验证。
    Bn254Pairing = 0x0F,

    // ===== 0x40-0x5F：poker_l1 专属 =====
    /// `object_read(obj_id, key, out_ptr, out_len)` — 读取对象字段。
    ObjectRead = 0x40,
    /// `object_write(obj_id, key, value_ptr, value_len)` — 写入对象字段。
    ObjectWrite = 0x41,
    /// `object_create(type_tag, data_ptr, data_len)` — 创建新对象。
    ObjectCreate = 0x42,
    /// `get_block_height()` — 获取当前区块高度。
    GetBlockHeight = 0x43,
    /// `get_timestamp()` — 获取当前区块时间戳。
    GetTimestamp = 0x44,
    /// `verify_signature(msg_ptr, msg_len, sig_ptr, pubkey_ptr)` — 验证交易签名。
    VerifySignature = 0x45,
    /// `verify_failure_proof(...)` — 验证失败证明（SEC-H9）。
    VerifyFailureProof = 0x46,
    /// `zk_verify(scheme_id, proof_ptr, proof_len)` — ZK 证明验证（Stwo/Groth16/IPA）。
    ZkVerify = 0x47,

    // ===== 0x80-0x8F：BLS12-381 系列（poker_l1） =====
    /// `bls12_381_g1_add(a_ptr, b_ptr, out_ptr)` — G1 点加法。
    Bls12_381G1Add = 0x80,
    /// `bls12_381_g1_mul(p_ptr, s_ptr, out_ptr)` — G1 标量乘法。
    Bls12_381G1Mul = 0x81,
    /// `bls12_381_g1_neg(p_ptr, out_ptr)` — G1 点取负。
    Bls12_381G1Neg = 0x82,
    /// `bls12_381_g2_add(a_ptr, b_ptr, out_ptr)` — G2 点加法。
    Bls12_381G2Add = 0x83,
    /// `bls12_381_g2_mul(p_ptr, s_ptr, out_ptr)` — G2 标量乘法。
    Bls12_381G2Mul = 0x84,
    /// `bls12_381_g2_neg(p_ptr, out_ptr)` — G2 点取负。
    Bls12_381G2Neg = 0x85,
    /// `bls12_381_pairing_check(g1_arr, g2_arr, n)` — 配对检查。
    Bls12_381PairingCheck = 0x86,
    /// `bls12_381_miller_loop(g1_arr, g2_arr, n, out_ptr)` — Miller 循环。
    Bls12_381MillerLoop = 0x87,
    /// `bls12_381_final_exp(f_ptr, out_ptr)` — 最终指数运算。
    Bls12_381FinalExp = 0x88,
    /// `bls12_381_hash_to_g1(msg_ptr, msg_len, out_ptr)` — 哈希到 G1。
    Bls12_381HashToG1 = 0x89,
    /// `bls12_381_hash_to_g2(msg_ptr, msg_len, out_ptr)` — 哈希到 G2。
    Bls12_381HashToG2 = 0x8A,
    /// `bls12_381_aggregate(sig_ptrs, n, out_ptr)` — 聚合签名。
    Bls12_381Aggregate = 0x8B,
}

impl SyscallId {
    /// 从 `u32` 构造 [`SyscallId`]，非法 ID 返回 `None`。
    #[must_use]
    pub fn from_u32(id: u32) -> Option<Self> {
        match id {
            0x01 => Some(Self::ReadInput),
            0x02 => Some(Self::CommitOutput),
            0x03 => Some(Self::Poseidon),
            0x04 => Some(Self::Sha256),
            0x05 => Some(Self::EcdsaVerify),
            0x06 => Some(Self::EmitEvent),
            0x07 => Some(Self::Log),
            0x08 => Some(Self::Panic),
            0x09 => Some(Self::GetRandomness),
            0x0A => Some(Self::ReadState),
            0x0B => Some(Self::Keccak256),
            0x0C => Some(Self::Modexp),
            0x0D => Some(Self::MerkleVerify),
            0x0E => Some(Self::Ed25519Verify),
            0x0F => Some(Self::Bn254Pairing),
            0x40 => Some(Self::ObjectRead),
            0x41 => Some(Self::ObjectWrite),
            0x42 => Some(Self::ObjectCreate),
            0x43 => Some(Self::GetBlockHeight),
            0x44 => Some(Self::GetTimestamp),
            0x45 => Some(Self::VerifySignature),
            0x46 => Some(Self::VerifyFailureProof),
            0x47 => Some(Self::ZkVerify),
            0x80 => Some(Self::Bls12_381G1Add),
            0x81 => Some(Self::Bls12_381G1Mul),
            0x82 => Some(Self::Bls12_381G1Neg),
            0x83 => Some(Self::Bls12_381G2Add),
            0x84 => Some(Self::Bls12_381G2Mul),
            0x85 => Some(Self::Bls12_381G2Neg),
            0x86 => Some(Self::Bls12_381PairingCheck),
            0x87 => Some(Self::Bls12_381MillerLoop),
            0x88 => Some(Self::Bls12_381FinalExp),
            0x89 => Some(Self::Bls12_381HashToG1),
            0x8A => Some(Self::Bls12_381HashToG2),
            0x8B => Some(Self::Bls12_381Aggregate),
            _ => None,
        }
    }

    /// 返回 `u32` 形式的 syscall ID。
    #[must_use]
    pub fn as_u32(&self) -> u32 {
        *self as u32
    }

    /// 是否为 zkvm 专属 syscall（0x01-0x0F）。
    #[must_use]
    pub fn is_zkvm(&self) -> bool {
        matches!(self.as_u32(), 0x01..=0x0F)
    }

    /// 是否为 poker_l1 专属 syscall（0x40-0xFF）。
    #[must_use]
    pub fn is_poker_l1(&self) -> bool {
        matches!(self.as_u32(), 0x40..=0xFF)
    }

    /// 是否为链上链下共用扩展 syscall（0x10-0x3F，当前为空，预留段）。
    #[must_use]
    pub fn is_shared(&self) -> bool {
        matches!(self.as_u32(), 0x10..=0x3F)
    }

    /// 是否为 BLS12-381 系列 syscall（0x80-0xFF）。
    #[must_use]
    pub fn is_bls12_381(&self) -> bool {
        matches!(self.as_u32(), 0x80..=0xFF)
    }

    /// 返回全部 syscall ID（按枚举顺序）。
    #[must_use]
    pub fn all() -> [Self; 35] {
        [
            // zkvm 15 个
            Self::ReadInput,
            Self::CommitOutput,
            Self::Poseidon,
            Self::Sha256,
            Self::EcdsaVerify,
            Self::EmitEvent,
            Self::Log,
            Self::Panic,
            Self::GetRandomness,
            Self::ReadState,
            Self::Keccak256,
            Self::Modexp,
            Self::MerkleVerify,
            Self::Ed25519Verify,
            Self::Bn254Pairing,
            // poker_l1 8 个
            Self::ObjectRead,
            Self::ObjectWrite,
            Self::ObjectCreate,
            Self::GetBlockHeight,
            Self::GetTimestamp,
            Self::VerifySignature,
            Self::VerifyFailureProof,
            Self::ZkVerify,
            // BLS12-381 12 个
            Self::Bls12_381G1Add,
            Self::Bls12_381G1Mul,
            Self::Bls12_381G1Neg,
            Self::Bls12_381G2Add,
            Self::Bls12_381G2Mul,
            Self::Bls12_381G2Neg,
            Self::Bls12_381PairingCheck,
            Self::Bls12_381MillerLoop,
            Self::Bls12_381FinalExp,
            Self::Bls12_381HashToG1,
            Self::Bls12_381HashToG2,
            Self::Bls12_381Aggregate,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== from_u32 / as_u32 往返测试 =====

    #[test]
    fn test_from_u32_zkvm_range() {
        assert_eq!(SyscallId::from_u32(0x01), Some(SyscallId::ReadInput));
        assert_eq!(SyscallId::from_u32(0x0F), Some(SyscallId::Bn254Pairing));
        assert_eq!(SyscallId::from_u32(0x00), None);
        assert_eq!(SyscallId::from_u32(0x10), None); // 共用段当前空
        assert_eq!(SyscallId::from_u32(0x3F), None);
    }

    #[test]
    fn test_from_u32_poker_l1_range() {
        assert_eq!(SyscallId::from_u32(0x40), Some(SyscallId::ObjectRead));
        assert_eq!(SyscallId::from_u32(0x47), Some(SyscallId::ZkVerify));
        assert_eq!(SyscallId::from_u32(0x48), None);
        assert_eq!(SyscallId::from_u32(0x7F), None);
    }

    #[test]
    fn test_from_u32_bls_range() {
        assert_eq!(SyscallId::from_u32(0x80), Some(SyscallId::Bls12_381G1Add));
        assert_eq!(
            SyscallId::from_u32(0x8B),
            Some(SyscallId::Bls12_381Aggregate)
        );
        assert_eq!(SyscallId::from_u32(0x8C), None);
        assert_eq!(SyscallId::from_u32(0xFF), None);
    }

    #[test]
    fn test_as_u32_roundtrip() {
        for id in SyscallId::all() {
            let u = id.as_u32();
            assert_eq!(
                SyscallId::from_u32(u),
                Some(id),
                "往返失败: {id:?} -> 0x{u:02X}"
            );
        }
    }

    // ===== 分段判断测试 =====

    #[test]
    fn test_is_zkvm() {
        assert!(SyscallId::ReadInput.is_zkvm());
        assert!(SyscallId::Bn254Pairing.is_zkvm());
        assert!(!SyscallId::ObjectRead.is_zkvm());
        assert!(!SyscallId::Bls12_381G1Add.is_zkvm());
    }

    #[test]
    fn test_is_poker_l1() {
        assert!(SyscallId::ObjectRead.is_poker_l1());
        assert!(SyscallId::ZkVerify.is_poker_l1());
        assert!(SyscallId::Bls12_381G1Add.is_poker_l1());
        assert!(!SyscallId::ReadInput.is_poker_l1());
    }

    #[test]
    fn test_is_shared() {
        // 共用段当前为空，所有现有 syscall 都不应匹配
        for id in SyscallId::all() {
            assert!(!id.is_shared(), "{id:?} 不应在 shared 段");
        }
    }

    #[test]
    fn test_is_bls12_381() {
        assert!(SyscallId::Bls12_381G1Add.is_bls12_381());
        assert!(SyscallId::Bls12_381Aggregate.is_bls12_381());
        assert!(!SyscallId::ObjectRead.is_bls12_381());
        assert!(!SyscallId::ReadInput.is_bls12_381());
    }

    // ===== all() 数量测试 =====

    #[test]
    fn test_all_count() {
        // 15 zkvm + 8 poker_l1 + 12 BLS = 35
        assert_eq!(SyscallId::all().len(), 35);
    }

    #[test]
    fn test_all_unique() {
        let all = SyscallId::all();
        let mut seen = std::collections::HashSet::new();
        for id in all {
            assert!(seen.insert(id.as_u32()), "重复 ID: 0x{:02X}", id.as_u32());
        }
    }

    // ===== 值稳定性测试（向后兼容） =====

    #[test]
    fn test_zkvm_values_unchanged() {
        // zkvm 现有值必须保持不变（向后兼容）
        assert_eq!(SyscallId::ReadInput as u32, 0x01);
        assert_eq!(SyscallId::CommitOutput as u32, 0x02);
        assert_eq!(SyscallId::Poseidon as u32, 0x03);
        assert_eq!(SyscallId::Sha256 as u32, 0x04);
        assert_eq!(SyscallId::EcdsaVerify as u32, 0x05);
        assert_eq!(SyscallId::EmitEvent as u32, 0x06);
        assert_eq!(SyscallId::Log as u32, 0x07);
        assert_eq!(SyscallId::Panic as u32, 0x08);
        assert_eq!(SyscallId::GetRandomness as u32, 0x09);
        assert_eq!(SyscallId::ReadState as u32, 0x0A);
        assert_eq!(SyscallId::Keccak256 as u32, 0x0B);
        assert_eq!(SyscallId::Modexp as u32, 0x0C);
        assert_eq!(SyscallId::MerkleVerify as u32, 0x0D);
        assert_eq!(SyscallId::Ed25519Verify as u32, 0x0E);
        assert_eq!(SyscallId::Bn254Pairing as u32, 0x0F);
    }
}
