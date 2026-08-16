//! Gas 计费表（Task 14 — SubTask 14.3）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **M8 修复 + NEW-M16 修复 + R3-M3 修正**：
//!   - BPF 算术指令 = 1 gas
//!   - 内存指令 = 3 gas（IMPL-SEC-4：(2) 改为 `3 + 2 * bytes_accessed`）
//!   - 分支指令 = 2 gas
//! - **syscall 计费**（常量定义已迁至 `vm_common::gas`，本模块通过 re-export 复用）：
//!   - `object_read` = 10 + 1 * bytes_returned
//!   - `object_write` = 20 + 1 * data_len_bytes
//!   - `object_create` = 20 + 1 * data_len_bytes
//!   - `emit_event` = 10 + 1 * payload_len_bytes（payload ≤ 16KB）
//!   - `secp256k1_verify` = 500（R3-M3 修正）
//!   - `bls12_381_g1_mul` = 500
//!   - `bls12_381_pairing_check` = 5000
//!   - `stwo_verify` = 300000（历史名 hypernova_verify，已废弃）
//!   - `groth16_verify` = 20000
//!   - `ipa_verify` = 15000
//!   - `verify_failure_proof` = 80000（SEC-H9 修复）
//! - **block gas limit** = 50,000,000
//! - **tx gas limit** = 10,000,000
//! - **IMPL-SEC-4 修复**：
//!   - (5) 指令执行前扣费，余额不足立即 trap
//!   - (7) 单个 Object ≤ 64KB
//!   - gas 计费仅适用 Public 通道 tx 与合约调用
//!   - GameTurn 通道游戏操作 tx 免 gas
//!
//! # Phase 1 迁移说明
//!
//! 跨 VM 共享的 syscall 级 gas 常量、size limits、gas limits 与纯函数
//! 已迁至 `vm_common::gas`，本模块通过 `pub use vm_common::gas::*;` re-export
//! 保持外部 API 完全兼容。仅 BPF 指令级常量与依赖 `PokerL1Error` 的函数保留本地。

// ===== 跨 VM 共享 gas 常量与函数（单一事实源：vm_common::gas）=====
pub use vm_common::gas::*;

// ===== BPF 指令级 gas（ISA 专有，保留本地）=====

/// BPF 算术指令 gas（M8）。
pub const GAS_ARITHMETIC: u64 = 1;
/// BPF 内存指令基础 gas（M8）。IMPL-SEC-4：(2) 实际为 `3 + 2 * bytes`。
pub const GAS_MEMORY_BASE: u64 = 3;
/// BPF 内存指令每字节附加 gas（IMPL-SEC-4：(2)）。
pub const GAS_MEMORY_PER_BYTE: u64 = 2;
/// BPF 分支指令 gas（M8）。
pub const GAS_BRANCH: u64 = 2;

// ===== BPF 专有纯函数 =====

/// 计算内存指令的 gas（IMPL-SEC-4：(2)）。
///
/// `3 + 2 * bytes_accessed`。
#[must_use]
pub const fn memory_gas(bytes_accessed: u64) -> u64 {
    GAS_MEMORY_BASE + GAS_MEMORY_PER_BYTE * bytes_accessed
}

/// 检查 BLS hash_to_curve 消息长度是否超限（spec：msg ≤ 65536 字节）。
///
/// M-8 修复：参数改为 `u64`，避免 32-bit 平台 `u64 as usize` 截断绕过上限检查。
/// 安全比较在 u64 域完成；`actual` 字段仅用于错误显示，截断不影响安全性。
pub const fn check_bls_hash_msg_len(msg_len: u64) -> crate::error::PokerL1Result<()> {
    if msg_len > MAX_BLS_HASH_MSG_SIZE as u64 {
        return Err(crate::error::PokerL1Error::InputTooLong {
            actual: msg_len as usize,
            limit: MAX_BLS_HASH_MSG_SIZE,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_gas_constants() {
        // BPF 指令级 gas 常量保留在 poker_l1 本地
        assert_eq!(GAS_ARITHMETIC, 1);
        assert_eq!(GAS_MEMORY_BASE, 3);
        assert_eq!(GAS_MEMORY_PER_BYTE, 2);
        assert_eq!(GAS_BRANCH, 2);
    }

    #[test]
    fn test_memory_gas() {
        assert_eq!(memory_gas(0), 3);
        assert_eq!(memory_gas(8), 3 + 16);
        assert_eq!(memory_gas(1024), 3 + 2048);
    }

    #[test]
    fn test_check_bls_hash_msg_len() {
        // 边界值：65536 应通过，65537 应失败
        assert!(check_bls_hash_msg_len(0).is_ok());
        assert!(check_bls_hash_msg_len(65_536).is_ok());
        assert!(check_bls_hash_msg_len(65_537).is_err());
    }

    // ===== 以下测试验证 re-export 自 vm_common 的常量与函数可正常访问 =====
    // （常量值本身的完整性测试已在 vm-common/src/gas.rs 中覆盖）

    #[test]
    fn test_reexported_gas_constants_accessible() {
        // 验证 re-export 的常量可访问且值正确
        assert_eq!(GAS_OBJECT_READ_BASE, 10);
        assert_eq!(GAS_SECP256K1_VERIFY, 500);
        assert_eq!(GAS_BLS_PAIRING, 5000);
        assert_eq!(GAS_STWO_VERIFY, 300_000);
        assert_eq!(GAS_GROTH16_VERIFY, 20000);
        assert_eq!(GAS_IPA_VERIFY, 15000);
        assert_eq!(GAS_ZK_VERIFY, 300_000);
        assert_eq!(GAS_VERIFY_FAILURE_PROOF, 80000);
        assert_eq!(BLOCK_GAS_LIMIT, 50_000_000);
        assert_eq!(TX_GAS_LIMIT, 10_000_000);
    }

    #[test]
    fn test_reexported_zkvm_gas_constants_accessible() {
        // 验证原 re-export 自 poker_zkvm 的常量现通过 vm_common 可访问
        assert_eq!(GAS_ZKVM_POSEIDON_BASE, 100);
        assert_eq!(GAS_ZKVM_POSEIDON_PER_BLOCK, 50);
        assert_eq!(GAS_ZKVM_SHA256_PER_BYTE, 1);
        assert_eq!(GAS_ZKVM_ECDSA_VERIFY, 100_000);
        assert_eq!(GAS_ZKVM_READ_STATE_PER_SLOT, 50);
    }

    #[test]
    fn test_reexported_size_limits_accessible() {
        assert_eq!(MAX_OBJECT_SIZE, 64 * 1024);
        assert_eq!(MAX_EVENT_PAYLOAD_SIZE, 16 * 1024);
        assert_eq!(MAX_HEAP_SIZE, 1024 * 1024);
        assert_eq!(MAX_STACK_SIZE, 64 * 1024);
    }

    #[test]
    fn test_reexported_functions_accessible() {
        assert_eq!(object_read_gas(100), 110);
        assert_eq!(object_write_gas(100), 120);
        assert_eq!(object_create_gas(100), 120);
        assert_eq!(emit_event_gas(100), 110);
        assert_eq!(bls_hash_to_g1_gas(32), 1000 + 320);
        assert_eq!(bls_hash_to_g2_gas(32), 1000 + 320);
        assert_eq!(zk_verify_gas(1), GAS_STWO_VERIFY); // Stwo（历史名 Hypernova）
        assert_eq!(zk_verify_gas(2), GAS_GROTH16_VERIFY);
        assert_eq!(zk_verify_gas(3), GAS_IPA_VERIFY);
    }
}
