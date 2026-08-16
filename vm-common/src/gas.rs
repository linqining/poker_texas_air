//! Gas 计费常量与纯函数 — 跨 VM 单一事实源（Phase 1 迁移）。
//!
//! # 迁移来源
//!
//! - `poker_l1/src/vm/gas_table.rs` 的 syscall 级常量（非 BPF 专有）
//! - `poker_zkvm/src/syscalls/gas.rs` 的 syscall 级常量（非 RV32I 专有）
//! - 两 crate 共享的 size limits 与 gas limits
//!
//! # 保留在各 crate 本地的 ISA 专有常量
//!
//! - `poker_l1`：`GAS_ARITHMETIC`、`GAS_MEMORY_BASE`、`GAS_MEMORY_PER_BYTE`、`GAS_BRANCH`（BPF 指令级）
//! - `poker_zkvm`：`GAS_INSN_*` 系列（RV32I 指令级）、`SyscallGasArgs`、`syscall_gas()`、`instruction_gas()`、`total_step_gas()`
//!
//! # 严格遵循 spec.md（FROZEN 2026-06-27）
//!
//! - **M8 修复 + NEW-M16 修复 + R3-M3 修正**：
//!   - BPF 算术指令 = 1 gas（保留在 poker_l1）
//!   - 内存指令 = 3 gas（保留在 poker_l1）
//!   - 分支指令 = 2 gas（保留在 poker_l1）
//! - **syscall 计费**（本文件）：
//!   - `object_read` = 10 + 1 * bytes_returned
//!   - `object_write` = 20 + 1 * data_len_bytes
//!   - `object_create` = 20 + 1 * data_len_bytes
//!   - `emit_event` = 10 + 1 * payload_len_bytes（payload ≤ 16KB）
//!   - `secp256k1_verify` = 500（R3-M3 修正）
//!   - `bls12_381_g1_mul` = 500
//!   - `bls12_381_pairing_check` = 5000
//!   - `stwo_verify` = 300000（历史名 `hypernova_verify`，Hypernova 已废弃）
//!   - `groth16_verify` = 20000
//!   - `ipa_verify` = 15000
//!   - `verify_failure_proof` = 80000（SEC-H9 修复）
//! - **block gas limit** = 50,000,000
//! - **tx gas limit** = 10,000,000

// ===========================================================================
// poker_l1 syscall 固定基础 cost
// ===========================================================================

/// `object_read` 基础 gas（IMPL-SEC-4：(6)）。
pub const GAS_OBJECT_READ_BASE: u64 = 10;
/// `object_read` 每字节返回数据 gas（IMPL-SEC-4：(6)）。
pub const GAS_OBJECT_READ_PER_BYTE: u64 = 1;
/// `object_write` 基础 gas（IMPL-SEC-4：(6)）。
pub const GAS_OBJECT_WRITE_BASE: u64 = 20;
/// `object_write` 每字节数据 gas（IMPL-SEC-4：(6)）。
pub const GAS_OBJECT_WRITE_PER_BYTE: u64 = 1;
/// `object_create` 基础 gas（IMPL-SEC-4：(6)）。
pub const GAS_OBJECT_CREATE_BASE: u64 = 20;
/// `object_create` 每字节数据 gas（IMPL-SEC-4：(6)）。
pub const GAS_OBJECT_CREATE_PER_BYTE: u64 = 1;
/// `emit_event` 基础 gas（IMPL-SEC-4：(6)）。
pub const GAS_EMIT_EVENT_BASE: u64 = 10;
/// `emit_event` 每字节 payload gas（IMPL-SEC-4：(6)）。
pub const GAS_EMIT_EVENT_PER_BYTE: u64 = 1;
/// `log` syscall gas。
pub const GAS_LOG: u64 = 10;
/// `panic` syscall gas。
pub const GAS_PANIC: u64 = 10;
/// `get_block_height` syscall gas。
pub const GAS_GET_BLOCK_HEIGHT: u64 = 1;
/// `get_timestamp` syscall gas。
pub const GAS_GET_TIMESTAMP: u64 = 1;

// ===========================================================================
// 密码学 syscall gas（R3-M3 / SEC-H9）
// ===========================================================================

/// `secp256k1_verify` gas（R3-M3 修正 — 用于 tx/vertex/receipt/operator_ack/ACK 签名验证）。
pub const GAS_SECP256K1_VERIFY: u64 = 500;
/// `bls12_381_g1_mul` gas（含子群检查）。
pub const GAS_BLS_G1_MUL: u64 = 500;
/// `bls12_381_g1_add` gas（含子群检查，与 g1_mul 同价）。
pub const GAS_BLS_G1_ADD: u64 = 500;
/// `bls12_381_g1_neg` gas（含子群检查，与 g1_mul 同价）。
pub const GAS_BLS_G1_NEG: u64 = 500;
/// `bls12_381_g2_mul` gas（含子群检查）。
pub const GAS_BLS_G2_MUL: u64 = 500;
/// `bls12_381_g2_add` gas（含子群检查）。
pub const GAS_BLS_G2_ADD: u64 = 500;
/// `bls12_381_g2_neg` gas（含子群检查）。
pub const GAS_BLS_G2_NEG: u64 = 500;
/// `bls12_381_pairing_check` gas（4 输入子群检查 + worst-case）。
pub const GAS_BLS_PAIRING: u64 = 5000;
/// `bls12_381_miller_loop` gas（worst-case；pairing = 2×miller + 1×final_exp = 5000）。
pub const GAS_BLS_MILLER_LOOP: u64 = 2000;
/// `bls12_381_final_exp` gas（worst-case）。
pub const GAS_BLS_FINAL_EXP: u64 = 1000;
/// `bls12_381_hash_to_g1` 基础 gas。
pub const GAS_BLS_HASH_TO_G1_BASE: u64 = 1000;
/// `bls12_381_hash_to_g1` 每字节 gas。
pub const GAS_BLS_HASH_TO_G1_PER_BYTE: u64 = 10;
/// `bls12_381_hash_to_g2` 基础 gas。
pub const GAS_BLS_HASH_TO_G2_BASE: u64 = 1000;
/// `bls12_381_hash_to_g2` 每字节 gas。
pub const GAS_BLS_HASH_TO_G2_PER_BYTE: u64 = 10;
/// `stwo_verify` gas（Stwo Circle-STARK 证明验证；历史名 `hypernova_verify`，Hypernova 方案已废弃，现统一为 Stwo）。
pub const GAS_STWO_VERIFY: u64 = 300_000;
/// `groth16_verify` gas。
pub const GAS_GROTH16_VERIFY: u64 = 20000;
/// `ipa_verify` gas。
pub const GAS_IPA_VERIFY: u64 = 15000;
/// `zk_verify` syscall 默认 gas（用于未知 scheme_id 时的 fallback 计费）。
///
/// 实际计费通过 [`zk_verify_gas`] 按 scheme 分派：
/// - Stwo（scheme_id=1，历史名 Hypernova）→ [`GAS_STWO_VERIFY`] = 300000
/// - Groth16 → [`GAS_GROTH16_VERIFY`] = 20000
/// - IPA → [`GAS_IPA_VERIFY`] = 15000
pub const GAS_ZK_VERIFY: u64 = 300_000;
/// `verify_failure_proof` gas（SEC-H9 修复 — 256-bit sparse Merkle 非包含证明 + 多签验证）。
///
/// 256 层路径 × ~200 gas ≈ 51200 + 3×secp256k1_verify(500) + round 校验 ~1500 + 3×500 ≈ 55700，
/// 预留 30% 安全边际上取整至 80000。
pub const GAS_VERIFY_FAILURE_PROOF: u64 = 80000;

/// Generic native precompile dispatch base cost.
///
/// Precompiles may remain caller-fee-free, but they must still consume deterministic
/// block resources so malformed requests cannot trigger unbounded host-native work.
pub const GAS_PRECOMPILE_BASE: u64 = 1_000;
/// Generic native precompile dispatch cost per argument byte.
pub const GAS_PRECOMPILE_PER_BYTE: u64 = 2;
/// Minimum resource cost recorded for a transaction that passed admission but failed execution.
pub const GAS_FAILED_TX_BASE: u64 = 1_000;

/// Deterministic fallback cost for a native precompile call.
#[must_use]
pub const fn precompile_gas(args_len: u64) -> u64 {
    GAS_PRECOMPILE_BASE.saturating_add(GAS_PRECOMPILE_PER_BYTE.saturating_mul(args_len))
}

// ===========================================================================
// poker_zkvm syscall gas（Phase 11.5 — 原 re-export 自 poker_zkvm，现统一到 vm-common）
// ===========================================================================

/// `read_input` 基础 gas。
pub const GAS_ZKVM_READ_INPUT_BASE: u64 = 10;

/// `commit_output` 基础 gas。
pub const GAS_ZKVM_COMMIT_OUTPUT_BASE: u64 = 10;

/// `poseidon` 基础 gas（spec L646）。
pub const GAS_ZKVM_POSEIDON_BASE: u64 = 100;

/// `poseidon` 每 32-byte block 的 gas（spec L646）。
pub const GAS_ZKVM_POSEIDON_PER_BLOCK: u64 = 50;

/// `sha256` 每字节 gas（spec L653）。
pub const GAS_ZKVM_SHA256_PER_BYTE: u64 = 1;

/// `ecdsa_verify` 固定 gas（spec L660，与既有 `GAS_SECP256K1_VERIFY` 对齐）。
pub const GAS_ZKVM_ECDSA_VERIFY: u64 = 100_000;

/// `emit_event` 基础 gas。
pub const GAS_ZKVM_EMIT_EVENT_BASE: u64 = 10;

/// `emit_event` 每字节 gas。
pub const GAS_ZKVM_EMIT_EVENT_PER_BYTE: u64 = 1;

/// `log` 基础 gas。
pub const GAS_ZKVM_LOG_BASE: u64 = 10;

/// `log` 每字节 gas。
pub const GAS_ZKVM_LOG_PER_BYTE: u64 = 1;

/// `panic` 固定 gas。
pub const GAS_ZKVM_PANIC: u64 = 10;

/// `get_randomness` 固定 gas。
pub const GAS_ZKVM_GET_RANDOMNESS: u64 = 100;

/// `read_state` 每 slot 的 gas（spec L669）。
pub const GAS_ZKVM_READ_STATE_PER_SLOT: u64 = 50;

/// `keccak256` 每字节 gas（absorb 阶段）。
pub const GAS_ZKVM_KECCAK256_PER_BYTE: u64 = 2;

/// `keccak256` 每轮 gas（Keccak-f\[1600\] 置换，24 轮）。
pub const GAS_ZKVM_KECCAK256_PER_ROUND: u64 = 10_000;

/// `modexp` 基础 gas。
pub const GAS_ZKVM_MODEXP_BASE: u64 = 50_000;

/// `modexp` 每指数位 gas。
pub const GAS_ZKVM_MODEXP_PER_BIT: u64 = 600;

/// `merkle_verify` 每层路径 gas。
pub const GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL: u64 = 100;

/// `ed25519_verify` 基础 gas。
pub const GAS_ZKVM_ED25519_BASE: u64 = 50_000;

/// `ed25519_verify` 每标量位 gas。
pub const GAS_ZKVM_ED25519_PER_BIT: u64 = 8_000;

/// `bn254_pairing` MVP gas（单 G1 检查）。
pub const GAS_ZKVM_BN254_PAIRING_MVP: u64 = 30_000;

/// `bn254_pairing` Full gas（双 G1 + hint）。
pub const GAS_ZKVM_BN254_PAIRING_FULL: u64 = 80_000;

// ===========================================================================
// gas limits
// ===========================================================================

/// block gas limit = 50M（M8）。
pub const BLOCK_GAS_LIMIT: u64 = 50_000_000;
/// tx gas limit = 10M（M8）。
pub const TX_GAS_LIMIT: u64 = 10_000_000;

// ===========================================================================
// 大小限制（IMPL-SEC-4）
// ===========================================================================

/// 单个 Object 序列化后最大字节数（IMPL-SEC-4：(7)，64KB）。
pub const MAX_OBJECT_SIZE: usize = 64 * 1024;
/// `emit_event` payload 最大字节数（IMPL-SEC-4：(6)，16KB）。
pub const MAX_EVENT_PAYLOAD_SIZE: usize = 16 * 1024;
/// 合约 heap 最大字节数（IMPL-SEC-4：(3)，1MB）。
pub const MAX_HEAP_SIZE: usize = 1024 * 1024;
/// 合约栈最大字节数（IMPL-SEC-4：(3)，64KB）。
pub const MAX_STACK_SIZE: usize = 64 * 1024;
/// BPF 输入数据最大字节数。
pub const MAX_INPUT_SIZE: usize = 64 * 1024;
/// BLS12-381 hash_to_curve 消息最大字节数（spec：65536）。
pub const MAX_BLS_HASH_MSG_SIZE: usize = 65_536;

// ===========================================================================
// 纯函数（gas 计算）
// ===========================================================================

/// 计算 `object_read` syscall 的 gas。
///
/// IMPL-SEC-4：(6) `object_read` gas = `10 + 1 * bytes_returned`。
#[must_use]
pub const fn object_read_gas(bytes_returned: u64) -> u64 {
    GAS_OBJECT_READ_BASE + GAS_OBJECT_READ_PER_BYTE * bytes_returned
}

/// 计算 `object_write` syscall 的 gas。
///
/// IMPL-SEC-4：(6) `object_write` gas = `20 + 1 * data_len_bytes`。
#[must_use]
pub const fn object_write_gas(data_len: u64) -> u64 {
    GAS_OBJECT_WRITE_BASE + GAS_OBJECT_WRITE_PER_BYTE * data_len
}

/// 计算 `object_create` syscall 的 gas。
///
/// IMPL-SEC-4：(6) `object_create` gas = `20 + 1 * data_len_bytes`。
#[must_use]
pub const fn object_create_gas(data_len: u64) -> u64 {
    GAS_OBJECT_CREATE_BASE + GAS_OBJECT_CREATE_PER_BYTE * data_len
}

/// 计算 `emit_event` syscall 的 gas。
///
/// IMPL-SEC-4：(6) `emit_event` gas = `10 + 1 * payload_len_bytes`。
#[must_use]
pub const fn emit_event_gas(payload_len: u64) -> u64 {
    GAS_EMIT_EVENT_BASE + GAS_EMIT_EVENT_PER_BYTE * payload_len
}

/// 计算 `bls12_381_hash_to_g1` gas（按字节线性计费）。
#[must_use]
pub const fn bls_hash_to_g1_gas(msg_len: u64) -> u64 {
    GAS_BLS_HASH_TO_G1_BASE + GAS_BLS_HASH_TO_G1_PER_BYTE * msg_len
}

/// 计算 `bls12_381_hash_to_g2` gas（按字节线性计费）。
#[must_use]
pub const fn bls_hash_to_g2_gas(msg_len: u64) -> u64 {
    GAS_BLS_HASH_TO_G2_BASE + GAS_BLS_HASH_TO_G2_PER_BYTE * msg_len
}

/// 计算 `zk_verify` syscall 的 gas（按 scheme_id 分派，Task 22.2）。
///
/// - `SCHEME_STWO` (1，历史名 Hypernova) → [`GAS_STWO_VERIFY`] = 300000
/// - `SCHEME_GROTH16` (2) → [`GAS_GROTH16_VERIFY`] = 20000
/// - `SCHEME_IPA` (3) → [`GAS_IPA_VERIFY`] = 15000
/// - 未知 scheme → [`GAS_ZK_VERIFY`] = 300000（fallback，实际会在 verifier 查找阶段失败）
#[must_use]
pub const fn zk_verify_gas(scheme_id: u32) -> u64 {
    match scheme_id {
        1 => GAS_STWO_VERIFY,
        2 => GAS_GROTH16_VERIFY,
        3 => GAS_IPA_VERIFY,
        _ => GAS_ZK_VERIFY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== 常量值测试（确保迁移后值不变） =====

    #[test]
    fn test_poker_l1_gas_constants() {
        assert_eq!(GAS_OBJECT_READ_BASE, 10);
        assert_eq!(GAS_OBJECT_READ_PER_BYTE, 1);
        assert_eq!(GAS_OBJECT_WRITE_BASE, 20);
        assert_eq!(GAS_OBJECT_WRITE_PER_BYTE, 1);
        assert_eq!(GAS_OBJECT_CREATE_BASE, 20);
        assert_eq!(GAS_OBJECT_CREATE_PER_BYTE, 1);
        assert_eq!(GAS_EMIT_EVENT_BASE, 10);
        assert_eq!(GAS_EMIT_EVENT_PER_BYTE, 1);
        assert_eq!(GAS_LOG, 10);
        assert_eq!(GAS_PANIC, 10);
        assert_eq!(GAS_GET_BLOCK_HEIGHT, 1);
        assert_eq!(GAS_GET_TIMESTAMP, 1);
    }

    #[test]
    fn test_crypto_gas_constants() {
        assert_eq!(GAS_SECP256K1_VERIFY, 500);
        assert_eq!(GAS_BLS_G1_MUL, 500);
        assert_eq!(GAS_BLS_G1_ADD, 500);
        assert_eq!(GAS_BLS_G1_NEG, 500);
        assert_eq!(GAS_BLS_G2_MUL, 500);
        assert_eq!(GAS_BLS_G2_ADD, 500);
        assert_eq!(GAS_BLS_G2_NEG, 500);
        assert_eq!(GAS_BLS_PAIRING, 5000);
        assert_eq!(GAS_BLS_MILLER_LOOP, 2000);
        assert_eq!(GAS_BLS_FINAL_EXP, 1000);
        assert_eq!(GAS_BLS_HASH_TO_G1_BASE, 1000);
        assert_eq!(GAS_BLS_HASH_TO_G1_PER_BYTE, 10);
        assert_eq!(GAS_BLS_HASH_TO_G2_BASE, 1000);
        assert_eq!(GAS_BLS_HASH_TO_G2_PER_BYTE, 10);
    }

    #[test]
    fn test_zk_verify_gas_constants() {
        assert_eq!(GAS_STWO_VERIFY, 300_000);
        assert_eq!(GAS_GROTH16_VERIFY, 20000);
        assert_eq!(GAS_IPA_VERIFY, 15000);
        assert_eq!(GAS_ZK_VERIFY, 300_000);
        assert_eq!(GAS_VERIFY_FAILURE_PROOF, 80000);
    }

    #[test]
    fn test_zkvm_gas_constants() {
        assert_eq!(GAS_ZKVM_READ_INPUT_BASE, 10);
        assert_eq!(GAS_ZKVM_COMMIT_OUTPUT_BASE, 10);
        assert_eq!(GAS_ZKVM_POSEIDON_BASE, 100);
        assert_eq!(GAS_ZKVM_POSEIDON_PER_BLOCK, 50);
        assert_eq!(GAS_ZKVM_SHA256_PER_BYTE, 1);
        assert_eq!(GAS_ZKVM_ECDSA_VERIFY, 100_000);
        assert_eq!(GAS_ZKVM_EMIT_EVENT_BASE, 10);
        assert_eq!(GAS_ZKVM_EMIT_EVENT_PER_BYTE, 1);
        assert_eq!(GAS_ZKVM_LOG_BASE, 10);
        assert_eq!(GAS_ZKVM_LOG_PER_BYTE, 1);
        assert_eq!(GAS_ZKVM_PANIC, 10);
        assert_eq!(GAS_ZKVM_GET_RANDOMNESS, 100);
        assert_eq!(GAS_ZKVM_READ_STATE_PER_SLOT, 50);
        assert_eq!(GAS_ZKVM_KECCAK256_PER_BYTE, 2);
        assert_eq!(GAS_ZKVM_KECCAK256_PER_ROUND, 10_000);
        assert_eq!(GAS_ZKVM_MODEXP_BASE, 50_000);
        assert_eq!(GAS_ZKVM_MODEXP_PER_BIT, 600);
        assert_eq!(GAS_ZKVM_MERKLE_VERIFY_PER_LEVEL, 100);
        assert_eq!(GAS_ZKVM_ED25519_BASE, 50_000);
        assert_eq!(GAS_ZKVM_ED25519_PER_BIT, 8_000);
        assert_eq!(GAS_ZKVM_BN254_PAIRING_MVP, 30_000);
        assert_eq!(GAS_ZKVM_BN254_PAIRING_FULL, 80_000);
    }

    #[test]
    fn test_gas_limits() {
        assert_eq!(BLOCK_GAS_LIMIT, 50_000_000);
        assert_eq!(TX_GAS_LIMIT, 10_000_000);
    }

    #[test]
    fn test_size_limits() {
        assert_eq!(MAX_OBJECT_SIZE, 64 * 1024);
        assert_eq!(MAX_EVENT_PAYLOAD_SIZE, 16 * 1024);
        assert_eq!(MAX_HEAP_SIZE, 1024 * 1024);
        assert_eq!(MAX_STACK_SIZE, 64 * 1024);
        assert_eq!(MAX_INPUT_SIZE, 64 * 1024);
        assert_eq!(MAX_BLS_HASH_MSG_SIZE, 65_536);
    }

    // ===== 纯函数测试 =====

    #[test]
    fn test_object_read_gas() {
        assert_eq!(object_read_gas(0), 10);
        assert_eq!(object_read_gas(100), 110);
        assert_eq!(object_read_gas(1024), 1034);
    }

    #[test]
    fn test_object_write_gas() {
        assert_eq!(object_write_gas(0), 20);
        assert_eq!(object_write_gas(100), 120);
        assert_eq!(object_write_gas(4096), 4116);
    }

    #[test]
    fn test_object_create_gas() {
        assert_eq!(object_create_gas(0), 20);
        assert_eq!(object_create_gas(100), 120);
    }

    #[test]
    fn test_emit_event_gas() {
        assert_eq!(emit_event_gas(0), 10);
        assert_eq!(emit_event_gas(100), 110);
        assert_eq!(emit_event_gas(MAX_EVENT_PAYLOAD_SIZE as u64), 10 + 16384);
    }

    #[test]
    fn test_bls_hash_gas() {
        assert_eq!(bls_hash_to_g1_gas(0), 1000);
        assert_eq!(bls_hash_to_g1_gas(32), 1000 + 320);
        assert_eq!(bls_hash_to_g2_gas(0), 1000);
        assert_eq!(bls_hash_to_g2_gas(65536), 1000 + 655360);
    }

    #[test]
    fn test_zk_verify_gas_dispatch() {
        assert_eq!(zk_verify_gas(1), GAS_STWO_VERIFY); // Stwo（历史名 Hypernova）
        assert_eq!(zk_verify_gas(2), GAS_GROTH16_VERIFY); // Groth16
        assert_eq!(zk_verify_gas(3), GAS_IPA_VERIFY); // IPA
        // 未知 scheme → fallback GAS_ZK_VERIFY
        assert_eq!(zk_verify_gas(0), GAS_ZK_VERIFY);
        assert_eq!(zk_verify_gas(99), GAS_ZK_VERIFY);
    }

    #[test]
    fn test_verify_failure_proof_gas_sec_h9() {
        // SEC-H9 修复：80000 gas
        // 验证：256 层 × 200 = 51200 + 3×500 + 1500 + 3×500 = 55700
        // 预留 30% 安全边际 ≈ 72410，上取整至 80000
        assert_eq!(GAS_VERIFY_FAILURE_PROOF, 80000);
        let base_cost = 256 * 200 + 3 * GAS_SECP256K1_VERIFY + 1500 + 3 * GAS_SECP256K1_VERIFY;
        assert_eq!(base_cost, 55700);
        assert!(GAS_VERIFY_FAILURE_PROOF > base_cost);
        assert!(GAS_VERIFY_FAILURE_PROOF >= (base_cost as f64 * 1.3) as u64);
    }
}
