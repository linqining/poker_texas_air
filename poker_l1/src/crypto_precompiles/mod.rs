//! BLS12-381 原生预编译模块（Phase 4 — Task 18 / 19 / 20）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **Task 18**：BLS12-381 G1/G2/pairing/hash_to_curve 操作（含子群检查）
//! - **Task 19**：预编译作为 VM syscall 注册
//! - **Task 20**：节点级 native API（`secp256k1_aggregate_verify` + `bls_verify`）
//!
//! # 安全说明
//!
//! 所有 G1/G2 输入通过 compressed bytes 反序列化，`from_compressed` 内部执行
//! 完整的点解码 + 子群成员检查。非子群元素在 pairing 之前被拒绝（DoS 防护）。
//! SEC2-L2 修复：hash_to_curve DST 固定，runtime 自动附加，不允许合约自定义。

pub mod bls;
pub mod native_api;

pub use bls::{
    BLS_G1_DST, BLS_G2_DST, G1_COMPRESSED_SIZE, G2_COMPRESSED_SIZE, GT_COMPRESSED_SIZE,
    SCALAR_SIZE, bls_final_exp, bls_g1_add, bls_g1_mul, bls_g1_neg, bls_g2_add, bls_g2_mul,
    bls_g2_neg, bls_hash_to_g1, bls_hash_to_g2, bls_miller_loop, bls_pairing_check,
};
