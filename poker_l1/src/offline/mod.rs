//! 链下执行 + ZK 证明验证模块（v2 重构后）。
//!
//! v2 变更（2026-07-20）：
//! - 完全放弃 Hypernova 兼容，删除 `ccs` / `hypernova` / `groth16` / `ipa` 模块。
//! - 保留 [`state`] — CheckinTx/PartialCheckinTx 结构（用户要求兼容）。
//! - 保留 [`zk_verifier`] — ZkVerifier trait + ZkVerifierRegistry 热插拔 + zk_verify syscall。
//!   证明系统后端将在 Phase 5 由 Stwo 递归证明 Verifier AIR 重写。
//! - 保留 [`ack_chain`] — RFC 6962 风格 ack_chain_hash Merkle 树。
//!
//! ## 模块依赖关系
//!
//! ```text
//! ack_chain ──┐
//!             ├──► state
//! zk_verifier ┘
//! ```
//!
//! ## 安全说明
//!
//! - 全部模块 `deny(unsafe_code)`
//! - v2 Phase 1 过渡期：ZK verifier 通过 stub 占位，仅校验 proof 格式合法性
//! - Phase 5 将实现 Stwo Verifier AIR（recursive proof composition）

pub mod ack_chain;
pub mod state;
pub mod zk_verifier;

// 公共常量（跨模块共享）
/// ack_chain Merkle 树域分离字节 — 叶子节点前缀（RFC 6962）。
pub const ACK_MERKLE_LEAF_PREFIX: u8 = 0x00;
/// ack_chain Merkle 树域分离字节 — 内部节点前缀（RFC 6962）。
pub const ACK_MERKLE_INTERNAL_PREFIX: u8 = 0x01;
/// ACK 签名域分离常量（NEW-H3 / SEC-C3）。
pub const ACK_DOMAIN_TAG: u8 = 0x02;
/// refuse_ack 签名域分离常量。
pub const REFUSE_ACK_DOMAIN_TAG: u8 = 0x03;
/// operator_ack 签名域分离常量（H5 修复）。
pub const OPERATOR_ACK_DOMAIN_TAG: u8 = 0x04;

/// max_ack_chain_length 默认值（SEC2-M4）。
pub const DEFAULT_MAX_ACK_CHAIN_LENGTH: u32 = 1000;
/// max_ack_chain_length 下限（SEC2-M4）。
pub const MIN_MAX_ACK_CHAIN_LENGTH: u32 = 100;
/// max_ack_chain_length 上限（SEC2-M4）。
pub const MAX_MAX_ACK_CHAIN_LENGTH: u32 = 10_000;
/// max_partial_checkin_count 默认值（SEC-H1）。
pub const DEFAULT_MAX_PARTIAL_CHECKIN_COUNT: u32 = 3;
/// max_partial_checkin_count 下限（SEC-H1）。
pub const MIN_MAX_PARTIAL_CHECKIN_COUNT: u32 = 1;
/// max_partial_checkin_count 上限（SEC-H1）。
pub const MAX_MAX_PARTIAL_CHECKIN_COUNT: u32 = 10;
/// ZK proof fold_step_count 上限（O15 修复，保留以兼容 ZkPublicIo::validate）。
///
/// v2 含义变更：原指 Hypernova fold step 数；v2 中指 Stwo 证明的 segment 数。
/// 上限保持 1000 以维持 CheckinTx 结构兼容性。
pub const MAX_FOLD_STEP_COUNT: u32 = 1000;
