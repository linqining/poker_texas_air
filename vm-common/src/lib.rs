//! vm-common — poker_l1 vm 与 poker_zkvm 的共享横切关注点。
//!
//! 严格不含 ISA 语义（BPF / RV32I），不依赖 solana_rbpf 或 arkworks。
//! 仅含六大横切关注点：
//! - `gas` — gas 常量单一事实源（Phase 1 迁入）
//! - `syscall_id` — 统一 SyscallId 枚举（Phase 1 迁入）
//! - `precompile` — Precompile trait + Registry（Phase 2 迁入）
//! - `crypto` — CryptoProvider trait（Phase 3 迁入）
//! - `gas_strategy` — GasStrategy trait（Phase 4 迁入）
//! - `catalog` — PrecompileCatalog 跨 VM 可用性目录（Phase 5 迁入）
//!
//! # 安全保证
//!
//! 本 crate 严格 `#![deny(unsafe_code)]`，不引入任何 unsafe 代码。
//! 这与 poker_zkvm 的 `#![deny(unsafe_code)]` 保持一致，
//! 且不影响 poker_l1 的 `#![allow(unsafe_code)]`（因 unsafe 仅在 poker_l1 内部）。

#![deny(unsafe_code)]
#![forbid(unsafe_code)]

pub mod catalog;
pub mod crypto;
pub mod gas;
pub mod gas_strategy;
pub mod precompile;
pub mod prove_task;
pub mod syscall_id;
