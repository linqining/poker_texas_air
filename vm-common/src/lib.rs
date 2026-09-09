//! vm-common — 早期多 VM 计划（poker_l1 vm + poker_zkvm）的共享横切层。
//!
//! **现状（2026-09-10 盘点）**：poker_zkvm 已不存在；workspace 真正在用的
//! 只有 `gas`（`MAX_OBJECT_SIZE`）、`prove_task`（`MethodInput`）。其余模块
//! （`syscall_id` / `precompile` / `crypto` / `gas_strategy` / `catalog`）
//! 无任何消费者，保留与否待 Phase 2b 布线决策——去留勿以本文档为据。
//!
//! 严格不含 ISA 语义（BPF / RV32I），不依赖 solana_rbpf 或 arkworks。
//! 仅含横切关注点：gas / syscall_id / precompile / crypto / gas_strategy /
//! catalog / prove_task。
//!
//! # 安全保证
//!
//! 本 crate 严格 `#![deny(unsafe_code)]`，不引入任何 unsafe 代码；
//! 不影响 poker_l1 的 `#![allow(unsafe_code)]`（unsafe 仅在 poker_l1 内部）。

#![deny(unsafe_code)]
#![forbid(unsafe_code)]

pub mod catalog;
pub mod crypto;
pub mod gas;
pub mod gas_strategy;
pub mod precompile;
pub mod prove_task;
pub mod syscall_id;
