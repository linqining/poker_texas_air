//! 合约层（Phase 1 收缩版）：仅保留 dispatch 边界与 texas_poker 合约库。
//!
//! 原 rBPF VM（solana_rbpf loader / syscalls / precompile / gas 计费 / 升级
//! 机制）属 L1 链机制，随 2026-09-05 模型收缩一并移除（git 历史可恢复）。

pub mod contracts;
