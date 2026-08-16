//! BpfGasStrategy — poker_l1 链上 BPF gas 策略（Phase 4）。
//!
//! 完整计费：指令级 1 gas/条 + syscall 级按 vm_common::gas 计费。
//!
//! # 范围说明
//!
//! Phase 4 仅形式化 gas 策略接口，**不接入 executor**。
//! 现有 PokerL1Context / syscalls.rs 的 gas 计费路径保持原状。
//! 本实现作为未来 executor 接入的参考，并作为跨 VM 一致性测试的 BPF 侧样本。

use vm_common::gas;
use vm_common::gas_strategy::{GasStrategy, InsnCategory};
use vm_common::syscall_id::SyscallId;

// BPF 指令级常量保留在 gas_table.rs（ISA 专有），此处复用
use crate::vm::gas_table::{GAS_ARITHMETIC, GAS_BRANCH, GAS_MEMORY_BASE};

/// poker_l1 链上 BPF gas 策略。
///
/// 实现完整 gas 计费：
/// - 指令级：按 [`InsnCategory`] 分派，算术 1 gas、内存 3 gas、分支 2 gas 等
/// - syscall 级：按 [`SyscallId`] 分派，调用 `vm_common::gas` 中的纯函数
///
/// # 示例
///
/// ```ignore
/// use poker_l1::vm::gas_strategy::BpfGasStrategy;
/// use vm_common::gas_strategy::{GasStrategy, InsnCategory};
///
/// let strategy = BpfGasStrategy::new();
/// assert_eq!(strategy.instruction_gas(InsnCategory::Arithmetic), 1);
/// assert_eq!(strategy.name(), "bpf");
/// assert!(strategy.instruction_meter_enabled());
/// ```
pub struct BpfGasStrategy;

impl BpfGasStrategy {
    /// 创建新策略。
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for BpfGasStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl GasStrategy for BpfGasStrategy {
    fn instruction_gas(&self, category: InsnCategory) -> u64 {
        match category {
            InsnCategory::Arithmetic | InsnCategory::UpperImm | InsnCategory::Other => {
                GAS_ARITHMETIC
            }
            InsnCategory::Memory => GAS_MEMORY_BASE,
            InsnCategory::ControlFlow | InsnCategory::System => GAS_BRANCH,
            InsnCategory::Shift => 2,
            InsnCategory::Mul => 20,
            InsnCategory::Div => 20,
        }
    }

    fn syscall_gas(&self, id: SyscallId, args_len: u32) -> u64 {
        match id {
            SyscallId::ObjectRead => gas::object_read_gas(args_len as u64),
            SyscallId::ObjectWrite => gas::object_write_gas(args_len as u64),
            SyscallId::ObjectCreate => gas::object_create_gas(args_len as u64),
            SyscallId::EmitEvent => gas::emit_event_gas(args_len as u64),
            SyscallId::VerifySignature => gas::GAS_SECP256K1_VERIFY,
            SyscallId::ZkVerify => gas::zk_verify_gas(0),
            _ => 0,
        }
    }

    fn instruction_meter_enabled(&self) -> bool {
        true
    }

    fn default_tx_gas_limit(&self) -> u64 {
        gas::TX_GAS_LIMIT
    }

    fn default_block_gas_limit(&self) -> u64 {
        gas::BLOCK_GAS_LIMIT
    }

    fn name(&self) -> &'static str {
        "bpf"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_strategy_name() {
        assert_eq!(BpfGasStrategy::new().name(), "bpf");
    }

    #[test]
    fn test_bpf_instruction_gas() {
        let s = BpfGasStrategy::new();
        // BPF 专有常量（来自 gas_table.rs）
        assert_eq!(s.instruction_gas(InsnCategory::Arithmetic), GAS_ARITHMETIC);
        assert_eq!(s.instruction_gas(InsnCategory::Memory), GAS_MEMORY_BASE);
        assert_eq!(s.instruction_gas(InsnCategory::ControlFlow), GAS_BRANCH);
        assert_eq!(s.instruction_gas(InsnCategory::UpperImm), GAS_ARITHMETIC);
        assert_eq!(s.instruction_gas(InsnCategory::Other), GAS_ARITHMETIC);
        assert_eq!(s.instruction_gas(InsnCategory::System), GAS_BRANCH);
        // 估算值（Mul/Div/Shift）
        assert_eq!(s.instruction_gas(InsnCategory::Shift), 2);
        assert_eq!(s.instruction_gas(InsnCategory::Mul), 20);
        assert_eq!(s.instruction_gas(InsnCategory::Div), 20);
    }

    #[test]
    fn test_bpf_meter_enabled() {
        assert!(BpfGasStrategy::new().instruction_meter_enabled());
    }

    #[test]
    fn test_bpf_gas_limits() {
        let s = BpfGasStrategy::new();
        assert_eq!(s.default_tx_gas_limit(), 10_000_000);
        assert_eq!(s.default_block_gas_limit(), 50_000_000);
        assert!(s.default_block_gas_limit() > s.default_tx_gas_limit());
    }

    #[test]
    fn test_bpf_syscall_gas() {
        let s = BpfGasStrategy::new();
        // object_read = 10 + 1 * bytes
        assert_eq!(s.syscall_gas(SyscallId::ObjectRead, 100), 110);
        // object_write = 20 + 1 * bytes
        assert_eq!(s.syscall_gas(SyscallId::ObjectWrite, 100), 120);
        // verify_signature 固定 500
        assert_eq!(s.syscall_gas(SyscallId::VerifySignature, 0), 500);
        // 未匹配的 syscall 返回 0
        assert_eq!(s.syscall_gas(SyscallId::Sha256, 0), 0);
    }

    #[test]
    fn test_bpf_trait_object() {
        let s: Box<dyn GasStrategy> = Box::new(BpfGasStrategy::new());
        assert_eq!(s.name(), "bpf");
        assert!(s.instruction_meter_enabled());
    }
}
