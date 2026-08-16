//! GasStrategy — 跨 VM gas 计费策略形式化接口（Phase 4）。
//!
//! # 设计
//!
//! - `BpfGasStrategy`（poker_l1）：指令级 1 gas/条 + syscall 级按 gas_table 计费
//! - `ZkvmGasStrategy`（poker_zkvm）：指令级 gas = 0（无 gas 费），仅 step_limit
//!
//! # 范围说明
//!
//! Phase 4 仅建立 trait + 双实现 + 跨实现测试，**不改造现有 executor 签名**。
//! 让 PokerL1Context::new / execute_elf_with_limits_and_config 改用 GasStrategy
//! 是未来增量工作，避免破坏 GameTurn gas-free 硬约束。

use crate::syscall_id::SyscallId;

/// 指令分类（用于 gas 计费抽象）。
///
/// 跨 VM 通用分类，不绑定具体 ISA（BPF / RV32I）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsnCategory {
    /// 算术指令（ADD/SUB/AND/OR/XOR 等）。
    Arithmetic,
    /// 内存指令（LOAD/STORE）。
    Memory,
    /// 控制流指令（JUMP/BRANCH/CALL）。
    ControlFlow,
    /// 移位指令（SHL/SHR/SAR）。
    Shift,
    /// 乘法指令（MUL/MULH）。
    Mul,
    /// 除法指令（DIV/REM）。
    Div,
    /// 上立即数加载（LUI/AUIPC）。
    UpperImm,
    /// 系统指令（ECALL/EBREAK）。
    System,
    /// 其他（无法归类的指令）。
    Other,
}

/// Gas 计费策略 trait。
///
/// 跨 VM gas 差异的形式化接口。Phase 4 为非侵入式形式化层：
/// 仅定义接口与双实现，**不接入 executor**。
///
/// # 实现者
///
/// - [`BpfGasStrategy`](../../poker_l1/vm/gas_strategy/struct.BpfGasStrategy.html)（poker_l1）
/// - [`ZkvmGasStrategy`](../../poker_zkvm/syscalls/gas_strategy/struct.ZkvmGasStrategy.html)（poker_zkvm）
pub trait GasStrategy: Send + Sync {
    /// 指令级 gas（每条指令按类别）。
    fn instruction_gas(&self, category: InsnCategory) -> u64;

    /// syscall 级 gas（按 [`SyscallId`] + 参数长度）。
    fn syscall_gas(&self, id: SyscallId, args_len: u32) -> u64;

    /// 是否启用指令级 gas 计量。
    ///
    /// `BpfGasStrategy` 返回 `true`，`ZkvmGasStrategy` 返回 `false`。
    fn instruction_meter_enabled(&self) -> bool;

    /// 默认 tx gas 上限。
    fn default_tx_gas_limit(&self) -> u64;

    /// 默认 block gas 上限。
    fn default_block_gas_limit(&self) -> u64;

    /// 策略名称（`"bpf"` / `"zkvm"`）。
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用 GasStrategy 实现（全 0，仅验证 trait object）。
    struct DummyStrategy;

    impl GasStrategy for DummyStrategy {
        fn instruction_gas(&self, _: InsnCategory) -> u64 {
            0
        }
        fn syscall_gas(&self, _: SyscallId, _: u32) -> u64 {
            0
        }
        fn instruction_meter_enabled(&self) -> bool {
            false
        }
        fn default_tx_gas_limit(&self) -> u64 {
            0
        }
        fn default_block_gas_limit(&self) -> u64 {
            0
        }
        fn name(&self) -> &'static str {
            "dummy"
        }
    }

    #[test]
    fn test_gas_strategy_trait_object() {
        let s: Box<dyn GasStrategy> = Box::new(DummyStrategy);
        assert_eq!(s.name(), "dummy");
        assert_eq!(s.instruction_gas(InsnCategory::Arithmetic), 0);
        assert_eq!(s.syscall_gas(SyscallId::Sha256, 0), 0);
        assert!(!s.instruction_meter_enabled());
    }

    #[test]
    fn test_insn_category_copy() {
        let c = InsnCategory::Arithmetic;
        let c2 = c;
        assert_eq!(c, c2);
    }

    #[test]
    fn test_insn_category_all_variants() {
        // 验证所有变体可构造且不相等
        let variants = [
            InsnCategory::Arithmetic,
            InsnCategory::Memory,
            InsnCategory::ControlFlow,
            InsnCategory::Shift,
            InsnCategory::Mul,
            InsnCategory::Div,
            InsnCategory::UpperImm,
            InsnCategory::System,
            InsnCategory::Other,
        ];
        assert_eq!(variants.len(), 9);
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b, "variant {i} should equal itself");
                } else {
                    assert_ne!(a, b, "variant {i} should not equal variant {j}");
                }
            }
        }
    }
}
