//! rBPF VM 合约加载器（Task 14 — SubTask 14.1 / 14.2）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 14.1**：创建 `rbpf_loader` 模块，加载 `.so` 字节码（ELF 格式）。
//!   IMPL-SEC-4：(1) 强制启用 [`RequisiteVerifier`] 字节码验证，验证失败返回
//!   [`InvalidBytecode`](crate::error::PokerL1Error::InvalidBytecode)。
//! - **SubTask 14.2**：实现 entrypoint 调用与上下文（[`PokerL1Context`]）。
//!   创建 VM 实例 + 内存区域（stack / heap / input），执行 entrypoint，
//!   gas 耗尽返回 [`OutOfGas`](crate::error::PokerL1Error::OutOfGas)。
//!
//! # 内存布局（IMPL-SEC-4：(3)）
//!
//! | Region  | 虚拟地址           | 大小上限          |
//! |---------|--------------------|-------------------|
//! | rodata  | `MM_PROGRAM_START` | 来自 ELF          |
//! | stack   | `MM_STACK_START`   | `MAX_STACK_SIZE`  |
//! | heap    | `MM_HEAP_START`    | `MAX_HEAP_SIZE`   |
//! | input   | `MM_INPUT_START`   | `MAX_INPUT_SIZE`  |
//!
//! # Gas 计费
//!
//! - 指令级 gas：VM 每执行一条指令调用 `consume(1)`，到 0 抛
//!   [`EbpfError::ExceededMaxInstructions`]，loader 转换为 [`OutOfGas`]。
//! - syscall 级 gas：由 `syscalls` 模块（Task 15）在 syscall 内部调用
//!   `consume(extra)` 对昂贵操作额外计费。

use std::sync::Arc;

use solana_rbpf::{
    aligned_memory::AlignedMemory,
    ebpf,
    elf::Executable,
    error::{EbpfError, ProgramResult},
    memory_region::{MemoryMapping, MemoryRegion},
    program::{BuiltinProgram, FunctionRegistry},
    verifier::RequisiteVerifier,
    vm::{Config, EbpfVm},
};

use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::ObjectID;

use super::context::{ContractCallResult, PokerL1Context};
use super::gas_table::{MAX_HEAP_SIZE, MAX_INPUT_SIZE, MAX_STACK_SIZE};

/// rBPF stack frame 大小（与 LLVM BPF backend 默认值对齐）。
const STACK_FRAME_SIZE: usize = 4096;
/// Poker L1 最大 BPF 调用深度。
///
/// IMPL-SEC-4：(3) 合约栈 ≤ 64KB = `MAX_STACK_SIZE`。
/// `max_call_depth = MAX_STACK_SIZE / STACK_FRAME_SIZE = 16`。
const MAX_CALL_DEPTH: usize = MAX_STACK_SIZE / STACK_FRAME_SIZE;

/// 构造 Poker L1 专用 rBPF [`Config`]。
///
/// - `enable_instruction_meter = true`：启用指令级 gas 计费。
/// - `max_call_depth = 16`：限制栈大小 ≤ 64KB（IMPL-SEC-4：(3)）。
fn poker_l1_config() -> Config {
    Config {
        enable_instruction_meter: true,
        max_call_depth: MAX_CALL_DEPTH,
        ..Config::default()
    }
}

/// 构造 Poker L1 专用 loader（[`BuiltinProgram`]）。
///
/// 使用 [`poker_l1_config`] 配置 + 注入全部核心 syscalls
/// （Task 15：object_read/write/create + emit_event + log/panic +
/// verify_signature + get_block_height/timestamp + verify_failure_proof）。
fn poker_l1_loader() -> Arc<BuiltinProgram<PokerL1Context>> {
    let mut registry = FunctionRegistry::default();
    super::syscalls::register_poker_l1_syscalls(&mut registry)
        .expect("注册 Poker L1 syscalls 不应失败（名称互不相同）");
    Arc::new(BuiltinProgram::<PokerL1Context>::new_loader(
        poker_l1_config(),
        registry,
    ))
}

/// rBPF loader 配置。
///
/// 控制 VM 执行行为。当前仅支持解释器模式（`use_jit = false`），
/// JIT 在后续版本通过 `solana_rbpf/jit` feature 启用。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RbpfLoaderConfig {
    /// 是否使用 JIT（默认 `false`，仅解释器）。
    ///
    /// 当前实现始终使用解释器；该字段为未来 JIT 支持预留。
    pub use_jit: bool,
    /// 是否启用指令 tracing（默认 `false`）。
    ///
    /// 启用后 [`PokerL1Context::trace`] 会记录每条指令的寄存器状态，
    /// 仅用于调试，生产环境应关闭以避免性能损失。
    pub enable_tracing: bool,
}

/// 已加载的合约（[`Executable`] + 元数据）。
///
/// 由 [`load_contract_bytecode`] 产生，传给 [`execute_contract`] 执行。
/// `executable` 已通过 [`RequisiteVerifier`] 验证，可安全重复执行。
#[derive(Debug)]
pub struct LoadedContract {
    /// 已验证的 rBPF [`Executable`]。
    pub executable: Executable<PokerL1Context>,
    /// 合约 ID（全局唯一，升级后不变）。
    pub contract_id: ObjectID,
    /// 合约版本号（从 1 开始，每次升级 +1）。
    pub version: u32,
}

/// 加载合约字节码（SubTask 14.1）。
///
/// 解析 ELF 格式 `.so` 字节码，构造 [`Executable`] 并强制执行
/// [`RequisiteVerifier`] 验证。
///
/// # IMPL-SEC-4：(1) 强制字节码验证
///
/// 验证失败（非法指令、未终止程序、未知 syscall 等）返回
/// [`InvalidBytecode`](PokerL1Error::InvalidBytecode)，拒绝加载。
///
/// # 参数
///
/// - `bytecode`：ELF 格式 BPF 字节码（`.so` 文件内容）。
/// - `contract_id`：合约全局唯一 ID。
/// - `version`：合约版本号（从 1 开始）。
///
/// # 错误
///
/// - [`InvalidBytecode`](PokerL1Error::InvalidBytecode)：ELF 解析失败或验证器拒绝。
///
/// # 示例
///
/// ```no_run
/// use poker_l1::vm::load_contract_bytecode;
/// use poker_l1::object_model::ObjectID;
///
/// let elf_bytes = std::fs::read("contract.so").unwrap();
/// let contract_id = ObjectID::new([0x01; 20], 1);
/// let loaded = load_contract_bytecode(&elf_bytes, contract_id, 1).unwrap();
/// assert_eq!(loaded.contract_id, contract_id);
/// assert_eq!(loaded.version, 1);
/// ```
pub fn load_contract_bytecode(
    bytecode: &[u8],
    contract_id: ObjectID,
    version: u32,
) -> PokerL1Result<LoadedContract> {
    let loader = poker_l1_loader();

    // 加载 ELF（含内部 validate + relocate）
    let executable = Executable::<PokerL1Context>::from_elf(bytecode, loader)
        .map_err(|e| PokerL1Error::InvalidBytecode(format!("ELF load failed: {e}")))?;

    // IMPL-SEC-4：(1) 强制 RequisiteVerifier 验证
    executable
        .verify::<RequisiteVerifier>()
        .map_err(|e| PokerL1Error::InvalidBytecode(format!("Verifier rejected: {e}")))?;

    Ok(LoadedContract {
        executable,
        contract_id,
        version,
    })
}

/// 执行合约（SubTask 14.2）。
///
/// 创建 [`EbpfVm`] 实例 + 内存区域（rodata / stack / heap / input），
/// 调用合约 entrypoint 并返回执行结果。
///
/// # Gas 计费
///
/// - 指令级 gas：VM 每执行一条指令调用 `consume(1)`。
/// - gas 耗尽时 VM 返回 [`EbpfError::ExceededMaxInstructions`]，本函数转换为
///   [`OutOfGas`](PokerL1Error::OutOfGas)。
/// - 实际消耗 gas 通过 [`PokerL1Context::gas_used`] 读取，写入
///   [`ContractCallResult::gas_used`]。
///
/// # IMPL-SEC-4
///
/// - (3) stack ≤ 64KB，heap ≤ 1MB（由 [`poker_l1_config`] 限制 `max_call_depth`）。
/// - 输入长度 ≤ 64KB（[`MAX_INPUT_SIZE`]），超长返回
///   [`InputTooLong`](PokerL1Error::InputTooLong)。
///
/// # 参数
///
/// - `loaded`：已加载并验证的合约（[`LoadedContract`]）。
/// - `ctx`：合约执行上下文（携带 gas budget + tx 上下文 + 对象缓存）。
///   执行后 `ctx` 中的 `events` / `created_objects` 会被清空并转移到返回值。
/// - `input`：合约输入数据（映射到 `MM_INPUT_START`，≤ 64KB）。
///
/// # 返回
///
/// 成功返回 [`ContractCallResult`]，包含 exit_code / gas_used / events /
/// created_objects / modified_objects。
///
/// # 错误
///
/// - [`InputTooLong`](PokerL1Error::InputTooLong)：`input` 超过 [`MAX_INPUT_SIZE`]。
/// - [`OutOfGas`](PokerL1Error::OutOfGas)：gas 耗尽。
/// - [`ContractExecutionFailed`](PokerL1Error::ContractExecutionFailed)：VM 内部错误
///   （非法指令、内存访问越界等）。
pub fn execute_contract(
    loaded: &LoadedContract,
    ctx: &mut PokerL1Context,
    input: &[u8],
) -> PokerL1Result<ContractCallResult> {
    // IMPL-SEC-4：输入长度校验
    if input.len() > MAX_INPUT_SIZE {
        return Err(PokerL1Error::InputTooLong {
            actual: input.len(),
            limit: MAX_INPUT_SIZE,
        });
    }

    let executable = &loaded.executable;
    let config = executable.get_config();
    let sbpf_version = executable.get_sbpf_version();

    // 准备 stack / heap / input 内存区域（IMPL-SEC-4：(3) 大小上限）
    let stack_size = config.stack_size();
    let mut stack = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(stack_size);
    let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(MAX_HEAP_SIZE);
    let mut input_buf = input.to_vec();

    let regions = vec![
        executable.get_ro_region(),
        MemoryRegion::new_writable(stack.as_slice_mut(), ebpf::MM_STACK_START),
        MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
        MemoryRegion::new_writable(input_buf.as_mut_slice(), ebpf::MM_INPUT_START),
    ];

    let memory_mapping = MemoryMapping::new(regions, config, sbpf_version)
        .map_err(|e| PokerL1Error::ContractExecutionFailed(format!("MemoryMapping: {e}")))?;

    let loader = executable.get_loader().clone();
    let stack_len = stack.len();

    // 执行 entrypoint（interpreted = true，仅解释器）
    //
    // EbpfVm 持有 &mut ctx 的可变借用，直到 vm 离开作用域。
    // 在此 block 内通过 vm.context_object_pointer 访问 ctx；
    // block 结束后 vm 被 drop，ctx 恢复可访问。
    let exit_code = {
        let mut vm = EbpfVm::new(loader, sbpf_version, ctx, memory_mapping, stack_len);
        let (_insn_count, result) = vm.execute_program(executable, /*interpreted=*/ true);

        match result {
            ProgramResult::Ok(code) => code,
            ProgramResult::Err(EbpfError::ExceededMaxInstructions) => {
                // gas 耗尽（IMPL-SEC-4：(5) 指令执行前扣费，余额不足立即 trap）
                let used = vm.context_object_pointer.gas_used();
                let remaining = vm.context_object_pointer.remaining_gas();
                return Err(PokerL1Error::OutOfGas {
                    used,
                    limit: used.saturating_add(remaining),
                });
            }
            ProgramResult::Err(e) => {
                return Err(PokerL1Error::ContractExecutionFailed(format!(
                    "VM error: {e}"
                )));
            }
        }
    };

    // vm 已 drop，ctx 恢复可访问。
    // 转移 events / created_objects 到返回值（不消耗 ctx）。
    let events = std::mem::take(&mut ctx.events);
    let created_objects = std::mem::take(&mut ctx.created_objects);
    let modified_objects = ctx.object_cache.keys().copied().collect();

    Ok(ContractCallResult {
        exit_code,
        gas_used: ctx.gas_used(),
        events,
        created_objects,
        modified_objects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::TaggedPubkey;
    use crate::vm::context::TxContext;
    use solana_rbpf::program::SBPFVersion;

    /// 简单的 BPF `exit` 指令（8 字节）。
    ///
    /// `0x95` = BPF_EXIT，立即数 0 = exit code。
    const BPF_EXIT: &[u8] = &[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    /// 构造测试用 [`TxContext`]。
    fn make_tx_context() -> TxContext {
        TxContext {
            caller: [1u8; 20],
            caller_pubkey: TaggedPubkey {
                tag: 0x01,
                raw: vec![0x02; 33],
            },
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 0,
            block_height: 100,
            block_timestamp: 100_000,
        }
    }

    /// 从 raw text bytes 构造 [`LoadedContract`]（测试辅助）。
    ///
    /// 跳过 ELF 解析，直接用 [`Executable::from_text_bytes`] 构造，
    /// 仍强制执行 [`RequisiteVerifier`] 验证（IMPL-SEC-4：(1)）。
    fn load_from_text_bytes(
        text: &[u8],
        contract_id: ObjectID,
        version: u32,
    ) -> PokerL1Result<LoadedContract> {
        let loader = poker_l1_loader();
        let executable = Executable::<PokerL1Context>::from_text_bytes(
            text,
            loader,
            SBPFVersion::V2,
            FunctionRegistry::default(),
        )
        .map_err(|e| PokerL1Error::InvalidBytecode(format!("text load failed: {e}")))?;

        executable
            .verify::<RequisiteVerifier>()
            .map_err(|e| PokerL1Error::InvalidBytecode(format!("Verifier rejected: {e}")))?;

        Ok(LoadedContract {
            executable,
            contract_id,
            version,
        })
    }

    // ===== SubTask 14.1: load_contract_bytecode 测试 =====

    #[test]
    fn test_load_empty_bytecode_fails() {
        // 空字节码 → InvalidBytecode
        let result = load_contract_bytecode(&[], ObjectID::default(), 1);
        assert!(
            matches!(result, Err(PokerL1Error::InvalidBytecode(_))),
            "空字节码应返回 InvalidBytecode, got: {result:?}"
        );
    }

    #[test]
    fn test_load_garbage_bytecode_fails() {
        // 非 ELF 字节码 → InvalidBytecode
        let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
        let result = load_contract_bytecode(&garbage, ObjectID::default(), 1);
        assert!(
            matches!(result, Err(PokerL1Error::InvalidBytecode(_))),
            "垃圾字节码应返回 InvalidBytecode, got: {result:?}"
        );
    }

    #[test]
    fn test_load_truncated_bytecode_fails() {
        // 截断的 ELF magic（仅 4 字节 \x7fELF）→ InvalidBytecode
        let truncated = [0x7f, b'E', b'L', b'F'];
        let result = load_contract_bytecode(&truncated, ObjectID::default(), 1);
        assert!(
            matches!(result, Err(PokerL1Error::InvalidBytecode(_))),
            "截断字节码应返回 InvalidBytecode, got: {result:?}"
        );
    }

    #[test]
    fn test_load_from_text_exit_instruction() {
        // raw BPF exit 指令可加载并验证通过
        let contract_id = ObjectID::new([0x42; 20], 7);
        let loaded = load_from_text_bytes(BPF_EXIT, contract_id, 3).expect("exit 指令应加载成功");
        assert_eq!(loaded.contract_id, contract_id);
        assert_eq!(loaded.version, 3);
    }

    #[test]
    fn test_load_from_text_invalid_bytecode_fails() {
        // 长度不是 8 字节倍数 → Verifier 拒绝
        let bad = &[0x95, 0x00, 0x00, 0x00]; // 4 字节，非 8 倍数
        let result = load_from_text_bytes(bad, ObjectID::default(), 1);
        assert!(
            matches!(result, Err(PokerL1Error::InvalidBytecode(_))),
            "非 8 倍数字节码应被拒绝, got: {result:?}"
        );
    }

    // ===== SubTask 14.2: execute_contract 测试 =====

    #[test]
    fn test_execute_exit_instruction_success() {
        // 执行 exit 指令 → exit_code = 0, gas_used ≥ 1
        let loaded = load_from_text_bytes(BPF_EXIT, ObjectID::default(), 1).unwrap();
        let mut ctx = PokerL1Context::new(make_tx_context(), 1_000);

        let result = execute_contract(&loaded, &mut ctx, &[]).expect("exit 应执行成功");

        assert_eq!(result.exit_code, 0, "exit 指令 exit_code 应为 0");
        assert!(
            result.gas_used >= 1,
            "至少执行 1 条指令, gas_used 应 ≥ 1, got {}",
            result.gas_used
        );
        assert_eq!(result.gas_used, 1, "exit 仅 1 条指令, gas_used 应 = 1");
        assert!(result.events.is_empty(), "无事件");
        assert!(result.created_objects.is_empty(), "无创建对象");
        assert!(result.modified_objects.is_empty(), "无修改对象");
    }

    #[test]
    fn test_execute_with_input_data() {
        // 带输入数据执行 exit → 成功
        let loaded = load_from_text_bytes(BPF_EXIT, ObjectID::default(), 1).unwrap();
        let mut ctx = PokerL1Context::new(make_tx_context(), 1_000);

        let input = b"hello poker l1".to_vec();
        let result = execute_contract(&loaded, &mut ctx, &input).expect("带输入应执行成功");

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.gas_used, 1);
    }

    #[test]
    fn test_execute_out_of_gas() {
        // gas_limit = 0 → OutOfGas
        let loaded = load_from_text_bytes(BPF_EXIT, ObjectID::default(), 1).unwrap();
        let mut ctx = PokerL1Context::new(make_tx_context(), 0);

        let result = execute_contract(&loaded, &mut ctx, &[]);

        assert!(
            matches!(result, Err(PokerL1Error::OutOfGas { .. })),
            "gas_limit=0 应返回 OutOfGas, got: {result:?}"
        );
        if let Err(PokerL1Error::OutOfGas { used, limit }) = result {
            assert_eq!(used, 0, "未执行任何指令, used 应为 0");
            assert_eq!(limit, 0, "limit 应等于初始 gas_limit");
        }
    }

    #[test]
    fn test_execute_input_too_long() {
        // input > MAX_INPUT_SIZE → InputTooLong
        let loaded = load_from_text_bytes(BPF_EXIT, ObjectID::default(), 1).unwrap();
        let mut ctx = PokerL1Context::new(make_tx_context(), 1_000);

        let oversized = vec![0u8; MAX_INPUT_SIZE + 1];
        let result = execute_contract(&loaded, &mut ctx, &oversized);

        assert!(
            matches!(result, Err(PokerL1Error::InputTooLong { actual, limit })
                if actual == MAX_INPUT_SIZE + 1 && limit == MAX_INPUT_SIZE),
            "超长输入应返回 InputTooLong, got: {result:?}"
        );
    }

    #[test]
    fn test_execute_gas_tracking_after_success() {
        // 执行后 ctx 的 gas_used 应与返回值一致
        let loaded = load_from_text_bytes(BPF_EXIT, ObjectID::default(), 1).unwrap();
        let initial_gas = 10_000u64;
        let mut ctx = PokerL1Context::new(make_tx_context(), initial_gas);

        let result = execute_contract(&loaded, &mut ctx, &[]).unwrap();

        assert_eq!(
            ctx.gas_used(),
            result.gas_used,
            "ctx.gas_used 应与返回值一致"
        );
        assert_eq!(
            ctx.remaining_gas(),
            initial_gas - result.gas_used,
            "remaining 应 = initial - used"
        );
    }

    #[test]
    fn test_rbpf_loader_config_default() {
        let config = RbpfLoaderConfig::default();
        assert!(!config.use_jit, "默认应不使用 JIT");
        assert!(!config.enable_tracing, "默认应不启用 tracing");
    }

    #[test]
    fn test_poker_l1_config_stack_limit() {
        // IMPL-SEC-4：(3) stack ≤ 64KB
        let config = poker_l1_config();
        assert_eq!(
            config.stack_size(),
            MAX_STACK_SIZE,
            "stack_size 应 = MAX_STACK_SIZE"
        );
        assert_eq!(config.max_call_depth, MAX_CALL_DEPTH);
        assert!(config.enable_instruction_meter, "应启用 instruction meter");
        assert!(config.stack_size() <= MAX_STACK_SIZE, "stack 不得超过 64KB");
    }
}
