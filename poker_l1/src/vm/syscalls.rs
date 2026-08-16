//! 核心 syscalls 实现（Task 15 — SubTask 15.1~15.8）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）+ IMPL-SEC-4 沙箱规范：
//! - (4) syscall 指针须验证 heap region
//! - (5) 执行前扣费（syscall 内部 `consume_gas`，余额不足返回 Err 触发 trap）
//! - (6) object_read/write/create + emit_event 按字节计费
//! - (7) Object ≤ 64KB
//!
//! ## Syscall 一览
//!
//! | Syscall                | SubTask | Gas                          | 说明                       |
//! |------------------------|---------|------------------------------|----------------------------|
//! | `object_read`          | 15.1    | 10 + 1 * bytes_returned      | 读取对象数据到合约 heap    |
//! | `object_write`         | 15.2    | 20 + 1 * data_len            | 写入/更新对象              |
//! | `object_create`        | 15.3    | 20 + 1 * data_len            | 创建新对象，返回 ObjectID  |
//! | `emit_event`           | 15.4    | 10 + 1 * payload_len (≤16KB) | 发射事件                   |
//! | `log`                  | 15.5    | 10                           | 记录日志                   |
//! | `panic`                | 15.5    | 10                           | 合约 panic，trap VM        |
//! | `verify_signature`     | 15.6    | 500                          | 统一签名验证               |
//! | `get_block_height`     | 15.7    | 1                            | 查询当前 block height      |
//! | `get_timestamp`        | 15.7    | 1                            | 查询当前 block timestamp   |
//! | `verify_failure_proof` | 15.8    | 80000                        | 验证 SMT 非包含证明        |
//! | `zk_verify`            | 22.2    | 300000/20000/15000 (按 scheme)| 通用 ZK 证明验证           |

use std::slice::{from_raw_parts, from_raw_parts_mut};

use solana_rbpf::{
    declare_builtin_function, ebpf,
    error::EbpfError,
    memory_region::{AccessType, MemoryMapping},
    program::{BuiltinFunction, FunctionRegistry},
};

use crate::error::PokerL1Error;
use crate::object_model::ObjectID;
use crate::object_model::smt::MerklePath;
use crate::signature::TaggedPubkey;
use crate::signature::unified::verify_signature;

use super::context::PokerL1Context;
use super::gas_table::*;

// ===== 辅助函数 =====

/// 将 [`PokerL1Error`] 转换为 syscall 错误（`Box<dyn Error>`）。
fn to_syscall_err(e: PokerL1Error) -> Box<dyn std::error::Error> {
    Box::new(e)
}

/// 校验指针位于 heap region 内（IMPL-SEC-4：(4)）。
///
/// heap region 范围：`[MM_HEAP_START, MM_HEAP_START + MAX_HEAP_SIZE)`。
fn validate_heap_ptr(vm_addr: u64, len: u64) -> Result<(), Box<dyn std::error::Error>> {
    let heap_start = ebpf::MM_HEAP_START;
    let heap_end = heap_start
        .checked_add(MAX_HEAP_SIZE as u64)
        .ok_or_else(|| {
            to_syscall_err(PokerL1Error::InvalidSyscallArgument(format!(
                "heap region overflow: start={heap_start:#x}"
            )))
        })?;

    let ptr_end = vm_addr
        .checked_add(len)
        .ok_or_else(|| to_syscall_err(PokerL1Error::HeapAccessViolation { ptr: vm_addr, len }))?;

    if vm_addr < heap_start || ptr_end > heap_end {
        return Err(to_syscall_err(PokerL1Error::HeapAccessViolation {
            ptr: vm_addr,
            len,
        }));
    }
    Ok(())
}

/// 从 VM 内存读取数据（复制到 `Vec<u8>`）。
///
/// # Safety
///
/// `memory_mapping.map(AccessType::Load, ...)` 已校验 `[vm_addr, vm_addr+len)`
/// 位于合法注册的内存 region 内。返回的 host_addr 指向该 region 内的有效内存。
fn read_vm_memory(
    memory_mapping: &mut MemoryMapping,
    vm_addr: u64,
    len: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    // solana_rbpf 的 map() 返回 StableResult，需用 .into() 转换为标准 Result
    let host_addr: Result<u64, EbpfError> =
        memory_mapping.map(AccessType::Load, vm_addr, len).into();
    let host_addr = host_addr.map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
    // SAFETY: map() 已校验地址合法，host_addr 指向有效内存区域。
    Ok(unsafe { from_raw_parts(host_addr as *const u8, len as usize) }.to_vec())
}

/// 向 VM 内存写入数据。
///
/// # Safety
///
/// `memory_mapping.map(AccessType::Store, ...)` 已校验 `[vm_addr, vm_addr+len)`
/// 位于合法可写 region 内。
fn write_vm_memory(
    memory_mapping: &mut MemoryMapping,
    vm_addr: u64,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok(());
    }
    let len = data.len() as u64;
    let host_addr: Result<u64, EbpfError> =
        memory_mapping.map(AccessType::Store, vm_addr, len).into();
    let host_addr = host_addr.map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;
    // SAFETY: map() 已校验地址合法且可写，host_addr 指向可写内存区域。
    unsafe {
        from_raw_parts_mut(host_addr as *mut u8, data.len()).copy_from_slice(data);
    }
    Ok(())
}

/// 检查并消耗 gas，不足时返回 `OutOfGas` 错误。
fn charge_gas(ctx: &mut PokerL1Context, amount: u64) -> Result<(), Box<dyn std::error::Error>> {
    if !ctx.consume_gas(amount) {
        let used = ctx.gas_used().saturating_add(amount);
        let limit = ctx.gas_used().saturating_add(ctx.remaining_gas());
        return Err(to_syscall_err(PokerL1Error::OutOfGas { used, limit }));
    }
    Ok(())
}

// ===== SubTask 15.1: object_read =====

declare_builtin_function!(
    /// 读取对象数据到合约 heap。
    ///
    /// # 参数
    /// - `id_ptr` / `id_len`：ObjectID 字节（28 字节），位于 heap region
    /// - `out_ptr` / `out_capacity`：输出缓冲区，位于 heap region
    /// - `arg5`：未使用
    ///
    /// # 返回
    /// - 成功：实际读取的字节数
    /// - 失败：`ObjectNotFound` / `OutOfGas` / `HeapAccessViolation`
    ///
    /// # Gas
    /// `10 + 1 * bytes_returned`（IMPL-SEC-4：(6)）
    ///
    /// # DoS 防护（SEC-FIX-1）
    /// 采用"预扣上界 + 事后退款"模式：
    /// 1. lookup 前按 `out_capacity`（bytes_returned 上界）预扣 gas
    /// 2. lookup 后按实际 `data.len()` 退还差额
    /// 净效果：成功调用支付 `object_read_gas(data.len())`（与原语义一致），
    /// 但失败调用（ObjectNotFound / capacity 不足）也支付 gas，防止免费 DoS。
    SyscallObjectRead,
    fn rust(
        ctx: &mut PokerL1Context,
        id_ptr: u64,
        id_len: u64,
        out_ptr: u64,
        out_capacity: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        // IMPL-SEC-4 (4)：校验指针位于 heap region
        validate_heap_ptr(id_ptr, id_len)?;
        validate_heap_ptr(out_ptr, out_capacity)?;

        // 校验 id 长度（ObjectID = 28 字节）
        if id_len != ObjectID::new([0u8; 20], 0).to_bytes().len() as u64 {
            return Err(to_syscall_err(PokerL1Error::InvalidSyscallArgument(format!(
                "object_read: id_len must be 28, got {id_len}"
            ))));
        }

        let id_bytes = read_vm_memory(memory_mapping, id_ptr, id_len)?;
        let object_id = ObjectID::from_bytes(&id_bytes).ok_or_else(|| {
            to_syscall_err(PokerL1Error::InvalidSyscallArgument(
                "object_read: invalid ObjectID bytes".to_string(),
            ))
        })?;

        // SEC-FIX-1：lookup 前按 out_capacity 预扣 gas（防免费 DoS）
        // out_capacity 是 bytes_returned 的上界（成功时 data.len() ≤ out_capacity）
        let prepaid_gas = object_read_gas(out_capacity);
        charge_gas(ctx, prepaid_gas)?;

        // 查找对象（clone 以释放不可变借用，后续可变借用 refund_gas）
        let data = ctx
            .object_cache
            .get(&object_id)
            .cloned()
            .ok_or_else(|| to_syscall_err(PokerL1Error::ObjectNotFound(object_id)))?;

        // 校验 out_capacity 足够（不足时不退款，调用方为无效调用付费）
        if out_capacity < data.len() as u64 {
            return Err(to_syscall_err(PokerL1Error::InvalidSyscallArgument(format!(
                "object_read: out_capacity={out_capacity} < data_len={}",
                data.len()
            ))));
        }

        // 退还差额：prepaid_gas - actual_gas
        let actual_gas = object_read_gas(data.len() as u64);
        let refund = prepaid_gas.saturating_sub(actual_gas);
        if refund > 0 {
            ctx.refund_gas(refund);
        }

        // 写入输出缓冲区
        write_vm_memory(memory_mapping, out_ptr, &data)?;

        Ok(data.len() as u64)
    }
);

// ===== SubTask 15.2: object_write =====

declare_builtin_function!(
    /// 写入/更新对象数据。
    ///
    /// # 参数
    /// - `id_ptr` / `id_len`：ObjectID 字节（28 字节），位于 heap region
    /// - `data_ptr` / `data_len`：待写入数据，位于 heap region
    /// - `arg5`：未使用
    ///
    /// # 返回
    /// - 成功：0
    /// - 失败：`ObjectTooLarge` / `OutOfGas` / `HeapAccessViolation`
    ///
    /// # Gas
    /// `20 + 1 * data_len`（IMPL-SEC-4：(6)）
    SyscallObjectWrite,
    fn rust(
        ctx: &mut PokerL1Context,
        id_ptr: u64,
        id_len: u64,
        data_ptr: u64,
        data_len: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        // IMPL-SEC-4 (4)：校验指针位于 heap region
        validate_heap_ptr(id_ptr, id_len)?;
        validate_heap_ptr(data_ptr, data_len)?;

        // IMPL-SEC-4 (7)：Object ≤ 64KB
        // M-8 修复：在 u64 域比较，避免 32-bit 平台 `as usize` 截断绕过上限
        if data_len > MAX_OBJECT_SIZE as u64 {
            return Err(to_syscall_err(PokerL1Error::ObjectTooLarge {
                actual: data_len as usize,
                limit: MAX_OBJECT_SIZE,
            }));
        }

        // 校验 id 长度
        if id_len != 28 {
            return Err(to_syscall_err(PokerL1Error::InvalidSyscallArgument(format!(
                "object_write: id_len must be 28, got {id_len}"
            ))));
        }

        let id_bytes = read_vm_memory(memory_mapping, id_ptr, id_len)?;
        let object_id = ObjectID::from_bytes(&id_bytes).ok_or_else(|| {
            to_syscall_err(PokerL1Error::InvalidSyscallArgument(
                "object_write: invalid ObjectID bytes".to_string(),
            ))
        })?;

        // H-5 修复：所有权检查 — 仅允许写入本次执行创建的或已缓存的对象
        if !ctx.created_objects.contains(&object_id) && !ctx.object_cache.contains_key(&object_id) {
            return Err(to_syscall_err(PokerL1Error::InvalidSyscallArgument(format!(
                "object_write: caller does not own object {object_id:?}"
            ))));
        }

        // IMPL-SEC-4 (5)(6)：执行前扣费
        let gas = object_write_gas(data_len);
        charge_gas(ctx, gas)?;

        // 读取数据并写入 cache
        let data = read_vm_memory(memory_mapping, data_ptr, data_len)?;
        ctx.object_cache.insert(object_id, data);

        Ok(0)
    }
);

// ===== SubTask 15.3: object_create =====

declare_builtin_function!(
    /// 创建新对象，返回 ObjectID。
    ///
    /// ObjectID 生成：`(caller_address, creation_nonce)`，其中 `creation_nonce`
    /// 由 `block_height << 20 | created_objects.len()` 确定性生成。
    ///
    /// # 参数
    /// - `data_ptr` / `data_len`：对象初始数据，位于 heap region
    /// - `out_id_ptr` / `out_id_len`：ObjectID 输出缓冲区（28 字节），位于 heap region
    /// - `arg5`：未使用
    ///
    /// # 返回
    /// - 成功：0
    /// - 失败：`ObjectTooLarge` / `OutOfGas` / `HeapAccessViolation`
    ///
    /// # Gas
    /// `20 + 1 * data_len`（IMPL-SEC-4：(6)）
    SyscallObjectCreate,
    fn rust(
        ctx: &mut PokerL1Context,
        data_ptr: u64,
        data_len: u64,
        out_id_ptr: u64,
        out_id_len: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        // IMPL-SEC-4 (4)：校验指针位于 heap region
        validate_heap_ptr(data_ptr, data_len)?;
        validate_heap_ptr(out_id_ptr, out_id_len)?;

        // IMPL-SEC-4 (7)：Object ≤ 64KB
        // M-8 修复：在 u64 域比较，避免 32-bit 平台 `as usize` 截断绕过上限
        if data_len > MAX_OBJECT_SIZE as u64 {
            return Err(to_syscall_err(PokerL1Error::ObjectTooLarge {
                actual: data_len as usize,
                limit: MAX_OBJECT_SIZE,
            }));
        }

        // 校验 out_id_len
        if out_id_len != 28 {
            return Err(to_syscall_err(PokerL1Error::InvalidSyscallArgument(format!(
                "object_create: out_id_len must be 28, got {out_id_len}"
            ))));
        }

        // IMPL-SEC-4 (5)(6)：执行前扣费
        let gas = object_create_gas(data_len);
        charge_gas(ctx, gas)?;

        // 生成 ObjectID（确定性：caller + block_height + tx.nonce + 本次调用内计数器）
        // H-3 修复：加入 tx.nonce 防止同一 caller 在同一 block 内多笔 tx 产生 ObjectID 碰撞
        let creation_nonce = ctx
            .tx
            .block_height
            .wrapping_shl(40)
            .wrapping_add(ctx.tx.nonce.wrapping_shl(20))
            .wrapping_add(ctx.created_objects.len() as u64);
        let object_id = ObjectID::new(ctx.tx.caller, creation_nonce);

        // 读取数据并写入 cache
        let data = read_vm_memory(memory_mapping, data_ptr, data_len)?;
        ctx.object_cache.insert(object_id, data);
        ctx.record_created_object(object_id);

        // 写入 ObjectID 到输出缓冲区
        write_vm_memory(memory_mapping, out_id_ptr, &object_id.to_bytes())?;

        Ok(0)
    }
);

// ===== SubTask 15.4: emit_event =====

declare_builtin_function!(
    /// 发射事件。
    ///
    /// # 参数
    /// - `payload_ptr` / `payload_len`：事件 payload，位于 heap region（≤ 16KB）
    /// - `arg3` / `arg4` / `arg5`：未使用
    ///
    /// # 返回
    /// - 成功：0
    /// - 失败：`EventTooLarge` / `OutOfGas` / `HeapAccessViolation`
    ///
    /// # Gas
    /// `10 + 1 * payload_len`（IMPL-SEC-4：(6)）
    SyscallEmitEvent,
    fn rust(
        ctx: &mut PokerL1Context,
        payload_ptr: u64,
        payload_len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        // IMPL-SEC-4 (4)：校验指针位于 heap region
        validate_heap_ptr(payload_ptr, payload_len)?;

        // IMPL-SEC-4 (6)：payload ≤ 16KB
        // M-8 修复：在 u64 域比较，避免 32-bit 平台 `as usize` 截断绕过上限
        if payload_len > MAX_EVENT_PAYLOAD_SIZE as u64 {
            return Err(to_syscall_err(PokerL1Error::EventTooLarge {
                actual: payload_len as usize,
                limit: MAX_EVENT_PAYLOAD_SIZE,
            }));
        }

        // IMPL-SEC-4 (5)(6)：执行前扣费
        let gas = emit_event_gas(payload_len);
        charge_gas(ctx, gas)?;

        // 读取 payload 并记录事件
        let payload = read_vm_memory(memory_mapping, payload_ptr, payload_len)?;
        ctx.emit_event(payload);

        Ok(0)
    }
);

// ===== SubTask 15.5: log / panic =====

declare_builtin_function!(
    /// 记录日志消息。
    ///
    /// # 参数
    /// - `msg_ptr` / `msg_len`：消息内容（UTF-8），位于 heap region
    /// - `arg3` / `arg4` / `arg5`：未使用
    ///
    /// # 返回
    /// - 成功：0
    ///
    /// # Gas
    /// 10
    SyscallLog,
    fn rust(
        ctx: &mut PokerL1Context,
        msg_ptr: u64,
        msg_len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        // IMPL-SEC-4 (4)：校验指针位于 heap region
        validate_heap_ptr(msg_ptr, msg_len)?;

        // 扣费
        charge_gas(ctx, GAS_LOG)?;

        // 读取消息并记录（tracing 默认关闭，此处仅消费 gas）
        let _msg = read_vm_memory(memory_mapping, msg_ptr, msg_len)?;

        Ok(0)
    }
);

declare_builtin_function!(
    /// 合约 panic — 记录消息并 trap VM。
    ///
    /// # 参数
    /// - `msg_ptr` / `msg_len`：panic 消息（UTF-8），位于 heap region
    /// - `arg3` / `arg4` / `arg5`：未使用
    ///
    /// # 返回
    /// - 始终返回 `Err(SyscallPanic)`，VM trap
    ///
    /// # Gas
    /// 10
    SyscallPanic,
    fn rust(
        ctx: &mut PokerL1Context,
        msg_ptr: u64,
        msg_len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        // IMPL-SEC-4 (4)：校验指针位于 heap region
        validate_heap_ptr(msg_ptr, msg_len)?;

        // 扣费
        charge_gas(ctx, GAS_PANIC)?;

        // 读取消息
        let msg_bytes = read_vm_memory(memory_mapping, msg_ptr, msg_len)?;
        let msg = String::from_utf8_lossy(&msg_bytes).into_owned();

        // 记录 panic 并返回错误（trap VM）
        ctx.panic(msg.clone());
        Err(to_syscall_err(PokerL1Error::SyscallPanic(msg)))
    }
);

// ===== SubTask 15.6: verify_signature =====

declare_builtin_function!(
    /// 统一签名验证（按 tagged pubkey tag 路由到 secp256k1 / ed25519）。
    ///
    /// # 参数
    /// - `pubkey_ptr` / `pubkey_len`：tagged pubkey 字节（1B tag || raw pubkey）
    /// - `sig_ptr` / `sig_len`：签名字节
    /// - `msg_hash_ptr`：32 字节消息哈希
    ///
    /// # 返回
    /// - 0：验证通过
    /// - 1：验证失败（签名不匹配）
    /// - Err：参数无效 / gas 不足
    ///
    /// # Gas
    /// 500（`GAS_SECP256K1_VERIFY`，R3-M3 修正）
    SyscallVerifySignature,
    fn rust(
        ctx: &mut PokerL1Context,
        pubkey_ptr: u64,
        pubkey_len: u64,
        sig_ptr: u64,
        sig_len: u64,
        msg_hash_ptr: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        // IMPL-SEC-4 (4)：校验指针位于 heap region
        validate_heap_ptr(pubkey_ptr, pubkey_len)?;
        validate_heap_ptr(sig_ptr, sig_len)?;
        validate_heap_ptr(msg_hash_ptr, 32)?;

        // 扣费（固定 500 gas）
        charge_gas(ctx, GAS_SECP256K1_VERIFY)?;

        // 读取数据
        let pubkey_bytes = read_vm_memory(memory_mapping, pubkey_ptr, pubkey_len)?;
        let sig_bytes = read_vm_memory(memory_mapping, sig_ptr, sig_len)?;
        let msg_hash_bytes = read_vm_memory(memory_mapping, msg_hash_ptr, 32)?;

        // 解析 tagged pubkey
        if pubkey_bytes.is_empty() {
            return Ok(1); // 验证失败
        }
        let tag = pubkey_bytes[0];
        let raw = pubkey_bytes[1..].to_vec();
        let tagged_pubkey = TaggedPubkey { tag, raw };

        // msg_hash 转 [u8; 32]
        let mut msg_hash = [0u8; 32];
        msg_hash.copy_from_slice(&msg_hash_bytes);

        // 调用统一签名验证
        match verify_signature(&tagged_pubkey, &sig_bytes, &msg_hash) {
            Ok(()) => Ok(0),
            Err(_) => Ok(1),
        }
    }
);

// ===== SubTask 15.7: get_block_height / get_timestamp =====

declare_builtin_function!(
    /// 查询当前 block height。
    ///
    /// # 返回
    /// - 当前 block height（u64）
    ///
    /// # Gas
    /// 1
    SyscallGetBlockHeight,
    fn rust(
        ctx: &mut PokerL1Context,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        charge_gas(ctx, GAS_GET_BLOCK_HEIGHT)?;
        Ok(ctx.tx.block_height)
    }
);

declare_builtin_function!(
    /// 查询当前 block timestamp（毫秒）。
    ///
    /// # 返回
    /// - 当前 block timestamp（u64，毫秒）
    ///
    /// # Gas
    /// 1
    SyscallGetTimestamp,
    fn rust(
        ctx: &mut PokerL1Context,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        charge_gas(ctx, GAS_GET_TIMESTAMP)?;
        Ok(ctx.tx.block_timestamp)
    }
);

// ===== SubTask 15.8: verify_failure_proof =====

/// `verify_failure_proof` 输入布局：
///
/// | 偏移  | 长度  | 字段                |
/// |-------|-------|---------------------|
/// | 0     | 32    | expected SMT root   |
/// | 32    | 32    | key hash            |
/// | 64    | 变长  | BCS-encoded MerklePath |
const FAILURE_PROOF_HEADER_SIZE: usize = 64;

declare_builtin_function!(
    /// 验证 SMT 非包含证明（SEC-H9 修复 — 256-bit sparse Merkle 非包含证明）。
    ///
    /// # 参数
    /// - `proof_ptr` / `proof_len`：证明数据，位于 heap region
    ///   - bytes 0..32：expected SMT root
    ///   - bytes 32..64：key hash（待证明不存在的 key）
    ///   - bytes 64..：BCS-serialized [`MerklePath`]
    /// - `arg3` / `arg4` / `arg5`：未使用
    ///
    /// # 返回
    /// - 0：证明有效（key 确实不在 tree 中）
    /// - 1：证明无效
    /// - Err：参数无效 / gas 不足
    ///
    /// # Gas
    /// 80000（SEC-H9 修复 — 含 256 层路径验证 + 多签验证预留）
    SyscallVerifyFailureProof,
    fn rust(
        ctx: &mut PokerL1Context,
        proof_ptr: u64,
        proof_len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        // IMPL-SEC-4 (4)：校验指针位于 heap region
        validate_heap_ptr(proof_ptr, proof_len)?;

        // 扣费（固定 80000 gas，SEC-H9）
        charge_gas(ctx, GAS_VERIFY_FAILURE_PROOF)?;

        // 校验最小长度
        // M-8 修复：在 u64 域比较，避免 32-bit 平台 `as usize` 截断导致大值绕过下限检查
        if proof_len < FAILURE_PROOF_HEADER_SIZE as u64 {
            return Ok(1); // 证明无效
        }

        // 读取证明数据
        let proof_bytes = read_vm_memory(memory_mapping, proof_ptr, proof_len)?;

        // 解析 header
        let mut root = [0u8; 32];
        root.copy_from_slice(&proof_bytes[..32]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&proof_bytes[32..64]);

        // BCS 反序列化 MerklePath
        let path: MerklePath = match borsh::from_slice(&proof_bytes[FAILURE_PROOF_HEADER_SIZE..]) {
            Ok(p) => p,
            Err(_) => return Ok(1), // 反序列化失败 → 证明无效
        };

        // 调用 SMT 验证（非包含：value=None, is_empty_leaf=true）
        // 注意：SEC-H9 完整规范还包括多签验证，此处仅验证 SMT 非包含证明。
        // 多签验证将在 Phase 5c（争议解决）中集成。
        let valid = SparseMerkleTree::verify(&root, &key, None, &path);

        Ok(if valid { 0 } else { 1 })
    }
);

// 为了使用 SparseMerkleTree::verify，需要引入
use crate::object_model::smt::SparseMerkleTree;

// ===== SubTask 22.2: zk_verify syscall（Phase 5a） =====
//
// 严格遵循 spec.md L493–525 + L853–857（FROZEN 2026-06-27）：
// - 通用 `zk_verify(scheme_id, proof, public_io) -> bool` 入口
// - gas 按 scheme 分派（zk_verify_gas：Stwo=300000 / Groth16=20000 / IPA=15000）
// - 通过 ctx.zk_verifier 注入 ZkVerifierRegistry（None → ZkVerifierNotRegistered）
// - Stub 状态下仅校验 proof 格式（verifier_status 由 registry 管理）

use crate::offline::zk_verifier::{MAX_ZK_PROOF_BYTES, ZkPublicIo, ZkVerifierRegistry};

/// `zk_verify` public_io 最大字节数（防 DoS，segment_continuity_proof 上限）。
const MAX_ZK_PUBLIC_IO_BYTES: u64 = 64 * 1024;

declare_builtin_function!(
    /// 通用 ZK 证明验证 syscall（Task 22.2）。
    ///
    /// # 参数
    /// - `scheme_id`：ZK scheme 标识（低 32 位有效）
    ///   - `1` = Stwo（历史名 Hypernova，已废弃）, `2` = Groth16, `3` = IPA
    /// - `proof_ptr` / `proof_len`：proof 字节，位于 heap region
    /// - `public_io_ptr` / `public_io_len`：[`ZkPublicIo`] 序列化字节，位于 heap region
    ///
    /// # 返回
    /// - 0：验证通过（proof 合法）
    /// - 1：验证失败（proof 不合法或验证不通过）
    /// - Err：参数无效 / gas 不足 / verifier 未注册 / registry 未注入
    ///
    /// # Gas
    /// 按 scheme_id 分派（[`zk_verify_gas`]）：
    /// - Stwo → 300000
    /// - Groth16 → 20000
    /// - IPA → 15000
    SyscallZkVerify,
    fn rust(
        ctx: &mut PokerL1Context,
        scheme_id_raw: u64,
        proof_ptr: u64,
        proof_len: u64,
        public_io_ptr: u64,
        public_io_len: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        // IMPL-SEC-4 (4)：校验指针位于 heap region
        validate_heap_ptr(proof_ptr, proof_len)?;
        validate_heap_ptr(public_io_ptr, public_io_len)?;

        // 长度上限校验（防 DoS）
        if proof_len > MAX_ZK_PROOF_BYTES as u64 {
            return Err(to_syscall_err(PokerL1Error::InputTooLong {
                actual: proof_len as usize,
                limit: MAX_ZK_PROOF_BYTES,
            }));
        }
        if public_io_len > MAX_ZK_PUBLIC_IO_BYTES {
            return Err(to_syscall_err(PokerL1Error::InputTooLong {
                actual: public_io_len as usize,
                limit: MAX_ZK_PUBLIC_IO_BYTES as usize,
            }));
        }

        // scheme_id 取低 32 位
        let scheme_id = scheme_id_raw as u32;

        // 扣费（按 scheme 分派）
        charge_gas(ctx, zk_verify_gas(scheme_id))?;

        // 读取 proof + public_io
        let proof_bytes = read_vm_memory(memory_mapping, proof_ptr, proof_len)?;
        let public_io_bytes = read_vm_memory(memory_mapping, public_io_ptr, public_io_len)?;

        // 反序列化 public_io
        let public_io = ZkPublicIo::from_bytes(&public_io_bytes).ok_or_else(|| {
            to_syscall_err(PokerL1Error::InvalidZkPublicIo(
                "public_io 反序列化失败：长度不足或格式错误".to_string(),
            ))
        })?;

        // 获取 registry（未注入 → 错误）
        let registry: &ZkVerifierRegistry = ctx.zk_verifier.as_ref().ok_or_else(|| {
            to_syscall_err(PokerL1Error::ZkVerifierNotRegistered(scheme_id))
        })?;

        // 调用 registry.zk_verify
        // max_skip_segments = 3（默认，SubTask 27.11）
        // max_ack_chain_length = DEFAULT_MAX_ACK_CHAIN_LENGTH（默认 1000）
        const DEFAULT_MAX_SKIP_SEGMENTS: u32 = 3;
        let result = registry.zk_verify(
            ctx.tx.chain_id,
            scheme_id,
            &proof_bytes,
            &public_io,
            DEFAULT_MAX_SKIP_SEGMENTS,
            crate::offline::DEFAULT_MAX_ACK_CHAIN_LENGTH,
        );

        match result {
            Ok(r) => Ok(if r.verified { 0 } else { 1 }),
            // verifier 未注册 / public_io 边界违规 / proof 格式错误 → Err（trap VM）
            Err(e) => Err(to_syscall_err(e)),
        }
    }
);

// ===== SubTask 19.1 ~ 19.3: BLS12-381 预编译 syscalls =====
//
// 严格遵循 spec.md（FROZEN 2026-06-27）+ Task 19：
// - SubTask 19.1：注册到 rBPF syscall table
// - SubTask 19.2：序列化格式（compressed bytes 48 / 96 / 288）
// - SubTask 19.3：gas 计费按 worst-case（g1_mul=500，pairing=5000，hash=1000+10*B）
//
// 所有 G1/G2 输入通过 `from_compressed` 内含子群检查（DoS 防护）。
// GameTurn 通道免 gas（与其它 syscall 一致）。

/// 读取 G1 compressed point（48 字节）从 VM 内存。
fn read_g1_from_vm(
    memory_mapping: &mut MemoryMapping,
    ptr: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    validate_heap_ptr(ptr, bls::G1_COMPRESSED_SIZE as u64)?;
    read_vm_memory(memory_mapping, ptr, bls::G1_COMPRESSED_SIZE as u64)
}

/// 读取 G2 compressed point（96 字节）从 VM 内存。
fn read_g2_from_vm(
    memory_mapping: &mut MemoryMapping,
    ptr: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    validate_heap_ptr(ptr, bls::G2_COMPRESSED_SIZE as u64)?;
    read_vm_memory(memory_mapping, ptr, bls::G2_COMPRESSED_SIZE as u64)
}

/// 读取 GT compressed（288 字节）从 VM 内存。
fn read_gt_from_vm(
    memory_mapping: &mut MemoryMapping,
    ptr: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    validate_heap_ptr(ptr, bls::GT_COMPRESSED_SIZE as u64)?;
    read_vm_memory(memory_mapping, ptr, bls::GT_COMPRESSED_SIZE as u64)
}

/// 读取 Scalar（32 字节）从 VM 内存。
fn read_scalar_from_vm(
    memory_mapping: &mut MemoryMapping,
    ptr: u64,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    validate_heap_ptr(ptr, bls::SCALAR_SIZE as u64)?;
    read_vm_memory(memory_mapping, ptr, bls::SCALAR_SIZE as u64)
}

use crate::crypto_precompiles::bls;

declare_builtin_function!(
    /// `bls12_381_g1_add(a_ptr, b_ptr, out_ptr)` — G1 点加法（含子群检查）。
    ///
    /// # 参数
    /// - `a_ptr`：G1 compressed（48 字节），位于 heap region
    /// - `b_ptr`：G1 compressed（48 字节），位于 heap region
    /// - `out_ptr`：输出缓冲区（48 字节），位于 heap region
    ///
    /// # 返回
    /// - 0：成功
    /// - Err：子群检查失败 / gas 不足 / heap 违规
    ///
    /// # Gas
    /// 500（`GAS_BLS_G1_ADD`）
    SyscallBlsG1Add,
    fn rust(
        ctx: &mut PokerL1Context,
        a_ptr: u64,
        b_ptr: u64,
        out_ptr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let a = read_g1_from_vm(memory_mapping, a_ptr)?;
        let b = read_g1_from_vm(memory_mapping, b_ptr)?;
        validate_heap_ptr(out_ptr, bls::G1_COMPRESSED_SIZE as u64)?;

        charge_gas(ctx, GAS_BLS_G1_ADD)?;

        let result = bls::bls_g1_add(&a, &b).map_err(to_syscall_err)?;
        write_vm_memory(memory_mapping, out_ptr, &result)?;
        Ok(0)
    }
);

declare_builtin_function!(
    /// `bls12_381_g1_mul(point_ptr, scalar_ptr, out_ptr)` — G1 标量乘法（含子群检查）。
    ///
    /// # 参数
    /// - `point_ptr`：G1 compressed（48 字节），位于 heap region
    /// - `scalar_ptr`：Scalar（32 字节，大端序），位于 heap region
    /// - `out_ptr`：输出缓冲区（48 字节），位于 heap region
    ///
    /// # Gas
    /// 500（`GAS_BLS_G1_MUL`）
    SyscallBlsG1Mul,
    fn rust(
        ctx: &mut PokerL1Context,
        point_ptr: u64,
        scalar_ptr: u64,
        out_ptr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let point = read_g1_from_vm(memory_mapping, point_ptr)?;
        let scalar = read_scalar_from_vm(memory_mapping, scalar_ptr)?;
        validate_heap_ptr(out_ptr, bls::G1_COMPRESSED_SIZE as u64)?;

        charge_gas(ctx, GAS_BLS_G1_MUL)?;

        let result = bls::bls_g1_mul(&point, &scalar).map_err(to_syscall_err)?;
        write_vm_memory(memory_mapping, out_ptr, &result)?;
        Ok(0)
    }
);

declare_builtin_function!(
    /// `bls12_381_g1_neg(point_ptr, out_ptr)` — G1 取负（含子群检查）。
    ///
    /// # Gas
    /// 500（`GAS_BLS_G1_NEG`）
    SyscallBlsG1Neg,
    fn rust(
        ctx: &mut PokerL1Context,
        point_ptr: u64,
        out_ptr: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let point = read_g1_from_vm(memory_mapping, point_ptr)?;
        validate_heap_ptr(out_ptr, bls::G1_COMPRESSED_SIZE as u64)?;

        charge_gas(ctx, GAS_BLS_G1_NEG)?;

        let result = bls::bls_g1_neg(&point).map_err(to_syscall_err)?;
        write_vm_memory(memory_mapping, out_ptr, &result)?;
        Ok(0)
    }
);

declare_builtin_function!(
    /// `bls12_381_g2_add(a_ptr, b_ptr, out_ptr)` — G2 点加法（含子群检查）。
    ///
    /// # Gas
    /// 500（`GAS_BLS_G2_ADD`）
    SyscallBlsG2Add,
    fn rust(
        ctx: &mut PokerL1Context,
        a_ptr: u64,
        b_ptr: u64,
        out_ptr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let a = read_g2_from_vm(memory_mapping, a_ptr)?;
        let b = read_g2_from_vm(memory_mapping, b_ptr)?;
        validate_heap_ptr(out_ptr, bls::G2_COMPRESSED_SIZE as u64)?;

        charge_gas(ctx, GAS_BLS_G2_ADD)?;

        let result = bls::bls_g2_add(&a, &b).map_err(to_syscall_err)?;
        write_vm_memory(memory_mapping, out_ptr, &result)?;
        Ok(0)
    }
);

declare_builtin_function!(
    /// `bls12_381_g2_mul(point_ptr, scalar_ptr, out_ptr)` — G2 标量乘法（含子群检查）。
    ///
    /// # Gas
    /// 500（`GAS_BLS_G2_MUL`）
    SyscallBlsG2Mul,
    fn rust(
        ctx: &mut PokerL1Context,
        point_ptr: u64,
        scalar_ptr: u64,
        out_ptr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let point = read_g2_from_vm(memory_mapping, point_ptr)?;
        let scalar = read_scalar_from_vm(memory_mapping, scalar_ptr)?;
        validate_heap_ptr(out_ptr, bls::G2_COMPRESSED_SIZE as u64)?;

        charge_gas(ctx, GAS_BLS_G2_MUL)?;

        let result = bls::bls_g2_mul(&point, &scalar).map_err(to_syscall_err)?;
        write_vm_memory(memory_mapping, out_ptr, &result)?;
        Ok(0)
    }
);

declare_builtin_function!(
    /// `bls12_381_g2_neg(point_ptr, out_ptr)` — G2 取负（含子群检查）。
    ///
    /// # Gas
    /// 500（`GAS_BLS_G2_NEG`）
    SyscallBlsG2Neg,
    fn rust(
        ctx: &mut PokerL1Context,
        point_ptr: u64,
        out_ptr: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let point = read_g2_from_vm(memory_mapping, point_ptr)?;
        validate_heap_ptr(out_ptr, bls::G2_COMPRESSED_SIZE as u64)?;

        charge_gas(ctx, GAS_BLS_G2_NEG)?;

        let result = bls::bls_g2_neg(&point).map_err(to_syscall_err)?;
        write_vm_memory(memory_mapping, out_ptr, &result)?;
        Ok(0)
    }
);

declare_builtin_function!(
    /// `bls12_381_pairing_check(a_g1_ptr, b_g2_ptr, c_g1_ptr, d_g2_ptr)` — 双线性配对检查。
    ///
    /// 对所有 4 个输入做子群检查，失败返回 Err（DoS 防护）。
    ///
    /// # 返回
    /// - 0：`e(a,b) == e(c,d)` 成立
    /// - 1：不成立
    /// - Err：子群检查失败 / gas 不足 / heap 违规
    ///
    /// # Gas
    /// 5000（`GAS_BLS_PAIRING`，worst-case）
    SyscallBlsPairingCheck,
    fn rust(
        ctx: &mut PokerL1Context,
        a_g1_ptr: u64,
        b_g2_ptr: u64,
        c_g1_ptr: u64,
        d_g2_ptr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let a = read_g1_from_vm(memory_mapping, a_g1_ptr)?;
        let b = read_g2_from_vm(memory_mapping, b_g2_ptr)?;
        let c = read_g1_from_vm(memory_mapping, c_g1_ptr)?;
        let d = read_g2_from_vm(memory_mapping, d_g2_ptr)?;

        charge_gas(ctx, GAS_BLS_PAIRING)?;

        let equal = bls::bls_pairing_check(&a, &b, &c, &d).map_err(to_syscall_err)?;
        Ok(if equal { 0 } else { 1 })
    }
);

declare_builtin_function!(
    /// `bls12_381_hash_to_g1(msg_ptr, msg_len, out_ptr)` — RFC 9380 hash to G1。
    ///
    /// SEC2-L2 修复：DST 固定，runtime 自动附加，不允许合约自定义。
    ///
    /// # Gas
    /// `1000 + 10 * msg_len`（`bls_hash_to_g1_gas`）
    SyscallBlsHashToG1,
    fn rust(
        ctx: &mut PokerL1Context,
        msg_ptr: u64,
        msg_len: u64,
        out_ptr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        validate_heap_ptr(msg_ptr, msg_len)?;
        validate_heap_ptr(out_ptr, bls::G1_COMPRESSED_SIZE as u64)?;

        // 先校验 msg 长度（避免 read 巨量数据前提前拒绝）
        // M-8 修复：check_bls_hash_msg_len 现接受 u64，避免 32-bit 截断
        check_bls_hash_msg_len(msg_len).map_err(to_syscall_err)?;

        // gas 按字节线性计费（worst-case）
        charge_gas(ctx, bls_hash_to_g1_gas(msg_len))?;

        let msg = read_vm_memory(memory_mapping, msg_ptr, msg_len)?;
        let result = bls::bls_hash_to_g1(&msg).map_err(to_syscall_err)?;
        write_vm_memory(memory_mapping, out_ptr, &result)?;
        Ok(0)
    }
);

declare_builtin_function!(
    /// `bls12_381_hash_to_g2(msg_ptr, msg_len, out_ptr)` — RFC 9380 hash to G2。
    ///
    /// # Gas
    /// `1000 + 10 * msg_len`（`bls_hash_to_g2_gas`）
    SyscallBlsHashToG2,
    fn rust(
        ctx: &mut PokerL1Context,
        msg_ptr: u64,
        msg_len: u64,
        out_ptr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        validate_heap_ptr(msg_ptr, msg_len)?;
        validate_heap_ptr(out_ptr, bls::G2_COMPRESSED_SIZE as u64)?;

        // M-8 修复：check_bls_hash_msg_len 现接受 u64，避免 32-bit 截断
        check_bls_hash_msg_len(msg_len).map_err(to_syscall_err)?;

        charge_gas(ctx, bls_hash_to_g2_gas(msg_len))?;

        let msg = read_vm_memory(memory_mapping, msg_ptr, msg_len)?;
        let result = bls::bls_hash_to_g2(&msg).map_err(to_syscall_err)?;
        write_vm_memory(memory_mapping, out_ptr, &result)?;
        Ok(0)
    }
);

declare_builtin_function!(
    /// `bls12_381_miller_loop(a_g1_ptr, b_g2_ptr, out_ptr)` — Miller loop + final exp。
    ///
    /// 注意：blstrs `MillerLoopResult` 不可序列化，因此本函数执行完整 pairing
    /// （miller + final_exp）并返回 GT compressed bytes（288 字节）。
    ///
    /// # Gas
    /// 2000（`GAS_BLS_MILLER_LOOP`）
    SyscallBlsMillerLoop,
    fn rust(
        ctx: &mut PokerL1Context,
        a_g1_ptr: u64,
        b_g2_ptr: u64,
        out_ptr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let a = read_g1_from_vm(memory_mapping, a_g1_ptr)?;
        let b = read_g2_from_vm(memory_mapping, b_g2_ptr)?;
        validate_heap_ptr(out_ptr, bls::GT_COMPRESSED_SIZE as u64)?;

        charge_gas(ctx, GAS_BLS_MILLER_LOOP)?;

        let result = bls::bls_miller_loop(&a, &b).map_err(to_syscall_err)?;
        write_vm_memory(memory_mapping, out_ptr, &result)?;
        Ok(0)
    }
);

declare_builtin_function!(
    /// `bls12_381_final_exp(gt_ptr, out_ptr)` — Final exponentiation（identity）。
    ///
    /// 由于 `miller_loop` 已执行完整 pairing，本函数为 identity（仅校验 GT 反序列化）。
    /// 保留以满足 SubTask 18.5 API 完整性。
    ///
    /// # Gas
    /// 1000（`GAS_BLS_FINAL_EXP`）
    SyscallBlsFinalExp,
    fn rust(
        ctx: &mut PokerL1Context,
        gt_ptr: u64,
        out_ptr: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let gt = read_gt_from_vm(memory_mapping, gt_ptr)?;
        validate_heap_ptr(out_ptr, bls::GT_COMPRESSED_SIZE as u64)?;

        charge_gas(ctx, GAS_BLS_FINAL_EXP)?;

        let result = bls::bls_final_exp(&gt).map_err(to_syscall_err)?;
        write_vm_memory(memory_mapping, out_ptr, &result)?;
        Ok(0)
    }
);

// ===== Syscall 注册 =====

/// 注册 Poker L1 全部核心 syscalls 到 [`FunctionRegistry`]。
///
/// 在 [`crate::vm::loader::load_contract_bytecode`] 中调用，
/// 使所有合约可调用以下 syscalls：
///
/// | Syscall name            | 对应结构体                  |
/// |-------------------------|-----------------------------|
/// | `object_read`           | [`SyscallObjectRead`]       |
/// | `object_write`          | [`SyscallObjectWrite`]      |
/// | `object_create`         | [`SyscallObjectCreate`]     |
/// | `emit_event`            | [`SyscallEmitEvent`]        |
/// | `log`                   | [`SyscallLog`]              |
/// | `panic`                 | [`SyscallPanic`]            |
/// | `verify_signature`      | [`SyscallVerifySignature`]  |
/// | `get_block_height`      | [`SyscallGetBlockHeight`]   |
/// | `get_timestamp`         | [`SyscallGetTimestamp`]     |
/// | `verify_failure_proof`  | [`SyscallVerifyFailureProof`] |
/// | `zk_verify`             | [`SyscallZkVerify`]          |
/// | `bls12_381_g1_add`      | [`SyscallBlsG1Add`]         |
/// | `bls12_381_g1_mul`      | [`SyscallBlsG1Mul`]         |
/// | `bls12_381_g1_neg`      | [`SyscallBlsG1Neg`]         |
/// | `bls12_381_g2_add`      | [`SyscallBlsG2Add`]         |
/// | `bls12_381_g2_mul`      | [`SyscallBlsG2Mul`]         |
/// | `bls12_381_g2_neg`      | [`SyscallBlsG2Neg`]         |
/// | `bls12_381_pairing_check` | [`SyscallBlsPairingCheck`] |
/// | `bls12_381_hash_to_g1`  | [`SyscallBlsHashToG1`]      |
/// | `bls12_381_hash_to_g2`  | [`SyscallBlsHashToG2`]      |
/// | `bls12_381_miller_loop` | [`SyscallBlsMillerLoop`]    |
/// | `bls12_381_final_exp`   | [`SyscallBlsFinalExp`]      |
pub fn register_poker_l1_syscalls(
    registry: &mut FunctionRegistry<BuiltinFunction<PokerL1Context>>,
) -> Result<(), PokerL1Error> {
    registry
        .register_function_hashed(*b"object_read", SyscallObjectRead::vm)
        .map_err(|e| PokerL1Error::Other(format!("register object_read: {e}")))?;
    registry
        .register_function_hashed(*b"object_write", SyscallObjectWrite::vm)
        .map_err(|e| PokerL1Error::Other(format!("register object_write: {e}")))?;
    registry
        .register_function_hashed(*b"object_create", SyscallObjectCreate::vm)
        .map_err(|e| PokerL1Error::Other(format!("register object_create: {e}")))?;
    registry
        .register_function_hashed(*b"emit_event", SyscallEmitEvent::vm)
        .map_err(|e| PokerL1Error::Other(format!("register emit_event: {e}")))?;
    registry
        .register_function_hashed(*b"log", SyscallLog::vm)
        .map_err(|e| PokerL1Error::Other(format!("register log: {e}")))?;
    registry
        .register_function_hashed(*b"panic", SyscallPanic::vm)
        .map_err(|e| PokerL1Error::Other(format!("register panic: {e}")))?;
    registry
        .register_function_hashed(*b"verify_signature", SyscallVerifySignature::vm)
        .map_err(|e| PokerL1Error::Other(format!("register verify_signature: {e}")))?;
    registry
        .register_function_hashed(*b"get_block_height", SyscallGetBlockHeight::vm)
        .map_err(|e| PokerL1Error::Other(format!("register get_block_height: {e}")))?;
    registry
        .register_function_hashed(*b"get_timestamp", SyscallGetTimestamp::vm)
        .map_err(|e| PokerL1Error::Other(format!("register get_timestamp: {e}")))?;
    registry
        .register_function_hashed(*b"verify_failure_proof", SyscallVerifyFailureProof::vm)
        .map_err(|e| PokerL1Error::Other(format!("register verify_failure_proof: {e}")))?;

    // Task 22.2 — 通用 ZK 证明验证 syscall（Phase 5a）
    registry
        .register_function_hashed(*b"zk_verify", SyscallZkVerify::vm)
        .map_err(|e| PokerL1Error::Other(format!("register zk_verify: {e}")))?;

    // Task 19 — BLS12-381 预编译 syscalls（含子群检查）
    registry
        .register_function_hashed(*b"bls12_381_g1_add", SyscallBlsG1Add::vm)
        .map_err(|e| PokerL1Error::Other(format!("register bls12_381_g1_add: {e}")))?;
    registry
        .register_function_hashed(*b"bls12_381_g1_mul", SyscallBlsG1Mul::vm)
        .map_err(|e| PokerL1Error::Other(format!("register bls12_381_g1_mul: {e}")))?;
    registry
        .register_function_hashed(*b"bls12_381_g1_neg", SyscallBlsG1Neg::vm)
        .map_err(|e| PokerL1Error::Other(format!("register bls12_381_g1_neg: {e}")))?;
    registry
        .register_function_hashed(*b"bls12_381_g2_add", SyscallBlsG2Add::vm)
        .map_err(|e| PokerL1Error::Other(format!("register bls12_381_g2_add: {e}")))?;
    registry
        .register_function_hashed(*b"bls12_381_g2_mul", SyscallBlsG2Mul::vm)
        .map_err(|e| PokerL1Error::Other(format!("register bls12_381_g2_mul: {e}")))?;
    registry
        .register_function_hashed(*b"bls12_381_g2_neg", SyscallBlsG2Neg::vm)
        .map_err(|e| PokerL1Error::Other(format!("register bls12_381_g2_neg: {e}")))?;
    registry
        .register_function_hashed(*b"bls12_381_pairing_check", SyscallBlsPairingCheck::vm)
        .map_err(|e| PokerL1Error::Other(format!("register bls12_381_pairing_check: {e}")))?;
    registry
        .register_function_hashed(*b"bls12_381_hash_to_g1", SyscallBlsHashToG1::vm)
        .map_err(|e| PokerL1Error::Other(format!("register bls12_381_hash_to_g1: {e}")))?;
    registry
        .register_function_hashed(*b"bls12_381_hash_to_g2", SyscallBlsHashToG2::vm)
        .map_err(|e| PokerL1Error::Other(format!("register bls12_381_hash_to_g2: {e}")))?;
    registry
        .register_function_hashed(*b"bls12_381_miller_loop", SyscallBlsMillerLoop::vm)
        .map_err(|e| PokerL1Error::Other(format!("register bls12_381_miller_loop: {e}")))?;
    registry
        .register_function_hashed(*b"bls12_381_final_exp", SyscallBlsFinalExp::vm)
        .map_err(|e| PokerL1Error::Other(format!("register bls12_381_final_exp: {e}")))?;
    Ok(())
}

// ===== 测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::smt::SparseMerkleTree;
    use crate::signature::TaggedPubkey;
    use crate::vm::context::TxContext;
    use solana_rbpf::{
        ebpf,
        memory_region::{MemoryMapping, MemoryRegion},
        program::SBPFVersion,
        vm::Config,
    };

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

    /// 创建测试用 MemoryMapping（仅 heap region）。
    ///
    /// 使用 `aligned_memory_mapping: false` 的 Config，避免 aligned 模式下
    /// 强制 4GB 边界对齐（生产环境由 EbpfVm 提供完整 4 个 region，测试只需 heap）。
    ///
    /// 使用 `Box::leak` 获取 `'static` Config / SBPFVersion 引用，
    /// 避免自引用结构问题。测试场景下少量内存泄漏可接受。
    ///
    /// **注意**：调用方须保证 `heap` 在 MemoryMapping 使用期间不被 resize / drop。
    fn make_test_mapping(heap: &mut [u8]) -> MemoryMapping<'static> {
        let regions = vec![MemoryRegion::new_writable(heap, ebpf::MM_HEAP_START)];
        let config: &'static Config = Box::leak(Box::new(Config {
            aligned_memory_mapping: false,
            ..Config::default()
        }));
        let sbpf_version: &'static SBPFVersion = Box::leak(Box::new(SBPFVersion::V2));
        MemoryMapping::new(regions, config, sbpf_version).expect("MemoryMapping creation")
    }

    /// heap 基地址（VM 虚拟地址）。
    const HEAP_BASE: u64 = ebpf::MM_HEAP_START;

    // ===== SubTask 15.1: object_read 测试 =====

    #[test]
    fn test_object_read_basic() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        // SEC-FIX-1：gas_limit 需覆盖 prepaid（out_capacity=1024 → prepaid=1034）
        let mut ctx = PokerL1Context::new(make_tx_context(), 2000);

        let id = ObjectID::new([1u8; 20], 42);
        ctx.object_cache.insert(id, b"hello world".to_vec());

        heap[..28].copy_from_slice(&id.to_bytes());

        let result = SyscallObjectRead::rust(
            &mut ctx,
            HEAP_BASE,
            28,
            HEAP_BASE + 100,
            1024,
            0,
            &mut mapping,
        )
        .expect("object_read 应成功");

        assert_eq!(result, 11);
        assert_eq!(&heap[100..111], b"hello world");
        // SEC-FIX-1：预扣 1034，退款 1013，净 gas_used = 21（与原语义一致）
        assert_eq!(ctx.gas_used(), 21); // 10 + 11
    }

    #[test]
    fn test_object_read_not_found() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        // SEC-FIX-1：gas 需足够覆盖 prepaid（out_capacity=1024 → prepaid=1034）
        let mut ctx = PokerL1Context::new(make_tx_context(), 2000);

        let id = ObjectID::new([0xff; 20], 999);
        heap[..28].copy_from_slice(&id.to_bytes());

        let result = SyscallObjectRead::rust(
            &mut ctx,
            HEAP_BASE,
            28,
            HEAP_BASE + 100,
            1024,
            0,
            &mut mapping,
        );

        assert!(result.is_err(), "对象不存在应返回错误");
        // SEC-FIX-1：失败调用也消耗 prepaid gas（防免费 DoS）
        // prepaid = 10 + 1024 = 1034，无退款
        assert_eq!(
            ctx.gas_used(),
            1034,
            "ObjectNotFound 应消耗 prepaid gas（DoS 防护）"
        );
    }

    #[test]
    fn test_object_read_out_of_gas() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        // SEC-FIX-1：gas_limit=5 < prepaid(1034)，在预扣阶段即失败
        // 这正是 DoS 防护的体现：gas 不足时连 lookup 都不会执行
        let mut ctx = PokerL1Context::new(make_tx_context(), 5);

        let id = ObjectID::new([1u8; 20], 42);
        ctx.object_cache.insert(id, b"data".to_vec());
        heap[..28].copy_from_slice(&id.to_bytes());

        let result = SyscallObjectRead::rust(
            &mut ctx,
            HEAP_BASE,
            28,
            HEAP_BASE + 100,
            1024,
            0,
            &mut mapping,
        );

        assert!(result.is_err(), "gas 不足应返回错误");
    }

    #[test]
    fn test_object_read_capacity_too_small() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);

        let id = ObjectID::new([1u8; 20], 42);
        ctx.object_cache.insert(id, b"hello world".to_vec());
        heap[..28].copy_from_slice(&id.to_bytes());

        let result = SyscallObjectRead::rust(
            &mut ctx,
            HEAP_BASE,
            28,
            HEAP_BASE + 100,
            5, // out_capacity=5 < data_len=11
            0,
            &mut mapping,
        );

        assert!(result.is_err(), "out_capacity 不足应返回错误");
        // SEC-FIX-1：capacity 不足时消耗 prepaid gas（10 + 5 = 15），无退款
        assert_eq!(
            ctx.gas_used(),
            15,
            "capacity 不足应消耗 prepaid gas（DoS 防护）"
        );
    }

    /// SEC-FIX-1：验证成功读取的 gas 退款正确性。
    ///
    /// out_capacity 远大于 data.len() 时，预扣后应正确退款，
    /// 净 gas_used = object_read_gas(data.len())，与原语义一致。
    #[test]
    fn test_object_read_refund_correctness() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        let id = ObjectID::new([2u8; 20], 7);
        ctx.object_cache.insert(id, b"abc".to_vec()); // data.len() = 3
        heap[..28].copy_from_slice(&id.to_bytes());

        let result = SyscallObjectRead::rust(
            &mut ctx,
            HEAP_BASE,
            28,
            HEAP_BASE + 100,
            2048, // out_capacity 远大于 data.len()=3
            0,
            &mut mapping,
        )
        .expect("object_read 应成功");

        assert_eq!(result, 3);
        // 净 gas: prepaid(10+2048=2058) - refund(2058-13=2045) = 13 = object_read_gas(3)
        assert_eq!(
            ctx.gas_used(),
            13,
            "成功读取应净收 object_read_gas(data.len())=13，预扣退款后余额应正确"
        );
    }

    /// SEC-FIX-1：验证 DoS 防护——攻击者无法免费触发大对象 lookup。
    ///
    /// 场景：攻击者合约对链上已知大对象反复调用 object_read，
    /// 但 gas_limit 不足以覆盖 prepaid。应在 lookup 前即失败，
    /// 节点不执行任何 clone 工作。
    #[test]
    fn test_object_read_dos_protection_large_object() {
        let mut heap = vec![0u8; 65536]; // 64KB heap 模拟大对象场景
        let mut mapping = make_test_mapping(&mut heap);
        // gas_limit 仅够 base fee，不足以覆盖大 out_capacity 预扣
        let mut ctx = PokerL1Context::new(make_tx_context(), 100);

        let id = ObjectID::new([3u8; 20], 1);
        // 模拟链上已知大对象（32KB）
        let large_data = vec![0xABu8; 32768];
        ctx.object_cache.insert(id, large_data);
        heap[..28].copy_from_slice(&id.to_bytes());

        let result = SyscallObjectRead::rust(
            &mut ctx,
            HEAP_BASE,
            28,
            HEAP_BASE + 100,
            32768, // 请求读取 32KB
            0,
            &mut mapping,
        );

        assert!(result.is_err(), "gas 不足以 prepaid 应在 lookup 前失败");
        // SEC-FIX-1：charge_gas 失败时 consume_gas 返回 false，不递减 remaining
        // 关键点是 lookup/clone 未执行（DoS 防护），而非 gas 是否被消耗
        assert_eq!(
            ctx.gas_used(),
            0,
            "gas 不足时 charge_gas 不递减 remaining，但 lookup 未执行"
        );
    }

    #[test]
    fn test_object_read_heap_violation() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);

        // 使用 stack 区域指针（非 heap）
        let result = SyscallObjectRead::rust(
            &mut ctx,
            ebpf::MM_STACK_START,
            28,
            HEAP_BASE + 100,
            1024,
            0,
            &mut mapping,
        );

        assert!(result.is_err(), "非 heap 指针应返回错误");
    }

    // 注：原 `test_object_read_gameturn_gas_free` 测试已移除。
    //
    // 重构后 gas-free precompile 调用经 `PrecompileRegistry::execute` 直接派发，
    // 不经 rBPF VM；进入 rBPF VM 的 syscall 一律按 gas 计费（无 syscall 级免 gas 旁路）。
    // 该行为由 executor.rs 的 lane-contract 一致性校验保障，无需在 syscall 层重测。

    // ===== SubTask 15.2: object_write 测试 =====

    #[test]
    fn test_object_write_basic() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);

        let id = ObjectID::new([1u8; 20], 42);
        // H-5 修复：object_write 须验证 caller 拥有对象。
        // 预填充 object_cache 模拟先前 object_read 获取的对象。
        ctx.object_cache.insert(id, b"old data".to_vec());
        heap[..28].copy_from_slice(&id.to_bytes());
        heap[100..108].copy_from_slice(b"new data");

        let result =
            SyscallObjectWrite::rust(&mut ctx, HEAP_BASE, 28, HEAP_BASE + 100, 8, 0, &mut mapping)
                .expect("object_write 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.object_cache.get(&id).unwrap(), b"new data");
        assert_eq!(ctx.gas_used(), 28); // 20 + 8
    }

    #[test]
    fn test_object_write_too_large() {
        let mut heap = vec![0u8; MAX_OBJECT_SIZE + 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), u64::MAX);

        let id = ObjectID::new([1u8; 20], 42);
        heap[..28].copy_from_slice(&id.to_bytes());

        let result = SyscallObjectWrite::rust(
            &mut ctx,
            HEAP_BASE,
            28,
            HEAP_BASE + 100,
            MAX_OBJECT_SIZE as u64 + 1,
            0,
            &mut mapping,
        );

        assert!(result.is_err(), "超长数据应返回 ObjectTooLarge");
    }

    // ===== SubTask 15.3: object_create 测试 =====

    #[test]
    fn test_object_create_basic() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);

        heap[0..11].copy_from_slice(b"object data");

        let result = SyscallObjectCreate::rust(
            &mut ctx,
            HEAP_BASE,
            11,
            HEAP_BASE + 100,
            28,
            0,
            &mut mapping,
        )
        .expect("object_create 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.created_objects.len(), 1);
        assert_eq!(ctx.gas_used(), 31); // 20 + 11

        let id_bytes = &heap[100..128];
        let object_id = ObjectID::from_bytes(id_bytes).expect("ObjectID 反序列化");
        assert_eq!(object_id.creator_address, ctx.tx.caller);
        assert!(ctx.object_cache.contains_key(&object_id));
    }

    #[test]
    fn test_object_create_multiple_unique_ids() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        heap[0..4].copy_from_slice(b"data");

        let mut ids = Vec::new();
        for i in 0..3u8 {
            let out_offset = 100 + i as usize * 28;
            SyscallObjectCreate::rust(
                &mut ctx,
                HEAP_BASE,
                4,
                HEAP_BASE + out_offset as u64,
                28,
                0,
                &mut mapping,
            )
            .unwrap();
            let id = ObjectID::from_bytes(&heap[out_offset..out_offset + 28]).unwrap();
            ids.push(id);
        }

        assert_eq!(ids.len(), 3);
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
        assert_ne!(ids[0], ids[2]);
    }

    // ===== SubTask 15.4: emit_event 测试 =====

    #[test]
    fn test_emit_event_basic() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);

        heap[0..13].copy_from_slice(b"event payload");

        let result = SyscallEmitEvent::rust(&mut ctx, HEAP_BASE, 13, 0, 0, 0, &mut mapping)
            .expect("emit_event 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.events.len(), 1);
        assert_eq!(ctx.events[0].payload, b"event payload");
        assert_eq!(ctx.gas_used(), 23); // 10 + 13
    }

    #[test]
    fn test_emit_event_too_large() {
        let mut heap = vec![0u8; MAX_EVENT_PAYLOAD_SIZE + 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), u64::MAX);

        let result = SyscallEmitEvent::rust(
            &mut ctx,
            HEAP_BASE,
            MAX_EVENT_PAYLOAD_SIZE as u64 + 1,
            0,
            0,
            0,
            &mut mapping,
        );

        assert!(result.is_err(), "超长 payload 应返回 EventTooLarge");
    }

    // ===== SubTask 15.5: log / panic 测试 =====

    #[test]
    fn test_log_basic() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);

        heap[0..11].copy_from_slice(b"log message");

        let result =
            SyscallLog::rust(&mut ctx, HEAP_BASE, 11, 0, 0, 0, &mut mapping).expect("log 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.gas_used(), GAS_LOG);
    }

    #[test]
    fn test_panic_traps_vm() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);

        heap[0..16].copy_from_slice(b"assertion failed");

        let result = SyscallPanic::rust(&mut ctx, HEAP_BASE, 16, 0, 0, 0, &mut mapping);

        assert!(result.is_err(), "panic 应返回错误 trap VM");
        assert_eq!(
            ctx.panic_message.as_deref(),
            Some("assertion failed"),
            "panic 消息应被记录"
        );
    }

    // ===== SubTask 15.6: verify_signature 测试 =====

    #[test]
    fn test_verify_signature_empty_pubkey() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);

        // 空 pubkey → 验证失败
        heap[100..103].copy_from_slice(b"sig");
        heap[200..232].copy_from_slice(&[0u8; 32]);

        let result = SyscallVerifySignature::rust(
            &mut ctx,
            HEAP_BASE, // pubkey_ptr（len=0，空数据）
            0,
            HEAP_BASE + 100,
            3,
            HEAP_BASE + 200,
            &mut mapping,
        )
        .expect("空 pubkey 应返回 Ok(1) 验证失败");

        assert_eq!(result, 1);
        assert_eq!(ctx.gas_used(), GAS_SECP256K1_VERIFY);
    }

    // ===== SubTask 15.7: get_block_height / get_timestamp 测试 =====

    #[test]
    fn test_get_block_height() {
        let mut heap = vec![0u8; 64];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 100);

        let result = SyscallGetBlockHeight::rust(&mut ctx, 0, 0, 0, 0, 0, &mut mapping)
            .expect("get_block_height 应成功");

        assert_eq!(result, 100);
        assert_eq!(ctx.gas_used(), GAS_GET_BLOCK_HEIGHT);
    }

    #[test]
    fn test_get_timestamp() {
        let mut heap = vec![0u8; 64];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 100);

        let result = SyscallGetTimestamp::rust(&mut ctx, 0, 0, 0, 0, 0, &mut mapping)
            .expect("get_timestamp 应成功");

        assert_eq!(result, 100_000);
        assert_eq!(ctx.gas_used(), GAS_GET_TIMESTAMP);
    }

    // ===== SubTask 15.8: verify_failure_proof 测试 =====

    #[test]
    fn test_verify_failure_proof_valid_non_inclusion() {
        let mut heap = vec![0u8; 16 * 1024];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 100_000);

        // 构造 SMT 并生成非包含证明
        let mut smt = SparseMerkleTree::new();
        let key1 = [0xaa; 32];
        smt.upsert(key1, b"value1");
        let root = smt.root();

        // 对不存在的 key2 生成非包含证明
        let key2 = [0xbb; 32];
        let path = smt.prove(&key2);
        assert!(path.is_empty_leaf, "key2 应为空叶（非包含）");

        let path_bytes = borsh::to_vec(&path).expect("BCS encode MerklePath");

        // 组装 proof：root(32) + key(32) + path_bytes
        let mut proof = Vec::with_capacity(FAILURE_PROOF_HEADER_SIZE + path_bytes.len());
        proof.extend_from_slice(&root);
        proof.extend_from_slice(&key2);
        proof.extend_from_slice(&path_bytes);

        heap[..proof.len()].copy_from_slice(&proof);

        let result = SyscallVerifyFailureProof::rust(
            &mut ctx,
            HEAP_BASE,
            proof.len() as u64,
            0,
            0,
            0,
            &mut mapping,
        )
        .expect("verify_failure_proof 应成功");

        assert_eq!(result, 0, "非包含证明应验证通过");
        assert_eq!(ctx.gas_used(), GAS_VERIFY_FAILURE_PROOF);
    }

    #[test]
    fn test_verify_failure_proof_invalid() {
        let mut heap = vec![0u8; 16 * 1024];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 100_000);

        let mut smt = SparseMerkleTree::new();
        let key1 = [0xaa; 32];
        smt.upsert(key1, b"value1");
        let root = smt.root();

        // 对存在的 key1 生成包含证明，但声称非包含 → 应验证失败
        let path = smt.prove(&key1);
        assert!(!path.is_empty_leaf, "key1 应为非空叶（包含）");

        let path_bytes = borsh::to_vec(&path).unwrap();

        let mut proof = Vec::with_capacity(FAILURE_PROOF_HEADER_SIZE + path_bytes.len());
        proof.extend_from_slice(&root);
        proof.extend_from_slice(&key1);
        proof.extend_from_slice(&path_bytes);

        heap[..proof.len()].copy_from_slice(&proof);

        let result = SyscallVerifyFailureProof::rust(
            &mut ctx,
            HEAP_BASE,
            proof.len() as u64,
            0,
            0,
            0,
            &mut mapping,
        )
        .expect("verify_failure_proof 应成功");

        assert_eq!(result, 1, "包含证明冒充非包含应验证失败");
    }

    #[test]
    fn test_verify_failure_proof_too_short() {
        let mut heap = vec![0u8; 1024];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 100_000);

        // 仅 32 字节（< 64 字节 header）
        let proof = vec![0u8; 32];
        heap[..32].copy_from_slice(&proof);

        let result =
            SyscallVerifyFailureProof::rust(&mut ctx, HEAP_BASE, 32, 0, 0, 0, &mut mapping)
                .expect("应返回 Ok(1) 证明无效");

        assert_eq!(result, 1, "过短的证明应判定无效");
    }

    // ===== SubTask 22.2: zk_verify 测试 =====

    /// 构造测试用 ZkVerifierRegistry（注册 Stwo + Groth16 + IPA test stub）。
    fn make_test_zk_registry() -> crate::offline::zk_verifier::ZkVerifierRegistry {
        let mut registry = crate::offline::zk_verifier::ZkVerifierRegistry::new();
        crate::offline::zk_verifier::register_test_only_stwo_stub_verifier(&mut registry);
        crate::offline::zk_verifier::register_groth16_stub_verifier(&mut registry);
        crate::offline::zk_verifier::register_ipa_stub_verifier(&mut registry);
        registry
    }

    /// 构造合法 ZkPublicIo 字节（fold_step_count=1, skip_count=0）。
    fn make_valid_public_io_bytes() -> Vec<u8> {
        use crate::offline::zk_verifier::ZkPublicIo;
        let pio = ZkPublicIo {
            initial_commitment: [0x01; 32],
            final_commitment: [0x02; 32],
            state_delta_hash: [0x03; 32],
            ack_chain_hash: [0x04; 32],
            fold_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };
        pio.to_bytes()
    }

    #[test]
    fn test_zk_verify_stub_status_fails_closed() {
        // Stub 只保留格式与 gas 路径，不能被 syscall 解释为密码学验证成功。
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let registry = make_test_zk_registry();
        let mut ctx = PokerL1Context::new(make_tx_context(), 500_000).with_zk_verifier(registry);

        let proof = vec![0xAAu8; 64];
        let pio_bytes = make_valid_public_io_bytes();

        // 布局：proof @ offset 0，public_io @ offset 512
        heap[..proof.len()].copy_from_slice(&proof);
        heap[512..512 + pio_bytes.len()].copy_from_slice(&pio_bytes);

        let result = SyscallZkVerify::rust(
            &mut ctx,
            1, // SCHEME_STWO
            HEAP_BASE,
            proof.len() as u64,
            HEAP_BASE + 512,
            pio_bytes.len() as u64,
            &mut mapping,
        )
        .expect("Stub 状态应返回 fail-closed 结果而不是 trap");

        assert_eq!(result, 1, "Stub 状态不得接受格式正确但未验证的 proof");
        // Hypernova gas = 300000（Phase 11.5 调整）
        assert_eq!(ctx.gas_used(), 300_000);
    }

    #[test]
    fn test_zk_verify_gas_dispatch_by_scheme() {
        // 验证不同 scheme 扣不同 gas：Groth16=20000（proof 须 192B）, IPA=15000（proof ≥ 32B）
        // (scheme_id, expected_gas, proof_len)
        for (scheme_id, expected_gas, proof_len) in [(2u32, 20000u64, 192usize), (3, 15000, 32)] {
            let mut heap = vec![0u8; 4096];
            let mut mapping = make_test_mapping(&mut heap);
            let registry = make_test_zk_registry();
            let mut ctx =
                PokerL1Context::new(make_tx_context(), 100_000).with_zk_verifier(registry);

            let proof = vec![0xBBu8; proof_len];
            let pio_bytes = make_valid_public_io_bytes();
            heap[..proof.len()].copy_from_slice(&proof);
            heap[512..512 + pio_bytes.len()].copy_from_slice(&pio_bytes);

            let result = SyscallZkVerify::rust(
                &mut ctx,
                scheme_id as u64,
                HEAP_BASE,
                proof.len() as u64,
                HEAP_BASE + 512,
                pio_bytes.len() as u64,
                &mut mapping,
            )
            .expect("Stub 状态应完成格式检查与 gas 分派");

            assert_eq!(result, 1, "scheme {scheme_id} 在 Stub 状态必须 fail closed");
            assert_eq!(
                ctx.gas_used(),
                expected_gas,
                "scheme {scheme_id} gas 应为 {expected_gas}"
            );
        }
    }

    #[test]
    fn test_zk_verify_empty_proof_returns_err() {
        // 空 proof → Err（InvalidZkProofFormat，trap VM）
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let registry = make_test_zk_registry();
        let mut ctx = PokerL1Context::new(make_tx_context(), 100_000).with_zk_verifier(registry);

        let pio_bytes = make_valid_public_io_bytes();
        heap[..pio_bytes.len()].copy_from_slice(&pio_bytes);

        let result = SyscallZkVerify::rust(
            &mut ctx,
            1, // SCHEME_STWO
            HEAP_BASE,
            0, // proof_len = 0
            HEAP_BASE,
            pio_bytes.len() as u64,
            &mut mapping,
        );

        assert!(result.is_err(), "空 proof 应返回 Err（trap VM）");
    }

    #[test]
    fn test_zk_verify_no_registry_returns_err() {
        // ctx 无 zk_verifier → Err（ZkVerifierNotRegistered）
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        // 注意：不调用 with_zk_verifier
        let mut ctx = PokerL1Context::new(make_tx_context(), 100_000);

        let proof = vec![0xCCu8; 32];
        let pio_bytes = make_valid_public_io_bytes();
        heap[..proof.len()].copy_from_slice(&proof);
        heap[512..512 + pio_bytes.len()].copy_from_slice(&pio_bytes);

        let result = SyscallZkVerify::rust(
            &mut ctx,
            1,
            HEAP_BASE,
            proof.len() as u64,
            HEAP_BASE + 512,
            pio_bytes.len() as u64,
            &mut mapping,
        );

        assert!(result.is_err(), "无 registry 应返回 Err");
    }

    #[test]
    fn test_zk_verify_invalid_public_io_returns_err() {
        // public_io 长度不足 → Err（InvalidZkPublicIo）
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let registry = make_test_zk_registry();
        let mut ctx = PokerL1Context::new(make_tx_context(), 100_000).with_zk_verifier(registry);

        let proof = vec![0xDDu8; 32];
        let short_pio = vec![0u8; 10]; // 远小于 MIN_BYTES=136
        heap[..proof.len()].copy_from_slice(&proof);
        heap[512..512 + short_pio.len()].copy_from_slice(&short_pio);

        let result = SyscallZkVerify::rust(
            &mut ctx,
            1,
            HEAP_BASE,
            proof.len() as u64,
            HEAP_BASE + 512,
            short_pio.len() as u64,
            &mut mapping,
        );

        assert!(result.is_err(), "public_io 过短应返回 Err");
    }

    #[test]
    fn test_zk_verify_gas_insufficient_returns_err() {
        // gas 不足 → Err（OutOfGas）
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let registry = make_test_zk_registry();
        // 仅 100 gas，远不够 Hypernova 的 300000
        let mut ctx = PokerL1Context::new(make_tx_context(), 100).with_zk_verifier(registry);

        let proof = vec![0xEEu8; 32];
        let pio_bytes = make_valid_public_io_bytes();
        heap[..proof.len()].copy_from_slice(&proof);
        heap[512..512 + pio_bytes.len()].copy_from_slice(&pio_bytes);

        let result = SyscallZkVerify::rust(
            &mut ctx,
            1,
            HEAP_BASE,
            proof.len() as u64,
            HEAP_BASE + 512,
            pio_bytes.len() as u64,
            &mut mapping,
        );

        assert!(result.is_err(), "gas 不足应返回 Err");
        // gas 未被扣除（charge_gas 失败前不扣）
        assert_eq!(ctx.remaining_gas(), 100);
    }

    #[test]
    fn test_zk_verify_unregistered_scheme_returns_err() {
        // 未知 scheme_id (99) → verifier 查找失败 → Err
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let registry = make_test_zk_registry();
        let mut ctx = PokerL1Context::new(make_tx_context(), 500_000).with_zk_verifier(registry);

        let proof = vec![0xFFu8; 32];
        let pio_bytes = make_valid_public_io_bytes();
        heap[..proof.len()].copy_from_slice(&proof);
        heap[512..512 + pio_bytes.len()].copy_from_slice(&pio_bytes);

        let result = SyscallZkVerify::rust(
            &mut ctx,
            99, // 未知 scheme
            HEAP_BASE,
            proof.len() as u64,
            HEAP_BASE + 512,
            pio_bytes.len() as u64,
            &mut mapping,
        );

        assert!(result.is_err(), "未知 scheme 应返回 Err");
        // gas 已被扣除（zk_verify_gas(99) = GAS_ZK_VERIFY = 300000，Phase 11.5 调整）
        assert_eq!(ctx.gas_used(), 300_000);
    }

    #[test]
    fn test_zk_verify_heap_violation_returns_err() {
        // 指针不在 heap region → Err
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let registry = make_test_zk_registry();
        let mut ctx = PokerL1Context::new(make_tx_context(), 100_000).with_zk_verifier(registry);

        // proof_ptr 指向 stack 区域（非法）
        let result = SyscallZkVerify::rust(
            &mut ctx,
            1,
            ebpf::MM_STACK_START, // 非法地址
            32,
            HEAP_BASE,
            136,
            &mut mapping,
        );

        assert!(result.is_err(), "heap 违规应返回 Err");
    }

    // ===== 注册函数测试 =====

    #[test]
    fn test_register_poker_l1_syscalls() {
        let mut registry: FunctionRegistry<BuiltinFunction<PokerL1Context>> =
            FunctionRegistry::default();
        register_poker_l1_syscalls(&mut registry).expect("注册应成功");

        // 验证所有 22 个 syscall 已注册（10 核心 + 1 zk_verify + 11 BLS 预编译）
        for name in [
            &b"object_read"[..],
            b"object_write",
            b"object_create",
            b"emit_event",
            b"log",
            b"panic",
            b"verify_signature",
            b"get_block_height",
            b"get_timestamp",
            b"verify_failure_proof",
            // Task 22.2 — 通用 ZK 证明验证
            b"zk_verify",
            // Task 19 — BLS12-381 预编译
            b"bls12_381_g1_add",
            b"bls12_381_g1_mul",
            b"bls12_381_g1_neg",
            b"bls12_381_g2_add",
            b"bls12_381_g2_mul",
            b"bls12_381_g2_neg",
            b"bls12_381_pairing_check",
            b"bls12_381_hash_to_g1",
            b"bls12_381_hash_to_g2",
            b"bls12_381_miller_loop",
            b"bls12_381_final_exp",
        ] {
            let key = solana_rbpf::ebpf::hash_symbol_name(name);
            assert!(
                registry.lookup_by_key(key).is_some(),
                "syscall {name:?} 应已注册"
            );
        }

        // 重复注册同一函数指针是幂等的（solana_rbpf 行为：value 相同返回 Ok）
        let result = registry.register_function_hashed(*b"object_read", SyscallObjectRead::vm);
        assert!(result.is_ok(), "重复注册同一函数指针应幂等返回 Ok");

        // 注册不同函数指针到同名 syscall 应失败（SymbolHashCollision）
        let result = registry.register_function_hashed(*b"object_read", SyscallObjectWrite::vm);
        assert!(result.is_err(), "注册不同函数到同名 syscall 应冲突");

        // BLS syscall 哈希冲突检查
        let result = registry.register_function_hashed(*b"bls12_381_g1_add", SyscallBlsG1Mul::vm);
        assert!(result.is_err(), "注册不同函数到同名 BLS syscall 应冲突");
    }

    // ===== 辅助函数测试 =====

    #[test]
    fn test_validate_heap_ptr_valid() {
        assert!(validate_heap_ptr(ebpf::MM_HEAP_START, 1).is_ok());
        assert!(validate_heap_ptr(ebpf::MM_HEAP_START + MAX_HEAP_SIZE as u64 - 1, 1).is_ok());
        assert!(validate_heap_ptr(ebpf::MM_HEAP_START, 0).is_ok());
    }

    #[test]
    fn test_validate_heap_ptr_invalid() {
        // stack 区域
        assert!(validate_heap_ptr(ebpf::MM_STACK_START, 28).is_err());
        // input 区域
        assert!(validate_heap_ptr(ebpf::MM_INPUT_START, 32).is_err());
        // heap 越界
        assert!(validate_heap_ptr(ebpf::MM_HEAP_START + MAX_HEAP_SIZE as u64, 1).is_err());
        // 溢出
        assert!(validate_heap_ptr(u64::MAX, 1).is_err());
    }

    #[test]
    fn test_charge_gas_sufficient() {
        let mut ctx = PokerL1Context::new(make_tx_context(), 100);
        assert!(charge_gas(&mut ctx, 50).is_ok());
        assert_eq!(ctx.remaining_gas(), 50);
    }

    #[test]
    fn test_charge_gas_insufficient() {
        let mut ctx = PokerL1Context::new(make_tx_context(), 100);
        assert!(charge_gas(&mut ctx, 101).is_err());
        assert_eq!(ctx.remaining_gas(), 100, "不足时不应扣减");
    }

    // ===== SubTask 19.1 ~ 19.3: BLS12-381 syscall 测试 =====

    use blstrs::{G1Projective, G2Projective, Scalar};
    use group::Group;

    /// 生成 G1 generator compressed bytes 并放入 heap 指定偏移。
    fn place_g1_generator(heap: &mut [u8], offset: usize) {
        let g = G1Projective::generator();
        let bytes = g.to_compressed();
        heap[offset..offset + bls::G1_COMPRESSED_SIZE].copy_from_slice(&bytes);
    }

    /// 生成 G2 generator compressed bytes 并放入 heap 指定偏移。
    fn place_g2_generator(heap: &mut [u8], offset: usize) {
        let g = G2Projective::generator();
        let bytes = g.to_compressed();
        heap[offset..offset + bls::G2_COMPRESSED_SIZE].copy_from_slice(&bytes);
    }

    /// 生成 Scalar=2 compressed bytes 并放入 heap 指定偏移。
    fn place_scalar_two(heap: &mut [u8], offset: usize) {
        let s = Scalar::from(2u64);
        let be = s.to_bytes_be();
        heap[offset..offset + bls::SCALAR_SIZE].copy_from_slice(&be);
    }

    #[test]
    fn test_bls_g1_add_syscall_basic() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        place_g1_generator(&mut heap, 0);
        place_g1_generator(&mut heap, bls::G1_COMPRESSED_SIZE);

        let out_ptr = HEAP_BASE + 2 * bls::G1_COMPRESSED_SIZE as u64;
        let result = SyscallBlsG1Add::rust(
            &mut ctx,
            HEAP_BASE,
            HEAP_BASE + bls::G1_COMPRESSED_SIZE as u64,
            out_ptr,
            0,
            0,
            &mut mapping,
        )
        .expect("bls12_381_g1_add 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.gas_used(), GAS_BLS_G1_ADD);

        // 验证输出 = G + G = 2G
        let out_bytes = &heap[2 * bls::G1_COMPRESSED_SIZE..3 * bls::G1_COMPRESSED_SIZE];
        let expected = G1Projective::generator() + G1Projective::generator();
        assert_eq!(out_bytes, &expected.to_compressed()[..]);
    }

    #[test]
    fn test_bls_g1_mul_syscall_basic() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        place_g1_generator(&mut heap, 0);
        place_scalar_two(&mut heap, bls::G1_COMPRESSED_SIZE);

        let out_ptr = HEAP_BASE + bls::G1_COMPRESSED_SIZE as u64 + bls::SCALAR_SIZE as u64;
        let result = SyscallBlsG1Mul::rust(
            &mut ctx,
            HEAP_BASE,
            HEAP_BASE + bls::G1_COMPRESSED_SIZE as u64,
            out_ptr,
            0,
            0,
            &mut mapping,
        )
        .expect("bls12_381_g1_mul 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.gas_used(), GAS_BLS_G1_MUL);

        let out_offset = bls::G1_COMPRESSED_SIZE + bls::SCALAR_SIZE;
        let out_bytes = &heap[out_offset..out_offset + bls::G1_COMPRESSED_SIZE];
        let expected = G1Projective::generator() * Scalar::from(2u64);
        assert_eq!(out_bytes, &expected.to_compressed()[..]);
    }

    #[test]
    fn test_bls_g1_neg_syscall_basic() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        place_g1_generator(&mut heap, 0);

        let result = SyscallBlsG1Neg::rust(
            &mut ctx,
            HEAP_BASE,
            HEAP_BASE + bls::G1_COMPRESSED_SIZE as u64,
            0,
            0,
            0,
            &mut mapping,
        )
        .expect("bls12_381_g1_neg 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.gas_used(), GAS_BLS_G1_NEG);

        let out_bytes = &heap[bls::G1_COMPRESSED_SIZE..2 * bls::G1_COMPRESSED_SIZE];
        let expected = -G1Projective::generator();
        assert_eq!(out_bytes, &expected.to_compressed()[..]);
    }

    #[test]
    fn test_bls_g2_add_syscall_basic() {
        let mut heap = vec![0u8; 8192];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        place_g2_generator(&mut heap, 0);
        place_g2_generator(&mut heap, bls::G2_COMPRESSED_SIZE);

        let out_ptr = HEAP_BASE + 2 * bls::G2_COMPRESSED_SIZE as u64;
        let result = SyscallBlsG2Add::rust(
            &mut ctx,
            HEAP_BASE,
            HEAP_BASE + bls::G2_COMPRESSED_SIZE as u64,
            out_ptr,
            0,
            0,
            &mut mapping,
        )
        .expect("bls12_381_g2_add 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.gas_used(), GAS_BLS_G2_ADD);

        let out_offset = 2 * bls::G2_COMPRESSED_SIZE;
        let out_bytes = &heap[out_offset..out_offset + bls::G2_COMPRESSED_SIZE];
        let expected = G2Projective::generator() + G2Projective::generator();
        assert_eq!(out_bytes, &expected.to_compressed()[..]);
    }

    #[test]
    fn test_bls_g2_mul_syscall_basic() {
        let mut heap = vec![0u8; 8192];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        place_g2_generator(&mut heap, 0);
        place_scalar_two(&mut heap, bls::G2_COMPRESSED_SIZE);

        let out_ptr = HEAP_BASE + bls::G2_COMPRESSED_SIZE as u64 + bls::SCALAR_SIZE as u64;
        let result = SyscallBlsG2Mul::rust(
            &mut ctx,
            HEAP_BASE,
            HEAP_BASE + bls::G2_COMPRESSED_SIZE as u64,
            out_ptr,
            0,
            0,
            &mut mapping,
        )
        .expect("bls12_381_g2_mul 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.gas_used(), GAS_BLS_G2_MUL);

        let out_offset = bls::G2_COMPRESSED_SIZE + bls::SCALAR_SIZE;
        let out_bytes = &heap[out_offset..out_offset + bls::G2_COMPRESSED_SIZE];
        let expected = G2Projective::generator() * Scalar::from(2u64);
        assert_eq!(out_bytes, &expected.to_compressed()[..]);
    }

    #[test]
    fn test_bls_g2_neg_syscall_basic() {
        let mut heap = vec![0u8; 8192];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        place_g2_generator(&mut heap, 0);

        let result = SyscallBlsG2Neg::rust(
            &mut ctx,
            HEAP_BASE,
            HEAP_BASE + bls::G2_COMPRESSED_SIZE as u64,
            0,
            0,
            0,
            &mut mapping,
        )
        .expect("bls12_381_g2_neg 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.gas_used(), GAS_BLS_G2_NEG);

        let out_bytes = &heap[bls::G2_COMPRESSED_SIZE..2 * bls::G2_COMPRESSED_SIZE];
        let expected = -G2Projective::generator();
        assert_eq!(out_bytes, &expected.to_compressed()[..]);
    }

    #[test]
    fn test_bls_pairing_check_syscall_equal() {
        let mut heap = vec![0u8; 8192];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        // e(g1, g2) == e(g1, g2) → 返回 0
        place_g1_generator(&mut heap, 0);
        place_g2_generator(&mut heap, bls::G1_COMPRESSED_SIZE);
        place_g1_generator(&mut heap, bls::G1_COMPRESSED_SIZE + bls::G2_COMPRESSED_SIZE);
        place_g2_generator(
            &mut heap,
            2 * bls::G1_COMPRESSED_SIZE + bls::G2_COMPRESSED_SIZE,
        );

        let result = SyscallBlsPairingCheck::rust(
            &mut ctx,
            HEAP_BASE,
            HEAP_BASE + bls::G1_COMPRESSED_SIZE as u64,
            HEAP_BASE + (bls::G1_COMPRESSED_SIZE + bls::G2_COMPRESSED_SIZE) as u64,
            HEAP_BASE + (2 * bls::G1_COMPRESSED_SIZE + bls::G2_COMPRESSED_SIZE) as u64,
            0,
            &mut mapping,
        )
        .expect("bls12_381_pairing_check 应成功");

        assert_eq!(result, 0, "e(g1,g2) == e(g1,g2) 应返回 0");
        assert_eq!(ctx.gas_used(), GAS_BLS_PAIRING);
    }

    #[test]
    fn test_bls_pairing_check_syscall_unequal() {
        let mut heap = vec![0u8; 8192];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        // e(g1, g2) != e(2g1, g2) → 返回 1
        place_g1_generator(&mut heap, 0);
        place_g2_generator(&mut heap, bls::G1_COMPRESSED_SIZE);
        // 2*g1
        let g1_double = G1Projective::generator() * Scalar::from(2u64);
        let g1_double_bytes = g1_double.to_compressed();
        heap[bls::G1_COMPRESSED_SIZE + bls::G2_COMPRESSED_SIZE
            ..2 * bls::G1_COMPRESSED_SIZE + bls::G2_COMPRESSED_SIZE]
            .copy_from_slice(&g1_double_bytes);
        place_g2_generator(
            &mut heap,
            2 * bls::G1_COMPRESSED_SIZE + bls::G2_COMPRESSED_SIZE,
        );

        let result = SyscallBlsPairingCheck::rust(
            &mut ctx,
            HEAP_BASE,
            HEAP_BASE + bls::G1_COMPRESSED_SIZE as u64,
            HEAP_BASE + (bls::G1_COMPRESSED_SIZE + bls::G2_COMPRESSED_SIZE) as u64,
            HEAP_BASE + (2 * bls::G1_COMPRESSED_SIZE + bls::G2_COMPRESSED_SIZE) as u64,
            0,
            &mut mapping,
        )
        .expect("bls12_381_pairing_check 应成功");

        assert_eq!(result, 1, "e(g1,g2) != e(2g1,g2) 应返回 1");
    }

    #[test]
    fn test_bls_hash_to_g1_syscall_basic() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        let msg = b"hello world";
        heap[..msg.len()].copy_from_slice(msg);

        let out_ptr = HEAP_BASE + 256;
        let result = SyscallBlsHashToG1::rust(
            &mut ctx,
            HEAP_BASE,
            msg.len() as u64,
            out_ptr,
            0,
            0,
            &mut mapping,
        )
        .expect("bls12_381_hash_to_g1 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.gas_used(), bls_hash_to_g1_gas(msg.len() as u64));

        let out_bytes = &heap[256..256 + bls::G1_COMPRESSED_SIZE];
        // 确定性：与直接调用 bls_hash_to_g1 一致
        let expected = crate::crypto_precompiles::bls::bls_hash_to_g1(msg).unwrap();
        assert_eq!(out_bytes, &expected[..]);
    }

    #[test]
    fn test_bls_hash_to_g2_syscall_basic() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        let msg = b"hello world";
        heap[..msg.len()].copy_from_slice(msg);

        let out_ptr = HEAP_BASE + 256;
        let result = SyscallBlsHashToG2::rust(
            &mut ctx,
            HEAP_BASE,
            msg.len() as u64,
            out_ptr,
            0,
            0,
            &mut mapping,
        )
        .expect("bls12_381_hash_to_g2 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.gas_used(), bls_hash_to_g2_gas(msg.len() as u64));

        let out_bytes = &heap[256..256 + bls::G2_COMPRESSED_SIZE];
        let expected = crate::crypto_precompiles::bls::bls_hash_to_g2(msg).unwrap();
        assert_eq!(out_bytes, &expected[..]);
    }

    #[test]
    fn test_bls_hash_to_g1_syscall_msg_too_long() {
        let mut heap = vec![0u8; MAX_BLS_HASH_MSG_SIZE + 1024];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), u64::MAX);

        let result = SyscallBlsHashToG1::rust(
            &mut ctx,
            HEAP_BASE,
            (MAX_BLS_HASH_MSG_SIZE + 1) as u64,
            HEAP_BASE + 256,
            0,
            0,
            &mut mapping,
        );

        assert!(result.is_err(), "超长 msg 应返回错误");
        assert_eq!(ctx.gas_used(), 0, "校验失败不应扣 gas");
    }

    #[test]
    fn test_bls_miller_loop_syscall_basic() {
        let mut heap = vec![0u8; 8192];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        place_g1_generator(&mut heap, 0);
        place_g2_generator(&mut heap, bls::G1_COMPRESSED_SIZE);

        let out_ptr = HEAP_BASE + bls::G1_COMPRESSED_SIZE as u64 + bls::G2_COMPRESSED_SIZE as u64;
        let result = SyscallBlsMillerLoop::rust(
            &mut ctx,
            HEAP_BASE,
            HEAP_BASE + bls::G1_COMPRESSED_SIZE as u64,
            out_ptr,
            0,
            0,
            &mut mapping,
        )
        .expect("bls12_381_miller_loop 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx.gas_used(), GAS_BLS_MILLER_LOOP);

        let out_offset = bls::G1_COMPRESSED_SIZE + bls::G2_COMPRESSED_SIZE;
        let out_bytes = &heap[out_offset..out_offset + bls::GT_COMPRESSED_SIZE];
        // 验证与直接调用一致
        let expected = crate::crypto_precompiles::bls::bls_miller_loop(
            &G1Projective::generator().to_compressed(),
            &G2Projective::generator().to_compressed(),
        )
        .unwrap();
        assert_eq!(out_bytes, &expected[..]);
    }

    #[test]
    fn test_bls_final_exp_syscall_identity() {
        let mut heap = vec![0u8; 8192];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        // 先执行 miller_loop 获取 GT
        place_g1_generator(&mut heap, 0);
        place_g2_generator(&mut heap, bls::G1_COMPRESSED_SIZE);
        let gt_offset = bls::G1_COMPRESSED_SIZE + bls::G2_COMPRESSED_SIZE;
        SyscallBlsMillerLoop::rust(
            &mut ctx,
            HEAP_BASE,
            HEAP_BASE + bls::G1_COMPRESSED_SIZE as u64,
            HEAP_BASE + gt_offset as u64,
            0,
            0,
            &mut mapping,
        )
        .expect("miller_loop 应成功");

        // 重置 gas 以独立验证 final_exp
        let mut ctx2 = PokerL1Context::new(make_tx_context(), 10_000);
        let out_ptr = HEAP_BASE + gt_offset as u64 + bls::GT_COMPRESSED_SIZE as u64;

        let result = SyscallBlsFinalExp::rust(
            &mut ctx2,
            HEAP_BASE + gt_offset as u64,
            out_ptr,
            0,
            0,
            0,
            &mut mapping,
        )
        .expect("bls12_381_final_exp 应成功");

        assert_eq!(result, 0);
        assert_eq!(ctx2.gas_used(), GAS_BLS_FINAL_EXP);

        // final_exp 是 identity，输出应等于输入
        let in_bytes = &heap[gt_offset..gt_offset + bls::GT_COMPRESSED_SIZE];
        let out_bytes =
            &heap[gt_offset + bls::GT_COMPRESSED_SIZE..gt_offset + 2 * bls::GT_COMPRESSED_SIZE];
        assert_eq!(in_bytes, out_bytes, "final_exp identity 应返回相同值");
    }

    #[test]
    fn test_bls_g1_add_syscall_out_of_gas() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        // gas 不足：GAS_BLS_G1_ADD = 500，仅给 499
        let mut ctx = PokerL1Context::new(make_tx_context(), 499);

        place_g1_generator(&mut heap, 0);
        place_g1_generator(&mut heap, bls::G1_COMPRESSED_SIZE);

        let result = SyscallBlsG1Add::rust(
            &mut ctx,
            HEAP_BASE,
            HEAP_BASE + bls::G1_COMPRESSED_SIZE as u64,
            HEAP_BASE + 2 * bls::G1_COMPRESSED_SIZE as u64,
            0,
            0,
            &mut mapping,
        );

        assert!(result.is_err(), "gas 不足应返回错误");
    }

    #[test]
    fn test_bls_g1_add_syscall_heap_violation() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        // 使用 stack 区域指针（非 heap）
        let result = SyscallBlsG1Add::rust(
            &mut ctx,
            ebpf::MM_STACK_START,
            HEAP_BASE,
            HEAP_BASE + bls::G1_COMPRESSED_SIZE as u64,
            0,
            0,
            &mut mapping,
        );

        assert!(result.is_err(), "非 heap 指针应返回错误");
    }

    #[test]
    fn test_bls_g1_add_syscall_subgroup_check_failure() {
        let mut heap = vec![0u8; 4096];
        let mut mapping = make_test_mapping(&mut heap);
        let mut ctx = PokerL1Context::new(make_tx_context(), 10_000);

        // 全零 bytes 不是合法的 compressed point
        // heap 已全为 0

        let result = SyscallBlsG1Add::rust(
            &mut ctx,
            HEAP_BASE,
            HEAP_BASE + bls::G1_COMPRESSED_SIZE as u64,
            HEAP_BASE + 2 * bls::G1_COMPRESSED_SIZE as u64,
            0,
            0,
            &mut mapping,
        );

        assert!(result.is_err(), "非法 G1 点应被子群检查拒绝");
    }

    // 注：原 `test_bls_pairing_check_syscall_gameturn_gas_free` 测试已移除。
    //
    // 重构后 rBPF VM 内的 syscall 不再有"GameTurn 免 gas"旁路：
    // gas-free precompile 调用经 `PrecompileRegistry::execute` 派发，不经 rBPF VM；
    // 进入 rBPF VM 的 BLS syscall 一律按 gas 计费。
}
