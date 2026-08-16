//! Poker 合约示例源码模板（Task 16 — SubTask 16.1 / 16.2 / 16.3）。
//!
//! 本模块提供 Rust 合约源码模板，文档化合约如何通过 syscall 与链交互。
//! 这些模板可用 `solana-bpf-tools` 编译为 `.so` BPF 字节码后部署到 Poker L1。
//!
//! # 编译要求
//!
//! 合约需使用 `bpf-tools` 工具链编译：
//!
//! ```bash
//! # 安装 solana-bpf-tools
//! sh -c "$(curl -sSfL https://release.solana.com/bpf-tools/install/nightly)"
//!
//! # 编译合约
//! cargo build-bpf --manifest-path contracts/minimal/Cargo.toml
//! ```
//!
//! # Syscall 调用约定
//!
//! 合约通过 `solana_rbpf` 的 `declare_builtin_function!` 宏声明的 syscall 与链交互。
//! 在合约源码中，syscall 通过 `extern "C"` 函数声明调用：
//!
//! ```ignore
//! extern "C" {
//!     fn object_read(id_ptr: *const u8, id_len: u64, out_ptr: *mut u8, out_capacity: u64) -> u64;
//!     fn object_write(id_ptr: *const u8, id_len: u64, data_ptr: *const u8, data_len: u64) -> u64;
//!     fn object_create(type_tag: u64, data_ptr: *const u8, data_len: u64) -> u64;
//!     fn emit_event(payload_ptr: *const u8, payload_len: u64) -> u64;
//!     fn log(msg_ptr: *const u8, msg_len: u64) -> u64;
//!     fn panic(msg_ptr: *const u8, msg_len: u64) -> u64;
//!     fn get_block_height() -> u64;
//!     fn get_timestamp() -> u64;
//! }
//! ```
//!
//! # 示例合约列表
//!
//! - **minimal**（SubTask 16.1）：最小合约，仅调用 `log` + 返回 0
//! - **create_game**（SubTask 16.2）：创建 Game 对象合约
//! - **modify_game**（SubTask 16.3）：修改 Game 状态合约

/// minimal 合约伪代码（SubTask 16.1）。
///
/// 这是最小的 Rust 合约模板，演示：
/// 1. entrypoint 签名
/// 2. 调用 `log` syscall
/// 3. 返回 exit code
///
/// # 编译
///
/// 将此源码放入 `contracts/minimal/src/main.rs`，使用 `cargo build-bpf` 编译。
///
/// # 部署
///
/// ```ignore
/// use poker_l1::vm::{load_contract_bytecode, execute_contract};
/// use poker_l1::object_model::ObjectID;
///
/// let bytecode = std::fs::read("contracts/minimal/target/deploy/minimal.so").unwrap();
/// let contract_id = ObjectID::new([0x01; 20], 1);
/// let loaded = load_contract_bytecode(&bytecode, contract_id, 1).unwrap();
/// ```
pub const MINIMAL_CONTRACT_SOURCE: &str = r#"// minimal.rs — 最小 Poker L1 合约
#![no_std]
#![no_main]

extern "C" {
    fn log(msg_ptr: *const u8, msg_len: u64) -> u64;
}

#[no_mangle]
pub extern "C" fn entrypoint(input: *const u8, input_len: u64) -> u64 {
    let msg = b"Hello Poker L1!";
    unsafe {
        log(msg.as_ptr(), msg.len() as u64);
    }
    0 // exit code
}
"#;

/// create_game 合约伪代码（SubTask 16.2）。
///
/// 演示如何通过 `object_create` syscall 创建 Game 对象：
/// 1. 解析输入（玩家列表、盲注金额、执行模式）
/// 2. 构造 `HandState` BCS 字节
/// 3. 调用 `object_create` 创建 Game 对象
/// 4. 调用 `emit_event` 通知链上 GameCreated 事件
///
/// # 输入格式（BCS 编码）
///
/// ```text
/// [0..20]   owner_address
/// [20..28]  big_blind_amount (u64 LE)
/// [28..36]  small_blind_amount (u64 LE)
/// [36..44]  execution_mode (0=OnChain, 1=OffChain)
/// [44..]    players (Vec<[u8;20]>)
/// ```
pub const CREATE_GAME_CONTRACT_SOURCE: &str = r#"// create_game.rs — 创建 Game 对象合约
#![no_std]
#![no_main]

extern "C" {
    fn object_create(type_tag: u64, data_ptr: *const u8, data_len: u64) -> u64;
    fn emit_event(payload_ptr: *const u8, payload_len: u64) -> u64;
    fn get_block_height() -> u64;
    fn panic(msg_ptr: *const u8, msg_len: u64) -> u64;
}

#[no_mangle]
pub extern "C" fn entrypoint(input: *const u8, input_len: u64) -> u64 {
    // 解析输入（简化版，实际用 BCS 反序列化）
    if input_len < 44 {
        unsafe { panic(b"input too short".as_ptr(), 15); }
        return 1;
    }

    // 读取 block height 作为 creation_nonce
    let block_height = unsafe { get_block_height() };

    // 构造 Game 对象数据（BCS 编码）
    // 实际实现需 BCS 序列化 GameContract
    let game_data = [0u8; 256]; // 占位

    // 创建 Game 对象
    let object_id = unsafe {
        object_create(1, game_data.as_ptr(), game_data.len() as u64) // type_tag=1=Game
    };

    if object_id == 0 {
        unsafe { panic(b"object_create failed".as_ptr(), 20); }
        return 2;
    }

    // emit GameCreated 事件
    let event = b"GameCreated";
    unsafe {
        emit_event(event.as_ptr(), event.len() as u64);
    }

    0
}
"#;

/// modify_game 合约伪代码（SubTask 16.3）。
///
/// 演示如何通过 `object_read` + `object_write` syscall 修改 Game 状态：
/// 1. 读取输入中的 game_id + 新状态
/// 2. 调用 `object_read` 加载当前 Game 对象
/// 3. 更新 HandState（如应用玩家动作）
/// 4. 调用 `object_write` 写回修改后的 Game 对象
/// 5. 调用 `emit_event` 通知状态变更
///
/// # 输入格式（BCS 编码）
///
/// ```text
/// [0..28]   game_id (ObjectID: 20B creator + 8B nonce)
/// [28..36]  action_type (0=Fold, 1=Check, 2=Call, 3=Raise, 4=Bet)
/// [36..44]  action_amount (u64, for Raise/Bet)
/// ```
pub const MODIFY_GAME_CONTRACT_SOURCE: &str = r#"// modify_game.rs — 修改 Game 状态合约
#![no_std]
#![no_main]

extern "C" {
    fn object_read(id_ptr: *const u8, id_len: u64, out_ptr: *mut u8, out_capacity: u64) -> u64;
    fn object_write(id_ptr: *const u8, id_len: u64, data_ptr: *const u8, data_len: u64) -> u64;
    fn emit_event(payload_ptr: *const u8, payload_len: u64) -> u64;
    fn get_block_height() -> u64;
    fn panic(msg_ptr: *const u8, msg_len: u64) -> u64;
}

#[no_mangle]
pub extern "C" fn entrypoint(input: *const u8, input_len: u64) -> u64 {
    if input_len < 44 {
        unsafe { panic(b"input too short".as_ptr(), 15); }
        return 1;
    }

    // 读取 game_id（28 字节 ObjectID）
    let mut game_id = [0u8; 28];
    unsafe {
        core::ptr::copy_nonoverlapping(input, game_id.as_mut_ptr(), 28);
    }

    // 读取当前 Game 对象
    let mut game_data = [0u8; 4096];
    let data_len = unsafe {
        object_read(
            game_id.as_ptr(),
            28,
            game_data.as_mut_ptr(),
            game_data.len() as u64,
        )
    };

    if data_len == 0 {
        unsafe { panic(b"object_read failed".as_ptr(), 20); }
        return 2;
    }

    // 解析 + 更新 Game 状态（实际用 BCS 反序列化 + 应用动作）
    // ... 省略 BCS 反序列化 + 状态机逻辑 ...

    // 写回修改后的 Game 对象
    let write_result = unsafe {
        object_write(
            game_id.as_ptr(),
            28,
            game_data.as_ptr(),
            data_len,
        )
    };

    if write_result != 0 {
        unsafe { panic(b"object_write failed".as_ptr(), 20); }
        return 3;
    }

    // emit GameModified 事件
    let event = b"GameModified";
    unsafe {
        emit_event(event.as_ptr(), event.len() as u64);
    }

    0
}
"#;

/// 返回所有示例合约源码列表。
///
/// 用于文档生成和测试验证。
#[must_use]
pub const fn all_examples() -> &'static [(&'static str, &'static str)] {
    &[
        ("minimal", MINIMAL_CONTRACT_SOURCE),
        ("create_game", CREATE_GAME_CONTRACT_SOURCE),
        ("modify_game", MODIFY_GAME_CONTRACT_SOURCE),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_contract_source_not_empty() {
        assert!(!MINIMAL_CONTRACT_SOURCE.is_empty());
        assert!(MINIMAL_CONTRACT_SOURCE.contains("entrypoint"));
        assert!(MINIMAL_CONTRACT_SOURCE.contains("log"));
    }

    #[test]
    fn test_create_game_contract_source_not_empty() {
        assert!(!CREATE_GAME_CONTRACT_SOURCE.is_empty());
        assert!(CREATE_GAME_CONTRACT_SOURCE.contains("entrypoint"));
        assert!(CREATE_GAME_CONTRACT_SOURCE.contains("object_create"));
        assert!(CREATE_GAME_CONTRACT_SOURCE.contains("emit_event"));
    }

    #[test]
    fn test_modify_game_contract_source_not_empty() {
        assert!(!MODIFY_GAME_CONTRACT_SOURCE.is_empty());
        assert!(MODIFY_GAME_CONTRACT_SOURCE.contains("entrypoint"));
        assert!(MODIFY_GAME_CONTRACT_SOURCE.contains("object_read"));
        assert!(MODIFY_GAME_CONTRACT_SOURCE.contains("object_write"));
    }

    #[test]
    fn test_all_examples_returns_three_contracts() {
        let examples = all_examples();
        assert_eq!(examples.len(), 3);
        assert!(examples.iter().any(|(name, _)| *name == "minimal"));
        assert!(examples.iter().any(|(name, _)| *name == "create_game"));
        assert!(examples.iter().any(|(name, _)| *name == "modify_game"));
    }

    #[test]
    fn test_contract_sources_contain_no_std() {
        // 所有合约应为 no_std（BPF 环境无标准库）
        for (name, src) in all_examples() {
            assert!(src.contains("#![no_std]"), "合约 {name} 应为 no_std");
        }
    }

    #[test]
    fn test_contract_sources_contain_entrypoint() {
        for (name, src) in all_examples() {
            assert!(
                src.contains("entrypoint"),
                "合约 {name} 应包含 entrypoint 函数"
            );
        }
    }
}
