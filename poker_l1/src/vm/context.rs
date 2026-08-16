//! VM 上下文对象（Task 14 — SubTask 14.2）。
//!
//! 实现 `solana_rbpf::vm::ContextObject` trait，作为合约执行时的上下文。
//! 承载 gas 计费（IMPL-SEC-4：(5) 指令执行前扣费）+ 交易上下文 + 区块上下文。
//!
//! ## Gas 计费模型
//!
//! - 指令级 gas：VM 每执行一条指令调用 `consume(1)`，到 0 抛 `ExceededMaxInstructions`
//! - syscall 级 gas：syscall 内部可主动调用 `consume(extra)` 对昂贵操作额外计费
//! - gas-free precompile 调用：executor 通过 `PrecompileRegistry::execute` 直接派发，
//!   不经 rBPF VM，故 `PokerL1Context` 永远不为 gas-free tx 构造（不会出现
//!   `remaining = u64::MAX` 的免 gas 路径；gas-free 不再由 `TxContext` 字段表达）
//! - 普通合约调用：按 `tx.gas.budget` 初始化（上限 `TX_GAS_LIMIT`）

use std::collections::BTreeMap;

use super::gas_table::TX_GAS_LIMIT;
use crate::object_model::ObjectID;
use crate::offline::zk_verifier::ZkVerifierRegistry;
use crate::signature::TaggedPubkey;
use crate::{Address, BlockHeight, ChainId, TimestampMs};

/// 合约调用结果。
#[derive(Debug, Clone)]
pub struct ContractCallResult {
    /// 合约 exit code（0 = 成功）。
    pub exit_code: u64,
    /// 实际消耗的 gas。
    pub gas_used: u64,
    /// 合约执行期间产生的事件列表。
    pub events: Vec<ContractEvent>,
    /// 合约执行期间创建的对象 ID 列表。
    pub created_objects: Vec<ObjectID>,
    /// 合约执行期间修改的对象 ID 列表。
    pub modified_objects: Vec<ObjectID>,
}

/// 合约事件（`emit_event` syscall 产生）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractEvent {
    /// 事件 payload（≤ 16KB，IMPL-SEC-4：(6)）。
    pub payload: Vec<u8>,
}

/// 交易上下文（传入合约执行环境）。
#[derive(Debug, Clone)]
pub struct TxContext {
    /// 调用者地址（tx 签名者派生地址）。
    pub caller: Address,
    /// 调用者 tagged pubkey。
    pub caller_pubkey: TaggedPubkey,
    /// 交易的 chain_id（SEC-L4）。
    pub chain_id: ChainId,
    /// 交易 nonce。
    pub nonce: u64,
    /// 当前 block height。
    pub block_height: BlockHeight,
    /// 当前 block timestamp（毫秒）。
    pub block_timestamp: TimestampMs,
}

/// Poker L1 合约执行上下文。
///
/// 实现 `solana_rbpf::vm::ContextObject` trait，承载：
/// - gas 计费（`remaining` 字段，`consume` / `get_remaining`）
/// - 交易上下文（`tx` 字段）
/// - 合约对象读写缓存（`object_cache` 字段）
/// - 事件收集（`events` 字段）
/// - ZK verifier 注册表（`zk_verifier` 字段，Phase 5a — `zk_verify` syscall 使用）
#[derive(Debug, Clone)]
pub struct PokerL1Context {
    /// 剩余 gas（指令级 + syscall 级共享）。
    remaining: u64,
    /// 初始 gas（用于计算 gas_used）。
    initial_gas: u64,
    /// 交易上下文。
    pub tx: TxContext,
    /// 对象读写缓存（ObjectID → 序列化数据）。
    pub object_cache: BTreeMap<ObjectID, Vec<u8>>,
    /// 本次执行产生的事件。
    pub events: Vec<ContractEvent>,
    /// 本次执行创建的对象 ID。
    pub created_objects: Vec<ObjectID>,
    /// panic 消息（若合约调用 panic syscall）。
    pub panic_message: Option<String>,
    /// ZK verifier 注册表（Phase 5a，Task 22.2）。
    ///
    /// `None` 时 `zk_verify` syscall 返回 `ZkVerifierNotRegistered` 错误。
    /// 由节点层在构造 `PokerL1Context` 时注入（[`with_zk_verifier`]）。
    pub zk_verifier: Option<ZkVerifierRegistry>,
}

impl PokerL1Context {
    /// 创建新上下文（无 ZK verifier）。
    ///
    /// 参数：
    /// - `tx`：交易上下文
    /// - `gas_limit`：gas 上限（上限被钳制到 `TX_GAS_LIMIT` 以内）
    ///
    /// H-4 修复：gas_limit 被限制在 TX_GAS_LIMIT（10M）以内，防止恶意 tx 设置
    /// 超大 gas_limit 导致 CPU DoS。
    ///
    /// 注意：gas-free precompile 调用不经 rBPF VM（由 `PrecompileRegistry::execute`
    /// 直接派发），故本函数不再接收 `u64::MAX` 表示免 gas 的语义。
    pub const fn new(tx: TxContext, gas_limit: u64) -> Self {
        let effective_gas = if gas_limit > TX_GAS_LIMIT {
            TX_GAS_LIMIT
        } else {
            gas_limit
        };
        Self {
            remaining: effective_gas,
            initial_gas: effective_gas,
            tx,
            object_cache: BTreeMap::new(),
            events: Vec::new(),
            created_objects: Vec::new(),
            panic_message: None,
            zk_verifier: None,
        }
    }

    /// 注入 ZK verifier 注册表（builder 模式，Task 22.2）。
    ///
    /// 节点层在构造 context 时调用：
    /// ```ignore
    /// let ctx = PokerL1Context::new(tx, gas_limit)
    ///     .with_zk_verifier(registry);
    /// ```
    pub fn with_zk_verifier(mut self, registry: ZkVerifierRegistry) -> Self {
        self.zk_verifier = Some(registry);
        self
    }

    /// 返回已消耗的 gas。
    pub const fn gas_used(&self) -> u64 {
        self.initial_gas.saturating_sub(self.remaining)
    }

    /// 返回剩余 gas。
    pub const fn remaining_gas(&self) -> u64 {
        self.remaining
    }

    /// 额外消耗 gas（syscall 内部调用）。
    ///
    /// 返回 `false` 表示 gas 不足。
    pub const fn consume_gas(&mut self, amount: u64) -> bool {
        if amount > self.remaining {
            return false;
        }
        self.remaining -= amount;
        true
    }

    /// 退还 gas（用于"预扣上界 + 事后退款"模式）。
    ///
    /// 典型场景：`object_read` 在 lookup 前按 `out_capacity` 预扣 gas，
    /// lookup 后按实际 `data.len()` 退还差额，既防止 DoS 又保持 gas 语义。
    ///
    /// 退还量会被钳制到已消耗量内（`refund <= gas_used`），防止恶意退款导致
    /// `remaining` 超过 `initial_gas`。退款不会超过初始 gas 上限。
    pub fn refund_gas(&mut self, amount: u64) {
        let max_refund = self.gas_used();
        let actual_refund = amount.min(max_refund);
        self.remaining = self.remaining.saturating_add(actual_refund);
    }

    /// 记录事件（`emit_event` syscall 调用）。
    pub fn emit_event(&mut self, payload: Vec<u8>) {
        self.events.push(ContractEvent { payload });
    }

    /// 记录 panic（`panic` syscall 调用）。
    pub fn panic(&mut self, msg: String) {
        self.panic_message = Some(msg);
    }

    /// 记录创建的对象。
    pub fn record_created_object(&mut self, id: ObjectID) {
        self.created_objects.push(id);
    }

    /// 获取调用结果。
    pub fn into_result(self, exit_code: u64) -> ContractCallResult {
        ContractCallResult {
            exit_code,
            gas_used: self.gas_used(),
            events: self.events,
            created_objects: self.created_objects,
            modified_objects: self.object_cache.keys().copied().collect(),
        }
    }
}

/// 实现 `solana_rbpf` 的 `ContextObject` trait。
///
/// VM 每执行一条指令调用 `consume(1)`，gas 耗尽时抛 `ExceededMaxInstructions`。
impl solana_rbpf::vm::ContextObject for PokerL1Context {
    fn trace(&mut self, _state: [u64; 12]) {
        // tracing 默认关闭，空实现
    }

    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_rbpf::vm::ContextObject; // 引入 trait 以调用 `ctx.consume(...)`

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

    #[test]
    fn test_context_gas_tracking() {
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);
        assert_eq!(ctx.remaining_gas(), 1000);
        assert_eq!(ctx.gas_used(), 0);

        // 模拟 VM 指令消耗
        ctx.consume(100);
        assert_eq!(ctx.remaining_gas(), 900);
        assert_eq!(ctx.gas_used(), 100);

        // 模拟 syscall 额外消耗
        assert!(ctx.consume_gas(200));
        assert_eq!(ctx.remaining_gas(), 700);
        assert_eq!(ctx.gas_used(), 300);
    }

    #[test]
    fn test_gas_limit_clamped_to_tx_gas_limit() {
        // gas_limit 超过 TX_GAS_LIMIT 时被钳制（H-4 修复）
        let ctx = PokerL1Context::new(make_tx_context(), u64::MAX);
        assert_eq!(ctx.remaining_gas(), TX_GAS_LIMIT);
        assert_eq!(ctx.gas_used(), 0);
    }

    #[test]
    fn test_gas_insufficient() {
        let mut ctx = PokerL1Context::new(make_tx_context(), 100);
        assert!(!ctx.consume_gas(101), "应返回 false");
        assert!(ctx.consume_gas(100), "刚好够应返回 true");
        assert!(!ctx.consume_gas(1), "耗尽后应返回 false");
    }

    /// SEC-FIX-1：验证 `refund_gas` 的基本语义与安全钳制。
    #[test]
    fn test_refund_gas_basic_and_clamp() {
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);

        // 预扣 500
        assert!(ctx.consume_gas(500));
        assert_eq!(ctx.gas_used(), 500);
        assert_eq!(ctx.remaining_gas(), 500);

        // 退还 300
        ctx.refund_gas(300);
        assert_eq!(ctx.gas_used(), 200);
        assert_eq!(ctx.remaining_gas(), 800);

        // 安全钳制：退款超过已消耗量时，仅退到 initial_gas
        // 当前 gas_used=200，退款 u64::MAX 应只退 200
        ctx.refund_gas(u64::MAX);
        assert_eq!(ctx.gas_used(), 0, "退款不应使 gas_used 变负");
        assert_eq!(
            ctx.remaining_gas(),
            1000,
            "退款不应使 remaining 超过 initial_gas"
        );
    }

    /// SEC-FIX-1：验证 `refund_gas` 不会超过初始 gas 上限（防恶意退款）。
    #[test]
    fn test_refund_gas_no_overflow() {
        let mut ctx = PokerL1Context::new(make_tx_context(), 100);

        // 预扣 30，退 30 → remaining 应为 100，不超过 initial_gas
        assert!(ctx.consume_gas(30));
        ctx.refund_gas(30);
        assert_eq!(ctx.remaining_gas(), 100);
        assert_eq!(ctx.gas_used(), 0);

        // 再次退款不应使 remaining 超过 100
        ctx.refund_gas(50);
        assert_eq!(
            ctx.remaining_gas(),
            100,
            "退款不应使 remaining 超过 initial_gas"
        );
    }

    #[test]
    fn test_events() {
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);
        ctx.emit_event(b"event1".to_vec());
        ctx.emit_event(b"event2".to_vec());
        assert_eq!(ctx.events.len(), 2);
        assert_eq!(ctx.events[0].payload, b"event1");
        assert_eq!(ctx.events[1].payload, b"event2");
    }

    #[test]
    fn test_panic() {
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);
        ctx.panic("assertion failed".to_string());
        assert_eq!(ctx.panic_message.as_deref(), Some("assertion failed"));
    }

    #[test]
    fn test_into_result() {
        let mut ctx = PokerL1Context::new(make_tx_context(), 1000);
        ctx.consume(500);
        ctx.emit_event(b"test".to_vec());
        let id = ObjectID::new([1u8; 20], 0);
        ctx.object_cache.insert(id, b"data".to_vec());

        let result = ctx.into_result(0);
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.gas_used, 500);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.modified_objects, vec![id]);
    }

    #[test]
    fn test_context_object_trait() {
        fn assert_context_object<T: solana_rbpf::vm::ContextObject>() {}
        assert_context_object::<PokerL1Context>();
    }
}
