//! 交易结构（Task 3 / SubTask 3.2）
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **M10**：tx 含 `chain_id` + `nonce` 用于 Public 通道重放保护
//! - **NEW-M9**：tx 含 `gameturn_nonce: Option<u64>` 用于 GameTurn 通道 per-game per-player 重放保护
//! - **SEC-H7**：tx 含 `is_fallback: bool`（默认 false），fallback tx 显式标记 true
//! - **SEC-L4**：签名域统一加 `chain_id` 作为首字段
//! - **NEW-M14**：tx 按通道分类（Public / GameTurn / CheckpointAnchor / ForceSync）
//!
//! Phase 1 定义数据结构 + 序列化 + 签名哈希计算；
//! Phase 2 实现路由与轮转校验逻辑。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::ChainId;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID};
use crate::signature::TaggedPubkey;

/// 交易通道分类（SubTask 7.1 — Phase 2 路由用，Phase 1 仅定义枚举）。
///
/// spec：
/// - `Public`：通用交易（转账、合约部署/调用、bridge 操作）— 路由任意 validator，正常计费
/// - `GameTurn`：游戏轮次交易（call/check/raise/bet/fold）— 路由 assigned_validator，免 gas
/// - `CheckpointAnchor`：链下执行 checkpoint anchor — 路由 assigned_validator，免 gas（system tx）
/// - `ForceSync`：强制同步类交易（force_advance / force_checkin / force_revert / request_*
///   / checkin / challenge_delta / refuse_ack / request_ack / checkpoint_skip /
///   force_checkpoint / partial_checkin / revoke_delegated_escape / rotate_validator_key）
///   — 路由任意 validator，正常计费（request_ack / refuse_ack / checkpoint_skip 免 gas）
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum TxLane {
    /// Public 通道：通用交易。
    Public,
    /// GameTurn 通道：游戏轮次交易（免 gas）。
    GameTurn,
    /// CheckpointAnchor 通道：链下执行 checkpoint（system tx，免 gas）。
    CheckpointAnchor,
    /// ForceSync 通道：强制同步 / 逃生通道类交易。
    ForceSync,
}

/// 路由提示（Phase 2 实现详细路由，Phase 1 仅定义结构）。
///
/// spec：
/// - GameTurn + CheckpointAnchor → assigned_validator
/// - ForceSync + Public → 任意 validator（客户端多副本广播）
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Default,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum RouteHint {
    /// 路由到任意 validator（Public / ForceSync 通道）。
    #[default]
    AnyValidator,
    /// 路由到 assigned_validator（GameTurn / CheckpointAnchor 通道）。
    AssignedValidator,
}

/// Gas 配置（Public 通道计费，GameTurn 通道免 gas）。
///
/// spec：
/// - `budget`：tx 愿意支付的最大 gas 量（tx gas limit = 10,000,000）
/// - `price`：每 gas 单价（用于 priority 排序）
/// - GameTurn 通道 tx 的 gas 字段忽略（免 gas），由买入锁仓作为反滥用保障
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Gas {
    /// Gas 预算上限。
    pub budget: u64,
    /// Gas 单价。
    pub price: u64,
}

impl Gas {
    /// 创建 Gas 配置。
    pub const fn new(budget: u64, price: u64) -> Self {
        Self { budget, price }
    }

    /// GameTurn 通道免 gas 用的零 Gas。
    pub const fn zero() -> Self {
        Self {
            budget: 0,
            price: 0,
        }
    }
}

/// 合约调用载荷。
///
/// spec：tx 可包含 contract_call 字段调用已部署的 rBPF 合约。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ContractCall {
    /// 目标合约对象 ID。
    pub contract_id: ObjectID,
    /// 方法选择器（32 字节，blake2b_256(method_name)[0..32]）。
    pub method_selector: [u8; 32],
    /// 调用参数（BCS 编码）。
    pub args: Vec<u8>,
}

/// 交易结构（spec：账户抽象与交易安全章节）。
///
/// 字段说明见模块级文档与 spec 各修复项引用。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Transaction {
    // ===== 对象模型相关 =====
    /// 引用的输入对象 ID 列表（consumed objects）。
    pub inputs: Vec<ObjectID>,
    /// 新创建的输出对象列表。
    pub outputs: Vec<Object>,
    /// 合约调用（可选）。
    pub contract_call: Option<ContractCall>,

    // ===== 签名相关 =====
    /// 签名者 tagged pubkey。
    pub tagged_pubkey: TaggedPubkey,
    /// 签名字节（secp256k1 = 65B r||s||v；ed25519 = 64B R||S）。
    pub signature: Vec<u8>,

    // ===== Gas 与路由 =====
    /// Gas 配置（GameTurn 通道免 gas，此处为 0）。
    pub gas: Gas,
    /// 通道提示（Phase 2 路由用）。
    pub lane_hint: TxLane,
    /// 路由提示（Phase 2 路由用）。
    pub route_hint: RouteHint,

    // ===== 重放保护（M10 + NEW-M9 + SEC-H7） =====
    /// 网络 chain_id（SEC-L4：签名域首字段，防跨链重放）。
    pub chain_id: ChainId,
    /// Account nonce（M10：Public / ForceSync 通道重放保护）。
    pub nonce: u64,
    /// GameTurn nonce（NEW-M9：per-game per-player 计数器，仅 GameTurn 通道使用）。
    pub gameturn_nonce: Option<u64>,
    /// Fallback 标识（SEC-H7：默认 false，fallback tx 显式标记 true）。
    pub is_fallback: bool,
}

/// 签名域分隔前缀（SEC-L4：所有 tx 签名对象以 chain_id 首字段开头）。
const TX_SIG_DOMAIN: u8 = 0x54; // 'T' for Transaction

impl Transaction {
    /// 计算交易的签名对象哈希（signing hash）。
    ///
    /// spec SEC-L4：签名消息对象 = `hash(chain_id || ...tx-specific-fields...)`，
    /// chain_id 必须作为首字段。
    ///
    /// 签名对象 = `blake2b_256(0x54 || chain_id || nonce || gameturn_nonce || is_fallback
    ///                       || lane_hint || inputs || outputs || contract_call || gas)`
    ///
    /// 注意：`tagged_pubkey` 与 `signature` 不参与签名哈希（它们是签名产物）。
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&[TX_SIG_DOMAIN]);
        h.update(&self.chain_id.to_le_bytes());
        h.update(&self.nonce.to_le_bytes());
        // gameturn_nonce: Option<u64> — 用 0x00/0x01 标记 Some/None
        match self.gameturn_nonce {
            Some(v) => {
                h.update(&[0x01]);
                h.update(&v.to_le_bytes());
            }
            None => {
                h.update(&[0x00]);
            }
        }
        h.update(&[self.is_fallback as u8]);
        h.update(&[self.lane_hint as u8]);
        h.update(&[self.route_hint as u8]);
        // gas
        h.update(&self.gas.budget.to_le_bytes());
        h.update(&self.gas.price.to_le_bytes());
        // inputs
        for input in &self.inputs {
            h.update(&input.to_bytes());
        }
        // outputs
        for output in &self.outputs {
            h.update(&output.content_hash());
        }
        // contract_call
        match &self.contract_call {
            Some(cc) => {
                h.update(&[0x01]);
                h.update(&cc.contract_id.to_bytes());
                h.update(&cc.method_selector);
                h.update(&(cc.args.len() as u64).to_le_bytes());
                h.update(&cc.args);
            }
            None => {
                h.update(&[0x00]);
            }
        }
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }

    /// 计算 tx 哈希（用于 tx_merkle_root 与索引）。
    ///
    /// tx_hash = blake2b_256(signing_hash || tagged_pubkey || signature)
    pub fn tx_hash(&self) -> [u8; 32] {
        let signing = self.signing_hash();
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&signing);
        h.update(&self.tagged_pubkey.to_bytes());
        h.update(&self.signature);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }

    /// BCS 序列化为字节。
    pub fn to_bcs(&self) -> PokerL1Result<Vec<u8>> {
        Ok(borsh::to_vec(self)?)
    }

    /// 从 BCS 字节反序列化。
    pub fn from_bcs(bytes: &[u8]) -> PokerL1Result<Self> {
        Ok(borsh::from_slice(bytes)?)
    }
}

/// TxRequest：客户端构造 tx 时的请求载荷（未签名）。
///
/// Phase 1 定义结构，Phase 2 实现客户端签名流程。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TxRequest {
    /// 引用的输入对象 ID 列表。
    pub inputs: Vec<ObjectID>,
    /// 新创建的输出对象列表。
    pub outputs: Vec<Object>,
    /// 合约调用（可选）。
    pub contract_call: Option<ContractCall>,
    /// Gas 配置。
    pub gas: Gas,
    /// 通道提示。
    pub lane_hint: TxLane,
    /// 路由提示。
    pub route_hint: RouteHint,
    /// 网络 chain_id。
    pub chain_id: ChainId,
    /// Account nonce。
    pub nonce: u64,
    /// GameTurn nonce（仅 GameTurn 通道）。
    pub gameturn_nonce: Option<u64>,
    /// Fallback 标识。
    pub is_fallback: bool,
}

impl TxRequest {
    /// 计算 signing_hash（与 Transaction::signing_hash 一致）。
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&[TX_SIG_DOMAIN]);
        h.update(&self.chain_id.to_le_bytes());
        h.update(&self.nonce.to_le_bytes());
        match self.gameturn_nonce {
            Some(v) => {
                h.update(&[0x01]);
                h.update(&v.to_le_bytes());
            }
            None => {
                h.update(&[0x00]);
            }
        }
        h.update(&[self.is_fallback as u8]);
        h.update(&[self.lane_hint as u8]);
        h.update(&[self.route_hint as u8]);
        h.update(&self.gas.budget.to_le_bytes());
        h.update(&self.gas.price.to_le_bytes());
        for input in &self.inputs {
            h.update(&input.to_bytes());
        }
        for output in &self.outputs {
            h.update(&output.content_hash());
        }
        match &self.contract_call {
            Some(cc) => {
                h.update(&[0x01]);
                h.update(&cc.contract_id.to_bytes());
                h.update(&cc.method_selector);
                h.update(&(cc.args.len() as u64).to_le_bytes());
                h.update(&cc.args);
            }
            None => {
                h.update(&[0x00]);
            }
        }
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }

    /// 用 tagged pubkey + 签名组装为完整 Transaction。
    pub fn into_transaction(self, tagged_pubkey: TaggedPubkey, signature: Vec<u8>) -> Transaction {
        Transaction {
            inputs: self.inputs,
            outputs: self.outputs,
            contract_call: self.contract_call,
            tagged_pubkey,
            signature,
            gas: self.gas,
            lane_hint: self.lane_hint,
            route_hint: self.route_hint,
            chain_id: self.chain_id,
            nonce: self.nonce,
            gameturn_nonce: self.gameturn_nonce,
            is_fallback: self.is_fallback,
        }
    }
}

/// 校验 tx 字段长度限制（防 InputTooLong DoS）。
///
/// spec：block gas limit = 50,000,000；tx gas limit = 10,000,000；
/// 单个 Object 序列化后 ≤ 64KB；vertex 上限 256KB。
pub const fn validate_tx_limits(tx: &Transaction) -> PokerL1Result<()> {
    const MAX_INPUTS: usize = 256;
    const MAX_OUTPUTS: usize = 256;
    const MAX_SIG_LEN: usize = 65; // secp256k1 = 65B
    const MAX_ARGS_LEN: usize = 64 * 1024; // 64KB

    if tx.inputs.len() > MAX_INPUTS {
        return Err(PokerL1Error::InputTooLong {
            actual: tx.inputs.len(),
            limit: MAX_INPUTS,
        });
    }
    if tx.outputs.len() > MAX_OUTPUTS {
        return Err(PokerL1Error::InputTooLong {
            actual: tx.outputs.len(),
            limit: MAX_OUTPUTS,
        });
    }
    if tx.signature.len() > MAX_SIG_LEN {
        return Err(PokerL1Error::InputTooLong {
            actual: tx.signature.len(),
            limit: MAX_SIG_LEN,
        });
    }
    if let Some(cc) = &tx.contract_call
        && cc.args.len() > MAX_ARGS_LEN
    {
        return Err(PokerL1Error::InputTooLong {
            actual: cc.args.len(),
            limit: MAX_ARGS_LEN,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::{Object, ObjectID, Ownership};
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

    fn dummy_tagged_pubkey() -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![0x02u8; 33],
        }
    }

    fn dummy_object() -> Object {
        Object::new(
            ObjectID::new([1u8; 20], 0),
            Ownership::Shared,
            "TestType",
            b"test_data".to_vec(),
            None,
        )
    }

    fn dummy_tx() -> Transaction {
        Transaction {
            inputs: vec![ObjectID::new([0u8; 20], 1)],
            outputs: vec![dummy_object()],
            contract_call: None,
            tagged_pubkey: dummy_tagged_pubkey(),
            signature: vec![0u8; 65],
            gas: Gas::new(1000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    #[test]
    fn tx_bcs_roundtrip() {
        let tx = dummy_tx();
        let bytes = tx.to_bcs().expect("BCS 序列化");
        let tx2 = Transaction::from_bcs(&bytes).expect("BCS 反序列化");
        assert_eq!(tx, tx2, "BCS 往返必须保持一致");
    }

    #[test]
    fn tx_json_roundtrip() {
        let tx = dummy_tx();
        let json = serde_json::to_string(&tx).expect("JSON 序列化");
        let tx2: Transaction = serde_json::from_str(&json).expect("JSON 反序列化");
        assert_eq!(tx, tx2, "JSON 往返必须保持一致");
    }

    #[test]
    fn signing_hash_deterministic() {
        let tx = dummy_tx();
        let h1 = tx.signing_hash();
        let h2 = tx.signing_hash();
        assert_eq!(h1, h2, "签名哈希必须确定性");
    }

    #[test]
    fn signing_hash_changes_with_chain_id() {
        let mut tx = dummy_tx();
        let h1 = tx.signing_hash();
        tx.chain_id = 0xDEAD_BEEF;
        let h2 = tx.signing_hash();
        assert_ne!(h1, h2, "chain_id 变化必须改变签名哈希");
    }

    #[test]
    fn signing_hash_changes_with_nonce() {
        let mut tx = dummy_tx();
        let h1 = tx.signing_hash();
        tx.nonce = 2;
        let h2 = tx.signing_hash();
        assert_ne!(h1, h2, "nonce 变化必须改变签名哈希");
    }

    #[test]
    fn signing_hash_changes_with_gameturn_nonce() {
        let mut tx = dummy_tx();
        let h1 = tx.signing_hash();
        tx.gameturn_nonce = Some(5);
        let h2 = tx.signing_hash();
        assert_ne!(h1, h2, "gameturn_nonce 变化必须改变签名哈希");
    }

    #[test]
    fn signing_hash_changes_with_is_fallback() {
        let mut tx = dummy_tx();
        let h1 = tx.signing_hash();
        tx.is_fallback = true;
        let h2 = tx.signing_hash();
        assert_ne!(h1, h2, "is_fallback 变化必须改变签名哈希");
    }

    #[test]
    fn signing_hash_excludes_pubkey_and_sig() {
        // tagged_pubkey 和 signature 不参与签名哈希
        let mut tx = dummy_tx();
        let h1 = tx.signing_hash();
        tx.signature = vec![0xFFu8; 65];
        let h2 = tx.signing_hash();
        assert_eq!(h1, h2, "signature 不应影响签名哈希");
    }

    #[test]
    fn tx_hash_differs_from_signing_hash() {
        let tx = dummy_tx();
        let signing = tx.signing_hash();
        let tx_hash = tx.tx_hash();
        assert_ne!(signing, tx_hash, "tx_hash 必须不同于 signing_hash");
    }

    #[test]
    fn tx_request_into_transaction() {
        let req = TxRequest {
            inputs: vec![ObjectID::new([0u8; 20], 1)],
            outputs: vec![dummy_object()],
            contract_call: None,
            gas: Gas::new(1000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let tp = dummy_tagged_pubkey();
        let sig = vec![0u8; 65];
        let tx = req.into_transaction(tp.clone(), sig.clone());
        assert_eq!(tx.tagged_pubkey, tp);
        assert_eq!(tx.signature, sig);
    }

    #[test]
    fn validate_tx_limits_ok() {
        let tx = dummy_tx();
        validate_tx_limits(&tx).expect("合法 tx 应通过校验");
    }

    #[test]
    fn validate_tx_limits_rejects_too_many_inputs() {
        let mut tx = dummy_tx();
        tx.inputs = vec![ObjectID::new([0u8; 20], 0); 300];
        let err = validate_tx_limits(&tx).unwrap_err();
        assert!(matches!(err, PokerL1Error::InputTooLong { .. }));
    }

    #[test]
    fn validate_tx_limits_rejects_too_many_outputs() {
        let mut tx = dummy_tx();
        tx.outputs = vec![dummy_object(); 257];
        let err = validate_tx_limits(&tx).unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::InputTooLong {
                actual: 257,
                limit: 256
            }
        ));
    }

    #[test]
    fn validate_tx_limits_rejects_too_long_sig() {
        let mut tx = dummy_tx();
        tx.signature = vec![0u8; 100];
        let err = validate_tx_limits(&tx).unwrap_err();
        assert!(matches!(err, PokerL1Error::InputTooLong { .. }));
    }

    #[test]
    fn validate_tx_limits_rejects_too_long_args() {
        let mut tx = dummy_tx();
        tx.contract_call = Some(ContractCall {
            contract_id: ObjectID::new([0u8; 20], 0),
            method_selector: [0u8; 32],
            args: vec![0u8; 100 * 1024],
        });
        let err = validate_tx_limits(&tx).unwrap_err();
        assert!(matches!(err, PokerL1Error::InputTooLong { .. }));
    }

    #[test]
    fn tx_lane_serde() {
        for lane in [
            TxLane::Public,
            TxLane::GameTurn,
            TxLane::CheckpointAnchor,
            TxLane::ForceSync,
        ] {
            let bytes = borsh::to_vec(&lane).unwrap();
            let lane2: TxLane = borsh::from_slice(&bytes).unwrap();
            assert_eq!(lane, lane2);
        }
    }

    #[test]
    fn gas_zero() {
        let g = Gas::zero();
        assert_eq!(g.budget, 0);
        assert_eq!(g.price, 0);
    }
}
