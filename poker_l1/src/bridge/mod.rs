//! 跨链桥模块（Task 34）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）第 893-907 行：
//! - **SubTask 34.1**：定义 `BridgeHook` trait + `bridge_verify` syscall 接口
//! - **SubTask 34.2**：`bridge_verify` 必须由协议层在 deposit 流程中调用，
//!   不允许任意合约直接调用（返回 `BridgeVerifyNotAuthorized`）
//! - **SubTask 34.3**：签名绑定 `(nonce, source_chain_id, dest_chain_id, asset, amount,
//!   recipient, source_tx_hash)` 防重放（SEC-H3 修复 — 补全 `recipient` 与 `source_tx_hash`）；
//!   防重放由 `nonce` + `dest_chain_id` 保证；在 poker_l1 上铸造对应 wrapped 对象给 `recipient`；
//!   **SEC2-M1 修复**：bridge_verify tx 须由 recipient 本人签名提交（防抢跑）；
//!   recipient 可指定 `preferred_relayer` 获额外奖励
//! - **SubTask 34.4**：反向操作需 burn wrapped 对象 + burn proof（burn-on-source）
//! - **SubTask 34.5**：桥验证器插槽注册机制
//!
//! # 安全约束
//!
//! - **SEC-H3**：签名绑定补全 `recipient` + `source_tx_hash`
//! - **SEC2-M1**：bridge_verify 须 recipient 签名 + preferred_relayer 机制
//! - **SubTask 34.2**：协议层调用强制

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership};
use crate::signature::TaggedPubkey;
use crate::signature::unified::verify_signature;
use crate::storage::ObjectBackend;
use crate::{Address, ChainId, Hash};

// ===== 常量 =====

/// 桥签名域分隔前缀。
const BRIDGE_SIG_DOMAIN: u8 = 0x42; // 'B' for Bridge

/// Domain separator for validator-authorized bridge configuration changes.
const BRIDGE_CONFIG_SIG_DOMAIN: &[u8] = b"ZCHAIN_BRIDGE_CONFIG_V1";

/// Burn proof 域分隔前缀。
const BURN_PROOF_DOMAIN: u8 = 0x62; // 'b' for burn

/// wrapped-asset 对象的类型标签（缺口 #9：bridge deposit 验证通过后铸造的 wrapped Object）。
///
/// 该类型对象由 bridge 铸币创建，`data` 字段为 [`WrappedAsset`] 的 borsh 编码。
/// owner 为 `AddressOwned { recipient }`，可被 recipient 正常转移 / 消费。
pub const BRIDGE_WRAPPED_OBJECT_TYPE: &str = "bridge-wrapped-asset";

/// Type tag for the consensus-committed bridge validator configuration singleton.
pub const BRIDGE_REGISTRY_CONFIG_OBJECT_TYPE: &str = "0x2::bridge::RegistryConfig";

/// Reserved singleton ID for bridge validator configuration.
///
/// Replay-protection nonces remain in a separately journaled store because they grow without
/// bound, while the security-critical validator slots are committed by ObjectDb and therefore by
/// every block's state root.
pub const BRIDGE_REGISTRY_CONFIG_OBJECT_ID: ObjectID = ObjectID::new([0u8; 20], u64::MAX - 3);

/// Type tag for the consensus-committed bridge replay-protection commitment singleton.
pub const BRIDGE_REPLAY_STATE_OBJECT_TYPE: &str = "0x2::bridge::ReplayState";

/// Reserved singleton ID for the bridge replay-protection commitment.
pub const BRIDGE_REPLAY_STATE_OBJECT_ID: ObjectID = ObjectID::new([0u8; 20], u64::MAX - 4);

// ===== BridgeDeposit（跨链存款凭证） =====

/// 跨链存款凭证（SubTask 34.3）。
///
/// SEC-H3 修复：签名绑定字段补全 `recipient` 与 `source_tx_hash`。
///
/// # 字段说明
///
/// - `nonce`：源链上的唯一 nonce（防重放）
/// - `source_chain_id`：源链 chain_id
/// - `dest_chain_id`：目标链 chain_id（poker_l1）
/// - `asset`：资产标识（源链上的合约地址 / token id）
/// - `amount`：存款金额
/// - `recipient`：poker_l1 上的接收地址（tagged pubkey 派生地址，SEC-H3）
/// - `source_tx_hash`：源链上的交易哈希（跨链追踪，SEC-H3）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BridgeDeposit {
    /// 源链上的唯一 nonce（防重放）。
    pub nonce: u64,
    /// 源链 chain_id。
    pub source_chain_id: ChainId,
    /// 目标链 chain_id（poker_l1）。
    pub dest_chain_id: ChainId,
    /// 资产标识（源链上的合约地址 / token id，32 字节）。
    pub asset: Hash,
    /// 存款金额。
    pub amount: u64,
    /// poker_l1 上的接收地址（SEC-H3：tagged pubkey 派生地址）。
    pub recipient: Address,
    /// 源链上的交易哈希（SEC-H3：跨链追踪）。
    pub source_tx_hash: Hash,
}

impl BridgeDeposit {
    /// 计算桥签名的消息哈希。
    ///
    /// 签名对象 = `blake2b_256(BRIDGE_SIG_DOMAIN || nonce || source_chain_id ||
    /// dest_chain_id || asset || amount || recipient || source_tx_hash)`
    ///
    /// SEC-H3：所有字段均参与哈希，防签名被重用到不同 recipient / amount。
    #[must_use]
    pub fn message_hash(&self) -> Hash {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&[BRIDGE_SIG_DOMAIN]);
        h.update(&self.nonce.to_le_bytes());
        h.update(&self.source_chain_id.to_le_bytes());
        h.update(&self.dest_chain_id.to_le_bytes());
        h.update(&self.asset);
        h.update(&self.amount.to_le_bytes());
        h.update(&self.recipient);
        h.update(&self.source_tx_hash);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }
}

// ===== BridgeVerifyTx（bridge_verify 交易） =====

/// bridge_verify 交易（SubTask 34.3 + SEC2-M1）。
///
/// SEC2-M1 修复：
/// - `recipient_sig`：须由 recipient 本人签名提交（防第三方抢跑）
/// - `preferred_relayer`：recipient 可指定优先 relayer 获额外奖励
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BridgeVerifyTx {
    /// 存款凭证。
    pub deposit: BridgeDeposit,
    /// 桥验证器的签名集合（多签背书）。
    pub validator_signatures: Vec<BridgeValidatorSig>,
    /// recipient 本人签名（SEC2-M1：防抢跑）。
    ///
    /// 签名对象 = `blake2b_256(BRIDGE_SIG_DOMAIN || deposit.message_hash())`
    pub recipient_sig: Vec<u8>,
    /// recipient 的 tagged pubkey（用于验证 recipient_sig）。
    pub recipient_pubkey: TaggedPubkey,
    /// 优先 relayer（SEC2-M1：获额外奖励；None 表示无优先）。
    pub preferred_relayer: Option<TaggedPubkey>,
}

/// 桥验证器签名。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BridgeValidatorSig {
    /// 验证器 tagged pubkey。
    pub validator: TaggedPubkey,
    /// 签名字节。
    pub signature: Vec<u8>,
}

// ===== BurnProof（burn-on-source） =====

/// Burn 证明（SubTask 34.4）。
///
/// 反向操作：在 poker_l1 上 burn wrapped 对象，生成 burn proof，
/// 提交到源链以解锁原始资产。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnProof {
    /// burn nonce（poker_l1 上的唯一 nonce，防重放）。
    pub burn_nonce: u64,
    /// 源链 chain_id（资产原始链）。
    pub source_chain_id: ChainId,
    /// 目标链 chain_id（poker_l1，burn 发生链）。
    pub dest_chain_id: ChainId,
    /// 资产标识。
    pub asset: Hash,
    /// burn 金额。
    pub amount: u64,
    /// 接收地址（源链上的接收者）。
    pub recipient: Address,
    /// poker_l1 上的 burn tx 哈希。
    pub burn_tx_hash: Hash,
}

impl BurnProof {
    /// 计算 burn proof 的消息哈希。
    #[must_use]
    pub fn message_hash(&self) -> Hash {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&[BURN_PROOF_DOMAIN]);
        h.update(&self.burn_nonce.to_le_bytes());
        h.update(&self.source_chain_id.to_le_bytes());
        h.update(&self.dest_chain_id.to_le_bytes());
        h.update(&self.asset);
        h.update(&self.amount.to_le_bytes());
        h.update(&self.recipient);
        h.update(&self.burn_tx_hash);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }
}

// ===== BridgeValidatorSlot（桥验证器插槽） =====

/// 桥验证器插槽（SubTask 34.5）。
///
/// 每条外部链可注册独立的桥验证器集，负责签名背书存款凭证。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BridgeValidatorSlot {
    /// 源链 chain_id。
    pub source_chain_id: ChainId,
    /// 注册的桥验证器 pubkey 集合。
    pub validators: BTreeSet<TaggedPubkey>,
    /// 所需 quorum 数（2/3 of validators）。
    pub quorum: usize,
}

/// Canonical, consensus-committed bridge validator slot configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BridgeRegistryConfig {
    /// Chain whose ObjectDb commits this configuration.
    pub chain_id: ChainId,
    /// Exactly one slot per external source chain.
    pub slots: BTreeMap<ChainId, BridgeValidatorSlot>,
}

impl BridgeRegistryConfig {
    /// Empty fail-closed bridge configuration for a new chain.
    #[must_use]
    pub fn empty(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            slots: BTreeMap::new(),
        }
    }

    /// Validate canonical slot keys and quorum rules.
    pub fn validate(&self) -> PokerL1Result<()> {
        for (&source_chain_id, slot) in &self.slots {
            if source_chain_id != slot.source_chain_id {
                return Err(PokerL1Error::BridgeSignatureInvalid(
                    "bridge config slot key does not match source_chain_id".to_string(),
                ));
            }
            slot.validate_configuration()?;
        }
        Ok(())
    }

    /// Deterministic commitment used to bind a configuration update to both old and new state.
    #[must_use]
    pub fn commitment_hash(&self) -> Hash {
        let encoded = borsh::to_vec(self)
            .expect("BridgeRegistryConfig serialization is infallible for an in-memory value");
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(BRIDGE_CONFIG_SIG_DOMAIN);
        h.update(&encoded);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }
}

/// Commitment to the complete externally stored bridge nonce sets.
///
/// The nonce archive remains in its dedicated RocksDB store to avoid placing an unbounded set in
/// ObjectDb, but every candidate block commits this digest and both cardinalities in ObjectDb.
/// A node whose local archive does not reproduce this value must fail closed before executing a
/// bridge block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BridgeReplayState {
    /// Chain whose bridge nonce sets are committed.
    pub chain_id: ChainId,
    /// Domain-separated hash of canonical deposit and burn nonce sets.
    pub nonce_root: Hash,
    /// Number of consumed deposit nonces.
    pub deposit_nonce_count: u64,
    /// Number of consumed burn nonces.
    pub burn_nonce_count: u64,
}

impl BridgeReplayState {
    /// The canonical empty replay state for a newly initialized chain.
    #[must_use]
    pub fn empty(chain_id: ChainId) -> Self {
        let registry = BridgeRegistry::new();
        let (nonce_root, deposit_nonce_count, burn_nonce_count) = registry.replay_commitment();
        Self {
            chain_id,
            nonce_root,
            deposit_nonce_count,
            burn_nonce_count,
        }
    }

    /// Test whether a registry exactly matches this state-root commitment.
    #[must_use]
    pub fn matches_registry(&self, registry: &BridgeRegistry) -> bool {
        let (nonce_root, deposit_nonce_count, burn_nonce_count) = registry.replay_commitment();
        self.nonce_root == nonce_root
            && self.deposit_nonce_count == deposit_nonce_count
            && self.burn_nonce_count == burn_nonce_count
    }
}

/// Create the immutable system object that commits bridge replay-protection state.
pub fn bridge_replay_state_object(
    state: &BridgeReplayState,
    version: u64,
) -> PokerL1Result<Object> {
    let mut object = Object::new(
        BRIDGE_REPLAY_STATE_OBJECT_ID,
        Ownership::Immutable,
        BRIDGE_REPLAY_STATE_OBJECT_TYPE,
        borsh::to_vec(state)?,
        None,
    );
    object.version = version;
    Ok(object)
}

/// Decode and chain-bind a bridge replay-protection state object.
pub fn decode_bridge_replay_state_object(
    object: &Object,
    expected_chain_id: ChainId,
) -> PokerL1Result<BridgeReplayState> {
    let state = validate_bridge_replay_state_object(object)?;
    if state.chain_id != expected_chain_id {
        return Err(PokerL1Error::Other(
            "bridge replay state chain_id does not match configured chain_id".to_string(),
        ));
    }
    Ok(state)
}

/// Validate the shape of a bridge replay-protection singleton without a node chain-id context.
pub fn validate_bridge_replay_state_object(object: &Object) -> PokerL1Result<BridgeReplayState> {
    if object.id != BRIDGE_REPLAY_STATE_OBJECT_ID
        || object.object_type != BRIDGE_REPLAY_STATE_OBJECT_TYPE
        || object.owner != Ownership::Immutable
        || object.assigned_validator.is_some()
    {
        return Err(PokerL1Error::Other(
            "invalid bridge replay state singleton".to_string(),
        ));
    }
    let state: BridgeReplayState = borsh::from_slice(&object.data).map_err(|error| {
        PokerL1Error::Serialization(format!("decode bridge replay state: {error}"))
    })?;
    Ok(state)
}

/// Whether an object claims the reserved bridge replay-state identity or type.
#[must_use]
pub fn is_bridge_replay_state_object(object: &Object) -> bool {
    object.id == BRIDGE_REPLAY_STATE_OBJECT_ID
        || object.object_type == BRIDGE_REPLAY_STATE_OBJECT_TYPE
}

/// A validator signature authorizing a replacement of the bridge configuration singleton.
///
/// The signature is deliberately over a configuration transition, not over the enclosing
/// transaction hash: including the signature vector in that hash would be circular. The old
/// object version and commitment make a signature single-use against the exact on-chain state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BridgeConfigSignature {
    /// Active consensus validator authorizing this exact transition.
    pub validator: TaggedPubkey,
    /// Scheme-native signature bytes.
    pub signature: Vec<u8>,
}

/// Public-lane payload for changing bridge verifier slots.
///
/// Every update replaces the whole map. This avoids ambiguous incremental merge rules and makes
/// the exact post-state visible to all signers before they authorize it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BridgeConfigUpdate {
    /// Version of the configuration singleton the validators inspected.
    pub expected_version: u64,
    /// Commitment of that exact current configuration.
    pub expected_config_hash: Hash,
    /// Complete next configuration.
    pub next_config: BridgeRegistryConfig,
    /// Distinct active-validator signatures for [`Self::message_hash`].
    pub signatures: Vec<BridgeConfigSignature>,
}

impl BridgeConfigUpdate {
    /// Signature message for a single, replay-safe configuration transition.
    #[must_use]
    pub fn message_hash(&self) -> Hash {
        let next_hash = self.next_config.commitment_hash();
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(BRIDGE_CONFIG_SIG_DOMAIN);
        h.update(&self.next_config.chain_id.to_le_bytes());
        h.update(&self.expected_version.to_le_bytes());
        h.update(&self.expected_config_hash);
        h.update(&next_hash);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }
}

/// Validate an active-validator authorized bridge configuration replacement.
///
/// This is kept independent of the executor so the authorization rule is testable without a
/// node. The executor additionally enforces the Public lane and singleton replacement atomically
/// in its ObjectDb transaction.
pub fn validate_bridge_config_update(
    update: &BridgeConfigUpdate,
    current: &BridgeRegistryConfig,
    current_version: u64,
    active_validators: &BTreeSet<TaggedPubkey>,
    network_chain_id: ChainId,
) -> PokerL1Result<()> {
    if current.chain_id != network_chain_id || update.next_config.chain_id != network_chain_id {
        return Err(PokerL1Error::Other(
            "bridge configuration update chain_id mismatch".to_string(),
        ));
    }
    current.validate()?;
    update.next_config.validate()?;
    if update.expected_version != current_version {
        return Err(PokerL1Error::Other(format!(
            "bridge configuration version mismatch: expected {}, current {current_version}",
            update.expected_version
        )));
    }
    if update.expected_config_hash != current.commitment_hash() {
        return Err(PokerL1Error::Other(
            "bridge configuration commitment does not match current state".to_string(),
        ));
    }
    let required = required_bridge_quorum(active_validators.len());
    if active_validators.is_empty() || update.signatures.len() < required {
        return Err(PokerL1Error::Other(format!(
            "insufficient active-validator bridge configuration signatures: got={}, required={required}",
            update.signatures.len()
        )));
    }
    let message = update.message_hash();
    let mut seen = BTreeSet::new();
    for signature in &update.signatures {
        if !active_validators.contains(&signature.validator) {
            return Err(PokerL1Error::Other(
                "bridge configuration signer is not an active validator".to_string(),
            ));
        }
        if !seen.insert(signature.validator.clone()) {
            return Err(PokerL1Error::DuplicateBridgeValidator(
                signature.validator.clone(),
            ));
        }
        verify_signature(&signature.validator, &signature.signature, &message).map_err(
            |error| {
                PokerL1Error::BridgeSignatureInvalid(format!(
                    "bridge configuration signature invalid: {error}"
                ))
            },
        )?;
    }
    Ok(())
}

/// Create the immutable system object that commits bridge validator slots.
pub fn bridge_registry_config_object(
    config: &BridgeRegistryConfig,
    version: u64,
) -> PokerL1Result<Object> {
    config.validate()?;
    let mut object = Object::new(
        BRIDGE_REGISTRY_CONFIG_OBJECT_ID,
        Ownership::Immutable,
        BRIDGE_REGISTRY_CONFIG_OBJECT_TYPE,
        borsh::to_vec(config)?,
        None,
    );
    object.version = version;
    Ok(object)
}

/// Decode a bridge configuration system object and bind it to the local chain ID.
pub fn decode_bridge_registry_config_object(
    object: &Object,
    expected_chain_id: ChainId,
) -> PokerL1Result<BridgeRegistryConfig> {
    let config = validate_bridge_registry_config_object(object)?;
    if config.chain_id != expected_chain_id {
        return Err(PokerL1Error::Other(format!(
            "bridge config chain_id {} does not match configured chain_id {expected_chain_id}",
            config.chain_id
        )));
    }
    Ok(config)
}

/// Validate the singleton's shape and return its decoded configuration.
pub fn validate_bridge_registry_config_object(
    object: &Object,
) -> PokerL1Result<BridgeRegistryConfig> {
    if object.id != BRIDGE_REGISTRY_CONFIG_OBJECT_ID
        || object.object_type != BRIDGE_REGISTRY_CONFIG_OBJECT_TYPE
        || object.owner != Ownership::Immutable
        || object.assigned_validator.is_some()
    {
        return Err(PokerL1Error::Other(
            "invalid bridge registry configuration singleton".to_string(),
        ));
    }
    let config: BridgeRegistryConfig = borsh::from_slice(&object.data)
        .map_err(|error| PokerL1Error::Serialization(format!("decode bridge config: {error}")))?;
    config.validate()?;
    Ok(config)
}

/// Whether an object claims the reserved bridge configuration identity or type.
#[must_use]
pub fn is_bridge_registry_config_object(object: &Object) -> bool {
    object.id == BRIDGE_REGISTRY_CONFIG_OBJECT_ID
        || object.object_type == BRIDGE_REGISTRY_CONFIG_OBJECT_TYPE
}

impl BridgeValidatorSlot {
    /// 创建新插槽。
    #[must_use]
    pub fn new(source_chain_id: ChainId, validators: BTreeSet<TaggedPubkey>) -> Self {
        let quorum = required_bridge_quorum(validators.len());
        Self {
            source_chain_id,
            validators,
            quorum,
        }
    }

    /// 校验签名数是否达到 quorum。
    #[must_use]
    pub fn has_quorum(&self, sig_count: usize) -> bool {
        // An empty validator set must never turn into a zero-signature minting authority.
        // Keeping this check here rather than only in registration also makes deserialized or
        // otherwise misconfigured historical slots fail closed during block replay.
        !self.validators.is_empty() && sig_count >= self.quorum
    }

    /// Validate the consensus-relevant configuration of this slot.
    ///
    /// The registry is intentionally permissive when deserializing old local state, but a slot
    /// cannot authorize bridge operations unless it contains at least one validator and its
    /// stored quorum is the canonical strict-two-thirds threshold.
    pub fn validate_configuration(&self) -> PokerL1Result<()> {
        if self.validators.is_empty() {
            return Err(PokerL1Error::BridgeSignatureInvalid(
                "bridge validator slot must not be empty".to_string(),
            ));
        }
        let expected = required_bridge_quorum(self.validators.len());
        if self.quorum != expected {
            return Err(PokerL1Error::BridgeSignatureInvalid(format!(
                "bridge validator slot has non-canonical quorum: got={}, expected={expected}",
                self.quorum
            )));
        }
        Ok(())
    }

    /// 校验签名者是否全部在插槽中，且无重复签名（H1 修复）。
    pub fn validate_signers(&self, sigs: &[BridgeValidatorSig]) -> PokerL1Result<()> {
        let mut seen = BTreeSet::new();
        for sig in sigs {
            if !self.validators.contains(&sig.validator) {
                return Err(PokerL1Error::BridgeValidatorSlotNotRegistered(
                    sig.validator.clone(),
                ));
            }
            if !seen.insert(sig.validator.clone()) {
                return Err(PokerL1Error::DuplicateBridgeValidator(
                    sig.validator.clone(),
                ));
            }
        }
        Ok(())
    }
}

/// 计算桥验证器 quorum（严格 >2/3）。
#[must_use]
pub const fn required_bridge_quorum(validator_count: usize) -> usize {
    if validator_count == 0 {
        return 0;
    }
    2 * validator_count / 3 + 1 // 严格 >2/3（C-3 修复）
}

// ===== BridgeHook trait（SubTask 34.1） =====

/// 跨链桥 hook trait（SubTask 34.1）。
///
/// 实现者通过此 trait 注册新桥，定义特定于源链的验证逻辑。
///
/// # 安全约束
///
/// - `bridge_verify` 必须由协议层在 deposit 流程中调用（SubTask 34.2）
/// - 不允许任意合约直接调用（返回 `BridgeVerifyNotAuthorized`）
pub trait BridgeHook: Send + Sync {
    /// 返回源链 chain_id。
    fn source_chain_id(&self) -> ChainId;

    /// 验证桥存款凭证的签名背书。
    ///
    /// # 参数
    /// - `deposit`：存款凭证
    /// - `sigs`：桥验证器签名集合
    ///
    /// # 返回
    /// - `Ok(())`：验证通过
    /// - `Err(_)`：签名不足 / 验证器未注册 / 签名无效
    fn verify_deposit(
        &self,
        deposit: &BridgeDeposit,
        sigs: &[BridgeValidatorSig],
    ) -> PokerL1Result<()>;

    /// 验证 burn proof（SubTask 34.4）。
    ///
    /// 反向操作：验证 poker_l1 上的 burn 是否合法。
    fn verify_burn(&self, burn: &BurnProof) -> PokerL1Result<()>;
}

// ===== BridgeRegistry（桥注册表） =====

/// 桥注册表（管理所有已注册的 BridgeHook）。
#[derive(Debug, Default, Clone)]
pub struct BridgeRegistry {
    /// 按 source_chain_id 索引的桥验证器插槽。
    slots: BTreeMap<ChainId, BridgeValidatorSlot>,
    /// 已消费的 nonce（防重放：`(source_chain_id, nonce)` → true）。
    consumed_nonces: BTreeSet<(ChainId, u64)>,
    /// 已消费的 burn nonce（防重放）。
    consumed_burn_nonces: BTreeSet<(ChainId, u64)>,
}

impl BridgeRegistry {
    /// 创建空注册表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册桥验证器插槽（SubTask 34.5）。
    pub fn register_slot(&mut self, slot: BridgeValidatorSlot) {
        self.slots.insert(slot.source_chain_id, slot);
    }

    /// Replace the local verifier slots from an authenticated on-chain configuration.
    pub(crate) fn replace_slots(&mut self, slots: BTreeMap<ChainId, BridgeValidatorSlot>) {
        self.slots = slots;
    }

    /// 获取指定源链的插槽。
    #[must_use]
    pub fn slot(&self, source_chain_id: ChainId) -> Option<&BridgeValidatorSlot> {
        self.slots.get(&source_chain_id)
    }

    /// 检查 nonce 是否已消费（防重放）。
    #[must_use]
    pub fn is_nonce_consumed(&self, source_chain_id: ChainId, nonce: u64) -> bool {
        self.consumed_nonces.contains(&(source_chain_id, nonce))
    }

    /// 标记 nonce 已消费。
    pub fn consume_nonce(&mut self, source_chain_id: ChainId, nonce: u64) {
        self.consumed_nonces.insert((source_chain_id, nonce));
    }

    /// 检查 burn nonce 是否已消费。
    #[must_use]
    pub fn is_burn_nonce_consumed(&self, dest_chain_id: ChainId, burn_nonce: u64) -> bool {
        self.consumed_burn_nonces
            .contains(&(dest_chain_id, burn_nonce))
    }

    /// 标记 burn nonce 已消费。
    pub fn consume_burn_nonce(&mut self, dest_chain_id: ChainId, burn_nonce: u64) {
        self.consumed_burn_nonces
            .insert((dest_chain_id, burn_nonce));
    }

    /// Canonical export of all replay-protection state for a block-commit snapshot.
    #[must_use]
    pub(crate) fn nonce_sets(&self) -> (BTreeSet<(ChainId, u64)>, BTreeSet<(ChainId, u64)>) {
        (
            self.consumed_nonces.clone(),
            self.consumed_burn_nonces.clone(),
        )
    }

    /// Return the state-root commitment and cardinalities of both canonical nonce sets.
    #[must_use]
    pub fn replay_commitment(&self) -> (Hash, u64, u64) {
        let encoded = borsh::to_vec(&(&self.consumed_nonces, &self.consumed_burn_nonces))
            .expect("bridge nonce set serialization is infallible");
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(b"ZCHAIN_BRIDGE_REPLAY_V1");
        h.update(&encoded);
        let mut nonce_root = [0u8; 32];
        h.finalize_variable(&mut nonce_root).expect("32 <= 64");
        (
            nonce_root,
            self.consumed_nonces.len() as u64,
            self.consumed_burn_nonces.len() as u64,
        )
    }

    /// Restore replay-protection sets during journal recovery.
    ///
    /// Slots are governance/configuration state and deliberately remain unchanged; this method
    /// only replaces the monotonic deposit/burn nonce sets that the bridge executor mutates.
    pub(crate) fn replace_nonce_sets(
        &mut self,
        consumed_nonces: BTreeSet<(ChainId, u64)>,
        consumed_burn_nonces: BTreeSet<(ChainId, u64)>,
    ) {
        self.consumed_nonces = consumed_nonces;
        self.consumed_burn_nonces = consumed_burn_nonces;
    }
}

// ===== bridge_verify（协议层调用，SubTask 34.2） =====

/// bridge_verify 协议层入口（SubTask 34.2 + 34.3 + SEC2-M1）。
///
/// **安全约束**：此函数必须由协议层在 deposit 流程中调用，
/// 不允许任意合约直接调用。合约直接调用应返回 `BridgeVerifyNotAuthorized`。
///
/// # 验证流程
///
/// 1. 校验 `tx.deposit.dest_chain_id == network_chain_id`（防跨链重放）
/// 2. 校验 nonce 未被消费（防重放）
/// 3. 校验 recipient 签名（SEC2-M1：须 recipient 本人签名）
/// 4. 校验桥验证器签名 quorum + 签名有效性
/// 5. 标记 nonce 已消费
/// 6. 返回验证结果，由协议层执行铸造
///
/// # 参数
///
/// - `registry`：桥注册表
/// - `tx`：bridge_verify 交易
/// - `network_chain_id`：当前网络 chain_id
/// - `is_protocol_caller`：调用方是否为协议层（false → 返回 `BridgeVerifyNotAuthorized`）
pub fn bridge_verify(
    registry: &mut BridgeRegistry,
    tx: &BridgeVerifyTx,
    network_chain_id: ChainId,
    is_protocol_caller: bool,
) -> PokerL1Result<BridgeVerifyOutcome> {
    // SubTask 34.2：必须由协议层调用
    if !is_protocol_caller {
        return Err(PokerL1Error::BridgeVerifyNotAuthorized);
    }

    // 1. 校验目标链匹配
    if tx.deposit.dest_chain_id != network_chain_id {
        return Err(PokerL1Error::BridgeSignatureInvalid(format!(
            "dest_chain_id mismatch: deposit={}, network={}",
            tx.deposit.dest_chain_id, network_chain_id
        )));
    }

    // 2. 校验 nonce 未被消费（防重放）
    if registry.is_nonce_consumed(tx.deposit.source_chain_id, tx.deposit.nonce) {
        return Err(PokerL1Error::BridgeNonceConsumed(tx.deposit.nonce));
    }

    // 3. 校验 recipient 签名（SEC2-M1）
    let deposit_msg_hash = tx.deposit.message_hash();
    verify_signature(&tx.recipient_pubkey, &tx.recipient_sig, &deposit_msg_hash).map_err(|e| {
        PokerL1Error::BridgeSignatureInvalid(format!("recipient signature invalid: {e}"))
    })?;

    // 校验 recipient_pubkey 派生地址 == deposit.recipient
    let derived_addr = derive_address(&tx.recipient_pubkey);
    if derived_addr != tx.deposit.recipient {
        return Err(PokerL1Error::BridgeSignatureInvalid(
            "recipient_pubkey does not derive to deposit.recipient".to_string(),
        ));
    }

    // 4. 校验桥验证器签名
    let slot = registry.slot(tx.deposit.source_chain_id).ok_or_else(|| {
        PokerL1Error::BridgeValidatorSlotNotRegistered(tx.recipient_pubkey.clone())
    })?;

    slot.validate_configuration()?;

    // 校验签名者全部在插槽中
    slot.validate_signers(&tx.validator_signatures)?;

    // 校验 quorum
    if !slot.has_quorum(tx.validator_signatures.len()) {
        return Err(PokerL1Error::BridgeSignatureInvalid(format!(
            "insufficient validator signatures: got={}, required={}",
            tx.validator_signatures.len(),
            slot.quorum
        )));
    }

    // 校验每个签名（验证桥验证器对 deposit 的签名）
    for sig in &tx.validator_signatures {
        verify_signature(&sig.validator, &sig.signature, &deposit_msg_hash).map_err(|e| {
            PokerL1Error::BridgeSignatureInvalid(format!(
                "validator {:?} signature invalid: {e}",
                sig.validator
            ))
        })?;
    }

    // 5. 标记 nonce 已消费
    registry.consume_nonce(tx.deposit.source_chain_id, tx.deposit.nonce);

    // 6. 返回验证结果
    Ok(BridgeVerifyOutcome {
        deposit: tx.deposit.clone(),
        recipient: tx.deposit.recipient,
        preferred_relayer: tx.preferred_relayer.clone(),
    })
}

/// bridge_verify 验证结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeVerifyOutcome {
    /// 已验证的存款凭证。
    pub deposit: BridgeDeposit,
    /// 接收地址。
    pub recipient: Address,
    /// 优先 relayer（如有）。
    pub preferred_relayer: Option<TaggedPubkey>,
}

// ===== wrapped-asset 铸造（缺口 #9：deposit 验证通过后铸造 wrapped Object） =====

/// wrapped-asset 的 typed 数据（存于 [`Object::data`]）。
///
/// 记录跨链来源信息，使 wrapped 对象可被追溯与反向 burn。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct WrappedAsset {
    /// 源链 chain_id（资产原始来源）。
    pub source_chain_id: ChainId,
    /// 资产标识（源链上的合约地址 / token id，32 字节）。
    pub asset: Hash,
    /// 包装金额。
    pub amount: u64,
}

impl WrappedAsset {
    /// 从已验证的存款凭证构造 wrapped-asset 数据。
    #[must_use]
    pub fn from_deposit(deposit: &BridgeDeposit) -> Self {
        Self {
            source_chain_id: deposit.source_chain_id,
            asset: deposit.asset,
            amount: deposit.amount,
        }
    }
}

/// 铸造 wrapped-asset Object 给 recipient（缺口 #9）。
///
/// 在 [`bridge_verify`] 验证通过后调用：用 `outcome` 构造一个
/// [`BRIDGE_WRAPPED_OBJECT_TYPE`] 类型的对象，owner 为 recipient，
/// 通过 `object_db.create()` 落库（影响 state_root）。
///
/// # ObjectID 确定性（state_root 可重现性）
///
/// `ObjectID::new(creator_address, creation_nonce)` 中 `creator_address = recipient`
/// （SEC2-M1：recipient 是 caller）。`creation_nonce` 由调用方传入，须在
/// **确定性位置**分配——出块方与验块方对同一笔 bridge_verify tx 必须用相同的
/// `creation_nonce`，使两者铸造出相同的 ObjectID → 相同 state_root。
/// 推荐方案：`creation_nonce` = (block_height << 32) | tx_index_in_block（块内确定序）。
///
/// # 参数
///
/// - `outcome`：[`bridge_verify`] 的返回值（含 deposit + recipient）
/// - `object_db`：对象后端（`ObjectDb` / `ObjectDbSnapshot`）
/// - `creation_nonce`：确定性创建序号（见上）
///
/// # 返回
///
/// 新铸造 wrapped 对象的 `ObjectID`。
pub fn mint_wrapped_object<B: ObjectBackend>(
    outcome: &BridgeVerifyOutcome,
    object_db: &mut B,
    creation_nonce: u64,
) -> PokerL1Result<ObjectID> {
    let wrapped = WrappedAsset::from_deposit(&outcome.deposit);
    let data = borsh::to_vec(&wrapped)?;
    let obj = Object::new(
        ObjectID::new(outcome.recipient, creation_nonce),
        Ownership::AddressOwned {
            owner: outcome.recipient,
        },
        BRIDGE_WRAPPED_OBJECT_TYPE,
        data,
        None,
    );
    let object_id = obj.id;
    object_db.create(obj)?;
    Ok(object_id)
}

// ===== native wrapped-asset burn =====

/// Record the replay-protection portion of a burn after the native executor has authenticated
/// and consumed the wrapped object.
///
/// This deliberately is not a public bridge API: accepting an arbitrary [`BurnProof`] without
/// first deleting its referenced wrapped UTXO was the former forged-burn vulnerability.
fn record_burn_nonce(
    registry: &mut BridgeRegistry,
    burn: &BurnProof,
    network_chain_id: ChainId,
) -> PokerL1Result<()> {
    // 校验 burn 发生在当前链
    if burn.dest_chain_id != network_chain_id {
        return Err(PokerL1Error::BurnProofInvalid(format!(
            "dest_chain_id mismatch: burn={}, network={}",
            burn.dest_chain_id, network_chain_id
        )));
    }

    // 校验 burn_nonce 未被消费
    if registry.is_burn_nonce_consumed(burn.dest_chain_id, burn.burn_nonce) {
        return Err(PokerL1Error::BurnProofInvalid(format!(
            "burn_nonce already consumed: {}",
            burn.burn_nonce
        )));
    }

    // 标记 burn_nonce 已消费
    registry.consume_burn_nonce(burn.dest_chain_id, burn.burn_nonce);

    Ok(())
}

/// Parameters for the native bridge burn transaction.
///
/// The caller is authenticated by the outer public-lane transaction.  Asset and amount are not
/// user inputs: they are decoded from the consumed wrapped object, so a caller cannot burn one
/// wrapped asset while emitting a proof for another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BridgeBurnTx {
    /// The wrapped object being permanently consumed on poker_l1.
    pub wrapped_object_id: ObjectID,
    /// Unique source-chain burn nonce.
    pub burn_nonce: u64,
    /// Original source chain of the wrapped asset.
    pub source_chain_id: ChainId,
    /// Recipient on the source chain.
    pub recipient: Address,
}

/// Consume one caller-owned wrapped object and derive its canonical burn proof.
///
/// This is the only poker_l1-side burn primitive.  It deliberately accepts neither a caller
/// supplied amount nor a caller supplied transaction hash.  The executor supplies the signed
/// transaction hash after authentication, and the object deletion plus replay nonce are staged
/// in the same transaction snapshot.
pub fn burn_wrapped_object<B: ObjectBackend>(
    registry: &mut BridgeRegistry,
    object_db: &mut B,
    caller: Address,
    request: &BridgeBurnTx,
    network_chain_id: ChainId,
    burn_tx_hash: Hash,
) -> PokerL1Result<BurnProof> {
    let object = object_db.read(&request.wrapped_object_id)?;
    if object.object_type != BRIDGE_WRAPPED_OBJECT_TYPE {
        return Err(PokerL1Error::BurnProofInvalid(
            "burn input is not a bridge wrapped asset".to_string(),
        ));
    }
    if object.owner != (Ownership::AddressOwned { owner: caller }) {
        return Err(PokerL1Error::BurnProofInvalid(
            "burn caller does not own the wrapped asset".to_string(),
        ));
    }
    let wrapped: WrappedAsset = borsh::from_slice(&object.data).map_err(|error| {
        PokerL1Error::BurnProofInvalid(format!("invalid wrapped asset encoding: {error}"))
    })?;
    if wrapped.source_chain_id != request.source_chain_id {
        return Err(PokerL1Error::BurnProofInvalid(
            "burn source_chain_id does not match wrapped asset".to_string(),
        ));
    }

    let proof = BurnProof {
        burn_nonce: request.burn_nonce,
        source_chain_id: wrapped.source_chain_id,
        dest_chain_id: network_chain_id,
        asset: wrapped.asset,
        amount: wrapped.amount,
        recipient: request.recipient,
        burn_tx_hash,
    };
    // Consume the nonce before deleting the object.  The executor's per-transaction snapshot
    // restores both sides if a later operation fails, so neither a proof nor a deletion can
    // become visible by itself.
    record_burn_nonce(registry, &proof, network_chain_id)?;
    object_db.delete(&request.wrapped_object_id)?;
    Ok(proof)
}

// ===== 辅助函数 =====

/// 从 tagged pubkey 派生地址（blake2b_256(tagged_pubkey)[0..20]）。
///
/// 与 `account` 模块的地址派生逻辑一致。
fn derive_address(pubkey: &TaggedPubkey) -> Address {
    let bytes = pubkey.to_bytes();
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&bytes);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&out[0..20]);
    addr
}

// ===== 合约直接调用防护（SubTask 34.2） =====

/// 合约直接调用 bridge_verify 的拒绝路径（SubTask 34.2）。
///
/// 合约层不可直接调用 `bridge_verify`，必须通过协议层。
/// 此函数供 syscall 注册时使用，始终返回 `BridgeVerifyNotAuthorized`。
pub const fn bridge_verify_contract_call_denied() -> PokerL1Error {
    PokerL1Error::BridgeVerifyNotAuthorized
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{CURRENT_VERSION, SignatureScheme};
    use crate::storage::ObjectDb;
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::{Message, Secp256k1};

    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        let mut raw = vec![byte];
        raw.extend_from_slice(&[0x02u8; 32]);
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw).unwrap()
    }

    fn make_addr(byte: u8) -> Address {
        [byte; 20]
    }

    fn make_deposit(nonce: u64, amount: u64, recipient: Address) -> BridgeDeposit {
        BridgeDeposit {
            nonce,
            source_chain_id: 0xAAAA,
            dest_chain_id: crate::DEFAULT_CHAIN_ID,
            asset: [0xAB; 32],
            amount,
            recipient,
            source_tx_hash: [0xCD; 32],
        }
    }

    fn make_real_keypair() -> (secp256k1::SecretKey, secp256k1::PublicKey, TaggedPubkey) {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let (secret_key, public_key) = secp.generate_keypair(&mut rng);
        // secp256k1_scheme::verify 期望 raw = compressed pubkey (33 字节)
        let compressed = public_key.serialize();
        let tagged = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            CURRENT_VERSION,
            compressed.to_vec(),
        )
        .unwrap();
        (secret_key, public_key, tagged)
    }

    fn sign_with_key(
        secp: &Secp256k1<secp256k1::All>,
        secret: &secp256k1::SecretKey,
        msg_hash: &Hash,
    ) -> Vec<u8> {
        let msg = Message::from_digest_slice(msg_hash).unwrap();
        // secp256k1_scheme::verify 期望 r(32) || s(32) || v(1) = 65 字节
        let sig = secp.sign_ecdsa_recoverable(&msg, secret);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut sig_bytes = compact.to_vec();
        sig_bytes.push(recovery_id.to_i32() as u8);
        sig_bytes
    }

    // ===== BridgeDeposit 测试 =====

    #[test]
    fn test_deposit_message_hash_deterministic() {
        let deposit1 = make_deposit(1, 100, make_addr(0x01));
        let deposit2 = make_deposit(1, 100, make_addr(0x01));
        assert_eq!(deposit1.message_hash(), deposit2.message_hash());
    }

    #[test]
    fn test_deposit_message_hash_differs_by_field() {
        let base = make_deposit(1, 100, make_addr(0x01));

        // nonce 不同
        let mut d = base.clone();
        d.nonce = 2;
        assert_ne!(base.message_hash(), d.message_hash());

        // amount 不同
        let mut d = base.clone();
        d.amount = 200;
        assert_ne!(base.message_hash(), d.message_hash());

        // recipient 不同（SEC-H3）
        let mut d = base.clone();
        d.recipient = make_addr(0x02);
        assert_ne!(base.message_hash(), d.message_hash());

        // source_tx_hash 不同（SEC-H3）
        let mut d = base.clone();
        d.source_tx_hash = [0xEF; 32];
        assert_ne!(base.message_hash(), d.message_hash());
    }

    // ===== BridgeValidatorSlot 测试 =====

    #[test]
    fn test_required_bridge_quorum() {
        assert_eq!(required_bridge_quorum(0), 0);
        assert_eq!(required_bridge_quorum(1), 1);
        assert_eq!(required_bridge_quorum(3), 3); // 2*3/3+1 = 3（严格 >2/3）
        assert_eq!(required_bridge_quorum(5), 4); // 2*5/3+1 = 4
        assert_eq!(required_bridge_quorum(10), 7); // 2*10/3+1 = 7
    }

    #[test]
    fn test_validator_slot_new() {
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);
        assert_eq!(slot.source_chain_id, 0xAAAA);
        assert_eq!(slot.validators.len(), 5);
        assert_eq!(slot.quorum, 4); // ceil(5*2/3) = 4
    }

    #[test]
    fn test_validator_slot_has_quorum() {
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);
        assert!(!slot.has_quorum(3));
        assert!(slot.has_quorum(4));
        assert!(slot.has_quorum(5));
    }

    #[test]
    fn empty_validator_slot_never_has_quorum() {
        let slot = BridgeValidatorSlot::new(0xAAAA, BTreeSet::new());
        assert!(!slot.has_quorum(0));
        assert!(matches!(
            slot.validate_configuration(),
            Err(PokerL1Error::BridgeSignatureInvalid(_))
        ));
    }

    #[test]
    fn test_validator_slot_validate_signers_ok() {
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators.clone());

        let sigs: Vec<BridgeValidatorSig> = validators
            .iter()
            .take(4)
            .map(|v| BridgeValidatorSig {
                validator: v.clone(),
                signature: vec![0u8; 65],
            })
            .collect();

        assert!(slot.validate_signers(&sigs).is_ok());
    }

    #[test]
    fn test_validator_slot_validate_signers_reject_unknown() {
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);

        // 未注册的 validator
        let sigs = vec![BridgeValidatorSig {
            validator: make_tagged_pubkey(0xFF),
            signature: vec![0u8; 65],
        }];

        assert!(matches!(
            slot.validate_signers(&sigs),
            Err(PokerL1Error::BridgeValidatorSlotNotRegistered(_))
        ));
    }

    // ===== BridgeRegistry 测试 =====

    #[test]
    fn test_registry_nonce_consumption() {
        let mut registry = BridgeRegistry::new();
        assert!(!registry.is_nonce_consumed(0xAAAA, 1));
        registry.consume_nonce(0xAAAA, 1);
        assert!(registry.is_nonce_consumed(0xAAAA, 1));
        // 不同 source_chain_id 的 nonce 不冲突
        assert!(!registry.is_nonce_consumed(0xBBBB, 1));
    }

    #[test]
    fn test_registry_burn_nonce_consumption() {
        let mut registry = BridgeRegistry::new();
        assert!(!registry.is_burn_nonce_consumed(crate::DEFAULT_CHAIN_ID, 1));
        registry.consume_burn_nonce(crate::DEFAULT_CHAIN_ID, 1);
        assert!(registry.is_burn_nonce_consumed(crate::DEFAULT_CHAIN_ID, 1));
    }

    #[test]
    fn test_registry_register_slot() {
        let mut registry = BridgeRegistry::new();
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);
        registry.register_slot(slot);
        assert!(registry.slot(0xAAAA).is_some());
        assert!(registry.slot(0xBBBB).is_none());
    }

    // ===== bridge_verify 测试 =====

    #[test]
    fn test_bridge_verify_rejects_contract_caller() {
        let mut registry = BridgeRegistry::new();
        let tx = BridgeVerifyTx {
            deposit: make_deposit(1, 100, make_addr(0x01)),
            validator_signatures: vec![],
            recipient_sig: vec![],
            recipient_pubkey: make_tagged_pubkey(0x01),
            preferred_relayer: None,
        };
        // is_protocol_caller = false → 拒绝
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, false);
        assert!(matches!(
            result,
            Err(PokerL1Error::BridgeVerifyNotAuthorized)
        ));
    }

    #[test]
    fn test_bridge_verify_dest_chain_mismatch() {
        let mut registry = BridgeRegistry::new();
        let tx = BridgeVerifyTx {
            deposit: BridgeDeposit {
                nonce: 1,
                source_chain_id: 0xAAAA,
                dest_chain_id: 0x9999, // 错误
                asset: [0xAB; 32],
                amount: 100,
                recipient: make_addr(0x01),
                source_tx_hash: [0xCD; 32],
            },
            validator_signatures: vec![],
            recipient_sig: vec![],
            recipient_pubkey: make_tagged_pubkey(0x01),
            preferred_relayer: None,
        };
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true);
        assert!(matches!(
            result,
            Err(PokerL1Error::BridgeSignatureInvalid(_))
        ));
    }

    #[test]
    fn test_bridge_verify_slot_not_registered() {
        let mut registry = BridgeRegistry::new();
        // 不注册 slot
        let tx = BridgeVerifyTx {
            deposit: make_deposit(1, 100, make_addr(0x01)),
            validator_signatures: vec![],
            recipient_sig: vec![0u8; 65],
            recipient_pubkey: make_tagged_pubkey(0x01),
            preferred_relayer: None,
        };
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true);
        // 应失败（slot 未注册 或 recipient 签名无效）
        assert!(result.is_err());
    }

    #[test]
    fn test_bridge_verify_nonce_consumed() {
        let mut registry = BridgeRegistry::new();
        // 预先注册 slot
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);
        registry.register_slot(slot);

        // 预先消费 nonce
        registry.consume_nonce(0xAAAA, 1);

        let tx = BridgeVerifyTx {
            deposit: make_deposit(1, 100, make_addr(0x01)),
            validator_signatures: vec![],
            recipient_sig: vec![0u8; 65],
            recipient_pubkey: make_tagged_pubkey(0x01),
            preferred_relayer: None,
        };
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true);
        assert!(matches!(result, Err(PokerL1Error::BridgeNonceConsumed(1))));
    }

    #[test]
    fn test_bridge_verify_insufficient_quorum() {
        let mut registry = BridgeRegistry::new();
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);
        registry.register_slot(slot);

        // 仅 3 个签名（< quorum=4）
        let sigs: Vec<BridgeValidatorSig> = (0..3)
            .map(|i| BridgeValidatorSig {
                validator: make_tagged_pubkey(0x10 + i as u8),
                signature: vec![0u8; 65],
            })
            .collect();

        let tx = BridgeVerifyTx {
            deposit: make_deposit(1, 100, make_addr(0x01)),
            validator_signatures: sigs,
            recipient_sig: vec![0u8; 65],
            recipient_pubkey: make_tagged_pubkey(0x01),
            preferred_relayer: None,
        };
        // recipient 签名会先失败（占位签名），所以错误是 BridgeSignatureInvalid
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_bridge_verify_full_flow_with_real_signatures() {
        let mut registry = BridgeRegistry::new();
        let secp = Secp256k1::new();

        // 生成 recipient 密钥对
        let (recipient_secret, _recipient_public, recipient_tagged) = make_real_keypair();

        // 生成 5 个桥验证器密钥对
        let validator_keys: Vec<(secp256k1::SecretKey, secp256k1::PublicKey, TaggedPubkey)> = (0
            ..5)
            .map(|_| {
                let (s, p) = secp.generate_keypair(&mut OsRng);
                let compressed = p.serialize();
                let tagged = TaggedPubkey::new(
                    SignatureScheme::Secp256k1,
                    CURRENT_VERSION,
                    compressed.to_vec(),
                )
                .unwrap();
                (s, p, tagged)
            })
            .collect();

        // 注册 slot
        let validator_set: BTreeSet<TaggedPubkey> =
            validator_keys.iter().map(|(_, _, t)| t.clone()).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validator_set);
        registry.register_slot(slot);

        // 构造 deposit（recipient 地址从 tagged pubkey 派生）
        let recipient_addr = derive_address(&recipient_tagged);
        let deposit = make_deposit(1, 1000, recipient_addr);
        let msg_hash = deposit.message_hash();

        // recipient 签名
        let recipient_sig = sign_with_key(&secp, &recipient_secret, &msg_hash);

        // 桥验证器签名（4 个 = quorum）
        let validator_sigs: Vec<BridgeValidatorSig> = validator_keys
            .iter()
            .take(4)
            .map(|(s, _, t)| {
                let sig = sign_with_key(&secp, s, &msg_hash);
                BridgeValidatorSig {
                    validator: t.clone(),
                    signature: sig,
                }
            })
            .collect();

        let tx = BridgeVerifyTx {
            deposit,
            validator_signatures: validator_sigs,
            recipient_sig,
            recipient_pubkey: recipient_tagged,
            preferred_relayer: Some(make_tagged_pubkey(0x99)),
        };

        // 执行 bridge_verify
        let outcome = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true).unwrap();
        assert_eq!(outcome.deposit.amount, 1000);
        assert_eq!(outcome.recipient, recipient_addr);
        assert!(outcome.preferred_relayer.is_some());

        // nonce 已消费 → 重复提交失败
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true);
        assert!(matches!(result, Err(PokerL1Error::BridgeNonceConsumed(1))));
    }

    #[test]
    fn bridge_verify_rejects_empty_validator_slot_even_with_valid_recipient_signature() {
        let mut registry = BridgeRegistry::new();
        registry.register_slot(BridgeValidatorSlot::new(0xAAAA, BTreeSet::new()));
        let secp = Secp256k1::new();
        let (recipient_secret, _, recipient_pubkey) = make_real_keypair();
        let deposit = make_deposit(99, 1, derive_address(&recipient_pubkey));
        let tx = BridgeVerifyTx {
            recipient_sig: sign_with_key(&secp, &recipient_secret, &deposit.message_hash()),
            deposit,
            validator_signatures: vec![],
            recipient_pubkey,
            preferred_relayer: None,
        };
        assert!(matches!(
            bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true),
            Err(PokerL1Error::BridgeSignatureInvalid(_))
        ));
    }

    #[test]
    fn test_bridge_verify_recipient_signature_invalid() {
        let mut registry = BridgeRegistry::new();
        let validators: BTreeSet<TaggedPubkey> =
            (0..5).map(|i| make_tagged_pubkey(0x10 + i as u8)).collect();
        let slot = BridgeValidatorSlot::new(0xAAAA, validators);
        registry.register_slot(slot);

        // 占位 recipient 签名（无效）
        let tx = BridgeVerifyTx {
            deposit: make_deposit(1, 100, make_addr(0x01)),
            validator_signatures: vec![],
            recipient_sig: vec![0u8; 65],
            recipient_pubkey: make_tagged_pubkey(0x01),
            preferred_relayer: None,
        };
        let result = bridge_verify(&mut registry, &tx, crate::DEFAULT_CHAIN_ID, true);
        assert!(matches!(
            result,
            Err(PokerL1Error::BridgeSignatureInvalid(_))
        ));
    }

    // ===== native burn nonce tests =====

    #[test]
    fn test_record_burn_nonce_success() {
        let mut registry = BridgeRegistry::new();
        let burn = BurnProof {
            burn_nonce: 1,
            source_chain_id: 0xAAAA,
            dest_chain_id: crate::DEFAULT_CHAIN_ID,
            asset: [0xAB; 32],
            amount: 500,
            recipient: make_addr(0x02),
            burn_tx_hash: [0xEF; 32],
        };
        record_burn_nonce(&mut registry, &burn, crate::DEFAULT_CHAIN_ID).unwrap();
        // 重复 burn → 失败
        let result = record_burn_nonce(&mut registry, &burn, crate::DEFAULT_CHAIN_ID);
        assert!(matches!(result, Err(PokerL1Error::BurnProofInvalid(_))));
    }

    #[test]
    fn test_record_burn_nonce_chain_mismatch() {
        let mut registry = BridgeRegistry::new();
        let burn = BurnProof {
            burn_nonce: 1,
            source_chain_id: 0xAAAA,
            dest_chain_id: 0x9999, // 错误
            asset: [0xAB; 32],
            amount: 500,
            recipient: make_addr(0x02),
            burn_tx_hash: [0xEF; 32],
        };
        let result = record_burn_nonce(&mut registry, &burn, crate::DEFAULT_CHAIN_ID);
        assert!(matches!(result, Err(PokerL1Error::BurnProofInvalid(_))));
    }

    #[test]
    fn burn_wrapped_object_consumes_only_the_callers_asset_and_derives_amount() {
        let owner = make_addr(0x11);
        let object_id = ObjectID::new(owner, 77);
        let wrapped = WrappedAsset {
            source_chain_id: 0xAAAA,
            asset: [0xAB; 32],
            amount: 500,
        };
        let object = Object::new(
            object_id,
            Ownership::AddressOwned { owner },
            BRIDGE_WRAPPED_OBJECT_TYPE,
            borsh::to_vec(&wrapped).unwrap(),
            None,
        );
        let mut db = ObjectDb::open_inmemory().unwrap();
        db.create(object).unwrap();
        let mut registry = BridgeRegistry::new();
        let request = BridgeBurnTx {
            wrapped_object_id: object_id,
            burn_nonce: 12,
            source_chain_id: 0xAAAA,
            recipient: make_addr(0x22),
        };

        let proof = burn_wrapped_object(
            &mut registry,
            &mut db,
            owner,
            &request,
            crate::DEFAULT_CHAIN_ID,
            [0xEF; 32],
        )
        .unwrap();
        assert_eq!(proof.amount, 500);
        assert_eq!(proof.asset, [0xAB; 32]);
        assert_eq!(proof.burn_tx_hash, [0xEF; 32]);
        assert!(
            db.read(&object_id).is_err(),
            "burn must delete wrapped object"
        );
        assert!(registry.is_burn_nonce_consumed(crate::DEFAULT_CHAIN_ID, 12));
    }

    #[test]
    fn burn_wrapped_object_rejects_wrong_owner_without_consuming_asset_or_nonce() {
        let owner = make_addr(0x11);
        let object_id = ObjectID::new(owner, 77);
        let object = Object::new(
            object_id,
            Ownership::AddressOwned { owner },
            BRIDGE_WRAPPED_OBJECT_TYPE,
            borsh::to_vec(&WrappedAsset {
                source_chain_id: 0xAAAA,
                asset: [0xAB; 32],
                amount: 500,
            })
            .unwrap(),
            None,
        );
        let mut db = ObjectDb::open_inmemory().unwrap();
        db.create(object).unwrap();
        let mut registry = BridgeRegistry::new();
        let request = BridgeBurnTx {
            wrapped_object_id: object_id,
            burn_nonce: 12,
            source_chain_id: 0xAAAA,
            recipient: make_addr(0x22),
        };

        assert!(matches!(
            burn_wrapped_object(
                &mut registry,
                &mut db,
                make_addr(0x33),
                &request,
                crate::DEFAULT_CHAIN_ID,
                [0xEF; 32],
            ),
            Err(PokerL1Error::BurnProofInvalid(_))
        ));
        assert!(db.read(&object_id).is_ok());
        assert!(!registry.is_burn_nonce_consumed(crate::DEFAULT_CHAIN_ID, 12));
    }

    // ===== BurnProof 测试 =====

    #[test]
    fn test_burn_proof_message_hash() {
        let burn1 = BurnProof {
            burn_nonce: 1,
            source_chain_id: 0xAAAA,
            dest_chain_id: crate::DEFAULT_CHAIN_ID,
            asset: [0xAB; 32],
            amount: 500,
            recipient: make_addr(0x02),
            burn_tx_hash: [0xEF; 32],
        };
        let burn2 = burn1.clone();
        assert_eq!(burn1.message_hash(), burn2.message_hash());

        // 不同 burn_nonce → 不同哈希
        let mut burn3 = burn1.clone();
        burn3.burn_nonce = 2;
        assert_ne!(burn1.message_hash(), burn3.message_hash());
    }

    // ===== bridge_verify_contract_call_denied 测试 =====

    #[test]
    fn test_bridge_verify_contract_call_denied() {
        let err = bridge_verify_contract_call_denied();
        assert!(matches!(err, PokerL1Error::BridgeVerifyNotAuthorized));
    }

    // ===== derive_address 测试 =====

    #[test]
    fn test_derive_address_deterministic() {
        let pk = make_tagged_pubkey(0x01);
        let addr1 = derive_address(&pk);
        let addr2 = derive_address(&pk);
        assert_eq!(addr1, addr2);
        // 不同 pubkey → 不同地址
        let pk2 = make_tagged_pubkey(0x02);
        let addr3 = derive_address(&pk2);
        assert_ne!(addr1, addr3);
    }

    #[test]
    fn bridge_config_update_requires_active_validator_supermajority_and_binds_state() {
        let secp = Secp256k1::new();
        let (secret_a, _, validator_a) = make_real_keypair();
        let (secret_b, _, validator_b) = make_real_keypair();
        let (secret_c, _, validator_c) = make_real_keypair();
        let active = BTreeSet::from([
            validator_a.clone(),
            validator_b.clone(),
            validator_c.clone(),
        ]);
        let current = BridgeRegistryConfig::empty(crate::DEFAULT_CHAIN_ID);
        let slot = BridgeValidatorSlot::new(0xAAAA, BTreeSet::from([validator_a.clone()]));
        let next = BridgeRegistryConfig {
            chain_id: crate::DEFAULT_CHAIN_ID,
            slots: BTreeMap::from([(slot.source_chain_id, slot)]),
        };
        let mut update = BridgeConfigUpdate {
            expected_version: 0,
            expected_config_hash: current.commitment_hash(),
            next_config: next,
            signatures: Vec::new(),
        };
        let message = update.message_hash();
        update.signatures = vec![
            BridgeConfigSignature {
                validator: validator_a.clone(),
                signature: sign_with_key(&secp, &secret_a, &message),
            },
            BridgeConfigSignature {
                validator: validator_b.clone(),
                signature: sign_with_key(&secp, &secret_b, &message),
            },
            BridgeConfigSignature {
                validator: validator_c.clone(),
                signature: sign_with_key(&secp, &secret_c, &message),
            },
        ];

        validate_bridge_config_update(&update, &current, 0, &active, crate::DEFAULT_CHAIN_ID)
            .expect("three of three active validators authorize the exact transition");

        let mut stale = update.clone();
        stale.expected_version = 1;
        assert!(
            validate_bridge_config_update(&stale, &current, 0, &active, crate::DEFAULT_CHAIN_ID,)
                .is_err()
        );

        let mut duplicate = update.clone();
        duplicate.signatures[2] = duplicate.signatures[0].clone();
        assert!(matches!(
            validate_bridge_config_update(
                &duplicate,
                &current,
                0,
                &active,
                crate::DEFAULT_CHAIN_ID,
            ),
            Err(PokerL1Error::DuplicateBridgeValidator(_))
        ));

        let mut insufficient = update.clone();
        insufficient.signatures.pop();
        assert!(
            validate_bridge_config_update(
                &insufficient,
                &current,
                0,
                &active,
                crate::DEFAULT_CHAIN_ID,
            )
            .is_err()
        );
    }

    #[test]
    fn bridge_replay_state_commits_every_nonce_set_change() {
        let mut registry = BridgeRegistry::new();
        let empty = BridgeReplayState::empty(crate::DEFAULT_CHAIN_ID);
        assert!(empty.matches_registry(&registry));

        registry.consume_nonce(0xAAAA, 7);
        assert!(!empty.matches_registry(&registry));
        let (nonce_root, deposit_nonce_count, burn_nonce_count) = registry.replay_commitment();
        let committed = BridgeReplayState {
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce_root,
            deposit_nonce_count,
            burn_nonce_count,
        };
        assert!(committed.matches_registry(&registry));

        registry.consume_burn_nonce(crate::DEFAULT_CHAIN_ID, 9);
        assert!(!committed.matches_registry(&registry));
    }

    #[test]
    fn bridge_system_object_ids_do_not_collide_with_other_consensus_singletons() {
        // These objects are created together during genesis.  A shared ObjectID would silently
        // replace one singleton with another inside the same ObjectDb batch, so retain this
        // invariant as a direct regression test rather than relying on later decode failures.
        assert_ne!(
            BRIDGE_REGISTRY_CONFIG_OBJECT_ID,
            crate::economics::TREASURY_CAP_OBJECT_ID
        );
        assert_ne!(
            BRIDGE_REGISTRY_CONFIG_OBJECT_ID,
            crate::economics::FEE_POLICY_OBJECT_ID
        );
        assert_ne!(
            BRIDGE_REGISTRY_CONFIG_OBJECT_ID,
            crate::consensus::validator_set::VALIDATOR_SET_OBJECT_ID
        );
        assert_ne!(
            BRIDGE_REPLAY_STATE_OBJECT_ID,
            crate::economics::TREASURY_CAP_OBJECT_ID
        );
        assert_ne!(
            BRIDGE_REPLAY_STATE_OBJECT_ID,
            crate::economics::FEE_POLICY_OBJECT_ID
        );
        assert_ne!(
            BRIDGE_REPLAY_STATE_OBJECT_ID,
            crate::consensus::validator_set::VALIDATOR_SET_OBJECT_ID
        );
        assert_ne!(
            BRIDGE_REGISTRY_CONFIG_OBJECT_ID,
            BRIDGE_REPLAY_STATE_OBJECT_ID
        );
    }

    // ===== 缺口 #9：mint_wrapped_object 铸币测试 =====

    #[test]
    fn mint_wrapped_object_creates_correct_object_and_changes_state_root() {
        // 端到端：构造 outcome → mint → wrapped Object 落库（type/owner/data 正确，
        // state_root 变化）。
        let mut db = crate::storage::ObjectDb::open_inmemory().expect("open ObjectDb");
        let root_before = db.state_root();

        let recipient = [0x99u8; 20];
        let deposit = make_deposit(1, 5000, recipient);
        let outcome = BridgeVerifyOutcome {
            deposit: deposit.clone(),
            recipient,
            preferred_relayer: None,
        };
        let creation_nonce = 0x0100_0000_0000_0001u64;
        let obj_id =
            mint_wrapped_object(&outcome, &mut db, creation_nonce).expect("mint wrapped object");

        // state_root 应变化（新对象入 SMT）。
        let root_after = db.state_root();
        assert_ne!(root_before, root_after, "铸币后 state_root 应变化");

        // 读回对象校验。
        let obj = db.read(&obj_id).expect("read minted object");
        assert_eq!(
            obj.owner,
            crate::object_model::Ownership::AddressOwned { owner: recipient }
        );
        assert_eq!(
            obj.object_type.as_str(),
            BRIDGE_WRAPPED_OBJECT_TYPE,
            "对象类型应为 bridge-wrapped-asset"
        );
        // data 解码为 WrappedAsset，字段与 deposit 一致。
        let wrapped: WrappedAsset = borsh::from_slice(&obj.data).expect("decode WrappedAsset");
        assert_eq!(wrapped.source_chain_id, deposit.source_chain_id);
        assert_eq!(wrapped.asset, deposit.asset);
        assert_eq!(wrapped.amount, deposit.amount);
    }

    #[test]
    fn mint_wrapped_object_is_deterministic() {
        // 出块/验块双方用相同 (recipient, creation_nonce) → 相同 ObjectID → 相同 state_root。
        let recipient = [0x77u8; 20];
        let deposit = make_deposit(2, 300, recipient);
        let outcome = BridgeVerifyOutcome {
            deposit,
            recipient,
            preferred_relayer: None,
        };
        let creation_nonce = 42u64;

        let mut db1 = crate::storage::ObjectDb::open_inmemory().expect("db1");
        let mut db2 = crate::storage::ObjectDb::open_inmemory().expect("db2");
        let id1 = mint_wrapped_object(&outcome, &mut db1, creation_nonce).expect("mint1");
        let id2 = mint_wrapped_object(&outcome, &mut db2, creation_nonce).expect("mint2");
        assert_eq!(id1, id2, "确定性 ObjectID");
        assert_eq!(db1.state_root(), db2.state_root(), "确定性 state_root");
    }
}
