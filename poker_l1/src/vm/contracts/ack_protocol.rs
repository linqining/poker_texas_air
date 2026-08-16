//! ACK 协议 — request_ack / refuse_ack / ack_deadline / 恶意 refuse_ack 累计
//! （Task 27 — SubTask 27.6 / 27.7 / 27.8 / 27.9）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 27.6**：`request_ack` tx（任意 validator，免 gas），链上设定
//!   `ack_deadline = block.height + ack_deadline_blocks`（默认 3，SEC2-H1 下限 10），
//!   写入 `Game.pending_ack_requests`。每 Game 每参与者同时只允许 1 个 active
//!   请求（NEW-M7）。同一 Game 在 `turn_timeout_blocks` 内最多
//!   `min(活跃参与者数, max_request_ack_per_turn_timeout)` 次（R4-M2）。
//!   **R3-H6**：`request_ack` 不更新 `last_action_height`。
//!   **R5-L6**：P 提交 ACK 或 refuse_ack 后立即清除 pending request。
//!   **SEC2-H1**：`ack_deadline_blocks` 下限 10；操作方提交 request_ack 后须等待
//!   `ack_grace_period_blocks`（默认 3）方可提交 opt_out_ack_proof。
//! - **SubTask 27.7**：`refuse_ack` tx（任意 validator，免 gas）：参与者须在 deadline
//!   内提交 `(game_id, request_id, reason, evidence)`。签名对象 =
//!   `hash(chain_id || game_id || request_id || reason)`（R4-H7）。
//!   evidence 验证失败 → 该参与者 forfeit 保证金；进入 dispute 流程。
//! - **SubTask 27.8**：`ack_deadline` 逾期 opt-out：`block.height > ack_deadline`
//!   且无 ACK 无 refuse_ack → 视为默认 ACK。
//! - **SubTask 27.9**：治理 slashing 恶意 refuse_ack：累计 `malicious_refuse_count`
//!   >= `malicious_refuse_threshold`（默认 3）→ 罚没保证金。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::ChainId;
use crate::account::derive_address;
use crate::error::PokerL1Error;
use crate::object_model::ObjectID;
use crate::signature::{TaggedPubkey, verify_signature};

use super::types::GameContract;

/// ack_deadline_blocks 默认值（SubTask 27.6）。
pub const DEFAULT_ACK_DEADLINE_BLOCKS: u64 = 3;
/// ack_deadline_blocks 下限（SEC2-H1：覆盖网络抖动 + DDoS）。
pub const MIN_ACK_DEADLINE_BLOCKS: u64 = 10;
/// ack_grace_period_blocks 默认值（SEC2-H1：操作方提交 request_ack 后须等待
/// 此 block 数方可提交 opt_out_ack_proof）。
pub const DEFAULT_ACK_GRACE_PERIOD_BLOCKS: u64 = 3;
/// max_request_ack_per_turn_timeout 上限（NEW-M7 / R4-M2）。
pub const MAX_REQUEST_ACK_PER_TURN_TIMEOUT: u32 = 10;
/// malicious_refuse_threshold 默认值（SubTask 27.9）。
pub const DEFAULT_MALICIOUS_REFUSE_THRESHOLD: u32 = 3;

/// refuse_ack 原因枚举（SubTask 27.7）。
///
/// 编码为 u8 用于签名域。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RefuseAckReason {
    /// 操作方提交了无效状态（state_hash 与链下执行结果不符）。
    InvalidState = 0x01,
    /// 操作方 equivocation（对同一 step_index 签不同 action）。
    OperatorEquivocation = 0x02,
    /// 数据不可用（操作方未提供必要数据）。
    DataUnavailable = 0x03,
    /// 其他原因（须附详细 evidence）。
    Other = 0x04,
}

impl RefuseAckReason {
    /// 编码为单字节。
    #[must_use]
    pub const fn as_byte(&self) -> u8 {
        *self as u8
    }

    /// 从字节解码。
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::InvalidState),
            0x02 => Some(Self::OperatorEquivocation),
            0x03 => Some(Self::DataUnavailable),
            0x04 => Some(Self::Other),
            _ => None,
        }
    }
}

impl borsh::BorshSerialize for RefuseAckReason {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(&[self.as_byte()])
    }
}

impl borsh::BorshDeserialize for RefuseAckReason {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Self::from_byte(buf[0]).ok_or_else(|| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "invalid RefuseAckReason byte",
            )
        })
    }
}

/// request_ack tx（SubTask 27.6）。
///
/// 操作方请求特定参与者对当前 checkpoint 状态提交 ACK。
/// 免 gas，走 CheckpointAnchor 通道（与 checkpoint_anchor 同路由）。
///
/// 链上设定 `ack_deadline = block.height + ack_deadline_blocks`，
/// 写入 `Game.pending_ack_requests[participant_address] = ack_deadline`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RequestAckTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// 被请求 ACK 的参与者 tagged pubkey。
    pub target_participant: TaggedPubkey,
}

/// refuse_ack tx（SubTask 27.7）。
///
/// 参与者须在 ack_deadline 内提交，附 reason + evidence。
/// 签名对象 = `hash(chain_id || game_id || request_id || reason)`（R4-H7）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RefuseAckTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// request_id（= 对应 pending request 的 ack_deadline）。
    pub request_id: u64,
    /// 拒绝原因。
    pub reason: RefuseAckReason,
    /// 证据数据（格式取决于 reason）。
    pub evidence: Vec<u8>,
    /// 拒绝方 tagged pubkey。
    pub participant: TaggedPubkey,
    /// 拒绝方签名（签名对象 = hash(chain_id || game_id || request_id || reason)）。
    pub signature: Vec<u8>,
}

impl RefuseAckTx {
    /// 计算 refuse_ack 签名域哈希（R4-H7）。
    ///
    /// `hash(chain_id || game_id || request_id || reason)`
    #[must_use]
    pub fn signing_hash(&self, chain_id: ChainId) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&chain_id.to_be_bytes());
        hasher.update(&self.game_id.to_bytes());
        hasher.update(&self.request_id.to_be_bytes());
        hasher.update(&[self.reason.as_byte()]);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }
}

/// 应用 request_ack 到 GameContract（SubTask 27.6）。
///
/// 校验与状态更新：
/// 1. **NEW-M7 频率限制**：每 Game 每参与者同时只允许 1 个 active pending request
///    - 若已有未过期请求 → `PendingAckExists`
/// 2. **NEW-M7 总量限制**：active pending requests 数 < `min(active_count, MAX)`
///    - 超出 → `RequestAckTooFrequent`
/// 3. 设定 `ack_deadline = block_height + ack_deadline_blocks`
/// 4. 写入 `game.pending_ack_requests[addr] = ack_deadline`
/// 5. **R3-H6**：不更新 `last_action_height`
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `tx`：request_ack tx
/// - `block_height`：当前 block height
/// - `ack_deadline_blocks`：ack_deadline 时长（须 >= `MIN_ACK_DEADLINE_BLOCKS`）
/// - `active_participant_count`：当前活跃参与者数（用于总量限制）
/// - `chain_id`：链 ID（用于日志/审计，不参与签名域）
pub fn apply_request_ack(
    game: &mut GameContract,
    tx: &RequestAckTx,
    block_height: u64,
    ack_deadline_blocks: u64,
    active_participant_count: u32,
) -> Result<u64, PokerL1Error> {
    // SEC2-H1: ack_deadline_blocks 下限校验
    if ack_deadline_blocks < MIN_ACK_DEADLINE_BLOCKS {
        return Err(PokerL1Error::Other(format!(
            "ack_deadline_blocks {} < MIN_ACK_DEADLINE_BLOCKS {}",
            ack_deadline_blocks, MIN_ACK_DEADLINE_BLOCKS
        )));
    }

    let target_addr = derive_address(&tx.target_participant);

    // NEW-M7: 每 Game 每参与者同时只允许 1 个 active pending request
    if let Some(&existing_deadline) = game.pending_ack_requests.get(&target_addr) {
        // R5-L6: ack_deadline 未过期前不得提交新 request_ack
        if block_height <= existing_deadline {
            return Err(PokerL1Error::PendingAckExists {
                game_id: tx.game_id,
                target: tx.target_participant.clone(),
            });
        }
    }

    // NEW-M7 / R4-M2: 总量限制
    let active_pending_count = game
        .pending_ack_requests
        .values()
        .filter(|&&deadline| block_height <= deadline)
        .count() as u32;
    let limit = active_participant_count.min(MAX_REQUEST_ACK_PER_TURN_TIMEOUT);
    if active_pending_count >= limit {
        return Err(PokerL1Error::RequestAckTooFrequent {
            actual: active_pending_count,
            limit,
        });
    }

    // 设定 ack_deadline
    let ack_deadline = block_height
        .checked_add(ack_deadline_blocks)
        .ok_or_else(|| PokerL1Error::Other("ack_deadline overflow".to_string()))?;

    // 写入 pending_ack_requests（request_id = ack_deadline）
    game.pending_ack_requests.insert(target_addr, ack_deadline);
    game.version = game.version.saturating_add(1);

    // R3-H6: 不更新 last_action_height

    Ok(ack_deadline)
}

/// 应用 refuse_ack 到 GameContract（SubTask 27.7 / 27.9）。
///
/// 校验与状态更新：
/// 1. 检查 pending request 存在：`pending_ack_requests[addr] == Some(request_id)`
/// 2. 检查在 deadline 内：`block_height <= ack_deadline`（SEC2-L6: <= 边界）
/// 3. 验证参与者签名
/// 4. **R5-L6**：清除 pending request
/// 5. 若 evidence 为空 → 视为恶意 refuse_ack → `malicious_refuse_count += 1`
/// 6. 若 `malicious_refuse_count >= threshold` → 返回 slashing 信号
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `tx`：refuse_ack tx
/// - `block_height`：当前 block height
/// - `chain_id`：链 ID（签名域）
/// - `malicious_refuse_threshold`：恶意 refuse_ack 累计阈值
///
/// # 返回
/// - `Ok(true)`：达到恶意 refuse_ack 阈值，触发 slashing
/// - `Ok(false)`：refuse_ack 接受，未达阈值
pub fn apply_refuse_ack(
    game: &mut GameContract,
    tx: &RefuseAckTx,
    block_height: u64,
    chain_id: ChainId,
    malicious_refuse_threshold: u32,
) -> Result<bool, PokerL1Error> {
    let participant_addr = derive_address(&tx.participant);

    // 检查 pending request 存在且 request_id 匹配
    let ack_deadline = game
        .pending_ack_requests
        .get(&participant_addr)
        .copied()
        .ok_or_else(|| {
            PokerL1Error::Other(format!(
                "no pending ack request for participant {:?}",
                tx.participant
            ))
        })?;

    if ack_deadline != tx.request_id {
        return Err(PokerL1Error::Other(format!(
            "request_id mismatch: expected {}, got {}",
            ack_deadline, tx.request_id
        )));
    }

    // SEC2-L6: 检查在 deadline 内（<= 边界，包含边界）
    if block_height > ack_deadline {
        return Err(PokerL1Error::Other(format!(
            "refuse_ack after deadline: block_height {} > ack_deadline {}",
            block_height, ack_deadline
        )));
    }

    // 验证参与者签名
    let msg_hash = tx.signing_hash(chain_id);
    verify_signature(&tx.participant, &tx.signature, &msg_hash)?;

    // R5-L6: 清除 pending request
    game.pending_ack_requests.remove(&participant_addr);

    // 检查 evidence 是否为空（基本校验 — 完整 evidence 验证由调用方/治理层处理）
    let is_malicious = tx.evidence.is_empty();
    if is_malicious {
        game.malicious_refuse_count = game.malicious_refuse_count.saturating_add(1);
    }

    game.version = game.version.saturating_add(1);

    // SubTask 27.9: 检查是否达到恶意 refuse_ack 阈值
    let should_slash = game.malicious_refuse_count >= malicious_refuse_threshold;
    Ok(should_slash)
}

/// 清除已完成的 pending ACK 请求（R5-L6）。
///
/// 当参与者提交 ACK（通过 checkpoint_anchor）后，调用此函数清除其 pending request。
/// 无需等 ack_deadline 过期即可重新 request_ack。
pub fn clear_pending_ack(game: &mut GameContract, participant: &TaggedPubkey) {
    let addr = derive_address(participant);
    if game.pending_ack_requests.remove(&addr).is_some() {
        game.version = game.version.saturating_add(1);
    }
}

/// 清除已过期的 pending ACK 请求。
///
/// 供 validator 在每个 block 调用，清理过期的 pending requests。
/// 过期后视为默认 ACK（SubTask 27.8），可被 opt_out_ack_proof 使用。
///
/// # 返回
/// 被清除的参与者地址列表（供 opt_out_ack_proof 构造参考）。
pub fn clear_expired_pending_acks(
    game: &mut GameContract,
    current_block_height: u64,
) -> Vec<crate::Address> {
    let expired_addrs: Vec<crate::Address> = game
        .pending_ack_requests
        .iter()
        .filter(|&(_, &deadline)| current_block_height > deadline)
        .map(|(&addr, _)| addr)
        .collect();

    if !expired_addrs.is_empty() {
        for addr in &expired_addrs {
            game.pending_ack_requests.remove(addr);
        }
        game.version = game.version.saturating_add(1);
    }

    expired_addrs
}

/// 检查参与者的 pending ACK 请求是否已逾期（SubTask 27.8）。
///
/// `block.height > ack_deadline` 且无 ACK 无 refuse_ack → 视为默认 ACK。
///
/// # 返回
/// - `Some(ack_deadline)`：有 pending request 且已逾期
/// - `None`：无 pending request 或未逾期
#[must_use]
pub fn check_ack_deadline_expired(
    game: &GameContract,
    participant: &TaggedPubkey,
    current_block_height: u64,
) -> Option<u64> {
    let addr = derive_address(participant);
    let &ack_deadline = game.pending_ack_requests.get(&addr)?;
    if current_block_height > ack_deadline {
        Some(ack_deadline)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{CURRENT_VERSION, SignatureScheme};
    use crate::vm::contracts::types::{ExecutionMode, RakeConfigRef};

    fn make_test_tagged_pubkey(byte: u8) -> TaggedPubkey {
        let mut raw = vec![byte];
        raw.extend_from_slice(&[0x02u8; 32]);
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw)
            .expect("构造 tagged pubkey 不应失败")
    }

    fn make_addr(byte: u8) -> crate::Address {
        [byte; 20]
    }

    fn make_game_id() -> ObjectID {
        ObjectID::new(make_addr(0x01), 1)
    }

    fn make_minimal_game() -> GameContract {
        GameContract::new(
            make_game_id(),
            make_addr(0x01),
            make_test_tagged_pubkey(0xFF),
            ExecutionMode::OffChain,
            RakeConfigRef {
                rake_rate_bps: 0,
                rake_cap: 0,
                rake_recipient: make_addr(0x00),
            },
            10,
        )
    }

    #[test]
    fn test_refuse_ack_reason_encoding() {
        assert_eq!(RefuseAckReason::InvalidState.as_byte(), 0x01);
        assert_eq!(RefuseAckReason::OperatorEquivocation.as_byte(), 0x02);
        assert_eq!(RefuseAckReason::DataUnavailable.as_byte(), 0x03);
        assert_eq!(RefuseAckReason::Other.as_byte(), 0x04);

        assert_eq!(
            RefuseAckReason::from_byte(0x01),
            Some(RefuseAckReason::InvalidState)
        );
        assert_eq!(
            RefuseAckReason::from_byte(0x04),
            Some(RefuseAckReason::Other)
        );
        assert_eq!(RefuseAckReason::from_byte(0x00), None);
        assert_eq!(RefuseAckReason::from_byte(0xFF), None);
    }

    #[test]
    fn test_refuse_ack_signing_hash_deterministic() {
        let tx = RefuseAckTx {
            game_id: make_game_id(),
            request_id: 100,
            reason: RefuseAckReason::InvalidState,
            evidence: vec![],
            participant: make_test_tagged_pubkey(1),
            signature: vec![],
        };
        let h1 = tx.signing_hash(crate::DEFAULT_CHAIN_ID);
        let h2 = tx.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_eq!(h1, h2, "相同输入应产生相同哈希");
    }

    #[test]
    fn test_refuse_ack_signing_hash_differs_by_chain_id() {
        let tx = RefuseAckTx {
            game_id: make_game_id(),
            request_id: 100,
            reason: RefuseAckReason::InvalidState,
            evidence: vec![],
            participant: make_test_tagged_pubkey(1),
            signature: vec![],
        };
        let h1 = tx.signing_hash(1);
        let h2 = tx.signing_hash(2);
        assert_ne!(h1, h2, "不同 chain_id 应产生不同哈希");
    }

    #[test]
    fn test_refuse_ack_signing_hash_differs_by_reason() {
        let tx1 = RefuseAckTx {
            game_id: make_game_id(),
            request_id: 100,
            reason: RefuseAckReason::InvalidState,
            evidence: vec![],
            participant: make_test_tagged_pubkey(1),
            signature: vec![],
        };
        let tx2 = RefuseAckTx {
            game_id: make_game_id(),
            request_id: 100,
            reason: RefuseAckReason::OperatorEquivocation,
            evidence: vec![],
            participant: make_test_tagged_pubkey(1),
            signature: vec![],
        };
        let h1 = tx1.signing_hash(crate::DEFAULT_CHAIN_ID);
        let h2 = tx2.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2, "不同 reason 应产生不同哈希");
    }

    #[test]
    fn test_apply_request_ack_success() {
        let mut game = make_minimal_game();
        let tx = RequestAckTx {
            game_id: make_game_id(),
            target_participant: make_test_tagged_pubkey(1),
        };
        let result = apply_request_ack(
            &mut game,
            &tx,
            500,
            MIN_ACK_DEADLINE_BLOCKS, // 使用下限值
            5,                       // 5 个活跃参与者
        );
        assert!(result.is_ok(), "首次 request_ack 应成功");
        let ack_deadline = result.unwrap();
        assert_eq!(ack_deadline, 500 + MIN_ACK_DEADLINE_BLOCKS);

        // 验证写入 pending_ack_requests
        let target_addr = derive_address(&tx.target_participant);
        assert_eq!(
            game.pending_ack_requests.get(&target_addr),
            Some(&ack_deadline),
            "pending_ack_requests 应包含 ack_deadline"
        );
    }

    #[test]
    fn test_apply_request_ack_deadline_blocks_too_low() {
        let mut game = make_minimal_game();
        let tx = RequestAckTx {
            game_id: make_game_id(),
            target_participant: make_test_tagged_pubkey(1),
        };
        let result = apply_request_ack(
            &mut game,
            &tx,
            500,
            MIN_ACK_DEADLINE_BLOCKS - 1, // 低于下限
            5,
        );
        assert!(result.is_err(), "ack_deadline_blocks < 下限应失败");
    }

    #[test]
    fn test_apply_request_ack_pending_exists() {
        let mut game = make_minimal_game();
        let participant = make_test_tagged_pubkey(1);
        let tx = RequestAckTx {
            game_id: make_game_id(),
            target_participant: participant,
        };
        // 首次提交
        let deadline =
            apply_request_ack(&mut game, &tx, 500, MIN_ACK_DEADLINE_BLOCKS, 5).expect("首次应成功");
        // 在 deadline 内再次提交 → PendingAckExists
        let result = apply_request_ack(
            &mut game,
            &tx,
            500 + MIN_ACK_DEADLINE_BLOCKS - 1,
            MIN_ACK_DEADLINE_BLOCKS,
            5,
        );
        assert!(
            matches!(result, Err(PokerL1Error::PendingAckExists { .. })),
            "未过期前重复提交应返回 PendingAckExists"
        );
        // deadline 过期后可重新提交
        let result = apply_request_ack(&mut game, &tx, deadline + 1, MIN_ACK_DEADLINE_BLOCKS, 5);
        assert!(result.is_ok(), "过期后应可重新提交");
    }

    #[test]
    fn test_apply_request_ack_too_frequent() {
        let mut game = make_minimal_game();
        // 活跃参与者数 = 2，所以 limit = min(2, 10) = 2
        // 提交 2 个不同参与者的 request_ack（达到 limit）
        let tx1 = RequestAckTx {
            game_id: make_game_id(),
            target_participant: make_test_tagged_pubkey(1),
        };
        let tx2 = RequestAckTx {
            game_id: make_game_id(),
            target_participant: make_test_tagged_pubkey(2),
        };
        apply_request_ack(&mut game, &tx1, 500, MIN_ACK_DEADLINE_BLOCKS, 2).expect("第一个应成功");
        apply_request_ack(&mut game, &tx2, 500, MIN_ACK_DEADLINE_BLOCKS, 2).expect("第二个应成功");

        // 第三个不同参与者 → 超出 limit
        let tx3 = RequestAckTx {
            game_id: make_game_id(),
            target_participant: make_test_tagged_pubkey(3),
        };
        let result = apply_request_ack(&mut game, &tx3, 500, MIN_ACK_DEADLINE_BLOCKS, 2);
        assert!(
            matches!(
                result,
                Err(PokerL1Error::RequestAckTooFrequent {
                    actual: 2,
                    limit: 2
                })
            ),
            "超出 limit 应返回 RequestAckTooFrequent"
        );
    }

    #[test]
    fn test_apply_request_ack_does_not_update_last_action_height() {
        let mut game = make_minimal_game();
        game.last_action_height = 400;
        let tx = RequestAckTx {
            game_id: make_game_id(),
            target_participant: make_test_tagged_pubkey(1),
        };
        apply_request_ack(&mut game, &tx, 500, MIN_ACK_DEADLINE_BLOCKS, 5).expect("应成功");
        // R3-H6: request_ack 不更新 last_action_height
        assert_eq!(
            game.last_action_height, 400,
            "R3-H6: request_ack 不应更新 last_action_height"
        );
    }

    #[test]
    fn test_apply_refuse_ack_no_pending_request() {
        let mut game = make_minimal_game();
        let tx = RefuseAckTx {
            game_id: make_game_id(),
            request_id: 100,
            reason: RefuseAckReason::InvalidState,
            evidence: vec![0xAB],
            participant: make_test_tagged_pubkey(1),
            signature: vec![0u8; 65],
        };
        let result = apply_refuse_ack(
            &mut game,
            &tx,
            500,
            crate::DEFAULT_CHAIN_ID,
            DEFAULT_MALICIOUS_REFUSE_THRESHOLD,
        );
        assert!(result.is_err(), "无 pending request 应失败");
    }

    #[test]
    fn test_apply_refuse_ack_request_id_mismatch() {
        let mut game = make_minimal_game();
        let participant = make_test_tagged_pubkey(1);
        let req_tx = RequestAckTx {
            game_id: make_game_id(),
            target_participant: participant.clone(),
        };
        let ack_deadline = apply_request_ack(&mut game, &req_tx, 500, MIN_ACK_DEADLINE_BLOCKS, 5)
            .expect("request_ack 应成功");

        // request_id 不匹配
        let refuse_tx = RefuseAckTx {
            game_id: make_game_id(),
            request_id: ack_deadline + 1, // 错误的 request_id
            reason: RefuseAckReason::InvalidState,
            evidence: vec![0xAB],
            participant,
            signature: vec![0u8; 65],
        };
        let result = apply_refuse_ack(
            &mut game,
            &refuse_tx,
            501,
            crate::DEFAULT_CHAIN_ID,
            DEFAULT_MALICIOUS_REFUSE_THRESHOLD,
        );
        assert!(result.is_err(), "request_id 不匹配应失败");
    }

    #[test]
    fn test_apply_refuse_ack_after_deadline() {
        let mut game = make_minimal_game();
        let participant = make_test_tagged_pubkey(1);
        let req_tx = RequestAckTx {
            game_id: make_game_id(),
            target_participant: participant.clone(),
        };
        let ack_deadline = apply_request_ack(&mut game, &req_tx, 500, MIN_ACK_DEADLINE_BLOCKS, 5)
            .expect("request_ack 应成功");

        // 在 deadline 之后提交（SEC2-L6: > 边界即过期）
        let refuse_tx = RefuseAckTx {
            game_id: make_game_id(),
            request_id: ack_deadline,
            reason: RefuseAckReason::InvalidState,
            evidence: vec![0xAB],
            participant,
            signature: vec![0u8; 65],
        };
        let result = apply_refuse_ack(
            &mut game,
            &refuse_tx,
            ack_deadline + 1, // 超过 deadline
            crate::DEFAULT_CHAIN_ID,
            DEFAULT_MALICIOUS_REFUSE_THRESHOLD,
        );
        assert!(result.is_err(), "deadline 后提交应失败");
    }

    #[test]
    fn test_apply_refuse_ack_at_deadline_boundary() {
        let mut game = make_minimal_game();
        let participant = make_test_tagged_pubkey(1);
        let req_tx = RequestAckTx {
            game_id: make_game_id(),
            target_participant: participant.clone(),
        };
        let ack_deadline = apply_request_ack(&mut game, &req_tx, 500, MIN_ACK_DEADLINE_BLOCKS, 5)
            .expect("request_ack 应成功");

        // 在 deadline 边界提交（SEC2-L6: <= 包含边界）
        let refuse_tx = RefuseAckTx {
            game_id: make_game_id(),
            request_id: ack_deadline,
            reason: RefuseAckReason::InvalidState,
            evidence: vec![0xAB],
            participant,
            signature: vec![0u8; 65],
        };
        let result = apply_refuse_ack(
            &mut game,
            &refuse_tx,
            ack_deadline, // == deadline，应允许
            crate::DEFAULT_CHAIN_ID,
            DEFAULT_MALICIOUS_REFUSE_THRESHOLD,
        );
        // 签名是占位符，应返回 InvalidSignature（但证明 deadline 边界校验通过）
        assert!(
            matches!(result, Err(PokerL1Error::InvalidSignature)),
            "deadline 边界应允许提交，占位符签名返回 InvalidSignature，got: {:?}",
            result
        );
    }

    #[test]
    fn test_clear_pending_ack() {
        let mut game = make_minimal_game();
        let participant = make_test_tagged_pubkey(1);
        let req_tx = RequestAckTx {
            game_id: make_game_id(),
            target_participant: participant.clone(),
        };
        apply_request_ack(&mut game, &req_tx, 500, MIN_ACK_DEADLINE_BLOCKS, 5)
            .expect("request_ack 应成功");

        let target_addr = derive_address(&participant);
        assert!(game.pending_ack_requests.contains_key(&target_addr));

        clear_pending_ack(&mut game, &participant);
        assert!(
            !game.pending_ack_requests.contains_key(&target_addr),
            "clear_pending_ack 后应移除 pending request"
        );
    }

    #[test]
    fn test_clear_expired_pending_acks() {
        let mut game = make_minimal_game();
        let p1 = make_test_tagged_pubkey(1);
        let p2 = make_test_tagged_pubkey(2);
        let p3 = make_test_tagged_pubkey(3);

        // 3 个 pending requests，deadline 分别为 510, 520, 530
        for (i, p) in [&p1, &p2, &p3].iter().enumerate() {
            let addr = derive_address(p);
            game.pending_ack_requests
                .insert(addr, 510 + (i as u64) * 10);
        }

        // block_height = 525 → p1(510) 和 p2(520) 过期，p3(530) 未过期
        let expired = clear_expired_pending_acks(&mut game, 525);
        assert_eq!(expired.len(), 2, "应有 2 个过期");
        let p1_addr = derive_address(&p1);
        let p2_addr = derive_address(&p2);
        let p3_addr = derive_address(&p3);
        assert!(expired.contains(&p1_addr));
        assert!(expired.contains(&p2_addr));
        assert!(!expired.contains(&p3_addr));

        // p3 仍存在
        assert!(game.pending_ack_requests.contains_key(&p3_addr));
        assert!(!game.pending_ack_requests.contains_key(&p1_addr));
        assert!(!game.pending_ack_requests.contains_key(&p2_addr));
    }

    #[test]
    fn test_check_ack_deadline_expired() {
        let mut game = make_minimal_game();
        let participant = make_test_tagged_pubkey(1);
        let req_tx = RequestAckTx {
            game_id: make_game_id(),
            target_participant: participant.clone(),
        };
        let ack_deadline = apply_request_ack(&mut game, &req_tx, 500, MIN_ACK_DEADLINE_BLOCKS, 5)
            .expect("request_ack 应成功");

        // 未过期
        assert_eq!(
            check_ack_deadline_expired(&game, &participant, ack_deadline),
            None,
            "未过期应返回 None"
        );

        // 过期
        assert_eq!(
            check_ack_deadline_expired(&game, &participant, ack_deadline + 1),
            Some(ack_deadline),
            "过期应返回 Some(ack_deadline)"
        );

        // 无 pending request
        let other = make_test_tagged_pubkey(99);
        assert_eq!(
            check_ack_deadline_expired(&game, &other, 999),
            None,
            "无 pending request 应返回 None"
        );
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_ACK_DEADLINE_BLOCKS, 3);
        assert_eq!(MIN_ACK_DEADLINE_BLOCKS, 10, "SEC2-H1 下限 = 10");
        assert_eq!(DEFAULT_ACK_GRACE_PERIOD_BLOCKS, 3);
        assert_eq!(MAX_REQUEST_ACK_PER_TURN_TIMEOUT, 10);
        assert_eq!(DEFAULT_MALICIOUS_REFUSE_THRESHOLD, 3);
    }
}
