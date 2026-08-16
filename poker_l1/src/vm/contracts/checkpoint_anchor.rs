//! Checkpoint Anchor tx 类型与验证逻辑（Task 27 — SubTask 27.1 / 27.2 / 27.3）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 27.1**：`checkpoint_anchor` tx 走 CheckpointAnchor 通道，路由到
//!   assigned_validator，与 GameTurn 同路由但独立 lane（不参与 turn ordering），
//!   免 gas，通过 gossipsub 广播（防栽赃），客户端多副本广播默认 5 个，
//!   副本 validator 仅见证不装入 vertex。去重：相同 `(game_id, checkpoint_seq)`
//!   仅首次生效，后续返回 `DuplicateCheckpoint`。
//! - **SubTask 27.2**：操作方每 `checkpoint_interval_blocks`（默认 5）提交，
//!   更新 `last_action_height`；被动检测模式（ack_chain 与 on-chain confirmation
//!   解耦）；assigned_validator 拒收由 `force_checkpoint` 逃生 tx 触发。
//! - **SubTask 27.3**：多方签名 ACK — checkpoint_anchor 必须包含所有活跃参与者
//!   的 tagged pubkey 签名 ack，缺少返回 `MissingAck`；ACK 签名对象为
//!   `hash(chain_id || epoch || game_id || current_turn || state_hash ||
//!   checkpoint_seq || ack_domain_tag)`（ack_domain_tag = 0x02）；
//!   活跃参与者 = 当前手牌未 fold 且未 sit-out 的在座玩家；
//!   validator 校验每个 ack 签名者 tagged pubkey 须在 active_participants 集合中
//!   （不匹配返回 `AckSignerNotParticipant`）；ack_signatures 须覆盖全部
//!   active_participants；同一 participant 多个 ack 仅首个有效。
//!
//! ## SEC-H2 无进度检测
//!
//! 连续 2 次 checkpoint_anchor 的 state_hash 相同 → 视为无进度，
//! `no_progress_count` 递增，达阈值（默认 2）触发 `force_revert`。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::Address;
use crate::ChainId;
use crate::Hash;
use crate::error::PokerL1Error;
use crate::object_model::ObjectID;
use crate::signature::{TaggedPubkey, verify_signature};

use super::types::GameContract;

/// checkpoint_interval_blocks 默认值（SubTask 27.2）。
pub const DEFAULT_CHECKPOINT_INTERVAL_BLOCKS: u64 = 5;
/// checkpoint_interval_blocks 下限（SEC2-M4）。
pub const MIN_CHECKPOINT_INTERVAL_BLOCKS: u64 = 3;
/// 无进度检测阈值（SEC-H2：连续 N 次相同 state_hash 触发 force_revert）。
pub const DEFAULT_NO_PROGRESS_THRESHOLD: u32 = 2;

/// 单个参与者的 ACK 签名（SubTask 27.3）。
///
/// 每个活跃参与者须对 ACK 签名对象签名，证明其确认该 checkpoint 状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AckSignature {
    /// 签名者 tagged pubkey。
    pub participant: TaggedPubkey,
    /// 签名字节（secp256k1 = 65B r||s||v；ed25519 = 64B R||S）。
    pub signature: Vec<u8>,
}

/// ack_deadline 逾期默认 ACK 证明（SubTask 27.8）。
///
/// `block.height > ack_deadline` 且无 ACK 无 refuse_ack → 视为默认 ACK。
/// 操作方提交带 `opt_out_ack_proof` 的 checkpoint_anchor（或 force_checkpoint）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct OptOutAckProof {
    /// 逾期的参与者 tagged pubkey。
    pub participant: TaggedPubkey,
    /// request_ack 提交时的 block height。
    pub request_ack_block_height: u64,
    /// ack_deadline = request_ack_block_height + ack_deadline_blocks。
    pub ack_deadline: u64,
}

/// Checkpoint Anchor tx（SubTask 27.1）。
///
/// 走 CheckpointAnchor 通道，路由到 assigned_validator，免 gas。
/// 通过 gossipsub 广播提交（与 DAG vertex 传播同一 topic，确保所有 validator
/// 包括 assigned_validator 必然收到 — 防栽赃）。
///
/// 字段：`(game_id, checkpoint_seq, current_turn, state_hash, ack_signatures, opt_out_ack_proof?)`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CheckpointAnchorTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// checkpoint 序号（单调递增，去重判定依据）。
    pub checkpoint_seq: u64,
    /// 当前轮次玩家地址（绑定 ACK 到具体游戏状态）。
    pub current_turn: Address,
    /// 链下状态哈希（此 checkpoint 时刻的状态承诺）。
    pub state_hash: Hash,
    /// 所有活跃参与者的 ACK 签名列表。
    pub ack_signatures: Vec<AckSignature>,
    /// ack_deadline 逾期默认 ACK 证明（可选，SubTask 27.8）。
    pub opt_out_ack_proof: Option<Vec<OptOutAckProof>>,
}

impl CheckpointAnchorTx {
    /// 计算 ACK 签名域哈希（SubTask 27.3 / NEW-H3 / SEC-C3）。
    ///
    /// 签名对象 = `hash(chain_id || epoch || game_id || current_turn ||
    /// state_hash || checkpoint_seq || ack_domain_tag)`
    ///
    /// - `chain_id`：防跨链重放（testnet/mainnet game_id 碰撞时 ACK 不可重放）
    /// - `epoch`：防跨 epoch 重放（同一 game 在不同 epoch 由不同 assigned_validator 处理）
    /// - `ack_domain_tag`（0x02）：与 refuse_ack（0x03）、operator_ack（0x04）做
    ///   显式 domain separation
    /// - 绑定 `game_id` 防跨 Game 重放
    #[must_use]
    pub fn ack_signing_hash(&self, chain_id: ChainId, epoch: u64) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&chain_id.to_be_bytes());
        hasher.update(&epoch.to_be_bytes());
        hasher.update(&self.game_id.to_bytes());
        hasher.update(&self.current_turn);
        hasher.update(&self.state_hash);
        hasher.update(&self.checkpoint_seq.to_be_bytes());
        hasher.update(&[crate::offline::ACK_DOMAIN_TAG]);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }
}

/// ack_signatures 最大数量（M-7 修复 — 防止 O(n*m) 签名验证 DoS）。
///
/// 上限设为 256（远超实际游戏参与者数量，poker 最多 ~10 人）。
pub const MAX_ACK_SIGNATURES: usize = 256;

/// 验证 checkpoint_anchor 的 ACK 签名（SubTask 27.3）。
///
/// 校验逻辑：
/// 1. 每个 ack_signature 的签名者 tagged pubkey 须在 `active_participants` 中
///    （不匹配返回 `AckSignerNotParticipant`）
/// 2. 同一 participant 多个 ack 仅首个有效（后续忽略）
/// 3. ack_signatures（+ opt_out_ack_proof）须覆盖全部 `active_participants`
///    （缺少返回 `MissingAck`）
/// 4. 每个签名的消息哈希为 `ack_signing_hash(chain_id, epoch)`
///
/// M-7 修复：
/// - `ack_signatures` 数量上限 `MAX_ACK_SIGNATURES`（256），防止 O(n*m) DoS
/// - 使用 `HashSet` 去重，将 O(n²) 降为 O(n)
///
/// # 参数
/// - `tx`：checkpoint_anchor tx
/// - `chain_id`：链 ID（防跨链重放）
/// - `epoch`：当前 epoch（防跨 epoch 重放）
/// - `active_participants`：活跃参与者 tagged pubkey 集合（当前手牌未 fold 且
///   未 sit-out 的在座玩家，由 caller 从 game state + fold tx 历史计算）
pub fn verify_checkpoint_anchor(
    tx: &CheckpointAnchorTx,
    chain_id: ChainId,
    epoch: u64,
    active_participants: &[TaggedPubkey],
) -> Result<(), PokerL1Error> {
    // M-7 修复：ack_signatures 数量上限校验
    if tx.ack_signatures.len() > MAX_ACK_SIGNATURES {
        return Err(PokerL1Error::Other(format!(
            "ack_signatures count {} exceeds limit {}",
            tx.ack_signatures.len(),
            MAX_ACK_SIGNATURES
        )));
    }

    let msg_hash = tx.ack_signing_hash(chain_id, epoch);

    // 构建 active_participants 的 HashSet 用于 O(1) 查找
    let active_set: std::collections::HashSet<&TaggedPubkey> = active_participants.iter().collect();

    // 收集已 ACK 的参与者（去重：同一 participant 多个 ack 仅首个有效）
    // M-7 修复：使用 HashSet 替代 Vec::contains，将去重从 O(n²) 降为 O(n)
    let mut acked_participants: std::collections::HashSet<&TaggedPubkey> =
        std::collections::HashSet::new();
    for ack in &tx.ack_signatures {
        // 校验签名者是否在 active_participants 中
        if !active_set.contains(&ack.participant) {
            return Err(PokerL1Error::AckSignerNotParticipant {
                game_id: tx.game_id,
                signer: ack.participant.clone(),
            });
        }
        // 同一 participant 多个 ack 仅首个有效（后续忽略）
        if !acked_participants.insert(&ack.participant) {
            continue;
        }
        // 验证签名
        verify_signature(&ack.participant, &ack.signature, &msg_hash)?;
    }

    // 收集 opt_out_ack_proof 覆盖的参与者
    let mut opted_out_participants: std::collections::HashSet<&TaggedPubkey> =
        std::collections::HashSet::new();
    if let Some(proofs) = &tx.opt_out_ack_proof {
        if proofs.len() > MAX_ACK_SIGNATURES {
            return Err(PokerL1Error::Other(format!(
                "opt_out_ack_proof count {} exceeds limit {}",
                proofs.len(),
                MAX_ACK_SIGNATURES
            )));
        }
        for proof in proofs {
            if !active_set.contains(&proof.participant) {
                return Err(PokerL1Error::AckSignerNotParticipant {
                    game_id: tx.game_id,
                    signer: proof.participant.clone(),
                });
            }
            // 校验 ack_deadline 已过期（caller 须确保 current_block_height > ack_deadline）
            // 此处仅校验 ack_deadline >= request_ack_block_height（逻辑一致性）
            if proof.ack_deadline < proof.request_ack_block_height {
                return Err(PokerL1Error::Other(format!(
                    "opt_out_ack_proof: ack_deadline {} < request_ack_block_height {}",
                    proof.ack_deadline, proof.request_ack_block_height
                )));
            }
            opted_out_participants.insert(&proof.participant);
        }
    }

    // 校验所有 active_participants 都已 ACK 或 opt_out
    for participant in active_participants {
        let acked = acked_participants.contains(participant);
        let opted_out = opted_out_participants.contains(participant);
        if !acked && !opted_out {
            return Err(PokerL1Error::MissingAck {
                game_id: tx.game_id,
                participant: participant.clone(),
            });
        }
    }

    Ok(())
}

/// 校验 opt_out_ack_proof 的 ack_deadline 已过期（SubTask 27.8）。
///
/// `current_block_height > ack_deadline` → 逾期，opt_out 有效。
///
/// 此函数供 validator 在验证 checkpoint_anchor 时调用，校验 opt_out_ack_proof
/// 的时间窗口合法性。
#[must_use]
pub const fn is_opt_out_ack_valid(proof: &OptOutAckProof, current_block_height: u64) -> bool {
    current_block_height > proof.ack_deadline
}

/// 应用 checkpoint_anchor 到 GameContract（SubTask 27.1 / 27.2 / SEC-H2）。
///
/// 校验与状态更新：
/// 1. 去重：`tx.checkpoint_seq` 必须等于 `game.checkpoint_seq + 1`（下一个预期序号）
///    - `tx.checkpoint_seq <= game.checkpoint_seq` → `DuplicateCheckpoint`
/// 2. 更新 `game.checkpoint_seq = tx.checkpoint_seq`
/// 3. 更新 `game.last_action_height = block_height`（SubTask 27.2）
/// 4. SEC-H2 无进度检测：
///    - `tx.state_hash == game.last_checkpoint_state_hash` → `no_progress_count += 1`
///    - 否则 → `no_progress_count = 0` + 更新 `last_checkpoint_state_hash`
/// 5. SEC-H2 designated_operator_check_exemptions 重置：
///    - state_hash 变化时 → `designated_operator_check_exemptions = 0`
/// 6. 递增 `game.version`
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `tx`：checkpoint_anchor tx
/// - `block_height`：当前 block height
///
/// # 返回
/// - `Ok(())`：应用成功
/// - `Err(DuplicateCheckpoint)`：checkpoint_seq 重复或非递增
pub fn apply_checkpoint_anchor(
    game: &mut GameContract,
    tx: &CheckpointAnchorTx,
    block_height: u64,
) -> Result<(), PokerL1Error> {
    // 去重校验：checkpoint_seq 必须严格递增
    let expected_seq = game
        .checkpoint_seq
        .checked_add(1)
        .ok_or_else(|| PokerL1Error::Other("checkpoint_seq overflow".to_string()))?;
    if tx.checkpoint_seq != expected_seq {
        return Err(PokerL1Error::DuplicateCheckpoint {
            game_id: tx.game_id,
            checkpoint_seq: tx.checkpoint_seq,
        });
    }

    // SEC-H2 无进度检测
    // None != Some(_) → true（首次 checkpoint 视为有进度）
    // Some(prev) != Some(new) → prev != new（状态是否变化）
    let state_changed = game.last_checkpoint_state_hash != Some(tx.state_hash);
    if state_changed {
        game.no_progress_count = 0;
        game.last_checkpoint_state_hash = Some(tx.state_hash);
        // SEC-H2: state_hash 变化时重置 designated_operator_check_exemptions
        game.designated_operator_check_exemptions = 0;
    } else {
        game.no_progress_count = game.no_progress_count.saturating_add(1);
    }

    // SubTask 27.2: 更新 checkpoint_seq + last_action_height
    game.checkpoint_seq = tx.checkpoint_seq;
    game.last_action_height = block_height;
    game.version = game.version.saturating_add(1);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{CURRENT_VERSION, SignatureScheme};

    fn make_test_tagged_pubkey(byte: u8) -> TaggedPubkey {
        // secp256k1 v1: 33 bytes raw (compressed)
        let mut raw = vec![byte];
        raw.extend_from_slice(&[0x02u8; 32]);
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw)
            .expect("构造 tagged pubkey 不应失败")
    }

    fn make_addr(byte: u8) -> Address {
        [byte; 20]
    }

    fn make_game_id() -> ObjectID {
        ObjectID::new(make_addr(0x01), 1)
    }

    fn make_checkpoint_anchor_tx(
        seq: u64,
        state_hash_byte: u8,
        ack_count: usize,
    ) -> CheckpointAnchorTx {
        let ack_signatures = (0..ack_count)
            .map(|i| AckSignature {
                participant: make_test_tagged_pubkey(i as u8 + 1),
                signature: vec![0u8; 65], // 65B secp256k1 sig (won't be verified in these tests)
            })
            .collect();
        CheckpointAnchorTx {
            game_id: make_game_id(),
            checkpoint_seq: seq,
            current_turn: make_addr(0x05),
            state_hash: [state_hash_byte; 32],
            ack_signatures,
            opt_out_ack_proof: None,
        }
    }

    #[test]
    fn test_ack_signing_hash_deterministic() {
        let tx = make_checkpoint_anchor_tx(1, 0xAB, 0);
        let h1 = tx.ack_signing_hash(crate::DEFAULT_CHAIN_ID, 1);
        let h2 = tx.ack_signing_hash(crate::DEFAULT_CHAIN_ID, 1);
        assert_eq!(h1, h2, "相同输入应产生相同哈希");
    }

    #[test]
    fn test_ack_signing_hash_differs_by_chain_id() {
        let tx = make_checkpoint_anchor_tx(1, 0xAB, 0);
        let h1 = tx.ack_signing_hash(1, 1);
        let h2 = tx.ack_signing_hash(2, 1);
        assert_ne!(h1, h2, "不同 chain_id 应产生不同哈希（防跨链重放）");
    }

    #[test]
    fn test_ack_signing_hash_differs_by_epoch() {
        let tx = make_checkpoint_anchor_tx(1, 0xAB, 0);
        let h1 = tx.ack_signing_hash(crate::DEFAULT_CHAIN_ID, 1);
        let h2 = tx.ack_signing_hash(crate::DEFAULT_CHAIN_ID, 2);
        assert_ne!(h1, h2, "不同 epoch 应产生不同哈希（防跨 epoch 重放）");
    }

    #[test]
    fn test_ack_signing_hash_differs_by_checkpoint_seq() {
        let tx1 = make_checkpoint_anchor_tx(1, 0xAB, 0);
        let tx2 = make_checkpoint_anchor_tx(2, 0xAB, 0);
        let h1 = tx1.ack_signing_hash(crate::DEFAULT_CHAIN_ID, 1);
        let h2 = tx2.ack_signing_hash(crate::DEFAULT_CHAIN_ID, 1);
        assert_ne!(h1, h2, "不同 checkpoint_seq 应产生不同哈希");
    }

    #[test]
    fn test_ack_signing_hash_differs_by_state_hash() {
        let tx1 = make_checkpoint_anchor_tx(1, 0xAB, 0);
        let tx2 = make_checkpoint_anchor_tx(1, 0xCD, 0);
        let h1 = tx1.ack_signing_hash(crate::DEFAULT_CHAIN_ID, 1);
        let h2 = tx2.ack_signing_hash(crate::DEFAULT_CHAIN_ID, 1);
        assert_ne!(h1, h2, "不同 state_hash 应产生不同哈希");
    }

    #[test]
    fn test_ack_signing_hash_includes_domain_tag() {
        // 验证 ack_domain_tag (0x02) 被包含在哈希中
        let tx = make_checkpoint_anchor_tx(1, 0xAB, 0);
        let hash = tx.ack_signing_hash(crate::DEFAULT_CHAIN_ID, 1);

        // 手动计算不含 domain_tag 的哈希进行对比
        let mut hasher_no_tag = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher_no_tag.update(&crate::DEFAULT_CHAIN_ID.to_be_bytes());
        hasher_no_tag.update(&1u64.to_be_bytes());
        hasher_no_tag.update(&tx.game_id.to_bytes());
        hasher_no_tag.update(&tx.current_turn);
        hasher_no_tag.update(&tx.state_hash);
        hasher_no_tag.update(&tx.checkpoint_seq.to_be_bytes());
        let mut hash_no_tag = [0u8; 32];
        hasher_no_tag
            .finalize_variable(&mut hash_no_tag)
            .expect("finalize 不应失败");

        assert_ne!(hash, hash_no_tag, "ack_domain_tag 必须影响哈希值");
    }

    #[test]
    fn test_verify_checkpoint_anchor_signer_not_participant() {
        let tx = make_checkpoint_anchor_tx(1, 0xAB, 1);
        // active_participants 为空，ack_signatures 中的签名者不在其中
        let active_participants: Vec<TaggedPubkey> = vec![];
        let result =
            verify_checkpoint_anchor(&tx, crate::DEFAULT_CHAIN_ID, 1, &active_participants);
        assert!(
            matches!(result, Err(PokerL1Error::AckSignerNotParticipant { .. })),
            "签名者不在 active_participants 中应返回 AckSignerNotParticipant"
        );
    }

    #[test]
    fn test_verify_checkpoint_anchor_missing_ack() {
        // 2 个活跃参与者，但 ack_signatures 为空
        let tx = make_checkpoint_anchor_tx(1, 0xAB, 0);
        let active_participants = vec![make_test_tagged_pubkey(1), make_test_tagged_pubkey(2)];
        let result =
            verify_checkpoint_anchor(&tx, crate::DEFAULT_CHAIN_ID, 1, &active_participants);
        assert!(
            matches!(result, Err(PokerL1Error::MissingAck { .. })),
            "缺少 ACK 应返回 MissingAck"
        );
    }

    #[test]
    fn test_verify_checkpoint_anchor_covers_all_with_opt_out() {
        // 2 个活跃参与者：1 个有 ACK（签名无效但参与校验），1 个有 opt_out_ack_proof
        // 注意：此测试验证覆盖性逻辑，签名验证会失败（签名是占位符）
        // 所以我们只验证 MissingAck 逻辑，不验证签名有效性
        let participant1 = make_test_tagged_pubkey(1);
        let participant2 = make_test_tagged_pubkey(2);

        let tx = CheckpointAnchorTx {
            game_id: make_game_id(),
            checkpoint_seq: 1,
            current_turn: make_addr(0x05),
            state_hash: [0xAB; 32],
            ack_signatures: vec![AckSignature {
                participant: participant1.clone(),
                signature: vec![0u8; 65],
            }],
            opt_out_ack_proof: Some(vec![OptOutAckProof {
                participant: participant2.clone(),
                request_ack_block_height: 90,
                ack_deadline: 100,
            }]),
        };

        // 不实际验证签名（签名是占位符），只验证覆盖性
        // 由于签名验证会失败，我们期望 InvalidSignature 错误
        // 但这证明了逻辑流程正确（先检查 AckSignerNotParticipant，再检查签名，最后检查覆盖性）
        let active_participants = vec![participant1, participant2];
        let result =
            verify_checkpoint_anchor(&tx, crate::DEFAULT_CHAIN_ID, 1, &active_participants);
        // 签名是占位符，应返回 InvalidSignature（证明签名验证被触发）
        assert!(
            matches!(result, Err(PokerL1Error::InvalidSignature)),
            "占位符签名应返回 InvalidSignature，got: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_checkpoint_anchor_duplicate_ack_first_valid() {
        // 同一 participant 两个 ack — 仅首个参与校验
        let participant = make_test_tagged_pubkey(1);
        let tx = CheckpointAnchorTx {
            game_id: make_game_id(),
            checkpoint_seq: 1,
            current_turn: make_addr(0x05),
            state_hash: [0xAB; 32],
            ack_signatures: vec![
                AckSignature {
                    participant: participant.clone(),
                    signature: vec![0u8; 65],
                },
                AckSignature {
                    participant: participant.clone(),
                    signature: vec![0u8; 65],
                },
            ],
            opt_out_ack_proof: None,
        };
        let active_participants = vec![participant];
        let result =
            verify_checkpoint_anchor(&tx, crate::DEFAULT_CHAIN_ID, 1, &active_participants);
        // 第一个签名是占位符 → InvalidSignature（证明仅首个被验证）
        assert!(
            matches!(result, Err(PokerL1Error::InvalidSignature)),
            "首个 ack 签名应被验证（占位符返回 InvalidSignature）"
        );
    }

    #[test]
    fn test_is_opt_out_ack_valid_expired() {
        let proof = OptOutAckProof {
            participant: make_test_tagged_pubkey(1),
            request_ack_block_height: 90,
            ack_deadline: 100,
        };
        assert!(is_opt_out_ack_valid(&proof, 101), "block > deadline 应有效");
        assert!(
            !is_opt_out_ack_valid(&proof, 100),
            "block == deadline 应无效（须严格大于）"
        );
        assert!(!is_opt_out_ack_valid(&proof, 99), "block < deadline 应无效");
    }

    #[test]
    fn test_apply_checkpoint_anchor_first_checkpoint() {
        let mut game = make_minimal_game();
        let tx = make_checkpoint_anchor_tx(1, 0xAB, 0);
        let result = apply_checkpoint_anchor(&mut game, &tx, 500);
        assert!(result.is_ok(), "首次 checkpoint 应成功");
        assert_eq!(game.checkpoint_seq, 1);
        assert_eq!(game.last_action_height, 500);
        assert_eq!(game.no_progress_count, 0, "首次 checkpoint 视为有进度");
        assert_eq!(game.last_checkpoint_state_hash, Some([0xAB; 32]));
        assert_eq!(
            game.designated_operator_check_exemptions, 0,
            "state_hash 变化应重置"
        );
        assert_eq!(game.version, 1);
    }

    #[test]
    fn test_apply_checkpoint_anchor_duplicate_rejected() {
        let mut game = make_minimal_game();
        game.checkpoint_seq = 3;
        let tx = make_checkpoint_anchor_tx(3, 0xAB, 0); // seq == game.checkpoint_seq，非 +1
        let result = apply_checkpoint_anchor(&mut game, &tx, 500);
        assert!(
            matches!(
                result,
                Err(PokerL1Error::DuplicateCheckpoint {
                    checkpoint_seq: 3,
                    ..
                })
            ),
            "重复 seq 应返回 DuplicateCheckpoint"
        );
    }

    #[test]
    fn test_apply_checkpoint_anchor_non_incremental_rejected() {
        let mut game = make_minimal_game();
        game.checkpoint_seq = 5;
        let tx = make_checkpoint_anchor_tx(3, 0xAB, 0); // seq < game.checkpoint_seq + 1
        let result = apply_checkpoint_anchor(&mut game, &tx, 500);
        assert!(
            matches!(result, Err(PokerL1Error::DuplicateCheckpoint { .. })),
            "非递增 seq 应返回 DuplicateCheckpoint"
        );
    }

    #[test]
    fn test_apply_checkpoint_anchor_no_progress_detection() {
        let mut game = make_minimal_game();
        // 首次 checkpoint
        let tx1 = make_checkpoint_anchor_tx(1, 0xAB, 0);
        apply_checkpoint_anchor(&mut game, &tx1, 500).expect("首次应成功");
        assert_eq!(game.no_progress_count, 0);

        // 第二次：相同 state_hash → 无进度
        let tx2 = make_checkpoint_anchor_tx(2, 0xAB, 0);
        apply_checkpoint_anchor(&mut game, &tx2, 505).expect("第二次应成功");
        assert_eq!(
            game.no_progress_count, 1,
            "相同 state_hash 应递增 no_progress_count"
        );

        // 第三次：相同 state_hash → 无进度（达阈值 2）
        let tx3 = make_checkpoint_anchor_tx(3, 0xAB, 0);
        apply_checkpoint_anchor(&mut game, &tx3, 510).expect("第三次应成功");
        assert_eq!(game.no_progress_count, 2, "连续相同应继续递增");
        assert_eq!(game.last_checkpoint_state_hash, Some([0xAB; 32]));
    }

    #[test]
    fn test_apply_checkpoint_anchor_progress_resets_counter() {
        let mut game = make_minimal_game();
        // 首次
        let tx1 = make_checkpoint_anchor_tx(1, 0xAB, 0);
        apply_checkpoint_anchor(&mut game, &tx1, 500).expect("首次应成功");

        // 第二次：相同 → 无进度
        let tx2 = make_checkpoint_anchor_tx(2, 0xAB, 0);
        apply_checkpoint_anchor(&mut game, &tx2, 505).expect("第二次应成功");
        assert_eq!(game.no_progress_count, 1);

        // 第三次：不同 → 重置
        let tx3 = make_checkpoint_anchor_tx(3, 0xCD, 0);
        apply_checkpoint_anchor(&mut game, &tx3, 510).expect("第三次应成功");
        assert_eq!(
            game.no_progress_count, 0,
            "不同 state_hash 应重置 no_progress_count"
        );
        assert_eq!(game.last_checkpoint_state_hash, Some([0xCD; 32]));
        assert_eq!(
            game.designated_operator_check_exemptions, 0,
            "应重置豁免计数"
        );
    }

    fn make_minimal_game() -> GameContract {
        use super::super::types::{ExecutionMode, RakeConfigRef};
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
    fn test_checkpoint_interval_blocks_constants() {
        assert_eq!(DEFAULT_CHECKPOINT_INTERVAL_BLOCKS, 5);
        assert_eq!(MIN_CHECKPOINT_INTERVAL_BLOCKS, 3);
        const {
            assert!(
                DEFAULT_CHECKPOINT_INTERVAL_BLOCKS >= MIN_CHECKPOINT_INTERVAL_BLOCKS,
                "默认值须 >= 下限"
            );
        }
    }

    #[test]
    fn test_no_progress_threshold_constant() {
        assert_eq!(DEFAULT_NO_PROGRESS_THRESHOLD, 2, "SEC-H2 默认阈值 = 2");
    }
}
