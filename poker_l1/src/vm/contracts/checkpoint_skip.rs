//! Checkpoint Skip 机制 — 审查截断容错（Task 27 — SubTask 27.10 / 27.11 /
//! 27.12 / 27.13 / 27.13a）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 27.10**：`checkpoint_skip` tx（任意 validator，免 gas）：
//!   `(game_id, skip_segment_start, skip_segment_end, last_known_state_hash,
//!   continuity_proof)`；仅更新 `last_action_height` 与 `skip_count += 1`，
//!   **不推进 ack_chain_hash**。
//!   **SEC-M6 修复**：start_state_proof 须包含完整活跃参与者集合；
//!   skip 段期间 fold 时 ack_set 收缩须显式记录；skip 后下一 checkpoint 的
//!   ack_set 须 == skip tx 中记录的 ack_set。
//! - **SubTask 27.11**：skip_count 上限 `max_skip_segments`（默认 3），
//!   超出则操作方必须提交 `request_revert`。
//! - **SubTask 27.12**：π 的 public_io 边界包含 `ack_chain_hash`（仅正常
//!   checkpoint 聚合）+ `skip_count` + `segment_continuity_proof`。
//! - **SubTask 27.13**：链上 verifier 校验 `skip_count <= max_skip_segments` +
//!   segment_continuity_proof 验证；任一失败 → checkin 拒绝 + forfeit。
//! - **SubTask 27.13a**：continuity_proof 格式 = `(start_state_proof,
//!   end_state_proof)`；start_state_proof 为 ≥2/3 参与者 ACK 签名聚合证据
//!   （签名对象 `hash(chain_id || game_id || checkpoint_seq || state_hash)`）；
//!   end_state_proof 待下一 checkpoint 提交时隐式补全。
//!   **R5-H6**：verify_segment_chain() 逐段校验段间状态连续性。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::ChainId;
use crate::Hash;
use crate::error::PokerL1Error;
use crate::object_model::ObjectID;
use crate::signature::{TaggedPubkey, verify_signature};

use super::checkpoint_anchor::AckSignature;
use super::types::GameContract;

/// max_skip_segments 默认值（SubTask 27.11）。
pub const DEFAULT_MAX_SKIP_SEGMENTS: u32 = 3;

/// 状态证明 — ≥2/3 参与者 ACK 签名聚合证据（SubTask 27.13a）。
///
/// 签名对象 = `hash(chain_id || game_id || checkpoint_seq || state_hash)`。
/// 证明某 checkpoint_seq 时刻的 state_hash 已被 ≥2/3 参与者确认。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct StateProof {
    /// 证明的 checkpoint_seq。
    pub checkpoint_seq: u64,
    /// 证明的 state_hash。
    pub state_hash: Hash,
    /// 参与者 ACK 签名列表（须 ≥2/3 活跃参与者）。
    pub ack_signatures: Vec<AckSignature>,
}

impl StateProof {
    /// 计算 state proof 签名域哈希（SubTask 27.13a）。
    ///
    /// `hash(chain_id || game_id || checkpoint_seq || state_hash)`
    #[must_use]
    pub fn signing_hash(&self, chain_id: ChainId, game_id: &ObjectID) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&chain_id.to_be_bytes());
        hasher.update(&game_id.to_bytes());
        hasher.update(&self.checkpoint_seq.to_be_bytes());
        hasher.update(&self.state_hash);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }

    /// 验证 state proof 的签名有效性 + 签名者覆盖 ≥2/3 活跃参与者。
    ///
    /// # 参数
    /// - `chain_id`：链 ID
    /// - `game_id`：Game 对象 ID
    /// - `active_participants`：活跃参与者集合
    pub fn verify(
        &self,
        chain_id: ChainId,
        game_id: &ObjectID,
        active_participants: &[TaggedPubkey],
    ) -> Result<(), PokerL1Error> {
        let msg_hash = self.signing_hash(chain_id, game_id);

        // 计算所需的 2/3 阈值
        let total = active_participants.len();
        if total == 0 {
            return Err(PokerL1Error::Other(
                "active_participants 为空，无法验证 state proof".to_string(),
            ));
        }
        let required = 2 * total / 3 + 1; // 严格 >2/3（C-3 修复）

        // 收集有效签名（去重：同一 participant 多个签名仅首个有效）
        let mut verified_count: u32 = 0;
        let mut verified_participants: Vec<&TaggedPubkey> = Vec::new();

        for ack in &self.ack_signatures {
            // 校验签名者在 active_participants 中
            if !active_participants.contains(&ack.participant) {
                return Err(PokerL1Error::AckSignerNotParticipant {
                    game_id: *game_id,
                    signer: ack.participant.clone(),
                });
            }
            // 去重
            if verified_participants.contains(&&ack.participant) {
                continue;
            }
            // 验证签名
            verify_signature(&ack.participant, &ack.signature, &msg_hash)?;
            verified_participants.push(&ack.participant);
            verified_count += 1;
        }

        // SEC-M6: 校验签名者覆盖 ≥2/3 活跃参与者
        if (verified_count as usize) < required {
            return Err(PokerL1Error::AckSetMismatch {
                expected: required,
                got: verified_count as usize,
            });
        }

        Ok(())
    }
}

/// 段间连续性证明（SubTask 27.13a / R4-M6）。
///
/// `continuity_proof = (start_state_proof, end_state_proof)`
/// - start_state_proof：skip 段起点状态已被 ≥2/3 参与者确认
/// - end_state_proof：待下一 checkpoint 提交时隐式补全（None = 未补全）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SegmentContinuityProof {
    /// 段起点状态证明。
    pub start_state_proof: StateProof,
    /// 段终点状态证明（None = 待下一 checkpoint/checkin 补全）。
    pub end_state_proof: Option<StateProof>,
}

/// Checkpoint Skip tx（SubTask 27.10）。
///
/// 走 CheckpointAnchor 通道，免 gas。仅更新 `last_action_height` 与
/// `skip_count += 1`，**不推进 ack_chain_hash**。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CheckpointSkipTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// skip 段起点 checkpoint_seq。
    pub skip_segment_start: u64,
    /// skip 段终点 checkpoint_seq。
    pub skip_segment_end: u64,
    /// 最后已知状态哈希。
    pub last_known_state_hash: Hash,
    /// 段间连续性证明。
    pub continuity_proof: SegmentContinuityProof,
    /// SEC-M6：skip 段后的 ack_set（须与下一 checkpoint 的 ack_set 一致）。
    pub ack_set: Vec<TaggedPubkey>,
}

impl CheckpointSkipTx {
    /// 验证 checkpoint_skip tx（SubTask 27.10 / 27.13 / SEC-M6）。
    ///
    /// 校验逻辑：
    /// 1. continuity_proof.start_state_proof 签名有效 + ≥2/3 覆盖
    /// 2. start_state_proof.state_hash == last_known_state_hash
    /// 3. skip_segment_end > skip_segment_start（段非空）
    /// 4. SEC-M6: ack_set 非空
    ///
    /// # 参数
    /// - `chain_id`：链 ID
    /// - `active_participants`：当前活跃参与者集合（用于 ≥2/3 校验）
    pub fn verify(
        &self,
        chain_id: ChainId,
        active_participants: &[TaggedPubkey],
    ) -> Result<(), PokerL1Error> {
        // 段非空校验
        if self.skip_segment_end <= self.skip_segment_start {
            return Err(PokerL1Error::Other(format!(
                "skip_segment_end {} <= skip_segment_start {}",
                self.skip_segment_end, self.skip_segment_start
            )));
        }

        // start_state_proof.state_hash 须匹配 last_known_state_hash
        if self.continuity_proof.start_state_proof.state_hash != self.last_known_state_hash {
            return Err(PokerL1Error::ContinuityProofInvalid(
                "start_state_proof.state_hash != last_known_state_hash".to_string(),
            ));
        }

        // 验证 start_state_proof
        self.continuity_proof.start_state_proof.verify(
            chain_id,
            &self.game_id,
            active_participants,
        )?;

        // SEC-M6: ack_set 非空
        if self.ack_set.is_empty() {
            return Err(PokerL1Error::AckSetMismatch {
                expected: 1,
                got: 0,
            });
        }

        Ok(())
    }
}

/// 应用 checkpoint_skip 到 GameContract（SubTask 27.10 / 27.11）。
///
/// 校验与状态更新：
/// 1. **SubTask 27.11**：`skip_count < max_skip_segments`（超出返回 `SkipCountExceeded`）
/// 2. 更新 `game.skip_count += 1`
/// 3. 更新 `game.last_action_height = block_height`
/// 4. **不推进 ack_chain_hash**（SubTask 27.10）
/// 5. 递增 `game.version`
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `tx`：checkpoint_skip tx
/// - `block_height`：当前 block height
/// - `max_skip_segments`：skip 段上限（默认 3）
pub fn apply_checkpoint_skip(
    game: &mut GameContract,
    tx: &CheckpointSkipTx,
    block_height: u64,
    max_skip_segments: u32,
) -> Result<(), PokerL1Error> {
    // game_id 一致性校验
    if game.id != tx.game_id {
        return Err(PokerL1Error::GameNotFound(tx.game_id));
    }

    // SubTask 27.11: skip_count 上限校验
    if game.skip_count >= max_skip_segments {
        return Err(PokerL1Error::SkipCountExceeded {
            actual: game.skip_count,
            limit: max_skip_segments,
        });
    }

    // SubTask 27.10: 更新 skip_count + last_action_height（不推进 ack_chain_hash）
    game.skip_count = game.skip_count.saturating_add(1);
    game.last_action_height = block_height;
    game.version = game.version.saturating_add(1);

    Ok(())
}

/// 验证 segment chain 连续性（SubTask 27.13a / R5-H6）。
///
/// 逐段校验：
/// 1. 每段 start_state_proof 签名有效
/// 2. 连续多段 skip 时每段 end_state == 下段 start_state
/// 3. 最后一段 end_state 须匹配终止条件：
///    - skip → checkin：end_state == π.initial_commitment
///    - skip → request_revert：end_state == last_acked_checkpoint.state_hash
///
/// # 参数
/// - `segments`：连续的 skip 段列表（按时间顺序）
/// - `chain_id`：链 ID
/// - `game_id`：Game 对象 ID
/// - `active_participants`：活跃参与者集合
/// - `final_state_hash`：终止状态哈希（π.initial_commitment 或 last_acked_checkpoint.state_hash）
pub fn verify_segment_chain(
    segments: &[SegmentContinuityProof],
    chain_id: ChainId,
    game_id: &ObjectID,
    active_participants: &[TaggedPubkey],
    final_state_hash: &Hash,
) -> Result<(), PokerL1Error> {
    if segments.is_empty() {
        return Err(PokerL1Error::ContinuityProofInvalid(
            "segment chain 为空".to_string(),
        ));
    }

    // 结构性检查先行：最后一段 end_state_proof 必须补全（否则后续签名验证无意义）
    let last_segment = segments.last().expect("非空已校验");
    let end_proof = last_segment.end_state_proof.as_ref().ok_or_else(|| {
        PokerL1Error::ContinuityProofInvalid("最后一段 end_state_proof 未补全".to_string())
    })?;
    if end_proof.state_hash != *final_state_hash {
        return Err(PokerL1Error::ContinuityProofInvalid(
            "最后一段 end_state != final_state_hash".to_string(),
        ));
    }

    // 签名验证 + 段间连续性校验
    let mut prev_end_state: Option<&Hash> = None;

    for (i, segment) in segments.iter().enumerate() {
        // 验证 start_state_proof 签名
        segment
            .start_state_proof
            .verify(chain_id, game_id, active_participants)?;

        // R5-H6 (1): 连续多段 skip 时每段 end_state == 下段 start_state
        if let Some(prev_end) = prev_end_state
            && *prev_end != segment.start_state_proof.state_hash
        {
            return Err(PokerL1Error::ContinuityProofInvalid(format!(
                "段 {i}: start_state != 前段 end_state"
            )));
        }

        // 中间段（非最后一段）必须有 end_state_proof 以便下一段做连续性校验
        if i + 1 < segments.len() {
            let mid_end = segment.end_state_proof.as_ref().ok_or_else(|| {
                PokerL1Error::ContinuityProofInvalid(format!("段 {i}: 中间段缺少 end_state_proof"))
            })?;
            prev_end_state = Some(&mid_end.state_hash);
        }
    }

    // 验证最后一段 end_state_proof 签名
    end_proof.verify(chain_id, game_id, active_participants)?;

    Ok(())
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

    fn make_state_proof(seq: u64, hash_byte: u8) -> StateProof {
        StateProof {
            checkpoint_seq: seq,
            state_hash: [hash_byte; 32],
            ack_signatures: vec![], // 测试中签名验证会因占位符失败
        }
    }

    fn make_skip_tx(seq_start: u64, seq_end: u64, hash_byte: u8) -> CheckpointSkipTx {
        CheckpointSkipTx {
            game_id: make_game_id(),
            skip_segment_start: seq_start,
            skip_segment_end: seq_end,
            last_known_state_hash: [hash_byte; 32],
            continuity_proof: SegmentContinuityProof {
                start_state_proof: make_state_proof(seq_start, hash_byte),
                end_state_proof: None,
            },
            ack_set: vec![make_test_tagged_pubkey(1)],
        }
    }

    #[test]
    fn test_state_proof_signing_hash_deterministic() {
        let proof = make_state_proof(1, 0xAB);
        let h1 = proof.signing_hash(crate::DEFAULT_CHAIN_ID, &make_game_id());
        let h2 = proof.signing_hash(crate::DEFAULT_CHAIN_ID, &make_game_id());
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_state_proof_signing_hash_differs_by_chain_id() {
        let proof = make_state_proof(1, 0xAB);
        let h1 = proof.signing_hash(1, &make_game_id());
        let h2 = proof.signing_hash(2, &make_game_id());
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_state_proof_signing_hash_differs_by_seq() {
        let p1 = make_state_proof(1, 0xAB);
        let p2 = make_state_proof(2, 0xAB);
        let h1 = p1.signing_hash(crate::DEFAULT_CHAIN_ID, &make_game_id());
        let h2 = p2.signing_hash(crate::DEFAULT_CHAIN_ID, &make_game_id());
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_state_proof_verify_empty_participants() {
        let proof = make_state_proof(1, 0xAB);
        let result = proof.verify(crate::DEFAULT_CHAIN_ID, &make_game_id(), &[]);
        assert!(result.is_err(), "空 active_participants 应失败");
    }

    #[test]
    fn test_state_proof_verify_insufficient_signatures() {
        // 3 个活跃参与者，需要严格 >2/3 = 3 个签名（C-3 修复），但 ack_signatures 为空
        let proof = make_state_proof(1, 0xAB);
        let active = vec![
            make_test_tagged_pubkey(1),
            make_test_tagged_pubkey(2),
            make_test_tagged_pubkey(3),
        ];
        let result = proof.verify(crate::DEFAULT_CHAIN_ID, &make_game_id(), &active);
        assert!(
            matches!(
                result,
                Err(PokerL1Error::AckSetMismatch {
                    expected: 3,
                    got: 0
                })
            ),
            "签名不足应返回 AckSetMismatch"
        );
    }

    #[test]
    fn test_checkpoint_skip_tx_verify_segment_empty() {
        let mut tx = make_skip_tx(1, 2, 0xAB);
        tx.skip_segment_end = 1; // end == start
        let result = tx.verify(crate::DEFAULT_CHAIN_ID, &[make_test_tagged_pubkey(1)]);
        assert!(result.is_err(), "空段应失败");
    }

    #[test]
    fn test_checkpoint_skip_tx_verify_state_hash_mismatch() {
        let mut tx = make_skip_tx(1, 2, 0xAB);
        tx.continuity_proof.start_state_proof.state_hash = [0xCD; 32]; // 不匹配 last_known_state_hash
        let result = tx.verify(crate::DEFAULT_CHAIN_ID, &[make_test_tagged_pubkey(1)]);
        assert!(
            matches!(result, Err(PokerL1Error::ContinuityProofInvalid { .. })),
            "state_hash 不匹配应返回 ContinuityProofInvalid"
        );
    }

    #[test]
    fn test_checkpoint_skip_tx_verify_empty_ack_set() {
        let mut tx = make_skip_tx(1, 2, 0xAB);
        tx.ack_set = vec![];
        let result = tx.verify(crate::DEFAULT_CHAIN_ID, &[make_test_tagged_pubkey(1)]);
        assert!(
            matches!(result, Err(PokerL1Error::AckSetMismatch { .. })),
            "空 ack_set 应返回 AckSetMismatch"
        );
    }

    #[test]
    fn test_apply_checkpoint_skip_success() {
        let mut game = make_minimal_game();
        let tx = make_skip_tx(1, 3, 0xAB);
        let result = apply_checkpoint_skip(&mut game, &tx, 500, DEFAULT_MAX_SKIP_SEGMENTS);
        assert!(result.is_ok(), "首次 skip 应成功");
        assert_eq!(game.skip_count, 1);
        assert_eq!(game.last_action_height, 500);
    }

    #[test]
    fn test_apply_checkpoint_skip_exceeds_limit() {
        let mut game = make_minimal_game();
        game.skip_count = DEFAULT_MAX_SKIP_SEGMENTS; // 已达上限
        let tx = make_skip_tx(1, 3, 0xAB);
        let result = apply_checkpoint_skip(&mut game, &tx, 500, DEFAULT_MAX_SKIP_SEGMENTS);
        assert!(
            matches!(
                result,
                Err(PokerL1Error::SkipCountExceeded {
                    actual: 3,
                    limit: 3
                })
            ),
            "超出上限应返回 SkipCountExceeded"
        );
    }

    #[test]
    fn test_apply_checkpoint_skip_multiple_until_limit() {
        let mut game = make_minimal_game();
        // skip 3 次（达到上限）
        for i in 0..DEFAULT_MAX_SKIP_SEGMENTS {
            let tx = make_skip_tx(i as u64 + 1, i as u64 + 2, 0xAB);
            let result =
                apply_checkpoint_skip(&mut game, &tx, 500 + i as u64, DEFAULT_MAX_SKIP_SEGMENTS);
            assert!(result.is_ok(), "第 {} 次 skip 应成功", i + 1);
        }
        assert_eq!(game.skip_count, DEFAULT_MAX_SKIP_SEGMENTS);

        // 第 4 次 → 超出
        let tx = make_skip_tx(4, 5, 0xAB);
        let result = apply_checkpoint_skip(&mut game, &tx, 510, DEFAULT_MAX_SKIP_SEGMENTS);
        assert!(result.is_err(), "第 4 次应失败");
    }

    #[test]
    fn test_verify_segment_chain_empty() {
        let result = verify_segment_chain(
            &[],
            crate::DEFAULT_CHAIN_ID,
            &make_game_id(),
            &[make_test_tagged_pubkey(1)],
            &[0xAB; 32],
        );
        assert!(result.is_err(), "空 chain 应失败");
    }

    #[test]
    fn test_verify_segment_chain_missing_end_proof() {
        let segment = SegmentContinuityProof {
            start_state_proof: make_state_proof(1, 0xAB),
            end_state_proof: None, // 未补全
        };
        let result = verify_segment_chain(
            &[segment],
            crate::DEFAULT_CHAIN_ID,
            &make_game_id(),
            &[make_test_tagged_pubkey(1)],
            &[0xAB; 32],
        );
        assert!(
            matches!(result, Err(PokerL1Error::ContinuityProofInvalid { .. })),
            "缺少 end_state_proof 应失败"
        );
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_MAX_SKIP_SEGMENTS, 3, "SubTask 27.11 默认 = 3");
    }
}
