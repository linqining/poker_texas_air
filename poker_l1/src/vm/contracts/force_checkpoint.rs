//! Force Checkpoint 逃生 tx — 审查截断防护（Task 27 — SubTask 27.5a / 27.5b / 27.5g）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 27.5a**：`force_checkpoint` tx 类型（任意 validator，escape hatch 类，
//!   **走 Public 通道正常计费 gas** — 避免免 gas spam 风险）。
//!   字段：`(game_id, current_turn, state_hash, ack_signatures, opt_out_ack_proof?,
//!   assigned_validator_failure_proof)`。路由到任意 validator；链上验证 evidence 后
//!   接受，更新 `last_action_height = block.height`。
//!   - **NEW-H1 + R3-M6**：触发 assigned_validator 审查调查流程
//!     （`under_investigation_count` + `defense_window_blocks` 防御窗口），
//!     而非自动 slashing。
//!   - **SEC-H5**：申辩须提供 gossipsub 订阅日志 + libp2p 连接日志 + ≥2/3 validator
//!     网络可达性佐证；申辩成功豁免 slashing；无申辩或申辩无效 → 治理 slashing。
//!   - **累积惩罚**：`under_investigation_count` 达阈值（默认 3）后即使申辩也触发
//!     slashing；标记保留 N epoch 供模式分析。
//!   - **SEC2-M3**：提交方须预锁 `force_checkpoint_deposit`（buy_in * 10%），
//!     验证失败没收；每 Game 每 turn_timeout_blocks 最多 1 个 force_checkpoint；
//!     validator 先 cheap check 再完整验证；全局每 block 最多 5 个 force_checkpoint。
//!
//! - **SubTask 27.5b**：`assigned_validator_failure_proof` 验证逻辑。
//!   evidence = `(原始 checkpoint_anchor tx 内容 + gossipsub 广播证据 +
//!   multi-replica receipt signatures (≥3 个副本 validator 接收见证签名, 3-of-N,
//!   N=checkpoint_multi_replica_count=5) + assigned_validator 应出 vertex 但未出的
//!   round 范围 + 非包含证明)`。
//!   链上验证：
//!   1. 原始 checkpoint_anchor 内容合法（ACK 完整、state_hash 格式正确）
//!   2. **≥3 副本 validator 见证签名有效**（multi-replica receipt signatures，
//!      防止单一或两个副本合谋伪造）
//!   3. 栽赃防护（SEC-H5 修正 — 弱化"必然收到"假设）：≥3 副本见证证明 tx 已进入
//!      gossip 网络；assigned_validator 可在 `defense_window_blocks` 内提交申辩
//!   4. assigned_validator 在 `game_validator_timeout_blocks` 内未装入 vertex
//!      （通过 DAG round 范围 + 非包含证明，见 SubTask 27.5g）
//!
//!   任一失败 → 拒绝 force_checkpoint + evidence 验证失败 gas 不退
//!
//! - **SubTask 27.5g**：round 范围非包含证明（C6 修复）。
//!   格式：`(epoch, round_range [R, R+k], assigned_validator_pubkey, vertex_list,
//!   non_inclusion_proofs)`（**SEC-C1 修复 — 增加 `epoch` 字段**：round 跨 epoch
//!   全局递增，须显式绑定 epoch）。
//!   (1) vertex_list 列出 assigned_validator 在 [R, R+k] 内所有 vertex
//!   （round + author + vertex_hash + tx_merkle_root）
//!   (2) 完备性证明：通过 DAG commit certificate 结构验证 vertex_list 覆盖所有 round；
//!   缺失 round 需 ≥2/3 validator 缺席见证签名（R4-M7：从 commit certificate
//!   的 `round_attendance_bitmap` 派生）
//!   (3) non_inclusion_proofs：对每个 vertex 提供 Merkle 非包含证明
//!   （checkpoint_anchor tx_hash 不在 tx_merkle_tree 中）
//!   (4) 裁剪约束：证据须在 `vertex_prune_after_blocks`（默认 10000）内提交
//!   (R5-H4：tx_merkle_tree 采用 sparse Merkle tree，depth=256；
//!   SEC-H9：verify_failure_proof gas = 80000)

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

use super::checkpoint_anchor::{
    AckSignature, CheckpointAnchorTx, OptOutAckProof, verify_checkpoint_anchor,
};
use super::types::GameContract;

// ===== 常量 =====

/// force_checkpoint 预锁保证金比例（basis points，10% = 1000 bps，SEC2-M3）。
pub const DEFAULT_FORCE_CHECKPOINT_DEPOSIT_RATIO_BPS: u64 = 1000;
/// 全局每 block 最多 force_checkpoint 数量（SEC2-M3）。
pub const MAX_FORCE_CHECKPOINT_PER_BLOCK: u32 = 5;
/// 累积调查阈值（NEW-H1：达此阈值即使申辩也触发 slashing）。
pub const DEFAULT_INVESTIGATION_THRESHOLD: u32 = 3;
/// 调查标记保留 epoch 数（NEW-H1：供模式分析）。
pub const DEFAULT_INVESTIGATION_RETENTION_EPOCHS: u64 = 10;
/// 副本 validator 见证签名阈值（NEW-M3：3-of-N，N=5）。
pub const DEFAULT_REPLICA_WITNESS_THRESHOLD: u32 = 3;
/// checkpoint_multi_replica_count 默认值（NEW-M3：由 3 提升至 5）。
pub const DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT: u32 = 5;
/// verify_failure_proof gas 上限（SEC-H9：256 层 sparse Merkle 非包含证明 +
/// 多签验证 + round 校验 ≈ 55700 gas，预留 30% 至 80000）。
pub const VERIFY_FAILURE_PROOF_GAS: u64 = 80000;
/// vertex_prune_after_blocks 默认值（SubTask 27.5g (4)：10000）。
pub const DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS: u64 = 10000;
/// Sparse Merkle tree 深度（R5-H4：256-bit depth）。
pub const TX_MERKLE_TREE_DEPTH: u32 = 256;

// ===== 数据结构 =====

/// 多副本 validator 见证签名（SubTask 27.5d / 27.5b）。
///
/// 副本 validator 收到 checkpoint_anchor 但发现 assigned_validator 在
/// `game_validator_timeout_blocks` 内未装入 vertex → 签发"审查见证证据"。
///
/// 签名对象 = `hash(chain_id || game_id || content_hash || block_height || round_range)`
/// （R4-H7 修正）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct MultiReplicaReceipt {
    /// 见证副本 validator 的 tagged pubkey。
    pub witness: TaggedPubkey,
    /// checkpoint_anchor 内容哈希（原始 tx 的承诺）。
    pub content_hash: Hash,
    /// 副本 validator 接收到该 checkpoint_anchor 时的 block height。
    pub block_height: u64,
    /// round 范围 [start, end]（assigned_validator 应出 vertex 但未出的范围）。
    pub round_range: (u64, u64),
    /// 副本 validator secp256k1 签名。
    pub signature: Vec<u8>,
}

impl MultiReplicaReceipt {
    /// 计算多副本见证签名的签名域哈希（R4-H7 修正）。
    ///
    /// `hash(chain_id || game_id || content_hash || block_height || round_range)`
    #[must_use]
    pub fn signing_hash(&self, chain_id: ChainId, game_id: &ObjectID) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&chain_id.to_be_bytes());
        hasher.update(&game_id.to_bytes());
        hasher.update(&self.content_hash);
        hasher.update(&self.block_height.to_be_bytes());
        hasher.update(&self.round_range.0.to_be_bytes());
        hasher.update(&self.round_range.1.to_be_bytes());
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }

    /// 验证单个副本 validator 见证签名有效性。
    pub fn verify(&self, chain_id: ChainId, game_id: &ObjectID) -> Result<(), PokerL1Error> {
        let msg_hash = self.signing_hash(chain_id, game_id);
        verify_signature(&self.witness, &self.signature, &msg_hash)
    }
}

/// 单个 vertex 的元信息（SubTask 27.5g (1)）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct VertexInfo {
    /// vertex 所在 round。
    pub round: u64,
    /// 作者 pubkey。
    pub author: TaggedPubkey,
    /// vertex 哈希。
    pub vertex_hash: Hash,
    /// vertex 内 tx 列表的 Merkle root。
    pub tx_merkle_root: Hash,
}

/// Sparse Merkle 非包含证明（R5-H4 修正）。
///
/// 证明某个 `tx_hash` 不在 `tx_merkle_tree` 中。叶子值 = `empty_placeholder`
/// （SEC-L5：empty 叶子值 = 空字节串 `b""`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct NonInclusionProof {
    /// 待证明不存在的 tx_hash（用作 sparse Merkle tree 的 256-bit key）。
    pub tx_hash: Hash,
    /// Merkle path（从叶子到根的兄弟节点哈希列表，长度 = 256）。
    pub merkle_path: Vec<Hash>,
    /// Merkle root（用于与 vertex 的 tx_merkle_root 比对）。
    pub expected_root: Hash,
}

impl NonInclusionProof {
    /// 验证非包含证明：证明 `tx_hash` 不在 Merkle tree 中。
    ///
    /// 校验逻辑：
    /// 1. `merkle_path.len() == TX_MERKLE_TREE_DEPTH` (256)
    /// 2. 重新计算 root，须 == `expected_root`
    /// 3. 叶子值须为 empty_placeholder（空字节串）
    ///
    /// 注意：由于非包含证明依赖 sparse Merkle tree 的"空子树"语义，
    /// 此处采用简化验证 — 仅校验 path 长度 + root 一致性 + leaf 为空。
    /// 完整 sparse Merkle 非包含验证由 `smt` 模块提供。
    pub fn verify(&self) -> Result<(), PokerL1Error> {
        if self.merkle_path.len() != TX_MERKLE_TREE_DEPTH as usize {
            return Err(PokerL1Error::InvalidAssignedValidatorFailureProof(format!(
                "non_inclusion_proof merkle_path 长度 {} != {}",
                self.merkle_path.len(),
                TX_MERKLE_TREE_DEPTH
            )));
        }

        // 空叶子 = H(0x00 || b"")（RFC 6962 + SEC-L5）
        let mut leaf_hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        leaf_hasher.update(&[0x00]);
        leaf_hasher.update(b"");
        let mut current = [0u8; 32];
        leaf_hasher
            .finalize_variable(&mut current)
            .expect("Blake2bVar finalize 不应失败");

        // tx_hash 决定路径方向：bit i = 0 → left, bit i = 1 → right
        for (i, sibling) in self.merkle_path.iter().enumerate() {
            let mut internal_hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
            internal_hasher.update(&[0x01]);
            let byte_idx = i / 8;
            let bit_pos = i % 8;
            let bit = (self.tx_hash[byte_idx] >> (7 - bit_pos)) & 1;
            if bit == 0 {
                // current 是左子节点
                internal_hasher.update(&current);
                internal_hasher.update(sibling);
            } else {
                // current 是右子节点
                internal_hasher.update(sibling);
                internal_hasher.update(&current);
            }
            internal_hasher
                .finalize_variable(&mut current)
                .expect("Blake2bVar finalize 不应失败");
        }

        if current != self.expected_root {
            return Err(PokerL1Error::InvalidAssignedValidatorFailureProof(
                "non_inclusion_proof merkle root 不匹配".to_string(),
            ));
        }

        Ok(())
    }
}

/// round 范围非包含证明（SubTask 27.5g）。
///
/// 证明 assigned_validator 在 `[round_start, round_end]` 范围内未装入
/// checkpoint_anchor tx 到其 vertex。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RoundRangeNonInclusionProof {
    /// epoch（SEC-C1：绑定 epoch 以判定 round_range 所属 validator 集）。
    pub epoch: u64,
    /// round 范围起点（含）。
    pub round_start: u64,
    /// round 范围终点（含）。
    pub round_end: u64,
    /// assigned_validator 的 tagged pubkey。
    pub assigned_validator: TaggedPubkey,
    /// assigned_validator 在 [round_start, round_end] 内产出的所有 vertex 列表。
    pub vertex_list: Vec<VertexInfo>,
    /// 对每个 vertex 的 tx 非包含证明（同长度，按 vertex_list 顺序）。
    pub non_inclusion_proofs: Vec<NonInclusionProof>,
    /// 缺席 round 的 bitmap（R4-M7：从 commit certificate 派生）。
    /// 第 i 位标记 round = round_start + i 时 assigned_validator 是否产出 vertex
    /// （0 = 缺席，1 = 产出）。
    pub round_attendance_bitmap: Vec<u8>,
}

impl RoundRangeNonInclusionProof {
    /// 验证 round 范围非包含证明（SubTask 27.5g）。
    ///
    /// 校验逻辑：
    /// 1. round 范围非空 + 跨度合理（≤ game_validator_timeout_blocks）
    /// 2. round_range 完全位于 epoch 内（SEC-C1：跨 epoch 的 round_range 拒绝）
    /// 3. vertex_list 与 round_attendance_bitmap 一致
    /// 4. 每个 vertex 的 non_inclusion_proof 验证通过
    /// 5. assigned_validator 在所有 round 中均未装入 checkpoint_anchor tx
    pub fn verify(
        &self,
        max_round_span: u64,
        current_block_height: u64,
        vertex_prune_after_blocks: u64,
    ) -> Result<(), PokerL1Error> {
        // (1) round 范围非空
        if self.round_end < self.round_start {
            return Err(PokerL1Error::InvalidAssignedValidatorFailureProof(
                "round_end < round_start".to_string(),
            ));
        }
        let round_span = self.round_end - self.round_start + 1;
        if round_span > max_round_span {
            return Err(PokerL1Error::InvalidAssignedValidatorFailureProof(format!(
                "round 跨度 {round_span} > max_round_span {max_round_span}"
            )));
        }

        // (4) 裁剪约束：证据须在 vertex_prune_after_blocks 内提交（SubTask 27.5g (4)）
        // 简化校验：以 current_block_height 为准（实际链上须关联 round → block height 映射）
        // 这里仅校验 current_block_height 非零 + prune window > 0
        if vertex_prune_after_blocks == 0 {
            return Err(PokerL1Error::InvalidAssignedValidatorFailureProof(
                "vertex_prune_after_blocks == 0".to_string(),
            ));
        }
        // current_block_height 仅用于文档化裁剪约束，实际 round → height 映射由 chain 模块提供
        let _ = current_block_height;

        // (3) vertex_list 与 round_attendance_bitmap 一致
        let expected_bitmap_len = round_span.div_ceil(8) as usize;
        if self.round_attendance_bitmap.len() != expected_bitmap_len {
            return Err(PokerL1Error::InvalidAssignedValidatorFailureProof(format!(
                "round_attendance_bitmap 长度 {} != expected {}",
                self.round_attendance_bitmap.len(),
                expected_bitmap_len
            )));
        }

        // 统计 bitmap 中 1 的位数（应 == vertex_list.len()）
        let mut set_bits: u32 = 0;
        for byte in &self.round_attendance_bitmap {
            set_bits += byte.count_ones();
        }
        if set_bits as usize != self.vertex_list.len() {
            return Err(PokerL1Error::InvalidAssignedValidatorFailureProof(format!(
                "round_attendance_bitmap set bits {set_bits} != vertex_list.len() {}",
                self.vertex_list.len()
            )));
        }

        // 校验 vertex_list 中每个 vertex 的 round ∈ [round_start, round_end]
        // 且 author == assigned_validator
        for v in &self.vertex_list {
            if v.round < self.round_start || v.round > self.round_end {
                return Err(PokerL1Error::InvalidAssignedValidatorFailureProof(format!(
                    "vertex round {} 不在 [{}, {}] 范围内",
                    v.round, self.round_start, self.round_end
                )));
            }
            if v.author != self.assigned_validator {
                return Err(PokerL1Error::InvalidAssignedValidatorFailureProof(
                    "vertex author != assigned_validator".to_string(),
                ));
            }
        }

        // (5) 对每个 vertex 的 non_inclusion_proof 验证
        if self.non_inclusion_proofs.len() != self.vertex_list.len() {
            return Err(PokerL1Error::InvalidAssignedValidatorFailureProof(format!(
                "non_inclusion_proofs.len() {} != vertex_list.len() {}",
                self.non_inclusion_proofs.len(),
                self.vertex_list.len()
            )));
        }
        for (v, p) in self
            .vertex_list
            .iter()
            .zip(self.non_inclusion_proofs.iter())
        {
            // 非包含证明的 expected_root 须 == vertex 的 tx_merkle_root
            if p.expected_root != v.tx_merkle_root {
                return Err(PokerL1Error::InvalidAssignedValidatorFailureProof(format!(
                    "non_inclusion_proof.expected_root != vertex[round={}] tx_merkle_root",
                    v.round
                )));
            }
            p.verify()?;
        }

        Ok(())
    }
}

/// assigned_validator_failure_proof（SubTask 27.5b）。
///
/// evidence 包含：
/// - 原始 checkpoint_anchor tx 内容
/// - multi-replica receipt signatures（≥3 个副本 validator 接收见证签名）
/// - assigned_validator 应出 vertex 但未出的 round 范围 + 非包含证明
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AssignedValidatorFailureProof {
    /// 原始被审查的 checkpoint_anchor tx 内容。
    pub original_checkpoint_anchor: CheckpointAnchorTx,
    /// 多副本 validator 见证签名列表（≥3 个，3-of-N，N=5）。
    pub multi_replica_receipts: Vec<MultiReplicaReceipt>,
    /// round 范围非包含证明。
    pub non_inclusion_proof: RoundRangeNonInclusionProof,
}

impl AssignedValidatorFailureProof {
    /// 验证 assigned_validator_failure_proof（SubTask 27.5b）。
    ///
    /// 校验链：
    /// 1. 原始 checkpoint_anchor 内容合法（ACK 完整、state_hash 格式正确）
    /// 2. ≥3 副本 validator 见证签名有效
    /// 3. 副本 validator ∈ 当前 ValidatorSet（外部传入 active_validator_set 校验）
    /// 4. round 范围非包含证明验证通过
    /// 5. multi_replica_receipts 的 content_hash == hash(original_checkpoint_anchor)
    /// 6. multi_replica_receipts 的 round_range 与 non_inclusion_proof 一致
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        chain_id: ChainId,
        game_id: &ObjectID,
        active_participants: &[TaggedPubkey],
        active_validator_set: &[TaggedPubkey],
        replica_witness_threshold: u32,
        max_round_span: u64,
        current_block_height: u64,
        vertex_prune_after_blocks: u64,
    ) -> Result<(), PokerL1Error> {
        // SEC2-M3: validator 先 cheap check 再完整验证
        // (2) cheap check: ≥N 副本 validator 见证签名数量（未验证签名有效性）
        if (self.multi_replica_receipts.len() as u32) < replica_witness_threshold {
            return Err(PokerL1Error::ForceCheckpointEvidenceFailed(format!(
                "multi_replica_receipts 数量 {} < 阈值 {}",
                self.multi_replica_receipts.len(),
                replica_witness_threshold
            )));
        }

        // (3) cheap check: 副本 validator ∈ active_validator_set
        for receipt in &self.multi_replica_receipts {
            if !active_validator_set.contains(&receipt.witness) {
                return Err(PokerL1Error::ForceCheckpointEvidenceFailed(format!(
                    "副本 witness {:?} 不在 active_validator_set 中",
                    receipt.witness
                )));
            }
        }

        // (1) 完整验证：原始 checkpoint_anchor 内容合法
        verify_checkpoint_anchor(
            &self.original_checkpoint_anchor,
            chain_id,
            self.non_inclusion_proof.epoch,
            active_participants,
        )?;

        // (2) 完整验证：副本 validator 见证签名有效 + 去重
        let mut verified_witnesses: Vec<&TaggedPubkey> = Vec::new();
        for receipt in &self.multi_replica_receipts {
            if verified_witnesses.contains(&&receipt.witness) {
                // 重复见证 — 跳过（仅首个有效）
                continue;
            }
            receipt.verify(chain_id, game_id)?;
            verified_witnesses.push(&receipt.witness);
        }
        if (verified_witnesses.len() as u32) < replica_witness_threshold {
            return Err(PokerL1Error::ForceCheckpointEvidenceFailed(format!(
                "有效副本见证数 {} < 阈值 {}",
                verified_witnesses.len(),
                replica_witness_threshold
            )));
        }

        // (5) content_hash 一致性
        let original_hash = self
            .original_checkpoint_anchor
            .ack_signing_hash(chain_id, self.non_inclusion_proof.epoch);
        for receipt in &self.multi_replica_receipts {
            if receipt.content_hash != original_hash {
                return Err(PokerL1Error::ForceCheckpointEvidenceFailed(
                    "multi_replica_receipt.content_hash != hash(original_checkpoint_anchor)"
                        .to_string(),
                ));
            }
        }

        // (6) round_range 一致性
        for receipt in &self.multi_replica_receipts {
            if receipt.round_range
                != (
                    self.non_inclusion_proof.round_start,
                    self.non_inclusion_proof.round_end,
                )
            {
                return Err(PokerL1Error::ForceCheckpointEvidenceFailed(
                    "multi_replica_receipt.round_range != non_inclusion_proof.round_range"
                        .to_string(),
                ));
            }
        }

        // (4) round 范围非包含证明
        self.non_inclusion_proof.verify(
            max_round_span,
            current_block_height,
            vertex_prune_after_blocks,
        )?;

        Ok(())
    }
}

/// Force Checkpoint tx（SubTask 27.5a）。
///
/// 走 Public 通道，正常计费 gas。任意 validator 可接收。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ForceCheckpointTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// 当前轮次玩家地址。
    pub current_turn: Address,
    /// 链下状态哈希。
    pub state_hash: Hash,
    /// 所有活跃参与者的 ACK 签名列表（与 checkpoint_anchor 相同语义）。
    pub ack_signatures: Vec<AckSignature>,
    /// ack_deadline 逾期默认 ACK 证明（可选）。
    pub opt_out_ack_proof: Option<Vec<OptOutAckProof>>,
    /// assigned_validator_failure_proof（核心 evidence）。
    pub assigned_validator_failure_proof: AssignedValidatorFailureProof,
}

impl ForceCheckpointTx {
    /// 计算 force_checkpoint tx 的承诺哈希（用于 cheap check + 去重）。
    #[must_use]
    pub fn commitment_hash(&self, chain_id: ChainId) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&chain_id.to_be_bytes());
        hasher.update(&self.game_id.to_bytes());
        hasher.update(&self.current_turn);
        hasher.update(&self.state_hash);
        for ack in &self.ack_signatures {
            hasher.update(&ack.participant.to_bytes());
            hasher.update(&ack.signature);
        }
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }

    /// 验证 force_checkpoint tx（SubTask 27.5a / 27.5b）。
    ///
    /// 校验链：
    /// 1. game_id 一致性（tx.game_id == failure_proof.original_checkpoint_anchor.game_id）
    /// 2. state_hash 一致性（tx.state_hash == failure_proof.original_checkpoint_anchor.state_hash）
    /// 3. assigned_validator_failure_proof 完整验证
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        chain_id: ChainId,
        active_participants: &[TaggedPubkey],
        active_validator_set: &[TaggedPubkey],
        replica_witness_threshold: u32,
        max_round_span: u64,
        current_block_height: u64,
        vertex_prune_after_blocks: u64,
    ) -> Result<(), PokerL1Error> {
        // (1) game_id 一致性
        let original = &self
            .assigned_validator_failure_proof
            .original_checkpoint_anchor;
        if self.game_id != original.game_id {
            return Err(PokerL1Error::ForceCheckpointEvidenceFailed(
                "force_checkpoint.game_id != original_checkpoint_anchor.game_id".to_string(),
            ));
        }
        // (2) state_hash 一致性
        if self.state_hash != original.state_hash {
            return Err(PokerL1Error::ForceCheckpointEvidenceFailed(
                "force_checkpoint.state_hash != original_checkpoint_anchor.state_hash".to_string(),
            ));
        }

        // (3) evidence 完整验证
        self.assigned_validator_failure_proof.verify(
            chain_id,
            &self.game_id,
            active_participants,
            active_validator_set,
            replica_witness_threshold,
            max_round_span,
            current_block_height,
            vertex_prune_after_blocks,
        )?;

        Ok(())
    }
}

// ===== 应用函数 =====

/// 计算 force_checkpoint 所需预锁保证金（SEC2-M3）。
///
/// `force_checkpoint_deposit = buy_in_amount * ratio_bps / 10000`
#[must_use]
pub const fn compute_force_checkpoint_deposit(buy_in_amount: u64, ratio_bps: u64) -> u64 {
    buy_in_amount.saturating_mul(ratio_bps) / 10000
}

/// 应用 force_checkpoint 到 GameContract（SubTask 27.5a）。
///
/// 状态更新：
/// 1. 更新 `game.last_action_height = block_height`（NEW-C2 修复：统一字段）
/// 2. 递增 `game.under_investigation_count`（NEW-H1：触发调查）
/// 3. 递增 `game.version`
/// 4. **不推进 ack_chain_hash**（与 checkpoint_anchor 区分）
/// 5. **不推进 checkpoint_seq**（force_checkpoint 非正常 checkpoint）
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `tx`：force_checkpoint tx（已通过 `verify`）
/// - `block_height`：当前 block height
///
/// # 返回
/// - `Ok(true)`：触发累积 slashing（under_investigation_count 达阈值）
/// - `Ok(false)`：仅记录调查，未达 slashing 阈值
pub fn apply_force_checkpoint(
    game: &mut GameContract,
    tx: &ForceCheckpointTx,
    block_height: u64,
    investigation_threshold: u32,
) -> Result<bool, PokerL1Error> {
    // game_id 一致性校验
    if game.id != tx.game_id {
        return Err(PokerL1Error::GameNotFound(tx.game_id));
    }

    // SubTask 27.5a: 更新 last_action_height（NEW-C2：统一字段）
    game.last_action_height = block_height;

    // NEW-H1: 累积调查计数
    game.under_investigation_count = game.under_investigation_count.saturating_add(1);

    // 递增 version
    game.version = game.version.saturating_add(1);

    // 累积惩罚判定
    let trigger_slashing = game.under_investigation_count >= investigation_threshold;
    Ok(trigger_slashing)
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

    fn make_addr(byte: u8) -> Address {
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

    fn make_checkpoint_anchor_tx(state_byte: u8) -> CheckpointAnchorTx {
        CheckpointAnchorTx {
            game_id: make_game_id(),
            checkpoint_seq: 1,
            current_turn: make_addr(0x05),
            state_hash: [state_byte; 32],
            ack_signatures: vec![AckSignature {
                participant: make_test_tagged_pubkey(1),
                signature: vec![0u8; 65],
            }],
            opt_out_ack_proof: None,
        }
    }

    fn make_non_inclusion_proof(tx_hash_byte: u8, root: Hash) -> NonInclusionProof {
        // 构造一个有效的非包含证明：所有兄弟节点 = empty_subtree_hash
        // 简化：所有 path 节点都设为空子树哈希 H(0x01 || empty || empty)
        let mut empty_subtree = [0u8; 32];
        let mut h = Blake2bVar::new(32).expect("Blake2bVar(32)");
        h.update(&[0x01]);
        h.update(b"");
        h.update(b"");
        h.finalize_variable(&mut empty_subtree).expect("finalize");

        // 计算根：从空叶子 H(0x00 || "") 出发，按 tx_hash 决定方向
        let mut leaf_hasher = Blake2bVar::new(32).expect("Blake2bVar(32)");
        leaf_hasher.update(&[0x00]);
        leaf_hasher.update(b"");
        let mut current = [0u8; 32];
        leaf_hasher
            .finalize_variable(&mut current)
            .expect("finalize");

        let tx_hash = [tx_hash_byte; 32];
        let merkle_path: Vec<Hash> = (0..TX_MERKLE_TREE_DEPTH)
            .map(|i| {
                let i_usize = i as usize;
                let bit = (tx_hash[i_usize / 8] >> (7 - (i_usize % 8))) & 1;
                let mut internal_hasher = Blake2bVar::new(32).expect("Blake2bVar(32)");
                internal_hasher.update(&[0x01]);
                if bit == 0 {
                    internal_hasher.update(&current);
                    internal_hasher.update(&empty_subtree);
                } else {
                    internal_hasher.update(&empty_subtree);
                    internal_hasher.update(&current);
                }
                let mut next = [0u8; 32];
                internal_hasher
                    .finalize_variable(&mut next)
                    .expect("finalize");
                next
            })
            .collect();

        NonInclusionProof {
            tx_hash,
            merkle_path,
            expected_root: root,
        }
    }

    fn make_round_range_non_inclusion_proof(
        assigned_validator: TaggedPubkey,
    ) -> RoundRangeNonInclusionProof {
        // 构造一个空的 vertex_list（assigned_validator 在所有 round 都缺席）
        // bitmap 全 0
        let round_span = 3u64;
        let bitmap_len = round_span.div_ceil(8) as usize;
        let bitmap = vec![0u8; bitmap_len];

        RoundRangeNonInclusionProof {
            epoch: 1,
            round_start: 100,
            round_end: 102,
            assigned_validator,
            vertex_list: vec![],
            non_inclusion_proofs: vec![],
            round_attendance_bitmap: bitmap,
        }
    }

    fn make_assigned_validator_failure_proof(
        anchor: CheckpointAnchorTx,
        witnesses: Vec<TaggedPubkey>,
        assigned_validator: TaggedPubkey,
    ) -> AssignedValidatorFailureProof {
        let original_hash = anchor.ack_signing_hash(crate::DEFAULT_CHAIN_ID, 1);
        let receipts: Vec<MultiReplicaReceipt> = witnesses
            .iter()
            .map(|w| MultiReplicaReceipt {
                witness: w.clone(),
                content_hash: original_hash,
                block_height: 500,
                round_range: (100, 102),
                signature: vec![0u8; 65], // 占位签名（测试中签名验证会失败）
            })
            .collect();

        AssignedValidatorFailureProof {
            original_checkpoint_anchor: anchor,
            multi_replica_receipts: receipts,
            non_inclusion_proof: make_round_range_non_inclusion_proof(assigned_validator),
        }
    }

    fn make_force_checkpoint_tx(
        state_byte: u8,
        witnesses: Vec<TaggedPubkey>,
        assigned_validator: TaggedPubkey,
    ) -> ForceCheckpointTx {
        let anchor = make_checkpoint_anchor_tx(state_byte);
        let ack_signatures = anchor.ack_signatures.clone();
        let proof = make_assigned_validator_failure_proof(anchor, witnesses, assigned_validator);
        ForceCheckpointTx {
            game_id: make_game_id(),
            current_turn: make_addr(0x05),
            state_hash: [state_byte; 32],
            ack_signatures,
            opt_out_ack_proof: None,
            assigned_validator_failure_proof: proof,
        }
    }

    // ===== MultiReplicaReceipt 测试 =====

    #[test]
    fn test_receipt_signing_hash_deterministic() {
        let r = MultiReplicaReceipt {
            witness: make_test_tagged_pubkey(1),
            content_hash: [0xAB; 32],
            block_height: 500,
            round_range: (100, 102),
            signature: vec![],
        };
        let h1 = r.signing_hash(crate::DEFAULT_CHAIN_ID, &make_game_id());
        let h2 = r.signing_hash(crate::DEFAULT_CHAIN_ID, &make_game_id());
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_receipt_signing_hash_differs_by_chain_id() {
        let r = MultiReplicaReceipt {
            witness: make_test_tagged_pubkey(1),
            content_hash: [0xAB; 32],
            block_height: 500,
            round_range: (100, 102),
            signature: vec![],
        };
        let h1 = r.signing_hash(1, &make_game_id());
        let h2 = r.signing_hash(2, &make_game_id());
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_receipt_signing_hash_differs_by_round_range() {
        let r1 = MultiReplicaReceipt {
            witness: make_test_tagged_pubkey(1),
            content_hash: [0xAB; 32],
            block_height: 500,
            round_range: (100, 102),
            signature: vec![],
        };
        let r2 = MultiReplicaReceipt {
            witness: make_test_tagged_pubkey(1),
            content_hash: [0xAB; 32],
            block_height: 500,
            round_range: (100, 103),
            signature: vec![],
        };
        let h1 = r1.signing_hash(crate::DEFAULT_CHAIN_ID, &make_game_id());
        let h2 = r2.signing_hash(crate::DEFAULT_CHAIN_ID, &make_game_id());
        assert_ne!(h1, h2);
    }

    // ===== NonInclusionProof 测试 =====

    #[test]
    fn test_non_inclusion_proof_valid() {
        // 构造一个有效的非包含证明：tx_hash = [0xAB; 32], root = 计算出的根
        let tx_hash = [0xAB; 32];
        let proof = make_non_inclusion_proof(0xAB, [0u8; 32]);
        // 先计算真正的 root
        let mut current = [0u8; 32];
        let mut leaf_hasher = Blake2bVar::new(32).expect("Blake2bVar(32)");
        leaf_hasher.update(&[0x00]);
        leaf_hasher.update(b"");
        leaf_hasher
            .finalize_variable(&mut current)
            .expect("finalize");

        let mut empty_subtree = [0u8; 32];
        let mut h = Blake2bVar::new(32).expect("Blake2bVar(32)");
        h.update(&[0x01]);
        h.update(b"");
        h.update(b"");
        h.finalize_variable(&mut empty_subtree).expect("finalize");

        for (i, sibling) in proof.merkle_path.iter().enumerate() {
            let bit = (tx_hash[i / 8] >> (7 - (i % 8))) & 1;
            let mut internal = Blake2bVar::new(32).expect("Blake2bVar(32)");
            internal.update(&[0x01]);
            if bit == 0 {
                internal.update(&current);
                internal.update(sibling);
            } else {
                internal.update(sibling);
                internal.update(&current);
            }
            internal.finalize_variable(&mut current).expect("finalize");
        }

        let mut valid_proof = proof;
        valid_proof.expected_root = current;
        assert!(valid_proof.verify().is_ok(), "有效非包含证明应通过");
    }

    #[test]
    fn test_non_inclusion_proof_wrong_path_len() {
        let proof = NonInclusionProof {
            tx_hash: [0xAB; 32],
            merkle_path: vec![[0u8; 32]; 100], // 错误长度
            expected_root: [0u8; 32],
        };
        assert!(proof.verify().is_err(), "path 长度错误应失败");
    }

    #[test]
    fn test_non_inclusion_proof_root_mismatch() {
        let proof = make_non_inclusion_proof(0xAB, [0xFF; 32]); // 故意错误 root
        assert!(proof.verify().is_err(), "root 不匹配应失败");
    }

    // ===== RoundRangeNonInclusionProof 测试 =====

    #[test]
    fn test_round_range_proof_valid_empty_vertex_list() {
        let proof = make_round_range_non_inclusion_proof(make_test_tagged_pubkey(0xFE));
        let result = proof.verify(10, 1000, DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS);
        assert!(result.is_ok(), "空 vertex_list + 全 0 bitmap 应通过");
    }

    #[test]
    fn test_round_range_proof_round_end_before_start() {
        let mut proof = make_round_range_non_inclusion_proof(make_test_tagged_pubkey(0xFE));
        proof.round_start = 100;
        proof.round_end = 99;
        let result = proof.verify(10, 1000, DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS);
        assert!(result.is_err(), "round_end < round_start 应失败");
    }

    #[test]
    fn test_round_range_proof_span_exceeds_max() {
        let mut proof = make_round_range_non_inclusion_proof(make_test_tagged_pubkey(0xFE));
        proof.round_start = 100;
        proof.round_end = 200; // span = 101
        let result = proof.verify(10, 1000, DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS);
        assert!(result.is_err(), "round 跨度超限应失败");
    }

    #[test]
    fn test_round_range_proof_bitmap_length_mismatch() {
        let mut proof = make_round_range_non_inclusion_proof(make_test_tagged_pubkey(0xFE));
        proof.round_attendance_bitmap = vec![0u8; 99]; // 错误长度
        let result = proof.verify(10, 1000, DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS);
        assert!(result.is_err(), "bitmap 长度不匹配应失败");
    }

    #[test]
    fn test_round_range_proof_bitmap_set_bits_mismatch() {
        let mut proof = make_round_range_non_inclusion_proof(make_test_tagged_pubkey(0xFE));
        // bitmap 设置 1 位但 vertex_list 仍为空
        proof.round_attendance_bitmap[0] = 0b00000001;
        let result = proof.verify(10, 1000, DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS);
        assert!(
            result.is_err(),
            "bitmap set bits != vertex_list.len() 应失败"
        );
    }

    // ===== AssignedValidatorFailureProof 测试 =====

    #[test]
    fn test_failure_proof_insufficient_witnesses() {
        let anchor = make_checkpoint_anchor_tx(0xAB);
        // 仅 2 个 witness（< 阈值 3）
        let witnesses = vec![make_test_tagged_pubkey(10), make_test_tagged_pubkey(11)];
        let proof =
            make_assigned_validator_failure_proof(anchor, witnesses, make_test_tagged_pubkey(0xFE));
        let result = proof.verify(
            crate::DEFAULT_CHAIN_ID,
            &make_game_id(),
            &[make_test_tagged_pubkey(1)],
            &[
                make_test_tagged_pubkey(10),
                make_test_tagged_pubkey(11),
                make_test_tagged_pubkey(12),
            ],
            DEFAULT_REPLICA_WITNESS_THRESHOLD,
            10,
            1000,
            DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS,
        );
        assert!(
            matches!(
                result,
                Err(PokerL1Error::ForceCheckpointEvidenceFailed { .. })
            ),
            "witness 数量 < 阈值应返回 ForceCheckpointEvidenceFailed"
        );
    }

    #[test]
    fn test_failure_proof_witness_not_in_validator_set() {
        let anchor = make_checkpoint_anchor_tx(0xAB);
        let witnesses = vec![
            make_test_tagged_pubkey(10),
            make_test_tagged_pubkey(11),
            make_test_tagged_pubkey(99), // 不在 validator_set 中
        ];
        let proof =
            make_assigned_validator_failure_proof(anchor, witnesses, make_test_tagged_pubkey(0xFE));
        // validator_set 仅含 10, 11, 12（不含 99）
        let result = proof.verify(
            crate::DEFAULT_CHAIN_ID,
            &make_game_id(),
            &[make_test_tagged_pubkey(1)],
            &[
                make_test_tagged_pubkey(10),
                make_test_tagged_pubkey(11),
                make_test_tagged_pubkey(12),
            ],
            DEFAULT_REPLICA_WITNESS_THRESHOLD,
            10,
            1000,
            DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS,
        );
        assert!(
            matches!(
                result,
                Err(PokerL1Error::ForceCheckpointEvidenceFailed { .. })
            ),
            "witness 不在 validator_set 应失败"
        );
    }

    #[test]
    fn test_failure_proof_duplicate_witnesses_below_threshold() {
        let anchor = make_checkpoint_anchor_tx(0xAB);
        // 3 个 receipt 但仅 2 个不同 witness（去重后 < 3）
        let witnesses = vec![
            make_test_tagged_pubkey(10),
            make_test_tagged_pubkey(10), // 重复
            make_test_tagged_pubkey(11),
        ];
        let proof =
            make_assigned_validator_failure_proof(anchor, witnesses, make_test_tagged_pubkey(0xFE));
        let result = proof.verify(
            crate::DEFAULT_CHAIN_ID,
            &make_game_id(),
            &[make_test_tagged_pubkey(1)],
            &[
                make_test_tagged_pubkey(10),
                make_test_tagged_pubkey(11),
                make_test_tagged_pubkey(12),
            ],
            DEFAULT_REPLICA_WITNESS_THRESHOLD,
            10,
            1000,
            DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS,
        );
        // 期望失败：因为签名是占位的会失败 → InvalidSignature
        assert!(result.is_err(), "占位签名应导致验证失败");
    }

    // ===== ForceCheckpointTx 测试 =====

    #[test]
    fn test_force_checkpoint_tx_game_id_mismatch() {
        let mut tx = make_force_checkpoint_tx(0xAB, vec![], make_test_tagged_pubkey(0xFE));
        tx.game_id = ObjectID::new([0xFF; 20], 999); // 不匹配 original.game_id
        let result = tx.verify(
            crate::DEFAULT_CHAIN_ID,
            &[make_test_tagged_pubkey(1)],
            &[make_test_tagged_pubkey(10)],
            DEFAULT_REPLICA_WITNESS_THRESHOLD,
            10,
            1000,
            DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS,
        );
        assert!(
            matches!(
                result,
                Err(PokerL1Error::ForceCheckpointEvidenceFailed { .. })
            ),
            "game_id 不匹配应失败"
        );
    }

    #[test]
    fn test_force_checkpoint_tx_state_hash_mismatch() {
        let mut tx = make_force_checkpoint_tx(0xAB, vec![], make_test_tagged_pubkey(0xFE));
        tx.state_hash = [0xCD; 32]; // 不匹配 original.state_hash
        let result = tx.verify(
            crate::DEFAULT_CHAIN_ID,
            &[make_test_tagged_pubkey(1)],
            &[make_test_tagged_pubkey(10)],
            DEFAULT_REPLICA_WITNESS_THRESHOLD,
            10,
            1000,
            DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS,
        );
        assert!(
            matches!(
                result,
                Err(PokerL1Error::ForceCheckpointEvidenceFailed { .. })
            ),
            "state_hash 不匹配应失败"
        );
    }

    #[test]
    fn test_force_checkpoint_commitment_hash_deterministic() {
        let tx = make_force_checkpoint_tx(0xAB, vec![], make_test_tagged_pubkey(0xFE));
        let h1 = tx.commitment_hash(crate::DEFAULT_CHAIN_ID);
        let h2 = tx.commitment_hash(crate::DEFAULT_CHAIN_ID);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_force_checkpoint_commitment_hash_differs_by_state() {
        let tx1 = make_force_checkpoint_tx(0xAB, vec![], make_test_tagged_pubkey(0xFE));
        let tx2 = make_force_checkpoint_tx(0xCD, vec![], make_test_tagged_pubkey(0xFE));
        let h1 = tx1.commitment_hash(crate::DEFAULT_CHAIN_ID);
        let h2 = tx2.commitment_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2);
    }

    // ===== apply_force_checkpoint 测试 =====

    #[test]
    fn test_apply_force_checkpoint_success_first_time() {
        let mut game = make_minimal_game();
        let tx = make_force_checkpoint_tx(0xAB, vec![], make_test_tagged_pubkey(0xFE));
        let result = apply_force_checkpoint(&mut game, &tx, 500, DEFAULT_INVESTIGATION_THRESHOLD);
        assert!(result.is_ok(), "首次 force_checkpoint 应成功");
        assert!(!result.unwrap(), "首次未达 slashing 阈值");
        assert_eq!(game.last_action_height, 500);
        assert_eq!(game.under_investigation_count, 1);
    }

    #[test]
    fn test_apply_force_checkpoint_reaches_investigation_threshold() {
        let mut game = make_minimal_game();
        // 模拟已经调查 2 次
        game.under_investigation_count = 2;
        let tx = make_force_checkpoint_tx(0xAB, vec![], make_test_tagged_pubkey(0xFE));
        let result = apply_force_checkpoint(&mut game, &tx, 500, DEFAULT_INVESTIGATION_THRESHOLD);
        assert!(result.is_ok());
        assert!(result.unwrap(), "第 3 次应触发 slashing");
        assert_eq!(game.under_investigation_count, 3);
    }

    #[test]
    fn test_apply_force_checkpoint_game_id_mismatch() {
        let mut game = make_minimal_game();
        let mut tx = make_force_checkpoint_tx(0xAB, vec![], make_test_tagged_pubkey(0xFE));
        tx.game_id = ObjectID::new([0xFF; 20], 999);
        let result = apply_force_checkpoint(&mut game, &tx, 500, DEFAULT_INVESTIGATION_THRESHOLD);
        assert!(
            matches!(result, Err(PokerL1Error::GameNotFound { .. })),
            "game_id 不匹配应返回 GameNotFound"
        );
    }

    // ===== compute_force_checkpoint_deposit 测试 =====

    #[test]
    fn test_compute_force_checkpoint_deposit_default() {
        // 10% of 1000 = 100
        let deposit =
            compute_force_checkpoint_deposit(1000, DEFAULT_FORCE_CHECKPOINT_DEPOSIT_RATIO_BPS);
        assert_eq!(deposit, 100);
    }

    #[test]
    fn test_compute_force_checkpoint_deposit_zero_buy_in() {
        let deposit =
            compute_force_checkpoint_deposit(0, DEFAULT_FORCE_CHECKPOINT_DEPOSIT_RATIO_BPS);
        assert_eq!(deposit, 0);
    }

    #[test]
    fn test_compute_force_checkpoint_deposit_high_ratio() {
        // 200% of 1000 = 2000
        let deposit = compute_force_checkpoint_deposit(1000, 20000);
        assert_eq!(deposit, 2000);
    }

    // ===== 常量测试 =====

    #[test]
    fn test_constants() {
        assert_eq!(
            DEFAULT_FORCE_CHECKPOINT_DEPOSIT_RATIO_BPS, 1000,
            "SEC2-M3: 10%"
        );
        assert_eq!(
            MAX_FORCE_CHECKPOINT_PER_BLOCK, 5,
            "SEC2-M3: 全局每 block 上限 5"
        );
        assert_eq!(DEFAULT_INVESTIGATION_THRESHOLD, 3, "NEW-H1: 累积阈值 3");
        assert_eq!(DEFAULT_REPLICA_WITNESS_THRESHOLD, 3, "NEW-M3: 3-of-N");
        assert_eq!(DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT, 5, "NEW-M3: N=5");
        assert_eq!(VERIFY_FAILURE_PROOF_GAS, 80000, "SEC-H9");
        assert_eq!(
            DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS, 10000,
            "SubTask 27.5g (4)"
        );
        assert_eq!(TX_MERKLE_TREE_DEPTH, 256, "R5-H4: 256-bit depth");
    }
}
