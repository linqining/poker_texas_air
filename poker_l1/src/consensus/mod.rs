//! DAG 共识结构（Task 3 / SubTask 3.3）
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SEC-C1**：DagVertex 签名对象 = `hash(chain_id || epoch || round || author_pubkey || vertex_hash || parent_hashes)`
//!   - 绑定 `chain_id` 防跨链重放
//!   - 绑定 `epoch` 防 epoch 边界 equivocation 证据歧义
//!   - 绑定 `author_pubkey` 使 slashing 证据归属不依赖 ECDSA recovery 反推
//! - **SEC2-C1**：DagCommitCertificate 签名对象 = `hash(chain_id || epoch || commit_round || prev_commit_hash || vertex_hash_list || round_attendance_bitmap || state_root || public_tx_root || gameturn_tx_root)`
//!   - 绑定 `epoch` 防 epoch 边界 equivocation 证据歧义
//!   - 绑定 `prev_commit_hash` 形成 hash chain 防 long-range attack
//!   - 绑定 `state_root` / `public_tx_root` / `gameturn_tx_root` 防 commit certificate 被重用到不同 block 内容
//!
//! Phase 1 定义数据结构 + 签名哈希计算；
//! Phase 2 实现 Bullshark 排序与 commit certificate 组装逻辑。

/// Bullshark 共识与 block 投影（Task 9）。
pub mod bullshark;
/// Commit certificate 签名验证（P05-H-source）。
pub mod cert_verification;
/// 检查点与归档（缺口 #9）。
pub mod checkpoint;
/// 真实 ECVRF-secp256k1-SHA256-TAI prover / verifier（缺口 #2 — IMPL-SEC-2）。
pub mod ecvrf;
/// 游戏分配与 epoch 重分配（Task 12）。
pub mod game_assignment;
/// 多玩家阶段超时惩罚执行（Phase 4 Task 8）。
pub mod phase_timeout;
/// tx 双通道分类与客户端路由（Task 7）。
pub mod routing;
/// Slashing 与审查调查（Task 13 / SubTask 13.2-13.5）。
pub mod slashing;
/// Texas Hold'em 完整轮转规则（Phase 2 Task 4）。
pub mod texas_holdem_turn_rule;
/// Versioned historical consensus-key aliases after validator key rotations.
pub mod validator_key_history;
/// ValidatorSet 与 VRF（Task 13 / SubTask 13.1）。
pub mod validator_set;
/// DAG vertex 产出与 game sub-block 嵌入（Task 8）。
pub mod vertex_production;

// 重新导出 routing 模块公开 API，便于上层直接 `consensus::GameStatus` 等使用。
pub use routing::{
    BettingRound, DEFAULT_MAX_ACTIVE_GAMES_PER_PLAYER, ExecutionMode, GamePhase, GameStatus,
    PhaseTransitionError, SimpleTurnRule, SubmitPhaseKind, TurnRule, validate_active_games_limit,
    validate_assigned_validator, validate_game_turn_phase_aware, validate_lane_route,
    validate_turn_order,
};

// 重新导出 texas_holdem_turn_rule 模块公开 API。
pub use texas_holdem_turn_rule::TexasHoldemTurnRule;

// 重新导出 phase_timeout 模块公开 API（Phase 4 Task 8）。
pub use phase_timeout::{KickResult, handle_submit_phase_timeout};

// 重新导出 vertex_production 模块公开 API。
pub use vertex_production::{
    DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT, GameSubBlock, TimeoutProof, VertexBuilder,
    build_game_sub_block, check_sech6_cross_commit_force_advance, required_parent_count,
    required_quorum, required_witness_count, sort_commit_txs_r4m4, sort_vertex_txs_s9,
    validate_fallback_tx, validate_game_turn_tx, validate_gameturn_gas_free,
};

// 重新导出 validator_set 模块公开 API（Task 13 / SubTask 13.1）。
pub use validator_set::{
    MAX_SINGLE_REDUCTION_RATIO, MIN_VALIDATOR_SET_SIZE, VALIDATOR_BONDING_DELAY_BLOCKS,
    VALIDATOR_UNBONDING_DELAY_BLOCKS, VRF_OUTPUT_SIZE, VRF_PROOF_SIZE, VRF_PUBKEY_SIZE,
    ValidatorEntry, ValidatorSet, ValidatorStatus, ValidatorSystemCall, VrfProof, VrfVerifier,
    compute_genesis_chain_randomness, compute_vrf_input, compute_vrf_output,
};

pub use validator_key_history::{
    VALIDATOR_KEY_HISTORY_OBJECT_ID, VALIDATOR_KEY_HISTORY_OBJECT_TYPE, ValidatorKeyHistory,
    ValidatorKeyRotationRecord, decode_validator_key_history_object,
    is_validator_key_history_object, read_validator_key_history,
    validate_validator_key_history_object, validator_key_history_object,
    write_validator_key_history,
};

// StubVrfVerifier 仅在 test-helpers feature 或 #[cfg(test)] 下导出（P1 修复 — 防止生产误用）
#[cfg(any(test, feature = "test-helpers"))]
pub use validator_set::StubVrfVerifier;

// 重新导出 slashing 模块公开 API（Task 13 / SubTask 13.2-13.5）。
pub use slashing::{
    CommitCertEquivocationEvidence, DEFAULT_DEFENSE_WINDOW_BLOCKS,
    DEFAULT_DOWNTIME_SLASH_PERCENTAGE, DEFAULT_DOWNTIME_THRESHOLD_BLOCKS, DEFAULT_SLASH_PERCENTAGE,
    InvestigationState, SlashingConfig, SlashingReason, SlashingResult, VertexEquivocationEvidence,
    apply_multi_slashing, apply_slashing, check_downtime_slashing, compute_slash_amount,
    is_downtime_auto_slashable, is_downtime_governance_kickout,
};

// 重新导出 game_assignment 模块公开 API（Task 12）。
pub use game_assignment::{
    DEFAULT_FORFEIT_BOND_PERCENTAGE, DEFAULT_GAME_VALIDATOR_TIMEOUT_BLOCKS, EpochTransitionState,
    GameAssignmentConfig, assign_validator_for_game, client_route_validator, compute_current_epoch,
    compute_forfeit_amount, config_from_time_consensus, create_epoch_transition_state,
    is_in_epoch_transition_window, is_validator_failover_triggered,
    validate_client_route_consistency, validate_epoch_reassignment,
    validate_force_advance_during_transition,
};

// 重新导出 bullshark 模块公开 API（Task 9）。
pub use bullshark::{
    BlockProjection, CommitLeader, Dag, assemble_commit_certificate,
    assemble_commit_certificate_with_epoch_transition, bullshark_linear_order,
    bullshark_linear_order_uncommitted, detect_commit_cert_equivocation, detect_commit_leader,
    project_block_from_commit, validate_commit_certificate_fields,
    validate_commit_certificate_quorum,
};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::signature::TaggedPubkey;
use crate::transaction::Transaction;
use crate::{BlockHeight, ChainId, Hash, TimestampMs};

/// DAG round 编号（全局递增，跨 epoch 不重置）。
pub type Round = u64;

/// Epoch 编号（validator 集重分配周期）。
pub type Epoch = u64;

/// Commit round 编号（Bullshark 共识产出 commit 的轮次）。
pub type CommitRound = u64;

/// 签名域分隔前缀。
const VERTEX_SIG_DOMAIN: u8 = 0x56; // 'V' for Vertex
const COMMIT_CERT_SIG_DOMAIN: u8 = 0x43; // 'C' for Commit Certificate

/// Narwhal-style DAG vertex（数据平面）。
///
/// spec：
/// - validator 把 tx 批量打包为 vertex
/// - 含 tx list + 引用 ≥2/3 validator 的上一轮 vertex hash + 自身 secp256k1 签名
/// - vertex 上限 `max_vertex_size`（默认 256KB），超出分多个 vertex
///
/// SEC-C1 修复：签名对象含 `epoch` 与 `author_pubkey` 字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct DagVertex {
    /// 当前 epoch（SEC-C1：绑定 epoch 防 equivocation 证据歧义）。
    pub epoch: Epoch,
    /// DAG round（epoch 内递增；epoch 切换后从 1 重新开始）。
    pub round: Round,
    /// 作者 validator 的 tagged pubkey（SEC-C1：author_pubkey 字段）。
    pub author_pubkey: TaggedPubkey,
    /// 交易列表（tx 批量）。
    pub tx_list: Vec<Transaction>,
    /// 引用的上一轮 vertex hash 列表（≥2/3 validator 的 vertex hash）。
    pub parent_hashes: Vec<Hash>,
    /// 作者 validator 的 secp256k1 签名（签名对象见 `signing_hash`）。
    pub author_sig: Vec<u8>,
}

/// vertex 上限 256KB（spec：max_vertex_size 默认 256KB）。
pub const MAX_VERTEX_SIZE: usize = 256 * 1024;

impl DagVertex {
    /// 计算 vertex_hash（vertex 内容哈希，用于 DAG 引用与 commit certificate）。
    ///
    /// vertex_hash = blake2b_256(0x56 || epoch || round || author_pubkey || tx_hashes || parent_hashes)
    ///
    /// 注意：vertex_hash 不含 author_sig（签名不参与自身的内容哈希）。
    pub fn vertex_hash(&self) -> Hash {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&[VERTEX_SIG_DOMAIN]);
        h.update(&self.epoch.to_le_bytes());
        h.update(&self.round.to_le_bytes());
        h.update(&self.author_pubkey.to_bytes());
        // tx_list：用 tx_hash 摘要
        for tx in &self.tx_list {
            h.update(&tx.tx_hash());
        }
        // parent_hashes
        for parent in &self.parent_hashes {
            h.update(parent);
        }
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }

    /// 计算签名对象哈希（SEC-C1）。
    ///
    /// signing_hash = blake2b_256(chain_id || epoch || round || author_pubkey || vertex_hash || parent_hashes)
    ///
    /// spec SEC-C1：绑定 chain_id 防跨链重放；绑定 epoch 防 epoch 边界 equivocation 证据歧义；
    /// 绑定 author_pubkey 使 slashing 证据归属不依赖 ECDSA recovery 反推。
    pub fn signing_hash(&self, chain_id: ChainId) -> Hash {
        let vertex_hash = self.vertex_hash();
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&chain_id.to_le_bytes());
        h.update(&self.epoch.to_le_bytes());
        h.update(&self.round.to_le_bytes());
        h.update(&self.author_pubkey.to_bytes());
        h.update(&vertex_hash);
        for parent in &self.parent_hashes {
            h.update(parent);
        }
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }

    /// BCS 序列化。
    pub fn to_bcs(&self) -> crate::error::PokerL1Result<Vec<u8>> {
        Ok(borsh::to_vec(self)?)
    }

    /// 从 BCS 反序列化。
    pub fn from_bcs(bytes: &[u8]) -> crate::error::PokerL1Result<Self> {
        Ok(borsh::from_slice(bytes)?)
    }
}

/// Bullshark commit certificate（共识平面）。
///
/// spec：
/// - 某轮 vertex 获得 ≥2/3 validator 引用 → 形成 commit certificate
/// - commit certificate 中的所有 vertex 及其引用的祖先 vertex 被视为 finalized
/// - 轻客户端只需验证 commit certificate 的 2/3 secp256k1 多签即可信任 block header
///
/// SEC2-C1 修复：签名对象含 `epoch` / `prev_commit_hash` / object/account state roots /
/// transaction roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct DagCommitCertificate {
    /// 当前 epoch（SEC2-C1：绑定 epoch 防 equivocation 证据歧义）。
    pub epoch: Epoch,
    /// Bullshark commit 轮次。
    pub commit_round: CommitRound,
    /// 前一个 commit certificate 的哈希（SEC2-C1：形成 hash chain 防 long-range attack）。
    pub prev_commit_hash: Hash,
    /// Epoch transition proof committed by the first certificate of a new epoch.
    ///
    /// The proof is optional only to permit the certificate-beacon fallback when the designated
    /// proposer misses its transition window.  When present it is covered by every certificate
    /// signature and verified during deterministic block replay.
    pub epoch_transition: Option<EpochTransitionProof>,
    /// 本 commit 涵盖的 vertex hash 列表（Bullshark 排序后的 vertex 序列）。
    pub vertex_hash_list: Vec<Hash>,
    /// 本轮出勤 bitmap（标记哪些 validator 参与了本轮 commit）。
    pub round_attendance_bitmap: Vec<u8>,
    /// 本 commit 产出的 block 的 state_root。
    pub state_root: Hash,
    /// AccountStore sparse-Merkle root for the same post-state.
    pub account_root: Hash,
    /// Public 通道 tx 的 Merkle root（NEW-M14）。
    pub public_tx_root: Hash,
    /// GameTurn + CheckpointAnchor 通道 tx 的 Merkle root（NEW-M14）。
    pub gameturn_tx_root: Hash,
    /// validator secp256k1 签名列表（与 signer_bitmap 对应）。
    pub signature_list: Vec<Vec<u8>>,
    /// 签名者 bitmap（标记哪些 validator 签名了本 commit certificate）。
    pub signer_bitmap: Vec<u8>,
}

/// A designated validator's ECVRF proof for one epoch transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct EpochTransitionProof {
    /// Active validator deterministically selected to provide the epoch's VRF output.
    pub proposer_pubkey: TaggedPubkey,
    /// Canonical 81-byte ECVRF-secp256k1-SHA256-TAI proof.
    pub proof: validator_set::VrfProof,
}

impl DagCommitCertificate {
    /// Compute the certificate signing hash bound to the complete block-header position.
    ///
    /// Production votes use this variant so a valid quorum certificate cannot be transplanted to
    /// another height, timestamp, or parent hash. The legacy `signing_hash` remains available for
    /// standalone slashing/evidence objects that do not carry a block header.
    pub fn signing_hash_for_header(
        &self,
        chain_id: ChainId,
        height: BlockHeight,
        timestamp_ms: TimestampMs,
        prev_hash: Hash,
    ) -> Hash {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&[COMMIT_CERT_SIG_DOMAIN]);
        h.update(b"header-bound-v1");
        h.update(&chain_id.to_le_bytes());
        h.update(&height.to_le_bytes());
        h.update(&timestamp_ms.to_le_bytes());
        h.update(&prev_hash);
        h.update(&self.epoch.to_le_bytes());
        h.update(&self.commit_round.to_le_bytes());
        h.update(&self.prev_commit_hash);
        match &self.epoch_transition {
            Some(transition) => {
                h.update(&[1]);
                let proposer = transition.proposer_pubkey.to_bytes();
                h.update(&(proposer.len() as u64).to_le_bytes());
                h.update(&proposer);
                h.update(&transition.proof.to_bytes());
            }
            None => h.update(&[0]),
        }
        h.update(&(self.vertex_hash_list.len() as u64).to_le_bytes());
        for vh in &self.vertex_hash_list {
            h.update(vh);
        }
        h.update(&(self.round_attendance_bitmap.len() as u64).to_le_bytes());
        h.update(&self.round_attendance_bitmap);
        h.update(&self.state_root);
        h.update(&self.account_root);
        h.update(&self.public_tx_root);
        h.update(&self.gameturn_tx_root);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }

    /// 计算签名对象哈希（SEC2-C1）。
    ///
    /// signing_hash = blake2b_256(chain_id || epoch || commit_round || prev_commit_hash
    ///                       || vertex_hash_list || round_attendance_bitmap
    ///                       || state_root || account_root || public_tx_root || gameturn_tx_root)
    ///
    /// spec SEC2-C1：绑定 prev_commit_hash 形成 hash chain 防 long-range attack；
    /// 绑定 object/account roots 和 tx roots，防 certificate 被重用到不同 block。
    pub fn signing_hash(&self, chain_id: ChainId) -> Hash {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&[COMMIT_CERT_SIG_DOMAIN]);
        h.update(&chain_id.to_le_bytes());
        h.update(&self.epoch.to_le_bytes());
        h.update(&self.commit_round.to_le_bytes());
        h.update(&self.prev_commit_hash);
        match &self.epoch_transition {
            Some(transition) => {
                h.update(&[1]);
                let proposer = transition.proposer_pubkey.to_bytes();
                h.update(&(proposer.len() as u64).to_le_bytes());
                h.update(&proposer);
                h.update(&transition.proof.to_bytes());
            }
            None => h.update(&[0]),
        }
        for vh in &self.vertex_hash_list {
            h.update(vh);
        }
        h.update(&self.round_attendance_bitmap);
        h.update(&self.state_root);
        h.update(&self.account_root);
        h.update(&self.public_tx_root);
        h.update(&self.gameturn_tx_root);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }

    /// 计算 commit certificate 自身的哈希（用于 prev_commit_hash 链式引用）。
    ///
    /// cert_hash = blake2b_256(signing_hash || signature_list || signer_bitmap)
    pub fn cert_hash(&self, chain_id: ChainId) -> Hash {
        let signing = self.signing_hash(chain_id);
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&signing);
        for sig in &self.signature_list {
            h.update(&(sig.len() as u64).to_le_bytes());
            h.update(sig);
        }
        h.update(&self.signer_bitmap);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }

    /// Certificate hash for a block-bound certificate.  This is the hash used for the on-chain
    /// previous-certificate link and deliberately includes the same header position as signatures.
    pub fn cert_hash_for_header(
        &self,
        chain_id: ChainId,
        height: BlockHeight,
        timestamp_ms: TimestampMs,
        prev_hash: Hash,
    ) -> Hash {
        let signing = self.signing_hash_for_header(chain_id, height, timestamp_ms, prev_hash);
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&signing);
        h.update(&(self.signature_list.len() as u64).to_le_bytes());
        for sig in &self.signature_list {
            h.update(&(sig.len() as u64).to_le_bytes());
            h.update(sig);
        }
        h.update(&(self.signer_bitmap.len() as u64).to_le_bytes());
        h.update(&self.signer_bitmap);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }

    /// 统计 signer_bitmap 中签名者数量。
    pub fn signer_count(&self) -> usize {
        self.signer_bitmap
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum()
    }

    /// BCS 序列化。
    pub fn to_bcs(&self) -> crate::error::PokerL1Result<Vec<u8>> {
        Ok(borsh::to_vec(self)?)
    }

    /// 从 BCS 反序列化。
    pub fn from_bcs(bytes: &[u8]) -> crate::error::PokerL1Result<Self> {
        Ok(borsh::from_slice(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

    fn dummy_tagged_pubkey() -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![0x02u8; 33],
        }
    }

    fn dummy_vertex() -> DagVertex {
        DagVertex {
            epoch: 1,
            round: 10,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![[0u8; 32], [1u8; 32]],
            author_sig: vec![0u8; 65],
        }
    }

    fn dummy_commit_cert() -> DagCommitCertificate {
        DagCommitCertificate {
            epoch: 1,
            commit_round: 5,
            prev_commit_hash: [0xAAu8; 32],
            epoch_transition: None,
            vertex_hash_list: vec![[0xBBu8; 32], [0xCCu8; 32]],
            round_attendance_bitmap: vec![0xFF, 0x0F],
            state_root: [0x11u8; 32],
            account_root: [0x44u8; 32],
            public_tx_root: [0x22u8; 32],
            gameturn_tx_root: [0x33u8; 32],
            signature_list: vec![vec![0u8; 65], vec![0u8; 65]],
            signer_bitmap: vec![0b00000011, 0b00000000],
        }
    }

    #[test]
    fn vertex_hash_deterministic() {
        let v = dummy_vertex();
        let h1 = v.vertex_hash();
        let h2 = v.vertex_hash();
        assert_eq!(h1, h2, "vertex_hash 必须确定性");
    }

    #[test]
    fn vertex_hash_excludes_author_sig() {
        // author_sig 不参与 vertex_hash
        let mut v = dummy_vertex();
        let h1 = v.vertex_hash();
        v.author_sig = vec![0xFFu8; 65];
        let h2 = v.vertex_hash();
        assert_eq!(h1, h2, "author_sig 不应影响 vertex_hash");
    }

    #[test]
    fn vertex_signing_hash_changes_with_chain_id() {
        let v = dummy_vertex();
        let h1 = v.signing_hash(crate::DEFAULT_CHAIN_ID);
        let h2 = v.signing_hash(0xDEAD_BEEF);
        assert_ne!(h1, h2, "chain_id 变化必须改变 signing_hash");
    }

    #[test]
    fn vertex_signing_hash_changes_with_epoch() {
        let mut v = dummy_vertex();
        let h1 = v.signing_hash(crate::DEFAULT_CHAIN_ID);
        v.epoch = 2;
        let h2 = v.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2, "epoch 变化必须改变 signing_hash");
    }

    #[test]
    fn vertex_signing_hash_changes_with_round() {
        let mut v = dummy_vertex();
        let h1 = v.signing_hash(crate::DEFAULT_CHAIN_ID);
        v.round = 20;
        let h2 = v.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2, "round 变化必须改变 signing_hash");
    }

    #[test]
    fn vertex_signing_hash_changes_with_author_pubkey() {
        let mut v = dummy_vertex();
        let h1 = v.signing_hash(crate::DEFAULT_CHAIN_ID);
        v.author_pubkey = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Ed25519, 1),
            raw: vec![0x03u8; 32],
        };
        let h2 = v.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2, "author_pubkey 变化必须改变 signing_hash");
    }

    #[test]
    fn vertex_bcs_roundtrip() {
        let v = dummy_vertex();
        let bytes = v.to_bcs().expect("BCS 序列化");
        let v2 = DagVertex::from_bcs(&bytes).expect("BCS 反序列化");
        assert_eq!(v, v2, "BCS 往返必须保持一致");
    }

    #[test]
    fn commit_cert_signing_hash_changes_with_chain_id() {
        let c = dummy_commit_cert();
        let h1 = c.signing_hash(crate::DEFAULT_CHAIN_ID);
        let h2 = c.signing_hash(0xDEAD_BEEF);
        assert_ne!(h1, h2, "chain_id 变化必须改变 signing_hash");
    }

    #[test]
    fn commit_cert_signing_hash_changes_with_prev_commit_hash() {
        let mut c = dummy_commit_cert();
        let h1 = c.signing_hash(crate::DEFAULT_CHAIN_ID);
        c.prev_commit_hash = [0x99u8; 32];
        let h2 = c.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2, "prev_commit_hash 变化必须改变 signing_hash");
    }

    #[test]
    fn commit_cert_signing_hash_changes_with_account_root() {
        let mut certificate = dummy_commit_cert();
        let before =
            certificate.signing_hash_for_header(crate::DEFAULT_CHAIN_ID, 1, 1_000, [0u8; 32]);
        certificate.account_root[0] ^= 1;
        let after =
            certificate.signing_hash_for_header(crate::DEFAULT_CHAIN_ID, 1, 1_000, [0u8; 32]);
        assert_ne!(
            before, after,
            "account root must be certificate-signature bound"
        );
    }

    #[test]
    fn commit_cert_signing_hash_changes_with_state_root() {
        let mut c = dummy_commit_cert();
        let h1 = c.signing_hash(crate::DEFAULT_CHAIN_ID);
        c.state_root = [0x99u8; 32];
        let h2 = c.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2, "state_root 变化必须改变 signing_hash");
    }

    #[test]
    fn commit_cert_signing_hash_changes_with_tx_roots() {
        let mut c = dummy_commit_cert();
        let h1 = c.signing_hash(crate::DEFAULT_CHAIN_ID);
        c.public_tx_root = [0x99u8; 32];
        let h2 = c.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2, "public_tx_root 变化必须改变 signing_hash");

        c.gameturn_tx_root = [0x88u8; 32];
        let h3 = c.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h2, h3, "gameturn_tx_root 变化必须改变 signing_hash");
    }

    #[test]
    fn commit_cert_signing_hash_excludes_signatures() {
        // signature_list 和 signer_bitmap 不参与 signing_hash
        let mut c = dummy_commit_cert();
        let h1 = c.signing_hash(crate::DEFAULT_CHAIN_ID);
        c.signature_list = vec![vec![0xFFu8; 65]];
        let h2 = c.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_eq!(h1, h2, "signature_list 不应影响 signing_hash");
    }

    #[test]
    fn commit_cert_cert_hash_includes_signatures() {
        // cert_hash 包含 signatures
        let mut c = dummy_commit_cert();
        let h1 = c.cert_hash(crate::DEFAULT_CHAIN_ID);
        c.signature_list = vec![vec![0xFFu8; 65]];
        let h2 = c.cert_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2, "signature_list 变化必须改变 cert_hash");
    }

    #[test]
    fn commit_cert_signer_count() {
        let c = dummy_commit_cert();
        // signer_bitmap = [0b00000011, 0b00000000] → 2 个签名者
        assert_eq!(c.signer_count(), 2);
    }

    #[test]
    fn commit_cert_bcs_roundtrip() {
        let c = dummy_commit_cert();
        let bytes = c.to_bcs().expect("BCS 序列化");
        let c2 = DagCommitCertificate::from_bcs(&bytes).expect("BCS 反序列化");
        assert_eq!(c, c2, "BCS 往返必须保持一致");
    }

    #[test]
    fn commit_cert_json_roundtrip() {
        let c = dummy_commit_cert();
        let json = serde_json::to_string(&c).expect("JSON 序列化");
        let c2: DagCommitCertificate = serde_json::from_str(&json).expect("JSON 反序列化");
        assert_eq!(c, c2, "JSON 往返必须保持一致");
    }
}
