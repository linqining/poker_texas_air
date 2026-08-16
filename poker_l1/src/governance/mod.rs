//! 治理与参数管理（Task 33）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）第 825-863 行：
//! - **SubTask 33.1**：参数调整提案（parameter_name, new_value）+ 投票期 `voting_period_blocks`
//! - **SubTask 33.2**：2/3 validator 赞成 → 通过；敏感参数需 90% quorum（SEC-H4 补全 9 项 +
//!   SEC-C2 validator_set_size）；timelock `parameter_delay_blocks`（默认 2000）；
//!   timelock 撤销机制（SEC-H8：≥90% 反对立即生效）；quorum 分母规则（SEC2-M6）
//! - **SubTask 33.3**：参数上下界约束（R4-H4 / R5-H2 / R5-M3 / R7-* 修正）
//! - **SubTask 33.4**：可治理参数完整列表（NEW-M12 / R4-M3 / R5-H8 修正）
//! - **SubTask 33.5**：Validator 集更新提案（加入/踢出），epoch 边界生效
//! - **SubTask 33.6**：verifier_status 治理（NEW-C1 + SEC-M4 per-chain_id 命名空间隔离）
//!
//! # 安全约束
//!
//! - **SEC-H4**：敏感参数 90% quorum 补全 9 项
//! - **SEC-C2**：validator_set_size 90% quorum + 下限 5
//! - **SEC-H8**：timelock 撤销须 ≥90% 反对，立即生效
//! - **SEC2-M6**：quorum 分母 = 当前 epoch validator 集大小（含离线）；参与率下限 2/3 / 90%
//! - **SEC-M2**：单次缩减比例 <= 20%
//! - **SEC-M4**：verifier_status per-chain_id（BTreeMap<chain_id, VerifierStatus>）
//! - **SEC2-H4**：密钥轮换 timelock（key_rotation_delay_blocks）

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::consensus::{Epoch, VRF_PUBKEY_SIZE, ValidatorEntry, ValidatorSet, ValidatorStatus};
use crate::economics::FeePolicy;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership};
use crate::signature::TaggedPubkey;
use crate::storage::ObjectBackend;
use crate::{Address, BlockHeight, ChainId};

pub mod validator_bond_escrow;

pub use validator_bond_escrow::{
    PendingValidatorBond, VALIDATOR_BOND_ESCROW_OBJECT_ID, VALIDATOR_BOND_ESCROW_OBJECT_TYPE,
    ValidatorBondEscrow, decode_validator_bond_escrow_object, is_validator_bond_escrow_object,
    pending_validator_bond_escrow, read_validator_bond_escrow,
    validate_validator_bond_escrow_object, validator_bond_escrow_object,
    write_validator_bond_escrow,
};

/// System address used by the governance-state singleton.
pub const GOVERNANCE_SYSTEM_ADDRESS: Address = [0u8; 20];

/// Reserved type tag for the consensus-committed governance state.
pub const GOVERNANCE_STATE_OBJECT_TYPE: &str = "0x2::governance::State";

/// Reserved singleton ID for the canonical governance state.
///
/// The values `MAX`, `MAX-1`, and `MAX-2` are TreasuryCap, ValidatorSet, and FeePolicy;
/// bridge configuration and replay state occupy `MAX-3` and `MAX-4` respectively.
pub const GOVERNANCE_STATE_OBJECT_ID: ObjectID =
    ObjectID::new(GOVERNANCE_SYSTEM_ADDRESS, u64::MAX - 5);

// ===== 默认值常量 =====

/// 默认投票期（block 数）。
pub const DEFAULT_VOTING_PERIOD_BLOCKS: u64 = 1000;
/// 默认参数延迟期（R3-M4：由 500 提升至 2000）。
pub const DEFAULT_PARAMETER_DELAY_BLOCKS: u64 = 2000;
/// 默认 epoch 长度。
pub const DEFAULT_EPOCH_LENGTH_BLOCKS: u64 = 1000;
/// 默认 turn 超时。
pub const DEFAULT_TURN_TIMEOUT_BLOCKS: u64 = 30;
/// 默认 max_interval_ms。
pub const DEFAULT_MAX_INTERVAL_MS: u64 = 2000;
/// 默认 block_gas_limit（100M gas）。
pub const DEFAULT_BLOCK_GAS_LIMIT: u64 = 100_000_000;
/// 默认 slash_percentage（NEW-M15：100%）。
pub const DEFAULT_SLASH_PERCENTAGE: u64 = 100;
/// 默认 downtime_slash_percentage（NEW-L2：10%）。
pub const DEFAULT_DOWNTIME_SLASH_PERCENTAGE: u64 = 10;
/// 默认 defense_window_blocks。
pub const DEFAULT_DEFENSE_WINDOW_BLOCKS: u64 = 500;
/// 默认 checkpoint_multi_replica_count（NEW-M3：5）。
pub const DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT: u64 = 5;
/// 默认 delegated_escape_max_expiry_blocks。
pub const DEFAULT_DELEGATED_ESCAPE_MAX_EXPIRY_BLOCKS: u64 = 100;
/// 默认 game_validator_timeout_blocks（= floor(turn_timeout_blocks / 2)）。
pub const DEFAULT_GAME_VALIDATOR_TIMEOUT_BLOCKS: u64 = 15;
/// 默认 ack_deadline_blocks。
pub const DEFAULT_ACK_DEADLINE_BLOCKS: u64 = 3;
/// 默认 max_skip_segments。
pub const DEFAULT_MAX_SKIP_SEGMENTS: u64 = 3;
/// 默认 max_active_games_per_player。
pub const DEFAULT_MAX_ACTIVE_GAMES_PER_PLAYER: u64 = 10;
/// 默认 max_vertex_size（256KB）。
pub const DEFAULT_MAX_VERTEX_SIZE: u64 = 256 * 1024;
/// 默认 bonding_period_blocks（= 1 epoch）。
pub const DEFAULT_BONDING_PERIOD_BLOCKS: u64 = 1000;
/// 默认 unbonding_period_blocks（= 2 × epoch）。
pub const DEFAULT_UNBONDING_PERIOD_BLOCKS: u64 = 2000;
/// 默认 downtime_threshold_blocks。
pub const DEFAULT_DOWNTIME_THRESHOLD_BLOCKS: u64 = 100;
/// 默认 under_investigation_threshold。
pub const DEFAULT_UNDER_INVESTIGATION_THRESHOLD: u64 = 3;
/// 默认 max_designated_operator_check_exemptions。
pub const DEFAULT_MAX_DESIGNATED_OPERATOR_CHECK_EXEMPTIONS: u64 = 3;
/// 默认 hand_max_duration_blocks。
pub const DEFAULT_HAND_MAX_DURATION_BLOCKS: u64 = 120;
/// 默认 archive_node_min_count。
pub const DEFAULT_ARCHIVE_NODE_MIN_COUNT: u64 = 3;
/// 默认 recovery_window_blocks。
pub const DEFAULT_RECOVERY_WINDOW_BLOCKS: u64 = 100;
/// 默认 checkpoint_interval_blocks。
pub const DEFAULT_CHECKPOINT_INTERVAL_BLOCKS: u64 = 5;
/// 默认 da_window_blocks。
pub const DEFAULT_DA_WINDOW_BLOCKS: u64 = 500;
/// 默认 dispute_window_blocks。
pub const DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 500;
/// 默认 tx_prune_after_blocks。
pub const DEFAULT_TX_PRUNE_AFTER_BLOCKS: u64 = 1000;
/// 默认 vertex_prune_after_blocks。
pub const DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS: u64 = 10_000;
/// 默认 archive_retention_blocks。
pub const DEFAULT_ARCHIVE_RETENTION_BLOCKS: u64 = 100_000;
/// 默认 epoch_transition_window_blocks。
pub const DEFAULT_EPOCH_TRANSITION_WINDOW_BLOCKS: u64 = 10;
/// 默认 malicious_refuse_threshold。
pub const DEFAULT_MALICIOUS_REFUSE_THRESHOLD: u64 = 3;
/// 默认 max_request_ack_per_turn_timeout。
pub const DEFAULT_MAX_REQUEST_ACK_PER_TURN_TIMEOUT: u64 = 3;
/// 默认 max_clock_drift_ms。
pub const DEFAULT_MAX_CLOCK_DRIFT_MS: u64 = 500;
/// 默认 forfeit_deposit_ratio（%）。
pub const DEFAULT_FORFEIT_DEPOSIT_RATIO: u64 = 50;
/// 默认 challenge_deposit_ratio（SEC-C4：50）。
pub const DEFAULT_CHALLENGE_DEPOSIT_RATIO: u64 = 50;
/// 默认 challenge_reward_ratio（SEC-C4：100）。
pub const DEFAULT_CHALLENGE_REWARD_RATIO: u64 = 100;
/// 默认 designated_operator_bond_amount。
pub const DEFAULT_DESIGNATED_OPERATOR_BOND_AMOUNT: u64 = 10_000;
/// 默认 key_rotation_delay_blocks。
pub const DEFAULT_KEY_ROTATION_DELAY_BLOCKS: u64 = 1000;
/// 默认 validator_set_size。
pub const DEFAULT_VALIDATOR_SET_SIZE: u64 = 10;
/// 默认 max_partial_checkin_count（SEC-H1：3）。
pub const DEFAULT_MAX_PARTIAL_CHECKIN_COUNT: u64 = 3;
/// Production verifier 切换后的 grace 期 block 数（v1.2 SubTask 8.2.3）。
///
/// grace 期内 proof_kind 双通道：ZkShuffle 旧 Stub proof + Zkvm Production proof 并存。
pub const PRODUCTION_GRACE_BLOCKS: u64 = 7200;

// ===== Phase 11.5 新增默认值常量（与 poker_zkvm 编译时常量对齐）=====

/// 默认 max_zkvm_trace_steps（= 1000 × 1024，满足一致性约束；poker_zkvm 编译期硬上限 1_048_576）。
pub const DEFAULT_MAX_ZKVM_TRACE_STEPS: u64 = 1_024_000;
/// 默认 max_zkvm_memory（16MB，与 `poker_zkvm::compiler::elf_validator::MAX_ZKVM_MEMORY` 对齐）。
pub const DEFAULT_MAX_ZKVM_MEMORY: u64 = 16 * 1024 * 1024;
/// 默认 max_zkvm_proof_size（64KB，与 `poker_zkvm::prover::MAX_ZKVM_PROOF_SIZE` 对齐）。
pub const DEFAULT_MAX_ZKVM_PROOF_SIZE: u64 = 64 * 1024;
/// 默认 zkvm_batch_size（1024，与 `poker_zkvm::constraints::ZKVM_BATCH_SIZE` 对齐）。
pub const DEFAULT_ZKVM_BATCH_SIZE: u64 = 1024;
/// 默认 max_recursion_depth（16，与 `poker_zkvm::prover::MAX_RECURSION_DEPTH` 对齐）。
pub const DEFAULT_MAX_RECURSION_DEPTH: u64 = 16;
/// 默认 max_trace_host_memory（512MB，与 `poker_zkvm::trace::MAX_TRACE_HOST_MEMORY` 对齐）。
pub const DEFAULT_MAX_TRACE_HOST_MEMORY: u64 = 512 * 1024 * 1024;
/// 默认 gas_stwo_verify（300000，与 `gas_table::GAS_STWO_VERIFY` 对齐）。
pub const DEFAULT_GAS_STWO_VERIFY: u64 = 300_000;
/// 默认 max_public_io_size（8KB，v1.4 M3-001）。
pub const DEFAULT_MAX_PUBLIC_IO_SIZE: u64 = 8 * 1024;
/// 默认 max_folded_instance_size（8KB，v1.4 M3-001）。
pub const DEFAULT_MAX_FOLDED_INSTANCE_SIZE: u64 = 8 * 1024;
/// 默认 max_sumcheck_proof_size（16KB，v1.4 M3-001）。
pub const DEFAULT_MAX_SUMCHECK_PROOF_SIZE: u64 = 16 * 1024;
/// 默认 max_pcs_opening_size（8KB，v1.4 M3-001）。
pub const DEFAULT_MAX_PCS_OPENING_SIZE: u64 = 8 * 1024;
/// 默认 max_event_hashes_count（256，v1.4 M3-001）。
pub const DEFAULT_MAX_EVENT_HASHES_COUNT: u64 = 256;

// ===== VerifierStatus（NEW-C1 + SEC-M4） =====

/// ZK verifier 状态的共识/runtime 统一类型。
///
/// SEC-M4：per-chain_id 命名空间隔离，存储为 `BTreeMap<chain_id, VerifierStatus>`。
pub use crate::offline::zk_verifier::VerifierStatus;

// ===== ParamName（可治理参数完整列表，NEW-M12 / R4-M3 / R5-H8 / R7-M2/M5） =====

/// 可治理参数名（强类型枚举）。
///
/// 完整列表见 spec.md 第 847-851 行（NEW-M12 / R4-M3 / R5-H8 / R7-M2/M5 修正）。
/// 共 41 个可治理参数。
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
pub enum ParamName {
    /// turn_timeout_blocks
    TurnTimeoutBlocks,
    /// hand_max_duration_blocks
    HandMaxDurationBlocks,
    /// dispute_window_blocks
    DisputeWindowBlocks,
    /// da_window_blocks
    DaWindowBlocks,
    /// recovery_window_blocks
    RecoveryWindowBlocks,
    /// checkpoint_interval_blocks
    CheckpointIntervalBlocks,
    /// game_validator_timeout_blocks
    GameValidatorTimeoutBlocks,
    /// ack_deadline_blocks
    AckDeadlineBlocks,
    /// max_skip_segments
    MaxSkipSegments,
    /// malicious_refuse_threshold
    MaliciousRefuseThreshold,
    /// max_interval_ms
    MaxIntervalMs,
    /// max_active_games_per_player
    MaxActiveGamesPerPlayer,
    /// epoch_length_blocks
    EpochLengthBlocks,
    /// max_vertex_size
    MaxVertexSize,
    /// block_gas_limit
    BlockGasLimit,
    /// tx_prune_after_blocks
    TxPruneAfterBlocks,
    /// vertex_prune_after_blocks
    VertexPruneAfterBlocks,
    /// archive_node_min_count
    ArchiveNodeMinCount,
    /// checkpoint_multi_replica_count
    CheckpointMultiReplicaCount,
    /// delegated_escape_max_expiry_blocks
    DelegatedEscapeMaxExpiryBlocks,
    /// defense_window_blocks
    DefenseWindowBlocks,
    /// parameter_delay_blocks
    ParameterDelayBlocks,
    /// epoch_transition_window_blocks
    EpochTransitionWindowBlocks,
    /// bonding_period_blocks
    BondingPeriodBlocks,
    /// slash_percentage
    SlashPercentage,
    /// downtime_slash_percentage
    DowntimeSlashPercentage,
    /// verifier_status（敏感 90% quorum）
    VerifierStatus,
    /// downtime_threshold_blocks
    DowntimeThresholdBlocks,
    /// voting_period_blocks
    VotingPeriodBlocks,
    /// max_designated_operator_check_exemptions
    MaxDesignatedOperatorCheckExemptions,
    /// under_investigation_threshold
    UnderInvestigationThreshold,
    /// max_request_ack_per_turn_timeout
    MaxRequestAckPerTurnTimeout,
    /// max_clock_drift_ms
    MaxClockDriftMs,
    /// forfeit_deposit_ratio
    ForfeitDepositRatio,
    /// challenge_deposit_ratio
    ChallengeDepositRatio,
    /// challenge_reward_ratio
    ChallengeRewardRatio,
    /// designated_operator_bond_amount
    DesignatedOperatorBondAmount,
    /// unbonding_period_blocks
    UnbondingPeriodBlocks,
    /// key_rotation_delay_blocks
    KeyRotationDelayBlocks,
    /// archive_retention_blocks
    ArchiveRetentionBlocks,
    /// validator_set_size（SEC-C2：敏感 90% quorum）
    ValidatorSetSize,
    /// max_partial_checkin_count（SEC-H1）
    MaxPartialCheckinCount,
    /// production_switch_height（v1.2 SubTask 11.5.2.10 — 一次性写入字段，敏感 90% quorum）
    ProductionSwitchHeight,
    /// max_zkvm_trace_steps（Phase 11.5 — 敏感 90% quorum）
    MaxZkvmTraceSteps,
    /// max_zkvm_memory（Phase 11.5 — 敏感 90% quorum）
    MaxZkvmMemory,
    /// max_zkvm_proof_size（Phase 11.5 — 敏感 90% quorum）
    MaxZkvmProofSize,
    /// zkvm_batch_size（Phase 11.5 — 敏感 90% quorum；含一致性约束）
    ZkvmBatchSize,
    /// max_recursion_depth（Phase 11.5 — 敏感 90% quorum）
    MaxRecursionDepth,
    /// max_trace_host_memory（Phase 11.5 — 敏感 90% quorum）
    MaxTraceHostMemory,
    /// production_grace_blocks（Phase 11.5 — 敏感 90% quorum）
    ProductionGraceBlocks,
    /// gas_stwo_verify（Phase 11.5 — 敏感 90% quorum；RPC 字符串保留 `gas_hypernova_verify` 兼容）
    GasStwoVerify,
    /// max_public_io_size（Phase 11.5 v1.3 M2-002 子分配 — 敏感 90% quorum）
    MaxPublicIoSize,
    /// max_folded_instance_size（Phase 11.5 v1.3 M2-002 子分配 — 敏感 90% quorum）
    MaxFoldedInstanceSize,
    /// max_sumcheck_proof_size（Phase 11.5 v1.3 M2-002 子分配 — 敏感 90% quorum）
    MaxSumcheckProofSize,
    /// max_pcs_opening_size（Phase 11.5 v1.3 M2-002 子分配 — 敏感 90% quorum）
    MaxPcsOpeningSize,
    /// max_event_hashes_count（Phase 11.5 v1.3 M2-002 子分配 — 敏感 90% quorum）
    MaxEventHashesCount,
}

impl ParamName {
    /// 返回参数的字符串名（用于错误信息）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TurnTimeoutBlocks => "turn_timeout_blocks",
            Self::HandMaxDurationBlocks => "hand_max_duration_blocks",
            Self::DisputeWindowBlocks => "dispute_window_blocks",
            Self::DaWindowBlocks => "da_window_blocks",
            Self::RecoveryWindowBlocks => "recovery_window_blocks",
            Self::CheckpointIntervalBlocks => "checkpoint_interval_blocks",
            Self::GameValidatorTimeoutBlocks => "game_validator_timeout_blocks",
            Self::AckDeadlineBlocks => "ack_deadline_blocks",
            Self::MaxSkipSegments => "max_skip_segments",
            Self::MaliciousRefuseThreshold => "malicious_refuse_threshold",
            Self::MaxIntervalMs => "max_interval_ms",
            Self::MaxActiveGamesPerPlayer => "max_active_games_per_player",
            Self::EpochLengthBlocks => "epoch_length_blocks",
            Self::MaxVertexSize => "max_vertex_size",
            Self::BlockGasLimit => "block_gas_limit",
            Self::TxPruneAfterBlocks => "tx_prune_after_blocks",
            Self::VertexPruneAfterBlocks => "vertex_prune_after_blocks",
            Self::ArchiveNodeMinCount => "archive_node_min_count",
            Self::CheckpointMultiReplicaCount => "checkpoint_multi_replica_count",
            Self::DelegatedEscapeMaxExpiryBlocks => "delegated_escape_max_expiry_blocks",
            Self::DefenseWindowBlocks => "defense_window_blocks",
            Self::ParameterDelayBlocks => "parameter_delay_blocks",
            Self::EpochTransitionWindowBlocks => "epoch_transition_window_blocks",
            Self::BondingPeriodBlocks => "bonding_period_blocks",
            Self::SlashPercentage => "slash_percentage",
            Self::DowntimeSlashPercentage => "downtime_slash_percentage",
            Self::VerifierStatus => "verifier_status",
            Self::DowntimeThresholdBlocks => "downtime_threshold_blocks",
            Self::VotingPeriodBlocks => "voting_period_blocks",
            Self::MaxDesignatedOperatorCheckExemptions => {
                "max_designated_operator_check_exemptions"
            }
            Self::UnderInvestigationThreshold => "under_investigation_threshold",
            Self::MaxRequestAckPerTurnTimeout => "max_request_ack_per_turn_timeout",
            Self::MaxClockDriftMs => "max_clock_drift_ms",
            Self::ForfeitDepositRatio => "forfeit_deposit_ratio",
            Self::ChallengeDepositRatio => "challenge_deposit_ratio",
            Self::ChallengeRewardRatio => "challenge_reward_ratio",
            Self::DesignatedOperatorBondAmount => "designated_operator_bond_amount",
            Self::UnbondingPeriodBlocks => "unbonding_period_blocks",
            Self::KeyRotationDelayBlocks => "key_rotation_delay_blocks",
            Self::ArchiveRetentionBlocks => "archive_retention_blocks",
            Self::ValidatorSetSize => "validator_set_size",
            Self::MaxPartialCheckinCount => "max_partial_checkin_count",
            Self::ProductionSwitchHeight => "production_switch_height",
            Self::MaxZkvmTraceSteps => "max_zkvm_trace_steps",
            Self::MaxZkvmMemory => "max_zkvm_memory",
            Self::MaxZkvmProofSize => "max_zkvm_proof_size",
            Self::ZkvmBatchSize => "zkvm_batch_size",
            Self::MaxRecursionDepth => "max_recursion_depth",
            Self::MaxTraceHostMemory => "max_trace_host_memory",
            Self::ProductionGraceBlocks => "production_grace_blocks",
            // 向后兼容：RPC 字符串保留历史名 `gas_hypernova_verify`（避免破坏现有治理客户端）。
            Self::GasStwoVerify => "gas_hypernova_verify",
            Self::MaxPublicIoSize => "max_public_io_size",
            Self::MaxFoldedInstanceSize => "max_folded_instance_size",
            Self::MaxSumcheckProofSize => "max_sumcheck_proof_size",
            Self::MaxPcsOpeningSize => "max_pcs_opening_size",
            Self::MaxEventHashesCount => "max_event_hashes_count",
        }
    }

    /// 判断是否为敏感参数（需 90% quorum）。
    ///
    /// 敏感参数完整列表（spec.md 第 839 行）：
    /// - R3-H1 修正（8 项）：block_gas_limit / epoch_length_blocks / validator_set 更新 /
    ///   slash_percentage / downtime_slash_percentage / verifier_status /
    ///   parameter_delay_blocks / defense_window_blocks
    /// - SEC-H4 补全（9 项）：bonding_period_blocks / unbonding_period_blocks /
    ///   key_rotation_delay_blocks / checkpoint_multi_replica_count /
    ///   archive_retention_blocks / max_skip_segments / turn_timeout_blocks /
    ///   malicious_refuse_threshold / max_request_ack_per_turn_timeout
    /// - SEC-C2（1 项）：validator_set_size
    #[must_use]
    pub const fn is_sensitive(self) -> bool {
        matches!(
            self,
            Self::BlockGasLimit
                | Self::EpochLengthBlocks
                | Self::SlashPercentage
                | Self::DowntimeSlashPercentage
                | Self::VerifierStatus
                | Self::ParameterDelayBlocks
                | Self::DefenseWindowBlocks
                | Self::BondingPeriodBlocks
                | Self::UnbondingPeriodBlocks
                | Self::KeyRotationDelayBlocks
                | Self::CheckpointMultiReplicaCount
                | Self::ArchiveRetentionBlocks
                | Self::MaxSkipSegments
                | Self::TurnTimeoutBlocks
                | Self::MaliciousRefuseThreshold
                | Self::MaxRequestAckPerTurnTimeout
                | Self::ValidatorSetSize
                | Self::ProductionSwitchHeight
                | Self::MaxZkvmTraceSteps
                | Self::MaxZkvmMemory
                | Self::MaxZkvmProofSize
                | Self::ZkvmBatchSize
                | Self::MaxRecursionDepth
                | Self::MaxTraceHostMemory
                | Self::ProductionGraceBlocks
                | Self::GasStwoVerify
                | Self::MaxPublicIoSize
                | Self::MaxFoldedInstanceSize
                | Self::MaxSumcheckProofSize
                | Self::MaxPcsOpeningSize
                | Self::MaxEventHashesCount
        )
    }
}

// ===== GovernanceParams（参数集合 + 边界校验） =====

/// 治理参数集合（所有可治理参数的当前值）。
///
/// 每个参数的默认值与边界见 spec.md 第 841-845 行。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GovernanceParams {
    /// turn_timeout_blocks ∈ [3, 1000]
    pub turn_timeout_blocks: u64,
    /// hand_max_duration_blocks ∈ [turn_timeout_blocks*4, 100000]
    pub hand_max_duration_blocks: u64,
    /// dispute_window_blocks ∈ [10, 10000]
    pub dispute_window_blocks: u64,
    /// da_window_blocks ∈ [10, 10000]
    pub da_window_blocks: u64,
    /// recovery_window_blocks ∈ [10, 10000]
    pub recovery_window_blocks: u64,
    /// checkpoint_interval_blocks ∈ [1, 1000]
    pub checkpoint_interval_blocks: u64,
    /// game_validator_timeout_blocks ∈ [1, floor(turn_timeout_blocks / 2)]
    pub game_validator_timeout_blocks: u64,
    /// ack_deadline_blocks ∈ [1, 100]
    pub ack_deadline_blocks: u64,
    /// max_skip_segments ∈ [1, 10]
    pub max_skip_segments: u64,
    /// malicious_refuse_threshold ∈ [1, 100]
    pub malicious_refuse_threshold: u64,
    /// max_interval_ms ∈ [500, 60000]
    pub max_interval_ms: u64,
    /// max_active_games_per_player ∈ [1, 1000]
    pub max_active_games_per_player: u64,
    /// epoch_length_blocks ∈ [100, 10000]
    pub epoch_length_blocks: u64,
    /// max_vertex_size ∈ [64KB, 4MB]
    pub max_vertex_size: u64,
    /// block_gas_limit ∈ [10M, 200M]
    pub block_gas_limit: u64,
    /// tx_prune_after_blocks ∈ [100, 100000]
    pub tx_prune_after_blocks: u64,
    /// vertex_prune_after_blocks ∈ [100, 100000]
    pub vertex_prune_after_blocks: u64,
    /// archive_node_min_count ∈ [1, 100]
    pub archive_node_min_count: u64,
    /// checkpoint_multi_replica_count ∈ [3, 15]
    pub checkpoint_multi_replica_count: u64,
    /// delegated_escape_max_expiry_blocks ∈ [10, 1000]
    pub delegated_escape_max_expiry_blocks: u64,
    /// defense_window_blocks ∈ [10, 1000]
    pub defense_window_blocks: u64,
    /// parameter_delay_blocks ∈ [100, 10000]
    pub parameter_delay_blocks: u64,
    /// epoch_transition_window_blocks ∈ [1, 100]
    pub epoch_transition_window_blocks: u64,
    /// bonding_period_blocks ∈ [epoch_length_blocks, 10*epoch_length_blocks]
    pub bonding_period_blocks: u64,
    /// slash_percentage ∈ [1, 100]
    pub slash_percentage: u64,
    /// downtime_slash_percentage ∈ [1, 100]
    pub downtime_slash_percentage: u64,
    /// downtime_threshold_blocks ∈ [10, 10000]
    pub downtime_threshold_blocks: u64,
    /// voting_period_blocks ∈ [10, 10000]
    pub voting_period_blocks: u64,
    /// max_designated_operator_check_exemptions ∈ [0, 10]
    pub max_designated_operator_check_exemptions: u64,
    /// under_investigation_threshold ∈ [1, 100]
    pub under_investigation_threshold: u64,
    /// max_request_ack_per_turn_timeout ∈ [1, 100]
    pub max_request_ack_per_turn_timeout: u64,
    /// max_clock_drift_ms ∈ [0, 60000]
    pub max_clock_drift_ms: u64,
    /// forfeit_deposit_ratio ∈ [10, 200]
    pub forfeit_deposit_ratio: u64,
    /// challenge_deposit_ratio ∈ [1, 100]
    pub challenge_deposit_ratio: u64,
    /// challenge_reward_ratio ∈ [10, 100]
    pub challenge_reward_ratio: u64,
    /// designated_operator_bond_amount ∈ [1, 10^9]
    pub designated_operator_bond_amount: u64,
    /// unbonding_period_blocks ∈ [epoch_length_blocks, 10*epoch_length_blocks]
    pub unbonding_period_blocks: u64,
    /// key_rotation_delay_blocks ∈ [100, 10000]
    pub key_rotation_delay_blocks: u64,
    /// archive_retention_blocks ∈ [1000, 1000000]
    pub archive_retention_blocks: u64,
    /// validator_set_size ∈ [5, 1000]（SEC-C2）
    pub validator_set_size: u64,
    /// max_partial_checkin_count ∈ [1, 10]（SEC-H1）
    pub max_partial_checkin_count: u64,
    /// production_switch_height（v1.2 SubTask 11.5.2.10 — 一次性写入字段，默认 0 表示未切换）。
    ///
    /// 治理切换 `verifier_status` 从 `Stub` 到 `Production` 时写入当前 block height，
    /// grace 期起算点；grace 期结束后可清零。非持续调整参数，但写入须 90% quorum。
    pub production_switch_height: u64,
    /// max_zkvm_trace_steps ∈ [65536, 16_777_216]（Phase 11.5 — 敏感 90% quorum）。
    pub max_zkvm_trace_steps: u64,
    /// max_zkvm_memory ∈ [4MB, 64MB]（Phase 11.5 — 敏感 90% quorum）。
    pub max_zkvm_memory: u64,
    /// max_zkvm_proof_size ∈ [16KB, 256KB]（Phase 11.5 — 敏感 90% quorum）。
    pub max_zkvm_proof_size: u64,
    /// zkvm_batch_size ∈ [64, 8192]（Phase 11.5 — 敏感 90% quorum；含一致性约束：
    /// `max_zkvm_trace_steps / zkvm_batch_size ≤ MAX_FOLD_STEP_COUNT=1000`）。
    pub zkvm_batch_size: u64,
    /// max_recursion_depth ∈ [4, 32]（Phase 11.5 — 敏感 90% quorum）。
    pub max_recursion_depth: u64,
    /// max_trace_host_memory ∈ [128MB, 2GB]（Phase 11.5 — 敏感 90% quorum）。
    pub max_trace_host_memory: u64,
    /// production_grace_blocks ∈ [720, 72000]（Phase 11.5 — 敏感 90% quorum）。
    pub production_grace_blocks: u64,
    /// gas_stwo_verify ∈ [100000, 1000000]（Phase 11.5 — 敏感 90% quorum；Stwo ZK 证明验证 gas）。
    pub gas_stwo_verify: u64,
    /// max_public_io_size ∈ [4KB, 32KB]（Phase 11.5 v1.3 M2-002 子分配 — 敏感 90% quorum）。
    pub max_public_io_size: u64,
    /// max_folded_instance_size ∈ [4KB, 32KB]（Phase 11.5 v1.3 M2-002 子分配 — 敏感 90% quorum）。
    pub max_folded_instance_size: u64,
    /// max_sumcheck_proof_size ∈ [8KB, 64KB]（Phase 11.5 v1.3 M2-002 子分配 — 敏感 90% quorum）。
    pub max_sumcheck_proof_size: u64,
    /// max_pcs_opening_size ∈ [4KB, 32KB]（Phase 11.5 v1.3 M2-002 子分配 — 敏感 90% quorum）。
    pub max_pcs_opening_size: u64,
    /// max_event_hashes_count ∈ [32, 1024]（Phase 11.5 v1.3 M2-002 子分配 — 敏感 90% quorum）。
    pub max_event_hashes_count: u64,
}

impl GovernanceParams {
    /// 创建默认参数集（所有参数取默认值）。
    #[must_use]
    pub const fn default_values() -> Self {
        Self {
            turn_timeout_blocks: DEFAULT_TURN_TIMEOUT_BLOCKS,
            hand_max_duration_blocks: DEFAULT_HAND_MAX_DURATION_BLOCKS,
            dispute_window_blocks: DEFAULT_DISPUTE_WINDOW_BLOCKS,
            da_window_blocks: DEFAULT_DA_WINDOW_BLOCKS,
            recovery_window_blocks: DEFAULT_RECOVERY_WINDOW_BLOCKS,
            checkpoint_interval_blocks: DEFAULT_CHECKPOINT_INTERVAL_BLOCKS,
            game_validator_timeout_blocks: DEFAULT_GAME_VALIDATOR_TIMEOUT_BLOCKS,
            ack_deadline_blocks: DEFAULT_ACK_DEADLINE_BLOCKS,
            max_skip_segments: DEFAULT_MAX_SKIP_SEGMENTS,
            malicious_refuse_threshold: DEFAULT_MALICIOUS_REFUSE_THRESHOLD,
            max_interval_ms: DEFAULT_MAX_INTERVAL_MS,
            max_active_games_per_player: DEFAULT_MAX_ACTIVE_GAMES_PER_PLAYER,
            epoch_length_blocks: DEFAULT_EPOCH_LENGTH_BLOCKS,
            max_vertex_size: DEFAULT_MAX_VERTEX_SIZE,
            block_gas_limit: DEFAULT_BLOCK_GAS_LIMIT,
            tx_prune_after_blocks: DEFAULT_TX_PRUNE_AFTER_BLOCKS,
            vertex_prune_after_blocks: DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS,
            archive_node_min_count: DEFAULT_ARCHIVE_NODE_MIN_COUNT,
            checkpoint_multi_replica_count: DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT,
            delegated_escape_max_expiry_blocks: DEFAULT_DELEGATED_ESCAPE_MAX_EXPIRY_BLOCKS,
            defense_window_blocks: DEFAULT_DEFENSE_WINDOW_BLOCKS,
            parameter_delay_blocks: DEFAULT_PARAMETER_DELAY_BLOCKS,
            epoch_transition_window_blocks: DEFAULT_EPOCH_TRANSITION_WINDOW_BLOCKS,
            bonding_period_blocks: DEFAULT_BONDING_PERIOD_BLOCKS,
            slash_percentage: DEFAULT_SLASH_PERCENTAGE,
            downtime_slash_percentage: DEFAULT_DOWNTIME_SLASH_PERCENTAGE,
            downtime_threshold_blocks: DEFAULT_DOWNTIME_THRESHOLD_BLOCKS,
            voting_period_blocks: DEFAULT_VOTING_PERIOD_BLOCKS,
            max_designated_operator_check_exemptions:
                DEFAULT_MAX_DESIGNATED_OPERATOR_CHECK_EXEMPTIONS,
            under_investigation_threshold: DEFAULT_UNDER_INVESTIGATION_THRESHOLD,
            max_request_ack_per_turn_timeout: DEFAULT_MAX_REQUEST_ACK_PER_TURN_TIMEOUT,
            max_clock_drift_ms: DEFAULT_MAX_CLOCK_DRIFT_MS,
            forfeit_deposit_ratio: DEFAULT_FORFEIT_DEPOSIT_RATIO,
            challenge_deposit_ratio: DEFAULT_CHALLENGE_DEPOSIT_RATIO,
            challenge_reward_ratio: DEFAULT_CHALLENGE_REWARD_RATIO,
            designated_operator_bond_amount: DEFAULT_DESIGNATED_OPERATOR_BOND_AMOUNT,
            unbonding_period_blocks: DEFAULT_UNBONDING_PERIOD_BLOCKS,
            key_rotation_delay_blocks: DEFAULT_KEY_ROTATION_DELAY_BLOCKS,
            archive_retention_blocks: DEFAULT_ARCHIVE_RETENTION_BLOCKS,
            validator_set_size: DEFAULT_VALIDATOR_SET_SIZE,
            max_partial_checkin_count: DEFAULT_MAX_PARTIAL_CHECKIN_COUNT,
            production_switch_height: 0,
            max_zkvm_trace_steps: DEFAULT_MAX_ZKVM_TRACE_STEPS,
            max_zkvm_memory: DEFAULT_MAX_ZKVM_MEMORY,
            max_zkvm_proof_size: DEFAULT_MAX_ZKVM_PROOF_SIZE,
            zkvm_batch_size: DEFAULT_ZKVM_BATCH_SIZE,
            max_recursion_depth: DEFAULT_MAX_RECURSION_DEPTH,
            max_trace_host_memory: DEFAULT_MAX_TRACE_HOST_MEMORY,
            production_grace_blocks: PRODUCTION_GRACE_BLOCKS,
            gas_stwo_verify: DEFAULT_GAS_STWO_VERIFY,
            max_public_io_size: DEFAULT_MAX_PUBLIC_IO_SIZE,
            max_folded_instance_size: DEFAULT_MAX_FOLDED_INSTANCE_SIZE,
            max_sumcheck_proof_size: DEFAULT_MAX_SUMCHECK_PROOF_SIZE,
            max_pcs_opening_size: DEFAULT_MAX_PCS_OPENING_SIZE,
            max_event_hashes_count: DEFAULT_MAX_EVENT_HASHES_COUNT,
        }
    }

    /// 获取指定参数的当前值。
    #[must_use]
    pub const fn get(&self, name: ParamName) -> u64 {
        match name {
            ParamName::TurnTimeoutBlocks => self.turn_timeout_blocks,
            ParamName::HandMaxDurationBlocks => self.hand_max_duration_blocks,
            ParamName::DisputeWindowBlocks => self.dispute_window_blocks,
            ParamName::DaWindowBlocks => self.da_window_blocks,
            ParamName::RecoveryWindowBlocks => self.recovery_window_blocks,
            ParamName::CheckpointIntervalBlocks => self.checkpoint_interval_blocks,
            ParamName::GameValidatorTimeoutBlocks => self.game_validator_timeout_blocks,
            ParamName::AckDeadlineBlocks => self.ack_deadline_blocks,
            ParamName::MaxSkipSegments => self.max_skip_segments,
            ParamName::MaliciousRefuseThreshold => self.malicious_refuse_threshold,
            ParamName::MaxIntervalMs => self.max_interval_ms,
            ParamName::MaxActiveGamesPerPlayer => self.max_active_games_per_player,
            ParamName::EpochLengthBlocks => self.epoch_length_blocks,
            ParamName::MaxVertexSize => self.max_vertex_size,
            ParamName::BlockGasLimit => self.block_gas_limit,
            ParamName::TxPruneAfterBlocks => self.tx_prune_after_blocks,
            ParamName::VertexPruneAfterBlocks => self.vertex_prune_after_blocks,
            ParamName::ArchiveNodeMinCount => self.archive_node_min_count,
            ParamName::CheckpointMultiReplicaCount => self.checkpoint_multi_replica_count,
            ParamName::DelegatedEscapeMaxExpiryBlocks => self.delegated_escape_max_expiry_blocks,
            ParamName::DefenseWindowBlocks => self.defense_window_blocks,
            ParamName::ParameterDelayBlocks => self.parameter_delay_blocks,
            ParamName::EpochTransitionWindowBlocks => self.epoch_transition_window_blocks,
            ParamName::BondingPeriodBlocks => self.bonding_period_blocks,
            ParamName::SlashPercentage => self.slash_percentage,
            ParamName::DowntimeSlashPercentage => self.downtime_slash_percentage,
            ParamName::VerifierStatus => 0, // VerifierStatus 单独存储，不在此处
            ParamName::DowntimeThresholdBlocks => self.downtime_threshold_blocks,
            ParamName::VotingPeriodBlocks => self.voting_period_blocks,
            ParamName::MaxDesignatedOperatorCheckExemptions => {
                self.max_designated_operator_check_exemptions
            }
            ParamName::UnderInvestigationThreshold => self.under_investigation_threshold,
            ParamName::MaxRequestAckPerTurnTimeout => self.max_request_ack_per_turn_timeout,
            ParamName::MaxClockDriftMs => self.max_clock_drift_ms,
            ParamName::ForfeitDepositRatio => self.forfeit_deposit_ratio,
            ParamName::ChallengeDepositRatio => self.challenge_deposit_ratio,
            ParamName::ChallengeRewardRatio => self.challenge_reward_ratio,
            ParamName::DesignatedOperatorBondAmount => self.designated_operator_bond_amount,
            ParamName::UnbondingPeriodBlocks => self.unbonding_period_blocks,
            ParamName::KeyRotationDelayBlocks => self.key_rotation_delay_blocks,
            ParamName::ArchiveRetentionBlocks => self.archive_retention_blocks,
            ParamName::ValidatorSetSize => self.validator_set_size,
            ParamName::MaxPartialCheckinCount => self.max_partial_checkin_count,
            ParamName::ProductionSwitchHeight => self.production_switch_height,
            ParamName::MaxZkvmTraceSteps => self.max_zkvm_trace_steps,
            ParamName::MaxZkvmMemory => self.max_zkvm_memory,
            ParamName::MaxZkvmProofSize => self.max_zkvm_proof_size,
            ParamName::ZkvmBatchSize => self.zkvm_batch_size,
            ParamName::MaxRecursionDepth => self.max_recursion_depth,
            ParamName::MaxTraceHostMemory => self.max_trace_host_memory,
            ParamName::ProductionGraceBlocks => self.production_grace_blocks,
            ParamName::GasStwoVerify => self.gas_stwo_verify,
            ParamName::MaxPublicIoSize => self.max_public_io_size,
            ParamName::MaxFoldedInstanceSize => self.max_folded_instance_size,
            ParamName::MaxSumcheckProofSize => self.max_sumcheck_proof_size,
            ParamName::MaxPcsOpeningSize => self.max_pcs_opening_size,
            ParamName::MaxEventHashesCount => self.max_event_hashes_count,
        }
    }

    /// 设置指定参数的值（不校验边界，调用方须先调用 [`validate_param`]）。
    pub const fn set(&mut self, name: ParamName, value: u64) {
        match name {
            ParamName::TurnTimeoutBlocks => self.turn_timeout_blocks = value,
            ParamName::HandMaxDurationBlocks => self.hand_max_duration_blocks = value,
            ParamName::DisputeWindowBlocks => self.dispute_window_blocks = value,
            ParamName::DaWindowBlocks => self.da_window_blocks = value,
            ParamName::RecoveryWindowBlocks => self.recovery_window_blocks = value,
            ParamName::CheckpointIntervalBlocks => self.checkpoint_interval_blocks = value,
            ParamName::GameValidatorTimeoutBlocks => self.game_validator_timeout_blocks = value,
            ParamName::AckDeadlineBlocks => self.ack_deadline_blocks = value,
            ParamName::MaxSkipSegments => self.max_skip_segments = value,
            ParamName::MaliciousRefuseThreshold => self.malicious_refuse_threshold = value,
            ParamName::MaxIntervalMs => self.max_interval_ms = value,
            ParamName::MaxActiveGamesPerPlayer => self.max_active_games_per_player = value,
            ParamName::EpochLengthBlocks => self.epoch_length_blocks = value,
            ParamName::MaxVertexSize => self.max_vertex_size = value,
            ParamName::BlockGasLimit => self.block_gas_limit = value,
            ParamName::TxPruneAfterBlocks => self.tx_prune_after_blocks = value,
            ParamName::VertexPruneAfterBlocks => self.vertex_prune_after_blocks = value,
            ParamName::ArchiveNodeMinCount => self.archive_node_min_count = value,
            ParamName::CheckpointMultiReplicaCount => self.checkpoint_multi_replica_count = value,
            ParamName::DelegatedEscapeMaxExpiryBlocks => {
                self.delegated_escape_max_expiry_blocks = value;
            }
            ParamName::DefenseWindowBlocks => self.defense_window_blocks = value,
            ParamName::ParameterDelayBlocks => self.parameter_delay_blocks = value,
            ParamName::EpochTransitionWindowBlocks => self.epoch_transition_window_blocks = value,
            ParamName::BondingPeriodBlocks => self.bonding_period_blocks = value,
            ParamName::SlashPercentage => self.slash_percentage = value,
            ParamName::DowntimeSlashPercentage => self.downtime_slash_percentage = value,
            ParamName::VerifierStatus => {
                // VerifierStatus 单独存储，不应通过此路径设置
            }
            ParamName::DowntimeThresholdBlocks => self.downtime_threshold_blocks = value,
            ParamName::VotingPeriodBlocks => self.voting_period_blocks = value,
            ParamName::MaxDesignatedOperatorCheckExemptions => {
                self.max_designated_operator_check_exemptions = value;
            }
            ParamName::UnderInvestigationThreshold => self.under_investigation_threshold = value,
            ParamName::MaxRequestAckPerTurnTimeout => self.max_request_ack_per_turn_timeout = value,
            ParamName::MaxClockDriftMs => self.max_clock_drift_ms = value,
            ParamName::ForfeitDepositRatio => self.forfeit_deposit_ratio = value,
            ParamName::ChallengeDepositRatio => self.challenge_deposit_ratio = value,
            ParamName::ChallengeRewardRatio => self.challenge_reward_ratio = value,
            ParamName::DesignatedOperatorBondAmount => self.designated_operator_bond_amount = value,
            ParamName::UnbondingPeriodBlocks => self.unbonding_period_blocks = value,
            ParamName::KeyRotationDelayBlocks => self.key_rotation_delay_blocks = value,
            ParamName::ArchiveRetentionBlocks => self.archive_retention_blocks = value,
            ParamName::ValidatorSetSize => self.validator_set_size = value,
            ParamName::MaxPartialCheckinCount => self.max_partial_checkin_count = value,
            ParamName::ProductionSwitchHeight => self.production_switch_height = value,
            ParamName::MaxZkvmTraceSteps => self.max_zkvm_trace_steps = value,
            ParamName::MaxZkvmMemory => self.max_zkvm_memory = value,
            ParamName::MaxZkvmProofSize => self.max_zkvm_proof_size = value,
            ParamName::ZkvmBatchSize => self.zkvm_batch_size = value,
            ParamName::MaxRecursionDepth => self.max_recursion_depth = value,
            ParamName::MaxTraceHostMemory => self.max_trace_host_memory = value,
            ParamName::ProductionGraceBlocks => self.production_grace_blocks = value,
            ParamName::GasStwoVerify => self.gas_stwo_verify = value,
            ParamName::MaxPublicIoSize => self.max_public_io_size = value,
            ParamName::MaxFoldedInstanceSize => self.max_folded_instance_size = value,
            ParamName::MaxSumcheckProofSize => self.max_sumcheck_proof_size = value,
            ParamName::MaxPcsOpeningSize => self.max_pcs_opening_size = value,
            ParamName::MaxEventHashesCount => self.max_event_hashes_count = value,
        }
    }
}

impl Default for GovernanceParams {
    fn default() -> Self {
        Self::default_values()
    }
}

// ===== 参数边界校验（R4-H4 / R5-H2 / R5-M3 / R7-* 修正） =====

/// 校验参数值是否在边界内。
///
/// 返回 `(min, max)` 表示边界；若 `value` 越界返回 `Err(ParamOutOfBounds)`。
///
/// # 依赖参数
///
/// 部分参数的边界依赖其他参数的当前值：
/// - `game_validator_timeout_blocks ∈ [1, floor(turn_timeout_blocks / 2)]`（R5-H2）
/// - `hand_max_duration_blocks ∈ [turn_timeout_blocks*4, 100000]`
/// - `bonding_period_blocks ∈ [epoch_length_blocks, 10*epoch_length_blocks]`
/// - `unbonding_period_blocks ∈ [epoch_length_blocks, 10*epoch_length_blocks]`
///
/// # VerifierStatus 特殊处理
///
/// `verifier_status` 非 u64 数值，而是一个枚举（Stub/Production）。
/// 此函数对 `VerifierStatus` 返回 `(0, 1)`（0=Stub, 1=Production），
/// 实际状态切换由 [`GovernanceState::set_verifier_status`] 处理。
pub const fn validate_param(
    params: &GovernanceParams,
    name: ParamName,
    value: u64,
) -> PokerL1Result<(u64, u64)> {
    let (min, max) = match name {
        ParamName::TurnTimeoutBlocks => (3, 1000),
        ParamName::HandMaxDurationBlocks => (params.turn_timeout_blocks * 4, 100_000),
        ParamName::DisputeWindowBlocks => (10, 10_000),
        ParamName::DaWindowBlocks => (10, 10_000),
        ParamName::RecoveryWindowBlocks => (10, 10_000),
        ParamName::CheckpointIntervalBlocks => (1, 1000),
        ParamName::GameValidatorTimeoutBlocks => (1, params.turn_timeout_blocks / 2),
        ParamName::AckDeadlineBlocks => (1, 100),
        ParamName::MaxSkipSegments => (1, 10),
        ParamName::MaliciousRefuseThreshold => (1, 100),
        ParamName::MaxIntervalMs => (500, 60_000),
        ParamName::MaxActiveGamesPerPlayer => (1, 1000),
        ParamName::EpochLengthBlocks => (100, 10_000),
        ParamName::MaxVertexSize => (64 * 1024, 4 * 1024 * 1024),
        ParamName::BlockGasLimit => (10_000_000, 200_000_000),
        ParamName::TxPruneAfterBlocks => (100, 100_000),
        ParamName::VertexPruneAfterBlocks => (100, 100_000),
        ParamName::ArchiveNodeMinCount => (1, 100),
        ParamName::CheckpointMultiReplicaCount => (3, 15),
        ParamName::DelegatedEscapeMaxExpiryBlocks => (10, 1000),
        ParamName::DefenseWindowBlocks => (10, 1000),
        ParamName::ParameterDelayBlocks => (100, 10_000),
        ParamName::EpochTransitionWindowBlocks => (1, 100),
        ParamName::BondingPeriodBlocks => {
            (params.epoch_length_blocks, params.epoch_length_blocks * 10)
        }
        ParamName::SlashPercentage => (1, 100),
        ParamName::DowntimeSlashPercentage => (1, 100),
        ParamName::VerifierStatus => (0, 1), // 0=Stub, 1=Production
        ParamName::DowntimeThresholdBlocks => (10, 10_000),
        ParamName::VotingPeriodBlocks => (10, 10_000),
        ParamName::MaxDesignatedOperatorCheckExemptions => (0, 10),
        ParamName::UnderInvestigationThreshold => (1, 100),
        ParamName::MaxRequestAckPerTurnTimeout => (1, 100),
        ParamName::MaxClockDriftMs => (0, 60_000),
        ParamName::ForfeitDepositRatio => (10, 200),
        ParamName::ChallengeDepositRatio => (1, 100),
        ParamName::ChallengeRewardRatio => (10, 100),
        ParamName::DesignatedOperatorBondAmount => (1, 1_000_000_000),
        ParamName::UnbondingPeriodBlocks => {
            (params.epoch_length_blocks, params.epoch_length_blocks * 10)
        }
        ParamName::KeyRotationDelayBlocks => (100, 10_000),
        ParamName::ArchiveRetentionBlocks => (1000, 1_000_000),
        ParamName::ValidatorSetSize => (5, 1000), // SEC-C2
        ParamName::MaxPartialCheckinCount => (1, 10), // SEC-H1
        // production_switch_height：0 表示未切换；非 0 值须 ≥ 1（无上界，由一次性写入语义约束）
        ParamName::ProductionSwitchHeight => (0, u64::MAX),
        // Phase 11.5 新增参数边界
        ParamName::MaxZkvmTraceSteps => (65_536, 16_777_216),
        ParamName::MaxZkvmMemory => (4 * 1024 * 1024, 64 * 1024 * 1024),
        ParamName::MaxZkvmProofSize => (16 * 1024, 256 * 1024),
        ParamName::ZkvmBatchSize => (64, 8192),
        ParamName::MaxRecursionDepth => (4, 32),
        ParamName::MaxTraceHostMemory => (128 * 1024 * 1024, 2 * 1024 * 1024 * 1024),
        ParamName::ProductionGraceBlocks => (720, 72_000),
        ParamName::GasStwoVerify => (100_000, 1_000_000),
        ParamName::MaxPublicIoSize => (4 * 1024, 32 * 1024),
        ParamName::MaxFoldedInstanceSize => (4 * 1024, 32 * 1024),
        ParamName::MaxSumcheckProofSize => (8 * 1024, 64 * 1024),
        ParamName::MaxPcsOpeningSize => (4 * 1024, 32 * 1024),
        ParamName::MaxEventHashesCount => (32, 1024),
    };
    if value < min || value > max {
        return Err(PokerL1Error::ParamOutOfBounds {
            param: name.as_str(),
            value,
            min,
            max,
        });
    }
    // Phase 11.5 跨参数一致性约束（SubTask 11.5.2.4）：
    // ceil(max_zkvm_trace_steps / zkvm_batch_size) ≤ MAX_FOLD_STEP_COUNT (1000)
    let fold_limit = crate::offline::MAX_FOLD_STEP_COUNT as u64;
    match name {
        ParamName::ZkvmBatchSize if value > 0 => {
            let max_fold_steps = params.max_zkvm_trace_steps.div_ceil(value);
            if max_fold_steps > fold_limit {
                return Err(PokerL1Error::ParamOutOfBounds {
                    param: name.as_str(),
                    value,
                    min: params.max_zkvm_trace_steps.div_ceil(fold_limit),
                    max,
                });
            }
        }
        ParamName::MaxZkvmTraceSteps if params.zkvm_batch_size > 0 => {
            let max_fold_steps = value.div_ceil(params.zkvm_batch_size);
            if max_fold_steps > fold_limit {
                return Err(PokerL1Error::ParamOutOfBounds {
                    param: name.as_str(),
                    value,
                    min,
                    max: params.zkvm_batch_size * fold_limit,
                });
            }
        }
        _ => {}
    }
    Ok((min, max))
}

// ===== Quorum 计算（SEC2-M6） =====

/// 计算普通参数（2/3 quorum）所需的赞成票数。
///
/// SEC2-M6：分母 = 当前 epoch validator 集大小（含离线）。
/// 严格 >2/3 的最小整数（C-3 修复）。
#[must_use]
pub const fn required_yes_votes_normal(validator_count: usize) -> usize {
    if validator_count == 0 {
        return 0;
    }
    2 * validator_count / 3 + 1 // 严格 >2/3
}

/// 计算敏感参数（90% quorum）所需的赞成票数。
///
/// SEC2-M6：分母 = 当前 epoch validator 集大小（含离线）。
/// 向上取整：`ceil(validator_count * 9 / 10)`。
#[must_use]
pub const fn required_yes_votes_sensitive(validator_count: usize) -> usize {
    if validator_count == 0 {
        return 0;
    }
    (validator_count * 9).div_ceil(10) // ceil(n * 9 / 10)
}

/// 计算投票参与率下限（SEC2-M6：普通 2/3，敏感 90%）。
#[must_use]
pub const fn required_participation(is_sensitive: bool, validator_count: usize) -> usize {
    if is_sensitive {
        required_yes_votes_sensitive(validator_count)
    } else {
        required_yes_votes_normal(validator_count)
    }
}

/// 计算撤销提案所需赞成票数（SEC-H8：≥90%）。
#[must_use]
pub const fn required_revocation_votes(validator_count: usize) -> usize {
    required_yes_votes_sensitive(validator_count)
}

// ===== 提案类型 =====

/// 提案类型。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum ProposalKind {
    /// 参数调整提案（SubTask 33.1）。
    ParameterChange {
        /// 目标参数名。
        param: ParamName,
        /// 提议新值。
        new_value: u64,
        /// 目标 chain_id（SEC-M4：verifier_status per-chain_id）。
        target_chain_id: ChainId,
    },
    /// Chain-wide resource-credit policy change.
    ///
    /// This is deliberately its own proposal kind rather than a node-local setting: it changes
    /// account-root transitions, so it requires the sensitive 90% vote and the normal parameter
    /// timelock before the executor replaces the FeePolicy singleton.
    FeePolicyChange {
        /// Policy to activate after the timelock.
        policy: FeePolicy,
    },
    /// Upgrade one deterministic native-precompile implementation after sensitive governance.
    ///
    /// The executable native code is supplied by the node release, but this proposal pins its
    /// version and activation in the state root so launch-local registry changes cannot fork
    /// execution.
    PrecompileUpgrade {
        /// Reserved precompile identifier.
        precompile_id: ObjectID,
        /// Strictly newer implementation version supplied by the release.
        new_version: u32,
    },
    /// Enable or disable one native precompile through the same sensitive governance lifecycle.
    PrecompileStatusChange {
        /// Reserved precompile identifier.
        precompile_id: ObjectID,
        /// Consensus-visible execution status.
        status: crate::vm::precompile::PrecompileStatus,
    },
    /// Validator 集更新提案（SubTask 33.5）。
    ValidatorSetUpdate {
        /// 加入的 validator（pubkey + vrf_pubkey + stake）。
        additions: Vec<ValidatorAddition>,
        /// 踢出的 validator pubkey。
        removals: Vec<TaggedPubkey>,
        /// 生效 epoch。
        effective_epoch: Epoch,
    },
    /// 密钥轮换提案（R5-L5）。
    KeyRotation {
        /// 旧 pubkey。
        old_pubkey: TaggedPubkey,
        /// 新 pubkey。
        new_pubkey: TaggedPubkey,
        /// timelock 结束 height。
        effective_height: BlockHeight,
    },
    /// Timelock 撤销提案（SEC-H8）。
    TimelockRevocation {
        /// 被撤销的原提案 ID。
        original_proposal_id: u64,
    },
}

/// Validator 加入提案的参数。
mod vrf_pubkey_serde {
    use super::VRF_PUBKEY_SIZE;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &[u8; VRF_PUBKEY_SIZE],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; VRF_PUBKEY_SIZE], D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != VRF_PUBKEY_SIZE {
            return Err(serde::de::Error::custom(format!(
                "expected {VRF_PUBKEY_SIZE}-byte VRF public key, got {}",
                bytes.len()
            )));
        }
        let mut value = [0u8; VRF_PUBKEY_SIZE];
        value.copy_from_slice(&bytes);
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ValidatorAddition {
    /// 新 validator 的 tagged pubkey。
    pub pubkey: TaggedPubkey,
    /// 新 validator 的 compressed secp256k1 VRF public key.
    #[serde(with = "vrf_pubkey_serde")]
    pub vrf_pubkey: [u8; VRF_PUBKEY_SIZE],
    /// 质押金额。
    pub stake: u64,
}

// ===== 提案状态 =====

/// 提案状态。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum ProposalStatus {
    /// 投票中。
    Voting,
    /// 投票通过，等待 timelock 结束（普通参数）。
    Timelock,
    /// 投票通过且无 timelock，待执行（validator 集更新 / 密钥轮换 / 撤销提案）。
    Passed,
    /// 已执行。
    Executed,
    /// 投票未通过（赞成不足 / 参与率不足）。
    Rejected,
    /// timelock 内被撤销（SEC-H8）。
    Revoked,
}

// ===== 提案 =====

/// 治理提案。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Proposal {
    /// 提案 ID（全局唯一，单调递增）。
    pub id: u64,
    /// 提案类型。
    pub kind: ProposalKind,
    /// 提案者（validator pubkey）。
    pub proposer: TaggedPubkey,
    /// 提案提交时的 block height。
    pub submit_height: BlockHeight,
    /// 投票期结束 height（= submit_height + voting_period_blocks）。
    pub voting_end_height: BlockHeight,
    /// 赞成票（validator pubkey 集合）。
    pub yes_votes: Vec<TaggedPubkey>,
    /// 反对票（validator pubkey 集合）。
    pub no_votes: Vec<TaggedPubkey>,
    /// 当前状态。
    pub status: ProposalStatus,
    /// timelock 结束 height（Passed/Timelock 状态下有意义）。
    pub timelock_end_height: Option<BlockHeight>,
}

impl Proposal {
    /// 总投票数（赞成 + 反对）。
    #[must_use]
    pub const fn total_votes(&self) -> usize {
        self.yes_votes.len() + self.no_votes.len()
    }

    /// 是否已投票。
    #[must_use]
    pub fn has_voted(&self, validator: &TaggedPubkey) -> bool {
        self.yes_votes.contains(validator) || self.no_votes.contains(validator)
    }
}

// ===== GovernanceState =====

/// 治理状态（全局唯一）。
///
/// 管理所有提案 + 参数 + verifier_status（per-chain_id）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GovernanceState {
    /// 当前参数集。
    pub params: GovernanceParams,
    /// 所有提案（按 ID 索引）。
    pub proposals: BTreeMap<u64, Proposal>,
    /// 下一个提案 ID。
    pub next_proposal_id: u64,
    /// verifier_status per chain_id（SEC-M4）。
    pub verifier_statuses: BTreeMap<ChainId, VerifierStatus>,
    /// 已消费的 bridge nonce（防重放，跨链桥模块共享此状态）。
    pub consumed_bridges: BTreeMap<ChainId, u64>,
}

/// Native governance operation executed exclusively by the block executor.
///
/// The payload is carried in a signed Public-lane transaction addressed to the reserved
/// governance system contract.  It is deliberately not a normal VM/precompile call: proposal
/// authorization, the current validator denominator, and replacement of the immutable
/// [`GovernanceState`] singleton are consensus rules rather than contract-local policy.
///
/// Validator-set membership and key rotation proposals remain intentionally unavailable from
/// this wire interface until their full, epoch-bound state transitions are implemented.  Merely
/// marking such a proposal `Executed` would give users a false impression that consensus
/// membership had changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum GovernanceSystemCall {
    /// Create a parameter-change proposal on behalf of the authenticated validator caller.
    CreateParameterProposal {
        /// Parameter to modify after its voting period and timelock.
        param: ParamName,
        /// Candidate value, validated against the committed current parameters.
        new_value: u64,
        /// Chain namespace for verifier-status proposals.
        target_chain_id: ChainId,
    },
    /// Create a sensitive proposal to replace the consensus FeePolicy singleton.
    CreateFeePolicyProposal {
        /// Policy to activate after quorum and timelock.
        policy: FeePolicy,
    },
    /// Create a sensitive validator-set change which is applied only at its declared epoch.
    CreateValidatorSetUpdateProposal {
        /// Validators to add, including their consensus and VRF identities.
        additions: Vec<ValidatorAddition>,
        /// Active validators to move into unbonding at the epoch boundary.
        removals: Vec<TaggedPubkey>,
        /// The future epoch at which the update may be applied.
        effective_epoch: Epoch,
    },
    /// Cast the authenticated validator caller's one vote for a proposal.
    Vote {
        /// Proposal identifier.
        proposal_id: u64,
        /// Whether this is an affirmative vote.
        approve: bool,
    },
    /// Close a proposal's voting period using the committed validator-set denominator.
    FinalizeVoting {
        /// Proposal identifier.
        proposal_id: u64,
    },
    /// Execute a passed/timelocked parameter proposal when its chain-defined delay has elapsed.
    ExecuteProposal {
        /// Proposal identifier.
        proposal_id: u64,
    },
}

/// Version-2 governance wire for validator additions backed by NativeCoin escrow.
///
/// This is deliberately a separate enum and reserved executor contract.  Appending fields or
/// variants to [`GovernanceSystemCall`] would make an existing Borsh wire format ambiguous to
/// old nodes.  Activation is therefore an explicit protocol capability: chains which never use
/// this contract need not create its companion escrow singleton.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum ValidatorBondGovernanceSystemCall {
    /// Consume signer-owned NativeCoin inputs and create a validator-set proposal whose
    /// additions are locked until the scheduled epoch or a terminal refund.
    CreateBondedValidatorSetUpdateProposal {
        /// Validators to add, with total stake exactly covered by transaction inputs.
        additions: Vec<ValidatorAddition>,
        /// Active validators to transition into ordinary unbonding at the epoch boundary.
        removals: Vec<TaggedPubkey>,
        /// Future epoch at which the update is eligible to activate.
        effective_epoch: Epoch,
    },
    /// Refund a rejected or revoked proposal's escrow to its original NativeCoin funder.
    ClaimRejectedValidatorBondRefund {
        /// Terminal governance proposal whose pending bond is reclaimed.
        proposal_id: u64,
    },
}

/// Versioned governance wire for validator consensus-key rotations.
///
/// The old key is the transaction signer; this avoids allowing one active validator to submit a
/// replacement for another validator.  The proposal itself is still subject to the sensitive
/// governance quorum and is applied only by the epoch-transition path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum ValidatorKeyRotationSystemCall {
    /// Propose an epoch-bound replacement for the signer's current consensus key.
    CreateKeyRotationProposal {
        /// New tagged consensus signing key.
        new_pubkey: TaggedPubkey,
    },
}

/// Versioned governance wire for native-precompile release and enablement changes.
///
/// This is intentionally separate from [`GovernanceSystemCall`]: appending a consensus-critical
/// native-code operation to an established wire format would make an old binary silently lack a
/// required execution path.  Voting, finalization and execution still use the canonical
/// governance lifecycle and its committed validator denominator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum PrecompileGovernanceSystemCall {
    /// Create a sensitive, timelocked native implementation upgrade proposal.
    CreateUpgradeProposal {
        /// Reserved native precompile to upgrade.
        precompile_id: ObjectID,
        /// New native implementation version compiled into the protocol release.
        new_version: u32,
    },
    /// Create a sensitive, timelocked enablement-state proposal.
    CreateStatusProposal {
        /// Reserved native precompile to enable or disable.
        precompile_id: ObjectID,
        /// Requested consensus status.
        status: crate::vm::precompile::PrecompileStatus,
    },
}

impl GovernanceState {
    /// 创建默认治理状态（所有参数取默认值，verifier_status 全部为 Stub）。
    #[must_use]
    pub fn new() -> Self {
        let mut verifier_statuses = BTreeMap::new();
        // SEC-M4：mainnet chain_id 初始为 Stub
        verifier_statuses.insert(crate::DEFAULT_CHAIN_ID, VerifierStatus::Stub);
        Self {
            params: GovernanceParams::default_values(),
            proposals: BTreeMap::new(),
            next_proposal_id: 1,
            verifier_statuses,
            consumed_bridges: BTreeMap::new(),
        }
    }

    /// 获取指定 chain_id 的 verifier_status（SEC-M4）。
    #[must_use]
    pub fn verifier_status(&self, chain_id: ChainId) -> VerifierStatus {
        self.verifier_statuses
            .get(&chain_id)
            .copied()
            .unwrap_or(VerifierStatus::Stub)
    }

    /// 设置指定 chain_id 的 verifier_status（SEC-M4）。
    ///
    /// 仅由治理提案执行路径调用，不直接暴露给合约。
    pub fn set_verifier_status(&mut self, chain_id: ChainId, status: VerifierStatus) {
        self.verifier_statuses.insert(chain_id, status);
    }

    /// 校验 OffChain checkout 是否被允许（NEW-C1）。
    ///
    /// 主网 chain_id + verifier_status=Stub → 拒绝（返回 `OffChainDisabledOnMainnet`）。
    /// testnet/devnet 不受限制。
    #[must_use]
    pub fn is_offchain_checkout_allowed(&self, chain_id: ChainId) -> bool {
        if chain_id == crate::DEFAULT_CHAIN_ID {
            // 主网：须 Production
            self.verifier_status(chain_id) == VerifierStatus::Production
        } else {
            // testnet/devnet：不受限制
            true
        }
    }

    /// 创建参数调整提案（SubTask 33.1）。
    ///
    /// 校验：
    /// 1. 参数边界（`validate_param`）
    /// 2. chain_id 与网络一致（SEC-M4，仅 verifier_status 提案需要）
    ///
    /// # 参数
    /// - `param`：目标参数
    /// - `new_value`：提议新值
    /// - `target_chain_id`：目标 chain_id（verifier_status 提案用，其他参数忽略）
    /// - `proposer`：提案者
    /// - `current_height`：当前 block height
    /// - `network_chain_id`：网络 chain_id（校验用）
    pub fn create_parameter_proposal(
        &mut self,
        param: ParamName,
        new_value: u64,
        target_chain_id: ChainId,
        proposer: TaggedPubkey,
        current_height: BlockHeight,
        network_chain_id: ChainId,
    ) -> PokerL1Result<u64> {
        // SEC-M4：verifier_status 提案须校验 chain_id == network_chain_id
        if param == ParamName::VerifierStatus && target_chain_id != network_chain_id {
            return Err(PokerL1Error::ProposalChainIdMismatch {
                proposal: target_chain_id,
                network: network_chain_id,
            });
        }

        // 校验参数边界
        validate_param(&self.params, param, new_value)?;

        let voting_period = self.params.voting_period_blocks;
        let proposal_id = self.next_proposal_id;
        self.next_proposal_id += 1;

        let proposal = Proposal {
            id: proposal_id,
            kind: ProposalKind::ParameterChange {
                param,
                new_value,
                target_chain_id,
            },
            proposer,
            submit_height: current_height,
            voting_end_height: current_height + voting_period,
            yes_votes: vec![],
            no_votes: vec![],
            status: ProposalStatus::Voting,
            timelock_end_height: None,
        };

        self.proposals.insert(proposal_id, proposal);
        Ok(proposal_id)
    }

    /// Create a consensus fee-policy proposal.
    ///
    /// Fee policy changes participate in the same explicit vote/timelock lifecycle as other
    /// chain parameters, but use a distinct variant so the executor can atomically replace the
    /// dedicated system object when the proposal executes.
    pub fn create_fee_policy_proposal(
        &mut self,
        policy: FeePolicy,
        proposer: TaggedPubkey,
        current_height: BlockHeight,
    ) -> PokerL1Result<u64> {
        let voting_period = self.params.voting_period_blocks;
        let proposal_id = self.next_proposal_id;
        self.next_proposal_id = self
            .next_proposal_id
            .checked_add(1)
            .ok_or_else(|| PokerL1Error::Other("governance proposal id overflow".into()))?;
        let voting_end_height = current_height
            .checked_add(voting_period)
            .ok_or_else(|| PokerL1Error::Other("governance voting end height overflow".into()))?;
        self.proposals.insert(
            proposal_id,
            Proposal {
                id: proposal_id,
                kind: ProposalKind::FeePolicyChange { policy },
                proposer,
                submit_height: current_height,
                voting_end_height,
                yes_votes: vec![],
                no_votes: vec![],
                status: ProposalStatus::Voting,
                timelock_end_height: None,
            },
        );
        Ok(proposal_id)
    }

    /// Create a sensitive timelocked proposal that pins a native-precompile release version.
    pub fn create_precompile_upgrade_proposal(
        &mut self,
        precompile_id: ObjectID,
        new_version: u32,
        proposer: TaggedPubkey,
        current_height: BlockHeight,
    ) -> PokerL1Result<u64> {
        if new_version == 0 {
            return Err(PokerL1Error::Other(
                "precompile implementation version must be nonzero".into(),
            ));
        }
        if self.proposals.values().any(|proposal| {
            matches!(
                &proposal.kind,
                ProposalKind::PrecompileUpgrade { precompile_id: existing, .. }
                    if *existing == precompile_id
                        && matches!(proposal.status, ProposalStatus::Voting | ProposalStatus::Timelock)
            )
        }) {
            return Err(PokerL1Error::Other(
                "precompile already has an unresolved governance upgrade".into(),
            ));
        }
        self.insert_sensitive_timelocked_proposal(
            ProposalKind::PrecompileUpgrade {
                precompile_id,
                new_version,
            },
            proposer,
            current_height,
        )
    }

    /// Create a sensitive timelocked proposal that changes native-precompile enablement.
    pub fn create_precompile_status_proposal(
        &mut self,
        precompile_id: ObjectID,
        status: crate::vm::precompile::PrecompileStatus,
        proposer: TaggedPubkey,
        current_height: BlockHeight,
    ) -> PokerL1Result<u64> {
        self.insert_sensitive_timelocked_proposal(
            ProposalKind::PrecompileStatusChange {
                precompile_id,
                status,
            },
            proposer,
            current_height,
        )
    }

    fn insert_sensitive_timelocked_proposal(
        &mut self,
        kind: ProposalKind,
        proposer: TaggedPubkey,
        current_height: BlockHeight,
    ) -> PokerL1Result<u64> {
        let proposal_id = self.next_proposal_id;
        self.next_proposal_id = self
            .next_proposal_id
            .checked_add(1)
            .ok_or_else(|| PokerL1Error::Other("governance proposal id overflow".into()))?;
        let voting_end_height = current_height
            .checked_add(self.params.voting_period_blocks)
            .ok_or_else(|| PokerL1Error::Other("governance voting end height overflow".into()))?;
        self.proposals.insert(
            proposal_id,
            Proposal {
                id: proposal_id,
                kind,
                proposer,
                submit_height: current_height,
                voting_end_height,
                yes_votes: vec![],
                no_votes: vec![],
                status: ProposalStatus::Voting,
                timelock_end_height: None,
            },
        );
        Ok(proposal_id)
    }

    /// 创建 validator 集更新提案（SubTask 33.5）。
    ///
    /// 校验：
    /// 1. SEC-C2：新 validator 集大小 >= 5
    /// 2. SEC-M2：单次缩减比例 <= 20%
    ///
    /// # 参数
    /// - `current_set`：当前 validator 集（用于校验缩减比例）
    /// - `additions`：加入的 validator 列表
    /// - `removals`：踢出的 validator pubkey 列表
    /// - `effective_epoch`：生效 epoch
    /// - `proposer`：提案者
    /// - `current_height`：当前 block height
    pub fn create_validator_set_update_proposal(
        &mut self,
        current_set: &ValidatorSet,
        additions: Vec<ValidatorAddition>,
        removals: Vec<TaggedPubkey>,
        effective_epoch: Epoch,
        proposer: TaggedPubkey,
        current_height: BlockHeight,
    ) -> PokerL1Result<u64> {
        if effective_epoch <= current_set.epoch {
            return Err(PokerL1Error::Other(format!(
                "validator-set update effective_epoch {effective_epoch} must be after current epoch {}",
                current_set.epoch
            )));
        }
        let prev_size = current_set.validators.len();
        if additions.iter().any(|addition| addition.stake == 0)
            || additions.iter().any(|addition| {
                current_set.find_validator(&addition.pubkey).is_some()
                    || additions
                        .iter()
                        .filter(|other| other.pubkey == addition.pubkey)
                        .count()
                        != 1
            })
            || removals
                .iter()
                .any(|pubkey| current_set.find_validator(pubkey).is_none())
            || removals
                .iter()
                .any(|pubkey| removals.iter().filter(|other| *other == pubkey).count() != 1)
            || removals
                .iter()
                .any(|pubkey| additions.iter().any(|addition| &addition.pubkey == pubkey))
        {
            return Err(PokerL1Error::Other(
                "validator-set proposal contains duplicate, unknown, overlapping, or zero-stake entries".into(),
            ));
        }
        let new_size = prev_size
            .checked_add(additions.len())
            .and_then(|size| size.checked_sub(removals.len()))
            .ok_or_else(|| PokerL1Error::Other("validator-set size overflow".into()))?;

        // SEC-C2：新 validator 集大小 >= 5
        if new_size < 5 {
            return Err(PokerL1Error::ValidatorSetReductionTooSmall { new_size });
        }

        // SEC-M2：单次缩减比例 <= 20%
        if !removals.is_empty() {
            let max_removals = prev_size * 20 / 100; // 20%
            if removals.len() > max_removals.max(1) {
                return Err(PokerL1Error::SingleReductionRatioExceeded {
                    removed: removals.len(),
                    prev_size,
                });
            }
        }

        let voting_period = self.params.voting_period_blocks;
        let proposal_id = self.next_proposal_id;
        self.next_proposal_id += 1;

        let proposal = Proposal {
            id: proposal_id,
            kind: ProposalKind::ValidatorSetUpdate {
                additions,
                removals,
                effective_epoch,
            },
            proposer,
            submit_height: current_height,
            voting_end_height: current_height + voting_period,
            yes_votes: vec![],
            no_votes: vec![],
            status: ProposalStatus::Voting,
            timelock_end_height: None,
        };

        self.proposals.insert(proposal_id, proposal);
        Ok(proposal_id)
    }

    /// Apply every passed validator-set proposal scheduled for `target_epoch`.
    ///
    /// This method is called only from the node's certificate epoch-transition staging path.
    /// Removals enter the ordinary unbonding lifecycle rather than disappearing (which would
    /// silently destroy their escrow); additions enter Bonding and cannot sign immediately.
    pub fn apply_validator_set_updates_at_epoch(
        &mut self,
        set: &mut ValidatorSet,
        target_epoch: Epoch,
        current_height: BlockHeight,
    ) -> PokerL1Result<bool> {
        let proposal_ids: Vec<u64> = self
            .proposals
            .iter()
            .filter_map(|(&id, proposal)| match &proposal.kind {
                ProposalKind::ValidatorSetUpdate {
                    effective_epoch, ..
                } if proposal.status == ProposalStatus::Passed
                    && *effective_epoch == target_epoch =>
                {
                    Some(id)
                }
                _ => None,
            })
            .collect();
        if proposal_ids.is_empty() {
            return Ok(false);
        }
        let mut next = set.clone();
        for id in &proposal_ids {
            let ProposalKind::ValidatorSetUpdate {
                additions,
                removals,
                ..
            } = self.proposals[id].kind.clone()
            else {
                unreachable!("filtered validator-set proposal changed kind")
            };
            for pubkey in removals {
                let validator = next
                    .find_validator_mut(&pubkey)
                    .ok_or_else(|| PokerL1Error::ValidatorNotInSet(pubkey.clone()))?;
                if !validator.can_participate_consensus() {
                    return Err(PokerL1Error::Other(
                        "governance cannot remove a non-active validator".into(),
                    ));
                }
                validator.status = ValidatorStatus::Unbonding;
                validator.unbonding_until_height = current_height
                    .checked_add(self.params.unbonding_period_blocks)
                    .ok_or_else(|| PokerL1Error::Other("unbonding deadline overflow".into()))?;
            }
            for addition in additions {
                let bonding_until_height = current_height
                    .checked_add(self.params.bonding_period_blocks)
                    .ok_or_else(|| PokerL1Error::Other("bonding deadline overflow".into()))?;
                next.validators.push(ValidatorEntry::new(
                    addition.pubkey,
                    addition.vrf_pubkey,
                    addition.stake,
                    bonding_until_height,
                ));
            }
        }
        next.validator_set_hash = next.compute_hash();
        next.validate_persisted()?;
        *set = next;
        for id in proposal_ids {
            self.proposals
                .get_mut(&id)
                .expect("proposal was collected from map")
                .status = ProposalStatus::Executed;
        }
        Ok(true)
    }

    /// Return key-rotation proposals eligible for the current authenticated epoch boundary.
    ///
    /// The caller validates the transition certificate with the old set first, then applies these
    /// replacements atomically with the validator-set and key-history singleton writes.
    pub fn pending_key_rotations_at_height(
        &self,
        current_height: BlockHeight,
    ) -> Vec<(u64, TaggedPubkey, TaggedPubkey)> {
        self.proposals
            .iter()
            .filter_map(|(&proposal_id, proposal)| match &proposal.kind {
                ProposalKind::KeyRotation {
                    old_pubkey,
                    new_pubkey,
                    effective_height,
                } if proposal.status == ProposalStatus::Passed
                    && *effective_height <= current_height =>
                {
                    Some((proposal_id, old_pubkey.clone(), new_pubkey.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// Mark exactly the rotations already written into the key-history/validator-set snapshot.
    pub fn mark_key_rotations_executed(&mut self, proposal_ids: &[u64]) -> PokerL1Result<()> {
        for proposal_id in proposal_ids {
            let proposal = self.proposals.get_mut(proposal_id).ok_or_else(|| {
                PokerL1Error::Other(format!("unknown key-rotation proposal {proposal_id}"))
            })?;
            if !matches!(proposal.kind, ProposalKind::KeyRotation { .. })
                || proposal.status != ProposalStatus::Passed
            {
                return Err(PokerL1Error::Other(
                    "key-rotation proposal is not pending epoch-bound execution".into(),
                ));
            }
            proposal.status = ProposalStatus::Executed;
        }
        Ok(())
    }

    /// 创建密钥轮换提案（R5-L5 / SEC2-H4）。
    ///
    /// timelock = `key_rotation_delay_blocks`，期间旧密钥仍可用于 slashing 证据。
    pub fn create_key_rotation_proposal(
        &mut self,
        old_pubkey: TaggedPubkey,
        new_pubkey: TaggedPubkey,
        proposer: TaggedPubkey,
        current_height: BlockHeight,
    ) -> PokerL1Result<u64> {
        if old_pubkey == new_pubkey {
            return Err(PokerL1Error::Other(
                "validator key rotation requires a different public key".into(),
            ));
        }
        // Borsh can deserialize a manually constructed TaggedPubkey, so repeat the canonical
        // tag/version/length validation at this consensus boundary.
        TaggedPubkey::from_bytes(&new_pubkey.to_bytes())?;
        if self.proposals.values().any(|proposal| {
            matches!(
                &proposal.kind,
                ProposalKind::KeyRotation {
                    old_pubkey: existing_old,
                    new_pubkey: existing_new,
                    ..
                } if (existing_old == &old_pubkey || existing_new == &new_pubkey)
                    && matches!(proposal.status, ProposalStatus::Voting | ProposalStatus::Passed)
            )
        }) {
            return Err(PokerL1Error::Other(
                "validator key rotation conflicts with an unresolved proposal".into(),
            ));
        }
        let voting_period = self.params.voting_period_blocks;
        let proposal_id = self.next_proposal_id;
        self.next_proposal_id = self
            .next_proposal_id
            .checked_add(1)
            .ok_or_else(|| PokerL1Error::Other("governance proposal id overflow".into()))?;
        let effective_height = current_height
            .checked_add(voting_period)
            .and_then(|height| height.checked_add(self.params.key_rotation_delay_blocks))
            .ok_or_else(|| PokerL1Error::Other("validator key rotation height overflow".into()))?;

        let proposal = Proposal {
            id: proposal_id,
            kind: ProposalKind::KeyRotation {
                old_pubkey,
                new_pubkey,
                effective_height,
            },
            proposer,
            submit_height: current_height,
            voting_end_height: current_height + voting_period,
            yes_votes: vec![],
            no_votes: vec![],
            status: ProposalStatus::Voting,
            timelock_end_height: None,
        };

        self.proposals.insert(proposal_id, proposal);
        Ok(proposal_id)
    }

    /// 创建 timelock 撤销提案（SEC-H8）。
    ///
    /// 撤销提案无 timelock，通过后立即生效。
    pub fn create_revocation_proposal(
        &mut self,
        original_proposal_id: u64,
        proposer: TaggedPubkey,
        current_height: BlockHeight,
    ) -> PokerL1Result<u64> {
        // 校验原提案存在且在 timelock 期
        let original = self.proposals.get(&original_proposal_id).ok_or_else(|| {
            PokerL1Error::Other(format!(
                "original proposal {original_proposal_id} not found"
            ))
        })?;
        if original.status != ProposalStatus::Timelock {
            return Err(PokerL1Error::ProposalNotInTimelock(original.status));
        }

        let voting_period = self.params.voting_period_blocks;
        let proposal_id = self.next_proposal_id;
        self.next_proposal_id += 1;

        let proposal = Proposal {
            id: proposal_id,
            kind: ProposalKind::TimelockRevocation {
                original_proposal_id,
            },
            proposer,
            submit_height: current_height,
            voting_end_height: current_height + voting_period,
            yes_votes: vec![],
            no_votes: vec![],
            status: ProposalStatus::Voting,
            timelock_end_height: None,
        };

        self.proposals.insert(proposal_id, proposal);
        Ok(proposal_id)
    }

    /// 投票（赞成或反对）。
    ///
    /// # 参数
    /// - `proposal_id`：提案 ID
    /// - `voter`：投票 validator pubkey
    /// - `approve`：true=赞成，false=反对
    /// - `current_height`：当前 block height
    pub fn vote(
        &mut self,
        proposal_id: u64,
        voter: TaggedPubkey,
        approve: bool,
        current_height: BlockHeight,
    ) -> PokerL1Result<()> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or_else(|| PokerL1Error::Other(format!("proposal {proposal_id} not found")))?;

        // 校验投票期
        if proposal.status != ProposalStatus::Voting {
            return Err(PokerL1Error::ProposalNotInVoting(proposal.status));
        }
        if current_height > proposal.voting_end_height {
            return Err(PokerL1Error::ProposalNotInVoting(proposal.status));
        }

        // 校验未重复投票
        if proposal.has_voted(&voter) {
            return Err(PokerL1Error::DuplicateVote(voter));
        }

        if approve {
            proposal.yes_votes.push(voter);
        } else {
            proposal.no_votes.push(voter);
        }
        Ok(())
    }

    /// 结束投票期，判定提案是否通过（SubTask 33.2 + SEC2-M6）。
    ///
    /// # 判定逻辑
    /// 1. quorum 分母 = validator_count（含离线）
    /// 2. 参与率下限：普通 2/3，敏感 90%
    /// 3. 赞成票下限：普通 2/3，敏感 90%
    /// 4. 撤销提案：90% quorum（SEC-H8）
    /// 5. validator 集更新 / 密钥轮换：通过后直接 Passed（无 timelock）
    /// 6. 参数调整：通过后进入 Timelock（parameter_delay_blocks）
    /// 7. 撤销提案：通过后立即撤销原提案（无 timelock）
    ///
    /// # 参数
    /// - `proposal_id`：提案 ID
    /// - `validator_count`：当前 epoch validator 集大小（含离线）
    /// - `current_height`：当前 block height
    pub fn finalize_voting(
        &mut self,
        proposal_id: u64,
        validator_count: usize,
        current_height: BlockHeight,
    ) -> PokerL1Result<ProposalStatus> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or_else(|| PokerL1Error::Other(format!("proposal {proposal_id} not found")))?;

        // 校验投票期已结束
        if proposal.status != ProposalStatus::Voting {
            return Err(PokerL1Error::ProposalNotInVoting(proposal.status));
        }
        if current_height < proposal.voting_end_height {
            return Err(PokerL1Error::ProposalNotInVoting(proposal.status));
        }

        // 判断是否为敏感提案
        let is_sensitive = match &proposal.kind {
            ProposalKind::ParameterChange { param, .. } => param.is_sensitive(),
            ProposalKind::FeePolicyChange { .. } => true,
            ProposalKind::PrecompileUpgrade { .. }
            | ProposalKind::PrecompileStatusChange { .. } => true,
            ProposalKind::ValidatorSetUpdate { .. } => true, // validator 集更新始终 90%
            ProposalKind::KeyRotation { .. } => true,        // 密钥轮换始终 90%
            ProposalKind::TimelockRevocation { .. } => true, // 撤销提案 90%（SEC-H8）
        };

        // SEC2-M6：参与率下限
        let required_participation = required_participation(is_sensitive, validator_count);
        if proposal.total_votes() < required_participation {
            proposal.status = ProposalStatus::Rejected;
            return Ok(ProposalStatus::Rejected);
        }

        // 赞成票下限
        let required_yes = if is_sensitive {
            required_yes_votes_sensitive(validator_count)
        } else {
            required_yes_votes_normal(validator_count)
        };
        if proposal.yes_votes.len() < required_yes {
            proposal.status = ProposalStatus::Rejected;
            return Ok(ProposalStatus::Rejected);
        }

        // 通过：根据提案类型决定后续状态
        match &proposal.kind {
            ProposalKind::ParameterChange { .. }
            | ProposalKind::FeePolicyChange { .. }
            | ProposalKind::PrecompileUpgrade { .. }
            | ProposalKind::PrecompileStatusChange { .. } => {
                // 参数调整：进入 timelock
                let timelock_end = current_height + self.params.parameter_delay_blocks;
                proposal.timelock_end_height = Some(timelock_end);
                proposal.status = ProposalStatus::Timelock;
                Ok(ProposalStatus::Timelock)
            }
            ProposalKind::ValidatorSetUpdate { .. } | ProposalKind::KeyRotation { .. } => {
                // validator 集更新 / 密钥轮换：直接 Passed（epoch 边界生效）
                proposal.status = ProposalStatus::Passed;
                Ok(ProposalStatus::Passed)
            }
            ProposalKind::TimelockRevocation {
                original_proposal_id,
            } => {
                // 撤销提案：立即撤销原提案（无 timelock）
                let orig_id = *original_proposal_id;
                proposal.status = ProposalStatus::Passed;
                // 撤销原提案
                if let Some(orig) = self.proposals.get_mut(&orig_id) {
                    orig.status = ProposalStatus::Revoked;
                }
                Ok(ProposalStatus::Passed)
            }
        }
    }

    /// 执行已通过 timelock 的提案（SubTask 33.2）。
    ///
    /// # 参数调整提案
    /// - timelock 结束后可执行
    /// - 执行后参数生效
    ///
    /// # validator 集更新 / 密钥轮换
    /// - Passed 状态即可执行（epoch 边界 / timelock 结束）
    pub fn execute_proposal(
        &mut self,
        proposal_id: u64,
        current_height: BlockHeight,
    ) -> PokerL1Result<()> {
        // 先提取提案信息（避免持有可变 borrow 时调用 self 方法）
        let (status, kind) = {
            let proposal = self
                .proposals
                .get(&proposal_id)
                .ok_or_else(|| PokerL1Error::Other(format!("proposal {proposal_id} not found")))?;
            (proposal.status, proposal.kind.clone())
        };

        // 校验状态
        match status {
            ProposalStatus::Timelock => {
                // 校验 timelock 已结束
                if let Some(end) = self.proposals[&proposal_id].timelock_end_height
                    && current_height < end
                {
                    return Err(PokerL1Error::Other(format!(
                        "timelock not expired: remaining={}",
                        end - current_height
                    )));
                }
            }
            ProposalStatus::Passed => {
                // validator 集更新 / 密钥轮换 / 撤销提案：直接执行
            }
            ProposalStatus::Voting
            | ProposalStatus::Rejected
            | ProposalStatus::Executed
            | ProposalStatus::Revoked => {
                return Err(PokerL1Error::ProposalNotInTimelock(status));
            }
        }

        // 执行参数调整（已释放 borrow，可安全调用 self 方法）
        match kind {
            ProposalKind::ParameterChange {
                param,
                new_value,
                target_chain_id,
            } => {
                if param == ParamName::VerifierStatus {
                    // SEC-M4：verifier_status per-chain_id
                    let verifier_status = if new_value == 1 {
                        VerifierStatus::Production
                    } else {
                        VerifierStatus::Stub
                    };
                    self.set_verifier_status(target_chain_id, verifier_status);
                } else {
                    self.params.set(param, new_value);
                }
            }
            ProposalKind::FeePolicyChange { .. } => {
                // The executor replaces FeePolicy in the same ObjectDb transaction after this
                // governance singleton transition has passed all lifecycle checks.
            }
            ProposalKind::PrecompileUpgrade { .. }
            | ProposalKind::PrecompileStatusChange { .. } => {
                // The executor updates the dedicated precompile-governance singleton in the
                // same transaction after this proposal's lifecycle transition is committed.
            }
            ProposalKind::ValidatorSetUpdate { .. } => {
                return Err(PokerL1Error::Other(
                    "validator-set updates execute only at their declared epoch boundary".into(),
                ));
            }
            ProposalKind::KeyRotation { .. } => {
                return Err(PokerL1Error::Other(
                    "validator key rotations execute only at an authenticated epoch boundary"
                        .into(),
                ));
            }
            ProposalKind::TimelockRevocation { .. } => {
                // 原提案已在 finalize_voting 中被撤销，此处仅标记撤销提案已执行
            }
        }

        // 标记提案已执行
        self.proposals
            .get_mut(&proposal_id)
            .expect("proposal exists")
            .status = ProposalStatus::Executed;
        Ok(())
    }

    /// Execute a proposal and publish the resulting verifier statuses to the runtime registry.
    ///
    /// Governance executors should use this boundary whenever a node has ZK verification enabled,
    /// so the serializable consensus state and the shared runtime verifier control plane cannot
    /// silently diverge after a `VerifierStatus` proposal.
    pub(crate) fn execute_proposal_and_sync_verifier_registry(
        &mut self,
        proposal_id: u64,
        current_height: BlockHeight,
        registry: &crate::offline::zk_verifier::ZkVerifierRegistry,
    ) -> PokerL1Result<()> {
        self.execute_proposal(proposal_id, current_height)?;
        registry.synchronize_governance_statuses(self);
        Ok(())
    }

    /// 检查 timelock 内是否有撤销提案（SEC-H8）。
    ///
    /// 返回 true 表示原提案已被撤销，不可执行。
    #[must_use]
    pub fn is_proposal_revoked(&self, proposal_id: u64) -> bool {
        self.proposals
            .get(&proposal_id)
            .is_some_and(|p| p.status == ProposalStatus::Revoked)
    }

    /// 检测投票期 DDoS（SEC2-M6：离线率 > 30%）。
    ///
    /// 返回 true 表示应延长投票期。
    ///
    /// # 参数
    /// - `proposal_id`：提案 ID
    /// - `validator_count`：当前 epoch validator 集大小
    #[must_use]
    pub fn detect_voting_ddos(&self, proposal_id: u64, validator_count: usize) -> bool {
        let Some(proposal) = self.proposals.get(&proposal_id) else {
            return false;
        };
        if proposal.status != ProposalStatus::Voting {
            return false;
        }
        let participation = proposal.total_votes();
        let offline = validator_count.saturating_sub(participation);
        validator_count > 0 && offline * 100 / validator_count > 30
    }
}

impl Default for GovernanceState {
    fn default() -> Self {
        Self::new()
    }
}

/// Wire representation of the governance singleton, including its chain namespace.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct PersistedGovernanceState {
    chain_id: ChainId,
    state: GovernanceState,
}

/// Return true when an object claims the reserved governance singleton identity or type.
#[must_use]
pub fn is_governance_state_object(object: &Object) -> bool {
    object.id == GOVERNANCE_STATE_OBJECT_ID || object.object_type == GOVERNANCE_STATE_OBJECT_TYPE
}

/// Encode canonical governance state as an immutable, system-replaceable object.
pub fn governance_state_object(
    chain_id: ChainId,
    state: &GovernanceState,
    version: u64,
) -> PokerL1Result<Object> {
    let mut object = Object::new(
        GOVERNANCE_STATE_OBJECT_ID,
        Ownership::Immutable,
        GOVERNANCE_STATE_OBJECT_TYPE,
        borsh::to_vec(&PersistedGovernanceState {
            chain_id,
            state: state.clone(),
        })?,
        None,
    );
    object.version = version;
    Ok(object)
}

/// Validate the singleton's shape and decode its chain namespace and state.
pub fn validate_governance_state_object(
    object: &Object,
) -> PokerL1Result<(ChainId, GovernanceState)> {
    if object.id != GOVERNANCE_STATE_OBJECT_ID
        || object.object_type != GOVERNANCE_STATE_OBJECT_TYPE
        || object.owner != Ownership::Immutable
        || object.assigned_validator.is_some()
    {
        return Err(PokerL1Error::Other(
            "invalid GovernanceState singleton identity, type or ownership".into(),
        ));
    }
    let persisted: PersistedGovernanceState = borsh::from_slice(&object.data)
        .map_err(|error| PokerL1Error::Serialization(format!("decode GovernanceState: {error}")))?;
    if persisted.state.next_proposal_id == 0 {
        return Err(PokerL1Error::Other(
            "GovernanceState next_proposal_id must be non-zero".into(),
        ));
    }
    Ok((persisted.chain_id, persisted.state))
}

/// Decode the canonical governance state and bind it to the expected chain namespace.
pub fn decode_governance_state_object(
    object: &Object,
    expected_chain_id: ChainId,
) -> PokerL1Result<GovernanceState> {
    let (chain_id, state) = validate_governance_state_object(object)?;
    if chain_id != expected_chain_id {
        return Err(PokerL1Error::Other(format!(
            "persisted GovernanceState chain_id {chain_id} does not match configured chain_id {expected_chain_id}"
        )));
    }
    Ok(state)
}

/// Replace governance state in an isolated execution backend after checking the expected base.
pub fn replace_persisted_governance_state<B: ObjectBackend>(
    object_db: &mut B,
    chain_id: ChainId,
    current: &GovernanceState,
    next: &GovernanceState,
) -> PokerL1Result<()> {
    let existing = object_db.read(&GOVERNANCE_STATE_OBJECT_ID)?;
    let persisted = decode_governance_state_object(&existing, chain_id)?;
    if &persisted != current {
        return Err(PokerL1Error::Other(
            "GovernanceState system transaction observed a stale authoritative state".into(),
        ));
    }
    let next_version = existing
        .version
        .checked_add(1)
        .ok_or_else(|| PokerL1Error::Other("GovernanceState object version overflow".into()))?;
    object_db.replace_system_object(governance_state_object(chain_id, next, next_version)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{CURRENT_VERSION, SignatureScheme};

    fn make_pubkey(byte: u8) -> TaggedPubkey {
        let mut raw = vec![byte];
        raw.extend_from_slice(&[0x02u8; 32]);
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw).unwrap()
    }

    fn make_pubkeys(count: usize) -> Vec<TaggedPubkey> {
        (0..count).map(|i| make_pubkey(0x10 + i as u8)).collect()
    }

    #[test]
    fn governance_state_system_object_roundtrip_is_chain_bound() {
        let state = GovernanceState::new();
        let object = governance_state_object(crate::DEFAULT_CHAIN_ID, &state, 7).unwrap();
        assert_eq!(object.id, GOVERNANCE_STATE_OBJECT_ID);
        assert_eq!(object.version, 7);
        assert_eq!(
            decode_governance_state_object(&object, crate::DEFAULT_CHAIN_ID).unwrap(),
            state
        );
        assert!(decode_governance_state_object(&object, crate::DEFAULT_CHAIN_ID + 1).is_err());
    }

    // ===== ParamName 测试 =====

    #[test]
    fn test_param_name_as_str() {
        assert_eq!(ParamName::TurnTimeoutBlocks.as_str(), "turn_timeout_blocks");
        assert_eq!(ParamName::VerifierStatus.as_str(), "verifier_status");
        assert_eq!(ParamName::ValidatorSetSize.as_str(), "validator_set_size");
    }

    #[test]
    fn test_is_sensitive_param_r3_h1() {
        // R3-H1：8 项敏感参数
        assert!(ParamName::BlockGasLimit.is_sensitive());
        assert!(ParamName::EpochLengthBlocks.is_sensitive());
        assert!(ParamName::SlashPercentage.is_sensitive());
        assert!(ParamName::DowntimeSlashPercentage.is_sensitive());
        assert!(ParamName::VerifierStatus.is_sensitive());
        assert!(ParamName::ParameterDelayBlocks.is_sensitive());
        assert!(ParamName::DefenseWindowBlocks.is_sensitive());
    }

    #[test]
    fn test_is_sensitive_param_sec_h4() {
        // SEC-H4：补全 9 项
        assert!(ParamName::BondingPeriodBlocks.is_sensitive());
        assert!(ParamName::UnbondingPeriodBlocks.is_sensitive());
        assert!(ParamName::KeyRotationDelayBlocks.is_sensitive());
        assert!(ParamName::CheckpointMultiReplicaCount.is_sensitive());
        assert!(ParamName::ArchiveRetentionBlocks.is_sensitive());
        assert!(ParamName::MaxSkipSegments.is_sensitive());
        assert!(ParamName::TurnTimeoutBlocks.is_sensitive());
        assert!(ParamName::MaliciousRefuseThreshold.is_sensitive());
        assert!(ParamName::MaxRequestAckPerTurnTimeout.is_sensitive());
    }

    #[test]
    fn test_is_sensitive_param_sec_c2() {
        // SEC-C2：validator_set_size
        assert!(ParamName::ValidatorSetSize.is_sensitive());
    }

    #[test]
    fn test_is_sensitive_param_production_switch_height() {
        // v1.2 SubTask 11.5.2.10：production_switch_height 敏感 90% quorum
        assert!(ParamName::ProductionSwitchHeight.is_sensitive());
    }

    #[test]
    fn test_production_switch_height_default_zero() {
        let params = GovernanceParams::default_values();
        assert_eq!(params.production_switch_height, 0, "默认值应为 0（未切换）");
        assert_eq!(
            params.get(ParamName::ProductionSwitchHeight),
            0,
            "get() 应返回 0"
        );
    }

    #[test]
    fn test_production_switch_height_one_time_write() {
        let mut params = GovernanceParams::default_values();
        // 一次性写入：设置非 0 值
        params.set(ParamName::ProductionSwitchHeight, 1000);
        assert_eq!(params.production_switch_height, 1000);
        assert_eq!(params.get(ParamName::ProductionSwitchHeight), 1000);
        // grace 期结束后可清零
        params.set(ParamName::ProductionSwitchHeight, 0);
        assert_eq!(params.production_switch_height, 0);
    }

    #[test]
    fn test_production_grace_blocks_constant() {
        assert_eq!(PRODUCTION_GRACE_BLOCKS, 7200);
    }

    // ===== Phase 11.5 新增参数测试 =====

    #[test]
    fn test_new_sensitive_params_zkvm_limits() {
        // Phase 11.5：6 项 ZKVM 限制参数标记为敏感
        assert!(ParamName::MaxZkvmTraceSteps.is_sensitive());
        assert!(ParamName::MaxZkvmMemory.is_sensitive());
        assert!(ParamName::MaxZkvmProofSize.is_sensitive());
        assert!(ParamName::ZkvmBatchSize.is_sensitive());
        assert!(ParamName::MaxRecursionDepth.is_sensitive());
        assert!(ParamName::MaxTraceHostMemory.is_sensitive());
    }

    #[test]
    fn test_new_sensitive_params_gas_and_grace() {
        // Phase 11.5：gas_stwo_verify / production_grace_blocks 敏感
        assert!(ParamName::GasStwoVerify.is_sensitive());
        assert!(ParamName::ProductionGraceBlocks.is_sensitive());
    }

    #[test]
    fn test_new_sensitive_params_proof_field_limits() {
        // Phase 11.5 v1.3 M2-002：5 项 Proof 字段长度参数敏感
        assert!(ParamName::MaxPublicIoSize.is_sensitive());
        assert!(ParamName::MaxFoldedInstanceSize.is_sensitive());
        assert!(ParamName::MaxSumcheckProofSize.is_sensitive());
        assert!(ParamName::MaxPcsOpeningSize.is_sensitive());
        assert!(ParamName::MaxEventHashesCount.is_sensitive());
    }

    #[test]
    fn test_new_params_default_values() {
        let params = GovernanceParams::default_values();
        assert_eq!(params.max_zkvm_trace_steps, DEFAULT_MAX_ZKVM_TRACE_STEPS);
        assert_eq!(params.max_zkvm_memory, DEFAULT_MAX_ZKVM_MEMORY);
        assert_eq!(params.max_zkvm_proof_size, DEFAULT_MAX_ZKVM_PROOF_SIZE);
        assert_eq!(params.zkvm_batch_size, DEFAULT_ZKVM_BATCH_SIZE);
        assert_eq!(params.max_recursion_depth, DEFAULT_MAX_RECURSION_DEPTH);
        assert_eq!(params.max_trace_host_memory, DEFAULT_MAX_TRACE_HOST_MEMORY);
        assert_eq!(params.production_grace_blocks, PRODUCTION_GRACE_BLOCKS);
        assert_eq!(params.gas_stwo_verify, DEFAULT_GAS_STWO_VERIFY);
        assert_eq!(params.max_public_io_size, DEFAULT_MAX_PUBLIC_IO_SIZE);
        assert_eq!(
            params.max_folded_instance_size,
            DEFAULT_MAX_FOLDED_INSTANCE_SIZE
        );
        assert_eq!(
            params.max_sumcheck_proof_size,
            DEFAULT_MAX_SUMCHECK_PROOF_SIZE
        );
        assert_eq!(params.max_pcs_opening_size, DEFAULT_MAX_PCS_OPENING_SIZE);
        assert_eq!(
            params.max_event_hashes_count,
            DEFAULT_MAX_EVENT_HASHES_COUNT
        );
    }

    #[test]
    fn test_new_params_get_set() {
        let mut params = GovernanceParams::default_values();
        // 验证 get() 返回默认值
        assert_eq!(
            params.get(ParamName::MaxZkvmTraceSteps),
            DEFAULT_MAX_ZKVM_TRACE_STEPS
        );
        assert_eq!(
            params.get(ParamName::GasStwoVerify),
            DEFAULT_GAS_STWO_VERIFY
        );
        // set() 后 get() 返回新值
        params.set(ParamName::MaxZkvmMemory, 32 * 1024 * 1024);
        assert_eq!(params.get(ParamName::MaxZkvmMemory), 32 * 1024 * 1024);
        params.set(ParamName::MaxRecursionDepth, 20);
        assert_eq!(params.get(ParamName::MaxRecursionDepth), 20);
        params.set(ParamName::MaxEventHashesCount, 512);
        assert_eq!(params.get(ParamName::MaxEventHashesCount), 512);
    }

    #[test]
    fn test_validate_new_params_in_bounds() {
        let params = GovernanceParams::default_values();
        // 边界内值通过（MaxZkvmTraceSteps 须同时满足一致性约束：ceil(N/1024) ≤ 1000 → N ≤ 1_024_000）
        assert!(validate_param(&params, ParamName::MaxZkvmTraceSteps, 1_024_000).is_ok());
        assert!(validate_param(&params, ParamName::MaxZkvmTraceSteps, 65_536).is_ok());
        assert!(validate_param(&params, ParamName::MaxZkvmMemory, 16 * 1024 * 1024).is_ok());
        assert!(validate_param(&params, ParamName::MaxZkvmProofSize, 64 * 1024).is_ok());
        assert!(validate_param(&params, ParamName::ZkvmBatchSize, 1024).is_ok());
        assert!(validate_param(&params, ParamName::MaxRecursionDepth, 16).is_ok());
        assert!(validate_param(&params, ParamName::MaxTraceHostMemory, 512 * 1024 * 1024).is_ok());
        assert!(validate_param(&params, ParamName::ProductionGraceBlocks, 7200).is_ok());
        assert!(validate_param(&params, ParamName::GasStwoVerify, 300_000).is_ok());
        assert!(validate_param(&params, ParamName::MaxPublicIoSize, 8 * 1024).is_ok());
        assert!(validate_param(&params, ParamName::MaxFoldedInstanceSize, 8 * 1024).is_ok());
        assert!(validate_param(&params, ParamName::MaxSumcheckProofSize, 16 * 1024).is_ok());
        assert!(validate_param(&params, ParamName::MaxPcsOpeningSize, 8 * 1024).is_ok());
        assert!(validate_param(&params, ParamName::MaxEventHashesCount, 256).is_ok());
    }

    #[test]
    fn test_validate_new_params_out_of_bounds() {
        let params = GovernanceParams::default_values();
        // 越界值被拒
        assert!(validate_param(&params, ParamName::MaxZkvmTraceSteps, 65_535).is_err());
        assert!(validate_param(&params, ParamName::MaxZkvmTraceSteps, 16_777_217).is_err());
        assert!(validate_param(&params, ParamName::MaxZkvmMemory, 3 * 1024 * 1024).is_err());
        assert!(validate_param(&params, ParamName::MaxZkvmProofSize, 15 * 1024).is_err());
        assert!(validate_param(&params, ParamName::ZkvmBatchSize, 63).is_err());
        assert!(validate_param(&params, ParamName::ZkvmBatchSize, 8193).is_err());
        assert!(validate_param(&params, ParamName::MaxRecursionDepth, 3).is_err());
        assert!(validate_param(&params, ParamName::MaxRecursionDepth, 33).is_err());
        assert!(validate_param(&params, ParamName::ProductionGraceBlocks, 719).is_err());
        assert!(validate_param(&params, ParamName::GasStwoVerify, 99_999).is_err());
        assert!(validate_param(&params, ParamName::MaxPublicIoSize, 3 * 1024).is_err());
        assert!(validate_param(&params, ParamName::MaxSumcheckProofSize, 7 * 1024).is_err());
        assert!(validate_param(&params, ParamName::MaxEventHashesCount, 31).is_err());
        assert!(validate_param(&params, ParamName::MaxEventHashesCount, 1025).is_err());
    }

    #[test]
    fn test_zkvm_batch_size_consistency_constraint() {
        // Phase 11.5 SubTask 11.5.2.4：ceil(max_zkvm_trace_steps / zkvm_batch_size) ≤ MAX_FOLD_STEP_COUNT (1000)
        let mut params = GovernanceParams::default_values();
        // 默认配置：ceil(1_024_000 / 1024) = 1000 ≤ 1000 → 通过
        assert!(validate_param(&params, ParamName::ZkvmBatchSize, 1024).is_ok());
        // batch_size=512 → ceil(1_024_000 / 512) = 2000 > 1000 → 失败
        assert!(validate_param(&params, ParamName::ZkvmBatchSize, 512).is_err());
        // 调整 max_zkvm_trace_steps=512_000 后 batch_size=512 → ceil(512_000/512) = 1000 ≤ 1000 → 通过
        params.max_zkvm_trace_steps = 512_000;
        assert!(validate_param(&params, ParamName::ZkvmBatchSize, 512).is_ok());
        // 反向校验：MaxZkvmTraceSteps 调整后也须满足约束
        // batch_size=1024, max_zkvm_trace_steps=1_024_001 → ceil(1_024_001/1024) = 1001 > 1000 → 失败
        params.zkvm_batch_size = 1024;
        assert!(validate_param(&params, ParamName::MaxZkvmTraceSteps, 1_024_001).is_err());
        // batch_size=1024, max_zkvm_trace_steps=1_024_000 → ceil(1_024_000/1024) = 1000 ≤ 1000 → 通过
        assert!(validate_param(&params, ParamName::MaxZkvmTraceSteps, 1_024_000).is_ok());
    }

    #[test]
    fn test_production_grace_blocks_default_matches_constant() {
        // Phase 11.5：production_grace_blocks 字段默认值 = PRODUCTION_GRACE_BLOCKS 常量
        let params = GovernanceParams::default_values();
        assert_eq!(params.production_grace_blocks, PRODUCTION_GRACE_BLOCKS);
        assert_eq!(
            params.get(ParamName::ProductionGraceBlocks),
            PRODUCTION_GRACE_BLOCKS
        );
    }

    #[test]
    fn test_non_sensitive_params() {
        // TurnTimeoutBlocks 是敏感参数（SEC-H4），不在此测试中
        assert!(!ParamName::AckDeadlineBlocks.is_sensitive());
        assert!(!ParamName::MaxActiveGamesPerPlayer.is_sensitive());
        assert!(!ParamName::ArchiveNodeMinCount.is_sensitive());
        assert!(!ParamName::CheckpointIntervalBlocks.is_sensitive());
        assert!(!ParamName::RecoveryWindowBlocks.is_sensitive());
        assert!(!ParamName::DaWindowBlocks.is_sensitive());
        assert!(!ParamName::DisputeWindowBlocks.is_sensitive());
        assert!(!ParamName::HandMaxDurationBlocks.is_sensitive());
        assert!(!ParamName::GameValidatorTimeoutBlocks.is_sensitive());
        assert!(!ParamName::MaxIntervalMs.is_sensitive());
        assert!(!ParamName::TxPruneAfterBlocks.is_sensitive());
        assert!(!ParamName::VertexPruneAfterBlocks.is_sensitive());
        assert!(!ParamName::DelegatedEscapeMaxExpiryBlocks.is_sensitive());
        assert!(!ParamName::EpochTransitionWindowBlocks.is_sensitive());
        assert!(!ParamName::DowntimeThresholdBlocks.is_sensitive());
        assert!(!ParamName::VotingPeriodBlocks.is_sensitive());
        assert!(!ParamName::MaxDesignatedOperatorCheckExemptions.is_sensitive());
        assert!(!ParamName::UnderInvestigationThreshold.is_sensitive());
        assert!(!ParamName::MaxClockDriftMs.is_sensitive());
        assert!(!ParamName::ForfeitDepositRatio.is_sensitive());
        assert!(!ParamName::ChallengeDepositRatio.is_sensitive());
        assert!(!ParamName::ChallengeRewardRatio.is_sensitive());
        assert!(!ParamName::DesignatedOperatorBondAmount.is_sensitive());
        assert!(!ParamName::MaxPartialCheckinCount.is_sensitive());
    }

    // ===== GovernanceParams 测试 =====

    #[test]
    fn test_default_params() {
        let params = GovernanceParams::default_values();
        assert_eq!(params.turn_timeout_blocks, DEFAULT_TURN_TIMEOUT_BLOCKS);
        assert_eq!(
            params.parameter_delay_blocks,
            DEFAULT_PARAMETER_DELAY_BLOCKS
        );
        assert_eq!(params.epoch_length_blocks, DEFAULT_EPOCH_LENGTH_BLOCKS);
        assert_eq!(params.validator_set_size, DEFAULT_VALIDATOR_SET_SIZE);
        assert_eq!(
            params.max_partial_checkin_count,
            DEFAULT_MAX_PARTIAL_CHECKIN_COUNT
        );
    }

    #[test]
    fn test_params_get_set() {
        let mut params = GovernanceParams::default_values();
        assert_eq!(
            params.get(ParamName::TurnTimeoutBlocks),
            DEFAULT_TURN_TIMEOUT_BLOCKS
        );
        params.set(ParamName::TurnTimeoutBlocks, 100);
        assert_eq!(params.get(ParamName::TurnTimeoutBlocks), 100);
    }

    // ===== validate_param 测试 =====

    #[test]
    fn test_validate_param_in_bounds() {
        let params = GovernanceParams::default_values();
        assert!(validate_param(&params, ParamName::TurnTimeoutBlocks, 30).is_ok());
        assert!(validate_param(&params, ParamName::TurnTimeoutBlocks, 3).is_ok());
        assert!(validate_param(&params, ParamName::TurnTimeoutBlocks, 1000).is_ok());
    }

    #[test]
    fn test_validate_param_out_of_bounds() {
        let params = GovernanceParams::default_values();
        assert!(validate_param(&params, ParamName::TurnTimeoutBlocks, 2).is_err());
        assert!(validate_param(&params, ParamName::TurnTimeoutBlocks, 1001).is_err());
        assert!(validate_param(&params, ParamName::SlashPercentage, 0).is_err());
        assert!(validate_param(&params, ParamName::SlashPercentage, 101).is_err());
        assert!(validate_param(&params, ParamName::ValidatorSetSize, 4).is_err());
        assert!(validate_param(&params, ParamName::ValidatorSetSize, 1001).is_err());
    }

    #[test]
    fn test_validate_param_dependency() {
        // game_validator_timeout_blocks ∈ [1, floor(turn_timeout_blocks / 2)]
        let mut params = GovernanceParams::default_values();
        params.turn_timeout_blocks = 30;
        assert!(validate_param(&params, ParamName::GameValidatorTimeoutBlocks, 15).is_ok());
        assert!(validate_param(&params, ParamName::GameValidatorTimeoutBlocks, 16).is_err());

        // 修改 turn_timeout_blocks 后边界变化
        params.turn_timeout_blocks = 100;
        assert!(validate_param(&params, ParamName::GameValidatorTimeoutBlocks, 50).is_ok());
        assert!(validate_param(&params, ParamName::GameValidatorTimeoutBlocks, 51).is_err());
    }

    #[test]
    fn test_validate_param_bonding_period() {
        // bonding_period_blocks ∈ [epoch_length_blocks, 10*epoch_length_blocks]
        let mut params = GovernanceParams::default_values();
        params.epoch_length_blocks = 1000;
        assert!(validate_param(&params, ParamName::BondingPeriodBlocks, 1000).is_ok());
        assert!(validate_param(&params, ParamName::BondingPeriodBlocks, 10_000).is_ok());
        assert!(validate_param(&params, ParamName::BondingPeriodBlocks, 999).is_err());
        assert!(validate_param(&params, ParamName::BondingPeriodBlocks, 10_001).is_err());
    }

    // ===== Quorum 计算测试 =====

    #[test]
    fn test_required_yes_votes_normal() {
        // 严格 >2/3（C-3 修复）
        assert_eq!(required_yes_votes_normal(3), 3); // 2*3/3+1 = 3
        assert_eq!(required_yes_votes_normal(5), 4); // 2*5/3+1 = 4
        assert_eq!(required_yes_votes_normal(10), 7); // 2*10/3+1 = 7
        assert_eq!(required_yes_votes_normal(0), 0);
    }

    #[test]
    fn test_required_yes_votes_sensitive() {
        // 90% quorum，向上取整
        assert_eq!(required_yes_votes_sensitive(5), 5); // ceil(5*0.9) = 5
        assert_eq!(required_yes_votes_sensitive(10), 9); // ceil(10*0.9) = 9
        assert_eq!(required_yes_votes_sensitive(100), 90);
        assert_eq!(required_yes_votes_sensitive(0), 0);
    }

    #[test]
    fn test_required_participation() {
        assert_eq!(required_participation(false, 10), 7); // 普通 2/3
        assert_eq!(required_participation(true, 10), 9); // 敏感 90%
    }

    #[test]
    fn test_required_revocation_votes() {
        // SEC-H8：撤销 90%
        assert_eq!(required_revocation_votes(10), 9);
    }

    // ===== GovernanceState 测试 =====

    #[test]
    fn test_governance_state_new() {
        let state = GovernanceState::new();
        assert_eq!(
            state.verifier_status(crate::DEFAULT_CHAIN_ID),
            VerifierStatus::Stub
        );
        assert_eq!(state.next_proposal_id, 1);
        assert!(state.proposals.is_empty());
    }

    #[test]
    fn test_verifier_status_per_chain_id() {
        let mut state = GovernanceState::new();
        // 默认 mainnet = Stub
        assert_eq!(
            state.verifier_status(crate::DEFAULT_CHAIN_ID),
            VerifierStatus::Stub
        );
        // testnet 初始也 = Stub
        assert_eq!(state.verifier_status(0x1234), VerifierStatus::Stub);
        // 设置 testnet = Production
        state.set_verifier_status(0x1234, VerifierStatus::Production);
        assert_eq!(state.verifier_status(0x1234), VerifierStatus::Production);
        // mainnet 不受影响（SEC-M4 命名空间隔离）
        assert_eq!(
            state.verifier_status(crate::DEFAULT_CHAIN_ID),
            VerifierStatus::Stub
        );
    }

    #[test]
    fn test_offchain_checkout_allowed() {
        let mut state = GovernanceState::new();
        // mainnet + Stub → 拒绝
        assert!(!state.is_offchain_checkout_allowed(crate::DEFAULT_CHAIN_ID));
        // mainnet + Production → 允许
        state.set_verifier_status(crate::DEFAULT_CHAIN_ID, VerifierStatus::Production);
        assert!(state.is_offchain_checkout_allowed(crate::DEFAULT_CHAIN_ID));
        // testnet 始终允许
        assert!(state.is_offchain_checkout_allowed(0x1234));
    }

    // ===== 提案创建测试 =====

    #[test]
    fn test_create_parameter_proposal() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        let id = state
            .create_parameter_proposal(
                ParamName::TurnTimeoutBlocks,
                50,
                crate::DEFAULT_CHAIN_ID,
                proposer,
                100,
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();
        assert_eq!(id, 1);
        assert_eq!(state.next_proposal_id, 2);
        let proposal = &state.proposals[&id];
        assert_eq!(proposal.status, ProposalStatus::Voting);
        assert_eq!(proposal.submit_height, 100);
        assert_eq!(
            proposal.voting_end_height,
            100 + DEFAULT_VOTING_PERIOD_BLOCKS
        );
    }

    #[test]
    fn test_create_parameter_proposal_out_of_bounds() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        // turn_timeout_blocks = 2 < 3 → 拒绝
        let result = state.create_parameter_proposal(
            ParamName::TurnTimeoutBlocks,
            2,
            crate::DEFAULT_CHAIN_ID,
            proposer,
            100,
            crate::DEFAULT_CHAIN_ID,
        );
        assert!(matches!(result, Err(PokerL1Error::ParamOutOfBounds { .. })));
    }

    #[test]
    fn test_create_verifier_status_proposal_chain_id_mismatch() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        // SEC-M4：verifier_status 提案 chain_id 须与网络一致
        let result = state.create_parameter_proposal(
            ParamName::VerifierStatus,
            1,
            0x9999, // 错误 chain_id
            proposer,
            100,
            crate::DEFAULT_CHAIN_ID,
        );
        assert!(matches!(
            result,
            Err(PokerL1Error::ProposalChainIdMismatch { .. })
        ));
    }

    #[test]
    fn test_create_validator_set_update_proposal() {
        use crate::consensus::validator_set::compute_genesis_chain_randomness;
        use crate::consensus::validator_set::{
            VRF_PUBKEY_SIZE, ValidatorEntry, ValidatorSet, ValidatorStatus,
        };

        let validators: Vec<ValidatorEntry> = (0..10)
            .map(|i| {
                let mut v = ValidatorEntry::new(
                    make_pubkey(0x10 + i as u8),
                    [0u8; VRF_PUBKEY_SIZE],
                    1_000_000,
                    0,
                );
                v.status = ValidatorStatus::Active;
                v
            })
            .collect();
        let genesis_randomness = compute_genesis_chain_randomness(&validators);
        let mut set = ValidatorSet {
            epoch: 1,
            validators,
            validator_set_hash: [0u8; 32],
            epoch_randomness: [0u8; 32],
            prev_epoch_randomness: [0u8; 32],
            genesis_chain_randomness: genesis_randomness,
        };
        set.validator_set_hash = set.compute_hash();

        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);

        // 加入 1 个 validator
        let addition = ValidatorAddition {
            pubkey: make_pubkey(0x20),
            vrf_pubkey: [0x20; VRF_PUBKEY_SIZE],
            stake: 1_000_000,
        };
        let id = state
            .create_validator_set_update_proposal(&set, vec![addition], vec![], 2, proposer, 100)
            .unwrap();
        assert_eq!(id, 1);
    }

    #[test]
    fn validator_set_update_applies_only_at_declared_epoch_and_preserves_escrow() {
        let mut validators = (0..5)
            .map(|index| {
                let mut entry = ValidatorEntry::new(
                    make_pubkey(0x40 + index),
                    [0x40 + index; VRF_PUBKEY_SIZE],
                    1_000,
                    0,
                );
                entry.status = ValidatorStatus::Active;
                entry
            })
            .collect::<Vec<_>>();
        let randomness = crate::consensus::compute_genesis_chain_randomness(&validators);
        let mut set = ValidatorSet {
            epoch: 1,
            validators: std::mem::take(&mut validators),
            validator_set_hash: [0; 32],
            epoch_randomness: randomness,
            prev_epoch_randomness: [0; 32],
            genesis_chain_randomness: randomness,
        };
        set.validator_set_hash = set.compute_hash();
        let removed = set.validators[0].pubkey.clone();
        let addition = ValidatorAddition {
            pubkey: make_pubkey(0x70),
            vrf_pubkey: [0x70; VRF_PUBKEY_SIZE],
            stake: 2_000,
        };
        let mut state = GovernanceState::new();
        let proposal_id = state
            .create_validator_set_update_proposal(
                &set,
                vec![addition.clone()],
                vec![removed.clone()],
                2,
                set.validators[1].pubkey.clone(),
                10,
            )
            .unwrap();
        state.proposals.get_mut(&proposal_id).unwrap().status = ProposalStatus::Passed;
        assert!(
            !state
                .apply_validator_set_updates_at_epoch(&mut set, 3, 100)
                .unwrap()
        );
        assert!(
            state
                .apply_validator_set_updates_at_epoch(&mut set, 2, 100)
                .unwrap()
        );
        let removed_entry = set.find_validator(&removed).unwrap();
        assert_eq!(removed_entry.status, ValidatorStatus::Unbonding);
        assert_eq!(removed_entry.stake, 1_000);
        let added_entry = set.find_validator(&addition.pubkey).unwrap();
        assert_eq!(added_entry.status, ValidatorStatus::Bonding);
        assert_eq!(added_entry.stake, 2_000);
        assert_eq!(
            state.proposals[&proposal_id].status,
            ProposalStatus::Executed
        );
        set.validate_persisted().unwrap();
    }

    #[test]
    fn test_validator_set_update_reject_below_min() {
        use crate::consensus::validator_set::compute_genesis_chain_randomness;
        use crate::consensus::validator_set::{
            VRF_PUBKEY_SIZE, ValidatorEntry, ValidatorSet, ValidatorStatus,
        };

        let validators: Vec<ValidatorEntry> = (0..5)
            .map(|i| {
                let mut v = ValidatorEntry::new(
                    make_pubkey(0x10 + i as u8),
                    [0u8; VRF_PUBKEY_SIZE],
                    1_000_000,
                    0,
                );
                v.status = ValidatorStatus::Active;
                v
            })
            .collect();
        let genesis_randomness = compute_genesis_chain_randomness(&validators);
        let mut set = ValidatorSet {
            epoch: 1,
            validators,
            validator_set_hash: [0u8; 32],
            epoch_randomness: [0u8; 32],
            prev_epoch_randomness: [0u8; 32],
            genesis_chain_randomness: genesis_randomness,
        };
        set.validator_set_hash = set.compute_hash();

        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);

        // 踢出 1 个 → 5-1=4 < 5 → SEC-C2 拒绝
        let result = state.create_validator_set_update_proposal(
            &set,
            vec![],
            vec![make_pubkey(0x10)],
            2,
            proposer,
            100,
        );
        assert!(matches!(
            result,
            Err(PokerL1Error::ValidatorSetReductionTooSmall { new_size: 4 })
        ));
    }

    #[test]
    fn test_validator_set_update_reject_excessive_reduction() {
        use crate::consensus::validator_set::compute_genesis_chain_randomness;
        use crate::consensus::validator_set::{
            VRF_PUBKEY_SIZE, ValidatorEntry, ValidatorSet, ValidatorStatus,
        };

        // 10 个 validator
        let validators: Vec<ValidatorEntry> = (0..10)
            .map(|i| {
                let mut v = ValidatorEntry::new(
                    make_pubkey(0x10 + i as u8),
                    [0u8; VRF_PUBKEY_SIZE],
                    1_000_000,
                    0,
                );
                v.status = ValidatorStatus::Active;
                v
            })
            .collect();
        let genesis_randomness = compute_genesis_chain_randomness(&validators);
        let mut set = ValidatorSet {
            epoch: 1,
            validators,
            validator_set_hash: [0u8; 32],
            epoch_randomness: [0u8; 32],
            prev_epoch_randomness: [0u8; 32],
            genesis_chain_randomness: genesis_randomness,
        };
        set.validator_set_hash = set.compute_hash();

        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);

        // 踢出 3 个 → 3/10 = 30% > 20% → SEC-M2 拒绝
        let result = state.create_validator_set_update_proposal(
            &set,
            vec![],
            vec![make_pubkey(0x10), make_pubkey(0x11), make_pubkey(0x12)],
            2,
            proposer,
            100,
        );
        assert!(matches!(
            result,
            Err(PokerL1Error::SingleReductionRatioExceeded { .. })
        ));
    }

    // ===== 投票 + 结束投票测试 =====

    #[test]
    fn test_vote_and_finalize_normal_param_pass() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        let pubkeys = make_pubkeys(10);

        // 创建普通参数提案（ack_deadline_blocks，非敏感）
        let id = state
            .create_parameter_proposal(
                ParamName::AckDeadlineBlocks,
                10,
                crate::DEFAULT_CHAIN_ID,
                proposer,
                100,
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();

        // 7 个赞成（2/3 of 10 = 7）
        for pk in &pubkeys[0..7] {
            state.vote(id, pk.clone(), true, 100).unwrap();
        }

        // 结束投票（voting_end_height = 100 + 1000 = 1100）
        let status = state.finalize_voting(id, 10, 1100).unwrap();
        assert_eq!(status, ProposalStatus::Timelock);

        // timelock 结束后执行
        let timelock_end = 1100 + DEFAULT_PARAMETER_DELAY_BLOCKS;
        state.execute_proposal(id, timelock_end).unwrap();
        assert_eq!(state.params.ack_deadline_blocks, 10);
    }

    #[test]
    fn test_vote_and_finalize_sensitive_param_requires_90() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        let pubkeys = make_pubkeys(10);

        // 创建敏感参数提案（slash_percentage，敏感 90%）
        let id = state
            .create_parameter_proposal(
                ParamName::SlashPercentage,
                50,
                crate::DEFAULT_CHAIN_ID,
                proposer,
                100,
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();

        // 仅 7 个赞成（< 9 = 90% of 10）→ 应被拒绝
        for pk in &pubkeys[0..7] {
            state.vote(id, pk.clone(), true, 100).unwrap();
        }

        let status = state.finalize_voting(id, 10, 1100).unwrap();
        assert_eq!(status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_vote_and_finalize_sensitive_param_pass() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        let pubkeys = make_pubkeys(10);

        let id = state
            .create_parameter_proposal(
                ParamName::SlashPercentage,
                50,
                crate::DEFAULT_CHAIN_ID,
                proposer,
                100,
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();

        // 9 个赞成（= 90% of 10）→ 通过
        for pk in &pubkeys[0..9] {
            state.vote(id, pk.clone(), true, 100).unwrap();
        }

        let status = state.finalize_voting(id, 10, 1100).unwrap();
        assert_eq!(status, ProposalStatus::Timelock);
    }

    #[test]
    fn test_vote_participation_too_low() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        let pubkeys = make_pubkeys(10);

        let id = state
            .create_parameter_proposal(
                ParamName::AckDeadlineBlocks,
                10,
                crate::DEFAULT_CHAIN_ID,
                proposer,
                100,
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();

        // 仅 5 个投票（< 7 = 2/3 of 10）→ 参与率不足
        for pk in &pubkeys[0..5] {
            state.vote(id, pk.clone(), true, 100).unwrap();
        }

        let status = state.finalize_voting(id, 10, 1100).unwrap();
        assert_eq!(status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_duplicate_vote_rejected() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        let voter = make_pubkey(0x02);

        let id = state
            .create_parameter_proposal(
                ParamName::AckDeadlineBlocks,
                10,
                crate::DEFAULT_CHAIN_ID,
                proposer,
                100,
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();

        state.vote(id, voter.clone(), true, 100).unwrap();
        // 重复投票 → 拒绝
        let result = state.vote(id, voter, true, 100);
        assert!(matches!(result, Err(PokerL1Error::DuplicateVote(_))));
    }

    #[test]
    fn test_vote_outside_voting_period() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        let voter = make_pubkey(0x02);

        let id = state
            .create_parameter_proposal(
                ParamName::AckDeadlineBlocks,
                10,
                crate::DEFAULT_CHAIN_ID,
                proposer,
                100,
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();

        // voting_end_height = 1100，在 1101 投票 → 拒绝
        let result = state.vote(id, voter, true, 1101);
        assert!(matches!(result, Err(PokerL1Error::ProposalNotInVoting(_))));
    }

    // ===== Timelock 撤销测试（SEC-H8） =====

    #[test]
    fn test_timelock_revocation() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        let pubkeys = make_pubkeys(10);

        // 1. 创建普通参数提案并通过
        let id1 = state
            .create_parameter_proposal(
                ParamName::AckDeadlineBlocks,
                10,
                crate::DEFAULT_CHAIN_ID,
                proposer.clone(),
                100,
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();
        for pk in &pubkeys[0..7] {
            state.vote(id1, pk.clone(), true, 100).unwrap();
        }
        state.finalize_voting(id1, 10, 1100).unwrap();
        assert_eq!(state.proposals[&id1].status, ProposalStatus::Timelock);

        // 2. 创建撤销提案（timelock 内）
        let rev_id = state
            .create_revocation_proposal(id1, proposer, 1200)
            .unwrap();

        // 3. 9 个赞成撤销（90% of 10）
        for pk in &pubkeys[0..9] {
            state.vote(rev_id, pk.clone(), true, 1200).unwrap();
        }

        // 4. 结束撤销投票 → 通过 + 原提案被撤销
        let status = state
            .finalize_voting(rev_id, 10, 1200 + DEFAULT_VOTING_PERIOD_BLOCKS)
            .unwrap();
        assert_eq!(status, ProposalStatus::Passed);
        assert_eq!(state.proposals[&id1].status, ProposalStatus::Revoked);

        // 5. 执行原提案 → 应失败（已撤销）
        let result = state.execute_proposal(id1, 5000);
        assert!(result.is_err());
    }

    #[test]
    fn test_revocation_quorum_insufficient() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        let pubkeys = make_pubkeys(10);

        // 创建并通过原提案
        let id1 = state
            .create_parameter_proposal(
                ParamName::AckDeadlineBlocks,
                10,
                crate::DEFAULT_CHAIN_ID,
                proposer,
                100,
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();
        for pk in &pubkeys[0..7] {
            state.vote(id1, pk.clone(), true, 100).unwrap();
        }
        state.finalize_voting(id1, 10, 1100).unwrap();

        // 创建撤销提案
        let rev_id = state
            .create_revocation_proposal(id1, make_pubkey(0x02), 1200)
            .unwrap();

        // 仅 8 个赞成（< 9 = 90% of 10）→ 撤销失败
        for pk in &pubkeys[0..8] {
            state.vote(rev_id, pk.clone(), true, 1200).unwrap();
        }
        let status = state
            .finalize_voting(rev_id, 10, 1200 + DEFAULT_VOTING_PERIOD_BLOCKS)
            .unwrap();
        assert_eq!(status, ProposalStatus::Rejected);
        // 原提案仍为 Timelock
        assert_eq!(state.proposals[&id1].status, ProposalStatus::Timelock);
    }

    // ===== verifier_status 治理测试 =====

    #[test]
    fn test_verifier_status_governance() {
        let mut state = GovernanceState::new();
        let registry = crate::offline::zk_verifier::ZkVerifierRegistry::new();
        let proposer = make_pubkey(0x01);
        let pubkeys = make_pubkeys(10);

        // mainnet 默认 Stub
        assert_eq!(
            state.verifier_status(crate::DEFAULT_CHAIN_ID),
            VerifierStatus::Stub
        );

        // 创建 verifier_status 提案（升级为 Production）
        let id = state
            .create_parameter_proposal(
                ParamName::VerifierStatus,
                1, // Production
                crate::DEFAULT_CHAIN_ID,
                proposer,
                100,
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();

        // 9 个赞成（90%）
        for pk in &pubkeys[0..9] {
            state.vote(id, pk.clone(), true, 100).unwrap();
        }
        state.finalize_voting(id, 10, 1100).unwrap();

        // timelock 结束后执行
        state
            .execute_proposal_and_sync_verifier_registry(
                id,
                1100 + DEFAULT_PARAMETER_DELAY_BLOCKS,
                &registry,
            )
            .unwrap();
        assert_eq!(
            state.verifier_status(crate::DEFAULT_CHAIN_ID),
            VerifierStatus::Production
        );
        assert!(state.is_offchain_checkout_allowed(crate::DEFAULT_CHAIN_ID));
        assert_eq!(
            registry.verifier_status(crate::DEFAULT_CHAIN_ID),
            VerifierStatus::Production
        );
    }

    // ===== 密钥轮换测试 =====

    #[test]
    fn test_key_rotation_proposal() {
        let mut state = GovernanceState::new();
        let old_pk = make_pubkey(0x01);
        let new_pk = make_pubkey(0x02);
        let pubkeys = make_pubkeys(10);

        let id = state
            .create_key_rotation_proposal(old_pk, new_pk, make_pubkey(0x03), 100)
            .unwrap();

        // 9 个赞成（90%）
        for pk in &pubkeys[0..9] {
            state.vote(id, pk.clone(), true, 100).unwrap();
        }
        let status = state.finalize_voting(id, 10, 1100).unwrap();
        assert_eq!(status, ProposalStatus::Passed); // 密钥轮换无 timelock（直接 Passed）

        // Generic execution cannot falsely mark it complete; only the authenticated epoch
        // transition, after writing ValidatorSet + ValidatorKeyHistory, may do so.
        assert!(state.execute_proposal(id, 1100).is_err());
        assert_eq!(state.proposals[&id].status, ProposalStatus::Passed);
        state.mark_key_rotations_executed(&[id]).unwrap();
        assert_eq!(state.proposals[&id].status, ProposalStatus::Executed);
    }

    // ===== DDoS 检测测试 =====

    #[test]
    fn test_detect_voting_ddos() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        let pubkeys = make_pubkeys(10);

        let id = state
            .create_parameter_proposal(
                ParamName::AckDeadlineBlocks,
                10,
                crate::DEFAULT_CHAIN_ID,
                proposer,
                100,
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();

        // 仅 5 个投票（5/10 离线率 = 50% > 30%）→ DDoS 检测
        for pk in &pubkeys[0..5] {
            state.vote(id, pk.clone(), true, 100).unwrap();
        }
        assert!(state.detect_voting_ddos(id, 10));

        // 8 个投票（2/10 离线率 = 20% < 30%）→ 无 DDoS
        for pk in &pubkeys[5..8] {
            state.vote(id, pk.clone(), true, 100).unwrap();
        }
        assert!(!state.detect_voting_ddos(id, 10));
    }

    #[test]
    fn test_execute_before_timelock_ends() {
        let mut state = GovernanceState::new();
        let proposer = make_pubkey(0x01);
        let pubkeys = make_pubkeys(10);

        let id = state
            .create_parameter_proposal(
                ParamName::AckDeadlineBlocks,
                10,
                crate::DEFAULT_CHAIN_ID,
                proposer,
                100,
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();
        for pk in &pubkeys[0..7] {
            state.vote(id, pk.clone(), true, 100).unwrap();
        }
        state.finalize_voting(id, 10, 1100).unwrap();

        // timelock 未结束就执行 → 失败
        let result = state.execute_proposal(id, 1100 + DEFAULT_PARAMETER_DELAY_BLOCKS - 1);
        assert!(result.is_err());
    }
}
