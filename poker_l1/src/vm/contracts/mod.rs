//! Poker 合约示例与业务逻辑（Task 16）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 16.1**：minimal Rust 合约模板（见 [`examples`] 模块）
//! - **SubTask 16.2 / 16.3**：Game 创建 / 修改合约示例（见 [`examples`] 模块）
//! - **SubTask 16.4**：poker settle 台费逻辑（见 [`settle`] 模块）
//! - **SubTask 16.5**：HandStarted 按 execution_mode 分支（见 [`hand_started`] 模块）
//! - **SubTask 16.6**：force_advance fold/check 规则（见 [`force_advance`] 模块）
//!
//! # 设计说明
//!
//! 由于 BPF 工具链（`bpf-tools` / `rust-bpf-linker`）在开发环境不可用，
//! 本模块采用"纯 Rust 业务逻辑 + 合约源码模板"双层设计：
//!
//! 1. **业务逻辑层**（`settle` / `hand_started` / `force_advance`）：纯 Rust 函数，
//!    可独立单元测试，验证协议层规则的正确性。这些函数对应合约在 VM 内执行
//!    时会调用的核心逻辑，合约 entrypoint 解析输入后调用这些函数。
//!
//! 2. **合约源码模板**（`examples`）：Rust 源码示例，文档化合约如何通过
//!    syscall（`object_read` / `object_write` / `object_create` / `emit_event`）
//!    与链交互。这些模板可用 `solana-bpf-tools` 编译为 `.so` 字节码后部署。
//!
//! 这种分层符合 spec 第 689-693 行的约束："规则由协议层定义，合约可覆盖"——
//! 协议层规则在 `force_advance` 模块实现，合约层可调用或覆盖。

pub mod ack_protocol;
pub mod censor_detection;
pub mod challenge_delta;
pub mod checkpoint_anchor;
pub mod checkpoint_skip;
pub mod delegated_escape;
pub mod dispatch;
pub mod examples;
pub mod force_advance;
pub mod force_checkin;
pub mod force_checkpoint;
pub mod force_settle;
pub mod forfeit;
pub mod game_precompile;
pub mod hand_started;
pub mod request_da;
pub mod revert;
pub mod settle;
pub mod texas_poker;
pub mod texas_poker_precompile;
pub mod types;

pub use ack_protocol::{
    RefuseAckReason, RefuseAckTx, RequestAckTx, apply_refuse_ack, apply_request_ack,
    check_ack_deadline_expired, clear_expired_pending_acks, clear_pending_ack,
};
pub use censor_detection::{
    CensorshipWitnessEvidence, DEFAULT_GOSSIPSUB_MESH_SIZE, FALSE_WITNESS_SLASH_PERCENTAGE,
    FalseWitnessEvidence, MIN_CANDIDATE_VALIDATORS_FOR_REPLICA, compute_replica_set,
    gossipsub_mesh_size, is_witness_in_replica_set,
};
pub use challenge_delta::{
    ChallengeDeltaOutcome, ChallengeDeltaTx, DEFAULT_CHALLENGE_DEPOSIT_RATIO,
    DEFAULT_CHALLENGE_REWARD_RATIO, MAX_CHALLENGE_DEPOSIT_RATIO, MAX_CHALLENGE_REWARD_RATIO,
    MIN_CHALLENGE_DEPOSIT_RATIO, MIN_CHALLENGE_REWARD_RATIO, apply_challenge_delta,
    compute_challenge_delta_outcome, compute_challenger_deposit, compute_challenger_reward,
    hash_state_delta, validate_challenge_deposit_ratio, validate_challenge_reward_ratio,
};
pub use checkpoint_anchor::{
    AckSignature, CheckpointAnchorTx, OptOutAckProof, apply_checkpoint_anchor,
    verify_checkpoint_anchor,
};
pub use checkpoint_skip::{
    CheckpointSkipTx, SegmentContinuityProof, StateProof, apply_checkpoint_skip,
    verify_segment_chain,
};
pub use delegated_escape::{
    DelegatedEscapeAuthorization, RevokeDelegatedEscapeTx, apply_revoke_delegated_escape,
    compute_next_credential_nonce, consume_delegated_escape_authorization,
};
pub use dispatch::{DispatchContext, DispatchResult, compute_method_selector, dispatch, selectors};
pub use force_advance::{
    ForceAdvanceError, ForceAdvanceInput, apply_force_advance, force_advance_action,
};
pub use force_checkin::{
    DEFAULT_DESIGNATED_OPERATOR_CHECK_EXEMPTION_LIMIT, DEFAULT_RECOVERY_WINDOW_BLOCKS,
    ForceCheckinInput, ForceCheckinOutcome, ForceCheckinScenario, ForfeitDecision, ForfeitReason,
    RecoveryStage, apply_designated_operator_check_exemption, apply_force_checkin,
    determine_force_checkin_scenario, is_designated_operator_exemption_exhausted,
    should_exempt_current_turn_player, validate_force_checkin_game_id,
};
pub use force_checkpoint::{
    AssignedValidatorFailureProof, ForceCheckpointTx, MultiReplicaReceipt, NonInclusionProof,
    RoundRangeNonInclusionProof, VertexInfo, apply_force_checkpoint,
    compute_force_checkpoint_deposit,
};
pub use force_settle::{
    ForceSettleOutcome, ForceSettleTx, apply_force_settle, is_force_settle_allowed,
};
pub use forfeit::{
    DEFAULT_FORFEIT_DEPOSIT_RATIO, ForfeitDistribution, ForfeitOutcome, MAX_FORFEIT_DEPOSIT_RATIO,
    MIN_FORFEIT_DEPOSIT_RATIO, RefundOutcome, apply_forfeit, apply_forfeit_refund,
    compute_designated_operator_bond, compute_forfeit_deposit, compute_forfeit_distribution,
    validate_designated_operator_bond, validate_forfeit_deposit_ratio,
};
pub use game_precompile::GamePrecompile;
pub use hand_started::{HandStartedError, HandStartedInput, hand_started_branch};
pub use request_da::{RequestDaOutcome, RequestDaTx, apply_request_da, is_request_da_appropriate};
pub use revert::{
    ForceRevertTx, RequestRevertTx, RevertOutcome, RevertReason, apply_force_revert,
    apply_request_revert,
};
pub use settle::{RakeConfig, SettleError, SettleResult, compute_rake, settle_hand};
pub use texas_poker_precompile::TexasPokerPrecompile;
pub use types::{BettingRound, GameAction, GameContract, GamePhase, HandState, PlayerStack};
