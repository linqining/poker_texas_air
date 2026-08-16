//! 时间共识（Task 11 — SubTask 11.1~11.5）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **S10 修复**：
//!   - `block.height = prev.height + 1`（严格单调递增，**权威**）
//!   - `timestamp_ms >= prev.timestamp_ms`（单调不减，**软引用**）
//!   - `timestamp_ms <= prev.timestamp_ms + max_interval_ms`（最大间隔，**软引用**）
//! - **SEC2-L6 修复**：所有时间窗口统一 `<=` / `>=` 包含边界判定
//! - **SEC-M5 修复**（timestamp_ms 合谋风险警示）：
//!   - block 提议者（DAG 中获得 commit 的 validator）可在
//!     `[prev.timestamp_ms, prev.timestamp_ms + max_interval_ms]` 合法范围内任意选 `timestamp_ms`
//!   - **安全约束**：
//!     1. 链下参与者触发 `force_advance` / `force_checkpoint` 等逃生 tx 的硬截止判定
//!        一律以 `block.height` 为权威，禁止以 `timestamp_ms` 作为触发条件
//!     2. `timestamp_ms` 仅可用于"显示用"与"非安全相关的软参考"
//!     3. 任何以 `timestamp_ms` 为依据的安全决策均视为实现错误
//! - **R5-L4 修正**：timestamp_ms 为软引用，所有硬截止判定以 block.height 为权威
//! - **R7-M3 修正**：`max_clock_drift_ms` 仅供链下参与者作软参考时钟漂移容忍度，
//!   不用于 validator 共识硬校验
//! - **SubTask 11.3**：所有超时参数以 block height 计量（非 timestamp_ms）
//! - **SubTask 11.4**：Game 对象维护 `last_action_height` / `hand_start_height` 字段
//!   （由 [`crate::consensus::GameStatus`] 承载）
//! - **SubTask 11.5**：轻客户端 block header 订阅接口（secp256k1 多签验证 + 2/3 quorum）
//!   依赖 Task 13 的 ValidatorSet，本模块仅定义校验函数骨架与超时配置；
//!   实际多签验证在 Task 13 完成后填充。
//!
//! ## 设计决策
//!
//! - `validate_block_time` 仅做时间共识硬校验（height 严格递增 + timestamp_ms 单调不减 + 间隔上限），
//!   不校验签名 / quorum / state_root 等（那些在 Task 10 block 验证器中实现）
//! - `TimeConsensusConfig` 集中所有可治理参数，避免散落常量
//! - 超时参数（turn_timeout_blocks 等）以 block height 计量，符合 SEC-M5 安全约束
//! - 轻客户端接口（`LightClientVerifyRequest` / `verify_block_header_quorum`）为骨架，
//!   实际 secp256k1 多签验证逻辑在 Task 13 ValidatorSet 完成后填充

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::block::BlockHeader;
use crate::error::{PokerL1Error, PokerL1Result};

/// 时间共识可治理参数（SubTask 11.2 / 11.3）。
///
/// 所有 timestamp 相关参数为软引用（SEC-M5），所有超时参数以 block height 计量。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct TimeConsensusConfig {
    /// `timestamp_ms` 相对 `prev.timestamp_ms` 的最大间隔（毫秒，软引用）。
    ///
    /// SEC2-L6：`timestamp_ms <= prev.timestamp_ms + max_interval_ms`（包含边界）。
    /// 默认 30_000ms（30 秒，对应 DAG commit 的典型间隔）。
    pub max_interval_ms: u64,

    /// 链下参与者软参考时钟漂移容忍度（R7-M3，不参与 validator 共识硬校验）。
    ///
    /// 默认 5_000ms（5 秒）。
    pub max_clock_drift_ms: u64,

    /// GameTurn 玩家行动超时（block 数，SubTask 11.3）。
    ///
    /// assigned_validator 在 `last_action_height + turn_timeout_blocks` 后
    /// 未装入该玩家 GameTurn tx → 任意参与者可触发 fallback（SubTask 8.9 / NEW-H2）。
    /// 默认 30 block。
    pub turn_timeout_blocks: u64,

    /// 单手牌最大持续 block 数（SubTask 11.3）。
    ///
    /// 超出 → 任意参与者可触发 `force_advance` / `request_revert`。
    /// 默认 300 block。
    pub hand_max_duration_blocks: u64,

    /// 争议窗口（block 数，SubTask 11.3）。
    ///
    /// 链下执行结果可被挑战的窗口；超出窗口视为 final。
    /// 默认 200 block。
    pub dispute_window_blocks: u64,

    /// 数据可用性窗口（block 数，SubTask 11.3）。
    ///
    /// DAG vertex 被视为 DA 已确认的窗口（vertex age）。
    /// 默认 500 block。
    pub da_window_blocks: u64,

    /// checkpoint 间隔（block 数，SubTask 11.3）。
    ///
    /// OffChain 模式 Game 操作方定期提交 `checkpoint_anchor` 的间隔。
    /// 默认 100 block。
    pub checkpoint_interval_blocks: u64,

    /// assigned_validator 超时阈值（block 数，SubTask 11.3 / 8.9）。
    ///
    /// assigned_validator 在 `game_validator_timeout_blocks` 内未提交任何 vertex
    /// → 可被指控 `assigned_validator_failure_proof`。
    /// 默认 50 block。
    pub game_validator_timeout_blocks: u64,

    /// epoch 长度（block 数，SubTask 11.3 / Task 12）。
    ///
    /// 每 `epoch_length_blocks` 自动重分配 validator 集。
    /// 默认 1000 block。
    pub epoch_length_blocks: u64,

    /// epoch 过渡窗口（block 数，NEW-M10）。
    ///
    /// OffChain 模式 Game 操作方须在 epoch 边界前此窗口内提交 `checkpoint_anchor`。
    /// 默认 10 block。
    pub epoch_transition_window_blocks: u64,

    /// Shuffle 阶段超时（block 数，spec Phase 4 Task 7）。
    ///
    /// 多玩家提交阶段 `SubmitPhaseKind::Shuffle` 的最大持续 block 数。
    /// 超出 → `pending_submitters` 中的玩家被 kick + 退款。
    /// 默认 100 block。
    pub shuffle_timeout_blocks: u64,

    /// RevealToken 阶段超时（block 数，spec Phase 4 Task 7）。
    ///
    /// 多玩家提交阶段 `SubmitPhaseKind::RevealToken` 的最大持续 block 数。
    /// 超出 → `pending_submitters` 中的玩家被 kick + 退款。
    /// 默认 50 block。
    pub reveal_token_timeout_blocks: u64,

    /// Reconstruct 阶段超时（block 数，spec Phase 4 Task 7）。
    ///
    /// 多玩家提交阶段 `SubmitPhaseKind::Reconstruct` 的最大持续 block 数。
    /// 超出 → `pending_submitters` 中的玩家被 kick + 退款。
    /// 默认 100 block。
    pub reconstruct_timeout_blocks: u64,
}

impl Default for TimeConsensusConfig {
    fn default() -> Self {
        Self {
            max_interval_ms: 30_000,
            max_clock_drift_ms: 5_000,
            turn_timeout_blocks: 30,
            hand_max_duration_blocks: 300,
            dispute_window_blocks: 200,
            da_window_blocks: 500,
            checkpoint_interval_blocks: 100,
            game_validator_timeout_blocks: 50,
            epoch_length_blocks: 1000,
            epoch_transition_window_blocks: 10,
            shuffle_timeout_blocks: 100,
            reveal_token_timeout_blocks: 50,
            reconstruct_timeout_blocks: 100,
        }
    }
}

impl TimeConsensusConfig {
    /// 创建默认配置（等价于 `Self::default()`，提供 const fn 语义友好接口）。
    pub const fn new() -> Self {
        Self {
            max_interval_ms: 30_000,
            max_clock_drift_ms: 5_000,
            turn_timeout_blocks: 30,
            hand_max_duration_blocks: 300,
            dispute_window_blocks: 200,
            da_window_blocks: 500,
            checkpoint_interval_blocks: 100,
            game_validator_timeout_blocks: 50,
            epoch_length_blocks: 1000,
            epoch_transition_window_blocks: 10,
            shuffle_timeout_blocks: 100,
            reveal_token_timeout_blocks: 50,
            reconstruct_timeout_blocks: 100,
        }
    }
}

/// 校验 block 时间共识（SubTask 11.1 / 11.2 / S10 / SEC2-L6 / SEC-M5）。
///
/// 硬校验项（不通过 → 拒绝 block）：
/// 1. `curr.height == prev.height + 1`（严格单调递增，权威）
/// 2. `curr.timestamp_ms >= prev.timestamp_ms`（单调不减，SEC2-L6 包含边界）
/// 3. `curr.timestamp_ms <= prev.timestamp_ms + config.max_interval_ms`（最大间隔，SEC2-L6 包含边界）
///
/// **SEC-M5 警示**：timestamp_ms 校验为软引用一致性检查（防 proposals 显著偏离），
/// 但任何安全决策（force_advance / slashing / 超时判定）必须以 `block.height` 为权威。
/// 本函数不判定超时，超时由各模块基于 `block.height` 单独计算。
///
/// 参数：
/// - `prev`：前一个 block 的 header（genesis 时传 `None`，跳过时间校验）
/// - `curr`：当前待校验的 block header
/// - `config`：时间共识配置
pub fn validate_block_time(
    prev: Option<&BlockHeader>,
    curr: &BlockHeader,
    config: &TimeConsensusConfig,
) -> PokerL1Result<()> {
    if let Some(prev) = prev {
        // S10：height 严格单调递增（prev.height + 1）
        let expected_height = prev
            .height
            .checked_add(1)
            .ok_or_else(|| PokerL1Error::Other("block height overflow".to_string()))?;
        if curr.height != expected_height {
            return Err(PokerL1Error::BlockHeightNotIncreasing {
                prev: prev.height,
                got: curr.height,
            });
        }

        // S10 / SEC2-L6：timestamp_ms 单调不减（包含等于）
        if curr.timestamp_ms < prev.timestamp_ms {
            return Err(PokerL1Error::BlockTimestampMovedBackwards {
                prev: prev.timestamp_ms,
                got: curr.timestamp_ms,
            });
        }

        // S10 / SEC2-L6：timestamp_ms <= prev.timestamp_ms + max_interval_ms（包含边界）
        let max_allowed = prev
            .timestamp_ms
            .checked_add(config.max_interval_ms)
            .ok_or_else(|| PokerL1Error::Other("timestamp_ms overflow".to_string()))?;
        if curr.timestamp_ms > max_allowed {
            return Err(PokerL1Error::BlockTimestampIntervalExceeded {
                prev: prev.timestamp_ms,
                got: curr.timestamp_ms,
                max_interval: config.max_interval_ms,
            });
        }
    }
    // genesis（prev = None）跳过时间校验：height=0 已由构造保证
    Ok(())
}

/// 判定 GameTurn 玩家行动是否超时（SubTask 11.3 / 11.4 / 8.9 / NEW-H2）。
///
/// SEC-M5 安全约束：以 `block.height` 为权威，禁止以 `timestamp_ms` 触发。
///
/// 参数：
/// - `last_action_height`：玩家最后一次 GameTurn / checkpoint_anchor 的 block height
/// - `current_height`：当前链 tip height
/// - `config`：时间共识配置
///
/// 返回 `true` 表示已超时（可触发 fallback）。
pub const fn is_turn_timeout(
    last_action_height: u64,
    current_height: u64,
    config: &TimeConsensusConfig,
) -> bool {
    current_height > last_action_height + config.turn_timeout_blocks
}

/// 判定 assigned_validator 是否超时（SubTask 11.3 / 8.9）。
///
/// SEC-M5 安全约束：以 `block.height` 为权威。
///
/// 参数：
/// - `last_vertex_height`：assigned_validator 最后一次产出 vertex 的 block height
/// - `current_height`：当前链 tip height
/// - `config`：时间共识配置
///
/// 返回 `true` 表示已超时（可触发 `assigned_validator_failure_proof`）。
pub const fn is_validator_timeout(
    last_vertex_height: u64,
    current_height: u64,
    config: &TimeConsensusConfig,
) -> bool {
    current_height > last_vertex_height + config.game_validator_timeout_blocks
}

/// 判定单手牌是否超时（SubTask 11.3）。
///
/// SEC-M5 安全约束：以 `block.height` 为权威。
///
/// 参数：
/// - `hand_start_height`：当前手牌起始 block height
/// - `current_height`：当前链 tip height
/// - `config`：时间共识配置
///
/// 返回 `true` 表示已超时（可触发 `force_advance` / `request_revert`）。
pub const fn is_hand_timeout(
    hand_start_height: u64,
    current_height: u64,
    config: &TimeConsensusConfig,
) -> bool {
    current_height > hand_start_height + config.hand_max_duration_blocks
}

/// 判定多玩家提交阶段是否超时（spec Phase 4 Task 7.2）。
///
/// SEC-M5 安全约束：以 `block.height` 为权威，禁止以 `timestamp_ms` 触发。
///
/// 根据当前 [`GameStatus::phase`] 选择对应超时阈值：
/// - `Betting { .. }`：下注阶段不走此超时，返回 `None`
/// - `MultiPlayerSubmit { kind: Shuffle }`：使用 `shuffle_timeout_blocks`
/// - `MultiPlayerSubmit { kind: RevealToken }`：使用 `reveal_token_timeout_blocks`
/// - `MultiPlayerSubmit { kind: Reconstruct }`：使用 `reconstruct_timeout_blocks`
/// - `MultiPlayerSubmit { kind: LeaveProof }`：LeaveProof 为被动行为，不超时，返回 `None`
///
/// 超时判定使用严格大于 `>`：
/// `current_height > phase_started_height + timeout_blocks` → 返回 `Some(kind)`
/// 边界 `current_height == phase_started_height + timeout_blocks` 视为未超时。
///
/// 使用 `checked_add` 防 overflow，溢出返回 `None`（保守不超时，避免误 kick）。
///
/// 参数：
/// - `game`：当前 Game 状态（消费 `phase` / `phase_started_height`）
/// - `current_height`：当前链 tip height
/// - `config`：时间共识配置
///
/// 返回 `Some(SubmitPhaseKind)` 表示对应阶段已超时；`None` 表示未超时或不适用此判定。
pub fn is_submit_phase_timed_out(
    game: &crate::consensus::GameStatus,
    current_height: crate::BlockHeight,
    config: &TimeConsensusConfig,
) -> Option<crate::consensus::SubmitPhaseKind> {
    use crate::consensus::{GamePhase, SubmitPhaseKind};

    match game.phase {
        // 下注阶段不走此超时
        GamePhase::Betting { .. } => None,
        GamePhase::MultiPlayerSubmit { kind } => match kind {
            SubmitPhaseKind::Shuffle => {
                let deadline = game
                    .phase_started_height
                    .checked_add(config.shuffle_timeout_blocks)?;
                if current_height > deadline {
                    Some(SubmitPhaseKind::Shuffle)
                } else {
                    None
                }
            }
            SubmitPhaseKind::RevealToken => {
                let deadline = game
                    .phase_started_height
                    .checked_add(config.reveal_token_timeout_blocks)?;
                if current_height > deadline {
                    Some(SubmitPhaseKind::RevealToken)
                } else {
                    None
                }
            }
            SubmitPhaseKind::Reconstruct => {
                let deadline = game
                    .phase_started_height
                    .checked_add(config.reconstruct_timeout_blocks)?;
                if current_height > deadline {
                    Some(SubmitPhaseKind::Reconstruct)
                } else {
                    None
                }
            }
            // LeaveProof 为被动行为，不超时
            SubmitPhaseKind::LeaveProof => None,
        },
    }
}

/// 判定 block 是否已过 DA 窗口（SubTask 11.3）。
///
/// SEC-M5 安全约束：以 `block.height` 为权威。
///
/// 参数：
/// - `block_height`：待判定 block 的 height
/// - `current_height`：当前链 tip height
/// - `config`：时间共识配置
///
/// 返回 `true` 表示 DA 窗口已过，vertex 被视为 DA 已确认。
pub const fn is_da_window_passed(
    block_height: u64,
    current_height: u64,
    config: &TimeConsensusConfig,
) -> bool {
    current_height > block_height + config.da_window_blocks
}

/// 判定争议窗口是否已过（SubTask 11.3）。
///
/// SEC-M5 安全约束：以 `block.height` 为权威。
///
/// 参数：
/// - `block_height`：待判定 block 的 height
/// - `current_height`：当前链 tip height
/// - `config`：时间共识配置
///
/// 返回 `true` 表示争议窗口已过，链下执行结果视为 final。
pub const fn is_dispute_window_passed(
    block_height: u64,
    current_height: u64,
    config: &TimeConsensusConfig,
) -> bool {
    current_height > block_height + config.dispute_window_blocks
}

/// 判定是否到达 checkpoint 提交时机（SubTask 11.3）。
///
/// SEC-M5 安全约束：以 `block.height` 为权威。
///
/// 参数：
/// - `last_checkpoint_height`：上次 checkpoint_anchor 提交的 block height
/// - `current_height`：当前链 tip height
/// - `config`：时间共识配置
///
/// 返回 `true` 表示应提交新 checkpoint_anchor。
pub const fn should_submit_checkpoint(
    last_checkpoint_height: u64,
    current_height: u64,
    config: &TimeConsensusConfig,
) -> bool {
    current_height >= last_checkpoint_height + config.checkpoint_interval_blocks
}

/// 判定是否进入 epoch 过渡窗口（SubTask 11.3 / NEW-M10）。
///
/// SEC-M5 安全约束：以 `block.height` 为权威。
///
/// 参数：
/// - `current_height`：当前链 tip height
/// - `config`：时间共识配置
///
/// 返回 `true` 表示当前位于 epoch 边界前的过渡窗口内。
pub const fn in_epoch_transition_window(current_height: u64, config: &TimeConsensusConfig) -> bool {
    let epoch_end =
        ((current_height / config.epoch_length_blocks) + 1) * config.epoch_length_blocks;
    // 距 epoch 边界不足 epoch_transition_window_blocks → 在过渡窗口内
    epoch_end.saturating_sub(current_height) <= config.epoch_transition_window_blocks
}

/// 判定是否到达 epoch 边界（SubTask 11.3 / Task 12）。
///
/// SEC-M5 安全约束：以 `block.height` 为权威。
///
/// 参数：
/// - `current_height`：当前链 tip height
/// - `config`：时间共识配置
///
/// 返回 `true` 表示当前 block 为 epoch 边界（应触发重分配）。
pub const fn is_epoch_boundary(current_height: u64, config: &TimeConsensusConfig) -> bool {
    config.epoch_length_blocks > 0 && current_height.is_multiple_of(config.epoch_length_blocks)
}

/// 计算给定 height 所属的 epoch 编号（SubTask 11.3 / Task 12）。
///
/// epoch = height / epoch_length_blocks（向下取整）。
#[allow(clippy::manual_checked_ops)]
pub const fn epoch_of(current_height: u64, config: &TimeConsensusConfig) -> u64 {
    if config.epoch_length_blocks == 0 {
        0
    } else {
        current_height / config.epoch_length_blocks
    }
}

/// 轻客户端 block header 验证请求（SubTask 11.5 骨架）。
///
/// 实际 secp256k1 多签验证逻辑依赖 Task 13 的 ValidatorSet 结构，
/// 此处仅定义请求载荷与校验入口，Task 13 完成后填充验证逻辑。
#[derive(Debug, Clone)]
pub struct LightClientVerifyRequest<'a> {
    /// 待验证的 block header。
    pub header: &'a BlockHeader,
    /// 网络 chain_id。
    pub chain_id: crate::ChainId,
    /// 已知 validator 集的 quorum 阈值（2/3 of |V|）。
    ///
    /// 由 Task 13 ValidatorSet 提供，轻客户端从 trusted checkpoint 同步。
    pub quorum_threshold: usize,
}

/// 轻客户端 block header quorum 校验（SubTask 11.5 骨架）。
///
/// **当前实现**：仅校验 `dag_commit_certificate.signer_count() >= quorum_threshold`。
///
/// **Task 13 完成后补充**：
/// - 逐个验证 `signature_list` 中每个 secp256k1 签名（签名对象 = commit cert 的 signing_hash）
/// - 校验 `signer_bitmap` 与 validator_set 的对应关系
/// - 校验 `state_root` / `public_tx_root` / `gameturn_tx_root` 字段一致性
///
/// 参数：
/// - `request`：验证请求
///
/// 返回 `Ok(())` 表示 quorum 校验通过；否则返回相应错误。
pub fn verify_block_header_quorum(request: &LightClientVerifyRequest<'_>) -> PokerL1Result<()> {
    let signer_count = request.header.dag_commit_certificate.signer_count();
    if signer_count < request.quorum_threshold {
        return Err(PokerL1Error::InsufficientQuorum {
            actual: signer_count,
            required: request.quorum_threshold,
        });
    }
    // Task 13 完成后：补充 secp256k1 多签验证 + signer_bitmap 一致性校验
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::DagCommitCertificate;

    fn dummy_commit_cert(signer_count: usize) -> DagCommitCertificate {
        // 构造 signer_bitmap 使其有 `signer_count` 个 1
        let full_bytes = signer_count / 8;
        let remainder = signer_count % 8;
        let mut bitmap = vec![0xFFu8; full_bytes];
        if remainder > 0 {
            let last = (1u8 << remainder) - 1;
            bitmap.push(last);
        }
        if bitmap.is_empty() {
            bitmap.push(0);
        }
        DagCommitCertificate {
            epoch: 1,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            epoch_transition: None,
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![0xFF],
            state_root: [0u8; 32],
            account_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![vec![0u8; 65]; signer_count],
            signer_bitmap: bitmap,
        }
    }

    fn dummy_header(height: u64, timestamp_ms: u64) -> BlockHeader {
        BlockHeader {
            height,
            timestamp_ms,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            account_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            dag_commit_certificate: dummy_commit_cert(5),
        }
    }

    fn default_config() -> TimeConsensusConfig {
        TimeConsensusConfig::new()
    }

    // ===== SubTask 11.1 / 11.2: validate_block_time 测试 =====

    #[test]
    fn validate_block_time_ok_for_genesis() {
        // genesis: prev = None，跳过时间校验
        let curr = dummy_header(0, 1_000);
        validate_block_time(None, &curr, &default_config()).expect("genesis 应通过");
    }

    #[test]
    fn validate_block_time_ok_for_normal_progress() {
        let prev = dummy_header(10, 1_000);
        let curr = dummy_header(11, 1_500);
        validate_block_time(Some(&prev), &curr, &default_config()).expect("正常推进应通过");
    }

    #[test]
    fn validate_block_time_ok_with_equal_timestamp() {
        // SEC2-L6：timestamp_ms 单调不减（包含等于）
        let prev = dummy_header(10, 1_000);
        let curr = dummy_header(11, 1_000);
        validate_block_time(Some(&prev), &curr, &default_config())
            .expect("timestamp_ms 相等应通过（SEC2-L6 包含边界）");
    }

    #[test]
    fn validate_block_time_ok_at_max_interval_boundary() {
        // SEC2-L6：timestamp_ms <= prev + max_interval（包含边界）
        let prev = dummy_header(10, 1_000);
        let curr = dummy_header(11, 1_000 + 30_000);
        validate_block_time(Some(&prev), &curr, &default_config())
            .expect("timestamp_ms == prev + max_interval 应通过（SEC2-L6 包含边界）");
    }

    #[test]
    fn validate_block_time_rejects_non_incrementing_height() {
        let prev = dummy_header(10, 1_000);
        let curr = dummy_header(10, 1_500); // height 未递增
        let err = validate_block_time(Some(&prev), &curr, &default_config()).unwrap_err();
        assert!(matches!(err, PokerL1Error::BlockHeightNotIncreasing { .. }));
    }

    #[test]
    fn validate_block_time_rejects_skipped_height() {
        let prev = dummy_header(10, 1_000);
        let curr = dummy_header(12, 1_500); // height 跳号
        let err = validate_block_time(Some(&prev), &curr, &default_config()).unwrap_err();
        assert!(matches!(err, PokerL1Error::BlockHeightNotIncreasing { .. }));
    }

    #[test]
    fn validate_block_time_rejects_backwards_timestamp() {
        let prev = dummy_header(10, 1_500);
        let curr = dummy_header(11, 1_000); // timestamp 回退
        let err = validate_block_time(Some(&prev), &curr, &default_config()).unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::BlockTimestampMovedBackwards { .. }
        ));
    }

    #[test]
    fn validate_block_time_rejects_exceeding_max_interval() {
        let prev = dummy_header(10, 1_000);
        let curr = dummy_header(11, 1_000 + 30_001); // 超出 1ms
        let err = validate_block_time(Some(&prev), &curr, &default_config()).unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::BlockTimestampIntervalExceeded { .. }
        ));
    }

    // ===== SubTask 11.3: 超时判定函数测试 =====

    #[test]
    fn is_turn_timeout_false_within_window() {
        let cfg = default_config();
        // last_action=100, current=130, turn_timeout=30 → 130 > 100+30=130 → false（SEC2-L6 包含边界）
        assert!(!is_turn_timeout(100, 130, &cfg));
    }

    #[test]
    fn is_turn_timeout_true_beyond_window() {
        let cfg = default_config();
        // last_action=100, current=131, turn_timeout=30 → 131 > 130 → true
        assert!(is_turn_timeout(100, 131, &cfg));
    }

    #[test]
    fn is_validator_timeout_false_within_window() {
        let cfg = default_config();
        // game_validator_timeout=50
        assert!(!is_validator_timeout(100, 150, &cfg));
    }

    #[test]
    fn is_validator_timeout_true_beyond_window() {
        let cfg = default_config();
        assert!(is_validator_timeout(100, 151, &cfg));
    }

    #[test]
    fn is_hand_timeout_false_within_window() {
        let cfg = default_config();
        // hand_max_duration=300
        assert!(!is_hand_timeout(100, 400, &cfg));
    }

    #[test]
    fn is_hand_timeout_true_beyond_window() {
        let cfg = default_config();
        assert!(is_hand_timeout(100, 401, &cfg));
    }

    #[test]
    fn is_da_window_passed_false_within_window() {
        let cfg = default_config();
        // da_window=500
        assert!(!is_da_window_passed(100, 600, &cfg));
    }

    #[test]
    fn is_da_window_passed_true_beyond_window() {
        let cfg = default_config();
        assert!(is_da_window_passed(100, 601, &cfg));
    }

    #[test]
    fn is_dispute_window_passed_false_within_window() {
        let cfg = default_config();
        // dispute_window=200
        assert!(!is_dispute_window_passed(100, 300, &cfg));
    }

    #[test]
    fn is_dispute_window_passed_true_beyond_window() {
        let cfg = default_config();
        assert!(is_dispute_window_passed(100, 301, &cfg));
    }

    #[test]
    fn should_submit_checkpoint_false_before_interval() {
        let cfg = default_config();
        // checkpoint_interval=100
        // last=100, current=199 → 199 < 100+100=200 → false
        assert!(!should_submit_checkpoint(100, 199, &cfg));
    }

    #[test]
    fn should_submit_checkpoint_true_at_interval() {
        let cfg = default_config();
        // last=100, current=200 → 200 >= 200 → true
        assert!(should_submit_checkpoint(100, 200, &cfg));
    }

    // ===== SubTask 11.3: epoch 边界判定测试 =====

    #[test]
    fn is_epoch_boundary_at_multiples() {
        let cfg = default_config();
        // epoch_length=1000
        assert!(is_epoch_boundary(0, &cfg));
        assert!(is_epoch_boundary(1000, &cfg));
        assert!(is_epoch_boundary(2000, &cfg));
        assert!(!is_epoch_boundary(999, &cfg));
        assert!(!is_epoch_boundary(1001, &cfg));
    }

    #[test]
    fn epoch_of_correct_computation() {
        let cfg = default_config();
        assert_eq!(epoch_of(0, &cfg), 0);
        assert_eq!(epoch_of(999, &cfg), 0);
        assert_eq!(epoch_of(1000, &cfg), 1);
        assert_eq!(epoch_of(1999, &cfg), 1);
        assert_eq!(epoch_of(2000, &cfg), 2);
    }

    #[test]
    fn in_epoch_transition_window_true_near_boundary() {
        let cfg = default_config();
        // epoch_transition_window=10
        // height=991 → 距 epoch=1000 边界 9 <= 10 → true
        assert!(in_epoch_transition_window(991, &cfg));
        // height=990 → 距边界 10 <= 10 → true（包含边界）
        assert!(in_epoch_transition_window(990, &cfg));
    }

    #[test]
    fn in_epoch_transition_window_false_far_from_boundary() {
        let cfg = default_config();
        // height=989 → 距边界 11 > 10 → false
        assert!(!in_epoch_transition_window(989, &cfg));
        // height=500 → 距边界 500 > 10 → false
        assert!(!in_epoch_transition_window(500, &cfg));
    }

    #[test]
    fn in_epoch_transition_window_at_boundary() {
        let cfg = default_config();
        // height=1000 是 epoch 边界，距下一 epoch=2000 边界 1000 > 10 → false
        // 但 height=1000 本身已是新 epoch 起点，过渡窗口应在边界前
        // 边界前 10 block 内才算过渡窗口
        assert!(!in_epoch_transition_window(1000, &cfg));
        assert!(in_epoch_transition_window(1995, &cfg));
    }

    // ===== SubTask 11.5: 轻客户端 quorum 校验骨架测试 =====

    #[test]
    fn verify_block_header_quorum_ok_when_meets_threshold() {
        let header = dummy_header(1, 1_000);
        let request = LightClientVerifyRequest {
            header: &header,
            chain_id: crate::DEFAULT_CHAIN_ID,
            quorum_threshold: 5, // signer_count=5 >= 5
        };
        verify_block_header_quorum(&request).expect("quorum 满足应通过");
    }

    #[test]
    fn verify_block_header_quorum_rejects_when_below_threshold() {
        let header = dummy_header(1, 1_000);
        let request = LightClientVerifyRequest {
            header: &header,
            chain_id: crate::DEFAULT_CHAIN_ID,
            quorum_threshold: 6, // signer_count=5 < 6
        };
        let err = verify_block_header_quorum(&request).unwrap_err();
        assert!(matches!(err, PokerL1Error::InsufficientQuorum { .. }));
    }

    // ===== 配置序列化往返测试 =====

    #[test]
    fn config_bcs_roundtrip() {
        let cfg = TimeConsensusConfig::new();
        let bytes = borsh::to_vec(&cfg).unwrap();
        let recovered: TimeConsensusConfig = borsh::from_slice(&bytes).unwrap();
        assert_eq!(cfg, recovered);
    }

    #[test]
    fn config_json_roundtrip() {
        let cfg = TimeConsensusConfig::new();
        let json = serde_json::to_string(&cfg).unwrap();
        let recovered: TimeConsensusConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, recovered);
    }

    #[test]
    fn config_default_matches_new() {
        assert_eq!(TimeConsensusConfig::default(), TimeConsensusConfig::new());
    }

    // ===== Phase 4 Task 7: 多玩家阶段超时配置默认值测试 =====

    #[test]
    fn config_default_phase4_timeouts() {
        let cfg = TimeConsensusConfig::default();
        assert_eq!(cfg.shuffle_timeout_blocks, 100);
        assert_eq!(cfg.reveal_token_timeout_blocks, 50);
        assert_eq!(cfg.reconstruct_timeout_blocks, 100);
        // new() 与 default() 一致
        let cfg2 = TimeConsensusConfig::new();
        assert_eq!(cfg, cfg2);
    }

    // ===== Phase 4 Task 7.2 / 7.3: is_submit_phase_timed_out 测试 =====

    /// 构造测试用 GameStatus（仅 phase / phase_started_height 字段有意义，其余为默认值）。
    fn make_game_status(
        phase: crate::consensus::GamePhase,
        phase_started_height: u64,
    ) -> crate::consensus::GameStatus {
        use crate::consensus::{ExecutionMode, GameStatus};
        use crate::object_model::ObjectID;
        use crate::signature::TaggedPubkey;
        use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
        use std::collections::{BTreeMap, BTreeSet};

        let assigned_tp = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![0x02u8; 33],
        };
        GameStatus {
            id: ObjectID::new([0xAA; 20], 1),
            assigned_validator: assigned_tp,
            current_turn_player: [0x10; 20],
            active_participants: BTreeSet::from([[0x10; 20], [0x20; 20], [0x30; 20]]),
            player_nonce: BTreeMap::new(),
            last_action_height: 100,
            hand_start_height: 90,
            execution_mode: ExecutionMode::OnChain,
            is_finalized: false,
            phase,
            pending_submitters: BTreeSet::new(),
            phase_started_height,
            completed_submitters: BTreeSet::new(),
        }
    }

    #[test]
    fn is_submit_phase_timed_out_shuffle_just_timed_out() {
        // Shuffle 阶段恰好超时：current = phase_started + shuffle_timeout + 1 → Some(Shuffle)
        use crate::consensus::{GamePhase, SubmitPhaseKind};
        let cfg = default_config();
        // shuffle_timeout_blocks = 100
        let game = make_game_status(
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            1000,
        );
        // 边界：1000 + 100 = 1100，current=1100 不超时（`>` 严格大于）
        assert_eq!(is_submit_phase_timed_out(&game, 1100, &cfg), None);
        // 恰好超时：current=1101
        assert_eq!(
            is_submit_phase_timed_out(&game, 1101, &cfg),
            Some(SubmitPhaseKind::Shuffle)
        );
    }

    #[test]
    fn is_submit_phase_timed_out_shuffle_within_window() {
        // Shuffle 阶段未超时：current = phase_started + shuffle_timeout → None（边界不超时）
        use crate::consensus::{GamePhase, SubmitPhaseKind};
        let cfg = default_config();
        let game = make_game_status(
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            1000,
        );
        // current = 1000 + 100 = 1100，边界视为未超时
        assert_eq!(is_submit_phase_timed_out(&game, 1100, &cfg), None);
        // 更早的时间更不超时
        assert_eq!(is_submit_phase_timed_out(&game, 1050, &cfg), None);
        assert_eq!(is_submit_phase_timed_out(&game, 1000, &cfg), None);
    }

    #[test]
    fn is_submit_phase_timed_out_reveal_token_timed_out() {
        // RevealToken 阶段超时：current > phase_started + 50 → Some(RevealToken)
        use crate::consensus::{GamePhase, SubmitPhaseKind};
        let cfg = default_config();
        let game = make_game_status(
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::RevealToken,
            },
            2000,
        );
        // 边界：2000 + 50 = 2050，current=2050 不超时
        assert_eq!(is_submit_phase_timed_out(&game, 2050, &cfg), None);
        // current=2051 超时
        assert_eq!(
            is_submit_phase_timed_out(&game, 2051, &cfg),
            Some(SubmitPhaseKind::RevealToken)
        );
    }

    #[test]
    fn is_submit_phase_timed_out_reconstruct_timed_out() {
        // Reconstruct 阶段超时：current > phase_started + 100 → Some(Reconstruct)
        use crate::consensus::{GamePhase, SubmitPhaseKind};
        let cfg = default_config();
        let game = make_game_status(
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Reconstruct,
            },
            3000,
        );
        // 边界：3000 + 100 = 3100，current=3100 不超时
        assert_eq!(is_submit_phase_timed_out(&game, 3100, &cfg), None);
        // current=3101 超时
        assert_eq!(
            is_submit_phase_timed_out(&game, 3101, &cfg),
            Some(SubmitPhaseKind::Reconstruct)
        );
    }

    #[test]
    fn is_submit_phase_timed_out_leave_proof_never_times_out() {
        // LeaveProof 阶段从不超时：任何高度都返回 None
        use crate::consensus::{GamePhase, SubmitPhaseKind};
        let cfg = default_config();
        let game = make_game_status(
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::LeaveProof,
            },
            1000,
        );
        assert_eq!(is_submit_phase_timed_out(&game, 1000, &cfg), None);
        assert_eq!(is_submit_phase_timed_out(&game, 5000, &cfg), None);
        assert_eq!(is_submit_phase_timed_out(&game, u64::MAX, &cfg), None);
    }

    #[test]
    fn is_submit_phase_timed_out_betting_never_times_out() {
        // Betting 阶段从不走此超时：任何高度都返回 None
        use crate::consensus::{BettingRound, GamePhase};
        let cfg = default_config();
        let game = make_game_status(
            GamePhase::Betting {
                round: BettingRound::Preflop,
            },
            1000,
        );
        assert_eq!(is_submit_phase_timed_out(&game, 1000, &cfg), None);
        assert_eq!(is_submit_phase_timed_out(&game, 100_000, &cfg), None);
    }

    #[test]
    fn is_submit_phase_timed_out_overflow_returns_none() {
        // overflow 场景：phase_started_height + timeout_blocks 溢出 → 返回 None（保守不超时）
        use crate::consensus::{GamePhase, SubmitPhaseKind};
        let cfg = default_config();
        // 构造 phase_started_height = u64::MAX，任何 timeout_blocks > 0 都会溢出
        let game = make_game_status(
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            u64::MAX,
        );
        // shuffle_timeout_blocks = 100，u64::MAX + 100 溢出 → None
        assert_eq!(is_submit_phase_timed_out(&game, u64::MAX, &cfg), None);
        // RevealToken / Reconstruct 同理
        let game_rt = make_game_status(
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::RevealToken,
            },
            u64::MAX,
        );
        assert_eq!(is_submit_phase_timed_out(&game_rt, u64::MAX, &cfg), None);
        let game_rc = make_game_status(
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Reconstruct,
            },
            u64::MAX,
        );
        assert_eq!(is_submit_phase_timed_out(&game_rc, u64::MAX, &cfg), None);
    }

    #[test]
    fn is_submit_phase_timed_out_betting_all_rounds_no_timeout() {
        // 覆盖所有 BettingRound，确认下注阶段任意 round 都不超时
        use crate::consensus::{BettingRound, GamePhase};
        let cfg = default_config();
        for round in [
            BettingRound::Preflop,
            BettingRound::Flop,
            BettingRound::Turn,
            BettingRound::River,
            BettingRound::Showdown,
        ] {
            let game = make_game_status(GamePhase::Betting { round }, 100);
            assert_eq!(
                is_submit_phase_timed_out(&game, 1_000_000, &cfg),
                None,
                "Betting::{round:?} 不应超时"
            );
        }
    }
}
