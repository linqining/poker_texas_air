//! 游戏分配与 epoch 重分配（Task 12）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 12.1**：Game 创建时计算 `assigned_validator = validator_set[hash(G.id, current_epoch) % |V|]`
//!   （已在 [`crate::consensus::ValidatorSet::assigned_validator_for_game`] 实现）
//! - **SubTask 12.2**：客户端本地路由发现 `hash(game_id, epoch) % |validator_set|`，零延迟路由
//! - **SubTask 12.3**：epoch 边界自动重分配 + **NEW-M10** OffChain 模式 epoch 过渡协议：
//!   - (a) 操作方在 epoch 边界前 `epoch_transition_window_blocks`（默认 10）内必须提交一次 `checkpoint_anchor`（带 ack）
//!   - (b) 未提交过渡锚点 → 任意参与者触发 `force_advance` 或 `request_revert`
//!   - (c) `last_partial_fold` 状态保留，新 assigned_validator 接受后续 `partial_checkin` / `checkin`
//!   - (d) 过渡期间 `force_checkpoint` 的 `assigned_validator_failure_proof` 仅可指控一个 assigned_validator（旧或新）
//!   - **R4-H2**：由链上 `tx 提交时的 current_epoch` 权威决定
//!   - **SEC2-H3**：操作方未提交过渡锚点 → forfeit 保证金按比例扣除（最低 50%）；
//!     epoch 边界 ±窗口内 force_advance 须证明操作方未提交过渡锚点；
//!     新 assigned_validator 在窗口内不得接受 force_advance（除非附证据）
//! - **SubTask 12.4**：assigned_validator 失败自动接管：`game_validator_timeout_blocks`（默认 2，
//!   R4-L8 修正 — 原 3 与 turn_timeout_blocks 同值致竞争条件，降为 2 给 fallback tx 留处理窗口）
//!   内未提交含该 game 的 vertex，其他 validator 可在 vertex 中包含该 game 的 tx（DAG 冗余）

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::BlockHeight;
use crate::block::TimeConsensusConfig;
use crate::consensus::ValidatorSet;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;

/// 默认 game_validator_timeout_blocks（SubTask 12.4：R4-L8 修正，默认 2）。
pub const DEFAULT_GAME_VALIDATOR_TIMEOUT_BLOCKS: BlockHeight = 2;

/// 默认 forfeit 保证金扣除比例（SEC2-H3：最低 50%）。
pub const DEFAULT_FORFEIT_BOND_PERCENTAGE: u32 = 50;

/// 游戏分配配置（Task 12 可治理参数）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct GameAssignmentConfig {
    /// assigned_validator 失效超时 block 数（SubTask 12.4：默认 2，R4-L8 修正）。
    pub game_validator_timeout_blocks: BlockHeight,
    /// epoch 长度（block 数，SubTask 12.3）。
    pub epoch_length_blocks: BlockHeight,
    /// epoch 过渡窗口 block 数（NEW-M10：默认 10）。
    pub epoch_transition_window_blocks: BlockHeight,
    /// forfeit 保证金扣除比例（SEC2-H3：最低 50%）。
    pub forfeit_bond_percentage: u32,
}

impl Default for GameAssignmentConfig {
    fn default() -> Self {
        Self {
            game_validator_timeout_blocks: DEFAULT_GAME_VALIDATOR_TIMEOUT_BLOCKS,
            epoch_length_blocks: 1000,
            epoch_transition_window_blocks: 10,
            forfeit_bond_percentage: DEFAULT_FORFEIT_BOND_PERCENTAGE,
        }
    }
}

/// 客户端本地路由发现（SubTask 12.2）。
///
/// spec：`hash(game_id, epoch) % |validator_set|`，零延迟路由。
///
/// 客户端通过轻客户端获取权威 `current_epoch`（R4-H2），然后本地计算 assigned_validator，
/// 无需向链上查询 Game 对象即可路由 tx。
///
/// 注意：此函数与 [`ValidatorSet::assigned_validator_for_game`] 使用相同的哈希计算，
/// 但 `assigned_validator_for_game` 还绑定 `epoch_randomness`（更强安全性），
/// 客户端本地路由可使用简化版本（仅 `hash(game_id, epoch)`）作为预路由提示，
/// 最终由 validator 校验 `assigned_validator` 权威性。
pub fn client_route_validator(
    game_id: &crate::object_model::ObjectID,
    epoch: u64,
    validator_set: &ValidatorSet,
) -> PokerL1Result<TaggedPubkey> {
    let active: Vec<&crate::consensus::ValidatorEntry> = validator_set
        .validators
        .iter()
        .filter(|v| v.can_participate_consensus())
        .collect();
    if active.is_empty() {
        return Err(PokerL1Error::ValidatorSetTooSmallForOffChain { size: 0 });
    }
    // hash(game_id || epoch)
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&game_id.to_bytes());
    h.update(&epoch.to_le_bytes());
    let mut hash = [0u8; 32];
    h.finalize_variable(&mut hash).expect("32 <= 64");
    // 取前 8 字节作为 u64 索引
    let mut idx_bytes = [0u8; 8];
    idx_bytes.copy_from_slice(&hash[0..8]);
    // M-8 修复：先在 u64 上取模再转 usize，避免 32-bit 平台截断
    let idx = (u64::from_le_bytes(idx_bytes) % active.len() as u64) as usize;
    Ok(active[idx].pubkey.clone())
}

/// epoch 过渡锚点状态（NEW-M10）。
///
/// 追踪操作方在 epoch 边界前 `epoch_transition_window_blocks` 内是否提交了 `checkpoint_anchor`。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct EpochTransitionState {
    /// 过渡所属的 epoch（即将进入的新 epoch）。
    pub target_epoch: u64,
    /// 过渡窗口起始 height。
    pub window_start: BlockHeight,
    /// 过渡窗口结束 height（= epoch 边界）。
    pub window_end: BlockHeight,
    /// 是否已提交 checkpoint_anchor。
    pub anchor_submitted: bool,
    /// 提交锚点的 height（未提交为 0）。
    pub anchor_height: BlockHeight,
}

impl EpochTransitionState {
    /// 创建新过渡状态（epoch 边界前调用）。
    pub const fn new(
        target_epoch: u64,
        window_start: BlockHeight,
        window_end: BlockHeight,
    ) -> Self {
        Self {
            target_epoch,
            window_start,
            window_end,
            anchor_submitted: false,
            anchor_height: 0,
        }
    }

    /// 提交 checkpoint_anchor（NEW-M10 (a)）。
    pub fn submit_anchor(&mut self, current_height: BlockHeight) -> PokerL1Result<()> {
        if self.anchor_submitted {
            return Err(PokerL1Error::Other(
                "epoch transition anchor already submitted".to_string(),
            ));
        }
        if current_height < self.window_start || current_height > self.window_end {
            return Err(PokerL1Error::Other(format!(
                "checkpoint_anchor submitted outside transition window (current={}, window=[{},{}])",
                current_height, self.window_start, self.window_end
            )));
        }
        self.anchor_submitted = true;
        self.anchor_height = current_height;
        Ok(())
    }

    /// 判定是否未提交过渡锚点（NEW-M10 (b)）。
    pub const fn anchor_missing(&self, current_height: BlockHeight) -> bool {
        current_height >= self.window_end && !self.anchor_submitted
    }

    /// 判定 force_advance 是否被允许（SEC2-H3）。
    ///
    /// spec SEC2-H3：
    /// - epoch 边界 ±窗口内 force_advance 须证明操作方未提交过渡锚点
    /// - 新 assigned_validator 在窗口内不得接受 force_advance（除非附证据）
    ///
    /// 参数：
    /// - `current_height`：当前 block height
    /// - `has_proof`：是否附有"操作方未提交过渡锚点"的证据
    pub fn force_advance_allowed(
        &self,
        current_height: BlockHeight,
        has_proof: bool,
    ) -> PokerL1Result<bool> {
        // 窗口外：force_advance 按正常流程
        if current_height < self.window_start || current_height > self.window_end {
            return Ok(true);
        }
        // 窗口内：须证明操作方未提交过渡锚点
        if self.anchor_submitted {
            // 已提交锚点 → force_advance 不被允许（操作方已履行义务）
            return Ok(false);
        }
        // 未提交锚点 → force_advance 须附证据
        if !has_proof {
            return Err(PokerL1Error::Other(
                "SEC2-H3: force_advance during transition window requires proof of missing anchor"
                    .to_string(),
            ));
        }
        Ok(true)
    }
}

/// 计算 forfeit 保证金扣除金额（SEC2-H3）。
///
/// spec SEC2-H3：操作方未提交过渡锚点 → forfeit 保证金按比例扣除（最低 50%）。
///
/// M-3 修复：使用 `saturating_mul` 防止 u64 乘法溢出。
pub const fn compute_forfeit_amount(bond: u64, forfeit_percentage: u32) -> u64 {
    bond.saturating_mul(forfeit_percentage as u64) / 100
}

/// 判定 assigned_validator 是否失效（SubTask 12.4）。
///
/// spec：`game_validator_timeout_blocks`（默认 2）内未提交含该 game 的 vertex
/// → 其他 validator 可在 vertex 中包含该 game 的 tx（DAG 冗余）。
///
/// 参数：
/// - `last_vertex_with_game_height`：assigned_validator 最后一次提交含该 game 的 vertex 的 block height
/// - `current_height`：当前 block height
/// - `config`：游戏分配配置
pub const fn is_validator_failover_triggered(
    last_vertex_with_game_height: BlockHeight,
    current_height: BlockHeight,
    config: &GameAssignmentConfig,
) -> bool {
    current_height.saturating_sub(last_vertex_with_game_height)
        > config.game_validator_timeout_blocks
}

/// 计算给定 block height 所在的 epoch（R4-H2：链上权威判定）。
///
/// spec R4-H2：由链上 `tx 提交时的 current_epoch` 权威决定，
/// 非客户端本地判断 — 客户端通过轻客户端获取权威 current_epoch。
pub const fn compute_current_epoch(
    current_height: BlockHeight,
    epoch_length_blocks: BlockHeight,
) -> u64 {
    if epoch_length_blocks == 0 {
        return 0;
    }
    current_height / epoch_length_blocks
}

/// 判定给定 height 是否在 epoch 过渡窗口内（NEW-M10 + R4-H2）。
///
/// 过渡窗口 = epoch 边界前 `epoch_transition_window_blocks` 个 block。
pub const fn is_in_epoch_transition_window(
    current_height: BlockHeight,
    epoch_length_blocks: BlockHeight,
    epoch_transition_window_blocks: BlockHeight,
) -> bool {
    if epoch_length_blocks == 0 {
        return false;
    }
    let epoch_end = ((current_height / epoch_length_blocks) + 1) * epoch_length_blocks;
    epoch_end.saturating_sub(current_height) <= epoch_transition_window_blocks
}

/// 创建 epoch 过渡状态（SubTask 12.3）。
///
/// 在 epoch 边界前 `epoch_transition_window_blocks` 个 block 时调用，
/// 初始化过渡状态供后续校验 checkpoint_anchor 提交。
pub const fn create_epoch_transition_state(
    current_height: BlockHeight,
    config: &GameAssignmentConfig,
) -> EpochTransitionState {
    let current_epoch = compute_current_epoch(current_height, config.epoch_length_blocks);
    let target_epoch = current_epoch + 1;
    let window_end = target_epoch * config.epoch_length_blocks;
    let window_start = window_end.saturating_sub(config.epoch_transition_window_blocks);
    EpochTransitionState::new(target_epoch, window_start, window_end)
}

/// 校验 force_advance 在 epoch 过渡窗口内的合法性（SEC2-H3 + NEW-M10 (d)）。
///
/// spec：
/// - 窗口内 force_advance 须证明操作方未提交过渡锚点
/// - 新 assigned_validator 在窗口内不得接受 force_advance（除非附证据）
/// - 过渡期间 `force_checkpoint` 的 `assigned_validator_failure_proof` 仅可指控一个 assigned_validator（旧或新）
///
/// 参数：
/// - `transition_state`：epoch 过渡状态
/// - `current_height`：当前 block height
/// - `has_missing_anchor_proof`：是否附有"操作方未提交过渡锚点"的证据
/// - `accused_validator_count`：force_checkpoint 指控的 assigned_validator 数量
pub fn validate_force_advance_during_transition(
    transition_state: &EpochTransitionState,
    current_height: BlockHeight,
    has_missing_anchor_proof: bool,
    accused_validator_count: u32,
) -> PokerL1Result<()> {
    // NEW-M10 (d)：assigned_validator_failure_proof 仅可指控一个 assigned_validator
    if accused_validator_count > 1 {
        return Err(PokerL1Error::Other(format!(
            "NEW-M10(d): force_checkpoint may accuse at most 1 assigned_validator, got {}",
            accused_validator_count
        )));
    }

    // SEC2-H3：窗口内 force_advance 须证明操作方未提交过渡锚点
    let allowed =
        transition_state.force_advance_allowed(current_height, has_missing_anchor_proof)?;
    if !allowed {
        return Err(PokerL1Error::Other(
            "SEC2-H3: force_advance not allowed — anchor already submitted or no proof provided"
                .to_string(),
        ));
    }
    Ok(())
}

/// 从 TimeConsensusConfig 构造 GameAssignmentConfig（参数对齐）。
pub const fn config_from_time_consensus(time_config: &TimeConsensusConfig) -> GameAssignmentConfig {
    GameAssignmentConfig {
        game_validator_timeout_blocks: DEFAULT_GAME_VALIDATOR_TIMEOUT_BLOCKS,
        epoch_length_blocks: time_config.epoch_length_blocks,
        epoch_transition_window_blocks: time_config.epoch_transition_window_blocks,
        forfeit_bond_percentage: DEFAULT_FORFEIT_BOND_PERCENTAGE,
    }
}

/// 计算某 Game 在指定 epoch 的 assigned_validator（链上权威，SubTask 12.1）。
///
/// 此函数委托给 [`ValidatorSet::assigned_validator_for_game`]，
/// 使用 `hash(game_id || epoch || epoch_randomness) % |V_active|`（更强安全性，绑定 epoch_randomness）。
///
/// spec SubTask 12.1：`assigned_validator = validator_set[hash(G.id, current_epoch) % |V|]`，写入 Game 对象。
pub fn assign_validator_for_game(
    validator_set: &ValidatorSet,
    game_id: &crate::object_model::ObjectID,
) -> PokerL1Result<TaggedPubkey> {
    validator_set.assigned_validator_for_game(game_id)
}

/// 验证客户端本地路由与链上权威分配是否一致（SubTask 12.2 + R4-H2）。
///
/// spec：客户端本地路由发现 `hash(game_id, epoch) % |validator_set|`，
/// 链上权威使用 `hash(game_id || epoch || epoch_randomness) % |V_active|`（更强）。
///
/// 客户端本地路由仅作为预路由提示，最终由 validator 校验权威性。
/// 此函数用于 validator 校验客户端路由是否与链上一致。
pub fn validate_client_route_consistency(
    validator_set: &ValidatorSet,
    game_id: &crate::object_model::ObjectID,
    client_routed_validator: &TaggedPubkey,
) -> PokerL1Result<()> {
    let authoritative = assign_validator_for_game(validator_set, game_id)?;
    if &authoritative != client_routed_validator {
        return Err(PokerL1Error::NotAssignedValidator {
            game_id: *game_id,
            assigned: authoritative,
            receiver: client_routed_validator.clone(),
        });
    }
    Ok(())
}

/// 全局 epoch 重分配校验（SubTask 12.3）。
///
/// spec：epoch 边界（每 `epoch_length_blocks`）自动重分配所有活跃 Game。
/// 此函数校验给定 Game 的 assigned_validator 是否与当前 epoch 的权威分配一致。
///
/// 参数：
/// - `validator_set`：当前 ValidatorSet
/// - `game_id`：Game 对象 ID
/// - `game_recorded_validator`：Game 对象中记录的 assigned_validator
/// - `game_recorded_epoch`：Game 对象中记录的 epoch（创建/上次重分配时的 epoch）
/// - `current_epoch`：链上当前权威 epoch
pub fn validate_epoch_reassignment(
    validator_set: &ValidatorSet,
    game_id: &crate::object_model::ObjectID,
    game_recorded_validator: &TaggedPubkey,
    game_recorded_epoch: u64,
    current_epoch: u64,
) -> PokerL1Result<()> {
    // epoch 未变化 → 校验记录的 validator 仍有效
    if game_recorded_epoch == current_epoch {
        // 校验 game_recorded_validator 仍在当前 ValidatorSet 中且 Active
        let v = validator_set
            .find_validator(game_recorded_validator)
            .ok_or_else(|| PokerL1Error::ValidatorNotInSet(game_recorded_validator.clone()))?;
        if !v.can_participate_consensus() {
            return Err(PokerL1Error::Other(format!(
                "recorded assigned_validator not active (status={:?})",
                v.status
            )));
        }
        return Ok(());
    }

    // epoch 变化 → 校验 game_recorded_validator 是否与新 epoch 的权威分配一致
    // 注意：epoch 变化后，assigned_validator 可能改变（依赖 epoch_randomness）
    let new_authoritative = assign_validator_for_game(validator_set, game_id)?;
    if &new_authoritative != game_recorded_validator {
        return Err(PokerL1Error::Other(format!(
            "epoch reassignment required: game_recorded_epoch={}, current_epoch={}, \
             game_recorded_validator != new_authoritative",
            game_recorded_epoch, current_epoch
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::TimeConsensusConfig;
    use crate::consensus::validator_set::{
        ValidatorEntry, ValidatorStatus, compute_genesis_chain_randomness,
    };
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![byte; 33],
        }
    }

    fn make_vrf_pubkey(byte: u8) -> [u8; 33] {
        [byte; 33]
    }

    fn make_validator_set(count: usize) -> ValidatorSet {
        let validators: Vec<ValidatorEntry> = (0..count)
            .map(|i| {
                let mut v = ValidatorEntry::new(
                    make_tagged_pubkey(0x10 + i as u8),
                    make_vrf_pubkey(0x10 + i as u8),
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
        set
    }

    fn make_game_id(nonce: u64) -> crate::object_model::ObjectID {
        crate::object_model::ObjectID::new([0xBB; 20], nonce)
    }

    // ===== GameAssignmentConfig 测试 =====

    #[test]
    fn game_assignment_config_default() {
        let config = GameAssignmentConfig::default();
        assert_eq!(config.game_validator_timeout_blocks, 2);
        assert_eq!(config.epoch_length_blocks, 1000);
        assert_eq!(config.epoch_transition_window_blocks, 10);
        assert_eq!(config.forfeit_bond_percentage, 50);
    }

    #[test]
    fn config_from_time_consensus_aligns() {
        let tc = TimeConsensusConfig {
            epoch_length_blocks: 500,
            epoch_transition_window_blocks: 20,
            ..TimeConsensusConfig::default()
        };
        let config = config_from_time_consensus(&tc);
        assert_eq!(config.epoch_length_blocks, 500);
        assert_eq!(config.epoch_transition_window_blocks, 20);
    }

    // ===== client_route_validator 测试（SubTask 12.2） =====

    #[test]
    fn client_route_validator_deterministic() {
        let set = make_validator_set(5);
        let game_id = make_game_id(1);
        let v1 = client_route_validator(&game_id, 1, &set).expect("路由");
        let v2 = client_route_validator(&game_id, 1, &set).expect("路由");
        assert_eq!(v1, v2, "客户端路由必须确定性");
    }

    #[test]
    fn client_route_validator_changes_with_epoch() {
        let set = make_validator_set(5);
        let game_id = make_game_id(1);
        let v1 = client_route_validator(&game_id, 1, &set).expect("路由");
        let v2 = client_route_validator(&game_id, 2, &set).expect("路由");
        // epoch 变化可能改变路由（取决于 hash）
        // 仅验证不 panic，结果可能相同也可能不同
        let _ = (v1, v2);
    }

    #[test]
    fn client_route_validator_rejects_empty_validator_set() {
        let validators: Vec<ValidatorEntry> = vec![];
        let set = ValidatorSet {
            epoch: 1,
            validators,
            validator_set_hash: [0u8; 32],
            epoch_randomness: [0u8; 32],
            prev_epoch_randomness: [0u8; 32],
            genesis_chain_randomness: [0u8; 32],
        };
        let game_id = make_game_id(1);
        let err = client_route_validator(&game_id, 1, &set).unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::ValidatorSetTooSmallForOffChain { .. }
        ));
    }

    // ===== assign_validator_for_game 测试（SubTask 12.1） =====

    #[test]
    fn assign_validator_for_game_delegates_to_validator_set() {
        let set = make_validator_set(5);
        let game_id = make_game_id(1);
        let v1 = assign_validator_for_game(&set, &game_id).expect("分配");
        let v2 = set.assigned_validator_for_game(&game_id).expect("分配");
        assert_eq!(v1, v2, "assign_validator_for_game 应委托给 ValidatorSet");
    }

    // ===== validate_client_route_consistency 测试 =====

    #[test]
    fn validate_client_route_consistency_ok() {
        let set = make_validator_set(5);
        let game_id = make_game_id(1);
        let routed = assign_validator_for_game(&set, &game_id).expect("分配");
        validate_client_route_consistency(&set, &game_id, &routed).expect("应一致");
    }

    #[test]
    fn validate_client_route_consistency_rejects_mismatch() {
        let set = make_validator_set(5);
        let game_id = make_game_id(1);
        let wrong = make_tagged_pubkey(0xFF); // 不在 set 中
        let err = validate_client_route_consistency(&set, &game_id, &wrong).unwrap_err();
        assert!(matches!(err, PokerL1Error::NotAssignedValidator { .. }));
    }

    // ===== compute_current_epoch 测试（R4-H2） =====

    #[test]
    fn compute_current_epoch_at_boundaries() {
        // epoch_length=1000
        assert_eq!(compute_current_epoch(0, 1000), 0);
        assert_eq!(compute_current_epoch(999, 1000), 0);
        assert_eq!(compute_current_epoch(1000, 1000), 1);
        assert_eq!(compute_current_epoch(1999, 1000), 1);
        assert_eq!(compute_current_epoch(2000, 1000), 2);
    }

    #[test]
    fn compute_current_epoch_zero_length_returns_zero() {
        assert_eq!(compute_current_epoch(100, 0), 0);
    }

    // ===== is_in_epoch_transition_window 测试 =====

    #[test]
    fn is_in_epoch_transition_window_near_boundary() {
        // epoch_length=1000, window=10
        // epoch 1 边界在 height=1000，窗口 [990, 999]（边界前 10 block）
        assert!(!is_in_epoch_transition_window(989, 1000, 10));
        assert!(is_in_epoch_transition_window(990, 1000, 10));
        assert!(is_in_epoch_transition_window(999, 1000, 10));
        // 边界点：已进入新 epoch，下一个边界在 2000（1000 block 外），不在窗口内
        assert!(!is_in_epoch_transition_window(1000, 1000, 10));
    }

    #[test]
    fn is_in_epoch_transition_window_zero_length_returns_false() {
        assert!(!is_in_epoch_transition_window(100, 0, 10));
    }

    // ===== EpochTransitionState 测试（NEW-M10） =====

    #[test]
    fn epoch_transition_state_new() {
        let state = EpochTransitionState::new(2, 990, 1000);
        assert_eq!(state.target_epoch, 2);
        assert_eq!(state.window_start, 990);
        assert_eq!(state.window_end, 1000);
        assert!(!state.anchor_submitted);
        assert_eq!(state.anchor_height, 0);
    }

    #[test]
    fn epoch_transition_state_submit_anchor_within_window() {
        let mut state = EpochTransitionState::new(2, 990, 1000);
        state.submit_anchor(995).expect("窗口内提交应成功");
        assert!(state.anchor_submitted);
        assert_eq!(state.anchor_height, 995);
    }

    #[test]
    fn epoch_transition_state_submit_anchor_rejects_outside_window() {
        let mut state = EpochTransitionState::new(2, 990, 1000);
        // 早于窗口
        let err = state.submit_anchor(989).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
        // 晚于窗口
        let err = state.submit_anchor(1001).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn epoch_transition_state_submit_anchor_rejects_duplicate() {
        let mut state = EpochTransitionState::new(2, 990, 1000);
        state.submit_anchor(995).expect("首次提交");
        let err = state.submit_anchor(996).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn epoch_transition_state_anchor_missing_after_window() {
        let mut state = EpochTransitionState::new(2, 990, 1000);
        // 窗口内未提交
        assert!(!state.anchor_missing(995));
        // 窗口过期未提交
        assert!(state.anchor_missing(1000));
        // 提交后不再 missing
        state.submit_anchor(998).expect("提交");
        assert!(!state.anchor_missing(1000));
    }

    // ===== force_advance_allowed 测试（SEC2-H3） =====

    #[test]
    fn force_advance_allowed_outside_window() {
        let state = EpochTransitionState::new(2, 990, 1000);
        // 窗口外：无需证据
        assert!(state.force_advance_allowed(500, false).expect("应允许"));
        assert!(state.force_advance_allowed(1500, false).expect("应允许"));
    }

    #[test]
    fn force_advance_allowed_in_window_without_anchor_with_proof() {
        let state = EpochTransitionState::new(2, 990, 1000);
        // 窗口内、未提交锚点、有证据 → 允许
        assert!(state.force_advance_allowed(995, true).expect("应允许"));
    }

    #[test]
    fn force_advance_rejected_in_window_without_proof() {
        let state = EpochTransitionState::new(2, 990, 1000);
        // 窗口内、未提交锚点、无证据 → 拒绝
        let err = state.force_advance_allowed(995, false).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn force_advance_rejected_in_window_with_anchor_submitted() {
        let mut state = EpochTransitionState::new(2, 990, 1000);
        state.submit_anchor(995).expect("提交锚点");
        // 已提交锚点 → force_advance 不被允许
        let allowed = state
            .force_advance_allowed(996, true)
            .expect("应返回 false");
        assert!(!allowed, "已提交锚点时 force_advance 应被拒绝");
    }

    // ===== compute_forfeit_amount 测试（SEC2-H3） =====

    #[test]
    fn compute_forfeit_amount_50_percent() {
        let amount = compute_forfeit_amount(1_000_000, 50);
        assert_eq!(amount, 500_000);
    }

    #[test]
    fn compute_forfeit_amount_zero_bond() {
        let amount = compute_forfeit_amount(0, 50);
        assert_eq!(amount, 0);
    }

    // ===== is_validator_failover_triggered 测试（SubTask 12.4） =====

    #[test]
    fn is_validator_failover_triggered_after_timeout() {
        let config = GameAssignmentConfig::default();
        // game_validator_timeout_blocks=2
        // last_vertex=100, current=103 → 3 > 2 → 触发
        assert!(is_validator_failover_triggered(100, 103, &config));
        // last_vertex=100, current=102 → 2 == 2 → 未触发（> 而非 >=）
        assert!(!is_validator_failover_triggered(100, 102, &config));
    }

    #[test]
    fn is_validator_failover_triggered_saturating_sub() {
        let config = GameAssignmentConfig::default();
        // current < last_vertex → saturating_sub 为 0 → 不触发
        assert!(!is_validator_failover_triggered(200, 100, &config));
    }

    // ===== create_epoch_transition_state 测试 =====

    #[test]
    fn create_epoch_transition_state_at_correct_window() {
        let config = GameAssignmentConfig::default();
        // current_height=995, epoch_length=1000, window=10
        // current_epoch=0, target_epoch=1
        // window_end=1000, window_start=990
        let state = create_epoch_transition_state(995, &config);
        assert_eq!(state.target_epoch, 1);
        assert_eq!(state.window_start, 990);
        assert_eq!(state.window_end, 1000);
    }

    #[test]
    fn create_epoch_transition_state_at_second_epoch() {
        let config = GameAssignmentConfig::default();
        // current_height=1995, epoch_length=1000, window=10
        // current_epoch=1, target_epoch=2
        // window_end=2000, window_start=1990
        let state = create_epoch_transition_state(1995, &config);
        assert_eq!(state.target_epoch, 2);
        assert_eq!(state.window_start, 1990);
        assert_eq!(state.window_end, 2000);
    }

    // ===== validate_force_advance_during_transition 测试（SEC2-H3 + NEW-M10 (d)） =====

    #[test]
    fn validate_force_advance_rejects_multiple_accused_validators() {
        let state = EpochTransitionState::new(2, 990, 1000);
        // NEW-M10 (d)：仅可指控 1 个 assigned_validator
        let err = validate_force_advance_during_transition(&state, 995, true, 2).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn validate_force_advance_ok_with_single_accused_and_proof() {
        let state = EpochTransitionState::new(2, 990, 1000);
        validate_force_advance_during_transition(&state, 995, true, 1).expect("应通过");
    }

    #[test]
    fn validate_force_advance_rejects_without_proof_in_window() {
        let state = EpochTransitionState::new(2, 990, 1000);
        let err = validate_force_advance_during_transition(&state, 995, false, 1).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    // ===== validate_epoch_reassignment 测试（SubTask 12.3） =====

    #[test]
    fn validate_epoch_reassignment_ok_same_epoch() {
        let set = make_validator_set(5);
        let game_id = make_game_id(1);
        let assigned = assign_validator_for_game(&set, &game_id).expect("分配");
        // 同一 epoch → 校验 validator 仍 Active
        validate_epoch_reassignment(&set, &game_id, &assigned, 1, 1).expect("应通过");
    }

    #[test]
    fn validate_epoch_reassignment_rejects_inactive_validator() {
        let mut set = make_validator_set(5);
        let game_id = make_game_id(1);
        let assigned = assign_validator_for_game(&set, &game_id).expect("分配");
        // 将 assigned validator 设为 Bonding
        let idx = set
            .validators
            .iter()
            .position(|v| v.pubkey == assigned)
            .unwrap();
        set.validators[idx].status = ValidatorStatus::Bonding;
        let err = validate_epoch_reassignment(&set, &game_id, &assigned, 1, 1).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn validate_epoch_reassignment_rejects_validator_not_in_set() {
        let set = make_validator_set(5);
        let game_id = make_game_id(1);
        let unknown = make_tagged_pubkey(0xFF);
        let err = validate_epoch_reassignment(&set, &game_id, &unknown, 1, 1).unwrap_err();
        assert!(matches!(err, PokerL1Error::ValidatorNotInSet(_)));
    }

    // ===== 序列化往返测试 =====

    #[test]
    fn game_assignment_config_bcs_roundtrip() {
        let config = GameAssignmentConfig::default();
        let bytes = borsh::to_vec(&config).unwrap();
        let recovered: GameAssignmentConfig = borsh::from_slice(&bytes).unwrap();
        assert_eq!(config, recovered);
    }

    #[test]
    fn epoch_transition_state_bcs_roundtrip() {
        let state = EpochTransitionState::new(2, 990, 1000);
        let bytes = borsh::to_vec(&state).unwrap();
        let recovered: EpochTransitionState = borsh::from_slice(&bytes).unwrap();
        assert_eq!(state, recovered);
    }
}
