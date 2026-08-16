//! Slashing 与审查调查（Task 13 — SubTask 13.2 / 13.3 / 13.4 / 13.5）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 13.2 — vertex equivocation slashing**：
//!   - **NEW-M15**：`slash_amount = stake * slash_percentage / 100`，`slash_percentage` 默认 100%（全额罚没，可治理）
//!   - **SEC2-H2 — 多重 slashing 处理规则**：扣除基数 = 剩余质押（非原始）；
//!     优先级：vertex equivocation > commit cert equivocation > 拒收 checkpoint > 停机 > refuse_ack；
//!     每项扣除 = 剩余 * slash_percentage / 100；质押耗尽转欠款记录；受害者补偿按优先级分配
//! - **SubTask 13.3 — 停机 slashing**：
//!   - 连续 `downtime_threshold_blocks`（默认 100）未提交任何 vertex → 治理踢出
//!   - **NEW-L2**：停机 validator 罚没 `downtime_slash_percentage`（默认 10%）保证金 + 失去出块资格
//!   - **SEC-M1**：连续 `downtime_threshold_blocks + 2 * epoch_length_blocks` 未提交任何 vertex
//!     → 自动 slashing `downtime_slash_percentage`（无需治理介入），治理仅用于争议申辩
//! - **SubTask 13.4 — 审查缓解**：force_* tx 任何 validator 必须接受并装入 vertex；
//!   审查证据可作治理踢出依据
//! - **SubTask 13.5 — 审查调查流程（NEW-H1）**：
//!   - `force_checkpoint` 触发 assigned_validator 标记 `under_investigation` + `defense_window_blocks`（默认 50）防御窗口
//!   - 窗口内可提交"未收到证明"申辩免责
//!   - 窗口内无申辩或申辩无效 → 治理 slashing
//!   - 窗口内合理申辩 → 豁免 slashing 仅记录审查嫌疑
//!   - **R4-H5**：`under_investigation_count` 仅当申辩无效或无申辩时 +1（非"无论申辩是否成功 +1"）；
//!     衰减机制：每 epoch 衰减 1（最低为 0），防止历史指控永久累积

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::BlockHeight;
use crate::ChainId;
use crate::consensus::{DagCommitCertificate, DagVertex, Epoch, ValidatorSet};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::signature::unified::verify_signature;

/// 默认 slashing 百分比（NEW-M15：equivocation 全额罚没，可治理）。
pub const DEFAULT_SLASH_PERCENTAGE: u32 = 100;

/// 默认停机阈值 block 数（SubTask 13.3：连续 100 block 未提交 vertex → 治理踢出）。
pub const DEFAULT_DOWNTIME_THRESHOLD_BLOCKS: BlockHeight = 100;

/// 默认停机 slashing 百分比（NEW-L2：10%，由 5% 提升至 10% 以威慑协助审查的停机）。
pub const DEFAULT_DOWNTIME_SLASH_PERCENTAGE: u32 = 10;

/// 默认防御窗口 block 数（NEW-H1：force_checkpoint 触发后 validator 有 50 block 提交申辩）。
pub const DEFAULT_DEFENSE_WINDOW_BLOCKS: BlockHeight = 50;

/// Slashing 原因（SEC2-H2：优先级排序）。
///
/// 优先级（数字越小优先级越高）：
/// 1. `VertexEquivocation` — 同一 (epoch, round, author) 双签 vertex
/// 2. `CommitCertEquivocation` — 同一 (epoch, commit_round) 双签 commit certificate
/// 3. `RefuseCheckpoint` — 拒收 checkpoint（审查证据）
/// 4. `Downtime` — 停机
/// 5. `RefuseAck` — 拒绝 ACK
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
pub enum SlashingReason {
    /// vertex equivocation（最高优先级，SEC2-H2）。
    VertexEquivocation,
    /// commit certificate equivocation（SEC2-H2）。
    CommitCertEquivocation,
    /// 拒收 checkpoint（SubTask 13.4：审查证据）。
    RefuseCheckpoint,
    /// 停机（SubTask 13.3：SEC-M1 / NEW-L2）。
    Downtime,
    /// 拒绝 ACK（最低优先级）。
    RefuseAck,
}

impl SlashingReason {
    /// 获取优先级（数字越小优先级越高，SEC2-H2）。
    pub const fn priority(self) -> u8 {
        match self {
            Self::VertexEquivocation => 1,
            Self::CommitCertEquivocation => 2,
            Self::RefuseCheckpoint => 3,
            Self::Downtime => 4,
            Self::RefuseAck => 5,
        }
    }

    /// 获取该原因对应的默认 slash_percentage。
    ///
    /// - equivocation 类：100%（NEW-M15 全额罚没）
    /// - 停机：10%（NEW-L2）
    /// - 其他：100%（保守默认）
    pub const fn default_slash_percentage(self) -> u32 {
        match self {
            Self::VertexEquivocation
            | Self::CommitCertEquivocation
            | Self::RefuseCheckpoint
            | Self::RefuseAck => DEFAULT_SLASH_PERCENTAGE,
            Self::Downtime => DEFAULT_DOWNTIME_SLASH_PERCENTAGE,
        }
    }
}

/// Slashing 配置（可治理参数）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct SlashingConfig {
    /// equivocation 类 slashing 百分比（NEW-M15：默认 100%）。
    pub slash_percentage: u32,
    /// 停机阈值 block 数（SubTask 13.3：默认 100）。
    pub downtime_threshold_blocks: BlockHeight,
    /// 停机 slashing 百分比（NEW-L2：默认 10%）。
    pub downtime_slash_percentage: u32,
    /// 防御窗口 block 数（NEW-H1：默认 50）。
    pub defense_window_blocks: BlockHeight,
    /// epoch 长度（block 数，SEC-M1 自动 slashing 计算 = downtime_threshold + 2*epoch_length）。
    pub epoch_length_blocks: BlockHeight,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            slash_percentage: DEFAULT_SLASH_PERCENTAGE,
            downtime_threshold_blocks: DEFAULT_DOWNTIME_THRESHOLD_BLOCKS,
            downtime_slash_percentage: DEFAULT_DOWNTIME_SLASH_PERCENTAGE,
            defense_window_blocks: DEFAULT_DEFENSE_WINDOW_BLOCKS,
            epoch_length_blocks: 1000,
        }
    }
}

impl SlashingConfig {
    /// 计算 SEC-M1 自动 slashing 触发阈值。
    ///
    /// spec SEC-M1：连续 `downtime_threshold_blocks + 2 * epoch_length_blocks` 未提交 vertex → 自动 slashing。
    pub const fn auto_slash_threshold(&self) -> BlockHeight {
        self.downtime_threshold_blocks + 2 * self.epoch_length_blocks
    }
}

/// 计算 slash 金额（NEW-M15）。
///
/// `slash_amount = remaining_stake * slash_percentage / 100`
///
/// SEC2-H2：扣除基数 = 剩余质押（非原始质押），每项 slashing 基于当时剩余质押计算。
///
/// M-2 修复：使用 `saturating_mul` 防止 u64 乘法溢出。
pub const fn compute_slash_amount(remaining_stake: u64, slash_percentage: u32) -> u64 {
    remaining_stake.saturating_mul(slash_percentage as u64) / 100
}

/// 判定是否触发治理踢出（SubTask 13.3：连续 `downtime_threshold_blocks` 未提交 vertex）。
pub const fn is_downtime_governance_kickout(
    last_vertex_height: BlockHeight,
    current_height: BlockHeight,
    config: &SlashingConfig,
) -> bool {
    current_height.saturating_sub(last_vertex_height) >= config.downtime_threshold_blocks
}

/// 判定是否触发 SEC-M1 自动 slashing（连续 `downtime_threshold + 2*epoch_length` 未提交 vertex）。
pub const fn is_downtime_auto_slashable(
    last_vertex_height: BlockHeight,
    current_height: BlockHeight,
    config: &SlashingConfig,
) -> bool {
    current_height.saturating_sub(last_vertex_height) >= config.auto_slash_threshold()
}

/// 审查调查状态（NEW-H1 / R4-H5）。
///
/// `force_checkpoint` 触发 assigned_validator 进入调查状态：
/// - `defense_window_blocks` 内可提交"未收到证明"申辩
/// - 申辩成功 → 豁免 slashing，仅记录审查嫌疑
/// - 申辩失败或无申辩 → 治理 slashing
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct InvestigationState {
    /// 调查触发 block height（force_checkpoint 提交时的 block height）。
    pub triggered_at_height: BlockHeight,
    /// 防御窗口结束 height（triggered_at + defense_window_blocks）。
    pub defense_deadline: BlockHeight,
    /// 是否已提交申辩。
    pub defense_submitted: bool,
    /// 申辩是否有效（false = 无效或未申辩）。
    pub defense_valid: bool,
    /// 是否已 resolve（申辩成功或窗口过期后处理）。
    pub resolved: bool,
}

impl InvestigationState {
    /// 创建新调查状态（force_checkpoint 触发时调用）。
    pub const fn new(triggered_at_height: BlockHeight, config: &SlashingConfig) -> Self {
        Self {
            triggered_at_height,
            defense_deadline: triggered_at_height + config.defense_window_blocks,
            defense_submitted: false,
            defense_valid: false,
            resolved: false,
        }
    }

    /// 提交申辩（窗口内有效）。
    ///
    /// 返回 `Ok(())` 表示申辩已记录；`Err` 表示已超过窗口或已 resolve。
    pub fn submit_defense(&mut self, current_height: BlockHeight) -> PokerL1Result<()> {
        if self.resolved {
            return Err(PokerL1Error::Other(
                "investigation already resolved".to_string(),
            ));
        }
        if current_height > self.defense_deadline {
            return Err(PokerL1Error::Other(format!(
                "defense window expired (current={}, deadline={})",
                current_height, self.defense_deadline
            )));
        }
        self.defense_submitted = true;
        Ok(())
    }

    /// 评估申辩有效性并 resolve 调查。
    ///
    /// 参数：
    /// - `current_height`：当前 block height
    /// - `defense_valid`：申辩是否有效（由治理或验证逻辑判定）
    ///
    /// 返回 `Ok(should_slash)`：
    /// - `true`：申辩无效或未提交 → 治理 slashing
    /// - `false`：申辩有效 → 豁免 slashing
    pub fn resolve(
        &mut self,
        current_height: BlockHeight,
        defense_valid: bool,
    ) -> PokerL1Result<bool> {
        if self.resolved {
            return Err(PokerL1Error::Other(
                "investigation already resolved".to_string(),
            ));
        }
        // 窗口过期且未申辩 → 视为申辩无效
        if current_height > self.defense_deadline && !self.defense_submitted {
            self.defense_valid = false;
            self.resolved = true;
            return Ok(true); // 应 slashing
        }
        self.defense_valid = defense_valid;
        self.resolved = true;
        Ok(!defense_valid) // 申辩无效 → slashing
    }

    /// 判定申辩窗口是否已过期。
    pub const fn is_window_expired(&self, current_height: BlockHeight) -> bool {
        current_height > self.defense_deadline
    }
}

/// Slashing 执行结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SlashingResult {
    /// 被 slashing 的 validator pubkey。
    pub validator: TaggedPubkey,
    /// slashing 原因。
    pub reason: SlashingReason,
    /// 扣除前的剩余质押。
    pub stake_before: u64,
    /// 扣除金额。
    pub slash_amount: u64,
    /// 扣除后的剩余质押。
    pub stake_after: u64,
    /// 是否转为欠款记录（stake_after == 0 且仍有应扣）。
    pub debt_recorded: bool,
}

/// 应用单次 slashing 到 ValidatorSet（SEC2-H2：扣除基数 = 剩余质押）。
///
/// spec NEW-M15 + SEC2-H2：
/// - `slash_amount = remaining_stake * slash_percentage / 100`
/// - 扣除后剩余质押 = remaining_stake - slash_amount
/// - 质押耗尽（remaining_stake < slash_amount）→ 全额扣除 + 转欠款记录
/// - validator 状态转为 Slashed
///
/// 参数：
/// - `validator_set`：可变 ValidatorSet 引用
/// - `validator_pubkey`：被 slashing 的 validator
/// - `reason`：slashing 原因（决定 slash_percentage）
/// - `config`：slashing 配置
pub fn apply_slashing(
    validator_set: &mut ValidatorSet,
    validator_pubkey: &TaggedPubkey,
    reason: SlashingReason,
    config: &SlashingConfig,
) -> PokerL1Result<SlashingResult> {
    let validator = validator_set
        .find_validator_mut(validator_pubkey)
        .ok_or_else(|| PokerL1Error::ValidatorNotInSet(validator_pubkey.clone()))?;

    // SEC2-H2：多重 slashing 须继续从剩余质押扣除；
    // 仅 Retired 状态（已退出且 VRF key 已销毁）不可再 slashing。
    if matches!(validator.status, crate::consensus::ValidatorStatus::Retired) {
        return Err(PokerL1Error::Other(format!(
            "validator retired, cannot be slashed (status={:?})",
            validator.status
        )));
    }

    let stake_before = validator.stake;
    let slash_percentage = match reason {
        SlashingReason::Downtime => config.downtime_slash_percentage,
        _ => config.slash_percentage,
    };
    let slash_amount = compute_slash_amount(stake_before, slash_percentage);
    let (stake_after, debt_recorded) = if stake_before >= slash_amount {
        (stake_before - slash_amount, false)
    } else {
        // 质押耗尽 → 全额扣除 + 转欠款记录（SEC2-H2）
        (0u64, true)
    };

    validator.stake = stake_after;
    // 标记为 Slashed（踢出 + 罚没）
    // 注意：停机类 slashing 保留出块资格剥夺但状态由治理决定
    if reason != SlashingReason::Downtime {
        // 使用 matches! 避免 const 不兼容问题（status 字段非 const 可写）
        validator.status = crate::consensus::ValidatorStatus::Slashed;
    }

    Ok(SlashingResult {
        validator: validator_pubkey.clone(),
        reason,
        stake_before,
        slash_amount,
        stake_after,
        debt_recorded,
    })
}

/// 多重 slashing 执行器（SEC2-H2：按优先级顺序处理）。
///
/// spec SEC2-H2：扣除基数 = 剩余质押（非原始）；优先级：
/// vertex equiv > commit cert equiv > refuse checkpoint > downtime > refuse_ack；
/// 每项扣除 = 剩余 * slash_percentage / 100。
///
/// 参数：
/// - `validator_set`：可变 ValidatorSet
/// - `validator_pubkey`：被 slashing 的 validator
/// - `reasons`：slashing 原因列表（将按优先级排序后依次执行）
/// - `config`：slashing 配置
///
/// 返回每项 slashing 的结果列表（按优先级排序）。
pub fn apply_multi_slashing(
    validator_set: &mut ValidatorSet,
    validator_pubkey: &TaggedPubkey,
    mut reasons: Vec<SlashingReason>,
    config: &SlashingConfig,
) -> PokerL1Result<Vec<SlashingResult>> {
    // 按优先级排序（数字越小优先级越高）
    reasons.sort_by_key(|r| r.priority());

    let mut results = Vec::with_capacity(reasons.len());
    for reason in reasons {
        // 每次 slashing 基于当时剩余质押计算
        let result = apply_slashing(validator_set, validator_pubkey, reason, config)?;
        // 若质押已耗尽，后续 slashing 仍记录但金额为 0（转欠款）
        let debt_recorded = result.debt_recorded && result.stake_after == 0;
        results.push(result);
        let _ = debt_recorded; // 继续处理剩余原因（记录欠款），但金额为 0
    }
    Ok(results)
}

/// vertex equivocation 证据（SubTask 13.2 + 缺口 #1-路径C：接通签名验证）。
///
/// spec：提交两个冲突 vertex + 两个签名证据 → 踢出 + 罚没保证金。
///
/// 缺口 #1-路径C（Q3 同意破坏性 schema 变更）：此前只存 `vertex_hash_1/2` 与原始签名，
/// 无法重算签名对象（vertex `signing_hash` 还需 chain_id + parent_hashes）。
/// 现改为携带两个完整 [`DagVertex`]，使 [`validate`] 能严格重算 `signing_hash(chain_id)`
/// 并调用 [`verify_signature`] 校验两个签名确由 `author` 对两个不同 vertex 签出。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct VertexEquivocationEvidence {
    /// 链 ID（SEC-L4：进入 vertex `signing_hash`，重算签名对象所必需）。
    pub chain_id: ChainId,
    /// epoch（SEC-C1：绑定 epoch 防 equivocation 证据歧义）。
    pub epoch: Epoch,
    /// DAG round（同一 round 双签构成 equivocation）。
    pub round: u64,
    /// validator pubkey（author，签名验证的公钥）。
    pub author: TaggedPubkey,
    /// 第一个完整 vertex（含 parent_hashes，供严格重算 signing_hash）。
    pub vertex_1: DagVertex,
    /// 第二个完整 vertex（必须与 vertex_1 同 epoch+round+author 但 vertex_hash 不同）。
    pub vertex_2: DagVertex,
}

impl VertexEquivocationEvidence {
    /// 校验证据有效性（缺口 #1-路径C：接通真实验签）。
    ///
    /// 校验项：
    /// 1. 两个 vertex 同 epoch + round + author
    /// 2. 两个 vertex_hash 不同（构成 equivocation）
    /// 3. **签名验证**：`vertex_1.author_sig` 与 `vertex_2.author_sig` 各自是对
    ///    `vertex.signing_hash(chain_id)` 的有效签名，且公钥为 `self.author`
    ///    （调用 [`crate::signature::unified::verify_signature`]）
    pub fn validate(&self) -> PokerL1Result<()> {
        // 1. 同 epoch + round + author
        if self.vertex_1.epoch != self.epoch
            || self.vertex_2.epoch != self.epoch
            || self.vertex_1.round != self.round
            || self.vertex_2.round != self.round
        {
            return Err(PokerL1Error::Other(
                "vertex equivocation: epoch/round mismatch".to_string(),
            ));
        }
        if self.vertex_1.author_pubkey != self.author || self.vertex_2.author_pubkey != self.author
        {
            return Err(PokerL1Error::Other(
                "vertex equivocation: author_pubkey mismatch".to_string(),
            ));
        }
        // 2. vertex_hash 不同
        let h1 = self.vertex_1.vertex_hash();
        let h2 = self.vertex_2.vertex_hash();
        if h1 == h2 {
            return Err(PokerL1Error::Other(
                "vertex equivocation: vertex_hash_1 == vertex_hash_2 (not equivocation)"
                    .to_string(),
            ));
        }
        // 3. 签名验证：两个 author_sig 必须各自对 signing_hash(chain_id) 有效
        if self.vertex_1.author_sig.is_empty() || self.vertex_2.author_sig.is_empty() {
            return Err(PokerL1Error::Other(
                "vertex equivocation: signatures must not be empty".to_string(),
            ));
        }
        let signing_hash_1 = self.vertex_1.signing_hash(self.chain_id);
        let signing_hash_2 = self.vertex_2.signing_hash(self.chain_id);
        verify_signature(&self.author, &self.vertex_1.author_sig, &signing_hash_1).map_err(
            |_| {
                PokerL1Error::Other(
                    "vertex equivocation: signature_1 verification failed".to_string(),
                )
            },
        )?;
        verify_signature(&self.author, &self.vertex_2.author_sig, &signing_hash_2).map_err(
            |_| {
                PokerL1Error::Other(
                    "vertex equivocation: signature_2 verification failed".to_string(),
                )
            },
        )?;
        Ok(())
    }

    /// 第一个 vertex hash（便捷访问）。
    pub fn vertex_hash_1(&self) -> crate::Hash {
        self.vertex_1.vertex_hash()
    }

    /// 第二个 vertex hash（便捷访问）。
    pub fn vertex_hash_2(&self) -> crate::Hash {
        self.vertex_2.vertex_hash()
    }

    /// 构造 slashing 原因。
    pub const fn to_reason(&self) -> SlashingReason {
        SlashingReason::VertexEquivocation
    }
}

/// commit certificate equivocation 证据（SEC2-C1 + 缺口 #1-路径C：接通签名验证）。
///
/// spec：同 (epoch, commit_round) 双签 commit certificate → 踢出 + 罚没。
///
/// 缺口 #1-路径C（Q3 同意破坏性 schema 变更）：此前只存 `cert_hash_1/2`，**连 author 与
/// 签名字段都没有**。现改为携带两个完整 [`DagCommitCertificate`] + 矛盾 validator 的
/// pubkey（双签者）+ 其在两个 cert 中各自的签名，使 [`validate`] 能严格重算
/// `cert.signing_hash(chain_id)` 并验证该 validator 在两个不同 cert 上都签了名。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CommitCertEquivocationEvidence {
    /// 链 ID（进入 cert `signing_hash`，重算签名对象所必需）。
    pub chain_id: ChainId,
    /// epoch。
    pub epoch: Epoch,
    /// commit round（同一 commit_round 双签构成 equivocation）。
    pub commit_round: u64,
    /// 矛盾 validator（双签者）的 pubkey（签名验证的公钥）。
    pub author: TaggedPubkey,
    /// 该 validator 在 `cert_1` 中的签名（从 cert_1.signature_list 提取）。
    pub signature_1: Vec<u8>,
    /// 该 validator 在 `cert_2` 中的签名（从 cert_2.signature_list 提取）。
    pub signature_2: Vec<u8>,
    /// 第一个完整 commit certificate（供严格重算 signing_hash）。
    pub cert_1: DagCommitCertificate,
    /// 第二个完整 commit certificate（同 epoch+commit_round 但内容不同）。
    pub cert_2: DagCommitCertificate,
}

impl CommitCertEquivocationEvidence {
    /// 校验证据有效性（缺口 #1-路径C：接通真实验签）。
    ///
    /// 校验项：
    /// 1. 两个 cert 同 epoch + commit_round
    /// 2. 两个 cert_hash 不同（构成 equivocation）
    /// 3. `signature_1/2` 非空
    /// 4. **签名验证**：`signature_1` 是 author 对 `cert_1.signing_hash(chain_id)` 的
    ///    有效签名；`signature_2` 同理对 cert_2。
    pub fn validate(&self) -> PokerL1Result<()> {
        // 1. 同 epoch + commit_round
        if self.cert_1.epoch != self.epoch
            || self.cert_2.epoch != self.epoch
            || self.cert_1.commit_round != self.commit_round
            || self.cert_2.commit_round != self.commit_round
        {
            return Err(PokerL1Error::Other(
                "commit cert equivocation: epoch/commit_round mismatch".to_string(),
            ));
        }
        // 2. cert_hash 不同
        if self.cert_1.cert_hash(self.chain_id) == self.cert_2.cert_hash(self.chain_id) {
            return Err(PokerL1Error::Other(
                "commit cert equivocation: cert_hash_1 == cert_hash_2 (not equivocation)"
                    .to_string(),
            ));
        }
        // 3. 签名非空
        if self.signature_1.is_empty() || self.signature_2.is_empty() {
            return Err(PokerL1Error::Other(
                "commit cert equivocation: signatures must not be empty".to_string(),
            ));
        }
        // 4. 签名验证
        let signing_hash_1 = self.cert_1.signing_hash(self.chain_id);
        let signing_hash_2 = self.cert_2.signing_hash(self.chain_id);
        verify_signature(&self.author, &self.signature_1, &signing_hash_1).map_err(|_| {
            PokerL1Error::Other(
                "commit cert equivocation: signature_1 verification failed".to_string(),
            )
        })?;
        verify_signature(&self.author, &self.signature_2, &signing_hash_2).map_err(|_| {
            PokerL1Error::Other(
                "commit cert equivocation: signature_2 verification failed".to_string(),
            )
        })?;
        Ok(())
    }

    /// 第一个 cert hash（便捷访问）。
    pub fn cert_hash_1(&self) -> crate::Hash {
        self.cert_1.cert_hash(self.chain_id)
    }

    /// 第二个 cert hash（便捷访问）。
    pub fn cert_hash_2(&self) -> crate::Hash {
        self.cert_2.cert_hash(self.chain_id)
    }

    /// 构造 slashing 原因。
    pub const fn to_reason(&self) -> SlashingReason {
        SlashingReason::CommitCertEquivocation
    }
}

/// 检查 validator 是否处于停机状态并返回对应 slashing 原因（SubTask 13.3）。
///
/// 返回：
/// - `Ok(Some(SlashingReason::Downtime))`：触发自动 slashing（SEC-M1）
/// - `Ok(None)`：未触发 slashing（但可能已触发治理踢出，由调用方检查 `is_downtime_governance_kickout`）
pub fn check_downtime_slashing(
    validator_set: &ValidatorSet,
    validator_pubkey: &TaggedPubkey,
    current_height: BlockHeight,
    config: &SlashingConfig,
) -> PokerL1Result<Option<SlashingReason>> {
    let validator = validator_set
        .find_validator(validator_pubkey)
        .ok_or_else(|| PokerL1Error::ValidatorNotInSet(validator_pubkey.clone()))?;

    if !validator.can_be_slashed() {
        return Ok(None);
    }

    // SEC-M1：连续 downtime_threshold + 2*epoch_length 未提交 vertex → 自动 slashing
    if is_downtime_auto_slashable(validator.last_vertex_height, current_height, config) {
        return Ok(Some(SlashingReason::Downtime));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
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

    // ===== SlashingReason 优先级测试 =====

    #[test]
    fn slashing_reason_priority_order() {
        assert!(
            SlashingReason::VertexEquivocation.priority()
                < SlashingReason::CommitCertEquivocation.priority()
        );
        assert!(
            SlashingReason::CommitCertEquivocation.priority()
                < SlashingReason::RefuseCheckpoint.priority()
        );
        assert!(SlashingReason::RefuseCheckpoint.priority() < SlashingReason::Downtime.priority());
        assert!(SlashingReason::Downtime.priority() < SlashingReason::RefuseAck.priority());
    }

    #[test]
    fn slashing_reason_default_slash_percentage() {
        assert_eq!(
            SlashingReason::VertexEquivocation.default_slash_percentage(),
            100
        );
        assert_eq!(
            SlashingReason::CommitCertEquivocation.default_slash_percentage(),
            100
        );
        assert_eq!(
            SlashingReason::RefuseCheckpoint.default_slash_percentage(),
            100
        );
        assert_eq!(SlashingReason::Downtime.default_slash_percentage(), 10);
        assert_eq!(SlashingReason::RefuseAck.default_slash_percentage(), 100);
    }

    // ===== compute_slash_amount 测试 =====

    #[test]
    fn compute_slash_amount_full() {
        // 100% 罚没
        let amount = compute_slash_amount(1_000_000, 100);
        assert_eq!(amount, 1_000_000);
    }

    #[test]
    fn compute_slash_amount_ten_percent() {
        // 10% 罚没
        let amount = compute_slash_amount(1_000_000, 10);
        assert_eq!(amount, 100_000);
    }

    #[test]
    fn compute_slash_amount_zero_stake() {
        let amount = compute_slash_amount(0, 100);
        assert_eq!(amount, 0);
    }

    #[test]
    fn compute_slash_amount_uses_remaining_not_original() {
        // SEC2-H2：扣除基数 = 剩余质押
        // 第一次扣除 100% 后剩余 0，第二次扣除应基于 0
        let after_first = compute_slash_amount(1_000_000, 100);
        assert_eq!(after_first, 1_000_000);
        let remaining = 1_000_000 - after_first;
        let after_second = compute_slash_amount(remaining, 100);
        assert_eq!(after_second, 0);
    }

    // ===== SlashingConfig 测试 =====

    #[test]
    fn slashing_config_default() {
        let config = SlashingConfig::default();
        assert_eq!(config.slash_percentage, 100);
        assert_eq!(config.downtime_threshold_blocks, 100);
        assert_eq!(config.downtime_slash_percentage, 10);
        assert_eq!(config.defense_window_blocks, 50);
        assert_eq!(config.epoch_length_blocks, 1000);
    }

    #[test]
    fn slashing_config_auto_slash_threshold() {
        let config = SlashingConfig::default();
        // SEC-M1：downtime_threshold + 2 * epoch_length = 100 + 2000 = 2100
        assert_eq!(config.auto_slash_threshold(), 2100);
    }

    // ===== 停机判定测试 =====

    #[test]
    fn is_downtime_governance_kickout_at_threshold() {
        let config = SlashingConfig::default();
        // 刚好达到阈值 → 触发治理踢出
        assert!(is_downtime_governance_kickout(100, 200, &config));
        // 未达到阈值
        assert!(!is_downtime_governance_kickout(100, 199, &config));
    }

    #[test]
    fn is_downtime_auto_slashable_at_threshold() {
        let config = SlashingConfig::default();
        // SEC-M1：连续 2100 block 未提交 → 自动 slashing
        assert!(is_downtime_auto_slashable(100, 2200, &config));
        // 未达到自动 slashing 阈值（仅治理踢出）
        assert!(!is_downtime_auto_slashable(100, 2000, &config));
    }

    #[test]
    fn is_downtime_auto_slashable_saturating_sub() {
        let config = SlashingConfig::default();
        // current < last_vertex → saturating_sub 为 0，不触发
        assert!(!is_downtime_auto_slashable(500, 100, &config));
    }

    // ===== apply_slashing 测试 =====

    #[test]
    fn apply_slashing_vertex_equivocation_full_slash() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        let config = SlashingConfig::default();

        let result = apply_slashing(
            &mut set,
            &target,
            SlashingReason::VertexEquivocation,
            &config,
        )
        .expect("slashing 应成功");

        assert_eq!(result.reason, SlashingReason::VertexEquivocation);
        assert_eq!(result.stake_before, 1_000_000);
        assert_eq!(result.slash_amount, 1_000_000); // 100%
        assert_eq!(result.stake_after, 0);
        assert!(!result.debt_recorded); // 刚好耗尽，无欠款
        assert_eq!(set.validators[0].status, ValidatorStatus::Slashed);
        assert_eq!(set.validators[0].stake, 0);
    }

    #[test]
    fn apply_slashing_downtime_ten_percent() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        let config = SlashingConfig::default();

        let result = apply_slashing(&mut set, &target, SlashingReason::Downtime, &config)
            .expect("停机 slashing 应成功");

        assert_eq!(result.slash_amount, 100_000); // 10%
        assert_eq!(result.stake_after, 900_000);
        // 停机类不立即标记 Slashed（保留治理申辩权）
        assert_eq!(set.validators[0].status, ValidatorStatus::Active);
        assert_eq!(set.validators[0].stake, 900_000);
    }

    #[test]
    fn apply_slashing_allows_already_slashed_for_multi_slashing() {
        // SEC2-H2：多重 slashing 须继续从剩余质押扣除
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        // 模拟第一次 slashing 后的状态：status=Slashed, stake=500_000
        set.validators[0].status = ValidatorStatus::Slashed;
        set.validators[0].stake = 500_000;
        let config = SlashingConfig::default();

        let result = apply_slashing(
            &mut set,
            &target,
            SlashingReason::CommitCertEquivocation,
            &config,
        )
        .expect("已 Slashed 的 validator 应可继续 slashing（SEC2-H2）");
        assert_eq!(result.stake_before, 500_000);
        assert_eq!(result.slash_amount, 500_000); // 100% of remaining
        assert_eq!(result.stake_after, 0);
    }

    #[test]
    fn apply_slashing_rejects_retired() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        set.validators[0].status = ValidatorStatus::Retired;
        let config = SlashingConfig::default();

        let err = apply_slashing(
            &mut set,
            &target,
            SlashingReason::VertexEquivocation,
            &config,
        )
        .unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn apply_slashing_rejects_validator_not_in_set() {
        let mut set = make_validator_set(5);
        let unknown = make_tagged_pubkey(0xFF);
        let config = SlashingConfig::default();

        let err = apply_slashing(
            &mut set,
            &unknown,
            SlashingReason::VertexEquivocation,
            &config,
        )
        .unwrap_err();
        assert!(matches!(err, PokerL1Error::ValidatorNotInSet(_)));
    }

    #[test]
    fn apply_slashing_debt_when_stake_insufficient() {
        let mut set = make_validator_set(5);
        // 将 stake 设为很小，使 slash_amount > stake
        set.validators[0].stake = 50;
        let target = set.validators[0].pubkey.clone();
        let config = SlashingConfig::default();

        let result = apply_slashing(
            &mut set,
            &target,
            SlashingReason::VertexEquivocation,
            &config,
        )
        .expect("slashing 应成功");

        // stake=50, slash_percentage=100% → slash_amount=50, 但 stake < amount → 全额扣除 + 欠款
        assert_eq!(result.stake_before, 50);
        assert_eq!(result.slash_amount, 50); // compute_slash_amount(50, 100) = 50
        assert_eq!(result.stake_after, 0);
        // stake_before (50) >= slash_amount (50) → 不转欠款
        assert!(!result.debt_recorded);
    }

    // ===== apply_multi_slashing 测试（SEC2-H2） =====

    #[test]
    fn apply_multi_slashing_processes_by_priority() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        let config = SlashingConfig::default();

        // 同时触发 vertex equiv + downtime + refuse_ack
        let reasons = vec![
            SlashingReason::RefuseAck,
            SlashingReason::Downtime,
            SlashingReason::VertexEquivocation,
        ];
        let results = apply_multi_slashing(&mut set, &target, reasons, &config)
            .expect("多重 slashing 应成功");

        // 按优先级排序后：vertex equiv (1) → downtime (4) → refuse_ack (5)
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].reason, SlashingReason::VertexEquivocation);
        assert_eq!(results[1].reason, SlashingReason::Downtime);
        assert_eq!(results[2].reason, SlashingReason::RefuseAck);

        // 第一次 vertex equiv 扣 100% → 剩余 0
        assert_eq!(results[0].stake_before, 1_000_000);
        assert_eq!(results[0].slash_amount, 1_000_000);
        assert_eq!(results[0].stake_after, 0);

        // 第二次 downtime 基于剩余 0 → 扣 0
        assert_eq!(results[1].stake_before, 0);
        assert_eq!(results[1].slash_amount, 0);

        // 第三次 refuse_ack 基于剩余 0 → 扣 0
        assert_eq!(results[2].stake_before, 0);
        assert_eq!(results[2].slash_amount, 0);
    }

    #[test]
    fn apply_multi_slashing_downtime_then_refuse_ack() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        let config = SlashingConfig::default();

        // downtime (10%) + refuse_ack (100%)
        let reasons = vec![SlashingReason::RefuseAck, SlashingReason::Downtime];
        let results = apply_multi_slashing(&mut set, &target, reasons, &config)
            .expect("多重 slashing 应成功");

        // 排序后：downtime (4) → refuse_ack (5)
        assert_eq!(results[0].reason, SlashingReason::Downtime);
        assert_eq!(results[1].reason, SlashingReason::RefuseAck);

        // downtime 扣 10% = 100_000，剩余 900_000
        assert_eq!(results[0].slash_amount, 100_000);
        assert_eq!(results[0].stake_after, 900_000);

        // refuse_ack 基于 900_000 扣 100% = 900_000
        assert_eq!(results[1].stake_before, 900_000);
        assert_eq!(results[1].slash_amount, 900_000);
        assert_eq!(results[1].stake_after, 0);
    }

    // ===== VertexEquivocationEvidence 测试（缺口 #1-路径C：真实签名） =====

    /// 构造一个 secp256k1 (secret, tagged_pubkey) 对。
    fn make_real_keypair(seed: u8) -> (secp256k1::SecretKey, TaggedPubkey) {
        use rand::rngs::OsRng;
        let secp = secp256k1::Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        for (i, b) in secret_bytes.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        // 确保标量合法（极低概率溢出，循环扰动直到合法）
        let secret = loop {
            match secp256k1::SecretKey::from_slice(&secret_bytes) {
                Ok(s) => break s,
                Err(_) => {
                    secret_bytes[31] = secret_bytes[31].wrapping_add(1);
                }
            }
        };
        let public = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let tagged = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            crate::signature::tagged_pubkey::CURRENT_VERSION,
            public.serialize().to_vec(),
        )
        .expect("tagged pubkey");
        (secret, tagged)
    }

    /// 用 secret 对 32B hash 做 recoverable ECDSA，返回 r||s||v（65B）。
    fn sign_hash(secret: &secp256k1::SecretKey, msg_hash: &[u8; 32]) -> Vec<u8> {
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest(*msg_hash);
        let sig = secp.sign_ecdsa_recoverable(&msg, secret);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut full = compact.to_vec();
        full.push(recovery_id.to_i32() as u8);
        full
    }

    /// 构造一个 DagVertex（author 用给定 tagged pubkey，含给定 parent_hashes），
    /// 用 secret 对 vertex.signing_hash(chain_id) 签名填入 author_sig。
    fn make_signed_vertex(
        secret: &secp256k1::SecretKey,
        author: TaggedPubkey,
        epoch: Epoch,
        round: u64,
        parent_hashes: Vec<crate::Hash>,
        chain_id: ChainId,
    ) -> DagVertex {
        let unsigned = DagVertex {
            epoch,
            round,
            author_pubkey: author,
            tx_list: vec![],
            parent_hashes: parent_hashes.clone(),
            author_sig: vec![],
        };
        let signing_hash = unsigned.signing_hash(chain_id);
        let sig = sign_hash(secret, &signing_hash);
        DagVertex {
            author_sig: sig,
            ..unsigned
        }
    }

    #[test]
    fn vertex_equivocation_evidence_validate_ok_with_real_sigs() {
        // 缺口 #1-路径C：两 vertex 同 epoch+round+author 但 parent_hashes 不同 → 不同
        // vertex_hash → 用同一 author 的 secret 分别签名 → 证据验签通过。
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let (secret, author) = make_real_keypair(0x10);
        let v1 = make_signed_vertex(&secret, author.clone(), 1, 10, vec![[0xAA; 32]], chain_id);
        let v2 = make_signed_vertex(&secret, author.clone(), 1, 10, vec![[0xBB; 32]], chain_id);
        assert_ne!(
            v1.vertex_hash(),
            v2.vertex_hash(),
            "parent 不同 → hash 不同"
        );
        let evidence = VertexEquivocationEvidence {
            chain_id,
            epoch: 1,
            round: 10,
            author,
            vertex_1: v1,
            vertex_2: v2,
        };
        evidence.validate().expect("真实双签证据应验签通过");
    }

    #[test]
    fn vertex_equivocation_evidence_rejects_same_vertex() {
        // 两个相同 vertex（vertex_hash 相同）→ 非 equivocation。
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let (secret, author) = make_real_keypair(0x11);
        let v1 = make_signed_vertex(&secret, author.clone(), 1, 10, vec![[0xAA; 32]], chain_id);
        let v2 = v1.clone();
        let evidence = VertexEquivocationEvidence {
            chain_id,
            epoch: 1,
            round: 10,
            author,
            vertex_1: v1,
            vertex_2: v2,
        };
        let err = evidence.validate().unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn vertex_equivocation_evidence_rejects_bad_signature() {
        // 第二个 vertex 的 author_sig 被篡改 → 验签失败。
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let (secret, author) = make_real_keypair(0x12);
        let v1 = make_signed_vertex(&secret, author.clone(), 1, 10, vec![[0xAA; 32]], chain_id);
        let mut v2 = make_signed_vertex(&secret, author.clone(), 1, 10, vec![[0xBB; 32]], chain_id);
        v2.author_sig[0] ^= 0xFF; // 篡改签名
        let evidence = VertexEquivocationEvidence {
            chain_id,
            epoch: 1,
            round: 10,
            author,
            vertex_1: v1,
            vertex_2: v2,
        };
        let err = evidence.validate().unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)), "篡改签名应拒绝");
    }

    #[test]
    fn vertex_equivocation_evidence_rejects_wrong_author() {
        // vertex_2 的 author 与证据 author 不一致（不同 validator 的 vertex）→ 拒绝。
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let (secret_a, author_a) = make_real_keypair(0x13);
        let (secret_b, author_b) = make_real_keypair(0x14);
        let v1 = make_signed_vertex(
            &secret_a,
            author_a.clone(),
            1,
            10,
            vec![[0xAA; 32]],
            chain_id,
        );
        // v2 用 author_b 签名，但证据 author 填 author_a
        let v2 = make_signed_vertex(&secret_b, author_b, 1, 10, vec![[0xBB; 32]], chain_id);
        let evidence = VertexEquivocationEvidence {
            chain_id,
            epoch: 1,
            round: 10,
            author: author_a,
            vertex_1: v1,
            vertex_2: v2,
        };
        let err = evidence.validate().unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)), "author 不一致应拒绝");
    }

    // ===== CommitCertEquivocationEvidence 测试（缺口 #1-路径C：真实签名） =====

    /// 构造一个 cert，由给定 (validator_idx, secret) 对 cert.signing_hash(chain_id) 签名。
    fn make_signed_cert(
        validator_idx: usize,
        validator_count: usize,
        secret: &secp256k1::SecretKey,
        vertex_hash_list: Vec<crate::Hash>,
        chain_id: ChainId,
    ) -> DagCommitCertificate {
        let cert = DagCommitCertificate {
            epoch: 1,
            commit_round: 5,
            prev_commit_hash: [0u8; 32],
            epoch_transition: None,
            vertex_hash_list,
            round_attendance_bitmap: vec![0xFF],
            state_root: [0x11; 32],
            account_root: [0x44; 32],
            public_tx_root: [0x22; 32],
            gameturn_tx_root: [0x33; 32],
            signature_list: vec![],
            signer_bitmap: vec![0u8; (validator_count + 7) / 8],
        };
        let signing_hash = cert.signing_hash(chain_id);
        let sig = sign_hash(secret, &signing_hash);
        crate::consensus::assemble_commit_certificate(
            1,
            5,
            [0u8; 32],
            cert.vertex_hash_list.clone(),
            cert.round_attendance_bitmap.clone(),
            cert.state_root,
            cert.account_root,
            cert.public_tx_root,
            cert.gameturn_tx_root,
            &[(validator_idx, sig)],
            validator_count,
        )
        .expect("assemble cert")
    }

    #[test]
    fn commit_cert_equivocation_evidence_validate_ok_with_real_sigs() {
        // 同一 validator 对两个不同 cert（不同 vertex_hash_list）签名 → equivocation。
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let (secret, tagged) = make_real_keypair(0x20);
        let cert1 = make_signed_cert(0, 3, &secret, vec![[0xAA; 32]], chain_id);
        let cert2 = make_signed_cert(0, 3, &secret, vec![[0xBB; 32]], chain_id);
        assert_ne!(
            cert1.cert_hash(chain_id),
            cert2.cert_hash(chain_id),
            "不同 vertex_hash_list → cert_hash 不同"
        );
        let evidence = CommitCertEquivocationEvidence {
            chain_id,
            epoch: 1,
            commit_round: 5,
            author: tagged,
            signature_1: cert1.signature_list[0].clone(),
            signature_2: cert2.signature_list[0].clone(),
            cert_1: cert1,
            cert_2: cert2,
        };
        evidence.validate().expect("真实双签 cert 证据应验签通过");
    }

    #[test]
    fn commit_cert_equivocation_evidence_rejects_identical_cert() {
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let (secret, tagged) = make_real_keypair(0x21);
        let cert1 = make_signed_cert(0, 3, &secret, vec![[0xAA; 32]], chain_id);
        let cert2 = cert1.clone();
        let evidence = CommitCertEquivocationEvidence {
            chain_id,
            epoch: 1,
            commit_round: 5,
            author: tagged,
            signature_1: cert1.signature_list[0].clone(),
            signature_2: cert2.signature_list[0].clone(),
            cert_1: cert1,
            cert_2: cert2,
        };
        let err = evidence.validate().unwrap_err();
        assert!(
            matches!(err, PokerL1Error::Other(_)),
            "相同 cert 非 equivocation"
        );
    }

    #[test]
    fn commit_cert_equivocation_evidence_rejects_bad_signature() {
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let (secret, tagged) = make_real_keypair(0x22);
        let cert1 = make_signed_cert(0, 3, &secret, vec![[0xAA; 32]], chain_id);
        let mut cert2 = make_signed_cert(0, 3, &secret, vec![[0xBB; 32]], chain_id);
        cert2.signature_list[0][0] ^= 0xFF; // 篡改第二签名
        let evidence = CommitCertEquivocationEvidence {
            chain_id,
            epoch: 1,
            commit_round: 5,
            author: tagged,
            signature_1: cert1.signature_list[0].clone(),
            signature_2: cert2.signature_list[0].clone(),
            cert_1: cert1,
            cert_2: cert2,
        };
        let err = evidence.validate().unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)), "篡改签名应拒绝");
    }

    // ===== check_downtime_slashing 测试 =====

    #[test]
    fn check_downtime_slashing_triggers_auto_slash() {
        let set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        let config = SlashingConfig::default();

        // last_vertex_height=100, current=2200 → 2100 block 未提交 → SEC-M1 自动 slashing
        // 注意：make_validator_set 中 last_vertex_height=0
        // 需要构造一个 last_vertex_height=100 的 set
        let mut set = set;
        set.validators[0].last_vertex_height = 100;

        let result = check_downtime_slashing(&set, &target, 2200, &config).expect("检查应成功");
        assert_eq!(result, Some(SlashingReason::Downtime));
    }

    #[test]
    fn check_downtime_slashing_no_trigger_below_threshold() {
        let mut set = make_validator_set(5);
        let target = set.validators[0].pubkey.clone();
        set.validators[0].last_vertex_height = 100;
        let config = SlashingConfig::default();

        // current=2000 → 1900 block 未提交，未达 2100 阈值
        let result = check_downtime_slashing(&set, &target, 2000, &config).expect("检查应成功");
        assert_eq!(result, None);
    }

    #[test]
    fn check_downtime_slashing_rejects_unknown_validator() {
        let set = make_validator_set(5);
        let unknown = make_tagged_pubkey(0xFF);
        let config = SlashingConfig::default();

        let err = check_downtime_slashing(&set, &unknown, 2200, &config).unwrap_err();
        assert!(matches!(err, PokerL1Error::ValidatorNotInSet(_)));
    }

    // ===== InvestigationState 测试（NEW-H1 / R4-H5） =====

    #[test]
    fn investigation_state_new() {
        let config = SlashingConfig::default();
        let state = InvestigationState::new(1000, &config);
        assert_eq!(state.triggered_at_height, 1000);
        assert_eq!(state.defense_deadline, 1050); // 1000 + 50
        assert!(!state.defense_submitted);
        assert!(!state.defense_valid);
        assert!(!state.resolved);
    }

    #[test]
    fn investigation_state_submit_defense_within_window() {
        let config = SlashingConfig::default();
        let mut state = InvestigationState::new(1000, &config);
        state.submit_defense(1020).expect("窗口内申辩应成功");
        assert!(state.defense_submitted);
        assert!(!state.resolved);
    }

    #[test]
    fn investigation_state_submit_defense_rejects_after_window() {
        let config = SlashingConfig::default();
        let mut state = InvestigationState::new(1000, &config);
        let err = state.submit_defense(1060).unwrap_err(); // > 1050
        assert!(matches!(err, PokerL1Error::Other(_)));
        assert!(!state.defense_submitted);
    }

    #[test]
    fn investigation_state_resolve_with_valid_defense() {
        let config = SlashingConfig::default();
        let mut state = InvestigationState::new(1000, &config);
        state.submit_defense(1020).expect("申辩");
        // 申辩有效 → 不 slashing
        let should_slash = state.resolve(1030, true).expect("resolve");
        assert!(!should_slash, "有效申辩不应 slashing");
        assert!(state.resolved);
        assert!(state.defense_valid);
    }

    #[test]
    fn investigation_state_resolve_with_invalid_defense() {
        let config = SlashingConfig::default();
        let mut state = InvestigationState::new(1000, &config);
        state.submit_defense(1020).expect("申辩");
        // 申辩无效 → slashing
        let should_slash = state.resolve(1030, false).expect("resolve");
        assert!(should_slash, "无效申辩应 slashing");
        assert!(state.resolved);
        assert!(!state.defense_valid);
    }

    #[test]
    fn investigation_state_resolve_no_defense_after_window() {
        let config = SlashingConfig::default();
        let mut state = InvestigationState::new(1000, &config);
        // 未提交申辩，窗口过期
        let should_slash = state.resolve(1060, false).expect("resolve");
        assert!(should_slash, "无申辩 + 窗口过期应 slashing");
        assert!(state.resolved);
    }

    #[test]
    fn investigation_state_resolve_rejects_already_resolved() {
        let config = SlashingConfig::default();
        let mut state = InvestigationState::new(1000, &config);
        state.resolve(1030, true).expect("首次 resolve");
        let err = state.resolve(1040, true).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn investigation_state_is_window_expired() {
        let config = SlashingConfig::default();
        let state = InvestigationState::new(1000, &config);
        assert!(!state.is_window_expired(1050)); // == deadline，未过期
        assert!(state.is_window_expired(1051)); // > deadline，过期
    }

    // ===== 序列化往返测试 =====

    #[test]
    fn slashing_reason_bcs_roundtrip() {
        for reason in [
            SlashingReason::VertexEquivocation,
            SlashingReason::CommitCertEquivocation,
            SlashingReason::RefuseCheckpoint,
            SlashingReason::Downtime,
            SlashingReason::RefuseAck,
        ] {
            let bytes = borsh::to_vec(&reason).unwrap();
            let recovered: SlashingReason = borsh::from_slice(&bytes).unwrap();
            assert_eq!(reason, recovered);
        }
    }

    #[test]
    fn slashing_config_bcs_roundtrip() {
        let config = SlashingConfig::default();
        let bytes = borsh::to_vec(&config).unwrap();
        let recovered: SlashingConfig = borsh::from_slice(&bytes).unwrap();
        assert_eq!(config, recovered);
    }

    #[test]
    fn vertex_equivocation_evidence_bcs_roundtrip() {
        // 缺口 #1-路径C：新 schema 携带两个完整 vertex 的 BCS 往返。
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let (secret, author) = make_real_keypair(0x30);
        let v1 = make_signed_vertex(&secret, author.clone(), 1, 10, vec![[0xAA; 32]], chain_id);
        let v2 = make_signed_vertex(&secret, author.clone(), 1, 10, vec![[0xBB; 32]], chain_id);
        let evidence = VertexEquivocationEvidence {
            chain_id,
            epoch: 1,
            round: 10,
            author,
            vertex_1: v1,
            vertex_2: v2,
        };
        let bytes = borsh::to_vec(&evidence).unwrap();
        let recovered: VertexEquivocationEvidence = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evidence, recovered);
    }

    #[test]
    fn investigation_state_bcs_roundtrip() {
        let config = SlashingConfig::default();
        let state = InvestigationState::new(1000, &config);
        let bytes = borsh::to_vec(&state).unwrap();
        let recovered: InvestigationState = borsh::from_slice(&bytes).unwrap();
        assert_eq!(state, recovered);
    }

    #[test]
    fn slashing_result_bcs_roundtrip() {
        let result = SlashingResult {
            validator: make_tagged_pubkey(0x10),
            reason: SlashingReason::VertexEquivocation,
            stake_before: 1_000_000,
            slash_amount: 1_000_000,
            stake_after: 0,
            debt_recorded: false,
        };
        let bytes = borsh::to_vec(&result).unwrap();
        let recovered: SlashingResult = borsh::from_slice(&bytes).unwrap();
        assert_eq!(result, recovered);
    }
}
