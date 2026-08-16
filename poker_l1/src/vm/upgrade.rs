//! 合约升级机制（Task 17 — SubTask 17.1~17.3a）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）的 SEC-L7 + SEC2-M11 要求：
//! - **SubTask 17.2**：升级 tx 提交新字节码 + UpgradeCap → 注册新版本，
//!   `contract_id` 不变，`version += 1`
//! - **SubTask 17.3**：旧版本字节码变为不可调用（通过
//!   [`ContractRegistry::activate_version`] 实现）
//! - **SubTask 17.3a**：
//!   - **SEC-L7 修复 — timelock 共识层强制**：
//!     (1) 升级 tx 进入 `upgrade_delay_blocks`（默认 2000）timelock，期间新版本仅注册不可调用，到期后自动生效
//!     (2) timelock 期间 UpgradeCap 持有者可 `cancel_upgrade`
//!     (3) timelock 期间任意参与者可 `dispute_upgrade` 触发治理冻结
//!     (4) 治理可将 `upgrade_delay_blocks` 设为 `u64::MAX` 实质冻结
//!     (5) 紧急升级须 90% validator quorum 通过专项提案绕过 timelock
//!   - **SEC2-M11 修复 — 紧急升级范围限制**：
//!     (1) 紧急升级须含 `critical_vulnerability_proof`
//!     (3) 生效后触发安全审计期 1000 blocks，期间可 `dispute_emergency_upgrade`
//!
//! ## 状态机
//!
//! ```text
//!   deploy ──► Idle ──initiate──► Pending ──commit(timelock到期)──► Idle
//!                ▲                    │
//!                │                    ├──cancel(-holder)──► Idle
//!                │                    └──dispute(任意)──► Frozen
//!                │
//!                └──emergency──► EmergencyAudit ──audit到期──► Idle
//!                                   │
//!                                   └──dispute_emergency──► EmergencyAudit{disputed=true}
//! ```

use crate::Address;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::ObjectID;
use crate::storage::{ObjectBackend, ObjectDb, ObjectDbSnapshot};
use crate::vm::contract::{
    ContractObject, ContractRegistry, ContractUpgradeState, MAX_CONTRACT_BYTECODE_SIZE,
    UpgradeState, contract_object, contract_upgrade_state_object, decode_contract_object,
    decode_contract_upgrade_state_object, is_contract_upgrade_state_object,
};

/// 升级配置。
///
/// 控制合约升级的 timelock 与紧急升级参数。
/// 由治理可调整（治理可将 `upgrade_delay_blocks` 设为 `u64::MAX` 实质冻结，
/// SEC-L7 (4)）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpgradeConfig {
    /// Timelock 延迟（默认 2000 blocks，SEC-L7 (1)）。
    ///
    /// 升级 tx 提交后须等待 `upgrade_delay_blocks` 个 block 才能生效。
    /// 治理可设为 `u64::MAX` 实质冻结该合约升级（SEC-L7 (4)）。
    pub upgrade_delay_blocks: u64,
    /// 紧急升级安全审计期（默认 1000 blocks，SEC2-M11 (3)）。
    ///
    /// 紧急升级生效后须进入此审计期，期间任意参与者可
    /// `dispute_emergency_upgrade` 触发治理复审。
    pub emergency_audit_period_blocks: u64,
    /// 紧急升级所需 validator quorum 比例（默认 90%，SEC-L7 (5)）。
    ///
    /// 紧急升级须至少 `emergency_quorum_threshold`% 的 validator 投票通过。
    pub emergency_quorum_threshold: u32,
}

impl Default for UpgradeConfig {
    fn default() -> Self {
        Self {
            upgrade_delay_blocks: 2000,
            emergency_audit_period_blocks: 1000,
            emergency_quorum_threshold: 90,
        }
    }
}

/// 升级错误（兼容 [`PokerL1Error`]）。
pub type UpgradeError = PokerL1Error;

/// Signed native-system calls for the consensus-persisted contract-upgrade state machine.
///
/// Emergency upgrades intentionally have no wire variant here.  Their existing in-memory API
/// accepts an already-computed validator approval percentage, which is not a consensus proof.
/// Exposing that value in a user transaction would let the sender forge its authorization.  The
/// ordinary timelocked path is therefore the only enabled on-chain upgrade path until emergency
/// approval is bound to a governance certificate.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub enum ContractUpgradeSystemCall {
    /// Register a new bytecode version and start its timelock.
    Initiate {
        /// Target executable contract.
        contract_id: ObjectID,
        /// Candidate bytecode for the next version.
        new_bytecode: Vec<u8>,
    },
    /// Cancel the caller's pending upgrade before activation.
    Cancel {
        /// Target executable contract.
        contract_id: ObjectID,
    },
    /// Freeze a pending upgrade for governance review.
    Dispute {
        /// Target executable contract.
        contract_id: ObjectID,
    },
}

/// Apply an initiate call to a consensus-persisted upgrade record.
pub fn initiate_persisted_upgrade(
    record: &mut ContractUpgradeState,
    contract: &ContractObject,
    config: &UpgradeConfig,
    caller: Address,
    new_bytecode: Vec<u8>,
    current_height: u64,
) -> PokerL1Result<u32> {
    check_bytecode_size(&new_bytecode)?;
    if record.contract_id != contract.contract_id
        || record.upgrade_cap.contract_id != contract.contract_id
    {
        return Err(PokerL1Error::Other(
            "contract upgrade record does not bind its contract".into(),
        ));
    }
    record.upgrade_cap.check_holder(&caller)?;
    check_not_frozen(&record.state, &record.contract_id)?;
    if !matches!(record.state, UpgradeState::Idle) {
        return Err(PokerL1Error::UpgradeInTimelock {
            contract_id: record.contract_id,
            remaining_blocks: 0,
        });
    }
    let new_version = contract.version.checked_add(1).ok_or_else(|| {
        PokerL1Error::Other(format!("version overflow for {:?}", record.contract_id))
    })?;
    let activate_at_height = current_height
        .checked_add(config.upgrade_delay_blocks)
        .ok_or_else(|| PokerL1Error::Other("contract upgrade activation height overflow".into()))?;
    record.state = UpgradeState::Pending {
        new_version,
        pending_bytecode: new_bytecode,
        activate_at_height,
        submitted_by: caller,
    };
    Ok(new_version)
}

/// Apply a capability-authorized cancellation to a persisted upgrade record.
pub fn cancel_persisted_upgrade(
    record: &mut ContractUpgradeState,
    caller: Address,
) -> PokerL1Result<()> {
    record.upgrade_cap.check_holder(&caller)?;
    check_not_frozen(&record.state, &record.contract_id)?;
    match record.state {
        UpgradeState::Pending { .. } => {
            record.state = UpgradeState::Idle;
            Ok(())
        }
        _ => Err(PokerL1Error::Other("no pending upgrade to cancel".into())),
    }
}

/// Apply an open dispute to a persisted upgrade record.
pub fn dispute_persisted_upgrade(record: &mut ContractUpgradeState) -> PokerL1Result<()> {
    match record.state {
        UpgradeState::Pending { .. } => {
            record.state = UpgradeState::Frozen;
            Ok(())
        }
        UpgradeState::Frozen => Err(PokerL1Error::Other("upgrade is already frozen".into())),
        _ => Err(PokerL1Error::Other("no pending upgrade to dispute".into())),
    }
}

/// Activate every persisted upgrade whose timelock has expired at the start of a block.
///
/// This runs against the same ObjectDb snapshot as ordinary transaction replay.  Consequently an
/// activation is part of the header state-root transition even when the block has no user
/// transaction.  A disputed/frozen record is intentionally left untouched.
pub fn activate_due_persisted_upgrades(
    object_db: &mut ObjectDbSnapshot,
    current_height: u64,
) -> PokerL1Result<Vec<ObjectID>> {
    let state_objects = object_db
        .iter()
        .filter(|object| is_contract_upgrade_state_object(object))
        .cloned()
        .collect::<Vec<_>>();
    let mut activated = Vec::new();

    for state_object in state_objects {
        let mut record = decode_contract_upgrade_state_object(&state_object, {
            let decoded: ContractUpgradeState =
                borsh::from_slice(&state_object.data).map_err(|error| {
                    PokerL1Error::Serialization(format!("ContractUpgradeState Borsh: {error}"))
                })?;
            decoded.chain_id
        })?;
        let UpgradeState::Pending {
            new_version,
            pending_bytecode,
            activate_at_height,
            ..
        } = &record.state
        else {
            continue;
        };
        if current_height < *activate_at_height {
            continue;
        }

        let stored_contract_object = object_db.read(&record.contract_id)?;
        let mut contract = decode_contract_object(&stored_contract_object)?;
        if !contract.is_active {
            return Err(PokerL1Error::ContractNotFound(record.contract_id));
        }
        let expected_version = contract.version.checked_add(1).ok_or_else(|| {
            PokerL1Error::Other("contract version overflow during timelock activation".into())
        })?;
        if *new_version != expected_version {
            return Err(PokerL1Error::Other(
                "pending upgrade version does not follow the active contract version".into(),
            ));
        }
        contract.version = *new_version;
        contract.bytecode = pending_bytecode.clone();
        contract.deployed_at_height = current_height;
        let next_contract_object_version = stored_contract_object
            .version
            .checked_add(1)
            .ok_or_else(|| {
                PokerL1Error::Other(
                    "contract object version overflow during timelock activation".into(),
                )
            })?;
        object_db
            .replace_contract_object(contract_object(&contract, next_contract_object_version)?)?;

        record.state = UpgradeState::Idle;
        let next_state_version = state_object.version.checked_add(1).ok_or_else(|| {
            PokerL1Error::Other("contract upgrade state object version overflow".into())
        })?;
        object_db
            .replace_system_object(contract_upgrade_state_object(&record, next_state_version)?)?;
        activated.push(record.contract_id);
    }
    Ok(activated)
}

/// 校验字节码大小（IMPL-SEC-4：(7)，单 Object ≤ 64KB）。
const fn check_bytecode_size(new_bytecode: &[u8]) -> PokerL1Result<()> {
    if new_bytecode.len() > MAX_CONTRACT_BYTECODE_SIZE {
        return Err(PokerL1Error::ObjectTooLarge {
            actual: new_bytecode.len(),
            limit: MAX_CONTRACT_BYTECODE_SIZE,
        });
    }
    Ok(())
}

/// 校验当前状态非 Frozen（SEC-L7 (4)）。
///
/// `Frozen` 状态下所有升级操作均失败。
const fn check_not_frozen(state: &UpgradeState, contract_id: &ObjectID) -> PokerL1Result<()> {
    if matches!(state, UpgradeState::Frozen) {
        return Err(PokerL1Error::NotAuthorized {
            contract_id: *contract_id,
        });
    }
    Ok(())
}

/// 发起升级（SubTask 17.2 + SEC-L7 (1)）。
///
/// 校验 UpgradeCap 持有者 → 注册 Pending 状态（timelock 期）。
/// timelock 到期前新版本不可调用。
///
/// # 参数
///
/// - `registry`：合约注册表
/// - `config`：升级配置（决定 timelock 长度）
/// - `contract_id`：目标合约 ID
/// - `caller`：调用者地址（须为 UpgradeCap 持有者）
/// - `new_bytecode`：新版本字节码（≤ 64KB）
/// - `current_height`：当前 block height
///
/// # 错误
///
/// - [`PokerL1Error::NotAuthorized`]：caller 非 UpgradeCap 持有者，或状态为 Frozen
/// - [`PokerL1Error::ObjectTooLarge`]：字节码超 64KB
/// - [`PokerL1Error::UpgradeInTimelock`]：已有 Pending 升级未生效
pub fn initiate_upgrade(
    registry: &mut ContractRegistry,
    config: &UpgradeConfig,
    contract_id: &ObjectID,
    caller: Address,
    new_bytecode: Vec<u8>,
    current_height: u64,
) -> PokerL1Result<u32> {
    // IMPL-SEC-4 (7)：字节码大小校验
    check_bytecode_size(&new_bytecode)?;

    // SubTask 17.2：校验 UpgradeCap 持有者
    let cap = registry.get_upgrade_cap(contract_id)?;
    cap.check_holder(&caller)?;

    // SEC-L7 (4)：Frozen 状态下禁止升级
    let state = registry.get_upgrade_state(contract_id)?;
    check_not_frozen(state, contract_id)?;

    // 同一合约不可重复发起升级（须先 cancel/commit/dispute）
    if !matches!(state, UpgradeState::Idle) {
        return Err(PokerL1Error::UpgradeInTimelock {
            contract_id: *contract_id,
            remaining_blocks: 0,
        });
    }

    // 计算新版本号（version += 1，contract_id 不变）
    let contract = registry.get_contract(contract_id)?;
    let new_version = contract
        .version
        .checked_add(1)
        .ok_or_else(|| PokerL1Error::Other(format!("version overflow for {contract_id:?}")))?;

    // SEC-L7 (1)：注册 Pending 状态，timelock 到期前不可调用
    let activate_at_height = current_height.saturating_add(config.upgrade_delay_blocks);
    *registry.get_upgrade_state_mut(contract_id)? = UpgradeState::Pending {
        new_version,
        pending_bytecode: new_bytecode,
        activate_at_height,
        submitted_by: caller,
    };

    Ok(new_version)
}

/// 取消升级（SEC-L7 (2)）。
///
/// timelock 期间 UpgradeCap 持有者可取消。
///
/// # 错误
///
/// - [`PokerL1Error::NotAuthorized`]：caller 非 UpgradeCap 持有者，或状态为 Frozen
/// - [`PokerL1Error::Other`]：当前无 Pending 升级可取消
pub fn cancel_upgrade(
    registry: &mut ContractRegistry,
    contract_id: &ObjectID,
    caller: Address,
) -> PokerL1Result<()> {
    // 校验 UpgradeCap 持有者
    let cap = registry.get_upgrade_cap(contract_id)?;
    cap.check_holder(&caller)?;

    // 检查状态：必须为 Pending
    let state = registry.get_upgrade_state_mut(contract_id)?;
    match state {
        UpgradeState::Pending { .. } => {
            *state = UpgradeState::Idle;
            Ok(())
        }
        UpgradeState::Frozen => Err(PokerL1Error::NotAuthorized {
            contract_id: *contract_id,
        }),
        _ => Err(PokerL1Error::Other(format!(
            "no pending upgrade to cancel for {contract_id:?}"
        ))),
    }
}

/// dispute 升级（SEC-L7 (3)）。
///
/// timelock 期间任意参与者可 dispute，冻结升级（防恶意升级）。
/// dispute 后状态变为 [`UpgradeState::Frozen`]，须治理介入解冻。
///
/// # 错误
///
/// - [`PokerL1Error::NotAuthorized`]：状态为 Frozen
/// - [`PokerL1Error::Other`]：当前无 Pending 升级可 dispute
pub fn dispute_upgrade(
    registry: &mut ContractRegistry,
    contract_id: &ObjectID,
) -> PokerL1Result<()> {
    // 任意参与者可 dispute，无需校验 caller
    let state = registry.get_upgrade_state_mut(contract_id)?;
    match state {
        UpgradeState::Pending { .. } => {
            // SEC-L7 (3)：dispute 触发治理冻结升级
            *state = UpgradeState::Frozen;
            Ok(())
        }
        UpgradeState::Frozen => Err(PokerL1Error::NotAuthorized {
            contract_id: *contract_id,
        }),
        _ => Err(PokerL1Error::Other(format!(
            "no pending upgrade to dispute for {contract_id:?}"
        ))),
    }
}

/// 提交 timelock 到期生效（SEC-L7 (1) 自动生效）。
///
/// 检查 timelock 是否到期，到期则激活新版本（旧版本变为不可调用）。
/// 未到期返回 [`PokerL1Error::UpgradeTimelockNotExpired`]。
///
/// # 错误
///
/// - [`PokerL1Error::UpgradeTimelockNotExpired`]：timelock 未到期
/// - [`PokerL1Error::NotAuthorized`]：状态为 Frozen
/// - [`PokerL1Error::Other`]：当前无 Pending 升级可 commit
pub fn commit_upgrade(
    registry: &mut ContractRegistry,
    contract_id: &ObjectID,
    current_height: u64,
) -> PokerL1Result<u32> {
    // 先检查状态 + timelock 是否到期（不取出 bytecode，避免回滚复杂度）
    let (new_version, activate_at_height) = {
        let state = registry.get_upgrade_state(contract_id)?;
        match state {
            UpgradeState::Pending {
                new_version,
                activate_at_height,
                ..
            } => (*new_version, *activate_at_height),
            UpgradeState::Frozen => {
                return Err(PokerL1Error::NotAuthorized {
                    contract_id: *contract_id,
                });
            }
            _ => {
                return Err(PokerL1Error::Other(format!(
                    "no pending upgrade to commit for {contract_id:?}"
                )));
            }
        }
    };

    // SEC-L7 (1)：timelock 未到期则拒绝
    if current_height < activate_at_height {
        return Err(PokerL1Error::UpgradeTimelockNotExpired {
            contract_id: *contract_id,
            remaining_blocks: activate_at_height - current_height,
        });
    }

    // timelock 已到期，取出 Pending 数据并激活新版本
    let (pending_bytecode, submitted_by) = {
        let state = registry.get_upgrade_state_mut(contract_id)?;
        match state {
            UpgradeState::Pending {
                pending_bytecode,
                submitted_by,
                ..
            } => (std::mem::take(pending_bytecode), *submitted_by),
            _ => unreachable!("checked above"),
        }
    };

    // SubTask 17.3：激活新版本，旧版本移入 history 并失活
    registry.activate_version(
        contract_id,
        new_version,
        pending_bytecode,
        submitted_by,
        current_height,
    )?;
    *registry.get_upgrade_state_mut(contract_id)? = UpgradeState::Idle;

    Ok(new_version)
}

/// 紧急升级（SEC-L7 (5) + SEC2-M11）。
///
/// 绕过 timelock，但须：
/// - 90% validator quorum 通过（SEC-L7 (5)）
/// - 含 `critical_vulnerability_proof`（SEC2-M11 (1)）
/// - 生效后进入 1000 blocks 安全审计期（SEC2-M11 (3)）
///
/// # 参数
///
/// - `validator_quorum_percent`：实际投票支持比例（0..=100）
/// - `critical_vulnerability_proof`：关键漏洞证据（非空）
///
/// # 错误
///
/// - [`PokerL1Error::MissingCriticalVulnerabilityProof`]：proof 为空
/// - [`PokerL1Error::InsufficientQuorum`]：quorum 不足
/// - [`PokerL1Error::NotAuthorized`]：caller 非 UpgradeCap 持有者，或状态为 Frozen
/// - [`PokerL1Error::ObjectTooLarge`]：字节码超 64KB
#[allow(clippy::too_many_arguments)]
pub fn emergency_upgrade(
    registry: &mut ContractRegistry,
    config: &UpgradeConfig,
    contract_id: &ObjectID,
    caller: Address,
    new_bytecode: Vec<u8>,
    current_height: u64,
    critical_vulnerability_proof: &[u8],
    validator_quorum_percent: u32,
) -> PokerL1Result<u32> {
    // IMPL-SEC-4 (7)：字节码大小校验
    check_bytecode_size(&new_bytecode)?;

    // SEC2-M11 (1)：紧急升级须含 critical_vulnerability_proof
    if critical_vulnerability_proof.is_empty() {
        return Err(PokerL1Error::MissingCriticalVulnerabilityProof);
    }

    // SEC-L7 (5)：紧急升级须 90% validator quorum 通过
    if validator_quorum_percent < config.emergency_quorum_threshold {
        return Err(PokerL1Error::InsufficientQuorum {
            actual: validator_quorum_percent as usize,
            required: config.emergency_quorum_threshold as usize,
        });
    }

    // 校验 UpgradeCap 持有者
    let cap = registry.get_upgrade_cap(contract_id)?;
    cap.check_holder(&caller)?;

    // SEC-L7 (4)：Frozen 状态下禁止升级
    let state = registry.get_upgrade_state(contract_id)?;
    check_not_frozen(state, contract_id)?;

    // 紧急升级直接生效，但进入审计期
    let contract = registry.get_contract(contract_id)?;
    let new_version = contract
        .version
        .checked_add(1)
        .ok_or_else(|| PokerL1Error::Other(format!("version overflow for {contract_id:?}")))?;

    // SEC2-M11 (2)：仅允许修复性升级（不可改变资金所有权）
    // —— 该约束在合约层无法静态判定，由 validator 在投票时审查，
    //    runtime 层不强制（已由 quorum + audit_period + dispute 兜底）。

    // SubTask 17.3：激活新版本
    registry.activate_version(
        contract_id,
        new_version,
        new_bytecode,
        caller,
        current_height,
    )?;

    // SEC2-M11 (3)：进入安全审计期
    let audit_ends_at_height = current_height.saturating_add(config.emergency_audit_period_blocks);
    *registry.get_upgrade_state_mut(contract_id)? = UpgradeState::EmergencyAudit {
        new_version,
        audit_ends_at_height,
        disputed: false,
    };

    Ok(new_version)
}

/// dispute 紧急升级（SEC2-M11 (3)）。
///
/// 紧急升级生效后的安全审计期内，任意参与者可 dispute 触发治理复审。
/// dispute 后 `EmergencyAudit.disputed = true`，后续须治理介入。
///
/// # 错误
///
/// - [`PokerL1Error::EmergencyUpgradeDisputed`]：已被 dispute（重复 dispute 拒绝）
/// - [`PokerL1Error::Other`]：不在审计期内 / 审计期已过
pub fn dispute_emergency_upgrade(
    registry: &mut ContractRegistry,
    contract_id: &ObjectID,
    current_height: u64,
) -> PokerL1Result<()> {
    let state = registry.get_upgrade_state_mut(contract_id)?;
    match state {
        UpgradeState::EmergencyAudit {
            audit_ends_at_height,
            disputed,
            ..
        } => {
            // SEC2-M11 (3)：审计期已过则不可再 dispute
            if current_height >= *audit_ends_at_height {
                return Err(PokerL1Error::Other(format!(
                    "emergency audit period expired for {contract_id:?}"
                )));
            }
            if *disputed {
                return Err(PokerL1Error::EmergencyUpgradeDisputed);
            }
            *disputed = true;
            Ok(())
        }
        UpgradeState::Frozen => Err(PokerL1Error::NotAuthorized {
            contract_id: *contract_id,
        }),
        _ => Err(PokerL1Error::Other(format!(
            "not in emergency audit period for {contract_id:?}"
        ))),
    }
}

/// 检查并推进 timelock 到期的升级（区块产出时调用，SEC-L7 (1) 自动生效）。
///
/// 遍历所有 [`UpgradeState::Pending`] 状态的合约，timelock 到期则自动激活。
/// 返回已激活的 contract_id 列表。
///
/// # 错误
///
/// 单个合约激活失败会立即返回（理论上不应发生，因 `initiate_upgrade` 已校验）。
pub fn process_pending_upgrades(
    registry: &mut ContractRegistry,
    current_height: u64,
) -> PokerL1Result<Vec<ObjectID>> {
    // 收集所有到期 Pending 的 (contract_id, new_version, bytecode, submitted_by)
    let pending_to_activate: Vec<(ObjectID, u32, Vec<u8>, Address)> = {
        let mut collected = Vec::new();
        for (contract_id, state) in registry.iter_upgrade_states_mut() {
            if let UpgradeState::Pending {
                new_version,
                pending_bytecode,
                activate_at_height,
                submitted_by,
            } = state
                && *activate_at_height <= current_height
            {
                collected.push((
                    *contract_id,
                    *new_version,
                    std::mem::take(pending_bytecode),
                    *submitted_by,
                ));
            }
        }
        collected
    };

    // 逐个激活新版本
    let mut activated = Vec::with_capacity(pending_to_activate.len());
    for (contract_id, new_version, bytecode, submitted_by) in pending_to_activate {
        registry.activate_version(
            &contract_id,
            new_version,
            bytecode,
            submitted_by,
            current_height,
        )?;
        *registry.get_upgrade_state_mut(&contract_id)? = UpgradeState::Idle;
        activated.push(contract_id);
    }

    Ok(activated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_address(byte: u8) -> Address {
        [byte; 20]
    }

    /// 部署一个测试合约，返回 (registry, contract_id, deployer, config)。
    fn setup_contract() -> (ContractRegistry, ObjectID, Address, UpgradeConfig) {
        let mut registry = ContractRegistry::new();
        let deployer = make_address(0x01);
        let (contract_id, _) = registry
            .deploy(b"v1-bytecode".to_vec(), deployer, 100)
            .unwrap();
        let config = UpgradeConfig::default();
        (registry, contract_id, deployer, config)
    }

    // ===== SubTask 17.1: 部署即创建 UpgradeCap（已在 contract.rs 实现，这里消费） =====

    #[test]
    fn test_deploy_creates_upgrade_cap_consumed_by_upgrade_module() {
        // SubTask 17.1：deploy 后 upgrade 模块可通过 registry.get_upgrade_cap 消费
        let (registry, contract_id, deployer, _) = setup_contract();

        let cap = registry.get_upgrade_cap(&contract_id).unwrap();
        assert_eq!(cap.holder, deployer);
        assert_eq!(cap.contract_id, contract_id);

        let state = registry.get_upgrade_state(&contract_id).unwrap();
        assert_eq!(*state, UpgradeState::Idle);
    }

    // ===== SubTask 17.2: initiate_upgrade 注册新版本，contract_id 不变 =====

    #[test]
    fn test_initiate_upgrade_registers_pending_state() {
        // SubTask 17.2 + SEC-L7 (1)：initiate 后进入 Pending timelock
        let (mut registry, contract_id, deployer, config) = setup_contract();

        let new_version = initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2-bytecode".to_vec(),
            200,
        )
        .unwrap();

        assert_eq!(new_version, 2);

        // 状态为 Pending，activate_at_height = 200 + 2000 = 2200
        let state = registry.get_upgrade_state(&contract_id).unwrap();
        match state {
            UpgradeState::Pending {
                new_version: v,
                activate_at_height,
                submitted_by,
                ..
            } => {
                assert_eq!(*v, 2);
                assert_eq!(*activate_at_height, 200 + 2000);
                assert_eq!(*submitted_by, deployer);
            }
            s => panic!("expected Pending, got {s:?}"),
        }

        // contract_id 不变，当前活跃版本仍为 1（新版本未生效）
        let contract = registry.get_contract(&contract_id).unwrap();
        assert_eq!(contract.version, 1);
    }

    #[test]
    fn test_initiate_upgrade_rejects_non_holder() {
        // SEC-L7 (1) + SubTask 17.2：非 UpgradeCap 持有者不可发起升级
        let (mut registry, contract_id, _, config) = setup_contract();
        let attacker = make_address(0x99);

        let result = initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            attacker,
            b"v2".to_vec(),
            200,
        );

        assert!(
            matches!(result, Err(PokerL1Error::NotAuthorized { contract_id: c }) if c == contract_id),
            "非持有者应被拒绝, got: {result:?}"
        );
    }

    #[test]
    fn test_initiate_upgrade_rejects_oversized_bytecode() {
        // IMPL-SEC-4 (7)：字节码超 64KB 拒绝
        let (mut registry, contract_id, deployer, config) = setup_contract();
        let oversized = vec![0u8; MAX_CONTRACT_BYTECODE_SIZE + 1];

        let result = initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            oversized,
            200,
        );

        assert!(
            matches!(result, Err(PokerL1Error::ObjectTooLarge { actual, limit })
                if actual == MAX_CONTRACT_BYTECODE_SIZE + 1 && limit == MAX_CONTRACT_BYTECODE_SIZE),
            "超长字节码应被拒绝, got: {result:?}"
        );
    }

    #[test]
    fn test_initiate_upgrade_rejects_double_initiate() {
        // 已有 Pending 升级时拒绝再次 initiate
        let (mut registry, contract_id, deployer, config) = setup_contract();

        initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2".to_vec(),
            200,
        )
        .unwrap();

        let result = initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v3".to_vec(),
            210,
        );

        assert!(
            matches!(result, Err(PokerL1Error::UpgradeInTimelock { .. })),
            "重复 initiate 应被拒绝, got: {result:?}"
        );
    }

    // ===== SubTask 17.3: 旧版本不可调用 =====

    #[test]
    fn test_commit_upgrade_activates_new_version_old_uncallable() {
        // SubTask 17.3：commit 后新版本可调用，旧版本不可调用
        let (mut registry, contract_id, deployer, config) = setup_contract();

        initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2-bytecode".to_vec(),
            200,
        )
        .unwrap();

        // timelock 到期
        let activated_version = commit_upgrade(&mut registry, &contract_id, 2200).unwrap();
        assert_eq!(activated_version, 2);

        // 新版本可调用
        assert!(registry.is_version_callable(&contract_id, 2).unwrap());
        // 旧版本不可调用（SubTask 17.3）
        assert!(!registry.is_version_callable(&contract_id, 1).unwrap());

        // contract_id 不变，version = 2
        let contract = registry.get_contract(&contract_id).unwrap();
        assert_eq!(contract.version, 2);
        assert_eq!(contract.bytecode, b"v2-bytecode");

        // 状态回到 Idle
        let state = registry.get_upgrade_state(&contract_id).unwrap();
        assert_eq!(*state, UpgradeState::Idle);
    }

    #[test]
    fn test_commit_upgrade_rejects_before_timelock_expiry() {
        // SEC-L7 (1)：timelock 未到期时 commit 返回 UpgradeTimelockNotExpired
        let (mut registry, contract_id, deployer, config) = setup_contract();

        initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2".to_vec(),
            200,
        )
        .unwrap();

        // 未到期（200 + 2000 = 2200，当前 1500）
        let result = commit_upgrade(&mut registry, &contract_id, 1500);

        assert!(
            matches!(result, Err(PokerL1Error::UpgradeTimelockNotExpired {
                contract_id: c,
                remaining_blocks: r
            }) if c == contract_id && r == 700),
            "未到期应返回 UpgradeTimelockNotExpired, got: {result:?}"
        );

        // 状态仍为 Pending
        let state = registry.get_upgrade_state(&contract_id).unwrap();
        assert!(matches!(state, UpgradeState::Pending { .. }));
    }

    // ===== SEC-L7 (2): cancel_upgrade =====

    #[test]
    fn test_cancel_upgrade_by_holder_clears_pending() {
        // SEC-L7 (2)：UpgradeCap 持有者可 cancel
        let (mut registry, contract_id, deployer, config) = setup_contract();

        initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2".to_vec(),
            200,
        )
        .unwrap();

        cancel_upgrade(&mut registry, &contract_id, deployer).unwrap();

        // 状态回到 Idle，未激活
        let state = registry.get_upgrade_state(&contract_id).unwrap();
        assert_eq!(*state, UpgradeState::Idle);

        let contract = registry.get_contract(&contract_id).unwrap();
        assert_eq!(contract.version, 1, "cancel 后版本不应变化");
    }

    #[test]
    fn test_cancel_upgrade_rejects_non_holder() {
        // SEC-L7 (2)：非持有者不可 cancel
        let (mut registry, contract_id, deployer, config) = setup_contract();
        let attacker = make_address(0x99);

        initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2".to_vec(),
            200,
        )
        .unwrap();

        let result = cancel_upgrade(&mut registry, &contract_id, attacker);

        assert!(
            matches!(result, Err(PokerL1Error::NotAuthorized { .. })),
            "非持有者 cancel 应被拒绝, got: {result:?}"
        );

        // 状态仍为 Pending
        let state = registry.get_upgrade_state(&contract_id).unwrap();
        assert!(matches!(state, UpgradeState::Pending { .. }));
    }

    // ===== SEC-L7 (3): dispute_upgrade =====

    #[test]
    fn test_dispute_upgrade_by_anyone_freezes() {
        // SEC-L7 (3)：任意参与者可 dispute，触发治理冻结
        let (mut registry, contract_id, deployer, config) = setup_contract();

        initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2".to_vec(),
            200,
        )
        .unwrap();

        // 任意参与者（无需校验 caller）
        dispute_upgrade(&mut registry, &contract_id).unwrap();

        // 状态变为 Frozen
        let state = registry.get_upgrade_state(&contract_id).unwrap();
        assert_eq!(*state, UpgradeState::Frozen);

        // Frozen 后所有升级操作都应失败
        let result = initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v3".to_vec(),
            300,
        );
        assert!(
            matches!(result, Err(PokerL1Error::NotAuthorized { .. })),
            "Frozen 状态下 initiate 应失败, got: {result:?}"
        );
    }

    #[test]
    fn test_dispute_upgrade_rejects_when_no_pending() {
        // 无 Pending 升级时 dispute 失败
        let (mut registry, contract_id, _, _) = setup_contract();

        let result = dispute_upgrade(&mut registry, &contract_id);

        assert!(
            matches!(result, Err(PokerL1Error::Other(_))),
            "无 Pending 时 dispute 应失败, got: {result:?}"
        );
    }

    // ===== SEC-L7 (1) 自动生效: process_pending_upgrades =====

    #[test]
    fn test_process_pending_upgrades_auto_activates_expired() {
        // SEC-L7 (1)：timelock 到期后自动激活
        let (mut registry, contract_id, deployer, config) = setup_contract();

        initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2".to_vec(),
            200,
        )
        .unwrap();

        // 未到期 → 不激活
        let activated = process_pending_upgrades(&mut registry, 2100).unwrap();
        assert!(activated.is_empty(), "未到期不应激活");

        // 到期 → 激活
        let activated = process_pending_upgrades(&mut registry, 2200).unwrap();
        assert_eq!(activated, vec![contract_id]);

        // 新版本可调用
        assert!(registry.is_version_callable(&contract_id, 2).unwrap());
        assert!(!registry.is_version_callable(&contract_id, 1).unwrap());

        let state = registry.get_upgrade_state(&contract_id).unwrap();
        assert_eq!(*state, UpgradeState::Idle);
    }

    #[test]
    fn test_process_pending_upgrades_handles_multiple_contracts() {
        // 多合约场景：部分到期，部分未到期
        // 注意：ObjectID = (creator_address, creation_nonce)，deploy 用 deploy_height
        // 作为 creation_nonce，故两个合约的 deploy_height 须不同以避免 contract_id 冲突。
        let mut registry = ContractRegistry::new();
        let deployer = make_address(0x01);
        let config = UpgradeConfig::default();

        let (cid_a, _) = registry.deploy(b"a-v1".to_vec(), deployer, 100).unwrap();
        let (cid_b, _) = registry.deploy(b"b-v1".to_vec(), deployer, 110).unwrap();
        assert_ne!(cid_a, cid_b, "两个合约的 contract_id 应不同");

        // cid_a 在 height=200 发起，2200 到期
        initiate_upgrade(
            &mut registry,
            &config,
            &cid_a,
            deployer,
            b"a-v2".to_vec(),
            200,
        )
        .unwrap();

        // cid_b 在 height=500 发起，2500 到期
        initiate_upgrade(
            &mut registry,
            &config,
            &cid_b,
            deployer,
            b"b-v2".to_vec(),
            500,
        )
        .unwrap();

        // height=2300：cid_a 到期，cid_b 未到期
        let activated = process_pending_upgrades(&mut registry, 2300).unwrap();
        assert_eq!(activated, vec![cid_a]);

        // height=2500：cid_b 到期
        let activated = process_pending_upgrades(&mut registry, 2500).unwrap();
        assert_eq!(activated, vec![cid_b]);

        // 两个合约都已激活
        assert!(registry.is_version_callable(&cid_a, 2).unwrap());
        assert!(registry.is_version_callable(&cid_b, 2).unwrap());
    }

    // ===== SEC-L7 (5) + SEC2-M11: emergency_upgrade =====

    #[test]
    fn test_emergency_upgrade_bypasses_timelock() {
        // SEC-L7 (5)：紧急升级绕过 timelock，立即生效
        let (mut registry, contract_id, deployer, config) = setup_contract();

        let new_version = emergency_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2-emergency".to_vec(),
            300,
            b"critical bug proof",
            95, // 95% quorum ≥ 90%
        )
        .unwrap();

        assert_eq!(new_version, 2);

        // 立即生效（绕过 timelock）
        assert!(registry.is_version_callable(&contract_id, 2).unwrap());
        assert!(!registry.is_version_callable(&contract_id, 1).unwrap());

        // 进入 EmergencyAudit 状态
        let state = registry.get_upgrade_state(&contract_id).unwrap();
        match state {
            UpgradeState::EmergencyAudit {
                new_version,
                audit_ends_at_height,
                disputed,
            } => {
                assert_eq!(*new_version, 2);
                assert_eq!(*audit_ends_at_height, 300 + 1000);
                assert!(!*disputed);
            }
            s => panic!("expected EmergencyAudit, got {s:?}"),
        }
    }

    #[test]
    fn test_emergency_upgrade_rejects_low_quorum() {
        // SEC-L7 (5)：quorum < 90% 拒绝
        let (mut registry, contract_id, deployer, config) = setup_contract();

        let result = emergency_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2".to_vec(),
            300,
            b"proof",
            89, // < 90
        );

        assert!(
            matches!(result, Err(PokerL1Error::InsufficientQuorum { actual, required })
                if actual == 89 && required == 90),
            "quorum 不足应被拒绝, got: {result:?}"
        );
    }

    #[test]
    fn test_emergency_upgrade_rejects_missing_proof() {
        // SEC2-M11 (1)：缺少 critical_vulnerability_proof 拒绝
        let (mut registry, contract_id, deployer, config) = setup_contract();

        let result = emergency_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2".to_vec(),
            300,
            &[], // 空 proof
            100,
        );

        assert!(
            matches!(result, Err(PokerL1Error::MissingCriticalVulnerabilityProof)),
            "空 proof 应被拒绝, got: {result:?}"
        );
    }

    #[test]
    fn test_emergency_upgrade_rejects_non_holder() {
        // 非 UpgradeCap 持有者不可紧急升级
        let (mut registry, contract_id, _, config) = setup_contract();
        let attacker = make_address(0x99);

        let result = emergency_upgrade(
            &mut registry,
            &config,
            &contract_id,
            attacker,
            b"v2".to_vec(),
            300,
            b"proof",
            100,
        );

        assert!(
            matches!(result, Err(PokerL1Error::NotAuthorized { .. })),
            "非持有者紧急升级应被拒绝, got: {result:?}"
        );
    }

    // ===== SEC2-M11 (3): dispute_emergency_upgrade =====

    #[test]
    fn test_dispute_emergency_upgrade_during_audit_period() {
        // SEC2-M11 (3)：审计期内可 dispute
        let (mut registry, contract_id, deployer, config) = setup_contract();

        emergency_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2".to_vec(),
            300,
            b"proof",
            95,
        )
        .unwrap();

        // 审计期内（300 + 1000 = 1300，当前 500）
        dispute_emergency_upgrade(&mut registry, &contract_id, 500).unwrap();

        // disputed = true
        let state = registry.get_upgrade_state(&contract_id).unwrap();
        match state {
            UpgradeState::EmergencyAudit { disputed, .. } => assert!(*disputed),
            s => panic!("expected EmergencyAudit, got {s:?}"),
        }

        // 重复 dispute 拒绝
        let result = dispute_emergency_upgrade(&mut registry, &contract_id, 600);
        assert!(
            matches!(result, Err(PokerL1Error::EmergencyUpgradeDisputed)),
            "重复 dispute 应被拒绝, got: {result:?}"
        );
    }

    #[test]
    fn test_dispute_emergency_upgrade_rejects_after_audit_expired() {
        // SEC2-M11 (3)：审计期过后不可 dispute
        let (mut registry, contract_id, deployer, config) = setup_contract();

        emergency_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2".to_vec(),
            300,
            b"proof",
            95,
        )
        .unwrap();

        // 审计期已过（300 + 1000 = 1300，当前 1500）
        let result = dispute_emergency_upgrade(&mut registry, &contract_id, 1500);
        assert!(
            matches!(result, Err(PokerL1Error::Other(_))),
            "审计期过后 dispute 应被拒绝, got: {result:?}"
        );
    }

    // ===== SEC-L7 (4): Frozen 状态下所有升级失败 =====

    #[test]
    fn test_frozen_state_blocks_all_upgrades() {
        // SEC-L7 (4)：dispute 后 Frozen，所有升级操作失败
        let (mut registry, contract_id, deployer, config) = setup_contract();

        initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v2".to_vec(),
            200,
        )
        .unwrap();
        dispute_upgrade(&mut registry, &contract_id).unwrap();

        // initiate 失败
        let r1 = initiate_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v3".to_vec(),
            300,
        );
        assert!(matches!(r1, Err(PokerL1Error::NotAuthorized { .. })));

        // emergency 失败
        let r2 = emergency_upgrade(
            &mut registry,
            &config,
            &contract_id,
            deployer,
            b"v3".to_vec(),
            300,
            b"proof",
            100,
        );
        assert!(matches!(r2, Err(PokerL1Error::NotAuthorized { .. })));

        // cancel 失败
        let r3 = cancel_upgrade(&mut registry, &contract_id, deployer);
        assert!(matches!(r3, Err(PokerL1Error::NotAuthorized { .. })));

        // dispute 失败
        let r4 = dispute_upgrade(&mut registry, &contract_id);
        assert!(matches!(r4, Err(PokerL1Error::NotAuthorized { .. })));
    }

    // ===== 配置测试 =====

    #[test]
    fn test_upgrade_config_default_values() {
        let config = UpgradeConfig::default();
        assert_eq!(config.upgrade_delay_blocks, 2000, "SEC-L7 (1) 默认 2000");
        assert_eq!(
            config.emergency_audit_period_blocks, 1000,
            "SEC2-M11 (3) 默认 1000"
        );
        assert_eq!(config.emergency_quorum_threshold, 90, "SEC-L7 (5) 默认 90%");
    }

    #[test]
    fn test_governance_freeze_via_max_delay() {
        // SEC-L7 (4)：治理将 upgrade_delay_blocks 设为 u64::MAX 实质冻结
        // （delay 极长，timelock 永不到期）
        let (mut registry, contract_id, deployer, _) = setup_contract();
        let frozen_config = UpgradeConfig {
            upgrade_delay_blocks: u64::MAX,
            emergency_audit_period_blocks: 1000,
            emergency_quorum_threshold: 90,
        };

        initiate_upgrade(
            &mut registry,
            &frozen_config,
            &contract_id,
            deployer,
            b"v2".to_vec(),
            200,
        )
        .unwrap();

        // 即使 height 极大，timelock 也未到期（u64::MAX 饱和加）
        let result = commit_upgrade(&mut registry, &contract_id, u64::MAX - 1);
        assert!(
            matches!(result, Err(PokerL1Error::UpgradeTimelockNotExpired { .. })),
            "u64::MAX delay 应实质冻结, got: {result:?}"
        );
    }

    #[test]
    fn persisted_upgrade_activates_only_at_due_height_and_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let mut db = ObjectDb::open(directory.path()).unwrap();
        let deployer = make_address(0x71);
        let contract_id = ObjectID::new(deployer, 42);
        let contract = ContractObject::new(contract_id, 1, b"v1".to_vec(), deployer, 10);
        db.create_contract_object(contract_object(&contract, 0).unwrap())
            .unwrap();

        let mut state =
            ContractUpgradeState::new(crate::DEFAULT_CHAIN_ID, contract_id, deployer, 10);
        initiate_persisted_upgrade(
            &mut state,
            &contract,
            &UpgradeConfig {
                upgrade_delay_blocks: 2,
                ..UpgradeConfig::default()
            },
            deployer,
            b"v2".to_vec(),
            10,
        )
        .unwrap();
        let state_id =
            crate::vm::contract::contract_upgrade_state_id(crate::DEFAULT_CHAIN_ID, contract_id);
        db.system_create(contract_upgrade_state_object(&state, 0).unwrap())
            .unwrap();

        let mut before_due = db.create_snapshot();
        assert!(
            activate_due_persisted_upgrades(&mut before_due, 11)
                .unwrap()
                .is_empty()
        );
        before_due.apply_to(&mut db).unwrap();
        assert_eq!(
            decode_contract_object(&db.read(&contract_id).unwrap())
                .unwrap()
                .bytecode,
            b"v1"
        );

        let mut due = db.create_snapshot();
        assert_eq!(
            activate_due_persisted_upgrades(&mut due, 12).unwrap(),
            vec![contract_id]
        );
        due.apply_to(&mut db).unwrap();
        let activated = decode_contract_object(&db.read(&contract_id).unwrap()).unwrap();
        assert_eq!(activated.version, 2);
        assert_eq!(activated.bytecode, b"v2");
        let persisted = decode_contract_upgrade_state_object(
            &db.read(&state_id).unwrap(),
            crate::DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(persisted.state, UpgradeState::Idle);

        drop(db);
        let reopened = ObjectDb::open(directory.path()).unwrap();
        assert_eq!(
            decode_contract_object(&reopened.read(&contract_id).unwrap())
                .unwrap()
                .version,
            2
        );
        assert_eq!(
            decode_contract_upgrade_state_object(
                &reopened.read(&state_id).unwrap(),
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap()
            .state,
            UpgradeState::Idle
        );
    }

    #[test]
    fn persisted_upgrade_rejects_a_version_not_chained_to_live_contract() {
        let mut db = ObjectDb::open_inmemory().unwrap();
        let deployer = make_address(0x72);
        let contract_id = ObjectID::new(deployer, 43);
        let contract = ContractObject::new(contract_id, 1, b"v1".to_vec(), deployer, 10);
        db.create_contract_object(contract_object(&contract, 0).unwrap())
            .unwrap();
        let mut state =
            ContractUpgradeState::new(crate::DEFAULT_CHAIN_ID, contract_id, deployer, 10);
        state.state = UpgradeState::Pending {
            new_version: 9,
            pending_bytecode: b"forged".to_vec(),
            activate_at_height: 10,
            submitted_by: deployer,
        };
        db.system_create(contract_upgrade_state_object(&state, 0).unwrap())
            .unwrap();
        let root_before = db.state_root();
        let mut snapshot = db.create_snapshot();
        assert!(activate_due_persisted_upgrades(&mut snapshot, 10).is_err());
        snapshot.discard();
        assert_eq!(db.state_root(), root_before);
    }
}
