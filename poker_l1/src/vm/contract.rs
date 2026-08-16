//! 合约对象模型与注册表（Task 14 / 17 基础）。
//!
//! 定义合约对象（ContractObject）、升级权（UpgradeCap）、合约注册表（ContractRegistry）。
//! 合约升级的 timelock 逻辑在 [`crate::vm::upgrade`] 模块。
//!
//! ## 设计
//!
//! - `ContractObject`：存储合约字节码 + 版本号，作为 ObjectStore 中的 Object
//! - `UpgradeCap`：升级权对象，持有者可发起合约升级
//! - `ContractRegistry`：链上合约注册表，管理 contract_id → 多版本字节码映射

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::gas_table::MAX_OBJECT_SIZE;
use crate::Address;
use crate::ChainId;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership};

/// 合约对象类型名。
pub const CONTRACT_TYPE: &str = "Contract";
/// UpgradeCap 对象类型名。
pub const UPGRADE_CAP_TYPE: &str = "UpgradeCap";
/// Persistent, consensus-owned upgrade state associated with one contract.
///
/// This object is deliberately separate from the executable [`ContractObject`].  Keeping a
/// pending bytecode payload out of the executable object means the currently active bytecode
/// remains the only code that an ordinary contract call can load.
pub const CONTRACT_UPGRADE_STATE_TYPE: &str = "ContractUpgradeState";

/// Maximum bytecode carried by a contract or a pending upgrade.
///
/// An object has a 64 KiB data limit, while its serialized `ContractObject` / upgrade state also
/// carries identifiers and metadata.  Leaving room for that metadata avoids accepting a payload
/// that can never be committed to ObjectDb.
pub const MAX_CONTRACT_BYTECODE_SIZE: usize = MAX_OBJECT_SIZE - 1024;

const CONTRACT_UPGRADE_STATE_DOMAIN: &[u8] = b"zchain.contract-upgrade-state.v1";

/// 合约字节码（ELF 格式 BPF 字节码）。
///
/// 存储在 ObjectStore 中，通过 contract_id 索引。
/// 一个 contract_id 可有多个版本，旧版本在升级后变为不可调用。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ContractObject {
    /// 合约 ID（全局唯一，升级后不变）。
    pub contract_id: ObjectID,
    /// 版本号（从 1 开始，每次升级 +1）。
    pub version: u32,
    /// BPF 字节码（ELF 格式）。
    pub bytecode: Vec<u8>,
    /// 部署者地址。
    pub deployer: Address,
    /// 部署时的 block height。
    pub deployed_at_height: u64,
    /// 是否为当前活跃版本。
    pub is_active: bool,
}

impl ContractObject {
    /// 创建新合约对象。
    pub const fn new(
        contract_id: ObjectID,
        version: u32,
        bytecode: Vec<u8>,
        deployer: Address,
        deployed_at_height: u64,
    ) -> Self {
        Self {
            contract_id,
            version,
            bytecode,
            deployer,
            deployed_at_height,
            is_active: true,
        }
    }

    /// 序列化字节数（用于 IMPL-SEC-4：(7) 大小校验）。
    pub const fn serialized_size(&self) -> usize {
        self.bytecode.len() + 128 // 估算 overhead
    }
}

/// Return whether an object is an executable contract object.
///
/// Contract bytecode is consensus-controlled state rather than user-mutable object data.  The
/// executor is the only component allowed to create or replace it; generic object syscalls must
/// never be able to alter the bytecode, transfer the object, or delete it.
#[must_use]
pub fn is_contract_object(object: &Object) -> bool {
    object.object_type == CONTRACT_TYPE
}

/// Decode and structurally validate an executable contract object.
///
/// New deployments use immutable ownership.  The address-owned form is accepted only when its
/// owner is the deployer, so nodes can load chains created before contract bytecode was moved to
/// the protected storage path.  Such legacy objects are nevertheless protected from ordinary
/// mutation as soon as this code is active and are normalized to immutable ownership on their
/// next executor-managed replacement.
pub fn decode_contract_object(object: &Object) -> PokerL1Result<ContractObject> {
    if !is_contract_object(object) {
        return Err(PokerL1Error::Other("object is not a Contract".into()));
    }
    let contract: ContractObject = borsh::from_slice(&object.data)
        .map_err(|error| PokerL1Error::Serialization(format!("ContractObject Borsh: {error}")))?;
    if contract.contract_id != object.id
        || contract.version == 0
        || contract.bytecode.len() > MAX_CONTRACT_BYTECODE_SIZE
    {
        return Err(PokerL1Error::Other(
            "contract object binding, version, or bytecode size is invalid".into(),
        ));
    }
    match object.owner {
        Ownership::Immutable => {}
        Ownership::AddressOwned { owner } if owner == contract.deployer => {}
        _ => {
            return Err(PokerL1Error::Other(
                "contract object must be immutable or legacy-owned by its deployer".into(),
            ));
        }
    }
    Ok(contract)
}

/// Build an immutable executable contract object for the executor-only storage path.
pub fn contract_object(contract: &ContractObject, object_version: u64) -> PokerL1Result<Object> {
    let mut object = Object::new(
        contract.contract_id,
        Ownership::Immutable,
        CONTRACT_TYPE,
        borsh::to_vec(contract)?,
        None,
    );
    object.version = object_version;
    decode_contract_object(&object)?;
    Ok(object)
}

/// Deterministically derive the reserved state-object ID for a contract upgrade record.
///
/// The derivation includes `chain_id`, so state imported from a different chain cannot occupy the
/// same consensus key.  The resulting object is created only through the executor's system path;
/// an ordinary transaction output cannot pre-create it.
#[must_use]
pub fn contract_upgrade_state_id(chain_id: ChainId, contract_id: ObjectID) -> ObjectID {
    use blake2::digest::{Update, VariableOutput};

    let mut hasher = blake2::Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(CONTRACT_UPGRADE_STATE_DOMAIN);
    hasher.update(&chain_id.to_le_bytes());
    hasher.update(&contract_id.to_bytes());
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[..20]);
    let nonce = u64::from_le_bytes(digest[20..28].try_into().expect("fixed length"));
    ObjectID::new(address, nonce)
}

/// UpgradeCap — 合约升级权对象（SubTask 17.1）。
///
/// 部署合约时创建并 transfer 给部署者。
/// 持有者可发起升级、取消升级、紧急升级。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct UpgradeCap {
    /// 关联的合约 ID。
    pub contract_id: ObjectID,
    /// 持有者地址。
    pub holder: Address,
    /// 创建时的 block height。
    pub created_at_height: u64,
}

impl UpgradeCap {
    /// 创建新 UpgradeCap。
    pub const fn new(contract_id: ObjectID, holder: Address, created_at_height: u64) -> Self {
        Self {
            contract_id,
            holder,
            created_at_height,
        }
    }

    /// 校验调用者是否为持有者。
    pub fn check_holder(&self, caller: &Address) -> PokerL1Result<()> {
        if &self.holder != caller {
            return Err(PokerL1Error::NotAuthorized {
                contract_id: self.contract_id,
            });
        }
        Ok(())
    }
}

/// 升级状态（SEC-L7 timelock）。
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum UpgradeState {
    /// 无待生效升级。
    #[default]
    Idle,
    /// Timelock 期：新版本已注册但不可调用，等待 `activate_at_height`。
    Pending {
        /// 待生效的新版本号。
        new_version: u32,
        /// 待生效的字节码。
        pending_bytecode: Vec<u8>,
        /// 生效 height（提交 height + upgrade_delay_blocks）。
        activate_at_height: u64,
        /// 提交者地址。
        submitted_by: Address,
    },
    /// 紧急升级安全审计期（SEC2-M11）。
    EmergencyAudit {
        /// 紧急生效的版本号。
        new_version: u32,
        /// 审计期结束 height（生效 height + 1000）。
        audit_ends_at_height: u64,
        /// 是否已被 dispute。
        disputed: bool,
    },
    /// 已被治理冻结（`upgrade_delay_blocks = u64::MAX`）。
    Frozen,
}

/// The consensus-persisted capability and state machine for one contract.
///
/// This is not an in-memory cache: it is serialized into a reserved ObjectDb object and therefore
/// participates in state-root calculation, snapshots, block replay, and crash recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ContractUpgradeState {
    /// Chain namespace to which this record belongs.
    pub chain_id: ChainId,
    /// The executable contract controlled by this record.
    pub contract_id: ObjectID,
    /// Upgrade capability holder.
    pub upgrade_cap: UpgradeCap,
    /// Timelock / freeze / emergency-audit state.
    pub state: UpgradeState,
}

impl ContractUpgradeState {
    /// Create an idle upgrade record at deployment time.
    #[must_use]
    pub const fn new(
        chain_id: ChainId,
        contract_id: ObjectID,
        deployer: Address,
        height: u64,
    ) -> Self {
        Self {
            chain_id,
            contract_id,
            upgrade_cap: UpgradeCap::new(contract_id, deployer, height),
            state: UpgradeState::Idle,
        }
    }
}

/// Return whether an object uses the reserved contract-upgrade state namespace.
#[must_use]
pub fn is_contract_upgrade_state_object(object: &Object) -> bool {
    object.object_type == CONTRACT_UPGRADE_STATE_TYPE
}

/// Decode and validate a contract-upgrade state object without trusting its object key.
pub fn decode_contract_upgrade_state_object(
    object: &Object,
    expected_chain_id: ChainId,
) -> PokerL1Result<ContractUpgradeState> {
    if !is_contract_upgrade_state_object(object) {
        return Err(PokerL1Error::Other(
            "object is not a ContractUpgradeState".into(),
        ));
    }
    let state: ContractUpgradeState = borsh::from_slice(&object.data).map_err(|error| {
        PokerL1Error::Serialization(format!("ContractUpgradeState Borsh: {error}"))
    })?;
    if state.chain_id != expected_chain_id
        || state.upgrade_cap.contract_id != state.contract_id
        || object.id != contract_upgrade_state_id(state.chain_id, state.contract_id)
    {
        return Err(PokerL1Error::Other(
            "contract upgrade state object binding mismatch".into(),
        ));
    }
    if let UpgradeState::Pending {
        new_version,
        pending_bytecode,
        ..
    } = &state.state
    {
        if *new_version == 0 || pending_bytecode.len() > MAX_CONTRACT_BYTECODE_SIZE {
            return Err(PokerL1Error::Other(
                "contract upgrade state carries an invalid pending version or bytecode size".into(),
            ));
        }
    }
    Ok(state)
}

/// Validate a contract-upgrade state object where the caller does not yet know its chain ID.
///
/// ObjectStore uses this structural form while loading RocksDB; consensus execution performs the
/// stricter chain-id binding through [`decode_contract_upgrade_state_object`].
pub fn validate_contract_upgrade_state_object(object: &Object) -> PokerL1Result<()> {
    if !is_contract_upgrade_state_object(object) {
        return Err(PokerL1Error::Other(
            "object is not a ContractUpgradeState".into(),
        ));
    }
    let state: ContractUpgradeState = borsh::from_slice(&object.data).map_err(|error| {
        PokerL1Error::Serialization(format!("ContractUpgradeState Borsh: {error}"))
    })?;
    decode_contract_upgrade_state_object(object, state.chain_id).map(|_| ())
}

/// Encode one upgrade record as a reserved immutable consensus object.
pub fn contract_upgrade_state_object(
    state: &ContractUpgradeState,
    version: u64,
) -> PokerL1Result<Object> {
    let mut object = Object::new(
        contract_upgrade_state_id(state.chain_id, state.contract_id),
        Ownership::Immutable,
        CONTRACT_UPGRADE_STATE_TYPE,
        borsh::to_vec(state)?,
        None,
    );
    object.version = version;
    validate_contract_upgrade_state_object(&object)?;
    Ok(object)
}

/// 合约注册表（链上 contract_id → ContractObject 映射）。
///
/// 管理所有已部署合约的多版本字节码 + UpgradeCap + 升级状态。
#[derive(Debug, Clone, Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ContractRegistry {
    /// contract_id → 当前活跃合约对象。
    contracts: BTreeMap<ObjectID, ContractObject>,
    /// contract_id → 历史版本（含已失活的旧版本）。
    history: BTreeMap<ObjectID, Vec<ContractObject>>,
    /// contract_id → UpgradeCap。
    upgrade_caps: BTreeMap<ObjectID, UpgradeCap>,
    /// contract_id → 升级状态。
    upgrade_states: BTreeMap<ObjectID, UpgradeState>,
}

impl ContractRegistry {
    /// 创建空注册表。
    pub fn new() -> Self {
        Self::default()
    }

    /// 部署新合约（SubTask 17.1）。
    ///
    /// 创建 ContractObject（version=1）+ UpgradeCap（transfer 给 deployer）。
    /// 返回 (contract_id, upgrade_cap_id)。
    /// H-2 修复：强制合约字节码 ≤ 64KB（MAX_OBJECT_SIZE），防止超大合约导致内存耗尽。
    pub fn deploy(
        &mut self,
        bytecode: Vec<u8>,
        deployer: Address,
        deploy_height: u64,
    ) -> PokerL1Result<(ObjectID, ObjectID)> {
        if bytecode.len() > MAX_CONTRACT_BYTECODE_SIZE {
            return Err(PokerL1Error::ObjectTooLarge {
                actual: bytecode.len(),
                limit: MAX_CONTRACT_BYTECODE_SIZE,
            });
        }

        let contract_id = ObjectID::new(deployer, deploy_height);
        // M-10 修复：checked_add 防止 deploy_height = u64::MAX 时溢出导致 cap_id 碰撞
        let cap_nonce = deploy_height.checked_add(1).ok_or_else(|| {
            PokerL1Error::InvalidSyscallArgument(format!(
                "deploy_height {deploy_height} overflow: cannot allocate cap_nonce"
            ))
        })?;
        let cap_id = ObjectID::new(deployer, cap_nonce);

        let contract = ContractObject::new(contract_id, 1, bytecode, deployer, deploy_height);
        let cap = UpgradeCap::new(contract_id, deployer, deploy_height);

        self.contracts.insert(contract_id, contract);
        self.upgrade_caps.insert(contract_id, cap);
        self.upgrade_states.insert(contract_id, UpgradeState::Idle);

        Ok((contract_id, cap_id))
    }

    /// 获取合约的当前活跃版本。
    pub fn get_contract(&self, contract_id: &ObjectID) -> PokerL1Result<&ContractObject> {
        self.contracts
            .get(contract_id)
            .ok_or(PokerL1Error::ContractNotFound(*contract_id))
    }

    /// 获取合约的 UpgradeCap。
    pub fn get_upgrade_cap(&self, contract_id: &ObjectID) -> PokerL1Result<&UpgradeCap> {
        self.upgrade_caps
            .get(contract_id)
            .ok_or(PokerL1Error::ContractNotFound(*contract_id))
    }

    /// 获取合约的升级状态。
    pub fn get_upgrade_state(&self, contract_id: &ObjectID) -> PokerL1Result<&UpgradeState> {
        self.upgrade_states
            .get(contract_id)
            .ok_or(PokerL1Error::ContractNotFound(*contract_id))
    }

    /// 获取可变升级状态。
    pub fn get_upgrade_state_mut(
        &mut self,
        contract_id: &ObjectID,
    ) -> PokerL1Result<&mut UpgradeState> {
        self.upgrade_states
            .get_mut(contract_id)
            .ok_or(PokerL1Error::ContractNotFound(*contract_id))
    }

    /// 迭代所有合约的升级状态（mutable）。
    ///
    /// 用于 [`crate::vm::upgrade::process_pending_upgrades`] 遍历所有 Pending
    /// 状态的合约并在 timelock 到期时自动激活。
    pub fn iter_upgrade_states_mut(
        &mut self,
    ) -> impl Iterator<Item = (&ObjectID, &mut UpgradeState)> {
        self.upgrade_states.iter_mut()
    }

    /// 获取可变 UpgradeCap。
    pub fn get_upgrade_cap_mut(
        &mut self,
        contract_id: &ObjectID,
    ) -> PokerL1Result<&mut UpgradeCap> {
        self.upgrade_caps
            .get_mut(contract_id)
            .ok_or(PokerL1Error::ContractNotFound(*contract_id))
    }

    /// 获取可变合约。
    pub fn get_contract_mut(
        &mut self,
        contract_id: &ObjectID,
    ) -> PokerL1Result<&mut ContractObject> {
        self.contracts
            .get_mut(contract_id)
            .ok_or(PokerL1Error::ContractNotFound(*contract_id))
    }

    /// 注册新版本（内部方法：将旧版本移入 history，激活新版本）。
    ///
    /// 由 [`crate::vm::upgrade`] 模块在 timelock 到期或紧急升级时调用。
    pub(crate) fn activate_version(
        &mut self,
        contract_id: &ObjectID,
        new_version: u32,
        new_bytecode: Vec<u8>,
        deployer: Address,
        height: u64,
    ) -> PokerL1Result<()> {
        let old = self
            .contracts
            .get_mut(contract_id)
            .ok_or(PokerL1Error::ContractNotFound(*contract_id))?;

        // 旧版本失活
        old.is_active = false;
        let old_clone = old.clone();

        // 移入历史
        self.history
            .entry(*contract_id)
            .or_default()
            .push(old_clone);

        // 激活新版本
        let new_contract =
            ContractObject::new(*contract_id, new_version, new_bytecode, deployer, height);
        self.contracts.insert(*contract_id, new_contract);

        Ok(())
    }

    /// 获取合约历史版本列表。
    pub fn get_history(&self, contract_id: &ObjectID) -> &[ContractObject] {
        self.history
            .get(contract_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// 检查指定版本是否可调用（当前活跃版本可调用，旧版本不可）。
    pub fn is_version_callable(&self, contract_id: &ObjectID, version: u32) -> PokerL1Result<bool> {
        let contract = self.get_contract(contract_id)?;
        Ok(contract.version == version && contract.is_active)
    }

    /// 合约总数。
    pub fn len(&self) -> usize {
        self.contracts.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.contracts.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_address(byte: u8) -> Address {
        [byte; 20]
    }

    #[test]
    fn test_deploy_contract() {
        let mut registry = ContractRegistry::new();
        let deployer = make_address(0x01);
        let (contract_id, cap_id) = registry
            .deploy(b"bytecode".to_vec(), deployer, 100)
            .unwrap();

        assert_ne!(contract_id, cap_id, "contract_id 和 cap_id 应不同");

        let contract = registry.get_contract(&contract_id).unwrap();
        assert_eq!(contract.version, 1);
        assert_eq!(contract.bytecode, b"bytecode");
        assert!(contract.is_active);

        let cap = registry.get_upgrade_cap(&contract_id).unwrap();
        assert_eq!(cap.holder, deployer);
        assert_eq!(cap.contract_id, contract_id);

        let state = registry.get_upgrade_state(&contract_id).unwrap();
        assert_eq!(*state, UpgradeState::Idle);
    }

    #[test]
    fn test_upgrade_cap_check_holder() {
        let cap = UpgradeCap::new(ObjectID::default(), make_address(0x01), 100);

        assert!(cap.check_holder(&make_address(0x01)).is_ok());
        assert!(cap.check_holder(&make_address(0x02)).is_err());
    }

    #[test]
    fn test_activate_version() {
        let mut registry = ContractRegistry::new();
        let deployer = make_address(0x01);
        let (contract_id, _) = registry.deploy(b"v1".to_vec(), deployer, 100).unwrap();

        // 激活 v2
        registry
            .activate_version(&contract_id, 2, b"v2".to_vec(), deployer, 200)
            .unwrap();

        let contract = registry.get_contract(&contract_id).unwrap();
        assert_eq!(contract.version, 2);
        assert_eq!(contract.bytecode, b"v2");
        assert!(contract.is_active);

        // 历史应有 1 个旧版本
        let history = registry.get_history(&contract_id);
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].version, 1);
        assert!(!history[0].is_active);
    }

    #[test]
    fn test_is_version_callable() {
        let mut registry = ContractRegistry::new();
        let deployer = make_address(0x01);
        let (contract_id, _) = registry.deploy(b"v1".to_vec(), deployer, 100).unwrap();

        assert!(registry.is_version_callable(&contract_id, 1).unwrap());
        assert!(!registry.is_version_callable(&contract_id, 2).unwrap());

        registry
            .activate_version(&contract_id, 2, b"v2".to_vec(), deployer, 200)
            .unwrap();

        assert!(!registry.is_version_callable(&contract_id, 1).unwrap());
        assert!(registry.is_version_callable(&contract_id, 2).unwrap());
    }

    #[test]
    fn test_contract_not_found() {
        let registry = ContractRegistry::new();
        let fake_id = ObjectID::new([0xff; 20], 0);
        assert!(matches!(
            registry.get_contract(&fake_id),
            Err(PokerL1Error::ContractNotFound(_))
        ));
    }

    #[test]
    fn test_upgrade_state_default() {
        assert_eq!(UpgradeState::default(), UpgradeState::Idle);
    }

    #[test]
    fn test_contract_serialized_size() {
        let contract = ContractObject::new(
            ObjectID::default(),
            1,
            vec![0u8; 1024],
            make_address(0x01),
            100,
        );
        assert!(contract.serialized_size() > 1024);
    }

    #[test]
    fn protected_contract_objects_reject_generic_mutation_paths() {
        let deployer = make_address(0x4A);
        let contract_id = ObjectID::new(deployer, 7);
        let contract = ContractObject::new(contract_id, 1, b"v1".to_vec(), deployer, 12);
        let object = contract_object(&contract, 0).unwrap();
        let mut store = crate::object_model::ObjectStore::new();

        assert!(store.create(object.clone()).is_err());
        store.system_create(object).unwrap();
        assert!(
            store
                .update(&contract_id, &deployer, b"forged".to_vec())
                .is_err()
        );
        assert!(
            store
                .transfer(&contract_id, &deployer, make_address(0x4B))
                .is_err()
        );
        assert!(store.delete(&contract_id).is_err());
    }

    #[test]
    fn contract_object_rejects_unbound_or_mutable_deployment_shape() {
        let deployer = make_address(0x51);
        let contract_id = ObjectID::new(deployer, 9);
        let mut contract = ContractObject::new(contract_id, 1, b"v1".to_vec(), deployer, 1);
        contract.contract_id = ObjectID::new(deployer, 10);
        let malformed = Object::new(
            contract_id,
            Ownership::Immutable,
            CONTRACT_TYPE,
            borsh::to_vec(&contract).unwrap(),
            None,
        );
        assert!(decode_contract_object(&malformed).is_err());
    }
}
