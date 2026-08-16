//! ObjectStore（SubTask 2.3 — 内存版 + Sparse Merkle Tree backing）
//!
//! 功能：
//! - create / read / update / delete / version 查询
//! - 创建时校验 ObjectID 不存在，冲突返回 `ObjectIDCollision`（NEW-L4）
//! - Sparse Merkle Root 计算（IMPL-SEC-3）— keyed by blake2b_256(ObjectID)
//! - 批量写入接口

use super::id::ObjectID;
use super::object::Object;
use super::smt::SparseMerkleTree;
use crate::Address;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::vm::gas_table::MAX_OBJECT_SIZE;
use std::collections::HashMap;

/// Whether an object has a reserved identity whose lifecycle is controlled by consensus code.
///
/// Snapshot restoration must use the same classification as normal object mutation: an
/// authenticated snapshot is a trusted state-transfer path, but it must not fall back to the
/// public `create` API for protected objects.
pub(crate) fn is_system_object(object: &Object) -> bool {
    crate::economics::is_treasury_cap_object(object)
        || crate::economics::is_fee_policy_object(object)
        || crate::consensus::validator_set::is_validator_set_object(object)
        || crate::governance::is_governance_state_object(object)
        || crate::bridge::is_bridge_registry_config_object(object)
        || crate::bridge::is_bridge_replay_state_object(object)
        || crate::genesis::is_genesis_anchor_object(object)
        || crate::governance::validator_bond_escrow::is_validator_bond_escrow_object(object)
        || crate::consensus::validator_key_history::is_validator_key_history_object(object)
        || crate::vm::precompile::is_precompile_governance_state_object(object)
        || crate::vm::contract::is_contract_object(object)
        || crate::vm::contract::is_contract_upgrade_state_object(object)
}

fn validate_system_object(object: &Object) -> PokerL1Result<()> {
    if crate::economics::is_treasury_cap_object(object) {
        crate::economics::decode_treasury_cap(object)?;
        return Ok(());
    }
    if crate::economics::is_fee_policy_object(object) {
        crate::economics::validate_fee_policy_object(object)?;
        return Ok(());
    }
    if crate::consensus::validator_set::is_validator_set_object(object) {
        crate::consensus::validator_set::validate_validator_set_object(object)?;
        return Ok(());
    }
    if crate::governance::is_governance_state_object(object) {
        crate::governance::validate_governance_state_object(object)?;
        return Ok(());
    }
    if crate::bridge::is_bridge_registry_config_object(object) {
        // The chain-id binding is checked by Node when it loads/executes state. ObjectStore only
        // validates the singleton shape during generic storage operations.
        crate::bridge::validate_bridge_registry_config_object(object)?;
        return Ok(());
    }
    if crate::bridge::is_bridge_replay_state_object(object) {
        crate::bridge::validate_bridge_replay_state_object(object)?;
        return Ok(());
    }
    if crate::genesis::is_genesis_anchor_object(object) {
        crate::genesis::decode_genesis_anchor(object)?;
        return Ok(());
    }
    if crate::governance::validator_bond_escrow::is_validator_bond_escrow_object(object) {
        // The chain-id binding is checked at the consensus caller.  Generic storage only
        // establishes that this is a structurally valid, reserved singleton.
        crate::governance::validator_bond_escrow::validate_validator_bond_escrow_object(object)?;
        return Ok(());
    }
    if crate::consensus::validator_key_history::is_validator_key_history_object(object) {
        // As above, chain namespace binding belongs to the node/consensus path.
        crate::consensus::validator_key_history::validate_validator_key_history_object(object)?;
        return Ok(());
    }
    if crate::vm::precompile::is_precompile_governance_state_object(object) {
        crate::vm::precompile::validate_precompile_governance_state_object(object)?;
        return Ok(());
    }
    if crate::vm::contract::is_contract_object(object) {
        crate::vm::contract::decode_contract_object(object)?;
        return Ok(());
    }
    if crate::vm::contract::is_contract_upgrade_state_object(object) {
        // The object key is bound to its encoded `(chain_id, contract_id)` tuple.  Chain-id
        // membership is checked by the executor before it acts on the record.
        crate::vm::contract::validate_contract_upgrade_state_object(object)?;
        return Ok(());
    }
    Err(PokerL1Error::Other(
        "object is not a recognized system singleton".into(),
    ))
}

/// 内存版 ObjectStore + SMT backing。
///
/// Phase 1 内存实现；Phase 4 扩展 rocksdb 后端。
///
/// `Clone` 用于 `ObjectDbSnapshot` 创建 fork：复制内存 SMT + objects HashMap，
/// 使 snapshot 可以独立计算 state_root 并记录 mutation log 供回放。
#[derive(Clone)]
pub struct ObjectStore {
    /// ObjectID -> Object
    objects: HashMap<ObjectID, Object>,
    /// Sparse Merkle Tree，key = blake2b_256(ObjectID)，value = BCS(Object)
    smt: SparseMerkleTree,
}

impl ObjectStore {
    /// 创建空 store。
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            smt: SparseMerkleTree::new(),
        }
    }

    /// 当前全局状态根（所有 live 对象的 Sparse Merkle Root）。
    pub const fn state_root(&self) -> crate::Hash {
        self.smt.root()
    }

    /// 创建对象。ObjectID 冲突返回 `ObjectIDCollision`（NEW-L4）。
    /// L-1 修复：校验 data 大小 ≤ MAX_OBJECT_SIZE（defense in depth，syscall 层已校验）。
    pub fn create(&mut self, object: Object) -> PokerL1Result<()> {
        if is_system_object(&object) {
            return Err(PokerL1Error::Other(
                "reserved system objects may only be created by a system path".into(),
            ));
        }
        self.create_inner(object)
    }

    /// Create one validated singleton from a trusted system path.
    pub(crate) fn system_create(&mut self, object: Object) -> PokerL1Result<()> {
        validate_system_object(&object)?;
        self.create_inner(object)
    }

    fn create_inner(&mut self, object: Object) -> PokerL1Result<()> {
        if object.data.len() > MAX_OBJECT_SIZE {
            return Err(PokerL1Error::ObjectTooLarge {
                actual: object.data.len(),
                limit: MAX_OBJECT_SIZE,
            });
        }
        if self.objects.contains_key(&object.id) {
            return Err(PokerL1Error::ObjectIDCollision(object.id));
        }
        let key = object.id.merkle_key();
        let value = borsh::to_vec(&object)
            .map_err(|e| PokerL1Error::Serialization(format!("Object BCS encode: {e}")))?;
        self.smt.upsert(key, &value);
        self.objects.insert(object.id, object);
        Ok(())
    }

    /// Replace one validated singleton without exposing a generic privileged write path.
    pub(crate) fn system_replace(&mut self, object: Object) -> PokerL1Result<()> {
        validate_system_object(&object)?;
        if object.data.len() > MAX_OBJECT_SIZE {
            return Err(PokerL1Error::ObjectTooLarge {
                actual: object.data.len(),
                limit: MAX_OBJECT_SIZE,
            });
        }
        let existing = self
            .objects
            .get(&object.id)
            .ok_or(PokerL1Error::ObjectNotFound(object.id))?;
        if !is_system_object(existing) || existing.object_type != object.object_type {
            return Err(PokerL1Error::Other(
                "system object ID is occupied by a different object type".into(),
            ));
        }
        let expected_version = existing
            .version
            .checked_add(1)
            .ok_or_else(|| PokerL1Error::Other("system object version overflow".into()))?;
        if object.version != expected_version {
            return Err(PokerL1Error::ObjectVersionMismatch {
                expected: expected_version,
                actual: object.version,
            });
        }
        let key = object.id.merkle_key();
        let value = borsh::to_vec(&object)
            .map_err(|e| PokerL1Error::Serialization(format!("Object BCS encode: {e}")))?;
        self.smt.upsert(key, &value);
        self.objects.insert(object.id, object);
        Ok(())
    }

    /// 读取对象。
    pub fn read(&self, id: &ObjectID) -> PokerL1Result<&Object> {
        self.objects
            .get(id)
            .ok_or(PokerL1Error::ObjectNotFound(*id))
    }

    /// 查询对象版本号。
    pub fn version_of(&self, id: &ObjectID) -> PokerL1Result<super::object::Version> {
        Ok(self.read(id)?.version)
    }

    /// 更新对象。校验：对象存在、可写（非 Immutable）、actor 有写权、data 大小 ≤ MAX_OBJECT_SIZE。
    /// 成功后 version += 1，SMT 同步更新。
    /// L-2 修复：校验 new_data 大小（defense in depth，syscall 层已校验）。
    pub fn update(
        &mut self,
        id: &ObjectID,
        actor: &Address,
        new_data: Vec<u8>,
    ) -> PokerL1Result<()> {
        if new_data.len() > MAX_OBJECT_SIZE {
            return Err(PokerL1Error::ObjectTooLarge {
                actual: new_data.len(),
                limit: MAX_OBJECT_SIZE,
            });
        }

        let obj = self
            .objects
            .get_mut(id)
            .ok_or(PokerL1Error::ObjectNotFound(*id))?;

        if is_system_object(obj) {
            return Err(PokerL1Error::Other(
                "reserved system objects may only be updated by a system path".into(),
            ));
        }
        if crate::economics::is_native_coin_object(obj) {
            return Err(PokerL1Error::Other(format!(
                "native coin {id:?} is an immutable UTXO and cannot be updated"
            )));
        }

        if !obj.can_write(actor) {
            return if obj.owner.is_immutable() {
                Err(PokerL1Error::ObjectImmutable(*id))
            } else {
                Err(PokerL1Error::NotOwner(*id))
            };
        }

        obj.data = new_data;
        obj.bump_version();

        // SMT 同步：用新 BCS(Object) 覆盖
        let key = obj.id.merkle_key();
        let value = borsh::to_vec(obj)
            .map_err(|e| PokerL1Error::Serialization(format!("Object BCS encode: {e}")))?;
        self.smt.upsert(key, &value);
        Ok(())
    }

    /// 转移所有权（仅 AddressOwned 对象可转移）。
    pub fn transfer(
        &mut self,
        id: &ObjectID,
        actor: &Address,
        new_owner: Address,
    ) -> PokerL1Result<()> {
        let obj = self
            .objects
            .get_mut(id)
            .ok_or(PokerL1Error::ObjectNotFound(*id))?;

        if is_system_object(obj) {
            return Err(PokerL1Error::Other(
                "reserved system objects may only be transferred by a system path".into(),
            ));
        }
        if crate::economics::is_native_coin_object(obj) {
            return Err(PokerL1Error::Other(format!(
                "native coin {id:?} is an immutable UTXO and cannot be transferred in place"
            )));
        }

        if !obj.owner.is_transferable() {
            return Err(PokerL1Error::ObjectImmutable(*id));
        }
        if !obj.can_write(actor) {
            return Err(PokerL1Error::NotOwner(*id));
        }

        obj.owner = crate::object_model::Ownership::AddressOwned { owner: new_owner };
        obj.bump_version();

        let key = obj.id.merkle_key();
        let value = borsh::to_vec(obj)
            .map_err(|e| PokerL1Error::Serialization(format!("Object BCS encode: {e}")))?;
        self.smt.upsert(key, &value);
        Ok(())
    }

    /// 删除对象（从 SMT 移除，状态根同步更新）。
    pub fn delete(&mut self, id: &ObjectID) -> PokerL1Result<Object> {
        if self.objects.get(id).is_some_and(is_system_object) {
            return Err(PokerL1Error::Other(
                "reserved system objects may only be replaced by a system path".into(),
            ));
        }
        let obj = self
            .objects
            .remove(id)
            .ok_or(PokerL1Error::ObjectNotFound(*id))?;
        let key = id.merkle_key();
        self.smt.remove(&key);
        Ok(obj)
    }

    /// 批量写入（原子语义：全部成功或全部失败回滚）。
    ///
    /// 注意：当前实现先预检所有 ObjectID 不冲突，再依次插入。若中途 BCS 序列化失败，
    /// 已插入的对象会保留（部分写入）—— Phase 1 内存版可接受；Phase 4 rocksdb 将用 WriteBatch。
    pub fn batch_create(&mut self, objects: Vec<Object>) -> PokerL1Result<()> {
        // 预检：所有 ObjectID 互不冲突且与现有 store 不冲突
        let mut seen = std::collections::HashSet::new();
        for o in &objects {
            if self.objects.contains_key(&o.id) || !seen.insert(o.id) {
                return Err(PokerL1Error::ObjectIDCollision(o.id));
            }
        }
        // 依次插入
        for o in objects {
            self.create(o)?;
        }
        Ok(())
    }

    /// 当前 live 对象数量。
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// 生成对象的 Merkle 包含证明（供轻客户端验证，R5-M8）。
    pub fn prove(&self, id: &ObjectID) -> PokerL1Result<super::smt::MerklePath> {
        if !self.objects.contains_key(id) {
            return Err(PokerL1Error::ObjectNotFound(*id));
        }
        Ok(self.smt.prove(&id.merkle_key()))
    }

    /// 生成非包含证明（证明某 ObjectID 不存在）。
    pub fn prove_nonexistence(&self, id: &ObjectID) -> super::smt::MerklePath {
        self.smt.prove(&id.merkle_key())
    }

    /// 迭代所有 live 对象。
    pub fn iter(&self) -> impl Iterator<Item = &Object> {
        self.objects.values()
    }
}

impl Default for ObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::Ownership;

    fn make_obj(creator: Address, nonce: u64, owner: Address) -> Object {
        Object::new(
            ObjectID::new(creator, nonce),
            Ownership::AddressOwned { owner },
            "Test",
            format!("data-{nonce}").into_bytes(),
            None,
        )
    }

    #[test]
    fn create_and_read() {
        let mut s = ObjectStore::new();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        s.create(o.clone()).unwrap();
        let read = s.read(&o.id).unwrap();
        assert_eq!(read, &o);
    }

    #[test]
    fn create_collision_returns_error() {
        let mut s = ObjectStore::new();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        s.create(o.clone()).unwrap();
        let err = s.create(o).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectIDCollision(_)));
    }

    #[test]
    fn new_consensus_singletons_require_the_system_creation_path() {
        let mut store = ObjectStore::new();
        let bond = crate::governance::validator_bond_escrow_object(
            crate::DEFAULT_CHAIN_ID,
            &crate::governance::ValidatorBondEscrow::default(),
            0,
        )
        .unwrap();
        let history = crate::consensus::validator_key_history_object(
            crate::DEFAULT_CHAIN_ID,
            &crate::consensus::ValidatorKeyHistory::default(),
            0,
        )
        .unwrap();

        assert!(store.create(bond.clone()).is_err());
        assert!(store.create(history.clone()).is_err());
        store.system_create(bond).unwrap();
        store.system_create(history).unwrap();
    }

    #[test]
    fn update_bumps_version_and_state_root() {
        let mut s = ObjectStore::new();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        s.create(o.clone()).unwrap();
        let root_before = s.state_root();

        s.update(&o.id, &[1u8; 20], b"new data".to_vec()).unwrap();

        assert_eq!(s.version_of(&o.id).unwrap(), 1);
        let root_after = s.state_root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn update_by_non_owner_fails() {
        let mut s = ObjectStore::new();
        let owner = [1u8; 20];
        let other = [2u8; 20];
        let o = make_obj([1u8; 20], 1, owner);
        s.create(o.clone()).unwrap();

        let err = s.update(&o.id, &other, b"x".to_vec()).unwrap_err();
        assert!(matches!(err, PokerL1Error::NotOwner(_)));
    }

    #[test]
    fn update_immutable_fails() {
        let mut s = ObjectStore::new();
        let owner = [1u8; 20];
        let mut o = make_obj([1u8; 20], 1, owner);
        o.owner = Ownership::Immutable;
        s.create(o.clone()).unwrap();

        let err = s.update(&o.id, &owner, b"x".to_vec()).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectImmutable(_)));
    }

    #[test]
    fn transfer_changes_owner() {
        let mut s = ObjectStore::new();
        let owner = [1u8; 20];
        let new_owner = [2u8; 20];
        let o = make_obj([1u8; 20], 1, owner);
        s.create(o.clone()).unwrap();

        s.transfer(&o.id, &owner, new_owner).unwrap();
        assert!(s.read(&o.id).unwrap().can_write(&new_owner));
        assert!(!s.read(&o.id).unwrap().can_write(&owner));
    }

    #[test]
    fn delete_restores_state_root() {
        let mut s = ObjectStore::new();
        let empty_root = s.state_root();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        s.create(o.clone()).unwrap();
        assert_ne!(s.state_root(), empty_root);
        s.delete(&o.id).unwrap();
        assert_eq!(s.state_root(), empty_root, "删除后状态根应恢复");
    }

    #[test]
    fn batch_create_atomic_collision() {
        let mut s = ObjectStore::new();
        let o1 = make_obj([1u8; 20], 1, [1u8; 20]);
        let o2 = make_obj([2u8; 20], 1, [2u8; 20]);
        // o3 与 o1 同 ID（冲突）
        let o3 = make_obj([1u8; 20], 1, [3u8; 20]);

        let err = s.batch_create(vec![o1, o2, o3]).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectIDCollision(_)));
        // 冲突时整个批次都不写入
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn prove_inclusion_verifies() {
        let mut s = ObjectStore::new();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        s.create(o.clone()).unwrap();

        let path = s.prove(&o.id).unwrap();
        let value_bytes = borsh::to_vec(&o).unwrap();
        assert!(super::super::smt::SparseMerkleTree::verify(
            &s.state_root(),
            &o.id.merkle_key(),
            Some(&value_bytes),
            &path,
        ));
    }

    #[test]
    fn prove_nonexistence_verifies() {
        let mut s = ObjectStore::new();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        s.create(o).unwrap();

        let absent_id = ObjectID::new([9u8; 20], 999);
        let path = s.prove_nonexistence(&absent_id);
        assert!(path.is_empty_leaf);
        assert!(super::super::smt::SparseMerkleTree::verify(
            &s.state_root(),
            &absent_id.merkle_key(),
            None,
            &path,
        ));
    }
}
