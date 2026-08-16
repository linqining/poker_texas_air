//! ObjectDb（SubTask 4.2 + 4.4 — 持久化 ObjectStore + SMT 状态根）
//!
//! 功能：
//! - 持久化所有 live 对象到 RocksDB（CF `objects`，key = `ObjectID::to_bytes()` → value = `BCS(Object)`）
//! - 内存中维护 `ObjectStore`（含 Sparse Merkle Tree）用于状态根计算
//! - 启动时从 RocksDB 全量加载到 ObjectStore（重建 SMT）
//! - 写入同时更新 ObjectStore + RocksDB
//!
//! 设计：
//! - `read` 返回 `Object` 的 clone（无法借用 RocksDB 内部缓冲区）
//! - 写入顺序：先持久化到 RocksDB（含 BCS 校验），再更新内存 SMT；若 DB 写失败则内存不变
//! - 删除顺序：先从内存删除（含存在性校验），再持久化删除；若 DB 写失败则内存已删除（不一致由重启恢复）

use std::path::Path;
use std::sync::Arc;

use rocksdb::{ColumnFamilyDescriptor, DB, IteratorMode, Options, WriteBatch};

use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::smt::MerklePath;
use crate::object_model::{Object, ObjectID, ObjectStore, Version};
use crate::{Address, Hash};

/// `objects` 列族名。
const OBJECTS_CF: &str = "objects";

/// A validated object mutation committed as part of one RocksDB batch.
#[derive(Debug, Clone)]
pub(crate) enum ObjectMutation {
    /// Create an object.
    Create(Object),
    /// Update an object's data as `actor`.
    Update {
        id: ObjectID,
        actor: Address,
        new_data: Vec<u8>,
    },
    /// Transfer an address-owned object.
    Transfer {
        id: ObjectID,
        actor: Address,
        new_owner: Address,
    },
    /// Delete an object.
    Delete(ObjectID),
    /// Create a validated singleton through a trusted system path.
    SystemCreate(Object),
    /// Replace a validated singleton through a trusted system path.
    SystemReplace(Object),
    /// Create executable contract bytecode through the executor-only path.
    ContractCreate(Object),
    /// Replace executable contract bytecode through the executor-only path.
    ContractReplace(Object),
}

/// 持久化 ObjectStore（RocksDB + 内存 SMT）。
///
/// 启动时从 RocksDB 全量加载对象到内存 `ObjectStore`，重建 Sparse Merkle Tree；
/// 后续读写同时维护 RocksDB 与内存 SMT，保证 `state_root()` 计算可用。
pub struct ObjectDb {
    /// RocksDB 句柄（CF `objects`）。
    db: Arc<DB>,
    /// 内存版 ObjectStore（含 SMT backing），用于状态根计算与证明生成。
    store: ObjectStore,
}

impl ObjectDb {
    /// 打开（或创建）指定路径下的 ObjectDb。
    ///
    /// 启动时遍历 `objects` CF 全量加载到内存 `ObjectStore`，重建 SMT。
    pub fn open(path: impl AsRef<Path>) -> PokerL1Result<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let objects_cf = ColumnFamilyDescriptor::new(OBJECTS_CF, Options::default());
        let db = DB::open_cf_descriptors(&db_opts, path, vec![objects_cf])
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;

        let mut store = ObjectStore::new();
        let cf = db
            .cf_handle(OBJECTS_CF)
            .expect("objects CF 必须存在（由 open 创建）");
        let iter = db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (_key, value) = item.map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
            let object: Object = borsh::from_slice(&value)?;
            // 启动加载：DB 中的对象不应冲突；若冲突说明 DB 已损坏，返回错误
            if crate::economics::is_treasury_cap_object(&object)
                || crate::economics::is_fee_policy_object(&object)
                || crate::consensus::validator_set::is_validator_set_object(&object)
                || crate::governance::is_governance_state_object(&object)
                || crate::bridge::is_bridge_registry_config_object(&object)
                || crate::bridge::is_bridge_replay_state_object(&object)
                || crate::genesis::is_genesis_anchor_object(&object)
                || crate::governance::validator_bond_escrow::is_validator_bond_escrow_object(
                    &object,
                )
                || crate::consensus::validator_key_history::is_validator_key_history_object(&object)
                || crate::vm::precompile::is_precompile_governance_state_object(&object)
                || crate::vm::contract::is_contract_object(&object)
                || crate::vm::contract::is_contract_upgrade_state_object(&object)
            {
                store.system_create(object)?;
            } else {
                store.create(object)?;
            }
        }

        Ok(Self {
            db: Arc::new(db),
            store,
        })
    }

    /// 打开一个临时目录下的 ObjectDb（用于测试 / 开发）。
    ///
    /// 实现说明：使用 `std::env::temp_dir()` + 随机后缀生成唯一路径，
    /// 避免对 `tempfile` crate 的非测试依赖。
    pub fn open_inmemory() -> PokerL1Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "poker_l1_objectdb_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        Self::open(path)
    }

    /// 获取 `objects` CF 句柄。
    fn objects_cf(&self) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(OBJECTS_CF)
            .expect("objects CF 必须存在（由 open 创建）")
    }

    /// 当前全局状态根（所有 live 对象的 Sparse Merkle Root）。
    pub const fn state_root(&self) -> Hash {
        self.store.state_root()
    }

    /// 创建对象。ObjectID 冲突返回 `ObjectIDCollision`（NEW-L4）。
    ///
    /// 写入顺序：先持久化到 RocksDB，再更新内存 SMT；若 DB 写失败则内存不变。
    pub fn create(&mut self, object: Object) -> PokerL1Result<()> {
        self.apply_batch(vec![ObjectMutation::Create(object)])
    }

    /// Atomically create multiple objects in one durable write and one in-memory SMT staging pass.
    ///
    /// This is the bulk counterpart of [`Self::create`].  It is intended for trusted import and
    /// genesis-style callers that have already assembled a complete object set; collisions still
    /// reject the entire batch without changing either RocksDB or the live state root.
    pub fn create_batch(&mut self, objects: Vec<Object>) -> PokerL1Result<()> {
        self.apply_batch(objects.into_iter().map(ObjectMutation::Create).collect())
    }

    /// 读取对象（返回 clone，因为不能借用 RocksDB 内部缓冲区）。
    pub fn read(&self, id: &ObjectID) -> PokerL1Result<Object> {
        // 内存查询更快，直接走内存
        Ok(self.store.read(id)?.clone())
    }

    /// 查询对象版本号。
    pub fn version_of(&self, id: &ObjectID) -> PokerL1Result<Version> {
        self.store.version_of(id)
    }

    /// 更新对象。校验：对象存在、可写（非 Immutable）、actor 有写权。
    /// 成功后 version += 1，SMT 同步更新。
    ///
    /// 写入顺序：先内存更新（含所有权校验），再持久化；若 DB 写失败则内存已更新
    /// （Phase 1 接受此不一致，重启后从 DB 恢复）。
    pub fn update(
        &mut self,
        id: &ObjectID,
        actor: &Address,
        new_data: Vec<u8>,
    ) -> PokerL1Result<()> {
        self.apply_batch(vec![ObjectMutation::Update {
            id: *id,
            actor: *actor,
            new_data,
        }])
    }

    /// 转移所有权（仅 AddressOwned 对象可转移）。
    pub fn transfer(
        &mut self,
        id: &ObjectID,
        actor: &Address,
        new_owner: Address,
    ) -> PokerL1Result<()> {
        self.apply_batch(vec![ObjectMutation::Transfer {
            id: *id,
            actor: *actor,
            new_owner,
        }])
    }

    /// 删除对象（从 SMT 与 RocksDB 同步移除）。
    ///
    /// 写入顺序：先内存删除（含存在性校验），再持久化删除。
    pub fn delete(&mut self, id: &ObjectID) -> PokerL1Result<Object> {
        let deleted = self.read(id)?;
        self.apply_batch(vec![ObjectMutation::Delete(*id)])?;
        Ok(deleted)
    }

    /// Validate all mutations against a cloned in-memory store and commit their final values in
    /// one RocksDB `WriteBatch`. The live SMT is replaced only after the durable write succeeds.
    pub(crate) fn apply_batch(&mut self, mutations: Vec<ObjectMutation>) -> PokerL1Result<()> {
        self.apply_batch_with_durability(mutations, false)
    }

    /// Apply a block-commit batch with a synchronous WAL flush.
    pub(crate) fn apply_batch_durable(
        &mut self,
        mutations: Vec<ObjectMutation>,
    ) -> PokerL1Result<()> {
        self.apply_batch_with_durability(mutations, true)
    }

    fn apply_batch_with_durability(
        &mut self,
        mutations: Vec<ObjectMutation>,
        sync: bool,
    ) -> PokerL1Result<()> {
        if mutations.is_empty() {
            return Ok(());
        }

        let mut staged = self.store.clone();
        let mut touched = Vec::<ObjectID>::new();
        for mutation in mutations {
            let id = match mutation {
                ObjectMutation::Create(object) => {
                    let id = object.id;
                    staged.create(object)?;
                    id
                }
                ObjectMutation::Update {
                    id,
                    actor,
                    new_data,
                } => {
                    staged.update(&id, &actor, new_data)?;
                    id
                }
                ObjectMutation::Transfer {
                    id,
                    actor,
                    new_owner,
                } => {
                    staged.transfer(&id, &actor, new_owner)?;
                    id
                }
                ObjectMutation::Delete(id) => {
                    staged.delete(&id)?;
                    id
                }
                ObjectMutation::SystemCreate(object) => {
                    let id = object.id;
                    staged.system_create(object)?;
                    id
                }
                ObjectMutation::SystemReplace(object) => {
                    let id = object.id;
                    staged.system_replace(object)?;
                    id
                }
                ObjectMutation::ContractCreate(object) => {
                    let id = object.id;
                    if !crate::vm::contract::is_contract_object(&object) {
                        return Err(PokerL1Error::Other(
                            "contract create mutation requires a Contract object".into(),
                        ));
                    }
                    staged.system_create(object)?;
                    id
                }
                ObjectMutation::ContractReplace(object) => {
                    let id = object.id;
                    if !crate::vm::contract::is_contract_object(&object) {
                        return Err(PokerL1Error::Other(
                            "contract replace mutation requires a Contract object".into(),
                        ));
                    }
                    staged.system_replace(object)?;
                    id
                }
            };
            if !touched.contains(&id) {
                touched.push(id);
            }
        }

        let cf = self.objects_cf();
        let mut batch = WriteBatch::default();
        for id in touched {
            match staged.read(&id) {
                Ok(object) => batch.put_cf(cf, id.to_bytes(), borsh::to_vec(object)?),
                Err(PokerL1Error::ObjectNotFound(_)) => batch.delete_cf(cf, id.to_bytes()),
                Err(error) => return Err(error),
            }
        }
        if sync {
            let mut options = rocksdb::WriteOptions::default();
            options.set_sync(true);
            self.db.write_opt(batch, &options)
        } else {
            self.db.write(batch)
        }
        .map_err(|error| PokerL1Error::Rocksdb(error.to_string()))?;
        self.store = staged;
        Ok(())
    }

    /// 当前 live 对象数量。
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// 生成对象的 Merkle 包含证明（供轻客户端验证，R5-M8）。
    pub fn prove(&self, id: &ObjectID) -> PokerL1Result<MerklePath> {
        self.store.prove(id)
    }

    /// 生成非包含证明（证明某 ObjectID 不存在）。
    pub fn prove_nonexistence(&self, id: &ObjectID) -> MerklePath {
        self.store.prove_nonexistence(id)
    }

    /// 迭代所有 live 对象（借用内存）。
    pub fn iter(&self) -> impl Iterator<Item = &Object> {
        self.store.iter()
    }

    /// 创建当前状态的 fork（snapshot），用于 tx 执行引擎的"试执行 → 提交/回滚"模式。
    ///
    /// 克隆内存 `ObjectStore`（含 SMT + objects HashMap），不复制 RocksDB。
    /// 后续 snapshot 上的写操作同时作用于克隆的 store（保持 state_root 一致）和 mutation log。
    /// `apply_to(self)` 将 mutation log 回放到主 ObjectDb（commit），`discard()` 丢弃（rollback）。
    ///
    /// 使用场景：`build_block_from_vertex` 试执行 vertex 的 txs 计算新 state_root，
    /// 试执行失败或决定不提交时调用 `discard()`，提交时调用 `apply_to()`。
    pub fn create_snapshot(&self) -> super::object_db_snapshot::ObjectDbSnapshot {
        super::object_db_snapshot::ObjectDbSnapshot::from_store(self.store.clone())
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
    fn open_creates_cf_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        let db = ObjectDb::open(dir.path()).unwrap();
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
        // 空状态根 = 空树根
        let empty_root = ObjectStore::new().state_root();
        assert_eq!(db.state_root(), empty_root);
    }

    #[test]
    fn create_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = ObjectDb::open(dir.path()).unwrap();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        db.create(o.clone()).unwrap();

        let read = db.read(&o.id).unwrap();
        assert_eq!(read, o);
        assert_eq!(db.version_of(&o.id).unwrap(), 0);
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn create_collision_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = ObjectDb::open(dir.path()).unwrap();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        db.create(o.clone()).unwrap();

        let err = db.create(o).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectIDCollision(_)));
        assert_eq!(db.len(), 1, "冲突时不应增加计数");
    }

    #[test]
    fn read_missing_returns_object_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let db = ObjectDb::open(dir.path()).unwrap();
        let id = ObjectID::new([9u8; 20], 999);
        let err = db.read(&id).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectNotFound(_)));
    }

    #[test]
    fn update_bumps_version_and_state_root() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = ObjectDb::open(dir.path()).unwrap();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        db.create(o.clone()).unwrap();
        let root_before = db.state_root();

        db.update(&o.id, &[1u8; 20], b"new data".to_vec()).unwrap();

        assert_eq!(db.version_of(&o.id).unwrap(), 1);
        let root_after = db.state_root();
        assert_ne!(root_before, root_after);

        // 验证 DB 中也是最新版本
        let read = db.read(&o.id).unwrap();
        assert_eq!(read.version, 1);
        assert_eq!(read.data, b"new data");
    }

    #[test]
    fn update_by_non_owner_fails() {
        let dir = tempfile::tempdir().unwrap();
        let owner = [1u8; 20];
        let other = [2u8; 20];
        let mut db = ObjectDb::open(dir.path()).unwrap();
        let o = make_obj([1u8; 20], 1, owner);
        db.create(o.clone()).unwrap();

        let err = db.update(&o.id, &other, b"x".to_vec()).unwrap_err();
        assert!(matches!(err, PokerL1Error::NotOwner(_)));
        // 内存与 DB 都不应被修改
        assert_eq!(db.version_of(&o.id).unwrap(), 0);
    }

    #[test]
    fn update_immutable_fails() {
        let dir = tempfile::tempdir().unwrap();
        let owner = [1u8; 20];
        let mut db = ObjectDb::open(dir.path()).unwrap();
        let mut o = make_obj([1u8; 20], 1, owner);
        o.owner = Ownership::Immutable;
        db.create(o.clone()).unwrap();

        let err = db.update(&o.id, &owner, b"x".to_vec()).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectImmutable(_)));
    }

    #[test]
    fn transfer_changes_owner() {
        let dir = tempfile::tempdir().unwrap();
        let owner = [1u8; 20];
        let new_owner = [2u8; 20];
        let mut db = ObjectDb::open(dir.path()).unwrap();
        let o = make_obj([1u8; 20], 1, owner);
        db.create(o.clone()).unwrap();

        db.transfer(&o.id, &owner, new_owner).unwrap();
        let read = db.read(&o.id).unwrap();
        assert!(read.can_write(&new_owner));
        assert!(!read.can_write(&owner));
        assert_eq!(read.version, 1);
    }

    #[test]
    fn delete_removes_object() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = ObjectDb::open(dir.path()).unwrap();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        db.create(o.clone()).unwrap();
        let root_before_delete = db.state_root();
        assert_ne!(root_before_delete, ObjectStore::new().state_root());

        let deleted = db.delete(&o.id).unwrap();
        assert_eq!(deleted, o);
        assert_eq!(db.len(), 0);

        // 读不到了
        let err = db.read(&o.id).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectNotFound(_)));

        // 状态根恢复为空树根
        assert_eq!(db.state_root(), ObjectStore::new().state_root());
    }

    #[test]
    fn delete_missing_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = ObjectDb::open(dir.path()).unwrap();
        let id = ObjectID::new([9u8; 20], 999);
        let err = db.delete(&id).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectNotFound(_)));
    }

    #[test]
    fn state_root_changes_with_writes() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = ObjectDb::open(dir.path()).unwrap();
        let empty_root = db.state_root();

        let o1 = make_obj([1u8; 20], 1, [1u8; 20]);
        db.create(o1.clone()).unwrap();
        let root1 = db.state_root();
        assert_ne!(empty_root, root1);

        let o2 = make_obj([2u8; 20], 1, [2u8; 20]);
        db.create(o2).unwrap();
        let root2 = db.state_root();
        assert_ne!(root1, root2);

        db.delete(&o1.id).unwrap();
        let root3 = db.state_root();
        assert_ne!(root2, root3);
    }

    #[test]
    fn prove_inclusion_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = ObjectDb::open(dir.path()).unwrap();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        db.create(o.clone()).unwrap();

        let path = db.prove(&o.id).unwrap();
        let value_bytes = borsh::to_vec(&o).unwrap();
        assert!(crate::object_model::SparseMerkleTree::verify(
            &db.state_root(),
            &o.id.merkle_key(),
            Some(&value_bytes),
            &path,
        ));
    }

    #[test]
    fn prove_nonexistence_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = ObjectDb::open(dir.path()).unwrap();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        db.create(o).unwrap();

        let absent_id = ObjectID::new([9u8; 20], 999);
        let path = db.prove_nonexistence(&absent_id);
        assert!(path.is_empty_leaf);
        assert!(crate::object_model::SparseMerkleTree::verify(
            &db.state_root(),
            &absent_id.merkle_key(),
            None,
            &path,
        ));
    }

    #[test]
    fn persist_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let o1 = make_obj([1u8; 20], 1, [1u8; 20]);
        let o2 = make_obj([2u8; 20], 1, [2u8; 20]);
        let root_after_writes = {
            let mut db = ObjectDb::open(dir.path()).unwrap();
            db.create(o1.clone()).unwrap();
            db.create(o2.clone()).unwrap();
            db.update(&o1.id, &[1u8; 20], b"updated".to_vec()).unwrap();
            db.state_root()
        };

        // 重新打开同一目录
        let db2 = ObjectDb::open(dir.path()).unwrap();
        assert_eq!(db2.len(), 2);
        assert_eq!(db2.state_root(), root_after_writes, "重启后状态根必须一致");

        // 验证 o1 是更新后的版本
        let read1 = db2.read(&o1.id).unwrap();
        assert_eq!(read1.version, 1);
        assert_eq!(read1.data, b"updated");

        let read2 = db2.read(&o2.id).unwrap();
        assert_eq!(read2.version, 0);
    }

    #[test]
    fn rejected_batch_leaves_memory_and_rocksdb_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let owner = [1u8; 20];
        let first = make_obj(owner, 1, owner);
        let existing = make_obj(owner, 2, owner);

        {
            let mut db = ObjectDb::open(dir.path()).unwrap();
            db.create(first.clone()).unwrap();
            db.create(existing.clone()).unwrap();
            let root_before = db.state_root();

            let error = db
                .apply_batch(vec![
                    ObjectMutation::Update {
                        id: first.id,
                        actor: owner,
                        new_data: b"must-not-commit".to_vec(),
                    },
                    ObjectMutation::Create(existing.clone()),
                ])
                .unwrap_err();

            assert!(matches!(error, PokerL1Error::ObjectIDCollision(id) if id == existing.id));
            assert_eq!(db.state_root(), root_before);
            assert_eq!(db.read(&first.id).unwrap(), first);
        }

        let reopened = ObjectDb::open(dir.path()).unwrap();
        assert_eq!(reopened.read(&first.id).unwrap(), first);
        assert_eq!(reopened.read(&existing.id).unwrap(), existing);
    }

    #[test]
    fn iter_yields_all_live_objects() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = ObjectDb::open(dir.path()).unwrap();
        let objs = vec![
            make_obj([1u8; 20], 1, [1u8; 20]),
            make_obj([2u8; 20], 1, [2u8; 20]),
            make_obj([3u8; 20], 1, [3u8; 20]),
        ];
        for o in &objs {
            db.create(o.clone()).unwrap();
        }

        let collected: Vec<Object> = db.iter().cloned().collect();
        assert_eq!(collected.len(), 3);
        for o in &objs {
            assert!(collected.contains(o));
        }
    }

    #[test]
    fn open_inmemory_works() {
        let mut db = ObjectDb::open_inmemory().unwrap();
        let o = make_obj([1u8; 20], 1, [1u8; 20]);
        db.create(o.clone()).unwrap();
        assert_eq!(db.read(&o.id).unwrap(), o);
    }

    #[test]
    fn large_batch_persists() {
        let dir = tempfile::tempdir().unwrap();
        // 用 block scope 保证第一个 DB 实例在重新打开前释放 RocksDB 文件锁
        let (state_root, count) = {
            let mut db = ObjectDb::open(dir.path()).unwrap();
            // 创建 100 个对象
            for i in 0..100u64 {
                let o = make_obj([(i % 255) as u8 + 1; 20], i, [(i % 255) as u8 + 1; 20]);
                db.create(o).unwrap();
            }
            assert_eq!(db.len(), 100);
            (db.state_root(), db.len())
        };

        // 重启后全部恢复（第一个 DB 已 drop，文件锁释放）
        let db2 = ObjectDb::open(dir.path()).unwrap();
        assert_eq!(db2.len(), count);
        assert_eq!(db2.state_root(), state_root);
    }
}
