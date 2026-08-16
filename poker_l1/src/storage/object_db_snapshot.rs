//! ObjectDb 的 Fork/Snapshot 实现（Track A — Task 3：Tx 执行引擎接线）。
//!
//! 功能：
//! - [`ObjectDbSnapshot`]：克隆 [`ObjectDb`] 的内存 SMT，所有写操作记录到 mutation log
//! - `apply_to()`：将 mutation log 回放到主 [`ObjectDb`]（commit）
//! - `discard()`：丢弃 snapshot（rollback）
//!
//! 设计动机：
//! - `build_block_from_vertex` 需要"试执行" vertex 中的 txs 以计算新 state_root
//! - 试执行失败时不应污染主 ObjectDb
//! - Fork/Snapshot 模式：克隆内存 SMT（O(n) 内存，n = live 对象数），
//!   mutation log 记录所有写操作，apply_to() 时按序回放到主 DB
//!
//! 与直接在 ObjectDb 上执行 + rollback 的对比：
//! - rollback 需要为每个操作保存 inverse（复杂、易遗漏状态泄漏）
//! - snapshot 只需保存正向 mutation log，apply_to 时复用 ObjectDb 现有方法
//! - snapshot 的 state_root() 直接从克隆的 SMT 读取，无需重新计算

use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, ObjectStore, Version};
use crate::{Address, Hash};

use super::object_backend::ObjectBackend;
use super::object_db::{ObjectDb, ObjectMutation};

/// 写操作记录（用于 apply_to 回放）。
#[derive(Debug, Clone)]
enum Mutation {
    /// 创建对象。
    Create(Object),
    /// 更新对象 data。
    Update {
        id: ObjectID,
        actor: Address,
        new_data: Vec<u8>,
    },
    /// 转移对象所有权。
    Transfer {
        id: ObjectID,
        actor: Address,
        new_owner: Address,
    },
    /// 删除对象。
    Delete(ObjectID),
    /// Create a validated singleton through the system path.
    SystemCreate(Object),
    /// Replace a validated singleton through the system path.
    SystemReplace(Object),
    /// Create executable contract bytecode through the executor-only path.
    ContractCreate(Object),
    /// Replace executable contract bytecode through the executor-only path.
    ContractReplace(Object),
}

/// ObjectDb 的内存 fork（snapshot）。
///
/// 创建时克隆 ObjectDb 的 `ObjectStore`（含 SMT + objects HashMap），
/// 后续所有写操作同时作用于克隆的 store（保持 state_root 一致）和 mutation log（供回放）。
/// 读操作直接走克隆的 store。
///
/// `apply_to(db)` 将 mutation log 按序回放到主 ObjectDb（写 RocksDB + 内存 SMT）。
/// `discard()` 直接丢弃 snapshot，不影响主 DB。
pub struct ObjectDbSnapshot {
    /// 克隆自 ObjectDb.store，用于独立计算 state_root + 服务读请求。
    store: ObjectStore,
    /// 写操作记录，按发生顺序排列。apply_to() 时按序回放。
    mutations: Vec<Mutation>,
}

impl ObjectDbSnapshot {
    /// 从 ObjectDb 创建 snapshot（fork 当前内存状态）。
    ///
    /// 注意：此方法需要访问 ObjectDb 的私有 `store` 字段，
    /// 故通过 ObjectDb::create_snapshot() 调用（见 object_db.rs）。
    pub(crate) fn from_store(store: ObjectStore) -> Self {
        Self {
            store,
            mutations: Vec::new(),
        }
    }

    /// Create a nested transaction snapshot from this candidate state.
    ///
    /// Block validation already runs in an outer snapshot.  Each transaction nevertheless needs
    /// its own child boundary: a failed call must not alter the outer candidate state that the
    /// block root commits to.
    pub(crate) fn create_child_snapshot(&self) -> Self {
        Self::from_store(self.store.clone())
    }

    /// 将 mutation log 回放到主 ObjectDb（commit）。
    ///
    /// 所有 mutation 在主库克隆上重新校验，并通过一个 RocksDB WriteBatch 提交。
    pub fn apply_to(self, db: &mut ObjectDb) -> PokerL1Result<()> {
        let mutations = self
            .mutations
            .into_iter()
            .map(|mutation| match mutation {
                Mutation::Create(object) => ObjectMutation::Create(object),
                Mutation::Update {
                    id,
                    actor,
                    new_data,
                } => ObjectMutation::Update {
                    id,
                    actor,
                    new_data,
                },
                Mutation::Transfer {
                    id,
                    actor,
                    new_owner,
                } => ObjectMutation::Transfer {
                    id,
                    actor,
                    new_owner,
                },
                Mutation::Delete(id) => ObjectMutation::Delete(id),
                Mutation::SystemCreate(object) => ObjectMutation::SystemCreate(object),
                Mutation::SystemReplace(object) => ObjectMutation::SystemReplace(object),
                Mutation::ContractCreate(object) => ObjectMutation::ContractCreate(object),
                Mutation::ContractReplace(object) => ObjectMutation::ContractReplace(object),
            })
            .collect();
        db.apply_batch(mutations)
    }

    /// Persist the outer block snapshot with a synchronous WAL flush.
    pub(crate) fn apply_to_durable(self, db: &mut ObjectDb) -> PokerL1Result<()> {
        let mutations = self
            .mutations
            .into_iter()
            .map(|mutation| match mutation {
                Mutation::Create(object) => ObjectMutation::Create(object),
                Mutation::Update {
                    id,
                    actor,
                    new_data,
                } => ObjectMutation::Update {
                    id,
                    actor,
                    new_data,
                },
                Mutation::Transfer {
                    id,
                    actor,
                    new_owner,
                } => ObjectMutation::Transfer {
                    id,
                    actor,
                    new_owner,
                },
                Mutation::Delete(id) => ObjectMutation::Delete(id),
                Mutation::SystemCreate(object) => ObjectMutation::SystemCreate(object),
                Mutation::SystemReplace(object) => ObjectMutation::SystemReplace(object),
                Mutation::ContractCreate(object) => ObjectMutation::ContractCreate(object),
                Mutation::ContractReplace(object) => ObjectMutation::ContractReplace(object),
            })
            .collect();
        db.apply_batch_durable(mutations)
    }

    /// Merge this nested snapshot into an outer snapshot.
    ///
    /// There is no RocksDB write at this level; all mutations are replayed into the parent's
    /// isolated store and are later persisted by the outer `apply_to` batch.  The child was
    /// validated against the exact parent view while the block commit lock was held, so any error
    /// here is treated as a consistency failure rather than an ordinary transaction failure.
    pub(crate) fn apply_to_snapshot(self, parent: &mut Self) -> PokerL1Result<()> {
        for mutation in self.mutations {
            match mutation {
                Mutation::Create(object) => parent.create(object)?,
                Mutation::Update {
                    id,
                    actor,
                    new_data,
                } => parent.update(&id, &actor, new_data)?,
                Mutation::Transfer {
                    id,
                    actor,
                    new_owner,
                } => parent.transfer(&id, &actor, new_owner)?,
                Mutation::Delete(id) => {
                    parent.delete(&id)?;
                }
                Mutation::SystemCreate(object) => parent.system_create(object)?,
                Mutation::SystemReplace(object) => parent.replace_system_object(object)?,
                Mutation::ContractCreate(object) => parent.create_contract_object(object)?,
                Mutation::ContractReplace(object) => parent.replace_contract_object(object)?,
            }
        }
        Ok(())
    }

    /// 丢弃 snapshot（rollback，不写回主 DB）。
    pub fn discard(self) {
        // 显式 drop，语义清晰
        drop(self);
    }

    /// 已记录的 mutation 数量（用于测试 / 调试）。
    pub fn mutation_count(&self) -> usize {
        self.mutations.len()
    }

    /// Iterate over every live object in this isolated candidate state.
    pub fn iter(&self) -> impl Iterator<Item = &Object> {
        self.store.iter()
    }

    /// Create a validated singleton in an isolated snapshot.
    ///
    /// This mirrors `ObjectDb`'s system-only creation rule so Fast Sync can import a complete
    /// post-genesis state without treating the monetary capability as an ordinary object.
    pub(crate) fn system_create(&mut self, object: Object) -> PokerL1Result<()> {
        self.store.system_create(object.clone())?;
        self.mutations.push(Mutation::SystemCreate(object));
        Ok(())
    }
}

impl ObjectBackend for ObjectDbSnapshot {
    fn create(&mut self, object: Object) -> PokerL1Result<()> {
        self.store.create(object.clone())?;
        self.mutations.push(Mutation::Create(object));
        Ok(())
    }

    fn system_create(&mut self, object: Object) -> PokerL1Result<()> {
        Self::system_create(self, object)
    }

    fn create_contract_object(&mut self, object: Object) -> PokerL1Result<()> {
        if !crate::vm::contract::is_contract_object(&object) {
            return Err(PokerL1Error::Other(
                "contract object creation requires a Contract object".into(),
            ));
        }
        self.store.system_create(object.clone())?;
        self.mutations.push(Mutation::ContractCreate(object));
        Ok(())
    }

    fn read(&self, id: &ObjectID) -> PokerL1Result<Object> {
        Ok(self.store.read(id)?.clone())
    }

    fn version_of(&self, id: &ObjectID) -> PokerL1Result<Version> {
        self.store.version_of(id)
    }

    fn update(&mut self, id: &ObjectID, actor: &Address, new_data: Vec<u8>) -> PokerL1Result<()> {
        self.store.update(id, actor, new_data.clone())?;
        self.mutations.push(Mutation::Update {
            id: *id,
            actor: *actor,
            new_data,
        });
        Ok(())
    }

    fn transfer(
        &mut self,
        id: &ObjectID,
        actor: &Address,
        new_owner: Address,
    ) -> PokerL1Result<()> {
        self.store.transfer(id, actor, new_owner)?;
        self.mutations.push(Mutation::Transfer {
            id: *id,
            actor: *actor,
            new_owner,
        });
        Ok(())
    }

    fn delete(&mut self, id: &ObjectID) -> PokerL1Result<Object> {
        let deleted = self.store.delete(id)?;
        self.mutations.push(Mutation::Delete(*id));
        Ok(deleted)
    }

    fn replace_system_object(&mut self, object: Object) -> PokerL1Result<()> {
        self.store.system_replace(object.clone())?;
        self.mutations.push(Mutation::SystemReplace(object));
        Ok(())
    }

    fn replace_contract_object(&mut self, object: Object) -> PokerL1Result<()> {
        if !crate::vm::contract::is_contract_object(&object) {
            return Err(PokerL1Error::Other(
                "contract object replacement requires a Contract object".into(),
            ));
        }
        self.store.system_replace(object.clone())?;
        self.mutations.push(Mutation::ContractReplace(object));
        Ok(())
    }

    fn state_root(&self) -> Hash {
        self.store.state_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::{Object, ObjectID, Ownership};

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
    fn snapshot_isolates_writes_from_main_db() {
        let mut db = ObjectDb::open_inmemory().expect("打开 ObjectDb 失败");
        let owner = [1u8; 20];
        let obj = make_obj(owner, 1, owner);
        db.create(obj.clone()).unwrap();
        let root_before = db.state_root();

        // 创建 snapshot
        let mut snap = db.create_snapshot();
        let snap_root_before = snap.state_root();
        assert_eq!(
            snap_root_before, root_before,
            "snapshot 初始 state_root 应等于主 DB"
        );

        // 在 snapshot 上写新对象
        let new_obj = make_obj(owner, 2, owner);
        snap.create(new_obj.clone()).expect("snapshot create");
        assert_eq!(snap.mutation_count(), 1);

        // snapshot state_root 应变化
        let snap_root_after = snap.state_root();
        assert_ne!(
            snap_root_after, snap_root_before,
            "snapshot state_root 应变化"
        );

        // 主 DB state_root 应不变
        assert_eq!(db.state_root(), root_before, "主 DB state_root 应不变");

        // 主 DB 应读不到 new_obj
        assert!(db.read(&new_obj.id).is_err(), "主 DB 不应有 new_obj");
        // snapshot 应读得到
        assert!(snap.read(&new_obj.id).is_ok(), "snapshot 应有 new_obj");
    }

    #[test]
    fn snapshot_apply_to_commits_mutations() {
        let mut db = ObjectDb::open_inmemory().expect("打开 ObjectDb 失败");
        let owner = [1u8; 20];
        let obj = make_obj(owner, 1, owner);
        db.create(obj.clone()).unwrap();
        let root_before = db.state_root();

        let mut snap = db.create_snapshot();
        let new_obj = make_obj(owner, 2, owner);
        snap.create(new_obj.clone()).unwrap();
        snap.update(&obj.id, &owner, b"updated".to_vec()).unwrap();

        let snap_root = snap.state_root();
        assert_ne!(snap_root, root_before);

        // apply_to 提交
        snap.apply_to(&mut db).expect("apply_to");

        // 主 DB state_root 应等于 snapshot 的 state_root
        assert_eq!(
            db.state_root(),
            snap_root,
            "apply_to 后主 DB state_root 应等于 snapshot"
        );

        // 主 DB 应能读到 new_obj
        let read = db.read(&new_obj.id).expect("主 DB 应有 new_obj");
        assert_eq!(read, new_obj);

        // 主 DB 应能读到 obj 的更新
        let updated = db.read(&obj.id).expect("主 DB 应有 obj");
        assert_eq!(updated.data, b"updated");
        assert_eq!(updated.version, 1);
    }

    #[test]
    fn snapshot_discard_does_not_affect_main_db() {
        let mut db = ObjectDb::open_inmemory().expect("打开 ObjectDb 失败");
        let owner = [1u8; 20];
        let obj = make_obj(owner, 1, owner);
        db.create(obj.clone()).unwrap();
        let root_before = db.state_root();

        let mut snap = db.create_snapshot();
        snap.create(make_obj(owner, 2, owner)).unwrap();
        snap.discard();

        assert_eq!(db.state_root(), root_before, "discard 后主 DB 不变");
    }

    #[test]
    fn snapshot_delete_then_apply() {
        let mut db = ObjectDb::open_inmemory().expect("打开 ObjectDb 失败");
        let owner = [1u8; 20];
        let obj = make_obj(owner, 1, owner);
        db.create(obj.clone()).unwrap();

        let mut snap = db.create_snapshot();
        snap.delete(&obj.id).unwrap();
        let snap_root = snap.state_root();

        snap.apply_to(&mut db).expect("apply_to");

        assert_eq!(db.state_root(), snap_root);
        assert!(db.read(&obj.id).is_err(), "apply_to 后主 DB 应已删除 obj");
    }

    #[test]
    fn snapshot_transfer_then_apply() {
        let mut db = ObjectDb::open_inmemory().expect("打开 ObjectDb 失败");
        let owner = [1u8; 20];
        let new_owner = [2u8; 20];
        let obj = make_obj(owner, 1, owner);
        db.create(obj.clone()).unwrap();

        let mut snap = db.create_snapshot();
        snap.transfer(&obj.id, &owner, new_owner).unwrap();
        snap.apply_to(&mut db).expect("apply_to");

        let read = db.read(&obj.id).unwrap();
        assert!(read.can_write(&new_owner), "transfer 后新 owner 应可写");
        assert!(!read.can_write(&owner), "transfer 后旧 owner 应不可写");
    }

    #[test]
    fn snapshot_object_backend_trait_dispatch() {
        let mut db = ObjectDb::open_inmemory().expect("打开 ObjectDb 失败");
        let owner = [1u8; 20];
        let obj = make_obj(owner, 1, owner);
        db.create(obj.clone()).unwrap();

        // 通过 trait 对象调用
        let mut snap: Box<dyn ObjectBackend> = Box::new(db.create_snapshot());
        let read = snap.read(&obj.id).expect("trait dispatch read");
        assert_eq!(read, obj);
        assert_eq!(snap.state_root(), db.state_root());
    }
}
