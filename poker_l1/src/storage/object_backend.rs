//! Object 读写后端抽象（Track A — Task 3：Tx 执行引擎接线）。
//!
//! 功能：
//! - 定义 [`ObjectBackend`] trait，抽象 Object 读写接口
//! - 使 `executor::execute_block` / `execute_tx` 可在 [`ObjectDb`] 或
//!   [`ObjectDbSnapshot`] 上泛型工作
//! - [`ObjectDb`] 实现：直接读写 RocksDB + 内存 SMT
//! - [`ObjectDbSnapshot`] 实现：在 fork 上试执行，记录 mutation log 供回放
//!
//! 设计动机：
//! - 单 validator 模式下 `build_block_from_vertex` 需要"试执行" vertex 中的 txs
//!   以计算新 state_root，但试执行失败时不应污染主 ObjectDb
//! - Fork/Snapshot 机制：克隆内存 SMT，所有写操作记录到 mutation log，
//!   `apply_to()` 将 log 回放到主 ObjectDb（commit），`discard()` 丢弃（rollback）

use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Version};
use crate::{Address, Hash};

/// Object 读写后端抽象。
///
/// 实现者：
/// - [`ObjectDb`](crate::storage::ObjectDb)：生产环境，直接读写 RocksDB + 内存 SMT
/// - [`ObjectDbSnapshot`](crate::storage::ObjectDbSnapshot)：fork 环境，克隆 SMT + mutation log
///
/// executor 层通过此 trait 泛型化，使"试执行 → 提交/回滚"模式成为可能。
pub trait ObjectBackend {
    /// 创建对象。ObjectID 冲突返回 `ObjectIDCollision`。
    fn create(&mut self, object: Object) -> PokerL1Result<()>;

    /// Create one validated, reserved system singleton.
    ///
    /// Ordinary contract backends must not accept this capability.  It is deliberately separate
    /// from [`Self::create`] so new consensus singletons cannot be pre-created through a regular
    /// transaction output.
    fn system_create(&mut self, _object: Object) -> PokerL1Result<()> {
        Err(PokerL1Error::Other(
            "system object creation is unavailable on this backend".into(),
        ))
    }

    /// Create executable contract bytecode through the executor-only path.
    fn create_contract_object(&mut self, _object: Object) -> PokerL1Result<()> {
        Err(PokerL1Error::Other(
            "contract object creation is unavailable on this backend".into(),
        ))
    }

    /// 读取对象（返回 clone，因为不能借用 RocksDB 内部缓冲区）。
    fn read(&self, id: &ObjectID) -> PokerL1Result<Object>;

    /// 查询对象版本号。
    fn version_of(&self, id: &ObjectID) -> PokerL1Result<Version>;

    /// 更新对象。校验：对象存在、可写（非 Immutable）、actor 有写权。
    /// 成功后 version += 1，SMT 同步更新。
    fn update(&mut self, id: &ObjectID, actor: &Address, new_data: Vec<u8>) -> PokerL1Result<()>;

    /// 转移所有权（仅 AddressOwned 对象可转移）。
    fn transfer(&mut self, id: &ObjectID, actor: &Address, new_owner: Address)
    -> PokerL1Result<()>;

    /// 删除对象（从 SMT 与持久化后端同步移除）。
    fn delete(&mut self, id: &ObjectID) -> PokerL1Result<Object>;

    /// Replace a set of consumed objects with newly created outputs.
    ///
    /// Backends with transactional storage should override this method. Fork/capture backends use
    /// the default ordered mutation path after callers have completed full preflight validation.
    fn replace_objects(
        &mut self,
        delete_ids: &[ObjectID],
        create_objects: Vec<Object>,
    ) -> PokerL1Result<()> {
        for id in delete_ids {
            self.delete(id)?;
        }
        for object in create_objects {
            self.create(object)?;
        }
        Ok(())
    }

    /// Replace one validated system-owned reserved object.
    ///
    /// Audited economics and consensus paths use this to advance singleton state
    /// without bypassing snapshot/commit semantics. Ordinary contract backends
    /// reject the capability unless they explicitly implement the system path.
    fn replace_system_object(&mut self, _object: Object) -> PokerL1Result<()> {
        Err(PokerL1Error::Other(
            "system object replacement is unavailable on this backend".into(),
        ))
    }

    /// Replace executable contract bytecode through the executor-only path.
    fn replace_contract_object(&mut self, _object: Object) -> PokerL1Result<()> {
        Err(PokerL1Error::Other(
            "contract object replacement is unavailable on this backend".into(),
        ))
    }

    /// 当前全局状态根（所有 live 对象的 Sparse Merkle Root）。
    fn state_root(&self) -> Hash;
}

/// A backend that can execute one transaction against an isolated child state and merge the
/// child only after the execution succeeds.
///
/// This is deliberately separate from [`ObjectBackend`].  A sequence such as a precompile
/// update followed by an invalid transaction output must never leave the precompile update in
/// consensus state merely because the last operation returned an error.  Both production
/// `ObjectDb` and block-validation `ObjectDbSnapshot` implement this boundary, so producers and
/// validators have identical failure semantics.
pub trait TransactionalObjectBackend: ObjectBackend {
    /// Isolated child state used for exactly one transaction.
    type Transaction: ObjectBackend;

    /// Start an isolated child state from the current committed view.
    fn begin_transaction(&self) -> Self::Transaction;

    /// Merge a successfully executed child state into this backend.
    ///
    /// Implementations must provide all-or-nothing persistence for this merge.  Callers discard
    /// the child on execution failure and never invoke this method in that case.
    fn commit_transaction(&mut self, transaction: Self::Transaction) -> PokerL1Result<()>;
}

// ============================================================
// ObjectDb 实现 ObjectBackend（委托现有方法）
// ============================================================

use super::object_db::ObjectDb;

impl ObjectBackend for ObjectDb {
    #[inline]
    fn create(&mut self, object: Object) -> PokerL1Result<()> {
        self.create(object)
    }

    #[inline]
    fn system_create(&mut self, object: Object) -> PokerL1Result<()> {
        use crate::storage::object_db::ObjectMutation;
        self.apply_batch(vec![ObjectMutation::SystemCreate(object)])
    }

    #[inline]
    fn create_contract_object(&mut self, object: Object) -> PokerL1Result<()> {
        use crate::storage::object_db::ObjectMutation;
        self.apply_batch(vec![ObjectMutation::ContractCreate(object)])
    }

    #[inline]
    fn read(&self, id: &ObjectID) -> PokerL1Result<Object> {
        self.read(id)
    }

    #[inline]
    fn version_of(&self, id: &ObjectID) -> PokerL1Result<Version> {
        self.version_of(id)
    }

    #[inline]
    fn update(&mut self, id: &ObjectID, actor: &Address, new_data: Vec<u8>) -> PokerL1Result<()> {
        self.update(id, actor, new_data)
    }

    #[inline]
    fn transfer(
        &mut self,
        id: &ObjectID,
        actor: &Address,
        new_owner: Address,
    ) -> PokerL1Result<()> {
        self.transfer(id, actor, new_owner)
    }

    #[inline]
    fn delete(&mut self, id: &ObjectID) -> PokerL1Result<Object> {
        self.delete(id)
    }

    #[inline]
    fn replace_objects(
        &mut self,
        delete_ids: &[ObjectID],
        create_objects: Vec<Object>,
    ) -> PokerL1Result<()> {
        use crate::storage::object_db::ObjectMutation;
        let mut mutations = Vec::with_capacity(delete_ids.len() + create_objects.len());
        mutations.extend(delete_ids.iter().copied().map(ObjectMutation::Delete));
        mutations.extend(create_objects.into_iter().map(ObjectMutation::Create));
        self.apply_batch(mutations)
    }

    #[inline]
    fn replace_system_object(&mut self, object: Object) -> PokerL1Result<()> {
        use crate::storage::object_db::ObjectMutation;
        self.apply_batch(vec![ObjectMutation::SystemReplace(object)])
    }

    #[inline]
    fn replace_contract_object(&mut self, object: Object) -> PokerL1Result<()> {
        use crate::storage::object_db::ObjectMutation;
        self.apply_batch(vec![ObjectMutation::ContractReplace(object)])
    }

    #[inline]
    fn state_root(&self) -> Hash {
        self.state_root()
    }
}

impl TransactionalObjectBackend for ObjectDb {
    type Transaction = super::object_db_snapshot::ObjectDbSnapshot;

    fn begin_transaction(&self) -> Self::Transaction {
        self.create_snapshot()
    }

    fn commit_transaction(&mut self, transaction: Self::Transaction) -> PokerL1Result<()> {
        transaction.apply_to(self)
    }
}

impl TransactionalObjectBackend for super::object_db_snapshot::ObjectDbSnapshot {
    type Transaction = super::object_db_snapshot::ObjectDbSnapshot;

    fn begin_transaction(&self) -> Self::Transaction {
        self.create_child_snapshot()
    }

    fn commit_transaction(&mut self, transaction: Self::Transaction) -> PokerL1Result<()> {
        transaction.apply_to_snapshot(self)
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

    /// 验证 ObjectDb 实现 ObjectBackend trait（编译时检查 + 运行时委托）。
    #[test]
    fn object_db_implements_object_backend() {
        let mut db = ObjectDb::open_inmemory().expect("打开 ObjectDb 失败");
        let owner = [1u8; 20];
        let obj = make_obj(owner, 1, owner);

        // 通过 trait 方法调用
        let backend: &mut dyn ObjectBackend = &mut db;
        backend.create(obj.clone()).expect("create via trait");
        let read = backend.read(&obj.id).expect("read via trait");
        assert_eq!(read, obj);
        assert_eq!(backend.version_of(&obj.id).unwrap(), 0);

        backend
            .update(&obj.id, &owner, b"new data".to_vec())
            .expect("update via trait");
        assert_eq!(backend.version_of(&obj.id).unwrap(), 1);

        let root_before = backend.state_root();
        let _deleted = backend.delete(&obj.id).expect("delete via trait");
        let root_after = backend.state_root();
        assert_ne!(root_before, root_after, "删除后状态根应变化");
    }
}
