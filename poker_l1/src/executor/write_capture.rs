//! WriteCaptureBackend —— 并行执行器的状态访问机制（Task P-1）。
//!
//! # 设计动机
//!
//! [`crate::storage::ObjectBackend::read`] 是 `&self`，而 `create/update/transfer/delete`
//! 是 `&mut self`。传统的并行执行要么给后端加锁（吞吐骤降），要么给每个 tx 做 O(n) 的
//! SMT fork（[`crate::storage::ObjectDbSnapshot`] 的克隆代价太高）。
//!
//! 本模块提供第三条路：**读委托给共享的 `&ObjectDb`（天然可被多线程共享引用），写进线程
//! 私有的 [`ObjectWriteLog`]**。这样并行波次内每个 worker：
//! - 读无锁（`&ObjectBackend::read` 走 `&ObjectDb`，多个 worker 共享同一引用）；
//! - 写无锁（写进自己的 `ObjectWriteLog`，线程间不共享可变状态）；
//! - 波次结束后串行 `apply_to` 把日志按序回放到主 [`crate::storage::ObjectDb`]。
//!
//! 这套机制**零 SMT clone**，且语义上等价于"在主库上串行执行"。
//!
//! # Read-Your-Writes
//!
//! 同一 tx 内可能先写后读同一对象（例如合约先 `object_write` 再 `object_read`）。
//! [`WriteCaptureBackend::read`] 先查自己的 log，命中则返回 log 中的最新值，
//! 未命中才委托给共享 `ObjectDb`。
//!
//! # Soundness 约束
//!
//! - [`ObjectWriteLog::apply_to`] **按写入顺序**回放，保证 merge 阶段与串行执行结果一致。
//! - 写校验（所有权 / 碰撞 / 存在性）在 capture 阶段就做一次，merge 阶段由 `ObjectDb`
//!   再做一次（纵深防御）；capture 校验保证 worker 间互不干扰，merge 校验保证最终一致。
//! - `state_root()` 在并行阶段不计算（仅 merge 后由主库算一次），此处返回共享库的当前
//!   根（仅供调试，不参与确定性判定）。

use std::collections::{HashMap, HashSet};

use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership, Version};
use crate::storage::object_db::ObjectMutation;
use crate::storage::{ObjectBackend, ObjectDb};
use crate::{Address, Hash};

/// Singleton economics objects still require a dedicated system-replacement path. Native coin
/// UTXOs are different: the audited economics APIs intentionally create/delete them while a
/// transaction is being captured. The direct `ObjectDb` backend already permits those UTXO
/// mutations, so rejecting them only in the capture backend made serial and parallel execution
/// diverge (native transfers failed only on the parallel path).
fn is_reserved_economic_singleton(object: &Object) -> bool {
    crate::economics::is_treasury_cap_object(object)
        || crate::economics::is_fee_policy_object(object)
}

/// 单条写操作记录（用于 apply_to 回放）。
///
/// 与 [`crate::storage::object_db_snapshot::Mutation`] 同构，但本模块独立定义，
/// 避免暴露 snapshot 模块的私有 enum。
#[derive(Debug, Clone)]
pub enum WriteOp {
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
}

impl WriteOp {
    /// 该写操作触及的 ObjectID（用于写集统计）。
    pub const fn target_id(&self) -> &ObjectID {
        match self {
            Self::Create(o) => &o.id,
            Self::Update { id, .. } => id,
            Self::Transfer { id, .. } => id,
            Self::Delete(id) => id,
        }
    }
}

/// 线程私有的写日志（替代 `&mut ObjectDb` 的写入侧）。
///
/// - `writes`：按发生顺序排列的写操作（apply_to 时按序回放）。
/// - `written_ids`：所有被写触及的 ObjectID 集合（冲突检测用，O(1) 查询）。
/// - `current`：被写对象的当前视图（Read-Your-Writes + 最新值查询用）。
///   key = ObjectID，value = 该对象在 log 末尾的快照（None 表示已被删除）。
///
/// `current` 与 `writes` 的末尾状态保持同步：每次写都更新 `current`。
#[derive(Debug, Default, Clone)]
pub struct ObjectWriteLog {
    /// 有序写操作记录。
    pub writes: Vec<WriteOp>,
    /// 写集（所有被触及的 ObjectID）。
    pub written_ids: HashSet<ObjectID>,
    /// 被写对象的当前视图：Some(obj) = 最新值；None = 已被本 log 删除。
    current: HashMap<ObjectID, Option<Object>>,
}

impl ObjectWriteLog {
    /// 创建空日志。
    pub fn new() -> Self {
        Self::default()
    }

    /// 是否为空（无任何写操作）。
    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }

    /// 写操作数量。
    pub fn len(&self) -> usize {
        self.writes.len()
    }

    /// 查询本 log 是否写过某对象（不论创建/更新/删除）。
    pub fn contains_write(&self, id: &ObjectID) -> bool {
        self.written_ids.contains(id)
    }

    /// 取本 log 中某对象的最新视图。
    ///
    /// 返回值语义：
    /// - `Some(Some(obj))`：本 log 写过该对象，且当前值为 `obj`。
    /// - `Some(None)`：本 log 已删除该对象。
    /// - `None`：本 log 未写过该对象（应委托共享库查询）。
    pub fn current(&self, id: &ObjectID) -> Option<Option<&Object>> {
        self.current.get(id).map(|v| v.as_ref())
    }

    /// 记录创建。
    fn push_create(&mut self, object: Object) {
        let id = object.id;
        self.written_ids.insert(id);
        self.current.insert(id, Some(object.clone()));
        self.writes.push(WriteOp::Create(object));
    }

    /// 记录更新（不含所有权校验，校验由 WriteCaptureBackend::update 负责）。
    ///
    /// `baseline` 为执行校验时解析出的当前对象快照（来自 log.current 或 shared），
    /// 用于在 current 视图中更新出 Read-Your-Writes 所需的最新值。
    fn push_update(&mut self, id: ObjectID, actor: Address, new_data: Vec<u8>, baseline: &Object) {
        self.written_ids.insert(id);
        // current 视图：基于 baseline 拷贝，替换 data + bump version。
        // version 由 apply_to 阶段在 ObjectDb::update 内部再处理一次；
        // 此处 bump 仅用于 Read-Your-Writes 的版本查询一致性。
        let mut view = baseline.clone();
        view.data = new_data.clone();
        view.bump_version();
        self.current.insert(id, Some(view));
        self.writes.push(WriteOp::Update {
            id,
            actor,
            new_data,
        });
    }

    /// 记录转移。
    fn push_transfer(
        &mut self,
        id: ObjectID,
        actor: Address,
        new_owner: Address,
        baseline: &Object,
    ) {
        self.written_ids.insert(id);
        let mut view = baseline.clone();
        view.owner = Ownership::AddressOwned { owner: new_owner };
        view.bump_version();
        self.current.insert(id, Some(view));
        self.writes.push(WriteOp::Transfer {
            id,
            actor,
            new_owner,
        });
    }

    /// 记录删除。
    fn push_delete(&mut self, id: ObjectID) {
        self.written_ids.insert(id);
        self.current.insert(id, None);
        self.writes.push(WriteOp::Delete(id));
    }

    /// 将日志原子提交到主 ObjectDb（commit）。
    ///
    /// capture 阶段已做过一次写校验，提交时 `ObjectDb` 在克隆状态上
    /// 再校验一次，然后使用单个 RocksDB WriteBatch 落盘。
    pub fn apply_to(self, db: &mut ObjectDb) -> PokerL1Result<()> {
        let mutations = self
            .writes
            .into_iter()
            .map(|op| match op {
                WriteOp::Create(object) => ObjectMutation::Create(object),
                WriteOp::Update {
                    id,
                    actor,
                    new_data,
                } => ObjectMutation::Update {
                    id,
                    actor,
                    new_data,
                },
                WriteOp::Transfer {
                    id,
                    actor,
                    new_owner,
                } => ObjectMutation::Transfer {
                    id,
                    actor,
                    new_owner,
                },
                WriteOp::Delete(id) => ObjectMutation::Delete(id),
            })
            .collect();
        db.apply_batch(mutations)
    }
}

/// 读委托共享 `&ObjectDb`，写进入私有 [`ObjectWriteLog`] 的并行执行后端。
///
/// 每个 worker 线程持有一个 `WriteCaptureBackend`：
/// - `read`：先查 `log.current(id)`（Read-Your-Writes），未命中委托 `shared.read(id)`。
/// - `create/update/transfer/delete`：先做只读校验，再记录到 `log`。
///
/// **为什么并发安全**：`shared: &ObjectDb` 是不可变共享引用（`ObjectDb` auto `Send+Sync`），
/// 多个 worker 可同时 `read`；写完全进各自私有的 `log`，线程间无共享可变状态。
pub struct WriteCaptureBackend<'a> {
    /// 共享只读基线（波次开始时的主库视图）。
    shared: &'a ObjectDb,
    /// 线程私有写日志。
    pub log: ObjectWriteLog,
}

impl<'a> WriteCaptureBackend<'a> {
    /// 从共享 ObjectDb 创建一个空的 capture 后端。
    #[must_use]
    pub fn new(shared: &'a ObjectDb) -> Self {
        Self {
            shared,
            log: ObjectWriteLog::new(),
        }
    }

    /// 取底层写日志（consume self），用于波次 merge 阶段。
    pub fn into_log(self) -> ObjectWriteLog {
        self.log
    }

    /// 查询某对象的当前值（合并 shared + log 的视图）。
    ///
    /// 优先级：log.current > shared.read。
    fn resolved_get(&self, id: &ObjectID) -> PokerL1Result<Option<Object>> {
        if let Some(v) = self.log.current(id) {
            return Ok(v.cloned());
        }
        match self.shared.read(id) {
            Ok(o) => Ok(Some(o)),
            Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl ObjectBackend for WriteCaptureBackend<'_> {
    fn create(&mut self, object: Object) -> PokerL1Result<()> {
        if is_reserved_economic_singleton(&object) {
            return Err(PokerL1Error::Other(
                "reserved economic objects may only be created by the economics system path".into(),
            ));
        }
        // 校验：shared 与 log 中都不应存在该 id（防碰撞）。
        if self.resolved_get(&object.id)?.is_some() {
            return Err(PokerL1Error::ObjectIDCollision(object.id));
        }
        self.log.push_create(object);
        Ok(())
    }

    fn read(&self, id: &ObjectID) -> PokerL1Result<Object> {
        // Read-Your-Writes：先查 log。
        if let Some(v) = self.log.current(id) {
            return v.cloned().ok_or_else(|| PokerL1Error::ObjectNotFound(*id));
        }
        // 未写过 → 委托共享库。
        self.shared.read(id)
    }

    fn version_of(&self, id: &ObjectID) -> PokerL1Result<Version> {
        if let Some(Some(obj)) = self.log.current(id) {
            return Ok(obj.version);
        }
        self.shared.version_of(id)
    }

    fn update(&mut self, id: &ObjectID, actor: &Address, new_data: Vec<u8>) -> PokerL1Result<()> {
        // 校验：对象存在 + 可写（所有权）。
        let existing = self.resolved_get(id)?;
        let obj = existing.ok_or(PokerL1Error::ObjectNotFound(*id))?;
        if is_reserved_economic_singleton(&obj) {
            return Err(PokerL1Error::Other(
                "reserved economic objects may only be updated by the economics system path".into(),
            ));
        }
        if crate::economics::is_native_coin_object(&obj) {
            return Err(PokerL1Error::Other(format!(
                "native coin {id:?} is an immutable UTXO and cannot be updated"
            )));
        }
        if !obj.can_write(actor) {
            return Err(PokerL1Error::NotOwner(*id));
        }
        // 大小校验（与 ObjectStore::update 一致）。
        if new_data.len() > crate::vm::gas_table::MAX_OBJECT_SIZE {
            return Err(PokerL1Error::ObjectTooLarge {
                actual: new_data.len(),
                limit: crate::vm::gas_table::MAX_OBJECT_SIZE,
            });
        }
        self.log.push_update(*id, *actor, new_data, &obj);
        Ok(())
    }

    fn transfer(
        &mut self,
        id: &ObjectID,
        actor: &Address,
        new_owner: Address,
    ) -> PokerL1Result<()> {
        // 校验：对象存在 + 可转移（仅 AddressOwned，且 actor 是当前 owner）。
        let existing = self.resolved_get(id)?;
        let obj = existing.ok_or(PokerL1Error::ObjectNotFound(*id))?;
        if is_reserved_economic_singleton(&obj) {
            return Err(PokerL1Error::Other(
                "reserved economic objects may only be transferred by the economics system path"
                    .into(),
            ));
        }
        if crate::economics::is_native_coin_object(&obj) {
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
        self.log.push_transfer(*id, *actor, new_owner, &obj);
        Ok(())
    }

    fn delete(&mut self, id: &ObjectID) -> PokerL1Result<Object> {
        // 校验：存在。返回被删除的对象（与 ObjectDb::delete 一致）。
        let existing = self
            .resolved_get(id)?
            .ok_or(PokerL1Error::ObjectNotFound(*id))?;
        if is_reserved_economic_singleton(&existing) {
            return Err(PokerL1Error::Other(
                "reserved economic objects may only be replaced by the economics system path"
                    .into(),
            ));
        }
        self.log.push_delete(*id);
        Ok(existing)
    }

    fn state_root(&self) -> Hash {
        // 并行阶段不重算 state_root（由 merge 后的主库计算）。
        // 返回共享库当前根，仅供调试/日志；不参与确定性判定。
        self.shared.state_root()
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

    fn fresh_db() -> ObjectDb {
        ObjectDb::open_inmemory().expect("打开 ObjectDb 失败")
    }

    // ===== Read-Your-Writes =====

    #[test]
    fn read_returns_shared_value_before_write() {
        let mut db = fresh_db();
        let owner = [1u8; 20];
        let obj = make_obj(owner, 1, owner);
        db.create(obj.clone()).unwrap();

        let cap = WriteCaptureBackend::new(&db);
        let read = cap.read(&obj.id).unwrap();
        assert_eq!(read, obj);
    }

    #[test]
    fn read_returns_logged_value_after_write() {
        let mut db = fresh_db();
        let owner = [1u8; 20];
        let obj = make_obj(owner, 1, owner);
        db.create(obj.clone()).unwrap();

        let mut cap = WriteCaptureBackend::new(&db);
        cap.update(&obj.id, &owner, b"updated".to_vec()).unwrap();

        // 主库未变
        assert_eq!(db.read(&obj.id).unwrap().data, b"data-1");
        // capture 读到自己写的值
        let read = cap.read(&obj.id).unwrap();
        assert_eq!(read.data, b"updated");
        assert_eq!(read.version, 1, "capture 视图应 bump version");
    }

    #[test]
    fn read_returns_logged_create() {
        let db = fresh_db();
        let owner = [1u8; 20];
        let new_obj = make_obj(owner, 2, owner);

        let mut cap = WriteCaptureBackend::new(&db);
        cap.create(new_obj.clone()).unwrap();

        // 主库读不到
        assert!(db.read(&new_obj.id).is_err());
        // capture 读到自己创建的值
        assert_eq!(cap.read(&new_obj.id).unwrap(), new_obj);
    }

    #[test]
    fn read_returns_not_found_after_delete() {
        let mut db = fresh_db();
        let owner = [1u8; 20];
        let obj = make_obj(owner, 1, owner);
        db.create(obj.clone()).unwrap();

        let mut cap = WriteCaptureBackend::new(&db);
        cap.delete(&obj.id).unwrap();
        assert!(matches!(
            cap.read(&obj.id),
            Err(PokerL1Error::ObjectNotFound(_))
        ));
    }

    // ===== 写校验 =====

    #[test]
    fn create_collision_rejected() {
        let mut db = fresh_db();
        let owner = [1u8; 20];
        let obj = make_obj(owner, 1, owner);
        db.create(obj.clone()).unwrap();

        let mut cap = WriteCaptureBackend::new(&db);
        let err = cap.create(obj.clone()).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectIDCollision(_)));
    }

    #[test]
    fn create_collision_with_own_log_rejected() {
        let db = fresh_db();
        let owner = [1u8; 20];
        let obj = make_obj(owner, 1, owner);

        let mut cap = WriteCaptureBackend::new(&db);
        cap.create(obj.clone()).unwrap();
        // 同一 capture 内再创建同名 → 碰撞
        let err = cap.create(obj.clone()).unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectIDCollision(_)));
    }

    #[test]
    fn update_by_non_owner_rejected() {
        let mut db = fresh_db();
        let owner = [1u8; 20];
        let other = [2u8; 20];
        let obj = make_obj(owner, 1, owner);
        db.create(obj.clone()).unwrap();

        let mut cap = WriteCaptureBackend::new(&db);
        let err = cap.update(&obj.id, &other, b"x".to_vec()).unwrap_err();
        assert!(matches!(err, PokerL1Error::NotOwner(_)));
    }

    #[test]
    fn update_missing_rejected() {
        let db = fresh_db();
        let mut cap = WriteCaptureBackend::new(&db);
        let err = cap
            .update(&ObjectID::new([9u8; 20], 999), &[0u8; 20], b"x".to_vec())
            .unwrap_err();
        assert!(matches!(err, PokerL1Error::ObjectNotFound(_)));
    }

    #[test]
    fn transfer_changes_owner_in_log_view() {
        let mut db = fresh_db();
        let owner = [1u8; 20];
        let new_owner = [2u8; 20];
        let obj = make_obj(owner, 1, owner);
        db.create(obj.clone()).unwrap();

        let mut cap = WriteCaptureBackend::new(&db);
        cap.transfer(&obj.id, &owner, new_owner).unwrap();
        let read = cap.read(&obj.id).unwrap();
        assert!(read.can_write(&new_owner));
        assert!(!read.can_write(&owner));
    }

    // ===== apply_to =====

    #[test]
    fn apply_to_commits_log_to_main_db() {
        let mut db = fresh_db();
        let owner = [1u8; 20];
        let pre = make_obj(owner, 1, owner);
        db.create(pre.clone()).unwrap();
        let root_before = db.state_root();

        {
            let mut cap = WriteCaptureBackend::new(&db);
            cap.create(make_obj(owner, 2, owner)).unwrap();
            cap.update(&pre.id, &owner, b"updated".to_vec()).unwrap();
            let log = cap.into_log();
            log.apply_to(&mut db).unwrap();
        }

        assert_ne!(db.state_root(), root_before);
        assert!(db.read(&ObjectID::new(owner, 2)).is_ok());
        let updated = db.read(&pre.id).unwrap();
        assert_eq!(updated.data, b"updated");
        assert_eq!(updated.version, 1);
    }

    #[test]
    fn apply_to_empty_log_is_noop() {
        let mut db = fresh_db();
        let cap = WriteCaptureBackend::new(&db);
        let root_before = db.state_root();
        cap.into_log().apply_to(&mut db).unwrap();
        assert_eq!(db.state_root(), root_before);
    }

    // ===== 写集统计（冲突检测用）=====

    #[test]
    fn written_ids_tracks_all_touched() {
        let db = fresh_db();
        let owner = [1u8; 20];
        let mut cap = WriteCaptureBackend::new(&db);
        cap.create(make_obj(owner, 1, owner)).unwrap();
        cap.create(make_obj(owner, 2, owner)).unwrap();
        let log = cap.into_log();
        assert_eq!(log.written_ids.len(), 2);
        assert!(log.contains_write(&ObjectID::new(owner, 1)));
        assert!(log.contains_write(&ObjectID::new(owner, 2)));
    }

    #[test]
    fn trait_object_dispatch_works() {
        let db = fresh_db();
        let owner = [1u8; 20];
        let mut cap = WriteCaptureBackend::new(&db);
        let backend: &mut dyn ObjectBackend = &mut cap;
        let obj = make_obj(owner, 1, owner);
        backend.create(obj.clone()).unwrap();
        assert_eq!(backend.read(&obj.id).unwrap(), obj);
    }
}
