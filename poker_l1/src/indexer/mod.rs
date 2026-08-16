//! 链上索引器与事件订阅（Indexer / Event Subscription）模块。
//!
//! ## 设计目标
//!
//! 为外部客户端（钱包、浏览器、dApp 后端）提供高效的链上数据查询与事件订阅：
//!
//! 1. **交易索引**：按 `tx_hash` / 发送者地址 / 合约 ID / 通道 / 高度范围 查询交易
//! 2. **区块索引**：按高度范围查询区块摘要（header + tx_count）
//! 3. **对象索引**：按 owner 地址 / 对象类型 查询对象 ID
//! 4. **事件订阅**：客户端注册订阅后，新块 / 新交易到达时入队待拉取
//!
//! ## 信任模型
//!
//! - 索引器**不**自行验证区块或交易，仅索引由 `Node` 共识层接受的区块
//! - 调用方（通常是 `Node`）在区块被 finalize 后调用 `index_block()`
//! - 索引内容与 `BlockStore` / `ObjectDb` 一致性由调用方保证（同源数据）
//!
//! ## 与现有模块的关系
//!
//! - 复用 [`crate::block::Block`] / [`crate::transaction::Transaction`] 作为索引源
//! - 复用 [`crate::account::derive_address`] 从 `tagged_pubkey` 派生发送者地址
//! - 复用 [`crate::object_model::Object`] / [`ObjectID`] / [`Ownership`] 提取 owner / type
//! - 复用 [`crate::rpc::EventType`] 作为事件类型枚举（保持与 WebSocket 订阅一致）
//! - 不引入新依赖，仅使用 `std::sync::Mutex` + `std::collections::BTreeMap`（与 `node` 模块一致）
//!
//! ## 容量与防 DoS
//!
//! - 每个订阅的事件队列上限 `MAX_EVENTS_PER_SUBSCRIPTION`（默认 1024）；溢出时保留最新事件，
//!   并在下一次拉取时返回明确的 [`IndexerEvent::Gap`]，客户端据此回补持久索引
//! - 订阅总数上限 `MAX_SUBSCRIPTIONS`（默认 1024），超过后 `subscribe()` 返回错误
//! - 索引表无内置上限（由 `Node` 的 pruning 策略控制链外数据生命周期）

use std::path::Path;
use std::sync::Arc;

use borsh::{BorshDeserialize, BorshSerialize};
use rocksdb::{ColumnFamilyDescriptor, DB, IteratorMode, Options, WriteBatch};

use crate::account::derive_address;
use crate::block::Block;
use crate::object_model::{Object, ObjectID, Ownership};
use crate::rpc::EventType;
use crate::transaction::{Transaction, TxLane};
use crate::{Address, BlockHeight, ChainId, Hash};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;

const INDEX_BLOCKS_CF: &str = "blocks";
const INDEX_TRANSACTIONS_CF: &str = "transactions";
const INDEX_OBJECTS_CF: &str = "objects";

/// 单个订阅的事件队列容量上限（防内存 DoS）。
pub const MAX_EVENTS_PER_SUBSCRIPTION: usize = 1024;

/// 全局订阅总数上限。
pub const MAX_SUBSCRIPTIONS: usize = 1024;

/// 订阅者 ID 类型。
pub type SubscriberId = u64;

/// 已索引的交易摘要——保存查询所需的元数据，原始 tx 可通过 `tx_hash` 从 `BlockStore` 反查。
///
/// 不直接保存 `Transaction` 全量（避免与 `BlockStore` 双写不一致）。
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct IndexedTransaction {
    /// 交易哈希（`Transaction::tx_hash()`）。
    pub tx_hash: Hash,
    /// 所在区块高度。
    pub block_height: BlockHeight,
    /// 所在区块哈希。
    pub block_hash: Hash,
    /// 交易通道。
    pub lane: TxLane,
    /// 发送者地址（`derive_address(tagged_pubkey)`）。
    pub sender: Address,
    /// 调用的合约 ID（若为合约调用 tx）。
    pub contract_id: Option<ObjectID>,
    /// 引用的输入对象 ID 列表（便于按对象反查 tx）。
    pub inputs: Vec<ObjectID>,
    /// 新创建的输出对象 ID 列表。
    pub outputs: Vec<ObjectID>,
    /// 区块时间戳（毫秒）。
    pub timestamp_ms: u64,
}

/// 已索引的区块摘要——保存 header + tx 计数，便于浏览器快速浏览。
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct IndexedBlock {
    /// 区块高度。
    pub height: BlockHeight,
    /// 区块哈希。
    pub block_hash: Hash,
    /// 区块时间戳（毫秒）。
    pub timestamp_ms: u64,
    /// 前 区块哈希（链式链接）。
    pub prev_hash: Hash,
    /// state_root。
    pub state_root: Hash,
    /// public_tx_root。
    pub public_tx_root: Hash,
    /// gameturn_tx_root。
    pub gameturn_tx_root: Hash,
    /// Public 通道 tx 数量。
    pub public_tx_count: usize,
    /// GameTurn + CheckpointAnchor 通道 tx 数量。
    pub gameturn_tx_count: usize,
}

impl IndexedBlock {
    /// 总 tx 数量。
    #[must_use]
    pub fn total_tx_count(&self) -> usize {
        self.public_tx_count + self.gameturn_tx_count
    }
}

/// 交易查询过滤器。
///
/// 所有字段为 `Option`，`None` 表示不限制该维度。多个字段同时给出时取**交集**。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TxFilter {
    /// 按发送者地址过滤。
    pub sender: Option<Address>,
    /// 按合约 ID 过滤（仅合约调用 tx）。
    pub contract_id: Option<ObjectID>,
    /// 按通道过滤。
    pub lane: Option<TxLane>,
    /// 按区块高度范围过滤 `[min, max]`（闭区间）。
    pub height_min: Option<BlockHeight>,
    pub height_max: Option<BlockHeight>,
    /// 按输入或输出对象 ID 过滤（任一匹配即纳入）。
    pub object_id: Option<ObjectID>,
    /// 最多返回条数（默认无限制）。
    pub limit: Option<usize>,
}

impl TxFilter {
    /// 构造空过滤器（匹配所有 tx）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 链式设置发送者。
    #[must_use]
    pub fn with_sender(mut self, sender: Address) -> Self {
        self.sender = Some(sender);
        self
    }

    /// 链式设置合约 ID。
    #[must_use]
    pub fn with_contract(mut self, contract_id: ObjectID) -> Self {
        self.contract_id = Some(contract_id);
        self
    }

    /// 链式设置通道。
    #[must_use]
    pub fn with_lane(mut self, lane: TxLane) -> Self {
        self.lane = Some(lane);
        self
    }

    /// 链式设置高度范围。
    #[must_use]
    pub fn with_height_range(mut self, min: BlockHeight, max: BlockHeight) -> Self {
        self.height_min = Some(min);
        self.height_max = Some(max);
        self
    }

    /// 链式设置对象 ID（输入或输出任一匹配）。
    #[must_use]
    pub fn with_object_id(mut self, id: ObjectID) -> Self {
        self.object_id = Some(id);
        self
    }

    /// 链式设置返回条数上限。
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// 判断一个 `IndexedTransaction` 是否匹配此过滤器。
    #[must_use]
    pub fn matches(&self, tx: &IndexedTransaction) -> bool {
        if let Some(sender) = self.sender {
            if tx.sender != sender {
                return false;
            }
        }
        if let Some(contract_id) = self.contract_id {
            if tx.contract_id != Some(contract_id) {
                return false;
            }
        }
        if let Some(lane) = self.lane {
            if tx.lane != lane {
                return false;
            }
        }
        if let Some(min) = self.height_min {
            if tx.block_height < min {
                return false;
            }
        }
        if let Some(max) = self.height_max {
            if tx.block_height > max {
                return false;
            }
        }
        if let Some(id) = self.object_id {
            let in_inputs = tx.inputs.iter().any(|x| *x == id);
            let in_outputs = tx.outputs.iter().any(|x| *x == id);
            if !in_inputs && !in_outputs {
                return false;
            }
        }
        true
    }
}

/// 区块查询过滤器。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockFilter {
    /// 高度范围 `[min, max]`（闭区间）。
    pub height_min: Option<BlockHeight>,
    pub height_max: Option<BlockHeight>,
    /// 最多返回条数。
    pub limit: Option<usize>,
}

impl BlockFilter {
    /// 构造空过滤器。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 链式设置高度范围。
    #[must_use]
    pub fn with_height_range(mut self, min: BlockHeight, max: BlockHeight) -> Self {
        self.height_min = Some(min);
        self.height_max = Some(max);
        self
    }

    /// 链式设置返回条数上限。
    #[must_use]
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// 判断一个 `IndexedBlock` 是否匹配此过滤器。
    #[must_use]
    pub fn matches(&self, block: &IndexedBlock) -> bool {
        if let Some(min) = self.height_min {
            if block.height < min {
                return false;
            }
        }
        if let Some(max) = self.height_max {
            if block.height > max {
                return false;
            }
        }
        true
    }
}

/// 推送给订阅者的事件消息（与 `rpc::EventMessage` 的 payload 字段对应）。
///
/// 为简化使用，Indexer 直接持有强类型事件；调用方可通过 BCS 序列化为
/// `rpc::EventMessage::payload` 字节，再通过 WebSocket 推送。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IndexerEvent {
    /// One or more earlier events were discarded because the subscriber did not drain its
    /// bounded queue in time.
    ///
    /// This is deliberately delivered before the retained events. A client must query the
    /// durable block/transaction indexes to recover the missing range instead of treating the
    /// subscription as a lossless log.
    Gap {
        /// Number of events that were discarded since the last successful poll.
        dropped_events: u64,
    },
    /// 新区块已索引。
    Block(IndexedBlock),
    /// 新交易已索引。
    Transaction(IndexedTransaction),
}

/// 单个订阅的状态。
#[derive(Debug)]
struct Subscription {
    /// 订阅 ID。
    id: SubscriberId,
    /// 订阅的事件类型集合。
    event_types: Vec<EventType>,
    /// 可选的 tx 过滤器（仅对 `EventType::Transaction` 生效；`None` 表示接收所有 tx 事件）。
    tx_filter: Option<TxFilter>,
    /// 待拉取的事件队列（FIFO）。
    queue: VecDeque<IndexerEvent>,
    /// Number of discarded events that must be reported before the next queue drain.
    dropped_events: u64,
}

impl Subscription {
    fn new(id: SubscriberId, event_types: Vec<EventType>, tx_filter: Option<TxFilter>) -> Self {
        Self {
            id,
            event_types,
            tx_filter,
            queue: VecDeque::new(),
            dropped_events: 0,
        }
    }

    /// Push an event, retaining the newest bounded suffix and recording any loss for polling.
    fn enqueue(&mut self, event: IndexerEvent) {
        if self.queue.len() >= MAX_EVENTS_PER_SUBSCRIPTION {
            self.queue.pop_front();
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        self.queue.push_back(event);
    }

    /// 是否对该事件类型感兴趣。
    fn interested_in(&self, event_type: EventType) -> bool {
        self.event_types.contains(&event_type)
    }
}

/// 索引器内部状态（被 `Mutex` 保护）。
#[derive(Debug, Default)]
struct IndexerState {
    /// `tx_hash -> IndexedTransaction`（主索引）。
    tx_by_hash: HashMap<Hash, IndexedTransaction>,
    /// `sender_address -> Vec<tx_hash>`（按发送者反查）。
    tx_by_sender: HashMap<Address, Vec<Hash>>,
    /// `contract_id -> Vec<tx_hash>`（按合约反查）。
    tx_by_contract: HashMap<ObjectID, Vec<Hash>>,
    /// `object_id -> Vec<tx_hash>`（按对象反查，输入或输出均收录）。
    tx_by_object: HashMap<ObjectID, Vec<Hash>>,
    /// `height -> IndexedBlock`（主索引，BTreeMap 支持范围查询）。
    block_by_height: BTreeMap<BlockHeight, IndexedBlock>,
    /// `block_hash -> height`（反查）。
    block_height_by_hash: HashMap<Hash, BlockHeight>,
    /// `owner_address -> Vec<ObjectID>`（按 owner 反查；仅 `AddressOwned` 对象）。
    object_by_owner: HashMap<Address, Vec<ObjectID>>,
    /// `object_type -> Vec<ObjectID>`（按类型反查）。
    object_by_type: HashMap<String, Vec<ObjectID>>,
    /// 已索引的最高区块高度。
    tip_height: Option<BlockHeight>,
    /// 下一个订阅 ID。
    next_subscriber_id: SubscriberId,
    /// 所有订阅。
    subscriptions: HashMap<SubscriberId, Subscription>,
}

/// Durable metadata needed to restore owner/type object queries without rereading full blocks.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct IndexedObject {
    id: ObjectID,
    owner: Option<Address>,
    object_type: String,
}

/// RocksDB-backed finalized index records.  Subscription queues intentionally remain process
/// local: reconnecting clients must resubscribe rather than receiving stale in-memory events.
struct DurableIndexer {
    db: Arc<DB>,
}

impl DurableIndexer {
    fn open(path: impl AsRef<Path>) -> crate::error::PokerL1Result<Self> {
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        let db = DB::open_cf_descriptors(
            &options,
            path,
            vec![
                ColumnFamilyDescriptor::new(INDEX_BLOCKS_CF, Options::default()),
                ColumnFamilyDescriptor::new(INDEX_TRANSACTIONS_CF, Options::default()),
                ColumnFamilyDescriptor::new(INDEX_OBJECTS_CF, Options::default()),
            ],
        )
        .map_err(|error| crate::error::PokerL1Error::Rocksdb(error.to_string()))?;
        Ok(Self { db: Arc::new(db) })
    }

    fn blocks_cf(&self) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(INDEX_BLOCKS_CF)
            .expect("index blocks CF exists at open")
    }

    fn transactions_cf(&self) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(INDEX_TRANSACTIONS_CF)
            .expect("index transactions CF exists at open")
    }

    fn objects_cf(&self) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(INDEX_OBJECTS_CF)
            .expect("index objects CF exists at open")
    }

    fn load_state(&self) -> crate::error::PokerL1Result<IndexerState> {
        let mut state = IndexerState::default();
        for entry in self.db.iterator_cf(self.blocks_cf(), IteratorMode::Start) {
            let (key, bytes) =
                entry.map_err(|error| crate::error::PokerL1Error::Rocksdb(error.to_string()))?;
            if key.len() != std::mem::size_of::<BlockHeight>() {
                return Err(crate::error::PokerL1Error::Serialization(format!(
                    "durable indexed block key has invalid length {}",
                    key.len()
                )));
            }
            let block: IndexedBlock = borsh::from_slice(&bytes)?;
            let key_height = u64::from_le_bytes(key.as_ref().try_into().map_err(|_| {
                crate::error::PokerL1Error::Serialization("invalid indexed block key".into())
            })?);
            if block.height != key_height
                || state
                    .block_by_height
                    .insert(block.height, block.clone())
                    .is_some()
            {
                return Err(crate::error::PokerL1Error::Serialization(
                    "durable indexed block height conflict".into(),
                ));
            }
            state
                .block_height_by_hash
                .insert(block.block_hash, block.height);
            state.tip_height = Some(
                state
                    .tip_height
                    .map_or(block.height, |tip| tip.max(block.height)),
            );
        }
        for entry in self
            .db
            .iterator_cf(self.transactions_cf(), IteratorMode::Start)
        {
            let (key, bytes) =
                entry.map_err(|error| crate::error::PokerL1Error::Rocksdb(error.to_string()))?;
            if key.len() != 32 {
                return Err(crate::error::PokerL1Error::Serialization(format!(
                    "durable indexed transaction key has invalid length {}",
                    key.len()
                )));
            }
            let indexed: IndexedTransaction = borsh::from_slice(&bytes)?;
            if key.as_ref() != indexed.tx_hash {
                return Err(crate::error::PokerL1Error::Serialization(
                    "durable indexed transaction key/hash mismatch".into(),
                ));
            }
            state.insert_indexed_tx(indexed)?;
        }
        for entry in self.db.iterator_cf(self.objects_cf(), IteratorMode::Start) {
            let (key, bytes) =
                entry.map_err(|error| crate::error::PokerL1Error::Rocksdb(error.to_string()))?;
            let indexed: IndexedObject = borsh::from_slice(&bytes)?;
            if key.as_ref() != indexed.id.to_bytes() {
                return Err(crate::error::PokerL1Error::Serialization(
                    "durable indexed object key/id mismatch".into(),
                ));
            }
            state.insert_indexed_object(indexed);
        }
        Ok(state)
    }

    fn write_block(
        &self,
        block: &IndexedBlock,
        transactions: &[IndexedTransaction],
        objects: &[IndexedObject],
    ) -> crate::error::PokerL1Result<()> {
        let mut batch = WriteBatch::default();
        batch.put_cf(
            self.blocks_cf(),
            block.height.to_le_bytes(),
            borsh::to_vec(block)?,
        );
        for transaction in transactions {
            batch.put_cf(
                self.transactions_cf(),
                transaction.tx_hash,
                borsh::to_vec(transaction)?,
            );
        }
        for object in objects {
            batch.put_cf(
                self.objects_cf(),
                object.id.to_bytes(),
                borsh::to_vec(object)?,
            );
        }
        self.db
            .write(batch)
            .map_err(|error| crate::error::PokerL1Error::Rocksdb(error.to_string()))
    }

    /// Atomically replace the owner/type view with the current live ObjectDb contents.
    ///
    /// Object creation is not the only state transition that matters to these queries: objects
    /// can be transferred or deleted by a later transaction.  Keeping old output records would
    /// make an address appear to own an object it no longer owns.  The finalized ObjectDb is the
    /// source of truth, so a complete replacement is preferable to attempting to infer every
    /// contract-side mutation from transaction payloads.
    fn replace_live_objects(&self, objects: &[IndexedObject]) -> crate::error::PokerL1Result<()> {
        let mut batch = WriteBatch::default();
        for entry in self.db.iterator_cf(self.objects_cf(), IteratorMode::Start) {
            let (key, _) =
                entry.map_err(|error| crate::error::PokerL1Error::Rocksdb(error.to_string()))?;
            batch.delete_cf(self.objects_cf(), key);
        }
        for object in objects {
            batch.put_cf(
                self.objects_cf(),
                object.id.to_bytes(),
                borsh::to_vec(object)?,
            );
        }
        self.db
            .write(batch)
            .map_err(|error| crate::error::PokerL1Error::Rocksdb(error.to_string()))
    }
}

impl IndexerState {
    fn build_indexed_tx(
        tx: &Transaction,
        block_height: BlockHeight,
        block_hash: Hash,
        timestamp_ms: u64,
    ) -> IndexedTransaction {
        IndexedTransaction {
            tx_hash: tx.tx_hash(),
            block_height,
            block_hash,
            lane: tx.lane_hint,
            sender: derive_address(&tx.tagged_pubkey),
            contract_id: tx.contract_call.as_ref().map(|call| call.contract_id),
            inputs: tx.inputs.clone(),
            outputs: tx.outputs.iter().map(|object| object.id).collect(),
            timestamp_ms,
        }
    }

    fn build_indexed_object(object: &Object) -> IndexedObject {
        IndexedObject {
            id: object.id,
            owner: match object.owner {
                Ownership::AddressOwned { owner } => Some(owner),
                _ => None,
            },
            object_type: object.object_type.clone(),
        }
    }

    fn insert_indexed_tx(
        &mut self,
        indexed: IndexedTransaction,
    ) -> crate::error::PokerL1Result<()> {
        if let Some(existing) = self.tx_by_hash.insert(indexed.tx_hash, indexed.clone())
            && existing != indexed
        {
            return Err(crate::error::PokerL1Error::Serialization(
                "durable transaction index contains conflicting metadata for one hash".into(),
            ));
        }
        self.tx_by_sender
            .entry(indexed.sender)
            .or_default()
            .push(indexed.tx_hash);
        if let Some(contract_id) = indexed.contract_id {
            self.tx_by_contract
                .entry(contract_id)
                .or_default()
                .push(indexed.tx_hash);
        }
        for object_id in indexed.inputs.iter().chain(&indexed.outputs) {
            self.tx_by_object
                .entry(*object_id)
                .or_default()
                .push(indexed.tx_hash);
        }
        Ok(())
    }

    fn insert_indexed_object(&mut self, indexed: IndexedObject) {
        let by_type = self.object_by_type.entry(indexed.object_type).or_default();
        if !by_type.contains(&indexed.id) {
            by_type.push(indexed.id);
        }
        if let Some(owner) = indexed.owner {
            let by_owner = self.object_by_owner.entry(owner).or_default();
            if !by_owner.contains(&indexed.id) {
                by_owner.push(indexed.id);
            }
        }
    }

    fn replace_indexed_objects(&mut self, objects: Vec<IndexedObject>) {
        self.object_by_owner.clear();
        self.object_by_type.clear();
        for object in objects {
            self.insert_indexed_object(object);
        }
    }

    /// 向所有匹配的订阅推入事件。
    fn notify(&mut self, event: IndexerEvent) {
        let event_type = match &event {
            IndexerEvent::Gap { .. } => return,
            IndexerEvent::Block(_) => EventType::Block,
            IndexerEvent::Transaction(_) => EventType::Transaction,
        };
        // 对 Transaction 事件，还需考虑每个订阅的 tx_filter
        for sub in self.subscriptions.values_mut() {
            if !sub.interested_in(event_type) {
                continue;
            }
            if let (IndexerEvent::Transaction(itx), Some(filter)) = (&event, &sub.tx_filter) {
                if !filter.matches(itx) {
                    continue;
                }
            }
            sub.enqueue(event.clone());
        }
    }
}

/// 链上索引器——线程安全的内存索引与事件订阅协调器。
///
/// 使用 `std::sync::Mutex` 保护内部状态（与 `node::Node` 模式一致）。
/// 所有查询方法返回 `Vec` 拷贝，调用方无需持锁。
pub struct Indexer {
    state: Mutex<IndexerState>,
    durable: Option<DurableIndexer>,
}

impl Indexer {
    /// 创建空索引器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(IndexerState::default()),
            durable: None,
        }
    }

    /// Open a durable finalized index.  The database contains only query metadata, never
    /// consensus state; a missing tail can therefore be deterministically repaired from the
    /// canonical BlockStore during node startup.
    pub fn open(path: impl AsRef<Path>) -> crate::error::PokerL1Result<Self> {
        let durable = DurableIndexer::open(path)?;
        let state = durable.load_state()?;
        Ok(Self {
            state: Mutex::new(state),
            durable: Some(durable),
        })
    }

    /// 索引一个区块及其所有交易，并向匹配的订阅推送事件。
    ///
    /// 重复索引同一高度会被静默忽略（幂等），便于 `Node` 在 reorg 后重放。
    ///
    /// # 参数
    /// - `block`：待索引的区块
    /// - `chain_id`：用于计算 `block_hash`
    ///
    /// # 返回
    /// `true` 表示首次索引成功；`false` 表示该高度已索引（幂等跳过）。
    pub fn index_block(&self, block: &Block, chain_id: ChainId) -> bool {
        self.try_index_block(block, chain_id).unwrap_or(false)
    }

    /// Index one finalized block and durably write its query metadata before exposing it to
    /// in-process readers or subscriptions.
    pub fn try_index_block(
        &self,
        block: &Block,
        chain_id: ChainId,
    ) -> crate::error::PokerL1Result<bool> {
        let mut state = self.state.lock().expect("indexer state mutex poisoned");

        let height = block.header.height;
        // 幂等：已索引则跳过
        if state.block_by_height.contains_key(&height) {
            return Ok(false);
        }

        let block_hash = block.block_hash(chain_id);
        let timestamp_ms = block.header.timestamp_ms;

        // 1. 先构造完整的持久索引记录，不让失败的 RocksDB 写入污染内存视图。
        let indexed_block = IndexedBlock {
            height,
            block_hash,
            timestamp_ms,
            prev_hash: block.header.prev_hash,
            state_root: block.header.state_root,
            public_tx_root: block.header.public_tx_root,
            gameturn_tx_root: block.header.gameturn_tx_root,
            public_tx_count: block.public_txs.len(),
            gameturn_tx_count: block.gameturn_txs.len(),
        };
        let transactions: Vec<IndexedTransaction> = block
            .public_txs
            .iter()
            .chain(&block.gameturn_txs)
            .map(|transaction| {
                IndexerState::build_indexed_tx(transaction, height, block_hash, timestamp_ms)
            })
            .collect();
        let objects: Vec<IndexedObject> = block
            .public_txs
            .iter()
            .chain(&block.gameturn_txs)
            .flat_map(|transaction| transaction.outputs.iter())
            .map(IndexerState::build_indexed_object)
            .collect();

        for transaction in &transactions {
            if state.tx_by_hash.contains_key(&transaction.tx_hash) {
                return Err(crate::error::PokerL1Error::Serialization(
                    "a finalized block repeats an already indexed transaction hash".into(),
                ));
            }
        }

        if let Some(durable) = &self.durable {
            durable.write_block(&indexed_block, &transactions, &objects)?;
        }

        // 2. The durable batch succeeded, so expose the matching in-memory records and events.
        state.block_by_height.insert(height, indexed_block.clone());
        state.block_height_by_hash.insert(block_hash, height);
        state.tip_height = Some(state.tip_height.map_or(height, |tip| tip.max(height)));
        for indexed_tx in transactions {
            state.insert_indexed_tx(indexed_tx.clone())?;
            state.notify(IndexerEvent::Transaction(indexed_tx));
        }
        for object in objects {
            state.insert_indexed_object(object);
        }

        // 3. 推送区块事件
        state.notify(IndexerEvent::Block(indexed_block));

        Ok(true)
    }

    /// Synchronize owner/type object queries from the finalized live ObjectDb view.
    ///
    /// This operation must be invoked only after the consensus state transition is durable.  It
    /// intentionally has no event side effects: subscriptions are a finalized-block stream,
    /// while these two queries describe the latest object state rather than a mutation log.
    pub fn synchronize_live_objects<'a>(
        &self,
        objects: impl IntoIterator<Item = &'a Object>,
    ) -> crate::error::PokerL1Result<()> {
        let mut indexed: Vec<IndexedObject> = objects
            .into_iter()
            .map(IndexerState::build_indexed_object)
            .collect();
        indexed.sort_by_key(|object| object.id.to_bytes());

        let mut state = self.state.lock().expect("indexer state mutex poisoned");
        if let Some(durable) = &self.durable {
            durable.replace_live_objects(&indexed)?;
        }
        state.replace_indexed_objects(indexed);
        Ok(())
    }

    /// 按 `tx_hash` 查询单笔交易。
    #[must_use]
    pub fn get_tx(&self, tx_hash: &Hash) -> Option<IndexedTransaction> {
        let state = self.state.lock().expect("indexer state mutex poisoned");
        state.tx_by_hash.get(tx_hash).cloned()
    }

    /// 按过滤器查询交易（按 `block_height` 升序排列）。
    #[must_use]
    pub fn query_txs(&self, filter: &TxFilter) -> Vec<IndexedTransaction> {
        let state = self.state.lock().expect("indexer state mutex poisoned");

        // 选择最优反查索引缩小候选集，再统一用 filter.matches 过滤
        let candidates: Vec<Hash> = if let Some(sender) = filter.sender {
            state.tx_by_sender.get(&sender).cloned().unwrap_or_default()
        } else if let Some(contract_id) = filter.contract_id {
            state
                .tx_by_contract
                .get(&contract_id)
                .cloned()
                .unwrap_or_default()
        } else if let Some(object_id) = filter.object_id {
            state
                .tx_by_object
                .get(&object_id)
                .cloned()
                .unwrap_or_default()
        } else {
            // 无反查索引可用，遍历全部
            state.tx_by_hash.keys().copied().collect()
        };

        let mut results: Vec<IndexedTransaction> = candidates
            .iter()
            .filter_map(|h| state.tx_by_hash.get(h))
            .filter(|tx| filter.matches(tx))
            .cloned()
            .collect();

        // 按区块高度升序排列，便于调用方按时序消费
        results.sort_by_key(|tx| (tx.block_height, tx.timestamp_ms));

        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }
        results
    }

    /// 按高度查询单个区块摘要。
    #[must_use]
    pub fn get_block_by_height(&self, height: BlockHeight) -> Option<IndexedBlock> {
        let state = self.state.lock().expect("indexer state mutex poisoned");
        state.block_by_height.get(&height).cloned()
    }

    /// 按哈希查询单个区块摘要。
    #[must_use]
    pub fn get_block_by_hash(&self, block_hash: &Hash) -> Option<IndexedBlock> {
        let state = self.state.lock().expect("indexer state mutex poisoned");
        state
            .block_height_by_hash
            .get(block_hash)
            .and_then(|h| state.block_by_height.get(h))
            .cloned()
    }

    /// 按过滤器查询区块摘要（按 `height` 升序排列）。
    #[must_use]
    pub fn query_blocks(&self, filter: &BlockFilter) -> Vec<IndexedBlock> {
        let state = self.state.lock().expect("indexer state mutex poisoned");

        let mut results: Vec<IndexedBlock> = state
            .block_by_height
            .values()
            .filter(|b| filter.matches(b))
            .cloned()
            .collect();

        results.sort_by_key(|b| b.height);

        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }
        results
    }

    /// 按 owner 地址查询对象 ID 列表（仅 `AddressOwned` 对象）。
    #[must_use]
    pub fn query_objects_by_owner(&self, owner: Address) -> Vec<ObjectID> {
        let state = self.state.lock().expect("indexer state mutex poisoned");
        state
            .object_by_owner
            .get(&owner)
            .cloned()
            .unwrap_or_default()
    }

    /// 按对象类型查询对象 ID 列表。
    #[must_use]
    pub fn query_objects_by_type(&self, object_type: &str) -> Vec<ObjectID> {
        let state = self.state.lock().expect("indexer state mutex poisoned");
        state
            .object_by_type
            .get(object_type)
            .cloned()
            .unwrap_or_default()
    }

    /// 当前已索引的最高区块高度（`None` 表示尚未索引任何区块）。
    #[must_use]
    pub fn tip_height(&self) -> Option<BlockHeight> {
        let state = self.state.lock().expect("indexer state mutex poisoned");
        state.tip_height
    }

    /// 已索引的交易总数。
    #[must_use]
    pub fn tx_count(&self) -> usize {
        let state = self.state.lock().expect("indexer state mutex poisoned");
        state.tx_by_hash.len()
    }

    /// 已索引的区块总数。
    #[must_use]
    pub fn block_count(&self) -> usize {
        let state = self.state.lock().expect("indexer state mutex poisoned");
        state.block_by_height.len()
    }

    // ===== 事件订阅 API =====

    /// 订阅事件。
    ///
    /// # 参数
    /// - `event_types`：感兴趣的事件类型列表（不可为空）
    /// - `tx_filter`：可选的交易过滤器；仅对 `EventType::Transaction` 生效，
    ///   `None` 表示接收所有 tx 事件
    ///
    /// # 错误
    /// - `event_types` 为空时返回错误
    /// - 订阅总数达 `MAX_SUBSCRIPTIONS` 上限时返回错误
    pub fn subscribe(
        &self,
        event_types: Vec<EventType>,
        tx_filter: Option<TxFilter>,
    ) -> crate::error::PokerL1Result<SubscriberId> {
        if event_types.is_empty() {
            return Err(crate::error::PokerL1Error::Other(
                "event_types must not be empty".to_string(),
            ));
        }
        let mut state = self.state.lock().expect("indexer state mutex poisoned");
        if state.subscriptions.len() >= MAX_SUBSCRIPTIONS {
            return Err(crate::error::PokerL1Error::Other(format!(
                "max subscriptions limit {} reached",
                MAX_SUBSCRIPTIONS
            )));
        }
        let id = state.next_subscriber_id;
        state.next_subscriber_id += 1;
        let sub = Subscription::new(id, event_types, tx_filter);
        state.subscriptions.insert(id, sub);
        Ok(id)
    }

    /// 取消订阅。返回 `true` 表示成功取消，`false` 表示 ID 不存在。
    pub fn unsubscribe(&self, id: SubscriberId) -> bool {
        let mut state = self.state.lock().expect("indexer state mutex poisoned");
        state.subscriptions.remove(&id).is_some()
    }

    /// 当前活跃订阅数。
    #[must_use]
    pub fn subscription_count(&self) -> usize {
        let state = self.state.lock().expect("indexer state mutex poisoned");
        state.subscriptions.len()
    }

    /// Non-blockingly drain queued events.
    ///
    /// A leading [`IndexerEvent::Gap`] reports queue overflow. Consumers must use their durable
    /// block/transaction cursor to recover that range; event loss is never silently hidden.
    /// `None` means the subscription does not exist; `Some(vec)` may be empty.
    #[must_use]
    pub fn poll_events(&self, id: SubscriberId) -> Option<Vec<IndexerEvent>> {
        let mut state = self.state.lock().expect("indexer state mutex poisoned");
        let sub = state.subscriptions.get_mut(&id)?;
        let mut events = Vec::with_capacity(sub.queue.len() + usize::from(sub.dropped_events > 0));
        if sub.dropped_events > 0 {
            events.push(IndexerEvent::Gap {
                dropped_events: sub.dropped_events,
            });
            sub.dropped_events = 0;
        }
        events.extend(sub.queue.drain(..));
        Some(events)
    }

    /// 查询订阅的待处理事件数（不消费）。
    #[must_use]
    pub fn pending_event_count(&self, id: SubscriberId) -> Option<usize> {
        let state = self.state.lock().expect("indexer state mutex poisoned");
        let sub = state.subscriptions.get(&id)?;
        Some(sub.queue.len())
    }
}

impl Default for Indexer {
    fn default() -> Self {
        Self::new()
    }
}

// ===== 测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Block, BlockHeader};
    use crate::consensus::DagCommitCertificate;
    use crate::signature::TaggedPubkey;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{Gas, RouteHint, TxLane};

    /// 构造测试用 DagCommitCertificate（最小有效结构）。
    fn dummy_commit_cert() -> DagCommitCertificate {
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
            signature_list: vec![vec![0u8; 65]],
            signer_bitmap: vec![0xFF],
        }
    }

    /// 构造测试用 BlockHeader。
    fn make_header(height: BlockHeight, state_root: Hash) -> BlockHeader {
        BlockHeader {
            height,
            timestamp_ms: 1_700_000_000_000 + height,
            prev_hash: [0u8; 32],
            state_root,
            account_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            dag_commit_certificate: dummy_commit_cert(),
        }
    }

    /// 构造测试用 tagged pubkey（可区分不同 sender）。
    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![byte; 33],
        }
    }

    /// 构造测试用 tx（可选合约调用、可选通道）。
    fn make_tx(
        sender_byte: u8,
        nonce: u64,
        lane: TxLane,
        contract_id: Option<ObjectID>,
    ) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: contract_id.map(|id| crate::transaction::ContractCall {
                contract_id: id,
                method_selector: [0u8; 32],
                args: vec![],
            }),
            tagged_pubkey: make_tagged_pubkey(sender_byte),
            signature: vec![0u8; 65],
            gas: Gas::new(1000, 1),
            lane_hint: lane,
            route_hint: RouteHint::AnyValidator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    /// 构造测试用 Object（AddressOwned，便于 owner 反查测试）。
    fn make_owned_object(creator: Address, nonce: u64, owner: Address, type_str: &str) -> Object {
        Object::new(
            ObjectID::new(creator, nonce),
            Ownership::AddressOwned { owner },
            type_str.to_string(),
            b"data".to_vec(),
            None,
        )
    }

    /// 构造一个含若干 tx + 输出对象的区块。
    fn make_block(
        height: BlockHeight,
        state_root: Hash,
        public_txs: Vec<Transaction>,
        gameturn_txs: Vec<Transaction>,
    ) -> Block {
        Block::new(make_header(height, state_root), public_txs, gameturn_txs)
    }

    #[test]
    fn test_index_block_basic() {
        let indexer = Indexer::new();
        let block = make_block(10, [0u8; 32], vec![], vec![]);
        assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));
        assert_eq!(indexer.block_count(), 1);
        assert_eq!(indexer.tip_height(), Some(10));
        assert!(indexer.get_block_by_height(10).is_some());
    }

    #[test]
    fn test_index_block_idempotent() {
        let indexer = Indexer::new();
        let block = make_block(10, [0u8; 32], vec![], vec![]);
        assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));
        // 重复索引同一高度应被忽略
        assert!(!indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));
        assert_eq!(indexer.block_count(), 1);
    }

    #[test]
    fn test_index_tx_with_sender_and_lane() {
        let indexer = Indexer::new();
        let tx1 = make_tx(0x01, 1, TxLane::Public, None);
        let tx2 = make_tx(0x02, 1, TxLane::GameTurn, None);
        let block = make_block(100, [0u8; 32], vec![tx1], vec![tx2]);
        assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));

        let sender1 = derive_address(&make_tagged_pubkey(0x01));
        let sender2 = derive_address(&make_tagged_pubkey(0x02));

        // 按发送者查询
        let results = indexer.query_txs(&TxFilter::new().with_sender(sender1));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sender, sender1);
        assert_eq!(results[0].lane, TxLane::Public);

        // 按通道查询
        let results = indexer.query_txs(&TxFilter::new().with_lane(TxLane::GameTurn));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].sender, sender2);

        // 按区块高度范围查询
        let results = indexer.query_txs(&TxFilter::new().with_height_range(50, 150));
        assert_eq!(results.len(), 2);

        let results = indexer.query_txs(&TxFilter::new().with_height_range(200, 300));
        assert!(results.is_empty());
    }

    #[test]
    fn test_index_tx_with_contract_call() {
        let indexer = Indexer::new();
        let contract_id = ObjectID::new([0xAA; 20], 1);
        let tx = make_tx(0x01, 1, TxLane::Public, Some(contract_id));
        let block = make_block(100, [0u8; 32], vec![tx], vec![]);
        assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));

        // 按合约 ID 查询
        let results = indexer.query_txs(&TxFilter::new().with_contract(contract_id));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].contract_id, Some(contract_id));

        // 无合约调用的 tx 不应被匹配
        let tx2 = make_tx(0x02, 1, TxLane::Public, None);
        let block2 = make_block(101, [0u8; 32], vec![tx2], vec![]);
        assert!(indexer.index_block(&block2, crate::DEFAULT_CHAIN_ID));

        let results = indexer.query_txs(&TxFilter::new().with_contract(contract_id));
        assert_eq!(results.len(), 1, "无合约调用的 tx 不应被匹配");
    }

    #[test]
    fn test_index_tx_with_object_io() {
        let indexer = Indexer::new();
        let sender = derive_address(&make_tagged_pubkey(0x01));
        let input_id = ObjectID::new([0xBB; 20], 1);
        let output_obj = make_owned_object(sender, 2, [0xCC; 20], "Coin");
        let output_id = output_obj.id;

        let mut tx = make_tx(0x01, 1, TxLane::Public, None);
        tx.inputs = vec![input_id];
        tx.outputs = vec![output_obj];
        let block = make_block(100, [0u8; 32], vec![tx], vec![]);
        assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));

        // 按输入对象 ID 查询
        let results = indexer.query_txs(&TxFilter::new().with_object_id(input_id));
        assert_eq!(results.len(), 1);

        // 按输出对象 ID 查询
        let results = indexer.query_txs(&TxFilter::new().with_object_id(output_id));
        assert_eq!(results.len(), 1);

        // 不相关对象不应匹配
        let unrelated = ObjectID::new([0xDD; 20], 99);
        let results = indexer.query_txs(&TxFilter::new().with_object_id(unrelated));
        assert!(results.is_empty());
    }

    #[test]
    fn test_index_objects_by_owner_and_type() {
        let indexer = Indexer::new();
        let sender = derive_address(&make_tagged_pubkey(0x01));
        let owner1 = [0xCC; 20];
        let owner2 = [0xDD; 20];

        let obj1 = make_owned_object(sender, 1, owner1, "Coin");
        let obj2 = make_owned_object(sender, 2, owner1, "Coin");
        let obj3 = make_owned_object(sender, 3, owner2, "NFT");

        let mut tx = make_tx(0x01, 1, TxLane::Public, None);
        tx.outputs = vec![obj1, obj2, obj3];
        let block = make_block(100, [0u8; 32], vec![tx], vec![]);
        assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));

        // 按 owner 查询
        let results = indexer.query_objects_by_owner(owner1);
        assert_eq!(results.len(), 2, "owner1 应有 2 个对象");

        let results = indexer.query_objects_by_owner(owner2);
        assert_eq!(results.len(), 1, "owner2 应有 1 个对象");

        // 按类型查询
        let results = indexer.query_objects_by_type("Coin");
        assert_eq!(results.len(), 2);

        let results = indexer.query_objects_by_type("NFT");
        assert_eq!(results.len(), 1);

        let results = indexer.query_objects_by_type("NonExistent");
        assert!(results.is_empty());
    }

    #[test]
    fn test_query_blocks_by_range() {
        let indexer = Indexer::new();
        for h in 10..15 {
            let block = make_block(h, [h as u8; 32], vec![], vec![]);
            assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));
        }

        // 全范围查询
        let results = indexer.query_blocks(&BlockFilter::new().with_height_range(10, 14));
        assert_eq!(results.len(), 5);
        // 应按高度升序排列
        assert_eq!(results[0].height, 10);
        assert_eq!(results[4].height, 14);

        // 子范围
        let results = indexer.query_blocks(&BlockFilter::new().with_height_range(11, 12));
        assert_eq!(results.len(), 2);

        // limit 截断
        let results =
            indexer.query_blocks(&BlockFilter::new().with_height_range(10, 14).with_limit(2));
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].height, 10);
        assert_eq!(results[1].height, 11);
    }

    #[test]
    fn test_get_tx_by_hash() {
        let indexer = Indexer::new();
        let tx = make_tx(0x01, 1, TxLane::Public, None);
        let tx_hash = tx.tx_hash();
        let block = make_block(100, [0u8; 32], vec![tx], vec![]);
        assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));

        let result = indexer.get_tx(&tx_hash);
        assert!(result.is_some());
        assert_eq!(result.unwrap().tx_hash, tx_hash);

        // 不存在的 hash
        let result = indexer.get_tx(&[0xFF; 32]);
        assert!(result.is_none());
    }

    #[test]
    fn test_get_block_by_hash() {
        let indexer = Indexer::new();
        let block = make_block(100, [0u8; 32], vec![], vec![]);
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let block_hash = block.block_hash(chain_id);
        assert!(indexer.index_block(&block, chain_id));

        let result = indexer.get_block_by_hash(&block_hash);
        assert!(result.is_some());
        assert_eq!(result.unwrap().block_hash, block_hash);

        // 不存在的 hash
        let result = indexer.get_block_by_hash(&[0xFF; 32]);
        assert!(result.is_none());
    }

    #[test]
    fn durable_index_survives_restart_with_transaction_block_and_object_queries() {
        let directory = tempfile::tempdir().unwrap();
        let owner = [0xA5; 20];
        let object = make_owned_object([0x01; 20], 7, owner, "Coin");
        let mut tx = make_tx(0x01, 1, TxLane::Public, None);
        tx.outputs = vec![object.clone()];
        let tx_hash = tx.tx_hash();
        let block = make_block(9, [0x44; 32], vec![tx], vec![]);
        let block_hash = block.block_hash(crate::DEFAULT_CHAIN_ID);

        {
            let indexer = Indexer::open(directory.path()).unwrap();
            assert!(
                indexer
                    .try_index_block(&block, crate::DEFAULT_CHAIN_ID)
                    .unwrap()
            );
        }

        let reopened = Indexer::open(directory.path()).unwrap();
        assert_eq!(reopened.tip_height(), Some(9));
        assert_eq!(reopened.get_tx(&tx_hash).unwrap().block_hash, block_hash);
        assert_eq!(reopened.get_block_by_hash(&block_hash).unwrap().height, 9);
        assert_eq!(reopened.query_objects_by_owner(owner), vec![object.id]);
        assert_eq!(reopened.query_objects_by_type("Coin"), vec![object.id]);
        assert!(
            !reopened
                .try_index_block(&block, crate::DEFAULT_CHAIN_ID)
                .unwrap()
        );
    }

    #[test]
    fn live_object_sync_replaces_stale_owner_and_type_records_durably() {
        let directory = tempfile::tempdir().unwrap();
        let original_owner = [0xA1; 20];
        let current_owner = [0xB2; 20];
        let original = make_owned_object([0x01; 20], 7, original_owner, "Coin");
        let current = make_owned_object([0x01; 20], 7, current_owner, "GameAsset");
        assert_eq!(original.id, current.id);

        {
            let indexer = Indexer::open(directory.path()).unwrap();
            indexer.synchronize_live_objects([&original]).unwrap();
            assert_eq!(
                indexer.query_objects_by_owner(original_owner),
                vec![original.id]
            );
            assert_eq!(indexer.query_objects_by_type("Coin"), vec![original.id]);

            // A later state transition can change both ownership and type-facing metadata.  The
            // current live-state refresh must remove the old query records rather than append.
            indexer.synchronize_live_objects([&current]).unwrap();
            assert!(indexer.query_objects_by_owner(original_owner).is_empty());
            assert!(indexer.query_objects_by_type("Coin").is_empty());
            assert_eq!(
                indexer.query_objects_by_owner(current_owner),
                vec![current.id]
            );
            assert_eq!(indexer.query_objects_by_type("GameAsset"), vec![current.id]);
        }

        let reopened = Indexer::open(directory.path()).unwrap();
        assert!(reopened.query_objects_by_owner(original_owner).is_empty());
        assert!(reopened.query_objects_by_type("Coin").is_empty());
        assert_eq!(
            reopened.query_objects_by_owner(current_owner),
            vec![current.id]
        );
        assert_eq!(
            reopened.query_objects_by_type("GameAsset"),
            vec![current.id]
        );
    }

    #[test]
    fn test_subscription_block_events() {
        let indexer = Indexer::new();
        let sub_id = indexer.subscribe(vec![EventType::Block], None).unwrap();

        // 索引区块应触发事件
        let block = make_block(100, [0u8; 32], vec![], vec![]);
        assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));

        let events = indexer.poll_events(sub_id).unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], IndexerEvent::Block(_)));

        // 二次拉取应无事件
        let events = indexer.poll_events(sub_id).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_subscription_tx_events_with_filter() {
        let indexer = Indexer::new();
        let sender1 = derive_address(&make_tagged_pubkey(0x01));
        let sender2 = derive_address(&make_tagged_pubkey(0x02));

        // 订阅 sender1 的所有 tx
        let sub_id = indexer
            .subscribe(
                vec![EventType::Transaction],
                Some(TxFilter::new().with_sender(sender1)),
            )
            .unwrap();

        let tx1 = make_tx(0x01, 1, TxLane::Public, None); // 匹配
        let tx2 = make_tx(0x02, 1, TxLane::Public, None); // 不匹配
        let block = make_block(100, [0u8; 32], vec![tx1, tx2], vec![]);
        assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));

        let events = indexer.poll_events(sub_id).unwrap();
        assert_eq!(events.len(), 1, "应只收到 sender1 的 tx 事件");
        if let IndexerEvent::Transaction(ref itx) = events[0] {
            assert_eq!(itx.sender, sender1);
        } else {
            panic!("应为 Transaction 事件");
        }
    }

    #[test]
    fn test_subscription_unsubscribe() {
        let indexer = Indexer::new();
        let sub_id = indexer.subscribe(vec![EventType::Block], None).unwrap();
        assert_eq!(indexer.subscription_count(), 1);

        assert!(indexer.unsubscribe(sub_id));
        assert_eq!(indexer.subscription_count(), 0);
        assert!(!indexer.unsubscribe(sub_id), "重复取消应返回 false");

        // 取消后不再接收事件
        let block = make_block(100, [0u8; 32], vec![], vec![]);
        assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));
        assert_eq!(indexer.poll_events(sub_id), None);
    }

    #[test]
    fn test_subscribe_rejects_empty_event_types() {
        let indexer = Indexer::new();
        let result = indexer.subscribe(vec![], None);
        assert!(result.is_err(), "空 event_types 应被拒绝");
    }

    #[test]
    fn test_subscription_queue_overflow_reports_gap_before_retained_events() {
        let indexer = Indexer::new();
        let sub_id = indexer.subscribe(vec![EventType::Block], None).unwrap();

        // 推入超过 MAX_EVENTS_PER_SUBSCRIPTION 个区块
        for h in 0..(MAX_EVENTS_PER_SUBSCRIPTION + 5) as BlockHeight {
            let block = make_block(h, [h as u8; 32], vec![], vec![]);
            assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));
        }

        let events = indexer.poll_events(sub_id).unwrap();
        assert_eq!(events.len(), MAX_EVENTS_PER_SUBSCRIPTION + 1);
        assert_eq!(
            events.first(),
            Some(&IndexerEvent::Gap { dropped_events: 5 }),
            "溢出必须显式报告，而不是静默丢失"
        );
        // 最旧的 5 个事件应被丢弃，最早保留的高度为 5
        if let IndexerEvent::Block(ref b) = events[1] {
            assert_eq!(b.height, 5, "最旧事件应被丢弃");
        } else {
            panic!("应为 Block 事件");
        }
    }

    #[test]
    fn test_multiple_subscriptions_independent() {
        let indexer = Indexer::new();
        let sub1 = indexer.subscribe(vec![EventType::Block], None).unwrap();
        let sub2 = indexer
            .subscribe(vec![EventType::Transaction], None)
            .unwrap();
        let sub3 = indexer
            .subscribe(vec![EventType::Block, EventType::Transaction], None)
            .unwrap();

        let tx = make_tx(0x01, 1, TxLane::Public, None);
        let block = make_block(100, [0u8; 32], vec![tx], vec![]);
        assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));

        // sub1 仅订阅 Block
        let e1 = indexer.poll_events(sub1).unwrap();
        assert_eq!(e1.len(), 1);
        assert!(matches!(e1[0], IndexerEvent::Block(_)));

        // sub2 仅订阅 Transaction
        let e2 = indexer.poll_events(sub2).unwrap();
        assert_eq!(e2.len(), 1);
        assert!(matches!(e2[0], IndexerEvent::Transaction(_)));

        // sub3 订阅两者
        let e3 = indexer.poll_events(sub3).unwrap();
        assert_eq!(e3.len(), 2, "应同时收到 Block 与 Transaction 事件");
    }

    #[test]
    fn test_tx_filter_limit_truncates() {
        let indexer = Indexer::new();
        // 构造 5 个同 sender 的 tx，分布在不同高度
        for h in 10..15 {
            let tx = make_tx(0x01, h, TxLane::Public, None);
            let block = make_block(h, [h as u8; 32], vec![tx], vec![]);
            assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));
        }

        let sender = derive_address(&make_tagged_pubkey(0x01));
        let results = indexer.query_txs(&TxFilter::new().with_sender(sender).with_limit(3));
        assert_eq!(results.len(), 3, "limit 应截断结果");
        // 应按高度升序排列，截断最旧的
        assert_eq!(results[0].block_height, 10);
        assert_eq!(results[2].block_height, 12);
    }

    #[test]
    fn test_indexed_block_total_tx_count() {
        let tx1 = make_tx(0x01, 1, TxLane::Public, None);
        let tx2 = make_tx(0x02, 1, TxLane::GameTurn, None);
        let block = make_block(100, [0u8; 32], vec![tx1], vec![tx2]);
        let indexed = IndexedBlock {
            height: 100,
            block_hash: block.block_hash(crate::DEFAULT_CHAIN_ID),
            timestamp_ms: block.header.timestamp_ms,
            prev_hash: block.header.prev_hash,
            state_root: block.header.state_root,
            public_tx_root: block.header.public_tx_root,
            gameturn_tx_root: block.header.gameturn_tx_root,
            public_tx_count: 1,
            gameturn_tx_count: 1,
        };
        assert_eq!(indexed.total_tx_count(), 2);
    }

    #[test]
    fn test_pending_event_count() {
        let indexer = Indexer::new();
        let sub_id = indexer.subscribe(vec![EventType::Block], None).unwrap();
        assert_eq!(indexer.pending_event_count(sub_id), Some(0));

        let block = make_block(100, [0u8; 32], vec![], vec![]);
        assert!(indexer.index_block(&block, crate::DEFAULT_CHAIN_ID));
        assert_eq!(indexer.pending_event_count(sub_id), Some(1));

        // 不存在的订阅
        assert_eq!(indexer.pending_event_count(99999), None);
    }
}
