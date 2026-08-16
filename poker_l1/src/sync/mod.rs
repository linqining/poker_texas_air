//! 状态快速同步（Fast/Snap Sync）模块。
//!
//! ## 设计目标
//!
//! 新节点加入网络时，无需从 genesis 全量回放所有交易，而是通过以下步骤快速同步到最新状态：
//!
//! 1. **发现快照**：从 peer 获取最近的 `SnapshotManifest`（含高度、state_root、分块信息）
//! 2. **验证快照头**：对照 `BlockStore` 中对应高度的 `BlockHeader.state_root` 校验快照根
//! 3. **分块下载**：按 chunk 下载对象数据（防 OOM，每块 ≤ `MAX_SNAPSHOT_CHUNK_SIZE`）
//! 4. **应用快照**：将对象批量写入 `ObjectDb`，重建 SMT，校验 state_root 一致
//! 5. **区块追赶**：从快照高度开始，下载并执行后续区块直到 tip
//!
//! ## 信任模型
//!
//! - 快照的 `state_root` 由 `BlockHeader` 背书（BFT 共识保证）
//! - 下载的 chunk 通过 `blake2b_256` 哈希逐一校验（防 Byzantine peer 投毒）
//! - 最终 `ObjectDb::state_root()` 必须等于 manifest 中的 `state_root`（端到端校验）
//!
//! ## 与现有模块的关系
//!
//! - 复用 [`crate::storage::ObjectDb`] 进行状态持久化与 SMT 重建
//! - 复用 [`crate::storage::BlockStore`] 进行区块头验证与追赶
//! - 复用 [`crate::object_model::Object`] 作为状态快照的基本单元
//! - 不引入新依赖，仅使用 `blake2b_256`（与全库一致）

use crate::account::{Account, AccountStore};
use crate::block::{Block, BlockHeader};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::network::NetworkTransport;
use crate::object_model::Object;
use crate::storage::{
    BlockStore, BridgeNonceSnapshot, BridgeRegistryStore, ObjectBackend, ObjectDb, ObjectDbSnapshot,
};
use crate::{BlockHeight, ChainId, Hash};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};

/// 快照分块大小上限（4MB，与 `MAX_BLOCK_SIZE` 一致）。
pub const MAX_SNAPSHOT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// 每个快照分块最多包含的对象数（防单块过大导致 OOM）。
pub const MAX_OBJECTS_PER_CHUNK: usize = 10_000;

/// The largest block range requested in one P2P round-trip during Fast Sync.
///
/// Bound requests before decoding a peer response so a remote tip cannot force
/// an unbounded allocation in a single response.
/// The transport frame is intentionally smaller than a worst-case batch of blocks. Three
/// 4-MiB blocks fit with framing headroom in the 16-MiB P2P limit, while larger batches would
/// force a responder to allocate an oversized response before it can reject it.
pub const MAX_BLOCKS_PER_SYNC_REQUEST: BlockHeight = 3;

/// 快照清单（manifest）—— 描述一个状态快照的元数据。
///
/// 由 archive 节点在指定高度生成，syncing 节点据此下载与验证。
/// 所有字段参与 `manifest_hash` 计算，防 Byzantine peer 篡改清单。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SnapshotManifest {
    /// 快照对应的区块高度。
    pub height: BlockHeight,
    /// 快照对应的区块哈希（用于从 BlockStore 查询 BlockHeader）。
    pub block_hash: Hash,
    /// 快照的 state_root（应等于 BlockHeader.state_root）。
    pub state_root: Hash,
    /// 快照包含的对象总数。
    pub object_count: u64,
    /// 分块数量。
    pub chunk_count: u64,
    /// 每个分块的 blake2b_256 哈希（按顺序对应 chunk index）。
    pub chunk_hashes: Vec<Hash>,
    /// 生成时间戳（毫秒，来自 BlockHeader.timestamp_ms）。
    pub timestamp_ms: u64,
}

impl SnapshotManifest {
    /// 计算清单自身的 blake2b_256 哈希（用于清单完整性校验）。
    ///
    /// 将所有字段 BCS 序列化后哈希，防清单被篡改。
    #[must_use]
    pub fn manifest_hash(&self) -> Hash {
        let bytes = borsh::to_vec(self).unwrap_or_default();
        hash_bytes(&bytes)
    }

    /// 校验清单内部一致性（chunk_count == chunk_hashes.len() 等）。
    #[must_use]
    pub fn validate(&self) -> bool {
        self.chunk_count as usize == self.chunk_hashes.len()
            && self.object_count > 0
            && self.chunk_count > 0
    }
}

/// 单个快照分块——包含一批序列化的 `Object`。
///
/// 分块大小受 `MAX_SNAPSHOT_CHUNK_SIZE` 与 `MAX_OBJECTS_PER_CHUNK` 双重限制。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SnapshotChunk {
    /// 分块索引（0-based）。
    pub index: u64,
    /// 本块包含的对象（BCS 序列化前）。
    pub objects: Vec<Object>,
}

/// Manifest for the account half of a full state snapshot.
///
/// Account records live in a dedicated store, but their root is committed by the same block
/// header as ObjectDb. Keeping a separate manifest avoids changing the object wire format while
/// ensuring a sync peer cannot omit balances or replay nonces.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AccountSnapshotManifest {
    /// Snapshot height; must equal the paired ObjectDb manifest.
    pub height: BlockHeight,
    /// Block hash binding this account snapshot to the finalized header.
    pub block_hash: Hash,
    /// Expected deterministic AccountStore root.
    pub account_root: Hash,
    /// Number of account records across every chunk.
    pub account_count: u64,
    /// Number of account chunks.
    pub chunk_count: u64,
    /// Hash of each account chunk by zero-based index.
    pub chunk_hashes: Vec<Hash>,
    /// Finalized header timestamp, matching the paired ObjectDb manifest.
    pub timestamp_ms: u64,
}

/// Manifest for the bridge replay-protection archive in a full state snapshot.
///
/// The nonce archive itself is stored outside ObjectDb, but `nonce_root` and both counts are
/// committed by the paired `BridgeReplayState` ObjectDb singleton. This manifest merely carries
/// the authenticated preimage required to resume bridge execution after sync.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BridgeSnapshotManifest {
    /// Snapshot height; must equal both ObjectDb and AccountStore manifests.
    pub height: BlockHeight,
    /// Finalized block hash shared by all three stores.
    pub block_hash: Hash,
    /// State-root-committed canonical bridge nonce-set hash.
    pub nonce_root: Hash,
    /// Number of deposit nonce records.
    pub deposit_nonce_count: u64,
    /// Number of burn nonce records.
    pub burn_nonce_count: u64,
    /// Number of nonce records in all chunks.
    pub nonce_count: u64,
    /// Number of bounded chunks.
    pub chunk_count: u64,
    /// Hash of each bridge chunk by zero-based index.
    pub chunk_hashes: Vec<Hash>,
    /// Finalized header timestamp, matching the paired manifests.
    pub timestamp_ms: u64,
}

impl BridgeSnapshotManifest {
    /// Validate internal allocation bounds and count relationships.
    #[must_use]
    pub fn validate(&self) -> bool {
        self.chunk_count as usize == self.chunk_hashes.len()
            && self.nonce_count
                == self
                    .deposit_nonce_count
                    .saturating_add(self.burn_nonce_count)
            && ((self.nonce_count == 0 && self.chunk_count == 0)
                || (self.nonce_count > 0 && self.chunk_count > 0))
    }
}

/// One canonical nonce record in a bridge snapshot chunk.
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
pub struct BridgeNonceRecord {
    /// `false` for a source-chain deposit nonce and `true` for a poker_l1 burn nonce.
    pub is_burn: bool,
    /// Source/destination chain component of the nonce key.
    pub chain_id: ChainId,
    /// Replay-protection nonce.
    pub nonce: u64,
}

/// One bounded bridge nonce archive chunk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BridgeSnapshotChunk {
    /// Zero-based chunk index.
    pub index: u64,
    /// Canonically ordered replay-protection nonce records.
    pub records: Vec<BridgeNonceRecord>,
}

impl BridgeSnapshotChunk {
    /// Hash this exact chunk for manifest authentication.
    #[must_use]
    pub fn chunk_hash(&self) -> Hash {
        hash_bytes(&borsh::to_vec(self).unwrap_or_default())
    }

    /// Apply the standard bounded chunk limits before retaining peer data.
    pub fn validate_size(&self) -> PokerL1Result<()> {
        if self.records.len() > MAX_OBJECTS_PER_CHUNK {
            return Err(PokerL1Error::Other(format!(
                "bridge snapshot chunk {} record count {} exceeds limit {}",
                self.index,
                self.records.len(),
                MAX_OBJECTS_PER_CHUNK
            )));
        }
        let serialized_len = borsh::to_vec(self)
            .map(|value| value.len())
            .unwrap_or(usize::MAX);
        if serialized_len > MAX_SNAPSHOT_CHUNK_SIZE {
            return Err(PokerL1Error::Other(format!(
                "bridge snapshot chunk {} serialized size {} exceeds limit {}",
                self.index, serialized_len, MAX_SNAPSHOT_CHUNK_SIZE
            )));
        }
        Ok(())
    }
}

impl AccountSnapshotManifest {
    /// Validate internal bounds without trusting any peer-supplied allocation size.
    #[must_use]
    pub fn validate(&self) -> bool {
        self.chunk_count as usize == self.chunk_hashes.len()
            && ((self.account_count == 0 && self.chunk_count == 0)
                || (self.account_count > 0 && self.chunk_count > 0))
    }
}

/// One bounded account-state snapshot chunk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
pub struct AccountSnapshotChunk {
    /// Zero-based chunk index.
    pub index: u64,
    /// Canonically serialized account records, each including its address, public key, nonce and balance.
    pub accounts: Vec<Account>,
}

impl AccountSnapshotChunk {
    /// Hash this exact chunk for manifest authentication.
    #[must_use]
    pub fn chunk_hash(&self) -> Hash {
        hash_bytes(&borsh::to_vec(self).unwrap_or_default())
    }

    /// Apply the same object-count and byte limits used by ObjectDb chunks.
    pub fn validate_size(&self) -> PokerL1Result<()> {
        if self.accounts.len() > MAX_OBJECTS_PER_CHUNK {
            return Err(PokerL1Error::Other(format!(
                "account snapshot chunk {} account count {} exceeds limit {}",
                self.index,
                self.accounts.len(),
                MAX_OBJECTS_PER_CHUNK
            )));
        }
        let serialized_len = borsh::to_vec(self)
            .map(|value| value.len())
            .unwrap_or(usize::MAX);
        if serialized_len > MAX_SNAPSHOT_CHUNK_SIZE {
            return Err(PokerL1Error::Other(format!(
                "account snapshot chunk {} serialized size {} exceeds limit {}",
                self.index, serialized_len, MAX_SNAPSHOT_CHUNK_SIZE
            )));
        }
        Ok(())
    }
}

/// The complete state required to resume deterministic block execution at one finalized height.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
pub struct FullSnapshot {
    /// ObjectDb state and its authenticated chunks.
    pub object_manifest: SnapshotManifest,
    /// ObjectDb chunks.
    pub object_chunks: Vec<SnapshotChunk>,
    /// AccountStore state and its authenticated chunks.
    pub account_manifest: AccountSnapshotManifest,
    /// AccountStore chunks.
    pub account_chunks: Vec<AccountSnapshotChunk>,
    /// Authenticated bridge replay archive, when the source node has bridge enabled.
    pub bridge_manifest: Option<BridgeSnapshotManifest>,
    /// Bridge replay nonce chunks paired with `bridge_manifest`.
    pub bridge_chunks: Vec<BridgeSnapshotChunk>,
}

/// Small P2P-discoverable descriptor for a complete snapshot.
///
/// Chunk payloads deliberately travel in separate bounded messages.  A peer must authenticate
/// this descriptor against a finalized block before retaining any object, account, or bridge
/// archive chunk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
pub struct FullSnapshotManifest {
    /// ObjectDb half of the snapshot.
    pub object_manifest: SnapshotManifest,
    /// AccountStore half of the snapshot.
    pub account_manifest: AccountSnapshotManifest,
    /// Optional bridge replay-archive half.  Bridge-enabled nodes require it.
    pub bridge_manifest: Option<BridgeSnapshotManifest>,
}

impl FullSnapshotManifest {
    /// Build a descriptor from an already consistent full snapshot.
    #[must_use]
    pub fn from_snapshot(snapshot: &FullSnapshot) -> Self {
        Self {
            object_manifest: snapshot.object_manifest.clone(),
            account_manifest: snapshot.account_manifest.clone(),
            bridge_manifest: snapshot.bridge_manifest.clone(),
        }
    }

    /// Return the finalized block hash that identifies every chunk request.
    #[must_use]
    pub const fn block_hash(&self) -> Hash {
        self.object_manifest.block_hash
    }

    /// Reject descriptors with mismatched or malformed component manifests.
    pub fn validate(&self) -> PokerL1Result<()> {
        match &self.bridge_manifest {
            Some(bridge_manifest) => verify_full_snapshot_triplet(
                &self.object_manifest,
                &self.account_manifest,
                bridge_manifest,
            ),
            None => verify_full_snapshot_pair(&self.object_manifest, &self.account_manifest),
        }
    }
}

impl SnapshotChunk {
    /// 计算分块的 blake2b_256 哈希（用于与 manifest.chunk_hashes[index] 比对）。
    #[must_use]
    pub fn chunk_hash(&self) -> Hash {
        let bytes = borsh::to_vec(self).unwrap_or_default();
        hash_bytes(&bytes)
    }

    /// 校验分块大小是否超限。
    ///
    /// 返回 `Err` 表示分块过大或对象数过多，应拒绝该分块。
    pub fn validate_size(&self) -> PokerL1Result<()> {
        if self.objects.len() > MAX_OBJECTS_PER_CHUNK {
            return Err(PokerL1Error::Other(format!(
                "snapshot chunk {} objects count {} exceeds limit {}",
                self.index,
                self.objects.len(),
                MAX_OBJECTS_PER_CHUNK
            )));
        }
        let serialized_len = borsh::to_vec(self).map(|v| v.len()).unwrap_or(usize::MAX);
        if serialized_len > MAX_SNAPSHOT_CHUNK_SIZE {
            return Err(PokerL1Error::Other(format!(
                "snapshot chunk {} serialized size {} exceeds limit {}",
                self.index, serialized_len, MAX_SNAPSHOT_CHUNK_SIZE
            )));
        }
        Ok(())
    }
}

/// 快照生成器——从 `ObjectDb` 创建快照清单与分块。
///
/// 典型由 archive 节点在指定高度调用。
pub struct SnapshotBuilder;

impl SnapshotBuilder {
    /// Build a complete ObjectDb + AccountStore snapshot for one finalized header.
    ///
    /// A caller must use this production API whenever account state is present.  The existing
    /// object-only builder remains for legacy object snapshots and unit tests, but it cannot
    /// restore account nonce or resource-credit state.
    pub fn build_full_snapshot(
        object_db: &ObjectDb,
        account_store: &AccountStore,
        block_header: &BlockHeader,
        chain_id: ChainId,
    ) -> PokerL1Result<FullSnapshot> {
        if object_db.state_root() != block_header.state_root {
            return Err(PokerL1Error::Other(
                "ObjectDb root does not match the requested snapshot header".to_string(),
            ));
        }
        if account_store.state_root() != block_header.account_root {
            return Err(PokerL1Error::Other(
                "AccountStore root does not match the requested snapshot header".to_string(),
            ));
        }
        let (object_manifest, object_chunks) =
            Self::build_snapshot(object_db, block_header, chain_id)?;

        let mut accounts: Vec<Account> = account_store.iter().cloned().collect();
        accounts.sort_by_key(|account| account.address);
        let mut account_chunks = Vec::new();
        let mut chunk_hashes = Vec::new();
        let mut current = Vec::new();
        let mut current_size = 0usize;
        for account in accounts {
            let account_size = borsh::to_vec(&account)?.len();
            if !current.is_empty()
                && (current.len() >= MAX_OBJECTS_PER_CHUNK
                    || current_size.saturating_add(account_size) > MAX_SNAPSHOT_CHUNK_SIZE)
            {
                let chunk = AccountSnapshotChunk {
                    index: account_chunks.len() as u64,
                    accounts: std::mem::take(&mut current),
                };
                chunk_hashes.push(chunk.chunk_hash());
                account_chunks.push(chunk);
                current_size = 0;
            }
            current_size = current_size.saturating_add(account_size);
            current.push(account);
        }
        if !current.is_empty() {
            let chunk = AccountSnapshotChunk {
                index: account_chunks.len() as u64,
                accounts: current,
            };
            chunk_hashes.push(chunk.chunk_hash());
            account_chunks.push(chunk);
        }
        let account_manifest = AccountSnapshotManifest {
            height: block_header.height,
            block_hash: block_header.block_hash(chain_id),
            account_root: block_header.account_root,
            account_count: account_store.len() as u64,
            chunk_count: account_chunks.len() as u64,
            chunk_hashes,
            timestamp_ms: block_header.timestamp_ms,
        };
        debug_assert!(account_manifest.validate());
        Ok(FullSnapshot {
            object_manifest,
            object_chunks,
            account_manifest,
            account_chunks,
            bridge_manifest: None,
            bridge_chunks: Vec::new(),
        })
    }

    /// Build an authenticated ObjectDb + AccountStore + bridge nonce archive snapshot.
    ///
    /// The caller must provide the bridge store from the same finalized node state as
    /// `object_db`. Its complete nonce archive is verified against the replay-state singleton
    /// already committed in `block_header.state_root`; an archive that does not match is never
    /// exported as a potentially replayable snapshot.
    pub fn build_full_snapshot_with_bridge(
        object_db: &ObjectDb,
        account_store: &AccountStore,
        bridge_store: &BridgeRegistryStore,
        block_header: &BlockHeader,
        chain_id: ChainId,
    ) -> PokerL1Result<FullSnapshot> {
        let mut full = Self::build_full_snapshot(object_db, account_store, block_header, chain_id)?;
        let replay_object = object_db.read(&crate::bridge::BRIDGE_REPLAY_STATE_OBJECT_ID)?;
        let replay_state =
            crate::bridge::decode_bridge_replay_state_object(&replay_object, chain_id)?;
        let (nonce_root, deposit_nonce_count, burn_nonce_count) = bridge_store.replay_commitment();
        if replay_state.nonce_root != nonce_root
            || replay_state.deposit_nonce_count != deposit_nonce_count
            || replay_state.burn_nonce_count != burn_nonce_count
        {
            return Err(PokerL1Error::Other(
                "bridge nonce archive does not match ObjectDb replay-state commitment".to_string(),
            ));
        }
        let nonce_snapshot = bridge_store.nonce_snapshot();
        let (bridge_manifest, bridge_chunks) =
            Self::build_bridge_snapshot(&nonce_snapshot, &replay_state, block_header, chain_id)?;
        full.bridge_manifest = Some(bridge_manifest);
        full.bridge_chunks = bridge_chunks;
        Ok(full)
    }

    fn build_bridge_snapshot(
        nonce_snapshot: &BridgeNonceSnapshot,
        replay_state: &crate::bridge::BridgeReplayState,
        block_header: &BlockHeader,
        chain_id: ChainId,
    ) -> PokerL1Result<(BridgeSnapshotManifest, Vec<BridgeSnapshotChunk>)> {
        let mut records = Vec::with_capacity(
            nonce_snapshot
                .deposit_nonces
                .len()
                .saturating_add(nonce_snapshot.burn_nonces.len()),
        );
        records.extend(
            nonce_snapshot
                .deposit_nonces
                .iter()
                .map(|&(chain_id, nonce)| BridgeNonceRecord {
                    is_burn: false,
                    chain_id,
                    nonce,
                }),
        );
        records.extend(nonce_snapshot.burn_nonces.iter().map(|&(chain_id, nonce)| {
            BridgeNonceRecord {
                is_burn: true,
                chain_id,
                nonce,
            }
        }));

        let mut chunks = Vec::new();
        let mut current = Vec::new();
        for record in records {
            current.push(record);
            let candidate = BridgeSnapshotChunk {
                index: chunks.len() as u64,
                records: current.clone(),
            };
            if candidate.records.len() > MAX_OBJECTS_PER_CHUNK
                || borsh::to_vec(&candidate)?.len() > MAX_SNAPSHOT_CHUNK_SIZE
            {
                let last = current.pop().expect("just pushed bridge nonce record");
                if current.is_empty() {
                    return Err(PokerL1Error::Other(
                        "single bridge nonce record exceeds snapshot chunk limit".to_string(),
                    ));
                }
                chunks.push(BridgeSnapshotChunk {
                    index: chunks.len() as u64,
                    records: std::mem::take(&mut current),
                });
                current.push(last);
            }
        }
        if !current.is_empty() {
            chunks.push(BridgeSnapshotChunk {
                index: chunks.len() as u64,
                records: current,
            });
        }
        let manifest = BridgeSnapshotManifest {
            height: block_header.height,
            block_hash: block_header.block_hash(chain_id),
            nonce_root: replay_state.nonce_root,
            deposit_nonce_count: replay_state.deposit_nonce_count,
            burn_nonce_count: replay_state.burn_nonce_count,
            nonce_count: replay_state
                .deposit_nonce_count
                .saturating_add(replay_state.burn_nonce_count),
            chunk_count: chunks.len() as u64,
            chunk_hashes: chunks.iter().map(BridgeSnapshotChunk::chunk_hash).collect(),
            timestamp_ms: block_header.timestamp_ms,
        };
        if !manifest.validate() {
            return Err(PokerL1Error::Other(
                "invalid generated bridge snapshot manifest".to_string(),
            ));
        }
        Ok((manifest, chunks))
    }

    /// 为指定 `ObjectDb` 在指定高度生成快照。
    ///
    /// # 参数
    /// - `object_db`：源状态库（只读迭代）
    /// - `block_header`：对应高度的区块头（提供 state_root / timestamp / block_hash）
    /// - `chain_id`：生成该区块哈希时使用的网络 chain ID
    ///
    /// # 返回
    /// `(SnapshotManifest, Vec<SnapshotChunk>)` —— 清单 + 全部分块
    ///
    /// # 错误
    /// - `ObjectDb` 为空时返回错误（空状态无需快照）
    /// - BCS 序列化失败时返回错误
    pub fn build_snapshot(
        object_db: &ObjectDb,
        block_header: &BlockHeader,
        chain_id: ChainId,
    ) -> PokerL1Result<(SnapshotManifest, Vec<SnapshotChunk>)> {
        if object_db.is_empty() {
            return Err(PokerL1Error::Other(
                "cannot snapshot empty ObjectDb".to_string(),
            ));
        }

        let mut chunks = Vec::new();
        let mut current_chunk_objects: Vec<Object> = Vec::new();
        let mut current_chunk_size: usize = 0;
        let mut total_object_count: u64 = 0;
        let mut chunk_hashes: Vec<Hash> = Vec::new();

        for object in object_db.iter() {
            let obj_bytes = borsh::to_vec(object)?;
            let obj_size = obj_bytes.len();

            // 若当前块已满（对象数或字节数），先封块
            if current_chunk_objects.len() >= MAX_OBJECTS_PER_CHUNK
                || current_chunk_size + obj_size > MAX_SNAPSHOT_CHUNK_SIZE
            {
                let chunk = SnapshotChunk {
                    index: chunks.len() as u64,
                    objects: std::mem::take(&mut current_chunk_objects),
                };
                chunk_hashes.push(chunk.chunk_hash());
                chunks.push(chunk);
                current_chunk_size = 0;
            }

            current_chunk_objects.push(object.clone());
            current_chunk_size += obj_size;
            total_object_count += 1;
        }

        // 封最后一块
        if !current_chunk_objects.is_empty() {
            let chunk = SnapshotChunk {
                index: chunks.len() as u64,
                objects: current_chunk_objects,
            };
            chunk_hashes.push(chunk.chunk_hash());
            chunks.push(chunk);
        }

        let manifest = SnapshotManifest {
            height: block_header.height,
            block_hash: block_header.block_hash(chain_id),
            state_root: block_header.state_root,
            object_count: total_object_count,
            chunk_count: chunks.len() as u64,
            chunk_hashes,
            timestamp_ms: block_header.timestamp_ms,
        };

        Ok((manifest, chunks))
    }
}

/// 快照验证器——校验下载的快照分块与清单一致性。
pub struct SnapshotVerifier;

impl SnapshotVerifier {
    /// Verify that a bridge manifest binds to the same finalized block as ObjectDb state.
    pub fn verify_bridge_manifest_against_block(
        manifest: &BridgeSnapshotManifest,
        block_store: &BlockStore,
    ) -> PokerL1Result<()> {
        if !manifest.validate() {
            return Err(PokerL1Error::Other(
                "invalid bridge snapshot manifest".to_string(),
            ));
        }
        let header = block_store.get_header_by_hash(&manifest.block_hash)?;
        if header.height != manifest.height || header.timestamp_ms != manifest.timestamp_ms {
            return Err(PokerL1Error::Other(
                "bridge snapshot manifest does not match finalized block header".to_string(),
            ));
        }
        Ok(())
    }

    /// Verify one bounded bridge nonce archive chunk against its manifest.
    pub fn verify_bridge_chunk(
        chunk: &BridgeSnapshotChunk,
        manifest: &BridgeSnapshotManifest,
    ) -> PokerL1Result<()> {
        let index = usize::try_from(chunk.index).map_err(|_| {
            PokerL1Error::Other("bridge snapshot chunk index does not fit usize".to_string())
        })?;
        let expected = manifest.chunk_hashes.get(index).ok_or_else(|| {
            PokerL1Error::Other("bridge snapshot chunk index out of range".to_string())
        })?;
        chunk.validate_size()?;
        if chunk.chunk_hash() != *expected {
            return Err(PokerL1Error::Other(format!(
                "bridge snapshot chunk {} hash mismatch",
                chunk.index
            )));
        }
        Ok(())
    }

    /// Verify that an account manifest is anchored by the same finalized block as ObjectDb state.
    pub fn verify_account_manifest_against_block(
        manifest: &AccountSnapshotManifest,
        block_store: &BlockStore,
    ) -> PokerL1Result<()> {
        if !manifest.validate() {
            return Err(PokerL1Error::Other(
                "invalid account snapshot manifest".to_string(),
            ));
        }
        let header = block_store.get_header_by_hash(&manifest.block_hash)?;
        if header.height != manifest.height
            || header.timestamp_ms != manifest.timestamp_ms
            || header.account_root != manifest.account_root
        {
            return Err(PokerL1Error::Other(
                "account snapshot manifest does not match finalized block header".to_string(),
            ));
        }
        Ok(())
    }

    /// Verify one account chunk before allocating it into staging state.
    pub fn verify_account_chunk(
        chunk: &AccountSnapshotChunk,
        manifest: &AccountSnapshotManifest,
    ) -> PokerL1Result<()> {
        let index = usize::try_from(chunk.index).map_err(|_| {
            PokerL1Error::Other("account snapshot chunk index does not fit usize".to_string())
        })?;
        let expected = manifest.chunk_hashes.get(index).ok_or_else(|| {
            PokerL1Error::Other("account snapshot chunk index out of range".to_string())
        })?;
        chunk.validate_size()?;
        if chunk.chunk_hash() != *expected {
            return Err(PokerL1Error::Other(format!(
                "account snapshot chunk {} hash mismatch",
                chunk.index
            )));
        }
        Ok(())
    }

    /// 校验单个分块的哈希与清单中对应索引的哈希一致。
    ///
    /// 防止 Byzantine peer 提供篡改的分块数据。
    pub fn verify_chunk(chunk: &SnapshotChunk, manifest: &SnapshotManifest) -> PokerL1Result<()> {
        // 1. 校验分块索引在范围内
        let idx = chunk.index as usize;
        if idx >= manifest.chunk_hashes.len() {
            return Err(PokerL1Error::Other(format!(
                "chunk index {} out of range (manifest has {} chunks)",
                chunk.index, manifest.chunk_count
            )));
        }

        // 2. 校验分块大小
        chunk.validate_size()?;

        // 3. 校验分块哈希
        let actual_hash = chunk.chunk_hash();
        let expected_hash = manifest.chunk_hashes[idx];
        if actual_hash != expected_hash {
            return Err(PokerL1Error::Other(format!(
                "chunk {} hash mismatch: expected {}, got {}",
                chunk.index,
                hex_encode(&expected_hash),
                hex_encode(&actual_hash)
            )));
        }

        Ok(())
    }

    /// 校验清单的 state_root 与 BlockStore 中对应高度的 BlockHeader 一致。
    ///
    /// 这是快照信任的锚点：state_root 由 BFT 共识背书。
    pub fn verify_manifest_against_block(
        manifest: &SnapshotManifest,
        block_store: &BlockStore,
    ) -> PokerL1Result<()> {
        let header = block_store.get_header_by_hash(&manifest.block_hash)?;
        if header.height != manifest.height {
            return Err(PokerL1Error::Other(format!(
                "manifest height {} != block height {}",
                manifest.height, header.height
            )));
        }
        if header.state_root != manifest.state_root {
            return Err(PokerL1Error::Other(format!(
                "manifest state_root {} != block state_root {}",
                hex_encode(&manifest.state_root),
                hex_encode(&header.state_root)
            )));
        }
        Ok(())
    }

    /// 校验已应用快照的 ObjectDb 的 state_root 与清单一致。
    ///
    /// 端到端校验：应用所有分块后，重建的 SMT root 必须等于 manifest.state_root。
    pub fn verify_applied_state(
        object_db: &ObjectDb,
        manifest: &SnapshotManifest,
    ) -> PokerL1Result<()> {
        let actual_root = object_db.state_root();
        if actual_root != manifest.state_root {
            return Err(PokerL1Error::Other(format!(
                "applied state_root {} != manifest state_root {}",
                hex_encode(&actual_root),
                hex_encode(&manifest.state_root)
            )));
        }
        Ok(())
    }
}

/// 快照应用器——将验证过的分块应用到 `ObjectDb`。
///
/// 应用顺序：在隔离 snapshot 中按 chunk index 写入所有对象 → 校验 state_root → 单批提交。
pub struct SnapshotApplier;

impl SnapshotApplier {
    /// Build an isolated ObjectDb candidate from a complete authenticated snapshot.
    ///
    /// This is deliberately separate from [`Self::apply_chunks`]: callers which restore more
    /// than one consensus store must validate *all* candidates before making either store
    /// visible.  The returned snapshot is still isolated and can be discarded without changing
    /// the destination database.
    fn stage_object_chunks(
        object_db: &ObjectDb,
        chunks: &[SnapshotChunk],
        manifest: &SnapshotManifest,
    ) -> PokerL1Result<ObjectDbSnapshot> {
        if !object_db.is_empty() {
            return Err(PokerL1Error::Other(
                "snapshot application requires an empty ObjectDb".to_string(),
            ));
        }
        if !manifest.validate() {
            return Err(PokerL1Error::Other("invalid snapshot manifest".to_string()));
        }
        if chunks.len() as u64 != manifest.chunk_count {
            return Err(PokerL1Error::Other(format!(
                "snapshot chunks {} != manifest {}",
                chunks.len(),
                manifest.chunk_count
            )));
        }

        let mut sorted_chunks: Vec<&SnapshotChunk> = chunks.iter().collect();
        sorted_chunks.sort_by_key(|chunk| chunk.index);
        let mut snapshot = object_db.create_snapshot();
        let mut applied_count: u64 = 0;
        for (expected_index, chunk) in sorted_chunks.iter().enumerate() {
            if chunk.index != expected_index as u64 {
                return Err(PokerL1Error::Other(
                    "snapshot chunk indexes are not contiguous".to_string(),
                ));
            }
            SnapshotVerifier::verify_chunk(chunk, manifest)?;
            for object in &chunk.objects {
                if crate::object_model::store::is_system_object(object) {
                    snapshot.system_create(object.clone())?;
                } else {
                    snapshot.create(object.clone())?;
                }
                applied_count = applied_count.checked_add(1).ok_or_else(|| {
                    PokerL1Error::Other("snapshot object count overflow".to_string())
                })?;
            }
        }
        if applied_count != manifest.object_count {
            return Err(PokerL1Error::Other(format!(
                "applied object count {} != manifest object_count {}",
                applied_count, manifest.object_count
            )));
        }
        if snapshot.state_root() != manifest.state_root {
            return Err(PokerL1Error::Other(format!(
                "applied state_root {} != manifest state_root {}",
                hex_encode(&snapshot.state_root()),
                hex_encode(&manifest.state_root)
            )));
        }
        Ok(snapshot)
    }

    /// Build an isolated AccountStore candidate from a complete authenticated snapshot.
    fn stage_account_chunks(
        account_store: &AccountStore,
        chunks: &[AccountSnapshotChunk],
        manifest: &AccountSnapshotManifest,
    ) -> PokerL1Result<AccountStore> {
        if !account_store.is_empty() {
            return Err(PokerL1Error::Other(
                "account snapshot application requires an empty AccountStore".to_string(),
            ));
        }
        if !manifest.validate() {
            return Err(PokerL1Error::Other(
                "invalid account snapshot manifest".to_string(),
            ));
        }
        if chunks.len() as u64 != manifest.chunk_count {
            return Err(PokerL1Error::Other(format!(
                "account snapshot chunks {} != manifest {}",
                chunks.len(),
                manifest.chunk_count
            )));
        }
        let mut sorted: Vec<&AccountSnapshotChunk> = chunks.iter().collect();
        sorted.sort_by_key(|chunk| chunk.index);
        let mut staged = AccountStore::new();
        let mut count = 0u64;
        for (expected_index, chunk) in sorted.iter().enumerate() {
            if chunk.index != expected_index as u64 {
                return Err(PokerL1Error::Other(
                    "account snapshot chunk indexes are not contiguous".to_string(),
                ));
            }
            SnapshotVerifier::verify_account_chunk(chunk, manifest)?;
            for account in &chunk.accounts {
                staged.create(account.clone())?;
                count = count.checked_add(1).ok_or_else(|| {
                    PokerL1Error::Other("account snapshot count overflow".to_string())
                })?;
            }
        }
        if count != manifest.account_count || staged.state_root() != manifest.account_root {
            return Err(PokerL1Error::Other(
                "account snapshot count or root mismatch".to_string(),
            ));
        }
        Ok(staged)
    }

    /// Reconstruct bridge nonce sets and prove them against the replay-state object in the
    /// already-authenticated ObjectDb candidate. No bridge store is mutated by this stage.
    fn stage_bridge_chunks(
        object_candidate: &ObjectDbSnapshot,
        chunks: &[BridgeSnapshotChunk],
        manifest: &BridgeSnapshotManifest,
    ) -> PokerL1Result<BridgeNonceSnapshot> {
        if !manifest.validate() || chunks.len() as u64 != manifest.chunk_count {
            return Err(PokerL1Error::Other(
                "incomplete or invalid bridge snapshot".to_string(),
            ));
        }
        let mut sorted_chunks: Vec<&BridgeSnapshotChunk> = chunks.iter().collect();
        sorted_chunks.sort_by_key(|chunk| chunk.index);
        let mut deposit_nonces = std::collections::BTreeSet::new();
        let mut burn_nonces = std::collections::BTreeSet::new();
        for (expected_index, chunk) in sorted_chunks.iter().enumerate() {
            if chunk.index != expected_index as u64 {
                return Err(PokerL1Error::Other(
                    "bridge snapshot chunk indexes are not contiguous".to_string(),
                ));
            }
            SnapshotVerifier::verify_bridge_chunk(chunk, manifest)?;
            for record in &chunk.records {
                let inserted = if record.is_burn {
                    burn_nonces.insert((record.chain_id, record.nonce))
                } else {
                    deposit_nonces.insert((record.chain_id, record.nonce))
                };
                if !inserted {
                    return Err(PokerL1Error::Other(
                        "bridge snapshot contains a duplicate nonce record".to_string(),
                    ));
                }
            }
        }
        if deposit_nonces.len() as u64 != manifest.deposit_nonce_count
            || burn_nonces.len() as u64 != manifest.burn_nonce_count
        {
            return Err(PokerL1Error::Other(
                "bridge snapshot nonce counts do not match manifest".to_string(),
            ));
        }
        let replay_object = object_candidate.read(&crate::bridge::BRIDGE_REPLAY_STATE_OBJECT_ID)?;
        let replay_state = crate::bridge::validate_bridge_replay_state_object(&replay_object)?;
        if replay_state.nonce_root != manifest.nonce_root
            || replay_state.deposit_nonce_count != manifest.deposit_nonce_count
            || replay_state.burn_nonce_count != manifest.burn_nonce_count
        {
            return Err(PokerL1Error::Other(
                "bridge snapshot manifest does not match ObjectDb replay-state commitment"
                    .to_string(),
            ));
        }
        let mut registry = crate::bridge::BridgeRegistry::new();
        registry.replace_nonce_sets(deposit_nonces.clone(), burn_nonces.clone());
        if !replay_state.matches_registry(&registry) {
            return Err(PokerL1Error::Other(
                "bridge nonce archive does not reproduce the committed replay root".to_string(),
            ));
        }
        Ok(BridgeNonceSnapshot {
            deposit_nonces,
            burn_nonces,
        })
    }

    /// Stage, verify and commit the complete AccountStore half of a full snapshot.
    ///
    /// The target must be empty so a peer cannot merge a partial account view with pre-existing
    /// nonce state. All chunk and root validation completes on an isolated AccountStore before
    /// the target's RocksDB batch is touched.
    pub fn apply_account_chunks(
        account_store: &mut AccountStore,
        chunks: &[AccountSnapshotChunk],
        manifest: &AccountSnapshotManifest,
    ) -> PokerL1Result<()> {
        let staged = Self::stage_account_chunks(account_store, chunks, manifest)?;
        account_store.apply_snapshot(staged)
    }

    /// 将一组已验证的分块应用到目标 `ObjectDb`。
    ///
    /// # 参数
    /// - `object_db`：空的目标状态库（将被写入）
    /// - `chunks`：已通过 `SnapshotVerifier::verify_chunk` 的分块（按 index 排序）
    /// - `manifest`：用于最终 state_root 校验
    ///
    /// # 错误
    /// - 任意对象写入失败（如 ObjectID 碰撞）
    /// - 最终 state_root 不匹配
    pub fn apply_chunks(
        object_db: &mut ObjectDb,
        chunks: &[SnapshotChunk],
        manifest: &SnapshotManifest,
    ) -> PokerL1Result<()> {
        let snapshot = Self::stage_object_chunks(object_db, chunks, manifest)?;
        snapshot.apply_to(object_db)
    }
}

/// 同步进度状态机。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// 初始状态，未开始同步。
    Idle,
    /// 已发现快照清单，正在验证。
    VerifyingManifest,
    /// 正在下载分块。
    DownloadingChunks { downloaded: u64, total: u64 },
    /// 正在应用分块到 ObjectDb。
    ApplyingChunks { applied: u64, total: u64 },
    /// 快照应用完成，正在追赶区块。
    CatchingUpBlocks {
        current_height: BlockHeight,
        tip_height: BlockHeight,
    },
    /// 同步完成。
    Synced,
    /// 同步失败（附带错误信息）。
    Failed(String),
}

/// 快速同步协调器——编排完整的同步流程。
///
/// 调用方（通常是 `Node`）按以下步骤使用：
///
/// ```ignore
/// use poker_l1::sync::{FastSync, SnapshotManifest, SnapshotChunk};
///
/// let mut fast_sync = FastSync::new(block_store, object_db);
/// // 1. 从 peer 获取清单
/// let manifest = fetch_manifest_from_peer()?;
/// // 2. 验证清单
/// fast_sync.verify_manifest(&manifest)?;
/// // 3. 下载并验证分块
/// for i in 0..manifest.chunk_count {
///     let chunk = fetch_chunk_from_peer(i)?;
///     fast_sync.receive_chunk(chunk, &manifest)?;
/// }
/// // 4. 应用分块
/// fast_sync.apply_snapshot(&manifest)?;
/// // 5. 追赶区块。回调必须走 Node::put_block（或等价的完整执行路径），
/// //    不能直接写 BlockStore。
/// fast_sync.catch_up_blocks_from_network(transport, tip_height, |block| {
///     node.put_block(block).map(|_| ())
/// })?;
/// ```
pub struct FastSync<'a> {
    block_store: &'a BlockStore,
    object_db: &'a mut ObjectDb,
    state: SyncState,
    received_chunks: Vec<SnapshotChunk>,
}

impl<'a> FastSync<'a> {
    /// 创建新的同步协调器。
    pub fn new(block_store: &'a BlockStore, object_db: &'a mut ObjectDb) -> Self {
        Self {
            block_store,
            object_db,
            state: SyncState::Idle,
            received_chunks: Vec::new(),
        }
    }

    /// 当前同步状态。
    #[must_use]
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    /// 步骤 1：验证快照清单（对照 BlockStore 中的 BlockHeader）。
    pub fn verify_manifest(&mut self, manifest: &SnapshotManifest) -> PokerL1Result<()> {
        self.state = SyncState::VerifyingManifest;
        if !manifest.validate() {
            self.state = SyncState::Failed("invalid manifest".to_string());
            return Err(PokerL1Error::Other("invalid snapshot manifest".to_string()));
        }
        SnapshotVerifier::verify_manifest_against_block(manifest, self.block_store)?;
        self.state = SyncState::DownloadingChunks {
            downloaded: 0,
            total: manifest.chunk_count,
        };
        Ok(())
    }

    /// 步骤 2：接收并验证单个分块。
    ///
    /// 分块按任意顺序接收，内部按 index 存储。重复分块会被忽略。
    pub fn receive_chunk(
        &mut self,
        chunk: SnapshotChunk,
        manifest: &SnapshotManifest,
    ) -> PokerL1Result<()> {
        // 验证分块
        SnapshotVerifier::verify_chunk(&chunk, manifest)?;

        // 去重：若已存在同 index 的分块，跳过
        if self.received_chunks.iter().any(|c| c.index == chunk.index) {
            return Ok(());
        }

        self.received_chunks.push(chunk);

        // 更新进度
        if let SyncState::DownloadingChunks { downloaded, total } = &self.state {
            self.state = SyncState::DownloadingChunks {
                downloaded: downloaded + 1,
                total: *total,
            };
        }

        Ok(())
    }

    /// 步骤 3：应用所有已接收的分块到 ObjectDb。
    ///
    /// 调用前需确保已接收全部分块（`received_chunks.len() == manifest.chunk_count`）。
    pub fn apply_snapshot(&mut self, manifest: &SnapshotManifest) -> PokerL1Result<()> {
        // 检查分块完整性
        if self.received_chunks.len() as u64 != manifest.chunk_count {
            self.state = SyncState::Failed(format!(
                "incomplete chunks: {} received, {} expected",
                self.received_chunks.len(),
                manifest.chunk_count
            ));
            return Err(PokerL1Error::Other(format!(
                "incomplete snapshot chunks: {} / {}",
                self.received_chunks.len(),
                manifest.chunk_count
            )));
        }

        self.state = SyncState::ApplyingChunks {
            applied: 0,
            total: manifest.object_count,
        };

        SnapshotApplier::apply_chunks(self.object_db, &self.received_chunks, manifest)?;

        self.state = SyncState::CatchingUpBlocks {
            current_height: manifest.height,
            tip_height: self
                .block_store
                .get_tip_height()?
                .unwrap_or(manifest.height),
        };

        Ok(())
    }

    /// Steps 4-5: download every missing block and submit it through the supplied execution path.
    ///
    /// Each peer response must contain exactly the requested, strictly ordered height range.
    /// The callback must perform full consensus/state validation, normally by delegating to
    /// [`crate::node::Node::put_block`].  Fast Sync deliberately never writes downloaded block
    /// bodies to [`BlockStore`] itself because that would bypass state-root replay.
    ///
    /// Returns the number of blocks successfully executed.
    pub fn catch_up_blocks_from_network<F>(
        &mut self,
        transport: &dyn NetworkTransport,
        tip_height: BlockHeight,
        mut apply_block: F,
    ) -> PokerL1Result<u64>
    where
        F: FnMut(&Block) -> PokerL1Result<()>,
    {
        let start_height = self.catch_up_start_height()?;
        if start_height >= tip_height {
            self.state = SyncState::Synced;
            return Ok(0);
        }

        let mut next_height = start_height.checked_add(1).ok_or_else(|| {
            PokerL1Error::Other("cannot advance Fast Sync height beyond u64::MAX".to_string())
        })?;
        let mut caught_up = 0u64;

        while next_height <= tip_height {
            let end_height = next_height
                .saturating_add(MAX_BLOCKS_PER_SYNC_REQUEST - 1)
                .min(tip_height);
            let expected_count = usize::try_from(end_height - next_height + 1).map_err(|_| {
                PokerL1Error::Other("Fast Sync block range does not fit usize".to_string())
            })?;
            let blocks = match transport.request_blocks_by_range(next_height, end_height) {
                Ok(blocks) => blocks,
                Err(error) => return self.fail_catch_up(error),
            };
            if blocks.len() != expected_count {
                return self.fail_catch_up(PokerL1Error::Other(format!(
                    "Fast Sync peer returned {} blocks for requested inclusive range {next_height}..={end_height} (expected {expected_count})",
                    blocks.len()
                )));
            }

            for (offset, block) in blocks.iter().enumerate() {
                let expected_height = next_height + offset as BlockHeight;
                if block.header.height != expected_height {
                    return self.fail_catch_up(PokerL1Error::Other(format!(
                        "Fast Sync peer returned block height {} at position {offset}; expected {expected_height}",
                        block.header.height
                    )));
                }
                if let Err(error) = apply_block(block) {
                    return self.fail_catch_up(error);
                }
                caught_up += 1;
                self.state = SyncState::CatchingUpBlocks {
                    current_height: expected_height,
                    tip_height,
                };
            }

            if end_height == tip_height {
                break;
            }
            next_height = end_height.checked_add(1).ok_or_else(|| {
                PokerL1Error::Other("cannot advance Fast Sync height beyond u64::MAX".to_string())
            })?;
        }

        self.state = SyncState::Synced;
        Ok(caught_up)
    }

    /// Retained for callers already at the snapshot tip.
    ///
    /// A local [`BlockStore`] scan cannot validate or execute downloaded blocks. When a peer tip
    /// is ahead of the snapshot, use [`Self::catch_up_blocks_from_network`] instead.
    #[deprecated(
        note = "use catch_up_blocks_from_network with a Node::put_block execution callback"
    )]
    pub fn catch_up_blocks(&mut self, tip_height: BlockHeight) -> PokerL1Result<u64> {
        let start_height = self.catch_up_start_height()?;

        if start_height >= tip_height {
            self.state = SyncState::Synced;
            return Ok(0);
        }

        self.fail_catch_up(PokerL1Error::Other(
            "cannot catch up from a local BlockStore scan; a network transport and full block execution callback are required".to_string(),
        ))
    }

    fn catch_up_start_height(&mut self) -> PokerL1Result<BlockHeight> {
        match &self.state {
            SyncState::CatchingUpBlocks { current_height, .. } => Ok(*current_height),
            _ => {
                self.state = SyncState::Failed("not in catching-up state".to_string());
                Err(PokerL1Error::Other(
                    "catch_up_blocks called before apply_snapshot".to_string(),
                ))
            }
        }
    }

    fn fail_catch_up<T>(&mut self, error: PokerL1Error) -> PokerL1Result<T> {
        self.state = SyncState::Failed(error.to_string());
        Err(error)
    }
}

/// Fast-sync coordinator for the complete consensus state.
///
/// [`FastSync`] remains available for historical object-only snapshots, but new production
/// callers must use this type.  It rejects manifests which are not anchored to the exact same
/// finalized header and it never applies either half until every object and account chunk has
/// passed authentication and root reconstruction.
///
/// The final two durable writes still use the stores' independent write batches.  A durable
/// cross-store journal is intentionally handled by the node storage transaction layer; this
/// coordinator nevertheless performs both validation stages first and restores the account half
/// on an ordinary ObjectDb write error so an in-process failure does not leave a partial sync.
pub struct FullFastSync<'a> {
    block_store: &'a BlockStore,
    object_db: &'a mut ObjectDb,
    account_store: &'a mut AccountStore,
    bridge_store: Option<&'a BridgeRegistryStore>,
    state: SyncState,
    received_object_chunks: Vec<SnapshotChunk>,
    received_account_chunks: Vec<AccountSnapshotChunk>,
    received_bridge_chunks: Vec<BridgeSnapshotChunk>,
}

impl<'a> FullFastSync<'a> {
    /// Create a coordinator for an initially empty ObjectDb and AccountStore.
    pub fn new(
        block_store: &'a BlockStore,
        object_db: &'a mut ObjectDb,
        account_store: &'a mut AccountStore,
    ) -> Self {
        Self {
            block_store,
            object_db,
            account_store,
            bridge_store: None,
            state: SyncState::Idle,
            received_object_chunks: Vec::new(),
            received_account_chunks: Vec::new(),
            received_bridge_chunks: Vec::new(),
        }
    }

    /// Create a coordinator that restores all three consensus stores for a bridge-enabled node.
    pub fn new_with_bridge(
        block_store: &'a BlockStore,
        object_db: &'a mut ObjectDb,
        account_store: &'a mut AccountStore,
        bridge_store: &'a BridgeRegistryStore,
    ) -> Self {
        Self {
            block_store,
            object_db,
            account_store,
            bridge_store: Some(bridge_store),
            state: SyncState::Idle,
            received_object_chunks: Vec::new(),
            received_account_chunks: Vec::new(),
            received_bridge_chunks: Vec::new(),
        }
    }

    /// Return the current full-sync state.
    #[must_use]
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    /// Authenticate both manifests and prove they describe the same finalized block.
    pub fn verify_manifests(
        &mut self,
        object_manifest: &SnapshotManifest,
        account_manifest: &AccountSnapshotManifest,
    ) -> PokerL1Result<()> {
        self.state = SyncState::VerifyingManifest;
        if let Err(error) = verify_full_snapshot_pair(object_manifest, account_manifest) {
            self.state = SyncState::Failed(error.to_string());
            return Err(error);
        }
        if let Err(error) =
            SnapshotVerifier::verify_manifest_against_block(object_manifest, self.block_store)
        {
            self.state = SyncState::Failed(error.to_string());
            return Err(error);
        }
        if let Err(error) = SnapshotVerifier::verify_account_manifest_against_block(
            account_manifest,
            self.block_store,
        ) {
            self.state = SyncState::Failed(error.to_string());
            return Err(error);
        }
        self.state = SyncState::DownloadingChunks {
            downloaded: 0,
            total: object_manifest
                .chunk_count
                .saturating_add(account_manifest.chunk_count),
        };
        Ok(())
    }

    /// Authenticate an ObjectDb, AccountStore and bridge archive manifest triplet.
    pub fn verify_manifests_with_bridge(
        &mut self,
        object_manifest: &SnapshotManifest,
        account_manifest: &AccountSnapshotManifest,
        bridge_manifest: &BridgeSnapshotManifest,
    ) -> PokerL1Result<()> {
        self.state = SyncState::VerifyingManifest;
        if self.bridge_store.is_none() {
            return self.fail(PokerL1Error::Other(
                "bridge manifest supplied to a FullFastSync without bridge storage".to_string(),
            ));
        }
        if let Err(error) =
            verify_full_snapshot_triplet(object_manifest, account_manifest, bridge_manifest)
                .and(SnapshotVerifier::verify_manifest_against_block(
                    object_manifest,
                    self.block_store,
                ))
                .and(SnapshotVerifier::verify_account_manifest_against_block(
                    account_manifest,
                    self.block_store,
                ))
                .and(SnapshotVerifier::verify_bridge_manifest_against_block(
                    bridge_manifest,
                    self.block_store,
                ))
        {
            return self.fail(error);
        }
        self.state = SyncState::DownloadingChunks {
            downloaded: 0,
            total: object_manifest
                .chunk_count
                .saturating_add(account_manifest.chunk_count)
                .saturating_add(bridge_manifest.chunk_count),
        };
        Ok(())
    }

    /// Authenticate and retain one ObjectDb chunk. Duplicate indices are idempotent.
    pub fn receive_object_chunk(
        &mut self,
        chunk: SnapshotChunk,
        object_manifest: &SnapshotManifest,
        account_manifest: &AccountSnapshotManifest,
    ) -> PokerL1Result<()> {
        if let Err(error) = verify_full_snapshot_pair(object_manifest, account_manifest)
            .and(SnapshotVerifier::verify_chunk(&chunk, object_manifest))
        {
            return self.fail(error);
        }
        if self
            .received_object_chunks
            .iter()
            .any(|known| known.index == chunk.index)
        {
            return Ok(());
        }
        self.received_object_chunks.push(chunk);
        self.record_downloaded_chunk();
        Ok(())
    }

    /// Authenticate and retain one AccountStore chunk. Duplicate indices are idempotent.
    pub fn receive_account_chunk(
        &mut self,
        chunk: AccountSnapshotChunk,
        object_manifest: &SnapshotManifest,
        account_manifest: &AccountSnapshotManifest,
    ) -> PokerL1Result<()> {
        if let Err(error) = verify_full_snapshot_pair(object_manifest, account_manifest).and(
            SnapshotVerifier::verify_account_chunk(&chunk, account_manifest),
        ) {
            return self.fail(error);
        }
        if self
            .received_account_chunks
            .iter()
            .any(|known| known.index == chunk.index)
        {
            return Ok(());
        }
        self.received_account_chunks.push(chunk);
        self.record_downloaded_chunk();
        Ok(())
    }

    /// Authenticate and retain one bridge nonce archive chunk. Duplicate indices are idempotent.
    pub fn receive_bridge_chunk(
        &mut self,
        chunk: BridgeSnapshotChunk,
        object_manifest: &SnapshotManifest,
        account_manifest: &AccountSnapshotManifest,
        bridge_manifest: &BridgeSnapshotManifest,
    ) -> PokerL1Result<()> {
        if let Err(error) =
            verify_full_snapshot_triplet(object_manifest, account_manifest, bridge_manifest).and(
                SnapshotVerifier::verify_bridge_chunk(&chunk, bridge_manifest),
            )
        {
            return self.fail(error);
        }
        if self
            .received_bridge_chunks
            .iter()
            .any(|known| known.index == chunk.index)
        {
            return Ok(());
        }
        self.received_bridge_chunks.push(chunk);
        self.record_downloaded_chunk();
        Ok(())
    }

    /// Download, authenticate, and install the latest complete snapshot advertised by a peer.
    ///
    /// The caller must already have the finalized header named by the manifest in `block_store`.
    /// Header/certificate synchronization is intentionally separate: accepting a peer-supplied
    /// snapshot header before consensus authentication would defeat the manifest root checks.
    /// Post-snapshot blocks can then be replayed through
    /// [`Self::catch_up_blocks_from_network`].
    pub fn download_snapshot_from_network(
        &mut self,
        transport: &dyn NetworkTransport,
    ) -> PokerL1Result<FullSnapshotManifest> {
        let manifest = transport
            .request_full_snapshot_manifest()?
            .ok_or_else(|| PokerL1Error::Other("no peer serves a full snapshot".to_string()))?;
        manifest.validate()?;

        match (&self.bridge_store, &manifest.bridge_manifest) {
            (Some(_), Some(bridge_manifest)) => {
                self.verify_manifests_with_bridge(
                    &manifest.object_manifest,
                    &manifest.account_manifest,
                    bridge_manifest,
                )?;
                self.download_object_and_account_chunks(transport, &manifest)?;
                for index in 0..bridge_manifest.chunk_count {
                    let chunk = transport
                        .request_bridge_snapshot_chunk(manifest.block_hash(), index)?
                        .ok_or_else(|| {
                            PokerL1Error::Other(format!(
                                "peer omitted bridge snapshot chunk {index}"
                            ))
                        })?;
                    self.receive_bridge_chunk(
                        chunk,
                        &manifest.object_manifest,
                        &manifest.account_manifest,
                        bridge_manifest,
                    )?;
                }
                self.apply_snapshot_with_bridge(
                    &manifest.object_manifest,
                    &manifest.account_manifest,
                    bridge_manifest,
                )?;
            }
            (Some(_), None) => {
                return self.fail(PokerL1Error::Other(
                    "bridge-enabled node refuses a snapshot without its replay archive".to_string(),
                ));
            }
            (None, Some(_)) => {
                return self.fail(PokerL1Error::Other(
                    "bridge snapshot received by a node without bridge storage".to_string(),
                ));
            }
            (None, None) => {
                self.verify_manifests(&manifest.object_manifest, &manifest.account_manifest)?;
                self.download_object_and_account_chunks(transport, &manifest)?;
                self.apply_snapshot(&manifest.object_manifest, &manifest.account_manifest)?;
            }
        }
        Ok(manifest)
    }

    fn download_object_and_account_chunks(
        &mut self,
        transport: &dyn NetworkTransport,
        manifest: &FullSnapshotManifest,
    ) -> PokerL1Result<()> {
        for index in 0..manifest.object_manifest.chunk_count {
            let chunk = transport
                .request_object_snapshot_chunk(manifest.block_hash(), index)?
                .ok_or_else(|| {
                    PokerL1Error::Other(format!("peer omitted object snapshot chunk {index}"))
                })?;
            self.receive_object_chunk(
                chunk,
                &manifest.object_manifest,
                &manifest.account_manifest,
            )?;
        }
        for index in 0..manifest.account_manifest.chunk_count {
            let chunk = transport
                .request_account_snapshot_chunk(manifest.block_hash(), index)?
                .ok_or_else(|| {
                    PokerL1Error::Other(format!("peer omitted account snapshot chunk {index}"))
                })?;
            self.receive_account_chunk(
                chunk,
                &manifest.object_manifest,
                &manifest.account_manifest,
            )?;
        }
        Ok(())
    }

    /// Apply both authenticated halves after staging their roots in isolation.
    pub fn apply_snapshot(
        &mut self,
        object_manifest: &SnapshotManifest,
        account_manifest: &AccountSnapshotManifest,
    ) -> PokerL1Result<()> {
        if let Err(error) = verify_full_snapshot_pair(object_manifest, account_manifest) {
            self.state = SyncState::Failed(error.to_string());
            return Err(error);
        }
        if self.received_object_chunks.len() as u64 != object_manifest.chunk_count
            || self.received_account_chunks.len() as u64 != account_manifest.chunk_count
        {
            let error = PokerL1Error::Other(format!(
                "incomplete full snapshot: objects {}/{}, accounts {}/{}",
                self.received_object_chunks.len(),
                object_manifest.chunk_count,
                self.received_account_chunks.len(),
                account_manifest.chunk_count
            ));
            self.state = SyncState::Failed(error.to_string());
            return Err(error);
        }

        self.state = SyncState::ApplyingChunks {
            applied: 0,
            total: object_manifest
                .object_count
                .saturating_add(account_manifest.account_count),
        };
        let object_candidate = match SnapshotApplier::stage_object_chunks(
            self.object_db,
            &self.received_object_chunks,
            object_manifest,
        ) {
            Ok(candidate) => candidate,
            Err(error) => return self.fail(error),
        };
        let account_candidate = match SnapshotApplier::stage_account_chunks(
            self.account_store,
            &self.received_account_chunks,
            account_manifest,
        ) {
            Ok(candidate) => candidate,
            Err(error) => return self.fail(error),
        };

        // Both roots are now proven before any durable mutation.  Retain the old account image
        // for an ordinary ObjectDb commit failure; crash recovery across the two DB handles is
        // supplied by the node-level journal added by the storage transaction work.
        let account_before = self.account_store.create_snapshot();
        if let Err(error) = self.account_store.apply_snapshot(account_candidate) {
            return self.fail(error);
        }
        if let Err(error) = object_candidate.apply_to(self.object_db) {
            if let Err(rollback_error) = self.account_store.apply_snapshot(account_before) {
                tracing::error!(
                    "full snapshot ObjectDb commit failed and account rollback also failed: {rollback_error}"
                );
            }
            return self.fail(error);
        }
        self.state = SyncState::CatchingUpBlocks {
            current_height: object_manifest.height,
            tip_height: self
                .block_store
                .get_tip_height()?
                .unwrap_or(object_manifest.height),
        };
        Ok(())
    }

    /// Stage and atomically-as-possible install a complete bridge-enabled snapshot.
    ///
    /// All three candidate states are authenticated before any live store changes. A destination
    /// bridge store must be empty, matching the empty ObjectDb/AccountStore requirement. Ordinary
    /// write failures restore the previously empty bridge/account states; crash recovery remains
    /// fail-closed because ObjectDb's replay commitment will not match a missing archive.
    pub fn apply_snapshot_with_bridge(
        &mut self,
        object_manifest: &SnapshotManifest,
        account_manifest: &AccountSnapshotManifest,
        bridge_manifest: &BridgeSnapshotManifest,
    ) -> PokerL1Result<()> {
        let Some(bridge_store) = self.bridge_store else {
            return self.fail(PokerL1Error::Other(
                "bridge snapshot supplied to a FullFastSync without bridge storage".to_string(),
            ));
        };
        if let Err(error) =
            verify_full_snapshot_triplet(object_manifest, account_manifest, bridge_manifest)
        {
            return self.fail(error);
        }
        if self.received_object_chunks.len() as u64 != object_manifest.chunk_count
            || self.received_account_chunks.len() as u64 != account_manifest.chunk_count
            || self.received_bridge_chunks.len() as u64 != bridge_manifest.chunk_count
        {
            return self.fail(PokerL1Error::Other(format!(
                "incomplete bridge full snapshot: objects {}/{}, accounts {}/{}, bridge {}/{}",
                self.received_object_chunks.len(),
                object_manifest.chunk_count,
                self.received_account_chunks.len(),
                account_manifest.chunk_count,
                self.received_bridge_chunks.len(),
                bridge_manifest.chunk_count,
            )));
        }
        let bridge_before = bridge_store.nonce_snapshot();
        if !bridge_before.deposit_nonces.is_empty() || !bridge_before.burn_nonces.is_empty() {
            return self.fail(PokerL1Error::Other(
                "bridge snapshot application requires an empty BridgeRegistryStore".to_string(),
            ));
        }
        self.state = SyncState::ApplyingChunks {
            applied: 0,
            total: object_manifest
                .object_count
                .saturating_add(account_manifest.account_count)
                .saturating_add(bridge_manifest.nonce_count),
        };
        let object_candidate = match SnapshotApplier::stage_object_chunks(
            self.object_db,
            &self.received_object_chunks,
            object_manifest,
        ) {
            Ok(candidate) => candidate,
            Err(error) => return self.fail(error),
        };
        let account_candidate = match SnapshotApplier::stage_account_chunks(
            self.account_store,
            &self.received_account_chunks,
            account_manifest,
        ) {
            Ok(candidate) => candidate,
            Err(error) => return self.fail(error),
        };
        let bridge_candidate = match SnapshotApplier::stage_bridge_chunks(
            &object_candidate,
            &self.received_bridge_chunks,
            bridge_manifest,
        ) {
            Ok(candidate) => candidate,
            Err(error) => return self.fail(error),
        };
        let account_before = self.account_store.create_snapshot();
        if let Err(error) = bridge_store.replace_nonce_snapshot_durable(bridge_candidate) {
            return self.fail(error);
        }
        if let Err(error) = self.account_store.apply_snapshot(account_candidate) {
            let _ = bridge_store.replace_nonce_snapshot_durable(bridge_before);
            return self.fail(error);
        }
        if let Err(error) = object_candidate.apply_to(self.object_db) {
            let _ = self.account_store.apply_snapshot(account_before);
            let _ = bridge_store.replace_nonce_snapshot_durable(bridge_before);
            return self.fail(error);
        }
        self.state = SyncState::CatchingUpBlocks {
            current_height: object_manifest.height,
            tip_height: self
                .block_store
                .get_tip_height()?
                .unwrap_or(object_manifest.height),
        };
        Ok(())
    }

    /// Download and execute every post-snapshot block through the supplied full validation path.
    pub fn catch_up_blocks_from_network<F>(
        &mut self,
        transport: &dyn NetworkTransport,
        tip_height: BlockHeight,
        mut apply_block: F,
    ) -> PokerL1Result<u64>
    where
        F: FnMut(&Block) -> PokerL1Result<()>,
    {
        let start_height = match self.state {
            SyncState::CatchingUpBlocks { current_height, .. } => current_height,
            _ => {
                return self.fail(PokerL1Error::Other(
                    "catch_up_blocks called before applying a full snapshot".to_string(),
                ));
            }
        };
        if start_height >= tip_height {
            self.state = SyncState::Synced;
            return Ok(0);
        }
        let mut next_height = start_height.checked_add(1).ok_or_else(|| {
            PokerL1Error::Other("cannot advance FullFastSync height beyond u64::MAX".to_string())
        })?;
        let mut caught_up = 0u64;
        while next_height <= tip_height {
            let end_height = next_height
                .saturating_add(MAX_BLOCKS_PER_SYNC_REQUEST - 1)
                .min(tip_height);
            let expected_count = usize::try_from(end_height - next_height + 1).map_err(|_| {
                PokerL1Error::Other("FullFastSync block range does not fit usize".to_string())
            })?;
            let blocks = match transport.request_blocks_by_range(next_height, end_height) {
                Ok(blocks) => blocks,
                Err(error) => return self.fail(error),
            };
            if blocks.len() != expected_count {
                return self.fail(PokerL1Error::Other(format!(
                    "FullFastSync peer returned {} blocks for {next_height}..={end_height} (expected {expected_count})",
                    blocks.len()
                )));
            }
            for (offset, block) in blocks.iter().enumerate() {
                let expected_height = next_height + offset as BlockHeight;
                if block.header.height != expected_height {
                    return self.fail(PokerL1Error::Other(format!(
                        "FullFastSync peer returned block height {} at position {offset}; expected {expected_height}",
                        block.header.height
                    )));
                }
                if let Err(error) = apply_block(block) {
                    return self.fail(error);
                }
                caught_up += 1;
                self.state = SyncState::CatchingUpBlocks {
                    current_height: expected_height,
                    tip_height,
                };
            }
            next_height = match end_height.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }
        self.state = SyncState::Synced;
        Ok(caught_up)
    }

    fn record_downloaded_chunk(&mut self) {
        if let SyncState::DownloadingChunks { downloaded, total } = &self.state {
            self.state = SyncState::DownloadingChunks {
                downloaded: downloaded.saturating_add(1),
                total: *total,
            };
        }
    }

    fn fail<T>(&mut self, error: PokerL1Error) -> PokerL1Result<T> {
        self.state = SyncState::Failed(error.to_string());
        Err(error)
    }
}

/// Reject two independently valid manifests unless they are one exact consensus snapshot.
fn verify_full_snapshot_pair(
    object_manifest: &SnapshotManifest,
    account_manifest: &AccountSnapshotManifest,
) -> PokerL1Result<()> {
    if !object_manifest.validate() || !account_manifest.validate() {
        return Err(PokerL1Error::Other(
            "invalid full snapshot manifest".to_string(),
        ));
    }
    if object_manifest.height != account_manifest.height
        || object_manifest.block_hash != account_manifest.block_hash
        || object_manifest.timestamp_ms != account_manifest.timestamp_ms
    {
        return Err(PokerL1Error::Other(
            "object and account snapshot manifests bind different blocks".to_string(),
        ));
    }
    Ok(())
}

/// Reject a bridge archive unless all three manifests bind one exact finalized state.
fn verify_full_snapshot_triplet(
    object_manifest: &SnapshotManifest,
    account_manifest: &AccountSnapshotManifest,
    bridge_manifest: &BridgeSnapshotManifest,
) -> PokerL1Result<()> {
    verify_full_snapshot_pair(object_manifest, account_manifest)?;
    if !bridge_manifest.validate()
        || object_manifest.height != bridge_manifest.height
        || object_manifest.block_hash != bridge_manifest.block_hash
        || object_manifest.timestamp_ms != bridge_manifest.timestamp_ms
    {
        return Err(PokerL1Error::Other(
            "object, account and bridge snapshot manifests do not bind one block".to_string(),
        ));
    }
    Ok(())
}

// ===== 辅助函数 =====

/// 计算 `blake2b_256(data)`。
fn hash_bytes(data: &[u8]) -> Hash {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 将字节转为 hex 字符串（用于错误信息）。
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ===== 测试 =====

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockHeader;
    use crate::network::InMemoryTransport;
    use crate::object_model::{Object, ObjectID, Ownership};
    use crate::signature::TaggedPubkey;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::storage::{BlockStore, ObjectDb};

    /// 构造测试用 DagCommitCertificate（最小有效结构）。
    fn dummy_commit_cert() -> crate::consensus::DagCommitCertificate {
        crate::consensus::DagCommitCertificate {
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
    fn make_block_header(height: BlockHeight, state_root: Hash) -> BlockHeader {
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

    /// 构造测试用 Object（5 参数版本）。
    /// `object_type` 为 String（`ObjectType = String`）。
    fn make_object(id_byte: u8, version: u32) -> Object {
        Object::new(
            ObjectID::new([id_byte; 20], version as u64),
            Ownership::AddressOwned {
                owner: [id_byte; 20],
            },
            "test_object".to_string(),
            b"data".to_vec(),
            None,
        )
    }

    /// 构造填充了 N 个对象的 ObjectDb。
    /// 使用 (id_byte, version) 组合确保 ObjectID 唯一。
    fn make_object_db(count: usize) -> ObjectDb {
        let mut db = ObjectDb::open_inmemory().unwrap();
        let objects = (0..count)
            .map(|i| {
                let id_byte = ((i % 200) as u8) + 1;
                make_object(id_byte, i as u32)
            })
            .collect();
        db.create_batch(objects).unwrap();
        db
    }

    fn make_account(byte: u8, balance: u64) -> Account {
        Account::new(
            TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![byte; 33],
            },
            balance,
        )
    }

    #[test]
    fn test_manifest_validate() {
        let manifest = SnapshotManifest {
            height: 100,
            block_hash: [0u8; 32],
            state_root: [0u8; 32],
            object_count: 10,
            chunk_count: 2,
            chunk_hashes: vec![[0u8; 32], [1u8; 32]],
            timestamp_ms: 1000,
        };
        assert!(manifest.validate());

        // chunk_count 与 chunk_hashes.len() 不一致
        let bad_manifest = SnapshotManifest {
            chunk_count: 3,
            chunk_hashes: vec![[0u8; 32], [1u8; 32]],
            ..manifest.clone()
        };
        assert!(!bad_manifest.validate());

        // object_count = 0 无效
        let empty_manifest = SnapshotManifest {
            object_count: 0,
            ..manifest.clone()
        };
        assert!(!empty_manifest.validate());
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let manifest = SnapshotManifest {
            height: 100,
            block_hash: [0u8; 32],
            state_root: [1u8; 32],
            object_count: 10,
            chunk_count: 2,
            chunk_hashes: vec![[0u8; 32], [1u8; 32]],
            timestamp_ms: 1000,
        };
        let h1 = manifest.manifest_hash();
        let h2 = manifest.manifest_hash();
        assert_eq!(h1, h2, "manifest_hash 应确定性");

        // 不同 manifest 应产生不同 hash
        let manifest2 = SnapshotManifest {
            height: 101,
            ..manifest.clone()
        };
        let h3 = manifest2.manifest_hash();
        assert_ne!(h1, h3, "不同 manifest 应有不同 hash");
    }

    #[test]
    fn test_build_snapshot_small() {
        let db = make_object_db(5);
        let state_root = db.state_root();
        let header = make_block_header(100, state_root);

        let (manifest, chunks) =
            SnapshotBuilder::build_snapshot(&db, &header, crate::DEFAULT_CHAIN_ID).unwrap();

        assert_eq!(manifest.height, 100);
        assert_eq!(manifest.state_root, state_root);
        assert_eq!(manifest.object_count, 5);
        assert_eq!(manifest.chunk_count, chunks.len() as u64);
        assert_eq!(manifest.chunk_hashes.len(), chunks.len());

        // 每个分块的哈希应与 manifest 中一致
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.chunk_hash(), manifest.chunk_hashes[i]);
            assert_eq!(chunk.index, i as u64);
        }
    }

    #[test]
    fn full_snapshot_roundtrip_restores_account_commitment() {
        let src_objects = make_object_db(3);
        let mut src_accounts = AccountStore::new();
        let first = make_account(0x11, 10);
        let first_address = first.address;
        src_accounts.create(first).unwrap();
        src_accounts.create(make_account(0x22, 20)).unwrap();
        src_accounts.credit(&first_address, 5).unwrap();
        src_accounts
            .get_mut(&first_address)
            .unwrap()
            .increment_nonce();

        let mut header = make_block_header(42, src_objects.state_root());
        header.account_root = src_accounts.state_root();
        let full = SnapshotBuilder::build_full_snapshot(
            &src_objects,
            &src_accounts,
            &header,
            crate::DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(full.account_manifest.account_count, 2);
        assert_eq!(
            full.account_manifest.account_root,
            src_accounts.state_root()
        );
        for chunk in &full.account_chunks {
            SnapshotVerifier::verify_account_chunk(chunk, &full.account_manifest).unwrap();
        }

        let mut dst_objects = ObjectDb::open_inmemory().unwrap();
        let mut dst_accounts = AccountStore::new();
        SnapshotApplier::apply_chunks(&mut dst_objects, &full.object_chunks, &full.object_manifest)
            .unwrap();
        SnapshotApplier::apply_account_chunks(
            &mut dst_accounts,
            &full.account_chunks,
            &full.account_manifest,
        )
        .unwrap();
        assert_eq!(dst_objects.state_root(), src_objects.state_root());
        assert_eq!(dst_accounts.state_root(), src_accounts.state_root());
        assert_eq!(dst_accounts.get(&first_address).unwrap().nonce, 1);
        assert_eq!(dst_accounts.get(&first_address).unwrap().balance, 15);
    }

    #[test]
    fn full_fast_sync_restores_objects_and_accounts_from_one_header() {
        let src_objects = make_object_db(3);
        let mut src_accounts = AccountStore::new();
        let account = make_account(0x31, 70);
        let address = account.address;
        src_accounts.create(account).unwrap();
        src_accounts.get_mut(&address).unwrap().increment_nonce();

        let mut header = make_block_header(42, src_objects.state_root());
        header.account_root = src_accounts.state_root();
        let full = SnapshotBuilder::build_full_snapshot(
            &src_objects,
            &src_accounts,
            &header,
            crate::DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let block_store = BlockStore::open_inmemory().unwrap();
        block_store
            .put(
                &Block {
                    header,
                    public_txs: vec![],
                    gameturn_txs: vec![],
                },
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();

        let mut dst_objects = ObjectDb::open_inmemory().unwrap();
        let mut dst_accounts = AccountStore::new();
        let mut sync = FullFastSync::new(&block_store, &mut dst_objects, &mut dst_accounts);
        sync.verify_manifests(&full.object_manifest, &full.account_manifest)
            .unwrap();
        for chunk in full.object_chunks.clone() {
            sync.receive_object_chunk(chunk, &full.object_manifest, &full.account_manifest)
                .unwrap();
        }
        for chunk in full.account_chunks.clone() {
            sync.receive_account_chunk(chunk, &full.object_manifest, &full.account_manifest)
                .unwrap();
        }
        sync.apply_snapshot(&full.object_manifest, &full.account_manifest)
            .unwrap();
        assert!(matches!(sync.state(), SyncState::CatchingUpBlocks { .. }));
        drop(sync);

        assert_eq!(dst_objects.state_root(), src_objects.state_root());
        assert_eq!(dst_accounts.state_root(), src_accounts.state_root());
        assert_eq!(dst_accounts.get(&address).unwrap().nonce, 1);
    }

    #[test]
    fn full_fast_sync_downloads_manifest_and_chunks_over_network_transport() {
        let src_objects = make_object_db(3);
        let mut src_accounts = AccountStore::new();
        let account = make_account(0x41, 90);
        let address = account.address;
        src_accounts.create(account).unwrap();
        src_accounts.get_mut(&address).unwrap().increment_nonce();

        let mut header = make_block_header(43, src_objects.state_root());
        header.account_root = src_accounts.state_root();
        let full = SnapshotBuilder::build_full_snapshot(
            &src_objects,
            &src_accounts,
            &header,
            crate::DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let transport = InMemoryTransport::new();
        transport.inject_full_snapshot(full).unwrap();

        // The header is independently available from consensus/header sync before state sync.
        let block_store = BlockStore::open_inmemory().unwrap();
        block_store
            .put(
                &Block {
                    header,
                    public_txs: vec![],
                    gameturn_txs: vec![],
                },
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();
        let mut dst_objects = ObjectDb::open_inmemory().unwrap();
        let mut dst_accounts = AccountStore::new();
        let mut sync = FullFastSync::new(&block_store, &mut dst_objects, &mut dst_accounts);
        let manifest = sync.download_snapshot_from_network(&transport).unwrap();
        assert_eq!(manifest.object_manifest.height, 43);
        assert!(matches!(sync.state(), SyncState::CatchingUpBlocks { .. }));
        drop(sync);

        assert_eq!(dst_objects.state_root(), src_objects.state_root());
        assert_eq!(dst_accounts.state_root(), src_accounts.state_root());
        assert_eq!(dst_accounts.get(&address).unwrap().nonce, 1);
    }

    #[test]
    fn bridge_full_fast_sync_restores_authenticated_nonce_archive() {
        let mut src_objects = make_object_db(2);
        let mut src_accounts = AccountStore::new();
        src_accounts.create(make_account(0x51, 9)).unwrap();
        let src_bridge = BridgeRegistryStore::open_inmemory().unwrap();
        src_bridge.persist_deposit_nonce(0xAAAA, 1).unwrap();
        src_bridge.persist_deposit_nonce(0xBBBB, 2).unwrap();
        src_bridge
            .persist_burn_nonce(crate::DEFAULT_CHAIN_ID, 3)
            .unwrap();
        let (nonce_root, deposit_nonce_count, burn_nonce_count) = src_bridge.replay_commitment();
        let mut object_snapshot = src_objects.create_snapshot();
        object_snapshot
            .system_create(
                crate::bridge::bridge_replay_state_object(
                    &crate::bridge::BridgeReplayState {
                        chain_id: crate::DEFAULT_CHAIN_ID,
                        nonce_root,
                        deposit_nonce_count,
                        burn_nonce_count,
                    },
                    0,
                )
                .unwrap(),
            )
            .unwrap();
        object_snapshot.apply_to(&mut src_objects).unwrap();

        let mut header = make_block_header(42, src_objects.state_root());
        header.account_root = src_accounts.state_root();
        let full = SnapshotBuilder::build_full_snapshot_with_bridge(
            &src_objects,
            &src_accounts,
            &src_bridge,
            &header,
            crate::DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let bridge_manifest = full.bridge_manifest.clone().expect("bridge manifest");
        assert_eq!(bridge_manifest.nonce_count, 3);

        let block_store = BlockStore::open_inmemory().unwrap();
        block_store
            .put(
                &Block {
                    header,
                    public_txs: vec![],
                    gameturn_txs: vec![],
                },
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();
        let mut dst_objects = ObjectDb::open_inmemory().unwrap();
        let mut dst_accounts = AccountStore::new();
        let dst_bridge = BridgeRegistryStore::open_inmemory().unwrap();
        let mut sync = FullFastSync::new_with_bridge(
            &block_store,
            &mut dst_objects,
            &mut dst_accounts,
            &dst_bridge,
        );
        sync.verify_manifests_with_bridge(
            &full.object_manifest,
            &full.account_manifest,
            &bridge_manifest,
        )
        .unwrap();
        for chunk in full.object_chunks.clone() {
            sync.receive_object_chunk(chunk, &full.object_manifest, &full.account_manifest)
                .unwrap();
        }
        for chunk in full.account_chunks.clone() {
            sync.receive_account_chunk(chunk, &full.object_manifest, &full.account_manifest)
                .unwrap();
        }
        for chunk in full.bridge_chunks.clone() {
            sync.receive_bridge_chunk(
                chunk,
                &full.object_manifest,
                &full.account_manifest,
                &bridge_manifest,
            )
            .unwrap();
        }
        sync.apply_snapshot_with_bridge(
            &full.object_manifest,
            &full.account_manifest,
            &bridge_manifest,
        )
        .unwrap();
        drop(sync);

        assert_eq!(dst_objects.state_root(), src_objects.state_root());
        assert_eq!(dst_accounts.state_root(), src_accounts.state_root());
        assert_eq!(dst_bridge.nonce_snapshot(), src_bridge.nonce_snapshot());
        assert_eq!(
            dst_bridge.replay_commitment(),
            src_bridge.replay_commitment()
        );
    }

    #[test]
    fn bridge_full_fast_sync_downloads_authenticated_archive_over_network_transport() {
        let mut src_objects = make_object_db(2);
        let mut src_accounts = AccountStore::new();
        src_accounts.create(make_account(0x61, 11)).unwrap();
        let src_bridge = BridgeRegistryStore::open_inmemory().unwrap();
        src_bridge.persist_deposit_nonce(0xDDDD, 7).unwrap();
        src_bridge
            .persist_burn_nonce(crate::DEFAULT_CHAIN_ID, 8)
            .unwrap();
        let (nonce_root, deposit_nonce_count, burn_nonce_count) = src_bridge.replay_commitment();
        let mut object_snapshot = src_objects.create_snapshot();
        object_snapshot
            .system_create(
                crate::bridge::bridge_replay_state_object(
                    &crate::bridge::BridgeReplayState {
                        chain_id: crate::DEFAULT_CHAIN_ID,
                        nonce_root,
                        deposit_nonce_count,
                        burn_nonce_count,
                    },
                    0,
                )
                .unwrap(),
            )
            .unwrap();
        object_snapshot.apply_to(&mut src_objects).unwrap();
        let mut header = make_block_header(44, src_objects.state_root());
        header.account_root = src_accounts.state_root();
        let full = SnapshotBuilder::build_full_snapshot_with_bridge(
            &src_objects,
            &src_accounts,
            &src_bridge,
            &header,
            crate::DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let transport = InMemoryTransport::new();
        transport.inject_full_snapshot(full).unwrap();

        let block_store = BlockStore::open_inmemory().unwrap();
        block_store
            .put(
                &Block {
                    header,
                    public_txs: vec![],
                    gameturn_txs: vec![],
                },
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();
        let mut dst_objects = ObjectDb::open_inmemory().unwrap();
        let mut dst_accounts = AccountStore::new();
        let dst_bridge = BridgeRegistryStore::open_inmemory().unwrap();
        let mut sync = FullFastSync::new_with_bridge(
            &block_store,
            &mut dst_objects,
            &mut dst_accounts,
            &dst_bridge,
        );
        sync.download_snapshot_from_network(&transport).unwrap();
        drop(sync);

        assert_eq!(dst_objects.state_root(), src_objects.state_root());
        assert_eq!(dst_accounts.state_root(), src_accounts.state_root());
        assert_eq!(dst_bridge.nonce_snapshot(), src_bridge.nonce_snapshot());
        assert_eq!(
            dst_bridge.replay_commitment(),
            src_bridge.replay_commitment()
        );
    }

    #[test]
    fn full_fast_sync_rejects_manifests_from_different_headers() {
        let objects = make_object_db(1);
        let mut accounts = AccountStore::new();
        accounts.create(make_account(0x44, 1)).unwrap();
        let mut header = make_block_header(7, objects.state_root());
        header.account_root = accounts.state_root();
        let mut full = SnapshotBuilder::build_full_snapshot(
            &objects,
            &accounts,
            &header,
            crate::DEFAULT_CHAIN_ID,
        )
        .unwrap();
        full.account_manifest.timestamp_ms = full.account_manifest.timestamp_ms.saturating_add(1);

        let block_store = BlockStore::open_inmemory().unwrap();
        let mut dst_objects = ObjectDb::open_inmemory().unwrap();
        let mut dst_accounts = AccountStore::new();
        let mut sync = FullFastSync::new(&block_store, &mut dst_objects, &mut dst_accounts);
        assert!(
            sync.verify_manifests(&full.object_manifest, &full.account_manifest)
                .is_err()
        );
        assert!(matches!(sync.state(), SyncState::Failed(_)));
    }

    #[test]
    fn snapshot_manifest_block_hash_uses_the_supplied_chain_id() {
        let db = make_object_db(1);
        let header = make_block_header(100, db.state_root());
        let non_default_chain_id = crate::DEFAULT_CHAIN_ID + 17;

        let (manifest, _) =
            SnapshotBuilder::build_snapshot(&db, &header, non_default_chain_id).unwrap();

        assert_eq!(manifest.block_hash, header.block_hash(non_default_chain_id));
        assert_ne!(
            manifest.block_hash,
            header.block_hash(crate::DEFAULT_CHAIN_ID),
            "snapshot manifests must not silently bind to DEFAULT_CHAIN_ID"
        );
    }

    #[test]
    fn test_build_snapshot_large() {
        // 构造足够多对象以触发分块
        let db = make_object_db(15_000);
        let state_root = db.state_root();
        let header = make_block_header(200, state_root);

        let (manifest, chunks) =
            SnapshotBuilder::build_snapshot(&db, &header, crate::DEFAULT_CHAIN_ID).unwrap();

        assert_eq!(manifest.object_count, 15_000);
        assert!(chunks.len() > 1, "15k 对象应跨多个分块");
        assert_eq!(manifest.chunk_count, chunks.len() as u64);

        // 每个分块（除最后一块）应达到 MAX_OBJECTS_PER_CHUNK 上限
        for chunk in &chunks[..chunks.len() - 1] {
            assert_eq!(chunk.objects.len(), MAX_OBJECTS_PER_CHUNK);
        }
    }

    #[test]
    fn test_build_snapshot_empty_db_errors() {
        let db = ObjectDb::open_inmemory().unwrap();
        let header = make_block_header(0, [0u8; 32]);
        let result = SnapshotBuilder::build_snapshot(&db, &header, crate::DEFAULT_CHAIN_ID);
        assert!(result.is_err(), "空 ObjectDb 不应生成快照");
    }

    #[test]
    fn test_verify_chunk_valid() {
        let db = make_object_db(3);
        let state_root = db.state_root();
        let header = make_block_header(50, state_root);

        let (manifest, chunks) =
            SnapshotBuilder::build_snapshot(&db, &header, crate::DEFAULT_CHAIN_ID).unwrap();

        for chunk in &chunks {
            SnapshotVerifier::verify_chunk(chunk, &manifest).unwrap();
        }
    }

    #[test]
    fn test_verify_chunk_hash_mismatch() {
        let db = make_object_db(3);
        let state_root = db.state_root();
        let header = make_block_header(50, state_root);

        let (mut manifest, mut chunks) =
            SnapshotBuilder::build_snapshot(&db, &header, crate::DEFAULT_CHAIN_ID).unwrap();

        // 篡改分块数据
        chunks[0].objects[0] = make_object(0xFE, 999);

        // 篡改后哈希应不匹配
        let result = SnapshotVerifier::verify_chunk(&chunks[0], &manifest);
        assert!(result.is_err(), "篡改的分块应验证失败");

        // 更新 manifest 哈希后应通过（模拟 Byzantine peer 同时篡改两者）
        manifest.chunk_hashes[0] = chunks[0].chunk_hash();
        SnapshotVerifier::verify_chunk(&chunks[0], &manifest).unwrap();
    }

    #[test]
    fn test_verify_chunk_index_out_of_range() {
        let db = make_object_db(3);
        let state_root = db.state_root();
        let header = make_block_header(50, state_root);

        let (manifest, _chunks) =
            SnapshotBuilder::build_snapshot(&db, &header, crate::DEFAULT_CHAIN_ID).unwrap();

        let bogus_chunk = SnapshotChunk {
            index: manifest.chunk_count + 100,
            objects: vec![make_object(0xAA, 1)],
        };
        let result = SnapshotVerifier::verify_chunk(&bogus_chunk, &manifest);
        assert!(result.is_err(), "越界索引应验证失败");
    }

    #[test]
    fn test_apply_snapshot_roundtrip() {
        // 1. 源库创建快照
        let src_db = make_object_db(20);
        let state_root = src_db.state_root();
        let header = make_block_header(100, state_root);
        let (manifest, chunks) =
            SnapshotBuilder::build_snapshot(&src_db, &header, crate::DEFAULT_CHAIN_ID).unwrap();

        // 2. 目标库应用快照
        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        SnapshotApplier::apply_chunks(&mut dst_db, &chunks, &manifest).unwrap();

        // 3. 验证 state_root 一致
        assert_eq!(
            dst_db.state_root(),
            src_db.state_root(),
            "应用快照后 state_root 应与源库一致"
        );
        assert_eq!(dst_db.len(), 20, "对象数应一致");
    }

    #[test]
    fn test_apply_snapshot_state_root_mismatch_detected() {
        let src_db = make_object_db(10);
        let header = make_block_header(100, src_db.state_root());
        let (mut manifest, chunks) =
            SnapshotBuilder::build_snapshot(&src_db, &header, crate::DEFAULT_CHAIN_ID).unwrap();

        // 篡改 manifest 的 state_root（模拟 Byzantine peer 投毒）
        manifest.state_root = [0xFF; 32];

        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        let result = SnapshotApplier::apply_chunks(&mut dst_db, &chunks, &manifest);
        assert!(result.is_err(), "state_root 不匹配应被检测到");
        assert!(dst_db.is_empty(), "失败的快照不得留下部分对象");
    }

    #[test]
    fn test_apply_snapshot_object_count_mismatch() {
        let src_db = make_object_db(10);
        let header = make_block_header(100, src_db.state_root());
        let (mut manifest, mut chunks) =
            SnapshotBuilder::build_snapshot(&src_db, &header, crate::DEFAULT_CHAIN_ID).unwrap();

        // 移除一个对象，模拟分块不完整
        chunks[0].objects.pop();

        // 更新 chunk_hash 以绕过单块验证
        manifest.chunk_hashes[0] = chunks[0].chunk_hash();
        // 但 object_count 仍为原值
        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        let result = SnapshotApplier::apply_chunks(&mut dst_db, &chunks, &manifest);
        assert!(result.is_err(), "对象数不匹配应被检测到");
    }

    #[test]
    fn test_fast_sync_full_workflow() {
        // 1. 准备源库与 BlockStore
        let src_db = make_object_db(30);
        let state_root = src_db.state_root();
        let header = make_block_header(100, state_root);
        let (manifest, chunks) =
            SnapshotBuilder::build_snapshot(&src_db, &header, crate::DEFAULT_CHAIN_ID).unwrap();

        // 2. BlockStore 中放入对应区块（简化：用 inmemory）
        let block_store = BlockStore::open_inmemory().unwrap();
        let block = crate::block::Block {
            header: header.clone(),
            public_txs: vec![],
            gameturn_txs: vec![],
        };
        block_store.put(&block, crate::DEFAULT_CHAIN_ID).unwrap();

        // 3. 目标库通过 FastSync 同步
        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        let mut fast_sync = FastSync::new(&block_store, &mut dst_db);

        assert_eq!(fast_sync.state(), &SyncState::Idle);

        // 3a. 验证清单
        fast_sync.verify_manifest(&manifest).unwrap();
        assert!(matches!(
            fast_sync.state(),
            SyncState::DownloadingChunks { .. }
        ));

        // 3b. 接收所有分块
        for chunk in chunks {
            fast_sync.receive_chunk(chunk, &manifest).unwrap();
        }
        if let SyncState::DownloadingChunks { downloaded, total } = fast_sync.state() {
            assert_eq!(*downloaded, *total, "全部分块应已接收");
        }

        // 3c. 应用快照
        fast_sync.apply_snapshot(&manifest).unwrap();
        assert!(matches!(
            fast_sync.state(),
            SyncState::CatchingUpBlocks { .. }
        ));

        // 3d. 追赶区块（tip == snapshot height，无需追赶）
        let caught = fast_sync.catch_up_blocks(100).unwrap();
        assert_eq!(caught, 0);
        assert_eq!(fast_sync.state(), &SyncState::Synced);

        // 4. 最终 state_root 一致
        assert_eq!(dst_db.state_root(), state_root);
    }

    #[test]
    fn fast_sync_downloads_complete_ranges_and_executes_each_block() {
        let src_db = make_object_db(3);
        let header = make_block_header(100, src_db.state_root());
        let (manifest, chunks) =
            SnapshotBuilder::build_snapshot(&src_db, &header, crate::DEFAULT_CHAIN_ID).unwrap();
        let block_store = BlockStore::open_inmemory().unwrap();
        block_store
            .put(
                &Block {
                    header,
                    public_txs: vec![],
                    gameturn_txs: vec![],
                },
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();

        let transport = InMemoryTransport::new();
        for height in 101..=102 {
            transport.inject_block(Block {
                header: make_block_header(height, [0u8; 32]),
                public_txs: vec![],
                gameturn_txs: vec![],
            });
        }

        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        let mut fast_sync = FastSync::new(&block_store, &mut dst_db);
        fast_sync.verify_manifest(&manifest).unwrap();
        for chunk in chunks {
            fast_sync.receive_chunk(chunk, &manifest).unwrap();
        }
        fast_sync.apply_snapshot(&manifest).unwrap();

        let mut applied = Vec::new();
        let caught = fast_sync
            .catch_up_blocks_from_network(&transport, 102, |block| {
                applied.push(block.header.height);
                Ok(())
            })
            .unwrap();
        assert_eq!(caught, 2);
        assert_eq!(applied, vec![101, 102]);
        assert_eq!(fast_sync.state(), &SyncState::Synced);
    }

    #[test]
    fn fast_sync_rejects_an_incomplete_peer_block_range_before_execution() {
        let src_db = make_object_db(3);
        let header = make_block_header(100, src_db.state_root());
        let (manifest, chunks) =
            SnapshotBuilder::build_snapshot(&src_db, &header, crate::DEFAULT_CHAIN_ID).unwrap();
        let block_store = BlockStore::open_inmemory().unwrap();
        block_store
            .put(
                &Block {
                    header,
                    public_txs: vec![],
                    gameturn_txs: vec![],
                },
                crate::DEFAULT_CHAIN_ID,
            )
            .unwrap();

        let transport = InMemoryTransport::new();
        transport.inject_block(Block {
            header: make_block_header(101, [0u8; 32]),
            public_txs: vec![],
            gameturn_txs: vec![],
        });

        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        let mut fast_sync = FastSync::new(&block_store, &mut dst_db);
        fast_sync.verify_manifest(&manifest).unwrap();
        for chunk in chunks {
            fast_sync.receive_chunk(chunk, &manifest).unwrap();
        }
        fast_sync.apply_snapshot(&manifest).unwrap();

        let mut apply_count = 0;
        assert!(
            fast_sync
                .catch_up_blocks_from_network(&transport, 102, |_| {
                    apply_count += 1;
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(apply_count, 0);
        assert!(matches!(fast_sync.state(), SyncState::Failed(_)));
    }

    #[test]
    fn test_fast_sync_rejects_incomplete_chunks() {
        let src_db = make_object_db(5);
        let header = make_block_header(100, src_db.state_root());
        let (manifest, mut chunks) =
            SnapshotBuilder::build_snapshot(&src_db, &header, crate::DEFAULT_CHAIN_ID).unwrap();

        // 故意丢弃最后一个分块
        chunks.pop();

        let block_store = BlockStore::open_inmemory().unwrap();
        // 将区块放入 BlockStore，以便 verify_manifest 能查到
        let block = crate::block::Block {
            header: header.clone(),
            public_txs: vec![],
            gameturn_txs: vec![],
        };
        block_store.put(&block, crate::DEFAULT_CHAIN_ID).unwrap();
        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        let mut fast_sync = FastSync::new(&block_store, &mut dst_db);

        fast_sync.verify_manifest(&manifest).unwrap();
        for chunk in chunks {
            fast_sync.receive_chunk(chunk, &manifest).unwrap();
        }

        // 应用应失败（分块不完整）
        let result = fast_sync.apply_snapshot(&manifest);
        assert!(result.is_err());
        assert!(matches!(fast_sync.state(), SyncState::Failed(_)));
    }

    #[test]
    fn test_fast_sync_dedup_chunks() {
        let src_db = make_object_db(3);
        let header = make_block_header(100, src_db.state_root());
        let (manifest, chunks) =
            SnapshotBuilder::build_snapshot(&src_db, &header, crate::DEFAULT_CHAIN_ID).unwrap();

        let block_store = BlockStore::open_inmemory().unwrap();
        // 将区块放入 BlockStore，以便 verify_manifest 能查到
        let block = crate::block::Block {
            header: header.clone(),
            public_txs: vec![],
            gameturn_txs: vec![],
        };
        block_store.put(&block, crate::DEFAULT_CHAIN_ID).unwrap();
        let mut dst_db = ObjectDb::open_inmemory().unwrap();
        let mut fast_sync = FastSync::new(&block_store, &mut dst_db);

        fast_sync.verify_manifest(&manifest).unwrap();

        // 重复发送同一分块应被去重
        for chunk in &chunks {
            fast_sync.receive_chunk(chunk.clone(), &manifest).unwrap();
        }
        for chunk in &chunks {
            fast_sync.receive_chunk(chunk.clone(), &manifest).unwrap();
        }

        if let SyncState::DownloadingChunks { downloaded, total } = fast_sync.state() {
            assert_eq!(*downloaded, *total, "去重后下载数应等于分块总数");
        }
    }

    #[test]
    fn test_chunk_validate_size() {
        // 构造超大分块（对象数超限）
        let mut objects = Vec::new();
        for i in 0..MAX_OBJECTS_PER_CHUNK + 1 {
            objects.push(make_object((i % 254) as u8, i as u32));
        }
        let oversized_chunk = SnapshotChunk { index: 0, objects };
        assert!(oversized_chunk.validate_size().is_err());
    }
}
