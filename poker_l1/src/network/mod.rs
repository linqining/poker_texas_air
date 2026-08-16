//! P2P 网络模块（Task 30）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）第 865-891 行：
//! - **SubTask 30.1**：libp2p gossipsub for DAG vertex / tx 传播（本实现提供 trait 抽象 +
//!   in-memory transport，libp2p 可后续接入实现 trait）
//! - **SubTask 30.2**：peer discovery
//! - **SubTask 30.3**：sync protocol（按 range 请求 blocks + DAG vertex + fast sync）
//! - **SubTask 30.4**：轻客户端 block header 订阅协议（secp256k1 多签验证 + 2/3 quorum）
//! - **SubTask 30.5**：Compact Block Relay（M12 修复 + SEC2-L3 short ID 冲突处理）
//! - **SubTask 30.6**：Block/tx/vertex 大小上限（block <= 4MB, tx <= 128KB, vertex <= max_vertex_size）
//! - **SubTask 30.7**：无 mempool（O1 移除）：tx 直接装入下一个 vertex，100ms 缓冲
//! - **SubTask 30.8**：客户端多副本广播：Public tx + force_* tx 广播给多 validator 副本
//!
//! # 设计说明
//!
//! 本模块**不依赖 libp2p**，而是定义 [`NetworkTransport`] trait 抽象传输层。
//! 提供 [`InMemoryTransport`] 用于测试（SubTask 43.1 要求 in-memory transport mock）。
//! 生产环境可后续实现 `libp2p::Transport` 满足此 trait。

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::time::{Duration, Instant};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::block::Block;
use crate::consensus::{DagVertex, EpochTransitionProof, MAX_VERTEX_SIZE};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::sync::{
    AccountSnapshotChunk, BridgeSnapshotChunk, FullSnapshot, FullSnapshotManifest, SnapshotChunk,
};
use crate::transaction::Transaction;
use crate::{BlockHeight, Hash};

// ===== 大小上限常量（SubTask 30.6） =====

/// Block 序列化后最大 4MB（SubTask 30.6）。
pub const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Maximum length-prefixed P2P message accepted by the TCP protocol.
pub const MAX_P2P_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// A light-client header must remain a compact authentication object, never a second block body.
///
/// The wire frame has a larger transport-wide cap, but accepting megabytes of certificate or
/// signature material here would let a peer retain disproportionate data in the header cache.
pub const MAX_LIGHT_CLIENT_HEADER_BYTES: usize = 1024 * 1024;

/// Maximum encoded size of one signature-bearing light-client header.
///
/// `header_bytes` alone is limited above, but an attacker could otherwise attach an excessive
/// signature vector and make a small header consume an entire P2P frame or the persistent header
/// store.  Four such objects always fit within the 12 MiB request-response budget.
pub const MAX_LIGHT_CLIENT_HEADER_WIRE_BYTES: usize = 2 * 1024 * 1024;

/// Maximum finalized header attestations served in one authenticated sync response.
pub const MAX_LIGHT_HEADERS_PER_SYNC_REQUEST: u64 = 4;

/// tx 序列化后最大 128KB（SubTask 30.6）。
pub const MAX_TX_SIZE: usize = 128 * 1024;

/// short ID 长度：8 字节（64 bit，SEC2-L3）。
pub const SHORT_ID_LEN: usize = 8;

/// short ID → tx hash 映射表大小上限（SEC2-L3：防内存膨胀，默认 100000）。
pub const SHORT_ID_MAP_LIMIT: usize = 100_000;

/// 无 mempool 缓冲窗口：100ms（SubTask 30.7）。
pub const MEMPOOL_BUFFER_WINDOW_MS: u64 = 100;

/// Compact Block Relay short ID 域分隔前缀。
const SHORT_ID_DOMAIN: u8 = 0x53; // 'S' for Short ID

/// Maximum opaque proof-package size accepted by the P2P sync protocol.
///
/// This deliberately matches the proving-service package limit without making
/// `poker_l1` depend on that higher-level crate.
pub const MAX_PROOF_PACKAGE_BYTES: usize = 64 * 1024 * 1024;

/// Canonical proof-package chunk size.  One chunk remains comfortably below
/// the node binary's 16 MiB framed-message limit after wire metadata is added.
pub const PROOF_PACKAGE_CHUNK_SIZE: usize = 1024 * 1024;

/// Maximum number of chunks in one package under the canonical limits.
pub const MAX_PROOF_PACKAGE_CHUNKS: u32 =
    (MAX_PROOF_PACKAGE_BYTES / PROOF_PACKAGE_CHUNK_SIZE) as u32;

const PROOF_PACKAGE_HASH_DOMAIN: &[u8] = b"zchain.proof_package.v1";
const PROOF_PACKAGE_CHUNK_HASH_DOMAIN: &[u8] = b"zchain.proof_package.chunk.v1";

/// Bounded description of one opaque proving-service package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ProofPackageManifest {
    /// Durable proving job whose sidecar is being synchronized.
    pub job_id: Hash,
    /// Domain-separated hash of the complete canonical package bytes.
    pub package_hash: Hash,
    /// Exact complete package length.
    pub total_len: u64,
    /// Canonical chunk size used for every non-final chunk.
    pub chunk_size: u32,
    /// Exact number of chunks required to reconstruct the package.
    pub chunk_count: u32,
}

impl ProofPackageManifest {
    /// Validate all manifest bounds before allocating download state.
    pub fn validate(&self) -> PokerL1Result<()> {
        if self.total_len == 0 || self.total_len > MAX_PROOF_PACKAGE_BYTES as u64 {
            return Err(proof_sync_error(format!(
                "invalid proof package length {}",
                self.total_len
            )));
        }
        if self.chunk_size as usize != PROOF_PACKAGE_CHUNK_SIZE {
            return Err(proof_sync_error(format!(
                "invalid proof package chunk size {}",
                self.chunk_size
            )));
        }
        let expected_count = self.total_len.div_ceil(u64::from(self.chunk_size));
        if expected_count == 0
            || expected_count > u64::from(MAX_PROOF_PACKAGE_CHUNKS)
            || self.chunk_count != expected_count as u32
        {
            return Err(proof_sync_error(format!(
                "invalid proof package chunk count {} for length {}",
                self.chunk_count, self.total_len
            )));
        }
        Ok(())
    }

    fn expected_chunk_len(&self, index: u32) -> PokerL1Result<usize> {
        self.validate()?;
        if index >= self.chunk_count {
            return Err(proof_sync_error(format!(
                "proof package chunk index {index} out of range {}",
                self.chunk_count
            )));
        }
        let offset = u64::from(index) * u64::from(self.chunk_size);
        let remaining = self.total_len - offset;
        usize::try_from(remaining.min(u64::from(self.chunk_size)))
            .map_err(|_| proof_sync_error("proof package chunk length does not fit usize"))
    }
}

/// One independently authenticated package chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ProofPackageChunk {
    pub job_id: Hash,
    pub package_hash: Hash,
    pub index: u32,
    pub bytes: Vec<u8>,
    pub chunk_hash: Hash,
}

impl ProofPackageChunk {
    /// Validate identity, size and hash against a previously accepted manifest.
    pub fn validate_against(&self, manifest: &ProofPackageManifest) -> PokerL1Result<()> {
        manifest.validate()?;
        if self.job_id != manifest.job_id || self.package_hash != manifest.package_hash {
            return Err(proof_sync_error(
                "proof package chunk identity does not match manifest",
            ));
        }
        let expected_len = manifest.expected_chunk_len(self.index)?;
        if self.bytes.len() != expected_len {
            return Err(proof_sync_error(format!(
                "proof package chunk {} length {} != expected {expected_len}",
                self.index,
                self.bytes.len()
            )));
        }
        let expected_hash =
            proof_package_chunk_hash(self.job_id, self.package_hash, self.index, &self.bytes);
        if self.chunk_hash != expected_hash {
            return Err(proof_sync_error(format!(
                "proof package chunk {} hash mismatch",
                self.index
            )));
        }
        Ok(())
    }
}

/// Build a canonical manifest for already-bounded opaque package bytes.
pub fn build_proof_package_manifest(
    job_id: Hash,
    bytes: &[u8],
) -> PokerL1Result<ProofPackageManifest> {
    if bytes.is_empty() || bytes.len() > MAX_PROOF_PACKAGE_BYTES {
        return Err(proof_sync_error(format!(
            "invalid proof package length {}",
            bytes.len()
        )));
    }
    let chunk_count = bytes.len().div_ceil(PROOF_PACKAGE_CHUNK_SIZE);
    let manifest = ProofPackageManifest {
        job_id,
        package_hash: proof_package_hash(bytes),
        total_len: bytes.len() as u64,
        chunk_size: PROOF_PACKAGE_CHUNK_SIZE as u32,
        chunk_count: u32::try_from(chunk_count)
            .map_err(|_| proof_sync_error("proof package chunk count does not fit u32"))?,
    };
    manifest.validate()?;
    Ok(manifest)
}

/// Extract one canonical chunk from a package described by `manifest`.
pub fn build_proof_package_chunk(
    manifest: &ProofPackageManifest,
    bytes: &[u8],
    index: u32,
) -> PokerL1Result<ProofPackageChunk> {
    manifest.validate()?;
    if bytes.len() as u64 != manifest.total_len
        || proof_package_hash(bytes) != manifest.package_hash
    {
        return Err(proof_sync_error(
            "proof package bytes do not match manifest",
        ));
    }
    let expected_len = manifest.expected_chunk_len(index)?;
    let start = index as usize * PROOF_PACKAGE_CHUNK_SIZE;
    let end = start + expected_len;
    let chunk_bytes = bytes[start..end].to_vec();
    Ok(ProofPackageChunk {
        job_id: manifest.job_id,
        package_hash: manifest.package_hash,
        index,
        chunk_hash: proof_package_chunk_hash(
            manifest.job_id,
            manifest.package_hash,
            index,
            &chunk_bytes,
        ),
        bytes: chunk_bytes,
    })
}

/// Bounded, order-independent package download state.
#[derive(Debug)]
pub struct ProofPackageAssembler {
    manifest: ProofPackageManifest,
    chunks: Vec<Option<Vec<u8>>>,
    received_len: u64,
}

impl ProofPackageAssembler {
    pub fn new(manifest: ProofPackageManifest) -> PokerL1Result<Self> {
        manifest.validate()?;
        let chunk_count = manifest.chunk_count as usize;
        Ok(Self {
            manifest,
            chunks: vec![None; chunk_count],
            received_len: 0,
        })
    }

    #[must_use]
    pub const fn manifest(&self) -> &ProofPackageManifest {
        &self.manifest
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.chunks.iter().all(Option::is_some)
    }

    /// Insert an out-of-order chunk. Exact duplicates are idempotent; a conflicting
    /// duplicate is rejected instead of silently changing the assembled package.
    pub fn insert(&mut self, chunk: ProofPackageChunk) -> PokerL1Result<()> {
        chunk.validate_against(&self.manifest)?;
        let slot = &mut self.chunks[chunk.index as usize];
        if let Some(existing) = slot {
            if existing == &chunk.bytes {
                return Ok(());
            }
            return Err(proof_sync_error(format!(
                "conflicting duplicate proof package chunk {}",
                chunk.index
            )));
        }
        self.received_len = self
            .received_len
            .checked_add(chunk.bytes.len() as u64)
            .ok_or_else(|| proof_sync_error("proof package received length overflow"))?;
        if self.received_len > self.manifest.total_len {
            return Err(proof_sync_error(
                "proof package received length exceeds manifest",
            ));
        }
        *slot = Some(chunk.bytes);
        Ok(())
    }

    /// Finish reconstruction and authenticate the complete package hash.
    pub fn finish(self) -> PokerL1Result<Vec<u8>> {
        if !self.is_complete() || self.received_len != self.manifest.total_len {
            return Err(proof_sync_error("proof package download is incomplete"));
        }
        let capacity = usize::try_from(self.manifest.total_len)
            .map_err(|_| proof_sync_error("proof package length does not fit usize"))?;
        let mut bytes = Vec::with_capacity(capacity);
        for chunk in self.chunks {
            bytes.extend(chunk.expect("complete package checked above"));
        }
        if bytes.len() != capacity || proof_package_hash(&bytes) != self.manifest.package_hash {
            return Err(proof_sync_error("complete proof package hash mismatch"));
        }
        Ok(bytes)
    }
}

#[must_use]
fn proof_package_hash(bytes: &[u8]) -> Hash {
    domain_hash(PROOF_PACKAGE_HASH_DOMAIN, &[bytes])
}

#[must_use]
fn proof_package_chunk_hash(job_id: Hash, package_hash: Hash, index: u32, bytes: &[u8]) -> Hash {
    domain_hash(
        PROOF_PACKAGE_CHUNK_HASH_DOMAIN,
        &[
            &job_id,
            &package_hash,
            &index.to_le_bytes(),
            &(bytes.len() as u64).to_le_bytes(),
            bytes,
        ],
    )
}

fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> Hash {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0u8; 32];
    hasher.finalize_variable(&mut output).expect("32 <= 64");
    output
}

fn proof_sync_error(message: impl Into<String>) -> PokerL1Error {
    PokerL1Error::Other(format!("proof package sync: {}", message.into()))
}

// ===== 大小校验（SubTask 30.6） =====

/// 校验 tx 序列化后大小是否 <= 128KB（SubTask 30.6）。
///
/// 超出返回 `TxTooLarge`。
pub fn validate_tx_size(tx: &Transaction) -> PokerL1Result<()> {
    let serialized =
        borsh::to_vec(tx).map_err(|e| PokerL1Error::Serialization(format!("borsh: {e}")))?;
    if serialized.len() > MAX_TX_SIZE {
        return Err(PokerL1Error::TxTooLarge {
            actual: serialized.len(),
            limit: MAX_TX_SIZE,
        });
    }
    Ok(())
}

/// 校验 block 序列化后大小是否 <= 4MB（SubTask 30.6）。
///
/// 超出返回 `BlockTooLarge`。
pub fn validate_block_size(block: &Block) -> PokerL1Result<()> {
    let serialized =
        borsh::to_vec(block).map_err(|e| PokerL1Error::Serialization(format!("borsh: {e}")))?;
    if serialized.len() > MAX_BLOCK_SIZE {
        return Err(PokerL1Error::BlockTooLarge {
            actual: serialized.len(),
            limit: MAX_BLOCK_SIZE,
        });
    }
    Ok(())
}

/// 校验 vertex 序列化后大小是否 <= max_vertex_size（SubTask 30.6）。
///
/// 超出返回 `VertexTooLarge`。
pub fn validate_vertex_size(vertex: &DagVertex) -> PokerL1Result<()> {
    let serialized =
        borsh::to_vec(vertex).map_err(|e| PokerL1Error::Serialization(format!("borsh: {e}")))?;
    if serialized.len() > MAX_VERTEX_SIZE {
        return Err(PokerL1Error::VertexTooLarge {
            actual: serialized.len(),
            limit: MAX_VERTEX_SIZE,
        });
    }
    Ok(())
}

// ===== Compact Block Relay（SubTask 30.5 + SEC2-L3） =====

/// short ID = 8 字节（64 bit，SEC2-L3）。
pub type ShortId = [u8; SHORT_ID_LEN];

/// 计算 tx_hash 的 short ID（SEC2-L3：8 字节，blake2b_256 前 8 字节）。
///
/// short ID = `blake2b_256(0x53 || tx_hash)[0..8]`
///
/// 冲突概率 < 2^-32（8 字节空间 = 2^64，birthday bound ≈ 2^32 tx 才有 50% 冲突）。
#[must_use]
pub fn compute_short_id(tx_hash: &Hash) -> ShortId {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&[SHORT_ID_DOMAIN]);
    h.update(tx_hash);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    let mut sid = [0u8; SHORT_ID_LEN];
    sid.copy_from_slice(&out[..SHORT_ID_LEN]);
    sid
}

/// Compact vertex（SubTask 30.5）。
///
/// validator 先广播 compact vertex（vertex header + tx short IDs），
/// 接收 validator 从本地已收 tx 集合匹配，仅请求缺失的 tx。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CompactVertex {
    /// 当前 epoch。
    pub epoch: u64,
    /// DAG round。
    pub round: u64,
    /// 作者 validator 的 tagged pubkey。
    pub author_pubkey: TaggedPubkey,
    /// vertex_hash（用于索引与验证）。
    pub vertex_hash: Hash,
    /// parent_hashes（DAG 引用，完整哈希）。
    pub parent_hashes: Vec<Hash>,
    /// tx short IDs（8 字节 each，SEC2-L3）。
    pub tx_short_ids: Vec<ShortId>,
    /// 作者签名（完整签名，不压缩）。
    pub author_sig: Vec<u8>,
}

impl CompactVertex {
    /// 从完整 DagVertex 构造 CompactVertex。
    ///
    /// 提取 tx short IDs，丢弃完整 tx 内容。
    #[must_use]
    pub fn from_vertex(vertex: &DagVertex) -> Self {
        let tx_short_ids = vertex
            .tx_list
            .iter()
            .map(|tx| compute_short_id(&tx.tx_hash()))
            .collect();
        Self {
            epoch: vertex.epoch,
            round: vertex.round,
            author_pubkey: vertex.author_pubkey.clone(),
            vertex_hash: vertex.vertex_hash(),
            parent_hashes: vertex.parent_hashes.clone(),
            tx_short_ids,
            author_sig: vertex.author_sig.clone(),
        }
    }
}

/// short ID → tx hash 映射表（SEC2-L3：防内存膨胀）。
///
/// validator 维护此映射表，大小有上限（`SHORT_ID_MAP_LIMIT`）。
/// 当 short ID 冲突（多个 tx 映射到同一 short ID）时，标记冲突并请求完整 tx hash 消歧。
#[derive(Debug, Default)]
pub struct ShortIdMap {
    /// short_id → tx_hash（单映射）。
    ///
    /// 当检测到冲突时，对应 short_id 从此映射移除，转入 `conflicts` 集合。
    map: HashMap<ShortId, Hash>,
    /// 冲突的 short_id 集合（SEC2-L3：多个 tx 匹配同一 short ID）。
    ///
    /// 冲突的 short_id 不可用于 compact block relay，须请求完整 vertex fallback。
    conflicts: BTreeSet<ShortId>,
}

impl ShortIdMap {
    /// 创建空映射表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 插入 (short_id, tx_hash) 映射。
    ///
    /// SEC2-L3：
    /// - 若 short_id 已存在且 tx_hash 不同 → 标记为冲突，从 map 移除
    /// - 若映射表已满（`SHORT_ID_MAP_LIMIT`）→ 返回 `ShortIdMapFull`
    /// - 冲突的 short_id 再次插入 → 直接忽略（已在 conflicts 集合）
    pub fn insert(&mut self, short_id: ShortId, tx_hash: Hash) -> PokerL1Result<()> {
        // 冲突 short_id 直接忽略
        if self.conflicts.contains(&short_id) {
            return Ok(());
        }

        // 检查是否已存在且 tx_hash 不同
        if let Some(&existing) = self.map.get(&short_id) {
            if existing != tx_hash {
                // SEC2-L3：标记冲突，从 map 移除
                self.map.remove(&short_id);
                self.conflicts.insert(short_id);
                return Ok(());
            }
            // 相同 tx_hash → 幂等，无操作
            return Ok(());
        }

        // 检查映射表大小上限
        if self.map.len() >= SHORT_ID_MAP_LIMIT {
            return Err(PokerL1Error::ShortIdMapFull {
                actual: self.map.len(),
                limit: SHORT_ID_MAP_LIMIT,
            });
        }

        self.map.insert(short_id, tx_hash);
        Ok(())
    }

    /// 查找 short_id 对应的 tx_hash。
    ///
    /// 返回 `Ok(Some(hash))` 表示唯一匹配；
    /// 返回 `Ok(None)` 表示无匹配或冲突（须请求完整 tx hash 消歧）。
    #[must_use]
    pub fn lookup(&self, short_id: &ShortId) -> Option<Hash> {
        // 冲突的 short_id 返回 None（须 fallback）
        if self.conflicts.contains(short_id) {
            return None;
        }
        self.map.get(short_id).copied()
    }

    /// 检查 short_id 是否冲突（SEC2-L3）。
    #[must_use]
    pub fn is_conflict(&self, short_id: &ShortId) -> bool {
        self.conflicts.contains(short_id)
    }

    /// 移除 (short_id, tx_hash) 映射（H7 修复 — tx_cache FIFO 淘汰时联动清理）。
    ///
    /// 仅当 short_id 当前映射的 tx_hash 与传入值一致时移除，
    /// 防止误删已映射到新 tx 的条目。
    pub fn remove(&mut self, short_id: &ShortId, tx_hash: &Hash) {
        if let Some(&existing) = self.map.get(short_id)
            && existing == *tx_hash
        {
            self.map.remove(short_id);
        }
    }

    /// 当前映射表大小。
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// 映射表是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// 冲突 short_id 数量。
    #[must_use]
    pub fn conflict_count(&self) -> usize {
        self.conflicts.len()
    }
}

/// Compact Block Relay 接收端：从 compact vertex + 本地 tx 缓存重建完整 vertex。
///
/// SEC2-L3 修复：
/// - short ID 冲突时返回 `ShortIdCollision`，调用方应请求完整 vertex fallback
/// - 缺失 tx 时返回缺失的 tx_hash 列表，调用方应请求这些 tx
///
/// # 参数
///
/// - `compact`：接收到的 compact vertex
/// - `short_id_map`：本地 short ID → tx_hash 映射表
/// - `tx_cache`：本地已收 tx 缓存（tx_hash → Transaction）
///
/// # 返回
///
/// - `Ok((tx_hashes, missing))`：`tx_hashes` 为匹配到的完整 tx_hash 列表（按 compact 顺序），
///   `missing` 为缺失的 short_id 列表（需请求完整 tx hash）
/// - `Err(ShortIdCollision)`：检测到 short ID 冲突，应请求完整 vertex fallback
pub fn reconstruct_vertex_tx_hashes(
    compact: &CompactVertex,
    short_id_map: &ShortIdMap,
    tx_cache: &HashMap<Hash, Transaction>,
) -> PokerL1Result<(Vec<Hash>, Vec<ShortId>)> {
    let mut tx_hashes = Vec::with_capacity(compact.tx_short_ids.len());
    let mut missing = Vec::new();

    for short_id in &compact.tx_short_ids {
        // SEC2-L3：冲突 short_id → 请求完整 vertex fallback
        if short_id_map.is_conflict(short_id) {
            return Err(PokerL1Error::ShortIdCollision(*short_id));
        }

        match short_id_map.lookup(short_id) {
            Some(tx_hash) => {
                // 检查本地 tx 缓存是否有完整 tx
                if tx_cache.contains_key(&tx_hash) {
                    tx_hashes.push(tx_hash);
                } else {
                    // short ID 匹配但本地无完整 tx → 请求此 tx
                    missing.push(*short_id);
                }
            }
            None => {
                // 无匹配 → 请求完整 tx hash 消歧
                missing.push(*short_id);
            }
        }
    }

    Ok((tx_hashes, missing))
}

// ===== 无 mempool 缓冲（SubTask 30.7） =====

/// 无 mempool tx 缓冲（SubTask 30.7：O1 移除 mempool）。
///
/// validator 收到 tx 后直接装入下一个 vertex，不维护 gossiped pending tx pool。
/// 内存中仅保留待装 vertex 的 tx 短暂缓冲（默认 100ms 内必装 vertex）。
///
/// # 设计
///
/// - `push(tx)`：加入缓冲，记录时间戳
/// - `drain_for_vertex()`：取出所有缓冲中的 tx（按 FIFO），丢弃超时的 tx（返回超时错误）
/// - `drain_if_ready(window_ms)`：检查最早的 tx 是否超过窗口，超时则 drain
#[derive(Debug)]
pub struct TxBuf {
    /// FIFO 队列：(tx, arrival_time)。
    queue: VecDeque<(Transaction, Instant)>,
    /// 缓冲窗口（默认 100ms）。
    window: Duration,
}

impl TxBuf {
    /// 创建空缓冲，默认 100ms 窗口。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            window: Duration::from_millis(MEMPOOL_BUFFER_WINDOW_MS),
        }
    }

    /// 创建指定窗口的缓冲（测试用）。
    #[must_use]
    pub const fn with_window(window: Duration) -> Self {
        Self {
            queue: VecDeque::new(),
            window,
        }
    }

    /// 加入 tx 到缓冲。
    pub fn push(&mut self, tx: Transaction) {
        self.queue.push_back((tx, Instant::now()));
    }

    /// 当前缓冲中的 tx 数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// 缓冲是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// 取出所有缓冲中的 tx（按 FIFO），检查超时。
    ///
    /// SubTask 30.7：tx 在缓冲中超过 `window` 未装入 vertex → 返回 `MempoolBufferTimeout`。
    ///
    /// 返回 `(txs, timeout_hashes)`：
    /// - `txs`：未超时的 tx 列表（应装入下一个 vertex）
    /// - `timeout_hashes`：超时的 tx 哈希列表（应记录并丢弃）
    pub fn drain_for_vertex(&mut self) -> (Vec<Transaction>, Vec<Hash>) {
        let now = Instant::now();
        let mut txs = Vec::with_capacity(self.queue.len());
        let mut timeout_hashes = Vec::new();

        while let Some((tx, arrival)) = self.queue.pop_front() {
            if now.duration_since(arrival) > self.window {
                // 超时 → 记录哈希，丢弃 tx
                timeout_hashes.push(tx.tx_hash());
            } else {
                txs.push(tx);
            }
        }

        (txs, timeout_hashes)
    }

    /// 检查最早的 tx 是否超过窗口（非破坏性检查）。
    ///
    /// 返回 true 表示应 drain（最早 tx 已超时或缓冲非空）。
    #[must_use]
    pub fn should_drain(&self) -> bool {
        if self.queue.is_empty() {
            return false;
        }
        // 检查最早的 tx 是否超过窗口
        let now = Instant::now();
        self.queue
            .front()
            .map(|(_, arrival)| now.duration_since(*arrival) > self.window)
            .unwrap_or(false)
    }
}

impl Default for TxBuf {
    fn default() -> Self {
        Self::new()
    }
}

// ===== 多副本广播（SubTask 30.8） =====

/// 多副本广播结果（SubTask 30.8）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadcastResult {
    /// 接受 tx 的副本数量。
    pub accepted_count: usize,
    /// 见证签名（副本 validator 仅见证不装入 vertex 的场景，SubTask 30.8）。
    pub witness_signatures: Vec<TaggedPubkey>,
}

/// 多副本广播配置（SubTask 30.8）。
#[derive(Debug, Clone)]
pub struct BroadcastConfig {
    /// 目标副本数量（默认 3）。
    pub replica_count: usize,
    /// 至少一个副本接受即视为成功。
    pub min_accept: usize,
}

impl Default for BroadcastConfig {
    fn default() -> Self {
        Self {
            replica_count: 3,
            min_accept: 1,
        }
    }
}

/// 客户端多副本广播（SubTask 30.8）。
///
/// Public tx + force_* tx（含 force_checkpoint）广播给多 validator 副本以提高确定性。
/// checkpoint_anchor 多副本广播作为审查检测证据（副本 validator 仅见证不装入 vertex）。
///
/// # 参数
///
/// - `tx_hash`：广播的 tx 哈希
/// - `replicas`：目标副本 validator pubkey 列表
/// - `accepted_by`：接受 tx 的 validator pubkey 列表
/// - `witnesses`：见证签发的 validator pubkey 列表（审查检测证据）
/// - `config`：广播配置
///
/// # 返回
///
/// - `Ok(BroadcastResult)`：至少 `min_accept` 个副本接受
/// - `Err(MultiReplicaBroadcastFailed)`：所有副本均未接受
pub fn multi_replica_broadcast(
    tx_hash: Hash,
    replicas: &[TaggedPubkey],
    accepted_by: &[TaggedPubkey],
    witnesses: &[TaggedPubkey],
    config: &BroadcastConfig,
) -> PokerL1Result<BroadcastResult> {
    let accepted_count = accepted_by.len();

    if accepted_count < config.min_accept {
        return Err(PokerL1Error::MultiReplicaBroadcastFailed {
            tx_hash,
            attempts: replicas.len(),
        });
    }

    Ok(BroadcastResult {
        accepted_count,
        witness_signatures: witnesses.to_vec(),
    })
}

// ===== 网络传输 trait（SubTask 30.1 / 30.2 / 30.3 / 30.4） =====

/// gossipsub 主题（SubTask 30.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GossipTopic {
    /// DAG vertex 传播。
    DagVertex,
    /// tx 传播。
    Transaction,
    /// Compact vertex 传播（SubTask 30.5）。
    CompactVertex,
    /// checkpoint_anchor 多副本广播（SubTask 30.8）。
    CheckpointAnchor,
    /// commit certificate 投票传播（缺口 #3：多 validator 2/3 多签闭环）。
    CommitVote,
    /// 下一 epoch 的指定 proposer ECVRF proof 传播。
    EpochTransition,
}

/// 网络消息（SubTask 30.1）。
#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum NetworkMessage {
    /// First frame of the mutually authenticated P2P handshake.
    P2pHello(P2pHello),
    /// Challenge response completing the mutually authenticated P2P handshake.
    P2pHelloAck(P2pHelloAck),
    /// Authenticated-encrypted transport envelope used after the P2P handshake.
    ///
    /// The payload is an independently Borsh-encoded [`NetworkMessage`]. Handshake frames are
    /// never wrapped, and a nested secure envelope is invalid.
    P2pSecureFrame(P2pSecureFrame),
    /// 完整 DAG vertex。
    DagVertex(DagVertex),
    /// 完整 tx。
    Transaction(Transaction),
    /// Compact vertex（SubTask 30.5）。
    CompactVertex(CompactVertex),
    /// 请求缺失的 tx（compact block relay）。
    RequestTx(Vec<Hash>),
    /// 响应缺失的 tx。
    ResponseTx(Vec<Transaction>),
    /// 请求完整 vertex fallback（SEC2-L3：short ID 冲突）。
    RequestFullVertex(Hash),
    /// 响应完整 vertex。
    ResponseFullVertex(DagVertex),
    /// sync protocol：按 range 请求 blocks（SubTask 30.3）。
    RequestBlocksByRange(BlockHeight, BlockHeight),
    /// sync protocol：响应 blocks。
    ResponseBlocks(Vec<Block>),
    /// sync protocol：按 range 请求 DAG vertices（SubTask 30.3）。
    RequestVerticesByRange(u64, u64),
    /// sync protocol：响应 vertices。
    ResponseVertices(Vec<DagVertex>),
    /// Request a bounded, contiguous range of quorum-authenticated light-client headers.
    RequestLightClientHeaders(BlockHeight, BlockHeight),
    /// Response containing only finalized headers with their validator signature attestations.
    ResponseLightClientHeaders(Vec<LightClientHeader>),
    /// Request the latest archive-node full-state snapshot descriptor.
    RequestFullSnapshotManifest,
    /// Return a complete snapshot descriptor, or `None` when the peer cannot safely serve one.
    ResponseFullSnapshotManifest(Option<FullSnapshotManifest>),
    /// Request one ObjectDb snapshot chunk from the snapshot identified by `block_hash`.
    RequestObjectSnapshotChunk { block_hash: Hash, index: u64 },
    /// Return one authenticated ObjectDb chunk, or `None` when unavailable.
    ResponseObjectSnapshotChunk(Option<SnapshotChunk>),
    /// Request one AccountStore snapshot chunk from the snapshot identified by `block_hash`.
    RequestAccountSnapshotChunk { block_hash: Hash, index: u64 },
    /// Return one authenticated AccountStore chunk, or `None` when unavailable.
    ResponseAccountSnapshotChunk(Option<AccountSnapshotChunk>),
    /// Request one bridge replay-archive chunk from the snapshot identified by `block_hash`.
    RequestBridgeSnapshotChunk { block_hash: Hash, index: u64 },
    /// Return one authenticated bridge archive chunk, or `None` when unavailable.
    ResponseBridgeSnapshotChunk(Option<BridgeSnapshotChunk>),
    /// Request the bounded manifest for one opaque proving-service package.
    RequestProofPackageManifest(Hash),
    /// Return a package manifest, or `None` when this peer does not retain it.
    ResponseProofPackageManifest(Option<ProofPackageManifest>),
    /// Request one package chunk by canonical zero-based index.
    RequestProofPackageChunk {
        job_id: Hash,
        package_hash: Hash,
        index: u32,
    },
    /// Return one authenticated chunk, or `None` when unavailable.
    ResponseProofPackageChunk(Option<ProofPackageChunk>),
    /// 轻客户端 block header 订阅（SubTask 30.4）。
    LightClientHeader(LightClientHeader),
    /// commit certificate 投票（缺口 #3：多 validator 2/3 多签闭环）。
    ///
    /// validator 观察到 commit leader 后，对 `cert_signing_hash` 单独签名并广播，
    /// 收集方凑齐 ≥2/3 后用 [`crate::consensus::bullshark::assemble_commit_certificate`]
    /// 组装完整 cert。cert signing_hash 域(0x43)与 vertex signing_hash 域不同，
    /// 故不能复用 vertex 的 author_sig。
    CommitVote(CommitVote),
    /// 预先传播下一 epoch 的 ECVRF proof。
    ///
    /// 该 proof 必须先被本地验证并缓存，随后所有 validator 才能对同一、带 proof 的
    /// certificate signing hash 投票。它不替代 certificate 签名：proof 会再次被放进
    /// certificate 并由 quorum signature 绑定。
    EpochTransitionProposal {
        /// Certificate / validator-set target epoch.
        target_epoch: crate::consensus::Epoch,
        /// The designated proposer proof for `target_epoch`.
        proof: EpochTransitionProof,
    },
    /// Peer Exchange（PEX，缺口 #5）：节点交换已知 peer 地址列表。
    PeerExchange(Vec<PeerInfo>),
}

/// Signed P2P protocol and chain-negotiation offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct P2pHello {
    /// Exact wire protocol revision required by the sender.
    pub protocol_version: u16,
    /// Consensus chain namespace required by the sender.
    pub chain_id: crate::ChainId,
    /// Stable process identity derived from `identity_pubkey`.
    pub peer_id: String,
    /// Secp256k1 identity key in the standard tagged-key representation.
    pub identity_pubkey: TaggedPubkey,
    /// Fresh sender challenge.
    pub nonce: Hash,
    /// Fresh secp256k1 ECDH key for this connection, covered by `signature`.
    pub session_pubkey: TaggedPubkey,
    /// Recoverable signature over the canonical hello challenge.
    pub signature: Vec<u8>,
}

/// Signed response to a peer's [`P2pHello`] challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct P2pHelloAck {
    /// Identity that signed this acknowledgement.
    pub peer_id: String,
    /// Same identity key supplied in the sender's [`P2pHello`].
    pub identity_pubkey: TaggedPubkey,
    /// Exact remote challenge being acknowledged.
    pub peer_nonce: Hash,
    /// Recoverable signature over the canonical acknowledgement challenge.
    pub signature: Vec<u8>,
}

/// A monotonic encrypted P2P frame.
///
/// Sequence numbers are per direction and must start at zero. They are checked before a frame
/// reaches any consensus or gossip handler, preventing replay and reordering on a connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct P2pSecureFrame {
    /// Per-direction strictly increasing frame sequence number.
    pub sequence: u64,
    /// ChaCha20-Poly1305 ciphertext including its authentication tag.
    pub ciphertext: Vec<u8>,
}

/// commit certificate 投票（缺口 #3）。
///
/// 每个 validator 对拟出块的 commit certificate 的
/// `signing_hash_for_header(chain_id, height, timestamp_ms, prev_hash)` 签名，
/// 广播给其他 validator。收集方凑齐 ≥2/3 签名后组装 cert 出块。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CommitVote {
    /// epoch。
    pub epoch: crate::consensus::Epoch,
    /// commit round。
    pub commit_round: u64,
    /// 签名对象（绑定完整 block-header 位置，32 字节）。
    /// 供收集方校验签名一致性。
    pub cert_signing_hash: Hash,
    /// 签名者 tagged pubkey。
    pub signer_pubkey: TaggedPubkey,
    /// secp256k1 签名（65B r||s||v，对 cert_signing_hash）。
    pub signature: Vec<u8>,
}

/// 轻客户端 block header（SubTask 30.4）。
///
/// 含 block header + 2/3 validator secp256k1 多签。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct LightClientHeader {
    /// block header 序列化字节（含 height / timestamp / state_root / prev_hash 等）。
    pub header_bytes: Vec<u8>,
    /// validator 签名列表（secp256k1 多签）。
    pub signatures: Vec<ValidatorSig>,
    /// 签名者 bitmap（对应 validator 集位置）。
    pub signer_bitmap: Vec<bool>,
}

/// validator 签名（轻客户端订阅用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ValidatorSig {
    /// validator tagged pubkey。
    pub validator: TaggedPubkey,
    /// secp256k1 签名（65B r||s||v）。
    pub signature: Vec<u8>,
}

/// peer 信息（SubTask 30.2）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PeerInfo {
    /// peer ID（libp2p PeerId 或自定义）。
    pub peer_id: String,
    /// peer 地址。
    pub address: String,
    /// peer 的 validator pubkey（如有）。
    pub validator_pubkey: Option<TaggedPubkey>,
}

/// 网络传输 trait（SubTask 30.1 / 30.2 / 30.3 / 30.4）。
///
/// 抽象 P2P 传输层，允许不同后端实现（libp2p / in-memory mock / 等）。
pub trait NetworkTransport: Send + Sync {
    /// 广播消息到指定 gossip topic（SubTask 30.1）。
    fn gossip_broadcast(&self, topic: GossipTopic, message: &NetworkMessage) -> PokerL1Result<()>;

    /// 发送消息到指定 peer（点对点）。
    fn send_to(&self, peer: &PeerInfo, message: &NetworkMessage) -> PokerL1Result<()>;

    /// 发现 peers（SubTask 30.2）。
    fn discover_peers(&self) -> PokerL1Result<Vec<PeerInfo>>;

    /// 按 range 请求 blocks（SubTask 30.3 sync protocol）。
    fn request_blocks_by_range(
        &self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> PokerL1Result<Vec<Block>>;

    /// 按 round range 请求 DAG vertices（SubTask 30.3 sync protocol）。
    fn request_vertices_by_range(
        &self,
        start_round: u64,
        end_round: u64,
    ) -> PokerL1Result<Vec<DagVertex>>;

    /// Request finalized, signature-bearing light-client headers in a closed height range.
    fn request_light_client_headers(
        &self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> PokerL1Result<Vec<LightClientHeader>>;

    /// Fetch the latest full-state snapshot descriptor from an archive peer.
    fn request_full_snapshot_manifest(&self) -> PokerL1Result<Option<FullSnapshotManifest>>;

    /// Fetch one bounded ObjectDb snapshot chunk.
    fn request_object_snapshot_chunk(
        &self,
        block_hash: Hash,
        index: u64,
    ) -> PokerL1Result<Option<SnapshotChunk>>;

    /// Fetch one bounded AccountStore snapshot chunk.
    fn request_account_snapshot_chunk(
        &self,
        block_hash: Hash,
        index: u64,
    ) -> PokerL1Result<Option<AccountSnapshotChunk>>;

    /// Fetch one bounded bridge replay-archive snapshot chunk.
    fn request_bridge_snapshot_chunk(
        &self,
        block_hash: Hash,
        index: u64,
    ) -> PokerL1Result<Option<BridgeSnapshotChunk>>;

    /// Fetch the manifest for one opaque proof package from an available peer.
    fn request_proof_package_manifest(
        &self,
        job_id: Hash,
    ) -> PokerL1Result<Option<ProofPackageManifest>>;

    /// Fetch one authenticated proof-package chunk from an available peer.
    fn request_proof_package_chunk(
        &self,
        job_id: Hash,
        package_hash: Hash,
        index: u32,
    ) -> PokerL1Result<Option<ProofPackageChunk>>;

    /// 订阅轻客户端 block header（SubTask 30.4）。
    fn subscribe_light_headers(&self) -> PokerL1Result<Vec<LightClientHeader>>;
}

/// In-memory transport（测试用，SubTask 43.1）。
///
/// 不依赖 libp2p，所有消息通过内存通道传递。
/// 适用于单元测试与集成测试。
#[derive(Debug, Default)]
pub struct InMemoryTransport {
    /// 已广播的消息（topic → messages）。
    broadcast_log: std::sync::Mutex<HashMap<GossipTopic, Vec<NetworkMessage>>>,
    /// 已知 peers。
    peers: std::sync::Mutex<Vec<PeerInfo>>,
    /// 模拟 block 存储（height → block）。
    blocks: std::sync::Mutex<BTreeMap<BlockHeight, Block>>,
    /// 模拟 vertex 存储（round → vertex）。
    vertices: std::sync::Mutex<BTreeMap<u64, DagVertex>>,
    /// 模拟轻客户端 header 存储。
    light_headers: std::sync::Mutex<Vec<LightClientHeader>>,
    /// Opaque proof packages retained by this mock peer.
    proof_packages: std::sync::Mutex<BTreeMap<Hash, Vec<u8>>>,
    /// Complete snapshot exposed by this mock archive peer.
    full_snapshot: std::sync::Mutex<Option<FullSnapshot>>,
}

impl InMemoryTransport {
    /// 创建空 transport。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 添加已知 peer。
    pub fn add_peer(&self, peer: PeerInfo) {
        self.peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(peer);
    }

    /// 注入 block 到模拟存储（测试用）。
    pub fn inject_block(&self, block: Block) {
        let height = block.header.height;
        self.blocks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(height, block);
    }

    /// 注入 vertex 到模拟存储（测试用）。
    pub fn inject_vertex(&self, vertex: DagVertex) {
        let round = vertex.round;
        self.vertices
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(round, vertex);
    }

    /// 注入轻客户端 header（测试用）。
    pub fn inject_light_header(&self, header: LightClientHeader) {
        self.light_headers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(header);
    }

    /// Inject one bounded opaque package for request/response sync tests.
    pub fn inject_proof_package(&self, job_id: Hash, bytes: Vec<u8>) -> PokerL1Result<()> {
        build_proof_package_manifest(job_id, &bytes)?;
        self.proof_packages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(job_id, bytes);
        Ok(())
    }

    /// Install a complete snapshot for in-memory fast-sync tests.
    pub fn inject_full_snapshot(&self, snapshot: FullSnapshot) -> PokerL1Result<()> {
        FullSnapshotManifest::from_snapshot(&snapshot).validate()?;
        *self
            .full_snapshot
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(snapshot);
        Ok(())
    }

    /// 获取已广播的消息（测试验证用）。
    pub fn broadcasted_messages(&self, topic: GossipTopic) -> Vec<NetworkMessage> {
        self.broadcast_log
            .lock()
            .unwrap()
            .get(&topic)
            .cloned()
            .unwrap_or_default()
    }
}

impl NetworkTransport for InMemoryTransport {
    fn gossip_broadcast(&self, topic: GossipTopic, message: &NetworkMessage) -> PokerL1Result<()> {
        self.broadcast_log
            .lock()
            .unwrap()
            .entry(topic)
            .or_default()
            .push(message.clone());
        Ok(())
    }

    fn send_to(&self, _peer: &PeerInfo, _message: &NetworkMessage) -> PokerL1Result<()> {
        // In-memory transport 点对点消息直接丢弃（测试不需要真实点对点）
        Ok(())
    }

    fn discover_peers(&self) -> PokerL1Result<Vec<PeerInfo>> {
        Ok(self.peers.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }

    fn request_blocks_by_range(
        &self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> PokerL1Result<Vec<Block>> {
        let blocks = self.blocks.lock().unwrap_or_else(|e| e.into_inner());
        let mut result = Vec::new();
        for height in start..=end {
            if let Some(block) = blocks.get(&height) {
                result.push(block.clone());
            }
        }
        Ok(result)
    }

    fn request_vertices_by_range(
        &self,
        start_round: u64,
        end_round: u64,
    ) -> PokerL1Result<Vec<DagVertex>> {
        let vertices = self.vertices.lock().unwrap_or_else(|e| e.into_inner());
        let mut result = Vec::new();
        for round in start_round..=end_round {
            if let Some(vertex) = vertices.get(&round) {
                result.push(vertex.clone());
            }
        }
        Ok(result)
    }

    fn request_light_client_headers(
        &self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> PokerL1Result<Vec<LightClientHeader>> {
        if start > end {
            return Ok(Vec::new());
        }
        let capped_end =
            end.min(start.saturating_add(MAX_LIGHT_HEADERS_PER_SYNC_REQUEST.saturating_sub(1)));
        let mut headers: Vec<(BlockHeight, LightClientHeader)> = self
            .light_headers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|light_header| {
                let header: crate::block::BlockHeader =
                    borsh::from_slice(&light_header.header_bytes).ok()?;
                (header.height >= start && header.height <= capped_end)
                    .then(|| (header.height, light_header.clone()))
            })
            .collect();
        headers.sort_by_key(|(height, _)| *height);
        Ok(headers.into_iter().map(|(_, header)| header).collect())
    }

    fn request_full_snapshot_manifest(&self) -> PokerL1Result<Option<FullSnapshotManifest>> {
        Ok(self
            .full_snapshot
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .map(FullSnapshotManifest::from_snapshot))
    }

    fn request_object_snapshot_chunk(
        &self,
        block_hash: Hash,
        index: u64,
    ) -> PokerL1Result<Option<SnapshotChunk>> {
        Ok(self
            .full_snapshot
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .filter(|snapshot| snapshot.object_manifest.block_hash == block_hash)
            .and_then(|snapshot| {
                usize::try_from(index)
                    .ok()
                    .and_then(|index| snapshot.object_chunks.get(index))
            })
            .cloned())
    }

    fn request_account_snapshot_chunk(
        &self,
        block_hash: Hash,
        index: u64,
    ) -> PokerL1Result<Option<AccountSnapshotChunk>> {
        Ok(self
            .full_snapshot
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .filter(|snapshot| snapshot.account_manifest.block_hash == block_hash)
            .and_then(|snapshot| {
                usize::try_from(index)
                    .ok()
                    .and_then(|index| snapshot.account_chunks.get(index))
            })
            .cloned())
    }

    fn request_bridge_snapshot_chunk(
        &self,
        block_hash: Hash,
        index: u64,
    ) -> PokerL1Result<Option<BridgeSnapshotChunk>> {
        Ok(self
            .full_snapshot
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .filter(|snapshot| {
                snapshot
                    .bridge_manifest
                    .as_ref()
                    .is_some_and(|manifest| manifest.block_hash == block_hash)
            })
            .and_then(|snapshot| {
                usize::try_from(index)
                    .ok()
                    .and_then(|index| snapshot.bridge_chunks.get(index))
            })
            .cloned())
    }

    fn request_proof_package_manifest(
        &self,
        job_id: Hash,
    ) -> PokerL1Result<Option<ProofPackageManifest>> {
        self.proof_packages
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&job_id)
            .map(|bytes| build_proof_package_manifest(job_id, bytes))
            .transpose()
    }

    fn request_proof_package_chunk(
        &self,
        job_id: Hash,
        package_hash: Hash,
        index: u32,
    ) -> PokerL1Result<Option<ProofPackageChunk>> {
        let packages = self
            .proof_packages
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(bytes) = packages.get(&job_id) else {
            return Ok(None);
        };
        let manifest = build_proof_package_manifest(job_id, bytes)?;
        if manifest.package_hash != package_hash {
            return Ok(None);
        }
        Ok(Some(build_proof_package_chunk(&manifest, bytes, index)?))
    }

    fn subscribe_light_headers(&self) -> PokerL1Result<Vec<LightClientHeader>> {
        Ok(self
            .light_headers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }
}

// ===== 轻客户端 header 验证（SubTask 30.4） =====

/// 验证轻客户端 block header 的 2/3 quorum（SubTask 30.4）。
///
/// spec：secp256k1 多签验证 + 2/3 quorum。
///
/// # 参数
///
/// - `header`：轻客户端 header
/// - `validators`：当前 finalized ValidatorSet 的活跃成员
/// - `verify_fn`：签名验证函数（用于验证每个 validator 的签名）
///
/// # 返回
///
/// - `Ok(())`：签名数 >= 2/3 quorum 且所有签名验证通过
/// - `Err(LightClientQuorumInsufficient)`：签名数不足 2/3
/// - `Err(InvalidSignature)`：签名验证失败
pub fn verify_light_client_header(
    header: &LightClientHeader,
    validators: &[TaggedPubkey],
    verify_fn: impl Fn(&TaggedPubkey, &[u8], &[u8; 32]) -> PokerL1Result<()>,
) -> PokerL1Result<()> {
    let unique_count = verify_light_client_header_signatures(header, validators, verify_fn)?;
    let required = crate::consensus::required_quorum(validators.len());
    if unique_count < required {
        return Err(PokerL1Error::LightClientQuorumInsufficient {
            actual: unique_count,
            required,
        });
    }
    Ok(())
}

/// Verify every unique light-header signature without requiring a full quorum.
///
/// Validators exchange individually authenticated signature shares before any peer has a full
/// light-client quorum. Callers may retain such shares only in a bounded, non-finalized pool;
/// [`verify_light_client_header`] remains required before treating a header as finalized or
/// relaying it to light clients.
pub fn verify_light_client_header_signatures(
    header: &LightClientHeader,
    validators: &[TaggedPubkey],
    verify_fn: impl Fn(&TaggedPubkey, &[u8], &[u8; 32]) -> PokerL1Result<()>,
) -> PokerL1Result<usize> {
    let encoded_len = borsh::to_vec(header)?.len();
    if encoded_len > MAX_LIGHT_CLIENT_HEADER_WIRE_BYTES {
        return Err(PokerL1Error::Other(format!(
            "light client header wire encoding exceeds {} byte limit",
            MAX_LIGHT_CLIENT_HEADER_WIRE_BYTES
        )));
    }
    if header.header_bytes.is_empty() || header.header_bytes.len() > MAX_LIGHT_CLIENT_HEADER_BYTES {
        return Err(PokerL1Error::Other(format!(
            "light client header has invalid byte length {}",
            header.header_bytes.len()
        )));
    }
    // A quorum count without the actual membership list is not a trust boundary: arbitrary
    // attacker-generated keys could otherwise satisfy it.  Reject malformed validator sets
    // rather than silently counting their duplicates.
    let members: BTreeSet<TaggedPubkey> = validators.iter().cloned().collect();
    if members.len() != validators.len() || members.is_empty() {
        return Err(PokerL1Error::Other(
            "light client validator set is empty or contains duplicate members".into(),
        ));
    }
    // H2 修复：签名者去重，防止重复签名通过 quorum
    let mut seen = BTreeSet::new();
    for sig in &header.signatures {
        if !members.contains(&sig.validator) {
            return Err(PokerL1Error::Other(
                "light client header contains a signer outside the finalized ValidatorSet".into(),
            ));
        }
        if !seen.insert(sig.validator.clone()) {
            return Err(PokerL1Error::DuplicateLightClientSigner(
                sig.validator.clone(),
            ));
        }
    }
    // 计算签名对象哈希（header_bytes 的 blake2b_256）
    let mut msg_hash = [0u8; 32];
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&header.header_bytes);
    h.finalize_variable(&mut msg_hash).expect("32 <= 64");

    // 验证每个签名
    for sig in &header.signatures {
        verify_fn(&sig.validator, &sig.signature, &msg_hash)?;
    }

    Ok(seen.len())
}

// ===== Gossip 管理器（SubTask 30.1 / 30.5） =====

/// tx_cache 默认最大条目数（H7 修复 — 防止内存 DoS）。
///
/// 攻击者可通过持续广播 tx 使 tx_cache 无限增长。此上限触发 FIFO 淘汰，
/// 保证内存占用有界。10,000 条足以覆盖 compact block relay 匹配窗口。
pub const MAX_TX_CACHE_SIZE: usize = 10_000;

/// Gossip 管理器：协调 Compact Block Relay + tx 缓冲 + short ID 映射。
///
/// 集成 SubTask 30.5（Compact Block Relay）+ SubTask 30.7（无 mempool 缓冲）。
///
/// M-9 修复：内部使用 `Mutex` 同步，方法签名从 `&mut self` 改为 `&self`，
/// 使 `GossipManager` 成为 `Sync` 类型，可通过 `Arc<GossipManager>` 共享。
pub struct GossipManager {
    /// 可变状态（M-9 修复 — 合并到单个 Mutex 减少锁竞争）。
    state: std::sync::Mutex<GossipState>,
    /// tx_cache 最大条目数（H7 修复 — 超限时 FIFO 淘汰，构造后不可变）。
    max_tx_cache_size: usize,
}

/// GossipManager 的可变状态。
struct GossipState {
    /// short ID → tx_hash 映射表（SEC2-L3）。
    short_id_map: ShortIdMap,
    /// 本地已收 tx 缓存（tx_hash → Transaction）。
    tx_cache: HashMap<Hash, Transaction>,
    /// tx_cache 插入顺序（H7 修复 — FIFO 淘汰追踪）。
    tx_cache_order: VecDeque<Hash>,
    /// 无 mempool tx 缓冲（SubTask 30.7）。
    tx_buf: TxBuf,
}

impl GossipManager {
    /// 创建空 gossip 管理器。
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_tx_cache_size(MAX_TX_CACHE_SIZE)
    }

    /// 创建指定 tx_cache 上限的 gossip 管理器（H7 修复 — 测试 / 配置用）。
    #[must_use]
    pub fn with_max_tx_cache_size(max_tx_cache_size: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(GossipState {
                short_id_map: ShortIdMap::new(),
                tx_cache: HashMap::new(),
                tx_cache_order: VecDeque::new(),
                tx_buf: TxBuf::new(),
            }),
            max_tx_cache_size,
        }
    }

    /// 接收 tx：校验大小 → 加入 short ID 映射 → 加入 tx 缓存 → 加入缓冲（SubTask 30.6 / 30.5 / 30.7）。
    ///
    /// 流程：
    /// 1. 校验 tx 大小 <= 128KB（SubTask 30.6）
    /// 2. 计算 tx_hash 与 short ID
    /// 3. 插入 short ID 映射表（SEC2-L3 冲突检测）
    /// 4. 缓存 tx 到本地（供 compact block relay 匹配）
    /// 5. 加入无 mempool 缓冲（100ms 内必装 vertex，SubTask 30.7）
    ///
    /// M-9 修复：`&self` + 内部 Mutex，支持 `Arc<GossipManager>` 共享。
    pub fn receive_tx(&self, tx: Transaction) -> PokerL1Result<()> {
        // SubTask 30.6：大小校验（无需持锁）
        validate_tx_size(&tx)?;

        let tx_hash = tx.tx_hash();
        let short_id = compute_short_id(&tx_hash);

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // SEC2-L3：插入 short ID 映射（冲突检测）
        state.short_id_map.insert(short_id, tx_hash)?;

        // 缓存 tx（H7 修复：FIFO 淘汰防止内存 DoS）
        if !state.tx_cache.contains_key(&tx_hash) {
            state.tx_cache_order.push_back(tx_hash);
        }
        state.tx_cache.insert(tx_hash, tx.clone());

        // H7 修复：超限时淘汰最旧条目
        while state.tx_cache.len() > self.max_tx_cache_size {
            if let Some(old_hash) = state.tx_cache_order.pop_front() {
                if state.tx_cache.remove(&old_hash).is_some() {
                    let old_short_id = compute_short_id(&old_hash);
                    state.short_id_map.remove(&old_short_id, &old_hash);
                }
            } else {
                break;
            }
        }

        // SubTask 30.7：加入无 mempool 缓冲
        state.tx_buf.push(tx);

        Ok(())
    }

    /// 广播 compact vertex（SubTask 30.5）。
    ///
    /// validator 打包 vertex 后，先广播 compact vertex（header + tx short IDs）。
    pub fn broadcast_compact_vertex(
        &self,
        vertex: &DagVertex,
        transport: &dyn NetworkTransport,
    ) -> PokerL1Result<()> {
        let compact = CompactVertex::from_vertex(vertex);
        transport.gossip_broadcast(
            GossipTopic::CompactVertex,
            &NetworkMessage::CompactVertex(compact),
        )
    }

    /// 接收 compact vertex 并尝试重建（SubTask 30.5 + SEC2-L3）。
    ///
    /// 返回 `(matched_tx_hashes, missing_short_ids)`：
    /// - `matched_tx_hashes`：本地已匹配的 tx_hash 列表
    /// - `missing_short_ids`：缺失的 short ID 列表（需请求完整 tx）
    pub fn receive_compact_vertex(
        &self,
        compact: &CompactVertex,
    ) -> PokerL1Result<(Vec<Hash>, Vec<ShortId>)> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        reconstruct_vertex_tx_hashes(compact, &state.short_id_map, &state.tx_cache)
    }

    /// 处理 compact vertex 的缺失 tx 回退（缺口 #8：Compact Block Relay 完整化）。
    ///
    /// `receive_compact_vertex` 返回的 `missing` short IDs 表示本地缺少的 tx。
    /// 此方法把缺失 tx 对应的 tx_hash（若 short_id_map 有映射）收集为 `RequestTx` 请求列表。
    /// 调用方（P2P handler）据此发送 `RequestTx(missing_hashes)` 给广播方。
    ///
    /// 返回 `(resolvable_hashes, unresolved_short_ids)`：
    /// - `resolvable_hashes`：short_id_map 有映射但本地无完整 tx 的 tx_hash（可请求）
    /// - `unresolved_short_ids`：short_id_map 无映射（需请求完整 vertex fallback）
    #[must_use]
    pub fn resolve_missing_txs(&self, missing_short_ids: &[ShortId]) -> (Vec<Hash>, Vec<ShortId>) {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut resolvable = Vec::new();
        let mut unresolved = Vec::new();
        for sid in missing_short_ids {
            match state.short_id_map.lookup(sid) {
                Some(tx_hash) => resolvable.push(tx_hash),
                None => unresolved.push(*sid),
            }
        }
        (resolvable, unresolved)
    }

    /// Return the locally cached transactions for an explicit set of hashes.
    ///
    /// The result keeps the request order and omits cache misses.  It is used
    /// exclusively to answer a peer's [`NetworkMessage::RequestTx`] during
    /// compact-vertex recovery; callers must still validate every returned
    /// transaction before admitting it to the node.
    #[must_use]
    pub fn cached_transactions(&self, hashes: &[Hash]) -> Vec<Transaction> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        hashes
            .iter()
            .filter_map(|hash| state.tx_cache.get(hash).cloned())
            .collect()
    }

    /// 取出缓冲中的 tx 用于装入下一个 vertex（SubTask 30.7）。
    ///
    /// 返回 `(txs, timeout_hashes)`：
    /// - `txs`：未超时的 tx 列表（应装入下一个 vertex）
    /// - `timeout_hashes`：超时的 tx 哈希列表（应记录并丢弃）
    pub fn drain_tx_for_vertex(&self) -> (Vec<Transaction>, Vec<Hash>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.tx_buf.drain_for_vertex()
    }

    /// 检查是否应 drain tx 缓冲（最早 tx 已超时或缓冲非空，SubTask 30.7）。
    #[must_use]
    pub fn should_drain_tx(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.tx_buf.should_drain()
    }

    /// 获取 short ID 映射表长度（测试用）。
    #[must_use]
    pub fn short_id_map_len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .short_id_map
            .len()
    }

    /// 检查 tx_cache 是否包含指定 hash（测试用）。
    #[must_use]
    pub fn tx_cache_contains(&self, tx_hash: &Hash) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tx_cache
            .contains_key(tx_hash)
    }

    /// 获取本地 tx 缓存条目数（测试用）。
    #[must_use]
    pub fn tx_cache_len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tx_cache
            .len()
    }
}

impl Default for GossipManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{CURRENT_VERSION, SignatureScheme};
    use crate::transaction::{Gas, RouteHint, TxLane};

    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        let raw = vec![byte; 33];
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw).unwrap_or_else(|_| {
            // fallback：直接构造
            TaggedPubkey {
                tag: 0x01,
                raw: vec![byte; 33],
            }
        })
    }

    #[test]
    fn proof_package_chunks_roundtrip_out_of_order() {
        let job_id = [0xA5; 32];
        let bytes: Vec<u8> = (0..(PROOF_PACKAGE_CHUNK_SIZE * 2 + 17))
            .map(|index| (index % 251) as u8)
            .collect();
        let transport = InMemoryTransport::new();
        transport
            .inject_proof_package(job_id, bytes.clone())
            .unwrap();

        let manifest = transport
            .request_proof_package_manifest(job_id)
            .unwrap()
            .unwrap();
        assert_eq!(manifest.chunk_count, 3);
        let mut assembler = ProofPackageAssembler::new(manifest.clone()).unwrap();
        for index in (0..manifest.chunk_count).rev() {
            let chunk = transport
                .request_proof_package_chunk(job_id, manifest.package_hash, index)
                .unwrap()
                .unwrap();
            assembler.insert(chunk.clone()).unwrap();
            assembler.insert(chunk).unwrap();
        }
        assert!(assembler.is_complete());
        assert_eq!(assembler.finish().unwrap(), bytes);
    }

    #[test]
    fn proof_package_sync_rejects_tampering_and_bad_bounds() {
        let job_id = [0x3C; 32];
        let bytes = vec![0x55; PROOF_PACKAGE_CHUNK_SIZE + 1];
        let manifest = build_proof_package_manifest(job_id, &bytes).unwrap();
        let mut chunk = build_proof_package_chunk(&manifest, &bytes, 0).unwrap();
        chunk.bytes[0] ^= 1;
        assert!(chunk.validate_against(&manifest).is_err());

        let mut bad_manifest = manifest.clone();
        bad_manifest.total_len = MAX_PROOF_PACKAGE_BYTES as u64 + 1;
        assert!(ProofPackageAssembler::new(bad_manifest).is_err());

        let mut assembler = ProofPackageAssembler::new(manifest.clone()).unwrap();
        let first = build_proof_package_chunk(&manifest, &bytes, 0).unwrap();
        assembler.insert(first).unwrap();
        let mut conflicting = build_proof_package_chunk(&manifest, &bytes, 0).unwrap();
        conflicting.bytes[0] ^= 1;
        conflicting.chunk_hash = proof_package_chunk_hash(
            conflicting.job_id,
            conflicting.package_hash,
            conflicting.index,
            &conflicting.bytes,
        );
        assert!(assembler.insert(conflicting).is_err());
    }

    #[test]
    fn proof_package_chunk_message_stays_below_node_frame_limit() {
        let bytes = vec![0x77; PROOF_PACKAGE_CHUNK_SIZE];
        let manifest = build_proof_package_manifest([0x11; 32], &bytes).unwrap();
        let chunk = build_proof_package_chunk(&manifest, &bytes, 0).unwrap();
        let encoded =
            borsh::to_vec(&NetworkMessage::ResponseProofPackageChunk(Some(chunk))).unwrap();
        assert!(encoded.len() < 2 * 1024 * 1024);
    }

    // ===== 大小校验测试（SubTask 30.6） =====

    #[test]
    fn test_short_id_deterministic() {
        let tx_hash = [0x42u8; 32];
        let sid1 = compute_short_id(&tx_hash);
        let sid2 = compute_short_id(&tx_hash);
        assert_eq!(sid1, sid2);
    }

    #[test]
    fn test_short_id_differs_by_tx_hash() {
        let h1 = [0x01u8; 32];
        let h2 = [0x02u8; 32];
        assert_ne!(compute_short_id(&h1), compute_short_id(&h2));
    }

    #[test]
    fn test_short_id_length() {
        let tx_hash = [0x42u8; 32];
        let sid = compute_short_id(&tx_hash);
        assert_eq!(sid.len(), SHORT_ID_LEN);
    }

    // ===== ShortIdMap 测试（SEC2-L3） =====

    #[test]
    fn test_short_id_map_insert_and_lookup() {
        let mut map = ShortIdMap::new();
        let tx_hash = [0x42u8; 32];
        let short_id = compute_short_id(&tx_hash);

        map.insert(short_id, tx_hash).unwrap();
        assert_eq!(map.lookup(&short_id), Some(tx_hash));
        assert!(!map.is_conflict(&short_id));
    }

    #[test]
    fn test_short_id_map_conflict_detection() {
        let mut map = ShortIdMap::new();
        let short_id = [0xAAu8; 8];
        let tx_hash1 = [0x01u8; 32];
        let tx_hash2 = [0x02u8; 32];

        // 第一次插入
        map.insert(short_id, tx_hash1).unwrap();
        assert_eq!(map.lookup(&short_id), Some(tx_hash1));

        // 第二次插入不同 tx_hash → 冲突
        map.insert(short_id, tx_hash2).unwrap();
        assert!(map.is_conflict(&short_id));
        // 冲突后 lookup 返回 None
        assert_eq!(map.lookup(&short_id), None);
        assert_eq!(map.conflict_count(), 1);
    }

    #[test]
    fn test_short_id_map_idempotent_insert() {
        let mut map = ShortIdMap::new();
        let short_id = [0xBBu8; 8];
        let tx_hash = [0x42u8; 32];

        // 重复插入相同 (short_id, tx_hash) → 幂等
        map.insert(short_id, tx_hash).unwrap();
        map.insert(short_id, tx_hash).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.lookup(&short_id), Some(tx_hash));
    }

    #[test]
    fn test_short_id_map_conflict_ignored_on_reinsert() {
        let mut map = ShortIdMap::new();
        let short_id = [0xCCu8; 8];

        // 制造冲突
        map.insert(short_id, [0x01u8; 32]).unwrap();
        map.insert(short_id, [0x02u8; 32]).unwrap();
        assert!(map.is_conflict(&short_id));

        // 冲突后再次插入 → 直接忽略
        map.insert(short_id, [0x03u8; 32]).unwrap();
        assert!(map.is_conflict(&short_id));
        assert_eq!(map.conflict_count(), 1);
    }

    // ===== CompactVertex 测试（SubTask 30.5） =====

    #[test]
    fn test_compact_vertex_from_vertex_preserves_header() {
        // 构造一个最小的 DagVertex
        let vertex = DagVertex {
            epoch: 1,
            round: 10,
            author_pubkey: make_tagged_pubkey(0x01),
            tx_list: vec![],
            parent_hashes: vec![[0xAA; 32]],
            author_sig: vec![0x42; 65],
        };
        let compact = CompactVertex::from_vertex(&vertex);
        assert_eq!(compact.epoch, 1);
        assert_eq!(compact.round, 10);
        assert_eq!(compact.parent_hashes, vec![[0xAA; 32]]);
        assert_eq!(compact.author_sig, vec![0x42; 65]);
        assert!(compact.tx_short_ids.is_empty());
    }

    // ===== TxBuf 测试（SubTask 30.7） =====

    #[test]
    fn test_tx_buf_push_and_drain() {
        let mut buf = TxBuf::new();
        assert!(buf.is_empty());

        // 创建一个最小 tx
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x01),
            signature: vec![0x42; 65],
            gas: Gas::default(),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::default(),
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };

        buf.push(tx);
        assert_eq!(buf.len(), 1);

        let (txs, timeout) = buf.drain_for_vertex();
        assert_eq!(txs.len(), 1);
        assert!(timeout.is_empty());
        assert!(buf.is_empty());
    }

    #[test]
    fn test_tx_buf_timeout() {
        // 使用极短窗口（1ms）测试超时
        let mut buf = TxBuf::with_window(Duration::from_millis(1));

        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x01),
            signature: vec![0x42; 65],
            gas: Gas::default(),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::default(),
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };

        buf.push(tx);
        // 等待超时
        std::thread::sleep(Duration::from_millis(5));

        let (txs, timeout) = buf.drain_for_vertex();
        assert!(txs.is_empty());
        assert_eq!(timeout.len(), 1);
    }

    // ===== 多副本广播测试（SubTask 30.8） =====

    #[test]
    fn test_multi_replica_broadcast_success() {
        let tx_hash = [0x42u8; 32];
        let replicas = vec![
            make_tagged_pubkey(0x10),
            make_tagged_pubkey(0x11),
            make_tagged_pubkey(0x12),
        ];
        let accepted = vec![make_tagged_pubkey(0x10)];
        let witnesses = vec![];
        let config = BroadcastConfig::default();

        let result = multi_replica_broadcast(tx_hash, &replicas, &accepted, &witnesses, &config);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().accepted_count, 1);
    }

    #[test]
    fn test_multi_replica_broadcast_all_failed() {
        let tx_hash = [0x42u8; 32];
        let replicas = vec![
            make_tagged_pubkey(0x10),
            make_tagged_pubkey(0x11),
            make_tagged_pubkey(0x12),
        ];
        let accepted = vec![];
        let witnesses = vec![];
        let config = BroadcastConfig::default();

        let result = multi_replica_broadcast(tx_hash, &replicas, &accepted, &witnesses, &config);
        assert!(matches!(
            result,
            Err(PokerL1Error::MultiReplicaBroadcastFailed { .. })
        ));
    }

    #[test]
    fn test_multi_replica_broadcast_with_witnesses() {
        let tx_hash = [0x42u8; 32];
        let replicas = vec![
            make_tagged_pubkey(0x10),
            make_tagged_pubkey(0x11),
            make_tagged_pubkey(0x12),
        ];
        let accepted = vec![make_tagged_pubkey(0x10)];
        let witnesses = vec![make_tagged_pubkey(0x11), make_tagged_pubkey(0x12)];
        let config = BroadcastConfig::default();

        let result = multi_replica_broadcast(tx_hash, &replicas, &accepted, &witnesses, &config);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.accepted_count, 1);
        assert_eq!(result.witness_signatures.len(), 2);
    }

    // ===== InMemoryTransport 测试（SubTask 30.1 / 30.3） =====

    #[test]
    fn test_in_memory_transport_gossip_broadcast() {
        let transport = InMemoryTransport::new();
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x01),
            signature: vec![0x42; 65],
            gas: Gas::default(),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::default(),
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };

        transport
            .gossip_broadcast(GossipTopic::Transaction, &NetworkMessage::Transaction(tx))
            .unwrap();

        let messages = transport.broadcasted_messages(GossipTopic::Transaction);
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn test_in_memory_transport_peer_discovery() {
        let transport = InMemoryTransport::new();
        let peer = PeerInfo {
            peer_id: "peer1".to_string(),
            address: "/ip4/127.0.0.1/tcp/4001".to_string(),
            validator_pubkey: Some(make_tagged_pubkey(0x01)),
        };
        transport.add_peer(peer.clone());

        let peers = transport.discover_peers().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0], peer);
    }

    // ===== GossipManager 测试（SubTask 30.5 / 30.7） =====

    #[test]
    fn test_gossip_manager_receive_tx() {
        let manager = GossipManager::new();
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x01),
            signature: vec![0x42; 65],
            gas: Gas::default(),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::default(),
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };

        manager.receive_tx(tx.clone()).unwrap();

        let tx_hash = tx.tx_hash();
        assert!(manager.tx_cache_contains(&tx_hash));
        assert_eq!(manager.short_id_map_len(), 1);
    }

    #[test]
    fn test_gossip_manager_cached_transactions_preserves_request_order() {
        let manager = GossipManager::new();
        let first = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x01),
            signature: vec![0x42; 65],
            gas: Gas::default(),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::default(),
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let mut second = first.clone();
        second.nonce = 2;
        let first_hash = first.tx_hash();
        let second_hash = second.tx_hash();
        manager.receive_tx(first).unwrap();
        manager.receive_tx(second).unwrap();

        let cached = manager.cached_transactions(&[[0xFF; 32], second_hash, first_hash]);
        assert_eq!(cached.len(), 2);
        assert_eq!(cached[0].tx_hash(), second_hash);
        assert_eq!(cached[1].tx_hash(), first_hash);
    }

    #[test]
    fn test_gossip_manager_drain_tx() {
        let manager = GossipManager::new();
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x01),
            signature: vec![0x42; 65],
            gas: Gas::default(),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::default(),
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };

        manager.receive_tx(tx).unwrap();
        let (txs, timeout) = manager.drain_tx_for_vertex();
        assert_eq!(txs.len(), 1);
        assert!(timeout.is_empty());
    }

    // ===== H7 修复测试：tx_cache FIFO 淘汰 =====

    /// H7：tx_cache 超限时淘汰最旧条目，防止内存 DoS。
    #[test]
    fn test_tx_cache_fifo_eviction() {
        let manager = GossipManager::with_max_tx_cache_size(3);
        let mut tx_hashes = Vec::new();

        for i in 1..=4u64 {
            let tx = Transaction {
                inputs: vec![],
                outputs: vec![],
                contract_call: None,
                tagged_pubkey: make_tagged_pubkey(0x01),
                signature: vec![0x42; 65],
                gas: Gas::default(),
                lane_hint: TxLane::Public,
                route_hint: RouteHint::default(),
                chain_id: crate::DEFAULT_CHAIN_ID,
                nonce: i,
                gameturn_nonce: None,
                is_fallback: false,
            };
            let h = tx.tx_hash();
            tx_hashes.push(h);
            manager.receive_tx(tx).unwrap();
        }

        // 缓存上限为 3，插入 4 条后应仅保留最新 3 条
        assert_eq!(manager.tx_cache_len(), 3, "tx_cache 应被淘汰至 max");
        assert!(
            !manager.tx_cache_contains(&tx_hashes[0]),
            "最旧 tx 应被淘汰"
        );
        assert!(manager.tx_cache_contains(&tx_hashes[1]));
        assert!(manager.tx_cache_contains(&tx_hashes[2]));
        assert!(manager.tx_cache_contains(&tx_hashes[3]));
    }

    /// H7：重复 tx_hash 不增加缓存条目数。
    #[test]
    fn test_tx_cache_dedup() {
        let manager = GossipManager::with_max_tx_cache_size(3);
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x01),
            signature: vec![0x42; 65],
            gas: Gas::default(),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::default(),
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };

        manager.receive_tx(tx.clone()).unwrap();
        manager.receive_tx(tx.clone()).unwrap();
        manager.receive_tx(tx).unwrap();

        assert_eq!(manager.tx_cache_len(), 1, "重复 tx 不应增加缓存条目");
    }

    // ===== 轻客户端 header 验证测试（SubTask 30.4） =====

    #[test]
    fn test_light_client_header_quorum_sufficient() {
        let header = LightClientHeader {
            header_bytes: vec![0x42; 100],
            signatures: vec![
                ValidatorSig {
                    validator: make_tagged_pubkey(0x01),
                    signature: vec![0; 65],
                },
                ValidatorSig {
                    validator: make_tagged_pubkey(0x02),
                    signature: vec![0; 65],
                },
                ValidatorSig {
                    validator: make_tagged_pubkey(0x03),
                    signature: vec![0; 65],
                },
            ],
            signer_bitmap: vec![true, true, true],
        };

        // validator_set_size = 3, required = 2*3/3+1 = 3（严格 >2/3，C-3 修复）
        // signatures = 3 >= 3 → 通过 quorum
        let validators = header
            .signatures
            .iter()
            .map(|signature| signature.validator.clone())
            .collect::<Vec<_>>();
        let result = verify_light_client_header(&header, &validators, |_, _, _| Ok(()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_light_client_header_quorum_insufficient() {
        let header = LightClientHeader {
            header_bytes: vec![0x42; 100],
            signatures: vec![ValidatorSig {
                validator: make_tagged_pubkey(0x01),
                signature: vec![0; 65],
            }],
            signer_bitmap: vec![true, false, false],
        };

        // validator_set_size = 3, required = 2*3/3+1 = 3（严格 >2/3，C-3 修复）
        // signatures = 1 < 3 → quorum 不足
        let validators = vec![
            header.signatures[0].validator.clone(),
            make_tagged_pubkey(0x02),
            make_tagged_pubkey(0x03),
        ];
        let result = verify_light_client_header(&header, &validators, |_, _, _| Ok(()));
        assert!(matches!(
            result,
            Err(PokerL1Error::LightClientQuorumInsufficient { .. })
        ));

        // An individually authenticated share is still useful to the bounded aggregation pool,
        // but cannot be exposed as a finalized header before the quorum arrives.
        assert_eq!(
            verify_light_client_header_signatures(&header, &validators, |_, _, _| Ok(())).unwrap(),
            1
        );
    }

    #[test]
    fn test_light_client_header_rejects_oversized_payload_before_signature_work() {
        let header = LightClientHeader {
            header_bytes: vec![0x42; MAX_LIGHT_CLIENT_HEADER_BYTES + 1],
            signatures: vec![],
            signer_bitmap: vec![],
        };
        let result = verify_light_client_header_signatures(&header, &[], |_, _, _| Ok(()));
        assert!(result.is_err());
    }

    #[test]
    fn test_light_client_header_signature_invalid() {
        let header = LightClientHeader {
            header_bytes: vec![0x42; 100],
            signatures: vec![
                ValidatorSig {
                    validator: make_tagged_pubkey(0x01),
                    signature: vec![0; 65],
                },
                ValidatorSig {
                    validator: make_tagged_pubkey(0x02),
                    signature: vec![0; 65],
                },
                ValidatorSig {
                    validator: make_tagged_pubkey(0x03),
                    signature: vec![0; 65],
                },
            ],
            signer_bitmap: vec![true, true, true],
        };

        // quorum 足够（3 >= 3，C-3 修复）但签名验证失败
        let validators = header
            .signatures
            .iter()
            .map(|signature| signature.validator.clone())
            .collect::<Vec<_>>();
        let result = verify_light_client_header(&header, &validators, |_, _, _| {
            Err(PokerL1Error::InvalidSignature)
        });
        assert!(matches!(result, Err(PokerL1Error::InvalidSignature)));
    }

    // ===== 常量验证测试 =====

    #[test]
    fn test_size_limits() {
        assert_eq!(MAX_BLOCK_SIZE, 4 * 1024 * 1024);
        assert_eq!(MAX_TX_SIZE, 128 * 1024);
        assert_eq!(MAX_VERTEX_SIZE, 256 * 1024);
        assert_eq!(SHORT_ID_LEN, 8);
        assert_eq!(MEMPOOL_BUFFER_WINDOW_MS, 100);
        assert_eq!(SHORT_ID_MAP_LIMIT, 100_000);
    }

    #[test]
    fn test_resolve_missing_txs_separates_resolvable_and_unresolved() {
        // 缺口 #8：compact relay 缺失 tx 回退测试。
        let gm = GossipManager::new();
        // 插入两个 tx 到 short_id_map（通过 receive_compact 或直接 insert）。
        let tx_hash1 = [0x11u8; 32];
        let tx_hash2 = [0x22u8; 32];
        let sid1 = compute_short_id(&tx_hash1);
        let sid2 = compute_short_id(&tx_hash2);
        let unknown_sid = [0xFFu8; 8]; // 不在 map 中的 short_id
        {
            let mut state = gm.state.lock().unwrap();
            state.short_id_map.insert(sid1, tx_hash1).unwrap();
            state.short_id_map.insert(sid2, tx_hash2).unwrap();
        }
        // 传入 [sid1, sid2, unknown_sid] → 前两个可解析，最后一个不可解析。
        let (resolvable, unresolved) = gm.resolve_missing_txs(&[sid1, sid2, unknown_sid]);
        assert_eq!(resolvable.len(), 2, "sid1/sid2 应可解析为 tx_hash");
        assert!(resolvable.contains(&tx_hash1));
        assert!(resolvable.contains(&tx_hash2));
        assert_eq!(unresolved.len(), 1, "unknown_sid 不可解析");
        assert_eq!(unresolved[0], unknown_sid);
    }
}
