//! DagVertexStore（SubTask 4.3 — DAG vertex 持久化存储）
//!
//! 功能：
//! - 按 `vertex_hash` 存取 `DagVertex`
//! - 按 `(epoch, round)` 索引到 vertex_hash 列表（同一 round 多 validator 各自一个 vertex）
//! - 按 `author_pubkey` 索引到 vertex_hash 列表（查询某 validator 历史）
//!
//! RocksDB 列族：
//! - `vertices`：key = `vertex_hash`（32 字节） → value = `BCS(DagVertex)`
//! - `round_index`：key = `epoch_le || round_le`（16 字节） → value = `BCS(Vec<Hash>)`
//! - `author_index`：key = `tag || raw_pubkey_bytes`（tagged pubkey 编码） → value = `BCS(Vec<Hash>)`
//!
//! 注意：tagged_pubkey 序列化为 `tag || raw_bytes`（参考 `src/signature/tagged_pubkey.rs`）。

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rocksdb::{ColumnFamilyDescriptor, DB, IteratorMode, Options, WriteBatch};

use crate::Hash;
use crate::consensus::{DagVertex, Epoch, Round};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;

/// `vertices` 列族名。
const VERTICES_CF: &str = "vertices";
/// `round_index` 列族名。
const ROUND_INDEX_CF: &str = "round_index";
/// `author_index` 列族名。
const AUTHOR_INDEX_CF: &str = "author_index";

/// DAG vertex 存储（RocksDB 后端）。
///
/// 支持按 hash / round / author 三维查询。`put` 用 WriteBatch 保证 vertex 与
/// 两个索引原子写入，并用进程内写锁串行化索引的 read-modify-write。
pub struct DagVertexStore {
    /// RocksDB 句柄（3 个 CF）。
    db: Arc<DB>,
    /// 串行化跨 CF 的 check/read/modify/write，防止并发 P2P writer 丢失索引更新。
    write_lock: Mutex<()>,
}

impl DagVertexStore {
    /// 打开（或创建）指定路径下的 DagVertexStore。
    pub fn open(path: impl AsRef<Path>) -> PokerL1Result<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let vertices_cf = ColumnFamilyDescriptor::new(VERTICES_CF, Options::default());
        let round_cf = ColumnFamilyDescriptor::new(ROUND_INDEX_CF, Options::default());
        let author_cf = ColumnFamilyDescriptor::new(AUTHOR_INDEX_CF, Options::default());

        let db = DB::open_cf_descriptors(&db_opts, path, vec![vertices_cf, round_cf, author_cf])
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;

        Ok(Self {
            db: Arc::new(db),
            write_lock: Mutex::new(()),
        })
    }

    /// 打开一个临时目录下的 DagVertexStore（用于测试 / 开发）。
    pub fn open_inmemory() -> PokerL1Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "poker_l1_dagvertexstore_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        Self::open(path)
    }

    /// 获取 `vertices` CF 句柄。
    fn vertices_cf(&self) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(VERTICES_CF)
            .expect("vertices CF 必须存在（由 open 创建）")
    }

    /// 获取 `round_index` CF 句柄。
    fn round_cf(&self) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(ROUND_INDEX_CF)
            .expect("round_index CF 必须存在（由 open 创建）")
    }

    /// 获取 `author_index` CF 句柄。
    fn author_cf(&self) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(AUTHOR_INDEX_CF)
            .expect("author_index CF 必须存在（由 open 创建）")
    }

    /// 编码 `round_index` 的 key：`epoch_le || round_le`（16 字节）。
    fn round_key(epoch: Epoch, round: Round) -> [u8; 16] {
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&epoch.to_le_bytes());
        key[8..].copy_from_slice(&round.to_le_bytes());
        key
    }

    /// 写入 vertex。原子地更新 `vertices` + `round_index` + `author_index`（WriteBatch）。
    ///
    /// 返回该 vertex 的 `vertex_hash`。重复写入同一 hash 是幂等的（不重复追加到索引）。
    pub fn put(&self, vertex: &DagVertex) -> PokerL1Result<Hash> {
        let hash = vertex.vertex_hash();
        let _write_guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        // 幂等优化：已存在则直接返回，不重复追加索引
        if self.exists(&hash)? {
            return Ok(hash);
        }

        let vertex_bytes = borsh::to_vec(vertex)?;
        let round_key = Self::round_key(vertex.epoch, vertex.round);
        let author_key = vertex.author_pubkey.to_bytes();

        // read-modify-write 两个索引；由 write_lock 保证同进程内不会发生 lost update。
        let mut round_list: Vec<Hash> = self
            .db
            .get_cf(self.round_cf(), round_key)
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?
            .map(|v| borsh::from_slice(&v))
            .transpose()?
            .unwrap_or_default();
        round_list.push(hash);

        let mut author_list: Vec<Hash> = self
            .db
            .get_cf(self.author_cf(), &author_key)
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?
            .map(|v| borsh::from_slice(&v))
            .transpose()?
            .unwrap_or_default();
        author_list.push(hash);

        let round_list_bytes = borsh::to_vec(&round_list)?;
        let author_list_bytes = borsh::to_vec(&author_list)?;

        // 原子写入三个 CF
        let mut batch = WriteBatch::default();
        batch.put_cf(self.vertices_cf(), hash, &vertex_bytes);
        batch.put_cf(self.round_cf(), round_key, &round_list_bytes);
        batch.put_cf(self.author_cf(), &author_key, &author_list_bytes);
        self.db
            .write(batch)
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;

        Ok(hash)
    }

    /// 按 `vertex_hash` 查询 vertex。不存在返回 `DagVertexNotFound`。
    pub fn get_by_hash(&self, hash: &Hash) -> PokerL1Result<DagVertex> {
        let bytes = self
            .db
            .get_cf(self.vertices_cf(), hash)
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?
            .ok_or(PokerL1Error::DagVertexNotFound)?;
        let vertex: DagVertex = borsh::from_slice(&bytes)?;
        Ok(vertex)
    }

    /// 按 `(epoch, round)` 查询所有 vertex（同一 round 多 validator 各自一个 vertex）。
    ///
    /// 不存在该 round 时返回空 Vec。
    pub fn get_by_round(&self, epoch: Epoch, round: Round) -> PokerL1Result<Vec<DagVertex>> {
        let key = Self::round_key(epoch, round);
        let hash_list: Vec<Hash> = self
            .db
            .get_cf(self.round_cf(), key)
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?
            .map(|v| borsh::from_slice(&v))
            .transpose()?
            .unwrap_or_default();

        let mut vertices = Vec::with_capacity(hash_list.len());
        for h in &hash_list {
            vertices.push(self.get_by_hash(h)?);
        }
        Ok(vertices)
    }

    /// 按 `author_pubkey` 查询该 validator 的所有历史 vertex。
    ///
    /// 不存在该 author 时返回空 Vec。
    pub fn get_by_author(&self, author: &TaggedPubkey) -> PokerL1Result<Vec<DagVertex>> {
        let key = author.to_bytes();
        let hash_list: Vec<Hash> = self
            .db
            .get_cf(self.author_cf(), &key)
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?
            .map(|v| borsh::from_slice(&v))
            .transpose()?
            .unwrap_or_default();

        let mut vertices = Vec::with_capacity(hash_list.len());
        for h in &hash_list {
            vertices.push(self.get_by_hash(h)?);
        }
        Ok(vertices)
    }

    /// 判断指定 `vertex_hash` 是否已存在。
    pub fn exists(&self, hash: &Hash) -> PokerL1Result<bool> {
        self.db
            .get_cf(self.vertices_cf(), hash)
            .map(|v| v.is_some())
            .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))
    }

    /// 当前存储的 vertex 数量（遍历 `vertices` CF 计数）。
    pub fn len(&self) -> PokerL1Result<usize> {
        let iter = self.db.iterator_cf(self.vertices_cf(), IteratorMode::Start);
        let mut count = 0usize;
        for item in iter {
            item.map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
            count += 1;
        }
        Ok(count)
    }

    /// 是否为空。
    pub fn is_empty(&self) -> PokerL1Result<bool> {
        Ok(self.len()? == 0)
    }

    /// 裁剪旧 DAG vertex（缺口 #4：State Pruning）。
    ///
    /// 删除 epoch < `prune_below_epoch` 的所有 vertex（`vertices` + `round_index` + `author_index` CF）。
    /// Archive 节点不调用此方法。
    ///
    /// 返回裁剪的 vertex 数量。
    pub fn prune_old_vertices(&self, prune_below_epoch: Epoch) -> PokerL1Result<usize> {
        let _write_guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        // 遍历 round_index（key = epoch_le || round_le），收集 epoch < prune_below_epoch 的 vertex hash。
        let iter = self.db.iterator_cf(self.round_cf(), IteratorMode::Start);
        let mut to_delete: Vec<([u8; 16], Vec<Hash>)> = Vec::new();
        for item in iter {
            let (key, value) = item.map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
            if key.len() == 16 {
                let epoch = u64::from_le_bytes(key[..8].try_into().unwrap());
                if epoch < prune_below_epoch {
                    // value = Vec<Hash>（round_index 存该轮所有 vertex hash）
                    let hashes: Vec<Hash> = borsh::from_slice(&value)?;
                    to_delete.push((key.as_ref().try_into().unwrap(), hashes));
                }
            }
        }
        let mut count = 0usize;
        if !to_delete.is_empty() {
            let deleted_hashes: HashSet<Hash> = to_delete
                .iter()
                .flat_map(|(_, hashes)| hashes.iter().copied())
                .collect();
            let mut batch = WriteBatch::default();
            for (round_key, hashes) in &to_delete {
                for hash in hashes {
                    batch.delete_cf(self.vertices_cf(), hash);
                    count += 1;
                }
                batch.delete_cf(self.round_cf(), round_key);
            }

            // author_index 必须同步清理，否则 get_by_author 会追到已删除 vertex 并报错。
            let author_iter = self.db.iterator_cf(self.author_cf(), IteratorMode::Start);
            for item in author_iter {
                let (author_key, value) = item.map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
                let mut hashes: Vec<Hash> = borsh::from_slice(&value)?;
                let original_len = hashes.len();
                hashes.retain(|hash| !deleted_hashes.contains(hash));
                if hashes.len() == original_len {
                    continue;
                }
                if hashes.is_empty() {
                    batch.delete_cf(self.author_cf(), &author_key);
                } else {
                    batch.put_cf(self.author_cf(), &author_key, borsh::to_vec(&hashes)?);
                }
            }
            self.db
                .write(batch)
                .map_err(|e| PokerL1Error::Rocksdb(e.to_string()))?;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

    fn make_pubkey(byte: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![byte; 33],
        }
    }

    fn make_vertex(epoch: Epoch, round: Round, author_byte: u8, salt: u8) -> DagVertex {
        DagVertex {
            epoch,
            round,
            author_pubkey: make_pubkey(author_byte),
            tx_list: vec![],
            parent_hashes: vec![[salt; 32]],
            author_sig: vec![0u8; 65],
        }
    }

    #[test]
    fn open_creates_cfs() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        assert!(store.db.cf_handle(VERTICES_CF).is_some());
        assert!(store.db.cf_handle(ROUND_INDEX_CF).is_some());
        assert!(store.db.cf_handle(AUTHOR_INDEX_CF).is_some());
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn put_and_get_by_hash() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        let v = make_vertex(1, 10, 0x02, 0xAA);
        let hash = store.put(&v).unwrap();

        let recovered = store.get_by_hash(&hash).unwrap();
        assert_eq!(recovered, v);
    }

    #[test]
    fn get_missing_hash_returns_vertex_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        let err = store.get_by_hash(&[0x11u8; 32]).unwrap_err();
        assert!(matches!(err, PokerL1Error::DagVertexNotFound));
    }

    #[test]
    fn exists_returns_true_after_put() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        let v = make_vertex(1, 10, 0x02, 0xAA);
        let hash = store.put(&v).unwrap();

        assert!(store.exists(&hash).unwrap());
        assert!(!store.exists(&[0x22u8; 32]).unwrap());
    }

    #[test]
    fn get_by_round_returns_all_vertices_in_round() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        // 同一 (epoch=1, round=10) 下 3 个不同 author 的 vertex
        let v1 = make_vertex(1, 10, 0x02, 0x01);
        let v2 = make_vertex(1, 10, 0x03, 0x02);
        let v3 = make_vertex(1, 10, 0x04, 0x03);
        store.put(&v1).unwrap();
        store.put(&v2).unwrap();
        store.put(&v3).unwrap();

        let vertices = store.get_by_round(1, 10).unwrap();
        assert_eq!(vertices.len(), 3);
        // 验证三个 vertex 都在其中（顺序按插入顺序）
        let hashes: Vec<Hash> = vertices.iter().map(|v| v.vertex_hash()).collect();
        assert!(hashes.contains(&v1.vertex_hash()));
        assert!(hashes.contains(&v2.vertex_hash()));
        assert!(hashes.contains(&v3.vertex_hash()));
    }

    #[test]
    fn get_by_round_empty_when_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        let vertices = store.get_by_round(99, 99).unwrap();
        assert!(vertices.is_empty());
    }

    #[test]
    fn get_by_author_returns_all_vertices_by_author() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        // 同一 author 在不同 round 下的 3 个 vertex
        let v1 = make_vertex(1, 10, 0x02, 0x01);
        let v2 = make_vertex(1, 11, 0x02, 0x02);
        let v3 = make_vertex(1, 12, 0x02, 0x03);
        store.put(&v1).unwrap();
        store.put(&v2).unwrap();
        store.put(&v3).unwrap();

        let author = make_pubkey(0x02);
        let vertices = store.get_by_author(&author).unwrap();
        assert_eq!(vertices.len(), 3);
    }

    #[test]
    fn get_by_author_empty_when_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        let author = make_pubkey(0xEE);
        let vertices = store.get_by_author(&author).unwrap();
        assert!(vertices.is_empty());
    }

    #[test]
    fn len_counts_vertices() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        assert_eq!(store.len().unwrap(), 0);

        store.put(&make_vertex(1, 10, 0x02, 0x01)).unwrap();
        assert_eq!(store.len().unwrap(), 1);

        store.put(&make_vertex(1, 11, 0x03, 0x02)).unwrap();
        store.put(&make_vertex(2, 12, 0x04, 0x03)).unwrap();
        assert_eq!(store.len().unwrap(), 3);
    }

    #[test]
    fn put_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        let v = make_vertex(1, 10, 0x02, 0xAA);

        let h1 = store.put(&v).unwrap();
        let h2 = store.put(&v).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(store.len().unwrap(), 1, "幂等写入不应增加计数");

        // 索引不应重复追加
        let round_vertices = store.get_by_round(1, 10).unwrap();
        assert_eq!(round_vertices.len(), 1);
        let author_vertices = store.get_by_author(&make_pubkey(0x02)).unwrap();
        assert_eq!(author_vertices.len(), 1);
    }

    #[test]
    fn different_rounds_indexed_separately() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        // 不同 round 的 vertex 不应混在同一索引项
        store.put(&make_vertex(1, 10, 0x02, 0x01)).unwrap();
        store.put(&make_vertex(1, 11, 0x03, 0x02)).unwrap();
        store.put(&make_vertex(1, 11, 0x04, 0x03)).unwrap();

        assert_eq!(store.get_by_round(1, 10).unwrap().len(), 1);
        assert_eq!(store.get_by_round(1, 11).unwrap().len(), 2);
        assert_eq!(store.get_by_round(1, 12).unwrap().len(), 0);
    }

    #[test]
    fn different_epochs_indexed_separately() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        // 同 round 但不同 epoch 的 vertex 不应混在同一索引项
        store.put(&make_vertex(1, 10, 0x02, 0x01)).unwrap();
        store.put(&make_vertex(2, 10, 0x03, 0x02)).unwrap();

        assert_eq!(store.get_by_round(1, 10).unwrap().len(), 1);
        assert_eq!(store.get_by_round(2, 10).unwrap().len(), 1);
    }

    #[test]
    fn open_inmemory_works() {
        let store = DagVertexStore::open_inmemory().unwrap();
        let v = make_vertex(1, 10, 0x02, 0xAA);
        let hash = store.put(&v).unwrap();
        let recovered = store.get_by_hash(&hash).unwrap();
        assert_eq!(recovered, v);
    }

    #[test]
    fn persist_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = make_vertex(1, 10, 0x02, 0x01);
        let v2 = make_vertex(1, 11, 0x03, 0x02);
        let (h1, h2) = {
            let store = DagVertexStore::open(dir.path()).unwrap();
            let h1 = store.put(&v1).unwrap();
            let h2 = store.put(&v2).unwrap();
            (h1, h2)
        };

        let store2 = DagVertexStore::open(dir.path()).unwrap();
        assert_eq!(store2.len().unwrap(), 2);
        assert_eq!(store2.get_by_hash(&h1).unwrap(), v1);
        assert_eq!(store2.get_by_hash(&h2).unwrap(), v2);

        // 索引也应持久化
        assert_eq!(store2.get_by_round(1, 10).unwrap().len(), 1);
        assert_eq!(store2.get_by_round(1, 11).unwrap().len(), 1);
        assert_eq!(store2.get_by_author(&make_pubkey(0x02)).unwrap().len(), 1);
        assert_eq!(store2.get_by_author(&make_pubkey(0x03)).unwrap().len(), 1);
    }

    #[test]
    fn large_batch_persists() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        // 5 epoch × 10 round × 3 author = 150 vertices
        for epoch in 1..=5u64 {
            for round in 1..=10u64 {
                for author_byte in 0x02..=0x04u8 {
                    let v = make_vertex(
                        epoch,
                        round,
                        author_byte,
                        ((epoch * 100 + round) % 255) as u8,
                    );
                    store.put(&v).unwrap();
                }
            }
        }
        assert_eq!(store.len().unwrap(), 150);

        // 每个 (epoch, round) 应有 3 个 vertex
        for epoch in 1..=5u64 {
            for round in 1..=10u64 {
                assert_eq!(store.get_by_round(epoch, round).unwrap().len(), 3);
            }
        }
        // 每个 author 应有 50 个 vertex
        for author_byte in 0x02..=0x04u8 {
            assert_eq!(
                store
                    .get_by_author(&make_pubkey(author_byte))
                    .unwrap()
                    .len(),
                50
            );
        }
    }

    #[test]
    fn concurrent_puts_preserve_every_round_and_author_index_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DagVertexStore::open(dir.path()).unwrap());
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let mut threads = Vec::new();
        for index in 0..16u8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                let vertex = make_vertex(7, 9, index + 2, index + 1);
                barrier.wait();
                store.put(&vertex).unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(store.len().unwrap(), 16);
        assert_eq!(store.get_by_round(7, 9).unwrap().len(), 16);
        for index in 0..16u8 {
            assert_eq!(
                store.get_by_author(&make_pubkey(index + 2)).unwrap().len(),
                1
            );
        }
    }

    #[test]
    fn pruning_uses_borsh_and_cleans_author_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let store = DagVertexStore::open(dir.path()).unwrap();
        let old_same_author = make_vertex(1, 10, 0x02, 0x11);
        let old_other_author = make_vertex(2, 11, 0x03, 0x22);
        let retained_same_author = make_vertex(3, 12, 0x02, 0x33);
        let old_same_hash = store.put(&old_same_author).unwrap();
        let old_other_hash = store.put(&old_other_author).unwrap();
        store.put(&retained_same_author).unwrap();

        assert_eq!(store.prune_old_vertices(3).unwrap(), 2);
        assert!(matches!(
            store.get_by_hash(&old_same_hash),
            Err(PokerL1Error::DagVertexNotFound)
        ));
        assert!(matches!(
            store.get_by_hash(&old_other_hash),
            Err(PokerL1Error::DagVertexNotFound)
        ));
        assert!(store.get_by_round(1, 10).unwrap().is_empty());
        assert!(store.get_by_round(2, 11).unwrap().is_empty());
        assert_eq!(store.get_by_round(3, 12).unwrap().len(), 1);

        let same_author = store.get_by_author(&make_pubkey(0x02)).unwrap();
        assert_eq!(same_author, vec![retained_same_author]);
        assert!(store.get_by_author(&make_pubkey(0x03)).unwrap().is_empty());
    }
}
