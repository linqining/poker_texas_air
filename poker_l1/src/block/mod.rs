//! 区块结构（Task 3 / SubTask 3.1 + 3.4）
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **NEW-M14**：block header 含 `height` / `timestamp_ms` / `prev_hash` / object/account state roots /
//!   `public_tx_root`（Public 通道 tx 的 Merkle root）/ `gameturn_tx_root`（GameTurn + CheckpointAnchor
//!   通道 tx 的 Merkle root）/ `dag_commit_certificate`，拆分为两个独立 tx_root 以支持双通道独立验证
//! - **SubTask 3.4**：区块哈希与链式链接（prev_hash 字段形成 hash chain）
//!
//! Phase 1 定义数据结构 + 哈希计算；
//! Phase 2 实现时间共识（timestamp 单调性校验）与 block 投影逻辑。

/// 时间共识（Task 11）：block 时间校验 + 超时参数配置 + 轻客户端 quorum 骨架。
pub mod time_consensus;
/// Block 验证器（Task 10）：tx 签名 / chain_id / nonce / GameTurn 免 gas / 多签验证。
pub mod validator;

// 重新导出 time_consensus 公开 API，便于上层直接 `block::TimeConsensusConfig` 等使用。
pub use time_consensus::{
    LightClientVerifyRequest, TimeConsensusConfig, epoch_of, in_epoch_transition_window,
    is_da_window_passed, is_dispute_window_passed, is_epoch_boundary, is_hand_timeout,
    is_submit_phase_timed_out, is_turn_timeout, is_validator_timeout, should_submit_checkpoint,
    validate_block_time, verify_block_header_quorum,
};

// 重新导出 validator 模块公开 API（Task 10）。
pub use validator::{
    BlockValidatorConfig, validate_block_header_and_body, validate_block_tx_roots,
    validate_commit_certificate_signatures, validate_commit_certificate_signatures_for_header,
    validate_game_sub_block, validate_game_sub_block_signature,
    validate_game_sub_block_turn_ordering, validate_gameturn_no_gas, validate_gameturn_tx_root,
    validate_public_tx_ordering, validate_public_tx_root, validate_state_root_transition,
    validate_tx_chain_id, validate_tx_full, validate_tx_nonce, validate_tx_signature,
    validate_vertex_tx_ordering,
};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::consensus::DagCommitCertificate;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::transaction::Transaction;
use crate::{BlockHeight, Hash, TimestampMs};

/// 签名域分隔前缀。
const BLOCK_HEADER_DOMAIN: u8 = 0x42; // 'B' for Block

/// 区块头（NEW-M14：双 tx_root）。
///
/// spec：
/// - `height`：严格单调递增（genesis = 0）
/// - `timestamp_ms`：权威时间戳（单调不减 + 最大间隔约束，Phase 2 校验）
/// - `prev_hash`：前一个 block 的 hash（链式链接）
/// - `state_root`：全局对象 Sparse Merkle Root
/// - `account_root`：账户余额、resource credit、nonce 的 Sparse Merkle Root
/// - `public_tx_root`：Public 通道 tx 的 Merkle root
/// - `gameturn_tx_root`：GameTurn + CheckpointAnchor 通道 tx 的 Merkle root
/// - `dag_commit_certificate`：Bullshark commit certificate（含 2/3 secp256k1 多签）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BlockHeader {
    /// 区块高度（严格单调递增，genesis = 0）。
    pub height: BlockHeight,
    /// 权威时间戳（毫秒，单调不减）。
    pub timestamp_ms: TimestampMs,
    /// 前一个 block 的 hash（链式链接）。
    pub prev_hash: Hash,
    /// 全局对象 Sparse Merkle Root。
    pub state_root: Hash,
    /// AccountStore sparse-Merkle root (balances, resource credits and replay nonces).
    pub account_root: Hash,
    /// Public 通道 tx 的 Merkle root（NEW-M14）。
    pub public_tx_root: Hash,
    /// GameTurn + CheckpointAnchor 通道 tx 的 Merkle root（NEW-M14）。
    pub gameturn_tx_root: Hash,
    /// Bullshark commit certificate（含 2/3 secp256k1 多签）。
    pub dag_commit_certificate: DagCommitCertificate,
}

impl BlockHeader {
    /// 计算区块头哈希（block_hash）。
    ///
    /// block_hash = blake2b_256(0x42 || height || timestamp_ms || prev_hash
    ///                       || state_root || account_root || public_tx_root || gameturn_tx_root
    ///                       || dag_commit_certificate)
    ///
    /// 注意：dag_commit_certificate 用其 cert_hash 摘要参与计算（避免重复序列化整个证书）。
    pub fn block_hash(&self, chain_id: crate::ChainId) -> Hash {
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&[BLOCK_HEADER_DOMAIN]);
        h.update(&chain_id.to_le_bytes());
        h.update(&self.height.to_le_bytes());
        h.update(&self.timestamp_ms.to_le_bytes());
        h.update(&self.prev_hash);
        h.update(&self.state_root);
        h.update(&self.account_root);
        h.update(&self.public_tx_root);
        h.update(&self.gameturn_tx_root);
        // 用绑定当前 header 位置的 cert_hash 摘要参与计算，防止证书被移植到另一条
        // height/timestamp/parent 链上。
        let cert_hash = self.dag_commit_certificate.cert_hash_for_header(
            chain_id,
            self.height,
            self.timestamp_ms,
            self.prev_hash,
        );
        h.update(&cert_hash);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }
}

/// 区块（header + body）。
///
/// spec：block 不需要单独 production，而是 DAG commit 的投影。
/// body 含两个通道的 tx 列表（public_txs / gameturn_txs）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Block {
    /// 区块头。
    pub header: BlockHeader,
    /// Public 通道 tx 列表（转账、合约调用、bridge 操作等）。
    pub public_txs: Vec<Transaction>,
    /// GameTurn + CheckpointAnchor 通道 tx 列表（游戏操作、checkpoint）。
    pub gameturn_txs: Vec<Transaction>,
}

impl Block {
    /// 创建新区块。
    pub const fn new(
        header: BlockHeader,
        public_txs: Vec<Transaction>,
        gameturn_txs: Vec<Transaction>,
    ) -> Self {
        Self {
            header,
            public_txs,
            gameturn_txs,
        }
    }

    /// 计算区块哈希（委托给 header）。
    pub fn block_hash(&self, chain_id: crate::ChainId) -> Hash {
        self.header.block_hash(chain_id)
    }

    /// 计算 Public 通道 tx 的 Merkle root。
    ///
    /// 使用 Sparse Merkle Tree（IMPL-SEC-3），key = blake2b_256(tx_hash)。
    /// 空列表返回空树根。
    pub fn compute_public_tx_root(&self) -> Hash {
        compute_tx_merkle_root(&self.public_txs)
    }

    /// 计算 GameTurn 通道 tx 的 Merkle root。
    pub fn compute_gameturn_tx_root(&self) -> Hash {
        compute_tx_merkle_root(&self.gameturn_txs)
    }

    /// Return the only valid block execution order.
    ///
    /// The two body lanes have independent Merkle commitments but do not execute
    /// independently: S9 requires all GameTurn / CheckpointAnchor transactions before the
    /// Public / ForceSync lane.  Producers and validators must use this helper instead of
    /// replaying only one lane.
    #[must_use]
    pub fn canonical_execution_txs(&self) -> Vec<Transaction> {
        self.gameturn_txs
            .iter()
            .chain(&self.public_txs)
            .cloned()
            .collect()
    }

    /// BCS 序列化。
    pub fn to_bcs(&self) -> crate::error::PokerL1Result<Vec<u8>> {
        Ok(borsh::to_vec(self)?)
    }

    /// 从 BCS 反序列化。
    pub fn from_bcs(bytes: &[u8]) -> crate::error::PokerL1Result<Self> {
        Ok(borsh::from_slice(bytes)?)
    }
}

/// 计算 tx 列表的 Merkle root（使用 Sparse Merkle Tree，IMPL-SEC-3）。
///
/// key = blake2b_256(tx_hash)，value = tx_hash。
/// 空列表返回空树根。
pub fn compute_tx_merkle_root(txs: &[Transaction]) -> Hash {
    let mut smt = crate::object_model::SparseMerkleTree::new();
    for tx in txs {
        let tx_hash = tx.tx_hash();
        // key = blake2b_256(tx_hash)
        let mut key_h = Blake2bVar::new(32).expect("32 <= 64");
        key_h.update(&tx_hash);
        let mut key = [0u8; 32];
        key_h.finalize_variable(&mut key).expect("32 <= 64");
        // value = tx_hash
        smt.upsert(key, &tx_hash);
    }
    smt.root()
}

/// 轻客户端交易包含性验证（缺口 #6：Light Client Protocol）。
///
/// 验证某 tx_hash 是否包含在给定 Merkle root 对应的 tx 集合中。
/// 轻客户端无需下载完整 block body，仅凭 `(tx_hash, merkle_proof, expected_root)` 即可验证。
pub fn verify_tx_inclusion(
    tx_hash: &Hash,
    merkle_proof: &crate::object_model::MerklePath,
    expected_root: &Hash,
) -> PokerL1Result<()> {
    let mut key_h = Blake2bVar::new(32).expect("32 <= 64");
    key_h.update(tx_hash);
    let mut key = [0u8; 32];
    key_h.finalize_variable(&mut key).expect("32 <= 64");
    if crate::object_model::SparseMerkleTree::verify(
        expected_root,
        &key,
        Some(tx_hash),
        merkle_proof,
    ) {
        Ok(())
    } else {
        Err(PokerL1Error::Other(
            "tx inclusion proof verification failed".to_string(),
        ))
    }
}

/// 生成交易包含性证明（供全节点为轻客户端构造证明）。返回 `(proof, root)`。
#[must_use]
pub fn prove_tx_inclusion(
    txs: &[Transaction],
    target_tx_hash: &Hash,
) -> Option<(crate::object_model::MerklePath, Hash)> {
    let mut smt = crate::object_model::SparseMerkleTree::new();
    for tx in txs {
        let tx_hash = tx.tx_hash();
        let mut key_h = Blake2bVar::new(32).expect("32 <= 64");
        key_h.update(&tx_hash);
        let mut key = [0u8; 32];
        key_h.finalize_variable(&mut key).expect("32 <= 64");
        smt.upsert(key, &tx_hash);
    }
    let root = smt.root();
    let mut key_h = Blake2bVar::new(32).expect("32 <= 64");
    key_h.update(target_tx_hash);
    let mut key = [0u8; 32];
    key_h.finalize_variable(&mut key).expect("32 <= 64");
    let proof = smt.prove(&key);
    Some((proof, root))
}

/// Genesis block 辅助函数（Phase 1 用于测试与初始化）。
///
/// spec：genesis height = 0，prev_hash = [0; 32]，state_root = 空树根。
pub fn genesis_block(
    timestamp_ms: TimestampMs,
    state_root: Hash,
    dag_commit_certificate: DagCommitCertificate,
) -> Block {
    let header = BlockHeader {
        height: 0,
        timestamp_ms,
        prev_hash: [0u8; 32],
        state_root,
        account_root: crate::object_model::SparseMerkleTree::new().root(),
        public_tx_root: compute_tx_merkle_root(&[]),
        gameturn_tx_root: compute_tx_merkle_root(&[]),
        dag_commit_certificate,
    };
    Block::new(header, vec![], vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::DagCommitCertificate;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{Gas, RouteHint, TxLane};

    fn dummy_tagged_pubkey() -> crate::signature::TaggedPubkey {
        crate::signature::TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![0x02u8; 33],
        }
    }

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

    fn dummy_tx(nonce: u64) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: dummy_tagged_pubkey(),
            signature: vec![0u8; 65],
            gas: Gas::new(1000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    fn dummy_header(height: BlockHeight, prev_hash: Hash) -> BlockHeader {
        BlockHeader {
            height,
            timestamp_ms: height * 1000,
            prev_hash,
            state_root: [0u8; 32],
            account_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            dag_commit_certificate: dummy_commit_cert(),
        }
    }

    #[test]
    fn block_hash_deterministic() {
        let h = dummy_header(1, [0u8; 32]);
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let hash1 = h.block_hash(chain_id);
        let hash2 = h.block_hash(chain_id);
        assert_eq!(hash1, hash2, "block_hash 必须确定性");
    }

    #[test]
    fn block_hash_changes_with_height() {
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let h1 = dummy_header(1, [0u8; 32]);
        let h2 = dummy_header(2, [0u8; 32]);
        assert_ne!(
            h1.block_hash(chain_id),
            h2.block_hash(chain_id),
            "height 变化必须改变 block_hash"
        );
    }

    #[test]
    fn block_hash_changes_with_prev_hash() {
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let h1 = dummy_header(1, [0u8; 32]);
        let h2 = dummy_header(1, [1u8; 32]);
        assert_ne!(
            h1.block_hash(chain_id),
            h2.block_hash(chain_id),
            "prev_hash 变化必须改变 block_hash"
        );
    }

    #[test]
    fn block_hash_changes_with_state_root() {
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let mut h = dummy_header(1, [0u8; 32]);
        let hash1 = h.block_hash(chain_id);
        h.state_root = [0xFFu8; 32];
        let hash2 = h.block_hash(chain_id);
        assert_ne!(hash1, hash2, "state_root 变化必须改变 block_hash");
    }

    #[test]
    fn block_hash_changes_with_tx_roots() {
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let mut h = dummy_header(1, [0u8; 32]);
        let hash1 = h.block_hash(chain_id);
        h.public_tx_root = [0xFFu8; 32];
        let hash2 = h.block_hash(chain_id);
        assert_ne!(hash1, hash2, "public_tx_root 变化必须改变 block_hash");

        h.gameturn_tx_root = [0xEEu8; 32];
        let hash3 = h.block_hash(chain_id);
        assert_ne!(hash2, hash3, "gameturn_tx_root 变化必须改变 block_hash");
    }

    #[test]
    fn block_hash_changes_with_chain_id() {
        let h = dummy_header(1, [0u8; 32]);
        let hash1 = h.block_hash(crate::DEFAULT_CHAIN_ID);
        let hash2 = h.block_hash(0xDEAD_BEEF);
        assert_ne!(hash1, hash2, "chain_id 变化必须改变 block_hash");
    }

    #[test]
    fn block_chain_linking() {
        // 模拟 3 个区块的链式链接
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let h0 = dummy_header(0, [0u8; 32]);
        let hash0 = h0.block_hash(chain_id);

        let h1 = dummy_header(1, hash0);
        let hash1 = h1.block_hash(chain_id);

        let h2 = dummy_header(2, hash1);
        let hash2 = h2.block_hash(chain_id);

        // 验证链式链接：每个 block 的 prev_hash 是前一个 block 的 hash
        assert_eq!(h1.prev_hash, hash0);
        assert_eq!(h2.prev_hash, hash1);
        // hash 链不循环
        assert_ne!(hash0, hash1);
        assert_ne!(hash1, hash2);
        assert_ne!(hash0, hash2);
    }

    #[test]
    fn block_bcs_roundtrip() {
        let header = dummy_header(1, [0u8; 32]);
        let block = Block::new(header, vec![dummy_tx(1)], vec![dummy_tx(2)]);
        let bytes = block.to_bcs().expect("BCS 序列化");
        let block2 = Block::from_bcs(&bytes).expect("BCS 反序列化");
        assert_eq!(block, block2, "BCS 往返必须保持一致");
    }

    #[test]
    fn block_json_roundtrip() {
        let header = dummy_header(1, [0u8; 32]);
        let block = Block::new(header, vec![], vec![]);
        let json = serde_json::to_string(&block).expect("JSON 序列化");
        let block2: Block = serde_json::from_str(&json).expect("JSON 反序列化");
        assert_eq!(block, block2, "JSON 往返必须保持一致");
    }

    #[test]
    fn compute_tx_merkle_root_empty() {
        let root = compute_tx_merkle_root(&[]);
        // 空树根 = empty_at(TREE_DEPTH)
        let expected = crate::object_model::SparseMerkleTree::new().root();
        assert_eq!(root, expected, "空 tx 列表的 Merkle root 必须是空树根");
    }

    #[test]
    fn compute_tx_merkle_root_single() {
        let tx = dummy_tx(1);
        let root = compute_tx_merkle_root(&[tx]);
        // 非空树根 ≠ 空树根
        let empty_root = compute_tx_merkle_root(&[]);
        assert_ne!(
            root, empty_root,
            "非空 tx 列表的 Merkle root 必须不同于空树根"
        );
    }

    #[test]
    fn compute_tx_merkle_root_order_independent() {
        // Sparse Merkle Tree：key = blake2b_256(tx_hash)，与插入顺序无关
        let tx1 = dummy_tx(1);
        let tx2 = dummy_tx(2);
        let root1 = compute_tx_merkle_root(&[tx1.clone(), tx2.clone()]);
        let root2 = compute_tx_merkle_root(&[tx2, tx1]);
        assert_eq!(root1, root2, "Sparse Merkle Tree 的 root 与插入顺序无关");
    }

    #[test]
    fn light_client_tx_inclusion_prove_and_verify() {
        // 缺口 #6：轻客户端 tx 包含性证明。
        let tx1 = dummy_tx(1);
        let tx2 = dummy_tx(2);
        let txs = vec![tx1.clone(), tx2.clone()];
        let target_hash = tx1.tx_hash();
        // 生成证明
        let (proof, root) = prove_tx_inclusion(&txs, &target_hash).expect("应能生成证明");
        // 验证：target tx 确实包含
        verify_tx_inclusion(&target_hash, &proof, &root).expect("包含性验证应通过");
        // 验证：不存在的 tx → 失败
        let fake_hash = [0xFF; 32];
        assert!(
            verify_tx_inclusion(&fake_hash, &proof, &root).is_err(),
            "不存在的 tx 应验证失败"
        );
    }

    #[test]
    fn genesis_block_height_zero() {
        let cert = dummy_commit_cert();
        let genesis = genesis_block(0, [0u8; 32], cert);
        assert_eq!(genesis.header.height, 0);
        assert_eq!(genesis.header.prev_hash, [0u8; 32]);
        assert!(genesis.public_txs.is_empty());
        assert!(genesis.gameturn_txs.is_empty());
    }
}
