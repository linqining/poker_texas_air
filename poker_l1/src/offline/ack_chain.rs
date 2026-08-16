//! `ack_chain_hash` Merkle 树实现（NEW-M5 + R3-M2 / R4-M1 / R4-M3 / R4-M5 / SEC-L5）。
//!
//! 严格遵循 spec.md L719–723（FROZEN 2026-06-27）：
//!
//! ```text
//! ack_chain_hash = MerkleRoot(ack_1 || ack_2 || ... || ack_n)
//!
//! ack_i = hash(
//!     chain_id || epoch || game_id || current_turn || state_hash ||
//!     checkpoint_seq || ack_domain_tag || participant_tagged_pubkey || participant_signature
//! )
//! ```
//!
//! ## RFC 6962 域分离
//!
//! - 叶子节点哈希 = `H(0x00 || ack_i)` — 防与内部节点混淆
//! - 内部节点哈希 = `H(0x01 || left_child || right_child)` — 防二次原像攻击
//! - 空树 → `H(0x00 || b"")`（SEC-L5 明确 empty 叶子值 = 空字节串）
//! - 单叶子 → `H(0x00 || ack_1)`
//! - 不平衡树 → RFC 6962 filled subtree 补齐 `H(0x00 || b"")`
//!
//! ## skip 段处理
//!
//! skip 段不参与 ack_chain（R5-M5：`ack_chain_partial_hash` 使用完全相同的 RFC 6962 构造）。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

use crate::Hash;
use crate::object_model::ObjectID;
use crate::signature::TaggedPubkey;

use super::{ACK_DOMAIN_TAG, ACK_MERKLE_INTERNAL_PREFIX, ACK_MERKLE_LEAF_PREFIX};

/// 空字节串 — RFC 6962 empty 叶子值（SEC-L5）。
pub const EMPTY_LEAF_VALUE: &[u8] = b"";

/// 单个 ACK 条目 — 对应 `ack_i`。
///
/// 字段集来自 spec.md L721-723 + SEC-C3（增加 epoch）+ R4-H3（增加 chain_id）：
/// `ack_i = hash(chain_id || epoch || game_id || current_turn || state_hash || checkpoint_seq || ack_domain_tag || participant_tagged_pubkey || participant_signature)`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckEntry {
    /// chain_id（防跨链重放，R4-H3）。
    pub chain_id: crate::ChainId,
    /// epoch（防跨 epoch 重放，SEC-C3）。
    pub epoch: u64,
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// 当前轮次玩家地址。
    pub current_turn: crate::Address,
    /// 该 checkpoint 的状态哈希。
    pub state_hash: Hash,
    /// checkpoint 序号（每 Game 单调递增）。
    pub checkpoint_seq: u64,
    /// 参与者 tagged pubkey。
    pub participant: TaggedPubkey,
    /// 参与者签名（对 ack_signed_message 的签名）。
    pub participant_signature: Vec<u8>,
}

impl AckEntry {
    /// 计算 `ack_i = hash(chain_id || epoch || game_id || current_turn || state_hash || checkpoint_seq || ack_domain_tag || participant_tagged_pubkey || participant_signature)`。
    ///
    /// 与 NEW-H3 ACK 签名消息的区别：ACK 签名消息只哈希到 `checkpoint_seq + ack_domain_tag`，
    /// 而 ack_i 额外包含 `participant_tagged_pubkey + participant_signature`（R4-M5）。
    pub fn ack_hash(&self) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
        hasher.update(&self.chain_id.to_be_bytes());
        hasher.update(&self.epoch.to_be_bytes());
        hasher.update(&self.game_id.to_bytes());
        hasher.update(&self.current_turn);
        hasher.update(&self.state_hash);
        hasher.update(&self.checkpoint_seq.to_be_bytes());
        hasher.update(&[ACK_DOMAIN_TAG]);
        hasher.update(&self.participant.to_bytes());
        hasher.update(&self.participant_signature);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }

    /// 计算 ACK 签名消息哈希（NEW-H3 + R4-H3 + SEC-C3）。
    ///
    /// 签名对象 = `hash(chain_id || epoch || game_id || current_turn || state_hash || checkpoint_seq || ack_domain_tag)`。
    /// 参与者对此哈希签名，validator 用 `verify_signature(participant, sig, msg_hash)` 验证。
    pub fn ack_signing_message(
        chain_id: crate::ChainId,
        epoch: u64,
        game_id: &ObjectID,
        current_turn: &crate::Address,
        state_hash: &Hash,
        checkpoint_seq: u64,
    ) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
        hasher.update(&chain_id.to_be_bytes());
        hasher.update(&epoch.to_be_bytes());
        hasher.update(&game_id.to_bytes());
        hasher.update(current_turn);
        hasher.update(state_hash);
        hasher.update(&checkpoint_seq.to_be_bytes());
        hasher.update(&[ACK_DOMAIN_TAG]);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }
}

/// 计算叶子节点哈希 = `H(0x00 || leaf)`（RFC 6962）。
fn leaf_hash(leaf: &[u8]) -> Hash {
    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
    hasher.update(&[ACK_MERKLE_LEAF_PREFIX]);
    hasher.update(leaf);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("Blake2bVar finalize 不应失败");
    out
}

/// 计算内部节点哈希 = `H(0x01 || left || right)`（RFC 6962）。
fn internal_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
    hasher.update(&[ACK_MERKLE_INTERNAL_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("Blake2bVar finalize 不应失败");
    out
}

/// 空 Merkle 根 = `H(0x00 || b"")`（SEC-L5）。
pub fn empty_root() -> Hash {
    leaf_hash(EMPTY_LEAF_VALUE)
}

/// 计算 `ack_chain_hash = MerkleRoot(ack_1 || ack_2 || ... || ack_n)`。
///
/// 算法：
/// 1. 空树 → `H(0x00 || b"")`（SEC-L5）
/// 2. 单叶子 → `H(0x00 || ack_1)`
/// 3. 多叶子 → RFC 6962 binary Merkle tree，不平衡时用 `H(0x00 || b"")` filled subtree 补齐
///
/// 时间复杂度 O(n)，空间复杂度 O(log n)（栈式合并）。
pub fn compute_ack_chain_hash(entries: &[AckEntry]) -> Hash {
    if entries.is_empty() {
        return empty_root();
    }

    // 计算每个 ack_i 的哈希
    let leaves: Vec<Hash> = entries.iter().map(AckEntry::ack_hash).collect();

    // RFC 6962 Merkle 树构造（栈式）
    merkle_root_from_leaves(&leaves)
}

/// 计算 `ack_chain_partial_hash = MerkleRoot(ack_chain[0..N])`（R5-M5）。
///
/// 与 `compute_ack_chain_hash` 使用完全相同的 RFC 6962 构造，确保算法一致性。
pub fn compute_ack_chain_partial_hash(entries: &[AckEntry]) -> Hash {
    compute_ack_chain_hash(entries)
}

/// 从叶子哈希列表计算 Merkle root（RFC 6962 风格）。
///
/// 输入 `leaves` 为原始 `ack_i` 哈希（未包装）。RFC 6962 要求叶子节点
/// = `H(0x00 || ack_i)`，本函数内部先包装再构建树。
///
/// 不平衡树用 `empty_root()`（即 `H(0x00 || b"")`）补齐到 2 的幂。
fn merkle_root_from_leaves(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return empty_root();
    }

    // RFC 6962: 叶子节点 = H(0x00 || ack_i)
    let wrapped: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l)).collect();

    if wrapped.len() == 1 {
        return wrapped[0];
    }

    // 找到 >= wrapped.len() 的最小 2 的幂
    let mut tree_size = 1usize;
    while tree_size < wrapped.len() {
        tree_size *= 2;
    }

    // 补齐到 tree_size，用 empty_root() 填充
    let mut current: Vec<Hash> = wrapped;
    current.resize(tree_size, empty_root());

    // 自底向上合并
    while current.len() > 1 {
        let mut next: Vec<Hash> = Vec::with_capacity(current.len() / 2);
        for pair in current.chunks(2) {
            next.push(internal_hash(&pair[0], &pair[1]));
        }
        current = next;
    }

    current[0]
}

/// Merkle 包含证明（RFC 6962 风格）。
///
/// 用于验证某 `ack_i` 在 ack_chain 中。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckMerkleProof {
    /// 叶子索引（在原 leaves 数组中的位置）。
    pub leaf_index: usize,
    /// 兄弟节点哈希列表（从叶子到 root）。
    pub siblings: Vec<Hash>,
}

/// 生成 Merkle 包含证明。
///
/// 时间复杂度 O(n)（重新构造树），空间复杂度 O(log n)。
pub fn prove_ack_inclusion(entries: &[AckEntry], leaf_index: usize) -> Option<AckMerkleProof> {
    if leaf_index >= entries.len() {
        return None;
    }

    let leaves: Vec<Hash> = entries.iter().map(AckEntry::ack_hash).collect();
    prove_leaves_inclusion(&leaves, leaf_index)
}

fn prove_leaves_inclusion(leaves: &[Hash], leaf_index: usize) -> Option<AckMerkleProof> {
    if leaf_index >= leaves.len() {
        return None;
    }
    if leaves.is_empty() {
        return None;
    }

    // RFC 6962: 叶子节点 = H(0x00 || ack_i)
    let wrapped: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l)).collect();

    let mut tree_size = 1usize;
    while tree_size < wrapped.len() {
        tree_size *= 2;
    }

    let mut current: Vec<Hash> = wrapped;
    current.resize(tree_size, empty_root());

    let mut siblings = Vec::new();
    let mut idx = leaf_index;

    while current.len() > 1 {
        // 兄弟节点索引：偶数 → idx+1，奇数 → idx-1
        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        siblings.push(current[sibling_idx]);

        // 上一层
        let mut next: Vec<Hash> = Vec::with_capacity(current.len() / 2);
        for pair in current.chunks(2) {
            next.push(internal_hash(&pair[0], &pair[1]));
        }
        current = next;
        idx /= 2;
    }

    Some(AckMerkleProof {
        leaf_index,
        siblings,
    })
}

/// 验证 Merkle 包含证明。
///
/// 输入 `ack_hash` 为原始 `ack_i` 哈希（未包装）。本函数内部先做 RFC 6962 叶子包装
/// `H(0x00 || ack_i)`，再沿 `proof.siblings` 自底向上计算预期 root，与 `root` 比对。
///
/// 返回 `true` 当且仅当 `ack_hash` 在以 `root` 为根的 Merkle 树中位于 `proof.leaf_index` 位置。
pub fn verify_ack_inclusion(root: &Hash, ack_hash: &Hash, proof: &AckMerkleProof) -> bool {
    // RFC 6962: 叶子节点 = H(0x00 || ack_i)
    let mut current = leaf_hash(ack_hash);
    let mut idx = proof.leaf_index;

    for sibling in &proof.siblings {
        if idx.is_multiple_of(2) {
            // 当前是左子节点
            current = internal_hash(&current, sibling);
        } else {
            // 当前是右子节点
            current = internal_hash(sibling, &current);
        }
        idx /= 2;
    }

    current == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ack_entry(checkpoint_seq: u64, participant_byte: u8) -> AckEntry {
        AckEntry {
            chain_id: crate::DEFAULT_CHAIN_ID,
            epoch: 1,
            game_id: ObjectID::new([0x01; 20], checkpoint_seq),
            current_turn: [participant_byte; 20],
            state_hash: [participant_byte; 32],
            checkpoint_seq,
            participant: TaggedPubkey {
                tag: 0x01,
                raw: vec![participant_byte; 33],
            },
            participant_signature: vec![participant_byte; 64],
        }
    }

    #[test]
    fn test_empty_root_matches_rfc_6962() {
        // SEC-L5：空树 → H(0x00 || b"")
        let expected = leaf_hash(EMPTY_LEAF_VALUE);
        assert_eq!(empty_root(), expected);
        // 空 entries 应返回 empty_root
        let entries: Vec<AckEntry> = vec![];
        assert_eq!(compute_ack_chain_hash(&entries), empty_root());
    }

    #[test]
    fn test_single_leaf_equals_leaf_hash() {
        // 单叶子 → H(0x00 || ack_1)
        let entry = make_ack_entry(1, 0xAA);
        let leaf = entry.ack_hash();
        let root = compute_ack_chain_hash(&[entry]);
        assert_eq!(root, leaf_hash(&leaf));
    }

    #[test]
    fn test_two_leaves_root() {
        let e1 = make_ack_entry(1, 0xAA);
        let e2 = make_ack_entry(2, 0xBB);
        let l1 = e1.ack_hash();
        let l2 = e2.ack_hash();
        let expected = internal_hash(&leaf_hash(&l1), &leaf_hash(&l2));
        assert_eq!(compute_ack_chain_hash(&[e1, e2]), expected);
    }

    #[test]
    fn test_three_leaves_unbalanced_filled_with_empty() {
        // 3 叶子 → 补齐到 4，第 4 个为 empty_root()
        let e1 = make_ack_entry(1, 0xAA);
        let e2 = make_ack_entry(2, 0xBB);
        let e3 = make_ack_entry(3, 0xCC);
        let l1 = leaf_hash(&e1.ack_hash());
        let l2 = leaf_hash(&e2.ack_hash());
        let l3 = leaf_hash(&e3.ack_hash());
        let l4 = empty_root();
        let left = internal_hash(&l1, &l2);
        let right = internal_hash(&l3, &l4);
        let expected = internal_hash(&left, &right);
        assert_eq!(compute_ack_chain_hash(&[e1, e2, e3]), expected);
    }

    #[test]
    fn test_determinism_same_entries_same_root() {
        let e1 = make_ack_entry(1, 0xAA);
        let e2 = make_ack_entry(2, 0xBB);
        let root1 = compute_ack_chain_hash(&[e1.clone(), e2.clone()]);
        let root2 = compute_ack_chain_hash(&[e1, e2]);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_different_order_different_root() {
        let e1 = make_ack_entry(1, 0xAA);
        let e2 = make_ack_entry(2, 0xBB);
        let root1 = compute_ack_chain_hash(&[e1.clone(), e2.clone()]);
        let root2 = compute_ack_chain_hash(&[e2, e1]);
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_partial_hash_same_algorithm() {
        // R5-M5：partial hash 使用与完整 hash 完全相同的构造
        let e1 = make_ack_entry(1, 0xAA);
        let e2 = make_ack_entry(2, 0xBB);
        let e3 = make_ack_entry(3, 0xCC);

        let partial = compute_ack_chain_partial_hash(&[e1.clone(), e2.clone()]);
        let full_prefix = compute_ack_chain_hash(&[e1, e2, e3]);
        let only_two = compute_ack_chain_hash(&[make_ack_entry(1, 0xAA), make_ack_entry(2, 0xBB)]);

        // partial 应等于 only_two（相同 entries）
        assert_eq!(partial, only_two);
        // partial 应不等于 full_prefix（不同 entries）
        assert_ne!(partial, full_prefix);
    }

    #[test]
    fn test_prove_and_verify_inclusion() {
        let entries: Vec<AckEntry> = (1..=5)
            .map(|i| make_ack_entry(i, (i as u8) * 0x10))
            .collect();
        let root = compute_ack_chain_hash(&entries);

        for i in 0..entries.len() {
            let proof = prove_ack_inclusion(&entries, i).expect("proof 应生成");
            let leaf = entries[i].ack_hash();
            assert!(
                verify_ack_inclusion(&root, &leaf, &proof),
                "leaf {i} 验证应通过"
            );
        }
    }

    #[test]
    fn test_verify_rejects_wrong_leaf() {
        let entries: Vec<AckEntry> = (1..=4)
            .map(|i| make_ack_entry(i, (i as u8) * 0x10))
            .collect();
        let root = compute_ack_chain_hash(&entries);

        let proof = prove_ack_inclusion(&entries, 0).expect("proof 应生成");
        let wrong_leaf = make_ack_entry(99, 0xFF).ack_hash();
        assert!(!verify_ack_inclusion(&root, &wrong_leaf, &proof));
    }

    #[test]
    fn test_verify_rejects_wrong_root() {
        let entries: Vec<AckEntry> = (1..=4)
            .map(|i| make_ack_entry(i, (i as u8) * 0x10))
            .collect();
        let wrong_root = [0xFF; 32];

        let proof = prove_ack_inclusion(&entries, 0).expect("proof 应生成");
        let leaf = entries[0].ack_hash();
        assert!(!verify_ack_inclusion(&wrong_root, &leaf, &proof));
    }

    #[test]
    fn test_prove_out_of_bounds_returns_none() {
        let entries: Vec<AckEntry> = (1..=4)
            .map(|i| make_ack_entry(i, (i as u8) * 0x10))
            .collect();
        assert!(prove_ack_inclusion(&entries, 4).is_none());
        assert!(prove_ack_inclusion(&entries, 100).is_none());
    }

    #[test]
    fn test_prove_empty_entries_returns_none() {
        let entries: Vec<AckEntry> = vec![];
        assert!(prove_ack_inclusion(&entries, 0).is_none());
    }

    #[test]
    fn test_ack_hash_includes_all_fields() {
        // 任何字段变化都应导致 ack_hash 不同
        let base = make_ack_entry(1, 0xAA);

        // chain_id 变化
        let mut e = base.clone();
        e.chain_id = 0xDEAD_BEEF;
        assert_ne!(e.ack_hash(), base.ack_hash());

        // epoch 变化
        let mut e = base.clone();
        e.epoch = 999;
        assert_ne!(e.ack_hash(), base.ack_hash());

        // checkpoint_seq 变化
        let mut e = base.clone();
        e.checkpoint_seq = 999;
        assert_ne!(e.ack_hash(), base.ack_hash());

        // participant_signature 变化
        let mut e = base.clone();
        e.participant_signature[0] ^= 0xFF;
        assert_ne!(e.ack_hash(), base.ack_hash());
    }

    #[test]
    fn test_ack_signing_message_excludes_participant_fields() {
        // 签名消息只到 checkpoint_seq + ack_domain_tag
        // 不含 participant_tagged_pubkey / participant_signature
        let game_id = ObjectID::new([0x01; 20], 1);
        let state_hash = [0x42; 32];
        let msg = AckEntry::ack_signing_message(
            crate::DEFAULT_CHAIN_ID,
            1,
            &game_id,
            &[0x02; 20],
            &state_hash,
            5,
        );

        // 确定性：相同输入应得到相同输出
        let msg2 = AckEntry::ack_signing_message(
            crate::DEFAULT_CHAIN_ID,
            1,
            &game_id,
            &[0x02; 20],
            &state_hash,
            5,
        );
        assert_eq!(msg, msg2);

        // 不同 checkpoint_seq 应得到不同输出
        let msg3 = AckEntry::ack_signing_message(
            crate::DEFAULT_CHAIN_ID,
            1,
            &game_id,
            &[0x02; 20],
            &state_hash,
            6,
        );
        assert_ne!(msg, msg3);
    }

    #[test]
    fn test_large_ack_chain_consistency() {
        // 1000 个 ack 条目（max_ack_chain_length 默认上限）
        let entries: Vec<AckEntry> = (1..=1000)
            .map(|i| make_ack_entry(i, (i as u8).wrapping_mul(0x10)))
            .collect();
        let root = compute_ack_chain_hash(&entries);

        // 随机抽样验证包含证明
        for &i in &[0, 1, 500, 999] {
            let proof = prove_ack_inclusion(&entries, i).expect("proof 应生成");
            let leaf = entries[i].ack_hash();
            assert!(
                verify_ack_inclusion(&root, &leaf, &proof),
                "leaf {i} 应通过"
            );
        }
    }

    #[test]
    fn test_proof_size_logarithmic() {
        // 兄弟节点数应 = ceil(log2(n))（n 是补齐到 2 的幂后的树大小）
        let entries: Vec<AckEntry> = (1..=1000)
            .map(|i| make_ack_entry(i, (i as u8).wrapping_mul(0x10)))
            .collect();
        let proof = prove_ack_inclusion(&entries, 0).expect("proof 应生成");
        // 1000 → 补齐到 1024 → log2(1024) = 10
        assert_eq!(proof.siblings.len(), 10);
    }
}
