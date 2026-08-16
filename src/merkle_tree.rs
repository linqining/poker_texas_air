//! Merkle 树实现 — seats / side_pots 的二叉 Merkle 树。
//!
//! ## 设计
//!
//! - 哈希函数：`Poseidon252(left, right)`（Starknet 标准）
//! - 叶子节点：业务对象（如 `Seat`）的 Poseidon252 编码
//! - 内部节点：`Poseidon252(left_child, right_child)`
//! - Padding：用 `FieldElement::ZERO` 补齐到 2^k
//! - 用于 AIR 内 Merkle Path 验证（Texas 自有组件待接入）

use starknet_ff::FieldElement;

use crate::error::{TexasAirError, TexasAirResult};

/// Merkle 树叶子节点 — `Seat` 字段的 Poseidon252 编码。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeatLeaf(pub FieldElement);

impl SeatLeaf {
    /// 从 `poker_l1` 的 `Seat` 构造叶子哈希。
    ///
    /// The leaf commits to the complete canonical Borsh encoding of `Seat`.
    #[must_use]
    pub fn from_seat(seat: &poker_l1::vm::contracts::texas_poker::types::Seat) -> Self {
        Self(crate::state_root::poseidon_borsh(
            "zchain.texas_poker.seat.v2",
            seat,
        ))
    }

    /// 返回内部字段。
    #[must_use]
    pub const fn field(self) -> FieldElement {
        self.0
    }
}

/// Merkle 树结构（叶子层固定为 2^k，k = log2(padding)）。
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// 所有层，从叶子层到根。
    /// `layers[0]` = 叶子层（padding 后），`layers[k]` = [root]。
    layers: Vec<Vec<FieldElement>>,
    /// 叶子数（未 padding 的真实数量）。
    leaf_count: usize,
}

impl MerkleTree {
    /// 从叶子构造 Merkle 树。
    ///
    /// 自动 padding 到 2^k，padding 叶子为 `FieldElement::ZERO`。
    #[must_use]
    pub fn from_leaves<L: Into<FieldElement> + Copy>(leaves: &[L]) -> Self {
        let leaf_count = leaves.len();
        if leaf_count == 0 {
            return Self {
                layers: vec![vec![]],
                leaf_count: 0,
            };
        }
        // padding 到 2^k（至少 2，保证单叶子也会被 hash）
        let k = (leaf_count.next_power_of_two()).max(2);
        let mut layer: Vec<FieldElement> = leaves.iter().map(|&l| l.into()).collect();
        layer.resize(k, FieldElement::ZERO);

        let mut layers = vec![layer.clone()];
        // 自底向上构造
        while layer.len() > 1 {
            let next: Vec<FieldElement> = (0..layer.len())
                .step_by(2)
                .map(|i| poseidon_pair(layer[i], layer[i + 1]))
                .collect();
            layers.push(next.clone());
            layer = next;
        }
        Self { layers, leaf_count }
    }

    /// 返回 root（空树返回 0）。
    #[must_use]
    pub fn root(&self) -> FieldElement {
        self.layers
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or(FieldElement::ZERO)
    }

    /// 返回叶子数（真实，未 padding）。
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// 返回 padding 后的叶子容量（2^k）。
    #[must_use]
    pub fn padded_leaf_count(&self) -> usize {
        self.layers.first().map(Vec::len).unwrap_or(0)
    }

    /// 返回树深度（log2(padded_leaf_count)）。
    #[must_use]
    pub fn depth(&self) -> u32 {
        let padded = self.padded_leaf_count();
        if padded == 0 {
            return 0;
        }
        debug_assert!(padded.is_power_of_two());
        padded.trailing_zeros()
    }

    /// 生成 leaf_index 处的 Merkle Path（从叶子到根）。
    ///
    /// 返回每层的 sibling hash（兄弟节点）。
    ///
    /// # Errors
    ///
    /// 当 `leaf_index >= leaf_count` 时返回错误。
    pub fn proof(&self, leaf_index: usize) -> TexasAirResult<Vec<FieldElement>> {
        if leaf_index >= self.leaf_count {
            return Err(TexasAirError::MerkleError(format!(
                "leaf_index {leaf_index} >= leaf_count {}",
                self.leaf_count
            )));
        }
        let mut path = Vec::with_capacity(self.depth() as usize);
        let mut idx = leaf_index;
        for layer in &self.layers {
            if layer.len() == 1 {
                break;
            }
            let sibling_idx = idx ^ 1;
            path.push(layer[sibling_idx]);
            idx /= 2;
        }
        Ok(path)
    }

    /// 验证 Merkle Path。
    ///
    /// 给定 `leaf`、`path`、`root`，验证 path 验证成立。
    #[must_use]
    pub fn verify_path(
        leaf: FieldElement,
        path: &[FieldElement],
        leaf_index: usize,
        root: FieldElement,
    ) -> bool {
        let mut acc = leaf;
        let mut idx = leaf_index;
        for &sibling in path {
            if idx % 2 == 0 {
                acc = poseidon_pair(acc, sibling);
            } else {
                acc = poseidon_pair(sibling, acc);
            }
            idx /= 2;
        }
        acc == root
    }
}

impl From<SeatLeaf> for FieldElement {
    fn from(l: SeatLeaf) -> Self {
        l.0
    }
}

/// Poseidon252 hash of two field elements (Starknet 标准)。
fn poseidon_pair(a: FieldElement, b: FieldElement) -> FieldElement {
    starknet_crypto::poseidon_hash(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::from_leaves::<FieldElement>(&[]);
        assert_eq!(tree.root(), FieldElement::ZERO);
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.depth(), 0);
    }

    #[test]
    fn test_single_leaf() {
        let leaves = [FieldElement::from(42u64)];
        let tree = MerkleTree::from_leaves(&leaves);
        // 单叶子 + 1 padding(0) → root = Poseidon(42, 0)
        let expected =
            starknet_crypto::poseidon_hash(FieldElement::from(42u64), FieldElement::ZERO);
        assert_eq!(tree.root(), expected);
        assert_eq!(tree.depth(), 1);
    }

    #[test]
    fn test_two_leaves() {
        let leaves = [FieldElement::from(1u64), FieldElement::from(2u64)];
        let tree = MerkleTree::from_leaves(&leaves);
        let expected = poseidon_pair(FieldElement::from(1u64), FieldElement::from(2u64));
        assert_eq!(tree.root(), expected);
        assert_eq!(tree.depth(), 1);
    }

    #[test]
    fn test_three_leaves_padded() {
        let leaves = [
            FieldElement::from(1u64),
            FieldElement::from(2u64),
            FieldElement::from(3u64),
        ];
        let tree = MerkleTree::from_leaves(&leaves);
        assert_eq!(tree.leaf_count(), 3);
        assert_eq!(tree.padded_leaf_count(), 4);
        assert_eq!(tree.depth(), 2);

        // 手算：layer0 = [1, 2, 3, 0]
        // layer1 = [Poseidon(1,2), Poseidon(3,0)]
        // root = Poseidon(Poseidon(1,2), Poseidon(3,0))
        let l1_left = poseidon_pair(FieldElement::from(1u64), FieldElement::from(2u64));
        let l1_right = poseidon_pair(FieldElement::from(3u64), FieldElement::ZERO);
        let expected = poseidon_pair(l1_left, l1_right);
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn test_merkle_proof_roundtrip() {
        let leaves = [
            FieldElement::from(1u64),
            FieldElement::from(2u64),
            FieldElement::from(3u64),
            FieldElement::from(4u64),
            FieldElement::from(5u64),
        ];
        let tree = MerkleTree::from_leaves(&leaves);
        let root = tree.root();
        for i in 0..leaves.len() {
            let path = tree.proof(i).unwrap();
            assert!(
                MerkleTree::verify_path(leaves[i], &path, i, root),
                "leaf {i} 验证失败"
            );
        }
    }

    #[test]
    fn test_merkle_proof_tamper_fails() {
        let leaves = [
            FieldElement::from(1u64),
            FieldElement::from(2u64),
            FieldElement::from(3u64),
            FieldElement::from(4u64),
        ];
        let tree = MerkleTree::from_leaves(&leaves);
        let root = tree.root();
        let path = tree.proof(0).unwrap();
        // 篡改 leaf
        let tampered = FieldElement::from(99u64);
        assert!(!MerkleTree::verify_path(tampered, &path, 0, root));
    }
}
