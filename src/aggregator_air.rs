//! Aggregator AIR PoC — 聚合 N 个 method descriptor，不验证 method proof。
//!
//! ## 架构定位
//!
//! - **Layer 0**：Method AIRs（19 个 active stable discriminant）
//! - **Layer 1**：当前仅有宿主逐 proof 验证；Texas 自有递归 verifier 电路尚未实现
//! - **Layer 2**：**Aggregator AIR（本模块）** — 二叉树聚合 N 个 descriptor 摘要
//! - **Layer 3**：Final Recursion — 尚未实现可信闭环
//!
//! ## 聚合模型
//!
//! 给定 N 个 method descriptor（按 `call_seq` 排序），构造完全二叉树：
//!
//! ```text
//!                   [root]
//!                  /      \
//!              [N/2]       [N/2]
//!              /   \       /   \
//!            p0    p1    p2    p3
//! ```
//!
//! 每个内部节点是一个 Aggregator AIR 实例，验证：
//!
//! 1. **链式连续性**：`left.post_state_root == right.pre_state_root`
//!    （状态在两次方法调用间连续过渡）
//! 2. **调用顺序**：`left.call_seq < right.call_seq`
//! 3. **同表同局**：`left.table_id == right.table_id` 且 `left.hand_id == right.hand_id`
//! 4. **聚合传播**：
//!    - `agg.pre_state_root == left.pre_state_root`
//!    - `agg.post_state_root == right.post_state_root`
//!
//! ## 列布局（10 列）
//!
//! | 列 | 含义 |
//! |----|------|
//! | `IS_ACTIVE` | 1=业务行，0=padding |
//! | `IS_PADDING` | 1=padding，0=业务 |
//! | `LEFT_PRE_STATE_ROOT_BASE[4]` | 左子 pre state_root |
//! | `LEFT_POST_STATE_ROOT_BASE[4]` | 左子 post state_root |
//! | `RIGHT_PRE_STATE_ROOT_BASE[4]` | 右子 pre state_root |
//! | `RIGHT_POST_STATE_ROOT_BASE[4]` | 右子 post state_root |
//! | `LEFT_CALL_SEQ` | 左子 call_seq |
//! | `RIGHT_CALL_SEQ` | 右子 call_seq |
//! | `LEFT_METHOD_KIND` | 左子方法种类 |
//! | `RIGHT_METHOD_KIND` | 右子方法种类 |
//!
//! 共 22 列（2 通用 + 20 业务）。
//!
//! ## 简化策略（阶段 4 PoC）
//!
//! 完整版应嵌入 Layer 1 Verifier AIR 递归验证每个子节点 proof。当前 PoC 版本：
//! - 只验证状态链式连续性（state_root 衔接）
//! - 不验证子 proof 的 Stwo verification（留待阶段 5）
//! - `agg.pre_state_root` / `agg.post_state_root` 作为 AIR 公开输入
//!
//! 因为 descriptor 可由调用者自行构造，本 AIR 证明不能作为“子 proof 已验证”的证据。
//! `prove_aggregator` / `verify_aggregator` 的生产入口因此默认拒绝，只有名称中明确带
//! `unchecked_for_tests` 的入口会运行此 PoC。
//!
//! ## 约束清单（degree ≤ 2）
//!
//! 1. `IS_ACTIVE`, `IS_PADDING` boolean + 互斥
//! 2. Padding 行：所有列为 0（除 IS_PADDING=1）
//! 3. `LEFT_POST_STATE_ROOT[i] == RIGHT_PRE_STATE_ROOT[i]` for i in 0..4
//!    （链式连续性，gate by IS_ACTIVE）
//! 4. `RIGHT_CALL_SEQ == LEFT_CALL_SEQ + 1`（顺序连续 — 简化为相邻）

use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

use crate::airs::common::{ZERO, u64_to_m31_limbs};
use crate::method_kind::MethodKind;

/// Aggregator AIR 列布局。
pub mod cols {
    /// `IS_ACTIVE` 列。
    pub const IS_ACTIVE: usize = 0;
    /// `IS_PADDING` 列。
    pub const IS_PADDING: usize = 1;
    /// `LEFT_PRE_STATE_ROOT` 起始列（4 limb）。
    pub const LEFT_PRE_STATE_ROOT_BASE: usize = 2;
    /// `LEFT_POST_STATE_ROOT` 起始列（4 limb）。
    pub const LEFT_POST_STATE_ROOT_BASE: usize = 6;
    /// `RIGHT_PRE_STATE_ROOT` 起始列（4 limb）。
    pub const RIGHT_PRE_STATE_ROOT_BASE: usize = 10;
    /// `RIGHT_POST_STATE_ROOT` 起始列（4 limb）。
    pub const RIGHT_POST_STATE_ROOT_BASE: usize = 14;
    /// `LEFT_CALL_SEQ` 列。
    pub const LEFT_CALL_SEQ: usize = 18;
    /// `RIGHT_CALL_SEQ` 列。
    pub const RIGHT_CALL_SEQ: usize = 19;
    /// `LEFT_METHOD_KIND` 列。
    pub const LEFT_METHOD_KIND: usize = 20;
    /// `RIGHT_METHOD_KIND` 列。
    pub const RIGHT_METHOD_KIND: usize = 21;
    /// `IS_TOP_LEVEL` 列（1=顶层聚合行，0=底层/中间层）。
    ///
    /// method_kind / call_seq 一致性约束只在顶层行生效，
    /// 因为多级聚合时底层行的 left/right 描述符与 AIR 公开输入不同。
    pub const IS_TOP_LEVEL: usize = 22;
    /// Aggregator AIR 总列数。
    pub const NUM_COLUMNS: usize = 23;
}

/// Aggregator AIR 的子节点描述符（一个被聚合的 method proof 摘要）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildDescriptor {
    /// 子节点的 pre state_root（4 limb）。
    pub pre_state_root: [M31; 4],
    /// 子节点的 post state_root（4 limb）。
    pub post_state_root: [M31; 4],
    /// 子节点的 call_seq。
    pub call_seq: u32,
    /// 子节点的方法种类。
    pub method_kind: MethodKind,
}

/// 把子节点描述符列表 mix 进 Fiat-Shamir channel（prover/verifier 共用，顺序固定）。
///
/// Aggregator proof 的 soundness 修复：把所有 `ChildDescriptor`（pre/post_state_root
/// 4-limb、call_seq、method_kind）按固定顺序 mix 进 channel，使聚合 proof 绑定到
/// 声明的 state_root 链。否则 AIR struct 里的 left/right 描述符可被替换而 proof 仍验证通过。
///
/// 顺序契约：对每个 child，依次 mix pre_state_root(4 u32) → post_state_root(4 u32)
/// → call_seq → method_kind。
pub fn mix_children_into_channel<C: stwo::core::channel::Channel>(
    channel: &mut C,
    children: &[ChildDescriptor],
) {
    // 子节点数先 mix，固定长度边界
    channel.mix_u32s(&[children.len() as u32]);
    for child in children {
        // pre/post_state_root 各 4 个 M31（u32）
        let mut roots_u32: Vec<u32> = Vec::with_capacity(8);
        roots_u32.extend(child.pre_state_root.iter().map(|m| m.0));
        roots_u32.extend(child.post_state_root.iter().map(|m| m.0));
        channel.mix_u32s(&roots_u32);
        channel.mix_u32s(&[child.call_seq, u32::from(child.method_kind as u8)]);
    }
}

/// Aggregator AIR 公开输入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatorAir {
    /// log2(trace 行数)。
    pub log_size: u32,
    /// 左子节点描述符。
    pub left: ChildDescriptor,
    /// 右子节点描述符。
    pub right: ChildDescriptor,
    /// 聚合后的 pre state_root（== left.pre_state_root）。
    pub agg_pre_state_root: [M31; 4],
    /// 聚合后的 post state_root（== right.post_state_root）。
    pub agg_post_state_root: [M31; 4],
}

impl AggregatorAir {
    /// 列数。
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }
}

impl FrameworkEval for AggregatorAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = M31::from(1u32).into();

        // 1. 读取通用列
        let is_active = eval.next_trace_mask();
        let is_padding = eval.next_trace_mask();

        // 2. 读取业务列
        let left_pre_0 = eval.next_trace_mask();
        let left_pre_1 = eval.next_trace_mask();
        let left_pre_2 = eval.next_trace_mask();
        let left_pre_3 = eval.next_trace_mask();
        let left_post_0 = eval.next_trace_mask();
        let left_post_1 = eval.next_trace_mask();
        let left_post_2 = eval.next_trace_mask();
        let left_post_3 = eval.next_trace_mask();
        let right_pre_0 = eval.next_trace_mask();
        let right_pre_1 = eval.next_trace_mask();
        let right_pre_2 = eval.next_trace_mask();
        let right_pre_3 = eval.next_trace_mask();
        let right_post_0 = eval.next_trace_mask();
        let right_post_1 = eval.next_trace_mask();
        let right_post_2 = eval.next_trace_mask();
        let right_post_3 = eval.next_trace_mask();
        let left_call_seq = eval.next_trace_mask();
        let right_call_seq = eval.next_trace_mask();
        let left_method_kind = eval.next_trace_mask();
        let right_method_kind = eval.next_trace_mask();
        let is_top_level = eval.next_trace_mask();

        // 约束 1：IS_ACTIVE, IS_PADDING boolean + 恰好二选一。
        //
        // 仅约束互斥会允许 `(0, 0)` 行，从而让攻击者构造既不是 active 也不是
        // padding 的完全无约束行。聚合 trace 的每一行必须明确属于其中一种。
        let active_minus_one = is_active.clone() - one.clone();
        let padding_minus_one = is_padding.clone() - one.clone();
        eval.add_constraint(is_active.clone() * active_minus_one);
        eval.add_constraint(is_padding.clone() * padding_minus_one);
        eval.add_constraint(is_active.clone() * is_padding.clone());
        eval.add_constraint(is_active.clone() + is_padding.clone() - one.clone());

        // Padding 行必须是规范全零行，避免把未被 active gate 消费的 descriptor
        // 数据藏在 padding 区域。IS_PADDING 自身按上面的约束固定为 1。
        for value in [
            left_pre_0.clone(),
            left_pre_1.clone(),
            left_pre_2.clone(),
            left_pre_3.clone(),
            left_post_0.clone(),
            left_post_1.clone(),
            left_post_2.clone(),
            left_post_3.clone(),
            right_pre_0.clone(),
            right_pre_1.clone(),
            right_pre_2.clone(),
            right_pre_3.clone(),
            right_post_0.clone(),
            right_post_1.clone(),
            right_post_2.clone(),
            right_post_3.clone(),
            left_call_seq.clone(),
            right_call_seq.clone(),
            left_method_kind.clone(),
            right_method_kind.clone(),
            is_top_level.clone(),
        ] {
            eval.add_constraint(is_padding.clone() * value);
        }

        // 约束 2：链式连续性 — LEFT_POST == RIGHT_PRE（4 limb）
        // left.post_state_root == right.pre_state_root
        // gate by is_active：is_active * (left_post_i - right_pre_i) = 0
        eval.add_constraint(is_active.clone() * (left_post_0.clone() - right_pre_0.clone()));
        eval.add_constraint(is_active.clone() * (left_post_1.clone() - right_pre_1.clone()));
        eval.add_constraint(is_active.clone() * (left_post_2.clone() - right_pre_2.clone()));
        eval.add_constraint(is_active.clone() * (left_post_3.clone() - right_pre_3.clone()));

        // 约束 3：IS_TOP_LEVEL boolean（只在 active 行有意义）
        // padding 行的 is_top_level 必须为 0
        let top_minus_one = is_top_level.clone() - one.clone();
        eval.add_constraint(is_top_level.clone() * top_minus_one);
        // padding 行不能是 top level：is_padding * is_top_level = 0
        eval.add_constraint(is_padding.clone() * is_top_level.clone());
        // top level 行必须是 active 行：is_top_level * (is_top_level - is_active) = 0
        // 即 is_top_level=1 时 is_active 必须为 1
        eval.add_constraint(is_top_level.clone() * (is_top_level.clone() - is_active.clone()));

        // 约束 4：方法种类一致性 — 只在顶层行验证 left/right 的 method_kind 等于 AIR 公开输入
        // 多级聚合时，底层行的 left/right 描述符与 AIR 公开输入不同，因此只在顶层行 gate。
        let expected_left_kind: E::F = M31::from(self.left.method_kind as u32).into();
        let expected_right_kind: E::F = M31::from(self.right.method_kind as u32).into();
        eval.add_constraint(is_top_level.clone() * (left_method_kind - expected_left_kind));
        eval.add_constraint(is_top_level.clone() * (right_method_kind - expected_right_kind));

        // 约束 5：call_seq 一致性 — 只在顶层行验证 left/right 的 call_seq 等于 AIR 公开输入
        let expected_left_seq: E::F = M31::from(self.left.call_seq).into();
        let expected_right_seq_pub: E::F = M31::from(self.right.call_seq).into();
        eval.add_constraint(is_top_level.clone() * (left_call_seq - expected_left_seq));
        eval.add_constraint(
            is_top_level.clone() * (right_call_seq.clone() - expected_right_seq_pub),
        );

        // 约束 6：顶层 row 必须绑定完整 left/right descriptor roots，并把聚合
        // 端点传播为 `left.pre` / `right.post`。此前这些字段只存在于 AIR struct，
        // 没有进入任何多项式约束，篡改 aggregate endpoint 不会影响验证结果。
        let left_pre = [left_pre_0, left_pre_1, left_pre_2, left_pre_3];
        let left_post = [left_post_0, left_post_1, left_post_2, left_post_3];
        let right_pre = [right_pre_0, right_pre_1, right_pre_2, right_pre_3];
        let right_post = [right_post_0, right_post_1, right_post_2, right_post_3];
        for i in 0..4 {
            let expected_left_pre: E::F = self.left.pre_state_root[i].into();
            let expected_left_post: E::F = self.left.post_state_root[i].into();
            let expected_right_pre: E::F = self.right.pre_state_root[i].into();
            let expected_right_post: E::F = self.right.post_state_root[i].into();
            let expected_agg_pre: E::F = self.agg_pre_state_root[i].into();
            let expected_agg_post: E::F = self.agg_post_state_root[i].into();
            eval.add_constraint(is_top_level.clone() * (left_pre[i].clone() - expected_left_pre));
            eval.add_constraint(is_top_level.clone() * (left_post[i].clone() - expected_left_post));
            eval.add_constraint(is_top_level.clone() * (right_pre[i].clone() - expected_right_pre));
            eval.add_constraint(
                is_top_level.clone() * (right_post[i].clone() - expected_right_post),
            );
            eval.add_constraint(is_top_level.clone() * (left_pre[i].clone() - expected_agg_pre));
            eval.add_constraint(is_top_level.clone() * (right_post[i].clone() - expected_agg_post));
        }

        eval
    }
}

/// Aggregator AIR 的 trace 行。
#[derive(Debug, Clone)]
pub struct AggregatorRow {
    /// `IS_ACTIVE` 列。
    pub is_active: M31,
    /// `IS_PADDING` 列。
    pub is_padding: M31,
    /// 左子 pre state_root（4 limb）。
    pub left_pre_state_root: [M31; 4],
    /// 左子 post state_root（4 limb）。
    pub left_post_state_root: [M31; 4],
    /// 右子 pre state_root（4 limb）。
    pub right_pre_state_root: [M31; 4],
    /// 右子 post state_root（4 limb）。
    pub right_post_state_root: [M31; 4],
    /// 左子 call_seq。
    pub left_call_seq: M31,
    /// 右子 call_seq。
    pub right_call_seq: M31,
    /// 左子方法种类。
    pub left_method_kind: M31,
    /// 右子方法种类。
    pub right_method_kind: M31,
    /// `IS_TOP_LEVEL` 列（1=顶层聚合行，0=底层/中间层）。
    pub is_top_level: M31,
}

impl AggregatorRow {
    /// 构造 active 行（聚合两个子节点）。
    ///
    /// # 参数
    /// - `left`: 左子节点描述符
    /// - `right`: 右子节点描述符
    /// - `is_top_level`: 是否为顶层聚合行（顶层行才验证 method_kind/call_seq 一致性）
    #[must_use]
    pub fn active(left: &ChildDescriptor, right: &ChildDescriptor, is_top_level: bool) -> Self {
        Self {
            is_active: M31::from(1u32),
            is_padding: ZERO,
            left_pre_state_root: left.pre_state_root,
            left_post_state_root: left.post_state_root,
            right_pre_state_root: right.pre_state_root,
            right_post_state_root: right.post_state_root,
            left_call_seq: M31::from(left.call_seq),
            right_call_seq: M31::from(right.call_seq),
            left_method_kind: M31::from(left.method_kind as u32),
            right_method_kind: M31::from(right.method_kind as u32),
            is_top_level: M31::from(u32::from(is_top_level)),
        }
    }

    /// 构造 padding 行（所有列为 0，除 IS_PADDING=1）。
    #[must_use]
    pub fn padding() -> Self {
        Self {
            is_active: ZERO,
            is_padding: M31::from(1u32),
            left_pre_state_root: [ZERO; 4],
            left_post_state_root: [ZERO; 4],
            right_pre_state_root: [ZERO; 4],
            right_post_state_root: [ZERO; 4],
            left_call_seq: ZERO,
            right_call_seq: ZERO,
            left_method_kind: ZERO,
            right_method_kind: ZERO,
            is_top_level: ZERO,
        }
    }

    /// 转为列向量。
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        let mut v = Vec::with_capacity(cols::NUM_COLUMNS);
        v.push(self.is_active);
        v.push(self.is_padding);
        v.extend_from_slice(&self.left_pre_state_root);
        v.extend_from_slice(&self.left_post_state_root);
        v.extend_from_slice(&self.right_pre_state_root);
        v.extend_from_slice(&self.right_post_state_root);
        v.push(self.left_call_seq);
        v.push(self.right_call_seq);
        v.push(self.left_method_kind);
        v.push(self.right_method_kind);
        v.push(self.is_top_level);
        debug_assert_eq!(v.len(), cols::NUM_COLUMNS);
        v
    }
}

/// 二叉树聚合器：把 N 个 ChildDescriptor 聚合为 1 个根描述符。
///
/// 假设 `children` 已按 `call_seq` 升序排列。
/// 若 N 不是 2 的幂，padding 缺失节点为 identity（pre==post==前一个的 post）。
///
/// # 参数
/// - `children`: 已排序的子节点描述符列表
///
/// # 返回
/// `(root_descriptor, levels)` — 根描述符 + 每层的聚合行列表（用于 trace 生成）。
///
/// # Errors
///
/// 当 `children` 为空时返回错误。
pub fn build_binary_tree(
    children: Vec<ChildDescriptor>,
) -> crate::error::TexasAirResult<(ChildDescriptor, Vec<Vec<AggregatorRow>>)> {
    if children.is_empty() {
        return Err(crate::error::TexasAirError::RecursionError(
            "build_binary_tree: children 为空".into(),
        ));
    }

    let mut levels: Vec<Vec<AggregatorRow>> = Vec::new();

    // 单节点：直接返回（无聚合行）
    if children.len() == 1 {
        return Ok((children.into_iter().next().unwrap(), levels));
    }

    // Leaf descriptors represent consecutive VM calls. Merely requiring a
    // strictly increasing sequence permits deletion/splicing gaps such as
    // `10, 12`; the aggregate must reject those before constructing parents.
    for (index, pair) in children.windows(2).enumerate() {
        let expected = pair[0].call_seq.checked_add(1).ok_or_else(|| {
            crate::error::TexasAirError::RecursionError(format!(
                "build_binary_tree: call_seq overflow at child {index}"
            ))
        })?;
        if pair[1].call_seq != expected {
            return Err(crate::error::TexasAirError::RecursionError(format!(
                "build_binary_tree: call_seq 不连续 at index {index}..{}：right={}，期望 {}",
                index + 1,
                pair[1].call_seq,
                expected
            )));
        }
        if pair[0].post_state_root != pair[1].pre_state_root {
            return Err(crate::error::TexasAirError::RecursionError(format!(
                "build_binary_tree: 链式连续性破坏 at index {index}..{}：left.post != right.pre",
                index + 1
            )));
        }
    }

    // 二叉树层级聚合
    let mut current = children;
    while current.len() > 1 {
        let mut next: Vec<ChildDescriptor> = Vec::with_capacity((current.len() + 1) / 2);
        let mut level_rows: Vec<AggregatorRow> = Vec::with_capacity(current.len() / 2);

        let mut i = 0;
        while i + 1 < current.len() {
            let left = &current[i];
            let right = &current[i + 1];

            // 验证链式连续性（host 端预检查）
            if left.post_state_root != right.pre_state_root {
                return Err(crate::error::TexasAirError::RecursionError(format!(
                    "build_binary_tree: 链式连续性破坏 at index {i}..{}：left.post != right.pre",
                    i + 1
                )));
            }
            if right.call_seq <= left.call_seq {
                return Err(crate::error::TexasAirError::RecursionError(format!(
                    "build_binary_tree: call_seq 顺序错误 at index {i}..{}：right={} 必须 > left={}",
                    i + 1,
                    right.call_seq,
                    left.call_seq
                )));
            }

            // 构造聚合行（is_top_level 默认 false，循环结束后再标记顶层行）
            level_rows.push(AggregatorRow::active(left, right, false));

            // 父节点：pre = left.pre, post = right.post
            let parent = ChildDescriptor {
                pre_state_root: left.pre_state_root,
                post_state_root: right.post_state_root,
                call_seq: left.call_seq, // 父节点用左子的 call_seq 作为起始
                method_kind: left.method_kind, // 聚合节点不绑定单一方法
            };
            next.push(parent);
            i += 2;
        }

        // 奇数个节点：最后一个直接晋升到下一层
        if i < current.len() {
            next.push(current[i].clone());
        }

        levels.push(level_rows);
        current = next;
    }

    // 标记最后一层（顶层）的聚合行为 is_top_level = true
    // 顶层行的 left/right 描述符与 AIR 公开输入一致，需验证 method_kind/call_seq
    if let Some(top_level) = levels.last_mut() {
        for row in top_level {
            row.is_top_level = M31::from(1u32);
        }
    }

    Ok((current.into_iter().next().unwrap(), levels))
}

/// 把 u64 转 4 个 M31 limb（host 端辅助，复用 common 的实现）。
#[must_use]
pub fn u64_to_limbs(v: u64) -> [M31; 4] {
    u64_to_m31_limbs(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_child(seq: u32, kind: MethodKind, root_val: u32) -> ChildDescriptor {
        let root = [M31::from(root_val); 4];
        ChildDescriptor {
            pre_state_root: root,
            post_state_root: root,
            call_seq: seq,
            method_kind: kind,
        }
    }

    #[test]
    fn test_build_binary_tree_single() {
        let c = make_child(0, MethodKind::CreateTable, 1);
        let (root, levels) = build_binary_tree(vec![c.clone()]).unwrap();
        assert_eq!(root.call_seq, c.call_seq);
        assert!(levels.is_empty());
    }

    #[test]
    fn test_build_binary_tree_pair() {
        let mut left = make_child(0, MethodKind::CreateTable, 1);
        left.post_state_root = [M31::from(2u32); 4];
        let mut right = make_child(1, MethodKind::JoinTable, 2);
        right.pre_state_root = [M31::from(2u32); 4]; // 与 left.post 一致
        right.post_state_root = [M31::from(3u32); 4];

        let (root, levels) = build_binary_tree(vec![left.clone(), right.clone()]).unwrap();
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0].len(), 1);
        // 根节点的 pre == left.pre, post == right.post
        assert_eq!(root.pre_state_root, left.pre_state_root);
        assert_eq!(root.post_state_root, right.post_state_root);
    }

    #[test]
    fn test_build_binary_tree_chain_break() {
        let left = make_child(0, MethodKind::CreateTable, 1);
        let right = make_child(1, MethodKind::JoinTable, 99); // 不同 root — 连续性破坏
        let result = build_binary_tree(vec![left, right]);
        assert!(result.is_err(), "链式连续性破坏应返回错误");
    }

    #[test]
    fn test_build_binary_tree_seq_break() {
        // 顺序错误：right.call_seq < left.call_seq
        let mut left = make_child(5, MethodKind::CreateTable, 1);
        left.post_state_root = [M31::from(2u32); 4];
        let mut right = make_child(0, MethodKind::JoinTable, 2); // call_seq 反向
        right.pre_state_root = [M31::from(2u32); 4];
        let result = build_binary_tree(vec![left, right]);
        assert!(result.is_err(), "call_seq 反向应返回错误");
    }

    #[test]
    fn test_build_binary_tree_four_nodes() {
        // 4 个节点：3 层聚合（实际 2 层）
        let roots = [10u32, 20, 30, 40];
        let mut children: Vec<ChildDescriptor> = Vec::with_capacity(4);
        for (i, &r) in roots.iter().enumerate() {
            let mut c = make_child(i as u32, MethodKind::CreateTable, r);
            // post = 下一个的 pre（除最后一个）
            let next_root = if i + 1 < roots.len() { roots[i + 1] } else { r };
            c.post_state_root = [M31::from(next_root); 4];
            children.push(c);
        }
        // 调整：每个 child 的 pre == 上一个的 post
        for i in 1..children.len() {
            children[i].pre_state_root = children[i - 1].post_state_root;
        }

        let (root, levels) = build_binary_tree(children.clone()).unwrap();
        assert_eq!(levels.len(), 2, "4 个节点应有 2 层聚合");
        assert_eq!(levels[0].len(), 2, "底层应有 2 个聚合行");
        assert_eq!(levels[1].len(), 1, "顶层应有 1 个聚合行");
        // 根节点的 pre == children[0].pre, post == children[3].post
        assert_eq!(root.pre_state_root, children[0].pre_state_root);
        assert_eq!(root.post_state_root, children[3].post_state_root);
    }
}
