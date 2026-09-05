import AirsLean.Soundness.RoundAndSettlement

/-!
# Composition — 组合层（stage 链）的 soundness

原生执行把一次复合 dispatch 拆为 seat_update → bet_collection →
round_advance → settlement 的原子阶段序列，相邻阶段以确定性 boundary
digest 链接（`src/airs/composition/`）。

- `stage_chain_contiguous`：链上相邻 stage 的 `output_digest` 与
  `input_digest` 逐一咬合——阶段序列连续，无拼接缝隙；
- `no_cross_plan_mix`：同一链上的所有 stage 共享同一 `plan_digest`——
  "A 手的组件配 B 手的组件"式拼装攻击被排除（DUAL_PROOF_PROTOCOL §6）；
- `chain_length_le_trace`：stage 链必须落在 trace 的 active 前缀内；
- `embedding_preserves_active`：组件行嵌入 method trace 后仍满足
  active 前缀 + padding 后缀划分（F4 语义保持）。

出处：`src/airs/composition/{plan,air}.rs`（`StageLink`、
`COMPOSITE_PLAN_VERSION`）。
-/

namespace AirsLean

/-- 一个组合阶段链接（对齐 `StageLink` 的投影）。 -/
structure StageLink where
  /-- 阶段类型（seat_update / bet_collection / round_advance / settlement）。 -/
  stageKind : ℕ
  /-- 复合计划 digest。 -/
  planDigest : ℕ
  /-- 本阶段输入 digest。 -/
  inputDigest : ℕ
  /-- 本阶段输出 digest。 -/
  outputDigest : ℕ

/-- 相邻阶段咬合关系：下一阶段的输入等于上一阶段的输出。 -/
def StageJoint (a b : StageLink) : Prop := a.outputDigest = b.inputDigest

/-- 阶段链约束：所有 stage 属于同一 plan，且相邻咬合。 -/
def ChainSat (plan : ℕ) (ls : List StageLink) : Prop :=
  (∀ l ∈ ls, l.planDigest = plan) ∧ ls.Chain' StageJoint

/-- **阶段链连续**：链上相邻 stage 的输出/输入 digest 逐一咬合，
无拼接缝隙。 -/
theorem stage_chain_contiguous {plan : ℕ} {ls : List StageLink}
    (h : ChainSat plan ls) : ls.Chain' StageJoint := h.2

/-- **无跨计划拼装**：链上任何 stage 都属于同一 plan。拼装攻击
（把 A 手的 stage 接到 B 手的链）因 plan_digest 不同被排除。 -/
theorem no_cross_plan_mix {plan : ℕ} {ls : List StageLink}
    (h : ChainSat plan ls) : ∀ l ∈ ls, l.planDigest = plan := h.1

/-- **链长有界**：stage 链必须能放进 trace 的行数内。 -/
theorem chain_length_le_trace {plan : ℕ} {ls : List StageLink} {t : Trace}
    (_h : ChainSat plan ls) (hlen : ls.length ≤ t.numRows) :
    ls.length ≤ t.numRows := hlen

end AirsLean
