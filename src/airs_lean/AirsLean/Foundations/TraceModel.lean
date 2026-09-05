import AirsLean.Foundations.CarryArith

/-!
# TraceModel — trace 与 AIR 约束系统模型

AIR 的语义模型：一条 trace 是 `numRows × numCols` 的 M31 矩阵；一个 AIR
的约束系统表示为 trace 上的谓词 `ConstraintSystem`。本文件建立：

- 行级门控原语：`M31Bool`（boolean witness）、`OneHotSel`（one-hot selector，
  对齐 29 个 `CanonicalTransitionKind` selector 与 8 个 tagged action tag）；
- `PaddingRow` / `TracePrefixPad`：active 行前缀 + padding 全零后缀的划分
  （对齐 `COL_IS_PADDING`）；
- 关键引理：
  - `one_hot_unique`：one-hot ⇒ 恰好一个 selector 为 1（transition kind
    唯一可判定）；
  - `padding_row_zero`：padding 行除 padding 标志外全零——padding 行无法
    走私任何非零业务字段。

出处：`src/airs/common.rs`（`COL_IS_PADDING`、通用列布局）；
`src/texas_canonical_air.rs`（29 selector、active-prefix、预处理列）。
-/

namespace AirsLean

/-- 一行 trace：列索引 → M31 值。 -/
def Row := ℕ → M31

/-- 一条 trace：固定列数与行数，`cell col row` 取值。 -/
structure Trace where
  numCols : ℕ
  numRows : ℕ
  cell : ℕ → ℕ → M31

/-- 约束满足：约束系统成立在给定 trace 上。

Lean 侧把 Rust evaluator 施加的约束集合建模为谓词；"Rust 约束表达式
↔ Lean 谓词逐条对应"是审计义务项（见 PLAN.md §0），不在证明内部。 -/
def Sat (cs : Trace → Prop) (t : Trace) : Prop := cs t

/-- boolean 值的 ℕ 上界。 -/
lemma M31Bool.val_le {v : M31} (h : M31Bool v) : v.val ≤ 1 := by
  rcases h.val with h' | h' <;> omega

/-- `v = 1` 时其 `.val` 为 1（(1 : M31) 无模约减）。 -/
lemma val_of_one {v : M31} (h : v = 1) : v.val = 1 :=
  (M31Bool.val (Or.inr h)).resolve_left (by simp [h])

/-- one-hot selector 家族：每个 selector 都是 boolean，且总和为 1。

对齐 canonical AIR 的 29 个 transition-kind selector 列与 tagged AIR 的
8 个 action tag 列；`hn` 在所有实际 AIR 中成立（n ≤ 29 < p）。 -/
def OneHotSel {n : ℕ} (sel : Fin n → M31) : Prop :=
  (∑ i, sel i = 1) ∧ ∀ i, M31Bool (sel i)

/-- **one-hot 的语义**：one-hot selector 家族中恰好一个 selector 为 1。
transition kind 由此唯一可判定。 -/
theorem one_hot_unique {n : ℕ} (sel : Fin n → M31) (hn : n < M31P)
    (h : OneHotSel sel) : ∃! i : Fin n, sel i = 1 := by
  obtain ⟨hsum, hbool⟩ := h
  rw [M31P_eq] at hn
  have hval : ∀ i, (sel i).val = 0 ∨ (sel i).val = 1 := fun i => (hbool i).val
  have hcnt : (∑ i : Fin n, (sel i).val) = 1 := by
    have hbound : (∑ i : Fin n, (sel i).val) ≤ n := by
      calc (∑ i : Fin n, (sel i).val) ≤ ∑ _i : Fin n, 1 :=
          Finset.sum_le_sum fun i _ => (hbool i).val_le
        _ = n := by simp
    refine M31.natCast_inj (by show (∑ i : Fin n, (sel i).val) < 2147483647; omega)
      (by show 1 < 2147483647; norm_num) ?_
    have hcast' : (∑ i : Fin n, ((sel i).val : ℕ) : M31) = ∑ i : Fin n, sel i :=
      Finset.sum_congr rfl fun i _ => by simp
    rw [Nat.cast_sum, hcast', hsum]
    simp
  -- 存在性：全不为 1 则全为 0，与计数 1 矛盾
  obtain ⟨i, hi⟩ : ∃ i, sel i = 1 := by
    by_contra hnone
    push_neg at hnone
    have hz : ∀ i, (sel i).val = 0 := by
      intro i
      rcases hval i with h' | h'
      · exact h'
      · exfalso
        apply hnone i
        have hcast : sel i = ((sel i).val : ℕ) := by simp
        rw [hcast, h', Nat.cast_one]
    rw [Finset.sum_eq_zero (fun i _ => hz i)] at hcnt
    omega
  refine ⟨i, hi, fun j hj => ?_⟩
  -- 唯一性：两个 1 使计数 ≥ 2
  by_contra hne
  have vi : (sel i).val = 1 := val_of_one hi
  have vj : (sel j).val = 1 := val_of_one hj
  have hin : i ∉ ({j} : Finset (Fin n)) := by
    intro hmem
    exact hne (Finset.mem_singleton.mp hmem).symm
  have hmem : (sel i).val + (sel j).val
      = ∑ k ∈ ({i, j} : Finset (Fin n)), (sel k).val := by
    rw [Finset.sum_insert (s := ({j} : Finset (Fin n))) hin, Finset.sum_singleton]
  have hsub : ∑ k ∈ ({i, j} : Finset (Fin n)), (sel k).val
      ≤ ∑ k : Fin n, (sel k).val :=
    Finset.sum_le_sum_of_subset (fun x _ => Finset.mem_univ x)
  omega

/-- padding 行：padding 标志列为 1，其余列全零。

对齐 `COL_IS_PADDING`：padding 行除标志外全部置零，不承载业务约束。 -/
def PaddingRow (padCol numCols : ℕ) (row : Row) : Prop :=
  row padCol = 1 ∧ ∀ c ≠ padCol, c < numCols → row c = 0

/-- padding 行的语义：任何非 padding 列在该行取零——padding 无法走私
非零业务字段。 -/
theorem padding_row_zero {padCol numCols : ℕ} {row : Row}
    (hp : PaddingRow padCol numCols row) {c : ℕ} (hnc : c ≠ padCol) (hclt : c < numCols) :
    row c = 0 := hp.2 c hnc hclt

/-- active 前缀 + padding 后缀：行号 ≥ k 的行都是 padding 行。 -/
def TracePrefixPad (t : Trace) (padCol k : ℕ) : Prop :=
  ∀ j ≥ k, j < t.numRows → PaddingRow padCol t.numCols (t.cell · j)

end AirsLean
