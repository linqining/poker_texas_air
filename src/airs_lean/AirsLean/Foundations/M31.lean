import Mathlib

/-!
# M31 — Stwo 的 31-bit 素域

AIR trace 的每个单元是 `F_p`（`p = 2^31 - 1 = 2147483647`，Mersenne 素数）中
的元素。本文件建模该域并提供"小值单射性"桥梁：

M31 中的加法/线性组合是**模 p** 的，而 AIR 关心的资金数值是 `u64`。
整个 soundness 论证依赖的事实是：**当涉及的自然数和都小于 p 时，
M31 等式可以无回绕地提升为 ℕ 等式**（`M31.natCast_inj`、`M31.add_inj`、
`M31.lin_inj`）。16-bit limb 分解（`AirsLean.Foundations.Limbs`）与逐 limb
进位约束正是保证这一前提的机制。

出处：`stwo::core::fields::m31`；`src/airs/common.rs`（`M31` 的使用方式）。
-/

/-- Stwo M31 素数 `2^31 - 1`。 -/
abbrev M31P : ℕ := 2147483647

/-- 供 simp/omega 解开缩写（omega 把缩写视为不透明原子）。 -/
lemma M31P_eq : M31P = 2147483647 := rfl

/-- `M31P` 是素数（Mersenne 素数 M31）。 -/
instance M31P.prime : Fact (Nat.Prime M31P) := ⟨by norm_num⟩

/-- AIR trace 单元的域：`F_{2^31-1}`。 -/
abbrev M31 := ZMod M31P

namespace M31

/-- `2^16 < p`：16-bit limb 的加法组合不会触及模约减。 -/
lemma pow16_lt_p : (2 : ℕ) ^ 16 < M31P := by norm_num

/-- `2^17 < p`：两个 16-bit limb 带进位相加仍在 p 之下。 -/
lemma pow17_lt_p : (2 : ℕ) ^ 17 < M31P := by norm_num

/-- `2^32 ≥ p`：多 limb 加权组合在 M31 中会回绕——这是 limb range check
与逐 limb 进位约束不可省略的原因（见 `AirsLean.Foundations.Limbs`）。 -/
lemma pow32_ge_p : ¬ (2 : ℕ) ^ 32 < M31P := by norm_num

/-- 自然数到 M31 的投射在 `[0, p)` 上单射：M31 等式在小值上提升为 ℕ 等式。 -/
lemma natCast_inj {x y : ℕ} (hx : x < M31P) (hy : y < M31P)
    (h : (x : M31) = (y : M31)) : x = y := by
  have hval : (x : M31).val = (y : M31).val := by rw [h]
  rw [ZMod.val_natCast, ZMod.val_natCast, Nat.mod_eq_of_lt hx, Nat.mod_eq_of_lt hy] at hval
  exact hval

/-- 小值上的和等式：若 `a + b < p` 且 `c + d < p`，则 M31 等式 `a+b = c+d`
提升为 ℕ 等式。这是把 limb 方程从域语义搬到自然数语义的标准桥。 -/
lemma add_inj {a b c d : ℕ} (h1 : a + b < M31P) (h2 : c + d < M31P)
    (h : (a : M31) + (b : M31) = (c : M31) + (d : M31)) : a + b = c + d := by
  refine natCast_inj h1 h2 ?_
  simpa [Nat.cast_add] using h

/-- 小值上的线性等式：若 `a + k·b < p` 且 `c < p`，则 M31 等式
`a + k·b = c` 提升为 ℕ 等式。`k = 2^16` 时覆盖 limb 加权约束。 -/
lemma lin_inj {a b c : ℕ} (k : ℕ) (h1 : a + k * b < M31P) (h2 : c < M31P)
    (h : (a : M31) + (k : M31) * (b : M31) = (c : M31)) : a + k * b = c := by
  refine natCast_inj h1 h2 ?_
  simpa [Nat.cast_add, Nat.cast_mul] using h

/-- 非零的小自然数值在 M31 中非零（用于 amount > 0 的可逆性 witness，
对齐 `INPUT_AMOUNT_INV` 的 invertibility 论证）。 -/
lemma natCast16_ne_zero {n : ℕ} (hn0 : n ≠ 0) (h : n < 2 ^ 16) : (n : M31) ≠ 0 := by
  intro hz
  have hn : n < M31P := by rw [M31P_eq]; omega
  have h0 : (0 : ℕ) < M31P := by rw [M31P_eq]; norm_num
  have : n = 0 := natCast_inj hn h0 (by rw [Nat.cast_zero]; exact hz)
  exact hn0 this

end M31
