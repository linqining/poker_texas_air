import Mathlib

/-!
# M31 — stwo 的 31-bit 基域

stwo（Starkware prover，本库锁定 2.3.0）的所有 trace 列与约化域是 Mersenne
素域 `F_p`，`p = 2^31 - 1 = 2147483647`。本文件给出该域的 Lean 模型：

* `P`：模数，素性由 Lucas-Lehmer 判据的**机器计算**给出（`P_prime`）；
* `M31 := ZMod P`：与 stwo 的 `struct M31(pub u32)` 数学等价——Rust 侧的
  `partial_reduce`/`reduce` 位技巧只是表示层优化，语义即 `ZMod P` 的
  加/乘/负，该等价由 `StwoLean.Vectors` 中从真实 stwo 导出的测试向量逐算子钉死；
* `fpow`：可执行快速幂，与 `^` 一致（`fpow_eq_pow`），用于
  Euler-判据式的"非平方剩余"计算性证明；
* `neg_one_not_square`、`five_not_square`：`-1` 与 `5` 在 `F_p` 中非平方
  剩余。前者保证 `CM31 = F_p[i]`、后者保证 `QM31 = CM31[u]`（`u² = 2+i`）
  的 inverse 规约成立（见 `CM31`/`QM31` 的 norm 论证）。

出处：`stwo/src/core/fields/m31.rs`（常量 `P`、`pow2147483645`）。
-/

namespace StwoLean

/-- stwo 基域的模数：Mersenne 素数 `2^31 - 1`（`stwo::core::fields::m31::P`）。 -/
def P : ℕ := 2147483647

theorem P_val : P = 2 ^ 31 - 1 := rfl

theorem P_ne_zero : P ≠ 0 := by decide
theorem P_ne_one : P ≠ 1 := by decide
theorem P_ne_two : P ≠ 2 := by decide
theorem P_ne_five : P ≠ 5 := by decide
theorem P_odd : Odd P := ⟨2 ^ 30 - 1, by rw [P_val]; ring⟩

/-- `2 * ((P-1) / 2) = P - 1`（`P` 为奇数的直接推论）。 -/
theorem two_mul_half : 2 * ((P - 1) / 2) = P - 1 := by
  obtain ⟨k, hk⟩ : Even (P - 1) := ⟨2 ^ 30 - 1, by rw [P_val]; ring⟩
  omega

/-- **素性**：`2^31 - 1` 是素数。证明方式：mathlib 的 Lucas-Lehmer 充分性定理
+ Lucas-Lehmer 残差的直接机器计算（29 步模平方）。 -/
theorem P_prime : Nat.Prime P := by
  have h := lucas_lehmer_sufficiency 31 (by norm_num)
  refine h ?_
  show lucasLehmerResidue 31 = 0
  decide

instance : Fact (Nat.Prime P) := ⟨P_prime⟩

/-- stwo 基域。`abbrev` 使 `ZMod P` 的全部域结构直接可用。 -/
abbrev M31 := ZMod P

section Fpow

variable {M : Type*} [Monoid M]

/-- 有燃料版本的快速幂：对 `fuel` **结构递归**（`decide`/内核可归约，这是
不直接用 well-founded 递归的原因）。`fuel = 0` 时退化为朴素幂，该分支仅在
`n ≥ 2^fuel` 时可达，且其退化值 `x ^ n` 仍满足正确性定理。
奇偶判定用 `n % 2 = 0`（内核原生可归约）而非 `Even n`
（∃-型 Prop，Decidable 实例无法被 `decide` 归约）。 -/
def fpowF (fuel : ℕ) (x : M) (n : ℕ) : M :=
  match fuel with
  | 0 => x ^ n
  | (f + 1) =>
    if n = 0 then 1
    else if n % 2 = 0 then fpowF f (x * x) (n / 2)
    else x * fpowF f (x * x) (n / 2)

theorem fpowF_eq_pow : ∀ (fuel n : ℕ), n < 2 ^ fuel → ∀ x : M, fpowF fuel x n = x ^ n := by
  intro fuel
  induction fuel with
  | zero => intro n _ x; rfl
  | succ f ih =>
    intro n hn x
    simp only [fpowF]
    split_ifs with h0 he
    · exact (h0 ▸ pow_zero x).symm
    · have hkn : 2 * (n / 2) = n := by omega
      have hk : n / 2 < 2 ^ f := by
        have h2 : 2 ^ (f + 1) = 2 ^ f * 2 := pow_succ 2 f
        omega
      rw [ih (n / 2) hk (x * x), ← pow_two, ← pow_mul, hkn]
    · have hkn : 2 * (n / 2) + 1 = n := by omega
      have hk : n / 2 < 2 ^ f := by
        have h2 : 2 ^ (f + 1) = 2 ^ f * 2 := pow_succ 2 f
        omega
      rw [ih (n / 2) hk (x * x), ← pow_two, ← pow_mul, ← pow_succ', hkn]

/-- 可执行快速幂（binary square-and-multiply）。与 `^` 一致
（`fpow_eq_pow`），用于非平方剩余的可执行判定。 -/
def fpow (x : M) (n : ℕ) : M := fpowF (n + 1) x n

theorem lt_two_pow_succ : ∀ n : ℕ, n < 2 ^ (n + 1) := by
  intro m
  induction m with
  | zero => norm_num
  | succ m ih =>
    have h2 : 2 ^ (m + 1 + 1) = 2 ^ (m + 1) * 2 := pow_succ 2 (m + 1)
    omega

theorem fpow_eq_pow (x : M) (n : ℕ) : fpow x n = x ^ n := by
  exact fpowF_eq_pow (n + 1) n (lt_two_pow_succ n) x

end Fpow

section Nonsquare

/-- Euler 判据（必要方向）：`a = z²` 且 `z ≠ 0` 蕴含 `a^((P-1)/2) = 1`。
这是 `z^(P-1) = 1`（Fermat 小定理，`ZMod.pow_card_sub_one_eq_one`）的直接改写。 -/
theorem fpow_half_eq_one_of_eq_sq {a z : M31} (hz : z ≠ 0) (ha : a = z * z) :
    fpow a ((P - 1) / 2) = 1 := by
  subst ha
  rw [fpow_eq_pow, ← pow_two, ← pow_mul, two_mul_half, ZMod.pow_card_sub_one_eq_one hz]

/-- 非平方剩余的可执行判定：若 `a ≠ 0` 且快速幂算出 `a^((P-1)/2) ≠ 1`，
则 `a` 不是平方。 -/
theorem not_isSquare_of_fpow_half_ne_one {a : M31} (ha : a ≠ 0)
    (h : fpow a ((P - 1) / 2) ≠ 1) : ¬ IsSquare a := by
  rintro ⟨z, rfl⟩
  have hz : z ≠ 0 := by
    rintro rfl
    exact ha rfl
  exact h (fpow_half_eq_one_of_eq_sq hz rfl)

/-- `-1` 在 `F_P` 中非平方剩余（`P ≡ 3 (mod 4)` 的经典事实；
此处以快速幂机器计算给出）。 -/
theorem neg_one_not_square : ¬ IsSquare (-1 : M31) := by
  refine not_isSquare_of_fpow_half_ne_one (by decide) ?_
  decide

/-- `5` 在 `F_P` 中非平方剩余。经典表述：由二次互反律，`(5/P) = (P mod 5 / 5) =
(2/5) = -1`（`P ≡ 2 (mod 5)`）；此处直接以快速幂机器计算：`5^((P-1)/2) = -1`。 -/
theorem five_not_square : ¬ IsSquare (5 : M31) := by
  refine not_isSquare_of_fpow_half_ne_one (by decide) ?_
  decide

/-- 供后人审计的显式数值：`5^((P-1)/2) = -1`。 -/
theorem five_fpow_half : fpow (5 : M31) ((P - 1) / 2) = P - 1 := by decide

end Nonsquare

section SmokeTest
example : (19 : M31) * (5 : M31) = 95 := by decide
example : fpow (5 : M31) 6 = 15625 := by decide
example : fpow (19 : M31) 2147483645 = 1017229096 := by decide
end SmokeTest

end StwoLean
