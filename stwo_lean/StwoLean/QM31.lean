import Mathlib
import StwoLean.M31
import StwoLean.CM31

/-!
# QM31 — 安全域 `CM31[u]`，`u² = 2 + i`

对应 stwo `struct QM31(pub CM31, pub CM31)`（表示 `(a + bi) + (c + di)·u`；
出处 `stwo/src/core/fields/qm31.rs`，stwo 2.3.0，其中 `R = 2 + i`）。
乘法公式与该文件逐行对应：
`(a + bu)(c + du) = (ac + R·bd) + (ad + bc)u`。

核心内容：

* `CommRing`/`Field` 实例（同 CM31 的手写模式）；
* `norm : QM31 → CM31`，`N(a + bu) = a² - R·b²`，乘性；
* `norm_eq_zero`：数论核心是 `5 = N(2+i)` 在 `F_p` 中非平方剩余
  （`M31.five_not_square`）——这正是二次互反律的经典推论
  `(5/P) = (P mod 5 / 5) = (2/5) = -1`；
* `inv`：与 stwo `FieldExpOps::inverse` 公式一致
  （`(a+bu)⁻¹ = (a-bu)/(a² - (2+i)b²)`）。
-/

namespace StwoLean

/-- 安全域 `CM31[u]`（`u² = 2 + i`），stwo 的约化域。 -/
structure QM31 where
  /-- 常数部分 `a + bi` -/
  c0 : CM31
  /-- `u` 系数 `c + di` -/
  c1 : CM31
  deriving DecidableEq

namespace QM31

/-- 二次扩张常数 `u² = 2 + i`（stwo `qm31::R`）。 -/
def R : CM31 := ⟨2, 1⟩

theorem R_def : R = ⟨2, 1⟩ := rfl

theorem CM31_norm_R : CM31.norm R = 5 := by
  decide

instance : Zero QM31 := ⟨⟨0, 0⟩⟩
instance : One QM31 := ⟨⟨1, 0⟩⟩
instance : Inhabited QM31 := ⟨0⟩

instance : Add QM31 := ⟨fun a b => ⟨a.c0 + b.c0, a.c1 + b.c1⟩⟩
instance : Sub QM31 := ⟨fun a b => ⟨a.c0 - b.c0, a.c1 - b.c1⟩⟩
instance : Neg QM31 := ⟨fun a => ⟨-a.c0, -a.c1⟩⟩
instance : Mul QM31 :=
  ⟨fun a b => ⟨a.c0 * b.c0 + R * (a.c1 * b.c1), a.c0 * b.c1 + a.c1 * b.c0⟩⟩

theorem zero_def : (0 : QM31) = ⟨0, 0⟩ := rfl
theorem one_def : (1 : QM31) = ⟨1, 0⟩ := rfl
theorem add_apply (a b : QM31) : a + b = ⟨a.c0 + b.c0, a.c1 + b.c1⟩ := rfl
theorem sub_apply (a b : QM31) : a - b = ⟨a.c0 - b.c0, a.c1 - b.c1⟩ := rfl
theorem neg_apply (a : QM31) : -a = ⟨-a.c0, -a.c1⟩ := rfl
theorem mul_apply (a b : QM31) :
    a * b = ⟨a.c0 * b.c0 + R * (a.c1 * b.c1), a.c0 * b.c1 + a.c1 * b.c0⟩ := rfl

@[simp] theorem zero_c0 : (0 : QM31).c0 = 0 := rfl
@[simp] theorem zero_c1 : (0 : QM31).c1 = 0 := rfl
@[simp] theorem one_c0 : (1 : QM31).c0 = 1 := rfl
@[simp] theorem one_c1 : (1 : QM31).c1 = 0 := rfl

@[ext]
theorem ext {a b : QM31} (h0 : a.c0 = b.c0) (h1 : a.c1 = b.c1) : a = b := by
  cases a
  cases b
  simp only [mk.injEq]
  exact ⟨h0, h1⟩

/-- stwo 的 `QM31::from_u32_unchecked`。 -/
def ofU32 (a b c d : ℕ) : QM31 := ⟨⟨a, b⟩, ⟨c, d⟩⟩

/-- 标量乘 `c · x`，`c ∈ CM31`（对应 stwo `QM31::mul_cm31`）。 -/
def mulCM31 (x : QM31) (c : CM31) : QM31 := ⟨x.c0 * c, x.c1 * c⟩

theorem mulCM31_apply (x : QM31) (c : CM31) : mulCM31 x c = ⟨x.c0 * c, x.c1 * c⟩ := rfl

/-- 标量乘 `m · x`，`m ∈ M31`（对应 stwo 自动派生的 `Mul<BaseField> for
SecureField`；`fft::ibutterfly` 等处使用）。 -/
def mulM31 (x : QM31) (m : M31) : QM31 := mulCM31 x (CM31.ofU32 m.val 0)

section Ring

instance : CommRing QM31 where
  zero := 0
  one := 1
  add := (· + ·)
  mul := (· * ·)
  neg := fun a => -a
  sub := fun a b => a - b
  add_assoc := by
    intro a b c
    ext <;> simp only [add_apply] <;> ring
  add_comm := by
    intro a b
    ext <;> simp only [add_apply] <;> ring
  zero_add := by
    intro a
    ext <;> simp only [add_apply, zero_c0, zero_c1] <;> ring
  add_zero := by
    intro a
    ext <;> simp only [add_apply, zero_c0, zero_c1] <;> ring
  neg_add_cancel := by
    intro a
    ext <;> simp only [add_apply, neg_apply, zero_c0, zero_c1] <;> ring
  sub_eq_add_neg := by
    intro a b
    ext <;> simp only [sub_apply, add_apply, neg_apply] <;> ring
  mul_assoc := by
    intro a b c
    ext <;> simp only [mul_apply] <;> ring
  mul_comm := by
    intro a b
    ext <;> simp only [mul_apply] <;> ring
  one_mul := by
    intro a
    ext <;> simp only [mul_apply, one_c0, one_c1] <;> ring
  mul_one := by
    intro a
    ext <;> simp only [mul_apply, one_c0, one_c1] <;> ring
  left_distrib := by
    intro a b c
    ext <;> simp only [mul_apply, add_apply] <;> ring
  right_distrib := by
    intro a b c
    ext <;> simp only [mul_apply, add_apply] <;> ring
  zero_mul := by
    intro a
    ext <;> simp only [mul_apply, zero_c0, zero_c1] <;> ring
  mul_zero := by
    intro a
    ext <;> simp only [mul_apply, zero_c0, zero_c1] <;> ring
  nsmul := nsmulRec
  zsmul := zsmulRec

end Ring

instance instNontrivial : Nontrivial QM31 := ⟨⟨0, 1⟩, 0, fun h => by
  simpa [zero_def] using congrArg QM31.c1 h⟩

/-- `u`-共轭 `conj(a + bu) = a - bu`。 -/
def conj (x : QM31) : QM31 := ⟨x.c0, -x.c1⟩

theorem conj_apply (x : QM31) : conj x = ⟨x.c0, -x.c1⟩ := rfl

theorem conj_mul (x y : QM31) : conj (x * y) = conj x * conj y := by
  ext <;> simp only [mul_apply, conj_apply, neg_apply, add_apply] <;> ring

/-- 范数 `N(a + bu) = a² - R·b²`。对应 stwo inverse 中的
`denom = a² - (b² + b² + i·b²)`（注意 `2·b² + i·b² = (2+i)·b² = R·b²`）。 -/
def norm (x : QM31) : CM31 := x.c0 * x.c0 - R * (x.c1 * x.c1)

theorem norm_apply (x : QM31) : norm x = x.c0 * x.c0 - R * (x.c1 * x.c1) := rfl

theorem mul_conj (x : QM31) : x * conj x = ⟨norm x, 0⟩ := by
  ext <;> simp only [mul_apply, conj_apply, norm_apply] <;> ring

/-- 范数乘性：`N(xy) = N(x)·N(y)`。 -/
theorem norm_mul (x y : QM31) : norm (x * y) = norm x * norm y := by
  simp only [norm_apply, mul_apply]
  ring

/-- 范数零判据：`N(x) = 0 ↔ x = 0`。正方向的数论核心：若 `c ≠ 0` 且
`c0² = R·c1²`，则 `(c0/c1)² = R = 2+i`，于是 `5 = N(2+i) = N((c0/c1)²) =
N(c0/c1)²` 是 `F_p` 中的平方，与 `M31.five_not_square` 矛盾。 -/
theorem norm_eq_zero {x : QM31} : norm x = 0 ↔ x = 0 := by
  refine ⟨fun h => ?_, fun h => by subst h; rfl⟩
  simp only [norm_apply] at h
  by_cases hc : x.c1 = 0
  · rw [hc] at h
    simp at h
    ext <;> simp [h, hc]
  · exfalso
    have hkey : x.c0 * x.c0 = R * (x.c1 * x.c1) :=
      eq_of_sub_eq_zero h
    have hcancel : (x.c1 * x.c1) * (x.c1⁻¹ * x.c1⁻¹) = 1 := by
      rw [← sq, ← sq, inv_pow, mul_inv_cancel₀ (pow_ne_zero 2 hc)]
    have hnorm5 : CM31.norm (x.c0 * x.c1⁻¹) * CM31.norm (x.c0 * x.c1⁻¹) = 5 := by
      rw [← CM31_norm_R, ← CM31.norm_mul]
      congr 1
      rw [← sq, mul_pow, pow_two, pow_two, hkey, mul_assoc, hcancel, mul_one]
    exact five_not_square ⟨_, hnorm5.symm⟩

/-- stwo 的 `QM31::inverse`：`(a+bu)⁻¹ = (a-bu)/(a² - (2+i)b²)`。 -/
noncomputable def inv (x : QM31) : QM31 := mulCM31 (conj x) (norm x)⁻¹

theorem inv_apply (x : QM31) : inv x = mulCM31 (conj x) (norm x)⁻¹ := rfl

theorem mul_smul_conj (x : QM31) (c : CM31) : x * mulCM31 (conj x) c = mulCM31 (x * conj x) c := by
  ext <;> simp only [mul_apply, mulCM31_apply, conj_apply, neg_apply] <;> ring

theorem mul_inv_cancel (x : QM31) (hx : x ≠ 0) : x * inv x = 1 := by
  have hnorm : norm x ≠ 0 := fun hn => hx (norm_eq_zero.mp hn)
  rw [inv_apply, mul_smul_conj, mul_conj,
    show mulCM31 (⟨norm x, 0⟩ : QM31) (norm x)⁻¹
        = ⟨norm x * (norm x)⁻¹, 0 * (norm x)⁻¹⟩ from rfl,
    mul_inv_cancel₀ hnorm, zero_mul]
  rfl

/-- `CM31[u]` 的域结构：inverse 即 stwo 的 norm 公式。 -/
noncomputable instance instInv : Inv QM31 := ⟨inv⟩

noncomputable instance instField : Field QM31 where
  __ := instCommRing
  __ := instNontrivial
  __ := instInv
  div := fun a b => a * inv b
  div_eq_mul_inv := fun _ _ => rfl
  zpow := zpowRec
  mul_inv_cancel := mul_inv_cancel
  inv_zero := by
    show inv 0 = 0
    rw [inv_apply, mulCM31_apply, conj_apply, norm_apply, zero_c0, zero_c1]
    simp [zero_def]
  nnqsmul := _
  nnqsmul_def := fun _ _ => rfl
  qsmul := _
  qsmul_def := fun _ _ => rfl

end QM31

end StwoLean
