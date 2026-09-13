import Mathlib
import StwoLean.M31

/-!
# CM31 — 复扩张 `F_p[i]`，`i² = -1`

对应 stwo `struct CM31(pub M31, pub M31)`（表示 `a + b·i`；出处
`stwo/src/core/fields/cm31.rs`，stwo 2.3.0）。乘法公式与该文件逐行对应：
`(a + bi)(c + di) = (ac - bd) + (ad + bc)i`。

核心内容：

* 环实例：在结构体上手写整个 `CommRing` 塔（每个字段证明都是
  `ext` + 分量 `ring` 的机械推理——显式表示换取可执行性的代价）；
* `norm`：`N(a+bi) = a² + b²`，乘性（`norm_mul`）；
* `norm_eq_zero`：`N(a) = 0 ↔ a = 0`——数论核心是 `-1` 非平方剩余
  （`M31.neg_one_not_square`，即 `p ≡ 3 (mod 4)` 的经典事实）；
* `Field` 实例：由 `inv a = conj a * (norm a)⁻¹` 构造，与 stwo 的
  `FieldExpOps::inverse`（`1/(a+bi) = (a-bi)/(a²+b²)`）公式一致。
-/

namespace StwoLean

/-- 复扩张 `F_p[i]`（`i² = -1`），stwo 的中间域。 -/
structure CM31 where
  /-- 实部 -/
  re : M31
  /-- 虚部 -/
  im : M31
  deriving DecidableEq

namespace CM31

instance : Zero CM31 := ⟨⟨0, 0⟩⟩
instance : One CM31 := ⟨⟨1, 0⟩⟩
instance : Inhabited CM31 := ⟨0⟩

instance : Add CM31 := ⟨fun a b => ⟨a.re + b.re, a.im + b.im⟩⟩
instance : Sub CM31 := ⟨fun a b => ⟨a.re - b.re, a.im - b.im⟩⟩
instance : Neg CM31 := ⟨fun a => ⟨-a.re, -a.im⟩⟩
instance : Mul CM31 :=
  ⟨fun a b => ⟨a.re * b.re - a.im * b.im, a.re * b.im + a.im * b.re⟩⟩

theorem zero_def : (0 : CM31) = ⟨0, 0⟩ := rfl
theorem one_def : (1 : CM31) = ⟨1, 0⟩ := rfl
theorem add_apply (a b : CM31) : a + b = ⟨a.re + b.re, a.im + b.im⟩ := rfl
theorem sub_apply (a b : CM31) : a - b = ⟨a.re - b.re, a.im - b.im⟩ := rfl
theorem neg_apply (a : CM31) : -a = ⟨-a.re, -a.im⟩ := rfl
theorem mul_apply (a b : CM31) :
    a * b = ⟨a.re * b.re - a.im * b.im, a.re * b.im + a.im * b.re⟩ := rfl

@[ext]
theorem ext {a b : CM31} (hre : a.re = b.re) (him : a.im = b.im) : a = b := by
  cases a
  cases b
  simp only [mk.injEq]
  exact ⟨hre, him⟩

@[simp] theorem zero_re : (0 : CM31).re = 0 := rfl
@[simp] theorem zero_im : (0 : CM31).im = 0 := rfl
@[simp] theorem one_re : (1 : CM31).re = 1 := rfl
@[simp] theorem one_im : (1 : CM31).im = 0 := rfl

/-- stwo 的 `CM31::from_u32_unchecked`。 -/
def ofU32 (a b : ℕ) : CM31 := ⟨a, b⟩

section Ring

/-- `F_p[i]` 的交换环结构（手写实例塔，各字段为分量级 `ring` 推理）。 -/
instance instCommRing : CommRing CM31 where
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
    ext <;> simp only [add_apply, zero_re, zero_im] <;> ring
  add_zero := by
    intro a
    ext <;> simp only [add_apply, zero_re, zero_im] <;> ring
  neg_add_cancel := by
    intro a
    ext <;> simp only [add_apply, neg_apply, zero_re, zero_im] <;> ring
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
    ext <;> simp only [mul_apply, one_re, one_im] <;> ring
  mul_one := by
    intro a
    ext <;> simp only [mul_apply, one_re, one_im] <;> ring
  left_distrib := by
    intro a b c
    ext <;> simp only [mul_apply, add_apply] <;> ring
  right_distrib := by
    intro a b c
    ext <;> simp only [mul_apply, add_apply] <;> ring
  zero_mul := by
    intro a
    ext <;> simp only [mul_apply, zero_re, zero_im] <;> ring
  mul_zero := by
    intro a
    ext <;> simp only [mul_apply, zero_re, zero_im] <;> ring
  nsmul := nsmulRec
  zsmul := zsmulRec

end Ring

instance instNontrivial : Nontrivial CM31 := ⟨⟨0, 1⟩, 0, fun h => by
  simpa [zero_def] using congrArg CM31.im h⟩

/-- 复共轭 `conj(a + bi) = a - bi`。 -/
def conj (a : CM31) : CM31 := ⟨a.re, -a.im⟩

theorem conj_apply (a : CM31) : conj a = ⟨a.re, -a.im⟩ := rfl

theorem conj_mul (a b : CM31) : conj (a * b) = conj a * conj b := by
  ext <;> simp only [mul_apply, conj_apply, neg_apply, add_apply] <;> ring

/-- 范数 `N(a + bi) = a² + b²`（stwo 注释中的 `a² + b²`）。 -/
def norm (a : CM31) : M31 := a.re * a.re + a.im * a.im

theorem norm_apply (a : CM31) : norm a = a.re * a.re + a.im * a.im := rfl

theorem mul_conj (a : CM31) : a * conj a = ⟨norm a, 0⟩ := by
  ext <;> simp only [mul_apply, conj_apply, norm_apply] <;> ring

/-- 范数乘性：`N(zw) = N(z)·N(w)`。 -/
theorem norm_mul (a b : CM31) : norm (a * b) = norm a * norm b := by
  simp only [norm_apply, mul_apply]
  ring

/-- 范数零判据：`N(a) = 0 ↔ a = 0`。正方向的数论核心是 `-1` 非平方剩余：
若 `a² + b² = 0` 且 `b ≠ 0`，则 `(a/b)² = -1`，与 `M31.neg_one_not_square`
矛盾。 -/
theorem norm_eq_zero {a : CM31} : norm a = 0 ↔ a = 0 := by
  refine ⟨fun h => ?_, fun h => by subst h; rfl⟩
  simp only [norm_apply] at h
  by_cases hy : a.im = 0
  · rw [hy] at h
    simp at h
    ext <;> simp [h, hy]
  · exfalso
    have hr : a.re * a.re = -(a.im * a.im) := add_eq_zero_iff_eq_neg.mp h
    exact neg_one_not_square ⟨a.re * a.im⁻¹, by
      have key : a.re * a.re * (a.im⁻¹ * a.im⁻¹) = -1 := by
        rw [hr, neg_mul, neg_inj, mul_assoc, ← mul_assoc a.im a.im⁻¹ a.im⁻¹,
          mul_inv_cancel₀ hy, one_mul, mul_inv_cancel₀ hy]
      rw [← key]
      ring⟩

/-- 标量乘 `c · a`（对应 stwo 自动派生的 `Mul<M31> for CM31`）。 -/
def smul (c : M31) (a : CM31) : CM31 := ⟨c * a.re, c * a.im⟩

theorem smul_apply (c : M31) (a : CM31) : smul c a = ⟨c * a.re, c * a.im⟩ := rfl

/-- 标量乘的结合：`a · (c · conj a) = c · (a · conj a)`。 -/
theorem mul_smul_conj (a : CM31) (c : M31) : a * smul c (conj a) = smul c (a * conj a) := by
  ext <;> simp only [mul_apply, smul_apply, conj_apply, neg_apply] <;> ring

/-- stwo 的 `CM31::inverse`：`1/(a+bi) = (a-bi)/(a²+b²)`
（Rust 侧为 `Self(self.0, -self.1) * (a²+b²).inverse()`，即标量乘）。 -/
noncomputable def inv (a : CM31) : CM31 := smul (norm a)⁻¹ (conj a)

theorem inv_apply (a : CM31) : inv a = smul (norm a)⁻¹ (conj a) := rfl

theorem mul_inv_cancel (a : CM31) (ha : a ≠ 0) : a * inv a = 1 := by
  have hnorm : norm a ≠ 0 := fun hn => ha (norm_eq_zero.mp hn)
  rw [inv_apply, mul_smul_conj, mul_conj, smul_apply,
    show (norm a)⁻¹ * norm a = 1 from inv_mul_cancel₀ hnorm, mul_zero]
  rfl

/-- `F_p[i]` 的求逆结构（域实例的 Inv 父类从这里委托）。 -/
noncomputable instance instInv : Inv CM31 := ⟨inv⟩

/-- `F_p[i]` 的域结构：inverse 即 stwo 的 norm 公式。 -/
noncomputable instance instField : Field CM31 where
  __ := instCommRing
  __ := instNontrivial
  __ := instInv
  div := fun a b => a * inv b
  div_eq_mul_inv := fun _ _ => rfl
  zpow := zpowRec
  mul_inv_cancel := mul_inv_cancel
  inv_zero := by
    show inv 0 = 0
    rw [inv_apply, smul_apply, conj_apply, norm_apply, zero_re, zero_im]
    simp [zero_def]
  nnqsmul := _
  nnqsmul_def := fun _ _ => rfl
  qsmul := _
  qsmul_def := fun _ _ => rfl

end CM31

end StwoLean
