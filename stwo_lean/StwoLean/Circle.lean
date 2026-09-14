import Mathlib
import StwoLean.M31
import StwoLean.QM31

/-!
# Circle — 圆群 `x² + y² = 1`

对应 stwo `struct CirclePoint<F>`（出处 `stwo/src/core/circle.rs`，
stwo 2.3.0）。Circle STARK 的多项式域不是乘法群而是这个圆群：M31 圆群的
阶是 `p + 1 = 2^31`，FRI 的 domain 即其 2-pri 子群/陪集。

核心内容：

* `cpAdd`：群运算 = 复数乘法公式，与 stwo `Add for CirclePoint` 逐行对应；
* `onCircle` 封闭性（Brahmagupta 恒等式）、`conj` 是圆上的逆元；
* `doubleX`：x 坐标倍增映射，`(p ∘ p).x = doubleX p.x`；
* `repeatedDouble` / `mulScalar` 及 spec 关系
  `repeatedDouble p n = mulScalar (2^n) p`；
* 生成元机器验证：
  - `m31Gen = (2, 1268011823)`（stwo `M31_CIRCLE_GEN`）：在圆上，且阶恰为
    `2^31`（31 次倍增到单位元、30 次不到，纯 `decide`）；
  - `secureGen`（stwo `SECURE_FIELD_CIRCLE_GEN`）：在圆上（`decide`）；
    阶的完整机器验证需要二进制标量乘，见 README 路线图；
* `getRandomPoint`：stwo `get_random_point` 的确定性公式（channel 抽取
  显式参数化为 `t`），并证明结果在圆上（`1 + t² ≠ 0` 条件显式化——
  stwo 侧该条件成立依赖 `t ≠ ±i`，由 channel 抽取概率保证）。
-/

namespace StwoLean

/-- 圆群点（stwo `CirclePoint<F>`）。 -/
structure CirclePoint (F : Type*) where
  /-- x 坐标 -/
  x : F
  /-- y 坐标 -/
  y : F
  deriving DecidableEq

namespace CirclePoint

variable {F : Type*} [CommRing F]

@[ext]
theorem ext {p q : CirclePoint F} (hx : p.x = q.x) (hy : p.y = q.y) : p = q := by
  cases p
  cases q
  simp only [mk.injEq]
  exact ⟨hx, hy⟩

/-- 群单位元 `(1, 0)`（stwo `CirclePoint::zero`）。 -/
def pointOne [One F] [Zero F] : CirclePoint F := ⟨1, 0⟩

@[simp] theorem pointOne_x [One F] [Zero F] : (pointOne : CirclePoint F).x = 1 := rfl
@[simp] theorem pointOne_y [One F] [Zero F] : (pointOne : CirclePoint F).y = 0 := rfl

/-- 圆群加法 = 复数乘法公式。 -/
def cpAdd (p q : CirclePoint F) : CirclePoint F :=
  ⟨p.x * q.x - p.y * q.y, p.x * q.y + p.y * q.x⟩

theorem cpAdd_apply (p q : CirclePoint F) :
    cpAdd p q = ⟨p.x * q.x - p.y * q.y, p.x * q.y + p.y * q.x⟩ := rfl

theorem cpAdd_comm (p q : CirclePoint F) : cpAdd p q = cpAdd q p := by
  ext <;> simp only [cpAdd_apply] <;> ring

theorem cpAdd_assoc (p q r : CirclePoint F) :
    cpAdd (cpAdd p q) r = cpAdd p (cpAdd q r) := by
  ext <;> simp only [cpAdd_apply] <;> ring

theorem pointOne_cpAdd {p : CirclePoint F} : cpAdd pointOne p = p := by
  ext <;> simp only [cpAdd_apply, pointOne_x, pointOne_y] <;> ring

theorem cpAdd_pointOne {p : CirclePoint F} : cpAdd p pointOne = p := by
  rw [cpAdd_comm, pointOne_cpAdd]

/-- 在圆上：`x² + y² = 1`。 -/
def onCircle (p : CirclePoint F) : Prop := p.x ^ 2 + p.y ^ 2 = 1

/-- 复共轭点 `(x, -y)`（stwo `conjugate`，即群逆元）。 -/
def conj (p : CirclePoint F) : CirclePoint F := ⟨p.x, -p.y⟩

theorem conj_apply (p : CirclePoint F) : conj p = ⟨p.x, -p.y⟩ := rfl

/-- 对径点 `(−x, −y)`（stwo `antipode`）。 -/
def antipode (p : CirclePoint F) : CirclePoint F := ⟨-p.x, -p.y⟩

theorem onCircle_conj {p : CirclePoint F} (h : onCircle p) : onCircle (conj p) := by
  show p.x ^ 2 + (-p.y) ^ 2 = 1
  rw [neg_sq]
  exact h

theorem onCircle_antipode {p : CirclePoint F} (h : onCircle p) :
    onCircle (antipode p) := by
  show (-p.x) ^ 2 + (-p.y) ^ 2 = 1
  rw [neg_sq, neg_sq]
  exact h

/-- 圆对加法封闭（Brahmagupta 恒等式）。 -/
theorem onCircle_cpAdd {p q : CirclePoint F} (hp : onCircle p) (hq : onCircle q) :
    onCircle (cpAdd p q) := by
  show (p.x * q.x - p.y * q.y) ^ 2 + (p.x * q.y + p.y * q.x) ^ 2 = 1
  have h : (p.x * q.x - p.y * q.y) ^ 2 + (p.x * q.y + p.y * q.x) ^ 2
      = (p.x ^ 2 + p.y ^ 2) * (q.x ^ 2 + q.y ^ 2) := by ring
  rw [h, hp, hq, one_mul]

/-- 圆上共轭即逆元。 -/
theorem conj_cpAdd_eq_pointOne {p : CirclePoint F} (h : onCircle p) :
    cpAdd p (conj p) = pointOne := by
  ext
  · show p.x * p.x - p.y * -p.y = 1
    rw [show p.x * p.x = p.x ^ 2 from (pow_two _).symm, mul_neg, sub_neg_eq_add, ← sq]
    exact h
  · show p.x * -p.y + p.y * p.x = 0
    ring

/-- x 坐标倍增映射（stwo `CirclePoint::double_x`：`sx + sx - 1`）。 -/
def doubleX (x : F) : F := x * x + x * x - 1

/-- 倍点的 x 坐标 = `doubleX`。 -/
theorem double_x_coord {p : CirclePoint F} (h : onCircle p) :
    (cpAdd p p).x = doubleX p.x := by
  show p.x * p.x - p.y * p.y = p.x * p.x + p.x * p.x - 1
  have hy : p.y ^ 2 = 1 - p.x ^ 2 := by
    have h2 : p.x ^ 2 + p.y ^ 2 = 1 := h
    calc p.y ^ 2 = p.x ^ 2 + p.y ^ 2 - p.x ^ 2 := by ring
      _ = 1 - p.x ^ 2 := by rw [h2]
  rw [← pow_two, ← pow_two, hy]
  ring

/-- `p` 连续自加 `n` 次（stwo `repeated_double`）。 -/
def repeatedDouble (p : CirclePoint F) : ℕ → CirclePoint F
  | 0 => p
  | n + 1 => cpAdd (repeatedDouble p n) (repeatedDouble p n)

theorem repeatedDouble_onCircle {p : CirclePoint F} (h : onCircle p) (n : ℕ) :
    onCircle (repeatedDouble p n) := by
  induction n with
  | zero => exact h
  | succ n ih => exact onCircle_cpAdd ih ih

/-- 线性标量乘：`n · p = p ∘ … ∘ p`（单位元 `pointOne`）。数学上与 stwo 的
double-and-add 标量乘等价；大二进制标量的可执行验证见 README 路线图。 -/
def mulScalar (n : ℕ) (p : CirclePoint F) : CirclePoint F :=
  match n with
  | 0 => pointOne
  | n + 1 => cpAdd p (mulScalar n p)

theorem mulScalar_succ (n : ℕ) (p : CirclePoint F) :
    mulScalar (n + 1) p = cpAdd p (mulScalar n p) := rfl

theorem mulScalar_one (p : CirclePoint F) : mulScalar 1 p = cpAdd p pointOne := rfl

theorem mulScalar_add (a b : ℕ) (p : CirclePoint F) :
    mulScalar (a + b) p = cpAdd (mulScalar a p) (mulScalar b p) := by
  induction b with
  | zero => rw [Nat.add_zero, mulScalar, cpAdd_pointOne]
  | succ b ih =>
    rw [Nat.add_succ, mulScalar, mulScalar, ih,
      cpAdd_comm p (cpAdd (mulScalar a p) (mulScalar b p)),
      cpAdd_assoc, cpAdd_comm (mulScalar b p) p]

/-- 自加 `n` 次等于标量乘 `2^n`。 -/
theorem repeatedDouble_eq_mulScalar (p : CirclePoint F) (n : ℕ) :
    repeatedDouble p n = mulScalar (2 ^ n) p := by
  induction n with
  | zero => rw [repeatedDouble, pow_zero, mulScalar_one, cpAdd_pointOne]
  | succ n ih =>
    rw [repeatedDouble, ih, ← mulScalar_add, pow_succ', two_mul]

/-- `n` 的低位在前比特表（燃料结构递归，内核可归约）。 -/
def natBitsAux : Nat → Nat → List Bool
  | 0, _ => []
  | fuel + 1, n => (n % 2 == 1) :: natBitsAux fuel (n / 2)

/-- `n` 的 31 位低位在前比特表（CirclePointIndex 环 `ZMod 2^31` 的宽度）。 -/
def natBits31 (n : Nat) : List Bool := natBitsAux 31 n

/-- 二进制标量乘（double-and-add，与 stwo `CirclePoint::mul` 同构）：
按低位比特表逐位处理，`cur` 每层自倍，比特为 1 时并入累加器。
线性 `mulScalar` 对 2^31 级索引不可执行，域点计算统一走本函数。 -/
def mulBitsAux (p : CirclePoint F) : List Bool → CirclePoint F → CirclePoint F → CirclePoint F
  | [], _, acc => acc
  | b :: bs, cur, acc =>
    mulBitsAux p bs (cpAdd cur cur) (if b then cpAdd acc cur else acc)

/-- 标量乘的二进制版本。`cur` 初值为 `p`，`acc` 初值为单位元。 -/
def mulBinary (p : CirclePoint F) (n : Nat) : CirclePoint F :=
  mulBitsAux p (natBits31 n) p pointOne

section Generators

/-- M31 圆群生成元（stwo `M31_CIRCLE_GEN = (2, 1268011823)`）。 -/
def m31Gen : CirclePoint M31 := ⟨2, 1268011823⟩

theorem m31Gen_onCircle : onCircle m31Gen := by
  show m31Gen.x ^ 2 + m31Gen.y ^ 2 = 1
  decide

/-- **M31 圆群生成元的阶是 2^31**：自加 `2^31` 次回到单位元（对应 stwo
doctest `M31_CIRCLE_GEN.repeated_double(31) == zero()`），机器计算验证。 -/
theorem m31Gen_repeatedDouble_31 : repeatedDouble m31Gen 31 = pointOne := by
  ext <;> decide

/-- 且 `2^30` 次不到单位元（阶恰为 `2^31`，对应 stwo doctest）。 -/
theorem m31Gen_repeatedDouble_30_ne : repeatedDouble m31Gen 30 ≠ pointOne := by
  intro hcon
  exact absurd (congrArg CirclePoint.x hcon)
    (by decide : ¬ ((repeatedDouble m31Gen 30).x = pointOne.x))

/-- 安全域圆群生成元（stwo `SECURE_FIELD_CIRCLE_GEN`）。 -/
def secureGen : CirclePoint QM31 :=
  ⟨⟨⟨1, 0⟩, ⟨478637715, 513582971⟩⟩, ⟨⟨992285211, 649143431⟩, ⟨740191619, 1186584352⟩⟩⟩

theorem secureGen_onCircle : onCircle secureGen := by
  show secureGen.x ^ 2 + secureGen.y ^ 2 = 1
  decide

end Generators

/-- stwo `CirclePoint::get_random_point` 的确定性公式：把 channel 抽取的
`t` 显式参数化。stwo 侧对 `1 + t² ≠ 0` 依赖 `inverse()` 的 panic 行为
（`t = ±i` 时确实为 0），此处以假设 `ht` 显式化。 -/
noncomputable def getRandomPoint (t : QM31) : CirclePoint QM31 :=
  ⟨(1 - t ^ 2) * (1 + t ^ 2)⁻¹, 2 * t * (1 + t ^ 2)⁻¹⟩

theorem getRandomPoint_apply (t : QM31) :
    getRandomPoint t = ⟨(1 - t ^ 2) * (1 + t ^ 2)⁻¹, 2 * t * (1 + t ^ 2)⁻¹⟩ := rfl

theorem getRandomPoint_onCircle (t : QM31) (ht : (1 : QM31) + t ^ 2 ≠ 0) :
    onCircle (getRandomPoint t) := by
  show ((1 - t ^ 2) * (1 + t ^ 2)⁻¹) ^ 2 + (2 * t * (1 + t ^ 2)⁻¹) ^ 2 = 1
  have hsq : ((1 - t ^ 2) * (1 + t ^ 2)⁻¹) ^ 2 + (2 * t * (1 + t ^ 2)⁻¹) ^ 2
      = ((1 - t ^ 2) ^ 2 + (2 * t) ^ 2) * ((1 + t ^ 2)⁻¹) ^ 2 := by ring
  have hkey : (1 - t ^ 2) ^ 2 + (2 * t) ^ 2 = (1 + t ^ 2) ^ 2 := by ring
  rw [hsq, hkey, ← mul_pow, mul_inv_cancel₀ ht, one_pow]

end CirclePoint

end StwoLean
