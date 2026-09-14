import Mathlib
import StwoLean.Circle

/-!
# CircleDomain — circle domain 索引与 LineDomain

对应 stwo 2.3.0 `core/circle.rs`（`CirclePointIndex` / `Coset`）、
`core/poly/line.rs`（`LineDomain`）与 `core/utils.rs`（`bit_reverse_index`）。

## CirclePointIndex

`CirclePointIndex` 是圆群加法循环群 `⟨G⟩`（阶 `2^31`）上的**整数索引**：
加法即 `mod 2^31`，`to_point(i) = i · G`（`M31_CIRCLE_GEN` 的标量乘）。
stwo 用整数索引而非点本身做域运算，本库同构表示为 `Nat`（`cpiReduce` 归约）。

## Coset

`Coset = initial + ⟨step⟩`，`step = subgroupGen(logSize) = 2^(31-logSize)`，
`at(i) = toPoint(initial + step·i)`；`double`：initial/step 翻倍、logSize 减一
（即域大小减半）。

## LineDomain

圆 coset 上各点的 **x 坐标**序列（x-projection）；`at(i) = cosetAt(i).x`。
FRI 折叠（circle→line）之后的所有层都在 LineDomain 上。

## bit_reverse_index

`bitReverseIndex i logSize`：`i` 的低 `logSize` 位按位反转
（对应 rust `i.reverse_bits() >> (64 - log_size)`）。
-/

namespace StwoLean

/-- CirclePointIndex：圆群循环 `⟨G⟩`（阶 `2^31`）的整数索引。 -/
def cpiReduce (i : Nat) : Nat := i % 2 ^ 31

/-- `CirclePointIndex::subgroup_gen(log_size) = 2^(31 - log_size)`。 -/
def subgroupGen (logSize : Nat) : Nat := 2 ^ (31 - logSize)

/-- `CirclePointIndex::to_point`：`i · G`（二进制标量乘）。 -/
def cpiToPoint (i : Nat) : CirclePoint M31 := CirclePoint.mulBinary CirclePoint.m31Gen i

/-- circle domain coset：`initial + ⟨step⟩`（只存索引与 logSize）。 -/
structure Coset where
  /-- 初始点索引 -/
  initialIndex : Nat
  /-- 域大小的 log -/
  logSize : Nat

/-- `Coset::new`。 -/
def Coset.mk' (initialIndex logSize : Nat) : Coset := ⟨initialIndex, logSize⟩

/-- `Coset::subgroup`：`⟨G_n⟩`，索引 `[0, 1, …, 2^n - 1]`。 -/
def Coset.subgroup (logSize : Nat) : Coset := ⟨0, logSize⟩

/-- `step_size = 2^(31 - log_size)`。 -/
def Coset.stepSize (c : Coset) : Nat := subgroupGen c.logSize

/-- `index_at(i) = initial + step·i (mod 2^31)`。 -/
def Coset.indexAt (c : Coset) (i : Nat) : Nat :=
  cpiReduce (c.initialIndex + c.stepSize * i)

/-- `at(i)`：coset 第 i 个圆点。 -/
def Coset.at (c : Coset) (i : Nat) : CirclePoint M31 := cpiToPoint (c.indexAt i)

/-- 域大小减半：initial/step 翻倍（`Coset::double`）。 -/
def Coset.double (c : Coset) : Coset := ⟨2 * c.initialIndex, c.logSize - 1⟩

/-- `LineDomain`：circle coset 的 x 坐标序列。 -/
structure LineDomain where
  /-- 底层 coset -/
  coset : Coset

/-- `LineDomain::new`（恒等包装；x 坐标唯一性由 coset 选取保证）。 -/
def LineDomain.ofCoset (c : Coset) : LineDomain := ⟨c⟩

/-- `LineDomain::at(i)`：第 i 个域点的 x 坐标（M31）。 -/
def LineDomain.at (d : LineDomain) (i : Nat) : M31 := (d.coset.at i).x

/-- `LineDomain::double`（FRI 每层域减半）。 -/
def LineDomain.double (d : LineDomain) : LineDomain := ⟨d.coset.double⟩

/-- `utils::bit_reverse_index`：低 `logSize` 位按位反转
（`rev(i, k) = (i%2)·2^(k-1) + rev(i/2, k-1)`，结构递归可归约）。 -/
def bitReverseIndexAux (logSize : Nat) (i : Nat) : Nat :=
  match logSize with
  | 0 => 0
  | k + 1 => (i % 2) * 2 ^ k + bitReverseIndexAux k (i / 2)

def bitReverseIndex (i logSize : Nat) : Nat :=
  bitReverseIndexAux logSize i

end StwoLean
