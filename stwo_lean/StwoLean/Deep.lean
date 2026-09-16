import Mathlib
import StwoLean.QM31
import StwoLean.CircleDomain
import StwoLean.FriVerifier

/-!
# Deep — DEEP 商多项式（OODS 采样 → FRI 首层答案）

对应 stwo 2.3.0 `core/pcs/quotients.rs`。验证器侧数据流：
`fri_answers` 对每个查询位置 p 计算

```
∑_batch ∑_term α^k · (c · f̃ᵢ(p) - (a · p.y + b)) / line(z, z̄)(p)
```

其中 `(a, b, c) = α^k · (conj(v) - v, v·c₀ - a₀·z.y, conj(z.y) - z.y)`
是过 `(z.y, v)` 与 `(conj(z.y), conj(v))` 的直线系数
（`complex_conjugate_line_coeffs`），分母是过 `z, z̄` 的直线在
`p` 处的取值（`CM31` 元素，`denominator_inverses` 批量求逆）。

组成部件：

* `PointSample`：`(z, f̃ᵢ(z))` 采样；
* `lineCoeffs`：复共轭直线系数（乘 `α^k`）；
* `cm31Inv`：**可计算** CM31 逆（`norm^(p-2) · conj`——Field 实例的
  `⁻¹` 是经典选择、不可求值，故对拍走本定义）；
* `denominator` / `denominatorInv`：`(Re(zx) - p.x)·Im(zy) -
  (Re(zy) - p.y)·Im(zx)` 及其逆；
* `buildSamples`：`build_samples_with_randomness_and_periodicity`——
  两采样点的列前置一个**周期性采样**（点 `z₂ + 2^logSize·G_{2^L}`、
  值同 `z₂`），`α^k` 全列流水分配；
* `groupBatches`：`ColumnSampleBatch::new_vec`——按采样点分组
  （IndexMap 语义 = 首次出现序）；
* `accumulateRow` / `friAnswers`：查询行商值累加。

`circleDomainAt` 对应 `CircleDomain.at`（`±half_coset` 排列：
前半 = `half_odds(L-1)` 陪集点，后半 = 其对径点）。
-/

namespace StwoLean

namespace Deep

/-- OODS 采样（`PointSample`）。 -/
structure PointSample where
  /-- 采样点 -/
  point : CirclePoint QM31
  /-- 列多项式在采样点的值 -/
  value : QM31
  deriving DecidableEq

/-- `complex_conjugate_line_coeffs`：过 `(z.y, v)`、`(conj(z.y), conj(v))`
的直线系数，乘随机幂 `randpow`。返回 `(αa, αb, αc)`。 -/
def lineCoeffs (z : CirclePoint QM31) (v randpow : QM31) : QM31 × QM31 × QM31 :=
  let a := QM31.conj v - v
  let c := QM31.conj z.y - z.y
  let b := v * c - a * z.y
  (randpow * a, randpow * b, randpow * c)

/-- 可计算 CM31 逆：`N(a)^(p-2) · conj(a)`（`CM31::batch_inverse` 的
单项；`inverseM31 = x^(p-2)` 见 `FriVerifier`）。 -/
def cm31Inv (a : CM31) : CM31 :=
  CM31.smul (FriVerifier.inverseM31 (CM31.norm a)) (CM31.conj a)

/-- 可计算 QM31 逆：`(a-bu)/N(a)`（`QM31::inverse` 的可执行形式；
`Field` 实例的 `⁻¹` 是经典选择、不可求值，重计算向量走本定义）。 -/
def qm31Inv (x : QM31) : QM31 :=
  QM31.mulCM31 (QM31.conj x) (cm31Inv (QM31.norm x))

/-- `CirclePoint::get_random_point` 的可执行形式（OODS 点）：
`t` 由 channel 抽取，`x = (1-t²)/(1+t²)`，`y = 2t/(1+t²)`。 -/
def oodsPoint (t : QM31) : CirclePoint QM31 :=
  let t2 := t * t
  let d := qm31Inv ((1 : QM31) + t2)
  ⟨(1 - t2) * d, (t + t) * d⟩

/-- 过 `z, z̄` 的直线在 M31 点 `p` 处的取值（`CM31` 元素）：
`(Re(z.x) - p.x)·Im(z.y) - (Re(z.y) - p.y)·Im(z.x)`。 -/
def denominator (z : CirclePoint QM31) (p : CirclePoint M31) : CM31 :=
  (z.x.c0 - CM31.ofU32 p.x.val 0) * z.y.c1
    - (z.y.c0 - CM31.ofU32 p.y.val 0) * z.x.c1

/-- 分母的逆。 -/
def denominatorInv (z : CirclePoint QM31) (p : CirclePoint M31) : CM31 :=
  cm31Inv (denominator z p)

/-- M31 点提升到 QM31 点（`into_ef`）。 -/
def liftPoint (p : CirclePoint M31) : CirclePoint QM31 :=
  ⟨QM31.ofU32 p.x.val 0 0 0, QM31.ofU32 p.y.val 0 0 0⟩

/-- 周期性采样的偏移点：lifting 域 step 点（索引 `2^(31-L)`）自倍
`logSize` 次（`period_generator = step.repeated_double(log_size)`）。 -/
def periodPoint (logSize liftingLog : Nat) : CirclePoint M31 :=
  CirclePoint.mulBinary CirclePoint.m31Gen (2 ^ (31 - liftingLog + logSize))

/-- 单列采样的 `α^k` 流水标注（返回 (标注列表, 下一幂)）。 -/
def buildSamplesSmp (α randpow : QM31) :
    List PointSample → List (PointSample × QM31) × QM31
  | [] => ([], randpow)
  | s :: rest =>
    let (tail, pow') := buildSamplesSmp α (randpow * α) rest
    ((s, randpow) :: tail, pow')

/-- `build_samples_with_randomness_and_periodicity`。输入每列
`(logSize, samples)`（samples 为 0/1/2 个采样）；两采样的列前置
周期性采样。`α^k` 按列序流水分配。返回**按列分组**的
`(采样, α^k)` 列表（列边界信息供 column_index 标注——对应 stwo
`new_vec` 的外层列枚举）。 -/
def buildSamples (α randpow : QM31) (liftingLog : Nat) :
    List (Nat × List PointSample) → List (List (PointSample × QM31))
  | [] => []
  | (logSize, samples) :: rest =>
    let (head, pow') :=
      match samples with
      | [_s0, s1] =>
        ([(⟨CirclePoint.cpAdd s1.point (liftPoint (periodPoint logSize liftingLog)),
            s1.value⟩, randpow)], randpow * α)
      | _ => ([], randpow)
    let (mid, pow'') := buildSamplesSmp α pow' samples
    (head ++ mid) :: buildSamples α pow'' liftingLog rest

/-- 带列号的平铺采样（column_index 标注）。 -/
def attachIdxAux {α : Type*} : Nat → List α → List (Nat × α)
  | _, [] => []
  | i, x :: rest => (i, x) :: attachIdxAux (i + 1) rest

def attachIdx {α : Type*} (l : List α) : List (Nat × α) := attachIdxAux 0 l

/-- 单条采样并入分组表：点已存在则尾部追加，否则新开 batch
（`IndexMap` 首次出现序）。batch = `(点, [(列号, 值, α^k)])`。 -/
def insertSample (colIdx : Nat) (s : PointSample) (rp : QM31) :
    List (CirclePoint QM31 × List (Nat × QM31 × QM31)) →
    List (CirclePoint QM31 × List (Nat × QM31 × QM31))
  | [] => [⟨s.point, [(colIdx, s.value, rp)]⟩]
  | ⟨z, terms⟩ :: rest =>
    if z == s.point then ⟨z, terms ++ [(colIdx, s.value, rp)]⟩ :: rest
    else ⟨z, terms⟩ :: insertSample colIdx s rp rest

/-- `ColumnSampleBatch::new_vec`：按采样点分组，首次出现序。 -/
def groupBatches (entries : List (Nat × (PointSample × QM31))) :
    List (CirclePoint QM31 × List (Nat × QM31 × QM31)) :=
  entries.foldl (fun acc (ci, s, rp) => insertSample ci s rp acc) []

/-- `accumulate_row_quotients`：单个查询位置的商值。`queried` 为该行
各列的值（全列序）。 -/
def accumulateRow (batches : List (CirclePoint QM31 × List (Nat × QM31 × QM31)))
    (queried : List M31) (p : CirclePoint M31) : QM31 :=
  batches.foldl (fun acc (z, terms) =>
    let num := terms.foldl (fun n (ci, v, rp) =>
        let (a, b, c) := lineCoeffs z v rp
        n + (QM31.mulM31 c (queried.getD ci 0))
          - (QM31.mulM31 a p.y + b)) 0
    acc + QM31.mulCM31 num (denominatorInv z p)) 0

/-- `CircleDomain.at`：`±half_coset` 排列。前半（`i < 2^(L-1)`）为
`half_odds(L-1)` 陪集第 `i` 点（索引 `2^(30-L) + 2^(32-L)·i`），
后半为其对径点（索引取负 mod `2^31`）。 -/
def circleDomainAt (L i : Nat) : CirclePoint M31 :=
  let half := 2 ^ (L - 1)
  if i < half then cpiToPoint (2 ^ (30 - L) + 2 ^ (32 - L) * i)
  else
    let j := 2 ^ (30 - L) + 2 ^ (32 - L) * (i - half)
    cpiToPoint ((2 ^ 31 - j) % 2 ^ 31)

/-- 带下标映射（`f 元素 下标`）。 -/
def mapWithIdxAux {α β : Type*} : Nat → (α → Nat → β) → List α → List β
  | _, _, [] => []
  | i, f, x :: rest => f x i :: mapWithIdxAux (i + 1) f rest

/-- `fri_answers`：每查询位置的 DEEP 商值。
`cols`：每列 `(logSize, samples)`；`queried`：每列每查询位置的值
（**按查询列表下标对齐**，非原始位置值——对应 stwo
`queried_values_at_row = queried_values.iter().map(|col| col[idx])`）。 -/
def friAnswers (α randpow : QM31) (liftingLog : Nat)
    (cols : List (Nat × List PointSample)) (queried : List (List M31))
    (queryPositions : List Nat) : List QM31 :=
  let perCols := buildSamples α randpow liftingLog cols
  -- stwo `new_vec` 的 column_index 只数**有采样的列**（空采样列被整体
  -- 丢弃后重新编号），而 queried_values 是全列展平——两者在含无采样
  -- 列（如未被组件 mask 的预处理列）时错位，此处逐行复刻该语义。
  let nonEmpty := perCols.filter (fun col => !col.isEmpty)
  let entries := (attachIdx nonEmpty).flatMap (fun (ci, col) => col.map (fun sp => (ci, sp)))
  let batches := groupBatches entries
  mapWithIdxAux 0 (fun pos idx =>
    let p := circleDomainAt liftingLog (bitReverseIndex pos liftingLog)
    accumulateRow batches (queried.map (fun col => col.getD idx 0)) p) queryPositions

end Deep

end StwoLean
