import Mathlib
import StwoLean.Commitment
import StwoLean.CircleDomain

/-!
# Verifier — STARK 证明验证器主循环

对应 stwo 2.3.0 `core/verifier.rs`（`verify_ex`）与
`core/air/accumulation.rs`（`PointEvaluationAccumulator`）、
`core/proof.rs`（`extract_composition_oods_eval`）、
`core/circle.rs`（`get_random_point`）。

## 主循环（逐行对齐 `verify_ex`）

1. `random_coeff = channel.draw_secure_felt()`；
2. 组合多项式承诺 `commitment_scheme.commit(最后一个承诺, 8 列,
   channel)`——`mix_root`；
3. OODS 点 `CirclePoint::get_random_point(channel)`：channel 抽取
   `t`，`x = (1-t²)/(1+t²)`，`y = 2t/(1+t²)`；
4. 采样点结构 = 组件 mask + 组合列 `[oods]×8`；
5. **DEEP-ALI 核对**：证明中的组合多项式 OODS 值
   （`extract_composition_oods_eval`：左右半分解的坐标求值经
   `from_partial_evals` 重构，`value = left + x·right`，其中
   `x = oods_point.repeated_double(max_log_degree_bound - 1).x`）
   必须等于组件约束商在 OODS 点的随机线性组合
   （`PointEvaluationAccumulator` 的 Horner 累加
   `acc = acc·α + term`）；
6. `commitment_scheme.verify_values(...)` → `Commitment.verifyValuesGen`。

组件接口（`ComponentSpec`）：`maxConstraintLogDegreeBound` 给出组合
多项式度界；`terms` 是该组件约束商在 OODS 点的求值项列表（AIR 层
接口——约束求值本身属约束层桥接，见 README 路线图 Phase 3/4）。
-/

namespace StwoLean

namespace Verifier

open Commitment

/-- 组件规格（`core/air` 的 `Component` 验证侧接口）。 -/
structure ComponentSpec where
  /-- 该组件约束商的最大 log 度界（`max_constraint_log_degree_bound`） -/
  maxConstraintLogDegreeBound : Nat
  /-- 该组件约束商在 OODS 点的求值项（按累加顺序；AIR 层接口） -/
  terms : List QM31

/-- 精简 STARK 证明：组合多项式树承诺、组合列的 OODS mask 求值
（8 个：左 4 + 右 4 坐标多项式）、PCS 证明体。 -/
structure StarkProofLite where
  /-- 组合多项式树承诺（`proof.commitments.last`） -/
  compositionCommitment : Fp252
  /-- 组合列在 OODS 点的 mask 求值（8 个） -/
  compositionMask : List QM31
  /-- PCS 证明体 -/
  pcs : PcsProofGen

/-- `PointEvaluationAccumulator`：Horner 累加
`acc = acc·α + eval`，`finalize = acc`。 -/
def accumulate (randomCoeff acc term : QM31) : QM31 :=
  acc * randomCoeff + term

/-- 组件序列的累加（`eval_composition_polynomial_at_point` 的
accumulator 部分：跨组件顺序累加）。 -/
def accumulateTerms (randomCoeff : QM31) (components : List ComponentSpec) : QM31 :=
  components.foldl (fun acc c =>
    c.terms.foldl (fun a t => accumulate randomCoeff a t) acc) 0

/-- `QM31::from_partial_evals`：`e₀ + e₁·i + e₂·u + e₃·iu`。 -/
def fromPartialEvals (e0 e1 e2 e3 : QM31) : QM31 :=
  e0 + e1 * QM31.ofU32 0 1 0 0
    + e2 * QM31.ofU32 0 0 1 0
    + e3 * QM31.ofU32 0 0 0 1

/-- `extract_composition_oods_eval`：组合列的 8 个 OODS mask 求值
（左 4 + 右 4 坐标多项式）重构组合多项式在 OODS 点的值：
`left + x·right`，`x = oods_point.repeated_double(shift).x`。 -/
def extractCompositionOods (mask : List QM31) (oods : CirclePoint QM31)
    (maxLogDegreeBound : Nat) : QM31 :=
  let last8 := mask.drop (mask.length - 8)
  let l := last8.take 4
  let r := last8.drop 4
  let left := fromPartialEvals (l.getD 0 0) (l.getD 1 0) (l.getD 2 0) (l.getD 3 0)
  let right := fromPartialEvals (r.getD 0 0) (r.getD 1 0) (r.getD 2 0) (r.getD 3 0)
  let dx := (CirclePoint.repeatedDouble oods (maxLogDegreeBound - 1)).x
  left + dx * right

/-- `core/verifier.rs::verify_ex` 的主循环。`cols` = 每列
`(logSize, OODS 采样)`（验证器输入）；`ch` = **trace 树 commit 之后**
的通道状态（调用者负责；主循环从这里开始：random_coeff → 组合树
commit → OODS 点 → DEEP-ALI → verify_values）。 -/
def verifyMain (cfg : PcsConfig) (components : List ComponentSpec)
    (maxLogDegreeBound : Nat)
    (cols : List (Nat × List Deep.PointSample))
    (proof : StarkProofLite) (ch : Channel.Chan) : Bool :=
  -- 1. random_coeff
  let pr := Channel.drawSecureFelt ch
  let randomCoeff := pr.1
  let ch1 := pr.2
  -- 2. 组合多项式承诺（读证明的最后一个承诺，8 列 mask）
  let ch2 := mixRoot proof.compositionCommitment ch1
  -- 3. OODS 点（channel 驱动 get_random_point）
  let pr2 := Channel.drawSecureFelt ch2
  let oods := Deep.oodsPoint pr2.1
  let ch3 := pr2.2
  -- 4. DEEP-ALI 核对：提取的组合 OODS 值 == 约束商的随机线性组合
  let extracted := extractCompositionOods proof.compositionMask oods maxLogDegreeBound
  let combined := accumulateTerms randomCoeff components
  if extracted != combined then false
  else
    -- 5. verify_values（通道状态延续）
    Commitment.verifyValuesGen cfg cols proof.pcs ch3

/-! ### Phase 2.5：组件 mask 参数化 -/

/-- `CanonicCoset::new(n).step()`：域生成元点（索引 `2^(31-n)`）。 -/
def traceStepPt (maxLogDegreeBound : Nat) : StwoLean.CirclePoint StwoLean.M31 :=
  StwoLean.cpiToPoint (2 ^ (31 - maxLogDegreeBound))

/-- 参数化的组件规格：mask 偏移驱动采样点派生。 -/
structure ComponentSpecP where
  /-- 最大约束 log 度界 -/
  maxConstraintLogDegreeBound : Nat
  /-- 每列 mask 偏移（列数 = offsets 长度） -/
  maskOffsets : List (List Int)
  /-- 约束商在 OODS 采样点的项 -/
  terms : List QM31

/-- mask 采样点：`oods + traceStep.mul_signed(offset).into_ef()`。 -/
def maskPoint (oods : StwoLean.CirclePoint StwoLean.QM31) (ts : StwoLean.CirclePoint StwoLean.M31) (offset : Int) :
    StwoLean.CirclePoint StwoLean.QM31 :=
  let stepLift : CirclePoint QM31 :=
    ⟨StwoLean.QM31.ofU32 ts.x.val 0 0 0, StwoLean.QM31.ofU32 ts.y.val 0 0 0⟩
  let rec foldAdd (base step : CirclePoint QM31) : Nat → CirclePoint QM31
    | 0 => base
    | k + 1 => StwoLean.CirclePoint.cpAdd (foldAdd base step k) step
  if offset ≥ 0 then foldAdd oods stepLift offset.natAbs
  else foldAdd oods (StwoLean.CirclePoint.antipode stepLift) (-offset).natAbs

/-- 从 OODS 点 + 组件 mask 偏移派生采样点列表。 -/
def deriveMaskPoints (oods : StwoLean.CirclePoint StwoLean.QM31) (maxLogDegreeBound : Nat)
    (offsets : List (List Int)) : List (List (StwoLean.CirclePoint StwoLean.QM31)) :=
  let ts := traceStepPt maxLogDegreeBound
  offsets.map fun offs => offs.map fun o => maskPoint oods ts o

end Verifier

end StwoLean
