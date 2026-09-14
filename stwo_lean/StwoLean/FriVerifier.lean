import Mathlib
import StwoLean.CircleDomain
import StwoLean.Merkle
import StwoLean.FriCore

/-!
# FriVerifier — 多层 FRI 折叠验证状态机

对应 stwo 2.3.0 `core/fri.rs` 的 `FriVerifier::decommit_on_queries` 循环
（fold_step = 1，line-domain inner layers）。完整 stwo 实现的多列流式
Merkle 状态机在本库化为**单查询路径**的逐层验证——每个查询位置一条
 witness 链，验证义务逐层相同：

1. **承诺核对**：本层位置 `idx` 与兄弟位置 `idx ⊕ 1` 的求值各自经
   `hashNode none (qm31ToM31s eval)` → `pathRoot` 重算层根，须等于
   该层承诺根（Merkle 路径验证调用）；
2. **折叠核对**：`foldPair evalSelf evalSibling x⁻¹ αᵢ` 得上层位置
   `idx / 2` 的求值（`x` 为本层 LineDomain 在 `bitReverseIndex idx`
   处的域点，`x⁻¹ = x^(p-2)`）；
3. **终局核对**：走完全部层后，最终求值须等于末层多项式
   （低次在前系数表，QM31 Horner）在末层域点处的取值。

与 stwo 的对应：`roots`/`alphas` 对应 `FriVerifier` 各层承诺与逐层
抽出的 folding alpha；`FriLayerWitness` 对应每层
`compute_decommitment_positions_and_rebuild_evals` 重建的求值对与
Merkle decommitment；首层 circle→line 折叠（`fold_circle_into_line`）
不在本状态机内——witness 链从 line domain 的首层求值对开始
（即 goal 中的 fold_line 多层对拍）。

全程结构递归 + 显式域运算，`native_decide`（编译器求值）可归约。
-/

namespace StwoLean

namespace FriVerifier

/-- M31 域逆：`x^(p-2)`（Fermat 小定理推论；向量与 spec 引理钉死）。
spec 以乘法形式给出（`x⁻¹` 在 ZMod 中是经典选择定义，whnf 不可归约）。 -/
def inverseM31 (x : M31) : M31 := fpow x (P - 2)

theorem inverseM31_mul_self (x : M31) (hx : x ≠ 0) : inverseM31 x * x = 1 := by
  have h1 : x ^ (P - 1) = 1 := ZMod.pow_card_sub_one_eq_one hx
  have hs : (P - 2) + 1 = P - 1 := by decide
  rw [← hs, pow_succ] at h1
  show fpow x (P - 2) * x = 1
  rw [fpow_eq_pow]
  exact h1

/-- QM31 的 4 个 M31 limb（M31 类型版；Nat 版见 `Channel.qm31Limbs`）。 -/
def qm31ToM31s (q : QM31) : List M31 := [q.c0.re, q.c0.im, q.c1.re, q.c1.im]

/-- QM31 系数多项式在 QM31 点上的 Horner 求值（低次在前）。 -/
def polyEvalQM31 (coeffs : List QM31) (x : QM31) : QM31 :=
  coeffs.foldr (fun c acc => acc * x + c) 0

/-- 单层 witness：本层求值对与两条 Merkle 路径。 -/
structure FriLayerWitness where
  /-- 位置 `idx` 处的本层求值 -/
  evalSelf : QM31
  /-- 位置 `idx ^ 1` 处的本层求值 -/
  evalSibling : QM31
  /-- 位置 `idx` 的 Merkle 路径（兄弟哈希链） -/
  pathSelf : List Fp252
  /-- 位置 `idx ^ 1` 的 Merkle 路径 -/
  pathSibling : List Fp252

/-- FRI 实例参数：各层承诺根、折叠系数、末层多项式与域。 -/
structure FriInstance where
  /-- 各层承诺根（长度 = 层数） -/
  roots : List Fp252
  /-- 各层折叠系数 α（长度 = 层数） -/
  alphas : List QM31
  /-- 末层多项式（低次在前，QM31 系数） -/
  lastPoly : List QM31
  /-- 首层 LineDomain（coset） -/
  initialDomain : LineDomain
  /-- 首层域大小的 log -/
  initialLogSize : Nat

/-- 单层验证 + 折叠（`FriLayer::verify_and_fold` 的路径版）：
承诺核对通过则返回 `(idx / 2, 折叠后求值)`，否则 `none`。
注意 `fold_line` 的 ±x 对以**偶下标**位置的域点为 +x：idx 奇时
(self, sibling) = (f(-x), f(x))，须先还原顺序，否则 h 分量反号。 -/
def friLayerVerifyAndFold (root : Fp252) (domain : LineDomain) (logSize : Nat)
    (idx : Nat) (alpha : QM31) (w : FriLayerWitness) : Option (Nat × QM31) :=
  let (fEven, fOdd) :=
    if idx % 2 == 0 then (w.evalSelf, w.evalSibling) else (w.evalSibling, w.evalSelf)
  let pairStart := 2 * (idx / 2)
  let x := LineDomain.at domain (bitReverseIndex pairStart logSize)
  -- 承诺叶按 bit-reverse 排列：位置 idx 的叶下标 = bitrev(idx, logSize)。
  let leafIdx := bitReverseIndex idx logSize
  let okSelf :=
    Merkle.pathRoot (Merkle.hashNode none (qm31ToM31s w.evalSelf)) leafIdx w.pathSelf == root
  let okSib :=
    Merkle.pathRoot (Merkle.hashNode none (qm31ToM31s w.evalSibling)) (leafIdx ^^^ 1)
      w.pathSibling == root
  if okSelf ∧ okSib then
    some (idx / 2, FriCore.foldPair fEven fOdd (inverseM31 x) alpha)
  else none

/-- 多层状态机：逐层 `friLayerVerifyAndFold`（域每层 double、logSize 减一、
位置折半），层尽后做末层多项式核对。 -/
def friVerifyAux (roots : List Fp252) (alphas : List QM31)
    (witnesses : List FriLayerWitness) (lastPoly : List QM31)
    (domain : LineDomain) (logSize : Nat) (idx : Nat) (curEval : QM31) : Bool :=
  match roots, alphas, witnesses with
  | [], [], [] =>
    curEval ==
      polyEvalQM31 lastPoly
        (QM31.ofU32 (LineDomain.at domain (bitReverseIndex idx logSize)).val 0 0 0)
  | root :: roots', alpha :: alphas', w :: ws =>
    match friLayerVerifyAndFold root domain logSize idx alpha w with
    | some (idx', folded) =>
      friVerifyAux roots' alphas' ws lastPoly (LineDomain.double domain) (logSize - 1) idx'
        folded
    | none => false
  | _, _, _ => false

/-- 顶层验证：`firstEval` 是首层（line domain）在位置 `idx` 处的求值，
`witnesses` 长度须等于层数。 -/
def friVerify (inst : FriInstance) (idx : Nat) (firstEval : QM31)
    (witnesses : List FriLayerWitness) : Bool :=
  friVerifyAux inst.roots inst.alphas witnesses inst.lastPoly inst.initialDomain
    inst.initialLogSize idx firstEval

end FriVerifier

end StwoLean
