import StwoLean.Verifier

/-!
# StarkProofJson — stwo `StarkProof` serde schema 的纯 Lean 可计算 JSON 解析

对应 stwo 2.3.0 的序列化 schema（serde derive 输出，`core/proof.rs` /
`core/pcs/quotients.rs` / `core/fri.rs` / `core/vcs_lifted/verifier.rs`）：

* `CommitmentSchemeProof { config, commitments, sampled_values,
  decommitments, queried_values, proof_of_work, fri_proof }`；
* `FriProof { first_layer, inner_layers, last_layer_poly }`，
  `FriLayerProof { fri_witness, decommitment, commitment }`；
* `MerkleDecommitmentLifted { hash_witness }`；
* `QM31 = [[a,b],[c,d]]`（元组结构 → 数组；`M31` 新类型 → u32），
  域元素哈希（Felt252）→ `"0x…"` 十六进制串，
  `LinePoly = { coeffs, log_size }`，`CirclePoint` → `{"x":…,"y":…}`。

JSON 文件由 `vector-gen` 从真实 stwo 类型经 `serde_json` 导出，外层包裹
`{"proof": <CommitmentSchemeProof>, "air": {...}}`——`air` 是验证器侧
输入（组件约束项、列 OODS 采样点/值、初始通道状态等），不属于 stwo
proof 结构本身。

解析器为 RFC 8259 子集（无符号整数、字符串、数组、对象、true/false/null；
schema 中不出现小数/指数/负数），全结构带燃料递归、内核可归约——
`native_decide` 即可完成「解析 → 构建 proof → `verifyMain` 通过」全链。
-/

namespace StwoLean.StarkProofJson

/-! ### JSON 值与解析器 -/

/-- JSON 值（本 schema 覆盖的子集）。 -/
inductive JVal where
  | null
  | bool (b : Bool)
  | num (n : Nat)
  | str (s : String)
  | arr (xs : List JVal)
  | obj (kvs : List (String × JVal))

/-- 白空白字符。 -/
def isWs (c : Char) : Bool := c = ' ' || c = '\n' || c = '\t' || c = '\r'

/-- 跳过白空白。 -/
def skipWs : List Char → List Char
  | c :: cs => if isWs c then skipWs cs else c :: cs
  | [] => []

/-- 解析结果。 -/
inductive PRes where
  | ok (v : JVal) (rest : List Char)
  | fail

/-- 数字字面量（无符号整数；每消耗一位数字燃料减一）。 -/
def numGo : Nat → Nat → List Char → PRes
  | 0, _, _ => PRes.fail
  | fuel + 1, acc, d :: rest =>
    if '0' ≤ d ∧ d ≤ '9' then numGo fuel (acc * 10 + (d.toNat - 48)) rest
    else PRes.ok (JVal.num acc) (d :: rest)
  | _ + 1, acc, [] => PRes.ok (JVal.num acc) []

-- 字符串字面量（acc 为已收集字符的逆序）；转义支持 `\" \\ \/ \n \t \r`，
-- `\b \f \u` 不在本 schema 中出现，遇之失败。
mutual
/-- 字符串字面量。 -/
def strGo : Nat → List Char → List Char → PRes
  | 0, _, _ => PRes.fail
  | fuel + 1, acc, c :: rest =>
    if c = '"' then PRes.ok (JVal.str (String.ofList acc.reverse)) rest
    else if c = '\\' then
      match rest with
      | e :: rest2 =>
        if e = '"' ∨ e = '\\' ∨ e = '/' then strGo fuel (e :: acc) rest2
        else if e = 'n' then strGo fuel ('\n' :: acc) rest2
        else if e = 't' then strGo fuel ('\t' :: acc) rest2
        else if e = 'r' then strGo fuel ('\r' :: acc) rest2
        else PRes.fail
      | [] => PRes.fail
    else strGo fuel (c :: acc) rest
  | _ + 1, _, [] => PRes.fail

/-- 字面量前缀匹配（`true`/`false`/`null`）。 -/
def litGo : Nat → List Char → JVal → List Char → PRes
  | 0, _, _, _ => PRes.fail
  | _ + 1, [], v, rest => PRes.ok v rest
  | fuel + 1, p :: ps, v, c :: rest => if p = c then litGo fuel ps v rest else PRes.fail
  | _ + 1, _ :: _, _, [] => PRes.fail

/-- 数组体：已收集元素（逆序）+ 期望 `,` 或 `]`。 -/
def arrGo : Nat → List Char → List JVal → PRes
  | 0, _, _ => PRes.fail
  | fuel + 1, cs, acc =>
    match parseV fuel cs with
    | PRes.fail => PRes.fail
    | PRes.ok v rest =>
      match skipWs rest with
      | ',' :: rest2 => arrGo fuel rest2 (v :: acc)
      | ']' :: rest2 => PRes.ok (JVal.arr (v :: acc).reverse) rest2
      | _ => PRes.fail

/-- 对象体：已收集键值对（逆序）。 -/
def objGo : Nat → List Char → List (String × JVal) → PRes
  | 0, _, _ => PRes.fail
  | fuel + 1, cs, acc =>
    match skipWs cs with
    | '}' :: rest => PRes.ok (JVal.obj acc.reverse) rest
    | _ =>
      match parseV fuel cs with
      | PRes.fail => PRes.fail
      | PRes.ok (JVal.str k) rest =>
        match skipWs rest with
        | ':' :: rest2 =>
          match parseV fuel rest2 with
          | PRes.fail => PRes.fail
          | PRes.ok v rest3 =>
            match skipWs rest3 with
            | ',' :: rest4 => objGo fuel rest4 ((k, v) :: acc)
            | '}' :: rest4 => PRes.ok (JVal.obj ((k, v) :: acc).reverse) rest4
            | _ => PRes.fail
        | _ => PRes.fail
      | PRes.ok _ _ => PRes.fail

/-- JSON 值解析（燃料每次递归递减，总量与输入长度成正比）。 -/
def parseV : Nat → List Char → PRes
  | 0, _ => PRes.fail
  | fuel + 1, cs0 =>
    match skipWs cs0 with
    | [] => PRes.fail
    | c :: cs =>
      if c = '{' then objGo fuel cs []
      else if c = '[' then arrGo fuel cs []
      else if c = '"' then strGo fuel [] cs
      else if c = 't' then litGo fuel "rue".toList (JVal.bool true) cs
      else if c = 'f' then litGo fuel "alse".toList (JVal.bool false) cs
      else if c = 'n' then litGo fuel "ull".toList JVal.null cs
      else numGo fuel 0 cs0
end

/-- 解析 JSON 文本（要求输入末尾无尾随垃圾）。 -/
def parseJson (s : String) : Option JVal :=
  match parseV (4 * s.length + 16) s.toList with
  | PRes.ok v rest => if (skipWs rest).isEmpty then some v else none
  | PRes.fail => none

/-! ### 访问器 -/

/-- 对象字段。 -/
def get? (j : JVal) (k : String) : Option JVal :=
  match j with
  | .obj kvs => (kvs.filter (fun kv => kv.1 == k)).head?.map (·.2)
  | _ => none

def asNat? (j : JVal) : Option Nat := match j with | .num n => some n | _ => none
def asStr? (j : JVal) : Option String := match j with | .str s => some s | _ => none
def asArr? (j : JVal) : Option (List JVal) := match j with | .arr xs => some xs | _ => none

def getN? (j : JVal) (k : String) : Option Nat := Option.bind (get? j k) asNat?
def getS? (j : JVal) (k : String) : Option String := Option.bind (get? j k) asStr?
def getA? (j : JVal) (k : String) : Option (List JVal) := Option.bind (get? j k) asArr?
def getJ? (j : JVal) (k : String) : Option JVal := get? j k

/-! ### 域元素与几何值 -/

/-- 十六进制位值。 -/
def hexDigit? (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - 48)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 97 + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 65 + 10)
  else none

/-- 十六进制串 → Nat（空串 = 0）。 -/
def hexToNatL (cs : List Char) : Option Nat :=
  cs.foldl (fun o c =>
    match o with
    | none => none
    | some a => (hexDigit? c).map fun d => a * 16 + d) (some 0)

/-- 十进制串 → Nat（空串 = 0；任一非数字字符 → 失败）。 -/
def decToNatL (cs : List Char) : Option Nat :=
  cs.foldl (fun o c =>
    match o with
    | none => none
    | some a => if '0' ≤ c ∧ c ≤ '9' then some (a * 10 + (c.toNat - 48)) else none)
    (some 0)

/-- Felt252 serde 形态 → `Fp252`：starknet-ff 0.3.7 输出十进制串，
types-core 可读形态为 `"0x…"` 十六进制串；两者皆接受。 -/
def feltOfStr? (s : String) : Option Fp252 :=
  if s.startsWith "0x" then (hexToNatL (s.toList.drop 2)).map (fun n => (n : Fp252))
  else (decToNatL s.toList).map (fun n => (n : Fp252))

/-- JSON 值 → Felt252（字符串形态）。 -/
def feltOfJ? (j : JVal) : Option Fp252 := do
  let s ← asStr? j
  feltOfStr? s

/-- `CM31 = [re, im]`。 -/
def cmOfJ? (j : JVal) : Option CM31 :=
  match j with
  | .arr [x, y] => do
    let x ← asNat? x
    let y ← asNat? y
    some (CM31.ofU32 x y)
  | _ => none

/-- `QM31 = [[a,b],[c,d]]`。 -/
def qmOfJ? (j : JVal) : Option QM31 :=
  match j with
  | .arr [a, b] => do
    let a ← cmOfJ? a
    let b ← cmOfJ? b
    some (QM31.mk a b)
  | _ => none

/-- `M31` limb。 -/
def m31OfJ? (j : JVal) : Option M31 := do
  let n ← asNat? j
  some (n : M31)

/-- `CirclePoint<SecureField>` serde 形态 `{"x":…,"y":…}`。 -/
def ptOfJ? (j : JVal) : Option (CirclePoint QM31) := do
  let xj ← getJ? j "x"
  let x ← qmOfJ? xj
  let yj ← getJ? j "y"
  let y ← qmOfJ? yj
  some (CirclePoint.mk x y)

/-- 采样点：`{"point": {...}, "value": ...}`。 -/
def sampleOfJ? (j : JVal) : Option (Deep.PointSample) := do
  let pj ← getJ? j "point"
  let pt ← ptOfJ? pj
  let vj ← getJ? j "value"
  let v ← qmOfJ? vj
  some (Deep.PointSample.mk pt v)

/-- 采样点数组 → 列。 -/
def samplesOfJArr? (js : List JVal) : Option (List Deep.PointSample) :=
  js.mapM sampleOfJ?

/-! ### StarkProof schema → 验证器输入 -/

/-- 解析后的完整验证器输入。 -/
structure ParsedProof where
  /-- PCS 配置 -/
  cfg : Commitment.PcsConfig
  /-- 组件约束项 -/
  components : List Verifier.ComponentSpec
  /-- 组合多项式最大 log 度界 -/
  maxLogDegreeBound : Nat
  /-- 每列 OODS 采样 -/
  cols : List (Nat × List Deep.PointSample)
  /-- 组合树承诺（air 侧；= commitments 末树根） -/
  compositionCommitment : Fp252
  /-- 组合列 OODS mask 求值 -/
  compositionMask : List QM31
  /-- PCS 证明体 -/
  proof : Commitment.PcsProofGen
  /-- commit 阶段后的初始通道 -/
  ch : Channel.Chan

/-- hex 串字段 → Fp252。 -/
def getFelt? (j : JVal) (k : String) : Option Fp252 := do
  let s ← getS? j k
  feltOfStr? s

/-- 哈希数组字段（`hash_witness` 等）→ `List Fp252`。 -/
def feltArrOfJ? (j : JVal) : Option (List Fp252) := do
  let xs ← asArr? j
  xs.mapM feltOfJ?

/-- `MerkleDecommitmentLifted` → witness。 -/
def decoOfJ? (j : JVal) : Option (List Fp252) := do
  let hw ← getJ? j "hash_witness"
  feltArrOfJ? hw

/-- `LinePoly` → 系数（低次在前，与 Lean `lastPoly` 一致）。 -/
def lastPolyOfJ? (j : JVal) : Option (List QM31) := do
  let coeffs ← getA? j "coeffs"
  coeffs.mapM qmOfJ?

/-- `config` 字段（`first_layer_log` / `pp_max_log` 来自 air 段——
前者即 lifting 域 log，属于验证器侧输入）。 -/
def cfgOfJ? (j : JVal) (firstLayerLog ppMaxLog : Nat) : Option Commitment.PcsConfig := do
  let fc ← getJ? j "fri_config"
  some
    { firstLayerLog := firstLayerLog
      foldStep := ← getN? fc "fold_step"
      powBits := ← getN? j "pow_bits"
      nQueries := ← getN? fc "n_queries"
      ppMaxLog := ppMaxLog }

/-- 组件数组。 -/
def componentsOfJ? (j : JVal) : Option (List Verifier.ComponentSpec) := do
  let cs ← getA? j "components"
  cs.mapM fun c => do
    let terms ← getA? c "terms"
    let terms ← terms.mapM qmOfJ?
    some { maxConstraintLogDegreeBound := ← getN? c "max_log_degree_bound", terms }

/-- 采样列数组。 -/
def colsOfJ? (j : JVal) : Option (List (Nat × List Deep.PointSample)) := do
  let cs ← getA? j "cols"
  cs.mapM fun c => do
    let log ← getN? c "log_size"
    let ss ← samplesOfJArr? (← getA? c "samples")
    some (log, ss)

/-- `sampled_values` → 全树平铺（树序 × 列序 × 采样序）。 -/
def flattenSampled? (tv : List JVal) : Option (List QM31) := do
  let trees ← tv.mapM (fun t => do
    let cols ← asArr? t
    cols.mapM (fun col => do
      let vs ← asArr? col
      vs.mapM qmOfJ?))
  some (trees.flatten.flatten)

/-- 一棵查询树：`commitments[j]` + `decommitments[j]` + `queried_values[j]`
（列 × 查询序 → 行 = 查询序 × 列序）。 -/
def treeOfJ? (root : JVal) (deco : JVal) (qcols : JVal) (height : Nat) :
    Option Commitment.TreeQueryProof := do
  let root ← feltOfJ? root
  let witness ← decoOfJ? deco
  let cols ← asArr? qcols
  let colsV ← cols.mapM (fun col => do
    let vs ← asArr? col
    vs.mapM m31OfJ?)
  -- 行数 = 首列长度（每查询一行）；行 i = 各列第 i 个值
  let nQ := (colsV.headD []).length
  let rows := (List.range nQ).map fun i => colsV.map (fun vs => vs.getD i 0)
  some { root, isPP := false, height, rows, witness }

/-- FRI 层：root + witness + 查询求值（自值 = FRI 树 4 limb 列在查询
位置的 QM31，伴值 = `fri_witness`）+ 位置对。求值按位置升序排列：
`p = q >> k` 偶 → `[自, 伴]`，奇 → `[伴, 自]`。 -/
def friLayerOfJ? (root : JVal) (deco : JVal) (qcol : JVal)
    (fwit : List JVal) (q k : Nat) : Option Commitment.FriLayerQueryProof := do
  let root ← feltOfJ? root
  let witness ← decoOfJ? deco
  let cols ← asArr? qcol
  -- 4 limb 列 → 查询序号 0（单查询）处的自值
  let limbs ← cols.mapM (fun col => do
    let vs ← asArr? col
    m31OfJ? (vs.getD 0 JVal.null))
  let selfV := QM31.mk (CM31.mk (limbs.getD 0 0) (limbs.getD 1 0))
    (CM31.mk (limbs.getD 2 0) (limbs.getD 3 0))
  let sib ← qmOfJ? (fwit.getD 0 JVal.null)
  let p := q / 2 ^ k
  let pos := [2 * (p / 2), 2 * (p / 2) + 1]
  let evals := if p % 2 == 0 then [selfV, sib] else [sib, selfV]
  some { root, positions := pos, evals, witness, packedShift := 0 }

/-- 顶层解析：`{"proof": …, "air": …}` → 验证器输入。 -/
def parseProof (s : String) : Option ParsedProof := do
  let j ← parseJson s
  let p ← getJ? j "proof"
  let air ← getJ? j "air"
  let firstLayerLog ← getN? air "first_layer_log"
  let ppMaxLog ← getN? air "pp_max_log"
  let cj ← getJ? p "config"
  let cfg ← cfgOfJ? cj firstLayerLog ppMaxLog
  let commitments ← getA? p "commitments"
  let sv ← getA? p "sampled_values"
  let sampled ← flattenSampled? sv
  let decos ← getA? p "decommitments"
  let queried ← getA? p "queried_values"
  let fp ← getJ? p "fri_proof"
  let fl ← getJ? fp "first_layer"
  let ils ← getA? fp "inner_layers"
  let llp ← getJ? fp "last_layer_poly"
  let lastPoly ← lastPolyOfJ? llp
  let powNonce ← getN? p "proof_of_work"
  let L := cfg.firstLayerLog
  -- 查询树（树 0..1 = trace / 组合；FRI 树单独处理）
  let t0 ← treeOfJ? (commitments.getD 0 JVal.null) (decos.getD 0 JVal.null)
      (queried.getD 0 JVal.null) L
  let t1 ← treeOfJ? (commitments.getD 1 JVal.null) (decos.getD 1 JVal.null)
      (queried.getD 1 JVal.null) L
  -- FRI 层查询求值列：queried_values[2+k]（4 limb 列）
  let friQC := queried.drop 2
  let qps ← getA? air "query_positions"
  let q ← asNat? (qps.getD 0 JVal.null)
  let fw0 ← getA? fl "fri_witness"
  let l0 ← friLayerOfJ? (commitments.getD 2 JVal.null) (decos.getD 2 JVal.null)
      (friQC.getD 0 JVal.null) fw0 q 0
  let i1 ← ils.getD 0 JVal.null
  let fw1 ← getA? i1 "fri_witness"
  let l1 ← friLayerOfJ? (commitments.getD 3 JVal.null) (decos.getD 3 JVal.null)
      (friQC.getD 1 JVal.null) fw1 q 1
  let i2 ← ils.getD 1 JVal.null
  let fw2 ← getA? i2 "fri_witness"
  let l2 ← friLayerOfJ? (commitments.getD 4 JVal.null) (decos.getD 4 JVal.null)
      (friQC.getD 2 JVal.null) fw2 q 2
  let lpc ← getA? air "last_poly_channel"
  let lastPolyChannel ← lpc.mapM qmOfJ?
  let components ← componentsOfJ? air
  let cols ← colsOfJ? air
  let maxLogDegreeBound ← getN? air "composition_log_degree_bound"
  let chInit ← getFelt? air "channel_init"
  let compCommit ← getFelt? air "composition_commitment"
  let cm ← getA? air "composition_mask"
  let compositionMask ← cm.mapM qmOfJ?
  some
    { cfg := cfg
      components := components
      maxLogDegreeBound := maxLogDegreeBound
      cols := cols
      compositionCommitment := compCommit
      compositionMask := compositionMask
      proof :=
        { trees := [t0, t1]
          sampledValues := sampled
          friLayers := [l0, l1, l2]
          lastPolyChannel := lastPolyChannel
          lastPoly := lastPoly
          powNonce := powNonce }
      ch := (chInit, 0) }

/-! ### 对拍入口 -/

/-- 解析并运行主循环（解析失败 = false）。 -/
def verifyJson (s : String) : Bool :=
  match parseProof s with
  | some pp => Verifier.verifyMain pp.cfg pp.components pp.maxLogDegreeBound pp.cols
      { compositionCommitment := pp.compositionCommitment
        compositionMask := pp.compositionMask
        pcs := pp.proof } pp.ch
  | none => false

/-- 解析结果的树 0 根（对拍用；失败 = 0）。 -/
def ppRoot0 : Option ParsedProof → Fp252
  | some pp => match pp.proof.trees with | t :: _ => t.root | [] => 0
  | none => 0

/-- 解析结果的树 1 根（对拍用）。 -/
def ppRoot1 : Option ParsedProof → Fp252
  | some pp => match pp.proof.trees with | _ :: t :: _ => t.root | _ => 0
  | none => 0

/-- 解析结果的 POW nonce（对拍用）。 -/
def ppNonce : Option ParsedProof → Nat
  | some pp => pp.proof.powNonce
  | none => 0

end StwoLean.StarkProofJson
