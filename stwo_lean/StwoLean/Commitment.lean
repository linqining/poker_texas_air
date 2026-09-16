import Mathlib
import StwoLean.Channel
import StwoLean.LiftedMerkle
import StwoLean.Deep

/-!
# Commitment — FRI 多项式承诺方案的验证器编排（泛化版）

对应 stwo 2.3.0 `core/pcs/verifier.rs`
（`CommitmentSchemeVerifier`）、`core/fri.rs`
（`FriVerifier::commit` / `decommit_on_queries` / `SparseEvaluation`）、
`core/queries.rs`（`draw_queries`）、`core/channel/poseidon252.rs`
（`verify_pow_nonce`）与 `core/pcs/utils.rs`
（`prepare_preprocessed_query_positions`）。

## 通道交互（与 stwo 逐行对齐）

* `commit`：`mix_root = poseidon_hash(digest, root)`（`n_draws` 清零）；
* `verify_values`：`mix_felts(采样值平铺)` → `draw_secure_felt`
  （DEEP 随机系数）→ FRI 承诺（每层 `mix_root` + `draw_secure_felt`，
  末尾 `mix_felts(last_poly)`）→ **POW**（低 128 位尾零 ≥ n_bits，
  再 `mix_u64(nonce)`）→ `draw_queries`（掩码 + 排序去重）→ 逐树
  lifted Merkle 验证 → `fri_answers` → 逐层 FRI 验证与折叠 → 末层
  多项式核对。

## 泛化（Phase 2 收尾）

* **多树**：`TreeQueryProof` 列表——树 0（预处理树）用 `preparePP`
  位置，其余树用查询位置；
* **多查询**：每个 FRI 层一棵树、一次 `liftedVerify`（该层全部去重
  子集位置）；每个查询位置一条折叠链 `foldQuery`，折叠子集求值全部
  从该层的 Merkle 已验求值表按位置读取。首层的查询位置求值被
  **替换为 `fri_answers` 值**后再做 Merkle 核对——这是 DEEP-ALI 的
  soundness 链接（`FriFirstLayerVerifier::verify` 的混合语义）；
* **fold_step / packed leaf**：`foldStep` 参数化。子集大小
  `2^foldStep`；首层圆→线 + 余下线→点逐级折叠（α 逐级平方，
  `SparseEvaluation::fold_circle`）；`foldStep > 1` 时该层叶按
  `LOG_PACKED_LEAF_SIZE = 2` 打包（4 位置/叶、行 = 16 limb，
  `groupByLeaf` 复刻 `build_merkle_verification_inputs`）。

已知解耦（`PcsProofGen.lastPolyChannel` 注释）：末层多项式的通道
绑定值与核对值在向量中解耦（真实证明中二者相同）；核对逻辑与
stwo 逐行一致。
-/

namespace StwoLean

namespace Commitment

/-- PCS 配置。 -/
structure PcsConfig where
  /-- 首层圆域 log（= lifting_log_size） -/
  firstLayerLog : Nat
  /-- FRI fold_step（子集大小 2^foldStep） -/
  foldStep : Nat
  /-- POW 位数 -/
  powBits : Nat
  /-- 查询数 -/
  nQueries : Nat
  /-- 树 0（预处理树）的 log 高度（`preparePP` 的 pp_max_log_size） -/
  ppMaxLog : Nat

/-- `mix_root`：`digest := poseidon_hash(digest, root)`。 -/
def mixRoot (root : Fp252) (ch : Channel.Chan) : Channel.Chan :=
  (poseidonHash ch.1 root, 0)

/-- u128 窗口内的尾零位数（`u128::trailing_zeros`；全零 = 128）。 -/
def trailingZerosAux : Nat → Nat → Nat
  | 0, _ => 0
  | fuel + 1, n => if n == 0 then 128
    else if n % 2 == 0 then trailingZerosAux fuel (n / 2) + 1
    else 0

/-- `verify_pow_nonce`：`H(H(POW_PREFIX, digest, n_bits), nonce)` 的
低 128 位（`to_bytes_be()[16..]`）尾零数 ≥ `n_bits`。 -/
def powCheck (digest : Fp252) (nBits nonce : Nat) : Bool :=
  let prefixed := poseidonHashMany [0x12345678, digest, nBits]
  let h := poseidonHash prefixed (nonce : Fp252)
  trailingZerosAux 128 (h.val % 2 ^ 128) >= nBits

/-- `draw_queries` 主循环：反复 `draw_u32s`，字掩码 `2^log - 1`，
攒够 `n` 个为止。 -/
def drawQueriesAux (mask n : Nat) : Nat → Channel.Chan → List Nat × Channel.Chan
  | 0, ch => ([], ch)
  | fuel + 1, ch =>
    if n == 0 then ([], ch)
    else
      let (words, ch') := Channel.drawU32s ch
      let ws := words.map (· &&& mask)
      if n ≤ ws.length then (ws.take n, ch')
      else
        let (more, ch'') := drawQueriesAux mask (n - ws.length) fuel ch'
        (ws ++ more, ch'')

/-- `draw_queries` 入口。 -/
def drawQueries (logSize n : Nat) (ch : Channel.Chan) :
    List Nat × Channel.Chan :=
  drawQueriesAux (2 ^ logSize - 1) n (n + 1) ch

/-- 有序插入。 -/
def insInto (a : Nat) : List Nat → List Nat
  | [] => [a]
  | b :: rest => if a ≤ b then a :: b :: rest else b :: insInto a rest

/-- 插入排序。 -/
def insSort : List Nat → List Nat
  | [] => []
  | a :: rest => insInto a (insSort rest)

/-- 升序列去重（`BTreeSet` 语义）。 -/
def dedupSorted : List Nat → List Nat
  | [] => []
  | a :: rest =>
    let ded := dedupSorted rest
    if ded.headD (a + 1) == a then ded else a :: ded

/-- 排序 + 去重（`Queries::new`）。 -/
def sortDedup (l : List Nat) : List Nat := dedupSorted (insSort l)

/-- `prepare_preprocessed_query_positions`。 -/
def preparePP (queryPositions : List Nat) (maxLog ppMaxLog : Nat) : List Nat :=
  if ppMaxLog == 0 then []
  else if maxLog < ppMaxLog then
    queryPositions.map fun pos => (pos / 2) * 2 ^ (ppMaxLog - maxLog + 1) + pos % 2
  else
    queryPositions.map fun pos => (pos / 2 ^ (maxLog - ppMaxLog + 1)) * 2 + pos % 2

/-- FRI 承诺阶段：每层 `mix_root` + `draw_secure_felt`，返回抽出的
α 列表与通道（`FriVerifier::commit` 的通道序列）。 -/
def friCommitAux : List Fp252 → Channel.Chan → List QM31 × Channel.Chan
  | [], ch => ([], ch)
  | root :: rest, ch =>
    let (a, ch') := Channel.drawSecureFelt (mixRoot root ch)
    let (as, ch'') := friCommitAux rest ch'
    (a :: as, ch'')

/-! ### 子集折叠（`SparseEvaluation::fold_circle` / `fold_coset`） -/

/-- 子集圆域点（`CircleDomain(Coset(initialIdx, subLog)).at(j)`）：
`j < 2^subLog` 为 `initialIdx + 2^(31-subLog)·j`，否则其对径点。 -/
def subsetCircleAt (initialIdx subLog j : Nat) : CirclePoint M31 :=
  let half := 2 ^ subLog
  if j < half then cpiToPoint (initialIdx + 2 ^ (31 - subLog) * j)
  else
    let k := initialIdx + 2 ^ (31 - subLog) * (j - half)
    cpiToPoint ((2 ^ 31 - k) % 2 ^ 31)

/-- 求值列表的相邻对（带对下标 j）。 -/
def pairsIdx : Nat → List QM31 → List (Nat × QM31 × QM31)
  | _, [] => []
  | j, f0 :: f1 :: rest => (j, f0, f1) :: pairsIdx (j + 1) rest
  | j, [f] => [(j, f, f)]

/-- `fold_circle_into_line` 的子集版：相邻对折到 x 投影，
twiddle = `p.y⁻¹`（`p` 为子集圆域在 `bitrev(2j, subLog+1)` 处的点）。 -/
def foldCircleSubset (initialIdx subLog : Nat) (α : QM31)
    (evals : List QM31) : List QM31 :=
  (pairsIdx 0 evals).map fun (j, f0, f1) =>
    let p := subsetCircleAt initialIdx subLog (bitReverseIndex (2 * j) (subLog + 1))
    FriCore.foldPair f0 f1 (FriVerifier.inverseM31 p.y) α

/-- `fold_coset` 的泛化版：线域陪集 `Coset(initialIdx, log)` 上相邻对
折叠（x = 域点 `bitrev(2j, log)` 处的 x 坐标），每层 α 平方、
域 `double`，直到单项。 -/
def foldCosetGen (initialIdx : Nat) :
    Nat → Nat → QM31 → List QM31 → QM31
  | _, _, _, [v] => v
  | 0, _, _, evals => evals.headD 0
  | fuel + 1, log, alpha, evals =>
    let stepped := (pairsIdx 0 evals).map fun (j, f0, f1) =>
      let x := LineDomain.at ⟨⟨initialIdx, log⟩⟩ (bitReverseIndex (2 * j) log)
      FriCore.foldPair f0 f1 (FriVerifier.inverseM31 x) alpha
    -- 域 double：陪集初值 ×2（`Coset::double` 语义）
    foldCosetGen (initialIdx * 2) fuel (log - 1) (alpha * alpha) stepped

/-- `SparseEvaluation::fold_circle`：大小 `2^foldStep` 的子集求值 →
单项。首层圆→线（twiddle `p.y⁻¹`）；`foldStep > 1` 时余下线→点
逐级折叠（α 平方，`fold_coset`）。
`initialIdx = source.index_at(bitrev(base, L))`。 -/
def foldSubset (initialIdx foldStep : Nat) (α : QM31) (evals : List QM31) : QM31 :=
  let subLog := foldStep - 1
  let buf := foldCircleSubset initialIdx subLog α evals
  if foldStep == 1 then buf.headD 0
  else foldCosetGen initialIdx (subLog + 1) subLog (α * α) buf

/-! ### 证明结构 -/

/-- 一棵承诺树的查询证明（`MerkleVerifierLifted::verify` 的输入）。 -/
structure TreeQueryProof where
  /-- 承诺根 -/
  root : Fp252
  /-- 是否预处理树（树 0：位置 = `preparePP` 结果） -/
  isPP : Bool
  /-- 树高（liftedVerify 的 height） -/
  height : Nat
  /-- 每查询位置的叶行（行序 = 列按 log size 稳定排序） -/
  rows : List (List M31)
  /-- 树 witness -/
  witness : List Fp252

/-- 一个 FRI 层的查询证明：该层树 + 全部去重子集位置的求值表。 -/
structure FriLayerQueryProof where
  /-- 层承诺根 -/
  root : Fp252
  /-- 本层全部子集位置（升序去重；域内 natural 位置） -/
  positions : List Nat
  /-- 每位置求值（与 positions 对齐） -/
  evals : List QM31
  /-- 树 witness（树位置 = pos >> packedShift 去重） -/
  witness : List Fp252
  /-- 叶打包位移：foldStep > 1 时 = 2（`LOG_PACKED_LEAF_SIZE`），否则 0 -/
  packedShift : Nat
  deriving Inhabited

/-- 列表的 (下标, 元素) 标注。 -/
def pairsIdxNat {α : Type*} : Nat → List α → List (Nat × α)
  | _, [] => []
  | i, x :: rest => (i, x) :: pairsIdxNat (i + 1) rest

/-- 线域连续 `double` n 次。 -/
def LineDomain.doubleN : LineDomain → Nat → LineDomain
  | d, 0 => d
  | d, n + 1 => doubleN (LineDomain.double d) n

/-- 每列每查询位置的值（按查询下标对齐）：从各树的叶行按列提取，
树序 × 列序 = `flatten_cols` 的列序。 -/
def queriedCols (trees : List TreeQueryProof) : List (List M31) :=
  trees.flatMap fun t =>
    let nCols := match t.rows with
      | [] => 0
      | r :: _ => r.length
    (List.range nCols).map fun c =>
      t.rows.map (fun row => row.getD c 0)

/-- 位置求值查找（positions 升序，evals 对齐；未命中返回 0）。 -/
def evalAtPos : List Nat → List QM31 → Nat → QM31
  | [], _, _ => 0
  | p :: ps, v :: vs, idx => if p == idx then v else evalAtPos ps vs idx
  | _ :: ps, [], idx => evalAtPos ps [] idx

/-- 位置在升序列表中的下标（未命中 none）。 -/
def posIdx : List Nat → Nat → Option Nat
  | [], _ => none
  | p :: ps, pos => if p == pos then some 0
    else (posIdx ps pos).map (· + 1)

/-- 位置的求值替换（首层 DEEP-ALI 混合：查询位置用 `fri_answers`
值，其余用层求值表）。 -/
def replaceEvals (positions : List Nat) (evals : List QM31)
    (qs : List Nat) (answers : List QM31) : List QM31 :=
  (positions.zip evals).map fun (pos, v) =>
    match posIdx qs pos with
    | some j => answers.getD j v
    | none => v

/-- 层的 Merkle 验证输入（`build_merkle_verification_inputs`）：
树位置 = `pos >> packedShift` 去重升序；叶行 = 该叶各位置 limb 的
offset-major 拼接（位置 0 的 4 坐标、位置 1 的 4 坐标、…）。 -/
def divShr (a b : Nat) : Nat := if b == 0 then a else a / b

/-- 连续同叶 `(pos, eval)` 段的切分（叶位置 = pos >> s）。 -/
private def spanSameLeaf (leaf s fuel : Nat) (l : List (Nat × QM31)) :
    List (Nat × QM31) × List (Nat × QM31) :=
  match fuel, l with
  | 0, _ => (l, [])
  | _ + 1, [] => ([], [])
  | fuel + 1, x :: rest =>
    if divShr x.1 s == leaf then
      let (same, others) := spanSameLeaf leaf s fuel rest
      (x :: same, others)
    else ([], x :: rest)

def groupByLeaf (s : Nat) :
    Nat → List (Nat × QM31) → List (Nat × List (Nat × QM31))
  | _, [] => []
  | 0, _ => []
  | fuel + 1, pe :: rest =>
    let leaf := divShr pe.1 (2 ^ s)
    let so := spanSameLeaf leaf (2 ^ s) (List.length rest) rest
    (leaf, pe :: so.1) :: groupByLeaf s fuel so.2

/-- FRI 层的 lifted Merkle 验证（该层全部去重子集位置一次核对）。 -/
def friLayerVerify (layer : FriLayerQueryProof) (logSize : Nat) : Bool :=
  let pairs := layer.positions.zip layer.evals
  let leaves := groupByLeaf layer.packedShift (List.length pairs) pairs
  let treePos := leaves.map (fun l => l.1)
  let treeRows := leaves.map (fun l =>
    (l.2.map fun pe => match pe with | (_, q) => FriVerifier.qm31ToM31s q).flatten)
  LiftedMerkle.liftedVerify layer.root (logSize - layer.packedShift)
    treePos treeRows layer.witness

/-- 子集求值读取：求值表中 `[base, base + 2^foldStep)` 连续段的求值。 -/
def subsetEvals : List (Nat × QM31) → Nat → Nat → List QM31
  | _, _, 0 => []
  | pairs, base, fuel + 1 =>
    let here := pairs.filter (fun pe => pe.1 == base)
    (here.headD (base, 0)).2 :: subsetEvals pairs (base + 1) fuel

/-- 单层折叠：子集（`base = (idx >> foldStep) << foldStep` 起
`2^foldStep` 个位置）的求值 → 上层位置 `idx >> foldStep` 的求值。
首层（圆域，`isFirst`）的子集陪集初值 = 圆域索引
`2^(30-L) + 2^(32-L)·bitrev(base, L)`；内层（线域）= 层陪集索引
`dom.initial + dom.step·bitrev(base, log)`。 -/
def friLayerFold (layer : FriLayerQueryProof) (foldStep : Nat)
    (isFirst : Bool) (dom : LineDomain) (logSize L : Nat)
    (idx : Nat) (α : QM31) : QM31 :=
  let base := (idx / 2 ^ foldStep) * 2 ^ foldStep
  let ev := subsetEvals (layer.positions.zip layer.evals) base (2 ^ foldStep)
  let bitrevBase := bitReverseIndex base logSize
  if isFirst then
    -- 首层圆→线（子集圆域初值 = 圆域索引）+ 余下线→点（α²）
    let initialIdx := 2 ^ (30 - L) + 2 ^ (32 - logSize) * bitrevBase
    let buf := foldCircleSubset initialIdx (foldStep - 1) α ev
    if foldStep == 1 then buf.headD 0
    else foldCosetGen initialIdx (foldStep - 1) (foldStep - 1) (α * α) buf
  else
    -- 内层线域：子集陪集初值 = 层陪集索引，纯 fold_coset（fold_line）
    let initialIdx := dom.coset.initialIndex + dom.coset.stepSize * bitrevBase
    foldCosetGen initialIdx foldStep foldStep α ev

/-- 单查询折叠链：首层圆→线（α₀），内层线域逐层（每层各自 α），
返回 (末层求值, 末层位置)。 -/
def foldQuery (layers : List FriLayerQueryProof) (alphas : List QM31)
    (foldStep L : Nat) (q : Nat) : QM31 × Nat :=
  let l0 := layers.headD default
  let v0 := friLayerFold l0 foldStep true (LineDomain.ofCoset (Coset.mk' 0 0)) L L q
    (alphas.getD 0 0)
  let dom0 : LineDomain := ⟨⟨2 ^ (29 - L + foldStep), L - foldStep⟩⟩
  lineFold (layers.drop 1) (alphas.drop 1) dom0
    (L - foldStep) (q / 2 ^ foldStep) v0
where lineFold (layers : List FriLayerQueryProof) (alphas : List QM31)
    (dom : LineDomain) (log idx : Nat) (v : QM31) : QM31 × Nat :=
  match layers, alphas with
  | [], _ => (v, idx)
  | layer :: rest, a :: as =>
    let v' := friLayerFold layer foldStep false dom log L idx a
    lineFold rest as (LineDomain.double dom) (log - 1)
      (idx / 2 ^ foldStep) v'
  | _, _ => (v, idx)

/-- 末层多项式核对（`decommit_last_layer`）。 -/
def lastLayerCheck (lastPoly : List QM31) (dom : LineDomain) (log idx : Nat)
    (queryEval : QM31) : Bool :=
  queryEval == FriVerifier.polyEvalQM31 lastPoly
    (QM31.ofU32 (LineDomain.at dom (bitReverseIndex idx log)).val 0 0 0)

/-- `CommitmentSchemeProof` 的泛化形态（多树 + 多查询 + foldStep）。 -/
structure PcsProofGen where
  /-- 承诺树（树 0 = 预处理树） -/
  trees : List TreeQueryProof
  /-- 全树采样值平铺（`flatten_cols`：树序 × 列序 × 采样序） -/
  sampledValues : List QM31
  /-- FRI 层（首层圆域 + 内层线域） -/
  friLayers : List FriLayerQueryProof
  /-- 通道绑定的末层多项式（真实证明中与 `lastPoly` 相同；对拍向量
  用占位值解耦——手工构造同时满足 FS 绑定与低次一致的末层多项式
  需要完整 AIR 一致性，属 Phase 3。核对逻辑与 stwo 逐行一致） -/
  lastPolyChannel : List QM31
  /-- 末层多项式（低次在前；核对 `queryEval == polyEval lastPoly x`） -/
  lastPoly : List QM31
  /-- POW nonce -/
  powNonce : Nat

/-- `CommitmentSchemeVerifier.verify_values` 的泛化编排。
`sampled` = 全树采样值平铺（`flatten_cols`）；`cols` = 每列
`(logSize, OODS 采样)`（验证器输入）；`queried` = 每列每查询位置的
值（按查询下标对齐）；`ch` = commit 阶段（全部树 `mix_root`）之后
的通道状态。 -/
def verifyValuesGen (cfg : PcsConfig)
    (cols : List (Nat × List Deep.PointSample))
    (p : PcsProofGen) (ch : Channel.Chan) : Bool :=
  let L := cfg.firstLayerLog
  -- mix_felts(采样值) → DEEP 随机系数
  let ch1 := Channel.mixFelts p.sampledValues ch
  let (αdeep, ch2) := Channel.drawSecureFelt ch1
  -- FRI 承诺：mix_root/α 交替 + mix_felts(last_poly)
  let (alphas, chF) := friCommitAux (p.friLayers.map (·.root)) ch2
  let chF := Channel.mixFelts p.lastPolyChannel chF
  -- POW
  if !powCheck chF.1 cfg.powBits p.powNonce then false
  else
    let chP := Channel.mixU64 p.powNonce chF
    -- 查询位置
    let (rawQs, _) := drawQueries L cfg.nQueries chP
    let qs := sortDedup rawQs
    let pp := preparePP qs L cfg.ppMaxLog
    -- 逐树 lifted Merkle 验证（树 0 = 预处理位置，其余 = 查询位置）
    let treeOk := p.trees.foldl (fun acc t =>
      let pos := if t.isPP then pp else qs
      acc && LiftedMerkle.liftedVerify t.root t.height pos t.rows t.witness) true
    if !treeOk then false
    else
      -- DEEP 商值（fri_answers）
      let queried := queriedCols p.trees
      let answers := Deep.friAnswers αdeep 1 L cols queried qs
      -- 首层：查询位置求值替换为 fri_answers 值（DEEP-ALI 混合）
      let l0 := p.friLayers.headD default
      let l0Evals := replaceEvals l0.positions l0.evals qs answers
      let l0' : FriLayerQueryProof := { l0 with evals := l0Evals }
      let layers := l0' :: p.friLayers.drop 1
      -- 逐层 Merkle 验证（层 k 的位置域 log = L - k）
      let layerOk := (pairsIdxNat 0 layers).foldl (fun acc t =>
        acc && friLayerVerify t.2 (L - cfg.foldStep * t.1)) true
      if !layerOk then false
      else
        -- 每查询折叠链 + 末层核对
        let nInner := p.friLayers.length - 1
        let domFinal : LineDomain :=
          ⟨⟨2 ^ (29 - L + cfg.foldStep), L - cfg.foldStep⟩⟩
        let domFinal := LineDomain.doubleN domFinal (cfg.foldStep * nInner)
        let logFinal := L - cfg.foldStep * (1 + nInner)
        qs.all (fun q =>
          let (v, idx) := foldQuery layers alphas cfg.foldStep L q
          lastLayerCheck p.lastPoly domFinal logFinal idx v)

end Commitment

end StwoLean
