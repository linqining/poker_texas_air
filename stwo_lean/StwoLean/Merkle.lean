import Mathlib
import StwoLean.Poseidon252
import StwoLean.Channel

/-!
# Merkle — Poseidon252 Merkle 树的节点哈希与路径验证

对应 stwo 2.3.0 `core/vcs/poseidon252_merkle.rs`（`Poseidon252MerkleHasher`
+ `construct_felt252_from_m31s`）。Channel/PCS/FRI 的承诺层。

## hash_node 三分支（逐行对齐源码）

* **叶节点**（无子哈希）：列值每 8 个 M31 打包成一个 felt
  （base-2^31 Horner，**fold 从 0 开始**——与 Channel 的 fold-from-ONE
  不同！），最后一个不足 8 的块注入块长 `+= len·2^248`；
  `hash_node = poseidon_hash_many(packs)`；
* **内部节点、无列值**：`poseidon_hash(left, right)`；
* **内部节点、有列值**：`poseidon_hash_many([left, right] ++ packs)`。

打包注意：M31 limb 直接拼在低位（`felt·2^31 + limb`），与 Channel 的
`mix_u32s` 打包同构但使用 base-2^31 与 M31 值。

## 路径验证

`pathRoot`：从叶哈希出发，每层按查询索引的奇偶选择 `poseidonHash` 的
参数顺序拼上兄弟哈希，折半上升。`verifyPath` 从叶列值出发并比对根。
完整的通用多列 `MerkleVerifier::verify` 状态机（跨层查询合并）在
Phase 2 后续按 PCS 的实际调用形式接入。
-/

namespace StwoLean

namespace Merkle

/-- M31 列值打包：每 8 个一块（base-2^31 Horner，从 0 开始），
末块长度注入 `+= len·2^248`（`construct_felt252_from_m31s`）。 -/
def packM31Block (block : List M31) : Fp252 :=
  let felt := block.foldl (fun cur l => cur * (2 ^ 31 : Fp252) + (l.val : Fp252)) 0
  if block.length < 8 then felt + (block.length : Fp252) * (2 ^ 248 : Fp252) else felt

/-- `construct_felt252_from_m31s`：列值列表按 8 一块打包。 -/
def packColumnValues (values : List M31) : List Fp252 :=
  (Channel.listChunks 8 values).map packM31Block

/-- `Poseidon252MerkleHasher::hash_node`：三分支逐行移植。 -/
def hashNode (children : Option (Fp252 × Fp252)) (columnValues : List M31) : Fp252 :=
  match children with
  | none => poseidonHashMany (packColumnValues columnValues)
  | some (l, r) =>
    if columnValues.isEmpty then poseidonHash l r
    else poseidonHashMany (l :: r :: packColumnValues columnValues)

/-- 单条查询路径的根重算：`siblings` 自叶向上每层的兄弟哈希，
`idx` 为叶索引（每层折半）。 -/
def pathRoot (h : Fp252) (idx : Nat) : List Fp252 → Fp252
  | [] => h
  | sib :: rest =>
    pathRoot (if idx % 2 == 0 then poseidonHash h sib else poseidonHash sib h) (idx / 2) rest

/-- 路径验证：从叶列值出发重建根并比对承诺根。 -/
def verifyPath (leafValues : List M31) (idx : Nat) (siblings : List Fp252)
    (root : Fp252) : Bool :=
  pathRoot (hashNode none leafValues) idx siblings == root

end Merkle

end StwoLean
