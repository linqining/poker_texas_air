import Mathlib
import StwoLean.Poseidon252
import StwoLean.Channel
import StwoLean.Merkle

/-!
# LiftedMerkle — lifted 多列 Merkle 承诺（PCS 实际使用的树）

对应 stwo 2.3.0 `core/vcs_lifted/poseidon252_merkle.rs`
（`Poseidon252MerkleHasher`）与 `core/vcs_lifted/verifier.rs`
（`MerkleVerifierLifted::verify`）。与 `Merkle.lean`（旧 `vcs/` 单列
`hash_node`）不同，PCS/FRI 的承诺树全部使用本模块：

## 叶哈希 = 3 槽 sponge（不是单次 hash_many！）

* `update_leaf(row)`：`buffer ++ row` 按 **16**（`ELEMENTS_IN_BUFFER`）分块；
  满块切成两半各 **8**（`ELEMENTS_IN_BLOCK`）打包（`packM31Block`，
  fold 从 0 + 末块长度注入），`poseidon_update` 成对吸收
  （`s0 += a, s1 += b, permute`，s2 顺带传递）；余数（<16）留在 buffer；
* `finalize`：buffer 按 8 打包成 felt，`poseidon_finalize`：
  成对吸收；奇数尾 `(s0 += last, s1 += 1)`；空尾 `(s0 += 1)`；再 permute，
  取 `s0`。

## 多查询树验证

`liftedVerify root height positions rows witness`：对（升序、去重的）
查询位置逐位置算叶哈希，逐层上折——相邻对（`idx ^^^ 1`）直接合并，
孤儿位置从 witness 顺序取兄弟哈希（按位置奇偶决定哈希参数顺序）；
`height` 层后须恰得 `(0, root)` 且 witness 耗尽。单查询位置时等价于
逐层一条路径；两查询位置为兄弟时第一层免 witness——`liftLayer`
统一处理两种情形（对应 stwo 的 `chunk_by(|a, b| a.0 ^ 1 == b.0)`）。

位置约定（与 vector-gen 对拍一致）：叶按 natural 域位置排列，索引链
逐层折半；行值顺序 = 列按 log size 稳定排序后的顺序（证明方写入顺序）。
-/

namespace StwoLean

namespace LiftedMerkle

/-- sponge 一对吸收：`s0 += a, s1 += b, permute`（`poseidon_update` 单步）。 -/
def spongePair (s : PState) (a b : Fp252) : PState :=
  hades (s.1 + a, s.2.1 + b, s.2.2)

/-- `poseidon_update`：成对吸收（长度为偶数；奇数尾不吸收）。 -/
def spongeUpdate (s : PState) : List Fp252 → PState
  | [] => s
  | [_a] => s
  | a :: b :: rest => spongeUpdate (spongePair s a b) rest

/-- `poseidon_finalize`：成对吸收 + 尾部填充，取 `s0`。
空尾 `state[0] += 1`；单元素尾 `state[0] += last, state[1] += 1`。 -/
def spongeFinalize (s : PState) : List Fp252 → Fp252
  | [] => (hades (s.1 + 1, s.2.1, s.2.2)).1
  | [a] => (hades (s.1 + a, s.2.1 + 1, s.2.2)).1
  | a :: b :: rest => spongeFinalize (spongePair s a b) rest

/-- `update_leaf` 的满块吸收循环：`buffer ++ row` 按 16 分块，满块
两半 8 打包成对吸收；返回 (新状态, 余数 buffer)。
`fuel` 为迭代上界（取行长即可）。 -/
def updateLeaf (fuel : Nat) (s : PState) (all : List M31) : PState × List M31 :=
  match fuel with
  | 0 => (s, all)
  | k + 1 =>
    if all.length < 16 then (s, all)
    else
      let c := all.take 16
      let s' := spongeUpdate s [Merkle.packM31Block (c.take 8), Merkle.packM31Block (c.drop 8)]
      updateLeaf k s' (all.drop 16)

/-- 叶哈希 = 空 buffer 起 `update_leaf(row)` + `finalize`。 -/
def leafHash (row : List M31) : Fp252 :=
  let (s, buf) := updateLeaf row.length (0, 0, 0) row
  spongeFinalize s ((Channel.listChunks 8 buf).map Merkle.packM31Block)

/-- 单层上折：相邻对合并（免 witness），孤儿从 witness 取兄弟。
返回 `some (上层节点表, 剩余 witness)`；witness 不足为 `none`。
上层表保持升序（对应 stwo `curr_layer_hashes` 的构造顺序）。 -/
def liftLayer (prev : List (Nat × Fp252)) (wit : List Fp252) :
    Option (List (Nat × Fp252) × List Fp252) :=
  match prev with
  | [] => some ([], wit)
  | (idx, h) :: rest =>
    match rest with
    | (idx2, h2) :: rest2 =>
      if idx ^^^ 1 == idx2 then
        match liftLayer rest2 wit with
        | some (out, wit') => some ((idx / 2, poseidonHash h h2) :: out, wit')
        | none => none
      else
        match wit with
        | w :: wit' =>
          match liftLayer rest wit' with
          | some (out, outwit) =>
            some ((idx / 2, if idx % 2 == 0 then poseidonHash h w else poseidonHash w h)
              :: out, outwit)
          | none => none
        | [] => none
    | [] =>
      match wit with
      | w :: wit' =>
        match liftLayer [] wit' with
        | some (out, outwit) =>
          some ((idx / 2, if idx % 2 == 0 then poseidonHash h w else poseidonHash w h)
            :: out, outwit)
        | none => none
      | [] => none

/-- `height` 层上折（fuel = height 作迭代上界）。 -/
def liftLayers (fuel height : Nat) (nodes : List (Nat × Fp252)) (wit : List Fp252) :
    Option (List (Nat × Fp252) × List Fp252) :=
  if height == 0 then some (nodes, wit)
  else
    match fuel with
    | 0 => none
    | k + 1 =>
      match liftLayer nodes wit with
      | some (next, wit') => liftLayers k (height - 1) next wit'
      | none => none

/-- `MerkleVerifierLifted::verify`：`positions` 须升序去重；每位置一行
叶值（行序 = 列按 log size 稳定排序）；witness 须恰好耗尽且重算根
等于承诺根。`height = 0` 时 stwo 直接放行（退化树）。 -/
def liftedVerify (root : Fp252) (height : Nat) (positions : List Nat)
    (rows : List (List M31)) (wit : List Fp252) : Bool :=
  if height == 0 then true
  else
    let leaves := (rows.zip positions).map (fun p => (p.2, leafHash p.1))
    match liftLayers (height + 1) height leaves wit with
    | some ([(0, r)], []) => r == root
    | _ => false

end LiftedMerkle

end StwoLean
