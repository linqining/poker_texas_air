import Mathlib
import StwoLean.Poseidon252

/-!
# Poseidon252Channel — Fiat–Shamir 通道

对应 stwo 2.3.0 `stwo::core::channel::poseidon252::Poseidon252Channel`
（`Channel` trait 的 Poseidon 实现，poker_texas_air 的 canonical AIR
出证/验证路径使用的正是该通道）。逐行移植：

* 状态 `(digest, n_draws)`，初始 `(0, 0)`；
* `draw_secure_felt252`：`permute(digest, n_draws, 3).s0`——常数 3 做
  mix/draw 的域分离（mix 用 0/1/2，draw 用 3，源码注释原话）；
* `draw_base_felts`：画出的 felt 的 **base-2^31 低位在前 8 个数字**
  （`floor_div` 链即按位取 digit），映射回 M31；
* `draw_secure_felt`：取前 4 个数字组成 QM31；
* `draw_u32s`：同上但 base-2^32、7 个字；
* `mix_u64`：`digest := poseidon_hash(digest, v)`；
* `mix_u32s`：数据按 7 字一组打包成 big-endian felt（`cur*2^32 + w`），
  补零到 7 的倍数，`padding_len ≠ 0` 时在最后一 felt 的 bits [248:251]
  注入打包元素个数（`add_length_padding`：`+= n·2^248`，防不同长度
  打包碰撞）；`digest := poseidon_hash_many([digest] ++ felts)`；
* `mix_felts`：两个 QM31（8 个 M31 limb）打包成一个 felt——
  **fold 从 ONE 开始**（不是零），`cur = cur·2^31 + limb`；
  `digest := poseidon_hash_many([digest] ++ packs)`。

函数式风格：`Chan → value × Chan` / `Chan → Chan`。对拍向量统一
`native_decide`（含 stwo 单元测试自带的两个 digest 金向量）。
-/

namespace StwoLean

namespace Channel

/-- 通道状态：`(digest, n_draws)`。 -/
abbrev Chan := Fp252 × Nat

/-- 通道初始状态（`FieldElement252::default()` = 0）。 -/
def chInit : Chan := (0, 0)

/-- 向量文件用的简写：QM31 从单个 M31 提升（`SecureField::from(m)`）。 -/
def qm31l (a : Nat) : QM31 := QM31.ofU32 a 0 0 0

/-- `v` 的 base-`base` 低位在前 `n` 个数字。 -/
def baseDigits (base n v : Nat) : List Nat :=
  match n with
  | 0 => []
  | k + 1 => v % base :: baseDigits base k (v / base)

/-- `draw_secure_felt252` 的原像值（Nat 形式，便于按位提取）。 -/
def drawFelt252Val (ch : Chan) : Nat := (hades (ch.1, ch.2, 3)).1.val

/-- `draw_base_felts`：8 个 base-2^31 数字 → M31（每 digit < 2^31，
`ZMod` 转换保值）。 -/
def drawBaseFelts (ch : Chan) : List M31 :=
  (baseDigits (2 ^ 31) 8 (drawFelt252Val ch)).map (fun d => (d : M31))

/-- `draw_secure_felt`：前 4 个数字组成 QM31（`from_m31_array`）。 -/
def drawSecureFelt (ch : Chan) : QM31 × Chan :=
  let ds := baseDigits (2 ^ 31) 8 (drawFelt252Val ch)
  let q := QM31.ofU32 (ds.getD 0 0) (ds.getD 1 0) (ds.getD 2 0) (ds.getD 3 0)
  (q, (ch.1, ch.2 + 1))

/-- `draw_u32s`：7 个 base-2^32 数字。 -/
def drawU32s (ch : Chan) : List Nat × Chan :=
  (baseDigits (2 ^ 32) 7 (drawFelt252Val ch), (ch.1, ch.2 + 1))

/-- `mix_u64`：`digest := poseidon_hash(digest, v)`。 -/
def mixU64 (v : Nat) (ch : Chan) : Chan := (poseidonHash ch.1 (v : Fp252), 0)

/-- `add_length_padding`：`word += n·2^248`（把打包元素个数注入
bits [248:251]，防不同长度打包的哈希碰撞）。 -/
def addLengthPadding (word : Fp252) (n : Nat) : Fp252 :=
  word + (n : Fp252) * (2 ^ 248 : Fp252)

/-- 按 `n` 个一组分块（内核可求值的燃料递归实现；
对应 Rust `slice::chunks(2)` / `chunks(7)`）。 -/
def listChunksAux {α : Type*} : Nat → Nat → List α → List (List α)
  | 0, _, _ => []
  | fuel + 1, n, l =>
    if l.isEmpty then [] else List.take n l :: listChunksAux fuel n (List.drop n l)

def listChunks {α : Type*} (n : Nat) (l : List α) : List (List α) :=
  listChunksAux l.length n l

/-- `mix_u32s`：7 字一组 big-endian 打包，补零 + 长度填充，
`digest := poseidon_hash_many([digest] ++ felts)`。 -/
def mixU32s (data : List Nat) (ch : Chan) : Chan :=
  let paddingLen := 6 - ((data.length + 6) % 7)
  let padded : List Nat := data ++ List.replicate paddingLen 0
  let felts : List Fp252 := (listChunks 7 padded).map
    (fun chunk => chunk.foldl (fun cur y => cur * (2 ^ 32 : Fp252) + (y : Fp252)) 0)
  let felts : List Fp252 := if paddingLen != 0
    then felts.dropLast ++ [addLengthPadding felts.getLast! (7 - paddingLen)]
    else felts
  (poseidonHashMany (ch.1 :: felts), 0)

/-- QM31 的 4 个 M31 limb（`to_m31_array`）。 -/
def qm31Limbs (q : QM31) : List Nat :=
  [q.c0.re.val, q.c0.im.val, q.c1.re.val, q.c1.im.val]

/-- 从 ONE 开始的 limb Horner 打包（对应源码
`fold(FieldElement252::ONE, |cur, y| cur * shift + y)`）。 -/
def packLimbsFromOne (limbs : List Nat) : Fp252 :=
  limbs.foldl (fun cur l => cur * (2 ^ 31 : Fp252) + (l : Fp252)) 1

/-- 两个 QM31（8 个 limb）打包成一个 felt。 -/
def packPair (q0 q1 : QM31) : Fp252 := packLimbsFromOne (qm31Limbs q0 ++ qm31Limbs q1)

/-- 单个 QM31（4 个 limb）打包——`chunks(2)` 末尾奇数 chunk 的情形。 -/
def packSingle (q : QM31) : Fp252 := packLimbsFromOne (qm31Limbs q)

/-- `mix_felts`：`digest := poseidon_hash_many(digest :: 每两个 QM31 的打包)`；
末尾奇数个 QM31 时最后一个 chunk 只含 4 个 limb。 -/
def mixFelts (qs : List QM31) (ch : Chan) : Chan :=
  let packs := (listChunks 2 qs).map (fun c => match c with
    | [a] => packSingle a
    | [a, b] => packPair a b
    | _ => 0)
  (poseidonHashMany (ch.1 :: packs), 0)

end Channel

end StwoLean
