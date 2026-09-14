import Mathlib
import StwoLean.Poseidon252Params

/-!
# Poseidon252 — Starknet Poseidon 哈希

对应 stwo 2.3.0 的 Poseidon252 委托链：
`stwo::core::channel::poseidon252` / `vcs::poseidon252_merkle`
→ `starknet-crypto 0.8.1::poseidon_hash`（本库 `Poseidon252.lean` 逐行移植）
→ `starknet-types-core 0.2.4` → `lambdaworks-crypto 0.10.0`
`PoseidonCairoStark252`（参数与轮常数的出处，见 `Poseidon252Params.lean`）。

规范（Starknet Poseidon，`docs.starknet.io`）：

* 域 `Fp252`，状态 3 元素，S-box `x³`（`ALPHA = 3`）；
* Hades：4 full（S-box 作用全部 3 个元素）→ 83 partial（只作用第 3 个
  元素——注意是 `state[2]`，Starknet 变体约定）→ 4 full；
* `mix`：`t = s0+s1+s2; (s0,s1,s2) := (t+2s0, t-2s1, t-3s2)`
  （等于 3×3 循环 MDS 矩阵乘，见 lambdaworks `parameters.rs` 的注释；
  本库直接实现优化式 mix，等价性由向量钉死）；
* 常数表用 **COMP 压缩形式**（107 个）：partial 轮的 `M·c''` 线性贡献
  被前移烘焙进后续常数。注意 UNOPTIMIZED（273，教科书式每轮全加）
  与 COMP **不等价**——对拍实验证伪了"仅性能重排"的说法；本库实现
  与 `poseidon_permute_comp` 逐行对应，常数索引 12..94 为 partial 轮；
* sponge（`poseidon_hash_many`）：吸收对 `(s0 += x, s1 += y, permute)`，
  奇数长度末尾 `(s0 += last, s1 += 1)`，空哈希 `(s0 += 1)`，最终再
  permute 一次，取 `s0`；`poseidon_hash(x,y) = permute(x, y, 2).s0`
  （第三槽常数 2 区分单/双/多参数域）。

所有函数为结构递归/裸 match，`native_decide`（编译器求值，GMP 加速）
可归约；91 轮 251-bit 排列纯 `decide` 内核求值需约 30 分钟/条，故
本层对拍向量统一用 `native_decide`（信任模型见 README 与审计脚本）。
-/

namespace StwoLean

/-- Hades 状态：嵌套三元组（便于模式匹配与内核求值）。 -/
abbrev PState := Fp252 × Fp252 × Fp252

/-- S-box：立方（`ALPHA = 3`）。 -/
def pCube (x : Fp252) : Fp252 := x * x * x

/-- mix（MDS）：与循环矩阵 `C(3,1,1)` 乘法一致。 -/
def pMix (s : PState) : PState :=
  let t := s.1 + s.2.1 + s.2.2
  (t + 2 * s.1, t - 2 * s.2.1, t - 3 * s.2.2)

/-- full round：全元素加常数 + S-box + mix
（对应 lambdaworks `full_round`）。 -/
def pFullRound (idx : Nat) (s : PState) : PState :=
  pMix (pCube (s.1 + RC idx), pCube (s.2.1 + RC (idx + 1)), pCube (s.2.2 + RC (idx + 2)))

/-- partial round：只对 `s2` 加常数 + S-box + mix
（对应 lambdaworks `partial_round`，注意作用位是 `state[2]`）。 -/
def pPartialRound (idx : Nat) (s : PState) : PState :=
  pMix (s.1, s.2.1, pCube (s.2.2 + RC idx))

/-- `n` 个连续 partial round（结构递归，内核可求值）。 -/
def pPartialRounds (n idx : Nat) (s : PState) : PState :=
  match n with
  | 0 => s
  | k + 1 => pPartialRounds k (idx + 1) (pPartialRound idx s)

/-- `n` 个连续 full round（每轮消耗 3 个常数）。 -/
def pFullRounds (n idx : Nat) (s : PState) : PState :=
  match n with
  | 0 => s
  | k + 1 => pFullRounds k (idx + 3) (pFullRound idx s)

/-- Hades 排列 = `poseidon_permute_comp` 的逐行移植：
4 full（常数 0-11）→ 83 partial（常数 12-94，只加 s2）→
首行并入 partial 压缩的 last full（常数 95-106，共 4 轮：95 行
消耗 95/96/97 三常数，随后 98/101/104）。 -/
def hades : PState → PState :=
  pFullRounds 4 95 ∘ pPartialRounds 83 12 ∘ pFullRounds 4 0

/-- `poseidon_hash(x, y)`：`permute(x, y, 2).s0`
（starknet-crypto `poseidon_hash`；第三槽 2 区分双参数域）。 -/
def poseidonHash (x y : Fp252) : Fp252 := (hades (x, y, 2)).1

/-- `poseidon_hash_single(x)`：`permute(x, 0, 1).s0`。 -/
def poseidonHashSingle (x : Fp252) : Fp252 := (hades (x, 0, 1)).1

/-- `poseidon_hash_many(msgs)` 的 sponge：逐行对应 starknet-crypto 的
`poseidon_hash_many` 主循环——完整对 permute，奇数尾 `(last, 1)` 填充，
空输入 `(1, ·, ·)` 填充，每个分支恰好再 permute 一次。 -/
def poseidonHashManyL : List Fp252 → PState → Fp252
  | [], s => (hades (s.1 + 1, s.2.1, s.2.2)).1
  | [x], s => (hades (s.1 + x, s.2.1 + 1, s.2.2)).1
  | x :: y :: rest, s => poseidonHashManyL rest (hades (s.1 + x, s.2.1 + y, s.2.2))

/-- `poseidon_hash_many` 的空状态入口。 -/
def poseidonHashMany (msgs : List Fp252) : Fp252 := poseidonHashManyL msgs (0, 0, 0)

end StwoLean
