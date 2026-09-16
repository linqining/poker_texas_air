import StwoLean.QM31

/-!
# Blake2s — 完整可计算 Blake2s 哈希与 Blake2sChannel

对应 stwo 2.3.0 `core/vcs/blake2_hash.rs`（`Blake2sHasherGeneric`，
底层为标准 BLAKE2s-256，RFC 7693）与 `core/channel/blake2s.rs`
（`Blake2sChannelGeneric<false>`）。

## Blake2s 规范

* 状态 8 个 u32（小端字），16 词消息块，10 轮；
* `G(v₀,v₁,v₂,v₃,x,y)`：四元 ARX 混合（加法、旋转 16/12/8/7、异或）；
* 轮函数：列 4 组 + 对角 4 组，SIGMA[r] 置换选消息词；
* 计数器 `t`（已处理字节数）注入 `v₁₂/v₁₃`，末块 `v₁₄ = ~v₁₄`；
* 无密钥参数块：`h₀ ⊕= 0x01010020`（摘要长 32、无密钥、fanout/depth 1）。

## Blake2sChannel（逐行对齐 blake2s.rs）

* `mixFelts`：QM31 列的 4·M31 limb 小端字节拼接，`H(digest ‖ bytes)`；
* `drawU32s`：`H(digest ‖ counter_le ‖ 0x00)` 的 8 个 u32（小端），
  `n_draws += 1`（域分离字节区分抽取与混合）；
* `drawBaseFelts`：重试循环直到 8 个 u32 全部 `< 2P`
  （每次重试消耗一个计数器），`reduce(x) = x - P (x ≥ P)`；
* `mixU32s`：`H(digest ‖ words_le)`；`mixU64`：两个 u32 小端；
* `verifyPowNonce`：`H(H(0x12345678_le ‖ 0¹² ‖ digest ‖ n_bits_le) ‖
  nonce_le)` 的低 16 字节（LE u128）尾零数 ≥ `n_bits`。

字节串以 `List Nat`（字节 0..255）表示；全部结构递归可被
`native_decide` 归约。
-/

namespace Blake2s

/-- u32 字（Nat 表示，值 < 2³²）。 -/
abbrev W32 := Nat

/-- 循环右移。 -/
def rotr (x n : Nat) : Nat :=
  (x / 2 ^ n + (x % 2 ^ n) * 2 ^ (32 - n)) % 4294967296

/-- IV（与 SHA-256 共用）。 -/
def iv : Array Nat := #[
  1779033703, 3144134277, 1013904242, 2773480762,
  1359893119, 2600822924, 528734635, 1541459225]

/-- 10 轮消息词置换表。 -/
def sigma : List (List Nat) := [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]]

/-- 消息块字节串（64 字节，不足补零）。 -/
def blockOf (data : List Nat) (i : Nat) : List Nat :=
  (data.drop (64 * i)).take 64

/-- 消息块小端取第 i 个 u32 词。 -/
def leWord (block : List Nat) (i : Nat) : Nat :=
  block.getD (4 * i) 0 + block.getD (4 * i + 1) 0 * 256
    + block.getD (4 * i + 2) 0 * 65536 + block.getD (4 * i + 3) 0 * 16777216

/-- `G(v₀,v₁,v₂,v₃,x,y)`：四元 ARX 混合（数组下标 a b c d）。 -/
def g (v : Array Nat) (a b c d x y : Nat) : Array Nat :=
  let v := v.set! a ((v.getD a 0 + v.getD b 0 + x) % 4294967296)
  let v := v.set! d (rotr (Nat.xor (v.getD d 0) (v.getD a 0)) 16)
  let v := v.set! c ((v.getD c 0 + v.getD d 0) % 4294967296)
  let v := v.set! b (rotr (Nat.xor (v.getD b 0) (v.getD c 0)) 12)
  let v := v.set! a ((v.getD a 0 + v.getD b 0 + y) % 4294967296)
  let v := v.set! d (rotr (Nat.xor (v.getD d 0) (v.getD a 0)) 8)
  let v := v.set! c ((v.getD c 0 + v.getD d 0) % 4294967296)
  let v := v.set! b (rotr (Nat.xor (v.getD b 0) (v.getD c 0)) 7)
  v

/-- 单轮：8 次 `G`（列 4 组 + 对角 4 组）；`s` 为消息词下标置换，
经 `m` 取词。 -/
def blakeRound (v : Array Nat) (m : Array Nat) (s : List Nat) : Array Nat :=
  let v := g v 0 4 8 12 (m.getD (s.getD 0 0) 0) (m.getD (s.getD 1 0) 0)
  let v := g v 1 5 9 13 (m.getD (s.getD 2 0) 0) (m.getD (s.getD 3 0) 0)
  let v := g v 2 6 10 14 (m.getD (s.getD 4 0) 0) (m.getD (s.getD 5 0) 0)
  let v := g v 3 7 11 15 (m.getD (s.getD 6 0) 0) (m.getD (s.getD 7 0) 0)
  let v := g v 0 5 10 15 (m.getD (s.getD 8 0) 0) (m.getD (s.getD 9 0) 0)
  let v := g v 1 6 11 12 (m.getD (s.getD 10 0) 0) (m.getD (s.getD 11 0) 0)
  let v := g v 2 7 8 13 (m.getD (s.getD 12 0) 0) (m.getD (s.getD 13 0) 0)
  let v := g v 3 4 9 14 (m.getD (s.getD 14 0) 0) (m.getD (s.getD 15 0) 0)
  v

/-- 64 字节块的压缩函数：`t` = 本块含末尾补零在内的累计字节数，
`last` = 末块标志。返回 `h ⊕ v[0..8]`。 -/
def compress (h : Array Nat) (block : List Nat) (t : Nat) (last : Bool) : Array Nat :=
  let m : Array Nat := (Array.range 16).map fun i => leWord block i
  let v0 : Array Nat := (h ++ iv)
  let v1 := (v0.set! 12 (Nat.xor (v0.getD 12 0) (t % 4294967296))).set! 13
    (Nat.xor (v0.getD 13 0) (t / 4294967296))
  let v2 := if last then v1.set! 14 (Nat.xor (v1.getD 14 0) 4294967295) else v1
  let v3 :=
    (sigma.foldl (fun v s => blakeRound v m s) v2)
  (Array.range 8).map fun i =>
    Nat.xor (Nat.xor (h.getD i 0) (v3.getD i 0)) (v3.getD (i + 8) 0)

/-- 无密钥 BLAKE2s-256：返回 8 个状态字。
`t` 取 `min(64·(i+1), len)`；末块以零补足 64 字节。 -/
def blake2sWords (data : List Nat) : Array Nat :=
  let h0 := (iv).set! 0 (Nat.xor (iv.getD 0 0) 16842784)
  go (max 1 ((data.length + 63) / 64)) 0 h0 data
where
  go : Nat → Nat → Array Nat → List Nat → Array Nat
    | 0, _, h, _ => h
    | fuel + 1, i, h, data =>
      let block := blockOf data i
      let t := min (64 * (i + 1)) data.length
      let h' := compress h block t (64 * (i + 1) ≥ data.length)
      go fuel (i + 1) h' data

/-- 8 个状态字 → 32 字节（小端）。 -/
def wordsToBytes (ws : Array Nat) : List Nat :=
  (List.range 32).map fun i =>
    let w := ws.getD (i / 4) 0
    let k := i % 4
    (w / 2 ^ (8 * k)) % 256

/-- BLAKE2s-256 摘要（32 字节列表）。 -/
def blake2s (data : List Nat) : List Nat := wordsToBytes (blake2sWords data)

end Blake2s

namespace Blake2s

/-! ### Blake2sChannel（`core/channel/blake2s.rs`） -/

/-- 通道状态：`(digest 字节串, n_draws)`。 -/
abbrev B2Chan := List Nat × Nat

/-- M31 limb → 4 字节小端。 -/
def m31Bytes (m : StwoLean.M31) : List Nat :=
  [m.val % 256, (m.val / 256) % 256, (m.val / 65536) % 256, (m.val / 16777216) % 256]

/-- QM31 → 16 字节小端（4 limb）。 -/
def qm31Bytes (x : StwoLean.QM31) : List Nat :=
  m31Bytes x.c0.re ++ m31Bytes x.c0.im ++ m31Bytes x.c1.re ++ m31Bytes x.c1.im

/-- u32 → 4 字节小端。 -/
def u32Bytes (w : Nat) : List Nat :=
  [w % 256, (w / 256) % 256, (w / 65536) % 256, (w / 16777216) % 256]

/-- u64 → 8 字节小端。 -/
def u64Bytes (w : Nat) : List Nat :=
  u32Bytes (w % 4294967296) ++ u32Bytes (w / 4294967296)

/-- `mix_felts`：`H(digest ‖ Σ QM31 limb 小端字节)`。 -/
def b2MixFelts (felts : List StwoLean.QM31) (st : B2Chan) : B2Chan :=
  (blake2s (st.1 ++ felts.flatMap qm31Bytes), 0)

/-- `mix_u32s`：`H(digest ‖ words 小端)`。 -/
def b2MixU32s (words : List Nat) (st : B2Chan) : B2Chan :=
  (blake2s (st.1 ++ words.flatMap u32Bytes), 0)

/-- `mix_u64` = `mix_u32s(&[value as u32, (value >> 32) as u32])`。 -/
def b2MixU64 (v : Nat) (st : B2Chan) : B2Chan :=
  b2MixU32s [v % 4294967296, v / 4294967296] st

/-- `draw_u32s`：`H(digest ‖ counter_le ‖ 0x00)` 的 8 个 u32。 -/
def b2DrawU32s (st : B2Chan) : List Nat × B2Chan :=
  let ws := blake2sWords (st.1 ++ u32Bytes st.2 ++ [0])
  ((List.range 8).map (ws.getD · 0), (st.1, st.2 + 1))

/-- 字节尾零位数（燃料递归；b < 256）。 -/
def byteTZ : Nat → Nat → Nat
  | _, 0 => 8
  | b, fuel + 1 => if b % 2 == 1 then 0 else 1 + byteTZ (b / 2) fuel

/-- LE 前 16 字节视作 128 位整数的尾零位数（全零 = 128）。 -/
def trailingZerosLE (res : List Nat) (j fuel : Nat) : Nat :=
  if fuel == 0 then 8 * j
  else match res with
    | [] => 128
    | b :: rest => if b == 0 then trailingZerosLE rest (j + 8) fuel else 8 * j + byteTZ b 8

/-- `verify_pow_nonce`：双重哈希后 LE u128 尾零 ≥ n_bits。 -/
def b2VerifyPowNonce (digest : List Nat) (nBits nonce : Nat) : Bool :=
  let prefixed := blake2s (u32Bytes 305419896 ++ List.replicate 12 0
    ++ digest ++ u32Bytes nBits)
  let res := blake2s (prefixed ++ u64Bytes nonce)
  trailingZerosLE (res.take 16) 0 16 >= nBits


/-- `draw_base_felts`（带燃料）：重试 `draw_u32s` 直到 8 词全部 `< 2P`，
再按 `reduce(x) = x - P (x ≥ P)` 归约。每次重试消耗一个计数器。
燃料 8 对任何实际输入都远超所需（单次通过概率 ≈ 1 - 2⁻²⁸）。 -/
def b2DrawBaseFelts : Nat → B2Chan → List StwoLean.M31 × B2Chan
  | 0, st => ([], st)
  | fuel + 1, st =>
    let (ws, st') := b2DrawU32s st
    if ws.all (fun w => w < 4294967294) then
      (ws.map (fun w =>
        (((if w ≥ 2147483647 then w - 2147483647 else w : ℕ) : StwoLean.M31))), st')
    else b2DrawBaseFelts fuel st'

/-- `draw_secure_felt`：一次 `draw_base_felts` 的前 4 个 M31 组成 QM31。 -/
def b2DrawSecureFelt (fuel : Nat) (st : B2Chan) : StwoLean.QM31 × B2Chan :=
  let (ms, st') := b2DrawBaseFelts fuel st
  (⟨⟨ms.getD 0 (0 : StwoLean.M31), ms.getD 1 (0 : StwoLean.M31)⟩,
    ⟨ms.getD 2 (0 : StwoLean.M31), ms.getD 3 (0 : StwoLean.M31)⟩⟩, st')

/-- 初始通道状态（`Blake2sChannel::default()`：digest 为 32 个零字节，
n_draws = 0）。 -/
def ch0 : B2Chan := (List.replicate 32 0, 0)

end Blake2s
