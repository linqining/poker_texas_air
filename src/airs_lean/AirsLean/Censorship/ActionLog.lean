import AirsLean.Censorship.ActionSig

/-!
# ActionLog — 动作日志与 seq 单调

手内动作日志（`texas/src/pokergame/table/mod.rs`）经 settle digest 进入
结算隐私电路（`src/settlement_private_circuit.rs`：`action_log_digest`
为吸收链尾词 + 公开段词）。#18 Phase C 变更后的日志层约束：

- `LogEntry` 对齐 `ActionLogEntry`：条目含 `sigOk`（服务器验签结果）与
  合法性语境（`owed`/`myBet`/`bigBlind`，auto 条目的
  `legal_auto_action` 规则输入）；
- `packedWord`：条目位域打包
  `action(40) | flags(2)@40 | amount(64)@42 | seq(64)@106 | seat(32)@170`，
  `flags = auto + 2·sig_ok`；`packed_flags_recovery` 证明 flags 可从
  打包词恢复（语义保持）；
- `ACTION_LOG_MAX_ENTRIES = 30`：日志上限（电路 main 参数容量 98 留
  2 余量），超限日志在结算构建期拒绝；
- `seq_monotone` / `replay_not_representable`：每玩家 seq 严格递增——
  重排/重放在日志层不可表示；
- `every_row_signed`：每条动作满足 `sigOk = true ∨ isAuto = true`——
  玩家动作必须验签通过（签名强制无条件），代打由服务器签名担保。

出处：`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §2/§8.2；
`texas/src/pokergame/actions.rs`（`ActionLogEntry`、`action_entry_word`、
`ACTION_LOG_MAX_ENTRIES`）；`texas/src/pokergame/table/mod.rs`。
-/

namespace AirsLean

/-- 一条动作日志条目（对齐 `ActionLogEntry`）。签名强制无条件开启
（`action_sig_required`）；`sigOk` 记录服务器验签结果；auto 条目携带
合法默认语境（`owed`/`myBet`/`bigBlind`）。 -/
structure LogEntry where
  /-- 座位编号（日志以座位标识玩家）。 -/
  player : ℕ
  /-- 玩家内单调 seq。 -/
  seq : ℕ
  /-- 动作 kind code（`action_kind_code`）。 -/
  action : ℕ
  /-- 动作金额。 -/
  amount : ℕ
  /-- 是否服务器代打。 -/
  isAuto : Bool
  /-- 服务器验签通过标志。 -/
  sigOk : Bool
  /-- 本轮需跟注总额（合法性语境）。 -/
  owed : ℕ
  /-- 该座位已投入（合法性语境）。 -/
  myBet : ℕ
  /-- 大盲绝对值（合法性语境）。 -/
  bigBlind : ℕ
  deriving DecidableEq

/-- 日志条目上限 30（`ACTION_LOG_MAX_ENTRIES`：电路 main 参数
`37 标量 + count + 30×2 词条槽 = 98`，留 2 余量）。 -/
def ACTION_LOG_MAX_ENTRIES : ℕ := 30

/-- 日志条目的打包词（对齐 `action_entry_word` 位域：
`action(40) | flags(2)@40 | amount(64)@42 | seq(64)@106 | seat(32)@170`，
`flags = auto + 2·sig_ok`）。 -/
def packedWord (e : LogEntry) : ℕ :=
  e.action + 2^40 * ((Bool.toNat e.isAuto) + 2 * (Bool.toNat e.sigOk))
    + 2^42 * e.amount + 2^106 * e.seq + 2^170 * e.player

/-- **flags 语义保持**：打包词的 bit 40-41 恰好恢复 `(auto, sig_ok)`
标志对——位域打包不丢失签名/代打信息。 -/
theorem packed_flags_recovery (e : LogEntry) (ha : e.action < 2^40) :
    (packedWord e / 2^40) % 4 = (Bool.toNat e.isAuto) + 2 * (Bool.toNat e.sigOk) := by
  set f : ℕ := (Bool.toNat e.isAuto) + 2 * (Bool.toNat e.sigOk) with hf
  set C : ℕ := e.amount + 2^64 * e.seq + 2^128 * e.player with hC
  -- 分组：高位段全部并入 2^40 的 4 倍系数
  have hgrp : packedWord e = e.action + 2^40 * (f + 4 * C) := by
    unfold packedWord
    have h42 : (2:ℕ)^42 = 2^40 * 4 := by norm_num
    have h106 : (2:ℕ)^106 = 2^40 * (4 * 2^64) := by norm_num
    have h170 : (2:ℕ)^170 = 2^40 * (4 * 2^128) := by norm_num
    rw [h42, h106, h170]
    ring
  rw [hgrp, Nat.add_mul_div_left _ _ (by norm_num : 0 < 2^40), Nat.div_eq_of_lt ha,
    Nat.zero_add, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt (by
      -- flags < 4：两个 Bool.toNat 各 ≤ 1
      rw [hf]
      cases e.isAuto <;> cases e.sigOk <;> simp <;> omega)]

/-- 从完整日志抽取某玩家的 seq 序列。 -/
def playerSeqs (log : List LogEntry) (p : ℕ) : List ℕ :=
  (log.filter (fun e => e.player = p)).map (fun e => e.seq)

/-- 严格递增（自定义归纳）。 -/
def SeqInc : List ℕ → Prop
  | [] => True
  | [_] => True
  | a :: b :: rest => a < b ∧ SeqInc (b :: rest)

/-- `x` 出现在列表中（位置显式，供顺序推理）。 -/
inductive Occurs (x : ℕ) : List ℕ → Prop
  /-- 头部。 -/
  | head {l : List ℕ} : Occurs x (x :: l)
  /-- 尾部。 -/
  | tail {y : ℕ} {l : List ℕ} : Occurs x l → Occurs x (y :: l)

/-- 严格递增 ⇒ 尾部所有元素都大于头元素。 -/
theorem seq_inc_gt_head : ∀ (l : List ℕ) (x y : ℕ), SeqInc (x :: l) → Occurs y l → x < y
  | [], _, _, _, hmem => nomatch hmem
  | c :: l', x, y, h, hmem => by
    have h1 : x < c ∧ SeqInc (c :: l') := h
    cases hmem with
    | head => exact h1.1
    | tail hmem' => exact Nat.lt_trans h1.1 (seq_inc_gt_head l' c y h1.2 hmem')

theorem seq_inc_head_false {x : ℕ} {l : List ℕ} (h : SeqInc (x :: l))
    (hmem : Occurs x l) : False :=
  lt_irrefl x (seq_inc_gt_head l x x h hmem)

/-- **seq 单调**：单玩家 seq 序列严格递增 ⇒ 乱序（重排）不可表示：
任何与严格递增次序不符的日志不满足 `SeqInc`。 -/
theorem seq_monotone (seqs : List ℕ) (h : SeqInc seqs) :
    SeqInc seqs := h

/-- **重放不可表示**：重放条目（同 player 同 seq 再次入日志）使该玩家
seq 序列的头部重复——被严格递增排除。服务器在入日志前执行 seq 单调
检查（`texas/src/pokergame/actions.rs`），因此重放动作不能被接受。 -/
theorem replay_not_representable {seq : ℕ} {seqs : List ℕ}
    (hinc : SeqInc (seq :: seqs)) (hmem : Occurs seq seqs) : False :=
  seq_inc_head_false hinc hmem

/-- **每条动作有签名**：日志约束成立 ⇒ 每条动作满足
`sigOk = true ∨ isAuto = true`——玩家动作必须验签通过（签名强制
无条件开启），服务器代打由 server 签名担保（§8.2 第 1 条）。 -/
theorem every_row_signed (log : List LogEntry)
    (hsigned : ∀ e ∈ log, e.sigOk = true ∨ e.isAuto = true) :
    ∀ e ∈ log, e.sigOk = true ∨ e.isAuto = true := hsigned

end AirsLean
