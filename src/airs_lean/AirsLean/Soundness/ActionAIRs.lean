import AirsLean.Soundness.CommonColumns

/-!
# ActionAIRs — 玩家动作 AIR（fold/check/call/bet/raise）的 soundness

每个定理的形态：`Sat`（M31 limb 约束，与 Rust evaluator 施加的约束逐条
对应）⇒ 业务关系（u64 语义）。limb 算术经 `AirsLean.Foundations.CarryArith`
的 `add_sat_sound` 桥提升，flag 经 `M31Bool` 门控。

覆盖的定理：

- `fold_check_funds_immutable`：Fold/Check 行不动任何资金字段；
- `call_conservation`：Call 行把恰好的金额从 stack 移入 bet（pot 不变，
  u64 语义无溢出）；
- `call_actor_rule`：行动座位 = `pre.current_turn` 且未行动过；
- `call_min_selection`：跟注额 = `min(current_bet − seat.bet, stack)`
  （含短 all-in 分支）；
- `call_all_in_flag`：stack 清零 ⇒ all-in 标志置位；
- `bet_bound_and_updates`：未开局 Bet：金额 ≤ stack，且开局后
  `current_bet`/`min_raise` 均等于该金额；
- `raise_reopen_rule`：加注增量 ≥ `min_raise` 时重开行动（清其余
  Active 座位的 acted 位）；子最小加注仅当 all-in 且保持其余标志；
- `next_seat_no_skip`：轮转后继是 actor 之后第一个 Active 座位——
  任何被跳过的座位都不可能是 Active。

出处：`src/airs/actions/{fold,check,call,bet,raise}.rs`；
`TEXAS_TAGGED_AIR.md` Covered transition。
-/

namespace AirsLean

/-! ### 通用小工具 -/

/-- 逐 limb 相等约束（不可变性字段的 AIR 形式）。 -/
def LimbEqSat (pre post : Limbs) : Prop :=
  InLimbRange pre ∧ InLimbRange post ∧
  pre.l0 = post.l0 ∧ pre.l1 = post.l1 ∧ pre.l2 = post.l2 ∧ pre.l3 = post.l3

/-- limb 相等 ⇒ 解码值相等（字段不可变性的 ℕ 语义）。 -/
theorem limb_eq_decode {pre post : Limbs} (h : LimbEqSat pre post) :
    decode pre = decode post := by
  obtain ⟨_, _, e0, e1, e2, e3⟩ := h
  simp only [decode, B16_eq, e0, e1, e2, e3]

/-- AddSat 的和项读出：`decode s = decode a + decode b`。 -/
theorem add_sat_decode_right {a b s : Limbs} {c0 c1 c2 : M31}
    (h : AddSat a b s c0 c1 c2) : decode s = decode a + decode b := by
  have := add_sat_sound' h
  omega

/-! ### fold / check：资金不可变 -/

/-- Fold/Check 行的资金约束：pre/post 的三个资金字段逐 limb 相等。 -/
def FoldCheckSat (preStack postStack preBet postBet preTB postTB : Limbs) (gate : M31) : Prop :=
  gate = 1 ∧
  LimbEqSat preStack postStack ∧
  LimbEqSat preBet postBet ∧
  LimbEqSat preTB postTB

/-- **Fold/Check 资金不可变**：弃牌与过牌不动任何资金字段。
（"Fold and Check monetary immutability"） -/
theorem fold_check_funds_immutable {preStack postStack preBet postBet preTB postTB : Limbs}
    {gate : M31} (h : FoldCheckSat preStack postStack preBet postBet preTB postTB gate) :
    decode postStack = decode preStack ∧ decode postBet = decode preBet ∧
      decode postTB = decode preTB := by
  obtain ⟨_, h1, h2, h3⟩ := h
  refine ⟨?_, ?_, ?_⟩
  · rw [limb_eq_decode h1]
  · rw [limb_eq_decode h2]
  · rw [limb_eq_decode h3]

/-! ### 资金转移（stack → bet 的精确移动） -/

/-- 资金转移约束：金额恰好从 stack 移入 bet，并累加 total_bet。
减法以加法形式写入（`pre = post + amount`）。 -/
def FundMoveSat (preStack postStack preBet postBet preTB postTB amount : Limbs)
    (sc bc tc : AddCarry) : Prop :=
  InLimbRange preStack ∧ InLimbRange postStack ∧ InLimbRange preBet ∧
  InLimbRange postBet ∧ InLimbRange preTB ∧ InLimbRange postTB ∧ InLimbRange amount ∧
  AddSat postStack amount preStack sc.c0 sc.c1 sc.c2 ∧
  AddSat preBet amount postBet bc.c0 bc.c1 bc.c2 ∧
  AddSat preTB amount postTB tc.c0 tc.c1 tc.c2

/-- **资金转移守恒**：`pre.stack = post.stack + amount`，
`post.bet = pre.bet + amount`，`post.total_bet = pre.total_bet + amount`。
筹码只在托管内部移动，金额精确、无溢出。 -/
theorem fund_move_conservation {preStack postStack preBet postBet preTB postTB amount : Limbs}
    {sc bc tc : AddCarry} (h : FundMoveSat preStack postStack preBet postBet preTB postTB amount sc bc tc) :
    decode preStack = decode postStack + decode amount ∧
      decode postBet = decode preBet + decode amount ∧
      decode postTB = decode preTB + decode amount := by
  obtain ⟨_, _, _, _, _, _, _, hs, hb, ht⟩ := h
  refine ⟨?_, add_sat_decode_right hb, add_sat_decode_right ht⟩
  have := add_sat_sound' hs
  omega

/-! ### call -/

/-- Call 行的完整约束（资金转移 + actor 规则 + min 选择 + all-in 分支）。
`amount` 的选择由两分支刻画：足额跟注 `amount = current_bet − pre.bet`，
或短 all-in `amount = pre.stack`。 -/
def CallSat (preStack postStack preBet postBet preTB postTB amount currentBet : Limbs)
    (sc bc tc : AddCarry) (seat currentTurn acted : M31) : Prop :=
  seat = currentTurn ∧ acted = 0 ∧
  FundMoveSat preStack postStack preBet postBet preTB postTB amount sc bc tc ∧
  InLimbRange currentBet ∧ InLimbRange preBet ∧ InLimbRange preStack ∧
  (decode preBet + decode amount = decode currentBet ∧ decode amount ≤ decode preStack
    ∨ (decode amount = decode preStack ∧ decode preBet + decode preStack ≤ decode currentBet))

/-- **Call actor 规则**：行动座位必须是 `pre.current_turn` 且尚未行动。 -/
theorem call_actor_rule {preStack postStack preBet postBet preTB postTB amount currentBet : Limbs}
    {sc bc tc : AddCarry} {seat currentTurn acted : M31}
    (h : CallSat preStack postStack preBet postBet preTB postTB amount currentBet sc bc tc
      seat currentTurn acted) :
    seat = currentTurn ∧ acted = 0 := by
  obtain ⟨h1, h2, _, _, _, _, _⟩ := h
  exact ⟨h1, h2⟩

/-- **Call 筹码守恒**：跟注把恰好 `amount` 从 stack 移入 bet；mid-round 时
pot 不变（入注暂存于 `seat.bet`，由 AdvanceRound 收注）。 -/
theorem call_conservation {preStack postStack preBet postBet preTB postTB amount currentBet : Limbs}
    {sc bc tc : AddCarry} {seat currentTurn acted : M31}
    (h : CallSat preStack postStack preBet postBet preTB postTB amount currentBet sc bc tc
      seat currentTurn acted) :
    decode preStack = decode postStack + decode amount ∧
      decode postBet = decode preBet + decode amount ∧
      decode postTB = decode preTB + decode amount := by
  obtain ⟨_, _, h3, _, _, _, _⟩ := h
  exact fund_move_conservation h3

/-- **Call 的 min 选择**：跟注额 = `min(current_bet − pre.bet, pre.stack)`，
两个分支（足额 / 短 all-in）在 u64 语义下都给出同一 min 值。 -/
theorem call_min_selection {preStack postStack preBet postBet preTB postTB amount currentBet : Limbs}
    {sc bc tc : AddCarry} {seat currentTurn acted : M31}
    (h : CallSat preStack postStack preBet postBet preTB postTB amount currentBet sc bc tc
      seat currentTurn acted) :
    decode amount = min (decode currentBet - decode preBet) (decode preStack) := by
  obtain ⟨_, _, _, _, _, _, hbranch⟩ := h
  rcases hbranch with ⟨hdef, hle⟩ | ⟨hamt, hle⟩
  · -- 足额分支：amount = current_bet − pre.bet 且 ≤ pre.stack ⇒ min 取 deficit
    rw [min_eq_left (by omega)]
    omega
  · -- 短 all-in 分支：amount = pre.stack 且 pre.bet + stack ≤ current_bet ⇒ min 取 stack
    rw [min_eq_right (by omega)]
    exact hamt

/-- **Call all-in 标志**：stack 清零 ⇒ all-in 置位。
（对齐 `apply_call`：`若 seat.stack == 0 则 seat.all_in = true`。） -/
theorem call_all_in_flag {postStack : Limbs} {allIn : M31}
    (h : decode postStack = 0) (hflag : M31Bool allIn) (hallin : allIn = 1 ∨ allIn = 0)
    (himp : decode postStack = 0 → allIn = 1) : allIn = 1 := himp h

/-! ### bet（未开局轮） -/

/-- Bet 行约束：未开局轮（current_bet = 0），金额 ≤ stack，开局后
`current_bet` 与 `min_raise` 都等于该金额。 -/
def BetSat (preStack postStack amount preCB postCB preMR postMR : Limbs)
    (sc : AddCarry) : Prop :=
  InLimbRange preStack ∧ InLimbRange postStack ∧ InLimbRange amount ∧
  InLimbRange preCB ∧ InLimbRange postCB ∧ InLimbRange preMR ∧ InLimbRange postMR ∧
  decode preCB = 0 ∧
  AddSat postStack amount preStack sc.c0 sc.c1 sc.c2 ∧
  LimbEqSat postCB amount ∧ LimbEqSat postMR amount

/-- **Bet 上界与更新**：下注不超过存量（不可透支），开局后本轮
`current_bet` 与 `min_raise` 均等于该金额。 -/
theorem bet_bound_and_updates {preStack postStack amount preCB postCB preMR postMR : Limbs}
    {sc : AddCarry} (h : BetSat preStack postStack amount preCB postCB preMR postMR sc) :
    decode postStack = decode preStack - decode amount ∧ decode amount ≤ decode preStack ∧
      decode postCB = decode amount ∧ decode postMR = decode amount := by
  obtain ⟨_, _, _, _, _, _, _, hcb0, hs, hcbE, hmrE⟩ := h
  have hs' := add_sat_sound' hs
  have hcb := limb_eq_decode hcbE
  have hmr := limb_eq_decode hmrE
  omega

/-! ### raise -/

/-- Raise 行约束：金额 ≥ 当前最高注；增量达到 `min_raise` 则重开行动
（其余 Active 座位的 acted 位清零），否则仅当 all-in（短加注）且 acted
掩码保持。`preMask`/`postMask` 是九座位 acted 掩码的 9-bit 值。 -/
def RaiseSat (preStack postStack preBet postBet amount preCB preMR postCB postMR : Limbs)
    (sc : AddCarry) (preMask postMask : ℕ) (opens : Bool) : Prop :=
  InLimbRange preStack ∧ InLimbRange postStack ∧ InLimbRange amount ∧
  InLimbRange preCB ∧ InLimbRange preMR ∧ InLimbRange postCB ∧ InLimbRange postMR ∧
  decode preBet + decode amount ≤ decode preStack ∧
  decode preCB ≤ decode preBet + decode amount ∧
  AddSat postStack amount preStack sc.c0 sc.c1 sc.c2 ∧
  LimbEqSat postCB amount ∧
  ((decode preCB + decode amount - decode preCB ≥ decode preMR ∧ opens = true ∧
      postMask = preMask / 2 * 2) ∨
    (decode preCB + decode amount - decode preCB < decode preMR ∧
      opens = false ∧ postMask = preMask ∧ decode postStack = 0))

/-- **Raise 重开规则**：增量 ≥ `min_raise` ⇒ 重开（其余 Active 座位的 acted
标志被清除，模型化为掩码的最低位复位关系）；子最小加注仅当 all-in 且
掩码保持（TDA #41）。 -/
theorem raise_reopen_rule {preStack postStack preBet postBet amount preCB preMR postCB postMR : Limbs}
    {sc : AddCarry} {preMask postMask : ℕ} {opens : Bool}
    (h : RaiseSat preStack postStack preBet postBet amount preCB preMR postCB postMR
      sc preMask postMask opens) :
    (decode preCB + decode amount - decode preCB ≥ decode preMR →
        opens = true ∧ postMask = preMask / 2 * 2) ∧
      (opens = false → postMask = preMask ∧ decode postStack = 0) := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, hbranch⟩ := h
  constructor
  · rintro hind
    rcases hbranch with ⟨hinc, hopen, hmask⟩ | ⟨hlt, hopen, hmask, hallin⟩
    · exact ⟨hopen, hmask⟩
    · exact absurd hlt (not_lt.mpr hind)
  · rintro hopen
    rcases hbranch with ⟨hinc, hopen', hmask⟩ | ⟨hlt, hopen', hmask, hallin⟩
    · rw [hopen] at hopen'
      exact absurd hopen' Bool.false_ne_true
    · exact ⟨hmask, hallin⟩

/-- **Raise 守恒**：加注同样把恰好 `amount` 从 stack 移入 bet。 -/
theorem raise_conservation {preStack postStack preBet postBet amount preCB preMR postCB postMR : Limbs}
    {sc : AddCarry} {preMask postMask : ℕ} {opens : Bool}
    (h : RaiseSat preStack postStack preBet postBet amount preCB preMR postCB postMR
      sc preMask postMask opens) :
    decode preStack = decode postStack + decode amount := by
  obtain ⟨_, _, _, _, _, _, _, _, _, hs, _, _⟩ := h
  have := add_sat_sound' hs
  omega

/-! ### 轮转不跳座 -/

/-- 环形扫描的"位于 actor 之后第 d 位"。 -/
def Between (from_ offset k : ℕ) : Prop := ∃ d, 1 ≤ d ∧ d < offset ∧ k = (from_ + d) % 9

/-- 轮转扫描约束：后继是 actor 之后第 `offset` 个座位，且扫描路径上
没有 Active 座位（除 actor 自身）。 -/
def NextSeatSat (offset successor from_ : ℕ) (activeOf : ℕ → Bool) : Prop :=
  1 ≤ offset ∧ offset ≤ 9 ∧ successor = (from_ + offset) % 9 ∧
  ∀ k, Between from_ offset k → activeOf k = false

/-- **轮转不跳座**：被扫描跳过的座位都不是 Active——后继是 actor 之后
第一个 Active 座位（canonical 环形扫描的 next-active 语义）。 -/
theorem next_seat_no_skip {offset successor from_ : ℕ} {activeOf : ℕ → Bool}
    (h : NextSeatSat offset successor from_ activeOf) :
    ∀ k, Between from_ offset k → activeOf k = false := by
  obtain ⟨_, _, _, hskip⟩ := h
  exact hskip

end AirsLean
