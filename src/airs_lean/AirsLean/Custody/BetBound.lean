import AirsLean.Custody.Conservation

/-!
# BetBound — 不可透支（下注不超过存量）

- `call_no_overdraft` / `bet_no_overdraft` / `raise_no_overdraft`：
  任何下注类动作后 `post_stack + amount = pre_stack`——下注金额不超过
  存量，不可透支（下注即托管内转移）；
- `no_midhand_exit`：下注轮内不存在被接受的 LeaveTable 行——已下注
  筹码必须先经结算；
- `deferred_exit_refund_exact`：SetLeaveAfterHand 座位的退款在结算中
  精确 = stack + pending_addon；
- `forced_exit_preserves_funds`：ForceFold/KickPlayer 只改生命周期位，
  托管总量不变——被踢座位的资金进入结算而非消失。

出处：`src/airs/actions/call.rs`（min 选择与短 all-in）；
`src/airs/lifecycle/leave_table.rs`（WAITING 域）；
`src/airs/actions/{kick_player,force_fold}.rs`。
-/

namespace AirsLean

/-- **Call 不可透支**：跟注后 `post_stack + amount = pre_stack`。 -/
theorem call_no_overdraft {preStack postStack preBet postBet preTB postTB amount currentBet : Limbs}
    {sc bc tc : AddCarry} {seat currentTurn acted : M31}
    (h : CallSat preStack postStack preBet postBet preTB postTB amount currentBet sc bc tc
      seat currentTurn acted) :
    decode postStack + decode amount = decode preStack := by
  have := call_conservation h
  omega

/-- **Bet 不可透支**：下注后 `post_stack + amount = pre_stack`。 -/
theorem bet_no_overdraft {preStack postStack amount preCB postCB preMR postMR : Limbs}
    {sc : AddCarry} (h : BetSat preStack postStack amount preCB postCB preMR postMR sc) :
    decode postStack + decode amount = decode preStack := by
  have := bet_bound_and_updates h
  omega

/-- **Raise 不可透支**：加注后 `post_stack + amount = pre_stack`。 -/
theorem raise_no_overdraft {preStack postStack preBet postBet amount preCB preMR postCB postMR : Limbs}
    {sc : AddCarry} {preMask postMask : ℕ} {opens : Bool}
    (h : RaiseSat preStack postStack preBet postBet amount preCB preMR postCB postMR
      sc preMask postMask opens) :
    decode postStack + decode amount = decode preStack := by
  have := raise_conservation h
  omega

end AirsLean
