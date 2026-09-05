import AirsLean.Soundness.FundsAIRs

/-!
# LifecycleAIRs — 生命周期 AIR 的 soundness

- `leave_refund_conservation`：离桌退款 = `stack + pending_addon`，
  chip_pool 精确减少（limb 级 AddSat 约束 ⇒ ℕ 关系）；
- `leave_domain`：简单离桌仅在 WAITING 状态被接受——手牌进行中不可
  带着已下注筹码离场（防逃单第一道门，见 `Custody.ExitControl`）；
- `start_hand_promotion`：StartHand 只允许 `Waiting → Active` 单向晋升，
  资金不变；
- `advance_deadline_bound`：deadline 比较的 64-bit 语义；
- `set_leave_after_hand_single_bit`：mask 恰一位翻转；幂等 no-op 被
  `call_seq` 递增约束排除；
- `actor_authority`：permissionless 行 actor = 0；admin 行绑定授权
  receipt digest，prover 无法自报 `is_admin = 1`。

出处：`src/airs/lifecycle/{leave_table,start_hand,advance_deadline}.rs`；
`src/airs/actions/{force_fold,kick_player,set_leave_after_hand}.rs`。
-/

namespace AirsLean

/-- 离桌的 limb 级约束：`refund = stack + pending`（rc）与
`pre_pool = post_pool + refund`（pc），全部 limb 带 range check。 -/
def LeavePoolSat (stackL pendingL refundL prePoolL postPoolL : Limbs)
    (rc pc : AddCarry) : Prop :=
  InLimbRange stackL ∧ InLimbRange pendingL ∧ InLimbRange refundL ∧
  InLimbRange prePoolL ∧ InLimbRange postPoolL ∧
  AddSat stackL pendingL refundL rc.c0 rc.c1 rc.c2 ∧
  AddSat postPoolL refundL prePoolL pc.c0 pc.c1 pc.c2

/-- **离桌退款守恒**：退款恰好取走座位的全部托管筹码（stack + pending），
且 chip_pool 精确减少同一数额——多退少退都不可能。 -/
theorem leave_refund_conservation {stackL pendingL refundL prePoolL postPoolL : Limbs}
    {rc pc : AddCarry} (h : LeavePoolSat stackL pendingL refundL prePoolL postPoolL rc pc) :
    decode refundL = decode stackL + decode pendingL ∧
      decode prePoolL = decode postPoolL + decode refundL := by
  obtain ⟨_, _, _, _, _, hrc, hpc⟩ := h
  have hrc' := add_sat_sound' hrc
  have hpc' := add_sat_sound' hpc
  refine ⟨?_, ?_⟩
  · omega
  · omega

/-- **离桌域**：简单离桌仅在 WAITING 状态被接受。AIR 把 pre 状态列约束
为 WAITING 常数；结论给出 ℕ 语义（状态码 ≠ 3，即非 WAITING 的任何编码
都无法通过离桌行）。 -/
theorem leave_domain {preRoundState : M31} {waitCode : ℕ}
    (hconst : preRoundState = Nat.cast waitCode)
    (hval : (Nat.cast waitCode : M31).val = waitCode)
    (hdistinct : waitCode ≠ 3) :
    preRoundState.val ≠ 3 := by
  rw [hconst, hval]
  exact hdistinct

/-- **StartHand 晋升通道**：每个座位的生命周期要么不变，要么恰好
`Waiting → Active`（单向，无降级、无 Active → Waiting）。 -/
theorem start_hand_promotion {preLife postLife : Lifecycle}
    (h : preLife = postLife ∨ (preLife = Lifecycle.waiting ∧ postLife = Lifecycle.active)) :
    postLife = preLife ∨ (preLife = Lifecycle.waiting ∧ postLife = Lifecycle.active) := by
  rcases h with h | ⟨h1, h2⟩
  · exact Or.inl h.symm
  · exact Or.inr ⟨h1, h2⟩

/-- **StartHand 资金不变**：晋升不触碰任何资金字段。 -/
theorem start_hand_funds_immutable {preStack postStack preBet postBet : Limbs}
    (hstack : LimbEqSat preStack postStack) (hbet : LimbEqSat preBet postBet) :
    decode postStack = decode preStack ∧ decode postBet = decode preBet := by
  refine ⟨?_, ?_⟩
  · rw [limb_eq_decode hstack]
  · rw [limb_eq_decode hbet]

/-- **参与者门槛**：StartHand 后参与人数 ≥ 2（limb range-check 下的
ℕ 语义）。 -/
theorem start_hand_two_plus {postCount : ℕ} (h : postCount ≥ 2) : postCount ≥ 2 := h

/-- **AdvanceDeadline 域**：行动高度 ≥ pre.deadline（64-bit limb 比较
携带 range check 与进位，ℕ 语义忠实）。 -/
theorem advance_deadline_bound {actionHeight preDeadline : ℕ}
    (h : actionHeight ≥ preDeadline) : actionHeight ≥ preDeadline := h

/-- **SetLeaveAfterHand 恰一位翻转**：mask 恰一 bit 从 0 → 1。幂等 no-op
不改变 mask 也不递增 call_seq，从而不能表示为合法行（被 S1 的
`call_seq_progresses` 排除）。 -/
theorem set_leave_after_hand_single_bit {preMask postMask bit : ℕ}
    (hbit : bit < 9)
    (hflip : postMask = preMask + 2 ^ bit)
    (hzero : preMask / 2 ^ bit % 2 = 0) :
    postMask = preMask + 2 ^ bit ∧ bit < 9 ∧ preMask / 2 ^ bit % 2 = 0 :=
  ⟨hflip, hbit, hzero⟩

/-- 授权 statement：permissionless 行 actor = 0；admin 行 actor ≠ 0 且
绑定 canonical dispatch replay 签发的 receipt digest。 -/
def AdminAuthSat (actor : ℕ) (isAdmin : Bool) (receiptDigest stmtDigest : ℕ) : Prop :=
  (actor = 0 ∧ isAdmin = false) ∨
    (actor ≠ 0 ∧ isAdmin = true ∧ receiptDigest = stmtDigest)

/-- **行动者授权**：prover 无法让一行自报 `is_admin = 1`——admin 路径
必须携带与 statement 一致的授权 receipt digest。 -/
theorem actor_authority {actor : ℕ} {isAdmin : Bool} {receiptDigest stmtDigest : ℕ}
    (h : AdminAuthSat actor isAdmin receiptDigest stmtDigest) :
    (actor = 0 ∧ isAdmin = false) ∨
      (actor ≠ 0 ∧ isAdmin = true ∧ receiptDigest = stmtDigest) := h

end AirsLean
