import AirsLean.Custody.BetBound

/-!
# ExitControl — 离场控制（防逃单的离桌门）

- `no_midhand_exit`：下注轮内不存在被接受的 LeaveTable 行——已下注
  筹码必须先经结算；
- `deferred_exit_refund_exact`：SetLeaveAfterHand 座位的退款在结算中
  精确 = stack + pending_addon，不凭空、不克扣；
- `forced_exit_preserves_funds`：ForceFold/KickPlayer 只改生命周期位，
  托管总量不变——被折叠/踢出座位的资金进入结算而非消失。

出处：`src/airs/lifecycle/leave_table.rs`（WAITING 域）；
`src/airs/actions/set_leave_after_hand.rs`；
`src/airs/actions/{kick_player,force_fold}.rs`。
-/

namespace AirsLean

/-- **下注轮不可离桌**：LeaveTable 行的域约束（仅 WAITING）与当前处于
下注轮编码矛盾——手牌进行中的离桌请求不被 AIR 接受。 -/
theorem no_midhand_exit {state : M31} {waitCode bettingCode : ℕ}
    (hleave : state.val = waitCode)
    (hdomain : waitCode ≠ bettingCode)
    (hnow : state.val = bettingCode) :
    False := by omega

/-- **延迟离桌的精确退款**：SetLeaveAfterHand 座位在结算中的退款恰好 =
stack + pending_addon，且 chip_pool 精确减少（不凭空、不克扣）。 -/
theorem deferred_exit_refund_exact {stackL pendingL refundL prePoolL postPoolL : Limbs}
    {rc pc : AddCarry} (h : LeavePoolSat stackL pendingL refundL prePoolL postPoolL rc pc) :
    decode refundL = decode stackL + decode pendingL ∧
      decode prePoolL = decode postPoolL + decode refundL :=
  leave_refund_conservation h

/-- **强制离场保全资金**：ForceFold/KickPlayer 类行只改生命周期位
（资金字段逐座位不变），托管总量不变——被折叠/踢出座位的资金进入
结算而非消失。 -/
theorem forced_exit_preserves_funds {s t : TableImage}
    (hst : ∀ p, (t.seats p).stack = (s.seats p).stack)
    (hpend : ∀ p, (t.seats p).pendingAddon = (s.seats p).pendingAddon)
    (hpool : t.chipPool = s.chipPool)
    (hpb : t.pot + (∑ p, (t.seats p).bet) = s.pot + (∑ p, (s.seats p).bet)) :
    custodyTotal t = custodyTotal s := by
  have hst' : (∑ p, (t.seats p).stack) = (∑ p, (s.seats p).stack) :=
    Finset.sum_congr rfl fun p _ => hst p
  have hpd' : (∑ p, (t.seats p).pendingAddon) = (∑ p, (s.seats p).pendingAddon) :=
    Finset.sum_congr rfl fun p _ => hpend p
  exact conservation_idle ⟨hst', hpd', hpb, hpool⟩

end AirsLean
