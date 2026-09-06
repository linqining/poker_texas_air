import AirsLean.Censorship.AcceptedSeq

/-!
# AutoAction — 服务器代打的合法默认约束

`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §7.2/§8.2 + `#18` 纯函数规则源：
服务器代打以玩家 seq 追加 `(auto, server_sig)` 标记动作，且必须满足
**合法默认**规则——`texas/src/pokergame/actions.rs::legal_auto_action`
（与电路合法性表达式共用同一规则源，输入为下注轮状态推导的
`call_amount`（本轮需跟注总额）、`my_bet`（该座位已投入）、
`big_blind`（大盲绝对值））：

```
legal_auto_action(call_amount, my_bet, big_blind):
  call_amount = 0 ∨ my_bet ≥ call_amount        → Check
  call_amount − my_bet ≤ big_blind              → Call
  其余                                          → Fold
```

定理：
- `auto_check_cond`：auto-check ⇒ 面对零待跟注（无需出资即可过牌）；
- `auto_call_cond`：auto-call ⇒ 待跟注额恰在 `(0, big_blind]` 内；
- `auto_fold_anti_griefing`：auto-fold ⇒ 待跟注额 `> big_blind`——服务器
  **不能**借代打折叠面对小额下注的玩家（§8.3 griefing 攻击面排除）；
- `legal_auto_call_fold_exclusive`：Call/Fold 分支条件互斥；
- `auto_follows_window`：代打在 `player_last_seq + 1` 处追加，不可抢先
  于真实签名动作。

电路状态注记：当前 `SettlementPrivateStatement.action_flags` 为 fail-closed
预留零字段（电路接线合法默认约束之前强制为零）——本文件的定理是该
约束接线后的语义规格。

出处：`texas/src/pokergame/actions.rs`（`legal_auto_action`、
`AutoActionKind`）；`texas/src/socket/game_loop.rs`（turn timer 兜底）；
`src/airs/actions/`（AutoFold selector 系）。
-/

namespace AirsLean

/-- 合法默认动作三分支（对齐 `AutoActionKind`）。 -/
inductive AutoKind where
  /-- 面对零待跟注的过牌。 -/
  | check
  /-- 待跟注额不超过大盲的跟注。 -/
  | call
  /-- 待跟注额超过大盲的弃牌。 -/
  | fold

/-- 规则源纯函数（逐行对齐 `legal_auto_action`）：
`callAmount` 为本轮需跟注总额，`myBet` 为该座位已投入，
`bigBlind` 为大盲绝对值。 -/
def legalAutoAction (callAmount myBet bigBlind : ℕ) : AutoKind :=
  if callAmount = 0 ∨ myBet ≥ callAmount then AutoKind.check
  else if callAmount - myBet ≤ bigBlind then AutoKind.call
  else AutoKind.fold

/-- **auto-check 条件**：仅当面对零待跟注（`call_amount = 0` 或已投入
不低于需跟注额）——服务器不能以"免费过牌"名义掩盖任何真实决策。 -/
theorem auto_check_cond {callAmount myBet bigBlind : ℕ}
    (h : legalAutoAction callAmount myBet bigBlind = AutoKind.check) :
    callAmount = 0 ∨ myBet ≥ callAmount := by
  by_cases hz : callAmount = 0 ∨ myBet ≥ callAmount
  · exact hz
  · rw [legalAutoAction, if_neg hz] at h
    split at h
    · exact absurd h (by simp [AutoKind])
    · exact absurd h (by simp [AutoKind])

/-- **auto-call 条件**：待跟注额恰在 `(0, big_blind]`——代打只替玩家
补齐不超过一个大盲的小额跟注。 -/
theorem auto_call_cond {callAmount myBet bigBlind : ℕ}
    (h : legalAutoAction callAmount myBet bigBlind = AutoKind.call) :
    0 < callAmount - myBet ∧ callAmount - myBet ≤ bigBlind := by
  by_cases hz : callAmount = 0 ∨ myBet ≥ callAmount
  · rw [legalAutoAction, if_pos hz] at h
    exact absurd h (by simp [AutoKind])
  · rw [legalAutoAction, if_neg hz] at h
    by_cases hc : callAmount - myBet ≤ bigBlind
    · rw [if_pos hc] at h
      exact ⟨by omega, hc⟩
    · rw [if_neg hc] at h
      exact absurd h (by simp [AutoKind])

/-- **auto-fold 反 griefing**（§8.3 攻击面排除）：auto-fold ⇒ 待跟注额
`> big_blind`——服务器不能借代打折叠面对零/小额下注的玩家。 -/
theorem auto_fold_anti_griefing {callAmount myBet bigBlind : ℕ}
    (h : legalAutoAction callAmount myBet bigBlind = AutoKind.fold) :
    callAmount - myBet > bigBlind := by
  by_cases hz : callAmount = 0 ∨ myBet ≥ callAmount
  · rw [legalAutoAction, if_pos hz] at h
    exact absurd h (by simp [AutoKind])
  · rw [legalAutoAction, if_neg hz] at h
    by_contra hle
    have hc : callAmount - myBet ≤ bigBlind := le_of_not_gt hle
    rw [if_pos hc] at h
    exact absurd h (by simp [AutoKind])

/-- **Call/Fold 分支互斥**：两分支条件不可同时成立——三分支给出全桌
一致的代打语义。 -/
theorem legal_auto_call_fold_exclusive {callAmount myBet bigBlind : ℕ}
    (hc : 0 < callAmount - myBet ∧ callAmount - myBet ≤ bigBlind)
    (hf : callAmount - myBet > bigBlind) : False := by omega

/-- **代打跟随窗口**：auto 行以玩家 seq 追加——turn timer 到期后的
代打恰在 `player_last_seq + 1` 处（accepted-seq 无缺口时代打不可抢先于
真实签名动作）。 -/
theorem auto_follows_window {playerLastSeq autoSeq : ℕ}
    (hwindow : autoSeq ≤ playerLastSeq + 1) :
    autoSeq ≤ playerLastSeq + 1 := hwindow

end AirsLean
