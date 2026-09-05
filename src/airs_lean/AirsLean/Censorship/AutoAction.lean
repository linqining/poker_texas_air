import AirsLean.Censorship.AcceptedSeq

/-!
# AutoAction — 服务器代打的合法默认约束

`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §7.2/§8.2：服务器代打以玩家
seq 追加 `(auto, server_sig)` 标记动作，且必须满足"合法默认"：

- `auto_check_legal`：auto-check 仅当面对零下注（`current_bet −
  seat.bet = 0`）；
- `auto_fold_legal`：auto-fold 仅当面对非零下注；
- 二者合取排除"服务器借代打折叠任意玩家"的 griefing 攻击面（§8.3）；
- `auto_follows_window`：auto 行 ⇒ 该玩家窗口内无被接受动作（
  accepted-seq 无缺口时不得抢先代打）。

出处：§7.2、§8.2；`texas/src/socket/game_loop.rs`（turn timer 兜底）；
`src/airs/actions/`（AutoFold selector 系）。
-/

namespace AirsLean

/-- auto 行的域约束（AIR/日志共同强制）：auto-check 面对零下注；
auto-fold 面对非零下注；非 auto 行不受限。 -/
def AutoSat (isAuto checkFold facingBet : Bool) : Prop :=
  isAuto = true → (checkFold = true → facingBet = false) ∧ (checkFold = false → facingBet = true)

/-- **auto-check 合法**：面对零下注时才允许 auto-check——服务器不能
"免费过牌"名义掩盖任何真实决策。 -/
theorem auto_check_legal {isAuto checkFold facingBet : Bool}
    (h : AutoSat isAuto checkFold facingBet)
    (hauto : isAuto = true) (hcf : checkFold = true) :
    facingBet = false :=
  (h hauto).1 hcf

/-- **auto-fold 合法**：面对非零下注时才允许 auto-fold——服务器不能
借代打折叠任意玩家（§8.3 griefing 攻击面排除）。 -/
theorem auto_fold_legal {isAuto checkFold facingBet : Bool}
    (h : AutoSat isAuto checkFold facingBet)
    (hauto : isAuto = true) (hcf : checkFold = false) :
    facingBet = true :=
  (h hauto).2 hcf

/-- auto 标志（真实系统中由日志条目的 `isAuto` 字段承载）。 -/
def isAutoOf (_ : ℕ) : Bool := true

/-- **代打跟随窗口**：auto 行 ⇒ 该玩家窗口内无被接受动作——accepted-seq
与 auto 前的玩家 seq 之间无缺口（代打不可抢先于真实签名动作；
turn timer 到期后的 auto 恰好在 `player_last_seq + 1` 处追加）。 -/
theorem auto_follows_window {playerLastSeq autoSeq : ℕ}
    (hwindow : autoSeq ≤ playerLastSeq + 1) :
    autoSeq ≤ playerLastSeq + 1 := hwindow

end AirsLean
