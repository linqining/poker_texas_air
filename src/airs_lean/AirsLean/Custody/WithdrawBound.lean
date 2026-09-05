import AirsLean.Custody.ExitControl

/-!
# WithdrawBound — 提款上界（逃单否定定理）

对固定玩家跟踪台账 `{dep, paid, merged, awards}`（累计存入、累计提走、
累计被收注、累计奖金），覆盖整局中被 AIR 接受的步骤：

- 存入（join/rebuy/addon，S3）：`dep += amount`；
- 奖金（settlement award，S5）：`awards += amount`；
- 收注（advanceRound）：`merged += amount`（bet → pot，对玩家不可逆）；
- 提走（leave 退款 / 结算支付，S4 的精确退款约束）：`paid += amount`，
  且合法性要求 `amount + paid + merged ≤ dep + awards`（提走不超过
  全部在桌权益）；
- 内部移动（call/bet/raise/fold/check）：台账不变。

不变量 `paid + merged ≤ dep + awards` 归纳保持；`merged ≥ 0` 给出：

- `withdraw_le_deposits_plus_awards`：累计提走 ≤ 累计存入 + 累计奖金
  ——用户逃单（提走超过应得）被排除；
- `vault_solvency`：全桌合计 `Σ paid ≤ Σ dep + Σ awards`——运营商
  跑路的最大损失有界（ACTION_SIGNING §7.3 的形式化基础）。

出处：Custody.Conservation（全局守恒）、S3（资金精确增量）、
S4（退款精确）、S5（奖金 ≤ 奖池）。
-/

namespace AirsLean

/-- 固定玩家视角的一步转移。 -/
inductive PStep
  /-- 非资金转移（fold/check/内部移动/force_fold/kick）。 -/
  | idle
  /-- 存入（join/rebuy/addon）。 -/
  | funding : ℕ → PStep
  /-- 奖金（settlement award）。 -/
  | award : ℕ → PStep
  /-- 收注（advanceRound）：bet 并入共享 pot。 -/
  | merge : ℕ → PStep
  /-- 提走（leave 退款 / 结算支付）。 -/
  | payout : ℕ → PStep

/-- 玩家台账。 -/
structure PLedger where
  /-- 累计存入。 -/
  dep : ℕ
  /-- 累计提走。 -/
  paid : ℕ
  /-- 累计被收注（不可逆并入底池）。 -/
  merged : ℕ
  /-- 累计奖金。 -/
  awards : ℕ

/-- 台账更新。 -/
def ledgerStep : PStep → PLedger → PLedger
  | .idle, g => g
  | .funding amt, g => ⟨g.dep + amt, g.paid, g.merged, g.awards⟩
  | .award amt, g => ⟨g.dep, g.paid, g.merged, g.awards + amt⟩
  | .merge amt, g => ⟨g.dep, g.paid, g.merged + amt, g.awards⟩
  | .payout amt, g => ⟨g.dep, g.paid + amt, g.merged, g.awards⟩

/-- 步骤合法性：提走/收注不超过玩家的全部在桌权益。 -/
def StepOk : PStep → PLedger → Prop
  | .idle, _ => True
  | .funding _, _ => True
  | .award _, _ => True
  | .merge amt, g => amt + g.paid + g.merged ≤ g.dep + g.awards
  | .payout amt, g => amt + g.paid + g.merged ≤ g.dep + g.awards

/-- 台账链：每一步对其起点台账合法。 -/
def ChainOk : List PStep → PLedger → Prop
  | [], _ => True
  | k :: rest, g => StepOk k g ∧ ChainOk rest (ledgerStep k g)

/-- 逐步执行后的台账。 -/
def chainLedger : List PStep → PLedger → PLedger
  | [], g => g
  | k :: rest, g => chainLedger rest (ledgerStep k g)

/-- 台账不变量。 -/
def Inv (g : PLedger) : Prop := g.paid + g.merged ≤ g.dep + g.awards

/-- **不变量单步保持**。 -/
theorem inv_preserved (k : PStep) (g : PLedger) (hok : StepOk k g) (hinv : Inv g) :
    Inv (ledgerStep k g) := by
  cases k with
  | idle => exact hinv
  | funding amt =>
    obtain ⟨dep, paid, merged, awards⟩ := g
    have h' : paid + merged ≤ dep + awards := hinv
    show paid + merged ≤ dep + amt + awards
    omega
  | award amt =>
    obtain ⟨dep, paid, merged, awards⟩ := g
    have h' : paid + merged ≤ dep + awards := hinv
    show paid + merged ≤ dep + (awards + amt)
    omega
  | merge amt =>
    obtain ⟨dep, paid, merged, awards⟩ := g
    have hok' : amt + paid + merged ≤ dep + awards := hok
    have h' : paid + merged ≤ dep + awards := hinv
    show paid + (merged + amt) ≤ dep + awards
    omega
  | payout amt =>
    obtain ⟨dep, paid, merged, awards⟩ := g
    have hok' : amt + paid + merged ≤ dep + awards := hok
    have h' : paid + merged ≤ dep + awards := hinv
    show (paid + amt) + merged ≤ dep + awards
    omega

/-- **不变量全程保持**。 -/
theorem chain_inv (steps : List PStep) (g : PLedger) (h : ChainOk steps g) (hinv : Inv g) :
    Inv (chainLedger steps g) := by
  induction steps generalizing g with
  | nil => simpa [chainLedger] using hinv
  | cons k rest ih =>
    obtain ⟨hok, hrest⟩ := h
    have hmid : Inv (ledgerStep k g) := inv_preserved k g hok hinv
    simpa [chainLedger] using ih (ledgerStep k g) hrest hmid

/-- **提款上界**（逃单否定定理）：整局结束后，玩家累计提走 ≤ 累计存入 +
累计奖金。所有提走都由 AIR 的精确退款/结算约束锁定，无法透支、无法
重复领取。 -/
theorem withdraw_le_aux (g : PLedger) (hinv : Inv g) :
    g.paid ≤ g.dep + g.awards := by
  obtain ⟨dep, paid, merged, awards⟩ := g
  unfold Inv at hinv
  omega

/-- **提款上界**（逃单否定定理）：整局结束后，玩家累计提走 ≤ 累计存入 +
累计奖金。所有提走都由 AIR 的精确退款/结算约束锁定，无法透支、无法
重复领取。 -/
theorem withdraw_le_deposits_plus_awards (steps : List PStep)
    (h : ChainOk steps (⟨0, 0, 0, 0⟩ : PLedger)) :
    (chainLedger steps (⟨0, 0, 0, 0⟩ : PLedger)).paid
      ≤ (chainLedger steps (⟨0, 0, 0, 0⟩ : PLedger)).dep
        + (chainLedger steps (⟨0, 0, 0, 0⟩ : PLedger)).awards := by
  have hinv : Inv (chainLedger steps (⟨0, 0, 0, 0⟩ : PLedger)) :=
    chain_inv steps (⟨0, 0, 0, 0⟩ : PLedger) h (by unfold Inv; norm_num)
  exact withdraw_le_aux _ hinv

/-- **金库偿付能力**：全桌合计提走 ≤ 合计存入 + 合计奖金——任何时刻
运营商的应付义务不超过玩家投入加奖池分配，跑路损失有界。 -/
theorem vault_solvency (chains : Fin 9 → List PStep)
    (hok : ∀ p, ChainOk (chains p) (⟨0, 0, 0, 0⟩ : PLedger)) :
    (∑ p, (chainLedger (chains p) (⟨0, 0, 0, 0⟩ : PLedger)).paid)
      ≤ (∑ p, (chainLedger (chains p) (⟨0, 0, 0, 0⟩ : PLedger)).dep)
        + (∑ p, (chainLedger (chains p) (⟨0, 0, 0, 0⟩ : PLedger)).awards) := by
  rw [← Finset.sum_add_distrib]
  exact Finset.sum_le_sum fun p _ =>
    withdraw_le_aux _
      (chain_inv (chains p) (⟨0, 0, 0, 0⟩ : PLedger) (hok p)
        (by unfold Inv; norm_num))

end AirsLean
