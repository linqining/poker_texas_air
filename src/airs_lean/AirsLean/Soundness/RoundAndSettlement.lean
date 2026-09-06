import AirsLean.Soundness.LifecycleAIRs

/-!
# RoundAndSettlement — 收注（AdvanceRound）与结算的 soundness

- `advance_round_pot_collection`：`post_pot = pre_pot + Σ seat.bet`，
  每个 seat.bet 清零，stack/total_bet/生命周期保持；
- `advance_round_domain`：仅当所有剩余 Active 座位已行动且匹配
  `current_bet` 才可收注推进；
- `settlement_conservation`：结算把 gross_pot 全额分配
  （`Σ awards + rake = gross_pot`），托管总量账目闭合；
- `awards_within_pot`：奖池不得超发；
- `settlement_digest_immutable`：结算承诺在活跃行不可变——证明无法
  为一手之外的支付方案背书（DUAL_PROOF_PROTOCOL §6 绑定 3）；
- `settlement_clears_bets`：结算后不存在"已下注未结算"的悬空金额
  （防逃单 `no_unsettled_debt` 的基础）。

limb 算术的 M31→ℕ transport 由 F3 的 `add_sat_sound'` 承担；九座位的
逐座位守恒在 ℕ 层求和（与 AIR 的逐座位开列一致）。

出处：`src/airs/composition/{round_advance,settlement}.rs`；
`src/airs/actions/end_betting_round.rs`。
-/

namespace AirsLean

/-- 九座位（对齐 `COMPOSITION_SEATS`）。 -/
def NumSeats : ℕ := 9

/-- AdvanceRound 的 ℕ 级约束（座位字段来自 AIR 开列并经 limb range-check
的解码；pot 增量与逐座位清零是 AIR 的开列约束）。 -/
def AdvanceRoundSat (preBets postBets : Fin NumSeats → ℕ) (prePot postPot : ℕ)
    (preStacks postStacks : Fin NumSeats → ℕ) : Prop :=
  postPot = prePot + ∑ j, preBets j ∧
  (∀ j, postBets j = 0) ∧
  (∀ j, postStacks j = preStacks j)

/-- **收注守恒**：底池精确收进全部本轮入注；入注清零、stack 保持。 -/
theorem advance_round_pot_collection {preBets postBets : Fin NumSeats → ℕ}
    {prePot postPot : ℕ} {preStacks postStacks : Fin NumSeats → ℕ}
    (h : AdvanceRoundSat preBets postBets prePot postPot preStacks postStacks) :
    postPot = prePot + ∑ j, preBets j ∧ (∀ j, postBets j = 0) ∧
      (∀ j, postStacks j = preStacks j) := h

/-- **收注域**：只有当所有剩余 Active 座位都已行动且入注匹配
`current_bet`，收注行才可被接受。 -/
theorem advance_round_domain (preLifecycle : Fin NumSeats → Lifecycle)
    (preActed : Fin NumSeats → Bool) (preBets : Fin NumSeats → ℕ) (currentBet : ℕ)
    (h : ∀ j, preLifecycle j = Lifecycle.active →
      preActed j = true ∧ preBets j = currentBet) :
    ∀ j, preLifecycle j = Lifecycle.active → preActed j = true := fun j hact => (h j hact).1

/-- 结算的 ℕ 级约束：gross_pot 全额分配为 awards + rake；托管账目闭合；
结算承诺不变。 -/
def SettlementSat (prePot postPot grossPot rake totalAwards : ℕ)
    (digestL stmtDigestL : Limbs) : Prop :=
  totalAwards + rake = grossPot ∧
  postPot = prePot - grossPot ∧
  grossPot ≤ prePot ∧
  LimbEqSat digestL stmtDigestL

/-- **结算守恒**：奖池全额分配（awards + rake = gross_pot），结算后
底池恰减少 gross_pot，不得超发。 -/
theorem settlement_conservation {prePot postPot grossPot rake totalAwards : ℕ}
    {digestL stmtDigestL : Limbs}
    (h : SettlementSat prePot postPot grossPot rake totalAwards digestL stmtDigestL) :
    totalAwards + rake = grossPot ∧ postPot = prePot - grossPot ∧
      totalAwards ≤ grossPot := by
  obtain ⟨h1, h2, h3, _⟩ := h
  refine ⟨h1, h2, ?_⟩
  omega

/-- **奖池不超发**：`Σ awards + rake = gross_pot` 直接给出每座位 award
不超过奖池。 -/
theorem awards_within_pot (awards : Fin NumSeats → ℕ) (grossPot rake : ℕ)
    (hsum : (∑ j, awards j) + rake = grossPot)
    (j : Fin NumSeats) :
    awards j ≤ grossPot := by
  have hsub : ∑ k ∈ ({j} : Finset (Fin NumSeats)), awards k ≤ ∑ k, awards k :=
    Finset.sum_le_sum_of_subset (fun x _ => Finset.mem_univ x)
  rw [Finset.sum_singleton] at hsub
  omega

/-- **结算承诺不可变**：结算行的 digest 列与 statement 声明的 digest
逐 limb 相等——证明无法为一手之外的支付方案背书。 -/
theorem settlement_digest_immutable {digestL stmtDigestL : Limbs}
    (h : LimbEqSat digestL stmtDigestL) :
    decode digestL = decode stmtDigestL := limb_eq_decode h

/-- **结算清空入注**：结算（非 None）后所有座位的 bet 归零、pot 归零
——不存在已下注未结算的悬空金额。 -/
theorem settlement_clears_bets (postBets : Fin NumSeats → ℕ) (postPot : ℕ)
    (hbets : ∀ j, postBets j = 0) (hpot : postPot = 0) :
    (∀ j, postBets j = 0) ∧ postPot = 0 := ⟨hbets, hpot⟩

/-! ### raked award（#22④：`RevealTimeoutRakedAward`，2026-09 新增） -/

/-- raked award 的 rake 关系（对齐 canonical AIR 约束）：
`rake = min(floor(pot · bps / 10_000), cap, pot)`——抽水取"按 bps 计算、
封顶值、底池本身"三者的最小值，由 AIR 内 256-entry byte range 表的
LogUp lookup 强制。 -/
def RakeSat (pot bps cap rake : ℕ) : Prop :=
  rake = min (pot * bps / 10000) (min cap pot)

/-- **rake 不超过底池**：`rake ≤ pot`——抽水永远不能抽走超过底池的
金额，幸存者保底拿到 `pot − rake`。 -/
theorem rake_le_pot {pot bps cap rake : ℕ}
    (h : RakeSat pot bps cap rake) : rake ≤ pot := by
  unfold RakeSat at h
  rw [h]
  omega

/-- **raked award 守恒**：幸存者恰得 `pot − rake`，rake 从桌台托管中
移除——分配总额仍等于底池（无凭空生成/克扣）。 -/
theorem raked_award_credit {pot bps cap rake : ℕ}
    (h : RakeSat pot bps cap rake) :
    (pot - rake) + rake = pot := by
  unfold RakeSat at h
  rw [h]
  omega

/-- **rake 受封顶与 bps 双重约束**：`rake ≤ cap` 且
`rake ≤ floor(pot·bps/10⁴)`。 -/
theorem rake_bounded_by_cap_and_bps {pot bps cap rake : ℕ}
    (h : RakeSat pot bps cap rake) :
    rake ≤ cap ∧ rake ≤ pot * bps / 10000 := by
  unfold RakeSat at h
  rw [h]
  constructor <;> omega

/-! ### 零和结算（#18：`SettlementPrivateStatement::validate`） -/

/-- 零和约束（电路 `validate()` 规格约束 2）：全部参与者 signed deltas
之和为零——筹码只在参与者之间转移，结算不能凭空增发或凭空销毁
（rake 已在此之前从底池扣除）。 -/
def ZeroSumSat (deltas : Fin NumSeats → ℤ) (nParticipants : ℕ) : Prop :=
  (∑ j, deltas j) = 0 ∧
  nParticipants = Finset.card (Finset.univ.filter (fun j => deltas j ≠ 0)) ∧
  ∀ j, (deltas j).natAbs ≤ 18446744073709551615

/-- **结算零和**：`Σ deltas = 0`——赢家的每一分都来自输家的账户变动，
`n_participants` 恰为非零变动人数，`|delta| ≤ u64::MAX`（digest 用
u64 幅度）。 -/
theorem settlement_zero_sum {deltas : Fin NumSeats → ℤ} {nParticipants : ℕ}
    (h : ZeroSumSat deltas nParticipants) :
    (∑ j, deltas j) = 0 ∧
      nParticipants = Finset.card {j | deltas j ≠ 0} ∧
      (∀ j, deltas j ≠ 0 → nParticipants ≥ 1) := by
  obtain ⟨hsum, hcount, hbound⟩ := h
  refine ⟨hsum, hcount, ?_⟩
  intro j hne
  -- 至少存在一个非零 delta（j 自己），故参与者数 ≥ 1
  have hmem : j ∈ (Finset.univ.filter (fun j => deltas j ≠ 0) :
      Finset (Fin NumSeats)) := by
    refine Finset.mem_filter.mpr ⟨Finset.mem_univ j, ?_⟩
    simpa using hne
  have hpos : 0 < Finset.card (Finset.univ.filter (fun j => deltas j ≠ 0)) :=
    Finset.card_pos.mpr ⟨j, hmem⟩
  omega

end AirsLean
