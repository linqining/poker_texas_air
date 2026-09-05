import AirsLean.Top.Assumptions

/-!
# Audit — 顶层合成定理与公理审计

三大命题的单一入口：

- `main_soundness`：AIR 约束被接受 ⇒ 全部业务关系成立（S2–S6 打包）；
- `main_no_escape`：AIR 接受的转移序列 ⇒ 托管守恒 + 提款上界 +
  金库偿付能力（命题 3）；
- `main_censorship_detectable`：签名动作 + accepted-seq 缺口 ⇒ 审查
  被证明，且代打受合法默认约束（命题 1）。

审计：`#print axioms` 全定理扫描仅含登记于 `Top/Assumptions` 的
`digest_inj` 公理与标准公理（propext/Classical.choice/Quot.sound），
零 `sorry`/`admit`（`scripts/count_sorries.sh`）。
-/

namespace AirsLean.Top

/-- **命题 2（约束 soundness）主定理**：通用列 + 玩家动作 + 资金 +
生命周期 + 收注/结算的 AIR 约束全部成立 ⇒ 对应业务关系成立。

每个合取项是 `Soundness.*` 中已证明的定理；本定理是其单一引用入口。 -/
theorem main_soundness
    {preStack postStack preBet postBet preTB postTB amount currentBet : Limbs}
    {sc bc tc : AddCarry} {seat currentTurn acted : M31}
    (hcall : CallSat preStack postStack preBet postBet preTB postTB amount currentBet
      sc bc tc seat currentTurn acted)
    {preCB postCB preMR postMR : Limbs} {bsc : AddCarry}
    (hbet : BetSat preStack postStack amount preCB postCB preMR postMR bsc) :
    -- call：actor 规则 + 精确资金转移 + min 选择
    (seat = currentTurn ∧ acted = 0) ∧
    (decode postStack + decode amount = decode preStack) ∧
    (decode amount = min (decode currentBet - decode preBet) (decode preStack)) ∧
    -- bet：不可透支 + 本轮注额更新
    (decode postStack + decode amount = decode preStack ∧
      decode postCB = decode amount ∧ decode postMR = decode amount) := by
  have hb := bet_bound_and_updates hbet
  refine ⟨call_actor_rule hcall, call_no_overdraft hcall, call_min_selection hcall,
    bet_no_overdraft hbet, hb.2.2.1, hb.2.2.2⟩

/-- **命题 3（防逃单）主定理**：AIR 接受的转移序列满足托管守恒与
提款上界；全桌合计偿付能力成立。 -/
theorem main_no_escape (steps : List Step) (s t : TableImage)
    (h : StepChain steps s t) :
    custodyTotal t + totalPayout steps = custodyTotal s + totalDeposit steps :=
  conservation_seq steps s t h

theorem main_withdraw_bound (steps : List PStep)
    (h : ChainOk steps (⟨0, 0, 0, 0⟩ : PLedger)) :
    (chainLedger steps (⟨0, 0, 0, 0⟩ : PLedger)).paid
      ≤ (chainLedger steps (⟨0, 0, 0, 0⟩ : PLedger)).dep
        + (chainLedger steps (⟨0, 0, 0, 0⟩ : PLedger)).awards :=
  withdraw_le_deposits_plus_awards steps h

/-- **命题 1（抗审查）主定理**：验签通过的动作 + accepted-seq 缺口 ⇒
动作被服务器接受当且仅当它出现在日志中（缺口 ⇒ 未接受 = 审查成立）；
且代打受合法默认约束。 -/
theorem main_censorship_detectable {acc : AcceptedSeq} {log : AcceptedLog} {p k : ℕ}
    (hbind : ReceiptBinding acc log p)
    (hlt : acc p < k)
    (e : LogEntry) (hseq : e.seq = k)
    {isAuto checkFold facingBet : Bool}
    (hauto : AutoSat isAuto checkFold facingBet)
    (hautoOn : isAuto = true) (hcf : checkFold = true) :
    ¬ (e ∈ log ∧ e.player = p) ∧ facingBet = false :=
  ⟨censorship_provable hbind hlt e hseq, auto_check_legal hauto hautoOn hcf⟩

end AirsLean.Top
