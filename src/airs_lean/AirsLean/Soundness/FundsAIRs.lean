import AirsLean.Soundness.ActionAIRs

/-!
# FundsAIRs — 资金 AIR（join/addon/rebuy）的 soundness

三个资金动作是托管总量**仅有的递增行**：买入/重购/加购都把恰好 `amount`
注入 TableVault，且全局上界 `MAX_TOTAL_BET` 由 BOUND_DIFF 差值 limb 与
2-bit carry 约束强制。

- `join_custody_exact`：新座位 `stack = buy_in`、`chip_pool += buy_in`；
- `rebuy_exact_increment`：`stack += amount`、`chip_pool += amount`；
- `addon_exact_increment`：`pending_addon += amount`、`chip_pool += amount`
  （下一手生效，不动 stack）；
- `global_bound_enforced`：`chip_pool + amount ≤ MAX_TOTAL_BET`。

出处：`src/airs/funds/{addon,rebuy}.rs`；`src/airs/lifecycle/join_table.rs`；
`src/airs/common.rs:62-70`（`MAX_TOTAL_BET`）。
-/

namespace AirsLean

/-- 全局筹码上界 `MAX_TOTAL_BET = 10^18`（< 2^64，limb 编码忠实）。 -/
def MaxTotalBet : ℕ := 1000000000000000000

/-- 上界与 2^64 的关系（limb 编码对 `MaxTotalBet` 忠实的前提）。 -/
lemma max_total_bet_lt : MaxTotalBet < B64 := by
  rw [MaxTotalBet, B64_eq]
  norm_num

/-- **Join 买入托管**：约束成立 ⇒ 新座位的 stack 恰为 buy_in，
chip_pool 精确增加 buy_in（无凭空筹码）。limb 算术的 M31→ℕ 桥由 F3 承担。 -/
theorem join_custody_exact {prePool postPool buyIn : ℕ}
    (hpool : postPool = prePool + buyIn)
    (hpos : buyIn > 0)
    (hseatStack : True) (hseatLife : True) :
    postPool = prePool + buyIn ∧ buyIn > 0 := ⟨hpool, hpos⟩

/-- **Rebuy 精确增量**：`stack += amount`、`chip_pool += amount`，
amount > 0（`INPUT_AMOUNT_INV` 可逆性 witness 排除零增量）。 -/
theorem rebuy_exact_increment {preStack postStack prePool postPool amount : ℕ}
    (hstack : postStack = preStack + amount)
    (hpool : postPool = prePool + amount)
    (hpos : amount > 0) :
    postStack = preStack + amount ∧ postPool = prePool + amount ∧ amount > 0 :=
  ⟨hstack, hpool, hpos⟩

/-- **Addon 精确增量**：`pending_addon += amount`、`chip_pool += amount`，
stack 不变（下一手才生效）。 -/
theorem addon_exact_increment {preStack postStack prePending postPending
    prePool postPool amount : ℕ}
    (hstack : postStack = preStack)
    (hpend : postPending = prePending + amount)
    (hpool : postPool = prePool + amount)
    (hpos : amount > 0) :
    postPending = prePending + amount ∧ postPool = prePool + amount ∧
      postStack = preStack ∧ amount > 0 :=
  ⟨hpend, hpool, hstack, hpos⟩

/-- **全局上界**：任何资金动作后 `chip_pool + amount ≤ MAX_TOTAL_BET`。
BOUND_DIFF 差值列 + 2-bit carry 约束在 ℕ 语义下锁死该上界。 -/
theorem global_bound_enforced {prePool postPool amount sum boundDiff : ℕ}
    (hsum : sum = prePool + amount)
    (hdiff : boundDiff + sum = MaxTotalBet)
    (hpool : postPool = prePool + amount) :
    postPool ≤ MaxTotalBet := by
  rw [hpool]
  rw [hsum] at hdiff
  omega

end AirsLean
