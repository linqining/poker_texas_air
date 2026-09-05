import AirsLean.Soundness.Composition

/-!
# ChipState — 桌面托管状态与守恒总量

`custodyTotal`：桌面全部筹码的托管总量 = Σ stack + Σ bet + pot +
chip_pool + Σ pending_addon。筹码只在托管内部移动或经明确入口
（funding 存入 / payout 支出）穿越边界——这是防逃单命题的核心不变量。

`balance`：单个玩家的在桌余额（stack + bet + pending）。bet 在
AdvanceRound 时并入共享 pot（对玩家不可逆），settlement 以 awards
返还——C5 的提款上界以此为基。

出处：`src/airs/common.rs`（列布局）；`src/airs/composition/seat_update.rs`。
-/

namespace AirsLean

/-- 桌面托管总量。 -/
def custodyTotal (s : TableImage) : ℕ :=
  (∑ k, (s.seats k).stack) + (∑ k, (s.seats k).bet) + s.pot + s.chipPool
    + (∑ k, (s.seats k).pendingAddon)

/-- 单个玩家的在桌余额。 -/
def balance (s : TableImage) (p : Fin 9) : ℕ :=
  (s.seats p).stack + (s.seats p).bet + (s.seats p).pendingAddon

/-- 点态相等（单点例外）⇒ 求和关系：除了 `j` 处差 `v`，两函数处处相等，
则总和恰好差 `v`。九座位固定宽度开列使该桥在 AIR 内成立。 -/
theorem sum_shift {f g : Fin 9 → ℕ} {j : Fin 9} {v : ℕ}
    (hj : g j + v = f j) (ho : ∀ k, k ≠ j → g k = f k) :
    (∑ k, g k) + v = ∑ k, f k := by
  have hsplit : (∑ k, g k) + v
      = ∑ k, (g k + (if k = j then v else 0)) := by
    rw [Finset.sum_add_distrib]
    congr 1
    simp
  have hpoint : ∀ k : Fin 9, g k + (if k = j then v else 0) = f k := by
    intro k
    by_cases h : k = j
    · subst h
      simp [hj]
    · rw [if_neg h, ho k h, add_zero]
  rw [hsplit]
  exact Finset.sum_congr rfl fun k _ => hpoint k

end AirsLean
