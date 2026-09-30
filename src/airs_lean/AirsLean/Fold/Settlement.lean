import Mathlib
import AirsLean.Fold.Chain

/-!
# Settlement — 结算语句的零和不变式与金额绑定（属性 P2）

生产公式（三方已对齐）：

* delta 语义：`combined.rs:432-434`（`build_settle_statement`：
  `signs[i] = (delta ≥ 0)`, `magnitudes[i] = |delta|`）与电路侧
  `settlement_stmt.cairo:158-176`（`s·(s-1)=0`、`sum = Σ ±m`、
  `assert!(sum == 0, "NOT_ZERO_SUM")`、`count == n_expected`）；
* digest 公式：`combined.rs:68-78` `expected_digest` =
  `poseidon([hand_id, (player, sign, magnitude)×n_actual, action_log_digest])`，
  电路侧 `settlement_stmt.cairo:67-89` 前缀吸收 + `DIGEST_MISMATCH` fail-closed；
* 金额量级：magnitudes 为 u64（`combined.rs:429` `|delta| ≤ u64::MAX` 拒收）。

机器可证命题：

1. **P2a（felt 回绕健全性）**：8 槽 ±m 和在 felt 域（ZMod StarkPrime）中为 0
   ⇔ 整数和为 0。由于 8·2^64 < 2^67 ≪ P ≈ 2^251，Cairo 电路的 felt 减法
   不会把非零和回绕成 0（不错收伪造结算），也不会把零和误判为非零（不误拒
   诚实结算）。这是 `NOT_ZERO_SUM` 检查成立与完备的算术前提。
2. **P2b（批零和 / 跨手守恒）**：每手零和 ⇒ 任意批合并零和；且零和结算中
   赢家总额恒等于输家总额。
3. **P2c（金额绑定）**：digest 预映像逐槽含 `(player, sign, magnitude)` ⇒
   任一 magnitude 变动必改 digest ⇒ 电路 `DIGEST_MISMATCH` fail-closed。
   （digest 哈希的抗碰撞性本身仍是外部假设，同 Chain.lean 的 H1。）
-/

namespace AirsLean.Fold.Settlement

/-- Stark felt252 素数 `P = 2^251 + 17·2^192 + 1`
    （`poker-protocol-core/src/stark_curve.rs:3`，Cairo felt252 域模数）。 -/
def StarkPrime : ℕ := 2^251 + 17 * 2^192 + 1

/-- delta 语义：`delta s m = (s==1 ? +m : −m)`。
    电路侧 `settlement_stmt.cairo:162-169`（`if s == 1 { sum += m } else { sum -= m }`）。 -/
def delta (s m : ℕ) : ℤ := (if s = 1 then (1 : ℤ) else -(1 : ℤ)) * m

/-- **P2a（回绕健全性，模形式）**：8 槽 ±m 和的量级界 ≤ 8·2^64 下，
    `d ≡ 0 (mod P)` ⇔ `d = 0`。 -/
theorem int_sum_zero_of_mod {d : ℤ} (hbound : |d| ≤ 8 * 2^64)
    (hmod : d % (StarkPrime : ℤ) = 0) : d = 0 := by
  by_contra hne
  obtain ⟨q, hq⟩ := Int.dvd_iff_emod_eq_zero.mpr hmod
  have hq0 : q ≠ 0 := by
    rintro rfl
    simp at hq
    exact hne hq
  have hp : (8 : ℤ) * 2^64 < (StarkPrime : ℤ) := by norm_num [StarkPrime]
  have hlt2 := abs_lt.mp (lt_of_le_of_lt hbound hp)
  have habs : (StarkPrime : ℤ) ≤ |d| := by
    rw [hq, abs_mul,
      abs_of_pos (show (0 : ℤ) < StarkPrime by norm_num [StarkPrime])]
    have hq1 : 1 ≤ |q| := Int.one_le_abs hq0
    have hstep : StarkPrime * 1 ≤ StarkPrime * |q| :=
      Int.mul_le_mul_of_nonneg_left hq1
        (le_of_lt (show (0 : ℤ) < StarkPrime by norm_num [StarkPrime]))
    simpa using hstep
  rcases lt_trichotomy d 0 with hd | hd | hd
  · rw [abs_of_neg hd] at habs
    omega
  · exact hne hd
  · rw [abs_of_pos hd] at habs
    omega

/-- **P2a（回绕健全性，ZMod/felt 形式）**：8 槽 sign∈{0,1}、每槽 m < 2^64 的
    ±m 和，若在 felt 域（ZMod StarkPrime）中为 0，则整数和为 0。
    Cairo `NOT_ZERO_SUM`（settlement_stmt.cairo:158-175）在 u64 金额量级下
    不错收、不误拒。 -/
theorem felt_zero_sum_is_int_zero {d : ℤ} (hbound : |d| ≤ 8 * 2^64)
    (hfelt : (d : ZMod StarkPrime) = 0) : d = 0 := by
  have hdvd : (StarkPrime : ℤ) ∣ d :=
    (ZMod.intCast_zmod_eq_zero_iff_dvd d StarkPrime).mp hfelt
  exact int_sum_zero_of_mod hbound (Int.dvd_iff_emod_eq_zero.mp hdvd)

/-- **P2b（批零和）**：每手零和 ⇒ 任意批合并零和（跨手守恒；
    电路按手逐条约束 `NOT_ZERO_SUM`，批层无需也不应再做全局检查）。 -/
theorem batch_zero_sum :
    ∀ (hands : List (List ℤ)), (∀ h ∈ hands, h.sum = 0) → hands.flatten.sum = 0 := by
  intro hands
  induction hands with
  | nil => intro _; rfl
  | cons h tl ih =>
    intro hok
    have h1 : h.sum = 0 := hok h (by simp)
    have h2 := ih (fun x hx => hok x (by simp [hx]))
    simp only [List.flatten_cons, List.sum_append, h1, h2]
    rfl

/-- 符号分拆恒等式：`Σ ds = Σ(正部) + Σ(负部)`（0 元素两边都不进 filter，
    对和贡献为 0，恒等式仍成立）。 -/
theorem sum_split_pos_neg (ds : List ℤ) :
    ds.sum = (ds.filter (fun d => 0 < d)).sum + (ds.filter (fun d => d < 0)).sum := by
  induction ds with
  | nil => simp
  | cons a tl ih =>
    rcases lt_trichotomy a 0 with hn | h0 | hp
    · have hna : ¬(decide (0 < a) = true) := by simp [show ¬(0 < a) from by omega]
      have hpa : decide (a < 0) = true := by simp [show a < 0 from hn]
      have f1 : (a :: tl).filter (fun d => 0 < d) = tl.filter (fun d => 0 < d) :=
        List.filter_cons_of_neg hna
      have f2 : (a :: tl).filter (fun d => d < 0) = a :: tl.filter (fun d => d < 0) :=
        List.filter_cons_of_pos hpa
      simp only [f1, f2, List.sum_cons, ih]
      omega
    · subst h0
      have f1 : (0 :: tl).filter (fun d => 0 < d) = tl.filter (fun d => 0 < d) := by
        simp
      have f2 : (0 :: tl).filter (fun d => d < 0) = tl.filter (fun d => d < 0) := by
        simp
      simp only [f1, f2, List.sum_cons, ih]
      omega
    · have hpa : decide (0 < a) = true := by simp [show 0 < a from hp]
      have hna : ¬(decide (a < 0) = true) := by simp [show ¬(a < 0) from by omega]
      have f1 : (a :: tl).filter (fun d => 0 < d) = a :: tl.filter (fun d => 0 < d) :=
        List.filter_cons_of_pos hpa
      have f2 : (a :: tl).filter (fun d => d < 0) = tl.filter (fun d => d < 0) :=
        List.filter_cons_of_neg hna
      simp only [f1, f2, List.sum_cons, ih]
      omega

/-- **P2b（守恒）**：零和结算中赢家总额恒等于输家总额——
    批结算的派奖总额被输家注金严格覆盖（无增发）。 -/
theorem winners_eq_losers (ds : List ℤ) (h : ds.sum = 0) :
    (ds.filter (fun d => 0 < d)).sum = -((ds.filter (fun d => d < 0)).sum) := by
  have hsplit := sum_split_pos_neg ds
  omega

section DigestBinding

variable {F : Type*} [DecidableEq F]

/-- 列表前缀消去：`(c1 ++ c2) = (c1 ++ c2') → c2 = c2'` 的长度式推论：
    追加非空段必改总长。 -/
theorem append_extra_ne (base tail_ extra : List F) (hextra : extra ≠ []) :
    base ++ extra ++ tail_ ≠ base ++ tail_ := by
  intro heq
  have hlen : (base ++ extra ++ tail_).length = (base ++ tail_).length := by rw [heq]
  simp only [List.length_append] at hlen
  have hexlen : extra.length = 0 := by omega
  exact hextra (List.length_eq_zero_iff.mp hexlen)

/-- **P2c（金额绑定）**：digest 预映像逐槽含 `(player, sign, magnitude)`
    （`combined.rs:68-78` / `settlement_stmt.cairo:67-88`）⇒ 任一 magnitude
    词变动必改 digest ⇒ 电路 `DIGEST_MISMATCH`（settlement_stmt.cairo:89）
    fail-closed。给定 H 单射（Chain.lean H1）。 -/
theorem digest_binds_magnitude (H : List F → F) (hH : Function.Injective H)
    (pre post : List F) (m m' : F) (hm : m ≠ m') :
    H (pre ++ m :: post) ≠ H (pre ++ m' :: post) := by
  intro heq
  exact hm (by simpa using Chain.append_right_cancel (hH heq))

/-- **P2c（参与人数绑定）**：多吸收一段非空前缀（= 新增参与者的
    `(player, sign, magnitude)` 三元组）必改 digest——n_actual 进预映像；
    尾部补位规范由 `NON_TRAILING_EMPTY_SLOT`（settlement_stmt.cairo:79）钉住。 -/
theorem digest_binds_participants (H : List F → F) (hH : Function.Injective H)
    (base tail_ extra : List F) (hextra : extra ≠ []) :
    H (base ++ extra ++ tail_) ≠ H (base ++ tail_) := by
  intro heq
  exact append_extra_ne base tail_ extra hextra (hH heq)

end DigestBinding

end AirsLean.Fold.Settlement
