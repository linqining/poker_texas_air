import AirsLean.Foundations.CarryArith
import AirsLean.Soundness.ActionAIRs

set_option maxHeartbeats 2000000

/-!
# ExecEval — 可执行 AIR eval ↔ 命题约束的桥接（Phase 3）

上游接口：stwo_lean `Verifier.ComponentSpec.terms`——组件约束商在 OODS
采样点的项；`verifyMain` 接受的证明要求这些项经 DEEP-ALI 混入 FRI 后
处处消没。约束商消没的**语义内容**正是"evaluator 施加的每条约束
residue 为零"。本文件把后者建成 **可计算** 的 residue 列表求值器，并
证明与命题模型（`AddSat` / `FundMoveSat`）的双向桥：

* **soundness**：eval 全零 ⇒ 命题约束成立（可执行检查不多不少地蕴含
  命题约束，`fund_move_eval_sound` / `add_sat_eval_sound`）；
* **completeness**：命题约束成立 ⇒ 在规范 bit witness（`bitsOfF`，
  对齐 host 端 `compute_add_carries` / `u64_to_m31_limbs` 的确定性
  分解）下 eval 全零（诚实 witness 总能通过检查，
  `*_complete`）。

最终 `fund_move_eval_conservation`：可执行求值全零 ⇒ u64 资金守恒
（stack/bet/total_bet 的精确转移）——把 stwo_lean 主循环接受的证明与
业务语义接通。range check 以定长 16-bit boolean 分解列（`BitsW`，对应
`RANGE_*_BITS` 的 64 bit 列）建模：`limbRes` 同时约束分解一致性与逐
bit boolean 性。

"求值器 residue 表达式 ↔ Rust evaluator 约束表达式逐条对应"是审计
义务项（PLAN §0），不在证明内部。
-/

namespace AirsLean

/-! ### 基础事实 -/

/-- ZMod 元素等于其 `.val` 的投射（同环 `ZMod.cast` 为恒等）。 -/
theorem val_cast_self (b : M31) : ((b.val : ℕ) : M31) = b :=
  (ZMod.natCast_val b).trans (ZMod.cast_id _ b)

/-- 几何级数：`∑_{i<n} 2^i = 2^n − 1`。 -/
lemma sum_pow_two_range (n : ℕ) : ∑ i ∈ Finset.range n, 2 ^ i = 2 ^ n - 1 := by
  induction n with
  | zero => simp
  | succ n ih =>
      rw [Finset.sum_range_succ, ih, pow_succ]
      omega

/-- **二进制分解恒等式**：`v < 2^k` 时逐位提取的加权和还原 `v`
（host 端 `u64_to_m31_limbs` 型确定性分解的数学内容）。 -/
theorem sum_bits_eq : ∀ k v : ℕ, v < 2 ^ k →
    ∑ i ∈ Finset.range k, (v / 2 ^ i % 2) * 2 ^ i = v
  | 0, v, hv => by
      have hv0 : v = 0 := by simpa using hv
      subst hv0
      simp
  | k + 1, v, hv => by
      have hdiv : v / 2 < 2 ^ k :=
        (Nat.div_lt_iff_lt_mul (k := 2) (by norm_num)).mpr
          (by have h2 : (2 : ℕ) ^ (k + 1) = 2 ^ k * 2 := by rw [pow_succ]
              omega)
      have ih := sum_bits_eq k (v / 2) hdiv
      have hsplit := Nat.div_add_mod v 2
      have h0 : v / 2 ^ 0 % 2 = v % 2 := by simp
      have h20 : (2 : ℕ) ^ 0 = 1 := by norm_num
      have key : ∀ i ∈ Finset.range k,
          (v / 2 ^ (i + 1) % 2) * 2 ^ (i + 1) = 2 * ((v / 2 / 2 ^ i % 2) * 2 ^ i) := by
        intro i _
        have hp : (2 : ℕ) ^ (i + 1) = 2 * 2 ^ i := by rw [pow_succ, Nat.mul_comm]
        rw [hp, Nat.div_div_eq_div_mul]
        ring
      rw [Finset.sum_range_succ', h0, Finset.sum_congr rfl key, ← Finset.mul_sum, ih,
        h20]
      omega

/-! ### boolean residue 与规范 bit 分解 -/

/-- boolean 性 residue：`b·(b−1) = 0 ⟺ b ∈ {0,1}`。 -/
def boolRes (b : M31) : M31 := b * (b - 1)

theorem boolRes_zero_iff {b : M31} : boolRes b = 0 ↔ M31Bool b := by
  unfold boolRes M31Bool
  constructor
  · intro h
    rcases mul_eq_zero.mp h with h | h
    · exact Or.inl h
    · exact Or.inr (by linear_combination h)
  · intro h
    rcases h with h | h <;> [rw [h]; rw [h]] <;> ring

/-- 16-bit 分解 witness 类型（定长，杜绝长度不匹配）。 -/
abbrev BitsW := Fin 16 → M31

/-- 规范 bit 分解（LSB 在前；host 端逐位提取 witness 的确定性计算）。 -/
def bitsOfF (v : ℕ) : BitsW := fun i => (Nat.cast (v / 2 ^ (i : ℕ) % 2) : M31)

/-- 规范分解逐位 boolean。 -/
theorem bitsOfF_boolean (v : ℕ) (i : Fin 16) : M31Bool (bitsOfF v i) := by
  unfold M31Bool bitsOfF
  rcases Nat.mod_two_eq_zero_or_one (v / 2 ^ (i : ℕ)) with h | h <;> rw [h] <;> simp

/-- ℕ 侧加权和。 -/
def wsumNF (bs : BitsW) : ℕ := ∑ i : Fin 16, (bs i).val * 2 ^ (i : ℕ)

/-- M31 侧加权和。 -/
def wsumF (bs : BitsW) : M31 := ∑ i : Fin 16, bs i * (2 : M31) ^ (i : ℕ)

/-- boolean 位表的 M31 加权和等于 ℕ 加权和的投射。 -/
theorem wsumF_cast {bs : BitsW} (hb : ∀ i, M31Bool (bs i)) :
    ((wsumNF bs : ℕ) : M31) = wsumF bs := by
  unfold wsumNF wsumF
  rw [Nat.cast_sum]
  exact Finset.sum_congr rfl fun i _ => by
    simp only [Nat.cast_mul, Nat.cast_pow, Nat.cast_ofNat, val_cast_self]

/-- boolean 位表的 ℕ 加权和上界：`wsumNF bs < 2^16`。 -/
theorem wsumNF_lt {bs : BitsW} (hb : ∀ i, M31Bool (bs i)) : wsumNF bs < 2 ^ 16 := by
  have hgeo : ∑ i : Fin 16, 2 ^ (i : ℕ) = 2 ^ 16 - 1 :=
    Fin.sum_univ_eq_sum_range (fun i : ℕ => (2 : ℕ) ^ i) 16 ▸ sum_pow_two_range 16
  unfold wsumNF
  calc wsumNF bs ≤ ∑ i : Fin 16, 2 ^ (i : ℕ) :=
      Finset.sum_le_sum fun i _ => by
        have hv1 := M31Bool.val (hb i)
        rcases hv1 with h | h
        · rw [h]; simp
        · rw [h]; simp
    _ = 2 ^ 16 - 1 := hgeo
  omega

/-- **分解恒等式**（M31 侧）：`v < 2^16` 时规范分解加权和还原 `v`。 -/
theorem wsumF_bitsOfF (v : ℕ) (hv : v < 2 ^ 16) : wsumF (bitsOfF v) = (v : M31) := by
  have hrange : (∑ i : Fin 16,
      (Nat.cast (v / 2 ^ (i : ℕ) % 2) : M31) * ((2 : M31) ^ (i : ℕ)))
      = ((∑ i ∈ Finset.range 16, (v / 2 ^ i % 2) * 2 ^ i : ℕ) : M31) := by
    rw [Fin.sum_univ_eq_sum_range
      (fun i : ℕ => (Nat.cast (v / 2 ^ i % 2) : M31) * ((2 : M31) ^ i)) 16, Nat.cast_sum]
    exact Finset.sum_congr rfl fun i _ => by simp [Nat.cast_mul, Nat.cast_pow]
  unfold wsumF bitsOfF
  rw [hrange, sum_bits_eq 16 v hv]

/-! ### limb 分解 residue（RANGE_*_BITS 的可执行形态） -/

/-- 单 limb 求值：分解一致性 + 逐 bit boolean 性。 -/
def limbRes (l : M31) (bs : BitsW) : List M31 :=
  (l - wsumF bs) :: (List.ofFn fun i => boolRes (bs i))

/-- **分解 soundness**：limb 求值全零 ⇒ limb 值 `< 2^16`（16-bit 列排除
limb 回绕）。 -/
theorem limbRes_sound {l : M31} {bs : BitsW} (hb : ∀ i, M31Bool (bs i))
    (h : ∀ r ∈ limbRes l bs, r = 0) : l.val < 2 ^ 16 := by
  have hw : l - wsumF bs = 0 := h _ (List.Mem.head _)
  have heq : l = wsumF bs := by linear_combination hw
  have hbound := wsumNF_lt hb
  have hcast := wsumF_cast hb
  have hNlt : wsumNF bs < M31P := by
    show wsumNF bs < 2147483647
    omega
  have hval : l.val = wsumNF bs := by
    rw [heq, ← hcast, ZMod.val_natCast, Nat.mod_eq_of_lt hNlt]
  omega

/-- 从 limb 求值全零中提取逐 bit boolean 性。 -/
theorem limbRes_bool {x : M31} {b : BitsW} (s : ∀ r ∈ limbRes x b, r = 0) :
    ∀ i, M31Bool (b i) := fun i =>
  boolRes_zero_iff.mp (s (boolRes (b i)) (List.Mem.tail _ (List.mem_ofFn.mpr ⟨i, rfl⟩)))

/-- **分解 completeness**：`l.val < 2^16` 时规范 bit 表通过全部 residue。 -/
theorem limbRes_complete {l : M31} (h : l.val < 2 ^ 16) :
    ∀ r ∈ limbRes l (bitsOfF l.val), r = 0 := by
  have hdec : wsumF (bitsOfF l.val) = (l.val : M31) := wsumF_bitsOfF l.val h
  intro r hr
  rcases List.mem_cons.mp hr with hr0 | hr'
  · rw [hr0, hdec, val_cast_self l]
    ring
  · rcases List.mem_ofFn.mp hr' with ⟨i, hr''⟩
    rw [← hr'']
    exact boolRes_zero_iff.mpr (bitsOfF_boolean l.val i)

/-! ### 4-limb 组与 AddSat 桥 -/

/-- 4-limb 的 bit 分解 witness（对齐 `RANGE_*_BITS` 的 64 bit 列）。 -/
structure LimbBits where
  w0 : BitsW
  w1 : BitsW
  w2 : BitsW
  w3 : BitsW

/-- 一组 limb 的可执行求值。 -/
def limbsRes (l : Limbs) (w : LimbBits) : List M31 :=
  limbRes l.l0 w.w0 ++ limbRes l.l1 w.w1 ++ limbRes l.l2 w.w2 ++ limbRes l.l3 w.w3

/-- 规范 bit witness（host 端确定性分解）。 -/
def limbBitsOf (l : Limbs) : LimbBits :=
  ⟨bitsOfF l.l0.val, bitsOfF l.l1.val, bitsOfF l.l2.val, bitsOfF l.l3.val⟩

theorem limbsRes_sound {l : Limbs} {w : LimbBits}
    (h : ∀ r ∈ limbsRes l w, r = 0) : InLimbRange l := by
  -- 反向组装：分段成员 → 整体成员（括号形状 = `++` 链的左结合展开）
  have up : ∀ (r : M31) (_ : ((r ∈ limbRes l.l0 w.w0 ∨ r ∈ limbRes l.l1 w.w1) ∨
      r ∈ limbRes l.l2 w.w2) ∨ r ∈ limbRes l.l3 w.w3), r ∈ limbsRes l w := by
    intro r hd
    simpa only [limbsRes, List.mem_append] using hd
  have seg0 : ∀ r ∈ limbRes l.l0 w.w0, r = 0 := fun r hr =>
    h r (up r (Or.inl (Or.inl (Or.inl hr))))
  have seg1 : ∀ r ∈ limbRes l.l1 w.w1, r = 0 := fun r hr =>
    h r (up r (Or.inl (Or.inl (Or.inr hr))))
  have seg2 : ∀ r ∈ limbRes l.l2 w.w2, r = 0 := fun r hr =>
    h r (up r (Or.inl (Or.inr hr)))
  have seg3 : ∀ r ∈ limbRes l.l3 w.w3, r = 0 := fun r hr =>
    h r (up r (Or.inr hr))
  exact ⟨limbRes_sound (limbRes_bool seg0) seg0,
    limbRes_sound (limbRes_bool seg1) seg1,
    limbRes_sound (limbRes_bool seg2) seg2,
    limbRes_sound (limbRes_bool seg3) seg3⟩

theorem limbsRes_complete {l : Limbs} (h : InLimbRange l) :
    ∀ r ∈ limbsRes l (limbBitsOf l), r = 0 := by
  obtain ⟨h0, h1, h2, h3⟩ := h
  intro r hr
  rcases List.mem_append.mp hr with h' | hr4
  rcases List.mem_append.mp h' with h' | hr3
  rcases List.mem_append.mp h' with h' | hr2
  · exact limbRes_complete h0 r h'
  · exact limbRes_complete h1 r hr2
  · exact limbRes_complete h2 r hr3
  · exact limbRes_complete h3 r hr4

/-- 一次带进位 limb 加法的可执行求值：4 条 limb 方程 + 3 个进位
boolean 性（对齐 `AddSat` 的约束集合；方程以减法形式写成 residue）。 -/
def addResEval (a b s : Limbs) (c0 c1 c2 : M31) : List M31 :=
  [a.l0 + b.l0 - s.l0 - (B16 : M31) * c0,
   a.l1 + b.l1 + c0 - s.l1 - (B16 : M31) * c1,
   a.l2 + b.l2 + c1 - s.l2 - (B16 : M31) * c2,
   a.l3 + b.l3 + c2 - s.l3,
   boolRes c0, boolRes c1, boolRes c2]

/-- residue 全零 ⟺ 方程组成立 + 进位 boolean（双向精确桥）。 -/
theorem addResEval_zero_iff (a b s : Limbs) (c0 c1 c2 : M31) :
    (∀ r ∈ addResEval a b s c0 c1 c2, r = 0) ↔
      (a.l0 + b.l0 = s.l0 + (B16 : M31) * c0) ∧
      (a.l1 + b.l1 + c0 = s.l1 + (B16 : M31) * c1) ∧
      (a.l2 + b.l2 + c1 = s.l2 + (B16 : M31) * c2) ∧
      (a.l3 + b.l3 + c2 = s.l3) ∧
      M31Bool c0 ∧ M31Bool c1 ∧ M31Bool c2 := by
  unfold addResEval
  constructor
  · intro h
    have e0 := h _ (List.Mem.head _)
    have e1 := h _ (List.Mem.tail _ (List.Mem.head _))
    have e2 := h _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))
    have e3 := h _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))))
    have b0 := boolRes_zero_iff.mp (h _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _
      (List.Mem.tail _ (List.Mem.head _))))))
    have b1 := boolRes_zero_iff.mp (h _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _
      (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))))))
    have b2 := boolRes_zero_iff.mp (h _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _
      (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))))))))
    refine ⟨?_, ?_, ?_, ?_, b0, b1, b2⟩
    · linear_combination e0
    · linear_combination e1
    · linear_combination e2
    · linear_combination e3
  · rintro ⟨e0, e1, e2, e3, b0, b1, b2⟩ r hr
    simp only [List.mem_cons] at hr
    rcases hr with hr0 | hr1 | hr2 | hr3 | hr4 | hr5 | hr6 | hnil
    · rw [hr0]; linear_combination e0
    · rw [hr1]; linear_combination e1
    · rw [hr2]; linear_combination e2
    · rw [hr3]; linear_combination e3
    · rw [hr4]; exact boolRes_zero_iff.mpr b0
    · rw [hr5]; exact boolRes_zero_iff.mpr b1
    · rw [hr6]; exact boolRes_zero_iff.mpr b2
    · exact absurd hnil (by simp)

/-- **AddSat 的可执行求值**：3 组 limb 分解 + 方程/进位 residues。 -/
def addSatEval (a b s : Limbs) (c0 c1 c2 : M31) (wa wb ws : LimbBits) : List M31 :=
  limbsRes a wa ++ limbsRes b wb ++ limbsRes s ws ++ addResEval a b s c0 c1 c2

/-- **可执行 → 命题**（soundness）：`addSatEval` 全零 ⇒ `AddSat`。 -/
theorem add_sat_eval_sound {a b s : Limbs} {c0 c1 c2 : M31} {wa wb ws : LimbBits}
    (h : ∀ r ∈ addSatEval a b s c0 c1 c2 wa wb ws, r = 0) : AddSat a b s c0 c1 c2 := by
  have up : ∀ (r : M31) (_ : ((r ∈ limbsRes a wa ∨ r ∈ limbsRes b wb) ∨
      r ∈ limbsRes s ws) ∨ r ∈ addResEval a b s c0 c1 c2),
      r ∈ addSatEval a b s c0 c1 c2 wa wb ws := by
    intro r hd
    simpa only [addSatEval, List.mem_append] using hd
  obtain ⟨e0, e1, e2, e3, hb0, hb1, hb2⟩ :=
    (addResEval_zero_iff a b s c0 c1 c2).mp (fun r hr =>
      h r (up r (Or.inr hr)))
  exact ⟨limbsRes_sound (fun r hr => h r (up r (Or.inl (Or.inl (Or.inl hr))))),
    limbsRes_sound (fun r hr => h r (up r (Or.inl (Or.inl (Or.inr hr))))),
    limbsRes_sound (fun r hr => h r (up r (Or.inl (Or.inr hr)))),
    hb0, hb1, hb2, e0, e1, e2, e3⟩

/-- **命题 → 可执行**（completeness）：`AddSat` 成立时，规范 bit witness
下 `addSatEval` 全零。 -/
theorem add_sat_eval_complete {a b s : Limbs} {c0 c1 c2 : M31}
    (h : AddSat a b s c0 c1 c2) :
    ∀ r ∈ addSatEval a b s c0 c1 c2 (limbBitsOf a) (limbBitsOf b) (limbBitsOf s), r = 0 := by
  obtain ⟨ra, rb, rs, hb0, hb1, hb2, e0, e1, e2, e3⟩ := h
  intro r hr
  rcases List.mem_append.mp hr with h' | hr4
  rcases List.mem_append.mp h' with h' | hr3
  rcases List.mem_append.mp h' with h' | hr2
  · exact limbsRes_complete ra r h'
  · exact limbsRes_complete rb r hr2
  · exact limbsRes_complete rs r hr3
  exact (addResEval_zero_iff a b s c0 c1 c2).mpr
    ⟨e0, e1, e2, e3, hb0, hb1, hb2⟩ r hr4

/-! ### 分段求值的通用 foldr 引理 -/

/-- 整体求值中的成员必来自某一段（或 init）。 -/
theorem foldr_mem_cases {α : Type _} {x : α} :
    ∀ (xs : List (List α)) (init : List α), x ∈ xs.foldr (· ++ ·) init →
      x ∈ init ∨ ∃ p ∈ xs, x ∈ p
  | [], init, h => Or.inl h
  | p :: xs, init, h => by
      rcases List.mem_append.mp h with h' | h'
      · exact Or.inr ⟨p, List.mem_cons_self .., h'⟩
      · rcases foldr_mem_cases xs init h' with h'' | ⟨q, hq, hq'⟩
        · exact Or.inl h''
        · exact Or.inr ⟨q, List.mem_cons_of_mem _ hq, hq'⟩

/-- 段成员 + 段属于分段表 ⇒ 整体成员。 -/
theorem mem_foldr_append {α : Type _} {x : α} :
    ∀ (xs : List (List α)) (init : List α) (p : List α), p ∈ xs → x ∈ p →
      x ∈ xs.foldr (· ++ ·) init
  | [], init, _, hp, _ => absurd hp (by simp)
  | q :: xs, init, p, hp, hx => by
      rcases List.mem_cons.mp hp with rfl | hp'
      · exact List.mem_append_left _ hx
      · exact List.mem_append_right _ (mem_foldr_append xs init p hp' hx)

/-! ### FundMove：可执行求值 → u64 资金守恒 -/

/-- 7 组 limb 的 bit witness（pre/post × stack/bet/total_bet + amount）。 -/
structure FundMoveBits where
  wPreStack : LimbBits
  wPostStack : LimbBits
  wPreBet : LimbBits
  wPostBet : LimbBits
  wPreTB : LimbBits
  wPostTB : LimbBits
  wAmount : LimbBits

/-- 规范 bit witness。 -/
def fundMoveBitsOf (preStack postStack preBet postBet preTB postTB amount : Limbs) :
    FundMoveBits :=
  { wPreStack := limbBitsOf preStack
    wPostStack := limbBitsOf postStack
    wPreBet := limbBitsOf preBet
    wPostBet := limbBitsOf postBet
    wPreTB := limbBitsOf preTB
    wPostTB := limbBitsOf postTB
    wAmount := limbBitsOf amount }

/-- **FundMove 的可执行求值**：7 组 limb 分解 + 3 次带进位 limb 加法
（`post.stack + amount = pre.stack`、`pre.bet + amount = post.bet`、
`pre.total_bet + amount = post.total_bet`——与 `FundMoveSat` 逐条对应）。 -/
def fundMovePieces (preStack postStack preBet postBet preTB postTB amount : Limbs)
    (sc bc tc : AddCarry) (w : FundMoveBits) : List (List M31) :=
  [limbsRes preStack w.wPreStack, limbsRes postStack w.wPostStack,
   limbsRes preBet w.wPreBet, limbsRes postBet w.wPostBet,
   limbsRes preTB w.wPreTB, limbsRes postTB w.wPostTB, limbsRes amount w.wAmount,
   addResEval postStack amount preStack sc.c0 sc.c1 sc.c2,
   addResEval preBet amount postBet bc.c0 bc.c1 bc.c2,
   addResEval preTB amount postTB tc.c0 tc.c1 tc.c2]

/-- **FundMove 的可执行求值**：7 组 limb 分解 + 3 次带进位 limb 加法
（`post.stack + amount = pre.stack`、`pre.bet + amount = post.bet`、
`pre.total_bet + amount = post.total_bet`——与 `FundMoveSat` 逐条对应）。 -/
def fundMoveEval (preStack postStack preBet postBet preTB postTB amount : Limbs)
    (sc bc tc : AddCarry) (w : FundMoveBits) : List M31 :=
  (fundMovePieces preStack postStack preBet postBet preTB postTB amount sc bc tc w).foldr
    (· ++ ·) []

/-- **可执行 → 命题**：`fundMoveEval` 全零 ⇒ `FundMoveSat`。 -/
theorem fund_move_eval_sound {preStack postStack preBet postBet preTB postTB amount : Limbs}
    {sc bc tc : AddCarry} {w : FundMoveBits}
    (h : ∀ r ∈ fundMoveEval preStack postStack preBet postBet preTB postTB amount sc bc tc w,
      r = 0) : FundMoveSat preStack postStack preBet postBet preTB postTB amount sc bc tc := by
  have lift : ∀ (p : List M31), p ∈ fundMovePieces preStack postStack preBet postBet preTB postTB amount sc bc tc w → ∀ r : M31, r ∈ p →
      r ∈ fundMoveEval preStack postStack preBet postBet preTB postTB amount sc bc tc w := by
    intro p hp r hr
    exact mem_foldr_append (fundMovePieces preStack postStack preBet postBet preTB postTB amount sc bc tc w) [] p hp hr
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact limbsRes_sound (fun r hr => h r (lift _ (List.Mem.head _) r hr)))
  · exact limbsRes_sound (fun r hr => h r (lift _ (List.Mem.tail _ (List.Mem.head _)) r hr)))
  · exact limbsRes_sound (fun r hr => h r (lift _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))) r hr)))
  · exact limbsRes_sound (fun r hr => h r (lift _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))) r hr)))
  · exact limbsRes_sound (fun r hr => h r (lift _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))))) r hr)))
  · exact limbsRes_sound (fun r hr => h r (lift _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))))) r hr)))
  · exact limbsRes_sound (fun r hr => h r (lift _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))))))) r hr)))
  · exact add_sat_eval_sound (fun r hr => h r (lift _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))))))) r hr)))
  · exact add_sat_eval_sound (fun r hr => h r (lift _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _))))))))) r hr)))
  · exact add_sat_eval_sound (fun r hr => h r (lift _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)))))))))) r hr)))

/-- **命题 → 可执行**：`FundMoveSat` 成立时，规范 bit witness 下
`fundMoveEval` 全零。 -/
theorem fund_move_eval_complete {preStack postStack preBet postBet preTB postTB amount : Limbs}
    {sc bc tc : AddCarry} (h : FundMoveSat preStack postStack preBet postBet preTB postTB
      amount sc bc tc) :
    ∀ r ∈ fundMoveEval preStack postStack preBet postBet preTB postTB amount sc bc tc
      (fundMoveBitsOf preStack postStack preBet postBet preTB postTB amount), r = 0 := by
  obtain ⟨r1, r2, r3, r4, r5, r6, r7, s1, s2, s3⟩ := h
  have hpc := fundMovePieces preStack postStack preBet postBet preTB postTB amount sc bc tc
    (fundMoveBitsOf preStack postStack preBet postBet preTB postTB amount)
  intro r hr
  have hr' : r ∈ (fundMovePieces preStack postStack preBet postBet preTB postTB amount sc bc tc
      (fundMoveBitsOf preStack postStack preBet postBet preTB postTB amount)).foldr (· ++ ·) [] := hr
  obtain ⟨hinit | ⟨p, hp, hrp⟩⟩ := foldr_mem_cases _ [] hr'
  · exact absurd hinit (by simp [fundMovePieces])
  rcases hp with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | (rfl | hnil)
  · exact limbsRes_complete r1 r hrp
  · exact limbsRes_complete r2 r hrp
  · exact limbsRes_complete r3 r hrp
  · exact limbsRes_complete r4 r hrp
  · exact limbsRes_complete r5 r hrp
  · exact limbsRes_complete r6 r hrp
  · exact limbsRes_complete r7 r hrp
  · exact add_sat_eval_complete s1 r hrp
  · exact add_sat_eval_complete s2 r hrp
  · exact add_sat_eval_complete s3 r hrp
  · exact absurd hnil (by simp)

/-- **Phase 3 主桥**：可执行求值全零 ⇒ u64 资金守恒。
stwo_lean 主循环（`verifyMain`）接受的证明，其组件约束商项消没的
语义内容即此处 residue 全零；由此 u64 语义的资金精确转移成立。 -/
theorem fund_move_eval_conservation {preStack postStack preBet postBet preTB postTB amount :
    Limbs} {sc bc tc : AddCarry} {w : FundMoveBits}
    (h : ∀ r ∈ fundMoveEval preStack postStack preBet postBet preTB postTB amount sc bc tc w,
      r = 0) :
    decode preStack = decode postStack + decode amount ∧
      decode postBet = decode preBet + decode amount ∧
      decode postTB = decode preTB + decode amount :=
  fund_move_conservation (fund_move_eval_sound h)

/-! ### 自检：诚实 witness 通过可执行求值 -/

/-- 诚实资金转移（stack 100 → 70，bet 5 → 35，total_bet 5 → 35，
amount 30，各 limb 无跨位进位）在规范 witness 下全部 residue 消零——
求值器可执行性 + completeness 的端到端机器自检。 -/
example :
    ∀ r ∈ fundMoveEval (encode 100) (encode 70) (encode 5) (encode 35) (encode 5) (encode 35)
        (encode 30) ⟨encode 70, encode 30, encode 100, 0, 0, 0⟩
        ⟨encode 5, encode 30, encode 35, 0, 0, 0⟩ ⟨encode 5, encode 30, encode 35, 0, 0, 0⟩
        (fundMoveBitsOf (encode 100) (encode 70) (encode 5) (encode 35) (encode 5) (encode 35)
          (encode 30)), r = 0 := by
  refine fund_move_eval_complete ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact encode_in_range 100
  · exact encode_in_range 70
  · exact encode_in_range 5
  · exact encode_in_range 35
  · exact encode_in_range 5
  · exact encode_in_range 35
  · exact encode_in_range 30
  all_goals
    exact ⟨encode_in_range _, encode_in_range _, encode_in_range _, Or.inl rfl,
      Or.inl rfl, Or.inl rfl, by native_decide, by native_decide, by native_decide,
      by native_decide⟩

end AirsLean
