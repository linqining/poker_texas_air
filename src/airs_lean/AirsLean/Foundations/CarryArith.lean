import AirsLean.Foundations.Limbs

/-!
# CarryArith — 逐 limb ripple-carry 算术

AIR 中的 u64 加/减法约束不整块进行（`2^64 > p` 会回绕），而是拆成 4 条
16-bit limb 方程 + 3 个进位 witness（对齐 `compute_add_carries`）：

```
e0: a0 + b0        = s0 + B·c0
e1: a1 + b1 + c0   = s1 + B·c1
e2: a2 + b2 + c1   = s2 + B·c2
e3: a3 + b3 + c2   = s3        （最高位无进位输出 ⇒ 无 u64 溢出）
```

- `limb_carry_eq_iff` / `limb_last_eq_iff`：小值前提下，M31 方程 ⟺ ℕ 方程。
- `add_sat_sound`：约束成立 ⇒ `decode a + decode b = decode s`（u64 语义，
  无溢出）。这是全部资金约束"在 M31 域成立 ⇒ 在 u64 语义成立"的枢纽。
- `add_complete`：诚实加法存在满足约束的进位 witness（completeness 侧，
  对应 host 端 `compute_add_carries` 的确定性 witness）。

出处：`src/airs/common.rs:111-`（`compute_add_carries`）；各 AIR 的
`*_CARRY_BASE` 列与 `CommonConstraints` 中的 limb 方程。
-/

namespace AirsLean

/-- 布尔门控：值为 0 或 1（AIR 中 boolean witness 的语义）。 -/
def M31Bool (v : M31) : Prop := v = 0 ∨ v = 1

lemma M31Bool.val {v : M31} (h : M31Bool v) : v.val = 0 ∨ v.val = 1 := by
  rcases h with h | h
  · exact Or.inl (by rw [h]; rfl)
  · right
    rw [h, ← Nat.cast_one (R := M31), ZMod.val_natCast, M31P_eq]

/-- 小自然数（≤ 65535）到 M31 的投射保持 `.val`。 -/
lemma cast_val_of_le {k : ℕ} (hk : k ≤ 65535) : (Nat.cast k : M31).val = k :=
  val_cast_of_lt_16 (by omega)

/-- 一次带进位的 limb 加法约束 witness。 -/
structure AddCarry where
  a : Limbs
  b : Limbs
  s : Limbs
  c0 : M31
  c1 : M31
  c2 : M31

/-- limb 加法约束（M31 语义，对齐 AIR 逐 limb 方程与 carry witness 列）。
range check 覆盖三组 limb；最高位方程无进位输出项（对应 u64 无溢出）。
约束直接以字段为参数，避免 struct 投影。 -/
def AddSat (a b s : Limbs) (c0 c1 c2 : M31) : Prop :=
  InLimbRange a ∧ InLimbRange b ∧ InLimbRange s ∧
  M31Bool c0 ∧ M31Bool c1 ∧ M31Bool c2 ∧
  (a.l0 + b.l0 = s.l0 + (B16 : M31) * c0) ∧
  (a.l1 + b.l1 + c0 = s.l1 + (B16 : M31) * c1) ∧
  (a.l2 + b.l2 + c1 = s.l2 + (B16 : M31) * c2) ∧
  (a.l3 + b.l3 + c2 = s.l3)

/-- 中段 limb 方程的 M31 ⟺ ℕ 桥：所有项在界内时无回绕。 -/
lemma limb_carry_eq_iff {p q r w c : M31}
    (hp : p.val < 65536) (hq : q.val < 65536) (hr : r.val < 65536)
    (hw : w.val ≤ 65535) (hcb : c.val ≤ 1) :
    p + q + w = r + (B16 : M31) * c ↔
    p.val + q.val + w.val = r.val + 65536 * c.val := by
  have hp' : ((p.val : ℕ) : M31) = p := by simp
  have hq' : ((q.val : ℕ) : M31) = q := by simp
  have hr' : ((r.val : ℕ) : M31) = r := by simp
  have hw' : ((w.val : ℕ) : M31) = w := by simp
  have hc' : ((c.val : ℕ) : M31) = c := by simp
  have h1 : p.val + q.val + w.val < M31P := by
    show p.val + q.val + w.val < 2147483647
    omega
  have h2 : r.val + 65536 * c.val < M31P := by
    show r.val + 65536 * c.val < 2147483647
    omega
  constructor
  · intro h
    refine M31.add_inj h1 h2 ?_
    simp only [Nat.cast_add, Nat.cast_mul]
    rw [hp', hq', hw', hr', hc']
    exact h
  · intro h
    rw [← hp', ← hq', ← hw', ← hr', ← hc']
    simp only [← Nat.cast_add, ← Nat.cast_mul, B16_eq]
    rw [h]

/-- 首位 limb 方程（无进位输入）的 M31 ⟺ ℕ 桥。 -/
lemma limb_first_eq_iff {p q r c : M31}
    (hp : p.val < 65536) (hq : q.val < 65536) (hr : r.val < 65536) (hcb : c.val ≤ 1) :
    p + q = r + (B16 : M31) * c ↔
    p.val + q.val = r.val + 65536 * c.val := by
  have hp' : ((p.val : ℕ) : M31) = p := by simp
  have hq' : ((q.val : ℕ) : M31) = q := by simp
  have hr' : ((r.val : ℕ) : M31) = r := by simp
  have hc' : ((c.val : ℕ) : M31) = c := by simp
  have h1 : p.val + q.val < M31P := by
    show p.val + q.val < 2147483647
    omega
  have h2 : r.val + 65536 * c.val < M31P := by
    show r.val + 65536 * c.val < 2147483647
    omega
  constructor
  · intro h
    refine M31.add_inj h1 h2 ?_
    simp only [Nat.cast_add, Nat.cast_mul]
    rw [hp', hq', hr', hc']
    exact h
  · intro h
    rw [← hp', ← hq', ← hr', ← hc']
    simp only [← Nat.cast_add, ← Nat.cast_mul, B16_eq]
    rw [h]

/-- 最高位 limb 方程（无进位输出）的 M31 ⟺ ℕ 桥。 -/
lemma limb_last_eq_iff {p q r w : M31}
    (hp : p.val < 65536) (hq : q.val < 65536) (hr : r.val < 65536) (hw : w.val ≤ 65535) :
    p + q + w = r ↔ p.val + q.val + w.val = r.val := by
  have hp' : ((p.val : ℕ) : M31) = p := by simp
  have hq' : ((q.val : ℕ) : M31) = q := by simp
  have hr' : ((r.val : ℕ) : M31) = r := by simp
  have hw' : ((w.val : ℕ) : M31) = w := by simp
  have h1 : p.val + q.val + w.val < M31P := by
    show p.val + q.val + w.val < 2147483647
    omega
  have h2 : r.val < M31P := by
    show r.val < 2147483647
    omega
  constructor
  · intro h
    refine M31.natCast_inj h1 h2 ?_
    simp only [Nat.cast_add]
    rw [hp', hq', hw', hr']
    exact h
  · intro h
    rw [← hp', ← hq', ← hw', ← hr']
    simp only [← Nat.cast_add]
    rw [h]

/-- **limb 加法约束的 soundness**（本层核心）：约束成立 ⇒ 解码值在 ℕ 上
精确相加，且最高位无进位（u64 无溢出）。 -/
theorem add_sat_sound (x : AddCarry) (h : AddSat x.a x.b x.s x.c0 x.c1 x.c2) :
    decode x.a + decode x.b = decode x.s := by
  obtain ⟨ra, rb, rs, hc0, hc1, hc2, e0, e1, e2, e3⟩ := h
  obtain ⟨a0, a1, a2, a3⟩ := ra
  obtain ⟨b0, b1, b2, b3⟩ := rb
  obtain ⟨s0, s1, s2, s3⟩ := rs
  have v0 := hc0.val
  have v1 := hc1.val
  have v2 := hc2.val
  rcases v0 with v0 | v0 <;> rcases v1 with v1 | v1 <;> rcases v2 with v2 | v2
  all_goals
    simp only [decode, B16_eq] at *
    have n0 : x.a.l0.val + x.b.l0.val + 0 = x.s.l0.val + 65536 * x.c0.val := by
      have h' := (limb_carry_eq_iff (w := (0 : M31)) (c := x.c0) a0 b0 s0
        (by simp) (by omega)).mp (by rw [add_zero]; exact e0)
      rwa [ZMod.val_zero] at h'
    have n1 : x.a.l1.val + x.b.l1.val + x.c0.val = x.s.l1.val + 65536 * x.c1.val :=
      (limb_carry_eq_iff (w := x.c0) (c := x.c1) a1 b1 s1 (by omega) (by omega)).mp e1
    have n2 : x.a.l2.val + x.b.l2.val + x.c1.val = x.s.l2.val + 65536 * x.c2.val :=
      (limb_carry_eq_iff (w := x.c1) (c := x.c2) a2 b2 s2 (by omega) (by omega)).mp e2
    have n3 : x.a.l3.val + x.b.l3.val + x.c2.val = x.s.l3.val :=
      (limb_last_eq_iff (w := x.c2) a3 b3 s3 (by omega)).mp e3
    omega

/-- `add_sat_sound` 的分量形式：直接接受 6 个字段。 -/
theorem add_sat_sound' {a b s : Limbs} {c0 c1 c2 : M31}
    (h : AddSat a b s c0 c1 c2) : decode a + decode b = decode s :=
  add_sat_sound ⟨a, b, s, c0, c1, c2⟩ h

/-- **limb 加法约束的 completeness**：只要诚实和不出 `u64`，就存在满足全部
约束的进位 witness（对应 host 端 `compute_add_carries` 的确定性计算）。 -/
theorem add_complete (a b : Limbs) (ra : InLimbRange a) (rb : InLimbRange b)
    (hsum : decode a + decode b < B64) :
    ∃ c0 c1 c2 : M31,
      M31Bool c0 ∧ M31Bool c1 ∧ M31Bool c2 ∧
      AddSat a b (encode (decode a + decode b)) c0 c1 c2 := by
  obtain ⟨a0, a1, a2, a3⟩ := ra
  obtain ⟨b0, b1, b2, b3⟩ := rb
  simp only [B16_eq] at a0 a1 a2 a3 b0 b1 b2 b3
  simp only [decode, B16_eq, B64_eq] at hsum ⊢
  norm_num at hsum ⊢
  set n : ℕ := (a.l0.val + 65536 * a.l1.val + 4294967296 * a.l2.val + 281474976710656 * a.l3.val) +
    (b.l0.val + 65536 * b.l1.val + 4294967296 * b.l2.val + 281474976710656 * b.l3.val) with hne
  -- 进位 witness：逐 limb 除基取商（对齐 compute_add_carries）
  set k0 : ℕ := (a.l0.val + b.l0.val) / 65536 with hk0
  set k1 : ℕ := (a.l1.val + b.l1.val + k0) / 65536 with hk1
  set k2 : ℕ := (a.l2.val + b.l2.val + k1) / 65536 with hk2
  have hb0 : k0 ≤ 1 := by omega
  have hb1 : k1 ≤ 1 := by omega
  have hb2 : k2 ≤ 1 := by omega
  have bool_of_le1 : ∀ k : ℕ, k ≤ 1 → M31Bool (Nat.cast k : M31) := by
    intro k hk
    match k with
    | 0 => exact Or.inl (by simp)
    | 1 => exact Or.inr (by simp)
    | k + 2 => omega
  -- encode 后 s limb 的 val
  have hs0 : (encode n).l0.val = n % 65536 := by
    show (Nat.cast (n % B16) : M31).val = n % 65536
    rw [val_mod16]; rfl
  have hs1 : (encode n).l1.val = n / 65536 % 65536 := by
    show (Nat.cast (n / B16 % B16) : M31).val = n / 65536 % 65536
    rw [val_mod16, B16_eq]
  have hs2 : (encode n).l2.val = n / 4294967296 % 65536 := by
    show (Nat.cast (n / B16 ^ 2 % B16) : M31).val = n / 4294967296 % 65536
    rw [val_mod16, B16_eq]
    norm_num
  have hs3 : (encode n).l3.val = n / 281474976710656 % 65536 := by
    show (Nat.cast (n / B16 ^ 3 % B16) : M31).val = n / 281474976710656 % 65536
    rw [val_mod16, B16_eq]
    norm_num
  refine ⟨Nat.cast k0, bool_of_le1 k0 hb0,
    Nat.cast k1, bool_of_le1 k1 hb1,
    Nat.cast k2, bool_of_le1 k2 hb2, ?_⟩
  unfold AddSat
  refine ⟨⟨a0, a1, a2, a3⟩, ⟨b0, b1, b2, b3⟩, encode_in_range n,
    bool_of_le1 k0 hb0, bool_of_le1 k1 hb1, bool_of_le1 k2 hb2, ?_, ?_, ?_, ?_⟩
  · -- e0：无进位输入；ℕ 侧证毕后经 M31.add_inj 提升
    have hr : (encode n).l0.val < 65536 := by
      rw [hs0]; exact Nat.mod_lt _ (by norm_num)
    have hcb : (Nat.cast k0 : M31).val ≤ 1 := by
      rw [cast_val_of_le (by omega)]; omega
    have hℕ : a.l0.val + b.l0.val
        = (encode n).l0.val + 65536 * (Nat.cast k0 : M31).val := by
      rw [hs0, cast_val_of_le (k := k0) (by omega)]
      omega
    have e0' : a.l0 + b.l0 = (encode n).l0 + (B16 : M31) * Nat.cast k0 := by
      have hp' : ((a.l0.val : ℕ) : M31) = a.l0 := by simp
      have hq' : ((b.l0.val : ℕ) : M31) = b.l0 := by simp
      have hr' : (((encode n).l0.val : ℕ) : M31) = (encode n).l0 := by simp
      have hc' : (((Nat.cast k0 : M31).val : ℕ) : M31) = Nat.cast k0 := by simp
      rw [← hp', ← hq', ← hr', ← hc']
      simp only [← Nat.cast_add, ← Nat.cast_mul, B16_eq]
      rw [hℕ]
    exact (limb_first_eq_iff a0 b0 hr hcb).mpr hℕ
  · refine (limb_carry_eq_iff (w := Nat.cast k0) a1 b1 ?_ ?_ ?_).mpr ?_
    · rw [hs1]; exact Nat.mod_lt _ (by norm_num)
    · rw [cast_val_of_le (by omega)]; omega
    · rw [cast_val_of_le (by omega)]; omega
    · rw [hs1, cast_val_of_le (k := k0) (by omega), cast_val_of_le (k := k1) (by omega)]
      omega
  · refine (limb_carry_eq_iff (w := Nat.cast k1) a2 b2 ?_ ?_ ?_).mpr ?_
    · rw [hs2]; exact Nat.mod_lt _ (by norm_num)
    · rw [cast_val_of_le (by omega)]; omega
    · rw [cast_val_of_le (by omega)]; omega
    · rw [hs2, cast_val_of_le (k := k1) (by omega), cast_val_of_le (k := k2) (by omega)]
      omega
  · refine (limb_last_eq_iff (w := Nat.cast k2) a3 b3 ?_ ?_).mpr ?_
    · rw [hs3]; exact Nat.mod_lt _ (by norm_num)
    · rw [cast_val_of_le (by omega)]; omega
    · rw [hs3, cast_val_of_le (k := k2) (by omega)]
      omega

end AirsLean
