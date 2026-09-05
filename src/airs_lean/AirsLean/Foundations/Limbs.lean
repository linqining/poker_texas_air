import AirsLean.Foundations.M31

/-!
# Limbs — 4×16-bit limb 编码

每个 method AIR 把 `u64` 业务量（stack / bet / pot / chip_pool / amount …）
编码为 4 个 M31 limb（每 limb 16 位）。M31 域上 `B^2 ≥ p`，所以
**没有 range check 时 limb 线性组合在 M31 中有回绕**——解码出的自然数不再
是编码时的值。range-check witness（`RANGE_*_BITS` 列）排除回绕，使 M31
trace 忠实承载 u64 语义。

- `decode_encode`：range check 成立 ⇒ 编码/解码在 `[0, 2^64)` 上互逆。
- `limb_range_sound`：range check 下 AIR 的加权组合等于解码值的投射。
- `limb_range_necessary`：去掉 range check 则存在同 M31 投射、不同 u64 值
  的编码——"删 range check = 打开漏洞"的形式化。

出处：`src/airs/common.rs:74-104`（`u64_to_m31_limbs` / `m31_limbs_to_u64`）；
各 AIR 的 `RANGE_*_BITS` 列。
-/

namespace AirsLean

/-- 16 位 limb 基（`2^16`）。 -/
def B16 : ℕ := 65536

/-- 64 位值域上界（`2^64`）。 -/
def B64 : ℕ := 18446744073709551616

@[simp] lemma B16_eq : B16 = 65536 := rfl
@[simp] lemma B64_eq : B64 = 18446744073709551616 := rfl

/-- 4 个 16-bit limb（对齐 `u64_to_m31_limbs` 的 `[M31; 4]`）。 -/
structure Limbs where
  l0 : M31
  l1 : M31
  l2 : M31
  l3 : M31

/-- 每个 limb 的取值落在 `[0, 2^16)`——AIR 中由 per-limb boolean 分解
（`RANGE_*_BITS`，16 bit × 4 limb）强制。 -/
def InLimbRange (l : Limbs) : Prop :=
  l.l0.val < B16 ∧ l.l1.val < B16 ∧ l.l2.val < B16 ∧ l.l3.val < B16

/-- 小值自然数到 M31 的投射保持 `.val`（`x < 2^16 < p` 时无回绕）。 -/
lemma val_cast_of_lt_16 {x : ℕ} (h : x < 65536) : (x : M31).val = x := by
  have hx : x < M31P := by rw [M31P_eq]; omega
  rw [ZMod.val_natCast, Nat.mod_eq_of_lt hx]

/-- mod-16 的值投射回 M31 后 `.val` 不变。注意这里必须显式 `Nat.cast`：
`(v % B16 : M31)` 记号会被 elaborator 提升为 M31 域内 mod，与 Rust 编码
（先 ℕ mod 再 cast）不符。 -/
lemma val_mod16 (x : ℕ) : (Nat.cast (x % B16) : M31).val = x % B16 :=
  val_cast_of_lt_16 (Nat.mod_lt x (by simp))

/-- 大端约定：`l0` 是最低位 limb。对齐 `m31_limbs_to_u64`：
`l0 | l1 << 16 | l2 << 32 | l3 << 48`。 -/
def decode (l : Limbs) : ℕ :=
  l.l0.val + B16 * l.l1.val + B16^2 * l.l2.val + B16^3 * l.l3.val

/-- 把 `u64` 值编码为 4 个 limb。对齐 `u64_to_m31_limbs`（先 ℕ mod 再 cast）。 -/
def encode (v : ℕ) : Limbs :=
  ⟨Nat.cast (v % B16), Nat.cast (v / B16 % B16),
   Nat.cast (v / B16^2 % B16), Nat.cast (v / B16^3 % B16)⟩

/-- 编码总是满足 range check（mod 余式均 `< B16`）。 -/
lemma encode_in_range (v : ℕ) : InLimbRange (encode v) := by
  have hmod : ∀ x : ℕ, x % B16 < B16 := fun x => Nat.mod_lt x (by simp)
  unfold InLimbRange encode
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [val_mod16]; exact hmod v
  · rw [val_mod16]; exact hmod (v / B16)
  · rw [val_mod16]; exact hmod (v / B16^2)
  · rw [val_mod16]; exact hmod (v / B16^3)

/-- **limb range check 的充分性**：`v < 2^64` 时解码还原编码值。
这是"M31 trace 忠实承载 u64"的第一半。 -/
lemma decode_encode (v : ℕ) (hv : v < B64) : decode (encode v) = v := by
  simp only [decode, encode]
  rw [val_mod16, val_mod16, val_mod16, val_mod16]
  rw [B64_eq] at hv
  norm_num [B16_eq]
  have hd : v / 65536 / 65536 = v / 4294967296 := by
    rw [Nat.div_div_eq_div_mul]
  have he : v / 4294967296 / 65536 = v / 281474976710656 := by
    rw [Nat.div_div_eq_div_mul]
  omega

/-- **range check 下的 M31 忠实性**：limb 全部在界内时，AIR 中的加权组合
`l0 + B·l1 + B²·l2 + B³·l3`（M31 语义）恰好是解码值的投射。
约束表达式 ↔ u64 值的对应由此建立。 -/
lemma limb_range_sound (l : Limbs) (h : InLimbRange l) :
    ((decode l : ℕ) : M31) = l.l0 + (B16 : M31) * l.l1
      + (B16 : M31)^2 * l.l2 + (B16 : M31)^3 * l.l3 := by
  have e0 : ((l.l0.val : ℕ) : M31) = l.l0 := by simp
  have e1 : ((l.l1.val : ℕ) : M31) = l.l1 := by simp
  have e2 : ((l.l2.val : ℕ) : M31) = l.l2 := by simp
  have e3 : ((l.l3.val : ℕ) : M31) = l.l3 := by simp
  simp only [decode, B16_eq, Nat.cast_add, Nat.cast_mul, Nat.cast_pow, Nat.cast_ofNat]
  rw [e0, e1, e2, e3]

/-- **range check 的必要性（反例）**：limbs `⟨p-1, 1, 0, 0⟩` 的 M31 加权组合
投射到 `65535`，但其解码值是 `p - 1 + 65536 ≠ 65535`。若 AIR 不对 limb
做 range check，"组合列相等"就锁不住 u64 语义。 -/
lemma limb_range_necessary :
    ∃ (l : Limbs) (v : ℕ),
      ((decode l : ℕ) : M31) = (v : M31) ∧
      l.l0 + (B16 : M31) * l.l1 + (B16 : M31)^2 * l.l2 + (B16 : M31)^3 * l.l3 = (v : M31) ∧
      decode l ≠ v := by
  refine ⟨⟨((2147483646 : ℕ) : M31), ((1 : ℕ) : M31), ((0 : ℕ) : M31), ((0 : ℕ) : M31)⟩,
    65535, ?_, ?_, ?_⟩
  all_goals
    have hv0 : ((2147483646 : ℕ) : M31).val = 2147483646 := by
      rw [ZMod.val_natCast, Nat.mod_eq_of_lt (by norm_num)]
    have hv1 : ((1 : ℕ) : M31).val = 1 := by
      rw [ZMod.val_natCast, Nat.mod_eq_of_lt (by norm_num)]
    have hv2 : ((0 : ℕ) : M31).val = 0 := by
      rw [ZMod.val_natCast, Nat.mod_eq_of_lt (by norm_num)]
    simp only [decode, hv0, hv1, hv2, B16_eq]
  · decide
  · decide
  · decide

/-- 由 limb range check 得到解码值在 `u64` 值域内。 -/
lemma decode_lt (l : Limbs) (h : InLimbRange l) : decode l < B64 := by
  simp only [InLimbRange, B16_eq] at h
  simp only [decode, B16_eq, B64_eq]
  omega

end AirsLean
