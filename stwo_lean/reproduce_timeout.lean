import StwoLean.QM31
open StwoLean
-- 最小重现：仅 norm_eq_zero 的证明体
example {x : QM31} (h : x.c0 * x.c0 - R * (x.c1 * x.c1) = 0) (hc : x.c1 ≠ 0) : False := by
  have hkey : x.c0 * x.c0 = R * (x.c1 * x.c1) := eq_of_sub_eq_zero h
  have hcancel : (x.c1 * x.c1) * (x.c1⁻¹ * x.c1⁻¹) = 1 := by
    rw [← sq, ← sq, inv_pow, mul_inv_cancel₀ (pow_ne_zero 2 hc)]
  have hnorm5 : CM31.norm (x.c0 * x.c1⁻¹) * CM31.norm (x.c0 * x.c1⁻¹) = 5 := by
    rw [← CM31_norm_R, ← CM31.norm_mul]
    congr 1
    rw [← sq, mul_pow, pow_two, pow_two, hkey, mul_assoc, hcancel, mul_one]
  exact five_not_square ⟨_, hnorm5.symm⟩
