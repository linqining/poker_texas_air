import Mathlib.Algebra.MvPolynomial.SchwartzZippel
import PokerProtocolLean.Foundations.Negligible
import PokerProtocolLean.Reconstruct.ReconstructionDLEQ

/-!
# ReconstructProof — base_coefficient double Schwartz-Zippel (M8-J3)

Backing `poker_protocol/src/zk_shuffle/reconstruction/proof.rs` (the
`base_coefficient` double-application argument).

A single application of `base_coeff` gives a linear-combination binding
(`sum_point_out_total = a • sum_point_in_total` for the extracted `a`).
A second, independent FS-transcript application (with a different
`base_coeff`) forces the per-card binding:
`points_in[i] = a • points_out[i]` for each `i`.

This is a two-variable Schwartz-Zippel argument over
`MvPolynomial F (Fin 2)`. For the n=2 case (two point groups: c1-sum
and c2-minus-card-sum used in the actual protocol), the proof is
elementary: two distinct Vandermonde rows force the per-card binding
via linear algebra.

## Proof idea (n = 2)

From two batch bindings with the same extracted `a`:

  a • (points_in[0] + r1 • points_in[1]) = points_out[0] + r1 • points_out[1]
  a • (points_in[0] + r2 • points_in[1]) = points_out[0] + r2 • points_out[1]

Let `e = points_out[1] - a • points_in[1]`.  Both equations give
`a • points_in[0] - points_out[0] = r1 • e = r2 • e`, so
`(r1 - r2) • e = 0`.  Since `r1 ≠ r2` and `F` is a field, `e = 0`,
which yields `points_out[1] = a • points_in[1]` and then
`points_out[0] = a • points_in[0]`.

The general-n case requires the full `MvPolynomial (Fin 2)`
Schwartz-Zippel argument with a `4/|F|` probability bound; the
n = 2 case has a constructive proof.
-/

open scoped ENNReal

namespace PokerProtocolLean.Reconstruct

variable (F : Type) [Field F] [Fintype F] [DecidableEq F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]

/-- Injectivity of scalar multiplication by a non-zero scalar
(on the left): `c • v = 0` with `c ≠ 0` implies `v = 0`.
Holds in any `Module F G` when `F` is a field. -/
lemma smul_ne_zero_inj (c : F) (hc : c ≠ 0) {v : G} (h : c • v = 0) : v = 0 := by
  have : c⁻¹ • (c • v) = c⁻¹ • (0 : G) := by rw [h]
  simpa [smul_smul, inv_mul_cancel₀ hc, smul_zero] using this

/-- Auxiliary: expand `base_point_in` for n = 2. -/
lemma base_point_in_fin2 (r : F) (stmt : Statement F G 2) :
    base_point_in F G r stmt = stmt.points_in 0 + r • stmt.points_in 1 := by
  unfold base_point_in
  simp [Fin.sum_univ_two, pow_zero, pow_one, one_smul]

/-- Auxiliary: expand `base_point_out` for n = 2. -/
lemma base_point_out_fin2 (r : F) (stmt : Statement F G 2) :
    base_point_out F G r stmt = stmt.points_out 0 + r • stmt.points_out 1 := by
  unfold base_point_out
  simp [Fin.sum_univ_two, pow_zero, pow_one, one_smul]

/-- **Double-application binding** (n = 2): two independent `base_coeff`
applications with the same extracted scalar `a` force per-card binding.

For the actual protocol (which uses two point groups: c1-sum and
c2-minus-card-sum), the algebraic argument is elementary: the two
batch-binding equations form a 2 × 2 Vandermonde system, which
inverts to give per-card binding.

The general-n case requires the full `MvPolynomial (Fin 2)`
Schwartz-Zippel argument with a `4/|F|` probability bound; the
n = 2 case has a constructive proof. -/
theorem double_application_binding
    (stmt1 stmt2 : Statement F G 2)
    (hpts_in : stmt1.points_in = stmt2.points_in)
    (hpts_out : stmt1.points_out = stmt2.points_out)
    (hbase : stmt1.base_coeff ≠ stmt2.base_coeff)
    (wit1 wit2 : Witness F)
    (hrel1 : relation F G 2 stmt1 wit1 = true)
    (hrel2 : relation F G 2 stmt2 wit2 = true)
    (ha : wit1.a = wit2.a) :
    ∀ i : Fin 2, stmt1.points_out i = wit1.a • stmt1.points_in i := by

  set r1 := stmt1.base_coeff with hr1
  set r2 := stmt2.base_coeff with hr2
  set a := wit1.a with ha_def

  -- Extract bindings from the two Σ-protocol proofs
  have hbind1 : a • base_point_in F G r1 stmt1 = base_point_out F G r1 stmt1 := by
    have h : wit1.a • base_point_in F G stmt1.base_coeff stmt1 =
        base_point_out F G stmt1.base_coeff stmt1 := of_decide_eq_true hrel1
    simpa [ha_def, ← hr1] using h

  have hbind2 : a • base_point_in F G r2 stmt2 = base_point_out F G r2 stmt2 := by
    have h : wit2.a • base_point_in F G stmt2.base_coeff stmt2 =
        base_point_out F G stmt2.base_coeff stmt2 := of_decide_eq_true hrel2
    simpa [← ha, ← hr2] using h

  -- Expand the batch bindings for n = 2
  have heq1 : a • (stmt1.points_in 0 + r1 • stmt1.points_in 1) =
      stmt1.points_out 0 + r1 • stmt1.points_out 1 := by
    rw [← base_point_in_fin2 F G r1 stmt1, ← base_point_out_fin2 F G r1 stmt1]
    exact hbind1

  have heq2 : a • (stmt2.points_in 0 + r2 • stmt2.points_in 1) =
      stmt2.points_out 0 + r2 • stmt2.points_out 1 := by
    rw [← base_point_in_fin2 F G r2 stmt2, ← base_point_out_fin2 F G r2 stmt2]
    exact hbind2

  -- Replace stmt2's points with stmt1's
  rw [← hpts_in, ← hpts_out] at heq2

  -- Let e = points_out[1] - a • points_in[1]
  set e := stmt1.points_out 1 - a • stmt1.points_in 1 with he

  -- Both bindings imply: a • points_in[0] - points_out[0] = r • e
  have h1 : a • stmt1.points_in 0 - stmt1.points_out 0 = r1 • e := by
    have h : a • (stmt1.points_in 0 + r1 • stmt1.points_in 1) =
        stmt1.points_out 0 + r1 • stmt1.points_out 1 := heq1
    have hexpand : a • stmt1.points_in 0 + a • (r1 • stmt1.points_in 1) =
        stmt1.points_out 0 + r1 • stmt1.points_out 1 := by
      rw [smul_add] at h
      exact h
    have hcomm : a • r1 • stmt1.points_in 1 = r1 • (a • stmt1.points_in 1) := by
      simp [smul_smul, mul_comm]
    have hlinear : a • stmt1.points_in 0 + r1 • (a • stmt1.points_in 1) =
        stmt1.points_out 0 + r1 • stmt1.points_out 1 := by
      rw [← hcomm]
      exact hexpand
    calc
      a • stmt1.points_in 0 - stmt1.points_out 0
        = r1 • stmt1.points_out 1 - r1 • (a • stmt1.points_in 1) := by
          have hshift : a • stmt1.points_in 0 =
              stmt1.points_out 0 + r1 • stmt1.points_out 1 - r1 • (a • stmt1.points_in 1) := by
            calc
              a • stmt1.points_in 0
                = a • stmt1.points_in 0 + r1 • (a • stmt1.points_in 1) - r1 • (a • stmt1.points_in 1) := by abel
              _ = stmt1.points_out 0 + r1 • stmt1.points_out 1 - r1 • (a • stmt1.points_in 1) := by rw [hlinear]
          rw [hshift]
          abel
      _ = r1 • (stmt1.points_out 1 - a • stmt1.points_in 1) := by simp [smul_sub]
      _ = r1 • e := by rw [← he]

  have h2 : a • stmt1.points_in 0 - stmt1.points_out 0 = r2 • e := by
    have h : a • (stmt1.points_in 0 + r2 • stmt1.points_in 1) =
        stmt1.points_out 0 + r2 • stmt1.points_out 1 := heq2
    have hexpand : a • stmt1.points_in 0 + a • (r2 • stmt1.points_in 1) =
        stmt1.points_out 0 + r2 • stmt1.points_out 1 := by
      rw [smul_add] at h
      exact h
    have hcomm : a • r2 • stmt1.points_in 1 = r2 • (a • stmt1.points_in 1) := by
      simp [smul_smul, mul_comm]
    have hlinear : a • stmt1.points_in 0 + r2 • (a • stmt1.points_in 1) =
        stmt1.points_out 0 + r2 • stmt1.points_out 1 := by
      rw [← hcomm]
      exact hexpand
    calc
      a • stmt1.points_in 0 - stmt1.points_out 0
        = r2 • stmt1.points_out 1 - r2 • (a • stmt1.points_in 1) := by
          have hshift : a • stmt1.points_in 0 =
              stmt1.points_out 0 + r2 • stmt1.points_out 1 - r2 • (a • stmt1.points_in 1) := by
            calc
              a • stmt1.points_in 0
                = a • stmt1.points_in 0 + r2 • (a • stmt1.points_in 1) - r2 • (a • stmt1.points_in 1) := by abel
              _ = stmt1.points_out 0 + r2 • stmt1.points_out 1 - r2 • (a • stmt1.points_in 1) := by rw [hlinear]
          rw [hshift]
          abel
      _ = r2 • (stmt1.points_out 1 - a • stmt1.points_in 1) := by simp [smul_sub]
      _ = r2 • e := by rw [← he]

  -- r1 • e = r2 • e, so (r1 - r2) • e = 0
  have h3 : r1 • e = r2 • e := by
    exact Eq.trans (Eq.symm h1) h2
  have h4 : (r1 - r2) • e = 0 := by
    have h5 : r1 • e - r2 • e = 0 := by
      calc
        r1 • e - r2 • e = r2 • e - r2 • e := by rw [h3]
        _ = 0 := by simp
    simpa [sub_smul] using h5

  have hr1_ne_r2 : r1 - r2 ≠ 0 := by
    intro hcontra
    have h : r1 = r2 := by simpa [sub_eq_zero] using hcontra
    exact hbase h

  have he_zero : e = 0 := by
    have h : (r1 - r2)⁻¹ • ((r1 - r2) • e) = (r1 - r2)⁻¹ • (0 : G) := by rw [h4]
    simpa [smul_smul, inv_mul_cancel₀ hr1_ne_r2, smul_zero] using h

  have hcard1 : a • stmt1.points_in 1 = stmt1.points_out 1 := by
    have h : stmt1.points_out 1 - a • stmt1.points_in 1 = 0 := by
      simpa [← he] using he_zero
    have h' : a • stmt1.points_in 1 - stmt1.points_out 1 = 0 := by
      have hneg : a • stmt1.points_in 1 - stmt1.points_out 1 =
          -(stmt1.points_out 1 - a • stmt1.points_in 1) := by
        exact Eq.symm (neg_sub (stmt1.points_out 1) (a • stmt1.points_in 1))
      rw [hneg, h]
      simp
    exact sub_eq_zero.mp h'

  have hcard0 : a • stmt1.points_in 0 = stmt1.points_out 0 := by
    have h : a • stmt1.points_in 0 - stmt1.points_out 0 = 0 := by
      calc
        a • stmt1.points_in 0 - stmt1.points_out 0
          = r1 • e := h1
        _ = r1 • (0 : G) := by rw [he_zero]
        _ = 0 := by simp
    exact sub_eq_zero.mp h

  intro i
  fin_cases i
  · exact Eq.symm hcard0
  · exact Eq.symm hcard1

end PokerProtocolLean.Reconstruct
