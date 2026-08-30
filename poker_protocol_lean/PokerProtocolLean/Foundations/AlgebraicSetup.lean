/-
! # Algebraic Setup for Mental-Poker ZK Proofs

This file establishes the abstract prime-order group convention used throughout
the `PokerProtocolLean` project, following the VCV-io `Module F G` pattern.

We model:
- `F` : the scalar field (typically `ZMod q` for a prime `q`)
- `G` : the group of curve points (an additive commutative group)
- `g : G` : a fixed public generator (passed explicitly to each theorem, VCV-io style)
- `hg : Function.Bijective (smulByG F G g)` : simple-transitivity of `F` on `G` via `g`
  (required by the VCV-io Schnorr σ-protocol template).

No concrete curve (BLS12-381, Ristretto255, etc.) is formalized. All soundness
arguments hold under the discrete-logarithm assumption on `G`, which is supplied
as a computational hypothesis via VCV-io's `HardnessAssumptions.DiffieHellman`.

## References
- `poker_protocol/soundness.md` §四 (cryptographic assumptions)
- `poker_protocol/src/zk_shuffle/generalized_schnorr_proof.rs`
- VCV-io `Examples/Schnorr/SigmaProtocol.lean`
-/

import Mathlib.Algebra.Module.Basic
import Mathlib.Algebra.Field.Basic
import Mathlib.Data.Fintype.Basic
import Mathlib.Data.Fintype.Card
import Mathlib.Data.Fintype.EquivFin
import Mathlib.Data.Set.Function
import Mathlib.GroupTheory.GroupAction.Basic
import Mathlib.Logic.Equiv.Defs
import Mathlib.Logic.Function.Basic

namespace PokerProtocolLean.Foundations

/-- The scalar-multiplication-by-`g` map, packaged as a named function so it
can be used unambiguously in `Function.Bijective` and `Set.range`.

The `F` and `G` parameters are explicit so this definition can be referenced
before the `variable` block below (and in particular inside the `hg`
hypothesis). The result is a *function* `F → G` so that
`Function.Bijective (smulByG F G g)` is well-typed. -/
def smulByG (F G : Type) [SMul F G] (g : G) : F → G := fun a => a • g

/-! ## The shared variable block for the entire project.

`F` is the scalar field; `G` is the additive group of points. Typeclass
instances (`Field F`, `Module F G`, `Fintype`, `DecidableEq`) are declared
as section variables so they are auto-inserted into theorem signatures when
the corresponding type appears.

Concretely: for `F = ZMod q` (prime `q`) and `G = ZMod q` with `g = 1`,
`hg` holds trivially since `smulByG F G 1 = id`. -/

variable (F : Type) [Field F] [Fintype F] [DecidableEq F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]

/-- The bijection `hg` packaged as an `Equiv`, for use with `Fintype.card_congr`.

The generator `g` and the bijection hypothesis `hg` are passed explicitly
(VCV-io style) rather than as section variables; this avoids the
"variable not auto-inserted" footgun when a theorem mentions `g`/`hg` only
in its body. -/
noncomputable def equivOfHg (g : G) (hg : Function.Bijective (smulByG F G g)) :
    F ≃ G :=
  Equiv.ofBijective (smulByG F G g) hg

/-- Injectivity of scalar-multiplication by `g`, derived from `hg`. -/
theorem smul_inj_of_bij (g : G) (hg : Function.Bijective (smulByG F G g))
    {a b : F} (h : a • g = b • g) : a = b :=
  Function.Bijective.injective hg h

/-- Surjectivity of scalar-multiplication by `g`, derived from `hg`. -/
theorem smul_surj_of_bij (g : G) (hg : Function.Bijective (smulByG F G g))
    (P : G) : ∃ a : F, a • g = P :=
  Function.Bijective.surjective hg P

/-- The field and group have the same cardinality, derived from `hg`
(the bijection witnesses a bijection between `F` and `G`). -/
theorem card_F_eq_card_G (g : G) (hg : Function.Bijective (smulByG F G g)) :
    Fintype.card F = Fintype.card G :=
  Fintype.card_congr (equivOfHg F G g hg)

set_option linter.unusedSectionVars false in
/-- A field has at least two elements (`0 ≠ 1`). -/
theorem card_field_ge_two : 2 ≤ Fintype.card F := by
  have h : 1 < Fintype.card F := Fintype.one_lt_card (α := F)
  omega

/-- The generator `g` is non-zero under `hg`.

Proof: if `g = 0`, then `smulByG F G g a = a • 0 = 0` for all `a : F`, so the
map is the constant-zero function. A constant function is bijective only
if its codomain has exactly one element. But by `card_F_eq_card_G`,
`|G| = |F| ≥ 2`, contradiction. -/
theorem g_ne_zero_of_bij (g : G) (hg : Function.Bijective (smulByG F G g)) :
    g ≠ 0 := by
  intro hzero
  -- The map `smulByG F G g` is constant zero.
  have hconst : ∀ a : F, smulByG F G g a = (0 : G) := by
    intro a
    unfold smulByG
    rw [hzero, smul_zero]
  -- Hence the range of `smulByG F G g` is `{0}`.
  have himg_singleton : Set.range (smulByG F G g : F → G) = {0} := by
    ext x
    constructor
    · rintro ⟨a, ha⟩
      simp only [Set.mem_singleton_iff]
      rw [← ha, hconst a]
    · rintro rfl
      exact ⟨0, hconst 0⟩
  -- Bijective ⟹ surjective ⟹ range = univ.
  have hsurj := Function.Bijective.surjective hg
  have hrange_univ : Set.range (smulByG F G g : F → G) = Set.univ := by
    ext x
    constructor
    · intro _
      trivial
    · intro _
      obtain ⟨a, ha⟩ := hsurj x
      exact ⟨a, ha⟩
  -- So `{0} = univ`, meaning every element of `G` equals `0`.
  have hG_singleton : ∀ x : G, x = (0 : G) := by
    intro x
    have hx : x ∈ Set.range (smulByG F G g : F → G) := by
      rw [hrange_univ]; trivial
    rw [himg_singleton] at hx
    simp only [Set.mem_singleton_iff] at hx
    exact hx
  -- Hence `|G| = 1`.
  have hcard_G : Fintype.card G = 1 := by
    rw [Fintype.card_eq_one_iff]
    exact ⟨0, hG_singleton⟩
  -- But `|G| = |F| ≥ 2`. Rewrite `hcard_G` to mention `Fintype.card F`.
  rw [← card_F_eq_card_G F G g hg] at hcard_G
  have h2 : 2 ≤ Fintype.card F := card_field_ge_two F
  omega

set_option linter.unusedSectionVars false in
/-- `1 • g = g` (definitional, exposed for rewriting). -/
theorem one_smul_g (g : G) : (1 : F) • g = g := one_smul F g

set_option linter.unusedSectionVars false in
/-- `0 • g = 0` (definitional, exposed for rewriting). -/
theorem zero_smul_g (g : G) : (0 : F) • g = 0 := zero_smul F g

set_option linter.unusedSectionVars false in
/-- `a • g = b • g ↔ a = b` (iff form of injectivity). -/
theorem smul_g_inj_iff (g : G) (hg : Function.Bijective (smulByG F G g))
    (a b : F) : a • g = b • g ↔ a = b :=
  ⟨fun h => Function.Bijective.injective hg h, fun h => h ▸ rfl⟩

end PokerProtocolLean.Foundations
