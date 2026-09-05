/-
# AirsLean

Lean 4 + Mathlib audit formalisation of the AIR constraint layer in
`poker_texas_air/src/airs` (19 method AIRs + composition components) and
`src/texas_canonical_air.rs`.

Three top-level propositions:

1. **Censorship resistance** (`AirsLean.Censorship.*`)
2. **Constraint soundness** (`AirsLean.Soundness.*`)
3. **No user escape from settlement** (`AirsLean.Custody.*`)

See `src/airs_lean/PLAN.md` for the full plan and `AirsLean.Top.Audit` for the
top-level synthesis theorems and assumption registry.
-/
import AirsLean.Foundations
import AirsLean.Soundness
import AirsLean.Custody
import AirsLean.Censorship
import AirsLean.Top
