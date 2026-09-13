import Lake
open Lake DSL

package stwo_lean where
  leanOptions := #[
    ⟨`pp.unicode, true⟩,
    ⟨`maxHeartbeats, 5120000⟩,
    ⟨`maxRecDepth, 1024⟩,
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩
  ]

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.32.0"

@[default_target]
lean_lib StwoLean where
  roots := #[`StwoLean]
