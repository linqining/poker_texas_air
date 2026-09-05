import AirsLean.Foundations.M31
import AirsLean.Foundations.Limbs
import AirsLean.Foundations.CarryArith
import AirsLean.Foundations.TraceModel

/-! # Foundations

Import root for the arithmetic and trace-model layer: the M31 prime field,
the 4×16-bit limb encoding used by every Texas Poker AIR, the ripple-carry
arithmetic that carries u64 semantics through the M31 trace, and the abstract
trace / constraint-satisfaction model on which all soundness statements rest.
-/
