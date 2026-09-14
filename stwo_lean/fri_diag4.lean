import StwoLean.FriVerifier
open StwoLean
def w1 : FriVerifier.FriLayerWitness := {
  evalSelf := QM31.ofU32 677499634 1482027059 1942397881 1233417706,
  evalSibling := QM31.ofU32 848433249 1718747303 404605204 1373246759,
  pathSelf := [((0x36a02fcd8d30d844e618779d406219016a0ce7e7b515ae105074e748350e7d2) : Fp252),
               ((0x861e4031f02bbb624006807ea621179b8a2782296edcbad4d844dadbeb35c6) : Fp252)],
  pathSibling := [((0x69e83a67f82fb485aa51a05d5b34c791ae3df1f138269f9cf300afc980a75a8) : Fp252),
                  ((0x861e4031f02bbb624006807ea621179b8a2782296edcbad4d844dadbeb35c6) : Fp252)]
}
def dom1 : LineDomain := LineDomain.ofCoset (Coset.mk' 2 2)
def a1 : QM31 := QM31.ofU32 1891530921 473222300 2100978939 576114068
def root1 : Fp252 := 0x1738892109345218771609704745963840182174163536449983405088587745559178358716
-- 域点（应与 fold_line 第 1 层 i=1 的 x 一致）
#eval (LineDomain.at dom1 (bitReverseIndex 2 2)).val
#eval (FriVerifier.inverseM31 (LineDomain.at dom1 (bitReverseIndex 2 2))).val
-- 叶哈希
#eval (Merkle.hashNode none (FriVerifier.qm31ToM31s w1.evalSelf)).val
#eval (Merkle.hashNode none (FriVerifier.qm31ToM31s w1.evalSibling)).val
-- pathSelf/pathSibling 首项对照
#eval w1.pathSelf 2>/dev/null || true
