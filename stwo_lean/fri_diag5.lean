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
def w2 : FriVerifier.FriLayerWitness := {
  evalSelf := QM31.ofU32 220290302 787659458 1018422525 278576806,
  evalSibling := QM31.ofU32 128959394 1409572010 279082117 1416859130,
  pathSelf := [((0x200999b3d13ba78a72d9c3e6c902e8894c16978b358cc328e8d2ae190f27e7f) : Fp252)],
  pathSibling := [((0x3d96d52149caa6a2a24db9b18ae3825bf66cfd1756c5c6c45860b2a3d642812) : Fp252)]
}
def dom1 : LineDomain := LineDomain.ofCoset (Coset.mk' 2 2)
def a1 : QM31 := QM31.ofU32 1891530921 473222300 2100978939 576114068
def root1 : Fp252 := 0x1738892109345218771609704745963840182174163536449983405088587745559178358716
def a2 : QM31 := QM31.ofU32 957614543 406636750 860736942 843383240
def root2 : Fp252 := 0x1942668220070435846743912071852295635172847444920500976407961633873407779395
-- 第 1 层 merkle
#eval Merkle.pathRoot (Merkle.hashNode none (FriVerifier.qm31ToM31s w1.evalSelf)) 2 w1.pathSelf == root1
#eval Merkle.pathRoot (Merkle.hashNode none (FriVerifier.qm31ToM31s w1.evalSibling)) 3 w1.pathSibling == root1
-- 第 1 层折叠输出（应 = layers[2][1] = [220290302, 787659458, 1018422525, 278576806]）
#eval (FriCore.foldPair w1.evalSelf w1.evalSibling (FriVerifier.inverseM31 (LineDomain.at dom1 (bitReverseIndex 2 2))) a1).c0.re.val
#eval (FriCore.foldPair w1.evalSelf w1.evalSibling (FriVerifier.inverseM31 (LineDomain.at dom1 (bitReverseIndex 2 2))) a1).c0.im.val
-- 第 2 层 merkle
#eval Merkle.pathRoot (Merkle.hashNode none (FriVerifier.qm31ToM31s w2.evalSelf)) 1 w2.pathSelf == root2
#eval Merkle.pathRoot (Merkle.hashNode none (FriVerifier.qm31ToM31s w2.evalSibling)) 0 w2.pathSibling == root2
-- 第 2 层折叠输出（应 = layers[3][0] = [648235255, 825979531, 589328773, 1941393369]）
#eval (FriCore.foldPair w2.evalSelf w2.evalSibling (FriVerifier.inverseM31 (LineDomain.at (LineDomain.ofCoset (Coset.mk' 4 1)) (bitReverseIndex 0 1))) a2).c0.re.val
#eval (FriCore.foldPair w2.evalSelf w2.evalSibling (FriVerifier.inverseM31 (LineDomain.at (LineDomain.ofCoset (Coset.mk' 4 1)) (bitReverseIndex 0 1))) a2).c0.im.val
-- 末层检查
#eval (FriVerifier.polyEvalQM31 [QM31.ofU32 648235255 825979531 589328773 1941393369] (QM31.ofU32 (LineDomain.at (LineDomain.ofCoset (Coset.mk' 8 0)) (bitReverseIndex 0 0)).val 0 0 0)).c0.a.val
