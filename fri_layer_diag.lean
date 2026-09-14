import StwoLean.FriVerifier
open StwoLean

-- 最新 Vectors.lean 断言数据
def root0 : Fp252 := 0x1642880796991927949565382477910301030680383986305878659501022631151450442582
def root1 : Fp252 := 0x1738892109345218771609704745963840182174163536449983405088587745559178358716
def a0 : QM31 := QM31.ofU32 685525509 849565931 666312783 106264701
def dom0 : LineDomain := LineDomain.ofCoset (Coset.mk' 1 3)
def w0 : FriVerifier.FriLayerWitness := {
  evalSelf := QM31.ofU32 1914695756 1121091745 2131163423 2041550243,
  evalSibling := QM31.ofU32 2099068665 1677531867 1572311425 964812412,
  pathSelf := [((0x5d3b8928089e352545e7d75d84ae4c8529f56b4d553bab9c5c6b83934f50a41) : Fp252),
               ((0x6a2085d5e3f64fc437e9ca29c525a156d266ae9b639e13ed1e2125b79a6c0c6) : Fp252),
               ((0x1a6db00bb77ad26f0e3b25e46901d6bbb4b464397d1bf097e4f9bd097e56780) : Fp252)],
  pathSibling := [((0x2fd7d9414a7a27ad39f9eec1c321be464c448548123e6c94251b8c64775e947) : Fp252),
                  ((0x6a2085d5e3f64fc437e9ca29c525a156d266ae9b639e13ed1e2125b79a6c0c6) : Fp252),
                  ((0x1a6db00bb77ad26f0e3b25e46901d6bbb4b464397d1bf097e4f9bd097e56780) : Fp252)]
}

-- 1. 域点（rust DIAG: 697879444）
#eval (LineDomain.at dom0 (bitReverseIndex 4 3)).val
-- 2. evalSelf 叶哈希（向量 pathSelf[0] 的兄弟链首项应为 evalSibling 叶）
#eval (Merkle.hashNode none (FriVerifier.qm31ToM31s w0.evalSelf)).val
#eval (Merkle.hashNode none (FriVerifier.qm31ToM31s w0.evalSibling)).val
-- 3. pathSelf/pathSibling 首项
#eval w0.pathSelf.head!
#eval w0.pathSibling.head!
-- 4. pathRoot 两个方向的核对
#eval Merkle.pathRoot (Merkle.hashNode none (FriVerifier.qm31ToM31s w0.evalSelf)) (bitReverseIndex 5 3) w0.pathSelf == root0
#eval Merkle.pathRoot (Merkle.hashNode none (FriVerifier.qm31ToM31s w0.evalSibling)) (bitReverseIndex 4 3) w0.pathSibling == root0
-- 5. 单层验证
#eval (FriVerifier.friLayerVerifyAndFold root0 dom0 3 5 a0 w0).isSome
-- 6. 折叠输出
#eval (match FriVerifier.friLayerVerifyAndFold root0 dom0 3 5 a0 w0 with
  | some (_, f) => f.c0.re.val
  | none => 0)
