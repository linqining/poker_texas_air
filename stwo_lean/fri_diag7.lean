import StwoLean.FriVerifier
open StwoLean
-- rust DIAG: g = [1866280774, 651139965, 1555991201, 858879008], h = [873524623, 423327480, 347394528, 1224101292]
-- gh = [677499634, 1482027059, 1942397881, 1233417706]
def fe : QM31 := QM31.ofU32 2099068665 1677531867 1572311425 964812412
def fo : QM31 := QM31.ofU32 1914695756 1121091745 2131163423 2041550243
def a0 : QM31 := QM31.ofU32 685525509 849565931 666312783 106264701
-- Lean foldPair（无因子 2）应 = DIAG gh
#eval (FriCore.foldPair fo fe 1334560213 a0).c0.re.val
#eval (FriCore.foldPair fo fe 1334560213 a0).c0.im.val
#eval (FriCore.foldPair fo fe 1334560213 a0).c1.re.val
#eval (FriCore.foldPair fo fe 1334560213 a0).c1.im.val
#eval (FriCore.foldPair fe fo 1334560213 a0).c0.re.val
#eval (FriCore.foldPair fe fo 1334560213 a0).c1.re.val
