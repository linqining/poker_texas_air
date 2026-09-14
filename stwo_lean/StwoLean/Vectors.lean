import StwoLean.M31
import StwoLean.CM31
import StwoLean.QM31
import StwoLean.Circle
import StwoLean.Poseidon252
import StwoLean.Channel
import StwoLean.Merkle
import StwoLean.FriCore
import StwoLean.FriVerifier

/-!
# Vectors — 从真实 stwo 2.3.0 导出的对拍测试向量

**本文件由 `vector-gen` 自动生成，勿手改。**
重新生成：`cd vector-gen && cargo run --release > ../StwoLean/Vectors.lean`。

每个 `example` 都是 Lean 数学模型与 Rust 生产实现（位技巧优化）
之间的逐算子一致性断言，由内核 `decide` 机器检验。
-/

namespace StwoLean.Vectors

section M31
example : ((0) : StwoLean.M31) + ((0) : StwoLean.M31) = ((0) : StwoLean.M31) := by decide
example : ((0) : StwoLean.M31) * ((0) : StwoLean.M31) = ((0) : StwoLean.M31) := by decide
example : ((1) : StwoLean.M31) + ((2147483646) : StwoLean.M31) = ((0) : StwoLean.M31) := by decide
example : ((1) : StwoLean.M31) * ((2147483646) : StwoLean.M31) = ((2147483646) : StwoLean.M31) := by decide
example : ((2147483646) : StwoLean.M31) + ((2147483646) : StwoLean.M31) = ((2147483645) : StwoLean.M31) := by decide
example : ((2147483646) : StwoLean.M31) * ((2147483646) : StwoLean.M31) = ((1) : StwoLean.M31) := by decide
example : ((2147483645) : StwoLean.M31) + ((2) : StwoLean.M31) = ((0) : StwoLean.M31) := by decide
example : ((2147483645) : StwoLean.M31) * ((2) : StwoLean.M31) = ((2147483643) : StwoLean.M31) := by decide
example : ((658379680) : StwoLean.M31) + ((2005472711) : StwoLean.M31) = ((516368744) : StwoLean.M31) := by decide
example : ((658379680) : StwoLean.M31) * ((2005472711) : StwoLean.M31) = ((505618109) : StwoLean.M31) := by decide
example : ((2147483645) : StwoLean.M31) - ((2) : StwoLean.M31) = ((2147483643) : StwoLean.M31) := by decide
example : ((1) : StwoLean.M31) * ((1) : StwoLean.M31) = 1 := by decide
example : ((19) : StwoLean.M31) * ((1017229096) : StwoLean.M31) = 1 := by decide
example : ((2147483646) : StwoLean.M31) * ((2147483646) : StwoLean.M31) = 1 := by decide
example : ((1689888529) : StwoLean.M31) * ((1978499458) : StwoLean.M31) = 1 := by decide
example : StwoLean.fpow ((19) : StwoLean.M31) 2147483645 = ((1017229096) : StwoLean.M31) := by decide
example : StwoLean.fpow ((1736831287) : StwoLean.M31) 2147483645 = ((1309325586) : StwoLean.M31) := by decide
end M31

section CM31
example : (StwoLean.CM31.ofU32 1 2) + (StwoLean.CM31.ofU32 4 5) = (StwoLean.CM31.ofU32 5 7) := by decide
example : (StwoLean.CM31.ofU32 1 2) * (StwoLean.CM31.ofU32 4 5) = (StwoLean.CM31.ofU32 2147483641 13) := by decide
example : -(StwoLean.CM31.ofU32 1 2) = (StwoLean.CM31.ofU32 2147483646 2147483645) := by decide
example : (StwoLean.CM31.ofU32 1 2) - (StwoLean.CM31.ofU32 4 5) = (StwoLean.CM31.ofU32 2147483644 2147483644) := by decide
example : (StwoLean.CM31.ofU32 1 2) * (StwoLean.CM31.ofU32 858993459 429496729) = StwoLean.CM31.ofU32 1 0 := by decide
example : (StwoLean.CM31.ofU32 1542279440 570279962) * (StwoLean.CM31.ofU32 1177963392 398107358) = (StwoLean.CM31.ofU32 1464850980 141031886) := by decide
example : (StwoLean.CM31.ofU32 1542279440 570279962) * (StwoLean.CM31.ofU32 911274020 2020037253) = StwoLean.CM31.ofU32 1 0 := by decide
example : (StwoLean.CM31.ofU32 1303023273 273674159) * (StwoLean.CM31.ofU32 1514296755 935994624) = (StwoLean.CM31.ofU32 169845393 2011871472) := by decide
example : (StwoLean.CM31.ofU32 1303023273 273674159) * (StwoLean.CM31.ofU32 1256134572 560394017) = StwoLean.CM31.ofU32 1 0 := by decide
end CM31

section QM31
example : (StwoLean.QM31.ofU32 1 2 3 4) + (StwoLean.QM31.ofU32 4 5 6 7) = (StwoLean.QM31.ofU32 5 7 9 11) := by decide
example : (StwoLean.QM31.ofU32 1 2 3 4) * (StwoLean.QM31.ofU32 4 5 6 7) = (StwoLean.QM31.ofU32 2147483576 93 2147483631 50) := by decide
example : -(StwoLean.QM31.ofU32 1 2 3 4) = (StwoLean.QM31.ofU32 2147483646 2147483645 2147483644 2147483643) := by decide
example : (StwoLean.QM31.ofU32 1 2 3 4) - (StwoLean.QM31.ofU32 4 5 6 7) = (StwoLean.QM31.ofU32 2147483644 2147483644 2147483644 2147483644) := by decide
example : (StwoLean.QM31.ofU32 1 2 3 4) * (StwoLean.QM31.ofU32 1855247052 856841008 1588674294 1863525709) = StwoLean.QM31.ofU32 1 0 0 0 := by decide
example : (StwoLean.QM31.ofU32 1304364711 941764839 774059002 354159035) * (StwoLean.QM31.ofU32 1159129443 2026488914 1075264964 2115462971) = (StwoLean.QM31.ofU32 423997707 381858373 1162635438 470508628) := by decide
example : (StwoLean.QM31.ofU32 1304364711 941764839 774059002 354159035) * (StwoLean.QM31.ofU32 1465808710 484095427 616320133 1651127605) = StwoLean.QM31.ofU32 1 0 0 0 := by decide
example : (StwoLean.QM31.ofU32 905178396 1618186601 349993170 771270275) * (StwoLean.QM31.ofU32 1471489169 1940097930 1600043701 81400831) = (StwoLean.QM31.ofU32 1520950909 1404132381 847032932 748600897) := by decide
example : (StwoLean.QM31.ofU32 905178396 1618186601 349993170 771270275) * (StwoLean.QM31.ofU32 921202508 1650776027 1083991534 352331712) = StwoLean.QM31.ofU32 1 0 0 0 := by decide
end QM31

section Circle
example : StwoLean.CirclePoint.repeatedDouble StwoLean.CirclePoint.m31Gen 1 = (StwoLean.CirclePoint.mk 7 777079998) := by decide
example : StwoLean.CirclePoint.repeatedDouble StwoLean.CirclePoint.m31Gen 3 = (StwoLean.CirclePoint.mk 18817 1720333214) := by decide
example : StwoLean.CirclePoint.repeatedDouble StwoLean.CirclePoint.m31Gen 7 = (StwoLean.CirclePoint.mk 212706801 1223819887) := by decide
example : StwoLean.CirclePoint.repeatedDouble StwoLean.CirclePoint.m31Gen 31 = (StwoLean.CirclePoint.mk 1 0) := by decide
example : StwoLean.CirclePoint.doubleX (((18817) : StwoLean.M31)) = (((708158977) : StwoLean.M31)) := by decide
example : StwoLean.CirclePoint.repeatedDouble StwoLean.CirclePoint.secureGen 2 = (StwoLean.CirclePoint.mk (StwoLean.QM31.ofU32 817765750 925291496 1037538637 438192810) (StwoLean.QM31.ofU32 1827512253 368970720 1706228210 1144879786)) := by decide
end Circle

section PoseidonChannel

-- 本节向量依赖 251-bit 域上的 91 轮 Hades 排列，内核
-- `decide` 求值过慢，统一用 `native_decide`（编译器求值）。
-- 信任模型说明见 README「分层信任模型」。

theorem hadesVec1 : StwoLean.hades ((1 : Fp252), 2, 3) = (((0xfa8c9b6742b6176139365833d001e30e932a9bf7456d009b1b174f36d558c5) : StwoLean.Fp252), ((0x4f04deca4cb7f9f2bd16b1d25b817ca2d16fba2151e4252a2e2111cde08bfe6) : StwoLean.Fp252), ((0x58dde0a2a785b395ee2dc7b60b79e9472ab826e9bb5383a8018b59772964892) : StwoLean.Fp252)) := by native_decide
theorem poseidonHashVec1 : StwoLean.poseidonHash 1 2 = ((0x5d44a3decb2b2e0cc71071f7b802f45dd792d064f0fc7316c46514f70f9891a) : StwoLean.Fp252) := by native_decide
theorem poseidonHashManyVec1 : StwoLean.poseidonHashMany [1, 2, 3, 4, 5] = ((0x159f4ab3b9bdc95a6a4a9ffb36456ad33290ea1fa809e0445bc449b0ad62da4) : StwoLean.Fp252) := by native_decide
theorem chMixU64Golden : StwoLean.Channel.mixU64 1229801703532086340 StwoLean.Channel.chInit = (((0x7cecc0ee3d858c843fe63165f038353f9f80f52dd8d32eead9f635e2f7d8b8e) : StwoLean.Fp252), 0) := by native_decide
theorem chMixU32sGolden : StwoLean.Channel.mixU32s [1, 2, 3, 4, 5, 6, 7, 8, 9] StwoLean.Channel.chInit = (((0x6c7fc11690eb272bcc81115e801ad52de4e6271ddff3f97a2b75315e3572ced) : StwoLean.Fp252), 0) := by native_decide
theorem chDrawU32sVec1 : (StwoLean.Channel.drawU32s StwoLean.Channel.chInit).1 = [886766026, 477679824, 3218540027, 1381728512, 24873733, 2344250857, 2336456258] := by native_decide
theorem chDrawSecureFeltVec1 : (StwoLean.Channel.drawSecureFelt (StwoLean.Channel.drawU32s StwoLean.Channel.chInit).2).1 = (StwoLean.QM31.ofU32 312597656 1594801172 461670550 671872323) := by native_decide
theorem chMixFeltsVec1 : StwoLean.Channel.mixFelts [StwoLean.Channel.qm31l 1923782, StwoLean.Channel.qm31l 1923783, StwoLean.Channel.qm31l 1923784] StwoLean.Channel.chInit = (((0x541a3b2e6cba2eda9576eca1d9b5c0b065521fda524c19eb04ccee42c45bc4d) : StwoLean.Fp252), 0) := by native_decide

end PoseidonChannel

section MerkleFri

example : StwoLean.Merkle.hashNode none [0, 1] = ((0x695fd120c149eb1f8be341835c963d6495fa6f07ba94685b294237b66764fb6) : StwoLean.Fp252) := by native_decide
example : StwoLean.Merkle.hashNode (some (((1) : StwoLean.Fp252), ((2) : StwoLean.Fp252))) [3] = ((0x743dd3193288bcbdbacccff636c35fe38ecc4fe69695a18d5b98ab9f21060de) : StwoLean.Fp252) := by native_decide
example : StwoLean.Merkle.verifyPath [2, 3] 1 [((0x695fd120c149eb1f8be341835c963d6495fa6f07ba94685b294237b66764fb6) : StwoLean.Fp252)] ((0x1d3f3c72ac3968634baedc1f7b1c0f02bc773e5e1ca3b83d0d2f062aa8eb2b5) : StwoLean.Fp252) = true := by native_decide
example : StwoLean.FriCore.ibutterfly (StwoLean.QM31.ofU32 336903605 1241316556 391647168 1456584050) (StwoLean.QM31.ofU32 635819733 358962873 1361802904 242716099) (554556338) = ((StwoLean.QM31.ofU32 972723338 1600279429 1753450072 1699300149), (StwoLean.QM31.ofU32 1357140340 1007649970 1377890963 338976832)) := by decide
example : StwoLean.FriCore.foldPair (StwoLean.QM31.ofU32 336903605 1241316556 391647168 1456584050) (StwoLean.QM31.ofU32 635819733 358962873 1361802904 242716099) (554556338) (StwoLean.QM31.ofU32 1589253648 185127011 1224774538 1562843519) = (StwoLean.QM31.ofU32 972723338 1600279429 1753450072 1699300149) + (StwoLean.QM31.ofU32 1589253648 185127011 1224774538 1562843519) * (StwoLean.QM31.ofU32 1357140340 1007649970 1377890963 338976832) := by decide
example : StwoLean.FriVerifier.friVerify
    { roots := [((0x3a1d66b920b71a51e9e4c711e306a50dc80182530215dccae20ee1b51a3cb56) : StwoLean.Fp252), ((0x3d82d9512dacc5718c20392f16f86400ff168f1486c46a5513a543fb5a3afbc) : StwoLean.Fp252), ((0x44b82e11b36a34ab1f98051e3877392ab4e968e67e0fb3b4e050086ca702243) : StwoLean.Fp252)], alphas := [(StwoLean.QM31.ofU32 685525509 849565931 666312783 106264701), (StwoLean.QM31.ofU32 1891530921 473222300 2100978939 576114068), (StwoLean.QM31.ofU32 957614543 406636750 860736942 843383240)], lastPoly := [(StwoLean.QM31.ofU32 648235255 825979531 589328773 1941393369)], initialDomain := LineDomain.ofCoset (Coset.mk' 1 3), initialLogSize := 3 }
    5 (StwoLean.QM31.ofU32 1914695756 1121091745 2131163423 2041550243) [        { evalSelf := (StwoLean.QM31.ofU32 1914695756 1121091745 2131163423 2041550243), evalSibling := (StwoLean.QM31.ofU32 2099068665 1677531867 1572311425 964812412), pathSelf := [((0x5d3b8928089e352545e7d75d84ae4c8529f56b4d553bab9c5c6b83934f50a41) : StwoLean.Fp252), ((0x6a2085d5e3f64fc437e9ca29c525a156d266ae9b639e13ed1e2125b79a6c0c6) : StwoLean.Fp252), ((0x1a6db00bb77ad26f0e3b25e46901d6bbb4b464397d1bf097e4f9bd097e56780) : StwoLean.Fp252)], pathSibling := [((0x5ba5d1a69dbafc772bd973820e802a12f51980ef023f679487b2de2ca9ea92e) : StwoLean.Fp252), ((0x1e3f5d4b916449f633bb773fda0d9242b347c9275d1518030ed75bf44e00309) : StwoLean.Fp252), ((0x368b0bd9bdbc30ce5302e558e5c27da2a579b3a2aa49e4a3d44dd8041484987) : StwoLean.Fp252)] },
             { evalSelf := (StwoLean.QM31.ofU32 677499634 1482027059 1942397881 1233417706), evalSibling := (StwoLean.QM31.ofU32 848433249 1718747303 404605204 1373246759), pathSelf := [((0x6d03efcfed7beb3f763a591e314a6565ddb4881b666092f15941162626f1127) : StwoLean.Fp252), ((0x663500bc8b8cd27f272aae6d59f4b461e49d245770911c3cb766dc4064bd7b0) : StwoLean.Fp252)], pathSibling := [((0x69e83a67f82fb485aa51a05d5b34c791ae3df1f138269f9cf300afc980a75a8) : StwoLean.Fp252), ((0x861e4031f02bbb624006807ea621179b8a2782296edcbad4d844dadbeb35c6) : StwoLean.Fp252)] },
             { evalSelf := (StwoLean.QM31.ofU32 220290302 787659458 1018422525 278576806), evalSibling := (StwoLean.QM31.ofU32 128959394 1409572010 279082117 1416859130), pathSelf := [((0x200999b3d13ba78a72d9c3e6c902e8894c16978b358cc328e8d2ae190f27e7f) : StwoLean.Fp252)], pathSibling := [((0x3d96d52149caa6a2a24db9b18ae3825bf66cfd1756c5c6c45860b2a3d642812) : StwoLean.Fp252)] }] = true := by native_decide

end MerkleFri

end StwoLean.Vectors
