import StwoLean.M31
import StwoLean.CM31
import StwoLean.QM31
import StwoLean.Circle

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

end StwoLean.Vectors
