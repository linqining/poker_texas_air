import Mathlib
import StwoLean.QM31

/-!
# FriCore — FRI 折叠验证的核心方程

对应 stwo 2.3.0 `core/fri.rs`（`fold_line` / `fold_coset`）与
`core/fft.rs`（`ibutterfly`）。这是 FriLayer::verify_and_fold 每层
执行的验证内核：给定同一域点 `x` 与 `-x` 处的多项式求值对
`(f(x), f(-x))` 与折叠随机系数 `α`，重算折叠后的上层求值。

数学含义：把 `f` 分解为偶部 `g` 与奇部 `h`
（`f(y) = g(y²) + y·h(y²)`），在 `y = x` 处：

* `ibutterfly(f(x), f(-x), x⁻¹)` 的两分量恰为 `g(x²)` 与 `h(x²)`
  （即 `(f(x)+f(-x), (f(x)-f(-x))·x⁻¹)`）；
* 折叠 `g(x²) + α·h(x²)` 即系数为 `α` 的新多项式在同一位置的求值。

多层 FRI 即对每层以新的 `α` 重复此步骤；验证器只需核对 witness
求值对按此方程折叠出的值与上层承诺的打开值一致。

`x⁻¹` 为 M31 域元素（circle domain 的 x 坐标在 M31 上），
`α`、求值为 QM31（安全域）。`fold_pair` 数值行为由 vector-gen 从
stwo `fold_line` 导出的向量钉死。
-/

namespace StwoLean

namespace FriCore

/-- `fft::ibutterfly`：`(v0 + v1, (v0 - v1) · itwid)`，
`itwid` 为 M31 域元素（此处是域点逆 `x⁻¹`）。 -/
def ibutterfly (v0 v1 : QM31) (itwid : M31) : QM31 × QM31 :=
  (v0 + v1, QM31.mulM31 (v0 - v1) itwid)

/-- `fold_line` 单对折叠：`(f(x), f(-x))` 与 `x⁻¹`、系数 `α`
→ 上层求值 `g + α·h`。注意 bit-reverse 域排列下 ibutterfly 输出本身
携带 2 倍（`f(x)+f(-x) = 2g(x²)`），无需再乘 2——**曾在此多加因子 2
导致 friVerify 对拍失败**，数值向量当场抓获。 -/
def foldPair (fx fnx : QM31) (xInv : M31) (alpha : QM31) : QM31 :=
  let (g, h) := ibutterfly fx fnx xInv
  g + alpha * h

end FriCore

end StwoLean
