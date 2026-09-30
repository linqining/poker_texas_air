import Mathlib

/-!
# KeyAgg — 手级聚合签名（MuSig2/BDN 形状）的 rogue-key 代数（属性 P3）

设计选型（任务书「■ 构造选型」）：每手 roster（2-8 人）对
「结算语句 digest + action_log_digest」联合签名，验证方程与单 Schnorr 同形：

    z̄·G = R̄ + c·P̄,   P̄ = Σ μ_i·pk_i,   μ_i = poseidon([L_label, roster_digest, pk_x, pk_y])

**模型（如实声明）**：指数模型 —— 群元素以其离散对数表示（ZMod n 环的加法群）。
对 keyagg 的**线性恒等式**（点加 / 标量乘 / 聚合方程）该模型是忠实的；
「攻击者只能计算公开点、不知道他人 dlog」的知识不对称性不是纯代数事实，
由 Rust 侧真实 Stark 曲线 proptest（fold_formal_props.rs）与文献归约补充。
Stark 曲线群阶 `n = 0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f`
为素数（stark_curve.rs:44-45，曲线参数文献事实）；本文件对任意素数阶证明。

为规避任意元 zip 展开的从样复杂性，二元情形 `keyagg2` 显式给出——它是
一般 `P̄ = Σ μ_i·pk_i` 的最小非平凡特例（roster = {诚实钥, 攻击钥} 正是
rogue-key 攻击的临界形状；n 元情形由同一线性代数逐项推广）。

机器可证命题：

1. **P3-负例（无系数聚合被无条件攻破）**：μ ≡ 1 时 `pk_a := Ā − pk_h`
   （纯公开点加法，无需任何 dlog）使聚合钥命中攻击者自选目标 Ā。
2. **P3-系数条件（BDN 形状）**：给定系数 μh、μa ≠ 0，`keyagg = Ā` ⇔
   `pk_a` 是 `μa·pk_a = Ā − μh·pk_h` 的解——而设计要求 `μa = RO(L, pk_a)`
   随 pk_a 变动，攻击退化为哈希不动点（ROM 中概率可忽略）。
   系数为 0 则诚实钥被无条件消去 ⇒ μ_i ≠ 0 必要。
3. **P3-PoP 防御代数核**：μh ≠ 0 时 rogue 方程 `μh·x_h + μa·x_a = a`
   对诚实私钥 x_h 的解唯一 ⇒ PoP（注册时证明知道 x_a）下攻击者只能期望
   唯一的诚实钥命中（概率层 1/n 为文字论证，n 为群阶）。
4. **P3/P5-完备性代数核**：全体 dlog 已知（PoP 注册面）时
   `z̄ = r + c·xbar` 必过验证方程；且 (R̄, c, xbar) 唯一决定 z̄
   （电路单方程的 soundness 形状——z̄ 无自由度）。
-/

namespace AirsLean.Fold.KeyAgg

-- 群阶素性：Stark 曲线群阶为素数（stark_curve.rs:44-45）。
variable {n : ℕ} [Fact (Nat.Prime n)]

/-- **keyagg（BDN 系数形状，二元临界情形）**：`P̄ = μh·pk_h + μa·pk_a`。
    生产公式的系数来自 RO：`μ_i = poseidon([L_label, roster_digest, pk_x, pk_y])`。 -/
def keyagg2 (μh μa pk_h pk_a : ZMod n) : ZMod n :=
  μh * pk_h + μa * pk_a

/-- **P3-负例（无系数聚合 = rogue-key / key cancellation 无条件成立）**：
    μ ≡ 1 时，`pk_a := Ā − pk_h` 由公开点直接可算，聚合钥命中攻击者自选的
    Ā。这是设计必须带 BDN 系数 + PoP 注册面的原因
    （任务书 security 节「注册面」条目、risks 5）。 -/
theorem naive_rogue (pk_h Ā : ZMod n) :
    keyagg2 1 1 pk_h (Ā - pk_h) = Ā := by
  simp only [keyagg2]
  ring

/-- **P3-BDN（rogue 退化为哈希不动点）**：固定系数 μh、μa ≠ 0 下，
    `keyagg2 μh μa pk_h pk_a = Ā` ⇔ `pk_a = μa⁻¹·(Ā − μh·pk_h)`。
    生产公式的 μa = RO(L, pk_a) 依赖 pk_a 本身，故命中需解不动点——
    ROM 中概率可忽略。proptest（fold_formal_props.rs）在真实曲线上做
    候选点搜索，0 命中。 -/
theorem bdn_rogue_iff_fixed_point {μa : ZMod n} (hμa : μa ≠ 0)
    (μh pk_h pk_a Ā : ZMod n) :
    keyagg2 μh μa pk_h pk_a = Ā ↔ pk_a = μa⁻¹ * (Ā - μh * pk_h) := by
  constructor
  · intro h
    simp only [keyagg2] at h
    rw [eq_inv_mul_iff_mul_eq₀ hμa]
    linear_combination h
  · intro h
    simp only [keyagg2]
    rw [h]
    field_simp
    ring

/-- **P3-系数非零必要性**：诚实钥系数为 0 时聚合钥与诚实钥完全无关——
    诚实钥被无条件消去。故 μ_i = RO(L, pk_i) 必须以非零为期望
    （为零的概率 1/n 可忽略），且电路侧若重建 P̄ 必须拒绝零系数槽。 -/
theorem zero_coeff_cancels_honest_key (μa pk_h pk_h' pk_a : ZMod n) :
    keyagg2 0 μa pk_h pk_a = keyagg2 0 μa pk_h' pk_a := by
  simp only [keyagg2]
  ring

/-- **P3-PoP 防御代数核**：μh ≠ 0 时，rogue 方程 `μh·x_h + μa·x_a = a`
    对诚实私钥 x_h 的解唯一（= μh⁻¹·(a − μa·x_a)）。PoP 注册面下攻击者
    必须知道自选钥的 x_a（否则注册被拒），方程把可命中的诚实钥钉到单点
    ——命中概率 1/n（n 为 251-bit 量级群阶）为文字论证层。 -/
theorem rogue_solution_unique {μh : ZMod n} (hμh : μh ≠ 0)
    (μa x_a a x_h : ZMod n) :
    (μh * x_h + μa * x_a = a) ↔ (x_h = μh⁻¹ * (a - μa * x_a)) := by
  constructor
  · intro h
    rw [eq_inv_mul_iff_mul_eq₀ hμh]
    linear_combination h
  · intro h
    rw [h]
    field_simp
    ring

/-- **P3/P5-诚实路径代数完备性**：z̄ = r + c·xbar 的聚合签名必过验证方程
    `z̄·G = R̄ + c·P̄`（指数模型；真实曲线对应物由 proptest
    `p5_honest_aggregate_*` 在 2/5/8 人 roster 上实跑确认）。 -/
theorem honest_sig_verifies (r c xbar gg : ZMod n) :
    (r + c * xbar) * gg = r * gg + c * (xbar * gg) := by
  ring

/-- **P3-验证方程 z̄ 唯一性（电路单方程的 soundness 形状）**：
    生成元非零时，(R̄, c, xbar) 唯一决定 z̄——电路内 c 由 poseidon 重算
    （prover 无自由度）后，通过方程的 z̄ 无第二个取值。 -/
theorem z_unique {gg : ZMod n} (hgg : gg ≠ 0) {z z' r c xbar : ZMod n}
    (h : z * gg = r * gg + c * (xbar * gg)) (h' : z' * gg = r * gg + c * (xbar * gg)) :
    z = z' := by
  apply mul_right_cancel₀ hgg
  rw [h, h']

/-- **P3-诚实钥敏感性**：μh ≠ 0 时，任一诚实钥 dlog 变动必改聚合钥 dlog
    （keyagg 对每个带非零系数的成员键敏感——诚实钥无法被悄悄替换）。 -/
theorem keyagg_sensitive {μh : ZMod n} (hμh : μh ≠ 0) (μa x_h x_h' x_a : ZMod n)
    (hx : x_h ≠ x_h') :
    μh * x_h + μa * x_a ≠ μh * x_h' + μa * x_a := by
  intro heq
  exact hx (mul_left_cancel₀ hμh (by linear_combination heq))

end AirsLean.Fold.KeyAgg
