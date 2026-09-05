import AirsLean.Censorship.DigestBinding

/-!
# Assumptions — 显式假设登记表

全部非证明论假设集中于此。每条假设标注：内容、使用它的定理、Rust/链上
对应物与验证状态。除本文件与 `DigestBinding` 的两条抗碰撞公理外，
AirsLean 不引入任何额外 `axiom`/`sorry`。

| 假设 | 内容 | 使用方 | 对应物 | 状态 |
| --- | --- | --- | --- | --- |
| STARK 忠实性 | `Sat cs t` 是 Rust evaluator 约束的忠实模型 | 全部 Soundness/Custody | `src/airs/*.rs` 的 `EvalAtRow` 约束表达式 | 审计义务项：逐条对照（PLAN §0） |
| Stwo soundness | FRI/承诺绑定成立（trace 被证明 = trace 满足约束） | 链上验证语义 | Stwo prover/verifier | 库外部假设 |
| EUF-CMA | `Authentic`：验签通过 ⇒ 由持 sk 方签名 | Censorship.genuine_action | Stark 曲线 Schnorr + FS transcript | poker_protocol_lean 已形式化 Schnorr 特称可靠性 |
| 哈希抗碰撞 | `actionDigest` 单射式（digest 相等 ⇒ 日志相等） | Censorship.DigestBinding | Poseidon/SHA-256 | 标准假设 |
| 链上事件不可篡改 | settle 事件的 accepted-seq 一经发布不可抵赖 | Censorship.AcceptedSeq 语境 | L1/L2 共识 | 共识层假设 |
| Rust ↔ Lean 对应 | 每个 Lean 谓词注明 Rust 出处（doc-comment） | 审计文档 | 各文件 doc-comment | 人工核对清单 |
-/

namespace AirsLean.Top

/-- Stwo 承诺绑定与 FRI soundness 的抽象：被 verifier 接受的 trace
满足其 AIR 约束。Lean 侧以 `Sat cs t` 直接建模，不引入公理；链上
"证明对象 ⇒ Sat"属于 Stwo 库的外部假设。 -/
def StarkFaithful (cs : Trace → Prop) (t : Trace) : Prop := Sat cs t

/-- EUF-CMA 不可伪造性（抽象谓词形式，供 Censorship 使用）。 -/
def Unforgeable (sch : SigScheme) (sk : sch.SK) : Prop :=
  ∀ msg σ, sch.verify (sch.pkOf sk) msg σ = true → sch.sign sk msg = σ

end AirsLean.Top
