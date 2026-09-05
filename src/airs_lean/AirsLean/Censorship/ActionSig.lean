import AirsLean.Custody.WithdrawBound

/-!
# ActionSig — 动作签名模型与不可伪造性

按 `ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §2 建模：签名者 = 玩家的
牌局身份 SK，消息域 = `(table_id, hand_id, seq, action, payload)`。
签名方案为抽象结构；EUF-CMA 不可伪造性以 `Authentic` 谓词为显式假设
（登记于 `Top/Assumptions.lean`；具体实例化依赖 DLP + ROM，与
poker_protocol_lean 的 Schnorr/FS 层衔接）。

定理：
- `genuine_action`：验签通过 ⇒ 签名由持 sk 方为该消息产生——服务器
  不能凭空捏造玩家动作（攻击表第 1 行："服务器伪造动作 ✗"）；
- `msg_injective`：消息域结构上由五元组决定——`(hand_id, seq)` 在
  签名域内，跨手/跨序号的消息互不相同（域分离的结构基础；重放的
  排除在 D2 的 seq 单调约束给出）。

出处：`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §2；
`client-wasm/src/lib.rs`（`sign_action`）；
`texas/src/pokergame/actions.rs`（服务器验签 + seq 单调）。
-/

namespace AirsLean

/-- 签名消息域：`(table, hand, seq)` 绑定 + 动作载荷。 -/
structure ActionMsg where
  /-- 桌 id。 -/
  table : ℕ
  /-- 手 id。 -/
  hand : ℕ
  /-- 玩家内单调 seq。 -/
  seq : ℕ
  /-- 动作编码。 -/
  action : ℕ
  /-- 载荷（金额等）。 -/
  payload : ℕ

/-- 抽象签名方案（确定性签名函数）。 -/
structure SigScheme where
  /-- 私钥域。 -/
  SK : Type
  /-- 公钥域。 -/
  PK : Type
  /-- 签名域。 -/
  Sig : Type
  /-- 派生公钥。 -/
  pkOf : SK → PK
  /-- 签名算法。 -/
  sign : SK → ActionMsg → Sig
  /-- 验签算法。 -/
  verify : PK → ActionMsg → Sig → Bool

variable {sch : SigScheme}

/-- 真实性谓词（EUF-CMA 抽象形式）：验签通过 ⇒ 该签名由持 sk 方为
**该消息**产生。 -/
def Authentic (sk : sch.SK) (msg : ActionMsg) (σ : sch.Sig) : Prop :=
  sch.verify (sch.pkOf sk) msg σ = true → sch.sign sk msg = σ

/-- 完备性：诚实客户端的签名总是验签通过。 -/
def SigCorrect (sk : sch.SK) : Prop :=
  ∀ msg, sch.verify (sch.pkOf sk) msg (sch.sign sk msg) = true

/-- **动作真实性**：验签通过的动作要么由玩家签出，要么构成 EUF-CMA
破译（假设排除）——服务器不能凭空捏造玩家动作。 -/
theorem genuine_action (sk : sch.SK) (msg : ActionMsg) (σ : sch.Sig)
    (hauth : Authentic sk msg σ) (hverify : sch.verify (sch.pkOf sk) msg σ = true) :
    sch.sign sk msg = σ := hauth hverify

/-- **域分离的结构基础**：消息由五元组唯一决定——`(hand_id, seq)` 在
签名域内，不同手/不同序号的消息互不相同。 -/
theorem msg_injective (m₁ m₂ : ActionMsg)
    (h1 : m₁.table = m₂.table) (h2 : m₁.hand = m₂.hand) (h3 : m₁.seq = m₂.seq)
    (h4 : m₁.action = m₂.action) (h5 : m₁.payload = m₂.payload) :
    m₁ = m₂ := by
  cases m₁
  cases m₂
  simp only [ActionMsg.mk.injEq] at *
  exact ⟨h1, h2, h3, h4, h5⟩

end AirsLean
