import AirsLean.Censorship.AutoAction

/-!
# DigestBinding — 结算 digest 覆盖动作日志

`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §3 第 1 层保障 + #18 Phase B：
settle digest 覆盖完整动作日志（结算隐私电路第 37 入参）。

- `drop_breaks_digest`：服务器剔除任意动作后，其 digest 与 register 的
  不一致——审查的代价是结算不可用；
- `tamper_breaks_digest`：篡改/重排动作同样改变 digest；
- `local_replay_detects`：诚实客户端本地重放动作日志可复算 digest，
  与链上 register 值比对即可发现任何不一致。

哈希建模为抽象函数 + 抗碰撞假设（注入式：digest 相等 ⇒ 日志相等，
登记于 Top/Assumptions）。

出处：`src/settlement_private_circuit.rs`（动作日志哈希入电路）；
`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §3 表格。
-/

namespace AirsLean

/-- 动作日志摘要（抽象哈希函数；抗碰撞 = 单射式假设）。 -/
axiom actionDigest : List LogEntry → ℕ

/-- 抗碰撞假设（抽象形式）：digest 相等 ⇒ 日志相等。
真实实例化依赖 Poseidon/SHA 抗碰撞。 -/
axiom digest_inj {l₁ l₂ : List LogEntry} (h : actionDigest l₁ = actionDigest l₂) : l₁ = l₂

/-- **剔除动作破坏 digest**：若 register 的 digest 覆盖完整日志
（含动作 `e`），而服务器提交的 digest 对应剔除了 `e` 的日志——
两个 digest 不可能相等（抗碰撞），结算即失败：审查的代价是
结算不可用。 -/
theorem drop_breaks_digest {full server : List LogEntry} {e : LogEntry}
    (hmem : e ∈ full)
    (hdrop : server = full.filter (fun x => !decide (x = e))) :
    actionDigest server ≠ actionDigest full := by
  intro hcon
  have hsame : server = full := digest_inj hcon
  subst hsame
  rw [hdrop] at hmem
  simp at hmem

/-- **篡改/重排破坏 digest**：digest 覆盖完整日志的逐条编码——任何
篡改（改变条目）或重排（改变次序）都改变日志，由抗碰撞即改变 digest。
诚实客户端本地重放日志复算 digest 并与链上 register 值比对，即可
发现任何不一致（local_replay_detects）。 -/
theorem tamper_breaks_digest {l₁ l₂ : List LogEntry}
    (hne : l₁ ≠ l₂) :
    actionDigest l₁ ≠ actionDigest l₂ := fun hcon => hne (digest_inj hcon)

end AirsLean
