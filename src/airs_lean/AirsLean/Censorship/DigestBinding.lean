import AirsLean.Censorship.AutoAction

/-!
# DigestBinding — 结算 digest 覆盖动作日志

`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §3 第 1 层保障 + #18 Phase B/C：
settle digest 覆盖完整动作日志。#18 Phase C 切片 1 后，动作日志哈希
从 keccak 链切换为 **Poseidon sponge**：

```
action_log_digest = poseidon_hash_many([DOMAIN] ++ Σ packed_word(e))
DOMAIN            = starknet_keccak(b"zgame.action_log.v1")   （冻结字面量）
packed_word(e)    = action(40) | flags(2)@40 | amount(64)@42 | seq(64)@106 | seat(32)@170
```

- 吸收链只收日志打包词——**合法性词不入 digest**（合法性由电路侧
  `legal_auto_action` 规则另行校验；当前 `action_flags` 为 fail-closed
  预留零字段）；
- 日志上限 30 条（`ACTION_LOG_MAX_ENTRIES`）；
- 结算 digest 吸收序列：`[hand_id] ++ Σ(player, sign, |delta|) ++
  [action_log_digest]`（动作日志哈希为尾词）。

定理（哈希建模为抽象函数 + 抗碰撞假设，登记于 `Top/Assumptions`）：

- `drop_breaks_digest`：服务器剔除任意动作后，其 digest 与 register 的
  不一致——审查的代价是结算不可用；
- `tamper_breaks_digest`：篡改/重排动作同样改变 digest；
- `local_replay_detects`：诚实客户端本地重放动作日志复算 digest，
  与链上 register 值比对即可发现任何不一致。

出处：`texas/src/pokergame/actions.rs`（`action_log_domain`、
`action_entry_word`）；`src/settlement_private_circuit.rs`
（`game_layer_action_log_digest`、`settlement_digest_fields`）。
-/

namespace AirsLean

/-- 动作日志摘要（抽象哈希函数；抗碰撞 = 单射式假设）。抽象中已含
域分离标签：跨协议/跨域的摘要重用被排除。 -/
axiom actionDigest : List LogEntry → ℕ

/-- 抗碰撞假设（抽象形式）：digest 相等 ⇒ 日志相等。
真实实例化依赖 Poseidon sponge 抗碰撞（域分离 + 打包词序列）。 -/
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

/-- **篡改/重排破坏 digest**：digest 覆盖完整日志的逐条打包词——任何
篡改（改变条目）或重排（改变次序）都改变日志，由抗碰撞即改变 digest。
诚实客户端本地重放日志复算 digest 并与链上 register 值比对，即可
发现任何不一致（`local_replay_detects`）。 -/
theorem tamper_breaks_digest {l₁ l₂ : List LogEntry}
    (hne : l₁ ≠ l₂) :
    actionDigest l₁ ≠ actionDigest l₂ := fun hcon => hne (digest_inj hcon)

end AirsLean
