# Project Status — Canonical AIR Coverage & Trust Boundary

> 2026-09-05 重写。本文件是 canonical AIR 覆盖/缺口的**权威表述源**
> （docs/TODO.md「canonical AIR 缺口」条目指向这里）。历史叙事
> （Ristretto 迁移、L1 链机制、无交易重放信任模型）已移至
> [`docs/archive/`](archive/)——Plan D（2026-09-05）后协议唯一曲线为
> Stark 曲线，poker_l1 收缩为合约库，常驻 mirror 已删除（结算 =
> prove_log 记录 + settle 时一次性重建）。

## Workspace model

This workspace is the extracted `poker_texas_air` project: a Starknet
off-chain stwo proving stack. There is no L1 chain, no transaction replay,
and no resident mirror. The proof pipeline is: game layer records accepted
inputs (`texas/src/starknet/prove_log.rs`) → one-shot rebuild
(`mirror::build_from_log`) → ProveTask chain → canonical AIR / outer
aggregate → on-chain settlement (`poker_contracts`). Settlement digests bind
the hand's action log (`action_log_digest` tail word, #18 Phase B).

## Canonical AIR — composed relations (current)

`texas_canonical_air` (fixed-width ABI, `CanonicalTransitionKind` 0..=28,
29 selectors) composes and admits:

- all fixed mid-round betting relations: `Call` (incl. short all-in), `Raise`,
  `Bet`, funding, join/leave, force/kick, `SetLeaveAfterHand`, `AdvanceRound`,
  betting time-bank extension;
- showdown settlement algebra (`canonical_settlement_air`, 16-row domain +
  borrow/carry decomposition) and the rake opening (`canonical_rake_opening`);
- reveal-assignment ledger opening (`canonical_reveal_opening`);
- non-terminal reveal-timeout cascade scope (`reveal_timeout_cascade`,
  pending-union ascending table walk);
- `AutoFold` timeout suffix, `EndWithoutShowdown`, reset-only and
  reveal/reconstruct timeout reset families;
- state-root **binding** (`state_root_binding` — Flock proof replaces host
  recomputation);
- the fixed non-cascading `AdvanceDeadline` shuffle-timeout micro-step
  (minimum pending seat, refund/pot/chip-pool conservation, deck-commitment
  rebuild);
- the settlement-privacy circuit skeleton (`settlement_private_circuit`,
  P2-M1; §8.2 `action_log_digest` slot wired by #18 Phase B —
  `action_flags` / `accepted_seq_digest` stay zero-reserved).

## Canonical AIR — real gaps (fail-closed)

1. **Curve crypto equalities stay out of AIR** (shuffle / reveal /
   reconstruct). Plan D scope: native verification (host + on-chain EC_OP
   `hand_batch_stark`). Acceptance = a full-residual batch settles in one
   sepolia tx at acceptable gas (Plan D P1.4; contract side ready, not yet
   measured on-chain).
2. **Final shuffle/reveal phase switches** still fail-closed — acceptance:
   canonical AIR composes the complete ShuffleComplete/RevealComplete
   terminal-transition relation.
   **实施就绪设计（2026-09-05 调研定稿，下一步按此实施）**：
   - fail-closed 门的确切位置 = `src/texas_canonical_air.rs:5304` 的
     `non_final_protocol_submit` 冻结约束（post == pre：phase/subtag/street/
     deadline 四组镜像）；`is_protocol_submit = SubmitShuffle | SubmitReveal |
     SubmitReconstruct`（:868），现仅 reconstruct completion 有组合范本
     （:5311-5322：post_phase=1、subtag=RECONSTRUCT、pending mask 重置为
     participants）。
   - VM 完成语义（oracle 依据 = poker_l1 dispatch.rs:2490-2540 的 e2e 测试）：
     ShuffleComplete = 最后一位贡献者提交后 deck 已被替换为最终 output、
     `shuffle_phase()` 离开 BEFORE_PREFLOP、进入发牌/reveal 阶段（pending
     mask 重置为 reveal 参与者、deadline 重挂）；RevealComplete = 最后一份
     reveal token 入账后 `enter_betting(ROUND_PREFLOP)`、street→preflop、
     betting deadline 重挂。
   - 组合面（按 reconstruct completion 的既有范本镜像）：
     ① `src/texas_canonical.rs`：`CanonicalProtocolCompletionKind` 增
        `Shuffle = 2` / `Reveal = 3`；`CanonicalProtocolCompletionOpening`
        增加对应 opening（completed/pending mask、deck 承诺切换
        pre/post、cards_dealt、street/phase 目标值、deadline）；validate
        侧按 :959-962/:1236/:1339 的既有 completion 校验模式镜像。
     ② `src/texas_canonical_air.rs`：witness 行新增 opening 列
        （PROTOCOL 区偏移顺延）；把 :5304 的 `non_final_protocol_submit`
        拆为 `non_final_submit = is_protocol_submit - all_completions`，
        Shuffle/Reveal completion 行改为组合约束（phase/subtag/street/
        deadline 目标值等式 + pending mask 重置等式 + deck 承诺绑定）；
        advice 侧复用 :1424 的 protocol_submit 逆元槽位。
     ③ 测试：两种 completion 的 prove/verify 正例 + 篡改负例
        （phase 目标值/掩码/承诺各自篡改必须拒绝），镜像既有
        RevealTimeout 家族测试形态。
     ④ 纪律：crypto 方程本身仍按 Plan D 留在 native/链上 EC_OP 通道——
        本组合只证明"状态机规范化语义"，不证明洗牌/揭示方程。
3. **Terminal timeout cascade** (all players kicked → hand ends → refunds) —
   acceptance: batch proof for the terminal cascade (current cascade scope
   covers non-terminal walk only).
4. **Reconstruction final composition** (deck/reveal commitment recomputation;
   Ristretto-era equations are obsolete in the Stark world) — acceptance:
   reconstruct submission leaves fail-closed.
5. **State-root recomputation** (as opposed to binding) inside the AIR —
   acceptance: AIR independently recomputes and matches the
   `state_root_binding` anchor.

Until these compose, a witness-free Stwo verification result alone must not
advance a production table head. `CanonicalTransitionWitness::validate_shape`
and the direct AIR both reject unused-payload smuggling (zero proof
commitments / auxiliary fields / legacy flags / deadline advice outside their
selectors; no-seat sentinel for seatless micro-steps).

## Layered soundness record

- DAPV (P layer) soundness: `DAPV_SOUNDNESS.md` (theorems 1/2, ρ-binding
  lemma; production instantiation = Stark curve EC_OP + Poseidon challenges).
- Settlement privacy: `SETTLEMENT_PRIVACY_PLAN.md` (P2-M1..M4 done; v2
  zero-plaintext settle contract deployed sepolia, server-side enablement
  pending).
- Censorship resistance: `ACTION_SIGNING_CENSORSHIP_RESISTANCE.md`
  (#16/#17/#18 Phase A+B wired; in-circuit legal-default constraints remain
  the mainnet gate).
- Performance baselines: `docs/plan_d_perf.md` (post-Plan-D release numbers;
  older reports archived).
- Historical design archive: `docs/archive/` (host-zero Ristretto charter,
  old perf reports, trust-model/replay essays, migration blueprints).

Downstream migration notes: [`../MIGRATION.md`](../MIGRATION.md).
