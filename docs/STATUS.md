# Project Status — Canonical AIR Coverage & Trust Boundary

> 2026-09-05 重写。本文件是 canonical AIR 覆盖/缺口的**权威表述源**
> （docs/TODO.md「canonical AIR 缺口」条目指向这里）。历史叙事
> （Ristretto 迁移、L1 链机制、无交易重放信任模型）已移至
> [`docs/archive/`](archive/)——Plan D（2026-09-05）后协议唯一曲线为
> Stark 曲线，poker_l1 收缩为合约库，常驻 mirror 已删除（结算 =
> 单一状态架构：实时 VM 镜像 + settle 时直接取用，prove_log 仅作对账基准）。

## Workspace model

This workspace is the extracted `poker_texas_air` project: a Starknet
off-chain stwo proving stack. There is no L1 chain, no transaction replay,
and no resident mirror. The proof pipeline is: a per-hand live VM mirror
(`texas/src/starknet/shadow.rs`, dispatched synchronously at every game
acceptance point) → ProveTask chain → canonical AIR / outer aggregate →
on-chain settlement (`poker_contracts`), cross-checked against game-layer
facts recorded in `texas/src/starknet/prove_log.rs`. Settlement digests bind
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
   - **实施状态（2026-09-05）**：ShuffleComplete 已全部落地（枚举/校验/AIR
     约束/正反例测试，canonical 145/145；约束度数保持声明值 3——完成单元
     布尔化 + 度数门拆分）。
   - **RevealComplete 实施进展（2026-09-11，#22② 恢复实施）**：
     ① **盲注/规则 opening 通道已落地**——复用 rules-opening（同一条
     Blake2b 语句鉴权完整 `TableRules`）：`CanonicalBlindOpening`
     （small/big blind、ante_mode、ante_amount）+ `blind_opening_of` 投影
     + `validate_rules_opening` 扩展盲注/ante 不变量（big>0、sb≤bb、
     ante 模式合法）。② **host 关系已组合**——`CompletionKind::Reveal = 3`
     + opening 扩展（UTG/SB/BB 座位、实投面额、单挑布尔、reveal 承诺
     端点锚）+ `validate_reveal_completion_opening`（镜像 `post_blinds` +
     `start_betting_round(is_preflop)`：参与者全 Active、无封顶盲注、
     ANTE_MODE_NONE、正常下注开局；越界形状独立错误 fail-closed）+
     正反例测试（UTG/座位/面额/单挑/价格/deadline/承诺锚/封顶逐项）。
     ③ **AIR 组合已贯通（2026-09-11 端到端 prove/verify 绿）**——重写为
     "追加列 + 线性化 gate"布局：~166 条新 advice 列全部追加在 ABI 末尾
     （既有偏移零扰动），完成选择子 `flag×SubmitReveal`（二次）经专用
     度数 1 gate 列线性化（`shuffle_timeout_gate` 模式），全部约束保持
     声明度数 3。位置规则 = 模 9 循环"首个 Active"扫描（每个基座
     button/SB/BB：rotated activity + "此前无 Active"前缀 q 递推 + 首位
     选择子 f = rot·q；SB 含单挑虚拟距离 0 槽 = button 本身；UTG =
     BB 后首个 Active——单挑下该扫描恰好回到 button，与 VM 特例一致）；
     占用收敛（非 Empty/Out 即 Active）+ 计数 ≥2 逆元使该扫描与 VM 的
     mod max_players 扫描一致。盲注面额经公开 blind scope 预处理列
     （13 列，插在 rake scope 与范围表之间）锚定到与 rake 共享的同一条
     rules-hash 语句（`prove_canonical_reveal_completion_batch` +
     `verify_canonical_rake_binding` 扩展）；逐座位资金移动
     （post_bet=posted、pre_stack=post_stack+posted、
     post_total=pre_total+posted）用 limb4 加法进位，盲注座 post stack
     非零（无 AllIn 翻转）由逆元证明；deadline=ts+betting_timeout；
     ante 必须 NONE（scope 列钉零）；reveal 承诺轮转留 native/EC_OP
     通道（suspended 槽钉零，deck/reconstruction 双端冻结锚定）。
     **准入已翻转**：`crypto_admitted` 与 `validate_direct_batch` 对
     SubmitReveal 放行。测试：heads-up + 三人局（非单挑位置分支）
     assert/prove/verify 正例 + 归档盲注脱钩/规则脱钩负例 + 12 列篡改
     负例全绿。**fail-closed 收窄**（host 接受、AIR 拒绝的不可达形状）：
     参与者 <2、占用座含 Folded/Waiting/AllIn、ante≠NONE。
   - **#22④ 准入翻转（2026-09-05）**：`validate_direct_batch` 对
     SubmitShuffle/SubmitReconstruct 放行；协议行全字段冻结集进 AIR
     （turn 双端 NO_SEAT、资金/参数/掩码/hand_id/timeout 配置/9 座位全像/
     非轮转承诺逐 limb 冻结）。canonical 147/147、全量 367/367。
   - **#22⑤ state-root 重算进 AIR——v2 已落地（2026-09-05）**：放弃 v1
     单体组件（1713 列混合布局，691s 仍 ConstraintsNotSatisfied），按
     cairo-air 官方形态重写为五组件分解（`src/poseidon252_v2.rs`）：
     ChainAir 链接组件（吸收/门控/mix 线性/边界/锚点 + 状态链 multiset）
     + MulAir（32×16→48 卷积协处理器）+ ReduceAir（48=z+32q·P 协处理器）
     + 2^16/2^12 范围表；非线性代数经 96 坐标 LogUp 链接元组下放。
     实测：e2e prove+verify **2.91s**（≈237×），五组件 rowcheck 全过，
     篡改负例三连全拒，原生层与 starknet_crypto 位精确等价保持。
     实施细节见 git 历史（原 `docs/plan-poseidon252-v2.md` 已删除）；v1 单体组件
     （`poseidon252_air_component`）已整体移除（2026-09-06：`--include-ignored`
     全量门禁会复活其失败测试；对照价值在 git 历史）。
   - **#22⑤ 字节 scope 组合——完成（2026-09-06）**：v2 验证路径不再做任何
     宿主 Poseidon 重算。三项机制：① 预处理树只含公开字节派生列
     （pos/flag/轮密钥/吸收词/选择子/init + 范围表 + 确定性 enabler），
     验证方用 `public_scope_columns` 重建整棵期望树做根等值比较
     （`v2_expected_preprocessed_root`）；② claimed anchor 字节在首次承诺前
     混入 Fiat–Shamir，ChainAir 终边界改为对 anchor limb **常量**钉住
     （S_ANCHOR 48 列删除）；③ void 元组（padding 漫步终态）移入见证树，
     由 multiset 链强制。同时修复两个真实缺陷：void 演化漏掉 `n_pad` 个
     完整零吸收 padding 置换（log≥9 布局即触发 logup 失衡）；协处理器
     行数公式漏算 padding/leftover 行（改为镜像行循环精确计数）。
     新增 `prove/verify_name_commitment_v2`：把 `zchain.string.v2` 名称
     契约（`canonical_borsh_preimage`）封成链 statement，AIR 重算
     poseidon_hash_many 并钉住锚点——等价测试断言锚点 lane-0 ==
     `table_name_commitment(name)`（legacy 宿主哈希，仅测试用作 oracle）。
     测试 8/8（e2e/rowcheck/篡改三连/name 正反例）；全量门禁 `--include-ignored` 384/384（2026-09-06）；原 v1
     rowcheck、create_table 8/8 回归全绿。**残留**：create_table AIR 的
     name-hash 期望值已切换为消费 v2 归档的 claimed anchor 投影
     （2026-09-11：方法归档 v4 + `name_commitment` 公开输入；后被 v34/v35
     展示名出共识重构整体移除——名字承诺随 metadata 对象出走，本项由
     该重构收口）。
3. ~~Terminal timeout cascade~~ — **closed (2026-09-05)**: the terminal
   cascade batch proofs exist and pass — multi-pending kick batches, the
   kicks→terminal-reset refund batch, the kicks→sole-survivor award batch
   and its raked variant (schedule tamper negatives included).
4. **Reconstruction final composition** — acceptance: reconstruct submission
   leaves fail-closed.
   **实施就绪设计（2026-09-05，与 #22② 同模式）**：reconstruct completion 的
   规范化约束已在 AIR（:5311-5360）；剩余 = (a) 非最终 reconstruct 提交行的
   **全字段冻结集**——turn=NO_SEAT、current_bet/min_raise、pot/chip_pool、
   acted_mask、leave_after_hand_mask、button/max_players、9 座位全像
   （status/acted/stack/bet/total_bet/addon/time_bank/三个承诺）、非轮转承诺
   （board/reveal/rules/governance/settlement/custody/rit）——全部 gate 在
   `is_protocol_submit`（度数 1，冻结约束 ≤3 ✓）；(b) **deck/reconstruction
   承诺轮转** = native/EC_OP 通道残留（与 ② shuffle 同一口径：opening/端点
   锚定 + Plan D ④）；(c) **准入翻转**：`validate_direct_batch` 对
   SubmitShuffle/SubmitReconstruct 放行（完成 opening 行 + 非最终行），
   SubmitReveal/FoldWithProof 维持拒绝；(d) 测试：两 completion + 非最终行
   的 prove/verify 正例与逐字段篡改负例。残留信任：deck/reconstruction
   承诺轮转由 native 验证 + 链上批次背书（既有信任模型），canonical AIR
   只证状态机规范化。
5. **State-root recomputation** (as opposed to binding) inside the AIR —
   acceptance: AIR independently recomputes and matches the
   `state_root_binding` anchor.

Until these compose, a witness-free Stwo verification result alone must not
advance a production table head. `CanonicalTransitionWitness::validate_shape`
and the direct AIR both reject unused-payload smuggling (zero proof
commitments / auxiliary fields / legacy flags / deadline advice outside their
selectors; no-seat sentinel for seatless micro-steps).

## Layered soundness record

- DAPV (P layer) soundness: `docs/SOUNDNESS.md` (theorems 1/2, ρ-binding
  lemma; production instantiation = Stark curve EC_OP + Poseidon challenges).
- Settlement privacy: `docs/design/SETTLEMENT_PRIVACY_PLAN.md` (P2-M1..M4 done; v2
  zero-plaintext settle contract deployed sepolia, server-side enablement
  pending).
- Censorship resistance: `docs/design/ACTION_SIGNING_CENSORSHIP_RESISTANCE.md`
  (#16/#17/#18 Phase A+B wired; in-circuit legal-default constraints remain
  the mainnet gate).
- Performance baselines: `docs/PERFORMANCE.md` (release numbers, production
  pipeline, on-chain gas; older reports archived).
- Historical design archive: `docs/archive/` (host-zero Ristretto charter,
  old perf reports, trust-model/replay essays, migration blueprints).

Document map: [`docs/README.md`](README.md).
