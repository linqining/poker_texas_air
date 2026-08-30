# Reconstruction 协议 Soundness 分析

本文是 `soundness.md`（ZKShuffleProof 洗牌证明）的姊妹篇，分析重构后
`poker_protocol` 门面层的 **reconstruction（牌组重建）协议**：从上一手遗留的
`user_readable_cards` 出发，证明并验证每个玩家对下一手牌组的"贡献"，聚合重建
出新牌组。形式化证明位于 `poker_protocol_lean`（Lean 4 + Mathlib，零
`sorry`/`admit`），论文级安全声明见
`poker_protocol_lean/SECURITY_RECONSTRUCTION.md`。

接入参考（重构前）：`texas_poker_move`（Move 合约 `submit_reconstruct_deck` /
`rebuild_deck_from_reconstruct_deck`）与 `texas/src/pokergame/table/reconstruct.rs`
（服务端镜像）。协议级测试见
`poker_protocol/tests/reconstruction_tests.rs`（BLS12-381 全链路）与
`poker-protocol-proofs/src/reconstruction/{tests,v3_tests}.rs`（曲线通用组件）。

---

## 一、协议概述与 user_readable_card 语义

一手牌结束后（无论是否 showdown），需要把"上一手被持走/烧掉的牌"从牌组中
移除并重新洗牌。reconstruction 的输入是每个玩家的
`user_readable_cards`：**上一轮洗牌后剩下的、仅剩持有者一人可解密的密文**。

其状态机语义（`src/z_poker/protocol/types.rs` `get_readable_card`）：

- 发牌时每张牌的 `pending_players` = 全部玩家；
- 每个非持有者玩家提交 reveal token（`sk_j · c1`，附 `RevealTokenProof`），
  从 `pending_players` 中移除；
- 当且仅当 `pending_players` **恰好只剩持有者一人**时，该牌进入
  user_readable 状态：`R = (c1, c2 − Σ_{j≠owner} sk_j·c1)`，
  即 `Enc_pk_owner(card; r)`（持有者 token 未扣除，牌面对其他人仍保密）；
- 若持有者最后也亮牌（showdown），`pending_players` 清空、牌面公开，该牌
  **离开** readable 集合。

### 1.1 血统（provenance）

`R_i` 不是凭空选择的输入，而是有一条被证明/被认证的代数血统（Lean
`Reconstruct/ReadableCardProvenance.lean`）：

```text
canonical init_deck 牌 (g, card_i) = Enc_0(card_i; 1)
  → 每玩家有证明的密钥演化（remask）与重加密置换（shuffle proof）
  → 状态机认证的上一手发牌
  → 所有非持有者的有效 reveal token（各附 DLEQ 证明、绑定同一密文）
  → R_i = Enc_pk_owner(card_i; r_i)
```

对应定理：`initialCard_eq_encrypt_zero_key`、`remask_extends_aggregate_key`、
`joinStep_preserves_plaintext`、`lineage_is_canonical_encryption`、
`partial_decryption_yields_owner_ciphertext`、
`authenticated_prior_hand_yields_user_readable_card`。

### 1.2 牌组密钥演化的两条实现路径

平凡初始牌组 `(g, m) = Enc_0(m; 1)` 的"初始随机性 1"属于零密钥。要让最终
牌组在聚合密钥下可解密，生产上有两条等价路径：

1. **join 路径（代数自洽，本地/中途加入）**：每个玩家执行 remask
   （`c2 += c1·sk_j`，牌组密钥演化 `pk += pk_j`，附 `RemaskProof`）后再在
   新 share 公钥下重加密置换（`MaskAndShuffleRound`，附 Bayer-Groth 证明）。
   终态牌组 = 完整聚合密钥下的合法 ElGamal。这正是 Lean 血统定理采用的
   演化模型，也是 `texas` 服务端 `join_player_and_shuffle` 的路径。
2. **纯 shuffle + 链上修正（`submit_shuffle_v2`）**：每个洗牌者提交纯
   re-encrypt 洗牌（证明在**未修正**输出上验证），链上随后执行
   `c2 += player_pk`。N 玩家后
   `c1 = g(1+Σr_j)`、`c2 = m + g·Σsk_j·(1+Σr_j) = m + sk_agg·c1`，
   聚合密钥解密恰好恢复 `m`（table.move `submit_shuffle_v2` 注释中的公式）。

**注意**：本地 `MentalPokerGame::submit_shuffle` 不含 v2 的 `c2 += pk`
修正；从平凡牌组直接调用纯 shuffle 链会得到整体差 `agg_pk` 偏移的牌组。
测试 `chain_shuffle_v2_offset_correction_keeps_deck_aggregate_decryptable`
显式镜像链上修正并验证两条路径的 readable 语义一致。

---

## 二、V2 的三个机器验证失败（为何必须 V3）

V2（`ReconstructProof`，兼容路径）已被 Lean
`Reconstruct/ReconstructV2Counterexample.lean` 机器验证地证伪。它**只作为
兼容类型和反例靶子保留**，不承担生产安全。

### 2.1 错位交换（misplaced swap）soundness 攻击

V2 验证器只证明 `output[i] + padded[i] = Enc_pk_user(cards[i])`，不约束
`padded[i]` 的明文。对不同的牌 `A ≠ B`，敌手可取
`padded[i] = Enc(A; s)`、`output[i] = Enc(B−A; r)`，两者之和仍是
`Enc(B; r+s)`，有序加密检查通过，但 `B−A` 既不是 0 也不是 `B`——攻击
无需求解任何离散对数。

- Lean：`misplaced_swap_satisfies_corrected_relation`、
  `misplaced_output_is_not_an_honest_branch`；
- Rust（反例被拒绝）：`slot_or_rejects_the_v2_misplaced_swap_attack{,_on_bls}`
  （Bayer-Groth 能证明密文来自输入多重集，但槽位 OR 关系要求
  `Enc(0)` 或 `Enc(−card_i)`，见证构造直接失败）。

### 2.2 公开随机性导致零知识失败

V2 输出随机性是公开 `coefficient` 的幂（`s_i = coefficient^{i+1}`）。任何
观察者可离线计算 `output[i].c2 − s_i·pk`：得到 `identity` 即"移除槽位"，
得到 `cards[i]` 即"保留槽位"——直接学到玩家上一手的持牌槽位。

- Lean：`recover_plaintext_from_known_randomness`、
  `public_randomness_reveals_branch`；
- Rust（攻击被执行并确认成功，作为 V2 不可用的证据）：
  `v2_public_coefficient_leaks_removed_slots`。

### 2.3 跨密钥聚合形状失配

每个 V2 玩家在**各自** `user_pk` 下加密。按 Move/Rust 服务端
`rebuild_deck_from_reconstruct_deck` / `on_complete_reconstruct` 公式聚合后，
`c2 − sk_agg·c1 = m − (Σ_{p≠t} s_p(pk_p − pk_t))` 对任何单个密钥 `t`
都不是 `m`——重建牌组在聚合密钥（乃至任何单钥）下不可解密。

- Lean：`same_randomness_cross_key_sum_shape`；
- Rust（反例被执行）：`v2_rebuild_formula_is_not_decryptable_under_aggregate_key`。

V2 兼容路径仍可验证诚实证明并做服务端绑定
（`v2_reconstruct_compatibility_and_server_side_binding`：换一组 readable
验证、篡改输出、非法 coefficient 均被拒绝），但**不得**声称 soundness/ZK，
也不得把 V2 输出当聚合密文求和。

---

## 三、V3 的结构与 soundness 论证

V3（`ReconstructProofV3`）把每个玩家的重建贡献统一到**聚合公钥**下：

```text
contribution[i] = Enc_PKagg(0; v_i)  或  Enc_PKagg(−cards[i]; v_i)
```

由四个组件构成，知识可靠性链条如下：

| 组件 | 公开关系 | Lean 结论 |
|------|----------|-----------|
| `CrossKeyNegationProof`（每张 readable 一个） | `pk_owner = sk_owner·g ∧ S.c1 = v·g ∧ sk_owner·R.c1 + v·PKagg = R.c2 + S.c2`，三元组共享见证 `(sk_owner, v)` | `ReconstructionV3JointSigma`：`relation_iff_cross_key`、`sigma_complete`、`sigma_speciallySound`、`sigma_perfect_hvzk`；`cross_key_negation_binds_plaintexts` |
| `BayerGrothShuffleProof`（贡献洗牌） | `contributions` 是 `负贡献 ⊕ 确定性零加密` 的重加密置换 | `poker-protocol-bg`（Bayer-Groth 标准论证；Lean 侧为显式假设，见 §5） |
| `SlotContributionOrProof`（每槽一个） | `contribution[i] ∈ {Enc(0;v), Enc(−cards[i];v)}`，分支/映射不出现在响应中 | `ReconstructionV3SlotOr`：`honest_accepts`、`specially_sound`、`simulate_accepts`、`honest_eq_simulate`、`response_translation_bijective`、`perfect_hvzk_algebraic` |
| statement 绑定 | version=3、`context_digest`、单调 `reconstruction_epoch`、`prior_state_digest`、双方公钥、全部密文按序进 transcript | `Reconstruct/ReconstructionV3.lean` 语义定理 + Fiat-Shamir transcript 绑定 |

### 3.1 语义 soundness（验证通过 ⇒ 贡献合法）

在组件假设下（§5），接受一个 V3 证明 ⇒ 提取的见证满足：

1. 每个槽位贡献解密恰为 `0` 或 `−cards[i]`
   （`accepted_contribution_is_zero_or_negative_card`）；
2. `removed[i]` ⟺ 恰好一张**认证过的** readable 牌映射到槽 `i`
   （`removed_iff_has_readable_witness`）；
3. 映射是单射（`readable_indices_are_unique`）——重复牌在 prover 侧
   fail-closed（`reconstruction_v3_prover_rejects_unauthenticated_readables`）。

跨密钥证明是关键修复：它把"readable 牌确实解密为该 canonical 牌"绑定到
贡献上，而不需要任何人知道 `DL(R.c1)`；错位交换攻击因此被槽位 OR 关系
直接排除（§2.1 的 Rust 反例测试）。

### 3.2 聚合重建正确性

链上/宿主重建从 canonical 基础牌组开始（`canonical_base_deck`：
`Enc_PKagg(cards[i]; i+1)`，随机性公开无害——牌点是公开的），逐玩家叠加
`apply_reconstruction_contributions`：

```text
rebuilt[i] = Enc_PKagg(cards[i]; i+1) + Σ_p contribution_p[i]
```

- 若上一手没有玩家持有 `cards[i]`：所有贡献加密 0，明文保持 `cards[i]`
  （`aggregatePlaintext_no_removal`）；
- 若恰有一个认证持有者：恰有一个贡献加密 `−cards[i]`，明文变为
  `identity`（`aggregatePlaintext_unique_removal`、
  `corrected_slot_semantics`）；
- 与 V2 不同，所有分量同在聚合密钥下，形状正确、可用聚合密钥解密，
  也可直接进入下一轮 shuffle（纯 re-encrypt 链保持可解密性，因为基础
  牌组本身就是聚合密钥下的合法密文）。

### 3.2.1 无残留（no-residue）性质

聚合重建后，任何槽位在聚合密钥下解密的结果只能是：

```text
identity（空牌） ∨ 不属于任何玩家 user_readable 集合的明文牌
```

且移除是精确的：空牌槽数 == readable 明文总数，非空槽位明文互不重复、
恰好等于 `deck \ readable`。这是下一手安全发牌的前提（上一手的私牌
不可能再次进入牌组）。

该性质由证明**强制**而非依赖 prover 诚实：cross-key 联合证明把每张
认证 readable 的负贡献明文绑定为 `−m`（`cross_key_negation_binds_plaintexts`），
槽位 OR 证明把该负贡献的落点约束到 `cards[i] = m` 的规范槽
（`accepted_contribution_is_zero_or_negative_card` + 精确覆盖
`removed_iff_has_readable_witness`）。恶意提交者即使提交**良构的**
全零贡献声明（statement 本身通过 `validate()`），证明验证也会失败——
测试 `rebuilt_deck_contains_no_user_readable_plaintext` 的反面用例
执行了这一攻击。

端到端验证：`reconstruction_v3_end_to_end_and_next_round_shuffle`（重建牌组
重新洗牌、Bayer-Groth 全验证、明文多重集保持、洗牌后牌组同样无残留）；
部分提交（超时路径）：`reconstruction_v3_partial_submission_removes_only_submitters_cards`。

### 3.3 防重放与状态绑定

`context_digest`（表/局/域分隔）、`reconstruction_epoch`（单调轮次）、
`prior_state_digest`（上一手认证状态）全部进入 transcript。篡改任一字段、
换外层 transcript label、换 owner/aggregate 公钥、改版本号，验证均失败
（`reconstruction_v3_rejects_statement_tampering` /
`..._rejects_proof_tampering`）。

**prior_state_digest 是协议与状态机之间的桥**：V3 证明只检查对摘要的密码
学关系，不重演历史。宿主/链必须保证该摘要认证了"这些 readable 密文确实是
该玩家上一手的牌、且血统起自 init_deck"（`reconstruct_v3` 的文档注释、
SECURITY_RECONSTRUCTION.md §2 的状态机义务清单）。

---

## 四、已知边界与状态机义务

reconstruction 证明**自身无法**建立、必须由外部保证的事实：

1. **readable 血统认证**：每个 readable 密文可追溯到 init_deck 的有证明
   洗牌/remask 链与被认证的上一手发牌（`prior_state_digest` 的职责）；
2. **跨玩家 readable 集合不相交**：一个 epoch 内两张认证 readable 不能映射
   到同一 canonical 槽——这是状态机不变量（发牌去重保证），单个玩家的证明
   无法单独建立；
3. **洗牌熵**：每张被挑战牌的血统中至少一次诚实、保密、均匀的重随机化
   （`FreshDLogHard` 平均情形假设 + `honest_rerandomizer_translation_bijective`
   平移双射），这是 `DL(R.c1)` 未知（保密性）的来源；soundness 方程不需要它；
4. **每手牌已发牌数 ≤ 牌组容量**、epoch 单调等表级不变量。

---

## 五、假设与 TCB

端到端定理（`Reconstruct/ReconstructionV3Security.lean`
`{completeness,knowledge_soundness,zero_knowledge}_under_assumptions`）显式
依赖 `ComponentAssumptions`：

1. Bayer-Groth 洗牌证明的 completeness / soundness / ZK（Rust 实现的
   Lean 形式化仍是 linking obligation）；
2. Fiat-Shamir 在 ROM 下的 forking 提取与模拟；
3. 共享 transcript 顺序组合；
4. transcript 字节级绑定（Rust↔Lean 序列化精化）；
5. 认证的 prior state（§4.1）与跨玩家 disjointness（§4.2）；
6. 曲线实现：素数阶子群成员检查与规范解码。

基础假设：BLS12-381 G1 上的离散对数困难性（Σ 协议知识可靠性）、ROM、
DDH（ElGamal 语义安全，ZK/隐私侧）。

---

## 六、Rust 测试 ↔ Lean 定理映射

| Rust 测试（`poker_protocol/tests/reconstruction_tests.rs` 除注明外） | 断言 | Lean 对应 |
|---|---|---|
| `readable_card_requires_every_other_reveal_token` | readable 仅在"只剩 owner 待亮"时出现；owner 单独解密恢复明文、他人不能；showdown 完整亮牌后离开 readable 集 | `partial_decryption_yields_owner_ciphertext`、`authenticated_prior_hand_yields_user_readable_card` |
| `peek_card_matches_game_readable_card` | 客户端 `peek_card` 与游戏状态 readable 密文逐位一致 | 同上（客户端/状态机一致性） |
| `readable_state_rejects_forged_reveal_tokens` | 冒名/篡改 token 被拒，readable 状态不受污染 | 血统前提"每个扣除的 token 有有效证明且绑定同一密文" |
| `chain_shuffle_v2_offset_correction_keeps_deck_aggregate_decryptable` | 纯 shuffle + 链上 `c2 += pk` 修正后聚合密钥可解密、readable 语义成立 | `lineage_is_canonical_encryption`（第二条密钥演化路径） |
| `reconstruction_v3_end_to_end_and_next_round_shuffle` | statement 逐字段绑定；独立验证；聚合重建精确移除；重建牌组可再洗牌且明文多重集保持 | `aggregatePlaintext_unique_removal`、`corrected_slot_semantics`、`valid_relation_complete` |
| `reconstruction_v3_partial_submission_removes_only_submitters_cards` | 超时部分提交只移除已提交玩家之牌 | `aggregatePlaintext_no_removal`（未提交玩家贡献为 0） |
| `rebuilt_deck_contains_no_user_readable_plaintext` | 无残留：每槽解密 ∈ {identity, 非 readable 明文}；空牌槽数 == readable 总数；恶意"不移除"声明（合法 Enc(0) 替换）被拒 | `removed_iff_has_readable_witness`、`readable_indices_are_unique`、`cross_key_negation_binds_plaintexts`、`accepted_contribution_is_zero_or_negative_card` |
| `reconstruction_v3_prover_rejects_unauthenticated_readables` | 非法/他钥/重复/空 readable fail-closed | `readable_indices_are_unique`、血统前提 |
| `reconstruction_v3_rejects_statement_tampering` | 任一 statement 字段篡改/换 transcript label 均拒绝（含 epoch 重放） | Fiat-Shamir transcript 绑定 |
| `reconstruction_v3_rejects_proof_tampering` | 四类证明组件篡改均拒绝 | 各组件 `speciallySound` |
| `reconstruction_v3_contributions_encrypt_zero_or_negative_card` | 每槽贡献解密 ∈ {0, −card_i} | `accepted_contribution_is_zero_or_negative_card` |
| `slot_or_rejects_the_v2_misplaced_swap_attack{,_on_bls}`（proofs crate） | V2 错位交换反例在 V3 槽位 OR 下无法构造见证 | `misplaced_swap_satisfies_corrected_relation`（反例）↔ `SlotOr.specially_sound`（修复） |
| `v2_reconstruct_compatibility_and_server_side_binding` | V2 兼容路径：诚实证明通过、服务端换 readable 集合/篡改输出/非法 coefficient 拒绝 | （兼容性，无 V2 soundness 声明） |
| `v2_public_coefficient_leaks_removed_slots` | 执行 V2 公开随机性攻击并确认泄露（ documenting 反例） | `recover_plaintext_from_known_randomness`、`public_randomness_reveals_branch` |
| `v2_rebuild_formula_is_not_decryptable_under_aggregate_key` | 执行 V2 跨密钥聚合反例并确认不可解密 | `same_randomness_cross_key_sum_shape` |

 proofs crate 中另有曲线通用组件测试（Ristretto/BLS）：
`reconstruction_v3_honest_and_plaintext_semantics`、
`reconstruction_v3_all_cards_removed`、
`reconstruction_v3_rejects_wrong_context_epoch_and_prior_state`、
`reconstruction_v3_proofs_are_randomized_without_mapping_fields` 等，映射见
`SECURITY_RECONSTRUCTION.md` §8 的完整 Rust–Lean 定理表。

---

## 七、结论

- **user_readable_card** 有精确的状态机语义（"仅剩持有者待亮"）与被证明的
  代数血统；两条生产洗牌路径（join remask / 链上 v2 修正）均能为其提供
  合法起点。
- **V2 不具备 soundness 与零知识性**（三个机器验证反例，Rust 侧均有可执行
  对应），仅作兼容与反例靶。
- **V3 在显式枚举的组件假设下**具备：每槽贡献 ∈ {0, −card_i} 的语义
  soundness、精确覆盖/单射的移除关系、聚合密钥下的正确重建、以及隐藏
  映射/分支/随机性/置换的零知识性；epoch/context/prior_state 摘要提供
  防重放与状态桥接。
- 剩余义务（Bayer-Groth 的 Lean 形式化、FS 顺序组合提取、Rust↔Lean 字节
  精化、状态机 disjointness 的机械化）在 SECURITY_RECONSTRUCTION.md §9
  列明，端到端声明应保持条件定理表述。
