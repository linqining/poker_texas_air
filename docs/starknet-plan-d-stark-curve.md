# Plan D：STARK 曲线迁移与信任加固执行计划

> 目标：把游戏协议本体从 BLS12-381 迁到 Starknet 原生 STARK 曲线
> （EC_OP builtin），让洗牌/发牌/摊牌残差进链上批次可负担地验证；
> 同时落地一组信任加固补丁，使"no admin can peek at cards"对**主动
> 恶意服务器**也成立（而不只对诚实服务器）。
>
> 前序：资金隐私见 [starknet-plan-b-anonymizer.md](starknet-plan-b-anonymizer.md)，
> 提交抗审查见 [starknet-plan-c-execution.md](starknet-plan-c-execution.md)。
> 本计划取代此前"迁移 secp256k1"的口头结论。

## 0. 核实结论（2026-08 代码核对，凭据可溯）

| # | 结论 | 凭据 |
|---|---|---|
| 1 | 被动隐私是**结构性保证**：`get_readable_card` 仅当 `pending_players` 恰好只剩持有者时构造 `c2 − Σ(其他 N−1 份 token)`，`c1` 原样保留，客户端本地补份额解密 | `poker_protocol/src/z_poker/protocol/types.rs:48` |
| 2 | **主动攻击面唯一且明确**：客户端 `handleReveal` 对服务器下发的 assignment 全盘出 token、零过滤；恶意服务器在非 showdown 阶段注入持有者自己的牌密文即可集齐 N 份解密 | `client/src/context/game/useCryptoOperations.ts:205`；服务端明文分支 `poker_protocol/src/z_poker/protocol/game.rs:295` |
| 3 | 拒绝配合的后果是被踢（`on_reveal_timeout`）——客户端守卫把隐私攻击降级为**活性攻击**，可接受 | `texas/src/pokergame/table/reveal.rs:192` |
| 4 | `Secp256k1Curve` 已是 core 完整后端，证明体系 curve-generic——迁移是"实现新后端+切换+重验"，非新密码学 | `poker-protocol-core/src/backend.rs:470`；`poker_protocol/ARCHITECTURE.md` |
| 5 | 认可密钥服务器托管（结算时 OsRng 生成） | `texas/src/starknet/hooks.rs:83` |
| 6 | `reveal_commitment` 为 keccak 占位，链上不重算 | `texas/src/starknet/dual_settle.rs`（已改注指向本计划） |
| 7 | DAPV 是**项目内部术语**，文献无此方案；`DUAL_PROOF_PROTOCOL.md`/`DAPV_SOUNDNESS.md` 从未入库（git 全历史无） | commit e744c6b 仅含代码 |
| 8 | cash-out 仍为公开 `vault.withdraw` | plan-b 文档"已知 seam"第 3 条 |
| 9 | blst（BLS12-381 C 依赖）无法编译 wasm32（Apple clang）——client-wasm **open blocker** | 迁移会话 sess_ef8bf73c 记录 |
| 10 | 钱包（Cartridge Controller）密钥非 secp256k1（owner/session = STARK 曲线；passkey = P-256）；钱包公钥**不可**复用为 ElGamal 公钥（API 取不到 `sk·c1`、无联合安全证明、隐私关联、无法 per-table 轮换） | 本计划 §5 |

## 1. 曲线选型：为什么是 STARK 曲线

链上 EC 支持三档（已修正 `dual_settle.rs` 头注释，原"EC_OP 只支持
secp256k1"为事实错误）：

| 档 | 机制 | 成本 | 曲线 |
|---|---|---|---|
| 1 | EC_OP 硬件 builtin（`R = P + mQ`） | 原生，最便宜 | 仅 STARK 曲线 |
| 2 | OS 级 `secp256k1_mul`/`secp256r1_mul` syscall | 中档（近期已降约 50%） | secp 系 |
| 3 | 纯 Cairo 模拟（Garaga） | 最贵 | BLS12-381 等 |

STARK 曲线群结构适合 ElGamal：`y² = x³ + 3` over
`P = 2²⁵¹ + 17·2¹⁹² + 1`，**素数群阶、cofactor = 1**，DDH 与 secp256k1
同级（~128-bit）。它保卫 Starknet 全部账户安全，实战检验充分。

**决定性账目（P1.4 全残差批次）**：迁移后每手折叠检查 ≈
O(玩家数 × 52 × 3) 次标量乘，9 人桌 ≈ **1400 次 EC mul/手**。
EC_OP 原生可负担；secp syscall × 1400 大概率超预算——STARK 曲线不是
"更优"，是全残差批次"可行/不可行"的分界。

**三个附带收益**：

1. **消解 blst wasm blocker**（#9）：`starknet-curve`/`starknet-crypto`
   纯 Rust 无 C 依赖，迁移即解锁 client-wasm 构建；
2. **Poseidon 双侧统一**：挑战/承诺哈希链上 builtin 与链下 crate 同一
   实现，`hand_binding`/RHO 域/g_attestation 告别 keccak 混用；
3. **认可层同曲线**：P 层认可换客户端生成的 STARK 曲线 Schnorr 密钥，
   ρ-折叠走 EC_OP（注意：Starknet 消息签名为 ECDSA，不可折叠——
   认可仍用独立 Schnorr 密钥，钱包只做绑定授权）。

**放弃 secp256k1 损失什么**：仅 EVM `ecrecover` 互操作（L1 验证场景）。
本 RFP Starknet-native，不构成需求；secp 后端保留在 core 备用。

## 2. P0 — 信任补丁（本周，独立于 P1）

| 项 | 内容 | 验收 |
|---|---|---|
| 0.1 客户端 reveal 守卫 | 缓存"曾作为自己 readable cards 推送的密文的 `c1` 集合"（c1 全生命周期不变，天然锚点）；`handleReveal` 在非 `ShowdownReveal` 阶段，assignment 中任何密文 c1 命中该集合 → 拒绝出 token 并告警。守卫在 TS 层，WASM 不动 | 恶意 assignment 注入模拟测试：客户端拒绝、牌不泄露；正常流程全回归 |
| 0.2 服务端不变量回归 | 测试断言：preflop/flop/turn/river 的 `player_assignments` 不得包含 assignee 自己的 `hand_encrypted`（防编排回归） | snforge/cargo 测试绿 |
| 0.3 文档债 | ~~修正 dual_settle.rs EC_OP 错误~~（已完成）；DAPV 术语在头注释展开或补 `docs/DUAL_PROOF_PROTOCOL.md`；对外表述统一为"ρ-folded Schnorr endorsement batch + host-verified STARK attestation" | 评审者不依赖口头解释可理解 P/G 两层 |
| 0.4 边缘处理 | `HAND_REVEAL_RESULT` 未到达（无锚点）时守卫的保守行为：拒绝非 showdown 的手牌类 assignment 并告警 | 单测覆盖冷启动路径 |

已知边界：守卫落地后，恶意服务器的隐私攻击只剩 griefing（踢人/
停服），无牌面泄露——与"no admin can peek"目标一致。

## 3. P1 — 协议迁移 STARK 曲线（2–4 周，最大杠杆）

前置 diligence（0.5 天）：`starknet-curve` crate 的 wasm32 编译验证；
`hand_batch.cairo` 实际机制核实（源码不在本仓，需定位合约仓库）。

| 步 | 内容 | 工期 | 验收 |
|---|---|---|---|
| 1.1 | core 新增 `StarkCurve` 后端（参照 backend.rs:470 secp 模式，基于 `starknet-curve`）；`hash_to_scalar` 用 Poseidon 归约；三层 Schnorr / Bayer-Groth V2 / RevealToken / DLEQ 全量测试——重点 `hash_to_scalar` 域偏置与 `soundness.md` 8 攻击套件回归 | 1 周 | 测试套件全绿 |
| 1.2 | `DefaultCurve` 切换 + 序列化面（facade、texas hex 点 JSON、DB pk）+ client-wasm 重编译，**移除 blstrs 依赖** | 1 周 | client-wasm 在 Apple clang 下构建通过（原 blocker 消项） |
| 1.3 | 密钥滚动迁移：现网玩家 pk 为 BLS 点 → STARK 曲线新身份；旧表结算完自然过期，新表启用，不做原地转换 | 并行 | 迁移期双曲线共存无脏读 |
| 1.4 | 残差批次扩容：shuffle/remask/reveal-token 残差写进 `batch_words`（两个 0 word 已预留），折叠走 **EC_OP builtin**；认可层 secp→STARK 一次切换到位；`reveal_commitment` 换规范 Poseidon 承诺并链上重算；哈希域统一 Poseidon | 0.5–1 周 | **9 人桌全残差批次单笔 settle 在 sepolia 通过且 gas 可承受**（secp 方案大概率过不了，此即换曲线理由）；host 预检不再是正确性依赖 |

## 4. P2 — 信任归位（与 P1 部分并行）

- **2.1 认可密钥客户端化**：认可私钥客户端生成持有（STARK 曲线
  Schnorr），结算经签名请求铸造；钱包对绑定消息签名（Controller
  session policy `messages` 可无弹窗）。删除服务器 `ENDORSEMENT_KEYS`
  注册表。验收：端到端结算不变，服务器不再持有任何认可私钥。
- **2.2 cash-out 私密化**：vault 加 `withdraw_to` + unshield 方向
  anonymizer（复用 Plan B `privacy_invoke` 模式反向）。验收：提现经
  privacy pool 出金，链上不可关联玩家。
- **2.3 RFP 叙事**：隐私模型表（谁能看到什么）整理进投标材料；
  "V2 mental poker 引擎 > RFP V1 trusted-dealer"写成显式优势声明。

## 5. 禁止事项（讨论已定论，防回头路）

- **钱包公钥 ≠ ElGamal 公钥**：签名 API 取不到 `sk·c1`（reveal token
  需对任意密文点运算）；签名+解密密钥复用无联合安全证明；钱包 pk =
  身份，击穿 paymaster/anonymizer 匿名栈；无法 per-table 轮换。
  钱包角色限定为：对独立生成的游戏/认可密钥**签授权**（协议已有
  `PKOwnershipProof` 同型机制）。
- **Poseidon 承诺级联洗牌不成立**：承诺不可同态重随机化，最后一层
  洗牌者全知牌序。同态级联必须有难群。
- **STARK 化 ≠ 后量子**：只要骑在椭圆曲线上（含 STARK 曲线），PQ
  属性是纸面的。STARK 化的真实收益是链上可验证 + soundness 标准化
  + 聚合经济学。

## 6. P3 — 触发式演进（不排期）

| 项 | 触发条件 | 内容 |
|---|---|---|
| Nova folding spike（1–2 周） | 每手残差方程数涨出单笔 EC_OP 预算，或锦标赛级跨手聚合需求 | 洗牌级联 = IVC 函数 F 的顺序应用（结构天然贴合）；CycleFold/Garaga verifier 成熟度调研 |
| 电路重执行 prototype（route B） | P1 完成后 EC 运算原生化，代价合理化 | 电路内重执行洗牌层 + 置换矩阵双射断言，淘汰自定义三层 Schnorr 的 soundness 包袱（batching/folding 只是载体，soundness 升级唯一来源是重执行） |

## 6b. P2.2 cash-out 私密化——交接规范（合约在外部结算 workspace）

合约源码在 `/Users/mac/projects/poker_texas_air/poker_contracts/src/`
（`poker_vault.cairo` / `poker_vault_anonymizer.cairo`），本仓库只承载
Rust/TS 集成面。unshield 方向的合约规范：

1. `poker_vault.cairo` 增加 `withdraw_to(player, amount, recipient,
   note_salt)`：校验调用链（仅 anonymizer），扣减 `player` 的
   `chip_balance`，把 STRK 经 pool 的 InvokeExternal 退出为 recipient
   的新 note（open note 或加密 note 均可——出金方向金额可以公开，
   关键是断开"玩家 → 收款地址"的关联）；
2. `poker_vault_anonymizer.cairo` 增加 `privacy_withdraw(player,
   amount, recipient, note_salt) -> Span<OpenNoteDeposit>`：仅 pool
   可调，遵循 STRK20 helper 规范（approve 拉回输出 note，返回
   `Span<OpenNoteDeposit>`）；
3. 客户端路径（本仓库）：`client/src/starknet/starknetGameActions.ts`
   的 `withdraw` 改走 `submitCalls` 的 `privacy_withdraw` 调用，配置
   门控沿用 `VITE_PRIVACY_BUYIN_ENABLED` 模式（`VITE_UNSHIELD_ENABLED`）；
4. 合规：出金同样经池的 viewing key 可追溯（"confidential by
   default, accountable when required"）。

**状态**：客户端/服务器集成面在合约 API 落地前不实现死代码；
本节即交接契约。

## 6c. 实施状态（2026-08-29 第二轮交付更新）

| 项 | 状态 | 证据 |
|---|---|---|
| snforge 全套 | ✅ 41 用例 | 35 默认预算 + 6 高步数（secp syscall 重，`--max-n-steps` 后全绿；预先存在的预算问题，与本次改动无关）。实测 EC_OP STARK 折叠 ~9.6×10⁸ steps vs secp ~5×10⁹（5 倍差，印证 Plan D 曲线选型） |
| P0.1/P0.4 客户端 reveal 守卫 | ✅ | `client/src/context/game/revealOwnCardGuard.ts` + `useCryptoOperations.ts` 集成；10 vitest 全绿；TSC 通过 |
| P0.2 服务端 assignment 不变量 | ✅ | `texas/src/pokergame/table/reveal.rs::reveal_invariant_tests`（3 测试） |
| P0.5 离开/弃牌防亮牌 bug | ✅ | 剥层输出公开 `input.c2−output.c2 = sk·c1`（= reveal token）——玩家自己的手牌槽必须原样保留，否则其余玩家串谋可解密其底牌。修复链：`LeaveGameRound::execute_with_exclusions`（协议层）+ wasm `leave_game(excluded)` + 客户端 `ownHoleCards.ts` c1 锚点缓存 + 服务端三处强校验（本地/Sui/外部 poker_l1 fold_with_proof 均从状态推导排除集，fail-closed）；回归 5 测试（`poker_protocol/tests/leave_exclusion.rs`） |
| P0.6 完整一手牌全流程测试 | ✅ | `texas/src/pokergame/table/full_hand_tests.rs`：2 人与 9 人（满桌/最低），StarkCurve——每人各洗一次（真实 BG V2 逐个验证）→ 发两张 → HandReveal（他人 token + 持有者本地解密命中明文牌组）→ 盲注 + 四条街 check/call → 每街 CommunityReveal → ShowdownReveal（各自交份额）→ settle_hand 判胜（win_messages 非空、5 张公共牌、摊牌手牌全公开）。覆盖用户指出的缺口：此前只有认可批次测试 |
| P0.3 文档债 | ✅ | `dual_settle.rs` EC_OP 事实修正 + DAPV 展开与外部 workspace 文档链接 |
| P1.1 StarkCurve 后端 | ✅ | `poker-protocol-core/src/stark_curve.rs`（Jacobian + mod-n 标量 + Poseidon 域）；core 35 测试 + oracle 对拍；proofs 回归 12 测试 |
| P1.2 DefaultCurve 切换 + wasm | ✅ | `legacy-bls` feature 门控；`client-wasm` wasm32 check 通过（blst blocker 消除）；texas 过渡态编译通过 |
| P1.3 双曲线共存 | ✅ | abi `CurveId::StarkCurve = 6`；texas 过渡态 legacy-bls 构建；新表默认 STARK 曲线 |
| P1.4 链上验证 | ✅ | host 侧（认可 STARK 化、Poseidon reveal_commitment v2、parity 测试 5）+ **合约侧**：`poker_contracts/src/dual/hand_batch_stark.cairo`（EC_OP builtin 变体，Poseidon challenge/rho 复刻 host 分帧，snforge 5/5：honest/tamper×2/跨手重放/畸形）；`verify_and_settle_dapv_stark` 入口接入 PokerDualSettlement；实测 EC_OP 折叠步数 ≈ secp syscall 版的 1/5。**poker_l1 VM**：外部 core 移植 StarkCurve 后端（62 测试全绿）+ `stark-curve` feature 化；VM 层 14600 行 blstrs 硬绑定（85 处）+ AIR 耦合按 MIGRATION.md 分阶段（feature 已就绪，VM 体内迁移为外部 workspace 工程） |
| P2.1 认可密钥客户端化 | ✅ 完成 | wasm `endorsement_keypair`/`endorsement_mint`；WS 双事件（`ENDORSEMENT_REQUEST` 广播 / `ENDORSEMENT_SUBMIT` 提交，会话钱包一致性校验）+ HTTP `POST /starknet/endorsement`；hooks 两阶段（prepare_dapv_binding 提前派生 → 广播 → spawn 收集 10s 超时 → build_from_client）；**服务器托管路径已删除**（ENDORSEMENT_KEYS/endorsement_keys_for/build_dual_settlement 移除，收不齐仅走 legacy 结算并日志降级）；客户端 `endorsementClient.ts` 能力探测 + sk 本地持久化 |
| P2.2 cash-out | ✅ 完成 | vault `burn_chips`（仅授权 helper，`set_authorized_helper` owner 门控）+ anonymizer `privacy_withdraw`（pool-only，烧筹码 1:1，输出 note 给出金地址）+ snforge 4 测试（happy/未授权/非池/超额）；客户端 `withdrawViaPrivacyPool`（`VITE_UNSHIELD_ENABLED` 门控，ABI 已加 privacy_withdraw） |
| P2.3 RFP 叙事 | ✅ | `docs/starknet-rfp-submission.md` |
| P3 测试+指标 | ✅ | `docs/plan-d-p3-metrics.md` + `plan_d_perf.rs`（release 7 项基线）+ stark_curve_regression 12 用例 |

## 7. 依赖与顺序

```
P0.1/0.2/0.4 客户端守卫 ──► 独立，立即
P0.3 文档（EC_OP 修正已完成，DAPV 展开待做）
Diligence(wasm 编译 + hand_batch.cairo 定位) ──► P1.1 StarkCurve 后端
  ──► P1.2 切换+序列化+wasm（消 blst blocker）──► P1.3 密钥滚动（并行）
  ──► P1.4 EC_OP 全残差批次 + 认可切换 + Poseidon 统一
P2.1 认可密钥客户端化（依赖 hand_binding 稳定，可与 P1.4 并行开发）
P2.2 cash-out anonymizer（独立）
P3 触发式
```

## 8. 谁能看到什么（P0+P1 落地后）

| 观察 | 状态 |
|---|---|
| 服务器（诚实） | 牌面盲（N−1 份额 + 持有者本地解密），结算摘要 + 认可批次可见 |
| 服务器（恶意） | 无法解密任何底牌（客户端守卫拒绝非 showdown 自牌 assignment）；最多 griefing（踢人/停服） |
| 链上观察者 | 每手一个 `hand_binding` + EC_OP 折叠校验（全残差）；筹码经 pool 的进出可见，玩家↔资金链接被切断 |
| 审计/合规 | viewing key（pool 原生）+ 争议驱动 STARK 复核（G 层摘要） |
