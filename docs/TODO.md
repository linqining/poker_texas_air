# TODO

> 盘点日期：2026-09-03。来源：`SETTLEMENT_PRIVACY_PLAN.md`、
> `ACTION_SIGNING_CENSORSHIP_RESISTANCE.md`、`docs/EXECUTION_PLAN.md`、
> `poker_contracts/DEPLOYMENTS.md`、`PERFORMANCE_FOLLOWUPS.md` 及代码内 TODO 标记。
> 排序原则：功能开发优先，主网相关放最后。

---

## 一、功能开发

### P0 — 尽快

- [ ] **1. 牌局抽水显示**
  - 现状：抽水只存在于链上结算（`compute_rake`，默认 5% / 上限 1000，翻后争夺底池才抽，
    见 `poker_l1/src/vm/contracts/settle.rs:106`、`texas/src/starknet/mirror.rs:49`）；
    **链下分池与前端完全没有抽水概念**——`determine_winner_by_ids` 把整池分给赢家，
    前端 winMessage 显示全池金额，与链上实际到账不一致。
  - 改法：服务器在 `end_without_showdown` / `determine_winner_by_ids` 分池时按
    `STARKNET_RAKE_BPS`（与 mirror 口径一致：翻后争夺底池才抽）先扣 rake 再分配，
    结算消息带上 rake 字段；前端渲染"到手金额 / 抽水"。
  - 位置：`texas/src/pokergame/table/pot.rs:203`、`lifecycle.rs:21`；
    前端 `client/src/context/game/useGameSocket.ts`、`pages/Play.tsx`。

- [ ] **2. 牌局记录看板**
  - 现状：只有"当前这一手"的快照数组 `summary.history`（新手牌开始即清空），
    无跨手历史、无查询 API、无 UI。
  - 改法：定义抽象存储接口（trait `HandHistoryStore`），内存实现保留最近 100 条；
    服务器新增历史查询端点（现有 HTTP API 无 history 路由）；
    前端看板组件（按桌/按手浏览，含底池、公共牌、赢家）。
  - 位置：`texas/src/pokergame/table/mod.rs:563`、`texas/src/main.rs:89-112`。

### P1 — 短期

- [ ] **3. 领取奖励 UI 重设计**
  - 现状：`ClaimRewardsModal` 功能完整（能力探测/池内余额/赔付承诺注册/私密+公开双路径），
    但样式朴素（InfoRow 列表 + 少量内联 style）。
  - 改法：按现有主题体系重新设计视觉（层级、留白、状态徽标），可用 ui-toolkit MCP
    生成/审计组件。
  - 位置：`client/src/components/modals/ClaimRewardsModal.tsx`。

- [ ] **4. time_bank 跨手不恢复（缺陷）**
  - 代码注释明示：补充逻辑未实现，time_bank 仅单调下降，无法跨手恢复。
  - 位置：`poker_l1/src/vm/contracts/texas_poker/state_machine.rs:3413`。

### P2 — 上线前

- [ ] **5. API 速率限制**（G17 TODO）：服务器 HTTP/socket 无 rate limiting。
  位置：`texas/src/main.rs:113`。

---

## 二、结算隐私 Phase 2 / C3.2（电路规格已定稿）

> 排期表见 `SETTLEMENT_PRIVACY_PLAN.md` §开发排期；P2-M1 电路规格已定稿，按此实施。

- [ ] **6. P2-M1 电路**：Stwo 电路证明 `(players, deltas)` 匹配已登记 digest ∧ 零和 ∧
  人数一致，输出 claim_cms。**预留约束（硬约束）**：动作签名 + auto 默认动作合法性 +
  accepted-seq（见第三节 §8.2）。验收：电路单测通过。
- [ ] **7. P2-M2 证明端**：server 从明文生成 trace + proof（复用 orchestrator）+
  动作级 SK 签名纳入动作日志。验收：真实手牌证明 < 30s。
- [ ] **8. P2-M3 合约验证端**：Stwo Cairo verifier（官方移植或 fact-registry，M3 定）+
  `verify_and_settle_dapv_stark_private_v2` 接入 π。验收：calldata 零明文。
- [ ] **9. P2-M4 联调部署**：sepolia 部署 + gas/size 测量 + 文档。
- [ ] **10. C3.2-M1 认领 sidecar**：Node sidecar 封装 STRK20 私密转账
  （运营浮存 → 赢家 viewing key note），Rust 服务端 HTTP 调用；需 SDK 依赖 + 服务器 KMS。
- [ ] **11. C3.2-M2 赔付路由**：settle 后异步队列：延迟抖动 + 批量 shield 补浮存 + 失败重试。
- [ ] **12. C3.2-M3 通知与 UX**：加密赔付通知推送 + 领取入口 UX；赢家零操作看到 note。
- [ ] **13. C3.2-M4 合规加固**：限额/频控/审计日志 + 运营手册。

**C5 验证清单（未勾完项）**：

- [ ] Ready 实机端到端：登录 → 买入 → 对局 → 私密领取（剩余人工钱包弹窗点击这一步，
  步骤见 `SETTLEMENT_PRIVACY_PLAN.md` §实机端到端剩余一步）。
- [ ] starknet-react / starknetkit 与 starknet.js 10.6.8 兼容矩阵。
- [ ] 池费 `get_fee_amount` 运行时读取（不硬编码）；赔付额 ≥ 池费的边界处理。
- [ ] 清理死代码 `client/src/starknet/cartridge.ts` + 移除 `@cartridge/*` 依赖。

---

## 三、抗审查（设计定稿、未实施，排期归 Phase 2-M2）

> 设计全文：`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md`。
> ⚠️ §8 硬约束：消息格式、事件字段、电路约束**现在就要预留**
> （动作签名+seq、服务器收据、accepted-seq、auto 标记、债券合约位），
> 否则后补会破坏签名域或触发电路重写——与第 6 项 P2-M1 的预留约束是同一件事。

- [ ] **14. 动作签名落地**：client-wasm `sign_action` 导出（~20 行）；客户端动作附
  `(seq, sig)` + seq 持久化；服务器验签（seat pk）+ seq 单调检查 + 动作日志入 ProveTask。
- [ ] **15. 签名回执 + accepted-seq**：服务器每动作回签收据
  `Sig_operator(player, hand_id, seq, 决定)`；settle 事件追加每玩家 accepted-seq 向量。
- [ ] **16. auto 默认动作签名化**：服务器代打标 `(auto, server_sig)`；
  **电路必须校验"合法默认"（零下注才可 auto-check，面对下注只能 auto-fold）后才可上线**
  ——否则服务器可借代打折叠任意玩家。
- [ ] **17. 实施前确认 4 个开放问题**：seq 持久化粒度（per-table / per-hand）；
  电路内验签 vs 链下预验签；replayer 最小数据集；双通道备用端点选型。

---

## 四、协议 / 证明层长期项

- [ ] **18. mirror 证明层与游戏 deck 客户端协议对齐**：浏览器玩家 mirror 份额缺失曾致
  settle 阻断（09-01 已通过回退路径跑通结算，证明层对齐仍是遗留）。
  按 `DUAL_PROOF_PROTOCOL.md` §5.3，独立工作量。见 `poker_contracts/DEPLOYMENTS.md:140`。
- [ ] **19. Phase 3：独立 prover 服务**：`STARKNET_PROVER_URL` 从 stub 变真实端点，
  移除 host attestation。见 README Roadmap。
- [ ] **20. canonical AIR 缺口**：reveal/reconstruction 密码学、final shuffle/reveal
  阶段切换、完整 timeout/terminal 级联、settlement、state-root 重算仍在 AIR 之外。
  见 `docs/STATUS.md`。
- [ ] **21. Layer 3 递归协议**：Texas 自有递归协议尚未实现（生产验证入口保持关闭）；
  无 sound 递归/简洁聚合证明，验证成本仍 O(N)。见 `src/lib.rs:12`、`docs/PO5_PO6_DESIGN_NOTES.md`。
- [ ] **22. 性能 followups**（需 release 基准 + soundness 矩阵后实施）：
  专用标量乘 AIR、MSM 平衡树、limb backend 选型、outer_aggregate 流式编码、
  错误分类、`/metrics` 路由。见 `PERFORMANCE_FOLLOWUPS.md`。
- [ ] **23. 全链路私密提现**：vault `withdraw_to` + 第二个 anonymizer（unshield 方向）。
  见 `docs/starknet-plan-b-anonymizer.md` §已知 seam。
- [ ] **24. STRK20 官方 SDK 跟踪**：SDK 上 npm 后核对 `tryComposeInvoke` 接口
  （当前运行时探测 + 公开路径回退）。
- [ ] **25. 杂项**：`texas/src/starknet/hooks.rs:168` 滞后 TODO 注释清理。

---

## 五、主网相关（最后）

- [ ] **26. 主网 ≥1 笔 STRK20 交易**（黑客松硬性要求）：在 PokerVault 主网最小部署与
  直接 STRK20 转账两案中选最简者；交易哈希写入 strk20.json。
  现状：`strk20.json` 的 `token.mainnet_address` 为空，未记录任何主网交易。
- [ ] **27. strk20.json 收尾**：`token.mainnet_address` / `sepolia_address` 回填；
  demo_video / demo_url / transactions 补全。
- [ ] **28. paymaster 生产加固**：中继请求附钱包签名（session key / typed-data）鉴权。
  位置：`texas/src/starknet/paymaster.rs:145`。主网开放前必须完成。
- [ ] **29. 债券 / 罚没合约（Phase 3）**：operator 链上质押债券；被证明的审查
  （签名动作 + accepted-seq 缺口）触发罚没赔付；债券 > 最大可窃取价值。主网化前提。
- [ ] **30. Demo 视频**：录"浏览器验证 G 证明"录屏（配合主网交易展示）。
