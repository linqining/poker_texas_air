# TODO

> 盘点日期：2026-09-03。来源：`SETTLEMENT_PRIVACY_PLAN.md`、
> `ACTION_SIGNING_CENSORSHIP_RESISTANCE.md`、`docs/EXECUTION_PLAN.md`、
> `poker_contracts/DEPLOYMENTS.md`、`PERFORMANCE_FOLLOWUPS.md`、
> "Fix strk20 shielded balance NOT_REGISTERED" 会话遗留清单及代码内 TODO 标记。
> 排序原则：功能开发优先，主网相关放最后。

---

## 一、功能开发

### P0 — 尽快

- [x] **1. 牌局抽水显示**（2026-09-03 完成）
  - 实现：新增 `texas/src/pokergame/rake.rs`（公式与分层分摊逐字对齐链上
    `settle.rs`/`settlement.rs`，带单测）；摊牌路径 `collect_rake_for_settlement`
    在分池前抽水（争夺层按比例分摊、uncontested 层豁免）；fold-win 不抽水；
    `summary.rake_collected` 随 TABLE_UPDATED 下发，前端 winMessage 为净额并
    显示"本手台费"胶囊。参数读 `STARKNET_RAKE_BPS`/`STARKNET_RAKE_CAP`
    （缺省 500/1000，与链上同源）。

- [x] **2. 牌局记录看板**（2026-09-03 完成）
  - 实现：`texas/src/pokergame/history_store.rs`——`HandHistoryStore` 抽象接口 +
    `MemoryHistoryStore` 内存实现（每桌 FIFO 保留 100 条，换持久化只改
    `global_store()` 装配点）；两条终局路径（`finish_showdown` /
    `end_without_showdown`）统一记录；HTTP 端点 `GET /api/tables/:id/history`
    与 `/history/:hand_seq`；前端 `HandHistoryPanel`（Play 页"记录"按钮，
    行内展开公共牌/座位明细，i18n zh/en/de）。

### P1 — 短期

- [x] **3. 领取奖励 UI 重设计**（2026-09-03 完成）
  - 重写 `ClaimRewardsModal`：金额主卡（渐变焦点）+ 私密路径/赔付承诺状态卡
    （状态点 + 次级行降级技术细节）+ 单一主行动按钮 + 警告/错误/成功态卡片化；
    全部探测、注册、双路径领取逻辑逐字保留。

- [x] **4. time_bank 跨手不恢复（已核实：已修复，无需再动）**
  - 2026-09-03 复核：VM 的 `reset_for_next_hand` 已实现每手补充
    （`TIME_BANK_REFILL_PER_HAND_MS`，上限 `DEFAULT_TIME_BANK_MS`）并带单测
    （`test_consume_time_bank_*`）。原清单条目误读了 P2-11 修复注释的
    过去时描述。游戏层（texas/src/pokergame）无 time_bank 概念。
  - 位置：`poker_l1/src/vm/contracts/texas_poker/state_machine.rs:3411`。

- [ ] **5. NOT_REGISTERED 私密领取修复的遗留清单**
  > 修复本体已完成并链上验证通过（私密领取三动作上链、烧毁生效）。
  > 来源：Fix strk20 shielded balance NOT_REGISTERED 会话（2026-09）遗留清单。

  - [x] 缺口 B（fail-fast）：materialize 失败静默推进牌局 → 已修
        （2026-09-03，`on_reveal_complete` 前置 `materialization_broken()` 检查，
        失败即全额退款中止该手，走既有 refund+reset 路径）。
  - [x] 缺口 C（报错语义）：迟到重复提交静默 → 已补全
        （`is_benign_reveal_error` 扩展覆盖 "phase not active"——窗口关闭后的
        迟到重复按幂等成功处理；同窗口重复原已静默）。
  - [ ] **提交 git**：按主题拆分 commit（合约/anonymizer 重部署、协议三动作、
        开局基线重建、本轮 TODO 功能开发）。
  - [ ] `set_authorized_helper` owner 单点问题：建议冷存储 / 时间锁（运维动作）。
  - [ ] （可选）对账：链上筹码 5000 → 0 但领取为 4000，差额 1000 来自后续手牌
        `apply_settlement` 结算变动，可核对结算流水确认。

### P2 — 上线前

- [x] **6. API 速率限制**（2026-09-03 完成，G17）
  - 新增 `texas/src/ratelimit.rs`：/api 固定窗口限流（10s / 200 次 per-IP，
    超限 429），键取 ConnectInfo 对端 IP（serve 侧已改
    `into_make_service_with_connect_info`），不可得时退化全局桶；
    带窗口重置与桶 GC 单测。socket.io 通道不在该层（说明见模块注释）。

- [x] **7. 全局代码审核：消除潜在 panic**（2026-09-03 完成 Top-10，遗留低风险项见下）
  - 审计（Explore 全扫 texas/poker_protocol/client-wasm/poker_contracts）定位
    5 高 / 4 中 / 1 治理项，全部修复：
    H1 `transition_to` severe 迁移 panic → 降级 error 日志+强制落地（原会冻结牌桌）；
    H2 链上余额-locked_chips 下溢/截断 → saturating + i64::try_from（handlers
    与 socket/handlers 两处）；H3 `register_player` 重复注册 expect → 幂等化；
    H4 raise/call 金额裸减法 → saturating + `amount <= seat.bet` 拒绝；
    H5 `handle_call` 金额计算先于校验 → 校验前置 + saturating；
    M1 endorsement 注册表锁污染连锁 expect → into_inner；
    M2 `point_xy` 恒等点 expect → 全零编码+error 日志（下游 EC 自然拒绝）；
    C1 `poker_dual_settlement.cairo` ownership 循环缺 `p_batch.len()` 守卫 → 补断言；
    #9 `/api/dev/bot` 匿名路由 → release 默认关闭（debug 或 TEXAS_DEV_BOT_ENABLED=1）；
    #10 删除无调用者死代码 `verify_reveal_proofs_core` 等 3 函数（含裸索引）。
  - 遗留低风险（记录在案，暂不动）：dev_bot 路径 `rounds.rs` 的 expect（仅 dev）；
    workspace release 开 `overflow-checks` 的权衡；SITTING_OUT/IN 补
    `verify_socket_sender_seat`（越权写，非 panic）；宏 `parse_payload!` 等
    已确认安全的 unwrap/索引保持现状。

---

## 二、结算隐私 Phase 2 / C3.2（电路规格已定稿）

> 排期表见 `SETTLEMENT_PRIVACY_PLAN.md` §开发排期；P2-M1 电路规格已定稿，按此实施。

- [x] **8. P2-M1 电路**（2026-09-03 骨架完成，验收=电路单测通过：10/10 ✅）：
  新增 `src/settlement_private_circuit.rs`——语句/见证类型、规格 trace 布局
  （每参与者一列组 ×(player, sign, |delta|, winner, cm, count)）；digest 与
  claim_cms 的 host 参考实现与 `submit.rs`/合约逐字段对齐（单测交叉验证）；
  Stwo AIR：witness↔scope 逐 limb 绑定、sign/winner booleanity、winner⇒sign、
  非赢家 cm 归零、计数绑定，scope 承诺根验证端重算比对；**§8.2 预留**：动作签名
  域/action_flags/accepted-seq 列位冻结并在电路上强制为零（M2 接线零重排）。
  **M2 待接入**：felt252 Poseidon component（digest 吸收链、claim_cms 原生推导）
  与多 limb 零和累加（模块头注释有诚实边界说明）。
  验收口径：`cargo test -p poker_texas_air --lib settlement_private_circuit`。
- [ ] **9. P2-M2 证明端**（2026-09-03 完成：电路 + 服务端接缝全通，实测 8.6-10.9s << 30s ✅）：
  - ✅ Cairo1 电路 `proving-tool/src/settlement_private.cairo`：规格四条约束全部
    落进证明（digest 匹配、零和、人数、赢家 claim_cms 原生推导，签名/值域守卫）；
    公开段 = `[MAGIC, hand_id, digest, n, binding, cm_0..cm_7]`——(players, deltas,
    commitments) 全部留在 witness，不进公开段。
  - ✅ 端到端脚本 `proving-tool/scripts/prove-settlement.sh`：Rust 参考
    （starknet_crypto）生成夹具 → prove-hand（Cairo VM → Stwo prove → verify）→
    跨语言公开段逐 felt 对齐（13 felt）→ registered_digest 篡改负例拒绝。
  - ✅ 服务端接缝 `texas/src/starknet/settlement_prover.rs`：请求构建
    （digest 重算与 register 口径一致、零和/值域/赢家承诺校验，6 单测）+
    `fetch_payout_commitments`（async vault 读）+ inputs 导出（best-effort，
    workload 目录）+ `HttpSettlementProver`（公开段本地重算校验——prover 无法
    用别的语句蒙混）；已接入 `submit_dual_settlement` proved 分支（非阻塞，
    失败仅告警）。prover 服务形态：`proving-tool/scripts/prover_service.py`
    （HTTP 包 prove-hand，负例 422，实测回路 10.9s）。
  - ⬜ 剩余：与 #10 P2-M3 成对——合约 `verify_and_settle_dapv_stark_private_v2`
    消费公开段 + Stwo Cairo verifier（官方移植或 fact-registry）；动作级 SK
    签名纳入动作日志（#16 落地后进吸收链，列位已预留）。
- [x] **10. P2-M3 合约验证端**（2026-09-03 完成：fact-registry 过渡形态，验收=零明文
  calldata ✅ 74/74 snforge）：
  - ✅ 电路增发 `total_winnings`（公开段 14 felt：`[MAGIC, hand_id, digest, n,
    binding, cm_0..cm_7, total]`），prove-settlement 端到端重跑全过（15.3s）；
  - ✅ 合约 `verify_and_settle_dapv_stark_private_v2`：calldata 只有
    `(hand_binding, hand_id, segment)`——**无 players/deltas**；入口校验段形
    （MAGIC/hand_id/binding/n）+ digest 对注册值 + fact 锚
    `poseidon([program_hash ++ segment])`（`set_circuit_program_hash` 钉电路 +
    `register_settlement_fact` prover/owner 登记）→ 托管 `total_winnings` +
    写 `claim_cms` + `amounts_hidden`；`consume_claim`/anonymizer 走隐藏模式
    （cm 绑定金额，escrow 余额封顶 Σ claim）。snforge 4 用例：诚实零明文结算 /
    算改 digest / 缺 fact / 重放全过；
  - ⬜ 剩余（与 #11 成对）：fact 登记的信任升级——Stwo Cairo verifier 上链
    （vendored `third_party/proving/stwo_cairo_verifier`）或 SNIP-36 fact
    registry，替换 operator 登记的 residual trust；sepolia 部署 + gas/size
    实测归入 #11。
- [ ] **11. P2-M4 联调部署**（2026-09-03 测量/文档/脚本完成，**链上部署被 sepolia
  gas 预算阻塞——需给 poker-deployer 补 ≈77 STRK**）：
  - ✅ 测量：dual v3 class = sierra 859 KB / casm 737 KB / 32,901 words；
    declare 需 l2_gas 2.86e9 单位 ≈ 142 STRK（实时价），账户余额 65 STRK；
    电路证明 14s / 2021 步 / 公开段 14 felt。
  - ✅ 脚本 `poker_contracts/scripts/deploy_sepolia_v3.sh`：declare（自动处理
    sepolia compiled-hash 方案差异，`--compiled-hash` 重试）→ deploy(owner,
    vault, prover) → set_claim_helper → set_circuit_program_hash → 回填
    texas/.env。文档详见 `poker_contracts/DEPLOYMENTS.md` 末节。
  - ⬜ 剩余：补 STRK 后执行脚本，然后把 texas 服务端指到 v3 做一笔真实
    零明文结算联调（配合 #28 的 sepolia 侧实机验证）。
- [ ] **12. C3.2-M1 认领 sidecar**：Node sidecar 封装 STRK20 私密转账
  （运营浮存 → 赢家 viewing key note），Rust 服务端 HTTP 调用；需 SDK 依赖 + 服务器 KMS。
  **前置核查（2026-09-03）**：官方 STRK20 Privacy SDK 仍未上 npm（registry 检索只有
  社区第三方包）——SDK_SEAM 继续阻塞本节全部四项；SDK 上线后按
  `docs/starknet-plan-b-anonymizer.md` §SDK_SEAM 核对 `tryComposeInvoke` 即可开工。
- [ ] **13. C3.2-M2 赔付路由**：settle 后异步队列：延迟抖动 + 批量 shield 补浮存 + 失败重试。
- [ ] **14. C3.2-M3 通知与 UX**：加密赔付通知推送 + 领取入口 UX；赢家零操作看到 note。
- [ ] **15. C3.2-M4 合规加固**：限额/频控/审计日志 + 运营手册。

**C5 验证清单（未勾完项）**：

- [ ] Ready 实机端到端：登录 → 买入 → 对局 → 私密领取（剩余人工钱包弹窗点击这一步，
  步骤见 `SETTLEMENT_PRIVACY_PLAN.md` §实机端到端剩余一步）。
- [ ] starknet-react / starknetkit 与 starknet.js 10.6.8 兼容矩阵。
- [ ] 池费 `get_fee_amount` 运行时读取（不硬编码）；赔付额 ≥ 池费的边界处理。
  （2026-09-03 核查：客户端/服务端现状**无**池费硬编码——该项是 #12 C3.2 sidecar
  构建时的前置要求，非独立任务，随 sidecar 一并交付。）
- [ ] 清理死代码 `client/src/starknet/cartridge.ts` + 移除 `@cartridge/*` 依赖。

---

## 三、抗审查（设计定稿、未实施，排期归 Phase 2-M2）

> 设计全文：`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md`。
> ⚠️ §8 硬约束：消息格式、事件字段、电路约束**现在就要预留**
> （动作签名+seq、服务器收据、accepted-seq、auto 标记、债券合约位），
> 否则后补会破坏签名域或触发电路重写——与第 8 项 P2-M1 的预留约束是同一件事。

- [x] **16. 动作签名落地**（2026-09-03 完成，三层回归绿）：
  - poker_protocol `game_action.rs`：StarkCurve 签名（msg = `zgame.action-sig.v1`
    || table_id || seq || action || amount，挑战绑定 r），sign/verify + 篡改/
    换桌/换 pk 负例 4 单测；
  - client-wasm `sign_action` 导出（pkg 已重建）；客户端 useGameActions 四动作
    附 `(seq, rHex, sHex)`，seq 按桌 localStorage 单调（`actionSigning.ts`，
    wasm 缺失时回退未签名）；
  - 服务端 `process_action` 单一派发点验签（seat pk）+ seq 严格单调检查 +
    `action_log`/`accepted_seq` 记账；`acceptedSeqs` 随 ClientTable 广播。
    迁移期：未签名动作默认放行（enforcement 开关后续接 env）。
- [x] **17. accepted-seq 承诺 + auto 代打标记**（2026-09-03 完成游戏层部分）：
  超时代打（fold/check/call 三路径）入日志并标 `auto`（seq 服务器分配 =
  accepted+1）；`acceptedSeqs` 向量随 ClientTable 广播（settle 前玩家可见）。
  ⬜ 剩余（可后置）：operator 对回执的服务端签名（`Sig_operator`）——需
  服务器游戏域密钥管理，当前以日志 + 广播向量作为可举证形态。
- [ ] **18. auto 默认动作签名化**：服务器代打标 `(auto, server_sig)`；
  **电路必须校验"合法默认"（零下注才可 auto-check，面对下注只能 auto-fold）后才可上线**
  ——否则服务器可借代打折叠任意玩家。
- [ ] **19. 实施前确认 4 个开放问题**：seq 持久化粒度（per-table / per-hand）；
  电路内验签 vs 链下预验签；replayer 最小数据集；双通道备用端点选型。

---

## 四、协议 / 证明层长期项

- [ ] **20. mirror 证明层与游戏 deck 客户端协议对齐**：浏览器玩家 mirror 份额缺失曾致
  settle 阻断（09-01 已通过回退路径跑通结算，证明层对齐仍是遗留）。
  按 `DUAL_PROOF_PROTOCOL.md` §5.3，独立工作量。见 `poker_contracts/DEPLOYMENTS.md:140`。
- [ ] **21. Phase 3：独立 prover 服务**：`STARKNET_PROVER_URL` 从 stub 变真实端点，
  移除 host attestation。见 README Roadmap。
- [ ] **22. canonical AIR 缺口**：reveal/reconstruction 密码学、final shuffle/reveal
  阶段切换、完整 timeout/terminal 级联、settlement、state-root 重算仍在 AIR 之外。
  见 `docs/STATUS.md`。
- [ ] **23. Layer 3 递归协议**：Texas 自有递归协议尚未实现（生产验证入口保持关闭）；
  无 sound 递归/简洁聚合证明，验证成本仍 O(N)。见 `src/lib.rs:12`、`docs/PO5_PO6_DESIGN_NOTES.md`。
- [ ] **24. 性能 followups**（需 release 基准 + soundness 矩阵后实施）：
  专用标量乘 AIR、MSM 平衡树、limb backend 选型、outer_aggregate 流式编码、
  错误分类、`/metrics` 路由。见 `PERFORMANCE_FOLLOWUPS.md`。
- [x] **25. 全链路私密提现**（2026-09-03 合约完成，snforge 77/77 ✅）：
  - vault `withdraw_to(player, recipient, amount)`：helper 门控（独立
    `unshield_helper` 信任门 + `set_unshield_helper` owner 设置），烧筹码并把
    STRK 定向转出（不经过玩家公开钱包）；
  - 第二个 anonymizer `CashoutUnshieldHelper`（unshield 方向）：
    `chip_to_note(amount, note_id)`——玩家发起，vault.withdraw_to 进 helper →
    approve 池 → 返回 `OpenNoteDeposit`（与 anonymizer 返回形状一致，池侧
    集成属 SDK_SEAM）。snforge 3 用例：烧筹码+approve 断言、无筹码回退、
    非绕过 helper 直调 vault 回退。
  - ⬜ 剩余（依赖外部）：池侧 note 应用入口（SDK_SEAM，随 #12 SDK）；
    生产部署归入下一轮 vault/合约重部署批次。
- [ ] **26. STRK20 官方 SDK 跟踪**：SDK 上 npm 后核对 `tryComposeInvoke` 接口
  （当前运行时探测 + 公开路径回退）。
- [ ] **27. 杂项**：`texas/src/starknet/hooks.rs:168` 滞后 TODO 注释清理。

---

## 五、主网相关（最后）

- [ ] **28. 主网 ≥1 笔 STRK20 交易**（黑客松硬性要求，**需用户钱包人工操作**）：
  操作指引见 `docs/MAINNET_TX_GUIDE.md`（方案 A 钱包直接转账 ≈5 分钟，推荐先行；
  方案 B PokerVault 主网最小部署可选）。完成后交易哈希回填 strk20.json
  （模板见指引）。
  现状：`strk20.json` 的 `token.mainnet_address` 为空，未记录任何主网交易。
- [ ] **29. strk20.json 收尾**：`token.mainnet_address` / `sepolia_address` 回填；
  demo_video / demo_url / transactions 补全。
- [ ] **30. paymaster 生产加固**：中继请求附钱包签名（session key / typed-data）鉴权。
  位置：`texas/src/starknet/paymaster.rs:145`。主网开放前必须完成。
- [ ] **31. 债券 / 罚没合约（Phase 3）**：operator 链上质押债券；被证明的审查
  （签名动作 + accepted-seq 缺口）触发罚没赔付；债券 > 最大可窃取价值。主网化前提。
- [ ] **32. Demo 视频**：录"浏览器验证 G 证明"录屏（配合主网交易展示）。
