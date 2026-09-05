# TODO

> 重梳日期：2026-09-05（全项目文档审核后整体重写）。上一版（2026-09-03 盘点）
> 的逐项详细完成记录见 git 历史（文档清理 commit 之前的 TODO.md）；已完成项
> 在文末压缩归档。编号与历史保持连续（其他文档仍引用 #N）。
> 排序原则：功能开发优先，主网相关放最后。

---

## 〇、文档地图（2026-09-05 审核后的现行权威）

| 文档 | 角色 |
| --- | --- |
| `README.md` / `README.zh-CN.md` | 项目入口、信任模型、Roadmap |
| `SETTLEMENT_PRIVACY_PLAN.md` | 结算隐私 P2 权威方案（digest 公式已按 #18 Phase B 更新） |
| `ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` | 抗审查唯一设计文档（主体已实施，状态见头注；§8.2 仍为主网门槛规格） |
| `DUAL_PROOF_PROTOCOL.md` | 结算目标架构（v2.9 头注对齐 Plan D / #18 Phase B） |
| `DAPV_SOUNDNESS.md` | DAPV 可靠性论证（v1.2 头注：生产 = Stark EC_OP + Poseidon） |
| `TEXAS_TAGGED_AIR.md` | tagged/canonical AIR 能力边界（29 selectors） |
| `PERFORMANCE_FOLLOWUPS.md` | 性能候选项门槛方法论（处置结论见 #24） |
| `docs/STATUS.md` | **canonical AIR 覆盖/缺口权威表述源**（2026-09-05 按现状重写） |
| `docs/plan_d_perf.md` | Plan D 后唯一性能基线（7 项） |
| `docs/plan-d-p3-metrics.md` §3b | 主网 gas 校准唯一数据（§1 旧基线已标失效） |
| `docs/starknet-plan-b/c/d-*.md` | 匿名化 / 执行层 / 曲线迁移政策（头注标终态） |
| `docs/MAINNET_TX_GUIDE.md` | #28 主网交易唯一操作指引 |
| `docs/RFP03_ALIGNMENT.md` · `docs/starknet-rfp-submission.md` | 对外对齐 |
| `poker_contracts/DEPLOYMENTS.md` | 合约部署地址/接线权威账本 |
| `docs/TEXAS_SOURCE_SLIMMING_AND_BATCH_DESIGN.md` | poker_l1 合约库 schema v3→v30 唯一设计史 |

**历史存档**（`docs/archive/`，均已加头注，仅史料价值）：
`HOST_ZERO_RISTRETTO_AIR`（Ristretto 宪章，路线已关闭）、`PERFORMANCE_REPORT`、
`PERFORMANCE_V2_PROTOCOL`（旧世界性能，被 plan_d_perf 取代）、
`TRUST_MODEL_NO_TRANSACTION_REPLAY`（链交易重放模型已废）、`SOUNDNESS_FIXES`、
`EXECUTION_PLAN`（迁移蓝图已执行完）、`MIRROR_UNIFICATION_PLAN`（被 #20 Phase 2
取代）、`PO5_PO6_DESIGN_NOTES`（VM 架构快照）。

---

## 一、立即行动（P0）

- [x] **34. dual v3.x 合约重部署 + 服务端切换（2026-09-05 完成）**
  - ✅ 部署：Dual v3.x `0x55784c90...`（class `0x6db1ea08...`）、新 claim helper
    `0x60a4c474...`（class `0x5c28571f...`，3 参构造 vault/pool/settlement——
    发现旧在网 class `0x5ec1...` 是无 settlement 绑定的 2 参旧版，一并修复）。
  - ✅ 接线（全部 SUCCEEDED）：`set_claim_helper` → `set_circuit_program_hash(
    0x25d81d2c...)`（新电路）→ vault v3 `set_settlement_contract(新 dual)`
    （切换点）。冒烟：`register_hand` 新 7 参 ABI 上链成功，
    `hand_action_log` 读回动作日志承诺 ✓（TX `0x4f0788df...`）。
  - ✅ 账本：`texas/.env`（dual + claim helper）、`DEPLOYMENTS.md`、
    `strk20.json` 已回填；旧 dual/旧 helper 保留服务历史认领。当前无运行中
    服务进程，下次启动即用新 ABI。
  - ✅ **链上真实结算冒烟（2026-09-05）**：真实证明链 + 认可批次的
    register（`0x28ab0dc7...`）+ settle（`0x1215cde0...`，SUCCEEDED）；
    **gas 实测（2 人合成手）：l2_gas 4,313,040 + l1_data_gas 288**。冒烟
    测试：`sepolia_settle_smoke`（`STARKNET_SEPOLIA_SMOKE=1` 触发）。

- [ ] **33（剩余）. 在局锁定应用内 e2e（需 Ready 实机）**
  入座触发服务端自动 lock → 游戏中领取弹窗显示在局锁定 → 打完一手结算
  续钟 → 离桌 TTL 解锁。链上强制已实测（2026-09-04 冒烟通过：lock→精确
  回滚→force_unlock），本条纯联调，配合 #34 切换后的实机环境一起做。

## 二、功能开发（P1）

- [x] **18（Phase C）. 电路内"合法默认"约束（主网上线门槛）——完成（2026-09-05）**
  **✅ 切片 1**：动作日志哈希链 keccak→Poseidon——游戏层 `action_log_digest_felt`
  改 Poseidon sponge；电路增加词条区用 poseidon_builtin 重放整链并断言链根
  == settlement digest 中的动作日志哈希；program hash 已上链。
  **✅ 切片 2（同日）**："合法默认"约束本体——`ActionLogEntry` 扩展下注语境
  （owed/my_bet/big_blind，`record_action` 单一收口点从桌状态派生，与
  `handle_auto_fold` 逐字段同源）；词条布局 2 词 × 30 槽（日志打包词 +
  合法性词 `kind(2)|owed(64)@2|my_bet(64)@66|big_blind(64)@130`，总参数
  98/100）；电路解包日志词做 action 白名单（FOLD/CHECK/CALL/RAISE）+
  flags 拆位，对 auto 词条强制 `legal_auto_action` 规则（零下注⇒Check、
  差额≤大盲⇒Call、差额>大盲⇒Fold，Raise/非法 kind 拒绝），非 auto 词条
  合法性词 canonical 0。验证：prove-settlement e2e 全通 + **非法默认负例**
  （auto FOLD 谎称 Check → 电路中止 ✓）——§8.2 主网门槛条款达成；
  新 program hash `0x744d16d3...` 已上链（TX `0x55f9297b...`）并视图验证 ✓。
  回归：根 crate 电路 11/11、texas starknet 快速集 35/35、auto_action 5/5。
  说明：accepted-seq 单调约束（`accepted_seq_digest` 槽）仍保留为零，作为
  Phase C 后续可选加固（当前 seq 校验在服务端 + 收据举证）。

- [x] **19. 实施前确认 4 个开放问题**（2026-09-05 定稿，决策全文 =
  `ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §9）：① seq = per-table 单调、
  跨手不重置（与现行实现一致，重置窗口即重放窗口）；② 电路内验签否决——
  现管线无 keccak/EC builtin，电路只约束日志哈希吸收 + "合法默认"规则，
  完整验签归上链验证路线（#22/M3）；③ replayer 最小数据集 =
  HandProofLog ∪ 本手动作日志窗口（收据为客户端可选补强）；④ 双通道 =
  客户端多 RPC failover + 服务器端点列表化（不引入信任），争议终局走链上
  证据（#31）。附 Phase C 实施要点：动作日志哈希链 keccak→Poseidon 切换。
- [ ] **22. canonical AIR 缺口收口**（权威表述 = `docs/STATUS.md`，2026-09-05
  重写）：
  ① ~~全残差批次 sepolia 单笔 settle gas 实测~~ **已完成（2026-09-05）**：
  2 人合成手全残差批次单笔 settle 实测 l2_gas 4,313,040 + l1_data_gas 288
  （sepolia TX `0x1215cde0...`；9 人真实手待实机联调细化，见三）；
  ② **ShuffleComplete 已组合（2026-09-05）**：`CanonicalProtocolCompletionKind`
  增 `Shuffle`，opening 校验（`validate_shuffle_completion_opening`）+ AIR
  组合约束（phase Shuffling→Revealing、subtag/street 不变、turn=NO_SEAT、
  reveal pending=活跃集、deck 轮转锚定 pre/post 端点、deadline=ts+
  reveal_timeout、hole 游标 0→2N），直接验证器对完成 opening 的 host 校验
  全部生效；完成单元布尔化 + 度数回归 3 ✓（canonical 145/145 含 4 个篡改
  负例）。**RevealComplete 仍 fail-closed**：其 post 状态含位置规则
  current_turn（BB 后首个活跃座/heads-up 特例）与盲注派生 current_bet，
  需先设计盲注/规则 opening（无 AIR 可锚定源），见 STATUS.md；
  ③ ~~终端级联批量证明~~ **复核除名（2026-09-05）**：验收批量已存在并通过
  （award/reset/raked 三套级联批量测试 + schedule 篡改负例）；
  ④ **reconstruction 提交解除 fail-closed —— 完成（与 ShuffleComplete 同批）**：
  `validate_direct_batch` 对 SubmitShuffle/SubmitReconstruct 放行
  （SubmitReveal/FoldWithProof 维持拒绝）；协议行全字段冻结集进 AIR
  （turn=NO_SEAT 双端、current_bet/min_raise/pot/chip_pool、acted/leave
  掩码、hand_id、timeout 配置、board/rit 承诺、9 座位全像、shuffle 行的
  reveal/reconstruction 不变——全部 gate 在度数 1 的 is_protocol_submit）；
  测试：4 组 prove/verify 正例 + 篡改负例，canonical 147/147、全量 367/367 ✓；
  残留信任：deck/reconstruction 承诺**轮转**绑定 = native/链上 EC_OP 通道
  （Plan D ④）；⑤ state-root 重算（区别于绑定）进 AIR——**v2 组件分解已落地
  （2026-09-05，`poseidon252_v2`，e2e 2.91s + 负例全拒）**；**字节 scope
  组合完成（2026-09-06）**：验证路径零宿主 Poseidon 重算（公开预处理树
  根等值 + anchor FS 绑定/常量钉住 + void 见证化），`name_commitment_v2`
  封装对齐 `table_name_commitment` 契约；剩：create_table AIR 消费侧切换
  （约束 10 期望值改取 v2 归档 anchor 投影）。
- [ ] **5（遗留）. `set_authorized_helper` owner 单点**：冷存储 / 时间锁
  （运维动作，随下一轮合约运维窗口）。
- [ ] **24⑤. 错误分类**：error.rs 字符串→稳定类别（低优持续项，外部输入
  边界先行）。其余 ①-④⑥ 的处置结论直接落在 `PERFORMANCE_FOLLOWUPS.md`
  头注（2026-09-05）。

## 三、结算隐私（剩余——多为实机/外部依赖）

- [ ] 一笔真实零明文结算联调（原 #11 剩余；需实机对局，配合 #34）。
- [ ] C5 Ready 实机端到端：登录→买入→对局→私密领取（剩人工钱包弹窗一步，
  见 `SETTLEMENT_PRIVACY_PLAN.md` §实机端到端剩余一步）。
- [ ] **12-15. sidecar 链**：维持推迟——官方 STRK20 Privacy SDK 未上 npm
  （#26 持续跟踪）；v2 escrow 输家扣款/现金出口修复启用前无消费方。解锁后
  按 `docs/starknet-plan-b-anonymizer.md` §SDK_SEAM 开工：M2 赔付路由 →
  M3 通知 UX → M4 合规加固。C5「池费运行时读取」随 #12 一并交付（非独立任务）。
- [ ] **26. STRK20 官方 SDK 跟踪**（持续）：上 npm 后核对 `tryComposeInvoke`。

## 四、长期项（条件触发）

- [ ] **21. 独立 prover 服务**：暂不动；上链验证路线（#22/M3）需要第三方
  可复现证明时再做。
- [ ] **23. Layer 3 递归协议**：长期演进；前置 = #22 缺口收口 + #21。
  范围/验收标准见 git 历史旧 TODO #23 与 `docs/archive/PO5_PO6_DESIGN_NOTES.md`。
- [ ] **31. 债券/罚没合约**：主网化前提（Phase 3）。

## 五、主网相关（最后，需用户操作）

- [ ] **28. 主网 ≥1 笔 STRK20 交易**（黑客松硬性要求）：操作指引
  `docs/MAINNET_TX_GUIDE.md`（方案 A 钱包直转推荐先行；vault v3 已绑
  canonical STRK，方案 B 无本地代币顾虑）。完成后哈希回填 strk20.json。
- [ ] **29. strk20.json 收尾**：mainnet_address（随 #28）/ demo_video /
  demo_url / transactions 补全（sepolia 地址已回填）。
- [ ] **32. Demo 视频**：浏览器验证 G 证明录屏（配合 #28 主网交易展示）。

---

## 已完成项归档（2026-09-05 重梳压缩；详情见 git 历史与各文档头注）

| # | 条目 | 完成时间 |
| --- | --- | --- |
| 1 | 牌局抽水显示 + "no flop, no drop" 对齐 + WEI 10 倍/fold-win 未上链两 bug | 2026-09-03/04 |
| 2 | 牌局记录看板（history_store + HandHistoryPanel + 亮牌隐私一致） | 2026-09-03 |
| 3 | 领取奖励 UI 重设计 | 2026-09-03 |
| 4 | time_bank 跨手恢复（核实已修，无需动） | 2026-09-03 |
| 5 | NOT_REGISTERED 修复 + DAPV 认可键 canonical 化 + 重播/等待窗（剩 owner 单点运维 → 二） | 2026-09-04 |
| 6 | API 速率限制（`ratelimit.rs`，10s/200 per-IP） | 2026-09-03 |
| 7 | 全局 panic 审计 Top-10 修复（遗留低风险项在案） | 2026-09-03 |
| 8 | P2-M1 结算隐私电路骨架（§8.2 预留列位冻结） | 2026-09-03 |
| 9 | P2-M2 证明端（prove-hand 管线，实测 8.6-15s） | 2026-09-03 |
| 10 | P2-M3 合约 v2（fact-registry 过渡，零明文 calldata） | 2026-09-03 |
| 11 | P2-M4 sepolia 部署 + 环境切换（vault v3 / dual v3 / anonymizer v3） | 2026-09-04 |
| 16 | 动作签名（客户端 wasm 签名 + 服务器验签 + seq 单调） | 2026-09-03 |
| 17 | 回签收据（ACTION_RECEIPT，operator 游戏域密钥） | 2026-09-03 |
| 18A | auto 默认动作规则收敛 + 审计日志哈希（服务端 Phase A） | 2026-09-04 |
| 18B | **action_log_digest 进 settlement_private 电路第 37 入参 / 公开段 15 felt / 合约 SETTLEMENT_SEGMENT_LEN=15 / register_hand+settle 新参 / 服务端全链 digest 接线**；回归：根 crate 电路 11✓、legacy DTO 14✓、snforge 88✓、prove-settlement e2e（15 felt 跨语言对齐 + 负例拒绝）✓、texas starknet 集见 commit；**部署收尾 → #34** | 2026-09-05 |
| 20 | poker_l1 收缩 -77k 行（Phase 1）+ 常驻 mirror 删除、prove_log 重建（Phase 2）+ Plan D（blst/BLS12-381 全量移除，Stark 唯一世界） | 2026-09-05 |
| 25 | 全链路私密提现（vault `withdraw_to` + CashoutUnshieldHelper，已部署） | 2026-09-03 |
| 27 | hooks 结算参数 TODO 注释清理（STARKNET_TREASURY_ADDRESS 已实现） | 2026-09-04 |
| 30 | paymaster 生产加固（SNIP-12 本地验签，`STARKNET_PAYMASTER_SIG_REQUIRED`） | 2026-09-03 |
| 33 | 在局锁定：vault v3（locked/session/TTL/force_unlock）+ 服务端接线 + 链上强制实测（剩应用内 e2e → 一） | 2026-09-03/04 |
| — | 文档治理：8 份历史文档归档 docs/archive/、10+ 份头注/内容修订、STATUS.md 重写、本 TODO 重梳 | 2026-09-05 |
| 35 | 旧测试清理：删除根 `tests/`（11 个 BLS precompile/链机制时代集成测试，Phase 1 起编译不过、拖红 CI `cargo test -p poker_texas_air --tests`）；fuzz/ 两个死 target（proof_wire/tx_decode 引用已删模块）重写为 settlement_statement/digest_felts 现役解析面，fuzz.yml 同步 | 2026-09-05 |
