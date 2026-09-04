# TODO

> 盘点日期：2026-09-03。来源：`SETTLEMENT_PRIVACY_PLAN.md`、
> `ACTION_SIGNING_CENSORSHIP_RESISTANCE.md`、`docs/EXECUTION_PLAN.md`、
> `poker_contracts/DEPLOYMENTS.md`、`PERFORMANCE_FOLLOWUPS.md`、
> "Fix strk20 shielded balance NOT_REGISTERED" 会话遗留清单及代码内 TODO 标记。
> 排序原则：功能开发优先，主网相关放最后。

---

## 一、功能开发

### P0 — 尽快

- [ ] **33. ⚠️ 在局锁定：牌局未结束取款逃单 / 全桌结算砖死（资金安全，主网前必须）
  ——合约侧已上线（vault v3），⬜ 剩余服务端接入**
  > 来源：会话「牌局未结束池子取款逃单风险」（2026-09-04 分析定稿，仅分析未改代码）。
  > 该风险此前未记录于任何文档。

  - **风险（当前合约下完全可行，且不需要抢跑）**：`vault.withdraw` 无许可
    （唯一门 = 余额 + 全局暂停，`poker_vault.cairo:244`；全合约无座位注册 /
    在局锁定概念）。逃跑窗口 = 买入直到该手结算上链（结算异步：ZK 证明 →
    register → settle）。后果三重：
    1. 输家中途提款逃单，拿回 100% 本金；
    2. **殃及全桌**：settle 循环逐玩家 `apply_settlement`，一个输家余额不足
       → assert revert（`poker_vault.cairo:386`，调用点
       `poker_settlement.cairo:282`）→ 整手结算失败，赢家也拿不到钱；
    3. **永久卡死**：digest/aggregate 一次性注册
       （`poker_settlement.cairo:176-182`），同一手无法用其他结果重结算。
    非恶意也触发：有未结算手时正常 cashout（客户端未拦截）。隐私路径同中招：
    `CashoutUnshieldHelper::chip_to_note`（`withdraw_to` 烧筹码直进池 note，
    `cashout_unshield_helper.cairo:110`）；v2 私密结算的输家公开扣款同样
    （`poker_dual_settlement.cairo:664`）。
  - **根因**：金库是"余额 = 随时可提债权"的纯账本；链上 pull 型结算用
    assert 假设扣款时余额还在——零和 ≠ 可支付。
  - **修复方案（会话已定稿，未实施）**：
    ① vault 加 `locked` 映射：入座/开局锁整份桌面筹码（覆盖该手全部风险
       额度，不只冻结快照）；`withdraw` / `withdraw_to` / `chip_to_note`
       只放行未锁定部分；结算先扣锁定额度再解锁（改动集中 vault）；
    ② 链上 session 注册（记 `last_activity`，operator 结算/续局刷新）——
       **必要组成**（否则 operator 触发锁定 = 后端失联即冻结玩家资金）；
    ③ 玩家自助 `unlock_after_deadline(session_id)`：
       `block.timestamp > last_activity + T`（T 建议 6–24h，明显大于正常
       结算耗时）；
    ④ （可选）operator 债券/罚没，转移不作为风险。
    底线：**从未入座（无活跃 session）的余额必须始终无许可可提**；锁定只
    覆盖明确入局的筹码。残余风险：锁刚过期、结算未上链的抢跑间隙（调大 T
    + 链下追责）。
  - **短期缓释（只缩窗不封死）**：每手即时结算 / operator 链下拦截提款 /
    最低在局余额。
  - 关键位置：`poker_vault.cairo:230/244/386`、`poker_settlement.cairo:282`、
    `poker_dual_settlement.cairo:664`、`cashout_unshield_helper.cairo:110`。
  - 建议顺序：①+②+③ 一并实施（纯② 会冻结资金；只做① 无超时解锁不可接
    受）；`chip_to_note` / `poker_vault_anonymizer` 的提现路径同样过锁定门。
  - ✅ **实现完成（2026-09-03，snforge 85/85 ✅）；随 #11 部署批次上线
    （`deploy_sepolia_v3.sh` 的 `DEPLOY_VAULT_V3=1` 段：vault v3 declare/deploy
    + set_unshield_helper + set_settlement_contract；详见 DEPLOYMENTS.md
    「Vault v3」节）。：`poker_vault.cairo` 增加
    `locked` / `session_last_activity` / `session_active` / `lock_ttl` 存储；
    `lock`（owner=operator）/ `refresh_session` / `unlock_after_deadline`
    （无许可，`timestamp >= last + ttl`）/ `set_lock_ttl`（owner，0=禁用）/
    `force_unlock`（owner 应急）；`withdraw` / `withdraw_to` / `burn_chips`
    统一 `assert_spendable`（只可花未锁定余额）；`apply_settlement` 负 delta
    **优先消耗锁定额度**并全额扣减余额（修结算砖死）。8 个 snforge 用例：
    锁定内取款拒绝 / 未锁定可取 / 结算先扣锁定（-900：锁定 800+未锁定 100）/
    锁定内结算不伤未锁定 / TTL 未过期拒绝 / TTL=0 禁用拒绝 / force_unlock /
    TTL 设置生效。✅ 已随 #11 部署批次上线（vault v3 `0x0629385f...`，2026-09-04）。
  - ✅ **服务端接入（2026-09-04，texas/src/starknet/lock.rs + 两处接线）**：
    ① 入座买入手续校验通过后 → `vault.lock(player, amount)`（异步尽力而为，
    失败 ERROR 级日志提示人工补锁）；② 每手结算上链成功（dapv/legacy 两路）
    → 逐参与者 `refresh_session` 续时钟；③ 离座**不自动解锁**（安全默认：
    结算被跳过时 force_unlock 会重开逃单窗口）——玩家 TTL（12h）后可无许可
    `unlock_after_deadline`，operator 保留 `force_unlock` 应急（snops invoke）；
    ④ 前端领取弹窗实时读 `locked_balance` 展示"在局锁定 X STRK"警示 +
    锁定覆盖领取额时给出预期提示（strk20.ts getVaultLockedBalanceWei）。
    ⑤ ✅ 链上强制已实测（2026-09-04，operator 冒烟）：lock 10 chips →
    locked_balance=10/session_active=1 → withdraw 10（≤可花 18.8）合法放行 →
    withdraw 20（28.8−20=8.8 < 锁定 10）被精确回滚
    `"Insufficient unlocked balance (in-hand lock)"` → force_unlock 还原。
    ⬜ 剩余：应用内 e2e（Ready 实机：入座触发服务端自动 lock → 游戏中
    领取弹窗显示在局锁定 → 打完一手结算续钟 → 离桌 TTL 解锁），配合
    #11 联调；服务端自动 lock 接线已在 09:45 二进制中。

- [x] **1. 牌局抽水显示**（2026-09-03 完成；2026-09-04 补漏：亮牌路径漏收台费）
  - 增补：`on_reveal_complete(ShowdownReveal)` 分池前漏调
    `collect_rake_for_settlement`——链上 deltas 含 5% 台费而前端筹码不扣，
    两本账每手偏差 5%（服务端 stack 总和守恒、牌史 rake=0）。已补齐，
    前端 stack/牌史 rake 字段/链上 delta 三者一致。
  - **2026-09-04 第二轮（规则对齐行业 "no flop, no drop" + 两个上链 bug）**：
    ① 结算腿单位错 10 倍：submit.rs / dual_settle.rs 局部 WEI_PER_CHIP=1e14
    vs 全局/买入 1e15 → 链上余额与游戏输赢每手漂移 9/10（线上复现：玩家
    链上只剩买入流水）。统一引用 config 常量 + 回归测试锁定。
    ② fold-win 手从未上链：derive_settlement_plan 牌面校验（board=5/亮牌）
    对弃牌手必败 → 输赢静默跳过。新增 `derive_fold_win_plan`（无牌面校验；
    弃牌事实由聚合链 fold receipts 证明）+ 快照补应用终局弃牌
    （`pre_settlement_final_fold`，踢人 force_fold 路径同款）。
    ③ 抽水规则对齐：翻前 fold-win 不抽；翻后 fold-win 抽「被争夺的钱」
    （底池 − 未跟注返还），游戏层 `fold_win_rake` 与链上 fold plan 同公式；
    validate 的 "uncontested 不抽" 不变量相应放宽。测试：poker_l1 fixture
    5 例（翻前/翻后未跟注排除/三人次高/cap/多人拒绝）+ texas rake 7 例 +
    快照补弃牌端到端 1 例 + WEI 锁定 1 例，全部通过。
  - 全面审核（2026-09-04，含 AIR 约束）三处修正：
    ① 台费基数改为**争夺层总额**（contested_gross，镜像链上
    settlement.rs）——原按总池计算，all-in 未跟注返还层会被多抽
    （1000 池=600 争夺+400 返还时抽 50 而非 30）；
    ② mirror 抽水参数改从 env 读（原固定 DEFAULT 常量，改
    STARKNET_RAKE_BPS/CAP 只改服务端一半）；
    ③ AIR 电路（settlement_private.cairo）审核结论：电路不重算抽水
    （正确——digest 是锚），约束四条与 v2 合约消费逐字段一致；但
    `verify_and_settle_dapv_stark_private_v2` **不扣输家**（设计如此：
    计划文档 §2 "输赢只在服务器内存"），配 permissionless withdraw =
    输家可超提 → vault 对其他玩家资不抵债。v2 在现金出口迁移到
    服务端受控模型前**不可启用**（当前线上走 v1 明文路径不受影响）。
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
  - 增补（2026-09-03）：记录每座位的**已亮出底牌**（摊牌亮牌座位才记录，
    弃牌/未亮牌不暴露——隐私一致）；看板展开行内渲染座位底牌。

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
  - [x] **提交 git**：按主题拆分 commit（合约/anonymizer 重部署、协议三动作、
        开局基线重建、本轮 TODO 功能开发——截至 2026-09-04：claim 弹窗重构
        b6ce436/80c3cb1、anonymizer v3 + v3 切换 1a147b5 等均已入库）。
  - [ ] `set_authorized_helper` owner 单点问题：建议冷存储 / 时间锁（运维动作）。
  - [x] **DAPV 认可键不一致 → 链上结算静默跳过（2026-09-04 线上复现+修复）**：
        注册侧存客户端补零地址（0x017cfd...），take 侧按 Felt {:#x} 查询
        （0x17cfd...）——前导零钱包永远 MISS，endorsement 永远收不齐，
        DAPV 每手被静默跳过，输赢从未上链（表现为"领取额=纯买入额，结算少了"）。
        修复：注册侧 canonical_wallet_key 统一规范化 + ENDORSEMENT_REQUEST
        每次重投重播（客户端 per-hand 去重）+ 认可等待窗 3s→10s +
        JOIN_TABLE 进房即重投待结算手。已验证两局 dapv on-chain 成交，
        链上 delta 与服务器牌史逐分吻合（含 5% 抽水）。
  - [x] （可选）对账：链上筹码 5000 → 0 但领取为 4000，差额 1000 来自后续手牌
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
- [x] **11. P2-M4 联调部署**（2026-09-04 部署 + 环境切换完成）：
  - ✅ 测量：dual v3 class = sierra 859 KB / casm 737 KB / 32,901 words；
    declare 需 l2_gas 2.86e9 单位 ≈ 142 STRK（实时价），电路证明 14s / 2021 步 /
    公开段 14 felt。
  - ✅ 脚本 `poker_contracts/scripts/deploy_sepolia_v3.sh`：declare（自动处理
    sepolia compiled-hash 方案差异，`--compiled-hash` 重试）→ deploy(owner,
    vault, prover) → set_claim_helper → set_circuit_program_hash → 回填
    texas/.env。文档详见 `poker_contracts/DEPLOYMENTS.md` 末节。
  - ✅ 链上部署（2026-09-04）：vault v3 `0x0629385f...` + dual v3 `0x516b8289...` +
    CashoutUnshieldHelper `0x1c35d808...`，全部接线 SUCCEEDED（见
    `DEPLOYMENTS.md`）；anonymizer v3 `0x6fd4be6e...`（新增 owner 门控
    `set_vault`，owner 显式构造参数）绑定 vault v3 并完成
    `set_authorized_helper`。
  - ✅ 环境切换（2026-09-04）：`texas/.env` → vault v3 + dual v3，
    `client/.env.development` → vault v3 + anonymizer v3，服务器已重启。
    测试网不做余额迁移（筹码读数实时跟随 `vault.chip_balance`，旧 v2 余额
    玩家可随时自行 withdraw）。
  - ⬜ 剩余：一笔真实零明文结算联调（需实机对局，配合 #28 的 sepolia 侧
    实机验证，见 C5 清单）。
- [ ] **12. C3.2-M1 认领 sidecar**：Node sidecar 封装 STRK20 私密转账
  （运营浮存 → 赢家 viewing key note），Rust 服务端 HTTP 调用；需 SDK 依赖 + 服务器 KMS。
  **前置核查（2026-09-03）**：官方 STRK20 Privacy SDK 仍未上 npm（registry 检索只有
  社区第三方包）——SDK_SEAM 继续阻塞本节全部四项；SDK 上线后按
  `docs/starknet-plan-b-anonymizer.md` §SDK_SEAM 核对 `tryComposeInvoke` 即可开工。
  **需求前提复核（2026-09-03，strk20-by-example.org 官方文档核实）**：「STRK20 必须
  用户主动领取」**不成立**——接收是推送制：发送方一笔 CreateEncNote 落入接收方
  channel，接收方离线扫描即得可花费余额，**无任何认领交易**（channels-and-subchannels：
  "no inbox"，扫描结果即 spendable private balance）。必须用户签名的只有两处：
  ① 出池花费——nullifier 含 owner 私钥，连创建 note 的发送方也无法代花
  （notes-and-nullifiers）；② viewing key 一次性自注册，仅本人可注册（买入用户已满足）。
  因此「赢家必须主动认领」是当前 vault 筹码 escrow 架构的产物（赔付以 open chips
  形态在池外，守恒腿 burn 只能用户签名），**不是协议限制**；且认领粒度是「每次出金」
  而非「每手」——赢家可攒至局末一次认领。sidecar 的真实边际收益 = 消除出金认领
  交易（金额/时间公开关联）+ 收款零操作；推送路线本身是官方一等路线
  （backend holding its own keys → Privacy SDK createPrivateTransfers），协议层可行。
  **结论：维持推迟**。解锁条件：① SDK 上 npm（#26 跟踪）；② v2 escrow 输家扣款/
  现金出口修复并启用（当前 v2 不可启用，sidecar 无消费方）。届时若嫌常驻服务重，
  降级为 Node CLI worker + 队列表（settle 后写队、worker 消费）。
- [ ] **13. C3.2-M2 赔付路由**：settle 后异步队列：延迟抖动 + 批量 shield 补浮存 + 失败重试。
- [ ] **14. C3.2-M3 通知与 UX**：加密赔付通知推送 + 领取入口 UX；赢家零操作看到 note。
- [ ] **15. C3.2-M4 合规加固**：限额/频控/审计日志 + 运营手册。

**C5 验证清单（未勾完项）**：

- [ ] Ready 实机端到端：登录 → 买入 → 对局 → 私密领取（剩余人工钱包弹窗点击这一步，
  步骤见 `SETTLEMENT_PRIVACY_PLAN.md` §实机端到端剩余一步）。
- [x] starknet-react / starknetkit 与 starknet.js 10.6.8 兼容矩阵
  （2026-09-04 收口：starknet.js 10.6.8 + starknet-react 5.0.3 + get-starknet-discovery 6.x
  组合已在 sepolia 实局端到端验证（dapv register/settle 多手 SUCCEEDED）；
  starknetkit 已作为死代码移除（见上条），不再参与矩阵。服务端
  starknet.rs 0.17 / starknet-ff 0.3 / starknet-types-core 0.2 与客户端
  10.6.8 的 felt/u256 编码经链上 calldata 交叉验证一致。
- [ ] 池费 `get_fee_amount` 运行时读取（不硬编码）；赔付额 ≥ 池费的边界处理。
  （2026-09-03 核查：客户端/服务端现状**无**池费硬编码——该项是 #12 C3.2 sidecar
  构建时的前置要求，非独立任务，随 sidecar 一并交付。）
- [x] 清理死代码 `client/src/starknet/cartridge.ts` + 移除 `@cartridge/*` 依赖
  （2026-09-04 完成；顺带移除同样零引用的 `starknetkit`——它是 @cartridge/*
  传递依赖的来源，锁文件 @cartridge 清零，构建/类型检查通过）。

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
  - ✅ 回签收据（2026-09-03 补全）：operator 游戏域密钥（随机生成、持久化
    `<work_dir>/operator-game-key.json`，与钱包零派生）对每个动作决定
    （accepted/autoAccepted/rejected+reason）签收据，ACTION_RECEIPT 广播
    全桌（`receipts.rs`，3 单测：签验回路/篡改拒绝/密钥持久化）。客户端
    留存回执 + acceptedSeqs 向量即可举证审查。
- [ ] **18. auto 默认动作签名化**（Phase A 服务端完成 2026-09-04；Phase B 电路待做）：
  - ✅ **Phase A（服务端，全部测试锁定）**：
    ① 规则源收敛为纯函数 `pokergame::actions::legal_auto_action(call_amount,
    my_bet, big_blind)`——零下注 Check / 差额≤BB Call / 超BB Fold；
    `handle_auto_fold` 改为消费该函数（原内联逻辑删除）；
    ② 回执签名绑定 auto：operator 签名覆盖 `decision="autoAccepted"`（经
    receipt_msg_bytes），客户端可本地验签"这是服务器代打 + 是 operator 承认的"；
    ③ 动作日志哈希：`action_log_digest_hex`（starknet_keccak 链式吸收
    seat/seq/action/amount/auto/sig_ok），`finish_showdown` 按本手窗口
    （`hand_log_start` 边界）输出 digest + auto 占比审计（>50% WARN）；
    ④ 测试 4+7 例（规则边界/日志哈希敏感性/full_hand 回归）全绿。
  - ⬜ **Phase B（电路，§8.2 预留启用）**：把 `action_log_digest` 作为
    settlement_private 电路第 37 入参追加进吸收链（wire 无重排）→ 公开段
    追加该哈希 → v2 合约 SETTLEMENT_SEGMENT_LEN 14→15 + register_aggregate
    增加 action_log 承诺入参 → **需要一批合约重部署**（declare/dual v3.x）。
    上线门槛（原文）：电路校验"合法默认"（零下注才可 auto-check）后才可
    上线主网——服务器可借代打折叠任意玩家的风险在 Phase B 落地前由
    ①的审计日志 + #33 锁定共同缓解。
- [ ] **19. 实施前确认 4 个开放问题**：seq 持久化粒度（per-table / per-hand）；
  电路内验签 vs 链下预验签；replayer 最小数据集；双通道备用端点选型。

---

## 四、协议 / 证明层长期项

- [ ] **20. poker_l1 收缩 + mirror 重放移除（2026-09-05 重新定性，取代原"证明层协议对齐"）**：
  > 用户定调：仓库模型已变——证明层 = Starknet 链下 stwo 程序（根 crate
  > poker_texas_air），不存在"mirror 交易重放"概念；poker_l1 的 L1 链本体未完成
  > 也非目标。原按 `DUAL_PROOF_PROTOCOL.md` §5.3 的"客户端协议对齐"方案作废。
  - **审计结论（2026-09-05 全仓核查）**：线上结算路径 = 游戏层(权威) → mirror VM
    重放（`mirror.rs`，角色已收缩为 ProveTask 铸造 + 终局快照）→ stwo
    orchestrator/outer_aggregate → register_aggregate/settle_hand(+DAPV)。
    poker_l1 共 99k 行/110 文件，其中活路径仅消费 **texas_poker 合约库**
    （types/state_machine/dispatch/settlement/betting/card/constants/events/
    utils + vm::contracts::dispatch，~17k 行）+ 5 个小类型（Address/error/
    ObjectID/TaggedPubkey/DispatchContext）；其余 **~80k 行链机制零外部消费者**
    （node 7.2k/state_machine 外的 executor/governance/sync/rpc/network/bridge/
    economics/indexer/storage/offline/consensus(bullshark 等)/syscalls/precompile/
    upgrade/texas_poker_precompile）。游戏层生产代码仅 rake.rs 引 2 个常量。
    注意：AIR trace_gen 本身调 state_machine::apply_bet/dispatch::dispatch 重放
    命令生成 trace（MethodBatchV2 = initial_table+commands+final_table，重放
    在证明内部是 STARK 语义，**不能删**）；要删的是服务端第二本账（mirror）。
    另：`verify_against_anchor` 是显式选配（活路径不带锚定），consensus_anchor
    及其引入的 consensus/block/transaction 依赖可随链机制一并归档。
  - **Phase 1（纯删除，零行为变化）✅ 完成（2026-09-05）**：poker_l1 收缩为
    合约库小 crate——删除 account/block/bridge/consensus/crypto_precompiles/
    economics/executor/genesis/governance/indexer/metrics/network/node/offline/
    rpc/storage/sync/transaction/wallet + vm/{context,contract,crypto_blstrs,
    gas_strategy,gas_table,loader,precompile,syscalls,upgrade} + vm/contracts/
    旧 GameContract 合约族（settle/force_*/checkpoint_*/ack/revert/DA/censor 等）
    + 根 crate consensus_anchor（1219 行，零消费者）+ task36 benches；净删
    **77,230 行**。保留闭包：error/object_model/signature/vm::contracts::
    {dispatch 边界类型, texas_poker 合约库}；两处内联修复（store.rs 的
    MAX_OBJECT_SIZE 改引 vm-common、utils.rs 的 BLS_G1_DST 常量内联——值逐字节
    相同）；error.rs 删除 7 个链机制专属变体（WrongLane/NotYourTurn/
    NotEligibleSubmitter/NotAssignedValidator/HandStartedError/ForceAdvanceError/
    SettleError + 2 个 governance 提案变体）；store.rs 的 is_system_object 恒为
    false（链系统单例已不存在，保护区结构保留）。Cargo.toml 修剪 9 个链依赖
    （rocksdb/solana_rbpf/tokio/rayon/vrf/openssl vendored 等）。
    **回归**：poker_l1 320/320 ✅、根 crate（stwo 证明层）362/362 ✅、
    texas 边界过滤集 15/15（submit/rake/mirror）✅、workspace cargo check ✅。
    ⚠️ 遗留：`fuzz/` 在 workspace exclude 外引用已删模块，构建会失败——随
    Phase 2 一并处理；poker_l1 326 条 missing_docs 风格警告为存量，不阻塞。
  - **Phase 2（架构对齐，"直接应用程序"）✅ 完成（2026-09-05）**：常驻 mirror
    （第二本账）移除，结算改为"游戏层记录 → 结算时一次性纯函数重建"：
    - **记录**（新 `texas/src/starknet/prove_log.rs`）：游戏层在接受动作的同一
      代码路径上写每手 `HandProofLog`——join 证明缓冲（SIT_DOWN/socket 双入口
      汇聚）→ `record_hand_start`（deck 终局时采集 HandStart 快照：参与者/
      **盲注前 stack**/button/deck）→ reveal 令牌（(pk,令牌集) 去重，客户端
      幂等重试不重复）→ 下注动作（auto 代打同路径天然覆盖）→ 强制弃牌。
    - **重建**（`mirror::build_from_log`，TableMirror 转为一次性构建器）：
      on_hand_complete 锁内只克隆日志，锁外按记录序重放（DeckHole 注入 →
      reveal/下注/force-fold → ShowdownDisplay 快照+派奖推进），产出
      ProveTask 链 + pre-payout 快照。Bet/Reveal 重放失败 = 记录异常 → 显式
      放弃该手（绝不带分歧状态结算）；ForceFold 沿用旧"失败仅跳过"语义。
    - **强制对账**（游戏层 = 唯一真相）：构建后比对 per-wallet total_bet 与
      公共牌数；settle_hand 派生 plan 后再比对 rake——任一不一致拒绝上链。
      顺带根治 hand 2 类 bug：join buy_in 改用 seat.stack（跨手结转），
      stack/reveal 失步整类消失。
    - **完整钱包 felt 记账**：参与者映射来自本手记录（`hand_wallet_map`），
      删 `SEAT_WALLETS`/`seat_wallet_remaps`/`LAST_JOINS`/`MirrorRegistry`
      及全部实时同步钩子（mirror_betting/sync_reveal/force_fold/
      advance_showdown_display/begin_reveal）；game_loop tick 只留有界重投。
    - 链上 ABI（register_aggregate/settle_hand/DAPV hand_binding）不变；
      20 字节截断重映射保留（VM Address 宽度属 AIR/序列化表面，Phase 2 不动）。
    - **回归**：workspace 编译 ✅；`starknet::` 测试集（submit 逻辑 + 全链路
      e2e：join→洗牌→reveal→下注→settle_hand 真实证明链→calldata 对拍）通过。
  - **Phase 3（可选，需单独拍板）**：v1 链上仅验 digest 注册 + delta 应用，
    可评估证明内容暂缩为 digest 承诺直至上链验证路线启用——改变安全模型。
  - **✅ Plan D 完成（2026-09-05，用户拍板"不考虑兼容，清理掉 blst 相关电路"）**：
    **blst/BLS12-381 从 workspace 全量移除**——poker-protocol-core 删 BLS 后端
    （backend.rs -354 行）；poker_protocol 删 legacy-bls381 feature（DefaultCurve
    = StarkCurve 唯一世界）+ bls borsh_impls 重写 + BASE_G 函数化；poker-protocol
    -proofs/-bg 的 borsh impls 切 StarkCurve（48B→32B 压缩点）；poker_l1 VM 四文件
    blstrs 硬绑定移植为 curve-generic 门面（utils.rs：parse/serialize 32B、
    hash_to_scalar/hash_to_curve/generator 委托 core Stark 后端=与 z_poker 客户端
    同源；pk ownership 证明 80B→64B；reconstruction context 域串改 stark-curve-v1）；
    abi 增加 `CurveId::StarkCurve = 6` + 三处 validate 白名单；poker_protocol-abi/
    proofs/rayon/serde_json/tracing/merlin 转 non-optional；根 workspace 删 blstrs
    依赖；poker_l1 旧链机制集成测试目录清退。**回归**：core 49/49、protocol 68/68、
    proofs 113/113、poker_l1 320/320、根 crate 证明层 362/362（AIR 消费 Stark 快照
    全兼容）、texas full_hand_tests 4/4（Stark 全流程真实 BG V2）+ starknet:: 38 绿
    + 全链路证明 e2e（join→记录→重建→Stark 证明链→calldata）✅。
    ⚠️ 已知行为变化：曲线点压缩 48B→32B、pk ownership 80B→64B、所有承诺/digest
    值改变（无兼容要求）；client-wasm 侧按 Plan D P1.2 已在 Stark 后端（blst wasm
    blocker 消除）。live_flow 测试为既有 debug 证明生成慢点（BLS 时代同样 >5min），
    非回归。
- [ ] **21. Phase 3：独立 prover 服务**：`STARKNET_PROVER_URL` 从 stub 变真实端点，
  移除 host attestation。见 README Roadmap。（2026-09-05 评估：暂不动——
  当前 host 证明路径已实测可用且不是阻塞项；独立 prover 服务引入运维面，
  等上链验证路线（#23/M3）需要第三方可复现证明时再做。）
- [ ] **22. canonical AIR 缺口**（2026-09-05 盘点修订；原五项声明部分过时）：
  **已入 AIR/组件**：23 selector 的 fixed 关系（Call/Raise/Bet/funding/join/leave/
  force/kick/SetLeaveAfterHand/AdvanceRound/timebank/AutoFold 后缀/AdvanceDeadline
  微步）✅；showdown settlement 代数 AIR（`canonical_settlement_air`，16 行域+
  borrow/carry 分解）✅；rake opening（`canonical_rake_opening`，结算终端消费）✅；
  reveal-assignment ledger opening（`canonical_reveal_opening`）✅；非终端 reveal
  timeout 级联 scope（`reveal_timeout_cascade`，含 pending-union 升序走桌）✅；
  state-root 绑定（`state_root_binding`，Flock 证明替代 host 重算）✅；结算隐私
  电路骨架（`settlement_private_circuit`，P2-M1）✅。**仍在 AIR 之外（真实缺口，
  含 Plan D 后的重新定界）**：
  ① shuffle/reveal/reconstruct 的**曲线密码学等式不进 AIR**——Plan D 定界为
     原生 verify（host + 链上 EC_OP `hand_batch_stark`）路线，不再追求电路组合；
     验收 = 全残差批次 sepolia 单笔 settle 且 gas 可承受（Plan D P1.4 验收，合约
     侧已就绪待实测）；
  ② final shuffle/reveal **阶段切换**仍 fail-closed——验收：canonical AIR 组合
     ShuffleComplete/RevealComplete 终局转换的完整关系；
  ③ **完整 timeout/terminal 级联**——现有 cascade scope 只覆盖非终端走桌，
     验收：终端（全员踢出→手终结→退款）级联的批量证明；
  ④ reconstruction 终局组合（STATUS "not yet composed"：deck/reveal 承诺重算 +
     Ristretto→现 Stark 时代等式）——验收：reconstruct 提交解除 fail-closed；
  ⑤ state-root **重算**（区别于绑定）进 AIR——验收：AIR 内独立重算并比对
     `state_root_binding` 锚点。
  权威表述源：`docs/STATUS.md`（§canonical AIR）。
- [ ] **23. Layer 3 递归协议**（长期演进项，与 #21 同类——本 session 不实施，
  2026-09-05 标注范围与验收）：Texas 自有递归协议尚未实现（生产验证入口保持
  关闭）；无 sound 递归/简洁聚合证明，验证成本仍 O(N）。见 `src/lib.rs:12`、
  `docs/PO5_PO6_DESIGN_NOTES.md`。
  **范围**：① sound 递归聚合（MethodBatch/outer aggregate 的 O(1) 压缩——现
  Aggregator 为 descriptor-only PoC）；② 简洁上链验证证明（衔接 Plan D P1.4 的
  EC_OP 批次输出）；③ 前置依赖 = #22 的缺口收口（ AIR 面）与 #21（独立 prover，
  递归证明生成需要持续算力服务）。
  **验收标准**：a) 递归证明 soundness 矩阵（诚实链/篡改命令/换序/跨手拼接）
  全绿；b) 9 人桌一手 O(N)→O(1) 验证成本实测报告（对照 `docs/plan_d_perf.md`
  基线）；c) 生产验证入口开关在合约+宿主两侧 fail-closed 保持。
- [ ] **24. 性能 followups**（2026-09-05：曲线切换后 release 基准已重测——
  **新基线见 `docs/plan_d_perf.md`**：标量乘 19µs/op、52 项 MSM 中位 3.4ms、
  52 卡洗牌 prove/verify 44/23ms、9 人桌全残差 host 折叠 2ms 等 7 项）。
  各项处置（host 端均无迫切瓶颈，按"净收益"门槛逐项决策）：
  ① 专用标量乘 AIR——host 19µs/op，进 AIR 成本远超收益，**维持 oracle 保留、
    不实施**；② MSM 平衡树——3.4ms 不构成瓶颈，**暂缓**（若实施需 N=2..52
    release 矩阵 + 非 2 幂 padding/sibling 篡改测试）；③ limb backend 选型——
    **暂缓**（需 rows×操作混合 release 矩阵，verifier 禁止本地启发式）；
  ④ outer_aggregate 流式编码——**暂缓**（峰值内存实测后再定）；
  ⑤ 错误分类（error.rs 字符串→稳定类别）——**低优持续项**，外部输入边界先行；
  ⑥ `/metrics` 路由——**归上层 server**（texas 侧），传输层不做。
  权威门槛文档：`PERFORMANCE_FOLLOWUPS.md`（pinned nightly + `--release`）。
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
- [x] **27. 杂项**：`hooks.rs` 结算参数 TODO 注释清理（2026-09-04：该参数
  已实现为 STARKNET_TREASURY_ADDRESS env + operator 兜底，注释转正）。

---

## 五、主网相关（最后）

- [ ] **28. 主网 ≥1 笔 STRK20 交易**（黑客松硬性要求，**需用户钱包人工操作**）：
  操作指引见 `docs/MAINNET_TX_GUIDE.md`（方案 A 钱包直接转账 ≈5 分钟，推荐先行；
  方案 B PokerVault 主网最小部署可选）。完成后交易哈希回填 strk20.json
  （模板见指引）。
  现状：`strk20.json` 的 `token.mainnet_address` 为空，未记录任何主网交易。
- [ ] **29. strk20.json 收尾**：`token.mainnet_address` / `sepolia_address` 回填；
  demo_video / demo_url / transactions 补全。
- [x] **30. paymaster 生产加固**（2026-09-03 完成，texas 回归 58/58 ✅）：
  `paymaster_executeTransaction` 的 body 本就携带用户对 OutsideExecution
  typed data 的签名——服务端现于中继层本地验证：提取
  `(userAddress, typedData, signature)` → `TypedData::message_hash`（SNIP-12）
  → 链上 `get_public_key`（TTL 缓存）+ `starknet_crypto::verify`。
  `STARKNET_PAYMASTER_SIG_REQUIRED=1` 时无效/缺失 → 拒绝；默认 off
  （迁移期仅记日志，buy-in 关键路径零破坏）。客户端零改动
  （签名本就在 executeTransaction 载荷内）。
  位置：`texas/src/starknet/paymaster.rs`。
- [ ] **31. 债券 / 罚没合约（Phase 3）**：operator 链上质押债券；被证明的审查
  （签名动作 + accepted-seq 缺口）触发罚没赔付；债券 > 最大可窃取价值。主网化前提。
- [ ] **32. Demo 视频**：录"浏览器验证 G 证明"录屏（配合主网交易展示）。
