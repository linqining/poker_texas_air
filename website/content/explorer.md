---
title: 区块浏览器
lang: zh-CN
section: explorer
lead: 交易、手、结算、rake 与 checkpoint 查询。所有数据标注确认层级。
sample: true
---

## 数据来源与确认层级

explorer 的每条记录都标注来源层级：<span class="st st-info">soft accepted</span>（软确认）→ <span class="st st-muted">BFT ordered</span>（未上线）→ <span class="st st-ok">proven</span>（已证明）→ <span class="st st-warn">finalized/claimable</span>。v1 阶段实际出现 soft accepted 与 proven 两级；失败原因与水位缺口也会如实展示，不做隐藏。

## 最近的块（SAMPLE DATA / devnet）

| 高度 | 时间 (UTC) | 操作数 | 状态根 | 层级 |
|---|---|---|---|---|
| 18204 | 2026-09-12 08:31:04 | 12 | 0x9a3f…c21e | <span class="st st-ok">proven</span> |
| 18203 | 2026-09-12 08:30:52 | 7 | 0x51bd…07aa | <span class="st st-info">soft accepted</span> |
| 18202 | 2026-09-12 08:30:41 | 9 | 0xe4c2…8f10 | <span class="st st-ok">proven</span> |

## 手牌与结算（SAMPLE DATA / devnet）

| hand id | 桌 | pot | rake | payout root | 结算层级 | proof |
|---|---|---|---|---|---|---|
| 1042 | 7 | 1,840 | 92 | 0x77ab…39d1 | <span class="st st-ok">proven</span> | <a href="/proofs/">下载 / 验证</a> |
| 1041 | 7 | 620 | 31 | 0x0cdd…a2f4 | <span class="st st-ok">proven</span> | <a href="/proofs/">下载 / 验证</a> |
| 1040 | 3 | 0 | 0 | 0x51bd…07aa | <span class="st st-info">soft accepted</span> | 待批次出证 |

rake 口径说明：`FIXED_RAKE` 策略下 `rake = min(floor(rake_base × rate_bps / 10000), cap)`，`rake_base` = contested 层 gross 之和——uncalled 返还与 sole-survivor 层不计费（BLOCKERS B9 已统一为 contested-only 口径，ABI v1.2.2；<a href="/docs/economics/rake/">经济模型文档</a>有详细说明）。

## Checkpoint / 水位（SAMPLE DATA / devnet）

| 项 | 值 |
|---|---|
| proven watermark | 18196 / 18204（缺口：无） |
| 最新批次根 | 0x00f6fae93ff03c440c1136a5d8b5eab742f07c268c52536d4932ce4171933c52 |
| BFT checkpoint | 未上线（v1.5） |
| 批次大小 | 32 ops / 批（示例配置） |

## 关于本页

- 本页是<strong>接口就绪的静态层</strong>：页面结构与数据口径已定义，数据全部为示例。生产 explorer 由独立服务提供（区块/交易/手/结算/rake 查询、proof 下载、confirmation 层级与失败原因展示）。
- 任意 settlement 都将可跳转 proof portal 由浏览器本地复验（WEB-ACC-4，待 portal 服务）。
- 浏览器分阶段开发计划（实时网关 → 领域查询 → proof 复验闭环）见<a href="/roadmap/">路线图</a>。
