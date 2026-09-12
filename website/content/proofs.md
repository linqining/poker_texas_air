---
title: 证明公平
lang: zh-CN
section: proofs
lead: 手牌证明、结算证明与独立验证入口。验证不依赖运营方私有服务。
sample: true
---

## 浏览器验证（proof portal，接口就绪）

v1 无 portal 后端。以下表单为接口就绪的静态层：生产环境将由独立的 proof portal 服务提供查询与浏览器本地验证（WebAssembly verifier），并显示 verifier 版本、proof digest 与验证耗时。

<form class="card" action="#" method="get" onsubmit="return false;">
  <p><label for="hand-id">hand id 或 proof digest</label></p>
  <p><input id="hand-id" name="hand_id" type="text" placeholder="例如：0x00f6fae93ff03c440c1136a5d8b5eab742f07c268c52536d4932ce4171933c52" style="width:100%;max-width:560px;background:#0d1710;color:#e9f2ec;border:1px solid #2a4233;border-radius:8px;padding:9px 12px;"></p>
  <p><button type="submit" disabled style="opacity:0.6;border-radius:8px;padding:8px 16px;">验证（portal 服务上线后开放）</button></p>
  <p class="kv">当前状态：v1 静态层 &#183; SAMPLE DATA / devnet &#183; 查询接口待 portal 服务</p>
</form>

## 独立验证命令（现在可用）

不依赖任何网页或运营方服务，直接用钱包 crate 的 CLI 验证证明文件（`poker-wallet` crate 由并行工作提供，命令以该接口为准）：

```console
# 验证一手牌的归档证明（proof.json 由 explorer/portal 下载或自节点导出）
cargo run -p poker-wallet --release -- verify proof.json

# 完整 STARK 验证路径（适配器 crate，开发/审计用）
cargo test -p poker-appchain-texasair --release
```

- verifier 版本（占位）：`texas-air-v2`；证明系统：stwo 2.3（circle-STARK，Stark curve）。
- 证明覆盖：canonical tagged AIR（29 选择子、状态镜像链、nullifier），批次绑定 table_id、pre/post 状态根、逐字节 pot 镜像。
- 负例保证：垃圾 STARK 字节、承诺不一致、桌不一致、缺绑定、坏签名、Fiat–Shamir 流篡改、状态镜像字节翻转均被验证器拒绝。

## 公开输入（scope v2 摘要）

归档 scope 与 canonical AIR 公开字段逐字段一致，关键字段：

| 字段 | 说明 |
|---|---|
| `table_id` | 桌标识，与结算记录一致 |
| `first/last_hand_id`、`first/last_call_seq` | 手牌与调用序列边界 |
| `transition_count` | 状态转移数（&gt; 0） |
| `batch_digest` | 批次摘要 |
| `pre/post_state_commitment` | 首/终态承诺 |
| `pre/post_state_root` | 首/终态 SMT 根 |
| `pre/post_lifecycle / overlay / settlement / custody` | 各子状态根 |
| `pre/post_state_image_bytes` | 定宽状态镜像（1680B，pot @ 偏移 74） |
| `rake_opening` / `blind_opening` | 费率与盲注开口 |

完整字段表见<a href="/docs/proofs/texas-air/">证明系统文档</a>。

## 示例：一批次的验证结果（SAMPLE DATA）

| 项 | 值 |
|---|---|
| hand_id | 42（示例） |
| verifier 版本 | texas-air-v2（占位） |
| 引擎 | poker-appchain-texasair / stwo 2.3 |
| 结果 | PASS（示例数据，非真实出证） |
| 验证耗时 | 约 1–3 s / 批次（开发机参考值，非承诺指标） |

<div class="notice">
<p>当前 devnet 的真实出证记录可通过仓库内 E2E 测试复现：<code>cargo test -p poker-appchain-texasair --release</code>（3 人 REAL 桌完整一手，单 canonical batch 真实 stwo 出证）。审计导出工具的说明见<a href="/docs/proofs/verify/">验证器与审计导出</a>。</p>
</div>
