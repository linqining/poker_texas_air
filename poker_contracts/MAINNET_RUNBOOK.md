# 主网部署 Runbook（2026-09-19 整理）

> 一页式执行手册。历史账目与逐次部署记录见 [DEPLOYMENTS.md](DEPLOYMENTS.md)，
> 合约地址速查见 [strk20.json](../strk20.json)。本文回答"现在主网跑什么、
> 要部署什么、怎么执行、怎么验证、怎么回退"。

## 0. 现状盘点（2026-09-19 快照）

### 主网在网（全部可用，但三个合约类已过时）

| 合约 | 地址 | 类（在网） | 类（当前源码） | 结论 |
| --- | --- | --- | --- | --- |
| PokerVault | `0x3f4ef706…` | `0x7c74ca1a…`（9-04 世代） | `0x6de64f9a…` | **重部署**（缺 P1-2 `set_session_tx_pk` → 桌面买入必挂） |
| PokerVaultAnonymizer | `0x88c1f843…` | `0x525646bd…`（9-07） | `0x6dbb1f82…` | **重部署**（与 vault 配套） |
| PokerDualSettlement v5 | `0x1d39b80b…` | `0x047e91d5…` | `0x255cafe3…`（v6） | **重部署**（v6：SNIP-36 门修正；无 set_vault，须随 vault 重部署实例） |
| PokerSettlement（legacy 兜底） | `0x2bf6a09c…` | `0x6f2e01a6…` | `0x6f2e01a6…` | ✅ 不动 |
| SettlementPayoutAnonymizer | `0x40237293…` | `0x7c11073c…` | `0x7c11073c…` | ✅ 不动 |
| PokerTableRegistry | — | — | `0x7cc910b5…` | 新增（可选但建议） |

- 主网 vault 存量玩家筹码：**9.47 STRK**（2026-09-19 实测）→ 需迁移公告。
- canonical STRK、主网隐私池 `0x040337b1…`、电路 program hash `0x744d16d3…`、
  hand-verify `0x303029d8…` 与 Sepolia 同值，无网络差异。

### Sepolia 参照（2026-09-19 已验证的同款批次）

vault `0x1b1b7b37…` / anonymizer `0x335db85a…` / dual v6 `0x66daeeee…` /
registry `0x39b3531d…`——9 笔部署接线 TX 全 SUCCEEDED，买入/结算冒烟通过。
执行顺序与接线即 `scripts/deploy_mainnet_v6.sh` 的蓝本。

## 1. 前置条件

1. **资金**：deployer `0x412e4d43…` 现余 **64.81 STRK**；本批估算 ≈97.5 STRK
   （declare vault≈28 + anonymizer≈6.3 + dual v6≈60 + registry≈3 + 部署接线≈0.2）。
   **先充值至 ≥150 STRK**（含 gas 波动缓冲）。
2. **构建**：`cargo build -p texas --bin snops --release`；
   `PATH="$HOME/.local/opt/toolchains/scarb-2.19.4/bin:$PATH" scarb build`
   （在 `poker_contracts/`，产物 `target/dev/*.json`）。
3. **账户**：`.env.mainnet` 的 ADDRESS/PRIVATE_KEY（= 全部在网合约 owner）。
4. **回填目标**：`strk20.json`、本文档、`texas/.env`、`client/.env.production`。

## 2. 执行（一键）

```bash
CONFIRM_MAINNET=yes ./scripts/deploy_mainnet_v6.sh
```

脚本流程（含 compiled-hash mismatch 自动重试与 nonce 竞态重试）：

```
declare ×4（vault / anonymizer / dual v6 / registry）
→ deploy vault(owner, canonical STRK, settlement=0)
→ deploy anonymizer(owner, vault, 主网池)
→ deploy dual v6(owner, vault, prover)   # dual 无 set_vault，必须随 vault 重部署
→ deploy registry(owner, grace=604800)
→ 接线：vault.settlement/unshield/authorized；dual.claim_helper/
  circuit_program_hash/hand_verify_program_hash/virtual_snos(占位)
→ 链上回读（含 session_tx_pk 入口存在性检查）
```

PAYOUT（`0x40237293…`）、池、两个 program hash 已内建为默认值，可用环境变量覆盖。

## 3. 部署后切换（改 env 即生效，旧合约原地保留）

```
texas/.env:                STARKNET_CHAIN_ID=SN_MAIN（保持）
                           STARKNET_VAULT_ADDRESS=<新 vault>
                           STARKNET_DUAL_SETTLEMENT_ADDRESS=<新 dual v6>
                           STARKNET_TABLE_REGISTRY_ADDRESS=<registry>
                           （legacy settlement / claim helper 不变）
client/.env.production:    VITE_POKER_VAULT_ADDRESS=<新 vault>
                           VITE_POKER_VAULT_ANONYMIZER_ADDRESS=<新 anonymizer>
                           （其余不变）
```

## 4. 验证清单

- [ ] 脚本回读全绿：`vault.token`=canonical STRK、`vault.unshield_helper`=新
      anonymizer、`session_tx_pk` 入口存在（P1-2）、`dual.vault`=新 vault、
      `dual.claim_helper`=payout、两个 program hash、registry.table_count=0
- [ ] 服务器重启后 registry 引导 `create_table` 上链 + `is_open` 回读 ✓
- [ ] 浏览器真实买入 1 STRK（会触发 `set_session_tx_pk`——本批的核心验证点）
- [ ] 打完一手牌，结算走 DAPV v2 入口（TX SUCCEEDED）
- [ ] 公开提现 `vault.withdraw` 一笔

## 5. 迁移与回退

- **迁移**：公告主网玩家在旧 vault `0x3f4ef706…` 公开 `withdraw`（存量
  9.47 STRK），到新 vault 重新买入。旧 vault/anonymizer/dual v5 原地保留，
  服务历史提现与认领，永不销毁。
- **回退**：`texas/.env` 与 client env 指回旧地址 + 两笔 owner invoke 把
  交易路径还原（旧 dual v5 / 旧 vault）即回 9-07 行为。

## 6. 开放门槛（不阻塞本批部署）

| 门 | 内容 | 处置 |
| --- | --- | --- |
| G2（SNIP-36） | dual 的 `virtual_snos_program_hash` 当前为占位值 `0x602b02cf…`；真实 proved 交易前须以主网实测 proof_facts 修正（`snops dump-proof-facts` 对拍） | 本批照部署；`STARKNET_DAPV_SETTLE_ENTRY` 保持 `v2`（fact-registry 腿，行为与 v5 等价）；过 G2 后再切 `snip36` |
| 私密领取 156 | Ready X / Avnu paymaster 对私密交易（含钱包原生 Shield）代发失败，交易不上链；Sepolia fork 测试证明合约腿健康，9-08 同流程曾成功 | 钱包侧问题，非本批合约阻塞项；私密出金 UX 暂以 Public withdrawal 兜底，进展见 DEPLOYMENTS.md 2026-09-19 章节 |
