# 主网 STRK20 交易操作指引（TODO #28，黑客松硬性要求）

> 目标：在 Starknet **主网**完成 ≥1 笔 STRK20 交易，交易哈希回填 `strk20.json`。
> 该步骤需要**人工钱包操作**（私钥不出本机），脚本无法代办。
> 执行前重读 `SETTLEMENT_PRIVACY_PLAN.md` §7 验证清单(历史迁移计划见 docs/archive/EXECUTION_PLAN.md)
> 「主网最小路径」：在「直接 STRK20 转账」与「PokerVault 主网最小部署」两案中
> **选最简者**。

## 方案对比

| 方案 | 动作 | 前置 | 成本 |
| --- | --- | --- | --- |
| A. 直接 STRK20 转账（推荐先行） | 钱包内发起一笔 STRK 转账（可自转账） | 主网钱包 + 少量 STRK（转账额 + gas） | 最低 |
| B. PokerVault 主网最小部署 + deposit | sncast declare + deploy + deposit | 主网账户（deployer 私钥）+ gas | declare/deploy gas 较高 |

黑客松要求「不必是完整游戏，deposit + withdraw 即可」——方案 A 用钱包原生
STRK20 转账即满足「一笔主网 STRK20 交易」；若评审叙事需要 Vault 买入闭环，
再补方案 B。

## 方案 A：直接转账（约 5 分钟）

1. 用 Ready（或任一 Starknet 主网钱包）确保主网账户有少量 STRK
   （转账金额 + ~0.01 STRK gas 余量即可）。
2. 在钱包内发起一笔 STRK 转账：
   - 接收地址建议用项目方演示地址（与 sepolia 演示同源），自转账亦可；
   - 金额任意（演示用 1 STRK 足够）。
3. 等待交易 ACCEPTED_ON_L2，从钱包或
   <https://starkscan.co>（切主网）复制交易哈希。
4. 回填 `strk20.json`（见下节模板），并同步 `README`/`README.zh-CN` 的
   Deployment 章节一句话记录。

## 方案 B：PokerVault 主网最小部署（可选，闭环叙事）

复用 `poker_contracts/scripts/deploy_sepolia.sh` 的口径，仅换主网参数：

```bash
# env（绝不入库私钥；用临时 shell 变量或本地 .env.mainnet）
SNCAST_URL="https://starknet-mainnet.public.blastapi.io/rpc/v0_7"  # 任一主网 RPC
SNCAST_ACCOUNT="<主网 deployer 账户名>"   # sncast account add 导入
```

1. `cd poker_contracts && scarb build`；
2. declare `PokerVault`（**无需本地代币**——vault v3 起绑定 canonical STRK：
   sepolia 现网 `vault.token()` 即原生 STRK，本地 pSTRK 已 retired，如需
   1:1000 兑换另有 `PokerSwap`。主网部署以同一构造为准，执行前仍建议
   核对 `poker_vault.cairo` 的 token_address 构造参数）；
3. deploy `PokerVault` + `deposit` + `withdraw` 各一笔（黑客松口径的最小闭环）；
4. 全部交易哈希回填 `strk20.json`。

> ~~方案 B 会把「本地测试代币」暴露到主网~~（已不成立：vault v3 绑定
> canonical STRK），但方案 A 仍是最简路径——先交付 A，B 仅作闭环叙事补充。

## strk20.json 回填模板

```jsonc
// token 节点：
"mainnet_address": "<主网 STRK：0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07271812f30d58d03>",
// 若方案 B：另补 contracts 节点的主网 address/class_hash 与 note。

// transactions（或顶层 demo）节点新增：
"mainnet_tx": {
  "network": "mainnet",
  "kind": "native_strk_transfer",   // 方案 B 填 "vault_deposit"
  "tx_hash": "0x…",
  "timestamp": "<ISO8601>",
  "note": "STRK20 mainnet transfer (hackathon step 3)"
}
```

## 验收

- [ ] `strk20.json` 记录主网交易哈希，starkscan 主网可查、状态 ACCEPTED_ON_L2；
- [ ] README（英/中）Deployment 章节更新一句话；
- [ ] TODO.md #28/#29 勾选。
