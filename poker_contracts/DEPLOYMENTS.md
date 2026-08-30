# Poker 合约部署清单

> 上主网前的部署参考。所有地址以 `strk20.json`（Sepolia）与本文档为准，
> 部署新环境后**必须**回填本文档与 `strk20.json`。

## 合约清单

| 合约 | 作用 | 构造参数 |
|---|---|---|
| `PokerToken` (pSTRK) | 游戏筹码 STRK20 代币（owner-only mint/burn） | `owner, name, symbol, initial_supply` |
| `PokerVault` | 1:1 pSTRK 存取 + 玩家筹码账本 | `owner, token_address, settlement_contract` |
| `PokerSettlement` | legacy 线性结算：aggregate digest 注册 + settle_hand | `owner, vault_address, initial_prover` |
| `PokerDualSettlement` | Phase 2 双证明结算（当前提交未启用） | `owner, vault_address, initial_prover` |
| `PokerSwap` | 双向固定汇率兑换：**1 STRK ⇄ 1000 pSTRK** | `owner, pstrk_address` |

### PokerSwap 细节（双向）

- 规范 STRK 地址硬编码：`0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d`
  （mainnet/Sepolia/devnet 一致）。
- 汇率存储在合约 `rate`（当前 1000）。双向固定汇率（非 AMM 定价）：
  - 正向 `swap_strk_to_pstrk(strk_amount)`：approve STRK → 得 `×1000` pSTRK；
  - 反向 `swap_pstrk_to_strk(pstrk_amount)`：approve pSTRK → 得 `÷1000` STRK，
    **数量必须整除 1000 wei**（即 0.001 pSTRK 的整数倍）。
  - `swap(...)` 保留为正向旧入口。
- 双侧储备：正向兑换的 STRK 自动留在合约作为反向储备；反向兑换的 pSTRK 自动留作正向储备。
- owner 运维：
  - `fund_pstrk(amount)` / `fund_strk(amount)`：注入双侧初始流动性（先 approve）。
  - `sweep_strk(recipient, amount)` / `sweep_pstrk(recipient, amount)`：提取盈余。
  - 视图：`pstrk_liquidity()` / `strk_balance()` / `rate()`。
- 前端：`VITE_POKER_SWAP_ADDRESS` 配置后导航栏显示"⇄ 兑换"入口（弹窗内可切换方向），未配置自动隐藏。

## 部署顺序

```bash
cd poker_contracts && scarb build

# 部署工具：snops（zgame 仓库）或 sncast；deploy_sepolia.sh 为参考脚本
OWNER=<owner 地址> OPKEY=<owner 私钥> URL=<rpc> ./scripts/local_deploy.sh  # devnet
```

1. `PokerToken(owner, "PokerSTRK", "pSTRK", 0)` — 初始供应走 owner mint，便于审计。
2. `PokerVault(owner, pstrk, 0)` — settlement 先占位 0。
3. `PokerSettlement(owner, vault, prover)` — prover 即 operator。
4. `vault.set_settlement_contract(settlement)` — 绑定结算合约。
5. `token.mint(owner, 初始流动性)`。
6. `PokerSwap(owner, pstrk)`：
   - `token.mint(owner, SWAP_LIQUIDITY)`（如 10_000e18）；
   - `token.approve(swap, SWAP_LIQUIDITY)`；
   - `swap.fund_pstrk(SWAP_LIQUIDITY)`。
7. 回填 `strk20.json` + 本文档 + server `.env` + client `.env`：

```
server .env:  STARKNET_STRK_ADDRESS / STARKNET_VAULT_ADDRESS /
              STARKNET_SETTLEMENT_ADDRESS / STARKNET_OPERATOR_*
client .env:  VITE_STRK_TOKEN_ADDRESS / VITE_POKER_VAULT_ADDRESS /
              VITE_POKER_SETTLEMENT_ADDRESS / VITE_POKER_SWAP_ADDRESS
```

## 当前部署：本地 devnet（starknet-devnet --seed 0，端口 5051）

chain id `SN_SEPOLIA`。地址随 devnet 重启 + 重新部署而变化（当前快照）：

| 合约 | 地址 |
|---|---|
| PokerToken | `0x508ab1bc518227bc444ced3b720f3e4f36309f53a32303fd2498ab26c5acb57` |
| PokerVault | `0x2409cd58b021c49d0a68522afbf3338fc3a1bb49d5f53ecaef70a990ea9116c` |
| PokerSettlement | `0x2106e927320e49be067890853c3b2a693dfe9c2fb81665aaf71ca344cc5a53b` |
| PokerDualSettlement | `0x70b4b8e19426a264a2da0cc3651cca137ebb374c61cc3a6e965f7ad1a86f9b2` |
| **PokerSwap**（双向） | `0x44185be81c5671147abd228b859e4af07b732880265cf85b90bbc61df579234` |

- owner/operator = devnet 预充值账户 #0（`--seed 0` 固定）。
- 双向储备：10_000 pSTRK + 10 STRK。
- 已验证：正向 1 STRK → 1000 pSTRK（tx `0x7d608be2…b506`）；
  反向 1000 pSTRK → 1 STRK（tx `0x7c82a228…538b`）。
- 单测：`snforge test poker_swap --max-n-steps 20000000`（3 个全过）。

## devnet 浏览器端到端兑换

浏览器钱包（Cartridge）签的是 Sepolia，无法给 devnet 合约签交易。为让兑换在
浏览器里真实跑通，`client/.env.development` 配置了 dev 直签账户（devnet
预充值账户 #1）：

```
VITE_DEV_ACCOUNT_ADDRESS=0x78662e7352d062084b0010068b99288486c2d8b914f6e2a55ce945f8792c8b1
VITE_DEV_ACCOUNT_PRIVATE_KEY=0x0e1406455b7d66b1690803be066cbe5e
```

配置后 `swapTokens` 用该账户直签（provider 用 `BlockTag.PRE_CONFIRMED` 读
nonce——devnet 交易停留在 pre-confirmed，默认 latest 会拿到过期 nonce，
报 `52: Invalid transaction nonce`）。**生产环境必须删除这两个变量**，兑换
自动回退到连接的钱包签名。已实测：浏览器输入 1 STRK → 确认 → 弹窗显示
"兑换成功 ✓"，链上余额变动精确（-1 STRK / +1000 pSTRK）。

## 上 Sepolia / 主网时

1. 用有 gas 的账户按上面顺序部署（`scripts/deploy_sepolia.sh` 参考；
   主网前把 `JWT_SECRET`/operator key 换成生产密钥，`SNCAST_URL` 换主网 RPC）。
2. `PokerSwap` 无需改动：规范 STRK 地址在各网络一致。
3. swap 流动性建议 ≥ 目标玩家峰值买入总量（1:1000 全额储备 pSTRK）。
4. 回填 `strk20.json`、本文档、server/client env；navbar 兑换入口自动出现。
5. 建议加：swap 合约 owner 转多签、`rate` 紧急可调（当前为固定常量写入 storage）。
