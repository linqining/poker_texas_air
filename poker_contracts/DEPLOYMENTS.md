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
# Sepolia 全量部署（含 PokerSwap，源 .env.dev）：
URL=https://starknet-sepolia-rpc.publicnode.com ./scripts/deploy_sepolia_full.sh
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

## 当前部署：Starknet Sepolia 测试网（2026-08-31，deploy_sepolia_full.sh）

chain id `SN_SEPOLIA`，RPC `https://starknet-sepolia-rpc.publicnode.com`。
部署者/owner/operator = `.env.dev` 账户 `0x6e37d33462f7319261396d7d7f669d147e40cdef91c6a8305cfde771805c782`。

| 合约 | 地址 | class hash |
|---|---|---|
| PokerToken (pSTRK) | `0x4bfad561733ba5bef162be3606cada13bc85a8a69fd6a52dae2b844d431f9db` | `0x5d745b518295d8ffede689e51f4ec26b020e831b19d2b50546206e5037efe8d` |
| PokerVault | `0x6c8ac4202222a9bcf1f69cc213a2570a393bb83ca64666c7a5cd4a5894c1321` | `0x2bf5d0dc6d58cf64eedad5a5747e3d8a7e426028ecf73263a7558162fdf46c9` |
| PokerSettlement (legacy) | `0x76a0b49a40c706d438c5f8675165d462de5a0a7d5183183e8b4746b955b5194` | `0x6cc6ff2c1753f8ab5ff9dc155b461cb0d8650332f648888751ae31adc520d9c` |
| PokerSwap（双向 1:1000） | `0x45a5d045fad8ba092e7919e26b34fa9e901b3ebc93b42120262dbade6cbcee9` | `0x682e15685f0b336e88b4b2d067bff95ebf6d5c296ecd1a7d8a5ca596745a592` |
| PokerDualSettlement | —（见下） | —（见下） |

- Token 复用上一轮（2026-08-29）UDC salt=0 部署；Vault/Settlement/Swap 为本轮全新部署
  （本轮起 vault lib 类已在链上声明，UDC 确定性地址不再与 unittest 旧类冲突）。
- 链上验证：`vault.token` ✓、`settle.vault` ✓、`swap.rate = 1000` ✓、
  swap 双侧储备 100,000 pSTRK + 15 STRK ✓。
- vault.settlement_contract → legacy PokerSettlement（服务端 `STARKNET_SETTLEMENT_MODE=legacy`）。
- **PokerDualSettlement 无法在 Sepolia 部署**：casm 字节码 81,175 felts 超过链上 80,000
  上限（节点拒绝声明；devnet 无此限制故本地 e2e 可跑 DAPV）。Phase 2 需先瘦身
  （当前超出约 1,175 felts）再走 on-chain DAPV。
- snops 补丁（zgame/texas/src/bin/snops.rs）：`SNOPS_GAS_AMOUNT_MULT` /
  `SNOPS_GAS_PRICE_MULT` 可收紧默认 1.5× 估价系数（低余额账户 declare 用）。
- 浏览器直签联调：`client/.env.development` 的 `VITE_DEV_ACCOUNT_*` 指向同一
  `.env.dev` 账户，登录签名/兑换/买入/提现全部直签（生产删除即回退钱包）。

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

浏览器钱包（Ready 等注入钱包）签的是 Sepolia，无法给 devnet 合约签交易。为让兑换在
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

## Sepolia E2E 状态（2026-08-31）

| 环节 | 状态 | 证据 |
| --- | --- | --- |
| 兑换 STRK→pSTRK | ✅ 浏览器跑通 | tx `0x7e5132dc…`，+1000 pSTRK 精确 |
| 买入（vault.deposit） | ✅ 浏览器跑通 | 服务端验证 `amount=1000`，tx `0x712c41dc…` |
| 手牌流程（发牌/reveal/下注/摊牌） | ✅ 浏览器+bot 打完 | showdown 触发 `on_hand_complete` |
| 链上结算（register_aggregate + settle_hand） | ⛔ 阻断 | mirror 证明层缺浏览器玩家份额（见下） |

### 结算阻断点（遗留）

mirror（poker_l1 证明层）走自治 deck 链，与游戏 deck 不同步（代码注释
"deck 链无法逐字节同步…生产需客户端协议对齐，见 DUAL_PROOF_PROTOCOL.md
§5.3"）。浏览器玩家无法产出 mirror 层的 reveal 份额（sk·c1_mirror），
mirror DealHole 永远等不到人类份额 → `mirror has no provable activity`
→ settle 跳过。已尝试/已修的相关项：transcript 统一（Merlin→FiatShamir，
poker_l1 + client.rs + dev_bot）、game_loop 每 tick 驱动 mirror
deadline + 缺失份额服务端补齐（`mirror_fill_pending_reveals`，利用
钱包确定性派生 sk）、mirror 下注缓冲重放。完整修复需按
DUAL_PROOF_PROTOCOL.md §5.3 做客户端协议对齐（独立工作量）。

### 本次修复的其他 bug（影响 e2e 的真实缺陷）

1. client `WEI_PER_CHIP` 1e5 ≠ server 1e14（买入金额差 9 个数量级）
2. `availableChips` 只用服务端结余，挡死首次链上买入
3. 钱包登录 `signature/messageHash` bigint 序列化崩溃（"闪退"根因）
4. LoginModal 在 dev 直签模式下开窗即自关
5. StrictMode 下 `isUnmountingRef` 永久 true → TABLE_UPDATED 每次广播
   都触发 STAND_UP（玩家被反复移座）
6. `broadcast_to_table` / `broadcast_player_reveal_result` 同钱包多
   socket 时取任意一条（陈旧 socket → 广播丢失）
7. reveal token 双重提交竞态（REVEAL_NOTICE 与 TABLE_UPDATED fallback
   并发）→ "already submitted" 报错
8. dev_bot 循环 mirror 分支 `continue` 饿死游戏层动作
9. snops 估价系数不可调（低余额 declare 被拒）→
   `SNOPS_GAS_AMOUNT_MULT` / `SNOPS_GAS_PRICE_MULT`

## Dual settlement v3（P2-M3 零明文结算，2026-09-03 待部署）

代码已就绪（`verify_and_settle_dapv_stark_private_v2`：calldata 零明文，消费
settlement_private 电路公开段），**链上部署被 gas 预算阻塞**：

| 项 | 值 |
| --- | --- |
| class 产物 | sierra 859 KB / casm 737 KB / 32,901 bytecode words |
| declare 资源需求（sepolia 实时报价） | l2_gas 2.86e9 单位 × 4.95e10 wei ≈ **142 STRK** |
| 部署账户（poker-deployer）余额 | ≈ 65 STRK → **缺 ≈77 STRK** |
| 已知坑 | sepolia 当前版本的 compiled-class hash 方案与本地 cairo 2.11.4 不一致——declare 报 `Mismatch compiled class hash ... Actual: 0x55387af9...`；脚本自动以 `--compiled-hash <Actual>` 重试 |
| 电路 program hash（set_circuit_program_hash 用） | `0x2ad181fc357c19c7e7d8a626314605436f6e5c24594d436b0e50af088977478`（prove 实测 14s / 2021 步） |

一键部署（补足 STRK 后）：`HELPER=0x393f... VAULT=0x1e9f... PROGRAM_HASH=0x2ad1... ./scripts/deploy_sepolia_v3.sh`
（自动：declare（含 hash 方案重试）→ deploy(owner, vault, prover) → set_claim_helper → set_circuit_program_hash → 回填 texas/.env。）

## Vault v3（#33 在局锁定，与 dual v3 同批，2026-09-03 代码就绪待部署）

`poker_vault.cairo` 新增（#33 逃单/砖死修复，snforge 8/8 ✅）：
- `locked` / `session_last_activity` / `session_active` / `lock_ttl` 存储；
- `lock`（owner=operator）：入座锁额度；`refresh_session`：结算/续局续时钟；
- `unlock_after_deadline`（无许可）：`timestamp >= last_activity + lock_ttl`
  后任何人可解锁（后端失联保护；TTL=0 禁用，constructor 默认 12h，
  `set_lock_ttl` owner 可调）；`force_unlock`（owner 应急）；
- `withdraw` / `withdraw_to` / `burn_chips` 统一 `assert_spendable`
  （只可花未锁定余额）；`apply_settlement` 负 delta **优先消耗锁定额度**
  （修"输家提款 → 结算砖死"）。

部署（脚本 `DEPLOY_VAULT_V3=1` 段自动完成）：declare vault v3 → deploy
(owner, token, settlement=旧 dual) → `set_unshield_helper(CashoutUnshieldHelper)`
→ `set_settlement_contract(DUAL_OLD)` → dual v3 以新 vault 地址构造。
迁移：旧 vault 玩家余额经公开 `withdraw` 提取后在新 vault 重新 deposit
（或运营 `deposit_for`）。

### ✅ 已部署（2026-09-04，sepolia）

| 合约 | 地址 | 说明 |
| --- | --- | --- |
| Vault v3 | `0x0629385f1e3b43684828cf46488fbd0ef2b1ec0dc27c7827ecbe6b2f15c7fa13` | class `0x2c829f5c...`；#33 在局锁定 + withdraw_to + unshield 门 |
| Dual v3 | `0x516b8289a8b154644b5098e4d4301f2f0c9cf1fd67cdac0516b439094d35f61` | class `0x2e039e95...`；#16/#17 动作签名预留 + `verify_and_settle_dapv_stark_private_v2` 零明文结算 |
| CashoutUnshieldHelper | `0x1c35d8083e25c166bfa033d77009541a2a3a79a5beeca58e7a0a9134a06aaf1` | #25 unshield 提现通道；已在 vault v3 `set_unshield_helper` 授权 |

接线完成：vault v3 `set_settlement_contract(Dual v3)`、`set_unshield_helper(CashoutUnshieldHelper)`；
dual v3 `set_claim_helper(0x393f...)` + `set_circuit_program_hash(0x2ad1...)`。

**迁移步骤（切换 texas/.env 前，玩家先从旧 vault 提走/花掉余额）**：
1. `texas/.env`：`STARKNET_VAULT_ADDRESS` → vault v3、`STARKNET_DUAL_SETTLEMENT_ADDRESS` → dual v3，重启服务器；
2. 旧 vault 余款：`0x1e9f4a93...` 上的剩余 STRK 由 owner `withdraw` 收回。

**✅ 已切换（2026-09-04，测试网不做余额迁移）**：`texas/.env`（vault v3 + dual v3）与
`client/.env.development`（vault v3 + anonymizer v3）均已指向 v3，texas 服务器已重启生效。
旧 vault v2 `0x1e9f4a93...` 上遗留的玩家筹码余额留在原地（筹码读数跟随
`vault.chip_balance`，切后即从 v3 起算；旧余额玩家可随时自行 `withdraw` 取回 STRK）。

相关 TX：vault declare `0x14fb018a...`、dual declare `0x1d5aa149...`（类 `0x2e039e95`）、
helper declare `0x5d751a8e...`、接线 TX 均 ACCEPTED_ON_L2（见各 `set_*` 调用）。

## Dual v3.x + 新 claim helper（#18 Phase B，2026-09-05 已部署 sepolia）

digest 尾词绑定动作日志哈希后的新 ABI 批次：

| 合约 | 地址 | class hash |
| --- | --- | --- |
| Dual v3.x | `0x55784c90b20b2727baec6482192d4600808e9c40c61bc31281350dd5c4de63f` | `0x6db1ea08f1e6759cc5c70e07ed6845ad7d756b226ecd9686c55acb1045b85f0`（declare TX `0x6039a54b...`） |
| SettlementPayoutAnonymizer（新） | `0x60a4c47416de31056cdca968001df0c199d663842c9372e0409d4c60b397871` | `0x5c28571f61d0ff937208e94b6e948a8b93367766a18b6cd448b701300f0d0ee`（declare TX `0x33f765a5...`） |

- **wire 变化**（与 #18 Phase B 代码一致，服务端源码 `8481aa6` 起匹配本 ABI）：
  `register_hand(hand_binding, settlement_digest, g_attestation, action_log_digest,
  exp_reveal, exp_leave, exp_recon)`；`verify_and_settle_dapv_stark[_private]`
  在 `hand_id` 后 +`action_log_digest` 标量；`SETTLEMENT_SEGMENT_LEN=15`
  （公开段尾词 = 动作日志哈希，对注册承诺逐 felt 比对）；legacy
  `settle_hand` 同步 +1 标量。新增 `hand_action_log(binding)` 视图。
- **接线**（全部 SUCCEEDED/ACCEPTED_ON_L2）：dual deploy TX `0x420fccb7...` →
  `set_claim_helper(0x60a4c474...)` TX `0x7a9e0eac...` →
  `set_circuit_program_hash(0x25d81d2c...)`（新电路，prove 实测 15.5s/2048 步）
  TX `0x70bf41c8...` → vault v3 `set_settlement_contract(0x55784c90...)` TX
  `0x4f9d87f0...`（切换点）。
- **冒烟**：`register_hand(0x736d6f6b652d3334/"smoke-34", 0xdeadbeef, 0, 0xa11c3d, 0,0,0)`
  TX `0x4f0788df...` → `hand_action_log` 读回 `0xa11c3d` ✓、registered flag=1 ✓。
  （完整 dapv 手结算冒烟归入实机联调，见 TODO #34④。）
- **发现并修复**：此前在网的 claim helper class `0x5ec1...` 是**加 settlement
  绑定之前**的旧 2 参版（`settlement()` EntrypointNotFound、vault 还指向
  vault v2 `0x1e9f4a93...`）——本次随 v3.x 重部署为现役 3 参 class。旧 helper
  `0x393fb6f9...` 的历史托管原地保留，服务旧 dual 的历史认领。
- **env 切换**：`texas/.env` 已指向 dual v3.x + 新 helper（当前无运行中的
  服务进程，下次 `cargo run` 即生效）。

## PokerVaultAnonymizer v3（2026-09-04，绑定 vault v3 + set_vault 维护口）

随 v3 切换重部署的私密买入/领取 helper（`privacy_invoke` operation 分流：0=买入
approve+deposit_for、1=领取 burn_chips+回池）。新增内容：

- **`set_vault(owner 门控)`**：vault 升级不再需要重部署 helper（此前 vault 地址
  构造器写死，切 v3 必须重部署）。
- **owner 改为显式构造参数**（`constructor(owner, vault, pool)`）：不能在构造器里
  用 `get_caller_address()` 取部署者——starknet-rs `deploy_v3` 经 UDC 部署，构造期
  caller 是 UDC 合约地址，用它当 owner 会让 `set_vault` 永远无人可调（实测踩坑）。

| 项 | 值 |
| --- | --- |
| class | `0x405327310fad98fc864d63282a97495fd9373e28987577ad4c54e8d900ec561` |
| 地址 | `0x6fd4be6e7af47f15b5c801623f49801e00610673fb42f6d7519d9119991b8f5` |
| 部署 TX | `0x228575a24d52d0c59db804ab6a21af4826a5b8c6f10631241bb406adf4b2527` |
| 构造参数 | owner=deployer(`0x6e37...c782`) vault=`0x0629385f...`(v3) pool=`0x254a6b...d91` |
| vault 授权 | vault v3 `set_authorized_helper(本合约)` TX `0x286ae4f39f68...` SUCCEEDED |

（中途一次部署 `0x3854d580...` 因 owner=UDC 缺陷作废，未授权、不可用。）

