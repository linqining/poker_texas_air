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

> 2026-09-10 起 `scripts/local_deploy.sh` 已切现代接线（与主网/Sepolia 一致）：
> 不再部署 PokerToken/pSTRK，vault 直接绑定规范 STRK（devnet 费用代币同址）。
> 一键流程（devnet + 部署 + 服务器本地 prover 启动）：`scripts/dev.sh`；
> Sepolia 测试网：`scripts/test.sh` + `texas/.env.test`。

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
"deck 链无法逐字节同步…生产需客户端协议对齐，见 docs/design/DUAL_PROOF_PROTOCOL.md
§5.3"）。浏览器玩家无法产出 mirror 层的 reveal 份额（sk·c1_mirror），
mirror DealHole 永远等不到人类份额 → `mirror has no provable activity`
→ settle 跳过。已尝试/已修的相关项：transcript 统一（Merlin→FiatShamir，
poker_l1 + client.rs + dev_bot）、game_loop 每 tick 驱动 mirror
deadline + 缺失份额服务端补齐（`mirror_fill_pending_reveals`，利用
钱包确定性派生 sk）、mirror 下注缓冲重放。完整修复需按
docs/design/DUAL_PROOF_PROTOCOL.md §5.3 做客户端协议对齐（独立工作量）。

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
  `set_circuit_program_hash(0x25d81d2c...)`（Phase B 电路，15.5s/2048 步）
  TX `0x70bf41c8...` → vault v3 `set_settlement_contract(0x55784c90...)` TX
  `0x4f9d87f0...`（切换点）。
- **冒烟**：`register_hand(0x736d6f6b652d3334/"smoke-34", 0xdeadbeef, 0, 0xa11c3d, 0,0,0)`
  TX `0x4f0788df...` → `hand_action_log` 读回 `0xa11c3d` ✓、registered flag=1 ✓。
- **✅ 真实 DAPV 全链路结算冒烟（2026-09-05，TODO #22①/#34④）**：
  游戏层真实流程 → prove_log 重建 → 真实证明链 → 认可批次 → 链上
  `register_hand`（TX `0x28ab0dc7...`）+ `verify_and_settle_dapv_stark`
  （TX `0x1215cde0...`，SUCCEEDED）。**gas 实测（2 人合成手）：l2_gas
  4,313,040 + l1_data_gas 288**。复现：
  `STARKNET_SEPOLIA_SMOKE=1 cargo test -p texas --bin texas sepolia_settle_smoke -- --ignored --nocapture`。
- **发现并修复**：此前在网的 claim helper class `0x5ec1...` 是**加 settlement
  绑定之前**的旧 2 参版（`settlement()` EntrypointNotFound、vault 还指向
  vault v2 `0x1e9f4a93...`）——本次随 v3.x 重部署为现役 3 参 class。旧 helper
  `0x393fb6f9...` 的历史托管原地保留，服务旧 dual 的历史认领。
- **env 切换**：`texas/.env` 已指向 dual v3.x + 新 helper（当前无运行中的
  服务进程，下次 `cargo run` 即生效）。

### ✅ #18 Phase C 切片 2："合法默认"约束（2026-09-05）

电路词条区改 2 词 × 30 槽（日志打包词 + 合法性词），解包校验 action 白名单
与 flags，对 auto 词条强制 `legal_auto_action` 规则（§8.2 主网门槛达成）；
e2e 含非法默认负例（auto FOLD 谎称 Check → 中止 ✓）。新 program hash
`0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4`
（prove 7.8s）已上链 `set_circuit_program_hash` TX `0x55f9297b...` 并视图验证 ✓。
无合约 ABI / 公开段变化（仍 15 felt），仅电路内部 + hash 指针。

### ✅ #18 Phase C 切片 1：动作日志哈希链 keccak→Poseidon（2026-09-05）

电路 main 增加动作日志词条区（1 计数 + 60×1 打包词，`action(40)|flags(2)@40|
amount(64)@42|seq(64)@106|seat(32)@170`，202 位），用 poseidon_builtin 重放
整链并断言链根 == 吸收进 settlement digest 的动作日志哈希；补零槽 canonical。
游戏层 `action_log_digest_felt` 从 starknet_keccak 链切到同一 Poseidon sponge。
新 program hash `0x5b993db5...`（prove 实测 7.5s），已 owner 上链
`set_circuit_program_hash` TX `0x31401a6e...` 并视图验证 ✓。
为切片 2（"合法默认"约束：解包 flags/action + owed/my_bet/big_blind 见证）铺路。

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


## PokerDualSettlement v4 — P2-M4 双证明私密结算（2026-09-06）

新增 `verify_and_settle_dapv_proved_private(hand_binding, hand_id, segment, p_batch_commitment, p_batch_len)`
（hand_verify + stark verify 双 fact 认证）与 `register_hand_proved`（钉住
p_batch 承诺/长度）、`set_hand_verify_program_hash`；双 fact：
`poseidon([hand_verify_program_hash, p_batch_commitment])` +
`poseidon([circuit_program_hash, segment])`。派奖与 v2 private 相同
（金额藏 cm，escrow 按公开段 total_winnings 划转）。snforge 92/92。

| 项 | 值 |
| --- | --- |
| class | `0x02c73f48a7b6e1f615e972525fc25c677aa1937234b5fe7aa9fe7c402072cf6b` |
| 地址 | `0xbfc7046b6a855a2c6a144441370e9cee27caf57a9aaf4708d8b48fa8640eb8` |
| declare TX | `0x12499773ffb7d3f416e6d9381bb597b2b7bf0960e9b8a4e6b2f7760e3677082`（casm Actual `0x74e1aadc...` 重试后落地） |
| deploy TX | `0x3a9610e5aeaee41caff5a6910fb76397074047a12562515748722aa4530b06a` |
| 构造参数 | owner=deployer(`0x6e37...c782`) vault=`0x0629385f...`(v3) initial_prover=deployer |
| set_claim_helper | `0x37d9a110...` → `0x60a4c474...`（SettlementPayoutAnonymizer） |
| set_circuit_program_hash | `0x4d46cb37...` → `0x744d16d3...`（#18 Phase C 切片 2 电路） |
| set_hand_verify_program_hash | `0x21cfd7c4...` → `0x303029d8...`（hand-verify-native form-② composed） |
| 回执 | 四笔均 SUCCEEDED；`circuit_program_hash` 视图已验证 |

（部署脚本 `scripts/deploy_sepolia_v4.sh`；旧 dual v3.x `0x55784c90...` 保留服务
历史已结算手的认领，`.env` 已切换指向 v4。）

## PokerDualSettlement v5 — cairo 2.19.4 迁移 + SNIP-36 v3 双门入口（2026-09-07）

P1+P2 落地：合约工具链 scarb 2.11.4 → **2.19.4**（与证明侧 vendored corelib
2.19.4 完全同版，双工具链合一）；snforge 0.39.0 → **0.63.0**（原生
`cheat_proof_facts` mock）。新增 `verify_and_settle_dapv_stark_private_v3`
（SNIP-36 `proof_facts` 协议内验证优先 + fact-registry 降级双门）+
`DualProofSettledSnip36` 事件。`poker_swap.cairo` 删除（pSTRK 已下线，
其 5 个测试随之移除）。测试 91/91（含 v3 四例：SNIP-36 门结算 /
fact 降级 / 错 program hash 拒 / 错消息哈希拒）。

**意外利好**：2.19.4 编译器产物 casm **36,508 felts**（2.11.4 时代为
81,175 贴近 81,226 上限）——余量 55%，后续入口扩容空间充足。

| 项 | 值 |
| --- | --- |
| 工具链 | scarb 2.19.4 + snforge 0.63.0（`~/.local/opt/toolchains/` 并行安装，PATH 前缀使用） |
| class | `0x047e91d54d171401a314a591ab1b67d3259e09b9f90c0036675829f533884cf8` |
| 地址 | `0x29bdc970330f545c8be2d78fdcd8a92cc0378dff4b6d7464257df9b4fdd47d6` |
| 配置 | claim_helper=`0x60a4c474...`、circuit_program_hash=`0x744d16d3...`（视图已验证）、hand_verify_program_hash=`0x303029d8...` |
| 回退 | v4 `0xbfc7046b...` 保留（v2/proved_private 入口）；`.env` 已切 v5 |

⚠️ 槽位冻结待办：v3 的 `facts[2]`/`facts[8]` 槽位与消息哈希公式以
SNIP-36 参考实现为口径——首个真实 SNIP-36 证明提交前需用 sepolia 真实
proof_facts 样本对拍一次（执行计划 G2 门）。

## 主网部署准备（2026-09-07，待执行）→ ✅ 已部署（同日）

在用合约 5 个（`strk20.json` 已同步清理：pSTRK/PokerSwap/CashoutUnshieldHelper 退役）：
PokerVault / PokerSettlement(legacy 兜底) / PokerDualSettlement(v5) /
PokerVaultAnonymizer(v4) / SettlementPayoutAnonymizer。

### 主网常量（已核对）

| 项 | 值 | 来源 |
| --- | --- | --- |
| canonical STRK | `0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d` | mainnet=sepolia 同址 |
| STRK20 privacy pool | `0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a` | strk20-by-example.org/contract-addresses（2026-09-03 验证） |
| chain id | `SN_MAIN`（client hex `0x534e5f4d41494e`） | — |
| 电路 program hash | `0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4` | #18 Phase C 切片 2（与 sepolia v5 同版） |
| hand-verify program hash | `0x303029d8ce0ec1d0295e4037fc7f87a1ada0c27423cc99bcd080d25b1c6829f` | 同上 |

⚠️ anonymizer 的 pool 地址构造时写死（v4 只有 `set_vault` 无 `set_pool`；
SettlementPayoutAnonymizer 无任何 setter）——STRK20 池升级需重部署 helper。

### 费用估算（2026-09-07 主网 RPC 真实模拟，simulateTransactions pre_confirmed）

方法：`starknet_simulateTransactions` 捆绑 [DECLARE + UDC deployContract INVOKE]
逐合约模拟，SKIP_VALIDATE/SKIP_FEE_CHARGE，gas 价快照 l2=2.76e10 fri、
l1_data=2.77e10 fri（Starknet 0.14.3，block ≈14,478,000）。declare 费用
以 l2_gas 为主（节点只对 declare 计 192 l1_data 单位）。

| 合约 | sierra / casm | declare | deploy(UDC) | 小计 |
| --- | --- | --- | --- | --- |
| PokerVault | 9,868 KB / 17,682 felts | 28.19 STRK | 0.016 | 28.21 |
| PokerSettlement | 4,726 KB / 8,559 felts | 14.11 STRK | 0.016 | 14.12 |
| PokerDualSettlement | 18,192 KB / 36,508 felts | 59.07 STRK | 0.016 | 59.09 |
| PokerVaultAnonymizer | 1,982 KB / 3,230 felts | 6.31 STRK | 0.016 | 6.32 |
| SettlementPayoutAnonymizer | 1,975 KB / 4,017 felts | 7.16 STRK | 0.016 | 7.18 |
| **合计** | | **114.84** | **0.08** | **114.92 STRK** |

- 接线 5 笔 owner invoke（set_settlement_contract / set_unshield_helper /
  set_claim_helper / 两个 program hash）合计 < 0.1 STRK。
- deployer 账户若未部署（OZ account declare+deploy）另需 ≈0.5 STRK。
- **建议部署账户充值 ≥ 130 STRK**（估算 115 + gas 价波动缓冲）。

已知坑（模拟时确认，主网 publicnode/Juno 同样存在）：节点重算的
compiled-class-hash 与本地 cairo 2.19.4 可能不一致（报
`Mismatch compiled class hash … Expected: 0x…`）——`deploy_mainnet.sh`
沿用了 snops 的 `--compiled-hash <Expected>` 自动重试。模拟端点曾把
sierra abi 按字符串序列化重算出不同 sierra hash，不影响费用结论
（费用只随 calldata 大小变化）；真实 declare 由 snops/starknet-rs
发送原生格式，sepolia v5 实测无此问题。

### 执行

```bash
cd poker_contracts && PATH="$HOME/.local/opt/toolchains/scarb-2.19.4/bin:$PATH" scarb build
cargo build -p texas --bin snops
# .env.mainnet 写入 ADDRESS/PRIVATE_KEY（主网 deployer，≥130 STRK）
CONFIRM_MAINNET=yes ./scripts/deploy_mainnet.sh
```

脚本顺序：declare×5 → vault(owner, STRK, settlement=0) → settlement(owner,
vault, prover) → dual(owner, vault, prover) → anonymizer(owner, vault, pool) →
payout(vault, pool, dual) → 接线（vault.settlement=dual、vault.unshield_helper=
anonymizer、dual.claim_helper=payout、dual 两个 program hash）→ 链上回读。
部署后回填 strk20.json / 本文档 / texas `.env` / client `.env.production`。

### ✅ 主网部署完成（2026-09-07）

deployer/owner/operator = `.env.mainnet` 账户 `0x412e4d43...46121a6`
（snops gen-key 离线生成，OZ class `0x05b4b537...`，充值 200 STRK）。
账户部署 TX `0x4512a29d...`；全量脚本 `CONFIRM_MAINNET=yes ./scripts/deploy_mainnet.sh`。

| 合约 | 主网地址 | class hash |
| --- | --- | --- |
| PokerVault | `0x3f4ef706ae2dc00ac685afffc05e5f1e1e9ab5aacf99c3205d2067e061cbb45` | `0x7c74ca1a...` |
| PokerSettlement (legacy) | `0x2bf6a09c0aaea154de34745056e7534f58fa0805c12afe18cf22a9bc66ee7a8` | `0x6f2e01a6...` |
| PokerDualSettlement (v5) | `0x1d39b80b990038ceeeaf3d39e83cb83031be95c0d0ccca5d18c5faea29aef6d` | `0x047e91d5...`（与 sepolia v5 同 class） |
| PokerVaultAnonymizer (v4) | `0x88c1f843588d1498fcd3f780fa7cf86ada18cd416754c77149a8c14e492877` | `0x525646bd...`（与 sepolia v4 同 class） |
| SettlementPayoutAnonymizer | `0x402372930ea52cccbafa459169b3dae3d67051ed741e9af7da669a0f1fbb308` | `0x7c11073c...`（当前源码新 class） |

- 接线验证（链上回读）：vault.token=canonical STRK ✓、vault.unshield_helper=
  anonymizer ✓、settlement.vault=vault ✓、dual.claim_helper=payout ✓、
  dual.circuit_program_hash=`0x744d16d3...` ✓；hand_verify_program_hash 无
  getter——幂等重设一次 SUCCEEDED（TX `0x1ddcf414...`）确认为 `0x303029d8...`。
- 实际花费 **122.37 STRK**（200 − 77.63，含账户部署+15 笔部署/接线+1 笔幂等重设；
  对比估算 115.5，gas 价波动内）。
- 主网 STRK20 池 `0x040337b1...` 已绑入两个 anonymizer 构造。
- 服务端/前端切换（改 env 后重启生效）：

```
texas/.env: STARKNET_RPC_URL=https://starknet-rpc.publicnode.com
            STARKNET_CHAIN_ID=SN_MAIN
            STARKNET_STRK_ADDRESS=0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d
            STARKNET_VAULT_ADDRESS=0x3f4ef706...
            STARKNET_SETTLEMENT_ADDRESS=0x2bf6a09c...
            STARKNET_DUAL_SETTLEMENT_ADDRESS=0x1d39b80b...
            STARKNET_CLAIM_HELPER_ADDRESS=0x40237293...
client/.env.production: VITE_STARKNET_CHAIN_ID=0x534e5f4d41494e
            VITE_STRK_TOKEN_ADDRESS=<canonical STRK 同上>
            VITE_POKER_VAULT_ADDRESS=0x3f4ef706...
            VITE_POKER_SETTLEMENT_ADDRESS=0x2bf6a09c...
            VITE_POKER_VAULT_ANONYMIZER_ADDRESS=0x88c1f843...
            VITE_STRK20_POOL_ADDRESS=0x040337b1af3c663e86e333bab5a4b28da8d4652a15a69beee2b677776ffe812a
```

## PokerVaultAnonymizer v4 — 私密领取守恒修复（2026-09-07）

OP_WITHDRAW 从 `burn_chips`（无代币移动 + 用户池内自筹注资——每领 X 销毁
X 价值：chips 烧掉、背书 STRK 滞留 vault 无人可领、输出 note 全额来自用户
自己的钱）改为 `withdraw_to`：烧 player 等额筹码并由 vault 释放背书 STRK
给 helper，输出 open note 由 vault 出资——**无需任何池内预存余额**，用户
chips −X / note +X 分文不丢。前端两动作删去自筹 withdraw 桥与屏蔽余额
前置检查（strk20.ts claimRewardsPrivate）。

| 项 | 值 |
| --- | --- |
| class | `0x525646bdab97344307b3bd4cbb80344ee26415366743d181e52c61f1a250c81` |
| 地址 | `0x7ee059ddb3afaa1975d8ac73f273ba6033bfc6a2f3b7421b35a2364023ad9dd` |
| 构造 | owner=deployer(`0x6e37...c782`) vault=`0x0629385f...`(v3) pool=`0x254a6b...d91`（STRK20 Sepolia 池，视图回读 ✓） |
| 接线 | vault `set_unshield_helper(0x7ee059dd...)` TX `0x18fbf4fa...`（旧 v3 `0x6fd4be6e...` 保留 authorized_helper 语义但 OP_WITHDRAW 已废弃） |
| 测试 | snforge 91/91（withdraw 三负例改守恒语义：unshield 门/超额/零 note） |
| env | client `VITE_POKER_VAULT_ANONYMIZER_ADDRESS` 已切新地址（vite 已重启） |
