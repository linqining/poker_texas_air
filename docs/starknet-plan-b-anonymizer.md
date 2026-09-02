# Plan B：PokerVaultAnonymizer 私密买入（B+C 抗审查组合）

> 目标：B（资金链路私密化）+ C（执行层加固，见
> [starknet-plan-c-execution.md](starknet-plan-c-execution.md)）组合后，
> **提交环节无法按用户身份定向拒绝**：链上交易发送者 ≠ 用户（C 的 paymaster
> 中继），私密交易 calldata 不含用户资金身份（B 的 note + ZK 证明），观察者
> 只看到"anonymizer 给某玩家记账"这一公开动作，且无法追溯到是谁出的钱。

## B+C 合并交互示意图（mermaid）

```mermaid
sequenceDiagram
    autonumber
    actor U as 玩家浏览器 UI
    participant PB as privacyBuyIn.ts<br/>(私密买入通道)
    participant PC as paymaster.ts<br/>(Plan C 提交通道)
    participant W as STRK20 钱包 / SDK<br/>(viewing key, 签名)
    participant R as game server 中继<br/>/api/starknet/paymaster
    participant A as 上游 paymaster
    participant P as STRK20 Privacy Pool<br/>0x0403…812a (mainnet)
    participant AN as PokerVaultAnonymizer<br/>privacy_invoke
    participant V as PokerVault
    participant S as game server<br/>verify_deposit

    rect rgb(240, 248, 255)
        note over U,W: 前置（一次性）：shield —— 用户把 STRK 入池变成加密 note
        U->>W: 钱包一键 shield（或 SDK deposit）
        W->>P: 公开 deposit（此步暴露"某人入池"，金额/身份即止于此）
    end

    rect rgb(235, 242, 255)
        note over U,S: 买入：私密交易（B 隐藏资金来源 + C 隐藏提交者）
        U->>PB: submitBuyIn(account, chips)
        PB->>PC: 私密交易经 Plan C 通道提交
        PC->>R: paymaster_buildTransaction(pool apply_actions)
        R->>A: 透传 + x-api-key（key 只在服务端）
        A-->>PC: OutsideExecution typed_data
        PC->>W: signMessage（签名留在客户端）
        PC->>R: paymaster_executeTransaction
        A->>P: 以 paymaster 账户广播私密交易<br/>（tx sender ≠ 用户；calldata = 加密 note + nullifier + ZK 证明）
        P->>P: 验证证明 → 花费 note → InvokeExternal 阶段
        P->>AN: privacy_invoke(player, amount, change_note_id)
        AN->>V: deposit_for(player, amount)（approve 后 vault 拉取）
        V-->>AN: 筹码 1:1 记给 player
        AN-->>P: 返回找零 Span&lt;OpenNoteDeposit&gt;（approve 池拉回）
        P->>U: 找零以 open note 回到用户
    end

    rect rgb(255, 244, 235)
        note over U,S: 回退：私密后端任一环节失败 → 公开路径（仍是 Plan C）
        PB->>PC: depositForBuyIn(approve+deposit)
        PC->>S: paymaster 中继或 session 直签（见 Plan C 图）
    end

    U->>S: SIT_DOWN_V2(depositTxHash 可为空)
    S->>S: verify_deposit: 空哈希→跳过回执<br/>chip_balance(player) ≥ chips 权威校验
```

### ASCII 版

```
                    ┌──────────────────── 玩家（客户端） ────────────────────┐
                    │  privacyBuyIn.ts ──失败/未配置──▶ depositForBuyIn      │
                    │   (B: 私密买入)                  (公开路径,Plan C)      │
                    │        │                               │               │
                    │   签名留在客户端                    approve+deposit     │
                    └────────┼───────────────────────────────┼───────────────┘
                             │ paymaster_* JSON-RPC          │
                             ▼                               ▼
                 ┌──────────────────────┐        ┌────────────────────┐
                 │ game server 中继      │        │ STRK20 Privacy Pool │
                 │ x-api-key 服务端注入  │──▶ 上游 paymaster 以自己账户广播
                 └──────────────────────┘        (C: tx sender ≠ 用户)
                                                             │ 私密交易
                             加密 note + nullifier + ZK 证明   ▼
                             (观察者看不到付款人/金额) ┌──────────────────────┐
                                                      │ pool InvokeExternal  │
                                                      └──────────┬───────────┘
                                                                 │ privacy_invoke(player, amount, note_id)
                                                                 ▼
                                                      ┌──────────────────────┐
                          B 隐藏"谁出钱"   ──────────▶ │ PokerVaultAnonymizer │
                                                      │  └ deposit_for ──▶ PokerVault
                                                      │    (筹码记给 player,  │
                                                      │     此动作公开)       │
                                                      └──────────────────────┘
                                                                 │
  SIT_DOWN_V2(depositTxHash=空) ──▶ server: chip_balance(player) ≥ chips ✓ ──▶ 入座
```

## 实现清单

| 位置 | 内容 | 验证 |
|---|---|---|
| `poker_texas_air/poker_contracts/src/poker_vault.cairo` | `deposit_for(player, amount)`：调用者付款、给任意 player 记账 1:1（与 `deposit` 共享 `pull_and_credit`） | snforge `deposit_for_credits_player_1to1` ✓ |
| `poker_texas_air/poker_contracts/src/poker_vault_anonymizer.cairo` | STRK20 规范的 `privacy_invoke(player, amount, change_note_id) -> Span<OpenNoteDeposit>`：approve vault → deposit_for → 找零 approve 池拉回 + 返回 open note；仅 pool 可调；u128 溢出/ZERO_OUT/空找零守卫 | snforge 5/5 ✓ |
| `texas/src/starknet/chips.rs` | `verify_deposit`：空 `deposit_tx_hash`（私密买入）跳过回执检查，`verify_chip_coverage`（chip_balance 权威）独立成函数 | `cargo +nightly check` ✓ |
| `client/src/starknet/privacyBuyIn.ts` | 私密买入双后端：STRK20 钱包 API（`strk20InvokeTransaction`，运行时探测）+ 官方 SDK（动态加载，register/approve/deposit 按官方示例，invoke 组合运行时探测）；viewing key 本地生成于 localStorage | tsc + vite build ✓ |
| `client/src/starknet/starknetGameActions.ts` | `submitBuyIn`：私密优先、公开回退（回退路径即 Plan C 的 `depositForBuyIn` → `submitCalls`） | tsc ✓ |
| `client/src/starknet/config.ts` | `privacy` 配置块（pool/anonymizer/proving/discovery） | tsc ✓ |
| `client/src/starknet/abis.ts` | `deposit_for` + `POKER_VAULT_ANONYMIZER_ABI` | tsc ✓ |

STRK20 规范要点（对照 starkware-libs/starknet-privacy 与 strk20-by-example）：

- helper 必须且只暴露 `privacy_invoke` 入口，池在 InvokeExternal 阶段经协议 INVOKE_SELECTOR 调用，每笔最多一次
- 池先以普通公开转账把用户输入 note 对应的 token 付给 helper，helper 工作完成后 **approve（不 transfer）** 池拉回输出
- 返回值必须是 `Span<OpenNoteDeposit>`（空 span 合法），池按余额快照 delta 度量输出
- 找零为 open note（salt=1，执行期填量）；金额是 u128 —— 合约里对 u256 余额始终先断言 `high == 0`

## 部署步骤

1. `cd poker_texas_air/poker_contracts && scarb build`（产物在 `target/dev/`）
2. 升级/重部署 PokerVault（新 ABI 增加 `deposit_for`；数据迁移按现有部署流程）
3. 部署 PokerVaultAnonymizer：constructor `(vault, pool)`；sepolia 的 STRK20 privacy pool 地址按官方 SDK/文档获取（mainnet pool 为 `0x040337b1af…812a`）
4. 前端配置（全部就绪才启用，否则自动走公开路径）：

```bash
# client (.env.local)
VITE_PRIVACY_BUYIN_ENABLED=true
VITE_STRK20_POOL_ADDRESS=0x…          # STRK20 privacy pool
VITE_POKER_VAULT_ANONYMIZER_ADDRESS=0x…  # 部署后的 anonymizer
VITE_PRIVACY_PROVING_URL=…            # proving service（PRIVACY-0.14.3-RC.x docker）
VITE_PRIVACY_DISCOVERY_URL=…          # discovery service
```

5. 上游服务：proving service + discovery service docker 镜像（配合 pathfinder v0.22.7）；SDK 依赖 `@starkware-libs/starknet-privacy-sdk` 需 GitHub Packages 鉴权安装（RC 阶段）

## 谁能看到什么（B+C 组合后的诚实边界）

| 观察 | B+C 之后 |
|---|---|
| 私密交易 calldata | 加密 note + nullifier + 证明 —— 付款人、金额、用了哪些 note 全隐藏 |
| 交易发送者 | paymaster 账户（C）；即使 outside-execution trace 里，执行者是池合约，不是用户 |
| anonymizer 的 `deposit_for` | **公开**：某地址给 player 记了账。但无法链接到出资用户 |
| 用户钱包 → 池的 shield 入金 | shield 本身公开（协议设计如此），但"入池的钱 → 哪个玩家"被池的混隔切断；可加拆分/延迟降低启发式关联 |
| 服务端 | 知道 player（游戏本来就需要）；不知道玩家钱包与出资的对应关系 |
| 合规 | 池内置 viewing key 追溯 + FPI 存款筛查不可绕过（"confidential by default, accountable when required"） |

## 已知 seam 与后续工作

1. **SDK invoke 组合（SDK_SEAM）**：官方 SDK 的 builder `invoke` 方法名/签名未在可获取的公开示例中确认（SDK 未上 npm）。`privacyBuyIn.ts` 运行时探测 `t.invoke(...)`，缺失即自动回退公开路径 —— 安装 SDK 后如接口不符只需改 `tryComposeInvoke` 一处。
2. **wallet-api 路径**依赖 STRK20-capable 钱包（Ready / Xverse，Starknet Phase-1 官方隐私钱包）。当前唯一连接钱包即 Ready（Cartridge 已整体移除），approve/deposit 等动作由钱包弹窗逐笔确认。
3. 提现（cash-out）目前是公开 `vault.withdraw`；若要求全链路私密，下一步给 vault 加 `withdraw_to` + 第二个 anonymizer（unshield 方向），复用同一套模式。
