# poker_texas_air — 作弊在数学上不可能的可验证公平德州扑克

[English](README.md) | **简体中文**

![License](https://img.shields.io/badge/license-BUSL--1.1-blue) ![STRK20](https://img.shields.io/badge/STRK20%20RFP-03-purple) ![Rust](https://img.shields.io/badge/rust-nightly--2026--04--15-orange)

本项目为 [STRK20 Private Sprint](https://strk20.starknet.io/hackathon) **RFP-03**（"作弊在数学上不可能的可验证公平扑克"）构建的全栈可验证公平在线德州扑克：

- **Mental poker V2（心灵扑克）** —— 完全没有受信发牌方。扑克牌以 ElGamal 加密，由玩家联合洗牌，每一步（洗牌 / 重掩码 / 离开 / 翻牌 / 重构）都携带 sigma 证明。
- **双证明结算（P/G）** —— P 层（每玩家的 secp256k1 所有权/弃牌/翻牌 sigma 证明）由 `PokerDualSettlement` Cairo 合约通过 Starknet EC_OP 内置件**链上验证**；G 层（牌桌规范状态转移批次，用 Stwo circle-STARK 证明）目前由主机验证、浏览器可独立验证（当前结算运行于 linear 模式，链上双证明验证器为 Phase 2 升级项）。
- **STRK20 作为筹码** —— 玩家将 STRK20 存入 `PokerVault`（1:1 兑换筹码），对局后经隐私池结算。测试网提供本地测试代币 `PokerToken`。
- **Lean 4 形式化验证** —— 重构协议用 Lean 4 + Mathlib 形式化；该过程发现了重构 V2 的不健全性（机器检查的反例），并产出修复后的 V3 及机器检查的完备性与健全性定理（[poker_protocol_lean](poker_protocol_lean)）。

超越 RFP 基线：RFP-03 建议使用受信 dealer，由其 STARK 证明使作弊可被发现。本项目更进一步——**彻底移除受信 dealer**：发牌由玩家联合生成，公平性由构造保证而非信任主机。

## 仓库结构

```
├── src/                    # poker_texas_air：德州 AIR + Stwo（circle-STARK）证明栈
├── texas/                  # 游戏服务器：axum + socket.io 对局循环 + Starknet 结算
├── client/                 # React 18 + Vite 网页客户端（Cartridge Controller 会话密钥）
├── client-wasm/            # wasm-bindgen 桥：浏览器端密码学与证明 bundle
├── poker_protocol/         # 心灵扑克协议（ElGamal、洗牌/翻牌/重构）
├── poker-protocol-core/    # 曲线泛型密码学后端（secp256k1 / STARK / BN254 / BLS12-381）
├── poker-protocol-proofs/  # Sigma 证明套件（shuffle、remask、leave、reveal、DLEq、unified sigma）
├── poker-protocol-bg/      # Bayer–Groth 洗牌论证
├── poker-protocol-abi/     # 证明预编译/电路适配器的稳定字节 ABI
├── poker_l1/ vm-common/    # 最小 L1/VM 层与证明公共组件
├── hand-bench/             # 一整手牌的端到端证明基准
├── poker_protocol_lean/    # Lean 4 + Mathlib 形式化（重构 V2/V3）
├── poker_contracts/        # Cairo 合约（Scarb）：Token、Vault、Anonymizer、Settlement、DualSettlement
├── proving-tool/           # prove-hand CLI：Cairo1 → cairo-vm → Stwo 证明 → 验证（独立 workspace）
├── third_party/proving/    # vendored starkware-libs/proving（Apache-2.0，含本地补丁）
├── docs/                   # 协议规范、信任模型、性能报告
└── strk20.json             # STRK20 黑客松 manifest（部署记录、证明策略）
```

## 信任模型与证明策略

证明处理分为三层，manifest（[strk20.json](strk20.json)）如实声明：

| 层 | 命题 | 验证位置 |
|---|---|---|
| **P（sigma）** | 每玩家所有权/弃牌/翻牌证明，secp256k1，keccak256 挑战 | **链上** —— `PokerDualSettlement` EC_OP 内置件 |
| **G（STARK）** | 牌桌规范状态转移批次（Stwo circle-STARK） | 当前**主机**；浏览器可经 `client-wasm` 证明 bundle 独立验证；链上验证为 Phase 2 |
| **洗牌链** | 玩家联合心灵扑克洗牌，每步 sigma 证明 | 每个客户端随牌局实时验证 |

**本次提交不部署独立 prover 服务。** 运营方（host）使用 `proving-tool` 在本地生成 G 层证明（整手牌约 29 秒，证明约 1.5 MB）并对其有效性作出 attestation。这**不是**正确性上的信任要求：任何玩家都可以下载证明 bundle 在浏览器中验证（client-wasm），或用 Rust 验证器本地验证。host 只是*可用性*依赖，而非*正确性*依赖。这一阶段性姿态是 RFP-03 明文允许的——RFP 仅要求链上 STARK 验证器 "eventually"（最终）到位。

路线图：**Phase 2** —— G-STARK 验证器合约上 Starknet（`cairo_verifier` 方向）；**Phase 3** —— 独立 prover 服务，届时完全移除 host attestation。设计细节见 [DUAL_PROOF_PROTOCOL.md](DUAL_PROOF_PROTOCOL.md)、[DAPV_SOUNDNESS.md](DAPV_SOUNDNESS.md)。

## 快速开始

前置要求：Rust `nightly-2026-04-15`（rust-toolchain.toml 已锁定）、[Scarb](https://docs.swmansion.com/scarb/) + snforge（Cairo/Starknet 2.11）、Node.js + pnpm、wasm-pack。

```bash
# 1. Rust 工作区（AIR 栈 + 协议 crate + 游戏服务器）
cargo test --workspace

# 2. Cairo 合约
cd poker_contracts && scarb build && snforge test && cd ..

# 3. 浏览器密码学/验证 WASM
wasm-pack build client-wasm --target web

# 4. 本地 devnet 部署 Token/Vault/Settlement
./poker_contracts/local_deploy.sh

# 5. 游戏服务器（先复制 texas/.env.example 为 texas/.env）
cargo run -p texas

# 6. 网页客户端
cd client && pnpm install && pnpm dev

# 7.（可选）G 层 STARK 证明演示——独立工具链，见 proving-tool/README.md
cd proving-tool && ./prove-hand.sh
```

服务器未配置 `STARKNET_RPC_URL` 时以 Starknet dev 模式启动（链上校验自动放行，便于本地对局）。

## 部署

### Sepolia 测试网

```bash
cd poker_contracts
export SNCAST_ACCOUNT=... SNCAST_URL=... OWNER=... PROVER=... INITIAL_SUPPLY=...
./deploy_sepolia.sh        # declare + deploy Token、Vault、Settlement、DualSettlement
```

细节与地址登记见 [poker_contracts/SEPOLIA.md](poker_contracts/SEPOLIA.md)。部署完成后，将地址与 class hash 回填到 [strk20.json](strk20.json)。

### 主网（黑客松硬性要求）

需在 Starknet 主网完成至少一笔真实 STRK20 交易。最小路径是经 `PokerVault` 的存入 + 提取（在尚未部署 vault 时，直接 STRK20 转账亦可）。交易哈希登记在 `strk20.json → transactions`。

### 配置与密钥安全

所有配置走环境变量；复制 `texas/.env.example` 为 `texas/.env`。私钥与部署者 seed 绝不入库。部署者凭据从 `SNCAST_ACCOUNT` / `.env.dev`（已 git-ignore）读取。

## RFP-03 对齐

逐条要求映射见 [docs/RFP03_ALIGNMENT.md](docs/RFP03_ALIGNMENT.md)。

| RFP-03 要求 | 本仓库对应 |
|---|---|
| 心灵扑克：无可信发牌 | `poker_protocol` ElGamal + 联合洗牌 + sigma 证明，Lean 验证的 V3 重构 |
| Dealer 每条街的 STARK 证明义务 | Stwo circle-STARK 栈（`src/`、`hand-bench`、`proving-tool`）；Phase 1 主机验证、Phase 2 链上 |
| STRK20 经隐私池作筹码 | `PokerVault` 1:1 存取，`PokerVaultAnonymizer` 私密买入 + paymaster 中继 |
| 底牌私有；牌局历史公开 | 加密发牌；链上结算仅对结果提交 Poseidon 承诺 |
| 引擎可离链 | 对局循环在 `texas/` 离链；结算上链 |

## 形式化验证

[poker_protocol_lean](poker_protocol_lean) 用 Lean 4 + Mathlib 形式化重构协议。亮点：机器检查的反例证明重构 V2 泄漏被移除的牌槽；修复后的 V3 带有已被证明的来源、完备性与健全性定理（[SECURITY_RECONSTRUCTION.md](poker_protocol_lean/SECURITY_RECONSTRUCTION.md)）。

## 文档

- [DUAL_PROOF_PROTOCOL.md](DUAL_PROOF_PROTOCOL.md) —— 双证明结算规范（v2.3，现行）
- [TEXAS_TAGGED_AIR.md](TEXAS_TAGGED_AIR.md) —— 直接状态转移 AIR 路径
- [TRUST_MODEL_NO_TRANSACTION_REPLAY.md](TRUST_MODEL_NO_TRANSACTION_REPLAY.md) —— 无交易重放信任边界
- [docs/plan-d-*.md](docs/) —— STARK 曲线迁移计划与实测基线
- [docs/STATUS.md](docs/STATUS.md) —— 历史技术状态叙述（过时章节已标注）
- [CONTRIBUTING.md](CONTRIBUTING.md) · [执行计划](docs/EXECUTION_PLAN.md)

## 路线图

1. **Phase 2** —— 链上 G-STARK 验证器（Cairo `cairo_verifier`）接入 `PokerDualSettlement`。
2. **Phase 3** —— 独立 prover 服务；移除 host attestation。
3. 真实 `hand_verify.cairo` 电路（替换 `proving-tool` 中的 bench 占位程序）。
4. 全套合约主网部署。

## 许可证

源码可见许可 **[BUSL-1.1](LICENSE)**：非商业用途、研究、教育与黑客松评审免费；商业使用需另行授权。2029-12-31 自动转为 Apache-2.0。第三方组件（StarkWare proving 栈、OpenZeppelin、Rust 生态 crate）保留其自身宽松许可——见许可证文本中的第三方声明。
