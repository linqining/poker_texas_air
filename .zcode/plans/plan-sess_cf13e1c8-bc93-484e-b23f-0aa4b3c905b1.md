## 目标
继续完成 Rust → Starknet Sepolia 的轻量结算接续层：off-chain 先完整验证 `OuterAggregateBundle`，再生成 Cairo `register_aggregate` / `settle_hand` 的严格 calldata；链上只校验 aggregate commitment、结算 commitment、零和和 replay protection。

## 实施步骤

### 1. 修正 Cairo commitment ABI 的不可逆编码问题
- 将 `PokerSettlement.register_aggregate` 的 `aggregate_digest` 从单个 `felt252` 改为两个 felt（建议 `(felt252, felt252)`，按 32 字节 digest 的高/低 16 字节或高/低 128-bit canonical chunks 编码）。
- 将 aggregate 存储 key 同样改为双 felt key，避免 256-bit Blake2b digest 被截断、取模或拒绝。
- 保持 `settlement_digest` 为单个 `felt252`，因为它本身是 Poseidon 输出。
- 同步更新 `strk20.json`、`SEPOLIA.md` 和部署后的调用说明。
- 为 digest split/merge 写 Rust 单元测试：round-trip、长度/非 canonical 输入拒绝、绝不丢失高位。

### 2. 新增 Rust Starknet 适配模块
新增 `src/starknet_settlement.rs`，并在 `src/lib.rs` 导出。该模块只接受已验证/已认证输入，不接受未验证的 `OuterAggregateBundle` 直接生成可信 calldata。

建议公开类型：

- `StarknetFelt`/`Calldata`：使用现有 `starknet_ff::FieldElement`，最终输出 `Vec<FieldElement>`。
- `AggregateRegistrationInput`：
  - `verified: &VerifiedOuterAggregate`
  - `first_hand_id` / `last_hand_id`
  - `pre_state_root` / `post_state_root`
  - 已按 hand 顺序准备好的 settlement commitment 列表
- `SettlementInput`：
  - verified aggregate digest
  - hand id
  - authenticated pre-settlement `TexasPokerTable`
  - canonical validated `SettlementPlan`
  - 可选 rake recipient

模块职责：
- 从 `VerifiedOuterAggregate` 提取 table/hand/state roots和 32 字节 aggregate digest；不信任 bundle 的声明字段。
- 将 32 字节 digest 按固定 big-endian 双 felt 规则编码。
- 从 `SettlementPlan.awards` 和 pre-state seats 计算玩家净变化：
  - `delta = awards[seat] - seat.total_bet()`
  - 使用同一 authenticated snapshot 中的 player address。
- 将 rake 累加到明确的 treasury/rake recipient；如果 rake recipient 与玩家地址相同则合并，保证地址唯一。
- 按 seat index 升序、treasury 最后（合并后重新排序/固定规则）生成 participants。
- 拒绝：空玩家、超过 9 个 participant、空地址、重复地址、u64→i128 溢出、非零和、plan/table 不一致、缺少 rake recipient 但 rake 非零。
- 按 Cairo 既定字段顺序计算 settlement Poseidon commitment：
  `hand_id, player, sign, magnitude, ...`，与 `settlement_hash.cairo` 完全一致。
- 输出严格的 Cairo ABI calldata，而不是 Borsh blob；内部 Borsh/digest 契约不变。

### 3. 生成两个明确的 calldata DTO
- `RegisterAggregateCalldata`：包含 selector/name、双 felt aggregate digest、hand range、四个 state-root felts、settlement root 数组及长度。
- `SettleHandCalldata`：包含双 felt aggregate digest、hand id、players 数组及长度、signed delta 的 Cairo `i128` ABI 编码、并暴露计算出的 settlement digest。
- 提供 `to_felts()` 和严格 `from_felts()` round-trip；拒绝 trailing felts、错误长度、超界 signed integer、非法地址。
- 暂不加入真实 RPC/签名发送，因为仓库没有 `starknet-rs` client、账户签名器或用户钱包凭据；先交付可审计的 calldata 生成层。

### 4. 与现有证明流程衔接
- 在 `outer_precompile.rs` 之外保持 aggregate 核心验证不变；适配模块只消费 `VerifiedOuterAggregate`。
- settlement builder 要求调用方显式提供 canonical `SettlementPlan` 和对应 pre-state table，因为 aggregate receipt 本身没有玩家地址、`total_bet` 或 rake recipient，不能自动推导 payouts。
- 在文档中明确：off-chain 必须先执行 `verify_outer_aggregate`，必要时再 `verify_against_anchor`，然后才能生成 register calldata。

### 5. 测试
新增 Rust 测试覆盖：
- Blake2b aggregate digest 双 felt split/merge golden vectors；高位非零不可丢失。
- settlement delta：奖励减下注、rake treasury、地址合并、零和、重复/空地址/溢出负例。
- Rust Poseidon/字段编码与 Cairo `settlement_hash.cairo` 的固定向量一致。
- register/settle calldata exact felt layout、数组长度、round-trip、trailing felt 拒绝。
- 未验证 bundle 不允许直接构造可信 registration input。
- 运行 `cargo fmt --check`、目标模块测试和现有 workspace 测试。

### 6. 文档与配置
- 更新 `poker_contracts/SEPOLIA.md`，补充 Rust calldata builder 的调用顺序和双 felt digest ABI。
- 更新 `strk20.json` ABI/schema 说明；地址继续保持空值，直到用户提供 Sepolia RPC、账户和授权后再部署。
- 不修改或回滚工作区中与本次接入无关的既有 Rust 修改。

## 验收标准
- Cairo 合约和 Rust 适配层均可编译。
- aggregate digest 全宽无损编码。
- settlement calldata 的顺序、符号、长度和 Poseidon commitment 与 Cairo 实现一致。
- 恶意输入 fail closed。
- 本地测试通过；真实 Sepolia 发送作为后续需要凭据的步骤，不伪造交易结果。