# Plan D 性能基线（release）

> 2026-09-05 重新测定。曲线切换（blst/BLS12-381 → 纯 Rust Stark 曲线，Plan D
> 完成）使旧基线全部失效；本文件为切换后的**新基线**，作为 #24 性能 followups
> 与 #23 递归协议成本对照的锚点。
>
> 测试：`poker-protocol-proofs/tests/plan_d_perf.rs`（7 项）
> 运行：`cargo test -p poker-protocol-proofs --features borsh --release
> --test plan_d_perf -- --ignored --nocapture`
> 环境：macOS arm64（Apple Silicon），pinned nightly，`--release`。

| # | 项 | 基线 | 说明 |
|---|---|---|---|
| 1 | 标量乘（double-and-add，251 bit） | **19 µs/op**（400 次共 7,860 µs） | 断言阈值 < 20ms/op（游戏可用性） |
| 2 | 52 项 vartime_multiscalar_mul | **中位 3,417 µs** | MSM 基线（#24 "MSM 平衡树"项的对照） |
| 3 | ZKShuffleProof 52 卡 prove / verify | **43,829 µs / 23,276 µs** | 单次洗牌证明全周期 ~67ms（release） |
| 4 | 52 卡批量 ElGamal 加密（含 52 标量乘） | **6,150 µs** | 发牌加密基线 |
| 5 | hash_to_scalar（Poseidon） | **8 µs/op** | 挑战派生原语 |
| 6 | hash_to_curve（try-and-increment + sqrt） | **118 µs/op** | 明文牌域派生原语 |
| 7 | 1540 项 host 折叠模拟（9 人桌全残差） | **2,048 µs** | 链上 EC_OP 版本按 builtin 单步估算——host 模拟即 2ms 量级，EC_OP 只会更快 |

## 读数要点（#24 决策输入）

- **9 人桌一手全残差 host 折叠 ~2ms**：每手折叠成本可忽略，"验证成本 O(N)"
  的压力在链上 gas 而非 host 算力——#24 各优化项的"净收益"门槛应以链上
  指标为准，host 端无迫切优化点。
- **单次洗牌 prove+verify ~67ms（release）**：真人节奏完全可接受；debug 模式
  慢数千倍（既有现象，测试慢点在客户端证明生成，非回归）。
- **vartime MSM 52 项 3.4ms**：平衡树改造（#24 第 2 项）需在 N=2..52 矩阵上
  证明净收益才值得动 wire format——当前 3.4ms 不构成瓶颈。
- **专用标量乘 AIR**（#24 第 1 项）：host 标量乘 19µs/op，进入 AIR 的成本
  远高于此——维持"oracle 保留、暂不实施"。

## 对照

Plan D §6c P3 的首版基线（Stark 后端交付时）与本表同源同方法；本表为
blst 移除后的复测确认值。
