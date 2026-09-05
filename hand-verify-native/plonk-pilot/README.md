# plonk-pilot — Stark 曲线 EC 的 PLONK 电路性能报告

> 2026-09-06 实测。gnark v0.14，PLONK 后端 BLS12-381，Stark 曲线经 gnark
> emulated arithmetic（官方 `emparams.STARKCurveFp/Fr` + `GetStarkCurveParams`）
> 在电路内仿真。测试 SRS（`unsafekzg`），非生产仪式——仅用于性能度量。

## 电路与结果

| 电路 | 约束数 | prove | verify | 备注 |
|---|---|---|---|---|
| felt252 模乘 ×1 | 1,624 | 40–63ms | 2ms | r = a·b mod P（2×126-bit limb 仿真）|
| felt252 模乘 ×8 | 8,984 | 212ms | 2ms | 线性 |
| felt252 模乘 ×64 | 62,344 | 800ms | 2ms | 线性，~776 约束/乘 |
| **Stark 曲线标量乘 ×1** | **289,942** | **5.9s** | 2ms | 完整 251-bit double-and-add 调度 |
| 篡改负例（错 Q） | — | **拒绝** | — | 证明生成即失败 ✓ |

## 关键结论

1. **一次标量乘 = 29 万约束、5.9s**。9 人满手（896 次标量乘）外推 ≈ **2.6 亿约束 / ~90 分钟 prove**——全量形态②在通用 PLONK 仿真层不可行，与 Cairo EC_OP 路线（296 步/次）和形态①（host 0.1s/手）的差距为 **2–3 个数量级**。
2. **验证端极强**：2ms 恒定、证明可锚定（BLS12-381 配对，Garaga 可搬到 Starknet、EIP-2537 可上 L1）。这是 SNARK 路线的核心卖点。
3. **降维可用**：单条语句的审计证明（1 次标量乘 ≈ 29 万约束 ≈ 6s prove）完全可行——契合"证明降级为异步审计工件"的 v1 架构。
4. 减约束的下一步（如需）：circuit-level Horner 折叠（单条多标量乘终检）、gnark `algopts` 批量窗口、或改用原生域 PLONK 框架（电路域 = felt252 的专用曲线/后端，免除仿真层——当前 gnark 尚无，属自研）。

## 运行

```bash
cd hand-verify-native/plonk-pilot
go run . scalar   # 标量乘电路：约束数/prove/verify
go run . tamper   # 负例
go run . mulbench # 模乘规模扫描
```

依赖：Go ≥ 1.24；gnark v0.14（BLS12-381 PLONK 后端）。独立 Go module，
不进入 Rust workspace 构图。
