# RistrettoAirV2 协议层性能基准与优化点

测量时间：2026-08（`refractor` 分支）。运行命令：

```bash
cargo +nightly run --release -p poker-hand-bench -- full-hand-v2
cargo +nightly test --release -p poker_texas_air --lib ristretto_shuffle_air -- --nocapture --test-threads=1
cargo +nightly test --release -p poker_texas_air --lib ristretto_reconstruction_v2_air -- --nocapture --test-threads=1
```

## 1. 整手牌基准（`full-hand-v2`，4 名玩家，release）

一次完整的 mental-poker 手牌：密钥注册（ownership 证明 ×4）、聚合密钥下的规范基牌组、
4 次连续 Bayer–Groth V2 洗牌、发 8 张底牌 + 5 张公共牌、一次中途 `fold_with_proof`
（折叠玩家密钥层从加密牌组与聚合密钥中移除）、下注线（3 个活动玩家跟注）、摊牌
（11 张牌 × 3 名活动玩家 = 33 个 reveal token，明文 = c2 − Σtokens）、结算。

| 阶段 | prove（客户端） | verify（服务端） | 备注 |
| --- | --- | --- | --- |
| ownership ×4 | 585 ms（冷启动） | 21 ms | 含首次 Flock STARK setup；真实客户端启动时预热后热路径 ~10 ms/个 |
| flock 预热 | 7 ms | — | `preheat_flock_setup()`，其后所有阶段热路径 |
| 洗牌 ×4 | 133 ms | 75 ms | BG 论证原生毫秒级；Flock 热 |
| fold_with_proof ×1 | 14 ms | 8.8 ms | leave DLEQ（52 卡批量） |
| 下注线 | 292 ns（原生） | — | 金额转移为纯状态；STARK 化见 hand-bench 默认模式 |
| reveal token（批量化，3 证明） | 31.9 ms | 13.2 ms（并行） | P0 落地前为 33 证明 329 ms/187 ms |
| 解密 + 结算 | 855 µs（原生） | — | |
| **合计** | **178.5 ms** | **96.8 ms** | 客户端证明总量 5.49 MB |

结论：P0/P1/P3 落地后，单手协议层 prove 1.09 s → 178.5 ms（5.9×）、
verify 297 → 96.8 ms（2.9×）、证明量 13.5 → 5.49 MB（−59%）。剩余体积主体
是 4 个洗牌信封（~3.3 MB）与各证明的 Flock 固定成本（~136 KB/链语句）。

## 2. 单组件基准（release，单线程）

| 路由 | prove | verify | 请求+归档 | 构成 |
| --- | --- | --- | --- | --- |
| V2 洗牌（52 卡） | 36–620 ms | 17 ms | 830 KB | BG wire 5.5 KB + 6 条 Flock 链 ~818 KB |
| V2 重构（ZR3N） | 17 s | 7.2 s | 25 KB + 7.3 MB | 状态绑定 lookup STARK ~5.7 MB + 2 个 Flock ~1.6 MB |
| 重构（旧 ZR3A 路径，对照） | ~1365 s（历史记录） | ~118 s | ~1.27 GB | 416 次标量乘 FpProgram 展开 |
| pk_ownership | ~10 ms（热） | ~5 ms | ~270 KB | 2 条 Flock 链 |
| reveal_token | ~10 ms（热） | ~6 ms | ~270 KB | 2 条 Flock 链 |
| remask / leave（52 卡） | ~15 ms | ~9 ms | ~1.9 MB | 2 条 Flock 链 + 52×32 B wire |

## 3. 性能优化点（按收益排序）

### P0 — 每证明 Flock STARK 体积（✅ 批量化部分已落地，参数部分待做）

13.5 MB 中约 10 MB 是 37 个独立 Flock 归档（每 2 条链语句 ~270 KB；每条链语句携带
独立 Ligerito 实例，固定 ~136 KB）。方向：

1. ~~**reveal token 按玩家批量化**~~ **已落地**（`prove_reveal_tokens_batched`）：
   每玩家一个批量 DLEQ（per-card 承诺 + 单挑战 + 单响应），实测 reveal 阶段
   prove 337→31.9 ms、verify 181→13.2 ms（并行）、整手证明量 −8 MB；
2. **跨证明批处理**：同一玩家一次提交（ownership + shuffle）的 transcript 链语句
   合并进一个 Flock 批证明（`prove_statements` 支持多语句且段间并行）——但
   Ligerito 每实例固定成本仍在，收益主要在语句复用；
3. **vendored flock 参数调优**（log_blowup / rate / 压缩），需在 third_party 内做，
   属独立工作项（剩余 ~5.5 MB 的主要份额）。

### P1 — 冷启动 Flock setup（✅ 已落地）

ownership 阶段 585 ms 几乎全部是第一个 Flock STARK 的 setup。已提供
`blake3_flock::preheat_flock_setup()`（构造一次哑链证明，实测预热本身 7 ms）；
客户端进程启动时调用即可把首手延迟拉平到热路径。

### P2 — 重构路径的状态绑定 lookup STARK（7.3 MB 归档 / ~7 s verify 的主体）

`ZR3N` 归档中 Blake2b lookup 绑定 STARK ~5.7 MB。它是 L1 锚定件（保持 STARK 合理），
但可优化：

1. openings 序列化面（52×2 座位密文 ×2 个 opening）全部进入 Blake2b 语句——按位压缩
   或只哈希承诺根（配合 opening 树）可缩语句数；
2. verify 侧 7.2 s 中含 binding lookup verify——检查其语句分段是否已并行（flock 路径
   已并行，lookup 栈未确认）。

### P3 — 服务端验证并行度（✅ 已落地）

reveal 阶段已按证明 rayon 并行（181→13.2 ms）。整手 verify 297→96.8 ms，剩余
长杆是 4 个洗牌的串行验证（75 ms）——V2 洗牌验证内部的 BG 六组点方程互相独立，
可再 3× 并行 MSM（待做，预计整手 verify 降到 ~60 ms）。

### P4 — 洗牌信封 830 KB（×4 = 3.3 MB/手）

同 P0-3：BG 论证仅 5.5 KB，其余是 6 条 Flock 链。语句数已最小化（1 init + 5 挑战），
收益在 flock 参数或跨洗牌复用（同一玩家连续动作可共享 init 链）。

### P5 — 下注/结算的 STARK 成本（tagged AIR 路径）

本基准中下注是原生状态（292 ns）。完整 host-zero 下注走 canonical tagged AIR
（hand-bench 默认模式：整手 lifecycle+hand 批 prove 数秒级）。两层的证明组合与
递归聚合是 Path A 的范围（见 `HOST_ZERO_RISTRETTO_AIR.md` 的 Path A 章节）。

### 已否决/已完成方向（勿重复）

- slot-OR / cross-key / 牌组转移的 FpProgram 展开：已由 V2 原生 sigma + Flock 替代
  （416 次标量乘 → 0）；
- 更小的 FRI fold_step、更小 Ristretto 域：历史上已验证为负收益；
- π 直接入 AIR：透明 STARK 泄漏置换，已否决（BG HVZK 保 π）。

## 4. 路径 A 递归成本（在电路内证明 admission 决策）

| 组件 | 电路内义务 | 估算 |
| --- | --- | --- |
| 洗牌 BG 点方程 | ~7 组 52-way MSM 等式 | ✅ 已落地：`ristretto_scalar_mul_air` 专用 fixed-window 梯子 AIR（N=52 批量 prove 19.0s / verify 1.7s，边际 ~0.34s/次；对比 FpProgram 压缩行路线 172.3s / 8.8s，**prove 9.1× / verify 5.2×**） |
| BG 标量侧调度 | 幂表 + 期望乘积（mod l） | ✅ 已落地：`ristretto_scalar_program_air`（prove 2.4s / verify 1.65s / 17.9MB，宽行 FRI 成本是后续压缩项） |
| pk_ownership / reveal_token | 各 2 条点方程 | 各 2 次标量乘 |
| remask / leave / fold | 53 条点方程 | ~106 次标量乘（52 卡批量 DLEQ） |
| transcript 链 | BLAKE3 二元域约束 | 即 Flock 已覆盖的语句 |
| 状态绑定 / openings | Blake2b lookup | 已是 M31 栈 STARK |

结论：每手牌的完整递归义务 ≈ 500–700 次电路内标量乘 + 哈希约束 + 标量侧调度
（✅ 已有 STARK：mod l program AIR）。点侧的专用 fixed-window scalar-mul AIR
也已落地（✅ `ristretto_scalar_mul_air`）：trace 每行是一次射影 Edwards 加法
（26 个 pinned 值 + 8 个商 witness + 8 条加减链 + `2·Z1` 倍乘链 + `2d·T1`
常数乘 + 7 个一般乘法），基点只 decode 一次、终值只 encode 一次（各一条
fixed-shape Fp program 批行）；行内值经预计算 scope 列钉死到验证者重建的确定
性 schedule，pinned 肢无需电路内 range/canonicity（重建即担保），只有商肢
（11-bit 单肢）与乘法 carry（17-bit 对）进共享 LogUp 表。同输入实测
（ristretto_perf）：N=1 prove 1.8s / verify 0.58s；N=8 prove 3.5s；N=52 prove
19.0s / verify 1.7s / 证明 6.24MB（FpProgram 压缩行路线 172.3s / 8.8s /
6.54MB）。剩余前置项只有递归聚合器的折叠摊销；标量侧调度的 17.9MB 与梯子
路线的 ~6.2MB 宽行证明均需列打包/批摊销优化后才适合并入 ZRS2 信封。
