# Plan D P3：测试用例与性能指标（交付物，不含实施）

> 按执行计划：P3（Nova folding spike / 电路重执行 prototype）不实施，
> 交付测试用例 + 性能指标。所有基线数字为 **release 模式实测**
> （Apple M-series, aarch64；`cargo test -p poker-protocol-proofs --release
> --test plan_d_perf -- --ignored --nocapture`）。

## 1. 实测基线（poker-protocol-core::stark_curve，STARK 曲线）

| 指标 | 实测值 | 说明 |
|---|---|---|
| 标量乘（double-and-add, 251 bit） | **24 µs/op** | naive 实现；窗口法（4-bit window）预期再降 30–40% |
| hash_to_scalar（Poseidon 归约） | **13 µs/op** | 31B 块 + poseidon_hash_many + mod n |
| hash_to_curve（try-and-increment + sqrt） | **113 µs/op** | 均值含 sqrt 成功路径 |
| 52 卡批量 ElGamal 加密 | **5.1 ms** | 52 次标量乘 + 点加 |
| 52 项 vartime_multiscalar_mul | **4.4 ms** | naive 逐项乘-和；Strauss/Joint window 是后续优化 |
| ZKShuffleProof 52 卡 prove | **53 ms** | 自定义三层 Schnorr（direct-Sigma） |
| ZKShuffleProof 52 卡 verify | **29 ms** | host 热路径 |
| 1540 项 host 折叠模拟（9 人桌全残差批次） | **2.6 ms** | P 层 ρ-折叠的 host 模拟 |

**结论**：direct-Sigma 热路径（实时对局）在 24 µs/标量乘下毫秒级完成，
证明 Plan D"STARK 不进热路径、Sigma 链下直验"的架构成立；host 折叠
1540 项 2.6 ms，说明链上 EC_OP 折叠的瓶颈在链上步数而非 host 计算。

## 2. Nova folding spike：成本模型与测试用例（不实施）

**结构契合点（已论证）**：洗牌级联 = 固定函数 F 的顺序应用
（层 i = 置换 + 重随机化 + 证明），恰好是 Nova IVC 的标准形状——
每层一个 fold step，整手一个累积实例。

**每手 fold step 数**（输入到最终 deck）：
- 洗牌层：N 层（玩家数）
- 每层的电路语句（route B 电路重执行版）：
  - 52 张重加密 = 52 × (2 次点乘) = **104 次原生点乘**
  - 置换矩阵双射检查 = 52² ≈ **2704 boolean 约束**
  - Poseidon transcript 域 ≈ 每层 5–10 次 poseidon

**Nova fold step 成本**（文献量级，非实测）：
- 折叠本身：2 次 MSM（规模 = 电路 witness 宽度）+ 2 次哈希
- EC 语句经 CycleFold（curve cycle）或 Cairo 原生曲线（STARK 曲线
  场景无 cycle 可用——这是 folding 落地 Starknet 的主要工程风险）

**切换判据（来自 Plan D §6）**：每手 EC_OP 折叠项 × syscall 成本
涨出单笔 tx 预算，或锦标赛跨手聚合需求出现。以 §1 实测推算：
9 人桌 1540 项、每项 1 次 EC_OP ≈ 1540 EC_OP steps——当前 Starknet
单步 builtin 成本下单笔 tx 可承载；**触发点未到，保持观察**。

**测试用例（spike 时启用，当前 `#[ignore]` 于
`poker-protocol-proofs/tests/stark_curve_regression.rs` 的复合语句
可直接复用为 fold step 的电路语句源）**：
1. `fold_step_statement_matches_sigma_verify`：同一层语句的电路验证
   结果与 direct-Sigma 验证一致；
2. `fold_accumulator_two_layers`：两层折叠后 verifier 接受、跨手
   hand_binding 域注入拒绝；
3. `fold_soundness_non_bijective_permutation_rejected`：置换矩阵
   缺一行/列的 witness 被电路拒绝（route B 双射断言）。

## 3. 电路重执行 prototype（route B）：成本模型（不实施）

**电路内容**（每洗牌层）：
| 项 | 数量 | 依据 |
|---|---|---|
| 重算 re-encryption | 104 次点乘 | 52 卡 × (c1: g·r, c2: pk·r) |
| 双射检查 | ~2704 boolean | 52×52 置换矩阵行列和=1 |
| Poseidon transcript | ~10 次 | Fiat-Shamir 域 |

**Cairo 侧估算**（STARK 曲线 EC_OP 原生）：104 点乘 × (≈10
builtin steps/乘) + 2704 boolean（≈1 step/约束）≈ **每层 ~4k steps，
9 层整手 ≈ 40k steps**；STWO 路线（QM31 limb 域）需另行实测，
位宽减半预期同量级。

**对比基准**：现 direct-Sigma verify 29 ms（host）；电路重执行把
soundness 从自定义 Sigma 归约到 STARK，代价是每手一次 ~40k 步证明
（异步、不挡牌局）——这正是 Plan D 双轨架构的量化依据。

**测试用例（已落地为可执行测试，route B 实施时直接复用）**：
`poker-protocol-proofs/tests/stark_curve_regression.rs`
- `zk_shuffle_*_on_stark_curve`（4 个）：三层 Schnorr 语句的诚实/
  篡改/跨 pk/恒等置换——route B 电路必须给出一致判定；
- `versioned_bayer_groth_v2_*`：BG V2 语句 + 明文置换关系；
- `composite_two_layer_versioned_shuffle_on_stark_curve`：两层组合
  语句（fold 链的输入形态）；
- `perf_*`（`plan_d_perf.rs`，6 个）：上表全部基线的可复现测量。

## 3b. hand_batch_stark 合约层实测 + 主网费用校准 + gas 压缩（2026-08-30 终版）

### 主网活体校准（公共 RPC 实抓，2026-08-30）

| 数据 | 值 | 来源 |
|---|---|---|
| l2_gas_price | ≈ 3.63×10¹⁰ fri/单位 ≈ **3.63×10⁻⁸ STRK/单位** | 主网区块 14056911 |
| 普通 invoke 实盘费 | **0.17–0.40 STRK/笔**（l2_gas ≈ 6M） | 三笔主网回执 |
| 校准验证 | 6.05M l2_gas × 价格 + data ≈ 回执 actual_fee（±5%，块价波动） | tx 0x6720…882 |

### 压缩前（字节流 transcript）与成本分解

| N | l2_gas | 主网折算 |
|---|---|---|
| 2 | 956.6M | ~35 STRK |
| 4 | 1,868.9M | ~68 STRK |
| 9（外推，线性 R²≈1） | 4.15×10⁹ | **~150 STRK —— 不可接受** |

微基准定位：EC_OP `add_mul` 单次仅 **0.08M**、poseidon 置换 <0.04M、
`EcPoint::new` 0.04M——**~95% 的开销在逐字节除法序列化
（u256_to_be_bytes）与纯 Cairo keccak**，密码学本身近乎免费。

### gas 压缩（已完成）：transcript 全面 felt 直通

challenge/rho 改为 felt 列表直接进 Poseidon（无字节转换、无 keccak、
无需 32B 奇偶压缩——完整仿射坐标天然单射）：

- `c = poseidon([proto_label_felt, hand_binding, Gx, Gy, pkx, pky, Rx, Ry]) mod n`
- `rho = poseidon([v1_label_felt, hand_binding, n_terms, (coeff, x, y)*]) mod n`

规范实现三端共享：core `stark_curve::dapv_endorsement_challenge /
dapv_hand_rho`（texas 与 wasm 调用），Cairo `hand_batch_stark.cairo`
逐项复刻。标签 = ASCII 直转 felt（运行时零哈希）。

### 压缩后实测

| N | l2_gas | 降幅 | 主网折算 |
|---|---|---|---|
| 2 | **1.60M** | 598× | ~0.058 STRK |
| 4 | **3.12M** | 599× | ~0.113 STRK |
| 线性模型 | 0.08M + 0.76M×N | | |
| **9（外推）** | **≈ 6.9M** | ~600× | **≈ 0.25 STRK —— 与一笔普通 invoke 同量级** |

**结论：无需 STARK、无需分片，当前 EC_OP 折叠架构在满桌规模可负担。**
剩余可压空间（u256_mul_mod_n 的 λ 计算 ≈ 0.2M×27 ≈ 5.4M，占压缩后
成本大头）预计还可再省一半，留待实盘数据驱动决定。

snforge 回归：hand_batch_stark 12/12 绿（honest N=2/N=4、tamper×3、
跨手重放、畸形、微基准×3、EC 基准×2）；全套 48/48 绿（200M 步；
5 个 secp 变体旧用例为既有步数预算项）。host parity 5/5、e2e 2/2 绿。

### A/B 优化落地（Horner 折叠，2026-08-30 终版）

A（Horner）+ B（±1 特判，被 A 结构性吸收）已实施：

- **方程内点**：`eq_i = s·G − c·pk − R`，负项用**点取反**表达
  （−c·pk = c·(−pk)，域级 −y 即群逆——规避 felt 域取反 ≠ −c mod n
  的陷阱）；每方程一次 `EcState` 批量累加（3 EC_OP）。
- **Horner 折叠**：`L = ρ·(ρ·(…(ρ·eq_N + eq_{N−1})…) + eq_1)`，每方程
  1 add_mul(ρ, acc) + 1 add——**无 ρ 幂表、无任何 mod-n 乘法**（B 的
  ±1 特判随 λ 计算整体消失）。
- **原始 felt 标量**：合约侧 c/ρ 用 poseidon 原始输出（< P）直接做
  EC 标量——群阶使 m 与 m mod n 同结果；host 侧 mint 仍用归约 c 做
  Z_n 算术（s = w + c·sk），两侧数学等价（parity 测试验证）。
- ρ transcript 输入缩为每方程 5 词 (s, pk, R)——wire 载荷格式不变。

| N | 优化前（felt 直通版） | 优化后（Horner） | 本轮降幅 |
|---|---|---|---|
| 2 | 1.60M | **0.44M** | 3.6× |
| 4 | 3.12M | **0.84M** | 3.7× |
| 线性模型 | 0.08M + 0.76M×N | **0.04M + 0.20M×N** | |
| **9（外推）** | ≈ 6.9M ≈ 0.25 STRK | **≈ 1.84M ≈ 0.067 STRK** | **3.7×** |

**三级累计：4.15×10⁹ → 1.84×10⁶（2,250×），满桌结算 ≈ 0.067 STRK
（主网现价），约为普通 invoke 实盘费（0.17–0.40 STRK）的 1/4。**
剩余构成已贴近 EC_OP 地板（27 内层 + 9 Horner ≈ 45 次 × 0.08M ≈
3.6M 中占 36 EC 次 ≈ 2.9M）；进一步压缩只剩 P3 STARK 常数化一条路，
费用维度已无必要。

实现备注：host↔合约 parity 由向量测试钉死（本轮捕获一个真实 sign
bug：合约侧 pk 项漏点取反，被 honest-vector 测试立即暴露）；host
`host_fold_check`/`OwnershipEquation` 与 Cairo `fold_and_check`/
`EquationWords` 同构，`parse_batch_terms` 仍是跨端一致性入口。

回归：snforge 48/48（200M 步）、host parity 5/5、e2e 2/2、协议栈
189 测试、client-wasm wasm32、client tsc 全绿。

### 满手全语句批次实测（可折叠 reveal 纪元，2026-08-30 终版）

语句计数来自真实 full_hand 流量（2 人：4 preflop + 10 community + 4
showdown = 18 个 reveal token；9 人：144 + 45 + 18 = 207 个）。方程在
StarkCurve 上以可折叠纪元铸造（felt 直通挑战
`dapv_reveal_challenge`；生产 reveal 证明用 FiatShamir(SHA3)，Cairo 只有
legacy Keccak syscall 无法逐字节重放——迁移至本纪元是三端同构的既有
模式，gas 数字即为迁移后形态）。ρ 输入压缩为每方程 (kind, s, c)——
c 由链上从全部公开输入重算（poseidon 抗碰撞），已整体绑定语句。

| 批次 | 语句 | 方程 | l2_gas | 主网折算 |
|---|---|---|---|---|
| 2 人满手（2 认可 + 18 reveal） | 20 | 38 | **7.80M** | **≈ 0.28 STRK** |
| 9 人满手（9 认可 + 207 reveal） | 216 | 423 | **86.64M** | **≈ 3.15 STRK** |
| 线性模型 | — | — | **≈ 10k + 0.205M × 方程** | — |
| 对照：9 人 ownership-only | 9 | 9 | 1.84M | 0.067 STRK |

判读：**2 人桌满手 ≈ 1–2 笔普通 invoke（0.17–0.40 STRK），完全可负担；
9 人桌满手 ≈ 3.15 STRK ≈ 8–18 笔 invoke（人均 0.35 STRK/手）**。
reveal 语句占比 >97%——若多桌高频运营需压至此以下，即是 P3 STARK
常数化的触发线（423 方程 → 1 个证明）；否则维持现状即可。

回归：hand_batch_stark 16/16（含满手 honest×2 + tampered×2）、snforge
全套 52/52、host parity 5/5、full_hand 2/2、e2e 2/2、leave_exclusion 5/5、
core 35。

## 4. 复现命令### A/B 优化落地（Horner 折叠，2026-08-30 终版）

A（Horner）+ B（±1 特判，被 A 结构性吸收）已实施：

- **方程内点**：`eq_i = s·G − c·pk − R`，负项用**点取反**表达
  （−c·pk = c·(−pk)，域级 −y 即群逆——规避 felt 域取反 ≠ −c mod n
  的陷阱）；每方程一次 `EcState` 批量累加（3 EC_OP）。
- **Horner 折叠**：`L = ρ·(ρ·(…(ρ·eq_N + eq_{N−1})…) + eq_1)`，每方程
  1 add_mul(ρ, acc) + 1 add——**无 ρ 幂表、无任何 mod-n 乘法**（B 的
  ±1 特判随 λ 计算整体消失）。
- **原始 felt 标量**：合约侧 c/ρ 用 poseidon 原始输出（< P）直接做
  EC 标量——群阶使 m 与 m mod n 同结果；host 侧 mint 仍用归约 c 做
  Z_n 算术（s = w + c·sk），两侧数学等价（parity 测试验证）。
- ρ transcript 输入缩为每方程 5 词 (s, pk, R)——wire 载荷格式不变。

| N | 优化前（felt 直通版） | 优化后（Horner） | 本轮降幅 |
|---|---|---|---|
| 2 | 1.60M | **0.44M** | 3.6× |
| 4 | 3.12M | **0.84M** | 3.7× |
| 线性模型 | 0.08M + 0.76M×N | **0.04M + 0.20M×N** | |
| **9（外推）** | ≈ 6.9M ≈ 0.25 STRK | **≈ 1.84M ≈ 0.067 STRK** | **3.7×** |

**三级累计：4.15×10⁹ → 1.84×10⁶（2,250×），满桌结算 ≈ 0.067 STRK
（主网现价），约为普通 invoke 实盘费（0.17–0.40 STRK）的 1/4。**
剩余构成已贴近 EC_OP 地板（27 内层 + 9 Horner ≈ 45 次 × 0.08M ≈
3.6M 中占 36 EC 次 ≈ 2.9M）；进一步压缩只剩 P3 STARK 常数化一条路，
费用维度已无必要。

实现备注：host↔合约 parity 由向量测试钉死（本轮捕获一个真实 sign
bug：合约侧 pk 项漏点取反，被 honest-vector 测试立即暴露）；host
`host_fold_check`/`OwnershipEquation` 与 Cairo `fold_and_check`/
`EquationWords` 同构，`parse_batch_terms` 仍是跨端一致性入口。

回归：snforge 48/48（200M 步）、host parity 5/5、e2e 2/2、协议栈
189 测试、client-wasm wasm32、client tsc 全绿。

### 满手全语句批次实测（可折叠 reveal 纪元，2026-08-30 终版）

语句计数来自真实 full_hand 流量（2 人：4 preflop + 10 community + 4
showdown = 18 个 reveal token；9 人：144 + 45 + 18 = 207 个）。方程在
StarkCurve 上以可折叠纪元铸造（felt 直通挑战
`dapv_reveal_challenge`；生产 reveal 证明用 FiatShamir(SHA3)，Cairo 只有
legacy Keccak syscall 无法逐字节重放——迁移至本纪元是三端同构的既有
模式，gas 数字即为迁移后形态）。ρ 输入压缩为每方程 (kind, s, c)——
c 由链上从全部公开输入重算（poseidon 抗碰撞），已整体绑定语句。

| 批次 | 语句 | 方程 | l2_gas | 主网折算 |
|---|---|---|---|---|
| 2 人满手（2 认可 + 18 reveal） | 20 | 38 | **7.80M** | **≈ 0.28 STRK** |
| 9 人满手（9 认可 + 207 reveal） | 216 | 423 | **86.64M** | **≈ 3.15 STRK** |
| 线性模型 | — | — | **≈ 10k + 0.205M × 方程** | — |
| 对照：9 人 ownership-only | 9 | 9 | 1.84M | 0.067 STRK |

判读：**2 人桌满手 ≈ 1–2 笔普通 invoke（0.17–0.40 STRK），完全可负担；
9 人桌满手 ≈ 3.15 STRK ≈ 8–18 笔 invoke（人均 0.35 STRK/手）**。
reveal 语句占比 >97%——若多桌高频运营需压至此以下，即是 P3 STARK
常数化的触发线（423 方程 → 1 个证明）；否则维持现状即可。

回归：hand_batch_stark 16/16（含满手 honest×2 + tampered×2）、snforge
全套 52/52、host parity 5/5、full_hand 2/2、e2e 2/2、leave_exclusion 5/5、
core 35。

## 4. 复现命令

```bash
# 基线（release）
cargo test -p poker-protocol-proofs --release --test plan_d_perf -- --ignored --nocapture
# 语句回归（12 个测试）
cargo test -p poker-protocol-proofs --test stark_curve_regression
# 后端单元 + oracle 测试
cargo test -p poker-protocol-core
```

### Phase 1 本地 prover bench（2026-08-29，stwo-cairo 官方 proving 仓库实测）

**管线**：Cairo 源码 → `compile_cairo1`（cairo-lang 2.19 + salsa 0.27）→ `run_and_prove`
（stwo-cairo 1.3，Circle STARK，96-bit 安全参数，M-series 并行 6.85 核观测）。

**基础设施修复记录**（影响后续复现）：
- stwo-cairo 旧 repo（salsa 0.24 + 新 rustc = cycle panic）已迁移至
  `starkware-libs/proving`（cairo-lang 2.19 + salsa 0.27 = 修复）；此为本会话
  关键发现之一
- Cairo1 Executable 路径（dev_utils）在 runner 里有一个 corelib 函数级
  runtime 兼容问题（poseidon_hash_span 调用后跳转异常——待查，非根本障碍；
  Cairo0 路径全通）

**校准数据**（官方测试语料，本地实测 wall-clock）：

| 程序 | CPU steps | EC_OP 实例 | Poseidon 实例 | 证明耗时 |
|---|---|---|---|---|
| trivial（return 42） | ~75 | 0 | 0 | **10.5s**（固定成本主导） |
| test_poseidon_builtin | — | 0 | 若干 | **8.6s** |
| test_all_opcode_components | 1,498 | 0 | 0 | **9.8s** |
| test_all_builtins | 9,157 | 7 | 12 | **25.1s** |
| test_poseidon_aggregator | — | 0 | ~30 链 | **7.2s** |

**成本模型**：固定 ~8-10s + ~2ms/CPU-step + EC_OP/Poseidon 实例的 trace 扩张。

**我们满手负载的推算**（423 方程 ≈ 1,480 EC_OP + 220 Poseidon + ~50k CPU steps）：
- 下界（线性 CPU 步 + builtin 摊销）：~30s
- 上界（保守 builtin 线性）：~120s
- **结论：秒级到分钟级，远优于此前"分钟级"的粗估，满足双轨异步锚定
  （热路径 37ms 直验放行，锚定路径延迟无关紧要）**。

托管判断数据点：本地 M-series 笔记本即可跑（6.85 核并行利用）；托管
（Atlantic/SHARP）的增益主要是运维（免维护、自动聚合到 L1），非性能必需。
