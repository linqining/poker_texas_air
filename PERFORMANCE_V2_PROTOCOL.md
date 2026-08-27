# RistrettoAirV2 协议层性能基准与优化点

测量时间：2026-08（`refractor` 分支）。运行命令：

```bash
cargo +nightly run --release -p poker-hand-bench -- full-hand-v2
cargo +nightly test --release -p poker_texas_air --lib ristretto_shuffle_air -- --nocapture --test-threads=1
cargo +nightly test --release -p poker_texas_air --lib ristretto_reconstruction_v2_air -- --nocapture --test-threads=1
```

## 0. 技术定位：两条路径

RistrettoAirV2 有两条性能上完全不同的路径，本文档的所有数字与优化点
都按此定位阅读：

| 路径 | 执行方 | 内容 | 成本量级 |
| --- | --- | --- | --- |
| **部署路径（生产）** | 客户端 **native prove** + 服务端 **AIR verify** | 客户端用 poker_protocol 原生密码学证明（ownership/洗牌/fold/reveal，交互级毫秒延迟）；服务端只执行验证器（`verify_*` / `admit_*`：BG 公式原生复核 + Flock transcript STARK 验证） | **整手 ~2s 墙钟，服务端 447ms**（§4.0 九人基准） |
| **递归工件路径（Path A 预留）** | （未来）聚合器/链上 | `prove_*_admission_components` 等统一 admission STARK——把服务端的验证义务折叠为单份多组件证明，供链上验证或递归聚合消费 | deck-52 prove 271.9s（§4.1） |

关键澄清：`prove_ristretto_bg_admission_components` / `prove_player_
admission_components` / `prove_ristretto_admission_stark_with_texas` 等
STARK prove **不在生产关键路径上**——客户端实际用 native 证明（毫秒级），
服务端用 AIR 验证器。admission STARK 的定位是递归信封工件：当目标是将
每手的验证义务压缩为链上可验的单证明时才需要它的 prove 侧。因此：

- §1–§3 与 §4.0 的数字是**部署路径**的基准与优化点（关键路径）；
- §4 与 §4.1 的 admission STARK 数字是**递归工件**的成本与优化点
  （非关键路径，按需排期）。

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
| **合计** | **168.1 ms** | **91.5 ms** | 客户端证明总量 5.49 MB |

结论：P0/P1/P3 落地后，单手协议层 prove 1.09 s → 178.5 ms（5.9×）、
verify 297 → 96.8 ms（2.9×）、证明量 13.5 → 5.49 MB（−59%）；梯子 codec
合并（§4.1-⑤/其余-1）再降到 168.1 ms / 91.5 ms（6.5× / 3.2×）。剩余体积主体
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

## 3. 部署路径性能优化点（按收益排序；§0 关键路径）

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

### P4 — 洗牌信封 ~2 MB（九人一手 9 个 ≈ 17.9 MiB 的体积主体，§4.0）

同 P0-3：BG 论证仅 5.5 KB，其余是 6 条 Flock 链。语句数已最小化（1 init + 5 挑战），
收益在 flock 参数或跨洗牌复用（同一玩家连续动作可共享 init 链）。

### P5 — 下注/结算的 STARK 成本（tagged AIR 路径）

本基准中下注是原生状态（292 ns）。完整 host-zero 下注走 canonical tagged AIR
（hand-bench 默认模式：整手 lifecycle+hand 批 prove 数秒级）。两层的证明组合与
递归聚合是 Path A 的范围（见 `HOST_ZERO_RISTRETTO_AIR.md` 的 Path A 章节）。

### P6 — 服务端验证吞吐（部署路径容量项）

九人基准下服务端每手 447ms（洗牌准入 21ms/个为最大项，reveal 已并行），
单核组 ≈ 47 洗牌准入/秒——数百桌并发无压力；多桌场景按准入吞吐横向
扩展（每准入独立、无共享状态）。冷启动仅会话首证（ownership 644ms 中
Flock setup 占大头），服务端预热 8ms。

### 已否决/已完成方向（勿重复）

- slot-OR / cross-key / 牌组转移的 FpProgram 展开：已由 V2 原生 sigma + Flock 替代
  （416 次标量乘 → 0）；
- 更小的 FRI fold_step、更小 Ristretto 域：历史上已验证为负收益；
- π 直接入 AIR：透明 STARK 泄漏置换，已否决（BG HVZK 保 π）。

## 4. 递归工件成本（Path A admission STARK；生产见 §0/§4.0）

| 组件 | 电路内义务 | 估算 |
| --- | --- | --- |
| 洗牌 BG 点方程 | ~7 组 52-way MSM 等式 | ✅ 已落地：`ristretto_scalar_mul_air` 专用 fixed-window 梯子 AIR（N=52 批量 prove 19.0s / verify 1.7s，边际 ~0.34s/次；对比 FpProgram 压缩行路线 172.3s / 8.8s，**prove 9.1× / verify 5.2×**） |
| BG 标量侧调度 | 幂表 + 期望乘积（mod l） | ✅ 已落地：`ristretto_scalar_program_air`（单条 prove 2.7s / verify 1.7s / 17.9MB；**跨调度批摊销实测**：52 条同形状调度一批 prove 2.8s / 证明 18.2MB = **0.35MB/条**，已达 <1MB 目标，无需新代码——结算层按窗口合批即可） |
| pk_ownership / reveal_token | 各 2 条点方程 | ✅ 已接入：player admission 分解器（各 2 / 4 次标量乘 + 原生等式，含 Flock 原生门） |
| remask / leave / fold | 53 条点方程 | ✅ 已接入：deck DLEQ 分解（106 次标量乘 + 53 等式；fold 的密钥更新减法仍为调用方原生检查） |
| transcript 链 | BLAKE3 二元域约束 | 即 Flock 已覆盖的语句 |
| 状态绑定 / openings | Blake2b lookup | 已是 M31 栈 STARK |

结论：每手牌的完整递归义务 ≈ 500–700 次电路内标量乘 + 哈希约束 + 标量侧调度
（✅ 已有 STARK：mod l program AIR）。**统一 admission STARK 骨架也已落地**
（✅ `ristretto_admission_air`，递归聚合器原型）：一份多组件证明把
[梯子 AIR + BG 标量调度 + 基点 decode + 终值 encode + 压缩点累加 + admission
绑定行] 六类组件折进共享的三棵树（tree 0 = 各组件 scope、tree 1 = 各原始
trace、tree 2 = 各 LogUp 交互层，由 stwo 固定索引强制）与单次 FRI。完整口径
实测（2 梯子 + 1 累加行 + deck-12 调度，分离侧计入全部 5 份证明）：合并
prove 3.40s / verify 1.69s / 18.12MB，分离 prove 3.58s / verify 1.55s /
17.11MB —— **成本大致中性（prove -5% / verify +9% / 体积 +6%）**；折叠的
价值在统一单工件、单次验证入口与递归骨架，而非压缩。验证端沿用
fail-closed 纪律：原生重建全部语句 + 可信 scope 比较 + 单次 STARK 验证。点侧的专用 fixed-window scalar-mul AIR
也已落地（✅ `ristretto_scalar_mul_air`）：trace 每行是一次射影 Edwards 加法
（26 个 pinned 值 + 8 个商 witness + 8 条加减链 + `2·Z1` 倍乘链 + `2d·T1`
常数乘 + 7 个一般乘法），基点只 decode 一次、终值只 encode 一次（各一条
fixed-shape Fp program 批行）；行内值经预计算 scope 列钉死到验证者重建的确定
性 schedule，pinned 肢无需电路内 range/canonicity（重建即担保），只有商肢
（11-bit 单肢）与乘法 carry（17-bit 对）进共享 LogUp 表。同输入实测
（ristretto_perf）：N=1 prove 1.4s / verify 0.53s；N=8 prove 3.5s；N=52 prove
16.0s / verify 1.5s / 证明 5.60MB（codec 合并后，2026-08；合并前 1.8s/0.58s、
19.0s/1.7s/6.24MB；FpProgram 压缩行路线 172.3s / 8.8s / 6.54MB）。剩余前置项只有递归聚合器的折叠摊销。宽行证明的批摊销已实测：BG 标量调度
52 条一批 0.35MB/条（`prove_ristretto_scalar_program_batch`，prove 几乎零增长——
宽度主导 FRI，行数只贡献 log 因子）；梯子路线 N=52 全批 5.60MB（codec 合并后）。仍按单条入
ZRS2 信封的场景（单调度 17.9MB / 单梯子 6.2MB）才需要进一步的列打包压缩。

### 4.0 九人整手牌部署路径基准（native 客户端 + AIR 服务端）

`hand-bench -- full-hand-v2-nine`（镜像 `texas_poker_move` Move 合约的一手牌
动作流：9×ownership → 9×BG 洗牌 → 发 18 底牌 + 5 公共牌 → preflop
fold_with_proof → preflop/flop/turn/river 四条街批量 reveal token（8 活跃
玩家）→ 摊牌解密结算）。客户端全程 native poker_protocol 证明，服务端只跑
AIR 验证器（verify_*/admit_*）：

| 阶段 | 客户端证明 | 服务端验证 |
| --- | --- | --- |
| ownership ×9 | 644ms（含冷 Flock 设置） | 65ms |
| BG 洗牌 ×9 | 372ms（41ms/个） | 191ms（21ms/准入） |
| fold_with_proof ×1 | 17.9ms | 8.9ms |
| 每条街 reveal（8 个批量证明） | 109–142ms | 39–50ms（并行） |
| 摊牌解密结算（21 张） | — | 4.9ms（native） |
| **整手合计** | **1.52s** | **447ms** |

整手墙钟 **1.99s**，客户端证明字节 **17.9 MiB**（9 个洗牌信封 ~2MB/个为
大头）。单客户端单动作延迟：洗牌 41ms、fold 18ms、每街 reveal ~14–18ms
（串行模拟 8 客户端的合计 ÷8）——全部交互级。注意：冷 Flock 设置只发生
在会话首证（644ms 中占绝大头），服务端预热 8ms 后全程 warm。此为**部署
路径**；Path A 递归信封（271.9s@deck-52）是链上/递归工件成本，不在该
关键路径上。

### 4.1 后续工作（增量优化 + 递归路线图）

**递归工件（admission STARK）成本结构与优化分析**——非生产关键路径
（§0），仅当需要链上单证明/递归聚合时排期。2026-08 实测基线：含
recurrence 段 prove 271.9s / verify 35.3s / 43.0MB：

stwo 的证明成本近似按**列数**而非单元数计费——recurrence 段只有
4M 单元（梯子段的 1/150）却花掉约一半 prove 时间（~131s），因为其
列数（~31K）是梯子（~2.4K）的 13 倍；这是通用标量程序 AIR 的结构性
成本（canonicity 列 ~360 值 × 51 列 + 每值 24 肢 + 每乘 141 列）。
参照系（§0）：部署路径整手墙钟 ~2s、服务端 447ms；271.9s 是
递归信封的 prove 成本，客户端 native 证明不受影响。

| 优化点 | 做法 | 预估收益 | 复杂度 |
| --- | --- | --- | --- |
| ① 专用 recurrence AIR | 梯子式固定布局：每步 7 个 pinned 值 + 2 乘 + 1 减链 ≈ 550 列/行（现 31K 列），值全部由公开响应确定性推导 → scope 钉死免 canonicity | recurrence 段 ~131s → 2–5s（**整体约 -45%**） | 中 |
| ② 专用 BG 调度 AIR | 幂表/累乘拆固定行（~600 列，现 15K 列），同法 | 再 -10–15% | 中 |
| ③ 梯子倍乘特化 | 4/5 Horner 行是倍乘，无 T 坐标专用公式（A=X², B=Y², C=2Z², E=(X+Y)²−A−B…）省 ~2–3 乘/行，宽度 -30% 覆盖 80% 行，LogUp carry 对同步减少 | ❌ **两个方向均已实测否决**（2026-08）：(a) 独立段——HWCD 倍乘行拆第二组件（窄 36%、4 输出乘 + 预平方 scope 钉死）后 N=52 prove 27.0s / verify 2.7s（原 18.3s / 1.8s），stwo 按列数计费，+1539 列净增；(b) 单组件选择子——stwo 的 FrameworkEval 行均匀（约束集对全定义域一致，无法按行跳过），选择子只能**增加** ~800 项/行而列数不变；实测约束斜率：+936 条满足约束/行仅 +2–4% prove（说明约束求值本就不是大头），故选择子方案严格为负。③ 在 stwo 2.3 上无可行实现，关闭 | ~~中~~ 不可行 |
| ④ 定基混合加法 | 表生成行右操作数 Z₂=1，混合加法省 D 乘链 | ~3–5% | 低 |
| ⑤ codec 段优化 | ✅ **decode+encode 已合并为单条 codec 程序批**（2026-08，`build_ladder_codec_program`，admission 侧 decode/encode 段同步合一）：省一次独立 FRI 固定成本，梯子批 N=52 prove 18.3→16.0s / verify 1.8→1.5s / 证明 6.24→5.60MB，N=1 prove 1.6→1.4s / 证明 −12%；剩余方向：重复基点（G/H/生成元）decode 去重、固定布局专用行 | 剩余 ~5% | 低-中 |
| ⑥ 双手合批 | log 18 填充率仅 55%，两手 860 梯子共一次 FRI | 每手 -30–40%（摊销） | 低（结算层合批） |
| ⑦ 见证生成定宽算术 | 430×335×8 次 BigUint 商计算换 4×u64 定点除法 | ~5–10s | 低 |
| ⑧ 跨手预计算 | G/H/生成元 decode 列每证明重复重证；真正摊销需递归折叠或共享预计算列协议 | 长期/架构型 | 高 |
| ⑨ 测量先行 | `TEXAS_PROVE_TIMING` 拆分 log-18 下 trace/承诺/FRI 占比与 rayon 并行度 | 定位剩余串行相位 | 低 |

叠加预估：①+②+③ 后 deck-52 约 **60–90s**，再加⑥约 **40–60s/手**；
进 10s 量级需 proof-verifies-proof 递归（超出 stwo 2.3）或专用后端
（GPU/GPU-FRI），属下一架构阶段。**不建议动**：肢宽（11→12 位仅
~10% 且 carry 表翻倍）、FRI 安全参数（协议决策）、carry 表拆分与
LOG_SIZE（历史红线）。

**其余增量优化（不阻塞主线，按需排期）**：

1. ~~decode/encode 段并入梯子 AIR~~：✅ 已按"合并为单条 codec 程序批"落地
   （见上表⑤，N=1 codec 独立 FRI 成本减半）；完全并入梯子 AIR（特殊行/额外
   组件）与③受同样的列数计费约束，收益存疑，暂缓。
2. 单条信封列打包（已评估，暂缓）：仅影响"单条入 ZRS2 信封"场景（单调度
   17.9MB / 单梯子 5.6MB）。理论上 2 肢/列打包可省一半列（prove 按列数计费），
   但链/卷积约束与 LogUp range-check 都按单肢线性消费列，线性抽取肢需再造
   独立列（净零收益），而直接 range-check 22-bit 打包对需要 2^22 表（现条带
   表 2^11/2^17，log 9 下即 8192 条表列，不可行）。需要新的 lookup 表设计
   （如分段 11-bit 拆分证明 packed 值域的交互层）才有正收益，属独立工作项，
   收益不确定，暂缓。

**递归路线图（Path A 聚合器，骨架已就位）**：

1. ✅ 统一 admission STARK 骨架（`ristretto_admission_air`，已完成）；
2. ✅ **decode/encode/累加 Fp 段并入**（已完成，admission STARK v2）：
   完整 BG 点方程族（decode→梯子→encode→累加）六类组件进同一三树布局；
3. ✅ **真实 BG admission 接线**（已完成）：`prove/verify_
   ristretto_bg_admission_components` + request 包装把 BG 验证器的全部
   公式分解为 [梯子语句 + 累加行 + 编码等式（原生）+ 标量调度 STARK]，
   deck-4 实测：46 梯子 + 38 累加 + 8 等式，一份 STARK prove 11.8s /
   verify 2.37s / 15.5MB；篡改响应标量/承诺点/语句/证明字节全拒。
   deck-52 实测（含 recurrence 标量段，见下）：430 梯子 + 422 累加，一份
   STARK prove 271.9s / verify 35.3s / 43.0MB（不含 recurrence 段时
   140.4s / 17.2s / 29.6MB——recurrence 宽行段是主要增量，列打包适用）；
4. ✅ **recurrence 标量段**（已完成）：`build_bayer_groth_recurrence_
   program` 把 `recurrence[i] = pc·b[i+1] − b[i]·a[i+1]` 与 `d = b[0] −
   a[0]` 的 mod-l 推导并入 admission STARK 第二标量段（语句携带
   AdmissionRecurrenceSpec，wire v4；`d == 0` 与 `b[n-1]` 比较仍为对
   pinned 输出的原生检查）；
5. ✅ **Texas Layer-1 折叠**（已完成，原型）：`prove/verify_
   ristretto_admission_stark_with_texas` 把任一方法 AIR（BoundAir 包装，
   trace 列进共享 tree 1、期望行摘要素入通道、零 claim 组件）折进
   admission STARK——CreateTable 与 pk+reveal 点方程一份证明验证通过，
   篡改期望行拒绝；dual-proof 全方法接线是后续项；
6. **边界**：电路内 FRI 验证超出 stwo 2.3 能力（无 verifier-air/
   recursion crate），当前骨架是递归的"折叠"半边（多组件单 FRI +
   摘要绑定），非 proof-verifies-proof；真正的电路内验证需升级
   stwo 或自研 verifier AIR。

