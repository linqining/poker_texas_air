# hand-verify-native — 原生 Stwo 版 hand_verify spike

**独立 workspace**（同 `proving-tool/` 模式）：不在根 `Cargo.toml` 的 members
列表里，有自己的 `Cargo.lock` / `target/`，根项目的任何 cargo 命令都不会碰
这个目录，本目录的构建也不影响主项目编译。

## 评估目标

把 `hand_verify`（hand_batch sigma 批量校验）从 **Cairo + STARK** 路线
（`hand_verify.cairo` → CairoVM → stwo-cairo，实测 prove 13.6s/手，
Apple M3 Pro）迁到 **Stark 曲线 sigma + 原生 Stwo** 路线，让 L1 / 第三方
的验证从 O(n) 重放变成 O(1) 验一份 STARK 证明。

## 架构（form-①，与主项目 `src/airs/crypto` 同构）

```
host（不进 STARK）                     STARK（原生组件，无 CairoVM）
──────────────────────                 ─────────────────────────────
payload 解析（fail-closed）      ──►   语句表 AIR：
Poseidon felt 挑战重放                  is_own/is_rev 选择子（布尔、互斥）
EC 残差直验（s·G−c·pk−R 等）            hand_binding limb 绑定（活跃行）
Horner ρ 折叠（恒等检查）               循环累计计数（Σis_own=n_own）
                   │                    claim（含 payload_digest）混入
                   └── digest ────►     Fiat–Shamir channel（commit 前）
```

**健全性边界（必须写进产品文档）**：STARK 证明的是「语句表算术关系成立 +
绑定到该 claim」，EC 残差为恒等是 **host 先验**、以 digest 形式绑定——即
证明 = O(1) 可验证的「运营方对这手牌 statement 的背书」，不是 EC 校验正确
性的可转移密码学证据。这与 v1（单 sequencer + watcher + 托管）信任模型
自洽；v2 需要密码学可转移时的升级路径：EC_OP 式组件进 trace，或 sigma 证明
递归聚合。

## 形态②（已实现）：Cairo EC attestation + 原生语句表 AIR 组合

`cargo run --release -- compose`（或 `cargo test --release --test compose_test -- --ignored`）。

EC 进 trace 的正确实现就是 Cairo 的 EC_OP builtin 机制（官方 28×9-bit limb +
carry + RangeCheck），在原生 stwo 里手搓这套等价电路是代码生成器级别的工程。
所以形态②走**组合**：真实 `hand_verify` 程序在 Cairo VM 上执行（EC_OP 把
每条标量乘的位调度记进 trace，EC 进 trace ✓），vendored starkware-libs/proving
出证明；spike 的原生语句表 AIR 作为另一半，claim 里携带 **Cairo program hash**
混入 Fiat–Shamir channel——两半绑定到同一 (hand_binding, payload)。

- **实测（2 ownership 语句）**：Cairo 半 22.2s（16 个 EC_OP，含编译/出证/复验），
  原生半 16ms / 1ms。**形态① 0.11s vs 形态② 22.3s ≈ 200×——这就是可转移
  健全性的标价**，且随语句数线性放大（Cairo 半边际 ~30ms/千步）。
- 完整满手形态②（436 方程）：Cairo 半 ≈ 44 万步 × ~30ms/千步 ≈ **~15s/手**
  （与本评估开篇的 Cairo 路线实测一致）。
- 测试：`form2_composed_roundtrip`（双半验证 + 程序哈希绑定负例）、
  `form2_rejects_unverifiable_payload`（过不了 host 验证的 payload 不组合）。
- 依赖：`prove-hand` 二进制（`cd proving-tool && cargo build --release`，
  一次即可），可用 `HAND_VERIFY_PROVE_HAND` 覆盖路径。

## 用法

```bash
cd hand-verify-native
cargo test            # 曲线/limbs/协议/golden vector 单测（诚实 + 篡改语料）
cargo test --release  # + perf 常驻回归门槛（9 人满手预算断言，debug 自动排除）
cargo run --release -- self-test   # 端到端自测：mint → 直验 → prove → verify + 负例
cargo run --release -- bench       # 规模扫描：2p/4p/9p/10×/40× 放大
cargo run --release -- vectors     # 打印 golden transcript 向量
cargo run --release -- compose     # 形态②：Cairo EC attestation + 原生 AIR 组合
# 完整性能矩阵（含缩放断言与批次摊销）：
cargo test --release --test perf -- --ignored --nocapture
```

## Spike 范围（fail-closed）

- **已实现**：ownership（5 词）、reveal（14 词）、leave（7 + 10n 词，批量
  DLEQ）、reconstruct（13 词，CP-DLEQ）四类语句——覆盖 `hand_verify.cairo`
  除 shuffle 外的全部语义；9 人满手 436 EC 方程（对照主项目 423 + 本语料
  的 leave/recon）。
- **显式拒绝**：shuffle（Bayer–Groth）非零即拒
  （`VerifyError::UnsupportedSection`），延续「未实现语义必须拒绝而非跳过」
  的纪律；BG 是独立论证系统，见主项目 `poker-protocol-bg`。
- transcript 公式复刻 `poker-protocol-core::stark_curve` 的 felt 直通纪元
  （`poker/hand-batch/proto`、`poker/reveal-token/fold-v1`、
  `poker/leave-fold/v1`、`poker/reconstruct-fold/v1`、ρ 词 `(kind, s, c)*`
  每方程一条）。**公式漂移由 golden vector 测试钉死**（`vectors` 子命令
  生成、`golden_vectors_pinned` 断言）；**跨端 parity 已验证**：
  `parity-checker/`（只读 path 依赖主项目 crate，独立构建）用
  `poker-protocol-core` 参考实现计算同一组固定输入，2026-09-05 比对
  endorsement / reveal / leave / reconstruct / hand_rho 五值**逐字节一致**
  （spike 侧 raw felt，参考侧 mod n 归约，输出 < n 时恒等）。

## limb 方案核查（对照官方 starkware-libs/proving）

本 spike 的 felt252 → **9 × 28-bit limb**：`2^28 < 2^31−1`（M31 安全，加法
不溢出）、9×28 = 252 恰好覆盖全值。与官方 vendored 代码的对照
（`third_party/proving/crates/cairo-air/src/components/`）：

- `cube_252.rs`（全宽 s-box）：252-bit = **28 个 9-bit limb + 27 个 carry**，
  按 `(l0 + l1·2^9 + l2·2^18)` 三三分组进 `RangeCheck_9_9` 查找表；
- `ec_op_builtin.rs`：坐标/标量同为 **28 × 9-bit limb**（`p_x_limb_0..27`）；
- `range_check_builtin.rs`：rc 单元走 `ReadPositiveNumBits128`（15 limb + MSB）；
- `examples/poseidon`：M31 域 Poseidon2，不涉及 felt252 分解。

**差异的本质**：官方组件在 trace 内做全宽算术，必须用 9-bit 叶子 + carry 链
+ range lookup（cube_252 达 141 列）保证 limb 有界；本 spike 的 limb 只是
**绑定常数**（活跃行上逐 limb 等于 claim 常数，无 limb 间运算），因此既不需要
range check 也不需要查找表——若将来做形态②（EC 进 trace），必须改用官方
这套查找表机制。

## 形态②原生内核（已实现）：felt252 模乘 AIR（`src/feltmul.rs`）

**无 Cairo VM、无指令集 trace**——每行 trace 直接就是一次 `a·b ≡ q·P + r`
的 limb 代数：28×9-bit limb（boolean 分解代替查找表）、逐位置卷积约束、
进位链（偏移编码 + 14-bit boolean 界）、稀疏 P 折叠（q·2^251 + 17·q·2^192
+ q 三段线性项）。实测（M3 Pro，release）：

| 行数 | prove | verify | 吞吐 |
|---|---|---|---|
| 256 | 121 ms | 38 ms | ~2100 muls/s |
| 1024 | 314 ms | 40 ms | ~3260 muls/s |
| 4096 | 1.19 s | 45 ms | ~3430 muls/s |

对照：Cairo 路线里一次等价的 felt252 乘法要付 ~296 条 CPU 指令步 + builtin
段开销——原生内核把 trace 从"指令 trace"换成"数学 trace"，去掉了整个解释器
层。EC 调度组件（点 double/add 行 ≈ 8–12 次内核乘/行）与 Poseidon 置换
（x^5 s-box + MDS ≈ 1233 次乘/置换）都是这个内核的直接上层增量。

## Cairo 路线优化（批摊销 + 参数调优）

已实测并交付 `docs/cairo-route-optimization.md`：10 手合批 + fast 参数
（pow_bits 16 / queries 40，需安全评审）→ **2.28s/手（−6×）**；40 手批外推
~1.5s/手。EC 算术本体（EC_OP 296 步/次）不变，优化全部来自固定成本摊销与
FRI 参数降档。

## PoseidonCairoStark252 核查（为何不能"直接用"）

`starknet_crypto::poseidon_hash_many` 的底层：0.6.2 = codegen 常数 + 内联
Hades（starknet-ff 算术）；0.8+ = 委托 `starknet-types-core` →
**lambdaworks-crypto 的 `PoseidonCairoStark252`**（8 全轮 + 83 部分轮、
3 元状态、优化轮常数）——它是 **host 原语**（Hades 参数 + Rust 算术），
不含任何约束系统。lambdaworks 侧的证明组件属于 lambdaworks 自己的 STARK
栈（单变量多项式 + 自己的域），与 stwo（M31 circle STARK）的 AIR 框架
**不可移植**——AIR 组件绑定于证明框架，不能跨栈投递。host 哈希部分本
spike 已直接在用（挑战派生 + parity 逐字节一致 ✓）；trace 内 Poseidon 的
现成实现只有官方 cairo-air 的 codegen 组件；自研路径 = 内核（本仓库已交付）
→ x^5 s-box + MDS → Poseidon 组件（≈1233 行内核 trace/置换，确定性增量）。

## AIR 约束一览（17 列 + 内核 1932 列）

| 约束 | 度 | 说明 |
|---|---|---|
| `sel_k²−sel_k` ×4，`sel_i·sel_j` ×6 | 2 | 四类选择子布尔且互斥 |
| `hb_i − claim_i·(Σsel)` ×9 | 1 | 活跃行绑定 claim limbs，padding 行置零 |
| `acc_k' − acc_k − sel_k + n_k/N` ×4 | 1 | 每类循环累计（自由旋转技巧，免 boundary 标记）|

PCS 配置与主项目一致（pow_bits=10，30 FRI queries，blowup 1）。

## 基线对照（本机 M3 Pro 12 核，release，2026-09-05 实测，含 leave/recon）

| 路线 | prove | verify | 证明 |
|---|---|---|---|
| Cairo + stwo-cairo（148 EC ≈ 一手） | **13.63 s**（固定 ~12s 主导） | 13–29 ms | 14.3 MB |
| Cairo 优化后（10 手合批 + fast 参数） | **2.28 s/手**（批摊销 −6×） | 9–10 ms | 同左 |
| Cairo 满手合约（9 人，O(n) gas） | — | 3.15 STRK（链上） | — |
| 本 spike（原生 Stwo，形态①） | **9 人满手 35 ms**；8,640 语句批 313 ms | 7.4 ms（满手）→ 20.4 ms（×402 批） | 37 KiB（满手）→ 147 KiB |

（`cargo test --release --test perf -- --ignored --nocapture` 实测：2p 7.2ms /
31ms / 2.9ms；4p 17.0 / 37.1 / 3.9；9p 73.7 / 35.4 / 7.4；×10 738 / 109 / 15.5；
×40 2935 / 313 / 20.4——列为 host 直验 / prove / verify 毫秒，证明 9.6→147 KiB。

读数：

- **prove 侧 ~390–650×**：9 人满手 13.63s → 35ms。host sigma 直验（436 方程，
  朴素标量乘）74ms，直验+prove+verify 总计 ≈ 0.12s，M4-ACC-1（≤3s p95）
  余量巨大。
- **verify 侧 O(log n)**：FRI 层数随 log_size 增长（2.9ms → 20.4ms 覆盖
  ×402 语句），常数毫秒级，工程上视作 O(1)；证明体积 9.6–147 KiB。
- **批次摊销 1.7×**：10 手合批证明（125ms）vs 10 份独立证明（215ms）
  （共享一棵 FRI 树），断言进 `perf_batch_amortization`。
- **性能回归门槛**：`perf_gate_single_hand` 常驻 release 测试
  （host < 500ms / prove < 1s / verify < 100ms / 证明 < 256KiB），
  debug 构建整文件编译排除；缩放断言（verify ×10 上限、证明 < 512KiB）
  在 `perf_full_matrix`。
- host 侧标量乘是朴素 case-aware Jacobian double-and-add：9p 手 ≈ 896 次
  标量乘 ÷ 71.5ms ≈ **80µs/次**；`poker-protocol-core` 后端实测
  **19µs/次**（`docs/plan_d_perf.md` #1），同量手直验约 **4×**；叠加
  挑战阶段求逆批量化（Montgomery batch inversion，~1300 次单独求逆 → 1 次）
  与窗口法，合计接近一个量级。注意：换后端只影响 host 时延，不移动信任
  边界（AIR 不约束标量乘，见上文形态①说明）。
