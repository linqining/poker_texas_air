# stwo-lean

Lean 4 + Mathlib 形式化的 **Stwo（Starkware STARK prover）证明验证库**。
目标：不信任 stwo 的 Rust 实现，用机器检验回答——

> 给定一份 stwo proof 与公开段，被证明的程序是否满足规范？

本仓库锁定 **stwo 2.3.0**（crates.io），所有语义以该版本源码为准。

## 当前状态

### Phase 1：数学基础层（已完成）

| 模块 | 对应 stwo 源码 | 内容 | 状态 |
|---|---|---|---|
| `StwoLean.M31` | `core/fields/m31.rs` | 基域 `F_p`（`p = 2^31-1`）：素性（Lucas-Lehmer 机器计算）、可执行快速幂 `fpow`、`-1` 与 `5` 非平方剩余 | ✅ 绿 |
| `StwoLean.CM31` | `core/fields/cm31.rs` | 复扩张 `F_p[i]`：手写 CommRing/Field 实例、norm 乘性、`N(a)=0 ↔ a=0`、stwo 公式的 inverse | ✅ 绿 |
| `StwoLean.QM31` | `core/fields/qm31.rs` | 安全域 `CM31[u]`（`u²=2+i`）：同上全套；norm 零判据依赖 `5` 非平方剩余 | ✅ 绿 |
| `StwoLean.Circle` | `core/circle.rs` | 圆群 `x²+y²=1`：加法封闭、逆元、`doubleX`、标量乘 spec、M31 生成元阶 `2^31` 机器验证、secure gen 在圆上、`getRandomPoint` 公式验证 | ✅ 绿 |

### Phase 2：证明系统层（进行中 — 哈希/通道/承诺/FRI 核心 完成）

| 模块 | 对应 stwo 源码 | 内容 | 状态 |
|---|---|---|---|
| `StwoLean.Poseidon252Params` | lambdaworks `starknet/parameters.rs` | Starknet 素数 `P252 = 2^251+17·2^192+1`、Fp252、COMP 压缩轮常数表（107 个，脚本提取生成） | ✅ 绿 |
| `StwoLean.Poseidon252` | `core/channel/poseidon252.rs` → `starknet-crypto::poseidon_hash` → lambdaworks `PoseidonCairoStark252` | Hades 排列（`poseidon_permute_comp` 逐行移植）、`poseidonHash`/`poseidonHashSingle`/`poseidonHashMany`（sponge） | ✅ 绿 |
| `StwoLean.Channel` | `core/channel/poseidon252.rs` | `Poseidon252Channel`：`mixU64`/`mixU32s`（含 `add_length_padding`）/`mixFelts`/`drawU32s`/`drawSecureFelt`（base-2^31 数字提取） | ✅ 绿 |
| `StwoLean.Merkle` | `core/vcs/poseidon252_merkle.rs` | `hashNode` 三分支（叶打包/内部/内部+列，8-M31 块 + 长度注入）、单路径 `pathRoot`/`verifyPath` | ✅ 绿 |
| `StwoLean.FriCore` | `core/fri.rs` + `core/fft.rs` | FRI 折叠核心方程：`ibutterfly`（`(f₀+f₁, (f₀-f₁)·x⁻¹)`）与 `foldPair`（`g + α·h`），即每层 `verify_and_fold` 的验证内核 | ✅ 绿 |
| `StwoLean.CircleDomain` | `core/circle.rs` + `core/poly/line.rs` + `core/utils.rs` | CirclePointIndex（mod 2^31）、Coset（`at`/`double`）、LineDomain、`bitReverseIndex` | ✅ 绿 |
| `StwoLean.FriVerifier` | `core/fri.rs` FriVerifier | 多层 FRI 折叠状态机：逐层 `friLayerVerifyAndFold`（merkle 路径核对 + foldPair 折叠）+ 末层多项式核对（Horner）；含 `inverseM31` 及 spec 引理 | ✅ 绿 |
| `StwoLean.LiftedMerkle` | `core/vcs_lifted/poseidon252_merkle.rs` + `vcs_lifted/verifier.rs` | PCS 实际使用的 lifted Merkle：3 槽 sponge 叶哈希（16-M31 块两半吸收 + finalize 填充）、多查询 `liftedVerify` 状态机（相邻对合并 + witness 顺序消费） | ✅ 绿 |
| `StwoLean.Deep` | `core/pcs/quotients.rs` | DEEP 商：`PointSample`、复共轭直线系数、`denominator`（可计算 CM31 逆）、周期性采样 + `α^k` 流水、按点分批（IndexMap 首现序）、`accumulateRow`/`friAnswers`、`circleDomainAt`（±half_coset） | ✅ 绿 |
| `StwoLean.Commitment` | `core/pcs/verifier.rs` + `core/queries.rs` + `core/fri.rs` | **泛化版** `verify_values`：多树/多查询/`foldStep` 参数化（子集折叠 `foldSubset`/`foldCosetGen`/`foldCircleSubset`）、packed leaf（`groupByLeaf` 复刻 `build_merkle_verification_inputs`）、首层圆→线折叠（`p.y⁻¹`）+ DEEP-ALI 替换语义、POW、drawQueries+排序去重、preparePP | ✅ 绿 |
| `StwoLean.Verifier` | `core/verifier.rs` + `core/air/accumulation.rs` + `core/proof.rs` | **验证器主循环**：`random_coeff` 抽取 → 组合多项式承诺 → OODS 点（channel 驱动 `get_random_point`）→ **DEEP-ALI 核对**（`extract_composition_oods_eval` 左右半分解 + `PointEvaluationAccumulator` Horner 累加）→ `verify_values` | ✅ 绿 |

向量（`StwoLean.Vectors`，72 条 = 52 decide + 21 native_decide，
实际 1 条两者皆可）：41 条 M31/CM31/QM31/Circle（decide）+
8 条 Poseidon/Channel（native_decide，含 stwo 测试金向量）+
6 条 Merkle/FRI 折叠（decide）+
1 条完整 3 层 FRI 实例 `friVerify`（native_decide）+
5 条 merkle 树节点值 + PCS 全链向量（泛化单查询 / 多树+多查询+packed / 主循环 DEEP-ALI 等）。PCS 金色值全部来自
**真实 stwo 组件**：通道交互用 `Poseidon252Channel`，trace 树验证用
`MerkleVerifierLifted::verify`（运行时自检通过），DEEP 商值用
`fri_answers`，折叠链用 `fold_circle_into_line`/`fold_line`；端到端
`pcsVerifyValues`（native_decide）覆盖
mix_root → mix_felts → draw α → FRI 承诺 → POW → 查询抽取 →
lifted Merkle 验证 → DEEP 商 → 首层圆→线折叠 → 内层链 → 末层核对。

**对拍发现的真实语义陷阱**（对拍方法学的直接收益）：

1. **COMP ≠ UNOPTIMIZED 常数表**。lambdaworks 注释称 OPTIMIZED 常数
   "not used, but are still valid"（暗示与 UNOPTIMIZED 可互换）——实测
   **不等价**：partial 轮 S-box 的非线性使 `M·c''` 前移不可与"教科书
   每轮全加"交换，两种表产生不同的排列。本库因此实现 COMP 形式
   （与 `poseidon_permute_comp` 逐行对应）。
2. `poseidon_hash_many` 的 sponge padding：空输入补 `1` 在 `s0`，
   奇数尾补 `1` 在 `s1`（与 `poseidon_hash(x,y)` 的第三槽常数 `2`、
   `hash_single` 的 `1` 各不相同，全部逐行对齐）。
3. **打包 fold 起点**：Channel `mix_u32s`/`mix_felts` 的 Horner 从
   `ONE` 开始，而 Merkle 列值打包从 `0` 开始且仅末块注入块长——
   两个"看起来一样"的打包实际是不同的哈希域。
4. **PCS 的叶哈希不是 `hash_node`**。`vcs_lifted` 的 lifted Merkle
   用 3 槽 sponge（16-M31 满块两半各 8 打包成对吸收 + finalize 的
   1 填充），与旧 `vcs/` 的 `hash_node`（单次 `hash_many` 打包表）
   完全不同——FRI/PCS 承诺树全部走前者。
5. **圆→线折叠的 twiddle 是 `p.y⁻¹` 不是 `p.x⁻¹`**：首层
   `fold_circle_into_line` 把对径点对 `(f(p), f(-p))` 折到 x 投影，
   查询对 `(2i, 2i+1)` 经 bit-reverse 映射恰好是 `±p` 对；线层之后
   的 twiddle 才是 x 坐标逆元。
6. **首层线域陪集 = `half_odds(L-1)`**（初值 `2^(30-L)`）：即
   `CanonicCoset(L).circle_domain()` 的 half_coset 本身——圆域的
   x 投影陪集与圆陪集共享初值索引与步长索引。
7. **末层多项式的可满足性**：Fiat–Shamir 同时绑定 last_poly 与查询
   位置，手工构造同时满足"低次一致"与"通道绑定"的末层多项式需要
   完整 AIR 一致性（真实 prover 的职责）。对拍向量将 `PcsProof` 的
   `lastPolyChannel`（通道绑定，占位）与 `lastPoly`（核对值，取自
   实际折叠输出）显式解耦——验证器核对逻辑与 stwo 逐行一致。

## 分层信任模型

所有机器检验的断言分两层，`scripts/check_axioms.sh` 分层审计：

1. **核心定理**（域/扩张/圆群/非剩余/生成元阶）：纯内核 `decide` 与
   tactic 证明，仅依赖标准公理 `[propext, Classical.choice, Quot.sound]`。
2. **重计算向量**（Poseidon/Channel 的 8 条具名定理）：`native_decide`
   ——251-bit 域上的 91 轮 Hades 排列用内核求值约 30 分钟/条，编译器
   （GMP 加速）求值秒级。其健全性依赖 Lean 编译器求值器的正确性
   （审计可见每定理专用的 `native_decide.ax` 公理），这是计算密集型
   断言的通行折中；禁止 `sorryAx`。若需绝对内核保证，可对任一向量
   改写为 `decide` 离线计算。

## 构建与测试

```bash
# 依赖 elan（Lean 4.32.0 toolchain）；mathlib v4.32.0 由 lake 自动获取
lake build
```

首次构建需下载 mathlib 及其缓存（`lake exe cache get`）。
注意：`StwoLean.Vectors` 的 41 条对拍断言每条都是内核对 31-bit 素域
运算的完整归约，该模块单次编译约 10-20 分钟（一次性成本，之后增量缓存）。

重新生成对拍向量（需要 Rust 工具链；独立于上层 cargo workspace）：

```bash
cd vector-gen && cargo run --release > ../StwoLean/Vectors.lean && cd ..
lake build
```

## 方法学

1. **干净模型 + 对拍钉死**。Lean 侧是数学标准构造（`M31 := ZMod (2^31-1)`、
   手写扩张域实例），不含 stwo 的延迟规约/位技巧；Rust 侧语义与 Lean 模型的
   等价性不靠人工对照，而由 `Vectors.lean` 中从真实 stwo 计算出的测试向量
   逐算子钉死（`decide` 内核机器检验）。
2. **计算性证明策略**。数论事实（素性、非平方剩余）不用重型定理，而是把
   论证归约为内核可判定的计算：
   - 素性：Lucas-Lehmer 残差 `s(29) mod (2^31-1)` 直接计算；
   - 非平方剩余：Euler 判据必要方向（Fermat，一行）+ 快速幂数值计算
     （`5^((p-1)/2) = -1` 等）。
   - 可执行函数（`fpow`）对燃料**结构递归**，保证 `decide` 可归约；
     well-founded 递归无法被内核求值。
3. **与 stwo 源码逐行对应**。每个模块头注明出处文件；乘法/逆元公式
   逐行移植（如 `QM31::inverse` 的 `(a-bu)/(a²-(2+i)b²)`）。

## 路线图

- **Phase 2（证明系统层）✅ 完成**：多树（TreeVec）/多查询/packed leaf
  （`foldStep > 1` 时 `LOG_PACKED_LEAF_SIZE = 2` 叶打包）泛化 + verifier
  主循环（`Verifier.verifyMain`：random_coeff → 组合承诺 → OODS →
  DEEP-ALI → verify_values）全部落地并对拍。
  - 附带：二进制标量乘（double-and-add）以机器验证 secure gen 的完整阶。
- **Phase 2.5（验证器收尾）**：`verifyMain` 接入真实 proof 反序列化
  （`StarkProof` 完整字段）、组件 mask 结构参数化、Blake2s 通道变体。
- **Phase 3（约束层桥接）**：`stwo-constraint-framework` 验证侧
  （LogUp、preprocessed columns、point 求值）+ 目标程序 AIR eval 的
  可执行化。对 `poker_texas_air` 项目：AIR 约束语义已有
  `src/airs_lean/` 命题模型，需补"可执行 eval ↔ 命题约束"桥接定理。
- **Phase 4（端到端定理）**：
  verifier 接受 ⟹ 约束满足（模 soundness error）⟹ 业务规范满足
  （衔接 `airs_lean` 的 Soundness/Censorship/Custody 三大命题）。

## 目录结构

```
stwo_lean/
├── StwoLean/            Lean 库源码
│   ├── M31.lean         基域
│   ├── CM31.lean        复扩张
│   ├── QM31.lean        安全域
│   ├── Circle.lean      圆群
│   ├── CircleDomain.lean 圆域陪集 / LineDomain / bit-reverse
│   ├── Poseidon252Params.lean  Starknet 域 + COMP 轮常数（脚本生成）
│   ├── Poseidon252.lean Hades 排列 / Poseidon 哈希族
│   ├── Channel.lean     Poseidon252Channel（Fiat–Shamir）
│   ├── Merkle.lean      旧 vcs/ Merkle 节点哈希 + 单路径验证
│   ├── LiftedMerkle.lean vcs_lifted/ sponge 叶哈希 + 多查询树验证
│   ├── FriCore.lean     FRI 折叠验证核心方程
│   ├── FriVerifier.lean 多层 FRI 折叠状态机
│   ├── Deep.lean        DEEP 商（quotients.rs）
│   ├── Commitment.lean  verify_values 泛化编排（多树/多查询/packed）
│   ├── Verifier.lean    验证器主循环（verifier.rs + DEEP-ALI + 累加器）
│   └── Vectors.lean     对拍向量（自动生成，勿手改）
├── vector-gen/          测试向量生成器（Rust，独立 workspace）
├── scripts/             质量门脚本 + 常数提取脚本
├── lakefile.lean
└── lean-toolchain       leanprover/lean4:v4.32.0
```

## 发布为独立仓库的清单

- [x] 自包含（不依赖 `poker_texas_air` 内其他目录；mathlib 通过 git require 获取）
- [x] `vector-gen` 独立 cargo workspace
- [ ] 添加 `LICENSE`（建议 Apache-2.0，与 stwo 一致）与 `NOTICE`
- [ ] CI（GitHub Actions：`lake build` + 两个质量门脚本 + 缓存）
- [ ] 从上层仓库 `git subtree split` 或迁移历史后独立发布

## 出处与许可

语义出处：[stwo 2.3.0](https://github.com/starkware-libs/stwo)（Apache-2.0）。
本库为独立实现，未复制 stwo 代码；`vector-gen` 仅将其作为 dev 工具依赖
用于生成测试向量。
