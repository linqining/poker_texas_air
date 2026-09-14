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
| （待做） | `core/fri.rs` FriVerifier | 多层 FRI 状态机 + circle domain 数学 + DEEP | ⏳ |
| （待做） | `core/pcs/` + `core/verifier.rs` | CommitmentSchemeVerifier + verifier 主循环 | ⏳ |

向量（`StwoLean.Vectors`，54 条）：41 条 M31/CM31/QM31/Circle（decide）+
8 条 Poseidon/Channel（native_decide，含 stwo 测试金向量）+
5 条 Merkle/FRI（2 个 `hash_node` stwo 金向量、4 叶树路径往返、
`ibutterfly`/`foldPair` 数值）。

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

- **Phase 2（证明系统层）— 剩余**：Merkle verifier（`vcs/poseidon252_merkle.rs`、
  `vcs_lifted/`）→ circle FRI verifier（`core/fri.rs`）→ PCS 查询与 DEEP
  （`core/pcs/`）→ verifier 主循环（`core/verifier.rs`）+ POW nonce 验证。
  产出：**可执行的独立 stwo proof 验证器**（输入规范化 proof + 公开段，
  输出接受/拒绝）。
  - 附带：二进制标量乘（double-and-add）以机器验证 secure gen 的完整阶。
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
│   ├── Poseidon252Params.lean  Starknet 域 + COMP 轮常数（脚本生成）
│   ├── Poseidon252.lean Hades 排列 / Poseidon 哈希族
│   ├── Channel.lean     Poseidon252Channel（Fiat–Shamir）
│   ├── Merkle.lean      Poseidon252 Merkle 节点哈希 + 路径验证
│   ├── FriCore.lean     FRI 折叠验证核心方程
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
