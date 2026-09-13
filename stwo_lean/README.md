# stwo-lean

Lean 4 + Mathlib 形式化的 **Stwo（Starkware STARK prover）证明验证库**。
目标：不信任 stwo 的 Rust 实现，用机器检验回答——

> 给定一份 stwo proof 与公开段，被证明的程序是否满足规范？

本仓库锁定 **stwo 2.3.0**（crates.io），所有语义以该版本源码为准。

## 当前状态（Phase 1：数学基础层，已完成）

| 模块 | 对应 stwo 源码 | 内容 | 状态 |
|---|---|---|---|
| `StwoLean.M31` | `core/fields/m31.rs` | 基域 `F_p`（`p = 2^31-1`）：素性（Lucas-Lehmer 机器计算）、可执行快速幂 `fpow`、`-1` 与 `5` 非平方剩余 | ✅ 绿 |
| `StwoLean.CM31` | `core/fields/cm31.rs` | 复扩张 `F_p[i]`：手写 CommRing/Field 实例、norm 乘性、`N(a)=0 ↔ a=0`、stwo 公式的 inverse | ✅ 绿 |
| `StwoLean.QM31` | `core/fields/qm31.rs` | 安全域 `CM31[u]`（`u²=2+i`）：同上全套；norm 零判据依赖 `5` 非平方剩余 | ✅ 绿 |
| `StwoLean.Circle` | `core/circle.rs` | 圆群 `x²+y²=1`：加法封闭、逆元、`doubleX`、标量乘 spec、M31 生成元阶 `2^31` 机器验证、secure gen 在圆上、`getRandomPoint` 公式验证 | ✅ 绿 |
| `StwoLean.Vectors` | （自动生成） | 41 条从真实 stwo 二进制导出的对拍向量，`decide` 机器检验 | ✅ 绿 |

质量门（`scripts/`）：

```bash
lake build                    # 零错误
bash scripts/count_sorries.sh # total sorry/admit: 0
bash scripts/check_axioms.sh  # 仅依赖 [propext, Classical.choice, Quot.sound]
```

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

- **Phase 2（证明系统层）**：`Poseidon252`（252-bit 素域 Hades，`vcs/`）→
  `Channel`（Fiat–Shamir）→ Merkle verifier（`vcs/`、`vcs_lifted/`）→
  circle FRI verifier（`core/fri.rs`）→ PCS 查询与 DEEP（`core/pcs/`）→
  verifier 主循环（`core/verifier.rs`）。产出：**可执行的独立 stwo proof
  验证器**（输入规范化 proof + 公开段，输出接受/拒绝）。
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
│   └── Vectors.lean     对拍向量（自动生成，勿手改）
├── vector-gen/          测试向量生成器（Rust，独立 workspace）
├── scripts/             质量门脚本
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
