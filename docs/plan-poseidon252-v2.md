# Poseidon252 state-root AIR v2 —— 官方 cairo-air 形态的组件分解

状态：**已实施并全绿（2026-09-05）**。任务来源 `docs/TODO.md` #22⑤。
实测：2 消息测试链 e2e prove+verify 2.91s（v1 单体 691s 且不通过，≈237×）；
五组件 rowcheck 全过；篡改负例三连（anchor/message/swap）全拒；原生层
7 项单测全绿。v1 组件的 prove 侧测试已 `#[ignore]`（保留作对照）。
实施中修复的四个真实缺陷：① cube 行进位误传 `x2c`；② lane-2 无 p 列
（p2≡z2 别名）被当作独立列读取；③ scope/表 mult 列漏 bit-reverse 导致
StateIn 的 pos 坐标与表配对错位；④ verify 侧信道顺序（witness 树需在
draw 关系之前 commit）。
决策：放弃 v1 单巨型组件（1713 列混合布局），按 cairo-air-1.3.0 官方形态
拆成"链接组件 + 代数协处理器"（用户拍板：追求极致性能 + 稳定）。

## 1. 为什么改

v1 的三个结构性困难，全部在官方形态里不存在：

| v1 痛点 | 官方（cairo-air）做法 |
| --- | --- |
| 单组件 231 预处理 + 1482 见证列，一处 OODS 失败无法定位 | 每组件 ≤ ~170 列，各自可独立 assert/regression |
| 组件内混合 log size（main 8 + 表 16/12 同树）踩 lifting/barycentric 边界 | 每组件单一 log size；跨组件混合尺寸由框架原生处理 |
| 约束数 ~2700/行 × 全域求值（含 padding 行） | 每组件只在自己的行上求值自己的约束 |

实测佐证：`set_store_polynomials_coefficients` 后 v1 全模式 prove 691s 仍
ConstraintsNotSatisfied；STATE_ONLY prove 通过（614s）说明状态链关系与
边界设计正确，失败点在范围表/布局层——正是分解要消掉的层。

## 2. 官方参考（cairo-air-1.3.0/src/components/）

- `poseidon_full_round_chain.rs`（607 行，126 列）：**不计算置换**。持有
  cube_252/round_keys 的输出 limb，用 `LinearCombinationN4Coefs*` 子程序
  证明 mix 线性组合，用 `CommonLookupElements`（state ‖ 虚拟地址，enabler
  门控）把轮串成链。
- `cube_252.rs`（141 列）：felt252 的 x³ mod P 协处理器，自带 limb 分解
  与多档 RangeCheck 查表（20-bit / 9+9-bit）。
- 每组件 `Claim::log_sizes = vec![log; N]`，`RELATION_USES_PER_ROW`
  显式声明 LogUp 列数；`max_constraint_log_degree_bound = log + 1`。

## 3. v2 组件设计

### 3.1 ChainAir（链接组件，log = 链行数）

持有每轮全部**值** limb（不含进位链），约束只做线性/门控/边界：

```text
列（见证）：state_in 48 · s_c 48 · sq 96 · x2 96 · x3 144 · z 48 · q 96
           p 48 · t 16 · mix(lane0 97, lane1/2 各145) · zm 48 · pos_next 等
列（预处理）：pos · is_full · k 48 · w 32 · sel 3 · init 49 · void 49 · anchor 48
约束：absorb 加法（s_c limb 直接线性）· p = is_full·z + (1−is_full)·s_c
      · mix 线性组合与借位链 · pos 递归 · sel_init/sel_final 边界 · 锚点
LogUp：state 链 (in‖pos)→(zm‖pos_next) + init/void（沿用 v1 已验证设计）
      + mul/reduce 链接元组（见 3.4）
```

sq 在部分轮 lane0/1 上无行（is_full=0 时 p=s_c，不引用 sq/x2/x3/z）。

### 3.2 MulAir（乘法协处理器，log = ⌈mul 行数⌉）

统一形状 `a(32) × b(16) = c(48)`（square 行：a=s_c‖0¹⁶, c=sq‖0¹⁶）：
- 列：a 32 · b 16 · c 48 · 卷积进位 ~48 · 自身 limb 的 range16 条目
- 约束：schoolbook 卷积（每 kk 位：Σ_{i+j=kk} a_i b_j + carry = c_kk + B·carry）
- LogUp：(a‖b‖c) 96 坐标 −1（与 ChainAir 的 +1 配平）

行数/置换：full 轮 6（3 square + 3 cube）、partial 轮 2（lane2）→
8×6 + 83×2 = **214/置换**。

### 3.3 ReduceAir（归约协处理器，log = ⌈reduce 行数⌉）

统一形状 `x(48) = z(16) + q(32)·P`（mix 归约行：x=v 补零, q=qm 补零）：
- 列：x 48 · z 16 · q 32 · 乘积进位/借位 ~48 · range 条目
- 约束：q·P 卷积 + z 相加 = x（P 为常量多项式，按 limb 展开）
- LogUp：(x‖z‖q) 96 坐标 −1

行数/置换：full 轮 6（3 cube 归约 + 3 mix 归约）、partial 轮 4（1+3）→
8×6 + 83×4 = **380/置换**。

### 3.4 LogUp 接线

```text
关系与元组（坐标数）：
  ChainState 49 : (state ‖ pos)          —— v1 已验证
  MulLink    96 : (a ‖ b ‖ c)
  ReduceLink 96 : (x ‖ z ‖ q)
  Range16     1 : (limb)                 —— 表组件 2^16
  Range12     1 : (limb)                 —— 表组件 2^12（顶 limb 界）

配平：ChainAir 每次使用发 +1；MulAir/ReduceAir 每行发 −1（并自身约束
c=a·b / x=z+qP）；multiset 相等 ⇒ 链上每个元组都满足代数关系
（与 cairo builtin↔CPU 链接同构，不要求元组唯一，只要求计数配平）。
range16 条目归属：谁的 limb 谁发（MulAir 管 a/b/c，ReduceAir 管 x/z/q，
ChainAir 管 mix 中间量与 carry）。
```

### 3.5 行数与尺寸核算（2 消息测试链，log 8 → 256 行）

```text
ChainAir  : 256 行（log 8），~970 见证列 + ~230 预处理
MulAir    : 214×2 + (4 full×6 + 70 partial×2) = 592 行（log 10），~150 列
ReduceAir : 380×2 + (4×6 + 70×4) = 1064 行（log 11），~130 列
表        : 2^16（log 16）、2^12（log 12），预处理恒等列 + mult 列
交互列    : Chain ~13 分数列 · Mul ~46 · Reduce ~46 · 表各 1（×4 M31）
           ≈ 430 M31 列（v1 为 1404）
约束求值  : ≈ 263k 次（v1 ≈ 1.38M，~5×）
```

生产尺寸（state_root 实际消息数 3–9 felt → 1–3 置换）同量级。

## 4. 稳定性设计

1. 每组件单一 log size —— 与官方一致，避开 v1 的混合 lifting 语义。
2. 跨组件混合尺寸只出现在共享树提交层，`mixed_log_components_prove`
   复现测试已证明该层正确。
3. 每组件独立 `assert_constraints_on_trace` + 独立 LogUp balance 断言。
4. pcs：blake2b 先例参数（pow 10 / FriConfig(0,1,30,1) / store
   coefficients），逐组件核对 max_constraint_log_degree_bound = log+1。
5. 负例三连（篡改 anchor / 篡改 message / 交换消息序）必须失败。

## 5. 实施步骤

1. 原生层 `poseidon252_air.rs`：`build_chain_trace` 同一趟收集
   `mul_rows: Vec<MulRow>` / `reduce_rows: Vec<ReduceRow>`（复用已验证
   的 `one_round_witness` 算术，不重写）。单测：gadget 行与 native 置换
   逐值一致。
2. 组件层新模块：ChainAir / MulAir / ReduceAir / RangeTable 四个
   FrameworkEval + 各自交互列生成（单一 log size，官方配对公式）。
3. prove/verify 驱动：三树（预处理/见证/交互）+ TraceLocationAllocator
   共享树提交；verify 侧树 log size 声明与 prover 一致。
4. e2e + 负例 + 性能对比（目标：显著低于 v1 的 691s）。
5. 清理 v1 调试遗留（env 开关/DBG/repro 模块），更新 STATUS/TODO。

## 6. 风险

- 元组坐标数 96 的关系在 LogUp 分母上是 96 项线性组合——官方
  CommonLookupElements 同规模（21/31 坐标）无问题；M31 上限 31 bit，
  16-bit limb × 96 项 → 分母多项式度不增长（仍是线性），仅 combine
  计算量线性。
- mix 借位链留在 ChainAir 使其列数偏高（~970）；若成为瓶颈，二期把
  borrow 链也下放为 SubAir 协处理器（官方 LinearCombination 子程序同构）。
