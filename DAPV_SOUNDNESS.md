# DAPV 密码学 Soundness 分析 与 手牌实例 × STARK 绑定方案

状态：分析报告 v1.2（2026-09-05 修订）。对应 `DUAL_PROOF_PROTOCOL.md` 的
DAPV 方向形式化与实验验证。

**v1.2 修订（现状对齐）**：定理 1/2、引理 8、四层绑定方案仍是生产
`dual/hand_batch_stark.cairo` 的可靠性依据；但曲线实例化已变——生产 =
**Stark 曲线（EC_OP）+ Poseidon 挑战/ρ**（Plan D 2026-09-05），正文中的
secp256k1 决策、BN254 记号与配对讨论仅作理论载体；§10 算法的现行签名为
`verify_and_settle_dapv_stark(hand_binding, hand_id_bytes, hand_id,
action_log_digest, players, deltas, p_batch)`，digest 断言含动作日志尾词
（#18 Phase B）；§14 第 1 条（L2 挑战绑定缺口）已闭合。

**v1.1 变更（链上落地决策——"L==O 决策"）**：配对在 DAPV 中自始至终只做
"L 是否为零点"的判定，而群本身免费提供该判定（一次坐标比较）。两个版本
（`e(L,H₂)=1` 与 `L==O`）接受**完全相同的 transcript 集合**，可靠性界
一字不差；配对却要求迁移 BN254 并手写 F_p¹² 塔——在 Starknet 上是最贵的
代码路径且无任何安全回报。因此链上实现定为：**留在 secp256k1（EC_OP
内建），聚合终判用 `L==O`；配对形态保留给真正有双线性工作的 §11 SNARK
终态**。已落地 `poker_contracts/src/dual/hand_batch.cairo`（ρ 折叠 +
`L==O`，own/reveal/fold 残差端到端，BG 洗牌待折叠、暂用既有逐证明验证器），
测试 27/27 绿（含跨手牌重放拒绝）。首轮实现曾仅把 hand_id 绑进 ρ——重放
测试当场接受了旧 transcript，实证了 §8 引理；修复为 §9-L2 的"内层
transcript 域派生自 hand_id"（`hand_transcript_domain`，链上内部派生，
不接受外部传入协议名）后重放被拒。

参考实现与实验：
- native 配对版原型：`poker-protocol-proofs/examples/dapv_hand.rs`
  （复现：`cargo run --release -p poker-protocol-proofs --example dapv_hand`）
- 链上 `L==O` 版：`poker_contracts/src/dual/hand_batch.cairo`
  （向量生成器：`cargo test -p poker-protocol-core --test hand_batch_vectors -- --nocapture --ignored`；
  测试：`snforge test --max-n-steps 100000000`）

实验平台：macOS / aarch64，halo2curves 0.7（bn256 配对引擎）、scarb 2.11.4
+ snforge 0.39.0。

---

## 第一部分：DAPV 可靠性（Soundness）分析

### 1. 系统与记号

| 记号 | 定义 |
|---|---|
| `G₁, G₂, G_T` | BN254：`E/F_p: y²=x³+3`（G₁，**余因子 1**）、twist `E'/F_p²`（G₂）、`F_p¹²` 中的目标群 |
| `r` | 群阶 `21888242871839275222246405745257275088548364400416034343698204186575808495617`（≈ 2^253.6） |
| `e` | optimal ate 配对，非退化；`H₂ ∈ G₂` 为固定常数生成元 |
| `Lᵢ` | 第 i 条验证方程的**群残差**：方程为真 ⟺ `Lᵢ = O` |
| `N` | 一手牌展开后的方程数（九人桌基准：253，见 §2） |
| `ρ` | 折叠挑战，`ρ = H("dapv/ρ/v1" ‖ hand_id ‖ hand_binding ‖ P_transcript)`，见第二部分 |

**五类证明 → 方程系统**（每条都是 `Lᵢ = Σₖ aₖ·Pₖ`，`aₖ` 为验证者可算标量、
`Pₖ` 为已知点；即群内仿射线性）：

| 证明 | 方程数/证明 | 残差形式 |
|---|---|---|
| ownership（Schnorr） | 1 | `s·G − R − c·pk` |
| Bayer–Groth V2 洗牌 | 8 | 密文 MSM 等式×2、承诺等式、`c_beta` 标量承诺、传输方程×2、乘积论证×2 |
| reveal token（CP-DLEQ） | 2 | `s·G − T₁ − c·pk`；`s·c1 − T₂ − c·token` |
| leave/remask 批量 DLEQ | 1 + 每卡 1 | `s·G − B − c·pk`；每卡 `s·c1ᵢ − Aᵢ − c·d2ᵢ` |
| （字段级检查） | 每次洗牌 2 | `b₀ = a₀`、乘积封闭值 —— **标量方程，进不了配对** |

九人桌基准（9 ownership + 9 洗牌 + 33 reveal + 2 leave）：**N = 253**，
折叠后一次 **4008 点 MSM**，证明 wire ≈ 57.8 KiB。

### 2. 聚合验证器的精确定义

```
V(P, hand_id) 接受 ⟺ 以下全部成立：

(W) wire 检查    ：每个点在曲线上且非恒等（G₁ 余因子 1 ⇒ 在曲线 = 在子群）、
                   密文结构、c1 不变、证明形状
(F) 字段检查     ：BG 乘积论证的 b₀=a₀ 与封闭值（标量等式，无法进入群配对）
(ρ) ρ = H(dom ‖ hand_id ‖ hand_binding ‖ 编码(P))，在所有内层挑战之后导出
(L) L = Σᵢ ρⁱ·Lᵢ（一次 MSM；方程序列 = settlement 规范定义的确定性顺序）
(E) e(L, H₂) = 1_{G_T}   —— 唯一一次配对
```

无配对批验证 = 把 (E) 换成自由的 `L == O` 点检查。两者**逻辑等价**（定理 2）。

### 3. 主定理与证明

**定理 1（聚合可靠性）。** 对任意 PPT 敌手 A，若其提交的 transcript 中存在
某方程 j，在诚实导出的内层挑战下残差 `Lⱼ ≠ O`，则

```
Pr[V 接受] ≤ (N−1)/2²⁵³ + q_H·2⁻²⁵⁶
```

其中 `q_H` 为哈希查询数；`2²⁵³` 是 ρ 的值域（见 §5.7）。
N = 253 时界 ≈ 2⁻²⁴⁵。

**证明（game-hop）。**

- **G0 → G1（ROM 重编程）**：把 ρ 的导出换成敌手固定 transcript 之后的
  均匀随机值。在随机预言机模型下，除非 A 找到 ρ 导出函数的碰撞/部分原像
  （优势 ≤ q_H·2⁻²⁵⁶，SHA3-256），两游戏不可区分。
- **G1 → G2（Schwartz–Zippel）**：设 `L(X) = Σ Xⁱ·Lᵢ`。取 𝔽_r 与 G₁ 的
  模同构 `ℓ`（存在即可，无需可计算），`L(X) = O ⟺ f(X) := Σ ℓ(Lᵢ)Xⁱ = 0`。
  `ℓ(Lⱼ) ≠ 0` 使 f 为次数 ≤ N−1 的非零多项式，至多 N−1 个根。ρ 均匀分布于
  值域 S（|S| = 2²⁵³ ⊂ 𝔽_r），故 `Pr[L(ρ) = O] ≤ (N−1)/|S| = (N−1)/2²⁵³`。
- **G2 → G3（残差归零）**：条件于 A 通过 G2，所有残差为零。此时每个内层
  验证方程恰好为真，可靠性完全归约到各内层协议自身的 FS 可靠性（§4）。
  聚合步骤不再引入任何额外优势。∎

**研磨（grinding）**：A 可试 q 份 transcript，总优势按联合界放大
`q·(N−1)/2²⁵³`；q ≤ 2⁴⁰ 时仍 ≥ 2⁻²⁰⁵ 安全边际。

**定理 2（与逐个验证的逻辑等价）。**
(i) 完备性：诚实 transcript 每条 `Lᵢ = O` ⇒ `L = O` ⇒ 由非退化性与 G₁
余因子 1，`e(L,H₂) = 1`。（`e(O,H₂)=1` 由双线性直接得出。）
(ii) 配对判定等价：`e(L,H₂)=1 ⟺ L = O`——核提取引理：写 `L = a·P₁`，
`e(L,H₂) = e(P₁,H₂)^a`，非退化 ⇒ `e(P₁,H₂)` 恰为 r 阶，故 `=1 ⟺ a≡0 ⟺ L=O`。
∎
（实验侧证：原型中 honest hand 三验证器同 accept，四类单点篡改与跨手重放
三验证器同 reject。）

### 4. 内层协议的可靠性前提

DAPV 是**验证的聚合器，不是可靠性的放大器**：聚合接受的前提是全部残差为零，
即每条内层方程为真——内层协议自身的 soundness 假设原样继承：

| 内层协议 | 假设 | 说明 |
|---|---|---|
| ownership Schnorr | DLP + ROM | 特称可靠性；pk/R 非恒等检查堵平凡解 |
| reveal token CP-DLEQ | DLP + ROM | 合取语句 2-特称可靠 |
| leave/remask 批量 DLEQ | DLP + ROM | 共享见证特称可靠：两个接受 transcript 提取唯一 sk，逐卡方程强制 `d2ᵢ = sk·c1ᵢ` |
| BG V2 洗牌 | DLP + Pedersen 绑定 | 乘积论证依赖承诺密钥 H 与 G 无已知 DL 关系——这是 backend 用 SVDW 派生 H（而非 `H = G·h`）的原因 |

**反例警示（来自本仓库自身）**：legacy V1 洗牌证明存在混合见证攻击
（`shuffle_proof.rs` 文档与回归测试记载）。把 DAPV 套在 V1 上同样会接受
伪造——**聚合永远继承内层的弱点**。生产聚合对象必须是 BG V2（本原型即如此）。

### 5. 结构性边界条件（实现必须保持的不变量）

1. **余因子**：BN254 G₁ 余因子 1，"在曲线上 ⇒ 在子群"，wire 检查 (W) 足够。
   若迁移 BLS12-381（G₁ 余因子 ≠ 1），`e(L,H₂)=1` 只能杀死 r-torsion 分量，
   必须补余因子清除——BN254 是本方案的自然选择。
2. **配对引擎的恒等项过滤**：halo2curves 的 `multi_miller_loop` 跳过恒等项，
   因此诚实路径（L=O）走快速路径直接得 `Fq12::one()`——正确性不受影响
   （e(O,H₂)=1 恰是要的答案），作弊路径正常进入 Miller 循环。
3. **方程序列规范化**：ρ 幂指数按 settlement 规范定义的确定性顺序分配
   （ownership → shuffle → reveal → leave）。任何固定顺序都不影响可靠性，
   但必须全网一致，否则共识分歧。
4. **字段检查不可省**：(F) 的两条标量方程（b₀=a₀、乘积封闭值）留在配对外，
   是 BG 乘积论证 soundness 的一部分，删掉它们等于打开漏洞。
5. **ρ 的导出时机与输入**：ρ 必须在全部内层证明固定之后、对所有语句与证明
   编码、带域分离标签导出——敌手不能先看 ρ 再决定破坏哪条方程。
6. **零知识性不受影响**：L 是公开 transcript 的确定性函数，聚合不引入新
   交互、不接触见证；内层协议的 HVZK 原样保持。
7. **挑战分布**：`hash_to_scalar` 清高 3 位 ⇒ 挑战与 ρ 均匀分布于
   `[0, 2²⁵³) ⊂ 𝔽_r`（BN254 的 r < 2²⁵⁴，需 3 位保证无 mod 约减偏差）。
   无模偏差，熵损 3 位；定理 1 的界按 2²⁵³ 计。
8. **transcript 语义**：分析将 Merlin（Strobe）按 RO 对待；链上重放路径
   （Keccak/SHA3）与该分析一致（`TranscriptId::FiatShamirSha3`）。

### 6. 与 G 层 STARK 的组合

两层的假设集合不相交：

- P 层：DLP（G₁）+ ROM（FS/ρ）+ Pedersen 绑定（BG）
- G 层：哈希抗碰撞 + FRI/低次性（代数，无曲线假设）

组合优势按联合界相加；配对在本方案中只承担"零测试"这一**代数恒等式**
（非退化性是固定配对的性质，不是计算假设），不引入新的安全假设。

---

## 第二部分：手牌实例 × STARK tagged proof 绑定方案

目标：结算合约接受的 `(P, π_G)` 必须属于**当局**（this hand）——防跨手牌
重放、跨层拼接、部分混合、双花、换桌/换 epoch 重放、过期密钥。

### 7. 威胁模型

| # | 攻击 | 描述 |
|---|---|---|
| A | 跨手牌整段重放 | 把 hand A 的 P transcript 当作 hand B 结算 |
| B | 跨层拼接 | P(A) 配 G(B)（或反向） |
| C | 部分混合 | 把 A 的部分（语句,证明）对混入 B 的 transcript |
| D | 双花 | 同一 (P, π_G) 结算两次 |
| E | 换桌/epoch | 隔局或换密钥纪元后重放 |
| F | 过期密钥 | 用旧注册纪元的 pk 提交证明 |

### 8. 关键引理：仅靠 ρ 绑定无法防整段重放

**引理（ρ-绑定不足）。** 设 P 是 hand A 的合法 transcript（全部残差为零）。
则对**任意** ρ，`L = Σ ρⁱ·Lᵢ = O`，`e(L,H₂) = 1` 恒成立。

证明：零残差与 ρ 无关，零的任意线性组合仍为零。∎

**推论**：重放防护必须进入**内层挑战层**（使移植后残差非零），不能只做
在折叠层。本仓库 `dleq_proof.rs` 文档亦明示：
"Replay protection across games/epochs remains the caller's responsibility
unless the outer transcript already binds that context"——本方案就是把这个
责任显式落进 transcript。

### 9. 四层绑定方案

与 `DUAL_PROOF_PROTOCOL.md` §6 的现有 `hand_binding` 设计对齐并补齐缺口。

**L1 · 手牌实例标签（链上一次性）**

```
hand_id = H(table_id ‖ hand_number ‖ chain_epoch ‖ 开局 block_height ‖ seat→pk@注册纪元)
```

开局时 `register_hand(hand_binding, settlement_digest)` 上链注册；
结算后状态机标记 consumed。hand_number 单调、hand_id 单次使用。

**L2 · P 层自绑定（每个内层 transcript 的 hand 前缀）——核心层**

每类证明的 Fiat–Shamir transcript 协议名派生为

```
proto(phase) = H("poker/proto" ‖ phase ‖ hand_binding)
```

（原型以 hand_id 代替 hand_binding 演示；生产用完整 hand_binding 摘要。）

效果：任何为 hand A 铸造的证明，在 hand B 的结算上下文中所有挑战错位 →
残差非零 → 配对/批验证整体拒绝。由引理 8，这一层是防攻击 A/C/E 的**唯一
充分手段**。

覆盖清单与缺口：
- shuffle / reveal / leave / remask 均走 Merlin transcript ✅（改协议名即可）
- **ownership 的挑战是 `H(G‖pk‖R)`，无 transcript** ⚠️ —— 需一行改动：
  `pk_ownership.rs` 的 `challenge` 输入前置 hand_binding 字节；或改按
  注册期一次性证明处理（语义为"此 pk 属于此纪元"，而非"此手牌"）。

**L3 · 跨层互绑（ρ ↔ STARK 公共输入 + settlement 对账）**

```
hand_binding = Poseidon(table_id, hand_id, num_players, players[],
                        deck_commit_0..9, reveal_commitment,
                        state_root_pre, state_root_post, settlement_digest)   [§6 现有定义]

G（canonical tagged batch STARK）公开输入包含 hand_binding            [§5.2 既定项]
ρ = H("dapv/ρ/v1" ‖ hand_id ‖ hand_binding ‖ P_transcript_digest)     [生产版 ρ]
```

结算时对账：G 声明的 hand_binding 必须与链上重算一致，且其 P 分量摘要必须
等于实际提交的 P transcript 摘要。拼接分析：
- P(A)+G(B)：G(B) 与链上 deck 链一致，但 P 对账失败（P 摘要是 A 的）；
  且 L2 使 P(A) 内部挑战也错位——双重失败。
- G(A)+P(B)：对账同样失败。
- 部分混合（C）：任何被 G 状态机消费过的语句都进入 hand_binding 的
  deck/reveal 承诺，混入语句与链上承诺不匹配。

**L4 · 链上状态机（新鲜性）**

- hand_id 单次使用（防 D）；hand_number 单调（防 E）；
- deck 承诺链逐阶段上链更新（submit_shuffle_v2 → …）；
- 证明中的 pk 必须匹配 hand_id 内快照的注册纪元（防 F）。

### 10. 结算验证算法

```
verify_and_settle(P, π_G, hand_id):
  1. hb := 从链上状态重算 hand_binding（deck 链、players、roots、settlement_digest）
  2. assert STARK.Verify(vk_G, pub=(hand_id, hb), π_G)
  3. assert hb.p_digest == H(P)                      # 跨层对账
  4. ρ := H("dapv/ρ/v1" ‖ hand_id ‖ hb)
  5. (equations, W∧F checks) := extract(P, hand_id)  # 所有 transcript 名带 hand 上下文
  6. L := MSM(ρ; equations)；assert e(L, H₂) = 1     # 唯一一次配对
  7. 标记 hand_id consumed；按 settlement_digest 支付
```

### 11. 组合可靠性定理

**定理 3。** 在 (i) 内层 sigma 各自 FS 可靠性（DLP+ROM）、(ii) BG V2
soundness、(iii) STARK soundness、(iv) 哈希抗碰撞、(v) 链上状态机不可回滚
之下，任何将"非本局诚实执行"的 `(P, π_G)` 结算成功的 PPT 敌手，优势

```
≤ Σᵢ ε_inner,i + ε_STARK + (N−1)/2²⁵³ + q_H·2⁻²⁵⁶
```

各攻击的失败点映射：

| 攻击 | 失败于 |
|---|---|
| A 跨手重放 | L1（hand_id 不同）+ **L2（内层挑战错位 → 残差非零）** |
| B 跨层拼接 | L3 对账（+L2 双保险） |
| C 部分混合 | L2 + L3（deck/reveal 承诺不匹配） |
| D 双花 | L1 consumed |
| E 换桌/epoch | L1（hand_id 含 table/epoch） |
| F 过期密钥 | L1/L4（pk 纪元快照） |

### 12. 原型实验结果（`examples/dapv_hand.rs` 实测）

| 实验 | naive | batch | DAPV |
|---|---|---|---|
| 诚实牌局（本 hand_id） | accept | accept | accept |
| 单点篡改 ×4（response/T₁/ciphertext_1/leave.response） | reject | reject | reject |
| **跨手牌重放**（hand A transcript 在 hand B 实例下结算） | **reject** | **reject** | **reject** |
| 同 transcript 回到本 id | accept | accept | accept |

注：原型中重放被拒由 shuffle/reveal/leave 的 hand 前缀达成；ownership 挑战
当前不含 hand 上下文（见 §9-L2 缺口），生产实现必须补齐该一行改动。

### 13. 与 §11 SNARK 升级路径的兼容性

若 P 层未来 Groth16/Plonk 化，绑定结构**不变**：SNARK 公共输入取
`(hand_id, hand_binding, P_digest)`，一次（组常数个）配对验证替代算法第
5–6 步；L1/L3/L4 与结算算法完全复用。

### 14. 剩余工作

1. `pk_ownership.rs::challenge` 前置 hand_binding 字节（L2 缺口，一行）。
2. 生产 `hand_rho`：hand_id 位替换为完整 hand_binding（Poseidon252 摘要），
   纳入 Cairo 双端重算路径与测试向量。
3. 各 phase transcript 协议名接入 hand_binding 派生（Rust + Cairo 两侧同步）。
4. Cairo 侧 `e(L,H₂)`：cairo-bn254 路径成本实测，或按 §11 用 SNARK 包装。
5. 定理 1 的界（ρ 值域 2²⁵³ 而非 r）与方程序列规范写入结算规范文档。
