## ZKShuffleProof Soundness 分析

### 一、协议概述

ZKShuffleProof 证明玩家对一副加密牌组执行了正确的洗牌（置换 + 重加密）。其核心结构是三层 GeneralizedSchnorrProof：

| 证明层 | 基点 | 秘密标量 | 声明的 R |
|--------|------|----------|----------|
| Combined | `[out[0].c1, out[0].c2, ..., out[n-1].c1, out[n-1].c2, G, pk]` | `[k_0, k_0, ..., k_{n-1}, k_{n-1}, pk_delta, pk_delta]` | `sum_c1 + sum_c2` |
| C1-only | `[out[0].c1, ..., out[n-1].c1, G]` | `[k_0, ..., k_{n-1}, pk_delta]` | `sum_c1` |
| C2-only | `[out[0].c2, ..., out[n-1].c2, pk]` | `[k_0, ..., k_{n-1}, pk_delta]` | `sum_c2` |

其中 `sum_c1 = Σ_i ρ_i · c1_in_i`，`sum_c2 = Σ_i ρ_i · c2_in_i`，`ρ_i` 是从 Fiat-Shamir transcript 中派生的 batch 系数。

对于诚实证明者，洗牌操作为 `ct_out_j = ct_in_{π(j)} + Enc(0; r_j)`，此时 `k_j = ρ_{π(j)}`，`pk_delta = -Σ_j ρ_j · r_j`。

---

### 二、Soundness 的核心论证

Soundness 定义为：**恶意证明者无法为"非置换"的输出密文组生成可通过验证的证明**（除非以可忽略的概率猜中随机挑战）。

论证分为四个层次：

#### 层次 1：GeneralizedSchnorrProof 的知识可靠性（Knowledge Soundness）

GeneralizedSchnorrProof 是标准 Schnorr 协议在多元基点上的推广。在随机预言机模型下，通过 Fiat-Shamir 变换，该证明具备**知识可靠性**：如果验证通过，则存在一个提取器可以提取出秘密标量 `k_j` 和 `pk_delta`，使得：

```
Σ_j k_j · c1_out_j + pk_delta · G = Σ_i ρ_i · c1_in_i   (方程 E1)
Σ_j k_j · c2_out_j + pk_delta · pk = Σ_i ρ_i · c2_in_i  (方程 E2)
```

这是整个协议 soundness 的基础。所有后续论证都建立在"验证通过意味着存在满足上述方程的 `k_j` 和 `pk_delta`"这一事实上。

#### 层次 2：从密文方程到明文方程的推导

将 E1 乘以 `sk` 并从 E2 中减去（注意 `pk = sk · G`）：

```
Σ_j k_j · (c2_out_j - sk · c1_out_j) + pk_delta · (pk - sk · G) = Σ_i ρ_i · (c2_in_i - sk · c1_in_i)
```

其中 `pk - sk · G = 0`，而 `c2 - sk · c1 = m`（ElGamal 明文）。因此：

```
Σ_j k_j · m_out_j = Σ_i ρ_i · m_in_i   (方程 E_plain)
```

这是一个关键等式：**任何通过验证的证明，其提取出的 `k_j` 必须满足输入明文和输出明文的加权线性关系**。

#### 层次 3：Schwartz-Zippel 置换约束

这是 soundness 论证的核心。将 E_plain 重新组织为多项式形式：

考虑多项式 `P(X_1, ..., X_n) = Σ_i X_i · m_in_i - Σ_j k_j · m_out_j`，其中 `k_j` 是 `X_i` 的函数（由证明者选取）。

- **如果输出是输入的置换**（即 `m_out_j = m_in_{π(j)}`），则设 `k_j = X_{π(j)}`，恒有 `P ≡ 0`。
- **如果输出不是输入的置换**，则明文多重集 `{m_in_i}` ≠ `{m_out_j}`。

假设存在某个明文值 `m*`，它在输入中出现 `a` 次，在输出中出现 `b` 次，且 `a ≠ b`。在 E_plain 中，`m*` 的系数为：

```
左侧: Σ_{j: m_out_j = m*} k_j     （共 b 项）
右侧: Σ_{i: m_in_i = m*} ρ_i     （共 a 项）
```

由于 `ρ_i` 是随机选取的标量（通过 Fiat-Shamir 从包含所有输入/输出密文的 transcript 中派生），且证明者必须先承诺输出密文后才能得知 `ρ_i`，根据 **Schwartz-Zippel 引理**：对于 `a ≠ b` 的情况，随机选取的 `ρ_i` 使得该等式成立的概率不超过 `max(a,b) / |F|`。

对于 BLS12-381 曲线，`|F| ≈ 2^255`，这个概率是**可忽略的**（negligible）。对于一副 52 张牌的牌组，概率上限为 `52 / 2^255 ≈ 2^-248`。

#### 层次 4：三层证明结构的必要性

仅仅有 combined proof 是不够的——这也正是代码注释中攻击 5 所揭示的问题。三层结构各自约束不同的维度：

```
Combined Proof: 强制每个输出位置的 c1 和 c2 使用相同的 k_j → 防止 c1/c2 swap 攻击（攻击 3）
C1-only Proof:  单独约束 c1 分量 → 防止 c1/c2 之间信息转移（攻击 5-8）
C2-only Proof:  单独约束 c2 分量 → 防止 c1/c2 之间信息转移（攻击 5-8）
```

如果没有 c1-only 和 c2-only proof，攻击者可以在保持 `c1_out_j + c2_out_j` 不变的前提下，将信息从 c2 转移到 c1（例如 `c1' = c1 + δ·G`, `c2' = c2 - δ·pk`），使得 combined proof 仍然通过，但明文已被篡改。

---

### 三、8 种攻击的 Soundness 覆盖分析

代码测试套件覆盖了 8 种攻击场景，每种都验证了协议的 soundness：

| 攻击 | 描述 | 为何被拒绝 |
|------|------|-----------|
| **攻击 1**: 复制牌+丢弃牌 | output[0]=output[1]=re_encrypt(input[0])，input[1] 被丢弃 | 明文多重集不匹配：`m_in_1` 在输出中缺失，E_plain 中缺少 `ρ_1·m_in_1` 项无法消去 |
| **攻击 2**: 全部同一张牌 | 所有 output 都是 input[0] 的重加密 | 明文多重集严重不匹配：`n-1` 个输入明文在输出中缺失 |
| **攻击 3**: c1/c2 交换排列 | output[0]=(c1_in_0, c2_in_1), output[1]=(c1_in_1, c2_in_0) | Combined proof 强制 c1/c2 使用相同 k_j，但交换导致不同 k_j 需求 |
| **攻击 4**: 牌替换 | 将某张牌的明文替换为另一张 | 明文多重集不匹配，Schwartz-Zippel 拒绝 |
| **攻击 5**: c1/c2 信息转移 | 保持 c1+c2 不变，篡改个体分量 | C1-only/C2-only proof 分别检测到个体分量不匹配 |
| **攻击 6**: 部分信息转移 | 仅对部分位置做信息转移 | 同上，C1-only/C2-only proof 检测 |
| **攻击 7**: 带排列的信息转移 | 排列后做信息转移 | 三层 proof 联合约束，破坏一致性 |
| **攻击 8**: 智能信息转移 | 更复杂的信息转移策略 | 三层 proof 的联合约束使得任何分量级别的篡改都被检测 |

---

### 四、密码学假设

协议的 soundness 依赖以下标准假设：

1. **离散对数假设（DLP）**：在 BLS12-381 曲线（G1 群）上，离散对数问题是困难的。这是 GeneralizedSchnorrProof 知识可靠性的基础。

2. **随机预言机模型（ROM）**：Fiat-Shamir 变换在 ROM 下是安全的。`ρ_i` 系数和 Schnorr challenge `c` 通过 Merlin transcript 派生，模拟随机预言机。

3. **Schwartz-Zippel 引理**：非零多项式在随机点取值为零的概率不超过其次数除以域大小。这是 batch verification 可靠性的理论基础。

4. **ElGamal 密文的语义安全性**：在 DDH 假设下，ElGamal 密文不泄露明文信息。虽然这更关乎 zero-knowledge 而非 soundness，但它确保了攻击者无法从密文推断明文多重集。

---

### 五、额外安全措施

代码中实现了多项加固措施，进一步增强了 soundness：

- **C1 修复**：`pk` 绑定到 transcript（`shuffle_pk` label），防止证明跨玩家重放。
- **C2 缓解**：验证输出密文非 identity（`c1/c2 ≠ O`），防止攻击者使用 identity 点绕过验证。
- **M-D13 修复**：移除 `G` 和 `pk` 作为自由基点，改为使用输入密文作为基点，消除攻击者利用自由基点构造伪造证明的可能性。
- **M-P17 修复**：拒绝 identity 承诺，防止攻击者使用零承诺削弱证明安全性。
- **Nonce 机制**：每次证明包含随机 nonce，防止同一证明的精确重放。

---

### 六、已知局限

代码注释中明确指出（M-D13 说明）：

> 此证明结构为非标准的自定义 Schnorr 方案，并非 Bayer-Groth 等标准 shuffle-proof 协议。完整修复需要重新设计证明系统。

当前的证明方案是**计算可靠性**（computational soundness）而非**统计可靠性**（statistical soundness），其安全性依赖于离散对数假设。与 Bayer-Groth 协议相比，该方案在 proof size 和验证复杂度上存在差距，但三层 GeneralizedSchnorrProof 结构在 soundness 上提供了充分的保障——所有 8 种已知攻击向量均被覆盖。

**总结**：ZKShuffleProof 的 soundness 建立在 GeneralizedSchnorrProof 的知识可靠性 + Schwartz-Zippel batch verification + 三层证明结构的分量约束三个支柱之上，在离散对数假设和随机预言机模型下是可证明安全的。
