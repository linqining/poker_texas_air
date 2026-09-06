# SNIP-36 直连执行计划 —— 证明瘦身 → cairo 迁移 → v3 双门 → SNOS 形态 → 提交工具 → sepolia 全链路

状态：**已定稿（2026-09-06）**。任务来源 `docs/SNIP36_INTEGRATION.md`
（同日二次核对修订：协议已主网激活 2026-04-21，无协议等待项）。
基线实测：settlement 证明 2.30MB（575k felts）/ hand-verify 3.52MB（879k
felts）二进制本体；生产锚点 500KB ≈ 75M L2gas（130/byte + 10M base）；
证明尺寸与手数基本无关（1 手 14.3MB vs 10 手 14.1MB JSON 实测）——
批聚合摊薄单位成本是本计划的成本结构基石。

## 0. 总览与依赖图

```
P0 证明瘦身实测 ──────────┐（G0 档位决策）
                          ├──▶ P3 SNOS 形态 + 管线 ──┐
P1 cairo ≥2.12 迁移 ─▶ P2 合约 v3 双门 ────────────┼──▶ P4 提交工具 + 后端 ─▶ P5 sepolia 全链路
        （G1 迁移门）        （G2 槽位冻结）          ┘
```

| 阶段 | 内容 | 量级 | 依赖 |
| --- | --- | --- | --- |
| P0 | FRI 参数×尺寸矩阵、批尺寸验证、成本模型 | 1–2 天 | 无（立即可开始） |
| P1 | scarb/cairo ≥2.12、92 测试重验、字节码限 | 2–4 天 | 无（与 P0 并行） |
| P2 | v3 双门入口 + facts 槽位对拍 + snforge mock | 2–3 天 | P1 |
| P3 | starknet_os_runner + create_proof 形态 + 双证明合一 | 1–2 周 | P0(G0)、P1 部分 |
| P4 | Invoke V3 proof 字段扩展 + snops + 后端激活 | 3–5 天 | P2、P3 |
| P5 | sepolia 部署 v5 + 冒烟 + 成本对账 + 文档 | 1–2 天 | 全部 |

总量级 **3–5 周**；P3 是关键路径（可再拆并行，见 §3.6）。

## 1. Phase 0 —— 证明瘦身实测（决策输入，1–2 天）

此前 FRI 参数档（默认 pow26/q70、fast pow16/q40、ultra pow10/q30）只测过
**时间**（−11%/−26%），从未测过**尺寸**。这是整个路线的第一个量化门。

- **0.1 尺寸矩阵**：prove-hand 三档 × settlement/hand-verify 两个电路，
  产出紧凑二进制字节数（felt 计数 × 4B 的直接序列化，脚本进
  `proving-tool/`）。预期 queries 70→30 主导 ~2× 削减，叠加编码优化。
- **0.2 安全校准**：每档对应安全位数（规范默认 96-bit）定可接受下限——
  ultra 档（pow10/q30）若 <90-bit 则只许内部审计用（沿既有定性）。
- **0.3 批尺寸验证**：10 手/40 手批证明在选定档位下的尺寸——验证
  "尺寸与手数无关"在收紧档位仍成立（若成立：40 手 × 500KB ≈ 1.9M
  L2gas/手）。
- **0.4 成本决策表**：档位 × 批大小 → L2gas/手 → STRK 计价（按当前
  sepolia/mainnet gas 价），给出推荐组合。

**验收 G0**：尺寸决策表落档。若最优档仍 >1.5MB → 备选触发：批大小加大
（成本线性摊薄不变）或恢复 PLONK/gnark 终局评估（SNIP36_INTEGRATION
备选路径）。

## 2. Phase 1 —— cairo ≥2.12 编译器迁移（2–4 天，与 P0 并行）

`TxInfo.proof_facts` 消费（合约侧）与配套 snforge mock 的硬前提。

- **1.1 工具链**：scarb/cairo ≥2.12（`third_party/corelib-2.19.4` 的
  `info.cairo:323` 已含该字段，可对照）；openzeppelin 1.0.0 与 snforge
  版本配套升级矩阵先摸清。
- **1.2 测试重验**：snforge 92 个全过。已知风险：cairo 2.11.4 下
  `dual/hand_batch` 的 lowering crash（现被 `dual_legacy_tests` feature
  门控）——2.12 下验证是否解门控。
- **1.3 产物重验**：casm 哈希（sepolia 的 compiled-class hash 方案差异，
  部署脚本已有 Actual 重试模式）+ **字节码上限**（历史教训：dual casm
  曾 81,175 felts > sepolia 81,226 限——v3 新增入口后再逼近上限则需
  布局瘦身）。
- **1.4 仓库联动**：`texas/.env` 无需动；`StrarknetConfig` 不变；e2e
  冒烟的字面量与新 corelib 对齐。

**验收 G1**：2.12 下 build 0 错 + snforge 全绿 + casm 在限内。
**回退**：编译器迁移受阻则 P2/P4 后移，P0/P3.1–3.2（形态设计）不受阻。

## 3. Phase 3 —— SNOS 形态适配 + 双证明合一（关键路径，1–2 周）

SNIP-36 被证明对象是**虚拟 Starknet OS 程序**（`starknet_proveTransaction`
上下文），不是裸 prove-hand 产物——这是 #1 的实质，也是最大工程项。

- **3.1 starknet_os_runner 本地部署**（2–3 天）：规范的自托管 JSON-RPC
  2.0 prover（`starknet_proveTransaction(block_id, invoke_tx)` → base64
  proof + proof_facts + l2_to_l1_messages）。资源基线按 snip-36 参考
  后端 ~18GB 内存/40–50s 预估；先跑通官方示例再接我方请求。
- **3.2 create_proof 合约入口**（3–4 天）：settlement 电路逻辑包成合约
  入口——私有输入经 calldata；公开输出走**恰好一条 `to_address=0` 的
  L2→L1 消息**，payload = 15-felt 公开段（MAGIC/hand_id/digest/n/binding/
  cm×8/total/action_log）。fee estimation 禁用 + 手动 resourceBounds
  （2× gas 价）——私有输入不进 RPC 节点。
- **3.3 双证明合一**（3–4 天，ADR-2026-09-06-1）：hand_batch σ 折叠校验
  并进电路；`p_batch_commitment = poseidon(hand_binding,
  poseidon(p_batch words))` 由电路**内部重算**（批次词为电路输入），
  绝不作外部断言。公开段 15→16 felt（尾加承诺）或替换——与 P2 的
  segment 布局同步冻结。
- **3.4 最小可证明手**（2–3 天）：2 人、空动作日志，devnet/sepolia 各一，
  verify 走 OS runner 的输出自校验。
- **3.5 尺寸/耗时回归**：改造后电路在 G0 选定档位下实测，回填 0.4 决策表。
- **3.6 并行拆分**：3.1（基础设施）与 3.2（合约形态）可两人并行；3.3 依赖
  3.2 的入口形态冻结。

**风险表**：
| 风险 | 缓解 |
| --- | --- |
| 虚拟 OS 上下文 EC_OP/builtin 支持不明 | 3.1 第一周内做 1 条 EC 标量乘的 spike 验证；不支持 → 方案 B：σ 校验留 host + 双 fact 门（v4 形态回退，SNIP-36 只锚 settlement） |
| OS 形态证明耗时显著高于裸 prove（基线 13.6s/手） | 批聚合摊薄；GPU（icicle，评估已估 1–2 周）按需启动 |
| 消息哈希/facts 槽位与 skill 参考不一致 | P2 的 G2 真样本对拍前置到 3.1 完成后立即做 |

## 4. Phase 2 —— 合约 v3 双门入口（2–3 天，依赖 P1）

实现草图已冻结在 `SNIP36_INTEGRATION.md` §4。

- **2.1 v3 入口**：`verify_and_settle_dapv_stark_private_v3`——注册侧/
  公开段断言与 v2 全同；验证门 = SNIP-36 优先（`proof_facts` 非空且
  `facts[2] == circuit_program_hash` ∧ `facts[8] == message_hash(segment)`）
  → 不满足则降级 fact-registry（现有 v2 门原样）。
- **2.2 槽位冻结（G2）**：用 3.1 产出的**真实 proof_facts 样本**对拍
  slot 布局与消息哈希公式（`poseidon(合约地址, 0, payload_len, payload)`）
  后再写死断言——skill 的槽位索引是参考不是规范。
- **2.3 snforge mock**：2.12 配套 snforge 的 tx_info/proof_facts mock
  能力验证；不可 mock 则契约测试降级为纯函数测试（消息哈希）+ sepolia
  真链验证（P5 覆盖）。
- **2.4 测试矩阵**：正例（有效 facts 结算）+ 负例（错 program hash /
  错消息哈希 / facts 空 → 降级 fact-registry 路径）。

**验收 G2**：snforge 全绿 + 槽位对拍记录入档。

## 5. Phase 4 —— 提交工具 + 后端激活（3–5 天，依赖 P2+P3）

- **4.1 starknet-rs 扩展**：Invoke V3 附加 `proof`/`proof_facts` 字段
  （tx hash 计算 + 序列化）——starknet-rs 0.16 大概率未支持，需自定义
  ExecutionEncoder 或 fork；参考 proof-enabled starknet.js fork 的实现。
- **4.2 snops submit-proof**：输入 proof/proof_facts JSON → 组装扩展
  Invoke V3 → 提交（跳过 estimate、手动 resourceBounds）。
- **4.3 后端激活**：`STARKNET_DAPV_SETTLE_ENTRY=snip36` 真实路径——
  `settlement_prover.rs` 的 HTTP 存根换 `starknet_proveTransaction` 客户端；
  v3 选择器（已预埋）指向新入口；segment 布局若 3.3 扩为 16 felt 则同步
  `settle_entry_calldata`。
- **4.4 fact 登记退役路径**：SNIP-36 验证成功后不调
  `register_settlement_fact`（降级路径保留）；`set_hand_verify_program_hash`
  在合一电路上链后由 owner 退役。

## 6. Phase 5 —— sepolia 全链路（1–2 天）

- **5.1 部署 v5**：cairo ≥2.12 class declare/deploy（casm Actual 重试）
  + `set_claim_helper` + `set_circuit_program_hash`（SNOS 形态新 hash）。
- **5.2 冒烟**：`sepolia_settle_smoke` 扩 snip36 路径——真实证明 → 提交 →
  v3 入口 facts 断言通过 → escrow/claim_cms 落账。
- **5.3 成本对账**：实测 L2gas vs 0.4 决策表偏差，回填文档。
- **5.4 文档收口**：DEPLOYMENTS.md（v5 档案）、TODO/STATUS、
  SNIP36_INTEGRATION.md 状态翻转（缺口表 0/1/2/3b/4/8 → ✅）。

## 7. 里程碑与现有资产衔接

| 里程碑 | 交付物 | 对应 |
| --- | --- | --- |
| M0（P0 完成） | 尺寸/成本决策表 | 决定后续一切预算 |
| M1（P1+P2 完成） | 2.12 工具链 + v3 合约（mock 测） | 合约侧就绪 |
| M2（P3 完成） | SNOS 形态证明产出 + 最小手 | 证明侧就绪 |
| M3（P4 完成） | 提交工具 + 后端 snip36 激活 | 端到端联调绿 |
| M4（P5 完成） | sepolia 真链结算 + 成本对账 | 路线闭环 |

现有资产全部复用：三态开关（`snip36` 选项已预埋）、libfuncs `all`、
双证明合一 ADR、§4 合约草图、v2 回退门（任一阶段失败都退回
`STARKNET_DAPV_SETTLE_ENTRY=v2`，已上线的 fact-registry 路径不受影响）。
