# 不依赖交易回放的信任模型

本文针对 `zgame_aleo` 当前 Varuna/Aleo-native 流程，说明如何把“host
回放交易后才接受证明”的信任边界，改成“不回放交易，但仍能验证状态迁移”的边界。
这里的“不回放”是指服务端不再重新执行交易 payload 来推导 post-state；它不等于
不验证交易的共识包含性，也不等于信任 RPC 返回的任意 mapping。

**状态：分层迁移已落地，完整业务 AIR 仍未完成。** 独立 workspace 现在提供
`TexasTransitionReceipt`、历史 mapping inclusion proof 和不可构造的
`AuthenticatedTexasReceipt`。它们可以把直接 tagged proof 绑定到 finalized
state root，而不执行交易回放。旧 `ProveTask`/VM replay 路径仍保留给兼容和审计；
由于 tagged AIR 尚未覆盖完整 `TexasPokerTable`、结算和密码协议，当前入口仍不能
宣称已经证明完整 VM 共识迁移。

## 当前边界

### `poker_texas_air` 直接路径的新增边界

`texas_tagged::verify_tagged_texas_proof` 现在可以只使用归档中的公开 scope
和 Stwo proof 完成验证，不再读取 `ProveTask`、交易 payload 或执行 native VM
replay。这只消除了 verifier 的回放依赖；它没有把 prover 提供的
`TexasStateImage` 变成链上事实。当前 AIR 仍只投影 acting seat、资金和
leave-mask 字段，Blake2 state-image digest 也不是 AIR 内的 state-root 计算。
archive 中的 table/hand/call-seq 也只是 Fiat-Shamir scope，尚未成为每一行
的 AIR state-column 约束。

因此该入口的安全结论是“证明了当前投影关系”，而不是“证明了完整
`TexasPokerTable` 的共识迁移”。只有 `authenticate_receipt` 成功产生
`AuthenticatedTexasReceipt` 后，生产 admission 才能绑定该 archive；单独调用
`verify_tagged_texas_proof` 仍必须 fail-closed，不能更新 confirmed head。

当前 receipt ABI 还要求 mapping 中的 `receipt_value` 等于包含完整 statement 的规范 digest，
并要求 statement 的 transition、pre/post state、lifecycle、overlay roots 分别等于 receipt
字段；只有这些等式和历史 state-root path 同时成立，才允许构造不可伪造的 authenticated
wrapper。

独立项目还提供 `authenticate_receipt_l1`。生产适配器必须使用
`TexasL1ReceiptInclusionProof`，它直接调用
`poker_l1::object_model::SparseMerkleTree::verify`：固定 256 层、
`H(0x00 || key || value)` 叶哈希、`H(0x01 || left || right)` 内部哈希，且
mapping value 固定为 statement-bound `receipt_value` 的 32 字节编码。旧的
`TexasReceiptInclusionProof` 只保留作通用 ABI/测试，不足以证明真实 L1 state root。

当前实现已经把几个边界分开，但生产路径仍有以下事实：

| 组件 | 当前信任内容 | 证明能否独立排除伪造 |
| --- | --- | --- |
| `aleo-varuna` R1CS/Varuna | 固定 circuit、VK、manifest，以及 prover 提供的 witness | 只能证明 circuit 约束；不能证明 witness 对应某笔 Aleo 交易 |
| Leo state kernel | `table_head` CAS、seq/hand、nullifier、authority、deadline、链上 `snark.verify` | 能约束已提交 effect；不认证 host 传入的外部交易来源 |
| coordinator | job、tentative/confirmed head、exact signed transaction sidecar | 负责持久化和顺序，不是共识证明 |
| `aleo-runtime` finality observer | 交易所在 canonical block、执行状态、同高度 `table_head` 写入 | 目前还检查 transaction/function/transition body；这属于 replay/transaction-shape 依赖 |
| native witness builder | 从游戏状态生成 opening、plan digest 和 public inputs | 如果 AIR 没有重算对应算法，builder 仍是信任边界 |

因此，当前的“proof verified”不能直接解释为“这笔链上交易按预期改变了状态”。

## 目标边界

目标流程应是：

```text
固定部署 manifest/VK
  -> Varuna proof 约束完整 pre/post transition
  -> Aleo program 在 finalize 中验证 proof 并写 authenticated receipt
  -> 共识最终确认 block + state root + receipt mapping
  -> runtime 只验证 receipt 的包含性和字段等式
```

安全性依赖 Aleo 共识正确执行已认证的 program，而不依赖服务端重新解释交易参数。
服务端仍然必须验证 canonical block、确认深度和历史 state root；移除的是业务语义 replay，
不是共识 finality 验证。

## 必须修改的部分

### 1. Leo state kernel：写入不可变 transition receipt

新增 `transition_receipt_v1` 及按唯一 key 存储的 mapping。receipt 至少应包含：

- `table_id`、`hand_id`、`pre_seq`、`post_seq`
- pre/post `state_root`、`lifecycle_root`、`overlay_root`
- `rules_commitment`、`fee_config_hash`
- `circuit_id`、`manifest_digest`、`effect_kind`、`authority_kind`
- `authority`、`transition_commitment`、`nullifier`、`deadline_height`
- terminal/next-hand 所需的 settlement、custody、opening commitment

每个 `commit_*_v1` 必须在同一个 finalize 原子地：

1. 检查旧 `table_head` 精确匹配；
2. 检查 relation binding、manifest、authority 和 `snark.verify`；
3. 检查 nullifier/receipt key 未使用；
4. 写入新 `table_head`、`spent_nullifier` 和完整 receipt。

receipt 不能由第二笔“登记交易”补写，否则会重新引入竞态和跨交易信任假设。terminal、
showdown、next-hand 的经济 receipt 也必须由同一个已验证 transition 写入，不能由 host
根据事件再拼接。

### 2. Public statement：把原来依赖 replay 的字段放进证明

每个 relation 的 public input 必须显式绑定：

```text
table/hand/seq + pre/post full state roots
rules/fee/overlay commitments
actor/authority statement
canonical action or timeout statement
transition commitment + nullifier
manifest digest + circuit id
```

`transition_plan_digest`、`trusted_row`、仅由 host 生成的 settlement summary 不能继续作为
“已验证事实”。如果字段仍然是 opaque digest，就必须有同一 relation 的约束证明其生成规则；
否则应从 public ABI 删除。

### 3. AIR/R1CS：接管 replay 曾经提供的业务约束

删除生产路径对 `validate_*`/`replay_tasks` 的依赖之前，必须把这些语义移入可验证关系：

- action legality、turn/round/phase gating；
- amount、stack、bet、pot 的全 limb 加减、非负和范围检查；
- round advance、timeout 与 deadline 的互斥；
- terminal 的 side-pot、rake、odd-chip、winner payout 和 custody conservation；
- deck/runout/hand-rank 的 transcript commitment；
- pre/post state opening 和 state-root 计算（或者一个已审计的递归 state-transition SNARK）。

特别是 Poseidon state root 不能只在 host 端重算后塞进 public input。若暂时做不到，必须把
该路径明确标为“host-attested”，不能宣称 no-replay trustless。

### 4. Finality observer：从 transaction replay 改为 receipt inclusion proof

`aleo-runtime` 应停止把 `validate_execution_target`、transition body shape 或重新解析
交易参数当成业务认证来源。新的 `AleoFinalityObservation` 应返回并校验：

- transaction ID、canonical block hash/height、确认深度、历史 state root；
- `transition_receipt` 的历史 mapping value；
- receipt key 和 value 的 Merkle/state-root inclusion proof；
- receipt 与 job public statement 的逐字段相等；
- receipt 对应的 program/manifest registry 已在共识状态中固定。

不能从“当前 mapping 查询结果”证明历史交易结果；必须读取与 finalized block 同高度的状态。
如果使用 explorer/RPC，必须改成能验证 block/state-root/receipt inclusion 的 light-client
接口；否则 RPC 仍是隐藏信任点。

transaction ID 在此模型中只用于定位和幂等 outbox，不再承担“交易参数语义正确”的证明。
exact signed bytes、broadcast retry、unknown 状态回查和冻结逻辑仍必须保留。

### 5. Coordinator admission：只接受 authenticated receipt

新增不可构造的 `AuthenticatedTransitionReceipt`（只能由 finality verifier 生成），admit
时检查：

- receipt table/hand/seq 与 tentative/confirmed head 严格连续；
- pre/post roots、manifest、circuit、authority、overlay 与 proof artifact 完全一致；
- receipt block/state-root 已 finalized，且包含证明通过；
- nullifier、job id、transaction id 不能跨桌/跨手重用。

`ProveTask` 可以继续作为 prover 的输入/缓存，但不能再作为 receipt provenance。生产 admission
不能从 task 自己构造 pre/post snapshot，也不能用 replay 后的本地状态替代链上 receipt。

### 6. 授权与部署

- actor signature 必须绑定到 proof statement；outer Aleo transaction signer 只负责执行/付费，
  不能被当成玩家 authority；
- relation registry、VK、program digest、manifest digest 必须 immutable 且版本化；
- authority policy（actor/operator/permissionless）必须由 state kernel 按 effect 固定检查；
- timeout 必须同时由 proof statement 和 `block.height > deadline_height` 约束；
- old/new program、VK、manifest 不能混用，升级必须产生新的 manifest/circuit domain。

## 迁移顺序

1. 先实现 receipt struct/mapping 和历史 state-root inclusion proof，保留现有 replay 作为双重校验；
2. 让每个 relation 的 proof public ABI 覆盖完整 pre/post、authority、economic commitment；
3. coordinator 改为“receipt + proof”双绑定，replay 仅作为 audit/debug；
4. runtime 默认走 receipt-only，保留显式 `audit_replay` 工具，不让其进入生产 admission；
5. 补 adversarial tests：伪造 receipt、拼接不同 job、乱序、旧 receipt 重放、RPC 最新状态替换历史状态、
   manifest/VK 替换、authority 替换、terminal/next-hand 跨手替换；
6. 只有在所有经济关系和 state-root relation 已在 proof/链上约束后，才移除 replay 代码。

## 不能接受的“简化”

以下做法不是 no-replay trust model：

- 仅删除 host replay，继续信任 task 携带的 post-state/settlement plan；
- 仅检查 transaction 已 finalized，不检查 receipt 字段和历史 state inclusion；
- 仅读取最新 `table_head`，不绑定交易所在 block height；
- 把 explorer 返回的 function/transition JSON 当成共识证明；
- 用一个通用 circuit/VK 接受多个 effect，再由 host 选择解释方式。

这些改动会把原来的“信任 canonical replay”降级成“信任 prover、服务或 RPC”，而不是减少
信任假设。
