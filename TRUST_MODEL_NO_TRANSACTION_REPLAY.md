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

`texas_tagged::verify_tagged_texas_proof` 和
`texas_canonical_air::verify_canonical_tagged_proof` 现在可以只使用归档中的公开
scope 和 Stwo proof 完成验证，不再读取 `ProveTask`、交易 payload 或执行 native VM
replay。前者只证明 betting/funding/leave 的投影关系；后者证明 20-kind canonical
trace 的形状、selector、序号、表作用域和相邻 state-image commitment 链接，并证明
下注完成后所有 seat `bet` 被精确收集进 pot；它还在 AIR 内约束 permissionless/actor
authority、settlement commitment 不变，以及 transition/nullifier 非零。canonical
trace builder 不再把 `validate_batch` 当作 admission prefilter，只保留固定宽度 ABI
guards（例如 crypto commitment、AdvanceRound opening/padding）；
`CanonicalTransitionWitness::validate_shape` 仍是可选结构检查，不应被当作完整
VM 语义证明。未列入 AIR 的 selector relation 仍必须在生产 admission 中 fail-closed。
这只消除了 verifier 的回放依赖；它没有把 prover 提供的
`TexasStateImage` 变成链上事实。当前 AIR 已为 betting 与可寻址 lifecycle
actions 打开全部九个 seat 的 mutable image（状态、stack、bet、total_bet、pending
addon、time bank），并约束 Create/Start 的 seat 不变性、目标 lifecycle
action 的非目标 seat 不变性、StartHand 的非零 deadline，以及
`SetLeaveAfterHand` 的精确九位掩码写入。`AdvanceDeadline` 还以 64-bit limb/
carry/range relation 证明 action height 不早于 pre deadline；但它
还未为 identity/key/hole-card 与 crypto-state commitment 的所有可变 VM 分支建立
专用关系，也未在同一 AIR 内重算 state image 的 Blake2b digest/state root。

`FoldWithProof` 已不再被误分类为“非 Betting crypto 行”：其非终局分支在 AIR
中遵循 current turn，要求目标 `Active -> Folded + acted`，保持所有 chip/seat
identity material，不允许改动 board/reveal/reconstruct/run-it-twice commitments，并
只允许 deck commitment 被 leave-DLEQ 层移除替换。三个 submit 标签也直接约束其
pre phase（shuffle/reveal/reconstruct）、非空提交座位和非零、16-bit range-bound 的
proof commitment；它们不能借由 protocol payload 改动筹码、座位、board 或普通
状态字段。这些只是 transition shape/anti-null 边界，**不**验证 DLEQ、shuffle、
reveal 或 reconstruction 的 Ristretto 方程。

尤其 `zchain` 的 `advance_deadline_in_place` 不是一个单一的“过期后不变”
转换：它先运行有限次 normalization，随后按 reconstruct、shuffle、reveal、betting
或 showdown deadline 分支；betting 还要区分消耗 time bank / 延长 deadline 与
自动 fold，其他分支会 kick、refund/reset、reconstruct 或结算。当前 canonical
`AdvanceDeadline` 行没有这些选择器、完整输入状态或确定性输出约束。因此任何把
它作为 finalized-head 更新的入口都必须 fail-closed，不能把
`deadline_height >= pre.deadline` 当成完整 VM timeout 证明。

canonical archive 中的 batch digest、state-image commitment，以及 state、lifecycle、
overlay、settlement、custody 五个域的首尾根都已进入 Fiat--Shamir transcript、公开
scope、trace 连续性约束和 canonical receipt binding，因此不能再把有效 proof 与另一组
根/receipt 拼接。AIR 仍未重算这些 Blake2b 值，也不能单独作为 admission 的语义来源。

因此当前入口的安全结论是“证明了当前编码的 AIR 关系”，而不是“证明了完整
`TexasPokerTable` 的共识迁移”。只有 `authenticate_receipt` 成功产生
`AuthenticatedTexasReceipt` 后，生产 admission 才能绑定该 archive；单独调用
`verify_tagged_texas_proof` 仍必须 fail-closed，不能更新 confirmed head。

当前 receipt ABI 还要求 mapping 中的 `receipt_value` 等于包含完整 statement 的规范 digest，
并要求 statement 的 transition、pre/post state、lifecycle、overlay roots、固定宽度
`state_object_key` 与 `state_opening_epoch` 分别等于 receipt 字段；只有这些等式和历史
state-root path 同时成立，才允许构造不可伪造的 authenticated wrapper。新的
`canonical_state_opening` 组合器再验证同一 object key 在 pre/post roots 下的两条 257-
compression Blake2b AIR opening，并把 opening value 绑定到 canonical pre/post image
commitment。它消除了 root-opening splice，但不宣称已经在 AIR 内重算完整
`CanonicalStateImage::commitment()`；固定宽度 state-leaf epoch 仍必须由 L1 manifest/receipt
注册。

`canonical_state_hash` 现已能用同一套 lookup Blake2b proof 认证精确的
`"zchain.texas.canonical-state.v2" || Borsh(CanonicalStateImage)` 预像；
`prove_canonical_batch_with_state_image_openings` 将此 byte→commitment proof 与
pre/post SMT opening 组合，得到 byte→commitment→root 链。canonical transition
AIR 已将 ABI/header、table、phase、资金、五类 root、九个 seat 的完整公开 image
（含 identity/key/hole-card commitment），以及 board/deck/reveal/reconstruction/
run-it-twice 五个 commitment（共 841 个 endpoint limb）回绑到这些 Borsh bytes；
对下注、funding、join/leave、force/kick、SetLeaveAfterHand 与 AdvanceRound，
已知不变的 commitment 字段也被约束为不变。完整 bytes 也进入 Fiat--Shamir scope。
Shuffle/reveal/reconstruct 的 phase/seat/proof-presence shape，以及非终局
`FoldWithProof` 的 betting/state-preservation shape 已受约束；它们的密码学与
完整 VM phase-completion/timeout/settlement 关系仍未受约束，故这个新组合仍不是
host-zero admission 证据，
`admit_canonical_proof_with_state_openings` 会明确 fail-closed。

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

对 `texas_canonical_air`，20 个 selector family relation 已有 canonical AIR
dispatch；其中 `AdvanceRound` 还在 AIR 中选择固定的 preflop/flop/turn（含
run-it-twice）board-reveal schedule，并约束 card cursor、board position、pending
mask、submitted mask 和 padding。archive 已将 admission 所需的 pre/post state、
lifecycle、overlay、settlement、custody root 公开绑定到 trace；下一步仍需将它们及
board/deck/reveal assignment inclusion 同完整 state opening / Blake2b root relation
绑定。否则恶意 prover 可以生成满足当前结构 AIR 的 trace，而经济或密码语义仍只能由
host 断言。

`AdvanceRound` 的 deck cursor 本身已在 AIR 中作 6-bit/`<=52` 约束；这只消除了
field-range 伪造，**不**证明 cursor 或 assignment 是 L1 加密 deck 的成员。生产 L1
当前将 poker table 分为一个可变长度 hot-state object 和 metadata/rules/governance
三个 context objects；host-zero 的 Blake2b opening component 必须认证这些实际对象的
key、value、leaf hash 和 256 层路径，或在新 table epoch 中部署等价的固定宽度 state
object。仅将 host 计算的 object digest/root 写入 public input 不满足该要求。

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
