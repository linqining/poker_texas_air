# Texas 源状态瘦身、命令归一化与批量证明设计

## 目标

在实现 Tagged-union Stage proof 与 heterogeneous method batch 前，先让
`poker_l1::texas_poker` 的 canonical 状态满足三条原则：

1. 一个事实只保存一次；可从 canonical 状态确定性派生的缓存不进入 state root。
2. 互斥状态使用 enum/tagged union；正交开关才使用 bit flags。
3. 每个外部命令执行后都运行 `normalize_until_blocked`，一次性推进所有不依赖新签名、
   proof 或时间到期的内部步骤。

外部 selector 可以在迁移期保留兼容 wrapper；proof 的 method tag 应绑定归一化后的内部命令，
而不是永久复制 23 套业务实现。

## 已安全删除的字段

本轮还补齐了 schema v7 -> v8 的真实解码路径：旧 v7 的平铺 reveal assignment 使用独立
legacy mirror 解码，经过 `migrate_reveal_state_v7`/`migrate_hand_phase_v7` 后再进入 v8 的
`HandPhase`。因此 v7 bytes 不会被 v8 parser 误接受，也不会因为升级缺少 fallback 而被拒绝。

schema v3 已删除以下 derived/transient 数据：

- `TexasPokerTable.side_pots`：由 `Seat.total_bet` 和 seat eligibility 确定性重建。
- `Seat.refunded`：退款在同一原子 transition 内完成；迁移拒绝有未清 wager 的歧义状态。
- `DeckState.plaintext`：52 个 BLS12-381 明文点是协议常量。
- `Timestamps.ready_at`、`hand_complete_at`：生产状态机未读取。
- `RunItTwiceState.trigger_round`：由 `shared_board_len` 的 canonical 边界推导。
- `TableConfig.zk_skip_*`：测试跳过属于编译期属性，不应成为共识状态。

schema v4 进一步把 seat 生命周期压成 `SeatStatus`。schema v5 删除了 `SeatFlags`，把
`acted_this_round` 与 `want_leave` 提升为桌级 `u16` mask，同时把 current turn/current shuffler
改成 `NO_SEAT`，把 shuffle/reveal/reconstruct participant vectors 改成 seat masks。
v2/v3/v4 -> v5 迁移精确读取旧布局，并对不规范 plaintext、refund、RIT、重复/越界 participant、
unknown flag bits 和冲突 seat 生命周期组合 fail-closed。

## 已完成的 schema v6/v7 与命令归一化

schema v6 已完成以下 canonical 化，并提供 v5 -> v6 精确迁移：

- `Card` 已改为 `CardId(u8)`，持久化值只允许 `0..51`；
- hole cards 与两张 board 均使用固定容量、canonical padding；
- RIT 只保存共享前缀长度与 second-board suffix；
- 所有成功 selector 末尾统一执行有界、原子的 `normalize_until_blocked`；
- 当前 19 个 fresh selector 已先解码为稳定的 `CanonicalCommand` tag；
- `tick`/`auto_fold` 的超时逻辑已汇入 `AdvanceDeadline`，`force_fold` 复用统一 fold transition；
- WAITING 状态没有隐式 deadline，`tick` 不再启动牌局；当前生产语义要求显式 `start_hand`。

生产 selector 集已按该模型冻结：新增 canonical `advance_deadline`，旧 `tick` 已从 fresh 与
archive/replay 解码面物理删除；`auto_fold` 与普通 public `reset_for_next_hand` 也已从
CanonicalCommand、MethodKind、独立 AIR 与证明编排器物理删除。`join_and_shuffle` 与 WAITING `leave_with_proof` 已进一步从
source dispatch、canonical/task decoder、AIR、precompile、dual-proof package 和 proving service
物理删除；稳定 discriminant 5/10/15/16 不重排，但在所有入口 fail-closed。

schema v7 已把持久化/state-root/prove-task 编码收敛为唯一 `HandPhase` tagged union：每个 active
variant 只保存一个绝对 `deadline_ms`，reconstruct 额外保存 proof transcript 所需的 `epoch_ms`。
五个生产 timeout 已缩窄为 checked `u32`；从未被生产状态机读取的 `ready_wait_ms` 与
`hand_complete_wait_ms` 不再持久化。v2-v6 exact migration 会立即 canonicalize timeout，并对
deadline 小于 timeout、reconstruct epoch 溢出、timeout 超过 `u32` 等输入 fail-closed。

运行时物理收口现已完成：`TexasPokerTable` 只保存 `hand_phase: HandPhase`，旧的
`round_state/betting_round/current_turn/shuffle_state/reveal_token_state/reconstruct_state/timestamps`
平铺字段已从结构体删除。AIR、composition、orchestrator、precompile binding、proving service 与状态机
统一通过 variant-aware accessor 和 `enter_*` API 读取/切换 phase；同 variant 更新使用
`active_*_mut`、`set_betting_turn`、`remove_seat_from_active_phase` 与 phase-specific deadline API。
因此 reveal + betting、reconstruct + shuffle 等非法重叠已无法在新运行时结构中表达。

schema v9 已完成 reveal ledger 的 fail-closed 类型迁移。v2-v8 的旧
`ciphertext: Option<_> + plaintext: Option<_>` 使用精确 legacy mirror 解码：`Some/None` 迁移为
`Partial`，`None/Some` 迁移为 `Plaintext`，旧 `None/None` tombstone 被清除，`Some/Some` 非法组合
直接拒绝。新 v9 bytes 也有回归测试保证不会被旧 v8 parser 接受。因此运行时 enum 压缩现在已进入
真实共识 schema，而不只是源码层类型替换。

schema v10 已完成 deck contributor lineage 的 canonical 化：持久化 deck 只保存
`contributor_mask`，`aggregated_pk` 不再进入 Borsh/state root，而是在 decode 后由 mask 中每个
occupied seat 的非 identity `seat.pk` 确定性重建。v2-v9 migration 最多枚举 9-seat 的 511 个非空
子集，只有 aggregate 恰好对应唯一 contributor 子集时才接受；无匹配、多解和 identity aggregate
全部 fail-closed。join/leave/fold-with-proof/kick/reset 均原子维护 mask，普通 fold、shuffle、reveal、
reconstruct 不改变 lineage。跨局 reset 会从所有仍占座且公钥有效的玩家重建新牌组 lineage，避免
`fold_with_proof` 玩家留座后永久丢失下一手密钥贡献。

schema v11 已物理删除运行时与持久化 `ShuffleState.current_shuffler`。当前洗牌者始终是
`first(pending_mask)`，因此不再需要写同步字段，也不再需要 normalize 为“选择 actor”单独产生一个
micro-step。v5-v10 的精确 legacy phase mirror 仍读取旧字段；迁移只接受它等于 pending mask 的最低
seat（空 mask 时必须为 `NO_SEAT`），随后丢弃，任何错配均 fail-closed。

WAITING 状态不再用隐藏的 `ShuffleState.completed_mask` 镜像长期 contributor lineage。
`DeckState.contributor_mask` 只描述 aggregate-key 成员并派生验证公钥；active shuffle variant 内的
completed mask 则只描述当前手牌新牌组的提交进度。由于 `start_hand` 会重新生成 canonical
plaintext-base deck，新一手的 completed mask 必须从零开始、pending mask 覆盖所有 active seat；
不能从长期 contributor mask 复制，否则会把尚未应用到新 deck 的加密层误判为已提交。WAITING
离场只走 `leave_table` 并原子移除 contributor membership；active hand 中移除 live deck layer 只走
`fold_with_proof`，并按 contributor lineage 验证成员资格。

外部命令序号也已完成收口。schema v17 已物理删除桌内逻辑 `version`；所有真正改变状态的
dispatch 只在原子提交边界写入 `post.call_seq = pre.call_seq + 1`，内部 normalize、reset、settlement
执行多少个 micro-stage 都不再改变该事实。历史 no-op `tick` 不递增序号、也不产生 proof task，
当前 selector 已不再接受它。Kick/reveal/advance-deadline 的复合分支改由 canonical replay events 与
四阶段 composition plan 判定，禁止再用
`version + 2/+N` 猜测 settlement。这使 method batch 的每一行都能使用固定的命令序号约束，Stage
顺序只由 batch id/row index 表达。ObjectDb 的 `Object.version` 继续承担 CAS/乐观锁职责；现有 proof
ABI 中仍名为 `pre_version/post_version` 的 legacy 兼容槽位承载 `call_seq`；tagged method ABI 已直接
使用 `pre_call_seq/post_call_seq`。

schema v18/v19/v20 已依次完成三项 custody 去重：v18 删除 `addon_pool`，以九个
`Seat.pending_addon` 的 checked sum 作为唯一 pending 明细；v19 删除 `ante_collected`，StartHand AIR
只接受由 `post_pot - pre_pot` 与逐 seat debit 确定性派生的 transition-local ante；v20 删除
`rake_collected`，Treasury 出金改由 `DispatchOutput` 事件导出的唯一
`SettlementTreasuryReceipt` 驱动。历史 production 数据已明确不再支持，v2-v22 migration codec
已从执行 crate 删除；任何非当前 resolved-v29 / ObjectDb hot-v30 输入都直接 fail-closed，不再把
旧 schema 的冗余镜像带入生产二进制。Receipt 同时绑定 showdown 的 `SettlementPlanCommitted` 或无摊牌的
`HandEndedWithoutShowdown`，重复、缺失或金额不匹配均在创建 UTXO 前拒绝。

schema v21 已把 reveal 的完成态彻底降为 dispatch-local：canonical assignment 只保存
`pending_mask/submitted_mask/reveal_tokens`，公共牌与 showdown 明文在 proof 验证后的同一 dispatch
直接写入 board/hole 并删除 assignment；fresh state 不再编码 `ReadyPartial/ReadyCard` 或 plaintext
ledger。旧 v20 完成态因无法证明它仍与当前 authenticated crypto request 对应而 fail-closed。

schema v22 先完成了 `SeatSlot` tagged-union 的 persisted/state-root 表示。resolved schema v25 与
ObjectDb hot schema v26 进一步把 runtime `Seat` 物理替换成同一个 `Vacant/Waiting/Playing/
DepartedThisHand` enum，并删除 codec 中重复的 persisted-seat mirror。每个 variant 只携带有意义的
payload：空座位只保留 time bank，Waiting 不携带 hand/bet，Playing 才携带 hand-local wager/status，
局中离场只保留 player、side-pot 所需 `total_bet` 和 time bank。生产与 AIR 统一通过 accessor、
`playing_mut/occupied_mut` 和 checked setter 访问；非 live seat 读取 Mental Poker key 返回 `None`，所有
crypto binding 点显式 fail-closed。v23/v24 flat-runtime bytes 与新布局不共享 schema tag，直接拒绝。

schema v23 已把 `max_players`、blinds、timeouts、ante、rake 与 RIT policy 物理收口为一个
`TableRules` 值，并从 `TexasPokerTable` 删除对应 flat fields。runtime 暂时通过
`Deref/DerefMut<Target = TableRules>` 保持 `table.big_blind` 等旧调用点可编译，但 canonical Borsh/state
root 已只编码一份 `rules`。v23 对非法 capacity/blinds/mode tag 和 `rake_bps > 10000` fail-closed；
v22 及更早 bytes 统一拒绝。该步骤只是“规则字段去重并建立对象边界”，还不等于 rules 已移出 hot table；真正
降低每个 transition state-root preimage，仍需后续独立 `TableRules` object/opening/hash binding。

当前 ObjectDb hot schema v30（低频对象拆分首次落地于 v24）只保存 hand-local mutable state
与三组 `{object_id, digest}`；`TableMetadata`、`TableRules`、`GovernancePolicy` 作为确定性 ID 的
immutable object 独立存储。precompile 每次执行先认证 type/ownership/ID/opening digest 再 hydrate
resolved runtime table；旧 full-v23 ObjectDb object、缺失 opening、替换 opening、错误 object type 或
ownership 均 fail-closed。create-table 以同一 capture/batch 创建四个对象，普通 transition 只修改 hot
table，三个 context object 只进入 read set。

AIR 的 resolved image 继续携带完整 table，供 host-native verifier 重放业务与密码学 binding；公开
state root 已切换为 `Poseidon252(canonical(hot-v30 bytes))`。因此 low-frequency value 只通过固定宽度
digest 进入每个 transition root，不再重复展开。consensus anchor wire 已直接破坏旧布局：每个 endpoint
必须提供 hot table、metadata、rules、governance 四份独立 SMT inclusion proof，并证明四者属于同一
authenticated block state root 后才可 hydrate。create-table 前态是 ObjectDb absence，只允许一个精确
placeholder 并映射为零 root。

当前决策是不支持旧 production ObjectDb/consensus-material 在线迁移。legacy codec mirror 可暂留用于
离线回归，但不得重新进入 production load path，也不得阻止后续 runtime tagged-union 重构。

## 下一步字段处理

### A. 保守方案：应优先完成

| 当前字段 | 建议表示 | 原因与约束 |
|---|---|---|
| ~~`Seat.folded/all_in/is_waiting/left_during_hand`~~ | 已完成：`SeatStatus: u8` | enum 已消灭 `folded && all_in` 等非法组合。|
| ~~`Seat.acted_this_round/want_leave`~~ | 已完成：桌级 `acted_mask/leave_after_hand_mask: u16` | 九个 seat 的正交 bool 分别只占一个 bit；空 seat 的 live bit 被拒绝。|
| ~~`current_turn: Option<u8>`~~ | 已完成：`u8` + `NO_SEAT = 0xff` | Borsh `Option<u8>` 使用 tag+value；固定哨兵更适合一列 AIR。|
| ~~`ShuffleState.current_shuffler`~~ | schema v11 已删除 | 始终由 `first(pending_mask)` 派生；旧 schema 字段仅用于迁移校验。|
| ~~`pending_players/completed_players: Vec<u8>`~~ | 已完成：`u16` seat mask | 最多 9 seat；mask 消除重复、顺序和变长编码。|
| ~~每个 reveal/reconstruct pending vector~~ | 已完成：`u16` seat mask | 提交即清 bit；越界 bit 在 state codec 和 canonical validation 拒绝。|
| ~~`Card { suit, rank }`~~ | 已完成：canonical `card_id: u8` (`0..51`) | suit/rank 由 canonical id 确定性派生。|
| ~~`Seat.hand: Vec<Card>`~~ | 已完成：`HoleCards { len, cards: [u8; 2] }` | 固定上界并拒绝非零 padding。|
| ~~`community_cards: Vec<Card>`~~ | 已完成：`BoardCards { len, cards: [u8; 5] }` | 固定上界并提供唯一编码。|
| ~~`second_board_cards`~~ | 已完成：仅保存非共享 suffix | shared prefix 只保存在 board 1。|

最大 9 人桌的两个正交 seat bool 已从 18 个独立字段降为两个 `u16` mask；更重要的是 AIR
不再为每个 seat 携带两个常驻 bool 列。mask 与固定数组还会消除 vector 顺序、重复和长度的
额外 canonicality 检查。

### A.1 当前源码的明确字段决策

| 分类 | 字段 | 决策 |
|---|---|---|
| 必须保留 | `stack/bet/total_bet/pot/chip_pool` | 保持 checked `u64`；这些是资产与 side-pot 的 canonical 输入，不能为了减列缩窄。|
| 必须保留 | seat `player/pk`、当前 encrypted deck | Mental Poker custody 与 proof request 的 canonical statement。|
| 已从 persisted/runtime state 删除 | `aggregated_pk` | `DeckState` 只持久化 `contributor_mask`；所有 crypto statement 在使用点由 mask + seat pk 现场派生。|
| schema v17 已完成 | 桌内 `version` | 已物理删除；证明顺序只保留 `call_seq`，ObjectDb `Object.version` 继续用于 CAS。|
| 已删除 | `ShuffleState.current_shuffler` | schema v11 使用 `first(pending_mask)`；v5-v10 迁移校验后丢弃旧字段。|
| 可立即派生 | `RevealTokenData.seat_index` | token 按 seat slot 或 seat-index 升序存放后，提交者由 slot/bitmap 决定。|
| normalize 后可删 | `RevealAssignment.decrypted` | `pending_mask == 0` 时立即 materialize card 并移除 assignment，不持久化“已完成但未消费”状态。|
| schema v29 已完成 | `DeckState.decrypted_cards: Vec<DecryptedCard>` | 改为固定 `(seat, hole_slot)` 的 `PartialHoleCardLedger`；owner/slot 由数组位置唯一表示，只保留 lineage deck index 和 owner-private ciphertext。|
| hot v30 当前表示（拆分自 resolved v29） | `name`、rules、creator/governance | 已拆成三个 immutable object；hot table 只保存确定性 ID 与 domain-separated digest，事件/RPC/proof replay 使用认证 opening 展开。|
| schema v20 已完成 | `rake_collected` | 已改成由 settlement events 唯一派生的 `SettlementTreasuryReceipt`；table/state root 不再保存“写入后立刻清零”的中转。|
| schema v18 已完成 | `addon_pool` | 已删除；唯一事实是 `sum(seat.pending_addon)`，所有 custody delta 使用 checked plan。|
| schema v19 已完成 | `ante_collected` | 已删除；start-hand amount 由逐 seat debit 与 pot delta 确定性派生。|
| ~~必须合并~~ | `round_state/betting Option/shuffle phase/reveal phase/reconstruct phase` | schema v7 persisted encoding 与当前 runtime 均已改成唯一 `HandPhase`；旧平铺布局只存在于 migration mirror。|
| 已完成 | 五个 timestamps | schema v7 每个 active `HandPhase` 只持久化一个绝对 deadline；runtime `Timestamps` 兼容类型和派生 projection 已物理删除。|

数值位宽建议：`rake_bps: u16`、timeout duration/time-bank 配额用 bounded `u32`、card id 用 6 bit、
seat index 用 4 bit、board position 用 3 bit、runout index 用 1 bit。Rust persisted schema 可以继续用
`u8/u16/u32` 保持清晰；AIR 中再做 range/bit decomposition。不要把 `u64` 资产字段降成较窄整数。

schema v13 已把 `Seat.time_bank_ms` 收窄为 checked `u32`，把 `rake_bps` 收窄为 `u16`，同时继续让
绝对 `deadline_ms` 保持 `u64`，因为它表示共识时间点而不是时长。v2-v12 的旧 `u64` 字段由 exact
legacy mirror 解码，越界对象 fail-closed；`rake_bps > 10000` 也不再是 canonical 配置。

schema v14 已把 `HandPhase::Shuffling` 改成二级 tagged union：`Initial` 只保存 shuffle progress 与
deadline，`Reconstruct` 必须同时保存 live street、shuffle progress 和 suspended reveal。旧 v13
`purpose + street + Option<reveal>` 布局只存在于 exact migration mirror；迁移拒绝 `Initial + reveal`、
`Reconstruct + None` 等非法组合。Initial 不再重复保存恒定的 `ROUND_WAITING`，purpose 也完全由
variant 派生。reconstruct complete 与 reconstruct-shuffle timeout 均有回归测试绑定恢复 street/reveal，
避免 phase take/replace 期间把恢复目标退化成 WAITING。

schema v15 已消除 active phase 的零 deadline 哨兵。业务 helper 在同一 command 内组合状态时仍可
短暂写入零，但 dispatch 提交前必须用 authenticated consensus timestamp 调用
`normalize_until_blocked`；该过程会为新建或轮换的 shuffle/reveal/reconstruct/betting/showdown
phase 原子写入非零绝对 deadline。`AdvanceDeadline` 只检查或消费已经提交的 deadline，不再承担
arm-only 状态变化。v14 WAITING 与已 armed active state 可精确迁移；零 deadline 或 reconstruct
`epoch/deadline` 半配对状态因缺少可信时间源而 fail-closed。Tick lifecycle ABI 的 branch 1 保留为
历史 reserved value，但 schema v15 的 canonical receipt 永远不会再签发它。

schema v16 已把 `DeckState.encrypted: Vec<ElGamalCiphertext>` 改成
`CipherDeck::Absent | Active(Box<[ElGamalCiphertext; 52]>)`。runtime 与新 Borsh bytes 均无法表达
1..51 或大于 52 张的牌组；host-native crypto API 边界才显式投影回 `Vec`。schema v15 的旧 Vec
布局按长度精确迁移：0 -> `Absent`、52 -> `Active`，其他长度全部 fail-closed。AIR、precompile
binding、orchestrator、dual-proof 与 proving service 的合法夹具也统一使用完整 52-card deck，不再
依赖 2/8-card 非法测试状态。

`SeatStatus` 应保留为互斥 enum，而不是退回多个 bool。若后续还需压列，可以把九个 3-bit status
打包到一个 27-bit word，但这是偏激进方案：每次 seat update 都要做选择性 bit extraction，只有
Tagged-union Stage 已稳定且 status 列确认为热点后再做。

### A.2 补充源码审计：可删除、可派生与不应过度打包的字段

| 当前字段 | 建议 | 说明 |
|---|---|---|
| `TimeoutConfig.ready_wait_ms/hand_complete_wait_ms` | schema v7 直接删除 | 当前生产状态机没有读取；显式 `start_hand` 和 normalize 后的原子 reset 已取代这两个计时器。|
| `TexasPokerTable.id` | 中期移出 table payload | ObjectDb key、dispatch context 和 AIR 公共输入已经绑定 table id；前提是对象存储层保证 key/payload 不可错配。事件从执行上下文取 id。|
| `state_schema_version` | 已移到 codec envelope | runtime table 不再保存可变版本字段；resolved v29/hot v30 envelope 与 state-root domain 继续绑定并严格拒绝错误版本。|
| `creator` | hot schema 已移入 `GovernancePolicy` | runtime/proof snapshot 的 `creator` 来自 authenticated opening；生产 ObjectDb 不再重复保存。未来扩展 admin set 必须同时升级 policy、receipt 与 AIR role semantics。|
| flat rules fields | schema v23 已收口为 `rules: TableRules`，hot schema 已移入独立 ObjectDb opening | hot table 只保存 metadata/rules/governance 的 typed ID + digest binding；precompile、consensus anchor 和 AIR state root 都要求 exact opening。|
| `max_players` | 与 `seats` 表示二选一 | 若继续使用长度永久不变的 `Vec<Seat>`，容量可由 `seats.len()` 派生；若改固定 `[Seat; 9]`，则必须保留独立 `seat_capacity`。不要同时保存两份容量事实。|
| `ShuffleState.current_shuffler` | schema v11 已删除 | 当前洗牌者是 `first(pending_mask)`，不再产生仅用于同步缓存的 normalize step。|
| `ShuffleState.completed_mask` | 仅表示当前手牌 freshly initialized deck 的本轮已提交者 | 它不能与 `DeckState.contributor_mask` 合并：后者是长期 aggregate-key 成员，前者在每次 `start_hand` 重建 deck 后必须从零开始。|
| `DeckState.aggregated_pk` | schema v10 已由持久化 `contributor_mask + seat.pk` 派生 | host-native verifier 最多做 9 次 G1 加法；join 置 bit，leave/fold proof 清 bit，跨局 reset 为仍占座玩家重建 mask。|
| `DeckState.cards_dealt` | 暂时保留 | reconstruct 会开启新的 deck epoch，旧 hole/board 仍存在，不能只用已公开牌数量推导新 deck 游标。引入显式 deck epoch 和 lineage 后才可重新评估。|
| `RevealAssignment.encrypted_card_index/runout_index/board_position` | 合并成 `RevealTarget` tagged payload + deck index | `Hole { seat, slot }` 与 `Board { runout_bit, position }` 消灭 `board_position=0xff` 等哨兵组合；deck index 仍是独立 lineage。|
| `RevealTokenData.seat_index` | 删除 | 保存 `submitted_mask` 和按 seat 升序排列的 token；提交者由 mask 中第 n 个 bit 唯一确定。若 required participant mask 可由 deck lineage 和 target 推导，则只需保存 pending/submitted 二者之一。|
| `RevealAssignment.decrypted` | 删除 | `pending_mask == 0` 后必须在同一 normalize 中验证、materialize 并移除 assignment，不能持久化完成但未消费的 bool。|
| schema v29 已完成 | `DeckState.decrypted_cards` 可变 ledger | 改为 9 座位 × 2 hole slot 的固定 ledger；plaintext 写入 hand/board 后立即移除，public card 不得进入该 ledger。|
| `RunItTwiceState.shared_board_len` | schema v13 已改成 `RitStartStreet::{Preflop, Flop, Turn}` | 合法值只有 `0/3/4`；street tag 确定性映射到共享前缀长度，旧非法组合 fail-closed。|

`bool -> bit` 只适合正交、经常一起扫描的开关，例如九个 seat 的 acted/leave flags。互斥状态必须用
enum/tagged union。不要为了 Borsh 少几个字节把 `SeatStatus`、phase tag、runout mode 和各种 rule mode
塞进同一个整数：AIR 每次使用仍要拆位和 range-check，可能减少状态字节却增加证明列。

规则字段已在 schema v23 先物理分组、hot schema 移出 hot state，再考虑压位：`AnteMode` 需要 2 bit，`RakeMode`/RIT enabled
各需 1 bit，但把它们压成 `rules_flags` 只节省几个状态字节，不会像 `TableRules -> rules_hash` 那样
减少每个 transition 的 state-root preimage。故推荐在 rules object 内保留清晰 enum，AIR 只绑定 rules
hash；不要让每个 method row重复携带所有 rules 位。

schema v17 已删除 `TexasPokerTable.version`。真实 CAS version 位于 ObjectDb/object envelope；扑克
证明链只保留 `call_seq`，Stage 内部顺序由 batch row index 表示。现有 AIR/public-input ABI 的
`pre_version/post_version` 名称暂不改 wire layout，但其值必须严格等于 pre/post `call_seq`；新的
method-batch ABI 应直接使用 `pre_call_seq/post_call_seq`，不再延续这个兼容别名。

### B. 中等方案：先建立 custody/phase invariant 再删除

| 当前字段 | 处理 | 前置条件 |
|---|---|---|
| ~~`addon_pool`~~ | schema v18 已删除，派生为 `sum(seat.pending_addon)` | 资金入口/退款已统一走 checked custody delta；AIR 约束逐 seat 求和。|
| ~~`ante_collected`~~ | schema v19 已删除，start-hand transition 的 ante 量由 seat `total_bet` delta 与 pot delta 派生 | start-hand plan 列出每 seat ante debit。|
| ~~`rake_collected`~~ | schema v20 已移出 table，作为 `DispatchOutput/SettlementTreasuryReceipt` | Treasury 输出只消费与 showdown plan 或 uncontested award 锚点完全匹配的唯一 receipt。|
| `pot` | 暂时保留；最终可由 vault conservation 派生 | 每次读取都需对 9 seat 求和，可能减少状态但增加 AIR 列/约束，不一定划算。|
| `max_players` | 保留 `seat_capacity`，不要仅由 `seats.len()` 猜测 | 若改成固定 `[Seat; 9]`，仍需配置允许的 seat 范围。|
| 桌内 `version` | schema v17 已删除 | ObjectDb 独立 object version 提供 CAS；桌内证明顺序由 `call_seq` 唯一表达。|

`addon_pool` 是 `chip_pool` 的子集，任何上界公式都不得把两者当成两份资产相加。

### C. 激进方案：收益最大，但需要协议状态重构

1. 把 `round_state + betting_round + current_turn + shuffle/reveal/reconstruct phase + timestamps`
   改成一个 `HandPhase` tagged union：

   ```text
   Waiting
   Shuffling { purpose, current_seat, pending_mask, completed_mask, deadline }
   Revealing { target, assignments, deadline }
   Reconstructing { pending_mask, coefficient, accumulator, deadline }
   Betting { street, current_bet, min_raise, current_seat, deadline }
   ShowdownDisplay { settle_at }
   ```

   `street`、RIT runout schedule 和恢复目标作为 variant payload；不再允许多个 phase 同时 active。

2. `Timestamps` 五个 u64 合并为当前 Stage 的一个 `deadline_ms`。当前任何时刻最多只有一个可执行
   deadline；time bank 直接延长 betting deadline。

3. 已完成：`ReconstructState.player_decks` 不再保存每位玩家的 52 张 contribution。验证一份
   proof 后立刻 fold 到 52-card accumulator，随后丢弃该玩家 contribution。最坏状态从
   `9 * 52 * ciphertext` 降为一个 52-card accumulator，通常可减少数十 KB。
   v5/v6 migration 会读取旧 deck 列表并 fail-closed 地折叠，重复 contributor、仍 pending
   contributor、越界 seat 或非 52-card 输入均拒绝。原 `OUTPUT_SUBMITTED_COUNT` AIR 列未参与
   任何约束，现已连同重复的 runtime count 字段删除。

4. 已完成：`owner_readable_hole_cards` 仅保留尚需用于 owner/showdown/reconstruct
   的 partial ciphertext。owner seat 与 hole slot 由固定数组位置唯一决定，重复 slot、重复
   lineage index、越界 index 和与已 materialize hand 重叠均 fail-closed。reconstruct V3 readable
   cards 与 prior-state digest 统一按 slot 0 -> 1 编码。

5. 已完成：schema v23 先把 blinds、timeouts、ante/rake/RIT rules 收口到单一 `TableRules`；hot
   v28 再把它与 `TableMetadata { name }`、`GovernancePolicy { creator/admin set }` 分别保存为
   ObjectDb opening。hot table 只绑定 typed object ID 与 domain-separated digest；缺失、错 type、
   错 owner、非 canonical opening 或 binding 不匹配均 fail-closed。

6. 已完成：`ProveTask` 不再同时持有 `method_input + selector + raw_args` 三份等价命令事实。
   `method_kind + raw_args` 是唯一持久化/内存命令表示；selector、typed payload、canonical command
   bytes 和 dispatch digest 均从它派生。四个 active crypto typed variant 也已删除内嵌的完整 `raw_args`，
   52-card deck 与 proof blob 不再被复制到 transient enum。service v2 归档使用独立 exact legacy enum
   解码，并继续拒绝 selector、typed input 或内嵌 raw args 的任何错配。

7. 已完成身份型入参的 authenticated lowering：`join_table` 的 `player` 只是
   `DispatchContext.caller` 的边界兼容断言；普通玩家命令的
   `seat_index` 先由 canonical pre-state 中唯一的 `caller -> occupied seat` 映射派生，旧
   payload 只校验相等。L1/AIR prove-task 解码也执行同一 lowering，因此合法 Borsh
   但伪造 actor 的 archive/task 会 fail-closed。table canonical validation 同时拒绝同一地址
   占用多个 seat。管理员命令的 target seat 仍显式保留。

## 方法归一化

### 源码审计结论（Tagged Stage proof 前的冻结清单）

以下结论针对当前 `poker_l1/src/vm/contracts/texas_poker` 源码，而不是只针对 AIR trace：

| 处理 | 字段/方法 | 当前决定 |
|---|---|---|
| 立即采用 | `acted_this_round`、`want_leave`、各 pending/completed participant vectors | seat bit mask；互斥生命周期继续用 `SeatStatus` enum |
| 立即采用 | `Card { suit, rank }`、可变长 hole/board、重复 RIT prefix | `CardId(u8)` + 固定容量数组 + second-board suffix |
| 已在 runtime 与 codec 生效 | `round_state`/`betting_round`/crypto phase/timestamps/reveal ledger/contributor lineage | runtime/persisted state 只保留 `HandPhase`、互斥 reveal enum 与 contributor mask；旧 flattened 布局仅存在于 legacy codec mirror |
| schema v13 已完成 | `Seat.time_bank_ms`、`rake_bps`、RIT payload | checked `u32`/`u16` 与 `Single | Twice { start, second_suffix }`；绝对 deadline 仍为 `u64` |
| 已完成 | `ShuffleState.current_shuffler`、`DeckState.aggregated_pk` | shuffler 由 pending mask 派生；aggregate 已从 runtime struct 删除，crypto statement 在验证点直接派生 |
| 不应删除 | `stack/bet/total_bet/pot/chip_pool`、`deck.encrypted`、`hand/board`、`total_bet` side-pot 输入 | 这些是资产守恒、牌组 lineage 或结算唯一事实 |
| 可合并入口 | `check`/`call`/`raise`/`bet` | canonical `PlayerAction::{MatchBet,RaiseTo}`；旧 selector 只做参数转换和严格语义断言 |
| 可合并入口 | `auto_fold`/`force_fold`/手动 `fold` | canonical `Fold { cause }`；timeout、admin、player 授权在 wrapper 校验 |
| 可合并入口 | `addon`/`rebuy` | canonical `FundSeat { timing }`；金额仍必须 checked-u64 且绑定 coin receipt |
| 已合并入口 | `tick`/`auto_fold`/`reset_for_next_hand` | `AdvanceDeadline` 与 normalize 内部步骤；当前生产只保留 `advance_deadline`，旧 selector、MethodKind 与独立 AIR 均已删除 |

`bool -> bit` 只用于正交 seat flags；`SeatStatus`、phase、RIT mode 等互斥值不能硬塞进同一个
flags word。这样能减少常驻列而不会把 AIR 的选择性拆位成本转移到每一行。

### 推荐内部命令

当前 19 个 active selector 归一化为以下内部命令族：

| 内部命令 | 兼容 selector |
|---|---|
| `CreateTable` | `create_table` |
| `SeatCommand::{Join, LeaveNow, SetLeaveAfterHand, Kick}` | `join_table`, `leave_table`, `set_leave_after_hand(bool)`, `kick_player_v2`；Join 内含 key-ownership authorization，leave policy 使用显式 bool 而不是 toggle |
| `FundSeat::{NextHand, Immediate}` | `addon`, `rebuy` |
| `PlayerAction::{Fold, MatchBet, RaiseTo}` | `fold`, `check`, `call`, `raise`, `bet`, `force_fold`；`MatchBet` 根据需补金额为 0/非 0 自动成为 check/call |
| `CryptoCommand::{Shuffle, RevealBatch, Reconstruct, RemoveLayerAndFold}` | `submit_shuffle_v2`, `submit_player_reveal_tokens`, `submit_reconstruct_deck`, active-hand `fold_with_proof`；退休的 `join_and_shuffle`/WAITING `leave_with_proof` 在所有 decoder fail-closed |
| `Lifecycle::{StartHand, AdvanceDeadline, AbortHand}` | 新调用只使用 `start_hand`、`advance_deadline`；旧 `tick` 不再解码，`auto_fold` 与普通 reset 已退休，只有未来带 checked refund plan 的治理 abort 可恢复外部终止能力 |

最终 proof 层不需要按 selector 拆分 `MethodKind`。建议保留 6 个顶层 command tag：
`Create`、`Seat`、`Funds`、`Action`、`Crypto`、`Lifecycle`；具体语义放在二级 tag。
RPC/ABI registry 与 AIR registry 现在都只枚举 19 个 active method，`all() == active()`；retired
selector/discriminant 不再混入能力发现、archive 或 method batch。

源码现已增加 `CanonicalCommandFamily + CanonicalBatchTag { family, subtag }`，并把兼容入口实际
折叠到上述六个 family：`check/call` 共用 `Action/MatchBet`，`raise/bet` 共用
`Action/RaiseTo`，`fold/force_fold` 共用 `Action/Fold`，历史 `tick/auto_fold` 共用
`Lifecycle/AdvanceDeadline`。生产 active wire set 现为 19 个 selector、19 个 canonical
`CanonicalCommand` tag；折叠 `check/call`、`raise/bet`、`fold/force_fold` 后是 16 个 active
`CanonicalBatchTag`。稳定的 `0..=22` discriminant 空间不重排：5/10/15/16 已物理退休并始终拒绝；
archive 解码与新的 method batch 都不接受 retired tag 作为外部 trace tag。

归一化不等于取消授权：`Fold` payload 仍携带 canonical `FoldCause::{Player, Timeout, Admin}`，
并分别校验 seat signature、deadline 或 creator authorization。

### 可以舍弃的方法

牌组生命周期已冻结。旧源码曾同时存在两套互相冲突的模型：

1. `join_and_shuffle` 在 WAITING 时把加入者的 layer 写入 deck；
2. `start_hand` 又调用 `set_initial_encrypted_deck` 重建 plaintext-base deck，并要求 active seat
   对新 deck 执行本手 shuffle。

第二步会丢弃第一步的牌组输出，所以不能再把 WAITING 的 contributor membership 当作“本手已
shuffle”。推荐明确采用 **fresh deck per hand**：

- canonical join 只做 seat/funding、非 identity key 与 key-ownership proof；不携带两副 52-card
  deck、remask proof 或 shuffle proof；
- `start_hand` 初始化 canonical deck，并令 `pending_mask = active contributor mask`、
  `completed_mask = 0`；
- 每个参与者仅通过本手 `SubmitShuffle` 应用一次 layer；
- WAITING 下没有需要保全的 live hand deck，因此普通 `LeaveNow` 直接删除 contributor membership，
  不再要求 `leave_with_proof`；
- 对局中的物理退出仍保留 `fold_with_proof/RemoveLayer`，因为这时移除 live deck layer 会影响后续
  reveal/reconstruct。

该方案现已从 canonical method 集合删除 `JoinAndShuffle` 与 WAITING-only `LeaveWithProof`，并删除对应
大体积 deck/proof args。旧 selector 不再兼容转换，而是在 mutation、task、AIR 与 package 边界统一
fail-closed，避免验证一份随后被 `start_hand` 丢弃的 shuffle output。

- `bet`：内部完全等价于 `RaiseTo`；旧 selector 只做参数换算与“postflop、尚无下注”的附加校验。
- `check` 与 `call` 的独立内部实现：合并为 `MatchBet`。`current_bet == seat.bet` 时金额为 0，产生
  check；否则扣除 `min(current_bet - seat.bet, stack)`，产生 call/all-in call。ABI wrapper 可继续区分并
  在边界附加“必须为 check/call”的断言。
- `auto_fold`：由 `AdvanceDeadline` 在 betting deadline 到期且 time bank 为零时产生
  `FoldCause::Timeout`。
- `start_hand`：当前保留为显式 canonical command。WAITING 没有 permissionless deadline，避免任意
  caller 在玩家刚入座时隐式开局。若未来需要自动开局，应新增已签名/共识化的 table policy 与
  `ReadyToStart` deadline，而不是恢复 `tick` 的隐式启动职责。
- public `reset_for_next_hand`：已删除；正常 settlement/reset 是 normalize 的内部步骤。未来若需要
  emergency/governance abort，必须以 checked refund plan 新建窄命令，不能复活无计划 reset。
- `force_fold` 的独立业务实现：保留兼容 selector 和管理员授权，但映射到统一 `Fold` transition。
- `addon/rebuy`、`fold/MatchBet/RaiseTo` 的重复 dispatch/state-machine 骨架：保留不同 action tag，
  共享一套 command validation 与 transition plan。
- `TickArgs.now_ms`：已物理删除；deadline command 只接受空 payload，时间只能来自 authenticated
  `DispatchContext.block_timestamp`。
- `set_leave_after_hand(want_leave)` 是唯一离桌策略入口：canonical payload 显式携带目标 bit，seat 从
  authenticated caller 派生；重复写同一 bit 不发事件、不递增 `call_seq`、也不产生 proof task。

### 采用 Tagged-union Stage proof + method batch 后的最终入口冻结

这里区分三层，避免把“删除 selector”“删除业务能力”“删除独立 AIR”混为一谈：

| 能力 | RPC/ABI 兼容入口 | canonical command | 独立业务 AIR |
|---|---|---|---|
| `check` / `call` | 可保留旧 selector | `Action::MatchBet` | 删除两份独立 AIR |
| `raise` / `bet` | 可保留旧 selector | `Action::RaiseTo` | 删除 `bet` 独立 AIR |
| `fold` / `force_fold` | 可保留玩家/管理员入口 | `Action::Fold { cause }` | 删除 `force_fold` 独立 AIR |
| `tick` / `auto_fold` | fresh consensus 只保留 permissionless `advance_deadline`；`tick` 已从 archive 解码删除 | `Lifecycle::AdvanceDeadline` | 删除 `auto_fold` 独立 AIR |
| 正常 `reset_for_next_hand` | 不再公开调用 | normalize 的内部 `Settlement -> Reset` stage | 删除普通 reset method AIR |
| emergency reset/abort | 必须单独治理授权和退款计划 | `Lifecycle::AbortHand { cause }` | 保留窄治理 AIR |
| `addon` / `rebuy` | 可保留旧 selector | `Funds::CreditSeat { timing }` | 共用一份 tagged Funds AIR |
| `join_and_shuffle` | 停止接受新调用 | 无；由 `JoinTable + SubmitShuffle` 取代 | 删除 |
| WAITING `leave_with_proof` | 停止接受新调用 | `Seat::LeaveNow` | 删除 |
| active-hand `fold_with_proof` | 必须保留能力 | `Crypto::RemoveLayerAndFold` | 保留 crypto binding + Stage rows |

`auto_fold` 可以从新 canonical API 消失，因为 permissionless `AdvanceDeadline` 已能在 betting deadline
到期且 time bank 用尽时产生 `FoldCause::Timeout`。`force_fold` 不能删除管理员治理语义，但不应继续拥有
独立状态转换或独立 trace shape；它只是在授权层选择 `FoldCause::Admin`。

`tick` 本身不应作为“万能推进”保留。新入口每次只消费当前 `HandPhase` 暴露的一个 deadline，随后
`normalize_until_blocked` 自动走完所有不需要新签名、proof 或未来时间的 Stage。这样一笔超时交易可以
覆盖 timeout fold、bet collection、round advance、uncontested settlement 与 reset，但不能替玩家生成
未来 shuffle/reveal/reconstruct proof，也不能提前消费尚未到期的 deadline。

### 仍可继续删除或合并的源码字段

| 优先级 | 当前源码字段 | 目标表示 | 安全前置条件 |
|---|---|---|---|
| 已完成 | legacy `ShuffleState.phase` | `HandPhase::Shuffling { purpose: Initial/Reconstruct, ... }` | runtime `ShuffleState` 已只保留 pending/completed mask；旧 phase 仅存在于 exact legacy mirror |
| 已完成 | legacy `ReconstructState.phase` | 删除 | runtime `ReconstructState` 已以 `pending_mask == 0` 表示完成；旧 phase 仅存在于 exact legacy mirror |
| 已完成 | `ReconstructState.coefficient: Option<_>` | 删除 | reconstruction V3 verifier 不读取该 retired V1 transcript 字段；legacy bytes 精确解码后丢弃 |
| 已完成 | `TimeoutConfig.ready_wait_ms/hand_complete_wait_ms` 与 runtime `Timestamps` 兼容类型 | 已从生产 runtime 表示删除 | active phase 的唯一时间事实是 typed `HandPhase` payload 中的绝对 deadline/epoch。|
| schema v13 已完成 | `RunItTwiceState.mode + shared_board_len` | `RunItTwiceState::Single | Twice { start, second_board_suffix }` | 共享长度只允许由 `Preflop/Flop/Turn -> 0/3/4` 映射 |
| schema v14 已完成 | `HandPhase::Shuffling { purpose, street, suspended_reveal: Option<_> }` | `ShufflingPhase::Initial { ... } | Reconstruct { street, suspended_reveal, ... }` | 从类型上消灭 `Initial + Some`、`Reconstruct + None`；v13 migration 只接受 canonical 搭配 |
| schema v15 已完成 | active phase 的 `deadline_ms == 0` 哨兵 | active variant 必带已认证的非零绝对 deadline | command 尾部 `normalize_until_blocked(consensus_timestamp)` 原子 arm；v14 未 armed active state fail-closed |
| schema v16 已完成 | `Vec<ElGamalCiphertext>` 表示的 52-card deck | `CipherDeck::Absent | Active([ElGamalCiphertext; 52])` | runtime/new bytes 无法表达非法长度；v15 的 0/52 精确迁移，其他长度 fail-closed |
| 已完成（resolved v28 / hot v29） | `NO_SEAT = 0xff` | 4-bit canonical sentinel `0x0f` | runtime、resolved/hot codec 与 AIR stage sentinel 已统一；seat index 只接受 `0..8` 或 `15`，旧 `0xff` 状态 fail-closed。当前 schema 已继续升级为 resolved v29 / hot v30。|
| 已完成 | `TickArgs.now_ms` | 物理删除，deadline command 使用空 payload | fresh `advance_deadline` 与 retired `tick` replay 都只使用 authenticated `DispatchContext.block_timestamp`；任何 timestamp payload fail-closed。|
| 已完成 | `join_table.player`、普通玩家动作/资金/离场请求的 `seat_index`、四类 active Mental Poker 的可派生 actor | 从 caller/当前 actor 派生 | canonical task/batch payload 不再编码这些字段；join 的 PK ownership proof 已进入 `join_table`，四类 active crypto statement/proof 原样保留，verifier 从 authenticated context + pre-state 重建边界 ABI。|
| 已完成 | `KickPlayerArgs.reason` | typed `KickCause` + seat-only canonical admin command | external admin selector 与 canonical payload 都只携带目标 seat；legacy selector 仅接受 `Admin`，其他值 fail-closed；timeout/reconstruct timeout 只能由对应状态机路径产生。|
| 已完成 | `DeckState.aggregated_pk` runtime cache | 按 `contributor_mask + seat.pk` 现场派生 | 字段与同步 API 均已删除；所有 crypto request 在使用点派生并验证 lineage |
| schema v21 已完成 | `RevealProgress::ReadyPartial/ReadyCard` | dispatch-local normalize output | proof 验证与 materialize 已在同一原子命令内完成 |
| schema v21 已完成 | `DecryptedCardState::Plaintext` record | 直接写入 hole/board 后删除 | normalize 不允许完成结果跨命令滞留 |
| schema v18 已完成 | `addon_pool` | `sum(seat.pending_addon)` | Funds/Reset Stage 约束逐 seat custody delta 与总和 |
| schema v19 已完成 | `ante_collected` | StartHand/BetCollection plan 的确定性 delta | ante debit、pot 与 `total_bet` 更新全部进入 checked plan |
| schema v20 已完成 | `rake_collected` | settlement treasury receipt | precompile 直接消费 fail-closed receipt，不再借 table 字段中转 |
| schema v17 已完成 | 桌内 `version` | ObjectDb CAS version；扑克状态只保留 `call_seq` | proof ABI 的 legacy version 槽暂承载 call_seq，method-batch v2 再改名 |
| 部分完成 | `id`、`state_schema_version` | schema version 已只存在于 codec envelope；`id` 暂留 runtime table | crypto transcript、event、state root 继续绑定 table id/schema domain；移除 runtime id 需先改所有事件/crypto context 从 authenticated dispatch 取值。|
| schema v23 已完成第一步，后续 ObjectDb 分离 | `name`、blinds、timeouts、ante/rake/RIT 配置与 creator/admin policy | flat rules 已收口；最终使用 `TableRules/Metadata/GovernancePolicy` object + hash | 每个 transition 公开绑定相同 rules/governance hash；管理员命令额外验证 policy opening/signature |
| 条件性 | `max_players` | `seats.len()` 或固定 `[Seat; 9] + seat_capacity` 二选一 | 禁止同时保存两份容量事实 |

以下字段暂不删除：`stack/bet/total_bet/pot/chip_pool`、`acted_mask`、`leave_after_hand_mask`、`button`、
`deck.encrypted/cards_dealt/contributor_mask`、hole/board、`hand_id/call_seq`。它们分别承担资产守恒、
下注完成判定、座位轮转、牌组 lineage 或 proof replay 防混淆；在没有新的唯一派生事实前删除只会把
状态字节成本转换成更宽、更复杂的 AIR。

### Seat 的二级 tagged-union（已完成）

schema v13 先把六个互斥 bool 收敛成 `SeatStatus`，schema v22 完成 persisted/state-root union。
resolved-v25/hot-v26 已把 runtime `Seat` 物理替换为同一个 tagged union，并删除 runtime/persisted
双向 mirror。九个 status 暂不打包成 27-bit word，当前实际表示为：

```text
Seat =
  | Vacant
  | Waiting { player, pk, stack, pending_addon, time_bank_ms }
  | Playing {
      player, pk, stack, pending_addon, time_bank_ms,
      status: Active/Folded/AllIn,
      hole, round_bet, hand_bet
    }
  | DepartedThisHand { player, hand_bet, time_bank_ms }
```

- `Vacant` 不再编码 `EMPTY_PLAYER + identity pk + zero balances + empty hand + status` 的重复事实。
- `Waiting` 不再携带本手 hole/bet/status payload。
- `InHand` 中 `round_bet` 与 `hand_bet` 不能合并：前者决定 call/raise，后者决定 side pot。
- `DepartedThisHand` 只保留结算仍需要的 contribution；stack/pending addon 已退款，pk layer 已移除，
  hole 已清除。若事件或审计仍需 player，可保留 player/address digest，而不是整份 occupied payload。
- `acted_mask` 与 `leave_after_hand_mask` 仍保持桌级 bit mask；union tag 描述互斥生命周期，mask 描述
  正交策略/进度，二者不能混成一个 flags word。

该重构已消灭 empty/waiting/departed 携带 live hand-local payload 的源码表达，并让 crypto key 在
非 live seat 上只能得到 `None`。它未必直接减少当前 Stage proof 的最大列宽；下一阶段仍需决定 AIR
按九个固定 seat slot 展开，还是只对被更新 seat 提供 opening + transition witness。若采用后者，
seat union 对证明宽度的收益会明显大于 27-bit status packing。

### Reveal 与 deck 中还可消除的重复表示

- resolved-v29/hot-v30 延续 typed reveal 表示：已删除 `RevealTokenState.reveal_phase`，改为
  `RevealPurpose::{DealHole, Board, ShowdownOwner}`。公共牌的 flop/turn/river 只保存在外层
  `HandPhase.street`，numeric phase 仅在 event/AIR ABI 边界唯一投影；`RevealPurpose` 没有 `None`
  variant，因此 persisted `NONE + assignments` 已不可表达。旧 `REDEAL` 常量只保留在稳定 ABI
  常量表中，生产状态机没有第二套 redeal 状态。
- schema v29 已把 `DeckState.decrypted_cards: Vec<_>` 替换为
  `PartialHoleCardLedger[seat][hole_slot]`。跨命令只保留 owner-private partial；owner/slot 不再
  重复编码。showdown 的 proof request 必须精确匹配 assignment target 的 `(seat, slot, lineage)`，
  不再按 deck index 扫描，也不得 fallback 到 reconstruct 后的新 deck。
- `DeckState.cards_dealt` 暂时保留。它是加密牌组的 canonical allocation cursor；在 reveal assignment、
  private partial 与 RIT 双 runout 都完成固定槽位化之前，单纯用 hole/board 长度反推会漏掉尚未
  materialize 的已分配牌。

- `RevealProgress::Collecting { pending_mask, submitted_mask, tokens }` 中，如果 required participant mask
  能由 target、owner 与 contributor lineage 唯一派生，则 `submitted_mask = required_mask - pending_mask`
  可删除；在该 invariant 完成前不能贸然删除，否则 token 到 seat 的映射会失去唯一性。
- schema v21 已删除 fresh `RevealProgress::ReadyPartial/ReadyCard` 与
  `DecryptedCardState::Plaintext`。proof 验证、materialize 与 assignment/ledger 清理在同一原子命令内
  完成，不再把“已完成但未消费”写入 state root；这些名字只允许出现在 v20 legacy mirror。
- `DeckState.aggregated_pk` 已从 persisted schema 与 runtime struct 同时删除；所有 crypto statement
  构造前直接从 contributor mask + seat pk 派生，杜绝 cache 与 lineage 漂移。

### Settlement plan 的 bool/重复汇总也应收口

源码中的持久化 table 已没有独立 bool 字段；剩余 `settlement.rs` 的 bool 都是 transition-plan
payload，也应按同一规则处理：

| 当前 plan 字段 | 建议 | 理由 |
|---|---|---|
| ~~`RunoutPotPlan.active: bool`~~ | 已从 runtime 与 settlement-plan v2 Borsh 删除，由 `winner_mask != 0` 派生 | inactive slot 的 amount/rank/award 非零仍在解码与 plan validation 时 fail-closed |
| ~~`SettlementPotPlan.contested: bool`~~ | 已从 runtime 与 settlement-plan v2 Borsh 删除，由 `eligible_mask.count_ones() >= 2` 派生 | 每层减少一个重复 bit byte；空 eligible mask 与不规范 runout payload继续拒绝 |
| ~~`SettlementBoards.runout_count + shared_board_len + board2`~~ | 已改成 `Single { board } | Twice { start: RitStartStreet, board1, board2 }` | single/twice 与共享前缀由一个 tag 决定；`0/3/4` 之外的非街道边界无法构造 |
| ~~`SettlementPlan.runout_count + shared_board_len`~~ | settlement plan v2 已改成 `SettlementRunoutSchedule::{Single, Twice { start }}` | plan Borsh 与 digest domain 升级为 v2；event/AIR 使用的 runout count 从 schedule 派生，旧 v1 digest fail-closed |
| `gross_pot/rake/total_awards/winner_mask/awards` 汇总 | 明细为唯一事实，汇总只作为 checked commitment/output | batch witness 可携带汇总，但 verifier 必须从 pot/runout awards 重算，不能同时信任两份 |

plan-local bit 在 AIR 中仍要约束 `b * (b - 1) = 0`；这不意味着 Rust 源码也应长期保留可与
payload 冲突的 bool。对互斥存在性优先使用 union tag，对正交资格集合使用 seat mask。

### bit packing 的边界

- Rust canonical state 中，九个 seat 的正交开关使用 `u16` mask；AIR 约束高 7 bit 为零。
- `SeatStatus`、`HandPhase`、shuffle purpose、reveal kind、`RunItTwiceState/RitStartStreet` 使用小 enum/tag，不拆回多个 bool。
- `CardId` range 为 `0..51`，seat 为 `0..8`，无 seat 为 `15`，board position 为 `0..4`，runout 为 1 bit。
- 金额继续使用 checked `u64`；在 M31 AIR 中使用 range-checked limbs，不因源码压缩而缩窄资产上限。
- timeout duration/time bank 收窄为 checked `u32`，绝对 `deadline_ms` 保留 `u64`。
- 不把 status、phase、rule modes 全塞进一个 flags word。状态编码可能少几个字节，但每个 Stage 都要
  重复拆位，通常会增加约束和列数。

### 可以从 canonical command 舍弃的入参

兼容 selector 的 wire args 可以暂时不变，但进入 method batch 前应解码成更窄的 canonical command：

| 当前入参 | canonical 处理 | 理由 |
|---|---|---|
| `player`（join） | 从 authenticated `context.caller` 派生 | 避免 caller/player 两份可错配身份；旧 ABI 只校验相等。|
| 玩家命令的 `seat_index` | 从唯一 `caller -> occupied seat` 映射或 `current_turn/current_shuffler` 派生 | table 已禁止同一 player 重复入座；admin target seat 仍必须显式携带。|
| `KickPlayerArgs.reason` | external `kick_player_v2(seat)` 与 canonical payload 均已删除该字段 | admin kick 固定 `KickCause::Admin`，deadline path 固定 `Timeout/ReconstructTimeout`；legacy `kick_player` 仅接受 `Admin` 并在 lowering 后丢弃 reason，任意其他值 fail-closed。|
| reveal `assignment_indices` | 已物理删除；一次提交 caller 当前全部 pending assignment，索引由 authenticated pre-state 按 canonical assignment 顺序派生 | 删除调用方可重复声明的索引列表、重复/乱序检查与 batch payload 字节；token/proof 数量少于或多于 pending assignment 均在 mutation 前 fail-closed。|
| `bet.amount` | wrapper 转成 `RaiseTo(total_bet)` | command 层只保留一种加注金额语义。|
| `selector + method_kind + typed input + raw_args` | 单一 `canonical_command_bytes` | tag、payload 与 digest 均从同一字节串派生；重型 crypto request 只保存一次。|

该项已完成到 lowering 边界：当前 `ProveTask` 只保存 `method_kind + raw_args`，
proof-facing `MethodInput` 会从 authenticated context + canonical pre-state 重新派生 actor。旧
wire/archive `raw_args` 仍保留 `player/seat_index` 以维持 Borsh 兼容，但它们只是相等断言；
新 method-batch payload 版本应物理删除这些冗余字节。历史 service v2 package 的重复字段只存在于
legacy mirror 中，并在迁移时逐项校验后丢弃。

Tagged Stage batch bundle v3 已落地 method-batch task commitment v2：每个 task 的 batch
statement 只编码 `family/subtag`、authenticated actor、canonical dispatch digest、pre/post root、
`table_id/hand_id/call_seq`。完整 `raw_args`、pre/post table 和 crypto proof bytes 仍由 verifier 持有并
用于真实 replay/host-native proof verification，但不会为了计算 batch digest 再整体 Borsh 一次。
旧 bundle v2 继续按完整 `ProveTask` digest 验证，保证历史 archive 可回放；新 prover 只签发 v3。

### `tick` 为什么不能直接消失

只让 `auto_fold/force_fold` 推进到底仍不能处理：

- shuffle participant 超时；
- reveal token participant 超时；
- reconstruct participant 超时；
- showdown display deadline；
- 无调用者继续提交业务交易时的 permissionless liveness。

因此应删除的是 tick 的“万能状态修复/普通推进”职责，而不是 deadline 驱动能力本身。
`AdvanceDeadline` 每次只消费当前 Stage 的 canonical deadline，之后调用
`normalize_until_blocked` 连续推进到下一个真正需要外部输入的位置。

## `normalize_until_blocked`

每个成功命令末尾执行有上限的确定性循环：

1. 若只剩一个 eligible player：收集 live bets，生成 settlement plan，结算并 reset。
2. 若 betting 已完成：collect bets，advance street，触发 RIT/reveal/showdown。
3. 若 shuffle pending 为空或 current 未选择：选择下一 canonical shuffler/进入 reveal。
4. 若 reveal assignments 全完成：写入 hand/board，进入 betting/下一 reveal/settlement。
5. 若 reconstruct pending 为空：提交 accumulator 为新 deck，进入 shuffle。
6. 遇到需要玩家签名、crypto proof、未到 deadline 或显式 start-hand 时停止。

循环必须设置小的静态上限，并在超过上限时 fail-closed；不能保留当前 tick fallback 那种退款后
继续掩盖非法 phase 组合的行为。

## 对 Tagged-union Stage proof 与 method batch 的影响

- Stage proof 使用 `stage_tag + shared columns + variant payload columns`。inactive payload 必须为零，
  且 tag one-hot/range constrained。
- 一行可以表示 SeatUpdate、BetCollection、RoundAdvance、Settlement 中任一 Stage；不再为每个
  transition 固定启动四份 proof。
- method batch 使用 `method_tag` 装入异构 canonical command rows；tag 选择对应约束，公共列统一
  绑定 table/hand/call_seq/pre-root/post-root/context digest。
- crypto/admin receipt 作为可选 tagged payload；没有 receipt 的 row 必须把相关列全部约束为零。
- `normalize_until_blocked` 输出 bounded `TransitionPlan`，同一 method row 引用连续 Stage row 范围，
  从而允许一笔 action 覆盖 fold -> collect -> round advance -> settlement，而无需额外 tick row。

不要把现有 23 份 Method AIR 的列布局直接扩成一个“最大宽度”全局 union。当前资金、timeout、
reveal 方法包含大量 checked-u64、deadline、receipt 和 settlement witness；若直接取最大宽度，简单
`check/fold` 行也会支付最宽方法的所有列 commitment 成本。

推荐把 method batch row 收敛为较窄的授权/编排层：

```text
method_tag + subtag + table/hand/call_seq + pre_root/post_root
+ canonical_command_digest
+ actor/admin/crypto receipt tag and digest
+ stage_batch_id + stage_start_row + stage_row_count
+ transition_plan_digest
```

金额更新、bet collection、round advance、settlement 和 checked-u64 witness 全部只出现在对应的
tagged Stage rows。这样 heterogeneous method batch 的宽度由“命令与 Stage 绑定”决定，而不是由
旧 `rebuy/auto_fold/reveal` 中最宽的一份 AIR 决定。旧 selector 只负责在 L1 边界解码 canonical
command，不再决定 proof trace shape。

schema v17 已删除桌内逻辑 `version`。新的 method row 应直接使用
`pre_root/post_root/pre_call_seq/post_call_seq`；真实 ObjectDb CAS version 属于区块执行/包含证明，
不是扑克业务 AIR 的重复状态字段。旧 ABI 的 version 命名只作为历史 wire 兼容存在。

连续 method batch 也不应为每个 task 保存完整 `pre_table + post_table` 两份快照。对同一 table/hand
的连续 batch，可编码为：

```text
initial_state + [canonical_command, authenticated_context, transition_plan]* + final_state
```

中间状态由前一 transition 的 post 唯一成为下一 transition 的 pre；archive 若需要随机访问，只保存
row index/root checkpoint，不再复制整张 table。这个优化对含 52 张密文的 deck state 比压几个 bool
更有价值。

### 当前实现状态

Stage batch v2 已实现单份 tagged-union STARK：active Stage 行按 task/stage canonical 顺序紧凑写入
1024 行 trace，四种 Stage 共用最大 variant 宽度并以 2-bit tag 区分，inactive/padding 行全零；
verifier 重放完整异构 method task 列表并重建 trace commitment。它已经把 batch 固定启动从四份
Stage proof 降为一份。单 task 的 durable bundle 暂时仍保留四份独立 component proof。批量
archive 已破坏性升级为 v4，不再接受旧的完整 task list 或 compact task list statement；唯一输入
承诺改为 `MethodBatchV2 = initial_state + commands + final_state`，解码时从初态逐条重放并拒绝任何
中间状态、table/hand/call 序列或最终状态错配。

这里的 “heterogeneous method” 已在 composition batch 输入层成立：同一 hand 的连续 batch 可混合
所有 MethodKind。`supports_composite_proof` 方法派生并占用 canonical Stage rows；start/shuffle 等
pipeline 外方法拥有 `stage_row_count = 0`，但仍进入连续 stream 和 tagged method proof。原始 method 层也已
新增固定宽度 tagged method STARK：它只承诺窄授权/编排行，不再生成每 task 一份旧 Method AIR。
throughput 入口因而对一段同 hand transition 固定只启动两份 Stwo proof：一份 tagged method proof
+ 一份 tagged Stage proof。full-hand driver 已切到 mixed zero-Stage 路径：create/join×2 仍是 3 个
legacy setup proofs；`start_hand + shuffle×2 + 18 composite transition` 形成 21-row method proof，
其中只有 16 个 active Stage row。末尾通过 `prove_verify_and_accept_tagged_batch` 原子验证 package、
签发逐 row receipt 并接入原有 host-verified chain。2026-08-09 debug test profile 端到端回归为
26.55–26.92s；此前只批量化 18 个 composite rows 的版本约 36.30s，Stage-only batching 路径约 134.91s。

method payload 的窄行契约已经落地：`MethodPayloadV2` 当前 schema version 为 v4，直接使用六类 `family + subtag`、
`pre_call_seq/post_call_seq`、pre/post root、canonical command digest、admin/crypto tagged receipt、
transition-plan digest，以及 `MethodBatchReferenceV2 { batch_id, row_index, row_count,
stage_start_row, stage_row_count }`。Stage archive 从 canonical replay 重建每条引用，调用方不能自行
声明 Stage span。tagged method AIR 约束 active/padding、family bits、admin/crypto receipt canonical
absence、crypto one-hot tag 和 checked `post_call_seq = pre_call_seq + 1`；verifier 还会重建整份 trace
commitment。管理员与 Mental Poker receipt 由生产 convenience path 从 canonical task 重新签发，
不会信任 archive 自报 digest。tagged package 已自带 `MethodBatchV2` 连续流，restart verifier 可
直接重放恢复 tasks；同步 service package/repository 已分别破坏性升级为 v7/v6 并拒绝历史格式。
HTTP 的 `start_hand` 或 composite job 现在可开启 `pending_proof`；已有 stream 内，同 hand 的
shuffle、资金、离场标记等 non-composite job 以 zero-Stage row 继续共享持久化 continuous stream。
显式 finalize、下一次 `start_hand` 或满 batch 才启动 two-proof prover。完成后每个 job 只保存
`batch_id + row_index + row_count`，下载、重验和 P2P repair 均解析到同一共享 sidecar。service
restart 对同一 tagged package 只验证/恢复一次，并严格校验所有 row job 的顺序、数量、task digest、
state root 和 result metadata；未 finalize 的 stream 仅恢复 pending queue，不签发 receipt。共享
sidecar repair 回归还验证了从非零 row job 下载后按 `batch_id` 恢复一次，即可让批内全部 job
重新读取并在 restart 中恢复 receipt chain。首 row 跨 hand 的 completed package 会在 staged
Orchestrator 上先开启新 receipt segment；验证失败保持原恢复链不变。

验证侧的重复开销也已收口：service package decode 会把严格校验时唯一一次 continuous-stream
replay 的 canonical tasks 与 immutable package 一起保留；restart 遇到共享 tagged reference 时由
row zero 校验完整 job set，后续 rows 不再重复读取、decode 或 replay 同一 sidecar。进程内
validated-package cache 使用完整 sidecar 内容哈希作为 identity，并有 64 entries / 256 MiB 上限。
live finalize 或首次完整 proof verification 成功后才可写入 cache；cache hit 仍逐 job 重算并比对
task digest、pre/post root、row index/count 和 reference scope。同一 `batch_id` 下只要 sidecar 字节
变化就必须 cache miss，因此该优化不会把 durable path/lifecycle metadata 从信任边界中移除。
repository v6 继承并继续强制批内 `prove_count/chain_length` 的逐 row 历史位置，在完成与 restart
两端拒绝共享基线、row 增量或最终计数不一致的 journal。

canonical command payload 已完成完整 actor 物理瘦身：`join_table` 不再持久化 `player`，
fold/check/call/leave/request-leave 不再持久化 actor seat，raise/bet/addon/rebuy 只保存金额。
这些 actor 统一从签名 caller 与 canonical pre-state 的唯一占座关系派生；native replay 前由唯一
`replay_dispatch_args` 路径重建边界 ABI。错误的非空 actor-only payload、caller 未占座、同一地址
重复占座均 fail-closed。四类 active Mental Poker payload（fold/shuffle/reveal/reconstruct）删除
authenticated seat；完整 deck、tokens、statement 和 proof 仍原样进入 canonical payload。
AIR/orchestrator/tagged/dual-proof
统一解码 authenticated replay ABI。为避免旧 payload 与新语义混用，continuous stream、method row、
method archive、composition bundle、service package 和 repository 已同步升级为 v4/v4/v3/v6/v7/v6，
dispatch digest domain 升为 `dispatch_call.v4`。

reveal payload 进一步删除了 `assignment_indices`。状态机此前已经要求每次提交 caller 在当前 reveal
state 中的全部 pending assignment，且顺序必须等于 canonical assignment 顺序；因此该向量从来不是
独立选择。L1 dispatch、canonical command、replay ABI、full-hand driver 与 precompile request builder
现在统一从 authenticated pre-state 派生索引，只在 native crypto request 的逐项 statement 中保留派生
后的 index 以绑定 ciphertext lineage。旧含索引 wire shape 无迁移入口并 fail-closed；少交、多交或
token/proof 数量不一致均在状态 mutation 前拒绝。

共识锚不会只把已认证交易参数“删字段后哈希”：它现在从 authenticated pre snapshot 开始，按调用
顺序用原始交易 ABI 重放完整 native dispatch，要求每次都产生 canonical proof task、legacy 与
canonical digest 一致，并要求最终重放 table 精确等于 authenticated post snapshot。因此错误的旧
`player/seat_index` 声明不能借由 actor-less 规范化与合法调用碰撞。

本轮源码也已把动作入口进一步收敛：`state_machine::PlayerAction` 是唯一普通下注实现，包含
`Fold { reason }`、`MatchBet`、`RaiseTo(u64)` 三个 tag；`check`/`call` 仍在 wrapper 中分别检查
“不欠注/确实欠注”，然后都进入 `MatchBet`。`bet` 只保留 postflop、无当前下注和金额大于零的
兼容检查，再转换为 `RaiseTo(seat.bet + amount)`。同理，`FundTiming::{NextHand, Immediate}`
统一了 `addon` 与 `rebuy` 的 checked-u64、chip-pool 和 seat 更新骨架，事件类型仍按旧 ABI 语义
分别输出。超时和管理员 fold 已经通过 `AdvanceDeadline`/`apply_fold_internal` 使用同一 fold
transition，不再有第三套自动 fold 业务逻辑。

因此当前可以冻结以下字段决策，作为 method batch 和 Stage 列设计的输入：

| 字段组 | 处理 | 约束 |
|---|---|---|
| `acted_this_round`、`want_leave` 以及所有 participant 列表 | `u16 SeatMask` | 只允许 `0..max_players` 的 bit；空座位 bit 必须为零。|
| `SeatStatus`、`HandPhase`、`RevealTarget`、`RevealProgress`、`RunoutMode` | 保持 enum/tagged union | 这些值互斥；硬塞进 flags 会把非法组合转移到 AIR 拆位。|
| `Card { suit, rank }`、可变长 hand/board、重复 RIT prefix | `CardId` + 固定容量数组 + suffix | 只接受 0..51 card id 和 canonical zero padding。|
| `side_pots`、`refunded`、`DeckState.plaintext`、ready/complete 的 transient reveal record | 删除或 normalize 后删除 | 删除前必须由同一 checked settlement/reveal plan 唯一重建，并 fail-closed 拒绝歧义旧状态。|
| `aggregated_pk`、`current_shuffler`、`ante_collected`、`addon_pool`、`rake_collected` | 均已从 canonical persisted state 删除或派生 | contributor mask、mask-derived actor、checked custody delta 与 settlement receipt 分别成为唯一事实。|
| `stack`、`bet`、`total_bet`、`pot`、`chip_pool`、encrypted deck、seat player/pk | 必须保留 | 它们分别是资产守恒、side-pot eligibility、Mental Poker lineage 和身份授权的唯一事实。|
| duration/time-bank/rake parameters | bounded `u32`/`u16` | AIR 做 range/checked-u64；绝对 `deadline_ms` 继续 `u64`。|

`bool -> bit` 的适用边界是“正交且批量扫描”的 seat flags；不适用于互斥生命周期、phase 或规则
模式。对九个 seat，两个桌级 mask 只需 18 个活跃 bit；将九个 `SeatStatus` 再压成一个 27-bit
word 属于激进优化，只有 status extraction 已成为实测热点时才值得承担复杂度。证明列通常比
Borsh 字节更贵，所以优先删除重复事实和变长容器，再考虑 bit packing。

## 推荐实施顺序

1. 已完成 schema v3 字段删除、尺寸回归和 active RIT migration 测试。
2. 已完成 schema v4 `SeatStatus` 与 v2/v3 fail-closed migration。
3. 已完成 schema v5 桌级 seat masks、`NO_SEAT`、participant masks 与 v2/v3/v4 exact migration。
4. 已完成 schema v6：Card 改 canonical id/fixed hole-board/RIT suffix。
5. 已完成 `normalize_until_blocked`，旧 selector 在成功执行后统一 normalize，并对非法 phase 原子失败。
6. 已引入 `CanonicalCommand`；旧 selector 先映射为稳定 command tag 再 dispatch。
7. 已用 `AdvanceDeadline` 统一 reconstruct/shuffle/reveal/betting/showdown timeout；`tick`、
   `auto_fold` 和 public `reset_for_next_hand` 已从 fresh selector 集删除；旧 `tick`、`auto_fold`
   与 public reset source dispatch 实现也已物理删除，超时测试只走 permissionless
   `advance_deadline`，牌局重置只由 settlement/normalization 内部调用。全部 retired
   selector 已从 strict archive 边界删除。precompile 与 proving service
   都在 VM mutation 前执行同一 active-command 过滤，selector registry 也只返回这 19 个入口。
   `join_and_shuffle` 与 WAITING `leave_with_proof` 的 source-internal dispatch、canonical/task 类型、
   AIR/precompile/package/service 路由也已物理删除。替代链分别由
   `join_table + start_hand + submit_shuffle_v2`、WAITING `leave_table` 和 active-hand
   `fold_with_proof` 覆盖；discriminant 5/10/15/16 在所有 decoder 保持 fail-closed，且旧
   `auto_fold`/普通 reset 独立 AIR 与 orchestrator route 已删除。
8. 已完成 schema v7 persisted/runtime `HandPhase` tagged union、单 deadline 与 reconstruct streaming
   accumulator；schema v9 已完成 reveal ledger enum，schema v10 已完成 contributor lineage，且
   aggregate key 已改为使用点现场派生；runtime flattened phase caches 已删除。
9. 已完成 throughput 路径的 Tagged-union Stage proof、原始 tagged method STARK，以及 durable
   service batch job。continuous `MethodBatchV2`、method payload v2、共享 sidecar、
   batch-id/row-index/Stage span、pending restart 与逐 row job recovery 均已接入；composite HTTP
   dispatch 不再生产 per-task method/component archive。full-hand 与 production HTTP 都已允许
   start/shuffle 等 zero-Stage methods 与后续 composite rows 共用 package；create/join 等 hand
   stream 外孤立 setup jobs 仍保留 single archive。
10. method batch 前按顺序完成：已完成 reveal ledger canonicalization、
    `DeckState.contributor_mask` 与 `aggregated_pk` 派生、schema v14 shuffle 二级 tagged union、单一
    canonical command 表示、crypto payload 去重、schema v15 active deadline 哨兵消除和 authenticated
    caller/seat lowering，以及 admin kick 的 external/canonical seat-only payload、typed `KickCause`；
    legacy `kick_player(seat, reason)` selector helper、参数结构和 replay 分支现已物理删除；schema v17 已删除
    桌内 `version`；schema v18/v19/v20 又依次删除 `addon_pool/ante_collected/rake_collected`。
    schema v21 已清理 reveal 临时完成态；schema v22 完成 persisted seat union，resolved-v25/hot-v26
    又完成 runtime `Seat` 物理 tagged union 与 codec mirror 删除；resolved-v27/hot-v28 完成 typed
    reveal purpose 并删除持久化 numeric reveal phase，resolved-v28/hot-v29 再统一 missing-seat 为
    4-bit `0x0f` sentinel；resolved-v29/hot-v30 又把 owner-readable partial ledger 固定为
    `(seat, hole_slot)` 表示，旧 Vec 编码直接 fail-closed；schema v23 已把所有规则字段物理
    收口为单一 `TableRules`。三个 immutable context opening 已完成，v2-v24 historical migration code
    已从 production crate 删除。durable batch statement 已收敛为连续 state stream，并完成原始
    method payload 的 batch-id/row-index/Stage span 数据契约；单份 tagged method proof 已生成并与
    Stage proof 封装为严格的 two-proof package。service 持久化/恢复路径也已迁移到共享 package
    reference，旧同步 schema 不再支持。

`RevealTokenState.submitted_mask` 审计后明确保留。玩家提交 reveal token 后可能被 kick，token 仍须
对应原 ciphertext layer，但该 seat 随即成为 `DepartedThisHand`、不再提供 Mental Poker key，且
contributor lineage 也会移除它；因此提交者集合无法从 live seat、`pending_mask` 或当前
`contributor_mask` 唯一重建。逐 token 保存 seat index 通常比 2-byte mask 更大。只有改变语义为
“reveal 中 contributor removal 必须丢弃已有 reveal progress 并进入 reconstruct”后才可安全删除。
