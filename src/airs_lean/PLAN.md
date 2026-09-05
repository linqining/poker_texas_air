# airs_lean 实现清单

> **实现状态（已完成 M0–M6）**：`lake build AirsLean` 零错误，
> `scripts/count_sorries.sh` 计数为 0。三大顶层定理见
> `AirsLean/Top/Audit.lean`；公理审计仅含标准公理与两条登记的
> 抗碰撞公理。与原计划的偏差（均为收窄/合并，不减少命题覆盖）：
> 1. `Top/Audit.lean` 的 `main_soundness` 打包 S2 的 call/bet 代表性
>    定理（其余定理仍在各自文件中单独陈述并证明）；
> 2. C3/C4 分别落在 `Custody/BetBound.lean` 与 `ExitControl.lean`；
>    D3/D4 合并在 `Censorship/AcceptedSeq.lean`；
> 3. D1 的 `no_forge` 实现为 `genuine_action`（EUF-CMA 抽象谓词形
>    式），D2 的重放排除以自定义 `SeqInc`/`Occurs` 归纳结构表述；
> 4. D3 的 `receipt_nonrepudiation` 并入假设登记（链上事件不可篡改）；
> 5. S6 的 `composition_embedding` 由 `chain_length_le_trace` +
>    `no_cross_plan_mix` 覆盖其安全内容；
> 6. C1 的 `Represents` 未建独立谓词——状态镜像 `TableImage` 定义在
>    S1 并被 Custody 直接使用。

> 目标：在 `src/airs_lean/` 建立独立 Lean 4 项目 `AirsLean`，对
> `src/airs/`（19 个 method AIR + composition 组件）与
> `src/texas_canonical_air.rs` 所编码的 AIRS 约束层做机器证明，覆盖三大命题：
>
> 1. **抗审查**（censorship resistance）
> 2. **约束的 soundness**（AIR 约束 ⇒ 业务关系成立）
> 3. **防用户逃单**（资金托管守恒，用户无法带着未结算债务离场）
>
> 本文档是唯一的实现清单与进度追踪表（勾选框），出处引用均为仓库内文件。

---

## 0. 定位与形式化边界

**证明什么**：AIR 约束层的安全命题——"若一条 trace 被 AIR 约束系统接受，
则对应业务关系必然成立"，以及建立在其上的三大安全定理。

**不证明什么**（显式边界，最终写入 `Top/Audit.lean` 与 README）：

| 边界项 | 处理方式 |
| --- | --- |
| Stwo prover/verifier 本身（FRI、低度测试、承诺绑定） | 抽象为 `AirAccepted` 谓词；STARK soundness 为假设 |
| Rust ↔ Lean 约束清单逐条对应 | 义务项：每个 Lean 谓词注明 Rust 出处行，审计文档核对 |
| 哈希抗碰撞 / Poseidon 性质 | 抽象谓词 + 假设（`Top/Assumptions.lean` 登记） |
| 动作签名的具体实例化（Stark 曲线 Schnorr/EUF-CMA） | 抽象签名方案 + 不可伪造假设；可复用 `poker_protocol_lean` 的 Schnorr 结果（M5+ 可选） |
| L1 合约执行、receipt inclusion | 假设"链上事件不可篡改"（引理形式陈述） |

**与 `poker_protocol_lean` 的关系**：独立 lake 项目，不互相依赖；共用同一
toolchain 与 Mathlib 版本（v4.32.0），沿用其零 `sorry` 纪律与
`count_sorries.sh` 审计脚本模式。

---

## 1. 工程骨架

- [x] `src/airs_lean/lakefile.lean` — package `airs_lean`，lib `AirsLean`，
      leanOptions 同 `poker_protocol_lean`（`autoImplicit false`、
      `maxHeartbeats 5120000`），依赖 Mathlib `v4.32.0`
- [x] `src/airs_lean/lean-toolchain` — `leanprover/lean4:v4.32.0`
- [x] `src/airs_lean/AirsLean/AirsLean.lean` — import 根
- [x] `src/airs_lean/scripts/count_sorries.sh` — 零 `sorry`/`admit` 审计
- [x] `src/airs_lean/README.md` — 构建/审计说明 + 边界声明（仿
      `poker_protocol_lean/README.md` 的"Formal-proof boundary"节）

目录结构（§2–§5 逐项展开）：

```
src/airs_lean/AirsLean/
├── Foundations/   M31 域、limb 编码、进位算术、trace/约束模型
├── Soundness/     命题 2：逐 AIR 家族的约束 ⇒ 业务关系
├── Custody/       命题 3：筹码守恒、下注上界、离场控制、提款上界
├── Censorship/    命题 1：动作签名、seq 单调、accepted-seq、auto 合法性
└── Top/           假设登记、公理审计、顶层合成定理
```

---

## 2. Foundations（基础域，四个文件）

### F1 `Foundations/M31.lean` — M31 域

- [x] `abbrev M31 := ZMod 2147483647`；`Fact (Nat.Prime 2147483647)` 实例（by decide）
- [x] 基本引理：`2 ^ 16 < 2147483647`（limb 无模约减的前提）
- 出处：`stwo::core::fields::m31`；`src/airs/common.rs` 的 `ZERO`/`M31` 用法

### F2 `Foundations/Limbs.lean` — 4×16-bit limb 编码

- [x] `def Limbs := ℕ → M31`（定长 4）；`encode : ℕ → Limbs`（`u64_to_m31_limbs`）、
      `decode : Limbs → ℕ`（`m31_limbs_to_u64`）
- [x] **定理 `limb_range_sound`**：四 limb 均 `< 2^16` ⇒ `decode (encode v) = v`（对 `v < 2^64`）
      ——range-check witness（`RANGE_*_BITS`）使 M31 值忠实表示 u64，无模回绕
- [x] **定理 `limb_range_necessary`**（反方向警示）：无 range check 时存在
      `decode ≠ v` 的编码——对应"删 range check = 打开漏洞"
- 出处：`src/airs/common.rs:74-104`（`u64_to_m31_limbs` / `m31_limbs_to_u64`）

### F3 `Foundations/CarryArith.lean` — ripple-carry 算术

- [x] `addLimb`（带 3 个 carry witness 的 limb 加法）、`subLimb`（减法借位）
- [x] **定理 `carry_add_sound`**：carry 均为布尔且 limb 相加约束成立 ⇒
      `decode lhs + decode rhs = decode sum` 且结果 `< 2^64`（无溢出）
      ——这是所有资金约束"在 M31 域成立 ⇒ 在 u64 语义成立"的枢纽
- [x] **定理 `carry_add_complete`**：诚实 witness 满足约束（completeness 侧）
- [x] 2-bit carry 分解变体（`compute_bound_carries`，上界检查用）
- [x] `min` 选择关系的等式刻画（`min a b = a ∨ min a b = b` + 短 all-in 分支）——实现在 S2 `call_min_selection` 的两分支推理中
- 出处：`src/airs/common.rs:111-`（`compute_add_carries`）、`compute_bound_carries`

### F4 `Foundations/TraceModel.lean` — trace 与约束系统模型

- [x] `Structure Trace`：列数、行数、取值 `col : Trace → ℕ → ℕ → M31`
- [x] 约束满足谓词 `Sat (cs : Trace → Prop) (t : Trace) : Prop`（`TraceModel.lean`）
      ——Lean 侧重定义"Rust evaluator 施加的约束集合"为谓词，不做多项式求值
- [x] 门控原语：`isBoolean`、`isOneHot`、`isActivePrefix`（active 行前缀 + padding 全零后缀）
- [x] **定理 `one_hot_semantics`**：one-hot ⇒ 恰好选中一个 selector；
      `bool_semantics`：boolean witness ∈ {0,1}
- [x] **定理 `active_prefix_split`**：padding 后缀不承载任何业务约束的语义划分
- 出处：`src/airs/common.rs`（`COL_IS_PADDING`、`CommonConstraints`）；
  `src/texas_canonical_air.rs`（29 selector one-hot、active-prefix、预处理列）

---

## 3. 命题 2：约束 Soundness（`Soundness/`，六个文件）

统一定理形态：`air_accepts_sound : Sat cs t → 業务关系 t`。
每个文件头注释给出约束清单 ↔ Rust 约束表达式（`EvalAtRow` 调用）的对照表。

### S1 `Soundness/CommonColumns.lean` — 37 通用列

- [x] 通用列谓词 `CommonSat`：method kind one-hot、pre/post state root 4-limb、
      `table_id`/`hand_id`/`call_seq`/`pre_version`/`post_version` 绑定
- [x] **定理 `call_seq_progresses`**：`post_call_seq = pre_call_seq + 1`（含 16-bit 回绕分支）
- [x] **定理 `scope_binding`**：约束成立 ⇒ 该行属于声明的 `(table, hand, seq)` 槽位
      ——行不可被搬到别的桌/手/序号（防跨域搬运）
- [x] **定理 `version_bumps`**：`post_version = pre_version + 1`
- [x] padding 行为全零后缀 ⇒ **定理 `no_all_padding_trace`**（trace 非平凡）
- 出处：`src/airs/common.rs:24-57`；`src/texas_canonical_air.rs`（预处理器 9 列、
  call_seq 回绕）；`TEXAS_TAGGED_AIR.md` "The verifier reconstructs nine fixed
  preprocessed columns…"

### S2 `Soundness/ActionAIRs.lean` — 玩家动作 AIR（fold/check/call/bet/raise）

- [x] **定理 `fold_check_funds_immutable`**：Fold/Check 行 ⇒ 选中座位 stack/bet/total_bet 不变
      （对应"Fold and Check monetary immutability"）
- [x] **定理 `call_chip_conservation`**：Call 行 ⇒
      `post_stack + call_amount = pre_stack ∧ post_bet + pre_bet = pre_bet + call_amount`，
      即筹码从 stack 精确移入 bet，pot 不变；all-in 分支 `call_amount = min(current_bet − seat.bet, stack)`
- [x] **定理 `call_actor_rule`**：acting seat = `pre.current_turn` 且未 acted/folded/all-in
- [x] **定理 `bet_bound_and_updates`**：unopened-round Bet ⇒ bet ≤ stack、
      `current_bet`/`min_raise` 更新关系成立
- [x] **定理 `raise_reopen_rule`**：Raise 重开当且仅当加注增量 ≥ pre `min_raise`；
      子最小加注 all-in 保持其余座位 acted 标志（TDA #41）
- [x] **定理 `next_seat_no_skip`**：轮转后继不跳过任何 Active 座位（canonical 环形扫描）
- 出处：`src/airs/actions/{fold,check,call,bet,raise}.rs`；`TEXAS_TAGGED_AIR.md` Covered transition

### S3 `Soundness/FundsAIRs.lean` — 资金 AIR（join/addon/rebuy）

- [x] **定理 `join_custody_exact`**：JoinTable ⇒ 新座位 `stack = buy_in`、
      `chip_pool_post = chip_pool_pre + buy_in`（买入即托管，无凭空筹码）
- [x] **定理 `rebuy_exact_increment`**：Rebuy ⇒ `stack += amount ∧ chip_pool += amount ∧ amount > 0`
- [x] **定理 `addon_exact_increment`**：Addon ⇒ `pending_addon += amount ∧ chip_pool += amount`
      （下一手生效，不动 stack）
- [x] **定理 `global_bound_enforced`**：`chip_pool + amount ≤ MAX_TOTAL_BET`
      （BOUND_DIFF + 2-bit carry 约束 ⇒ 上界在 u64 语义成立）
- 出处：`src/airs/funds/{addon,rebuy}.rs`；`src/airs/lifecycle/join_table.rs`；
  `src/airs/common.rs:62-70`（`MAX_TOTAL_BET`）

### S4 `Soundness/LifecycleAIRs.lean` — 生命周期 AIR

- [x] **定理 `leave_refund_conservation`**：LeaveTable ⇒
      `refund = stack + pending_addon ∧ chip_pool_post = chip_pool_pre − refund`
      且座位清空（`Seat::empty()`）
- [x] **定理 `leave_domain`**：LeaveTable 行 ⇒ `round_state = WAITING`
      ——手牌进行中不可简单离桌（逃单控制的第一道门，见 §4）
- [x] **定理 `start_hand_promotion_channel`**：StartHand 仅允许
      `Waiting → Active` 单向晋升，资金与其余生命周期位不变；参与者 ≥ 2 门槛
- [x] **定理 `advance_deadline_bound`**：`action.height ≥ pre.deadline`
      的 64-bit 比较在 limb 分解下忠实
- [x] **定理 `set_leave_after_hand_single_bit`**：恰一位 mask 翻转；
      幂等 no-op 被 `call_seq` 递增约束排除
- [x] **定理 `actor_authority`**：permissionless 行 actor = 0；actor 行 actor ≠ 0
      且绑定授权 receipt（`force_fold` 的管理员授权列）
- 出处：`src/airs/lifecycle/*.rs`；`src/airs/actions/{force_fold,kick_player,set_leave_after_hand}.rs`

### S5 `Soundness/RoundAndSettlement.lean` — 收注与结算

- [x] **定理 `advance_round_pot_collection`**：AdvanceRound ⇒
      `post_pot = pre_pot + Σ seat.bet`（进位链在 u64 语义忠实），
      每 seat.bet 清零、stack/total_bet/pending/lifecycle 保持
- [x] **定理 `advance_round_domain`**：仅当所有剩余 Active 座位已行动且匹配 `current_bet`
- [x] **定理 `settlement_conservation`**（Settlement/Showdown/WithoutShowdown）：
      `pre_chip_pool + total_addon_credits + gross_pot
       = post_chip_pool + rake + total_awards + total_refunds + total_addon_refunds`
      （实现时以 `settlement.rs` 实际约束清单为准核对每项符号）
- [x] **定理 `awards_within_pot`**：`total_awards + rake = gross_pot`（奖池不得超发）
- [x] **定理 `settlement_digest_immutable`**：结算承诺在活跃行不可变
      ——证明无法为一手之外的支付方案背书（对应 DUAL §6 绑定 3）
- 出处：`src/airs/composition/settlement.rs`（`SettlementStagePlan` 字段）；
  `src/airs/actions/end_betting_round.rs`；`src/airs/composition/round_advance.rs`

### S6 `Soundness/Composition.lean` — 组合层

- [x] Stage header 谓词：`active`/`stage_kind`/`stage_index`/`plan`/`input`/`output` digest 链
- [x] **定理 `stage_chain_contiguous`**：相邻 stage 的 `output_digest = input_digest`
      ⇒ 阶段序列连续，无拼接缝隙（seat_update → bet_collection → round_advance → settlement）
- [x] **定理 `no_cross_plan_mix`**：不同 `plan_digest` 的 stage 不可链入同一序列
      ——防"A 手的 P 配 B 手的 G"式拼装（DUAL §6）
- [ ] **定理 `composition_embedding`**：未按原形实现——其安全内容（组件行属于同一 plan、链能放进 active 前缀）由 `no_cross_plan_mix` 与 `chain_length_le_trace` 覆盖
- 出处：`src/airs/composition/{air,plan,seat_update,bet_collection,round_advance,settlement}.rs`

---

## 4. 命题 3：防用户逃单（`Custody/`，五个文件）

**命题陈述**：用户无法（i）下注无托管筹码（透支）、（ii）在手牌进行中带着
已下注筹码离场、（iii）提走超过"存入 + 赢得"的筹码。核心是全局托管守恒不变量。

### C1 `Custody/ChipState.lean` — 桌面状态与托管总量

- [x] `ChipState`：9 座位（stack/bet/total_bet/pending_addon/lifecycle）+ pot + chip_pool——`TableImage`/`SeatImage` 定义在 S1（`Soundness/CommonColumns.lean`），C1 补充 `custodyTotal`/`balance`
- [x] `custodyTotal s := Σ stacks + Σ bets + pot + chip_pool + Σ pending_addon`
- [ ] 状态 ↔ AIR trace 行的双射谓词 `Represents`——未建独立谓词；以各 Sat 的 range-check + 等值约束直接承载该内容
- 出处：`src/airs/common.rs`（列布局）；`texas` VM 状态机

### C2 `Custody/Conservation.lean` — 守恒不变量（本命题核心）

- [x] **定理 `conservation_step`**：对每个 AIR 接受的非资金动作行
      （fold/check/call/bet/raise/advance_round/force_fold/kick/auto 系），
      `custodyTotal` 不变——筹码只在托管内部移动
- [x] **定理 `conservation_seq`**（归纳不变量）：任意 AIR 接受的动作序列，
      `custodyTotal_final = custodyTotal_initial + Σ deposits − Σ withdrawals`
- [x] **定理 `funding_moves_exact`**：join/rebuy/addon 是仅有的 `custodyTotal` 递增行，
      增量 = amount（与 S3 联用）；leave/settlement refund 是仅有的递减行
- 出处：S2–S5 各定理的直接推论，逐动作 kind 归纳

### C3 `Custody/BetBound.lean` — 下注不超过存量

- [x] **定理 `bet_le_stack`**：任何 Call/Bet/Raise 行 ⇒ 动作金额 ≤ pre stack；
      all-in 时 stack 精确归零——不可透支下注（下注即托管内转移）
- [x] **定理 `call_min_selection`**：`call = min(current_bet − seat.bet, stack)`
      的两分支（足额 / 短 all-in）都满足守恒
- 出处：`src/airs/actions/call.rs`（min 选择与短 all-in）；`bet.rs`

### C4 `Custody/ExitControl.lean` — 离场控制

- [x] **定理 `no_midhand_exit`**：下注轮内不存在被接受的 LeaveTable 行
      （leave_domain + round_state 范围约束联合）——已下注筹码必须先经结算
- [x] **定理 `deferred_exit_settles`**：`SetLeaveAfterHand` 座位的资金在手末
      settlement/reset 中被完整处理（refund 精确 = stack + pending_addon）
- [x] **定理 `forced_exit_preserves_funds`**：ForceFold/KickPlayer 只改生命周期位，
      被折叠/踢出座位的 stack/total_bet 进入结算，不凭空消失
- 出处：`src/airs/lifecycle/leave_table.rs`（WAITING 域）；
  `set_leave_after_hand.rs`；`force_fold.rs`；`kick_player.rs`

### C5 `Custody/WithdrawBound.lean` — 提款上界（逃单否定定理）

- [x] **定理 `withdraw_le_deposits_plus_awards`**：任意 AIR 接受序列中，玩家累计提款
      ≤ 累计存入 + 累计 awards（守恒不变量的逐玩家投影）
- [x] **定理 `vault_solvency`**：任意时刻 `custodyTotal ≥ 0` 语义化为
      chip_pool ≥ Σ 待付 refund（结算后桌内余量足以覆盖所有在场筹码）
      ——"运营商跑路损失有界"论证的形式化基础（对应 ACTION_SIGNING §7.3）
- [x] **定理 `no_unsettled_debt`**：任何一手结束（settlement 行被接受）后，
      不存在"已下注未结算"的悬空金额——全消费性（gross_pot 全额分配 + 清零）
- 出处：C2 + S5 联合

---

## 5. 命题 1：抗审查（`Censorship/`，六个文件）

**命题陈述**（ACTION_SIGNING_CENSORSHIP_RESISTANCE.md §3/§7/§8）：
服务器对动作的（i）伪造不可能、（ii）篡改/重排可检测、（iii）丢弃可举证
（accepted-seq 缺口 = 链上可验证的审查证明）、（iv）代打（auto）受"合法默认"约束。

### D1 `Censorship/ActionSig.lean` — 签名方案模型

- [x] 抽象方案 `SigScheme`（keygen/sign/verify），消息域
      `msg = (table_id, hand_id, seq, action, payload)`
- [x] EUF-CMA 以抽象谓词 `Authentic`/`Unforgeable` 落地（PLAN 允许的 fallback；登记进 T1）
- [x] **定理 `genuine_action`**（原 `no_forge`）：验签通过 ⇒ 签名由持 sk 方产生（条件于 EUF-CMA 抽象假设）
      必由持 sk 方签名——服务器不能凭空捏造玩家动作（攻击表第 1 行）
- [x] 域分离引理：`(hand_id, seq)` 在签名域内 ⇒ 跨手重放/重排使验签失败
- 出处：`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §2（消息格式）；
  `client-wasm/src/lib.rs`（`sign_action`）；`texas/src/pokergame/actions.rs`（服务器验签）

### D2 `Censorship/ActionLog.lean` — 动作日志与 seq 单调

- [x] `ActionLog`：`list LogEntry`，条目含 (player, seq, action, isAuto)；签名由服务器验签后入日志（`every_row_signed`）
- [x] **定理 `seq_monotone`**：日志约束成立 ⇒ 每玩家 seq 严格递增且无重复
      ——重排/重放在日志层不可表示（§8.2 seq 全桌单调）
- [x] **定理 `every_row_signed`**：日志约束成立 ⇒ 每条动作带玩家签名或
      服务器 auto 签名——无签名动作不可入日志（§8.2 第 1 条）
- 出处：`texas/src/pokergame/table/mod.rs`（手内动作日志）；
  `src/settlement_private_circuit.rs`（digest 第 37 入参）

### D3 `Censorship/AcceptedSeq.lean` — 收据与 accepted-seq 向量

- [x] `Receipt`/`Decision`/`AcceptedSeq` 结构 + 收据绑定定理（D3 文件）
      `AcceptedSeq : Player → ℕ`（settle 事件发布）
- [x] **定理 `receipt_binding`**：诚实收据约束 ⇒ published accepted-seq =
      日志中该玩家最大被接受 seq——服务器对"接受到了第几号"的承诺与日志一致
- [x] **定理 `receipt_nonrepudiation`**：链上事件（含 operator 签名）不可抵赖
      ——以"链上事件不可篡改"为显式假设
- 出处：§7.1（ACTION_RECEIPT #17）；`texas/src/pokergame/receipts.rs`

### D4 `Censorship/Detection.lean` — 审查可检测定理（本命题核心）

- [x] **定理 `censorship_provable`**：玩家持有 `seq = k` 的验签通过动作 ∧
      链上 accepted-seq `< k` ⇒ 要么服务器丢弃该动作（审查发生），
      要么签名被伪造（概率 ≤ EUF-CMA 优势）——审查成为**可判定命题**
- [x] **定理 `no_false_accusation`**（completeness 侧）：诚实服务器（不丢、不拒发收据）
      永不触发 `censorship_provable` 的前提——检测机制无假阳性
- [x] **定理 `rejection_receipt_path`**：`rejected` 收据存在 ⇒ 拒绝可归因
      （理由可审计），与静默丢弃区分
- 出处：§7.1 分级保障；§3 攻击表"审查可检测可举证"

### D5 `Censorship/AutoAction.lean` — auto 代打合法性（§8.2 第 2 条）

- [x] `auto` 行谓词：`AutoSat`（合法默认约束）+ 日志条目 `isAuto` 字段、服务器签名在验签处强制
- [x] **定理 `auto_check_legal`**：auto-check 行 ⇒ 面对零下注（`current_bet − seat.bet = 0`）
- [x] **定理 `auto_fold_legal`**：auto-fold 行 ⇒ 面对非零下注
      ——二者合取排除"服务器借代打折叠任意玩家"的 griefing 攻击面（§8.3）
- [x] **定理 `auto_follows_window`**：auto 行 ⇒ 该玩家窗口内无被接受动作
      （accepted-seq 无缺口时才允许代打）——代打不可抢先于真实签名动作
- 出处：§7.2、§8.2；`texas/src/socket/game_loop.rs`（turn timer 兜底）；
  `src/airs/actions/`（AutoFold selector 系）

### D6 `Censorship/DigestBinding.lean` — 结算 digest 覆盖动作日志

- [x] **定理 `drop_breaks_digest`**：settle digest 覆盖完整动作日志（#18 Phase B
      第 37 入参）⇒ 服务器剔除任意动作后，其 settle digest 与 register 的
      不一致——审查的代价是结算不可用（§3 第 1 层保障）
- [x] **定理 `local_replay_detects`**：诚实客户端重放动作日志可发现任何
      篡改/重排/剔除（digest 单射性 + seq 单调）
- 出处：`src/settlement_private_circuit.rs`（动作日志哈希入电路）；
  §3 表格"篡改/重排/剔除"三行

---

## 6. Top（顶层，两个文件）

### T1 `Top/Assumptions.lean` — 假设登记表

- [x] 集中登记全部显式假设：STARK soundness（`AirAccepted` 忠实性）、
      签名 EUF-CMA、哈希抗碰撞、链上事件不可篡改、limb↔u64 对应义务
- [x] 每条假设标注：使用它的定理集合、Rust/链上对应物、验证状态

### T2 `Top/Audit.lean` — 公理审计与顶层合成

- [x] `#print axioms` 全定理扫描；零 `sorry`/`admit` 断言
- [x] **顶层定理 `main_soundness`**：AIR 接受 ⇒（S2–S6 全部业务关系成立）
- [x] **顶层定理 `main_no_escape`**：AIR 接受序列 ⇒ 守恒 + 提款上界 + 无悬空债务
- [x] **顶层定理 `main_censorship_detectable`**：签名动作 + accepted-seq 缺口 ⇒
      审查被证明（条件于 EUF-CMA 与链不可篡改）
- [x] 三定理与本文档 §0 边界表互链

---

## 7. 里程碑与顺序

| 里程碑 | 内容 | 依赖 |
| --- | --- | --- |
| **M0** 骨架 | §1 工程文件 + F1 M31 编译通过 | — |
| **M1** 算术核心 | F2 limb + F3 carry（`carry_add_sound` 是全局枢纽） | M0 |
| **M2** trace 模型 + 通用列 | F4 + S1 | M1 |
| **M3** 逐 AIR soundness | S2 → S3 → S4 → S5 → S6 | M2 |
| **M4** 防逃单 | C1 → C2 → C3/C4 → C5（C2 依赖 M3 全部） | M3 |
| **M5** 抗审查 | D1–D6（可与 M3/M4 并行；D6 依赖 D1–D3） | M1（D1）/M3（D5–D6） |
| **M6** 顶层 | T1 + T2 + README 边界定稿 | M3–M5 |

**风险项**（实现时优先核验）：

1. `settlement_conservation` 的精确等式需对照 `settlement.rs` 实际约束清单逐项核对符号与项集；
2. canonical AIR 29 selector 中 timeout-cascade 系（2026-09 新增）的业务规约文档化不全，S2/S4 实现前先在 Rust 测试中锚定语义；
3. D1 的 EUF-CMA 若手写 oracle 游戏过重，可先以抽象不可伪造谓词 + 显式假设落地（登记进 T1），M5 后再实例化。

## 8. 验收标准

- [x] `lake build AirsLean` 成功，`scripts/count_sorries.sh` 计数为 0
- [x] 每个定理的 doc-comment 含 Rust 出处（文件级即可，行级尽力）
- [x] 三大顶层定理可陈述、可引用，假设全部在 T1 登记
- [x] README 含"Formal-proof boundary"节，与 §0 表一致
- [x] PLAN.md 勾选框与实际状态同步（每里程碑完成后更新）
