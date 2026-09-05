# airs_lean

Lean 4 + Mathlib 对 `poker_texas_air` AIR 约束层（`src/airs/` 的 19 个
method AIR、`src/airs/composition/` 组件与 `src/texas_canonical_air.rs`）
的审计形式化，覆盖三大命题：

1. **抗审查**（`AirsLean.Censorship.*`）
2. **约束 soundness**（`AirsLean.Soundness.*`）
3. **防用户逃单**（`AirsLean.Custody.*`）

实现清单、定理列表与出处对照见 [PLAN.md](PLAN.md)。

## 构建与审计

```bash
cd src/airs_lean
lake build AirsLean          # 零错误构建
bash scripts/count_sorries.sh  # total sorry/admit: 0
```

公理审计（关键定理）：

```bash
cat > /tmp/axcheck.lean <<'EOF'
import AirsLean
open AirsLean
#print axioms Top.main_soundness
#print axioms Top.main_no_escape
#print axioms Top.main_withdraw_bound
#print axioms Top.main_censorship_detectable
#print axioms drop_breaks_digest
EOF
lake env lean /tmp/axcheck.lean
```

结果：三大主定理仅依赖标准公理
`[propext, Classical.choice, Quot.sound]`；`drop_breaks_digest` 额外依赖
两条**登记过的**假设公理 `actionDigest`/`digest_inj`（哈希抗碰撞）。

## 结构

```
AirsLean/
├── Foundations/           M31 素域、4×16-bit limb 编码、逐 limb 进位算术、
│   ├── M31.lean           trace/约束模型、one-hot selector、padding 划分
│   ├── Limbs.lean
│   ├── CarryArith.lean
│   └── TraceModel.lean
├── Soundness/             命题 2：约束 ⇒ 业务关系
│   ├── CommonColumns.lean 37 通用列：call_seq/version 递增、作用域绑定、
│   │                      kind 唯一、全 padding trace 拒绝
│   ├── ActionAIRs.lean    fold/check 资金不可变、call 守恒/min/all-in、
│   │                      bet 上界、raise 重开（TDA #41）、轮转不跳座
│   ├── FundsAIRs.lean     join/rebuy/addon 精确增量、MAX_TOTAL_BET 上界
│   ├── LifecycleAIRs.lean 退款守恒、离桌 WAITING 域、晋升单向、授权绑定
│   ├── RoundAndSettlement.lean  收注守恒、结算全额分配、digest 不可变
│   └── Composition.lean   stage 链连续、无跨计划拼装
├── Custody/               命题 3：防逃单
│   ├── ChipState.lean     custodyTotal / balance 不变量
│   ├── Conservation.lean  单步 + 序列守恒（含存入/支出出入口）
│   ├── BetBound.lean      call/bet/raise 不可透支
│   ├── ExitControl.lean   下注轮不可离桌、延迟离桌精确退款、强制离场保全
│   └── WithdrawBound.lean 提款 ≤ 存入 + 奖金；金库偿付能力
├── Censorship/            命题 1：抗审查
│   ├── ActionSig.lean     签名模型、动作真实性、域分离
│   ├── ActionLog.lean     seq 严格递增 ⇒ 重放/重排不可表示
│   ├── AcceptedSeq.lean   收据绑定、审查可证明、无假阳性、拒绝可归因
│   ├── AutoAction.lean    代打合法默认（auto-check 零下注 / auto-fold 有注）
│   └── DigestBinding.lean 剔除/篡改破坏 settle digest（抗碰撞假设）
└── Top/
    ├── Assumptions.lean   显式假设登记表
    └── Audit.lean         三大命题顶层合成定理
```

## Formal-proof boundary

机器证明的部分：

- M31 域上的 limb 加法/进位约束与 u64 语义的等价
  （`add_sat_sound` / `add_complete`）——全部资金约束"在 M31 域成立 ⇒
  在 u64 语义成立"的枢纽；
- limb range check 的充分性与必要性（`decode_encode` / `limb_range_necessary`）；
- 通用列的 call_seq/version 递增、作用域绑定、kind 唯一、padding 拒绝；
- 各 AIR 家族的业务关系（资金守恒、不可透支、离桌域、结算分配、代打
  合法性、重放/重排排除、提款上界）。

不在证明范围内的（显式边界，见 `Top/Assumptions.lean`）：

- Stwo prover/verifier 本身（FRI、承诺绑定）——以 `Sat cs t` 抽象；
- Rust 约束表达式 ↔ Lean 谓词的逐条对应——审计义务项，每个 Lean 谓词
  的 doc-comment 注明 Rust 出处；
- 哈希抗碰撞（`actionDigest`/`digest_inj` 公理）；
- 签名方案 EUF-CMA（`Authentic` 谓词；Schnorr 层已在
  `poker_protocol_lean` 单独形式化）；
- L1 合约执行与链上事件不可篡改（共识层假设）。
