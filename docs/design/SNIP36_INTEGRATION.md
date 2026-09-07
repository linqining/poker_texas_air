# SNIP-36 接入设计（in-protocol proof verification → DAPV）

> **Summary (EN).** The single design doc for SNIP-36 integration; decision
> record: dual-proof in one (§3). **Phase 1 is shipped** — dual v5
> (`verify_and_settle_dapv_stark_private_v3`: in-protocol SNIP-36 verification
> with fact-registry fallback) deployed on Starknet mainnet 2026-09-07, with
> real SNIP-36 private transactions on mainnet; deployment/wiring details in
> `poker_contracts/DEPLOYMENTS.md`. Remaining follow-ups (prover tooling, SNOS
> form) are tracked in `docs/TODO.md`. Binding scheme and settlement
> algorithm: see `docs/SOUNDNESS.md` (P-layer pillar). Chinese is the working
> language of this spec.
>
> 状态：**Phase 1 已落地（dual v5，2026-09-07 主网）**——
> `verify_and_settle_dapv_stark_private_v3`（SNIP-36 协议内验证 +
> fact-registry 降级双门）已部署主网，主网已有真实 SNIP-36 私密交易。
> 决策记录：hand_verify 形态裁决 = **双证明合一**（§3）。
>
> **2026-09-06 核对修订**：SNIP-36 **未被废弃**——已随 Shinobi 升级于
> **2026-04-21 主网激活**（Starknet v0.14.2），现为 STRK20/strkBTC 隐私的
> 核心基础设施。此前文档中"SNIP-36 新版本不支持"系对 prover 工具链版本
> 问题的误传，不是协议状态；协议侧无等待项，缺口全部在我方（§5）。
> 原执行计划（`plan-snip36-execution.md`）已删除，见 git 历史。
> 关联：`docs/SOUNDNESS.md`（绑定方案/结算验证算法，原 DAPV_SOUNDNESS §9-10）、
> `poker_contracts/DEPLOYMENTS.md`（部署档案）、
> `docs/TODO.md`（任务状态以 TODO 为准）。

## 1. SNIP-36 机制（与 fact-registry 的对照）

SNIP-36 = **协议内 S-Two 证明验证**（Starknet v0.14.2+）：不再部署
Cairo verifier 合约 + fact registry，由协议/共识直接验证 stwo-cairo 证明。

| | fact-registry（现状） | SNIP-36（目标） |
| --- | --- | --- |
| 证明验证方 | 运营侧离线验证，人工登记 fact | 协议在 tx 执行内验证 |
| 信任锚 | 运营方背书（residual trust） | Phase 1：sequencer/consensus 验证（**同级**残差信任，非 SNOS）；后续：SHARP 集成 → 以太坊 L1 终局验证（真升级） |
| 合约消费 | `settlement_facts.read(fact)` | `get_execution_info_v3_syscall().tx_info.proof_facts` |
| 注册动作 | `register_settlement_fact`（prover/owner 门控） | **无注册**——`create_proof` 入口（发 `to_address=0` 的 L2→L1 消息）是被证明对象 |
| fact 公式 | `poseidon([program_hash, segment])` | `proof_facts[8] = poseidon(合约地址, 0, payload_len, payload)`；`facts[2] = virtual_OS_prog_hash` |
| 证明数据位置 | 不上链 | `proof` 字段（uint32 数组）只经 gateway/mempool 传播，**不进 calldata、不进区块**（绕过 5K felt calldata 上限——这正是 SNIP-36 的动机） |
| 计费 | 一个 felt 的存储 | **125（传播）+ 5（存储）= 130 L2gas/byte + 10M L2gas 基础**；规范示例 500KB ≈ 75M L2gas（生产锚点，STRK20 隐私在用） |

流程：一笔 INVOKE_V3（调 `create_proof` 形态入口）不广播 → 证明服务
（`starknet_os_runner::starknet_proveTransaction`，被证明对象是**虚拟
Starknet OS** 程序形态）对照参考区块状态离线执行产出证明 → 提交时
携带 `proof`/`proof_facts` 字段，tx hash 附加 `proof_facts_hash` →
sequencer 验证后传播 → settle 入口内读 `proof_facts` 做绑定断言。

## 2. 仓库现状与关键判定（2026-09-06，二次核对修订）

- **协议侧无等待项**：SNIP-36 已主网激活（2026-04-21）。此前"新版本不
  支持"的判断撤销；工作全部在我方形态适配与成本压缩。
- **证明系统同族**：proving-tool 管线已是 `Cairo1 → compile → run →
  witness → stwo prove`（`proof.json`/`public_outputs.json`），无需换
  证明系统。但 SNIP-36 被证明对象是**虚拟 Starknet OS 程序**形态——
  我方 Cairo 程序需适配 `starknet_proveTransaction` 的执行/证明上下文，
  不是裸 prove-hand 产物直连（§5 #1 的实质）。
- **证明尺寸实测（2026-09-06，felt 计数 × 4B 二进制估算）**：
  settlement 电路 12.2MB JSON ≈ 575k felts ≈ **2.30MB**；hand-verify
  composed 19.5MB JSON ≈ 879k felts ≈ **3.52MB**。对照生产锚点
  500KB（≈75M L2gas）：超锚点 **4.6×/7×**（≈300M/460M L2gas）——
  不是不可行，是需要参数收紧 + 批聚合摊薄（§3a）。注意 hand-verify
  评估实测证明尺寸与手数基本无关（1 手 14.3MB vs 10 手 14.1MB），
  即**批聚合不增加证明字节**，单位成本随批大小线性下降。
- **合约侧硬前提缺口**：cairo **2.11.4** 的捆绑 corelib **不含**
  `TxInfo.proof_facts`（`strings scarb | grep -c proof_facts` = 0；
  `third_party/corelib-2.19.4/corelib/src/starknet/info.cairo:323` 已含
  `pub proof_facts: Span<felt252>`）。消费路径要求 **cairo ≥ 2.12**——
  这是一次编译器迁移（92 个 snforge 测试 + casm 哈希 + 字节码上限全部
  重验），归入 §5 的 SNIP-36 腿，不与零风险项混做。
- **libfuncs 已放开**：`poker_contracts/Scarb.toml` `[cairo]
  allowed-libfuncs-list.name = "all"`（`get_execution_info_v3_syscall`
  在白名单之外；当前代码未用白名单外 libfunc，零行为变化）。
- **后端入口选择已预埋**：`STARKNET_DAPV_SETTLE_ENTRY` = `v2`（默认，
  可随时回退）| `proved_private`（双 fact，dual v4 已上链）| `snip36`
  （v3 入口选择器已预埋，**合约侧随 cairo ≥2.12 迁移上链后生效**——
  选中后发往现网会 revert，属预期）。

## 3. 裁决：hand_verify 形态 = 双证明合一（ADR-2026-09-06-1）

**决定**：SNIP-36 路径下不再保留独立的 hand_verify 证明——把
hand_batch σ 批量校验（ρ 折叠 MSM）**并进 settlement_private 电路**，
单证明覆盖「批次校验成立 ∧ 结算派生正确」。

理由：
1. **避开 EC_OP 在 SNIP-36 下的不确定性**：hand-verify form-① 是原生
   stwo AIR（非 Cairo 程序），根本进不了 SNIP-36；form-②（Cairo EC_OP
   composed）可以，但 EC_OP builtin 在虚拟 OS 上下文的支持需单独验证。
   并进 settlement 电路后 EC 方程与现有电路共用证明上下文，一处验证。
2. **省一半证明费**：SNIP-36 证明数据费 ≈ 10M L2gas 基础 + 130/byte；
   两张证明 → 一张。
3. **fact 结构消解**：`p_batch_commitment` 进公开段（尾词或替换
   `hand_verify_program_hash` 绑定），合约双 fact 断言退化为单 fact。

**代价与边界**：
- 电路步数增加：σ 折叠 MSM ≈ 每手 700 方程（2 人手 ~90 条）→ Cairo
  EC_OP 步数线性放大，prove 时间与 proof 尺寸重估（现 2048 步基线）。
- `p_batch_commitment`（`poseidon(hand_binding, poseidon(p_batch words))`)
  必须由电路内部重算（输入 = 批次词），不能作为外部断言——否则证明
  只覆盖「给定承诺的结算」而非「真实批次的结算」。
- 双 fact 入口（`verify_and_settle_dapv_proved_private`）保留至合一
  电路上链，作为过渡期双保险；届时退役
  `set_hand_verify_program_hash`（owner 门控，天然可退役）。

## 4. 合约 v3 双门入口设计（cairo ≥2.12 上链时实施）

```cairo
/// P2-M5：SNIP-36 优先、fact-registry 降级的双门私密结算。
/// calldata 与 v2 完全一致：[hand_binding, hand_id, segment(15)]。
fn verify_and_settle_dapv_stark_private_v3(
    ref self: ContractState,
    hand_binding: felt252,
    hand_id: u64,
    segment: Span<felt252>,
) {
    // ……（与 v2 相同的注册侧/公开段断言：magic/hand_id/binding/digest/
    //    action_log/n 范围）……

    // —— 双门：SNIP-36 优先，fact-registry 降级 ——
    let exec = get_execution_info_v3_syscall().unwrap_syscall();
    let facts = exec.tx_info.proof_facts;
    let snip36_ok = !facts.is_empty() && {
        // facts[2] = virtual_OS_prog_hash 必须等于钉死电路哈希
        *facts.at(2) == self.circuit_program_hash.read()
        // facts[8] = 消息哈希：poseidon([本合约地址, 0, payload_len, payload])
        // payload 即 segment（create_proof 入口发出的公开段）——逐 felt 重算比对
        && *facts.at(8) == message_hash_for_segment(get_contract_address(), segment)
    };
    if !snip36_ok {
        // 降级：fact-registry（过渡期信任锚，与 v2 同门）
        let program_hash = self.circuit_program_hash.read();
        assert!(program_hash != 0, "Circuit program hash not set");
        assert!(
            self.settlement_facts.read(fact_for_segment(program_hash, segment)),
            "Settlement fact not registered"
        );
    }
    // ……（与 v2 相同的私密派奖：escrow + claim_cms + amounts_hidden）……
}

fn message_hash_for_segment(self_addr: ContractAddress, segment: Span<felt252>) -> felt252 {
    let mut h = PoseidonTrait::new();
    h = h.update(self_addr.into());
    h = h.update(0);
    h = h.update(segment.len().into());
    let mut w: u32 = 0;
    while w < segment.len() { h = h.update(*segment.at(w)); w += 1; }
    h.finalize()
}
```

> 注意：`facts[8]`/`facts[2]` 的槽位与消息哈希公式以 SNIP-36 最终规范
> 为准（skill 参考实现：poseidon(合约地址, 0, payload_len, payload)）；
> 上链前用 sepolia 真实 proof_facts 样本对拍一次再冻结常量。

## 5. 缺口状态表（2026-09-06 二次核对修订）

| # | 工作项 | 状态 |
| --- | --- | --- |
| 7 | Phase 1 安全边界落档（本文 §1/§2） | ✅ 2026-09-06（同日修订：协议已主网激活，无协议等待项） |
| 3a | libfuncs `all`（Scarb.toml） | ✅ 2026-09-06（构建 0 错、snforge 92/92） |
| 0 | **证明瘦身实测**（新增，SNIP-36 直连的先决量化项） | ⏳ 目标 ≤500KB 级：紧凑二进制已定基（2.30MB）；FRI 参数收紧（70→30 queries 等）对**尺寸**的影响未实测（此前只测了时间 −11%/−26%）；批聚合摊薄单位成本（尺寸与手数无关已实测） |
| 3b | 合约 proof_facts 消费路径（§4 v3 入口） | ✅ 2026-09-07：cairo 2.19.4 迁移 + v3 双门入口上链（dual v5 `0x29bdc970...`，snforge `cheat_proof_facts` mock 四例全绿） |
| 5 | hand_verify 形态裁决 = 双证明合一（§3 ADR） | ✅ 已裁决；电路合并待做 |
| 1 | 电路改造为 create_proof 入口 + 虚拟 SNOS 形态适配 | ⏳ §3 规格；被证明对象是虚拟 Starknet OS 程序（`starknet_proveTransaction` 上下文），非裸 prove-hand 产物 |
| 2 | 证明管线切换（`starknet_os_runner` 自托管 prover） | ⏳ 规范给了 JSON-RPC 接口（`starknet_proveTransaction` → base64 proof + proof_facts + messages）；stwo 同族已确认 |
| 4 | 提交工具（Invoke V3 `proof`/`proof_facts` 字段的 account.execute 扩展 + snops submit-proof） | ⏳ 后端 `snip36` 选项已预埋；激活随 3b |
| 8 | snforge mock + sepolia 复现 | ✅ mock 部分（0.63 `cheat_proof_facts`）；sepolia 真实 proof_facts 样本对拍随 P4 |

**cairo ≥2.12 迁移**：✅ 2026-09-07 完成——scarb 2.19.4 + snforge 0.63.0
（与证明侧 vendored corelib 2.19.4 同版，双工具链合一）；91/91 测试；
casm 36,508 felts（2.11.4 时代 81,175 → 编译器瘦身 55% 余量）；
dual v5 已上链（见 DEPLOYMENTS.md）。测试命令：
`PATH=~/.local/opt/toolchains/scarb-2.19.4/bin:~/.local/opt/toolchains/snforge-0.63.0/bin:$PATH snforge test`。
