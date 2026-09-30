//! 聚合链 host 层：K 手语句 → 批 → 叶预映像/H1 → 折叠计划 → 累加链接。
//!
//! 两种手段形态（同一骨架，不同叶载荷）：
//! - **wrap（baseline，保留勿动）**：[`HandEntry`] 段 = prove-hand 公开内存
//!   段 16 词（长度前缀 15 + 'SP2M_OK' + 14），fact 由
//!   `WrapWitness::expected_fact` 吞含前缀整段；
//! - **combined（本层新形态）**：[`CombinedHandEntry`] 输出 = combined.cairo
//!   合并信封公开输出 16 词（`[chain_acc] ++ v2 公开段 15`，无长度前缀），
//!   fact = [`combined_expected_fact`]（program_hash 后跟整段 16 词——
//!   合约 `fact_for_segment` 同式）。
//!
//! # 公式出处（凡「精确镜像」均为逐式复刻，测试钉死）
//!
//! - **fact（wrap）**：`poseidon_hash_many([program_hash ‖ 16-felt 段])`
//!   （fact-verify/src/lib.rs:78-83 `fact_for_output` 同式；见证侧复用
//!   `groth16_wrap::wrap_circuit::WrapWitness::expected_fact`，两者在
//!   groth16-wrap 内已被对拍）。
//! - **fact（combined）**：`poseidon_hash_many([program_hash ‖ 16 词公开
//!   输出])`（poker_dual_settlement.cairo:302 `fact_for_segment` 同式——
//!   对 combined 合约入口，与 v2 的 15 词段式不同源）。
//! - **keccak 批根**：leaf_i = keccak256(index_be32 ‖ program_hash ‖ binding ‖
//!   fact)，两两折叠，条数 2 的幂（`groth16_wrap::batch::keccak_batch_root`，
//!   与 zchain SettleBatch.sol:99-119 链上重算逐式一致——该一致性已由 zchain
//!   forge 金向量测试钉死，本 crate 直接复用同一函数，不另写实现；
//!   statements 形状两形态同构 → 批根不受手段形态影响）。
//! - **32B hi/lo 拆分**：`split32_hi_lo`（groth16-wrap/src/batch.rs:46-55 同式；
//!   keccak 256bit 输出 ~17% 概率 ≥ r_BN254/felt P，单 felt 承载有损，故拆两 felt）。
//! - **叶输出 H1**：`blake2s(cairo-felt 编码(preimage))` 的 8 个 LE u32 词
//!   （third_party/proving crates/stwo_run_and_prove_recursive_tree/src/leaf_io.rs:44-63
//!   `LeafInput::output_values` 的精确宿主镜像；编码用同一库函数
//!   starknet-types-core 0.2.4 `Blake2Felt252::encode_felts_to_u32s`，精确性同源）。
//!   preimage = `[program_hash] ++ concat(K×段)`（wrap 段 16 词含前缀 /
//!   combined 输出 16 词无前缀）—— 与
//!   leaf_proof_format/src/lib.rs:75-77 `Plain.output_preimage`（"the task's
//!   program hash followed by the task's raw output"）同形状。
//! - **累加链接（本 crate 的协议定义，新增）**：
//!   `batch_fact_n = poseidon_hash_many([aph ‖ 根输出 8 felts ‖ acc_{n-1} ‖ 根hi ‖ 根lo])`，
//!   `acc_0 = 0`，`acc_n = batch_fact_n`。批 n 的终证语句把 acc_{n-1}（即批 n-1
//!   的 fact）与 keccak 根一并位绑定进电路 → 篡改任一历史 fact / 换批序 /
//!   换批根都会使终证验证失败（tests/root_wrap_k2.rs 负例实证）。
//!
//! # K/L 政策（内存纪律）
//!
//! `MAX_HANDS_PER_LEAF = 64`：canonical_small trace 地板 2^20 行
//! （third_party/proving crates/circuit_params/src/lib.rs:227 原文 "20 for
//! canonical_small"），实测单手 5374 steps（proving-tool/output/settlement/
//! summary.json:22）→ 上限 ~195 手，取 64 留 3× 余量（bootloader/H1/段开销，
//! 架构 §K/L 选择依据）。

use anyhow::{anyhow, Context, Result};
use ark_ff::PrimeField as _;
use groth16_wrap::batch::{keccak_batch_root, BatchStatement};
use groth16_wrap::felt::{felt_from_hex, felt_to_starknet, Felt252};
use groth16_wrap::poseidon::poseidon_hash_many;
use groth16_wrap::wrap_circuit::{WrapWitness, HAND_BINDING_INDEX};
use starknet_types_core::hash::Blake2Felt252;

/// 单叶（= 单份 Cairo 批证明）覆盖的手数上限（政策值，见模块注释 K/L 政策）。
pub const MAX_HANDS_PER_LEAF: usize = 64;
/// canonical_small 变体的 trace 行数地板（log2）——circuit_params/src/lib.rs:227。
pub const TRACE_FLOOR_LOG2: u32 = 20;
/// 单手实测 steps（proving-tool/output/settlement/summary.json:22）。
pub const MEASURED_STEPS_PER_HAND: u64 = 5374;
/// trace 预算安全系数（bootloader/H1/段开销；架构 K/L 选择依据）。
pub const TRACE_HEADROOM_FACTOR: u64 = 3;
/// 单批折叠树叶数上限（稳态 4-8，架构口径；政策上限留到 64）。
pub const MAX_LEAVES_PER_TREE: usize = 64;
/// 叶电路公开输出保留词数 = blake2s 摘要词数（circuit_common/src/lib.rs:13
/// N_RESERVED = circuits/src/blake.rs:20 BLAKE2S_DIGEST_N_WORDS = 8）。
pub const ROOT_OUTPUT_WORDS: usize = 8;
/// 累加链 genesis（acc_0 = 0）。
pub const ACC_GENESIS: u64 = 0;

/// 一条手语句 + 其 16-felt 公开段见证。
///
/// statement 三元组与电路/链上公开输入同形；segment 与
/// `groth16_wrap::wrap_circuit::WrapWitness.output` 同形。
#[derive(Debug, Clone)]
pub struct HandEntry {
    pub statement: BatchStatement,
    /// 长度前缀 15 + 'SP2M_OK' + 14 felts（wrap_circuit.rs:60-66 同形）。
    pub segment: Vec<Felt252>,
}

/// K 手批计划（= SHARP 一个 task 的语句面）。
#[derive(Debug, Clone)]
pub struct BatchPlan {
    pub program_hash: Felt252,
    pub hands: Vec<HandEntry>,
}

impl BatchPlan {
    /// 构造并逐条校验（fail-closed）：
    /// 1..=MAX_HANDS_PER_LEAF、条数 2 的幂（keccak 根折叠与 SettleBatch 同约束）、
    /// 段形状（MAGIC/前缀）、fact 宿主重算一致、binding 与段槽位一致、binding 无重复
    /// （SettleBatch.sol:127 DuplicateBinding 同政策，入链前先拒）。
    ///
    /// # Errors
    /// 任一校验失败（含具体手序号）。
    pub fn new(program_hash: Felt252, hands: Vec<HandEntry>) -> Result<Self> {
        check_hand_count(hands.len())?;
        let mut seen_bindings: Vec<Felt252> = Vec::with_capacity(hands.len());
        for (i, hand) in hands.iter().enumerate() {
            let witness = WrapWitness { output: hand.segment.clone() };
            witness.validate().map_err(|e| anyhow!("hand {i}: {e}"))?;
            let fact = witness.expected_fact(&program_hash);
            if fact != hand.statement.fact {
                return Err(anyhow!("hand {i}: fact != poseidon(program_hash ‖ output)（宿主重算不一致）"));
            }
            let binding_felt = hand.segment[HAND_BINDING_INDEX];
            if binding_felt != hand.statement.hand_binding {
                return Err(anyhow!("hand {i}: hand_binding != segment[{HAND_BINDING_INDEX}]"));
            }
            if seen_bindings.contains(&binding_felt) {
                return Err(anyhow!("hand {i}: duplicate hand_binding（SettleBatch DuplicateBinding 同政策）"));
            }
            seen_bindings.push(binding_felt);
        }
        Ok(Self { program_hash, hands })
    }

    /// 语句切片（keccak 根与链上公开输入的载荷）。
    #[must_use]
    pub fn statements(&self) -> Vec<BatchStatement> {
        self.hands.iter().map(|h| h.statement).collect()
    }

    /// keccak 批根（SettleBatch 链上校验并登记的根；精确复用 groth16-wrap 实现）。
    ///
    /// # Errors
    /// 条数非 2 的幂（构造时已拒，防御性保留）。
    pub fn keccak_batch_root(&self) -> Result<[u8; 32]> {
        keccak_batch_root(&self.statements()).context("keccak batch root")
    }

    /// 叶任务预映像：`[program_hash] ++ concat(K×16 段)`。
    ///
    /// 与 leaf_proof_format `Plain.output_preimage` 同形状（leaf_io.rs:30-35：
    /// "the task's program hash followed by the task's raw output"）。
    #[must_use]
    pub fn leaf_preimage(&self) -> Vec<Felt252> {
        let mut preimage = Vec::with_capacity(1 + self.hands.len() * groth16_wrap::wrap_circuit::OUTPUT_LEN);
        preimage.push(self.program_hash);
        for hand in &self.hands {
            preimage.extend_from_slice(&hand.segment);
        }
        preimage
    }

    /// 本批（单叶形态）的叶输出 H1（leaf_io.rs:44-63 精确镜像，见 [`leaf_output_words`]）。
    ///
    /// # Errors
    /// 内部编码失败（不发生：输入均为合法 felt）。
    pub fn leaf_output_words(&self) -> Result<[u32; ROOT_OUTPUT_WORDS]> {
        leaf_output_words(&self.leaf_preimage())
    }
}

/// K 政策校验（wrap / combined 两形态共用）：1..=MAX_HANDS_PER_LEAF 且
/// 条数 2 的幂（keccak 根折叠与 SettleBatch 同约束）。
fn check_hand_count(k: usize) -> Result<()> {
    if k == 0 {
        return Err(anyhow!("batch must contain at least one hand"));
    }
    if k > MAX_HANDS_PER_LEAF {
        return Err(anyhow!(
            "batch has {k} hands > MAX_HANDS_PER_LEAF={MAX_HANDS_PER_LEAF}（trace 地板 2^{TRACE_FLOOR_LOG2} 内的政策上限）"
        ));
    }
    if !k.is_power_of_two() {
        return Err(anyhow!("batch hand count must be a power of two, got {k}（SettleBatch keccak 根折叠同约束）"));
    }
    Ok(())
}

/// combined 信封公开输出词数：`[chain_acc] ++ v2 公开段(15)`，无长度前缀
/// （combined.cairo main 返回数组原样）。与 wrap 路径的
/// `groth16_wrap::wrap_circuit::OUTPUT_LEN`（16 = 长度前缀 1 + 返回 15）
/// 数值相同、语义不同——首词一个是折叠累计承诺、一个是长度前缀，
/// 勿混用（两常量并存即为此锚定）。
pub const COMBINED_OUTPUT_LEN: usize = 16;

/// combined 输出槽位（combined.cairo / 合约 verify_and_settle_dapv_
/// combined_private 的段布局，合约索引同值）。
pub const COMBINED_MAGIC_INDEX: usize = 1;
pub const COMBINED_BINDING_INDEX: usize = 5;

/// 一条 combined 手语句 + 其 16 词公开输出见证。
///
/// output = `[chain_acc, MAGIC('SP2M_OK'), hand_id, registered_digest,
/// n_expected, hand_binding, cm_0..cm_7, total_winnings, action_log_digest]`
/// ——combined.cairo（P 层递归 + settlement 语句一次出证）的公开输出，
/// 亦即链上 combined 入口的 segment 参数原样。statement 三元组与 wrap
/// 形态同构（keccak 批根/链上公开输入直接复用）。
#[derive(Debug, Clone)]
pub struct CombinedHandEntry {
    pub statement: BatchStatement,
    /// 16 词 combined 公开输出（无长度前缀，首词 chain_acc）。
    pub output: Vec<Felt252>,
}

/// combined fact：`poseidon_hash_many([program_hash ‖ 整段 16 词输出])`——
/// 与合约 `fact_for_segment`（poker_dual_settlement.cairo:302）同式；区别于
/// v2 合约入口的 15 词段式（texas settlement_prover::settlement_fact）。
#[must_use]
pub fn combined_expected_fact(program_hash: &Felt252, output: &[Felt252]) -> Felt252 {
    let mut felts = Vec::with_capacity(1 + output.len());
    felts.push(*program_hash);
    felts.extend_from_slice(output);
    poseidon_hash_many(&felts)
}

/// K 手 combined 批计划（= SHARP 一个 task 的语句面，combined 信封形态）。
///
/// 与 [`BatchPlan`]（wrap baseline，保留勿动）并列：不用 enum 泛化
/// `HandEntry` 的原因——两形态的段语义（长度前缀 vs chain_acc 首词）与
/// fact 公式锚点不同，混装一个批必然歧义；独立类型让旧路径零改动、
/// 编译期即禁止混装，K 政策/keccak 根/叶 H1 经共享函数复用
/// （`check_hand_count` / `keccak_batch_root` / [`leaf_output_words`]）。
#[derive(Debug, Clone)]
pub struct CombinedBatchPlan {
    pub program_hash: Felt252,
    pub hands: Vec<CombinedHandEntry>,
}

impl CombinedBatchPlan {
    /// 构造并逐条校验（fail-closed，逐手标注序号）：
    /// 1..=MAX_HANDS_PER_LEAF、条数 2 的幂、输出形状（恰 16 词、
    /// `output[1] == MAGIC`、`output[5] == statement.hand_binding`）、
    /// fact 宿主重算一致（[`combined_expected_fact`] 新公式：program_hash
    /// 后跟整段 16 词）、binding 无重复。
    ///
    /// # acc 链信任边界（如实声明，不伪造校验）
    ///
    /// 跨手 acc 链（手 i 的 prev_acc = 手 i-1 的 `output[0]`）在本层**不可
    /// 校验**：折叠 claim 词是证明的私有输入，宿主只有公开输出——连首手
    /// prev_acc 是否等于调用方预期都无法读出（`output[0]` 是折叠**后**的
    /// 新 acc，prev_acc 不在输出里）。该不变量由生产者侧把关：
    /// hand-verify-native `combined.rs::prove_combined_layer` 的 host acc
    /// parity 门（host `host_fold_tasks` 独立重算）+ texas 的
    /// `data/combined_acc.txt` acc 状态文件。本层保证的只有：chain_acc
    /// 进 fact 预映像首词（篡改 `output[0]` 必改 fact → 批根/终证语句全变，
    /// 测试 `combined_chain_acc_is_fact_bound` 钉死）。
    ///
    /// # Errors
    /// 任一校验失败（含具体手序号）。
    pub fn new(program_hash: Felt252, hands: Vec<CombinedHandEntry>) -> Result<Self> {
        check_hand_count(hands.len())?;
        let magic = Felt252::from(groth16_wrap::wrap_circuit::SEGMENT_MAGIC);
        let mut seen_bindings: Vec<Felt252> = Vec::with_capacity(hands.len());
        for (i, hand) in hands.iter().enumerate() {
            if hand.output.len() != COMBINED_OUTPUT_LEN {
                return Err(anyhow!(
                    "hand {i}: combined output len = {}, expected {COMBINED_OUTPUT_LEN}（[chain_acc] ++ v2 段 15，无长度前缀）",
                    hand.output.len()
                ));
            }
            if hand.output[COMBINED_MAGIC_INDEX] != magic {
                return Err(anyhow!(
                    "hand {i}: output[{COMBINED_MAGIC_INDEX}] must be MAGIC 'SP2M_OK' (0x5350324d5f4f4b)"
                ));
            }
            let fact = combined_expected_fact(&program_hash, &hand.output);
            if fact != hand.statement.fact {
                return Err(anyhow!(
                    "hand {i}: fact != poseidon(program_hash ‖ combined output_16)（宿主重算不一致）"
                ));
            }
            let binding_felt = hand.output[COMBINED_BINDING_INDEX];
            if binding_felt != hand.statement.hand_binding {
                return Err(anyhow!(
                    "hand {i}: hand_binding != output[{COMBINED_BINDING_INDEX}]"
                ));
            }
            if seen_bindings.contains(&binding_felt) {
                return Err(anyhow!("hand {i}: duplicate hand_binding（SettleBatch DuplicateBinding 同政策）"));
            }
            seen_bindings.push(binding_felt);
        }
        Ok(Self { program_hash, hands })
    }

    /// 语句切片（keccak 根与链上公开输入的载荷；形状与 wrap 形态同构）。
    #[must_use]
    pub fn statements(&self) -> Vec<BatchStatement> {
        self.hands.iter().map(|h| h.statement).collect()
    }

    /// keccak 批根（SettleBatch 链上校验并登记的根；精确复用 groth16-wrap
    /// 实现——statements 形状未变，批根不受 combined 重定基影响）。
    ///
    /// # Errors
    /// 条数非 2 的幂（构造时已拒，防御性保留）。
    pub fn keccak_batch_root(&self) -> Result<[u8; 32]> {
        keccak_batch_root(&self.statements()).context("keccak batch root")
    }

    /// 叶任务预映像：`[program_hash] ++ concat(K × output_16)`。
    ///
    /// 与 leaf_proof_format `Plain.output_preimage` 同形状（"the task's
    /// program hash followed by the task's raw output"——combined 任务的原
    /// 始输出即 16 词公开输出）。
    #[must_use]
    pub fn leaf_preimage(&self) -> Vec<Felt252> {
        let mut preimage =
            Vec::with_capacity(1 + self.hands.len() * COMBINED_OUTPUT_LEN);
        preimage.push(self.program_hash);
        for hand in &self.hands {
            preimage.extend_from_slice(&hand.output);
        }
        preimage
    }

    /// 本批（单叶形态）的叶输出 H1（leaf_io.rs:44-63 精确镜像，见
    /// [`leaf_output_words`]）。
    ///
    /// # Errors
    /// 内部编码失败（不发生：输入均为合法 felt）。
    pub fn leaf_output_words(&self) -> Result<[u32; ROOT_OUTPUT_WORDS]> {
        leaf_output_words(&self.leaf_preimage())
    }
}

/// 叶输出 H1：`blake2s(cairo-felt 编码(preimage))` 的 8 个 LE u32 词。
///
/// leaf_io.rs:44-63 逐式镜像：felt 编码 = `Blake2Felt252::encode_felts_to_u32s`
/// （types-core 0.2.4 hash/blake2s.rs:73-113，同一库函数故精确同源），摘要按
/// 8 个小端 u32 词读出（circuit_common N_RESERVED=8，circuits/src/blake.rs:20）。
///
/// # Errors
/// 内部编码失败（不发生：输入均为合法 felt）。
pub fn leaf_output_words(preimage: &[Felt252]) -> Result<[u32; ROOT_OUTPUT_WORDS]> {
    let felts: Vec<starknet_types_core::felt::Felt> =
        preimage.iter().map(|f| felt_to_starknet(f)).collect();
    // H1，与 Cairo `encode_felt252_data_and_calc_blake2s` 同一 u32 词编码；32 摘要字节
    // 按 8 个小端词读出（leaf_io.rs:55-62 原文语义）
    let encoded_bytes: Vec<u8> = Blake2Felt252::encode_felts_to_u32s(&felts)
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect();
    use blake2::Digest as _;
    let h1: [u8; 32] = blake2::Blake2s256::digest(&encoded_bytes).into();
    Ok(std::array::from_fn(|i| {
        u32::from_le_bytes(h1[i * 4..i * 4 + 4].try_into().expect("4 bytes"))
    }))
}

/// u32 词 → felt（终证哈希预映像用；u32 恒 < P，无损）。
#[must_use]
pub fn output_words_to_felts(words: &[u32; ROOT_OUTPUT_WORDS]) -> [Felt252; ROOT_OUTPUT_WORDS] {
    std::array::from_fn(|i| Felt252::from(words[i]))
}

/// 32B 根 → (hi, lo)（各 16 字节大端入域；batch.rs:46-55 同式）。
///
/// # Errors
/// 入参即 32B，不失败；保留 Result 以对称 join。
pub fn split_root_hi_lo(root: &[u8; 32]) -> (Felt252, Felt252) {
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&root[0..16]);
    let mut lo = [0u8; 32];
    lo[16..].copy_from_slice(&root[16..32]);
    (
        Felt252::from_be_bytes_mod_order(&hi),
        Felt252::from_be_bytes_mod_order(&lo),
    )
}

/// (hi, lo) → 32B 根（split 逆变换；链上重组式 `bytes32((hi << 128) | lo)`）。
///
/// # Errors
/// hi/lo ≥ 2^128（不是 split 的像；fail-closed）。
pub fn join_root_hi_lo(hi: &Felt252, lo: &Felt252) -> Result<[u8; 32]> {
    let two_pow_128 = {
        let mut b = [0u8; 32];
        b[15] = 1; // 2^128 大端
        Felt252::from_be_bytes_mod_order(&b)
    };
    anyhow::ensure!(*hi < two_pow_128, "hi >= 2^128: not a split image");
    anyhow::ensure!(*lo < two_pow_128, "lo >= 2^128: not a split image");
    let hb = groth16_wrap::felt::felt_to_be_bytes(hi);
    let lb = groth16_wrap::felt::felt_to_be_bytes(lo);
    let mut root = [0u8; 32];
    root[0..16].copy_from_slice(&hb[16..32]);
    root[16..32].copy_from_slice(&lb[16..32]);
    Ok(root)
}

/// 折叠树计划：平衡二叉树，深度 ceil(log2 L)；L=1 走自折叠根
/// （fold.rs:114-120 `reduce_root_single`：折叠自身，使根为普通 multiverifier 证明）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldPlan {
    /// 叶数（2 的幂；1 允许 = 自折叠根）。
    pub leaves: usize,
    /// 折叠步序列（layer 从 1 起；每步把上一层的两个条目折成一个）。
    pub steps: Vec<FoldStep>,
}

/// 一步折叠：`right = None` 表示自折叠（L=1 根通过；同 fold.rs:119 的
/// `reduce(input.clone(), input, …)` 形态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldStep {
    pub layer: usize,
    pub left: usize,
    pub right: Option<usize>,
}

impl FoldPlan {
    /// 构造平衡折叠计划。
    ///
    /// # Errors
    /// L = 0、L 非零且非 2 的幂（真实折叠器按满二叉树两两折叠，tests.rs 用例均
    /// 为 2 的幂）、L > MAX_LEAVES_PER_TREE。
    pub fn new(leaves: usize) -> Result<Self> {
        anyhow::ensure!(leaves >= 1, "tree needs at least one leaf");
        anyhow::ensure!(
            leaves <= MAX_LEAVES_PER_TREE,
            "leaves {leaves} > MAX_LEAVES_PER_TREE={MAX_LEAVES_PER_TREE}"
        );
        if leaves > 1 {
            anyhow::ensure!(
                leaves.is_power_of_two(),
                "leaf count must be a power of two, got {leaves}"
            );
        }
        let mut steps = Vec::new();
        if leaves == 1 {
            // 单叶自折叠根（fold.rs:114-120 同形：fold the lone leaf with itself）
            steps.push(FoldStep { layer: 1, left: 0, right: None });
        } else {
            let mut width = leaves;
            let mut layer = 1;
            while width > 1 {
                for pair in 0..width / 2 {
                    steps.push(FoldStep { layer, left: pair * 2, right: Some(pair * 2 + 1) });
                }
                width /= 2;
                layer += 1;
            }
        }
        Ok(Self { leaves, steps })
    }

    /// 折叠层数（ceil(log2 L)；L=1 亦为 1 —— 自折叠根层）。
    #[must_use]
    pub fn n_layers(&self) -> usize {
        self.steps.last().map(|s| s.layer).unwrap_or(0)
    }
}

/// 累加链 genesis acc（felt 0）。
#[must_use]
pub fn acc_genesis() -> Felt252 {
    Felt252::from(ACC_GENESIS)
}

/// 终证语句的 host 侧派生（root_circuit 电路的见证同源值）：
/// `fact = poseidon_hash_many([aph ‖ 根输出 8 felts ‖ acc_prev ‖ 根hi ‖ 根lo])`。
///
/// 返回 (hi, lo, fact)；hi/lo 同时是链上 bytes32 根的拆分（[`join_root_hi_lo`] 逆）。
#[must_use]
pub fn derive_batch_fact(
    aggregator_program_hash: &Felt252,
    root_output: &[u32; ROOT_OUTPUT_WORDS],
    acc_prev: &Felt252,
    keccak_root: &[u8; 32],
) -> (Felt252, Felt252, Felt252) {
    let (hi, lo) = split_root_hi_lo(keccak_root);
    let mut preimage = Vec::with_capacity(2 + ROOT_OUTPUT_WORDS + 2);
    preimage.push(*aggregator_program_hash);
    preimage.extend_from_slice(&output_words_to_felts(root_output));
    preimage.push(*acc_prev);
    preimage.push(hi);
    preimage.push(lo);
    let fact = poseidon_hash_many(&preimage);
    (hi, lo, fact)
}

/// 累加链接：批 n 的 acc = 批 n 的 batch_fact（批 n 终证语句绑定 acc_{n-1}）。
///
/// 折叠树/终证在电路内已把「根输出」钉进 fact；此处再把 keccak 根与历史链
/// 一并钉进 → 终证语句成为全历史的滚动承诺。
#[must_use]
pub fn acc_next(acc_prev: &Felt252, batch_fact: &Felt252) -> Felt252 {
    let _ = acc_prev; // acc_prev 已在 batch_fact 预映像内；acc 即 fact（见 derive_batch_fact）
    *batch_fact
}

/// 从 `0x…` hex 解析 felt（累加链/语句的 JSON 载荷用）。
///
/// # Errors
/// 非法 hex。
pub fn felt_from_hex_str(s: &str) -> Result<Felt252> {
    felt_from_hex(s).map_err(|e| anyhow!("bad felt hex {s:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use groth16_wrap::felt::{felt_from_hex, felt_to_hex};
    use groth16_wrap::golden;
    use groth16_wrap::wrap_circuit::HAND_BINDING_INDEX;

    /// 金向量段（与 groth16-wrap tests/roundtrip.rs:14-47 同源的真实形状公开段）。
    fn golden_hands(k: u64) -> (Felt252, Vec<HandEntry>) {
        let program_hash = felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap();
        let base_segment: Vec<Felt252> = golden::GOLDEN_OUTPUT
            .iter()
            .map(|h| felt_from_hex(h).unwrap())
            .collect();
        let hands = (0..k)
            .map(|i| {
                let binding = felt_from_hex(golden::GOLDEN_HAND_BINDING).unwrap()
                    + Felt252::from(i);
                let mut segment = base_segment.clone();
                segment[HAND_BINDING_INDEX] = binding;
                let fact = WrapWitness { output: segment.clone() }.expected_fact(&program_hash);
                HandEntry {
                    statement: BatchStatement {
                        program_hash,
                        hand_binding: binding,
                        fact,
                    },
                    segment,
                }
            })
            .collect();
        (program_hash, hands)
    }

    /// host fact 公式与 groth16-wrap 金向量钉死（跨 crate 公式一致性）。
    #[test]
    fn hand_fact_matches_golden() {
        let program_hash = felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap();
        let segment: Vec<Felt252> =
            golden::GOLDEN_OUTPUT.iter().map(|h| felt_from_hex(h).unwrap()).collect();
        let fact = WrapWitness { output: segment }.expected_fact(&program_hash);
        assert_eq!(felt_to_hex(&fact), golden::GOLDEN_FACT, "host fact 公式必须与金向量一致");
    }

    /// combined 金向量手：16 词输出 = [acc_i] ++ golden v2 段（去长度前缀
    /// 的 15 词），acc 链确定性生成（acc_{i+1} = poseidon([acc_i, i])——
    /// 生产者不变量的 host 镜像形态）、手序号进 hand_id 槽位、binding
    /// 逐手递增；fact 用 [`combined_expected_fact`] 新公式。
    fn combined_golden_hands(k: u64) -> (Felt252, Vec<CombinedHandEntry>) {
        let program_hash = felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap();
        let base_v2: Vec<Felt252> = golden::GOLDEN_OUTPUT
            .iter()
            .skip(1) // wrap 段 [0] = 长度前缀 15，combined 输出无前缀
            .map(|h| felt_from_hex(h).unwrap())
            .collect();
        assert_eq!(base_v2.len(), 15, "v2 公开段 15 词");
        let mut acc = acc_genesis();
        let hands = (0..k)
            .map(|i| {
                let binding = felt_from_hex(golden::GOLDEN_HAND_BINDING).unwrap()
                    + Felt252::from(i);
                let mut output = Vec::with_capacity(COMBINED_OUTPUT_LEN);
                output.push(acc);
                output.extend(base_v2.iter().copied());
                output[2] = Felt252::from(1_000u64 + i); // hand_id 槽位
                output[COMBINED_BINDING_INDEX] = binding;
                let fact = combined_expected_fact(&program_hash, &output);
                // 确定性 acc 链（单 claim 词折叠形态；只求金向量可复现）。
                acc = poseidon_hash_many(&[acc, Felt252::from(i)]);
                CombinedHandEntry {
                    statement: BatchStatement { program_hash, hand_binding: binding, fact },
                    output,
                }
            })
            .collect();
        (program_hash, hands)
    }

    /// combined fact 新公式钉死：`poseidon([program_hash ‖ 整段 16 词])`
    /// （合约 fact_for_segment 同式）——改 chain_acc 首词、换 ph、改任一
    /// 段词都必改 fact；并证与 wrap 段（含长度前缀）的 fact 不同源。
    #[test]
    fn combined_fact_formula_pinned() {
        let (ph, hands) = combined_golden_hands(1);
        let hand = &hands[0];
        // 独立重算（不经 helper）。
        let mut msg = Vec::with_capacity(1 + COMBINED_OUTPUT_LEN);
        msg.push(ph);
        msg.extend(hand.output.iter().copied());
        assert_eq!(
            felt_to_hex(&combined_expected_fact(&ph, &hand.output)),
            felt_to_hex(&poseidon_hash_many(&msg)),
            "combined fact 必须逐词同式"
        );
        assert_eq!(combined_expected_fact(&ph, &hand.output), hand.statement.fact);
        // 绑定性：chain_acc / ph / 段尾词（action_log）任一变动 → fact 变。
        let mut tampered = hand.output.clone();
        tampered[0] += Felt252::from(1u64);
        assert_ne!(
            combined_expected_fact(&ph, &tampered),
            hand.statement.fact,
            "chain_acc 是预映像首词（改 acc 必改 fact）"
        );
        let other_ph = ph + Felt252::from(1u64);
        assert_ne!(combined_expected_fact(&other_ph, &hand.output), hand.statement.fact);
        let mut tail = hand.output.clone();
        tail[COMBINED_OUTPUT_LEN - 1] += Felt252::from(1u64);
        assert_ne!(combined_expected_fact(&ph, &tail), hand.statement.fact);
        // 与 wrap 段（[15 前缀 ++ v2 段]）不同源：同一 v2 内容、两种首词
        // （chain_acc vs 15）→ fact 必不同。
        let mut wrap_style = hand.output.clone();
        wrap_style[0] = Felt252::from(groth16_wrap::wrap_circuit::SEGMENT_LEN);
        assert_ne!(
            combined_expected_fact(&ph, &wrap_style),
            combined_expected_fact(&ph, &hand.output),
            "长度前缀形态与 chain_acc 形态不可互换"
        );
    }

    /// K=2 combined 批：构造校验全过；keccak 根与直接复用一致（statements
    /// 形状未变 → 批根不受重定基影响）；叶预映像形状 [ph] ++ K×16。
    #[test]
    fn combined_batch_plan_k2_builds_and_roots() {
        let (ph, hands) = combined_golden_hands(2);
        let plan = CombinedBatchPlan::new(ph, hands.clone()).expect("K=2 combined plan");
        let root = plan.keccak_batch_root().unwrap();
        let direct = keccak_batch_root(&plan.statements()).unwrap();
        assert_eq!(root, direct);
        // acc 链在金向量内真的推进（手 1 的 chain_acc ≠ 手 0 的）。
        assert_ne!(hands[0].output[0], hands[1].output[0]);
        // 叶预映像形状与顺序敏感。
        let preimage = plan.leaf_preimage();
        assert_eq!(preimage.len(), 1 + 2 * COMBINED_OUTPUT_LEN);
        assert_eq!(preimage[0], ph);
        assert_eq!(&preimage[1..17], hands[0].output.as_slice());
        assert_eq!(&preimage[17..33], hands[1].output.as_slice());
        let mut swapped = hands.clone();
        swapped.reverse();
        let swapped_root =
            CombinedBatchPlan::new(ph, swapped).unwrap().keccak_batch_root().unwrap();
        assert_ne!(root, swapped_root, "批根必须对语句顺序敏感");
        // H1 可算且确定（叶预映像变化 → H1 变）。
        let w = plan.leaf_output_words().unwrap();
        assert_ne!(w, [0u32; ROOT_OUTPUT_WORDS]);
    }

    /// combined 批负例：词数 15/17、MAGIC 篡改、binding 不一致、fact 篡改、
    /// binding 重复、K=3 非 2 的幂——全部 fail-closed。
    #[test]
    fn combined_batch_plan_rejects_bad_shapes() {
        let (ph, mut hands) = combined_golden_hands(2);
        assert!(CombinedBatchPlan::new(ph, vec![]).is_err(), "空批拒绝");
        let short = {
            let mut h = hands[0].clone();
            h.output.pop();
            h
        };
        let err = CombinedBatchPlan::new(ph, vec![short, hands[1].clone()])
            .expect_err("15 词必须拒绝");
        assert!(format!("{err}").contains("hand 0"), "逐手标注序号：{err}");
        let long = {
            let mut h = hands[0].clone();
            h.output.push(Felt252::from(1u64));
            h
        };
        assert!(CombinedBatchPlan::new(ph, vec![long, hands[1].clone()]).is_err());
        let bad_magic = {
            let mut h = hands[0].clone();
            h.output[COMBINED_MAGIC_INDEX] += Felt252::from(1u64);
            h
        };
        assert!(CombinedBatchPlan::new(ph, vec![bad_magic, hands[1].clone()]).is_err());
        let bad_binding = {
            let mut h = hands[0].clone();
            h.statement.hand_binding += Felt252::from(0x1234u64);
            h
        };
        assert!(CombinedBatchPlan::new(ph, vec![bad_binding, hands[1].clone()]).is_err());
        let bad_fact = {
            let mut h = hands[0].clone();
            h.statement.fact = Felt252::from(7u64);
            h
        };
        assert!(CombinedBatchPlan::new(ph, vec![bad_fact, hands[1].clone()]).is_err());
        let mut dup = hands.clone();
        dup[1].output[COMBINED_BINDING_INDEX] = dup[0].output[COMBINED_BINDING_INDEX];
        dup[1].statement.hand_binding = dup[0].statement.hand_binding;
        dup[1].statement.fact =
            combined_expected_fact(&ph, &dup[1].output);
        assert!(CombinedBatchPlan::new(ph, dup).is_err(), "binding 重复拒绝");
        let third = hands[0].clone();
        hands.push(third);
        assert!(CombinedBatchPlan::new(ph, hands).is_err(), "K=3 非 2 的幂拒绝");
    }

    /// acc 链信任边界（文档性断言）：本层不校验跨手链连续性（claims 私有），
    /// 但 chain_acc 进 fact——换首词后 fact 重算一致的新语句能通过形状校验
    /// （如实呈现信任边界），而批根/fact 必然随之改变（绑定生效）。
    #[test]
    fn combined_chain_acc_is_fact_bound() {
        let (ph, hands) = combined_golden_hands(2);
        let plan = CombinedBatchPlan::new(ph, hands.clone()).unwrap();
        let root = plan.keccak_batch_root().unwrap();
        // 换手 0 的 chain_acc（重算 fact 保持宿主一致性）→ 仍可构造（本层
        // 无法判定该 acc 是否真链在上一手之后——生产者不变量管这事），
        // 但批根变了：任何 acc 漂移都会被 SettleBatch 根/终证语句捕获。
        let mut drifted = hands.clone();
        drifted[0].output[0] += Felt252::from(1u64);
        drifted[0].statement.fact = combined_expected_fact(&ph, &drifted[0].output);
        let drifted_plan = CombinedBatchPlan::new(ph, drifted).expect("形状仍合法");
        assert_ne!(
            root,
            drifted_plan.keccak_batch_root().unwrap(),
            "chain_acc 漂移必改批根（fact 绑定生效）"
        );
    }

    /// K=2 批：构造校验全过；keccak 根与 groth16-wrap 直接复用一致（同函数自证）；
    /// 语句载荷新序敏感。
    #[test]
    fn batch_plan_k2_builds_and_roots() {
        let (ph, hands) = golden_hands(2);
        let plan = BatchPlan::new(ph, hands.clone()).expect("K=2 plan");
        let root = plan.keccak_batch_root().unwrap();
        let direct = keccak_batch_root(&plan.statements()).unwrap();
        assert_eq!(root, direct);
        // 顺序敏感（SettleBatch 叶序 = index 序）
        let mut swapped = hands.clone();
        swapped.reverse();
        let swapped_root = BatchPlan::new(ph, swapped).unwrap().keccak_batch_root().unwrap();
        assert_ne!(root, swapped_root, "批根必须对语句顺序敏感");
    }

    /// 批构造负例：K=3 非 2 的幂、K=65 超政策上限、binding 重复、fact 篡改。
    #[test]
    fn batch_plan_rejects_bad_shapes() {
        let (ph, hands) = golden_hands(2);
        assert!(BatchPlan::new(ph, vec![]).is_err(), "空批拒绝");
        // K=3：非 2 的幂（金向量段造第三手）
        let (ph2, mut hands3) = golden_hands(2);
        hands3.push(hands[0].clone());
        assert!(BatchPlan::new(ph2, hands3).is_err(), "K=3 必须拒绝");
        // K=65 超政策上限
        let (ph3, _) = golden_hands(2);
        let many: Vec<HandEntry> = (0..65u64)
            .map(|i| {
                let (p, hs) = golden_hands(2);
                let mut h = hs[(i % 2) as usize].clone();
                let b = felt_from_hex(golden::GOLDEN_HAND_BINDING).unwrap() + Felt252::from(i);
                h.segment[HAND_BINDING_INDEX] = b;
                h.statement.hand_binding = b;
                h.statement.fact = WrapWitness { output: h.segment.clone() }.expected_fact(&p);
                h
            })
            .collect();
        assert!(BatchPlan::new(ph3, many).is_err(), "K=65 必须拒绝（政策上限 64）");
        // fact 篡改
        let (_, mut bad) = golden_hands(2);
        bad[1].statement.fact = Felt252::from(7u64);
        let _ = ph;
        assert!(BatchPlan::new(felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap(), bad).is_err());
        // binding 与段槽位不一致
        let (_, mut bad2) = golden_hands(2);
        bad2[0].statement.hand_binding = Felt252::from(0x1234u64);
        assert!(BatchPlan::new(felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap(), bad2).is_err());
        // binding 重复
        let (_, hands4) = golden_hands(2);
        let mut dup = hands4.clone();
        dup[1].segment[HAND_BINDING_INDEX] = dup[0].segment[HAND_BINDING_INDEX];
        dup[1].statement.hand_binding = dup[1].segment[HAND_BINDING_INDEX];
        dup[1].statement.fact = WrapWitness { output: dup[1].segment.clone() }
            .expected_fact(&felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap());
        assert!(BatchPlan::new(felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap(), dup).is_err());
    }

    /// 叶输出 H1 镜像：与 types-core 文档编码（词→LE 字节→blake2s→8 LE 词）
    /// 的独立内联重实现逐词一致；小/大 felt 两条编码路径均覆盖
    /// （blake2s.rs:31-35：< 2^63 编 2 词，≥ 2^63 编 8 词 + MSB 标记）。
    #[test]
    fn leaf_output_words_matches_documented_encoding() {
        let program_hash = felt_from_hex(golden::GOLDEN_PROGRAM_HASH).unwrap();
        let (_, hands) = golden_hands(2);
        let plan = BatchPlan::new(program_hash, hands).unwrap();
        let preimage = plan.leaf_preimage();
        let got = leaf_output_words(&preimage).unwrap();

        // 独立内联重实现（不经 Blake2Felt252::encode_felt252_data_and_calc_blake_hash 的封装）
        use blake2::Digest as _;
        let felts: Vec<starknet_types_core::felt::Felt> =
            preimage.iter().map(|f| felt_to_starknet(f)).collect();
        let words = Blake2Felt252::encode_felts_to_u32s(&felts);
        let mut bytes = Vec::new();
        for w in &words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        let expect: [u8; 32] = blake2::Blake2s256::digest(&bytes).into();
        let expect_words: [u32; 8] =
            std::array::from_fn(|i| u32::from_le_bytes(expect[i * 4..i * 4 + 4].try_into().unwrap()));
        assert_eq!(got, expect_words, "H1 镜像必须与文档编码一致");

        // 大 felt 路径（≥ 2^63 → 8 词 + MSB 标记）：program_hash 本身即大值
        let big = leaf_output_words(&[program_hash, Felt252::from(1u64)]).unwrap();
        let small = leaf_output_words(&[Felt252::from(1u64), Felt252::from(2u64)]).unwrap();
        assert_ne!(big, small, "大小值编码路径必须区分");
        // 确定性
        assert_eq!(leaf_output_words(&preimage).unwrap(), got);
    }

    /// 折叠计划形状：L=1 自折叠、L=2/4/8 的层数与步数（L-1 次两两折叠 + L=1 一次自折叠）；
    /// 非法输入拒绝。
    #[test]
    fn fold_plan_shapes() {
        let p1 = FoldPlan::new(1).unwrap();
        assert_eq!(p1.steps.len(), 1);
        assert_eq!(p1.steps[0].right, None, "L=1 必须是自折叠根");
        assert_eq!(p1.n_layers(), 1);

        let p2 = FoldPlan::new(2).unwrap();
        assert_eq!(p2.steps.len(), 1);
        assert_eq!(p2.steps[0], FoldStep { layer: 1, left: 0, right: Some(1) });

        let p4 = FoldPlan::new(4).unwrap();
        assert_eq!(p4.steps.len(), 3, "4 叶 = 3 次两两折叠（golden e2e n_pair_reductions=3 同口径）");
        assert_eq!(p4.n_layers(), 2);

        let p8 = FoldPlan::new(8).unwrap();
        assert_eq!(p8.steps.len(), 7);
        assert_eq!(p8.n_layers(), 3);

        assert!(FoldPlan::new(0).is_err());
        assert!(FoldPlan::new(3).is_err());
        assert!(FoldPlan::new(65).is_err());
    }

    /// hi/lo 拆分-重组往返；join 拒绝非拆分像（≥ 2^128）。
    #[test]
    fn split_join_roundtrip() {
        let mut root = [0u8; 32];
        for (i, b) in root.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        let (hi, lo) = split_root_hi_lo(&root);
        assert_eq!(join_root_hi_lo(&hi, &lo).unwrap(), root);
        // 非拆分像拒绝
        let big = felt_from_hex("0x8000000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert!(join_root_hi_lo(&big, &lo).is_err());
        assert!(join_root_hi_lo(&hi, &big).is_err());
    }

    /// 累加链接：确定性、换根输出/换根/换序都改变后续 fact（终证语句负例的 host 面）。
    #[test]
    fn accumulator_chain_links() {
        let aph = felt_from_hex(
            "0x744d16d382e7940b7b93c0a069ab0df04704c5b28d6476d23cca6c2370a7ad4",
        )
        .unwrap();
        let (ph, hands) = golden_hands(2);
        let _ = ph;
        let plan = BatchPlan::new(aph, hands).unwrap();
        let root = plan.keccak_batch_root().unwrap();
        let w = plan.leaf_output_words().unwrap();

        // 批 1：acc_prev = genesis
        let genesis = acc_genesis();
        let (hi1, lo1, fact1) = derive_batch_fact(&aph, &w, &genesis, &root);
        assert_eq!(acc_next(&genesis, &fact1), fact1);

        // 批 2：acc_prev = fact1；换批根（另一语句集）→ fact2 不同
        let (_, hands_b) = golden_hands(2);
        let mut hands_b2 = hands_b;
        hands_b2.reverse();
        let plan_b = BatchPlan::new(aph, hands_b2).unwrap();
        let root_b = plan_b.keccak_batch_root().unwrap();
        let (_, _, fact2) = derive_batch_fact(&aph, &w, &fact1, &root_b);
        let (_, _, fact2_alt_root) = derive_batch_fact(&aph, &w, &fact1, &root);
        assert_ne!(fact2, fact2_alt_root, "换 keccak 根必须改变 fact（根绑定）");

        // 换根输出词 → fact 变（根输出绑定）
        let mut w2 = w;
        w2[0] ^= 1;
        let (_, _, fact2_alt_w) = derive_batch_fact(&aph, &w2, &fact1, &root_b);
        assert_ne!(fact2, fact2_alt_w, "换根输出必须改变 fact");

        // 换 acc_prev（历史链）→ fact 变（累加链接）
        let alt_acc = &hi1 + &lo1;
        let (_, _, fact2_alt_acc) = derive_batch_fact(&aph, &w, &alt_acc, &root_b);
        assert_ne!(fact2, fact2_alt_acc, "换 acc_prev 必须改变 fact（累加链接）");

        // genesis（acc_prev=0）与任意非零 acc_prev 不同
        let (_, _, fact2_genesis) = derive_batch_fact(&aph, &w, &acc_genesis(), &root_b);
        assert_ne!(fact2, fact2_genesis);
    }

    /// K/L 政策自检：上限 64 必须落在 trace 地板预算内（2^20 / 5374 / 3）。
    #[test]
    fn max_hands_policy_within_trace_floor() {
        let budget = (1u64 << TRACE_FLOOR_LOG2) / MEASURED_STEPS_PER_HAND / TRACE_HEADROOM_FACTOR;
        assert!(
            budget >= MAX_HANDS_PER_LEAF as u64,
            "政策上限 {MAX_HANDS_PER_LEAF} 必须有余量：预算 {budget} 手（2^{TRACE_FLOOR_LOG2}/{MEASURED_STEPS_PER_HAND}/{TRACE_HEADROOM_FACTOR}）"
        );
        assert_eq!(MAX_HANDS_PER_LEAF, 64);
    }

    /// output 词 → felt 无损（u32 恒 < P）。
    #[test]
    fn words_to_felts_lossless() {
        let words = [0u32, 1, 0x7fff_ffff, 0x8000_0000, u32::MAX, 42, 7, 0xffff_ffff];
        let felts = output_words_to_felts(&words);
        for (w, f) in words.iter().zip(felts.iter()) {
            assert_eq!(felt_to_hex(f), felt_to_hex(&Felt252::from(*w)));
            assert_eq!(*f, Felt252::from(*w));
        }
    }
}
