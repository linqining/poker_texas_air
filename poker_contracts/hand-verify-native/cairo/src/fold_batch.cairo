//! fold_batch — 牌桌手级聚合签名验证 + acc 链折叠（**生产版**：并入 98 词
//! settle wire，FoldDesign v2）。
//!
//! 一批 = **同一张牌桌**的一串手：roster（本批玩家的公钥集）只进一次电路，
//! keyagg 只算一次；每手 = `settlement_stmt::settlement_statement` 全量语句
//! 约束（digest 折叠、NOT_ZERO_SUM、COUNT_MISMATCH、动作日志整链重放、
//! 认领承诺）+ 3 次 poseidon + 单方程 EC 检查 + z̄ 范围检查，claim 逐手
//! 折进 acc 链。
//!
//! ## 公开输出（生产形状，fold-spec D1）
//!
//! 每手公开段 = **17 词** = combined 16 词信封原样 + roster_digest 尾插
//! index 16；main 返回 K 段 17 词平铺（runner 序列化为 `[len, elements…]`）：
//!
//! ```text
//! 段 index:  0          1        2        3                4        5        6..=13  14      15     16
//!            chain_acc  MAGIC   hand_id  registered_digest n_expected binding cm×8   total   ald    roster_digest
//! ```
//!
//! - word 0–15 与 combined 信封逐词同位（`combined.cairo` 输出 = [new_acc]
//!   ++ settlement 15 词公开段），全部既有槽位锚（MAGIC@1、digest@3、n@4、
//!   binding@5、cm@6..13、total@14、ald@15）零位移复用；唯一新增语义收口
//!   在 index 16（roster_digest，消费面对照 `roster_registry` 注册值——
//!   H1 单射 ⇒ wire pks == 注册 pks）。
//! - **word 0 = 批终 acc 复制**（Q-1 定案）：本程序只有一次 acc 折叠
//!   （`poseidon([prev_acc] ++ claims)`，K 手一批一个链节点），不存在逐手
//!   prev_acc 输入——每段 slot 0 携带同一批终 acc，使每手段独立成 fact
//!   （`poseidon([ph‖seg])`）时都钉住整批链状态；roster_digest 同为批常量、
//!   K 段同值（D1a）。两链 acc 公式不同源（fold claim 带域标签），跨链
//!   acc 不对等是有意设计（fold-spec D5-4）。
//!
//! ## 与 agg0/agg1 测量原型的关系（攻击复审后的生产形状）
//!
//! - agg0 形状（P̄ 为自由 wire 词）已被审方 forge0 攻击否决（wire 自选
//!   P̄ + 攻击者自签 → verified=true/388 steps）——本电路**弃用**该形状。
//! - 本电路内重算（agg1 骨架 + 切片第 2-5 步断言链，语义不动）：
//!   1. roster 逐 pk on-curve（`EcPointTrait::new` Option 模式）+ 非恒等
//!      （`NonZeroEcPoint`）——Stark 群阶素数 / cofactor=1（审方 F-1 实测：
//!      无 2-torsion、n·G=O）⇒ on-curve + 非恒等即满阶；z̄<n 用 u256 比较
//!      （RangeCheck 面板，felt 无 PartialOrd）；
//!   2. **电路内 keyagg**：μ_i = poseidon([keyagg_label, n, pkx, pky])
//!      （BDN 系数，Bellare–Neven CCS'06 plain-PK 形状——μ 只经 RO 依赖
//!      各自 pk，rogue-key 退化为 poseidon 不动点难度），
//!      P̄ = Σ μ_i·pk_i；roster_digest = poseidon([roster_label, n]
//!      ++ pks) 电路内从同一批 wire pks 重算；
//!   3. roster_digest **作为每手公开段 index 16 词**——soundness 不在电路
//!      内闭合：换 pks 电路照样自洽（wire pks 仍自由），闭合点在消费面对照
//!      roster_registry 注册值（H1 单射 ⇒ wire pks == 注册 pks）。切片
//!      阶段 = host parity 门模拟注册面（fold_batch_test T9/T10）；
//!   4. c = poseidon([sig_label, hand_binding, M_h, P̄x, P̄y, R̄x, R̄y])
//!      电路内重算；M_h = poseidon([m_label, hand_binding, m1, m2,
//!      cm_digest, roster_digest])——**真槽映射（D2，以 settlement_stmt.cairo
//!      实际布局为准）**：hand_binding = wire[3]、m1 = wire[1]
//!      （registered_digest）、m2 = wire[2]（n_expected）、cm_digest =
//!      poseidon(wire[28..=35])（8 词 c0..c7 压缩）。**ald（wire[36]）不是
//!      M_h 独立槽（D2a）**：约束 1 把 ald 吸收进 digest 且断言
//!      digest == registered_digest = wire[1] ∈ M_h，ACTION_CHAIN_MISMATCH
//!      另钉链根 == wire[36]——改 ald 必改 digest 必破 m1。hand_binding 进
//!      c ⇒ 跨手重放 (R̄,z̄) 必改 c（T3）；
//!   5. 单方程 z̄·G − c·P̄ − R̄ == O assert（残差非恒等 → panic → 无证明，
//!      fail-closed）。challenge 均为 raw felt（< P，不显式 mod n）——EC
//!      标量乘按群阶自动归约，与 handbatch `action_sig_challenge_raw`
//!      同纪律，host 镜像逐 felt parity（foldagg.rs）。
//!
//! ## wire 布局（inputs Span，生产版）
//!
//! ```text
//! [P, (pkx, pky)×P, K, (settle 98 词, R̄x, R̄y, z̄)×K]
//! ```
//!
//! settle 98 词 = `settlement_stmt.cairo` wire 布局：
//! `[hand_id, registered_digest, n_expected, hand_binding, p0..p7, s0..s7,
//!   m0..m7, c0..c7, action_log_digest, action_count, w0..w59]`。
//!
//! main 的完整 inputs = `[prev_acc, span_len] ++ 上述 Span`（Span 参数
//! [len, elements…] 摊平，与 combined.cairo 同约定）。
//!
//! ## fail-closed
//! 任何 roster 点非满阶编码 / z̄ ≥ n / 任一语句约束失败（digest 折叠 /
//! 动作链重放 / sign∈{0,1} / |delta|≤u64 / NOT_ZERO_SUM / COUNT_MISMATCH /
//! 认领承诺）/ 任一残差非恒等 → panic → 无证明。

mod settlement_stmt;

use core::array::{ArrayTrait, SpanTrait};
use core::ec::{ec_point_unwrap, EcPoint, EcPointTrait, EcStateTrait, NonZeroEcPoint};
use core::option::Option;
use core::poseidon::poseidon_hash_span;
use core::traits::TryInto;

use settlement_stmt::settlement_statement;

/// STARK 曲线群阶（与 dual::hand_batch_stark::STARK_N 同一常量；n < P）。
const STARK_N: u256 =
    0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f;

/// STARK 曲线生成元（与 dual::hand_batch_stark / agg1.cairo 同一常量）。
const GENERATOR_X: felt252 =
    0x01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca;
const GENERATOR_Y: felt252 =
    0x005668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f;

// ---- BDN 域标签（T8 KAT 与 foldagg.rs 逐字节钉死；语义不动）----
const KEYAGG_LABEL: felt252 = 'poker/fold-batch/keyagg.v1';
const ROSTER_LABEL: felt252 = 'poker/fold-batch/roster.v1';
const M_LABEL: felt252 = 'poker/fold-batch/msg.v1';
const SIG_LABEL: felt252 = 'poker/fold-batch/sig.v1';
const CLAIM_LABEL: felt252 = 'poker/fold-batch/claim.v1';

/// settle wire 词数（settlement_stmt.cairo SETTLE_WORDS 同值）。
const SETTLE_WORDS: usize = 98;
/// cm 槽起点：c0..c7 = settle wire[28..=35]（settlement_stmt.cairo :194
/// 以 settle.at(28 + i)、i∈0..8 吸收的实测布局）。
const CM_START: usize = 28;
/// cm 槽词数（8 词 c0..c7 压缩进 cm_digest，D2/K-4）。
const CM_WORDS: usize = 8;
/// 每手签名见证词数（R̄x, R̄y, z̄）。
const SIG_WORDS: usize = 3;
/// 每手 wire 块词数 = settle 98 + 签名见证 3。
const HAND_WORDS: usize = SETTLE_WORDS + SIG_WORDS;
/// settlement_statement 公开段词数（[MAGIC … ald]，combined.cairo 输出尾）。
const STMT_WORDS: usize = 15;
/// 每手公开段词数 = [acc] ++ 语句公开段 15 ++ [roster_digest]（D1）。
pub const SEGMENT_LEN: usize = STMT_WORDS + 2;

#[executable]
fn main(prev_acc: felt252, words: Span<felt252>) -> Array<felt252> {
    let n_players: usize = (*words.at(0)).try_into().unwrap();

    // ---- 第 1-2 步：roster 逐 pk 满阶编码检查 + 电路内 keyagg + roster_digest
    let mut roster_in: Array<felt252> = array![ROSTER_LABEL, *words.at(0)];
    let mut agg = EcStateTrait::init();
    let mut i: usize = 0;
    while i < n_players {
        let pkx = *words.at(1 + 2 * i);
        let pky = *words.at(2 + 2 * i);
        roster_in.append(pkx);
        roster_in.append(pky);
        // on-curve（EcPointTrait::new Option 模式）+ 非恒等：n 素 /
        // cofactor=1 / 无 2-torsion（审方 F-1 实测）⇒ 满阶，fail-closed。
        let pk_nz: NonZeroEcPoint = match EcPointTrait::new(pkx, pky) {
            Option::Some(p) => match p.try_into() {
                Option::Some(nz) => nz,
                Option::None => panic_with_felt252('PK_IS_IDENTITY'),
            },
            Option::None => panic_with_felt252('PK_OFF_CURVE'),
        };
        // BDN 系数（μ 只经 poseidon RO 依赖 (n, pk)，CCS'06 plain-PK 形状）
        let mu = poseidon_hash_span(array![KEYAGG_LABEL, *words.at(0), pkx, pky].span());
        agg.add_mul(mu, pk_nz);
        i += 1;
    }
    let roster_digest = poseidon_hash_span(roster_in.span());
    let pbar_pt: EcPoint = agg.finalize();
    let pbar_nz: NonZeroEcPoint = match pbar_pt.try_into() {
        Option::Some(nz) => nz,
        Option::None => panic_with_felt252('PBAR_IS_IDENTITY'),
    };
    let (pbar_x, pbar_y) = ec_point_unwrap(pbar_nz);

    // ---- 第 3-5 步：逐手语句约束 + M_h/c 真槽重算 + z̄ 范围检查 + 单方程
    let n_hands: usize = (*words.at(1 + 2 * n_players)).try_into().unwrap();
    let g_nz: NonZeroEcPoint = EcPointTrait::new(GENERATOR_X, GENERATOR_Y)
        .unwrap()
        .try_into()
        .unwrap();
    let mut claims: Array<felt252> = array![];
    // 语句公开段缓冲（K×15 词；acc/roster_digest 为批常量，末尾统一插——Q-1）
    let mut stmt_words: Array<felt252> = array![];
    let mut cursor: usize = 2 + 2 * n_players;
    let mut j: usize = 0;
    while j < n_hands {
        // 本手 98 词 settle wire；语句函数内全部 assert（digest 按实际人数
        // 折叠、动作日志整链重放、sign∈{0,1}、|delta|≤u64、NOT_ZERO_SUM、
        // COUNT_MISMATCH、认领承诺），fail-closed。
        let settle = words.slice(cursor, SETTLE_WORDS);
        let segment = settlement_statement(settle);
        let seg = segment.span();
        assert!(seg.len() == STMT_WORDS, "BAD_STMT_SEGMENT_LEN");

        // M_h 真槽（D2）：hand_binding=wire[3]、m1=wire[1]
        // （registered_digest）、m2=wire[2]（n_expected）、
        // cm_digest=poseidon(wire[28..=35])（8 词 c0..c7 压缩）。
        let hand_binding = *settle.at(3);
        let m1 = *settle.at(1);
        let m2 = *settle.at(2);
        let cm_digest = poseidon_hash_span(settle.slice(CM_START, CM_WORDS));

        let rbar_x = *words.at(cursor + SETTLE_WORDS);
        let rbar_y = *words.at(cursor + SETTLE_WORDS + 1);
        let zbar = *words.at(cursor + SETTLE_WORDS + 2);

        // R̄ 满阶编码检查（fail-closed）
        let rbar_pt: EcPoint = match EcPointTrait::new(rbar_x, rbar_y) {
            Option::Some(p) => p,
            Option::None => panic_with_felt252('RBAR_OFF_CURVE'),
        };
        let _rbar_nz: NonZeroEcPoint = match rbar_pt.try_into() {
            Option::Some(nz) => nz,
            Option::None => panic_with_felt252('RBAR_IS_IDENTITY'),
        };

        // z̄ < n（RangeCheck 面板；z̄ 出域即签名方程无意义）
        let z_u: u256 = zbar.into();
        assert!(z_u < STARK_N, "ZBAR_OUT_OF_RANGE");

        // M_h（修复 2/4 形状：真槽 + roster_digest 进共签消息）
        let m_h = poseidon_hash_span(
            array![M_LABEL, hand_binding, m1, m2, cm_digest, roster_digest].span(),
        );
        // 挑战 c（raw felt——群阶自动归约，与 host 逐 felt parity）
        let c = poseidon_hash_span(
            array![SIG_LABEL, hand_binding, m_h, pbar_x, pbar_y, rbar_x, rbar_y].span(),
        );

        // claim 绑定手（binding + 共签消息）后折进 acc 链
        claims.append(poseidon_hash_span(array![CLAIM_LABEL, hand_binding, m_h].span()));

        // 单方程：z̄·G − c·P̄ − R̄ == O（残差非恒等 → panic → 无证明）
        let pbar_neg_nz: NonZeroEcPoint = match (-pbar_pt).try_into() {
            Option::Some(nz) => nz,
            Option::None => panic_with_felt252('PBAR_IS_IDENTITY'),
        };
        let rbar_neg_nz: NonZeroEcPoint = match (-rbar_pt).try_into() {
            Option::Some(nz) => nz,
            Option::None => panic_with_felt252('RBAR_IS_IDENTITY'),
        };
        let mut st = EcStateTrait::init();
        st.add_mul(zbar, g_nz);
        st.add_mul(c, pbar_neg_nz);
        st.add(rbar_neg_nz);
        let residual: EcPoint = st.finalize();
        let residual_nz: Option<NonZeroEcPoint> = residual.try_into();
        match residual_nz {
            Option::None => {},
            Option::Some(_) => panic_with_felt252('RESIDUAL_NOT_IDENTITY'),
        }

        // 语句公开段 15 词入批缓冲
        let mut w: usize = 0;
        while w < STMT_WORDS {
            stmt_words.append(*seg.at(w));
            w += 1;
        }

        cursor += HAND_WORDS;
        j += 1;
    }

    // ---- acc 链折叠：acc = poseidon([prev_acc] ++ claims)（与 host
    // fold_acc / recurse::fold_accumulator 同公式）——批终 acc（Q-1）
    let mut acc_in: Array<felt252> = array![prev_acc];
    let claims_span = claims.span();
    let mut w: usize = 0;
    while w < claims_span.len() {
        acc_in.append(*claims_span.at(w));
        w += 1;
    }
    let acc = poseidon_hash_span(acc_in.span());

    // ---- 公开输出：K 段 × 17 词平铺，段 = [acc] ++ 语句公开段(15) ++
    // [roster_digest]（D1：word 0–15 = combined 信封同位、index 16 =
    // roster_digest；acc/roster_digest 为批常量、K 段同值——D1a/Q-1）
    let stmts = stmt_words.span();
    let mut out = ArrayTrait::new();
    let mut j: usize = 0;
    while j < n_hands {
        out.append(acc);
        let mut w: usize = 0;
        while w < STMT_WORDS {
            out.append(*stmts.at(j * STMT_WORDS + w));
            w += 1;
        }
        out.append(roster_digest);
        j += 1;
    }
    out
}
