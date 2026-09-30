//! fold_batch — 牌桌手级聚合签名验证 + acc 链折叠（FoldDesign v2 最小切片）。
//!
//! 一批 = **同一张牌桌**的一串手：roster（本批玩家的公钥集）只进一次电路，
//! keyagg 只算一次；每手只做「3 次 poseidon + 单方程 EC 检查 + z̄ 范围检查」，
//! claim 逐手折进 acc 链。公开输出 = `[acc, roster_digest]`。
//!
//! ## 与 agg0/agg1 测量原型的关系（攻击复审后的生产形状）
//!
//! - agg0 形状（P̄ 为自由 wire 词）已被审方 forge0 攻击否决（wire 自选
//!   P̄ + 攻击者自签 → verified=true/388 steps）——本电路**弃用**该形状。
//! - 本电路内重算（agg1 骨架 + 切片第 2-5 步断言链）：
//!   1. roster 逐 pk on-curve（`EcPointTrait::new` Option 模式）+ 非恒等
//!      （`NonZeroEcPoint`）——Stark 群阶素数 / cofactor=1（审方 F-1 实测：
//!      无 2-torsion、n·G=O）⇒ on-curve + 非恒等即满阶；z̄<n 用 u256 比较
//!      （RangeCheck 面板，felt 无 PartialOrd）；
//!   2. **电路内 keyagg**：μ_i = poseidon([keyagg_label, n, pkx, pky])
//!      （BDN 系数，Bellare–Neven CCS'06 plain-PK 形状——μ 只经 RO 依赖
//!      各自 pk，rogue-key 退化为 poseidon 不动点难度），
//!      P̄ = Σ μ_i·pk_i；roster_digest = poseidon([roster_label, n]
//!      ++ pks) 电路内从同一批 wire pks 重算；
//!   3. roster_digest **作为公开输出词**——soundness 不在电路内闭合：
//!      换 pks 电路照样自洽（wire pks 仍自由），闭合点在消费面对照
//!      roster_registry 注册值（H1 单射 ⇒ wire pks == 注册 pks）。切片
//!      阶段 = host parity 门模拟注册面（fold_batch_test T9/T10）；
//!   4. c = poseidon([sig_label, hand_binding, M_h, P̄x, P̄y, R̄x, R̄y])
//!      电路内重算；M_h = poseidon([m_label, hand_binding, m1, m2,
//!      cm_digest, roster_digest])——m1/m2/cm_digest 取每手固定 witness
//!      槽（生产版 = settle wire[1] registered_digest / wire[2] n_expected
//!      / wire[36] ald + cm_digest，修复 2/4：digest、人数、认领承诺全进
//!      共签消息；本切片不含 98 词 settle wire，槽语义见 foldagg.rs）。
//!      hand_binding 进 c ⇒ 跨手重放 (R̄,z̄) 必改 c（T3）；
//!   5. 单方程 z̄·G − c·P̄ − R̄ == O assert（残差非恒等 → panic → 无证明，
//!      fail-closed）。challenge 均为 raw felt（< P，不显式 mod n）——EC
//!      标量乘按群阶自动归约，与 handbatch `action_sig_challenge_raw`
//!      同纪律，host 镜像逐 felt parity（foldagg.rs）。
//!
//! ## wire 布局（inputs Span，设计切片第 0 节）
//!
//! ```text
//! [P, (pkx, pky)×P, K, (hand_binding, m1, m2, cm_digest, R̄x, R̄y, z̄)×K]
//! ```
//!
//! main 的完整 inputs = `[prev_acc, span_len] ++ 上述 Span`（Span 参数
//! [len, elements…] 摊平，与 recursion.cairo / combined.cairo 同约定）。
//!
//! ## fail-closed
//! 任何 roster 点非满阶编码 / z̄ ≥ n / 任一残差非恒等 → panic → 无证明。

use core::array::{ArrayTrait, SpanTrait};
use core::ec::{ec_point_unwrap, EcPoint, EcPointTrait, EcStateTrait, NonZeroEcPoint};
use core::option::Option;
use core::poseidon::poseidon_hash_span;
use core::traits::TryInto;

/// STARK 曲线群阶（与 dual::hand_batch_stark::STARK_N 同一常量；n < P）。
const STARK_N: u256 =
    0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f;

/// STARK 曲线生成元（与 dual::hand_batch_stark / agg1.cairo 同一常量）。
const GENERATOR_X: felt252 =
    0x01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca;
const GENERATOR_Y: felt252 =
    0x005668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f;

// ---- BDN 域标签（T8 KAT 与 foldagg.rs 逐字节钉死）----
const KEYAGG_LABEL: felt252 = 'poker/fold-batch/keyagg.v1';
const ROSTER_LABEL: felt252 = 'poker/fold-batch/roster.v1';
const M_LABEL: felt252 = 'poker/fold-batch/msg.v1';
const SIG_LABEL: felt252 = 'poker/fold-batch/sig.v1';
const CLAIM_LABEL: felt252 = 'poker/fold-batch/claim.v1';

/// 每手 wire 词数（hand_binding, m1, m2, cm_digest, R̄x, R̄y, z̄）。
const HAND_WORDS: u32 = 7;

#[executable]
fn main(prev_acc: felt252, words: Span<felt252>) -> Array<felt252> {
    let n_players: u32 = (*words.at(0)).try_into().unwrap();

    // ---- 第 1-2 步：roster 逐 pk 满阶编码检查 + 电路内 keyagg + roster_digest
    let mut roster_in: Array<felt252> = array![ROSTER_LABEL, *words.at(0)];
    let mut agg = EcStateTrait::init();
    let mut i: u32 = 0;
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

    // ---- 第 3-5 步：逐手 M_h / c 重算 + z̄ 范围检查 + 单方程
    let n_hands: u32 = (*words.at(1 + 2 * n_players)).try_into().unwrap();
    let g_nz: NonZeroEcPoint = EcPointTrait::new(GENERATOR_X, GENERATOR_Y)
        .unwrap()
        .try_into()
        .unwrap();
    let mut claims: Array<felt252> = array![];
    let mut cursor: u32 = 2 + 2 * n_players;
    let mut j: u32 = 0;
    while j < n_hands {
        let hand_binding = *words.at(cursor);
        let m1 = *words.at(cursor + 1);
        let m2 = *words.at(cursor + 2);
        let cm_digest = *words.at(cursor + 3);
        let rbar_x = *words.at(cursor + 4);
        let rbar_y = *words.at(cursor + 5);
        let zbar = *words.at(cursor + 6);

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

        // M_h（修复 2/4 形状：固定 witness 槽 + roster_digest 进共签消息）
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

        cursor += HAND_WORDS;
        j += 1;
    }

    // ---- acc 链折叠：acc = poseidon([prev_acc] ++ claims)（与 host
    // fold_acc / recurse::fold_accumulator 同公式）
    let mut acc_in: Array<felt252> = array![prev_acc];
    let claims_span = claims.span();
    let mut w: u32 = 0;
    while w < claims_span.len() {
        acc_in.append(*claims_span.at(w));
        w += 1;
    }
    let acc = poseidon_hash_span(acc_in.span());

    // ---- 公开输出 [acc, roster_digest]（roster_digest 进消费面供
    // roster_registry 对照——切片阶段 host parity 门模拟）
    let mut out = ArrayTrait::new();
    out.append(acc);
    out.append(roster_digest);
    out
}
