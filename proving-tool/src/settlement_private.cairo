//! P2-M2 结算隐私电路（Cairo1 executable，走 prove-hand 的 Cairo VM → Stwo 管线）。
//!
//! 语句与约束见根 crate `src/settlement_private_circuit.rs` 模块头（P2-M1）。
//! 本程序把规格四条约束真正落进证明：
//! 1. digest：`PoseidonTrait` sponge 吸收 `[hand_id] ++ Σ(player, sign, |delta|)`
//!    后 finalize，必须等于公开入参 `registered_digest`（与合约
//!    `compute_settlement_digest` 的 `poseidon_hash_span` 同一 sponge：配对吸收、
//!    余项补 1，逐字段一致）；
//! 2. 零和：`Σ sign·|delta| == 0`（|delta| ≤ u64 在下方强制；8 项之和
//!    < 2^67 << felt 素数，模零 ⟺ 整数零）；
//! 3. 人数：非零 |delta| 参与者数 == `n_expected`；
//! 4. 每赢家输出 `cm_i = Poseidon(commitment_i, hand_binding, amount_lo, amount_hi)`
//!    （amount = u256(delta)，low = |delta|，high = 0），非赢家 cm = 0
//!    ——与合约写入 `claim_cms` 的公式逐字段一致。
//!
//! 隐私模型：`(players, signs, mags, commitments)` 是 prove-hand 的程序入参
//!（witness，不进公开段）；公开段（public_outputs.json / Stwo public memory）
//! 只有返回数组 `[MAGIC, hand_id, registered_digest, n_expected, hand_binding,
//! cm_0..cm_7]` —— P2-M3 的 `verify_and_settle_dapv_stark_private_v2` 合约以
//! `registered_digest == 已登记 digest ∧ 公开段 cms == 待写 claim_cms` 消费该段。
//!
//! §8.2 预留：动作签名域（action_domain / auto 合法性 / accepted-seq）不在本
//! 程序吸收序列中——M2-后续把动作日志哈希作为第 37 个入参追加进 digest 吸收链
//! 即可，wire 无重排（根 crate 骨架的对应预留列位同步）。

use core::array::ArrayTrait;
use core::poseidon::PoseidonTrait;
use core::hash::HashStateTrait;
use core::traits::TryInto;

/// 公开段成功标记（'SP2M_OK' 短字符串）。
const MAGIC: felt252 = 0x5350324d5f4f4b;

/// 参与者上限（与根 crate MAX_PARTICIPANTS 一致）。
const N_PLAYERS: usize = 8;

#[executable]
fn main(
    hand_id: felt252,
    registered_digest: felt252,
    n_expected: felt252,
    hand_binding: felt252,
    p0: felt252, p1: felt252, p2: felt252, p3: felt252,
    p4: felt252, p5: felt252, p6: felt252, p7: felt252,
    s0: felt252, s1: felt252, s2: felt252, s3: felt252,
    s4: felt252, s5: felt252, s6: felt252, s7: felt252,
    m0: felt252, m1: felt252, m2: felt252, m3: felt252,
    m4: felt252, m5: felt252, m6: felt252, m7: felt252,
    c0: felt252, c1: felt252, c2: felt252, c3: felt252,
    c4: felt252, c5: felt252, c6: felt252, c7: felt252,
) -> Array<felt252> {
    let players = array![p0, p1, p2, p3, p4, p5, p6, p7].span();
    let signs = array![s0, s1, s2, s3, s4, s5, s6, s7].span();
    let mags = array![m0, m1, m2, m3, m4, m5, m6, m7].span();
    let commitments = array![c0, c1, c2, c3, c4, c5, c6, c7].span();

    // --- 约束 1：digest 匹配（Starknet Poseidon sponge，与链上逐字段一致） ---
    let mut h = PoseidonTrait::new();
    h = h.update(hand_id);
    let mut i: usize = 0;
    while i < N_PLAYERS {
        h = h.update(*players.at(i));
        h = h.update(*signs.at(i));
        h = h.update(*mags.at(i));
        i += 1;
    }
    let digest = h.finalize();
    assert!(digest == registered_digest, "DIGEST_MISMATCH");

    // --- 见证良构：sign ∈ {0,1}，|delta| ≤ u64（规格分解的值域） ---
    let mut i: usize = 0;
    while i < N_PLAYERS {
        let s = *signs.at(i);
        let m = *mags.at(i);
        assert!(s * (s - 1) == 0, "SIGN_NOT_BOOL");
        // felt→u64 try_into 失败即 |delta| 超出 u64 值域（合约同款守卫）
        let _m_u64: u64 = m.try_into().expect('MAGNITUDE_OVER_U64');
        i += 1;
    }

    // --- 约束 2：零和（有界模零 ⟺ 整数零）；约束 3：人数 ---
    let mut sum: felt252 = 0;
    let mut count: felt252 = 0;
    let mut i: usize = 0;
    while i < N_PLAYERS {
        let s = *signs.at(i);
        let m = *mags.at(i);
        if s == 1 {
            sum += m;
        } else {
            sum -= m;
        };
        if m != 0 {
            count += 1;
        };
        i += 1;
    }
    assert!(sum == 0, "NOT_ZERO_SUM");
    assert!(count == n_expected, "COUNT_MISMATCH");

    // --- 约束 4：赢家认领承诺（公开段输出） ---
    let mut out = ArrayTrait::new();
    out.append(MAGIC);
    out.append(hand_id);
    out.append(registered_digest);
    out.append(n_expected);
    out.append(hand_binding);
    // total_winnings = Σ 赢家 |delta|（有界 < 2^67，无模回绕）——v2 合约据此
    // 把 pot 划入认领托管（公开段取代明文 deltas 成为托管金额来源）。
    let mut total_winnings: felt252 = 0;
    let mut i: usize = 0;
    while i < N_PLAYERS {
        let s = *signs.at(i);
        let m = *mags.at(i);
        if s == 1 {
            if m != 0 {
                total_winnings += m;
                let mut ch = PoseidonTrait::new();
                ch = ch.update(*commitments.at(i));
                ch = ch.update(hand_binding);
                ch = ch.update(m);
                ch = ch.update(0);
                out.append(ch.finalize());
            } else {
                out.append(0);
            };
        } else {
            out.append(0);
        };
        i += 1;
    }
    out.append(total_winnings);
    out
}
