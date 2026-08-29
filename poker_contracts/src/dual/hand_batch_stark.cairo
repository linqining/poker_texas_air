//! Hand-level batch verification of direct-sigma ownership endorsements on
//! the Cairo-native STARK curve (Plan D) — the EC_OP builtin variant of
//! `dual::hand_batch` (which runs secp256k1 syscalls).
//!
//! Why EC_OP: the STARK curve is the curve of the EC_OP builtin, so every
//! point operation is one native builtin step — the full 9-player residual
//! batch fits a single settlement transaction (see zgame
//! docs/plan-d-p3-metrics.md for the host-measured budget).
//!
//! Relationship to the secp variant (same payload layout, same binding
//! chain, different curve and challenge hash):
//! - Payload (felt252-range u256 words): [n_own, 0, 0, ownership × n_own:
//!   [pk_x, pk_y, r_x, r_y, s]]. Coordinates and scalars are < n < P, so
//!   every word is a valid felt252 and converts losslessly.
//! - Transcript domain: keccak256("poker/hand-batch/proto" ‖ hand_id) as
//!   LE bytes — identical to the secp variant and to the host's
//!   `hand_transcript_domain` (Rust sha3-Keccak256).
//! - Challenges and rho: Poseidon, NOT keccak. The host mints with
//!   `poker-protocol-core::StarkCurve::hash_to_scalar`, which is
//!   `poseidon_hash_many([len, 31-byte BE chunks]) mod n`; both the
//!   per-endorsement challenge and the hand rho replay exactly that
//!   framing here (`core::poseidon::poseidon_hash_span` is the same
//!   two-at-a-time Hades absorption as starknet-crypto's
//!   `poseidon_hash_many`).
//! - Point compression in challenge transcripts: the host's 32-byte
//!   canonical STARK encoding `byte0 = x_be[0] | (0x80 if y odd)` (NOT the
//!   33-byte SEC1 02/03 form used by the secp variant).
//! - Point arithmetic: corelib `EcPoint` (EC_OP builtin); `new` rejects
//!   off-curve payload points fail-closed; acceptance is
//!   `EcState::finalize_nz() == None` (the L == O identity test).
//!
//! Reveal-token and leave-DLEQ residuals land here after the poker_l1
//! mirror migrates to the STARK curve (payload slots n_reveal/n_fold are
//! reserved, same as the secp variant).

use core::array::{ArrayTrait, SpanTrait};
use core::ec::{EcPoint, EcPointTrait, EcStateTrait, NonZeroEcPoint};
use core::num::traits::Zero;
use core::option::Option;
use core::poseidon::poseidon_hash_span;
use core::traits::TryInto;


/// The STARK curve group order (`starknet_curve::curve_params::EC_ORDER`,
/// identical constant to the host's `EC_ORDER_U256`). n < P, so every
/// canonical scalar is felt252-representable.
pub const STARK_N: u256 =
    0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f;

/// STARK curve generator (starknet_curve curve_params GENERATOR — the same
/// point Cairo's EC_OP builtin documentation uses).
const GENERATOR_X: felt252 =
    0x01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca;
const GENERATOR_Y: felt252 =
    0x005668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f;

/// DAPV transcript labels as felt（ASCII 直转，与 Rust core 的 ascii_felt
/// 逐字节一致派生；运行时零哈希成本）。
const DAPV_PROTO_LABEL: felt252 = 0x706f6b65722f68616e642d62617463682f70726f746f; // "poker/hand-batch/proto"
const DAPV_V1_LABEL: felt252 = 0x706f6b65722f68616e642d62617463682f7631; // "poker/hand-batch/v1"

/// poseidon over felts then reduce mod n（challenge/rho 共用）。
fn poseidon_span_mod_n(input: Span<felt252>) -> u256 {
    let h = poseidon_hash_span(input);
    let h_u: u256 = h.into();
    h_u % STARK_N
}

fn nz_n() -> NonZero<u256> {
    let nz: Option<NonZero<u256>> = STARK_N.try_into();
    match nz {
        Option::Some(value) => value,
        Option::None => core::panic_with_felt252(0),
    }
}

/// `a · b mod n` — 512-bit safe via `core::math::u256_mul_mod_n`
/// (same primitive as fr.cairo, instantiated for the STARK group order).
fn fr_mul(a: u256, b: u256) -> u256 {
    core::math::u256_mul_mod_n(a, b, nz_n())
}

/// `−a mod n` (canonical input; zero maps to zero).
fn fr_neg(a: u256) -> u256 {
    if a.is_zero() {
        0
    } else {
        STARK_N - a
    }
}

/// felt252 → u256 (lossless: felts are < P < 2^252).
fn felt_to_u256(f: felt252) -> u256 {
    f.into()
}

fn u256_to_felt(v: u256) -> Option<felt252> {
    v.try_into()
}











/// One accumulator term: `coeff · (x, y)` with coordinates as felts.
#[derive(Copy, Drop, Debug)]
pub struct TermStark {
    pub coeff: u256,
    pub x: felt252,
    pub y: felt252,
}

/// Ownership residual `s·G − R − c·pk` with the hand-bound challenge
/// c = poseidon(domain ‖ G32 ‖ pk32 ‖ R32) mod n — byte-identical to
/// `client-wasm::endorsement_mint` / `dual_settle::mint_endorsement`.
/// Per-endorsement residual as ONE equation point (A/B optimization):
///   eq = s·G − c·pk − R = s·G + c·(−pk) + (−R)
/// Negative terms use POINT negation (felt-level −y, the true group
/// inverse); c is the RAW poseidon output (< P) used directly as an EC
/// scalar — EC scalar mult is invariant under m → m mod n (group order),
/// so the host's reduced-c minting (s = w + c·sk in Z_n) and this raw-c
/// replay verify the same equation. No u256 arithmetic anywhere.
fn ownership_equation(
    hand_binding: felt252,
    pk: (felt252, felt252),
    big_r: (felt252, felt252),
    s: felt252,
) -> Option<EcPoint> {
    let (pk_x, pk_y) = pk;
    let (r_x, r_y) = big_r;
    let pk_point = match EcPointTrait::new(pk_x, pk_y) {
        Option::Some(p) => p,
        Option::None => { return Option::None; }, // off-curve: fail-closed
    };
    let r_point = match EcPointTrait::new(r_x, r_y) {
        Option::Some(p) => p,
        Option::None => { return Option::None; },
    };
    // c = poseidon([proto_label, hand_binding, Gx, Gy, pkx, pky, Rx, Ry])
    // — RAW (< P), no mod-n reduction (see fn doc).
    let input: Array<felt252> = array![
        DAPV_PROTO_LABEL, hand_binding, GENERATOR_X, GENERATOR_Y, pk_x, pk_y, r_x, r_y
    ];
    let c = poseidon_hash_span(input.span());

    let g_nz: NonZeroEcPoint = EcPointTrait::new(GENERATOR_X, GENERATOR_Y).unwrap().try_into().unwrap();
    // 负项用点取反：−c·pk = c·(−pk)，−R 直接加 −R（域级 −y 即群逆）。
    let pk_neg_nz: NonZeroEcPoint = match (-pk_point).try_into() {
        Option::Some(nz) => nz,
        Option::None => { return Option::None; },
    };
    let r_neg_nz: NonZeroEcPoint = match (-r_point).try_into() {
        Option::Some(nz) => nz,
        Option::None => { return Option::None; },
    };
    let mut state = EcStateTrait::init();
    state.add_mul(s, g_nz);
    state.add_mul(c, pk_neg_nz);
    state.add(r_neg_nz);
    Option::Some(state.finalize())
}


/// rho = poseidon("poker/hand-batch/v1" ‖ hand_id ‖ per-term
/// (coeff_be ‖ x_be ‖ y_be)) mod n — byte-identical to
/// `dual_settle::host_fold_check`'s rho derivation.
/// rho over the EQUATION words (A optimization):
///   rho = poseidon([v1_label, hand_binding, n_eq, (s, pkx, pky, Rx, Ry)*])
/// — RAW (< P) used directly as the Horner scalar; the host's
/// `dapv_hand_rho` reduces mod n and the two are EC-equivalent.
fn hand_rho(hand_binding: felt252, equations: Span<EquationWords>) -> felt252 {
    let mut input: Array<felt252> = array![DAPV_V1_LABEL, hand_binding];
    input.append(equations.len().into());
    for eq in equations {
        let e: EquationWords = *eq;
        input.append(e.s);
        input.append(e.pk_x);
        input.append(e.pk_y);
        input.append(e.r_x);
        input.append(e.r_y);
    }
    poseidon_hash_span(input.span())
}

/// Wire words of one ownership equation (rho transcript input).
#[derive(Copy, Drop, Debug)]
pub struct EquationWords {
    pub s: felt252,
    pub pk_x: felt252,
    pub pk_y: felt252,
    pub r_x: felt252,
    pub r_y: felt252,
}


/// Fold all residuals with powers of rho and accept iff `L == O`.
///
/// `EcState::add_mul` accumulates `lambda · point` in one EC_OP circuit per
/// term; `finalize_nz() == None` is the group's own identity test. The host
/// Horner fold (A optimization; host mirror: `dual_settle::host_fold_check`): accept iff
///   L = ρ·(ρ·(…(ρ·eq_N + eq_{N−1})…) + eq_1) == O.
/// Per equation: ONE add_mul(ρ, acc) + ONE add(eq) — no ρ power table,
/// no λ mod-n multiplications (the ±1 special case of optimization B
/// disappears structurally). `finalize_nz() == None` is the identity test.
fn fold_and_check(hand_binding: felt252, equations: Array<EcPoint>, words: Array<EquationWords>) -> bool {
    let n = equations.len();
    if n == 0 {
        return false;
    }
    let rho = hand_rho(hand_binding, words.span());
    let rho_nz_scalar = rho; // raw felt scalar; EC mult handles mod-n implicitly

    let mut acc = *equations.at(n - 1);
    let mut i: u32 = n - 1;
    while i > 0 {
        i -= 1;
        let eq_point = *equations.at(i);
        let eq_opt: Option<NonZeroEcPoint> = eq_point.try_into();
        // eq_i = O contributes nothing (ρ·acc + O = ρ·acc).
        if eq_opt.is_none() {
            continue;
        }
        let acc_opt: Option<NonZeroEcPoint> = acc.try_into();
        // acc = O mid-chain: ρ·O + eq_i = eq_i — restart accumulator here;
        // subsequent Horner steps resume correctly.
        if acc_opt.is_none() {
            acc = eq_point;
            continue;
        }
        let acc_nz = acc_opt.unwrap();
        let eq_nz = eq_opt.unwrap();
        let mut state = EcStateTrait::init();
        state.add_mul(rho_nz_scalar, acc_nz);
        state.add(eq_nz);
        acc = state.finalize();
    }
    // Accept iff the final accumulator is the identity point.
    let final_opt: Option<NonZeroEcPoint> = acc.try_into();
    match final_opt {
        Option::None => true,
        Option::Some(_) => false,
    }
}


/// Verify a hand's ownership-endorsement batch in one folded EC_OP check.
/// Fail-closed on malformed payloads and off-curve points. Reveal-token and
/// leave-DLEQ residual slots (n_reveal/n_fold) are reserved and must be
/// zero until the poker_l1 mirror lands its STARK-curve residuals here.
pub fn verify_hand_batch_stark(hand_binding: felt252, payload: Span<felt252>) -> bool {
    if payload.len() < 3 {
        return false;
    }
    let n_own = felt_to_u256(*payload.at(0));
    let zero_word: felt252 = 0;
    if *payload.at(1) != zero_word || *payload.at(2) != zero_word {
        // Reserved slots must be zero (ownership-only accumulator).
        return false;
    }
    let n_own_u32: u32 = match n_own.try_into() {
        Option::Some(v) => v,
        Option::None => { return false; },
    };
    if payload.len() != 3 + 5 * n_own_u32 {
        return false;
    }
    let mut equations: Array<EcPoint> = array![];
    let mut words: Array<EquationWords> = array![];
    let mut i: u32 = 0;
    let mut cursor: u32 = 3;
    while i < n_own_u32 {
        let s_felt = *payload.at(cursor + 4);
        let (pk_x, pk_y) = (*payload.at(cursor), *payload.at(cursor + 1));
        let (r_x, r_y) = (*payload.at(cursor + 2), *payload.at(cursor + 3));
        let eq = match ownership_equation(hand_binding, (pk_x, pk_y), (r_x, r_y), s_felt) {
            Option::Some(p) => p,
            Option::None => { return false; }, // off-curve: fail-closed
        };
        equations.append(eq);
        words.append(EquationWords { s: s_felt, pk_x, pk_y, r_x, r_y });
        cursor += 5;
        i += 1;
    }
    fold_and_check(hand_binding, equations, words)
}

#[cfg(target: 'test')]
mod tests {
    use super::super::hand_batch_stark::verify_hand_batch_stark;
    use core::array::{ArrayTrait, SpanTrait};

    // Generated by texas/src/starknet/dual_settle.rs
    // `print_stark_batch_vector` (STARK curve, 2 honest ownership
    // endorsements, host parity check passes on this exact payload).
    

    

    const HAND_BINDING: felt252 = 0x25b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b;

    fn payload() -> Array<felt252> {
        array![
            0x0000000000000000000000000000000000000000000000000000000000000002,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            0x0601d3d2e265c10ff645e1554c435e72ce6721f0ba5fc96f0c650bfc6231191a,
            0x007da2512be6af510d63c0ab9e35876669d1665d3acff5a23de0aeb806d7fcb8,
            0x008e1475872ab7fa8f247671c8526184cf3140deacb88ff63eca1c9e282bc567,
            0x012b53567909e5daeea0e7d61cecb60c45ffab5d3d193c8f864e44c6bb3d9272,
            0x0704a9551604bb681fc6f4c0f3f80cadd1172c33998b8dd955d520a15e001e27,
            0x04851321b0e0fb93d9aa4871cb6989e7cf815348b63b453ae4bd5602ae3ac4f8,
            0x0503df15cad1b85900b4cd3bf0d3dfcacaff1a6a9b77e6dceffeed432bc4d164,
            0x06b7c2678fcb75d3a3274a8e4f9bfd7eaea15ac5df005e29cb02d6dc319bc8dd,
            0x046d8027c41b3b608eb2c4d3d8c1ba5f51c6a18150a77c7a9773cf59d32c6c2e,
            0x0733726b021bb21119cbf90e1af1c9c42cb99afe08281979b07096ce293a681d,
        ]
    }

    fn payload_n4() -> Array<felt252> {
        array![
            0x0000000000000000000000000000000000000000000000000000000000000004,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            0x0601d3d2e265c10ff645e1554c435e72ce6721f0ba5fc96f0c650bfc6231191a,
            0x007da2512be6af510d63c0ab9e35876669d1665d3acff5a23de0aeb806d7fcb8,
            0x07ac8da974d6fc688ecf4d042f982f5e8dd22d87aa33956ccd615218203a9c2f,
            0x02791185f3a1df929bb9065521376751b96c715be988a03620456851cac8498f,
            0x057bcc7b014f4203cfc75e6a62cd96369c4a99cbc209e2011d6fcf508b4d8ed2,
            0x04851321b0e0fb93d9aa4871cb6989e7cf815348b63b453ae4bd5602ae3ac4f8,
            0x0503df15cad1b85900b4cd3bf0d3dfcacaff1a6a9b77e6dceffeed432bc4d164,
            0x029a372f6ab027091704abee01c143c78b4c37e73cf3fe066e81649bb6e4a9c8,
            0x0618bca189f992d14b3f22108887bf30a319d28b842a762e3544585f5b3e2df8,
            0x0688fe3085f835af850691b92c53defd7b6ba18e569065ec2aed3904aad5b9b4,
            0x0746db56abc4d9fab4832ee42e92e96bbbf8cf4c9fd063b8515bda90d1e8aa5d,
            0x03805c7ba66d3a13a63fc943fe082cc9b35a8786bdf1749b44615e58bbea7d80,
            0x01b6b01ec7e83e160fa85a812ce608862c5d9e8908264bcbd16bb9c011249fd6,
            0x06afceb06f3e2b0fff42c1b49e86df9535c5b752c63756c3c3337900d67ca66e,
            0x03845eb69dbe58b2aca9f3d882635865f3734706e60c11724f494f087e584f10,
            0x07a21231a533d41e642c324d2420a0437f7357878a70dd6176f8d79db1a00ec3,
            0x05b6b70c6530acb53145a40f452b440f83e98c29bcf54cd27cf0182bd4bc086c,
            0x030c4da1a363c0ed797bc5c1b4cc1e442b23956e7eefc69e8f7cc97a3f2b08a5,
            0x0402839e8eab8312454f2dfdac3b78cca78583e147eeb0e9ea0e0f24a1125648,
            0x04261a7653284169e3e39943a29994f3fd49ed62632f69c92994b422d2455388,
        ]
    }

    fn bumped(payload: Array<felt252>, index: u32) -> Array<felt252> {
        let mut out: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < payload.len() {
            if i == index {
                out.append(*payload.at(i) + 1);
            } else {
                out.append(*payload.at(i));
            }
            i += 1;
        }
        out
    }

    fn flipped_binding() -> felt252 {
        HAND_BINDING + 1
    }


    // N=4 honest vector（同一 host 生成器；规模缩放实测用）。
    

    

    #[test]
    fn honest_hand_n4_accepts() {
        assert!(
            verify_hand_batch_stark(HAND_BINDING, payload_n4().span()),
            "honest N=4 hand must fold to L == O"
        );
    }

    #[test]
    fn tampered_n4_last_scalar_rejected() {
        let p = bumped(payload_n4(), 22); // ownership[3].s + 1
        assert!(!verify_hand_batch_stark(HAND_BINDING, p.span()));
    }

    #[test]
    fn honest_hand_accepts() {
        assert!(
            verify_hand_batch_stark(HAND_BINDING, payload().span()),
            "honest hand must fold to L == O on the STARK curve"
        );
    }

    #[test]
    fn tampered_ownership_response_rejected() {
        // ownership[0].s + 1 (word index 7, payload header is 3 words)
        let p = bumped(payload(), 7);
        assert!(!verify_hand_batch_stark(HAND_BINDING, p.span()));
    }

    #[test]
    fn tampered_public_key_rejected() {
        // ownership[1].pk_x + 1 (word index 10)
        let p = bumped(payload(), 10);
        assert!(!verify_hand_batch_stark(HAND_BINDING, p.span()));
    }

    #[test]
    fn cross_hand_replay_rejected() {
        // Same transcript settled under a different hand instance id: the
        // hand-bound domain changes every challenge, so the fold is nonzero.
        assert!(!verify_hand_batch_stark(flipped_binding(), payload().span()));
    }

    #[test]
    fn malformed_payload_rejected() {
        // Truncated: length walk fails.
        let p = payload();
        assert!(!verify_hand_batch_stark(
            HAND_BINDING,
            p.span().slice(0, 8),
        ));
        // Reserved reveal/fold slots must be zero.
        let mut q: Array<felt252> = array![];
        let mut i: u32 = 0;
        while i < p.len() {
            if i == 1 {
                q.append(1);
            } else {
                q.append(*p.at(i));
            }
            i += 1;
        }
        assert!(!verify_hand_batch_stark(HAND_BINDING, q.span()));
        // Count mismatch: header claims 2 but only 1 endorsement present.
        assert!(!verify_hand_batch_stark(
            HAND_BINDING,
            p.span().slice(0, 8),
        ));
    }
}

#[cfg(target: 'test')]
mod micro_bench {
    use core::poseidon::poseidon_hash_span;
    use core::math::u256_mul_mod_n;

    #[test]
    fn bench_floor_empty_assert() {
        // 合约调用地板：立即返回（对照 malformed 的 120k）。
        assert!(true, "floor");
    }

    #[test]
    fn bench_poseidon_span_two() {
        // corelib 文档基准值同款输入。
        let span = array![1, 2].span();
        assert!(poseidon_hash_span(span) == 0x0371cb6995ea5e7effcd2e174de264b5b407027a75a231a70c2c8d196107f0e7, "doc vector");
    }

    #[test]
    fn bench_u256_mul_mod_n_once() {
        // mod-n 乘一次（与 hand_batch_stark::fr_mul 同原语）。
        let a: u256 = u256 { low: 0x1234567890abcdef1234567890abcdef_u128, high: 0x0123456789abcdef_u128 };
        let b: u256 = u256 { low: 0xfedcba0987654321fedcba0987654321_u128, high: 0x001234567890abcd_u128 };
        let nz: Option<NonZero<u256>> = super::super::hand_batch_stark::STARK_N.try_into();
        match nz {
            Option::Some(nzv) => {
                let _ = u256_mul_mod_n(a, b, nzv);
            },
            Option::None => {},
        }
        assert!(true, "mul done");
    }
}

#[cfg(target: 'test')]
mod ec_bench {
    use core::ec::{EcPointTrait, EcStateTrait, NonZeroEcPoint};

    #[test]
    fn bench_ec_point_new() {
        // STARK 曲线生成点（合法点）：单次 on-curve 构造。
        let p = EcPointTrait::new(
            0x01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca,
            0x005668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f,
        );
        assert!(!p.is_none(), "valid point");
    }

    #[test]
    fn bench_add_mul_once() {
        // 单次 EC_OP：P + scalar·Q。
        let q = EcPointTrait::new(
            0x01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca,
            0x005668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f,
        ).unwrap();
        let q_nz: NonZeroEcPoint = q.try_into().unwrap();
        let mut state = EcStateTrait::init();
        state.add_mul(12345, q_nz);
        let out = state.finalize();
        let _ = out;
        assert!(true, "add_mul done");
    }
}
