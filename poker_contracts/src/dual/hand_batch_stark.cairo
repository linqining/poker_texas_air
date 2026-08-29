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
use core::ec::{EcPointTrait, EcStateTrait};
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
fn ownership_terms(
    hand_binding: felt252,
    pk: (felt252, felt252),
    big_r: (felt252, felt252),
    s: u256,
    ref terms: Array<TermStark>,
) -> bool {
    let (pk_x, pk_y) = pk;
    let (r_x, r_y) = big_r;
    // Fail-closed on off-curve payload points (EcPoint::new checks the
    // curve equation via the builtin).
    if EcPointTrait::new(pk_x, pk_y).is_none() || EcPointTrait::new(r_x, r_y).is_none() {
        return false;
    }
    // Gas-compressed challenge (felt-direct Poseidon; matches the Rust core
    // canonical `dapv_endorsement_challenge`):
    //   c = poseidon([proto_label, hand_binding, Gx, Gy, pkx, pky, Rx, Ry]) mod n
    // No byte serialization, no keccak — full affine coordinates are
    // injective, so the parity bit of the compressed form is unneeded.
    let input: Array<felt252> = array![
        DAPV_PROTO_LABEL, hand_binding, GENERATOR_X, GENERATOR_Y, pk_x, pk_y, r_x, r_y
    ];
    let c = poseidon_span_mod_n(input.span());
    terms.append(TermStark { coeff: s, x: GENERATOR_X, y: GENERATOR_Y });
    terms.append(TermStark { coeff: fr_neg(c), x: pk_x, y: pk_y });
    terms.append(TermStark { coeff: fr_neg(1_u256), x: r_x, y: r_y });
    true
}

/// rho = poseidon("poker/hand-batch/v1" ‖ hand_id ‖ per-term
/// (coeff_be ‖ x_be ‖ y_be)) mod n — byte-identical to
/// `dual_settle::host_fold_check`'s rho derivation.
fn hand_rho(hand_binding: felt252, terms: Span<TermStark>) -> u256 {
    // Gas-compressed rho (felt-direct Poseidon; matches the Rust core
    // canonical `dapv_hand_rho`):
    //   rho = poseidon([v1_label, hand_binding, n_terms, (coeff, x, y)*]) mod n
    let mut input: Array<felt252> = array![DAPV_V1_LABEL, hand_binding];
    input.append(terms.len().into());
    for term in terms {
        let value: TermStark = *term;
        // coeff < n < P：单 felt（与 host dapv_hand_rho 的 word_to_felt 同构）
        let coeff_felt: felt252 = value.coeff.try_into().expect('coeff fits felt');
        input.append(coeff_felt);
        input.append(value.x);
        input.append(value.y);
    }
    poseidon_span_mod_n(input.span())
}

/// Fold all residuals with powers of rho and accept iff `L == O`.
///
/// `EcState::add_mul` accumulates `lambda · point` in one EC_OP circuit per
/// term; `finalize_nz() == None` is the group's own identity test. The host
/// (`host_fold_check`) performs the identical accumulation over the same
/// rho schedule, so honest batches agree on both sides.
fn fold_and_check(hand_binding: felt252, terms: Array<TermStark>) -> bool {
    if terms.len() == 0 {
        return false;
    }
    let rho = hand_rho(hand_binding, terms.span());
    // rpow advances once per EQUATION (3 terms in the ownership-only
    // batch), exactly like the host's `terms.chunks(3)` schedule and the
    // secp variant's eq_sizes walk.
    let mut rpow: u256 = u256 { low: 1_u128, high: 0_u128 };
    let mut state = EcStateTrait::init();
    let mut i: u32 = 0;
    let mut in_eq: u32 = 0;
    while i < terms.len() {
        let term = *terms.at(i);
        let lambda = fr_mul(rpow, term.coeff);
        if lambda != 0 {
            let lambda_felt = match u256_to_felt(lambda) {
                Option::Some(f) => f,
                Option::None => { return false; },
            };
            let point = match EcPointTrait::new(term.x, term.y) {
                Option::Some(p) => p,
                Option::None => { return false; },
            };
            let point_nz = match point.try_into() {
                Option::Some(nz) => nz,
                Option::None => { return false; },
            };
            state.add_mul(lambda_felt, point_nz);
        }
        in_eq += 1;
        if in_eq == 3 {
            in_eq = 0;
            rpow = fr_mul(rpow, rho);
        }
        i += 1;
    }
    match state.finalize_nz() {
        // L == O: the identity point. Accept.
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
    let mut terms: Array<TermStark> = array![];
    let mut i: u32 = 0;
    let mut cursor: u32 = 3;
    while i < n_own_u32 {
        let pk = (*payload.at(cursor), *payload.at(cursor + 1));
        let big_r = (*payload.at(cursor + 2), *payload.at(cursor + 3));
        let s = felt_to_u256(*payload.at(cursor + 4));
        if !ownership_terms(hand_binding, pk, big_r, s, ref terms) {
            return false;
        }
        cursor += 5;
        i += 1;
    }
    fold_and_check(hand_binding, terms)
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
            0x05f63e824a08cdde327be42e37882ea15a04a05a476ede275404edb1b0b2be21,
            0x078ef4ba64382241399d1ce587e355fa8529177c81e4cb5d4acc7cd16980542d,
            0x068ec04f7a378a9029215082e8f0a120a0972080726c9d2df36628bd3f02f964,
            0x04851321b0e0fb93d9aa4871cb6989e7cf815348b63b453ae4bd5602ae3ac4f8,
            0x0503df15cad1b85900b4cd3bf0d3dfcacaff1a6a9b77e6dceffeed432bc4d164,
            0x04c450cbddab24859a41c751e06c5f70921bc32f1421570377ed846623f2b511,
            0x0652ca10974cbf996a14eec9c58c4f79dc9dfca21b07001dedff7da83eb43fd7,
            0x02e309592a8301d7dc233a03dd499da843c23cd19d4a6edd3f6ed66764f485da,
        ]
    }

    fn payload_n4() -> Array<felt252> {
        array![
            0x0000000000000000000000000000000000000000000000000000000000000004,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            0x0000000000000000000000000000000000000000000000000000000000000000,
            0x0601d3d2e265c10ff645e1554c435e72ce6721f0ba5fc96f0c650bfc6231191a,
            0x007da2512be6af510d63c0ab9e35876669d1665d3acff5a23de0aeb806d7fcb8,
            0x025eeb3d4e0194d3446344d000108c0a84af5bed0792851f72e922d249081214,
            0x02602213ba164c3eb99f766caf41a32e28481ebb676a6ecad34f9aa9efd18066,
            0x031a78ad846ac81808bb47831294f690c8b03d4c14e23814e0c3bf5ca925cfa4,
            0x04851321b0e0fb93d9aa4871cb6989e7cf815348b63b453ae4bd5602ae3ac4f8,
            0x0503df15cad1b85900b4cd3bf0d3dfcacaff1a6a9b77e6dceffeed432bc4d164,
            0x019d60692b8dcc56e6e2444f97aecc1a774b32998e136efa0061e32fbf1eb96a,
            0x007e667ba5ea4e23c1d47d96c7122a0b18392cdafae81e5f689863d16a10ab03,
            0x07ee79bcfdafc7f046c77d1de342cf52ac8ce0b6aaa9d65268e8b9b0b8b07e93,
            0x0746db56abc4d9fab4832ee42e92e96bbbf8cf4c9fd063b8515bda90d1e8aa5d,
            0x03805c7ba66d3a13a63fc943fe082cc9b35a8786bdf1749b44615e58bbea7d80,
            0x04265b48984cce591735fbfed6c4a428521c1fe0e778cd73b9ea76685deb8d80,
            0x02f3c1c2e5d3b3cf21846b1d47e3c3387d4d5bfa8b361254969ba76df6e12836,
            0x00a54d0c32093ee5907997579560e03b5455c51e60a3e2eabb1920a5256c491c,
            0x07a21231a533d41e642c324d2420a0437f7357878a70dd6176f8d79db1a00ec3,
            0x05b6b70c6530acb53145a40f452b440f83e98c29bcf54cd27cf0182bd4bc086c,
            0x042538c15248b44e7ad07af031c60b286885d107286353bc7207a98345e7ff16,
            0x007fd8a137e1a6af0cae1c56fa71ddfa72f65f768c1c912a7a2323216c53a0d0,
            0x03ae28b37d498528a41bc8f4481d4a6832e22f10a5c429b1a11d5b3cacf00642,
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
