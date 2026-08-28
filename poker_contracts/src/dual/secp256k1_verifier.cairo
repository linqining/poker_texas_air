//! On-chain P-proof verification via Starknet's native secp256k1 EC_OP
//! builtin (DUAL_PROOF_PROTOCOL.md v2.2, §4).
//!
//! The protocol group is secp256k1 exactly so this verifier can use the VM's
//! curve builtins — no custom field arithmetic, no Montgomery. Rust-side
//! reference: `poker_protocol_core::Secp256k1Curve` and the sigma suite in
//! `poker-protocol-proofs` (FiatShamirSha3 transcript); Rust↔Cairo vectors
//! pin the semantics (§4.2 discipline).
//!
//! Wire shape per ownership proof (calldata): `(pk_x, pk_y, r_x, r_y, c, s)`
//! — six `u256` values, big-endian field/scalar encodings.

use core::starknet::secp256k1::Secp256k1Point;
use core::starknet::secp256_trait::{Secp256PointTrait, Secp256Trait};
use super::keccak::{challenge_mod_n, u256_to_be_bytes};
use super::keccak_transcript::{point_compressed, scalar_be, transcript_append,
    transcript_challenge, transcript_new};


/// secp256k1 base field prime p (for point negation: -y = p - y).
pub const SECP256K1_P: u256 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;

// ---- shared EC helpers (EC_OP builtin wrappers) ----

fn ec_decode(x: u256, y: u256) -> Option<Secp256k1Point> {
    decode_new(Secp256Trait::<Secp256k1Point>::secp256_ec_new_syscall(x, y))
}

fn ec_mul(point: Secp256k1Point, scalar: u256) -> Option<Secp256k1Point> {
    match Secp256PointTrait::mul(point, scalar) {
        Result::Ok(point) => Option::Some(point),
        Result::Err(_) => Option::None,
    }
}

fn ec_add(a: Secp256k1Point, b: Secp256k1Point) -> Option<Secp256k1Point> {
    match Secp256PointTrait::add(a, b) {
        Result::Ok(point) => Option::Some(point),
        Result::Err(_) => Option::None,
    }
}

fn ec_negate(x: u256, y: u256) -> (u256, u256) {
    (x, SECP256K1_P - y)
}

fn ec_equation_holds(lhs: Secp256k1Point, rhs: Secp256k1Point) -> bool {
    let (lx, ly) = match Secp256PointTrait::get_coordinates(lhs) {
        Result::Ok(pair) => pair,
        Result::Err(_) => {
            return false;
        }
    };
    let (rx, ry) = match Secp256PointTrait::get_coordinates(rhs) {
        Result::Ok(pair) => pair,
        Result::Err(_) => {
            return false;
        }
    };
    lx == rx && ly == ry
}

fn label(parts: Span<u8>) -> Span<u8> {
    parts
}


/// secp256k1 generator, affine x (SEC2 / RFC 5480).
pub const GENERATOR_X: u256 = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;

/// secp256k1 generator, affine y.
pub const GENERATOR_Y: u256 = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8;

/// Proof-kind discriminants for the settlement dispatcher.
pub const PROOF_KIND_OWNERSHIP: u8 = 1;
pub const PROOF_KIND_SHUFFLE_BG: u8 = 2;
pub const PROOF_KIND_FOLD_LEAVE: u8 = 3;
pub const PROOF_KIND_REVEAL_TOKENS: u8 = 4;
pub const PROOF_KIND_UNIFIED: u8 = 5;

/// Flatten `SyscallResult<Option<Secp256k1Point>>`: syscall failure
/// (unexpected in the VM) becomes `None` — fail-closed.
fn decode_new(result: Result<Option<Secp256k1Point>, Array<felt252>>) -> Option<Secp256k1Point> {
    match result {
        Result::Ok(option) => option,
        Result::Err(_) => Option::None,
    }
}

/// Verify a Schnorr proof of key ownership: `s·G == R + c·pk` with the
/// Fiat–Shamir challenge derived **on-chain**:
/// `c = keccak256(G_compressed ‖ pk_compressed ‖ R_compressed) mod n`
/// — matching `PKOwnershipProof::challenge` in Rust (33-byte SEC1 compressed
/// encodings, Keccak-256, little-endian scalar interpretation).
///
/// Points that fail on-curve decoding are rejected (`secp256_ec_new` returns
/// `None`); the challenge is never caller-supplied, removing the transcript
/// forgery surface from calldata.
pub fn verify_ownership(pk: (u256, u256), big_r: (u256, u256), s: u256) -> bool {
    let (pk_x, pk_y) = pk;
    let (r_x, r_y) = big_r;
    let generator = match decode_new(
        Secp256Trait::<Secp256k1Point>::secp256_ec_new_syscall(GENERATOR_X, GENERATOR_Y),
    ) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let pk_point = match decode_new(
        Secp256Trait::<Secp256k1Point>::secp256_ec_new_syscall(pk_x, pk_y),
    ) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let r_point = match decode_new(
        Secp256Trait::<Secp256k1Point>::secp256_ec_new_syscall(r_x, r_y),
    ) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let mut challenge_input: Array<u8> = array![];
    append_compressed(ref challenge_input, GENERATOR_X, GENERATOR_Y);
    append_compressed(ref challenge_input, pk_x, pk_y);
    append_compressed(ref challenge_input, r_x, r_y);
    let c = challenge_mod_n(challenge_input.span());

    let lhs = match ec_mul(generator, s) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let c_pk = match ec_mul(pk_point, c) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let rhs = match ec_add(r_point, c_pk) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    ec_equation_holds(lhs, rhs)
}

fn append_compressed(ref out: Array<u8>, x: u256, y: u256) {
    let tag: u8 = if y.low & 1 == 1 { 0x03 } else { 0x02 };
    out.append(tag);
    let x_bytes = u256_to_be_bytes(x);
    let mut i: u32 = 0;
    while i < 32 {
        out.append(*x_bytes.at(i));
        i += 1;
    }
}

/// Verify one P proof by kind against a protocol name (transcript domain).
/// Fail-closed: the Bayer-Groth shuffle product argument
/// (PROOF_KIND_SHUFFLE_BG) is not wired on-chain yet and is always rejected.
pub fn verify_p_proof(
    kind: u8, protocol_name: Span<u8>, payload: Span<u256>,
) -> bool {
    if kind == PROOF_KIND_OWNERSHIP {
        // Layout (5): [pk_x, pk_y, r_x, r_y, s] - the challenge is derived
        // on-chain from the compressed points.
        if payload.len() != 5_u32 {
            return false;
        }
        let pk = (*payload.at(0), *payload.at(1));
        let big_r = (*payload.at(2), *payload.at(3));
        return verify_ownership(pk, big_r, *payload.at(4));
    }
    if kind == PROOF_KIND_REVEAL_TOKENS {
        // Layout (14): [pk 2, c1 2, c2 2, token 2, t1 2, t2 2, nonce 1, s 1]
        if payload.len() != 14_u32 {
            return false;
        }
        let pk = (*payload.at(0), *payload.at(1));
        let c1 = (*payload.at(2), *payload.at(3));
        let c2 = (*payload.at(4), *payload.at(5));
        let token = (*payload.at(6), *payload.at(7));
        let t1 = (*payload.at(8), *payload.at(9));
        let t2 = (*payload.at(10), *payload.at(11));
        let nonce = *payload.at(12);
        let s = *payload.at(13);
        return verify_reveal_token(
            protocol_name, pk, c1, c2, token, t1, t2, nonce, s,
        );
    }
    if kind == PROOF_KIND_FOLD_LEAVE {
        // Layout (7 + 8n): [pk 2, commitment_pk 2, nonce 1, s 1, n 1,
        //  in_c1 2n, in_c2 2n, out_c1 2n, out_c2 2n, a 2n]
        let len = payload.len();
        if len < 15_u32 {
            return false;
        }
        let tail = len - 7_u32;
        if tail % 8_u32 != 0 {
            return false;
        }
        let n: u32 = (tail / 8_u32).try_into().expect('n fits u32');
        let pk = (*payload.at(0), *payload.at(1));
        let commitment_pk = (*payload.at(2), *payload.at(3));
        let nonce = *payload.at(4);
        let s = *payload.at(5);
        let n_declared: u32 = (*payload.at(6)).try_into().expect('n fits u32');
        if n_declared != n {
            return false;
        }
        let in_c1 = payload.slice(7_u32, 7_u32 + 2 * n);
        let in_c2 = payload.slice(7_u32 + 2 * n, 7_u32 + 4 * n);
        let out_c1 = payload.slice(7_u32 + 4 * n, 7_u32 + 6 * n);
        let out_c2 = payload.slice(7_u32 + 6 * n, 7_u32 + 8 * n);
        let a = payload.slice(7_u32 + 8 * n, len);
        return verify_fold_leave(
            protocol_name, pk, commitment_pk, nonce, s, n,
            in_c1, in_c2, out_c1, out_c2, a,
        );
    }
    if kind == PROOF_KIND_UNIFIED {
        // Layout (6 + 4*n_fold + 3*n_reveal + 1 + n_rel):
        // [pk 2, n_fold 1, n_reveal 1, fold 4*n_fold, reveal 3*n_reveal,
        //  s 1, commitments 2*n_rel] where n_rel = 1 + n_fold + n_reveal.
        let len = payload.len();
        if len < 8_u32 {
            return false;
        }
        let n_fold_val = *payload.at(2);
        let n_reveal_val = *payload.at(3);
        let n_fold: u32 = n_fold_val.try_into().expect('n_fold fits u32');
        let n_reveal: u32 = n_reveal_val.try_into().expect('n_reveal fits u32');
        let n_rel = 1_u32 + n_fold + n_reveal;
        let expected = 4_u32 + 4 * n_fold + 3 * n_reveal + 1 + 2 * n_rel;
        if len != expected {
            return false;
        }
        let s_scalar = *payload.at(4_u32 + 4 * n_fold + 3 * n_reveal);
        let pk = (*payload.at(0), *payload.at(1));
        let fold = payload.slice(4_u32, 4_u32 + 4 * n_fold);
        let reveal = payload.slice(
            4_u32 + 4 * n_fold,
            4_u32 + 4 * n_fold + 3 * n_reveal,
        );
        let commitments = payload.slice(
            4_u32 + 4 * n_fold + 3 * n_reveal + 1,
            len,
        );
        return verify_unified(
            protocol_name, pk, n_fold, n_reveal, fold, reveal, s_scalar, commitments,
        );
    }
    // Shuffle (BG product argument) verifier: pending on-chain wiring.
    false
}

/// Verify the per-player unified Sigma proof (standard:
/// `poker_protocol::unified_sigma`, protocol name
/// `b"poker_unified_sigma_v1"`):
/// relations R_k = (X_k, Y_k) = (G, pk), per fold card (in_c1_i,
/// in_c2_i - out_c2_i), per reveal card (c1_j, token_j); check
/// `s * X_k == A_k + c * Y_k` for every k with the challenge replayed from
/// the Keccak transcript (labels byte-identical to the Rust labels).
pub fn verify_unified(
    protocol_name: Span<u8>,
    pk: (u256, u256),
    n_fold: u32,
    n_reveal: u32,
    fold: Span<u256>,
    reveal: Span<u256>,
    s_scalar: u256,
    commitments: Span<u256>,
) -> bool {
    let n_rel = 1_u32 + n_fold + n_reveal;

    // ---- Transcript replay (consensus order). ----
    let l_pk = label(array![0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x70, 0x6b].span()); // unified_pk
    let l_n_fold = label(array![
        0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x6e, 0x5f, 0x66, 0x6f, 0x6c, 0x64
    ].span());
    let l_in_c1 = label(array![
        0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x66, 0x6f, 0x6c, 0x64, 0x5f, 0x69,
        0x6e, 0x5f, 0x63, 0x31
    ].span());
    let l_in_c2 = label(array![
        0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x66, 0x6f, 0x6c, 0x64, 0x5f, 0x69,
        0x6e, 0x5f, 0x63, 0x32
    ].span());
    let l_out_c1 = label(array![
        0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x66, 0x6f, 0x6c, 0x64, 0x5f, 0x6f,
        0x75, 0x74, 0x5f, 0x63, 0x31
    ].span());
    let l_out_c2 = label(array![
        0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x66, 0x6f, 0x6c, 0x64, 0x5f, 0x6f,
        0x75, 0x74, 0x5f, 0x63, 0x32
    ].span());
    let l_n_reveal = label(array![
        0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x6e, 0x5f, 0x72, 0x65, 0x76, 0x65,
        0x61, 0x6c
    ].span());
    let l_r_c1 = label(array![
        0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x72, 0x65, 0x76, 0x65, 0x61, 0x6c,
        0x5f, 0x63, 0x31
    ].span());
    let l_r_c2 = label(array![
        0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x72, 0x65, 0x76, 0x65, 0x61, 0x6c,
        0x5f, 0x63, 0x32
    ].span());
    let l_r_token = label(array![
        0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x72, 0x65, 0x76, 0x65, 0x61, 0x6c,
        0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e
    ].span());
    let l_commit = label(array![
        0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
        0x6d, 0x65, 0x6e, 0x74
    ].span());
    let l_ch = label(array![
        0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65
    ].span());

    let (pk_x, pk_y) = pk;
    let mut state = transcript_new(protocol_name);
    state = transcript_append(state, l_pk, point_compressed(pk_x, pk_y).span());
    state = transcript_append(state, l_n_fold, scalar_be(n_fold.into()).span());
    let mut i: u32 = 0;
    while i < n_fold {
        let base = 4 * i;
        state = transcript_append(state, l_in_c1, point_compressed(*fold.at(base), *fold.at(base + 1)).span());
        state = transcript_append(state, l_in_c2, point_compressed(*fold.at(base + 2), *fold.at(base + 3)).span());
        state = transcript_append(state, l_out_c1, point_compressed(*fold.at(base + 4), *fold.at(base + 5)).span());
        state = transcript_append(state, l_out_c2, point_compressed(*fold.at(base + 6), *fold.at(base + 7)).span());
        i += 1;
    }
    state = transcript_append(state, l_n_reveal, scalar_be(n_reveal.into()).span());
    // Reveal layout: [c1 2, c2 2, token 2] per card.
    i = 0;
    while i < n_reveal {
        let base = 6 * i;
        state = transcript_append(state, l_r_c1, point_compressed(*reveal.at(base), *reveal.at(base + 1)).span());
        state = transcript_append(state, l_r_c2, point_compressed(*reveal.at(base + 2), *reveal.at(base + 3)).span());
        state = transcript_append(state, l_r_token, point_compressed(*reveal.at(base + 4), *reveal.at(base + 5)).span());
        i += 1;
    }
    i = 0;
    while i < n_rel {
        state = transcript_append(
            state,
            l_commit,
            point_compressed(*commitments.at(2 * i), *commitments.at(2 * i + 1)).span(),
        );
        i += 1;
    }
    let c = transcript_challenge(state, l_ch);

    // ---- Equation checks. ----
    // Relation 0: (G, pk).
    let generator = match ec_decode(GENERATOR_X, GENERATOR_Y) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let a0 = match ec_decode(*commitments.at(0), *commitments.at(1)) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let lhs0 = match ec_mul(generator, s_scalar) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    // c * pk: decode pk then scale by c.
    let pk_point = match ec_decode(pk_x, pk_y) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let c_pk_scaled = match ec_mul(pk_point, c) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let rhs0 = match ec_add(a0, c_pk_scaled) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    if !ec_equation_holds(lhs0, rhs0) {
        return false;
    }

    // Fold relations: (in_c1_i, in_c2_i - out_c2_i).
    i = 0;
    while i < n_fold {
        let base = 4 * i;
        let c1_point = match ec_decode(*fold.at(base), *fold.at(base + 1)) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let in_c2 = match ec_decode(*fold.at(base + 2), *fold.at(base + 3)) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let (ox, oy) = ec_negate(*fold.at(base + 6), *fold.at(base + 7));
        let neg_out = match ec_decode(ox, oy) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let d2 = match ec_add(in_c2, neg_out) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let rel = 1 + i;
        let a_point = match ec_decode(*commitments.at(2 * rel), *commitments.at(2 * rel + 1)) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let lhs = match ec_mul(c1_point, s_scalar) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let c_d2 = match ec_mul(d2, c) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let rhs = match ec_add(a_point, c_d2) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        if !ec_equation_holds(lhs, rhs) {
            return false;
        }
        i += 1;
    }

    // Reveal relations: (c1_j, token_j).
    i = 0;
    while i < n_reveal {
        let base = 6 * i;
        let c1_point = match ec_decode(*reveal.at(base), *reveal.at(base + 1)) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let token_point = match ec_decode(*reveal.at(base + 4), *reveal.at(base + 5)) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let rel = 1 + n_fold + i;
        let a_point = match ec_decode(*commitments.at(2 * rel), *commitments.at(2 * rel + 1)) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let lhs = match ec_mul(c1_point, s_scalar) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let c_token = match ec_mul(token_point, c) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let rhs = match ec_add(a_point, c_token) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        if !ec_equation_holds(lhs, rhs) {
            return false;
        }
        i += 1;
    }
    true
}

/// Verify a Chaum-Pedersen reveal-token proof:
/// `s*G == t1 + c*pk` and `s*c1 == t2 + c*token`, with the challenge replayed
/// from the Keccak transcript over (nonce, pk, c1, c2, token, t1, t2) - the
/// exact schedule of `RevealTokenProof::compute_challenge` in Rust.
pub fn verify_reveal_token(
    protocol_name: Span<u8>,
    pk: (u256, u256), c1: (u256, u256), c2: (u256, u256), token: (u256, u256),
    t1: (u256, u256), t2: (u256, u256), nonce: u256, s: u256,
) -> bool {
    let l_nonce = label(array![0x72, 0x65, 0x76, 0x65, 0x61, 0x6c, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x5f, 0x6e, 0x6f, 0x6e, 0x63, 0x65].span());
    let l_pk = label(array![0x70, 0x6b].span());
    let l_c1 = label(array![0x63, 0x31].span());
    let l_c2 = label(array![0x63, 0x32].span());
    let l_token = label(array![0x72, 0x65, 0x76, 0x65, 0x61, 0x6c, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e].span());
    let l_t1 = label(array![0x74, 0x31].span());
    let l_t2 = label(array![0x74, 0x32].span());
    let l_ch = label(array![0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65].span());

    let (pk_x, pk_y) = pk;
    let (c1_x, c1_y) = c1;
    let (c2_x, c2_y) = c2;
    let (token_x, token_y) = token;
    let (t1_x, t1_y) = t1;
    let (t2_x, t2_y) = t2;
    let mut state = transcript_new(protocol_name);
    state = transcript_append(state, l_nonce, scalar_be(nonce).span());
    state = transcript_append(state, l_pk, point_compressed(pk_x, pk_y).span());
    state = transcript_append(state, l_c1, point_compressed(c1_x, c1_y).span());
    state = transcript_append(state, l_c2, point_compressed(c2_x, c2_y).span());
    state = transcript_append(state, l_token, point_compressed(token_x, token_y).span());
    state = transcript_append(state, l_t1, point_compressed(t1_x, t1_y).span());
    state = transcript_append(state, l_t2, point_compressed(t2_x, t2_y).span());
    let c = transcript_challenge(state, l_ch);

    let pk_point = match ec_decode(pk_x, pk_y) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let c1_point = match ec_decode(c1_x, c1_y) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let token_point = match ec_decode(token_x, token_y) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let t1_point = match ec_decode(t1_x, t1_y) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let t2_point = match ec_decode(t2_x, t2_y) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let generator = match ec_decode(GENERATOR_X, GENERATOR_Y) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };

    // Equation 1: s*G == t1 + c*pk
    let lhs_g = match ec_mul(generator, s) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let c_pk = match ec_mul(pk_point, c) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let rhs_g = match ec_add(t1_point, c_pk) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    if !ec_equation_holds(lhs_g, rhs_g) {
        return false;
    }

    // Equation 2: s*c1 == t2 + c*token
    let lhs_ct = match ec_mul(c1_point, s) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let c_token = match ec_mul(token_point, c) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let rhs_ct = match ec_add(t2_point, c_token) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    ec_equation_holds(lhs_ct, rhs_ct)
}

/// Verify a batch leave (fold) DLEQ proof:
/// `s*G == commitment_pk + c*pk` and per card
/// `s*in_c1_i == a_i + c*d2_i` with `d2_i = in_c2_i - out_c2_i`.
/// Transcript replay follows `append_dleq_context` for the `LeaveKind`
/// labels.
pub fn verify_fold_leave(
    protocol_name: Span<u8>,
    pk: (u256, u256), commitment_pk: (u256, u256), nonce: u256, s: u256,
    n: u32,
    in_c1: Span<u256>, in_c2: Span<u256>, out_c1: Span<u256>, out_c2: Span<u256>,
    a: Span<u256>,
) -> bool {
    let l_pk = label(array![0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x70, 0x6b].span());
    let l_in_c1 = label(array![0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x31].span());
    let l_in_c2 = label(array![0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x32].span());
    let l_out_c1 = label(array![0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x31].span());
    let l_out_c2 = label(array![0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x32].span());
    let l_a = label(array![0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x70, 0x65, 0x72, 0x5f, 0x63, 0x61, 0x72, 0x64, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74].span());
    let l_cpk = label(array![0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x5f, 0x70, 0x6b].span());
    let l_d2 = label(array![0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x64, 0x32].span());
    let l_nonce = label(array![0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x6e, 0x6f, 0x6e, 0x63, 0x65].span());
    let l_ch = label(array![0x6c, 0x65, 0x61, 0x76, 0x65, 0x5f, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65].span());

    let (pk_x, pk_y) = pk;
    let (cpk_x, cpk_y) = commitment_pk;
    let mut state = transcript_new(protocol_name);
    state = transcript_append(state, l_pk, point_compressed(pk_x, pk_y).span());
    let mut i: u32 = 0;
    while i < n {
        let x1 = *in_c1.at(2 * i);
        let y1 = *in_c1.at(2 * i + 1);
        state = transcript_append(state, l_in_c1, point_compressed(x1, y1).span());
        let x2 = *in_c2.at(2 * i);
        let y2 = *in_c2.at(2 * i + 1);
        state = transcript_append(state, l_in_c2, point_compressed(x2, y2).span());
        i += 1;
    }
    i = 0;
    while i < n {
        let x1 = *out_c1.at(2 * i);
        let y1 = *out_c1.at(2 * i + 1);
        state = transcript_append(state, l_out_c1, point_compressed(x1, y1).span());
        let x2 = *out_c2.at(2 * i);
        let y2 = *out_c2.at(2 * i + 1);
        state = transcript_append(state, l_out_c2, point_compressed(x2, y2).span());
        i += 1;
    }
    i = 0;
    while i < n {
        let xa = *a.at(2 * i);
        let ya = *a.at(2 * i + 1);
        state = transcript_append(state, l_a, point_compressed(xa, ya).span());
        i += 1;
    }
    state = transcript_append(
        state,
        l_cpk,
        point_compressed(cpk_x, cpk_y).span(),
    );
    i = 0;
    while i < n {
        let (nx, ny) = ec_negate(*out_c2.at(2 * i), *out_c2.at(2 * i + 1));
        let d2 = match ec_decode(nx, ny) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let in_point = match ec_decode(*in_c2.at(2 * i), *in_c2.at(2 * i + 1)) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let d2_point = match ec_add(in_point, d2) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let (dx, dy) = match Secp256PointTrait::get_coordinates(d2_point) {
            Result::Ok(pair) => pair,
            Result::Err(_) => {
                return false;
            }
        };
        state = transcript_append(state, l_d2, point_compressed(dx, dy).span());
        i += 1;
    }
    state = transcript_append(state, l_nonce, scalar_be(nonce).span());
    let c = transcript_challenge(state, l_ch);

    let pk_point = match ec_decode(pk_x, pk_y) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let cpk_point = match ec_decode(cpk_x, cpk_y) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let generator = match ec_decode(GENERATOR_X, GENERATOR_Y) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };

    // Equation 1: s*G == commitment_pk + c*pk
    let lhs_g = match ec_mul(generator, s) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let c_pk = match ec_mul(pk_point, c) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    let rhs_g = match ec_add(cpk_point, c_pk) {
        Option::Some(point) => point,
        Option::None => {
            return false;
        }
    };
    if !ec_equation_holds(lhs_g, rhs_g) {
        return false;
    }

    // Equation 2 per card: s*in_c1_i == a_i + c*d2_i
    let mut k: u32 = 0;
    while k < n {
        let c1_point = match ec_decode(*in_c1.at(2 * k), *in_c1.at(2 * k + 1)) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let a_point = match ec_decode(*a.at(2 * k), *a.at(2 * k + 1)) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let (nx, ny) = ec_negate(*out_c2.at(2 * k), *out_c2.at(2 * k + 1));
        let neg_out = match ec_decode(nx, ny) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let in_c2_point = match ec_decode(*in_c2.at(2 * k), *in_c2.at(2 * k + 1)) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let d2_point = match ec_add(in_c2_point, neg_out) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let lhs = match ec_mul(c1_point, s) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let c_d2 = match ec_mul(d2_point, c) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        let rhs = match ec_add(a_point, c_d2) {
            Option::Some(point) => point,
            Option::None => {
                return false;
            }
        };
        if !ec_equation_holds(lhs, rhs) {
            return false;
        }
        k += 1;
    }
    true
}

#[cfg(target: 'test')]
mod tests {
    use super::*;

    #[test]
    fn schnorr_rust_vector_verifies_and_forgery_rejected() {
        // Generated by poker-protocol-core/tests/secp256k1_vectors.rs (after
        // the Keccak-256 challenge switch): sk = hash("cairo_vector_sk"),
        // pk = sk*G, R = w*G, s = w + c*sk with c = keccak256(G‖pk‖R) mod n
        // derived on-chain by the verifier.
        let pk = (
            0xb088d62da5fd575a3255db4fcc211b5d900d8e8257ea55213e3edd5688dae34f,
            0x92d054e7d6df0f0e35dc251354c7f565c92781112072944070e3ef4e4b726e1a,
        );
        let big_r = (
            0x5b80c59b594535c31bdbe2ea578216f2f37e8813249ea7c5cbcd4f19b110c92b,
            0x13a666faceab974bbd10290f9204ae53b1347fe09b9b70ab04eeecd53ac510b9,
        );
        let s = 0x5dfd414cc5e8608c0f5e50f0f1d93b54243b1b409c1709bf2dbb4c2d9235e28e;
        assert!(verify_ownership(pk, big_r, s), "honest schnorr verifies");

        let s_bad = 0x5dfd414cc5e8608c0f5e50f0f1d93b54243b1b409c1709bf2dbb4c2d9235e28f;
        assert!(!verify_ownership(pk, big_r, s_bad), "forged s must not verify");

        // Wrong public key must not verify (a different k*G point).
        let pk_other = (
            0x8ff59fdfde37d31eabd2e5ccdc5f11986bd1c36eddb3bdd428e4a7df08ed647f,
            0x31d606ae4285d0cc1d642cc41af22685c160c7d32803ce801cf7d5f216b428e9,
        );
        assert!(!verify_ownership(pk_other, big_r, s), "wrong pk must not verify");

        // Off-curve point must be rejected by decoding.
        let off_curve = (
            0x0000000000000000000000000000000000000000000000000000000000000001,
            0x0000000000000000000000000000000000000000000000000000000000000001,
        );
        assert!(!verify_ownership(off_curve, big_r, s), "off-curve pk rejected");
    }

    #[test]
    fn challenge_input_probe() {
        let mut ci: Array<u8> = array![];
        append_compressed(ref ci, GENERATOR_X, GENERATOR_Y);
        assert!(ci.len() == 33, "after G");
        append_compressed(ref ci, 0x1111, 0x2222);
        append_compressed(ref ci, 0x3333, 0x4444);
        assert!(ci.len() == 99, "after three");
        let c = super::super::keccak::challenge_mod_n(ci.span());
        assert!(c > 0, "challenge nonzero");
    }

    #[test]
    fn challenge_matches_rust_vector() {
        // The on-chain derived challenge must equal the Rust generator's C.
        let pk = (
            0xb088d62da5fd575a3255db4fcc211b5d900d8e8257ea55213e3edd5688dae34f,
            0x92d054e7d6df0f0e35dc251354c7f565c92781112072944070e3ef4e4b726e1a,
        );
        let big_r = (
            0x5b80c59b594535c31bdbe2ea578216f2f37e8813249ea7c5cbcd4f19b110c92b,
            0x13a666faceab974bbd10290f9204ae53b1347fe09b9b70ab04eeecd53ac510b9,
        );
        let (pk_x, pk_y) = pk;
        let (r_x, r_y) = big_r;
        let mut challenge_input: Array<u8> = array![];
        append_compressed(ref challenge_input, GENERATOR_X, GENERATOR_Y);
        append_compressed(ref challenge_input, pk_x, pk_y);
        append_compressed(ref challenge_input, r_x, r_y);
        let c = super::super::keccak::challenge_mod_n(challenge_input.span());
        let expected_c = 0x7ce2a717e93b0e5c5ae5bcd1a69a69fe3e3ee14dfc5e3336a0b5dfa8e9794f8b;
        assert!(c == expected_c, "challenge matches rust C");
    }

    #[test]
    fn challenge_bytes_golden() {
        // Golden 99-byte challenge input from the Rust generator
        // (secp256k1_vectors::print_ownership_challenge_debug).
        let golden: Array<u8> = array![0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98, 0x02, 0xb0, 0x88, 0xd6, 0x2d, 0xa5, 0xfd, 0x57, 0x5a, 0x32, 0x55, 0xdb, 0x4f, 0xcc, 0x21, 0x1b, 0x5d, 0x90, 0x0d, 0x8e, 0x82, 0x57, 0xea, 0x55, 0x21, 0x3e, 0x3e, 0xdd, 0x56, 0x88, 0xda, 0xe3, 0x4f, 0x03, 0x5b, 0x80, 0xc5, 0x9b, 0x59, 0x45, 0x35, 0xc3, 0x1b, 0xdb, 0xe2, 0xea, 0x57, 0x82, 0x16, 0xf2, 0xf3, 0x7e, 0x88, 0x13, 0x24, 0x9e, 0xa7, 0xc5, 0xcb, 0xcd, 0x4f, 0x19, 0xb1, 0x10, 0xc9, 0x2b];
        let (pk_x, pk_y) = (
            0xb088d62da5fd575a3255db4fcc211b5d900d8e8257ea55213e3edd5688dae34f,
            0x92d054e7d6df0f0e35dc251354c7f565c92781112072944070e3ef4e4b726e1a,
        );
        let (r_x, r_y) = (
            0x5b80c59b594535c31bdbe2ea578216f2f37e8813249ea7c5cbcd4f19b110c92b,
            0x13a666faceab974bbd10290f9204ae53b1347fe09b9b70ab04eeecd53ac510b9,
        );
        let mut built: Array<u8> = array![];
        append_compressed(ref built, GENERATOR_X, GENERATOR_Y);
        append_compressed(ref built, pk_x, pk_y);
        append_compressed(ref built, r_x, r_y);
        let mut i: u32 = 0;
        while i < 99 {
            assert!(*built.at(i) == *golden.at(i), "byte mismatch");
            i += 1;
        }
        let c = super::super::keccak::challenge_mod_n(golden.span());
        let expected_c = 0x7ce2a717e93b0e5c5ae5bcd1a69a69fe3e3ee14dfc5e3336a0b5dfa8e9794f8b;
        assert!(c == expected_c, "challenge matches golden");
    }

    #[test]
    fn reveal_token_rust_vector_verifies_and_forgery_rejected() {
        // Generated by secp256k1_vectors::print_reveal_and_dleq_keccak_vectors
        // (KeccakTranscript, protocol_name = "poker_secp256k1_keccak_v1").
        let protocol_name: Array<u8> = array![
            0x70, 0x6f, 0x6b, 0x65, 0x72, 0x5f, 0x73, 0x65, 0x63, 0x70, 0x32, 0x35, 0x36, 0x6b,
            0x31, 0x5f, 0x6b, 0x65, 0x63, 0x63, 0x61, 0x6b, 0x5f, 0x76, 0x31
        ];
        let pk = (
            0xb088d62da5fd575a3255db4fcc211b5d900d8e8257ea55213e3edd5688dae34f,
            0x92d054e7d6df0f0e35dc251354c7f565c92781112072944070e3ef4e4b726e1a,
        );
        let c1 = (
            0x037a0992fa3e5e280b2e0af14a73896ec727a3ac37342f25ce694bdf69152eab,
            0xd609710afe4a2afd32783d442ffc65f5275ab47845b79ac800315ec6fef56cd8,
        );
        let c2 = (
            0x5479ae49417e8757f3de6ab4078e00621909d6fffcf064b0ed69eca849347e94,
            0xa33138d97a3be42bd8957db790a767d6b66790f06a0cdc0b1502c596333bbe9d,
        );
        let token = (
            0xf524cea9d9e2a3d96a3f513aa018132d94dda2ae7c2fd48a1c0c58aa2dc241b9,
            0x067d588b361c0773d777b4b0a1833f8da9ec503cae798959b65309f9782d6120,
        );
        let t1 = (
            0x65a4bb85142bcaf4d406f22ee4f815c0f517ccabd1e4570e483e4df20a2fe50c,
            0xc3ee676911ef4632dab0461245900d9482cb70943cf225e60426fddcbae5f59c,
        );
        let t2 = (
            0x8acb17cdd3dd36a69a1e02351d9ef5667c0b979730d232f147084d1311f5e5ab,
            0x7acf6c52848bb69269bc4c4c0f63094f0eb55c1b50b87252bf13a63b193d8aac,
        );
        let nonce = 0x72813f993e3d8529e966bc2c1437b02859f62c4e4092ee42ff096f58ab4f1acf;
        let s = 0xfc9c558cdee604439115d8b258542144b407f0c9624a13bff02e9606695901a5;
        assert!(
            verify_reveal_token(
                protocol_name.span(), pk, c1, c2, token, t1, t2, nonce, s,
            ),
            "honest CP verifies"
        );

        // Forged response must not verify.
        let s_bad = s - 1;
        assert!(
            !verify_reveal_token(protocol_name.span(), pk, c1, c2, token, t1, t2, nonce, s_bad),
            "forged s must not verify"
        );

        // Point negation (on-curve) must fail the equation path.
        let (token_x, token_y) = token;
        let token_neg = (token_x, SECP256K1_P - token_y);
        assert!(
            !verify_reveal_token(
                protocol_name.span(), pk, c1, c2, token_neg, t1, t2, nonce, s,
            ),
            "negated token must not verify"
        );
    }

    #[test]
    fn fold_leave_rust_vector_verifies_and_tamper_rejected() {
        // Generated by secp256k1_vectors::print_reveal_and_dleq_keccak_vectors
        // (2-card leave batch, KeccakTranscript, same protocol_name).
        let protocol_name: Array<u8> = array![
            0x70, 0x6f, 0x6b, 0x65, 0x72, 0x5f, 0x73, 0x65, 0x63, 0x70, 0x32, 0x35, 0x36, 0x6b,
            0x31, 0x5f, 0x6b, 0x65, 0x63, 0x63, 0x61, 0x6b, 0x5f, 0x76, 0x31
        ];
        let pk = (
            0xb088d62da5fd575a3255db4fcc211b5d900d8e8257ea55213e3edd5688dae34f,
            0x92d054e7d6df0f0e35dc251354c7f565c92781112072944070e3ef4e4b726e1a,
        );
        let in_c1: Array<u256> = array![
            0xc9867585960a7f42455c2f94398dbfeb88ab8b9e1d3882bb23872992259c4b02,
            0x8c1cbdcce16306fc92ce9324f0f460966be7680c58b33ea704be7cd090453e2d,
            0x35531cf6998245bf9177987a3ef9ab8f25ee05f85d65e089a5f12e661317a728,
            0x314d0ae1b511a53fe0be37f6974b2f10ea1d3db318a7217a94a5741896326704,
        ];
        let in_c2: Array<u256> = array![
            0x43f916c6e81fa5b4972a87ceff651ae5643162f0189ef8cec2cb58fd6cc6ff60,
            0xfeb41629a52607f684c760d365cc96adb3db2c3b77fc12af50789eedf5657d3c,
            0x1cd87aa6ce350a7aa116de40bd1c8a045e11ae0324e3bd4d5d1e791dc3b05ddc,
            0x5439eea526e7aeee4243dc4f9ab16e6a6331beb346b6af112267c6263cd034d6,
        ];
        let out_c1: Array<u256> = array![
            0xc9867585960a7f42455c2f94398dbfeb88ab8b9e1d3882bb23872992259c4b02,
            0x8c1cbdcce16306fc92ce9324f0f460966be7680c58b33ea704be7cd090453e2d,
            0x35531cf6998245bf9177987a3ef9ab8f25ee05f85d65e089a5f12e661317a728,
            0x314d0ae1b511a53fe0be37f6974b2f10ea1d3db318a7217a94a5741896326704,
        ];
        let out_c2: Array<u256> = array![
            0x3bd400c0ad840dc32c17c531eb56bdbd55ba70e45be10205269e238c8243bebc,
            0xb1c69fe7507026527fe8a93ffd7dc558978cc873e74fd1218f7ea8f5a5e04d97,
            0xf8067dfd2789badb95acf8b9c59e81ac8010a3bed5ab7484d841cf34aa6a3c97,
            0x4a56e997d55278a71694469fa59fca41da4ca6547426e5b09cd104ace4af1113,
        ];
        let a: Array<u256> = array![
            0x2659bc62f6634f44868ddec1c1e93ca539fa9f5583bce9df6f6cf4a9eee09d0e,
            0xcebcf50f9d443b5fa8f12ff62deee7d308f7ff17bca096da3e86ac77a0384cfe,
            0x1a0cfbe105daabd89922c800b07a651cd186cc9f458aeea516669070141c8155,
            0x312bd00a2ba76d026d911403b7de8d912a289e9f2d45da73531855407a226c16,
        ];
        let commitment_pk = (
            0xa5f2ca69ebbe70937787c6f49fd10d99b932c1b49b365c7b4e6279ab0739495a,
            0xde509a125fa14e8639d7f3d0d0c62ff6b9ae1eea9ee7f67eded2d56e6a79e48d,
        );
        let nonce = 0x418d554c42f90cba14a57a9afb3df827055808e08a2d12b8ea370dfa24d61649;
        let s = 0x9271b94d3ccac556f575501ac588a24a475c8c693e8d42bee780cc72669fc57c;
        assert!(
            verify_fold_leave(
                protocol_name.span(), pk, commitment_pk, nonce, s, 2,
                in_c1.span(), in_c2.span(), out_c1.span(), out_c2.span(), a.span(),
            ),
            "honest fold DLEQ verifies"
        );

        // Tampered output ciphertext breaks d2 → must not verify.
        let mut tampered: Array<u256> = array![];
        let mut t_idx: u32 = 0;
        while t_idx < 4 {
            if t_idx == 0 {
                tampered.append(0x1111);
            } else if t_idx == 1 {
                tampered.append(0x2222);
            } else {
                tampered.append(*out_c2.at(t_idx));
            }
            t_idx += 1;
        }
        assert!(
            !verify_fold_leave(
                protocol_name.span(), pk, commitment_pk, nonce, s, 2,
                in_c1.span(), in_c2.span(), out_c1.span(), tampered.span(), a.span(),
            ),
            "tampered out_c2 must not verify"
        );
    }


    #[test]
    fn unified_sigma_rust_vector_verifies_and_tamper_rejected() {
        // Generated by secp256k1_vectors::print_unified_sigma_vector
        // (n_fold=2, n_reveal=3, protocol b"poker_unified_sigma_v1").
        let protocol_name: Array<u8> = array![
            0x70, 0x6f, 0x6b, 0x65, 0x72, 0x5f, 0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f,
            0x73, 0x69, 0x67, 0x6d, 0x61, 0x5f, 0x76, 0x31
        ];
        let pk_x = 0xb088d62da5fd575a3255db4fcc211b5d900d8e8257ea55213e3edd5688dae34f;
        let pk_y = 0x92d054e7d6df0f0e35dc251354c7f565c92781112072944070e3ef4e4b726e1a;
        let fold: Array<u256> = array![

            0xe84a6ed0f2249c4a0e3005c6c88044da9f9e54144d784697696833a4e9fa00ce, 0x2696e7e2cae1e588813f114d85875224b5581f712a77a351bac27a08c6b3cc8c,  // F0_IN_C1
            0x19beb6b5e89ae1962ede4fa2677b05def6ff1e11cd102a2784fc41e54358f229, 0x7373dc7f1ef1d927f4c4423d6f306f6ba436def81ac8b5d2b5a1cf587d3cf0aa,  // F0_IN_C2
            0xe84a6ed0f2249c4a0e3005c6c88044da9f9e54144d784697696833a4e9fa00ce, 0x2696e7e2cae1e588813f114d85875224b5581f712a77a351bac27a08c6b3cc8c,  // F0_IN_C1
            0x3bd400c0ad840dc32c17c531eb56bdbd55ba70e45be10205269e238c8243bebc, 0xb1c69fe7507026527fe8a93ffd7dc558978cc873e74fd1218f7ea8f5a5e04d97,  // F0_OUT_C2
            0x028cd90094c93f4702697990b5c6106975482f445b9eca9f7778233f07f79379, 0x2e5387d40a7eace75f26dbe52f92bf175bf9f4f4d95166e0181a39524cd55494,  // F1_IN_C1
            0x5f693677ab95074eb9e64b55e6222817bf336085a3325eb8da711a2b1766909b, 0x7f3f4edd852bd85fb32c179d8eccfe6b10eaada3a61d888c60fd21e05449a50a,  // F1_IN_C2
            0x028cd90094c93f4702697990b5c6106975482f445b9eca9f7778233f07f79379, 0x2e5387d40a7eace75f26dbe52f92bf175bf9f4f4d95166e0181a39524cd55494,  // F1_IN_C1
            0xf8067dfd2789badb95acf8b9c59e81ac8010a3bed5ab7484d841cf34aa6a3c97, 0x4a56e997d55278a71694469fa59fca41da4ca6547426e5b09cd104ace4af1113,  // F1_OUT_C2
        ];
        let reveal: Array<u256> = array![
            0xd02becdf533c3f613da5f6b6f2d36b8b187a10f323b75f493b4cb740dbbc1406, 0xc42aad0f0d7b5cc8483a599fce8b9618615e9f437b47e930d36bb1bf816796f5,  // R0_C1
            0x747ccfe0067ad47d768ad98b0b73f648492f3cce383d4b2f8d03cf947d1b46a9, 0x633cdf0ee50a5e9225b4d2f61e60b40feb99568de3cf7326ca743b5f73992961,  // R0_C2
            0xa54bb9a025e686a069af11046471ec87c410ff729d67a273e85399d274beb7e3, 0x680c803a7a9b0cbfa72675ac697bd495200aa0b6b4e4330bad24ec37c81923fa,  // R0_TOKEN
            0x1979b321af66d8352243ebc75f213ed3929df7b1bbb8147bd1e8a12b991bbf74, 0x0d77d3c72cdab0080941c29c0069a2f6f32833d3c10bcd9c39c6a277488186bc,  // R1_C1
            0x1a93dccc2a03f5833cd13ac144a896725895df937f6cbed55e48f2fb89e0ae53, 0x30f407f0cc0d46d91f9b307e794a76cde47e6d51d5a1d84f1886344b1cd83ab9,  // R1_C2
            0x68ccf048d9c8abac4876b4e5b53adf5447783ab9d09cfe4a05704f17b79b95af, 0x1e0870b0c451f8feae114c5c5805597cc5c193786b7a49c9d1a8336ac1a9318c,  // R1_TOKEN
            0x3dba94991247db1ecc036584fd137a0114c2dc13f0da4e94b203bcb1b221c2e1, 0xfebd1df9c67672a7986b3d3f34cdc57786b5228be2e3e9fc668b34ba709fde94,  // R2_C1
            0x42faa9add0bf968b4748497d8f43c29182abafdc26ddea4cbc679f3fd4daa37b, 0xa061b1d5bf8aaa8848c268c86280c79014ffdc06d0030d0bb0047286836cf230,  // R2_C2
            0xb7403f88b97eb7423597f6e6fc17aa228792c10b149476f9e973faaba77b03ab, 0xc8516a00c40a272339f0666b6553190cc889f194e7ea314b9bec7901bb9e7880,  // R2_TOKEN
        ];
        let s_scalar = 0x8ec5cff25e091603f85c5f07861f33093aaf9af414e16c163eb17817b6773975;
        let commitments: Array<u256> = array![
            0x54a32ec558baa06269bdfae9e8e6fd6cdf2694be19440945031e150e36c66804, 0xcc7afd26f28f7f2cbbdc17c34306656ba240c5f47fd8c67ae077c2728eadd243,  // A0
            0x4ee70c788f36ccc9d431f03a2f43e20612eefa82d11ab082323b5ddec1d61900, 0xf85065932fc59c67ba77c1877fd46616d04426e7c61c812136a130ae9a0f0adc,  // A1
            0x7f6e6c49176446bb666e1163ea3932f49d3cb16fe44d0ec5060439ab4fe40bea, 0x29aeb93eabb7e2117ef8dec113fd2b88474e8fc805d3c2ef0749d74ed6a8b140,  // A2
            0xa0a8807b32d6a5aeb7747d8abb1f4ceb56a17f084d5e767a95f6eaa20a99cb53, 0x1b3a07d4d787d2652c74ac72223156bfbfb695019882243a3082478c08757760,  // A3
            0x7463cff684e12ac06f2d60844bab5536dce012d9e7357aac1c37d5debf244a96, 0x35c68a604904b25ca1e073391938677c2dc56ab9099893192625639bc7908bd2,  // A4
            0x1c010812a70e673f2f0dde56d0d46f47c3d9e3eeb383cf839cbe5a717e8c908a, 0xcf75745f8fae54afd43a27245d6a03f63730cd331956384341c1ba22eac6460f,  // A5
        ];
        assert!(
            verify_unified(
                protocol_name.span(),
                (pk_x, pk_y),
                2,
                3,
                fold.span(),
                reveal.span(),
                s_scalar,
                commitments.span(),
            ),
            "honest unified verifies"
        );

        // Forged response must fail.
        assert!(
            !verify_unified(
                protocol_name.span(),
                (pk_x, pk_y),
                2,
                3,
                fold.span(),
                reveal.span(),
                s_scalar - 1,
                commitments.span(),
            ),
            "forged s must not verify"
        );

        // Tampered fold output breaks d2 -> must fail.
        let mut tampered: Array<u256> = array![];
        let mut t_idx: u32 = 0;
        while t_idx < fold.len() {
            if t_idx == 7 {
                tampered.append(*fold.at(t_idx) + 1);
            } else {
                tampered.append(*fold.at(t_idx));
            }
            t_idx += 1;
        }
        assert!(
            !verify_unified(
                protocol_name.span(),
                (pk_x, pk_y),
                2,
                3,
                tampered.span(),
                reveal.span(),
                s_scalar,
                commitments.span(),
            ),
            "tampered fold must not verify"
        );

        // Wrong protocol name must fail.
        let other_name: Array<u8> = array![0x6f, 0x74, 0x68, 0x65, 0x72];
        assert!(
            !verify_unified(
                other_name.span(),
                (pk_x, pk_y),
                2,
                3,
                fold.span(),
                reveal.span(),
                s_scalar,
                commitments.span(),
            ),
            "wrong domain must not verify"
        );
    }

    #[test]
    fn unified_ownership_only_probe() {
        // Ownership-only unified vector (n_fold=0, n_reveal=0):
        // OA0 = A0 (same w), OS0 from the Rust generator.
        let protocol_name: Array<u8> = array![
            0x70, 0x6f, 0x6b, 0x65, 0x72, 0x5f, 0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f,
            0x73, 0x69, 0x67, 0x6d, 0x61, 0x5f, 0x76, 0x31
        ];
        let pk = (
            0xb088d62da5fd575a3255db4fcc211b5d900d8e8257ea55213e3edd5688dae34f,
            0x92d054e7d6df0f0e35dc251354c7f565c92781112072944070e3ef4e4b726e1a,
        );
        let a0 = (
            0x54a32ec558baa06269bdfae9e8e6fd6cdf2694be19440945031e150e36c66804,
            0xcc7afd26f28f7f2cbbdc17c34306656ba240c5f47fd8c67ae077c2728eadd243,
        );
        let s_scalar = 0x4c9da7e45043baf0397cdce127c71164681d225d2092d6ec0f6713ae4cf88ab0;
        let fold: Array<u256> = array![];
        let reveal: Array<u256> = array![];
        let (a0_x, a0_y) = a0;
        let commitments: Array<u256> = array![a0_x, a0_y];
        assert!(
            verify_unified(
                protocol_name.span(),
                pk,
                0,
                0,
                fold.span(),
                reveal.span(),
                s_scalar,
                commitments.span(),
            ),
            "ownership-only unified verifies"
        );
    }


    #[test]
    fn unified_fold1_only_probe() {
        // n_fold=1, n_reveal=0 vector from the Rust generator (B_* values).
        let protocol_name: Array<u8> = array![
            0x70, 0x6f, 0x6b, 0x65, 0x72, 0x5f, 0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f,
            0x73, 0x69, 0x67, 0x6d, 0x61, 0x5f, 0x76, 0x31
        ];
        let pk = (
            0xb088d62da5fd575a3255db4fcc211b5d900d8e8257ea55213e3edd5688dae34f,
            0x92d054e7d6df0f0e35dc251354c7f565c92781112072944070e3ef4e4b726e1a,
        );
        // Fold quad: [in_c1, in_c2, out_c1, out_c2]
        let fold: Array<u256> = array![
            0xe84a6ed0f2249c4a0e3005c6c88044da9f9e54144d784697696833a4e9fa00ce,
            0x2696e7e2cae1e588813f114d85875224b5581f712a77a351bac27a08c6b3cc8c,
            0x19beb6b5e89ae1962ede4fa2677b05def6ff1e11cd102a2784fc41e54358f229,
            0x7373dc7f1ef1d927f4c4423d6f306f6ba436def81ac8b5d2b5a1cf587d3cf0aa,
            0xe84a6ed0f2249c4a0e3005c6c88044da9f9e54144d784697696833a4e9fa00ce,
            0x2696e7e2cae1e588813f114d85875224b5581f712a77a351bac27a08c6b3cc8c,
            0x3bd400c0ad840dc32c17c531eb56bdbd55ba70e45be10205269e238c8243bebc,
            0xb1c69fe7507026527fe8a93ffd7dc558978cc873e74fd1218f7ea8f5a5e04d97,
        ];
        let reveal: Array<u256> = array![];
        let s_scalar = 0x5490612a330b5589d241cd741cea04bf392946e41e7e174fffd439decc5d7fd7;
        let commitments: Array<u256> = array![
            0x54a32ec558baa06269bdfae9e8e6fd6cdf2694be19440945031e150e36c66804,
            0xcc7afd26f28f7f2cbbdc17c34306656ba240c5f47fd8c67ae077c2728eadd243,
            0x4ee70c788f36ccc9d431f03a2f43e20612eefa82d11ab082323b5ddec1d61900,
            0xf85065932fc59c67ba77c1877fd46616d04426e7c61c812136a130ae9a0f0adc,
        ];
        assert!(
            verify_unified(
                protocol_name.span(), pk, 1, 0, fold.span(), reveal.span(), s_scalar,
                commitments.span(),
            ),
            "fold1-only unified verifies"
        );
    }

    #[test]
    fn unified_fold2_only_probe() {
        // n_fold=2, n_reveal=0 vector (C_* values; C_A0 == A0).
        let protocol_name: Array<u8> = array![
            0x70, 0x6f, 0x6b, 0x65, 0x72, 0x5f, 0x75, 0x6e, 0x69, 0x66, 0x69, 0x65, 0x64, 0x5f,
            0x73, 0x69, 0x67, 0x6d, 0x61, 0x5f, 0x76, 0x31
        ];
        let pk = (
            0xb088d62da5fd575a3255db4fcc211b5d900d8e8257ea55213e3edd5688dae34f,
            0x92d054e7d6df0f0e35dc251354c7f565c92781112072944070e3ef4e4b726e1a,
        );
        let fold: Array<u256> = array![
            0xe84a6ed0f2249c4a0e3005c6c88044da9f9e54144d784697696833a4e9fa00ce,
            0x2696e7e2cae1e588813f114d85875224b5581f712a77a351bac27a08c6b3cc8c,
            0x19beb6b5e89ae1962ede4fa2677b05def6ff1e11cd102a2784fc41e54358f229,
            0x7373dc7f1ef1d927f4c4423d6f306f6ba436def81ac8b5d2b5a1cf587d3cf0aa,
            0xe84a6ed0f2249c4a0e3005c6c88044da9f9e54144d784697696833a4e9fa00ce,
            0x2696e7e2cae1e588813f114d85875224b5581f712a77a351bac27a08c6b3cc8c,
            0x3bd400c0ad840dc32c17c531eb56bdbd55ba70e45be10205269e238c8243bebc,
            0xb1c69fe7507026527fe8a93ffd7dc558978cc873e74fd1218f7ea8f5a5e04d97,
            0x028cd90094c93f4702697990b5c6106975482f445b9eca9f7778233f07f79379,
            0x2e5387d40a7eace75f26dbe52f92bf175bf9f4f4d95166e0181a39524cd55494,
            0x5f693677ab95074eb9e64b55e6222817bf336085a3325eb8da711a2b1766909b,
            0x7f3f4edd852bd85fb32c179d8eccfe6b10eaada3a61d888c60fd21e05449a50a,
            0x028cd90094c93f4702697990b5c6106975482f445b9eca9f7778233f07f79379,
            0x2e5387d40a7eace75f26dbe52f92bf175bf9f4f4d95166e0181a39524cd55494,
            0xf8067dfd2789badb95acf8b9c59e81ac8010a3bed5ab7484d841cf34aa6a3c97,
            0x4a56e997d55278a71694469fa59fca41da4ca6547426e5b09cd104ace4af1113,
        ];
        let reveal: Array<u256> = array![];
        let s_scalar = 0x4a70bb717535164b899525d42b412d0b5c0c9f2cca046ae8cc9605d45f660dc4;
        let commitments: Array<u256> = array![
            0x54a32ec558baa06269bdfae9e8e6fd6cdf2694be19440945031e150e36c66804,
            0xcc7afd26f28f7f2cbbdc17c34306656ba240c5f47fd8c67ae077c2728eadd243,
            0x4ee70c788f36ccc9d431f03a2f43e20612eefa82d11ab082323b5ddec1d61900,
            0xf85065932fc59c67ba77c1877fd46616d04426e7c61c812136a130ae9a0f0adc,
            0x7f6e6c49176446bb666e1163ea3932f49d3cb16fe44d0ec5060439ab4fe40bea,
            0x29aeb93eabb7e2117ef8dec113fd2b88474e8fc805d3c2ef0749d74ed6a8b140,
        ];
        assert!(
            verify_unified(
                protocol_name.span(), pk, 2, 0, fold.span(), reveal.span(), s_scalar,
                commitments.span(),
            ),
            "fold2-only unified verifies"
        );
    }

    #[test]
    fn unknown_proof_kind_fails_closed() {

        let payload = array![];
        let name: Array<u8> = array![
            0x70, 0x6f, 0x6b, 0x65, 0x72, 0x5f, 0x73, 0x65, 0x63, 0x70, 0x32, 0x35, 0x36, 0x6b,
            0x31, 0x5f, 0x6b, 0x65, 0x63, 0x63, 0x61, 0x6b, 0x5f, 0x76, 0x31
        ];
        assert!(!verify_p_proof(PROOF_KIND_SHUFFLE_BG, name.span(), payload.span()), "bg fail-closed");
        assert!(!verify_p_proof(PROOF_KIND_FOLD_LEAVE, name.span(), payload.span()), "fold fail-closed");
        assert!(!verify_p_proof(99, name.span(), payload.span()), "unknown fail-closed");
    }
}
