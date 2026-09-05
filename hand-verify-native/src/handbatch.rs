//! hand_verify, host side — payload parsing, Poseidon felt-native challenges,
//! EC residual checks and the Horner fold, all natively on the STARK curve.
//!
//! This is the "Stark-curve sigma" layer of the spike: everything here runs
//! on the host, *outside* any STARK. The [`crate::air`] layer attests the
//! statement table and binds this layer's digests (form-① architecture — see
//! README).
//!
//! Transcript formulas mirror `poker-protocol-core::stark_curve` (Plan D
//! felt-native gas-compressed epoch) so the spike stays protocol-shaped:
//! - endorsement: `c = poseidon([proto_label, hand_binding, Gx, Gy, pkx, pky, Rx, Ry])`
//! - reveal:      `c = poseidon([reveal_label, hand_binding, pk, c1, c2, token,
//!                  t1, t2, nonce])` (affine coordinates as individual felts)
//! - leave:       `c = poseidon([leave_label, hand_binding, pk, cpk, nonce, n,
//!                  (in_c1, in_c2, out_c1, out_c2, a, d2)*])`, `d2 = in_c2 − out_c2`
//! - recon:       `c = poseidon([recon_label, hand_binding, g1, g2, p1, p2, a, b])`
//! - rho:         `rho = poseidon([v1_label, hand_binding, n_eq, (kind, s, c)*])`
//! - equations:   ownership `s·G − c·pk − R`; reveal pair
//!                  `s·G − t1 − c·pk` / `s·c1 − t2 − c·token`;
//!                  leave `s·G − cpk − c·pk` + per-card `s·in_c1 − a − c·d2`;
//!                  recon pair `s·G1 − A − c·P1` / `s·G2 − B − c·P2`
//! - fold:        `L = ρ·(ρ·(…(ρ·eq_N + eq_{N−1})…) + eq_1)` (Horner, one
//!                  entry per EC equation)
//!
//! Spike scope (fail-closed): ownership, reveal, leave and reconstruct are
//! implemented. Shuffle (Bayer–Groth) remains fail-closed rejected — it is a
//! separate argument system (see the `poker-protocol-bg` port in the main
//! project) and explicitly out of this spike's scope.

use starknet_crypto::poseidon_hash_many;
use starknet_crypto::FieldElement as Felt;

use crate::curve::Point;

pub const PROTO_LABEL: &str = "poker/hand-batch/proto";
pub const REVEAL_LABEL: &str = "poker/reveal-token/fold-v1";
pub const LEAVE_LABEL: &str = "poker/leave-fold/v1";
pub const RECON_LABEL: &str = "poker/reconstruct-fold/v1";
pub const V1_LABEL: &str = "poker/hand-batch/v1";

/// Statement kind tags for the ρ transcript — matches the foldable epoch's
/// numbering (`hand_verify.cairo` pins recon as kind 4).
pub const KIND_OWNERSHIP: u64 = 1;
pub const KIND_REVEAL: u64 = 2;
pub const KIND_LEAVE: u64 = 3;
pub const KIND_RECONSTRUCT: u64 = 4;

/// Words per statement section, matching `hand_verify.cairo`'s wire format.
pub const WORDS_PER_OWNERSHIP: usize = 5; // pk 2, R 2, s
pub const WORDS_PER_REVEAL: usize = 14; // pk 2, c1 2, c2 2, token 2, t1 2, t2 2, nonce, s
/// Leave: `[n, pk 2, cpk 2, nonce, s, in_c1 2n, in_c2 2n, out_c1 2n,
/// out_c2 2n, a 2n]`.
pub const WORDS_PER_LEAVE_HEADER: usize = 7;
pub const WORDS_PER_LEAVE_CARD: usize = 2; // per-word-pair section; 5 sections × 2n
/// Recon: `[g1 2, g2 2, p1 2, p2 2, A 2, B 2, s]`.
pub const WORDS_PER_RECONSTRUCT: usize = 13;

/// ASCII label → single felt (big-endian, ≤31 bytes) — same encoding as the
/// protocol's `ascii_felt`.
fn ascii_felt(s: &str) -> Felt {
    let bytes = s.as_bytes();
    assert!(bytes.len() <= 31, "label must fit one felt");
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(bytes);
    Felt::from_bytes_be(&buf).expect("padded label < P")
}

/// One parsed EC equation entering the fold.
#[derive(Clone, Copy, Debug)]
pub struct FoldEquation {
    pub kind: u64,
    pub s: Felt,
    pub c: Felt,
    pub residual: Point,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// Payload shorter than the declared structure.
    Truncated,
    /// Spike scope: shuffle (Bayer–Groth) is fail-closed rejected.
    UnsupportedSection(&'static str),
    /// A section count does not fit u32 (mirrors the Cairo try_into).
    CountOverflow,
    /// A coordinate word is not a point on the STARK curve (mirrors Cairo
    /// `EcPoint::new` returning `None`).
    OffCurve(&'static str),
}

/// Structured result of a full hand verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyReport {
    pub n_own: u32,
    pub n_reveal: u32,
    pub n_leave: u32,
    pub n_recon: u32,
    /// Number of EC equations folded (= n_own + 2·n_reveal
    /// + Σ(1 + cards) over leave + 2·n_recon).
    pub n_eq: u32,
    /// Every individual residual is the group identity.
    pub all_residuals_identity: bool,
    /// The Horner-folded combination is the group identity (implied by
    /// `all_residuals_identity`, checked for structural parity with the
    /// contract epoch).
    pub fold_identity: bool,
}

impl VerifyReport {
    pub fn accepted(&self) -> bool {
        self.all_residuals_identity && self.fold_identity
    }
}

fn felt_to_u32(f: Felt) -> Result<u32, VerifyError> {
    let bytes = f.to_bytes_be();
    if bytes[..28].iter().any(|&b| b != 0) {
        return Err(VerifyError::CountOverflow);
    }
    Ok(u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]))
}

fn point_word(x: Felt, y: Felt, what: &'static str) -> Result<Point, VerifyError> {
    Point::from_affine(x, y).ok_or(VerifyError::OffCurve(what))
}

/// One parsed leave card: the five point pairs the equation and transcript
/// read. `d2` is recomputed at verification time as `in_c2 − out_c2`.
#[derive(Clone, Copy, Debug)]
pub struct LeaveCard {
    pub in_c1: Point,
    pub in_c2: Point,
    pub out_c1: Point,
    pub out_c2: Point,
    pub a: Point,
}

/// Payload statement order matches `hand_verify.cairo`:
/// header `[n_own, n_shuffle, n_reveal, n_leave, n_recon]`, then ownership
/// block, (shuffle block — fail-closed), reveal, leave, recon blocks.
pub fn verify_hand(hand_binding: Felt, payload: &[Felt]) -> Result<VerifyReport, VerifyError> {
    if payload.len() < 5 {
        return Err(VerifyError::Truncated);
    }
    let n_own = felt_to_u32(*payload.get(0).expect("header checked"))?;
    let n_shuffle = felt_to_u32(*payload.get(1).expect("header checked"))?;
    let n_reveal = felt_to_u32(*payload.get(2).expect("header checked"))?;
    let n_leave = felt_to_u32(*payload.get(3).expect("header checked"))?;
    let n_recon = felt_to_u32(*payload.get(4).expect("header checked"))?;
    if n_shuffle > 0 {
        return Err(VerifyError::UnsupportedSection("shuffle"));
    }
    let (n_own, n_reveal, n_leave, n_recon) =
        (n_own as usize, n_reveal as usize, n_leave as usize, n_recon as usize);

    // Leave blocks are variable-length: walk the layout to compute the
    // expected total before touching statement words.
    let mut cursor = 5;
    let mut leave_card_counts = Vec::with_capacity(n_leave);
    for _ in 0..n_own {
        cursor += WORDS_PER_OWNERSHIP;
    }
    for _ in 0..n_reveal {
        cursor += WORDS_PER_REVEAL;
    }
    for _ in 0..n_leave {
        let n_cards = felt_to_u32(
            *payload
                .get(cursor)
                .ok_or(VerifyError::Truncated)?,
        )? as usize;
        leave_card_counts.push(n_cards);
        cursor += WORDS_PER_LEAVE_HEADER + 5 * WORDS_PER_LEAVE_CARD * n_cards;
    }
    for _ in 0..n_recon {
        cursor += WORDS_PER_RECONSTRUCT;
    }
    if cursor != payload.len() {
        return Err(VerifyError::Truncated);
    }

    let g = Point::generator();

    let mut equations: Vec<FoldEquation> = Vec::new();
    let mut all_identity = true;
    let mut cursor = 5;

    // ---- ownership: eq = s·G − c·pk − R ----
    for _ in 0..n_own {
        let pk = point_word(payload[cursor], payload[cursor + 1], "pk")?;
        let r = point_word(payload[cursor + 2], payload[cursor + 3], "R")?;
        let s = payload[cursor + 4];
        let c = endorsement_challenge(hand_binding, g, pk, r);
        let residual = g.mul(s) - pk.mul(c) - r;
        all_identity &= residual.is_identity();
        equations.push(FoldEquation { kind: KIND_OWNERSHIP, s, c, residual });
        cursor += WORDS_PER_OWNERSHIP;
    }

    // ---- reveal: eq1 = s·G − t1 − c·pk; eq2 = s·c1 − t2 − c·token ----
    for _ in 0..n_reveal {
        let pk = point_word(payload[cursor], payload[cursor + 1], "pk")?;
        let c1 = point_word(payload[cursor + 2], payload[cursor + 3], "c1")?;
        let c2 = point_word(payload[cursor + 4], payload[cursor + 5], "c2")?;
        let token = point_word(payload[cursor + 6], payload[cursor + 7], "token")?;
        let t1 = point_word(payload[cursor + 8], payload[cursor + 9], "t1")?;
        let t2 = point_word(payload[cursor + 10], payload[cursor + 11], "t2")?;
        let nonce = payload[cursor + 12];
        let s = payload[cursor + 13];
        let c = reveal_challenge(hand_binding, pk, c1, c2, token, t1, t2, nonce);
        let eq1 = g.mul(s) - t1 - pk.mul(c);
        let eq2 = c1.mul(s) - t2 - token.mul(c);
        all_identity &= eq1.is_identity() && eq2.is_identity();
        equations.push(FoldEquation { kind: KIND_REVEAL, s, c, residual: eq1 });
        equations.push(FoldEquation { kind: KIND_REVEAL, s, c, residual: eq2 });
        cursor += WORDS_PER_REVEAL;
    }

    // ---- leave: eq0 = s·G − cpk − c·pk; per card eq_i = s·in_c1 − a − c·d2 ----
    for &n_cards in &leave_card_counts {
        let pk = point_word(payload[cursor + 1], payload[cursor + 2], "pk")?;
        let cpk = point_word(payload[cursor + 3], payload[cursor + 4], "cpk")?;
        let nonce = payload[cursor + 5];
        let s = payload[cursor + 6];
        let base = cursor + WORDS_PER_LEAVE_HEADER;
        let mut cards = Vec::with_capacity(n_cards);
        for i in 0..n_cards {
            let at = |section: usize, coord: usize| payload[base + section * 2 * n_cards + 2 * i + coord];
            let in_c1 = point_word(at(0, 0), at(0, 1), "in_c1")?;
            let in_c2 = point_word(at(1, 0), at(1, 1), "in_c2")?;
            let out_c1 = point_word(at(2, 0), at(2, 1), "out_c1")?;
            let out_c2 = point_word(at(3, 0), at(3, 1), "out_c2")?;
            let a = point_word(at(4, 0), at(4, 1), "a")?;
            cards.push(LeaveCard { in_c1, in_c2, out_c1, out_c2, a });
        }
        let c = leave_challenge(hand_binding, pk, cpk, nonce, &cards);
        // eq0
        let eq0 = g.mul(s) - cpk - pk.mul(c);
        all_identity &= eq0.is_identity();
        equations.push(FoldEquation { kind: KIND_LEAVE, s, c, residual: eq0 });
        // per-card equations; d2 = in_c2 − out_c2 (recomputed, may be identity)
        for card in &cards {
            let d2 = card.in_c2 - card.out_c2;
            let eq_i = card.in_c1.mul(s) - card.a - d2.mul(c);
            all_identity &= eq_i.is_identity();
            equations.push(FoldEquation { kind: KIND_LEAVE, s, c, residual: eq_i });
        }
        cursor += WORDS_PER_LEAVE_HEADER + 5 * WORDS_PER_LEAVE_CARD * n_cards;
    }

    // ---- recon (CP-DLEQ): eq1 = s·G1 − A − c·P1; eq2 = s·G2 − B − c·P2 ----
    for _ in 0..n_recon {
        let g1 = point_word(payload[cursor], payload[cursor + 1], "g1")?;
        let g2 = point_word(payload[cursor + 2], payload[cursor + 3], "g2")?;
        let p1 = point_word(payload[cursor + 4], payload[cursor + 5], "p1")?;
        let p2 = point_word(payload[cursor + 6], payload[cursor + 7], "p2")?;
        let a = point_word(payload[cursor + 8], payload[cursor + 9], "a")?;
        let b = point_word(payload[cursor + 10], payload[cursor + 11], "b")?;
        let s = payload[cursor + 12];
        let c = reconstruct_challenge(hand_binding, g1, g2, p1, p2, a, b);
        let eq1 = g1.mul(s) - a - p1.mul(c);
        let eq2 = g2.mul(s) - b - p2.mul(c);
        all_identity &= eq1.is_identity() && eq2.is_identity();
        equations.push(FoldEquation { kind: KIND_RECONSTRUCT, s, c, residual: eq1 });
        equations.push(FoldEquation { kind: KIND_RECONSTRUCT, s, c, residual: eq2 });
        cursor += WORDS_PER_RECONSTRUCT;
    }

    // ---- Horner fold: L = ρ·(ρ·(…(ρ·eq_N + eq_{N−1})…) + eq_1) ----
    let rho = hand_rho(hand_binding, &equations);
    let mut acc = equations
        .last()
        .map(|e| e.residual)
        .ok_or(VerifyError::Truncated)?;
    for eq in equations[..equations.len() - 1].iter().rev() {
        acc = acc.mul(rho) + eq.residual;
    }

    Ok(VerifyReport {
        n_own: n_own as u32,
        n_reveal: n_reveal as u32,
        n_leave: n_leave as u32,
        n_recon: n_recon as u32,
        n_eq: equations.len() as u32,
        all_residuals_identity: all_identity,
        fold_identity: acc.is_identity(),
    })
}

/// `c = poseidon([proto_label, hb, Gx, Gy, pkx, pky, Rx, Ry])` — raw felt
/// (used directly as an EC scalar; group order makes the reduction a no-op).
pub fn endorsement_challenge(hb: Felt, g: Point, pk: Point, r: Point) -> Felt {
    let (gx, gy) = g.to_affine().expect("non-identity G");
    let (pkx, pky) = pk.to_affine().expect("non-identity pk");
    let (rx, ry) = r.to_affine().expect("non-identity R");
    poseidon_hash_many(&[
        ascii_felt(PROTO_LABEL), hb, gx, gy, pkx, pky, rx, ry,
    ])
}

/// `c = poseidon([reveal_label, hb, pk, c1, c2, token, t1, t2, nonce])`.
#[allow(clippy::too_many_arguments)]
pub fn reveal_challenge(
    hb: Felt,
    pk: Point,
    c1: Point,
    c2: Point,
    token: Point,
    t1: Point,
    t2: Point,
    nonce: Felt,
) -> Felt {
    let (pkx, pky) = pk.to_affine().expect("non-identity pk");
    let (c1x, c1y) = c1.to_affine().expect("non-identity c1");
    let (c2x, c2y) = c2.to_affine().expect("non-identity c2");
    let (tokx, toky) = token.to_affine().expect("non-identity token");
    let (t1x, t1y) = t1.to_affine().expect("non-identity t1");
    let (t2x, t2y) = t2.to_affine().expect("non-identity t2");
    poseidon_hash_many(&[
        ascii_felt(REVEAL_LABEL), hb, pkx, pky, c1x, c1y, c2x, c2y,
        tokx, toky, t1x, t1y, t2x, t2y, nonce,
    ])
}

/// Point into its two transcript felts; the identity encodes as (0, 0)
/// (same convention as the protocol's leave transcript).
fn point_felts(p: Point) -> (Felt, Felt) {
    p.to_affine().unwrap_or((Felt::ZERO, Felt::ZERO))
}

/// `c = poseidon([leave_label, hb, pk, cpk, nonce, n, (in_c1, in_c2, out_c1,
/// out_c2, a, d2)*])` with `d2 = in_c2 − out_c2` recomputed.
pub fn leave_challenge(hb: Felt, pk: Point, cpk: Point, nonce: Felt, cards: &[LeaveCard]) -> Felt {
    let (pkx, pky) = pk.to_affine().expect("non-identity pk");
    let (cpkx, cpky) = cpk.to_affine().expect("non-identity cpk");
    let mut felts = Vec::with_capacity(8 + 12 * cards.len());
    felts.push(ascii_felt(LEAVE_LABEL));
    felts.push(hb);
    felts.push(pkx);
    felts.push(pky);
    felts.push(cpkx);
    felts.push(cpky);
    felts.push(nonce);
    felts.push(Felt::from(cards.len() as u64));
    for card in cards {
        let d2 = card.in_c2 - card.out_c2;
        for p in [card.in_c1, card.in_c2, card.out_c1, card.out_c2, card.a, d2] {
            let (x, y) = point_felts(p);
            felts.push(x);
            felts.push(y);
        }
    }
    poseidon_hash_many(&felts)
}

/// `c = poseidon([recon_label, hb, g1, g2, p1, p2, a, b])`.
#[allow(clippy::too_many_arguments)]
pub fn reconstruct_challenge(hb: Felt, g1: Point, g2: Point, p1: Point, p2: Point, a: Point, b: Point) -> Felt {
    let (g1x, g1y) = g1.to_affine().expect("non-identity g1");
    let (g2x, g2y) = g2.to_affine().expect("non-identity g2");
    let (p1x, p1y) = p1.to_affine().expect("non-identity p1");
    let (p2x, p2y) = p2.to_affine().expect("non-identity p2");
    let (ax, ay) = a.to_affine().expect("non-identity a");
    let (bx, by) = b.to_affine().expect("non-identity b");
    poseidon_hash_many(&[
        ascii_felt(RECON_LABEL), hb, g1x, g1y, g2x, g2y, p1x, p1y, p2x, p2y, ax, ay, bx, by,
    ])
}

/// `rho = poseidon([v1_label, hb, n_eq, (kind, s, c)*])` — one transcript
/// entry per EC equation (multi-equation statements repeat their (kind, s, c)).
pub fn hand_rho(hb: Felt, equations: &[FoldEquation]) -> Felt {
    let mut felts = Vec::with_capacity(3 + 3 * equations.len());
    felts.push(ascii_felt(V1_LABEL));
    felts.push(hb);
    felts.push(Felt::from(equations.len() as u64));
    for eq in equations {
        felts.push(Felt::from(eq.kind));
        felts.push(eq.s);
        felts.push(eq.c);
    }
    poseidon_hash_many(&felts)
}

/// Commitment over the full payload (header + statement words), bound into
/// the STARK claim. `poseidon_hash_many` over `payload.len()` + all words.
pub fn payload_digest(payload: &[Felt]) -> Felt {
    let mut felts = Vec::with_capacity(payload.len() + 1);
    felts.push(Felt::from(payload.len() as u64));
    felts.extend_from_slice(payload);
    poseidon_hash_many(&felts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::mint_hand;

    #[test]
    fn honest_two_player_hand_accepts() {
        let hb = Felt::from(0xabcdefu64);
        let payload = mint_hand(hb, 2, 18, 1, 1, 1);
        let report = verify_hand(hb, &payload).expect("parse");
        assert!(report.accepted());
        assert_eq!(report.n_own, 2);
        assert_eq!(report.n_reveal, 18);
        assert_eq!(report.n_leave, 1);
        assert_eq!(report.n_recon, 1);
        // 2 own + 36 reveal + (1 + 2 cards) leave + 2 recon
        assert_eq!(report.n_eq, 2 + 36 + 3 + 2);
    }

    #[test]
    fn tampered_s_rejects() {
        let hb = Felt::from(0xabcdefu64);
        let mut payload = mint_hand(hb, 2, 4, 0, 0, 2);
        // bump the first ownership response word (header 5 + word 4)
        payload[5 + 4] = payload[5 + 4] + Felt::from(1u32);
        let report = verify_hand(hb, &payload).unwrap();
        assert!(!report.accepted());
        assert!(!report.all_residuals_identity);
    }

    #[test]
    fn tampered_leave_card_rejects() {
        let hb = Felt::from(0xabcdefu64);
        // layout: 5 header + own + reveal; first leave word block follows
        let mut payload = mint_hand(hb, 1, 2, 1, 1, 3);
        let leave_at = 5 + 1 * WORDS_PER_OWNERSHIP + 2 * WORDS_PER_REVEAL;
        // bump the first card's `a` x-coordinate: header 7 + four 2n-word
        // sections (in_c1, in_c2, out_c1, out_c2) precede `a`
        let a_x = leave_at + WORDS_PER_LEAVE_HEADER + 8 * 2;
        payload[a_x] = payload[a_x] + Felt::from(1u32);
        // Both outcomes reject: a bumped coordinate is either off-curve
        // (parse error) or on-curve but violating the equation.
        match verify_hand(hb, &payload) {
            Err(_) => {}
            Ok(report) => assert!(!report.accepted()),
        }
    }

    #[test]
    fn tampered_recon_rejects() {
        let hb = Felt::from(0xabcdefu64);
        let mut payload = mint_hand(hb, 1, 1, 0, 1, 4);
        // last word of the payload is the recon response s
        let last = payload.len() - 1;
        payload[last] = payload[last] + Felt::from(1u32);
        let report = verify_hand(hb, &payload).unwrap();
        assert!(!report.accepted());
    }

    #[test]
    fn cross_hand_replay_rejects() {
        let hb = Felt::from(0xabcdefu64);
        let payload = mint_hand(hb, 2, 4, 0, 0, 3);
        // same payload verified under a different hand binding must fail
        let report = verify_hand(hb + Felt::from(1u32), &payload).unwrap();
        assert!(!report.accepted());
    }

    #[test]
    fn truncated_payload_rejects() {
        let hb = Felt::from(0xabcdefu64);
        let payload = mint_hand(hb, 2, 4, 0, 0, 4);
        assert_eq!(verify_hand(hb, &payload[..8]), Err(VerifyError::Truncated));
    }

    #[test]
    fn shuffle_section_fail_closed() {
        let hb = Felt::from(0xabcdefu64);
        let mut payload = mint_hand(hb, 1, 2, 0, 0, 5);
        payload[1] = Felt::from(1u32); // n_shuffle = 1
        assert_eq!(
            verify_hand(hb, &payload),
            Err(VerifyError::UnsupportedSection("shuffle"))
        );
    }

    #[test]
    fn off_curve_pk_rejects() {
        let hb = Felt::from(0xabcdefu64);
        let mut payload = mint_hand(hb, 1, 0, 0, 0, 6);
        payload[5] = payload[5] + Felt::from(1u32); // pk_x + 1 → off curve
        assert!(matches!(verify_hand(hb, &payload), Err(VerifyError::OffCurve("pk"))));
    }
}
