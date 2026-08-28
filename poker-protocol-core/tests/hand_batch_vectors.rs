//! Generator for the Cairo-side hand-level batch verifier vectors
//! (poker_contracts/src/dual/hand_batch.cairo tests). Run with:
//! `cargo test -p poker-protocol-core --test hand_batch_vectors -- --nocapture --ignored`
//!
//! The hand is folded exactly like the Cairo verifier: every proof's
//! residual equations (same Keccak challenge replays as the individual
//! verifiers) are collected in canonical order, then
//!   rho = LE(keccak256(b"poker/hand-batch/v1" ‖ hand_id ‖
//!                       (scalar_wire ‖ point_wire) per term)) mod n,
//!   L   = Σ_eq rho^eq · Σ_term coeff·point,
//! and the honest hand must fold to L == identity. Scalar and point wire
//! encodings follow the existing secp256k1 vector conventions verbatim
//! (`as_bytes()` for scalars, SEC1 uncompressed BE for points).

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, Scalar};
use poker_protocol_core::{
    CryptoTranscript, Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, Secp256k1Curve,
};
use poker_protocol_proofs::dleq_proof::{DLEqProof, DLEqProofKind, LeaveKind};
use poker_protocol_proofs::pk_ownership::PKOwnershipProof;
use poker_protocol_proofs::reveal_token_proof::RevealTokenProof;
use poker_protocol_proofs::transcript_ext::KeccakTranscript;

type Pt = <Secp256k1Curve as Curve>::Point;
type Sc = <Secp256k1Curve as Curve>::Scalar;

const PROTOCOL_NAME: &[u8] = b"poker_hand_batch_test_v1";
const HAND_PROTO_DOMAIN: &[u8] = b"poker/hand-batch/proto";

fn hand_transcript_domain(hand_id: &[u8; 32]) -> Vec<u8> {
    use sha3::Digest;
    let mut h = sha3::Keccak256::new();
    h.update(HAND_PROTO_DOMAIN);
    h.update(hand_id);
    h.finalize().to_vec()
}
const RHO_DOMAIN: &[u8] = b"poker/hand-batch/v1";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex digit"))
        .collect()
}

/// Scalar literal convention: identical to the existing secp256k1 generator
/// (`to_repr` bytes printed as hex, no reversal).
fn scalar_hex(s: &Sc) -> String {
    to_hex(&s.as_bytes())
}

/// Byte sequence the Cairo verifier reconstructs from a scalar literal via
/// `u256_to_be_bytes`: `as_bytes()` is already big-endian (probe-verified),
/// so the literal hex and the wire bytes coincide.
fn scalar_wire_bytes(s: &Sc) -> Vec<u8> {
    s.as_bytes()
}

/// Point literal convention: SEC1 uncompressed x/y, big-endian.
fn point_affine(p: &Pt) -> AffinePoint {
    use k256::elliptic_curve::Group as _;
    p.to_affine()
}

fn point_hex(p: &Pt) -> (String, String) {
    let encoded = point_affine(p).to_encoded_point(false);
    (
        to_hex(encoded.x().expect("non-identity")),
        to_hex(encoded.y().expect("non-identity")),
    )
}

fn point_wire_bytes(p: &Pt) -> Vec<u8> {
    let (x, y) = point_hex(p);
    let mut out = hex_to_bytes(&x);
    out.extend(hex_to_bytes(&y));
    out
}

fn hs(label: &[u8]) -> Sc {
    <Secp256k1Curve as Curve>::hash_to_scalar(label)
}

fn neg(s: &Sc) -> Sc {
    Sc::zero() - *s
}

#[test]
fn scalar_repr_endianness_probe() {
    // Documents the literal convention the vectors rely on: `as_bytes()`
    // printed as hex IS the u256 literal, whatever its internal order.
    let one = Sc::from_u64(1);
    let b = one.as_bytes();
    println!(
        "as_bytes of 1: first=0x{:02x} last=0x{:02x}",
        b[0], b[b.len() - 1]
    );
}

#[test]
#[ignore]
fn print_hand_batch_cairo_vectors() {
    let g = Secp256k1Curve::base_g();
    let one = Sc::one();

    // ---------- hand construction ----------
    let mut ownership = Vec::new();
    for label in [b"hb_own_a".as_slice(), b"hb_own_b".as_slice()] {
        let sk = hs(label);
        let pk = g * sk;
        let proof = PKOwnershipProof::<Secp256k1Curve>::prove(&sk, &pk, &mut rand_core::OsRng);
        ownership.push((pk, proof));
    }

    let hand_id: [u8; 32] = {
        use sha3::Digest;
        let mut h = sha3::Keccak256::new();
        h.update(b"hb_cairo_hand_id");
        h.finalize().into()
    };
    // Transcript domain derived from the hand instance, mirroring
    // hand_batch.cairo::hand_transcript_domain (replay binding).
    let hand_proto = hand_transcript_domain(&hand_id);

    let sk_r = hs(b"hb_reveal_sk");
    let pk_r = g * sk_r;
    let card = Secp256k1Curve::hash_to_curve(b"texas_poker_secp256k1/card/11");
    let r_enc = hs(b"hb_reveal_r");
    let c1 = g * r_enc;
    let c2 = card + pk_r * r_enc;
    let token = c1 * sk_r;
    let ct = ElGamalCiphertextGeneric::<Secp256k1Curve> { c1, c2 };
    let reveal = RevealTokenProof::<Secp256k1Curve>::prove(
        &sk_r,
        &pk_r,
        &ct,
        &token,
        &mut rand_core::OsRng,
        &mut KeccakTranscript::new(&hand_proto),
    );

    let sk_f = hs(b"hb_fold_sk");
    let pk_f = g * sk_f;
    let n_fold_cards = 2usize;
    let mut fold_input = Vec::new();
    let mut fold_output = Vec::new();
    for i in 0..n_fold_cards {
        let card_i =
            Secp256k1Curve::hash_to_curve(format!("texas_poker_secp256k1/card/{i}").as_bytes());
        let r_i = hs(format!("hb_fold_r_{i}").as_bytes());
        let c1i = g * r_i;
        let c2i = card_i + pk_f * r_i;
        let input = ElGamalCiphertextGeneric::<Secp256k1Curve> { c1: c1i, c2: c2i };
        let output = ElGamalCiphertextGeneric::<Secp256k1Curve> {
            c1: c1i,
            c2: c2i - c1i * sk_f,
        };
        fold_input.push(input);
        fold_output.push(output);
    }
    let fold = DLEqProof::<Secp256k1Curve, LeaveKind>::prove(
        &fold_input,
        &fold_output,
        &sk_f,
        &pk_f,
        &mut KeccakTranscript::new(&hand_proto),
    );

    // Per-proof parity.
    for (pk, proof) in &ownership {
        assert!(proof.verify(pk), "ownership parity");
    }
    assert!(
        reveal
            .verify(&ct, &token, &pk_r, &mut KeccakTranscript::new(&hand_proto))
            .is_ok(),
        "reveal parity"
    );
    assert!(
        fold.verify(
            &fold_input,
            &fold_output,
            &pk_f,
            &mut KeccakTranscript::new(&hand_proto)
        ),
        "fold parity"
    );

    // ---------- residual terms in canonical order ----------
    struct Term {
        coeff: Sc,
        point: Pt,
    }
    let mut terms: Vec<Term> = Vec::new();
    let mut eq_sizes: Vec<usize> = Vec::new();

    for (pk, proof) in &ownership {
        let mut input = Vec::new();
        input.extend_from_slice(g.compress().as_ref());
        input.extend_from_slice(pk.compress().as_ref());
        input.extend_from_slice(proof.commitment.compress().as_ref());
        let c = <Secp256k1Curve as Curve>::hash_to_scalar(&input);
        terms.push(Term { coeff: proof.response, point: g });
        terms.push(Term { coeff: neg(&c), point: *pk });
        terms.push(Term { coeff: neg(&one), point: proof.commitment });
        eq_sizes.push(3);
    }

    let c_reveal = {
        let mut t = KeccakTranscript::new(&hand_proto);
        t.append_scalar::<Secp256k1Curve>(b"reveal_token_nonce", &reveal.nonce);
        t.append_point::<Secp256k1Curve>(b"pk", &reveal.user_public_key);
        t.append_point::<Secp256k1Curve>(b"c1", &ct.c1);
        t.append_point::<Secp256k1Curve>(b"c2", &ct.c2);
        t.append_point::<Secp256k1Curve>(b"reveal_token", &token);
        t.append_point::<Secp256k1Curve>(b"t1", &reveal.commitment_t1);
        t.append_point::<Secp256k1Curve>(b"t2", &reveal.commitment_t2);
        t.challenge::<Secp256k1Curve>(b"challenge").scalar
    };
    terms.push(Term { coeff: reveal.response_s, point: g });
    terms.push(Term { coeff: neg(&c_reveal), point: reveal.user_public_key });
    terms.push(Term { coeff: neg(&one), point: reveal.commitment_t1 });
    eq_sizes.push(3);
    terms.push(Term { coeff: reveal.response_s, point: ct.c1 });
    terms.push(Term { coeff: neg(&c_reveal), point: token });
    terms.push(Term { coeff: neg(&one), point: reveal.commitment_t2 });
    eq_sizes.push(3);

    let d2s: Vec<Pt> = fold_input
        .iter()
        .zip(&fold_output)
        .map(|(i, o)| i.c2 - o.c2)
        .collect();
    let c_fold = {
        let mut t = KeccakTranscript::new(&hand_proto);
        let labels = <LeaveKind as DLEqProofKind<Secp256k1Curve>>::labels();
        t.append_point::<Secp256k1Curve>(labels.pk, &pk_f);
        for ct_i in &fold_input {
            t.append_point::<Secp256k1Curve>(labels.input_c1, &ct_i.c1);
            t.append_point::<Secp256k1Curve>(labels.input_c2, &ct_i.c2);
        }
        for ct_o in &fold_output {
            t.append_point::<Secp256k1Curve>(labels.output_c1, &ct_o.c1);
            t.append_point::<Secp256k1Curve>(labels.output_c2, &ct_o.c2);
        }
        for a in &fold.per_card_commitments {
            t.append_point::<Secp256k1Curve>(labels.per_card_commitment, a);
        }
        t.append_point::<Secp256k1Curve>(labels.commitment_pk, &fold.commitment_pk);
        for d2 in &d2s {
            t.append_point::<Secp256k1Curve>(labels.d2, d2);
        }
        t.append_scalar::<Secp256k1Curve>(labels.nonce, &fold.nonce);
        t.challenge::<Secp256k1Curve>(labels.challenge).scalar
    };
    terms.push(Term { coeff: fold.response, point: g });
    terms.push(Term { coeff: neg(&c_fold), point: pk_f });
    terms.push(Term { coeff: neg(&one), point: fold.commitment_pk });
    eq_sizes.push(3);
    for i in 0..n_fold_cards {
        terms.push(Term { coeff: fold.response, point: fold_input[i].c1 });
        terms.push(Term { coeff: neg(&c_fold), point: d2s[i] });
        terms.push(Term { coeff: neg(&one), point: fold.per_card_commitments[i] });
        eq_sizes.push(3);
    }

    // ---------- rho + folding ----------
    // Debug: each equation's unweighted residual must already be identity.
    {
        let mut i = 0usize;
        for (eqi, sz) in eq_sizes.iter().enumerate() {
            let mut acc = <Secp256k1Curve as Curve>::Point::identity();
            for _ in 0..*sz {
                acc = acc + terms[i].point * terms[i].coeff;
                i += 1;
            }
            println!("eq {eqi} ({sz} terms) residual identity: {}", acc.is_identity());
        }
    }
    let mut rho_input: Vec<u8> = RHO_DOMAIN.to_vec();
    rho_input.extend_from_slice(&hand_id);
    for term in &terms {
        rho_input.extend_from_slice(&scalar_wire_bytes(&term.coeff));
        rho_input.extend_from_slice(&point_wire_bytes(&term.point));
    }
    let rho = <Secp256k1Curve as Curve>::hash_to_scalar(&rho_input);

    let points: Vec<Pt> = terms.iter().map(|t| t.point).collect();
    let mut folded: Vec<Sc> = Vec::new();
    let mut rpow = Sc::one();
    let mut idx = 0;
    for eq_size in &eq_sizes {
        for _ in 0..*eq_size {
            folded.push(rpow * terms[idx].coeff);
            idx += 1;
        }
        rpow = rpow * rho;
    }
    let l = Pt::vartime_multiscalar_mul(&folded, &points);
    assert!(l.is_identity(), "honest hand must fold to L == O");
    println!("honest hand: L == identity  [accept]");

    // Tamper parity: ownership[0] response +1 must break the fold.
    let mut folded_bad = folded.clone();
    folded_bad[0] = folded[0] + one; // first term of the first equation
    let l_bad = Pt::vartime_multiscalar_mul(&folded_bad, &points);
    assert!(!l_bad.is_identity(), "tampered hand must fold to non-zero L");
    println!("tampered hand: L != identity  [reject]");

    // ---------- print Cairo vectors ----------
    println!("\n// ---- Cairo test vectors ----");
    println!("    let hand_id = b\"{}\";", to_hex(&hand_id));

    let mut payload: Vec<String> = vec!["2".into(), "1".into(), "1".into()];
    for (pk, proof) in &ownership {
        let (px, py) = point_hex(pk);
        let (rx, ry) = point_hex(&proof.commitment);
        payload.push(format!("0x{px}"));
        payload.push(format!("0x{py}"));
        payload.push(format!("0x{rx}"));
        payload.push(format!("0x{ry}"));
        payload.push(format!("0x{}", scalar_hex(&proof.response)));
    }
    {
        let (x, y) = point_hex(&reveal.user_public_key);
        payload.push(format!("0x{x}"));
        payload.push(format!("0x{y}"));
        let (x, y) = point_hex(&ct.c1);
        payload.push(format!("0x{x}"));
        payload.push(format!("0x{y}"));
        let (x, y) = point_hex(&ct.c2);
        payload.push(format!("0x{x}"));
        payload.push(format!("0x{y}"));
        let (x, y) = point_hex(&token);
        payload.push(format!("0x{x}"));
        payload.push(format!("0x{y}"));
        let (x, y) = point_hex(&reveal.commitment_t1);
        payload.push(format!("0x{x}"));
        payload.push(format!("0x{y}"));
        let (x, y) = point_hex(&reveal.commitment_t2);
        payload.push(format!("0x{x}"));
        payload.push(format!("0x{y}"));
        payload.push(format!("0x{}", scalar_hex(&reveal.nonce)));
        payload.push(format!("0x{}", scalar_hex(&reveal.response_s)));
    }
    {
        payload.push(format!("{}", n_fold_cards));
        let (x, y) = point_hex(&pk_f);
        payload.push(format!("0x{x}"));
        payload.push(format!("0x{y}"));
        let (x, y) = point_hex(&fold.commitment_pk);
        payload.push(format!("0x{x}"));
        payload.push(format!("0x{y}"));
        payload.push(format!("0x{}", scalar_hex(&fold.nonce)));
        payload.push(format!("0x{}", scalar_hex(&fold.response)));
        for ct_i in &fold_input {
            let (x, y) = point_hex(&ct_i.c1);
            payload.push(format!("0x{x}"));
            payload.push(format!("0x{y}"));
        }
        for ct_i in &fold_input {
            let (x, y) = point_hex(&ct_i.c2);
            payload.push(format!("0x{x}"));
            payload.push(format!("0x{y}"));
        }
        for ct_o in &fold_output {
            let (x, y) = point_hex(&ct_o.c1);
            payload.push(format!("0x{x}"));
            payload.push(format!("0x{y}"));
        }
        for ct_o in &fold_output {
            let (x, y) = point_hex(&ct_o.c2);
            payload.push(format!("0x{x}"));
            payload.push(format!("0x{y}"));
        }
        for a in &fold.per_card_commitments {
            let (x, y) = point_hex(a);
            payload.push(format!("0x{x}"));
            payload.push(format!("0x{y}"));
        }
    }
    println!("    let payload: Array<u256> = array![");
    for word in &payload {
        println!("        {word},");
    }
    println!("    ];");
    println!("    // tamper test: add 1 to the word at index 7 (ownership[0].s)");
}
