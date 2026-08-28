//! Generator for the Cairo-side secp256k1 verifier test vectors
//! (poker_contracts/src/dual/secp256k1_verifier.cairo tests). Run with:
//! `cargo test -p poker-protocol-core --test secp256k1_vectors -- --nocapture --ignored`

use k256::elliptic_curve::{
    ops::Reduce, PrimeField,
    sec1::ToEncodedPoint as ToSec1,
};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use poker_protocol_core::{
    Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, Secp256k1Curve,
};
use poker_protocol_proofs::transcript_ext::KeccakTranscript;

fn print_u256(name: &str, bytes: &[u8; 32]) {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    println!("        let {name} = 0x{hex};");
}

fn print_point(name: &str, point: &AffinePoint) {
    let encoded = point.to_encoded_point(false);
    let mut x = [0u8; 32];
    x.copy_from_slice(encoded.x().expect("non-identity"));
    let mut y = [0u8; 32];
    y.copy_from_slice(encoded.y().expect("non-identity"));
    print_u256(&format!("{name}_x"), &x);
    print_u256(&format!("{name}_y"), &y);
}

fn repr32<F: PrimeField>(value: &F) -> [u8; 32] {
    let repr = value.to_repr();
    let mut out = [0u8; 32];
    out.copy_from_slice(repr.as_ref());
    out
}

#[test]
#[ignore]
fn print_secp256k1_cairo_vectors() {
    let sk = <Secp256k1Curve as Curve>::hash_to_scalar(b"cairo_vector_sk");
    let pk_affine = (Secp256k1Curve::base_g() * &sk).to_affine();
    let w = <Secp256k1Curve as Curve>::hash_to_scalar(b"cairo_vector_w");
    let big_r_affine = (Secp256k1Curve::base_g() * &w).to_affine();
    // The real Schnorr challenge: keccak256(G ‖ pk ‖ R) mod n — must match
    // PKOwnershipProof::challenge exactly (do NOT use an independent label).
    let mut challenge_input: Vec<u8> = Vec::new();
    challenge_input.extend_from_slice(
        &Secp256k1Curve::base_g().to_affine().to_encoded_point(true).as_bytes(),
    );
    challenge_input.extend_from_slice(&pk_affine.to_encoded_point(true).as_bytes());
    challenge_input.extend_from_slice(&big_r_affine.to_encoded_point(true).as_bytes());
    let c = <Secp256k1Curve as Curve>::hash_to_scalar(&challenge_input);
    let s = w + c * sk;
    let s_bad = s + Scalar::from(1u64);

    print_point("PK", &pk_affine);
    print_point("BIG_R", &big_r_affine);
    print_u256(
        "C",
        <Scalar as PrimeField>::to_repr(&c).as_ref(),
    );
    print_u256(
        "S",
        <Scalar as PrimeField>::to_repr(&s).as_ref(),
    );
    print_u256(
        "S_BAD",
        <Scalar as PrimeField>::to_repr(&s_bad).as_ref(),
    );

    // Cross-check: the honest tuple satisfies s*G == R + c*pk in k256 too.
    let lhs = ProjectivePoint::GENERATOR * s;
    let rhs = <AffinePoint as Into<ProjectivePoint>>::into(big_r_affine)
        + <AffinePoint as Into<ProjectivePoint>>::into(pk_affine) * c;
    assert_eq!(lhs, rhs, "vector statement must hold in k256");
}

#[test]
#[ignore]
fn print_ownership_challenge_debug() {
    use sha3::{Digest, Keccak256};
    let sk = <Secp256k1Curve as Curve>::hash_to_scalar(b"cairo_vector_sk");
    let pk = (Secp256k1Curve::base_g() * &sk).to_affine();
    let big_r = (Secp256k1Curve::base_g() * <Secp256k1Curve as Curve>::hash_to_scalar(b"cairo_vector_w")).to_affine();
    let g_enc: [u8; 33] = Secp256k1Curve::base_g().to_affine().to_encoded_point(true).as_bytes().try_into().unwrap();
    let pk_enc: [u8; 33] = pk.to_encoded_point(true).as_bytes().try_into().unwrap();
    let r_enc: [u8; 33] = big_r.to_encoded_point(true).as_bytes().try_into().unwrap();
    let mut input = Vec::new();
    input.extend_from_slice(&g_enc);
    input.extend_from_slice(&pk_enc);
    input.extend_from_slice(&r_enc);
    let to_hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    println!("G33={}", to_hex(&g_enc));
    println!("PK33={}", to_hex(&pk_enc));
    println!("R33={}", to_hex(&r_enc));
    let digest = Keccak256::digest(&input);
    println!("DIGEST={}", to_hex(&digest));
    println!(
        "CHAL_LE_MODN={}",
        to_hex(&<Secp256k1Curve as Curve>::hash_to_scalar(&input).as_bytes())
    );
}

#[test]
#[ignore]
fn print_reveal_and_dleq_keccak_vectors() {
    use k256::elliptic_curve::PrimeField;
    use poker_protocol_core::CryptoTranscript;
    use poker_protocol_proofs::dleq_proof::{DLEqProof, LeaveKind};
    use poker_protocol_proofs::reveal_token_proof::RevealTokenProof;
    use poker_protocol_proofs::transcript_ext::KeccakTranscript;

    const NAME: &[u8] = b"poker_secp256k1_keccak_v1";
    let proj = |a: k256::AffinePoint| -> ProjectivePoint { a.into() };
    let sk = <Secp256k1Curve as Curve>::hash_to_scalar(b"cairo_vector_sk");
    let pk = (Secp256k1Curve::base_g() * &sk).to_affine();
    let pk_proj = proj(pk);
    let to_hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    let print_scalar = |name: &str, s: &Scalar| {
        println!(
            "        let {name} = 0x{};",
            to_hex(<Scalar as PrimeField>::to_repr(s).as_ref())
        );
    };

    let sk = <Secp256k1Curve as Curve>::hash_to_scalar(b"cairo_vector_sk");
    let pk = (Secp256k1Curve::base_g() * &sk).to_affine();
    let card = Secp256k1Curve::hash_to_curve(b"texas_poker_secp256k1/card/7");
    let r = <Secp256k1Curve as Curve>::hash_to_scalar(b"cairo_vector_ct_r");
    let c1 = Secp256k1Curve::base_g() * &r;
    let c2 = card + pk_proj * r;
    let token = c1 * &sk;

    // ---- CP (reveal token) vector ----
    let mut transcript = KeccakTranscript::new(NAME);
    let proof = RevealTokenProof::<Secp256k1Curve>::prove(
        &sk,
        &pk_proj,
        &ElGamalCiphertextGeneric::<Secp256k1Curve> { c1, c2 },
        &token,
        &mut rand_core::OsRng,
        &mut transcript,
    );
    println!("--- CP vector ---");
    print_point("PK", &pk);
    let c1a: k256::AffinePoint = c1.into();
    let c2a: k256::AffinePoint = c2.into();
    let ta: k256::AffinePoint = token.into();
    print_point("C1", &c1a);
    print_point("C2", &c2a);
    print_point("TOKEN", &ta);
    let t1a: k256::AffinePoint = proof.commitment_t1.into();
    print_point("T1", &t1a);
    let t2a: k256::AffinePoint = proof.commitment_t2.into();
    print_point("T2", &t2a);
    print_scalar("NONCE", &proof.nonce);
    print_scalar("S", &proof.response_s);

    // ---- DLEQ (fold leave) vector, 2 cards ----
    let in_cts: Vec<ElGamalCiphertextGeneric<Secp256k1Curve>> = (0..2)
        .map(|i| {
            let card = Secp256k1Curve::hash_to_curve(format!("texas_poker_secp256k1/card/{i}").as_bytes());
            let r = <Secp256k1Curve as Curve>::hash_to_scalar(format!("r{i}").as_bytes());
            ElGamalCiphertextGeneric::<Secp256k1Curve>::encrypt(&card, &pk_proj, &r)
        })
        .collect();
    let out_cts: Vec<ElGamalCiphertextGeneric<Secp256k1Curve>> = in_cts
        .iter()
        .map(|ct| ElGamalCiphertextGeneric::<Secp256k1Curve> {
            c1: ct.c1,
            c2: ct.c2 - ct.c1 * &sk,
        })
        .collect();
    let mut transcript = KeccakTranscript::new(NAME);
    let dleq = DLEqProof::<Secp256k1Curve, LeaveKind>::prove(
        &in_cts,
        &out_cts,
        &sk,
        &pk_proj,
        &mut transcript,
    );
    // CP challenge from an identical replay (must equal the prove-time one).
    {
        use poker_protocol_core::CryptoTranscript;
        let mut t = KeccakTranscript::new(NAME);
        t.append_scalar::<Secp256k1Curve>(b"reveal_token_nonce", &proof.nonce);
        t.append_point::<Secp256k1Curve>(b"pk", &pk_proj);
        t.append_point::<Secp256k1Curve>(b"c1", &c1);
        t.append_point::<Secp256k1Curve>(b"c2", &c2);
        t.append_point::<Secp256k1Curve>(b"reveal_token", &token);
        t.append_point::<Secp256k1Curve>(b"t1", &proof.commitment_t1);
        t.append_point::<Secp256k1Curve>(b"t2", &proof.commitment_t2);
        let c = t.challenge::<Secp256k1Curve>(b"challenge");
        println!(
            "CP_CHAL={}",
            to_hex(<Scalar as PrimeField>::to_repr(c.scalar.as_ref()).as_ref())
        );
    }

    println!("--- DLEQ vector (n=2) ---");
    print_point("PK", &pk);
    for (i, ct) in in_cts.iter().enumerate() {
        let a: k256::AffinePoint = ct.c1.into();
        let b: k256::AffinePoint = ct.c2.into();
        print_point(&format!("IN{i}_C1"), &a);
        print_point(&format!("IN{i}_C2"), &b);
    }
    for (i, ct) in out_cts.iter().enumerate() {
        let a: k256::AffinePoint = ct.c1.into();
        let b: k256::AffinePoint = ct.c2.into();
        print_point(&format!("OUT{i}_C1"), &a);
        print_point(&format!("OUT{i}_C2"), &b);
    }
    for (i, com) in dleq.per_card_commitments.iter().enumerate() {
        let a: k256::AffinePoint = (*com).into();
        print_point(&format!("A{i}"), &a);
    }
    let cpk: k256::AffinePoint = dleq.commitment_pk.into();
    print_point("CPK", &cpk);
    print_scalar("NONCE", &dleq.nonce);
    print_scalar("S", &dleq.response);
}

#[test]
#[ignore]
fn print_unified_sigma_vector() {
    use poker_protocol_core::{ElGamalCiphertextGeneric, Secp256k1Curve};
    use poker_protocol_proofs::transcript_ext::KeccakTranscript;
    use poker_protocol_proofs::unified_sigma::{
        PlayerHandSigma, UnifiedFoldCard, UnifiedRevealCard, UnifiedStatement,
        UNIFIED_SIGMA_PROTOCOL_NAME,
    };
    use poker_protocol_core::CryptoTranscript;

    let to_hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    let print_scalar = |name: &str, s: &Scalar| {
        println!(
            "        let {name} = 0x{};",
            to_hex(<Scalar as PrimeField>::to_repr(s).as_ref())
        );
    };

    let sk = <Secp256k1Curve as Curve>::hash_to_scalar(b"cairo_vector_sk");
    let pk = (Secp256k1Curve::base_g() * &sk).to_affine();
    let pk_proj: ProjectivePoint = pk.into();
    let print_point = |name: &str, point: &k256::AffinePoint| {
        let encoded = point.to_encoded_point(false);
        let mut x = [0u8; 32];
        x.copy_from_slice(encoded.x().expect("non-identity"));
        let mut y = [0u8; 32];
        y.copy_from_slice(encoded.y().expect("non-identity"));
        println!("        let {name}_x = 0x{};", to_hex(&x));
        println!("        let {name}_y = 0x{};", to_hex(&y));
    };

    // 2 fold cards + 3 reveal cards, deterministic randomness via hashed scalars.
    let mut fold = Vec::new();
    for i in 0..2 {
        let card = Secp256k1Curve::hash_to_curve(format!("texas_poker_secp256k1/card/{i}").as_bytes());
        let r = <Secp256k1Curve as Curve>::hash_to_scalar(format!("cairo_unified_fr{i}").as_bytes());
        let in_ct = ElGamalCiphertextGeneric::<Secp256k1Curve>::encrypt(&card, &pk_proj, &r);
        let out_ct = ElGamalCiphertextGeneric::<Secp256k1Curve> {
            c1: in_ct.c1,
            c2: in_ct.c2 - in_ct.c1 * &sk,
        };
        fold.push(UnifiedFoldCard { in_ct, out_ct });
    }
    let mut reveal = Vec::new();
    for i in 0..3 {
        let card = Secp256k1Curve::hash_to_curve(format!("texas_poker_secp256k1/card/{}0", i + 2).as_bytes());
        let r = <Secp256k1Curve as Curve>::hash_to_scalar(format!("cairo_unified_rr{i}").as_bytes());
        let ct = ElGamalCiphertextGeneric::<Secp256k1Curve>::encrypt(&card, &pk_proj, &r);
        reveal.push(UnifiedRevealCard { token: ct.c1 * &sk, ct });
    }
    let statement = UnifiedStatement {
        pk: pk_proj,
        fold,
        reveal,
    };

    // Deterministic blinding: w = hash(b"cairo_unified_w") so the vector is stable.
    let w = <Secp256k1Curve as Curve>::hash_to_scalar(b"cairo_unified_w");
    // Binary-search probe: n_fold=1, n_reveal=0 (same first fold card as the
    // full vector).
    let fold0 = {
        let card = Secp256k1Curve::hash_to_curve(b"texas_poker_secp256k1/card/0");
        let r = <Secp256k1Curve as Curve>::hash_to_scalar(b"cairo_unified_fr0");
        let in_ct = ElGamalCiphertextGeneric::<Secp256k1Curve>::encrypt(&card, &pk_proj, &r);
        UnifiedFoldCard {
            out_ct: ElGamalCiphertextGeneric::<Secp256k1Curve> {
                c1: in_ct.c1,
                c2: in_ct.c2 - in_ct.c1 * &sk,
            },
            in_ct,
        }
    };
    {
        let mut t = KeccakTranscript::new(UNIFIED_SIGMA_PROTOCOL_NAME);
        let st1 = UnifiedStatement::<Secp256k1Curve> {
            pk: pk_proj,
            fold: vec![fold0.clone()],
            reveal: vec![],
        };
        st1.append_to_transcript(&mut t);
        let x1 = st1.relation(1).0;
        let a1 = x1 * w;
        let a0 = Secp256k1Curve::base_g() * w;
        t.append_point::<Secp256k1Curve>(b"unified_commitment", &a0);
        t.append_point::<Secp256k1Curve>(b"unified_commitment", &a1);
        let c1v = t.challenge::<Secp256k1Curve>(b"challenge").scalar;
        let s1v = w + c1v * sk;
        let a0a: k256::AffinePoint = a0.into();
        let a1a: k256::AffinePoint = a1.into();
        println!("--- UNIFIED-FOLD1-ONLY ---");
        print_point("B_A0", &a0a);
        print_point("B_A1", &a1a);
        print_scalar("B_S", &s1v);
        print_scalar("B_C", &c1v);
    }
    // Binary-search probe 2: n_fold=2, n_reveal=0.
    {
        let fold1 = {
            let card = Secp256k1Curve::hash_to_curve(b"texas_poker_secp256k1/card/1");
            let r = <Secp256k1Curve as Curve>::hash_to_scalar(b"cairo_unified_fr1");
            let in_ct = ElGamalCiphertextGeneric::<Secp256k1Curve>::encrypt(&card, &pk_proj, &r);
            UnifiedFoldCard {
                out_ct: ElGamalCiphertextGeneric::<Secp256k1Curve> {
                    c1: in_ct.c1,
                    c2: in_ct.c2 - in_ct.c1 * &sk,
                },
                in_ct,
            }
        };
        let mut t = KeccakTranscript::new(UNIFIED_SIGMA_PROTOCOL_NAME);
        let st = UnifiedStatement::<Secp256k1Curve> {
            pk: pk_proj,
            fold: vec![fold0.clone(), fold1],
            reveal: vec![],
        };
        st.append_to_transcript(&mut t);
        let a0 = Secp256k1Curve::base_g() * w;
        let a1 = st.relation(1).0 * w;
        let a2 = st.relation(2).0 * w;
        for a in [&a0, &a1, &a2] {
            t.append_point::<Secp256k1Curve>(b"unified_commitment", a);
        }
        let c = t.challenge::<Secp256k1Curve>(b"challenge").scalar;
        let s = w + c * sk;
        println!("--- UNIFIED-FOLD2-ONLY ---");
        print_scalar("C_C", &c);
        let a1a: k256::AffinePoint = a1.into();
        let a2a: k256::AffinePoint = a2.into();
        print_point("C_A1", &a1a);
        print_point("C_A2", &a2a);
        print_scalar("C_S", &s);
    }


    // Ownership-only probe vector first (n_fold=0, n_reveal=0).
    {
        let st0 = UnifiedStatement::<Secp256k1Curve> {
            pk: pk_proj,
            fold: vec![],
            reveal: vec![],
        };
        let mut t = KeccakTranscript::new(UNIFIED_SIGMA_PROTOCOL_NAME);
        st0.append_to_transcript(&mut t);
        let a0 = Secp256k1Curve::base_g() * w;
        t.append_point::<Secp256k1Curve>(b"unified_commitment", &a0);
        let c0 = t.challenge::<Secp256k1Curve>(b"challenge").scalar;
        let s0 = w + c0 * sk;
        let a0a: k256::AffinePoint = a0.into();
        println!("--- UNIFIED-OWNERSHIP-ONLY ---");
        print_point("OA0", &a0a);
        print_scalar("OS0", &s0);
    }

    let mut transcript = KeccakTranscript::new(UNIFIED_SIGMA_PROTOCOL_NAME);
    statement.append_to_transcript(&mut transcript);
    let commitments: Vec<_> = (0..statement.relation_count())
        .map(|i| {
            let (x, _) = statement.relation(i);
            x * w
        })
        .collect();
    for commitment in &commitments {
        transcript.append_point::<Secp256k1Curve>(b"unified_commitment", commitment);
    }
    let c = transcript.challenge::<Secp256k1Curve>(b"challenge").scalar;
    let s = w + c * sk;
    print_scalar("UC", &c);

    println!("--- UNIFIED vector (n_fold=2, n_reveal=3) ---");
    print_point("PK", &pk);
    for (i, card) in statement.fold.iter().enumerate() {
        let a: k256::AffinePoint = card.in_ct.c1.into();
        let b: k256::AffinePoint = card.in_ct.c2.into();
        let o1: k256::AffinePoint = card.out_ct.c1.into();
        let o2: k256::AffinePoint = card.out_ct.c2.into();
        print_point(&format!("F{i}_IN_C1"), &a);
        print_point(&format!("F{i}_IN_C2"), &b);
        print_point(&format!("F{i}_OUT_C1"), &o1);
        print_point(&format!("F{i}_OUT_C2"), &o2);
    }
    for (i, card) in statement.reveal.iter().enumerate() {
        let a: k256::AffinePoint = card.ct.c1.into();
        let b: k256::AffinePoint = card.ct.c2.into();
        let t: k256::AffinePoint = card.token.into();
        print_point(&format!("R{i}_C1"), &a);
        print_point(&format!("R{i}_C2"), &b);
        print_point(&format!("R{i}_TOKEN"), &t);
    }
    for (i, commitment) in commitments.iter().enumerate() {
        let a: k256::AffinePoint = (*commitment).into();
        print_point(&format!("A{i}"), &a);
    }
    print_scalar("S", &s);

    // Self-check via the real API.
    let mut t2 = KeccakTranscript::new(UNIFIED_SIGMA_PROTOCOL_NAME);
    let check = PlayerHandSigma::<Secp256k1Curve> {
        commitments: commitments.clone(),
        response: s,
    };
    assert!(
        check.verify(&statement, &mut t2),
        "vector must verify through the standard API"
    );
}
