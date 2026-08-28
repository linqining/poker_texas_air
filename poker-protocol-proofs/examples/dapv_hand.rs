//! DAPV prototype: one-pairing verification of a full hand's direct-sigma
//! proofs on BN254.
//!
//! Hand transcript (9-max Texas Hold'em, mirroring the settlement surface of
//! DUAL_PROOF_PROTOCOL.md):
//!   - 9  x PKOwnershipProof       (1  group equation each)
//!   - 9  x Bayer-Groth V2 shuffle (8  group equations + 2 field checks each)
//!   - 33 x RevealTokenProof       (2  group equations each)
//!   - 2  x LeaveKind batch DLEQ   (1 + 52 group equations each)
//!
//! Three verifiers are compared:
//!   1. naive - every proof runs its own `verify()`
//!   2. batch - all N residuals folded with powers of rho into ONE MSM, then
//!      the free check `L == O`
//!   3. DAPV  - same L, accept iff `e(L, H2) == 1` (single pairing)
//!
//! Soundness of 2/3: Schwartz-Zippel over the Fiat-Shamir derived rho gives
//! Pr[accept | some residual != O] <= (N-1)/r with r = BN254 group order
//! (~2^254); for N = 253 this is ~2^-246. Equation extraction replays each
//! proof's exact transcript schedule, so a tampered proof shifts its own
//! challenge and leaves a non-zero residual.
//!
//! Hand-instance binding: every phase transcript derives its protocol name
//! from (phase, hand_id), and rho folds the same hand_id in. A transcript
//! minted for hand A then fails every challenge in hand B's settlement; the
//! replay experiment at the end demonstrates this for all three verifiers.
//! Note rho-binding alone cannot stop a full-transcript replay (all residuals
//! stay zero for any rho) - the binding must enter the inner challenges.

use std::time::{Duration, Instant};

use halo2curves::bn256::{multi_miller_loop, G1Affine, G2, G2Affine, Gt};
use halo2curves::group::cofactor::CofactorCurveAffine;
use halo2curves::pairing::MillerLoopResult;
use poker_protocol_bg::BayerGrothShuffleProof;
use poker_protocol_core::{
    Bn254Curve, Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric,
};
use poker_protocol_proofs::dleq_proof::{DLEqProof, DLEqProofKind, LeaveKind};
use poker_protocol_proofs::pk_ownership::PKOwnershipProof;
use poker_protocol_proofs::reveal_token_proof::RevealTokenProof;
use poker_protocol_proofs::transcript_ext::MerlinTranscript;
use poker_protocol_proofs::CryptoTranscript;
use rand::seq::SliceRandom;
use rand_core::OsRng;

type C = Bn254Curve;
type Pt = <C as Curve>::Point;
type Sc = <C as Curve>::Scalar;
type Ct = ElGamalCiphertextGeneric<C>;

const N_PLAYERS: usize = 9;
const N_REVEAL: usize = 33;
const N_LEAVERS: usize = 2;
const DECK: usize = 52;

const SHUFFLE_PROTO: &[u8] = b"dapv/bg-shuffle";
const REVEAL_PROTO: &[u8] = b"dapv/reveal-token";
const LEAVE_PROTO: &[u8] = b"dapv/leave";
const HAND_DOMAIN: &[u8] = b"dapv/hand-binding/v1";

/// Per-hand protocol name: every inner Fiat-Shamir transcript derives from
/// (phase, hand_id), so proofs minted for one hand derive wrong challenges in
/// any other hand's settlement.
fn phase_proto(base: &[u8], hand_id: Option<&[u8; 32]>) -> Vec<u8> {
    use sha3::digest::Digest;
    match hand_id {
        None => base.to_vec(),
        Some(id) => {
            let mut h = sha3::Sha3_256::new();
            h.update(b"dapv/proto");
            h.update(base);
            h.update(id);
            h.finalize().to_vec()
        }
    }
}

// Bayer-Groth constants mirrored from poker-protocol-bg/src/proof.rs (private
// there); the commitment key is a deterministic function of the deck size, so
// the whole hand shares one derivation.
const BG_PROTOCOL_ID: &[u8] = b"poker/bayer-groth-shuffle/v2";
const BG_COMMITMENT_H_DOMAIN: &[u8] = b"poker/bg12/v2/H";

fn card_point(i: usize) -> Pt {
    C::hash_to_curve(format!("texas_poker/card/{i}").as_bytes())
}

// ============================================================
// Hand construction
// ============================================================

struct Player {
    sk: Sc,
    pk: Pt,
}

struct Hand {
    hand_id: Option<[u8; 32]>,
    players: Vec<Player>,
    ownership: Vec<PKOwnershipProof<C>>,
    shuffle_inputs: Vec<Vec<Ct>>,
    shuffle_outputs: Vec<Vec<Ct>>,
    shuffles: Vec<BayerGrothShuffleProof<C>>,
    reveal_cts: Vec<Ct>,
    reveal_tokens: Vec<Pt>,
    reveal_proofs: Vec<RevealTokenProof<C>>,
    leave_inputs: Vec<Vec<Ct>>,
    leave_outputs: Vec<Vec<Ct>>,
    leave_proofs: Vec<DLEqProof<C, LeaveKind>>,
}

fn build_hand(hand_id: Option<[u8; 32]>) -> Result<Hand, String> {
    let mut rng = OsRng;
    let shuffle_proto = phase_proto(SHUFFLE_PROTO, hand_id.as_ref());
    let reveal_proto = phase_proto(REVEAL_PROTO, hand_id.as_ref());
    let leave_proto = phase_proto(LEAVE_PROTO, hand_id.as_ref());

    let players: Vec<Player> = (0..N_PLAYERS)
        .map(|_| {
            let sk = Sc::random(&mut rng);
            Player { pk: C::base_g() * sk, sk }
        })
        .collect();

    let t = Instant::now();
    let ownership = players
        .iter()
        .map(|p| PKOwnershipProof::prove(&p.sk, &p.pk, &mut rng))
        .collect::<Vec<_>>();
    println!("  ownership x{N_PLAYERS}: {:?}", t.elapsed());

    let t = Instant::now();
    let cards: Vec<Pt> = (0..DECK).map(card_point).collect();
    let mut deck: Vec<Ct> = cards
        .iter()
        .map(|c| Ct::encrypt(c, &players[0].pk, &Sc::random(&mut rng)))
        .collect();
    let mut shuffle_inputs = Vec::with_capacity(N_PLAYERS);
    let mut shuffle_outputs = Vec::with_capacity(N_PLAYERS);
    let mut shuffles = Vec::with_capacity(N_PLAYERS);
    for i in 0..N_PLAYERS {
        let mut permutation: Vec<usize> = (0..DECK).collect();
        permutation.shuffle(&mut rng);
        let rerandomizers: Vec<Sc> = (0..DECK).map(|_| Sc::random(&mut rng)).collect();
        let output: Vec<Ct> = (0..DECK)
            .map(|j| deck[permutation[j]].re_encrypt(&players[i].pk, &rerandomizers[j]))
            .collect();
        let mut transcript = MerlinTranscript::new(&shuffle_proto);
        let proof = BayerGrothShuffleProof::prove(
            &deck,
            &output,
            &permutation,
            &rerandomizers,
            &players[i].pk,
            &mut rng,
            &mut transcript,
        )
        .map_err(|e| format!("shuffle prove {i}: {e:?}"))?;
        shuffle_inputs.push(std::mem::take(&mut deck));
        shuffle_outputs.push(output.clone());
        shuffles.push(proof);
        deck = output;
    }
    println!("  BG shuffle x{N_PLAYERS} (52 cards): {:?}", t.elapsed());

    let t = Instant::now();
    let showdown = &players[0];
    let mut reveal_cts = Vec::with_capacity(N_REVEAL);
    let mut reveal_tokens = Vec::with_capacity(N_REVEAL);
    let mut reveal_proofs = Vec::with_capacity(N_REVEAL);
    for j in 0..N_REVEAL {
        let ct = Ct::encrypt(&cards[j % DECK], &showdown.pk, &Sc::random(&mut rng));
        let token = ct.c1 * showdown.sk;
        let mut transcript = MerlinTranscript::new(&reveal_proto);
        let proof = RevealTokenProof::try_prove(
            &showdown.sk,
            &showdown.pk,
            &ct,
            &token,
            &mut rng,
            &mut transcript,
        )
        .map_err(|e| format!("reveal prove {j}: {e:?}"))?;
        reveal_cts.push(ct);
        reveal_tokens.push(token);
        reveal_proofs.push(proof);
    }
    println!("  reveal token x{N_REVEAL}: {:?}", t.elapsed());

    let t = Instant::now();
    let mut leave_inputs = Vec::with_capacity(N_LEAVERS);
    let mut leave_outputs = Vec::with_capacity(N_LEAVERS);
    let mut leave_proofs = Vec::with_capacity(N_LEAVERS);
    for f in 0..N_LEAVERS {
        let leaver = &players[N_PLAYERS - N_LEAVERS + f];
        // A leave strips the leaver's own encryption layer: c1 unchanged,
        // c2' = c2 - c1*sk, so d2 = c2 - c2' = sk*c1 as the DLEQ requires.
        let input: Vec<Ct> = cards
            .iter()
            .map(|c| Ct::encrypt(c, &leaver.pk, &Sc::random(&mut rng)))
            .collect();
        let output: Vec<Ct> = input
            .iter()
            .map(|ct| Ct { c1: ct.c1, c2: ct.c2 - ct.c1 * leaver.sk })
            .collect();
        let mut transcript = MerlinTranscript::new(&leave_proto);
        let proof = DLEqProof::<C, LeaveKind>::try_prove(
            &input,
            &output,
            &leaver.sk,
            &leaver.pk,
            &mut transcript,
        )
        .map_err(|e| format!("leave prove {f}: {e:?}"))?;
        leave_inputs.push(input);
        leave_outputs.push(output);
        leave_proofs.push(proof);
    }
    println!("  leave DLEQ x{N_LEAVERS} (52 cards): {:?}", t.elapsed());

    Ok(Hand {
        hand_id,
        players,
        ownership,
        shuffle_inputs,
        shuffle_outputs,
        shuffles,
        reveal_cts,
        reveal_tokens,
        reveal_proofs,
        leave_inputs,
        leave_outputs,
        leave_proofs,
    })
}

fn proof_wire_bytes() -> usize {
    const PT: usize = 32;
    const SC: usize = 32;
    let shuffles = N_PLAYERS * (11 * PT + (3 * DECK + 6) * SC);
    let ownership = N_PLAYERS * (PT + SC);
    let reveals = N_REVEAL * (3 * PT + 2 * SC);
    let leaves = N_LEAVERS * ((DECK + 1) * PT + 2 * SC);
    shuffles + ownership + reveals + leaves
}

// ============================================================
// Naive verification (production code paths)
// ============================================================

/// `claim` is the hand instance the settlement is running for; it must equal
/// the id the proofs were minted under, otherwise every phase transcript (and
/// rho) derives differently and verification fails.
fn verify_naive(h: &Hand, claim: Option<&[u8; 32]>) -> Result<(), String> {
    let shuffle_proto = phase_proto(SHUFFLE_PROTO, claim);
    let reveal_proto = phase_proto(REVEAL_PROTO, claim);
    let leave_proto = phase_proto(LEAVE_PROTO, claim);
    for (i, (player, proof)) in h.players.iter().zip(&h.ownership).enumerate() {
        if !proof.verify(&player.pk) {
            return Err(format!("ownership {i} rejected"));
        }
    }
    for (i, proof) in h.shuffles.iter().enumerate() {
        proof
            .verify(
                &h.shuffle_inputs[i],
                &h.shuffle_outputs[i],
                &h.players[i].pk,
                &mut MerlinTranscript::new(&shuffle_proto),
            )
            .map_err(|e| format!("shuffle {i} rejected: {e:?}"))?;
    }
    for (j, proof) in h.reveal_proofs.iter().enumerate() {
        proof
            .verify(
                &h.reveal_cts[j],
                &h.reveal_tokens[j],
                &h.players[0].pk,
                &mut MerlinTranscript::new(&reveal_proto),
            )
            .map_err(|e| format!("reveal {j} rejected: {e:?}"))?;
    }
    for (f, proof) in h.leave_proofs.iter().enumerate() {
        let pi = N_PLAYERS - N_LEAVERS + f;
        if !proof.verify(
            &h.leave_inputs[f],
            &h.leave_outputs[f],
            &h.players[pi].pk,
            &mut MerlinTranscript::new(&leave_proto),
        ) {
            return Err(format!("leave {f} rejected"));
        }
    }
    Ok(())
}

// ============================================================
// Residual extraction (mirrors each verify() exactly, emitting
// L_eq = sum coeff * point with L_eq == O as the pass condition)
// ============================================================

type Equation = Vec<(Sc, Pt)>;

struct Extracted {
    equations: Vec<Equation>,
    terms: usize,
    key_derive: Duration,
}

fn scalar_pow(mut base: Sc, mut exponent: usize) -> Sc {
    let mut result = Sc::one();
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = result * base;
        }
        base = base * base;
        exponent >>= 1;
    }
    result
}

fn challenge_nonzero(t: &mut impl CryptoTranscript, label: &[u8]) -> Sc {
    let mut challenge = t.challenge::<C>(label).scalar;
    let mut counter = 0u32;
    while challenge == Sc::zero() {
        t.append_message(b"bg12_zero_challenge_retry", &counter.to_le_bytes());
        challenge = t.challenge::<C>(label).scalar;
        counter = counter.wrapping_add(1);
    }
    challenge
}

fn bg_commitment_key(n: usize) -> (Pt, Vec<Pt>) {
    let h = C::hash_to_curve(BG_COMMITMENT_H_DOMAIN);
    let generators: Vec<Pt> = (0..n)
        .map(|i| C::hash_to_curve(format!("poker/bg12/v2/G/{n}/{i}").as_bytes()))
        .collect();
    (h, generators)
}

fn append_bg_ciphertext(t: &mut impl CryptoTranscript, label: &[u8], ct: &Ct) {
    t.append_message(b"bg12_ciphertext_label", label);
    t.append_point::<C>(b"bg12_ciphertext_c1", &ct.c1);
    t.append_point::<C>(b"bg12_ciphertext_c2", &ct.c2);
}

fn push_ownership(eqs: &mut Vec<Equation>, pk: &Pt, proof: &PKOwnershipProof<C>) -> Result<(), String> {
    if pk.is_identity() || proof.commitment.is_identity() {
        return Err("ownership: identity point".into());
    }
    // Mirrors pk_ownership::challenge (private in the crate).
    let mut input = Vec::new();
    input.extend_from_slice(C::base_g().compress().as_ref());
    input.extend_from_slice(pk.compress().as_ref());
    input.extend_from_slice(proof.commitment.compress().as_ref());
    let c = C::hash_to_scalar(&input);
    // s*G - R - c*pk = O
    eqs.push(vec![
        (proof.response, C::base_g()),
        (-Sc::one(), proof.commitment),
        (-c, *pk),
    ]);
    Ok(())
}

fn push_reveal(
    eqs: &mut Vec<Equation>,
    proto: &[u8],
    ct: &Ct,
    token: &Pt,
    expected_pk: &Pt,
    proof: &RevealTokenProof<C>,
) -> Result<(), String> {
    if !ct.is_valid()
        || expected_pk.is_identity()
        || proof.user_public_key.is_identity()
        || token.is_identity()
        || proof.user_public_key != *expected_pk
        || proof.commitment_t1.is_identity()
        || proof.commitment_t2.is_identity()
    {
        return Err("reveal: wire validation".into());
    }
    // Mirrors RevealTokenProof::compute_challenge (private in the crate).
    let mut t = MerlinTranscript::new(proto);
    t.append_scalar::<C>(b"reveal_token_nonce", &proof.nonce);
    t.append_point::<C>(b"pk", &proof.user_public_key);
    t.append_point::<C>(b"c1", &ct.c1);
    t.append_point::<C>(b"c2", &ct.c2);
    t.append_point::<C>(b"reveal_token", token);
    t.append_point::<C>(b"t1", &proof.commitment_t1);
    t.append_point::<C>(b"t2", &proof.commitment_t2);
    let c = t.challenge::<C>(b"challenge").scalar;
    // s*G - T1 - c*pk = O
    eqs.push(vec![
        (proof.response_s, C::base_g()),
        (-Sc::one(), proof.commitment_t1),
        (-c, proof.user_public_key),
    ]);
    // s*c1 - T2 - c*token = O
    eqs.push(vec![
        (proof.response_s, ct.c1),
        (-Sc::one(), proof.commitment_t2),
        (-c, *token),
    ]);
    Ok(())
}

fn push_leave(
    eqs: &mut Vec<Equation>,
    proto: &[u8],
    input: &[Ct],
    output: &[Ct],
    pk: &Pt,
    proof: &DLEqProof<C, LeaveKind>,
) -> Result<(), String> {
    let n = proof.per_card_commitments.len();
    if n == 0 || n != input.len() || n != output.len() {
        return Err("leave: shape".into());
    }
    if pk.is_identity() {
        return Err("leave: identity pk".into());
    }
    let mut d2s = Vec::with_capacity(n);
    for i in 0..n {
        if !input[i].is_valid() || !output[i].is_valid() {
            return Err("leave: invalid ciphertext".into());
        }
        if input[i].c1 != output[i].c1 {
            return Err("leave: c1 invariance".into());
        }
        let d2: Pt = <LeaveKind as DLEqProofKind<C>>::compute_d2(&input[i].c2, &output[i].c2);
        if d2.is_identity() {
            return Err("leave: identity d2".into());
        }
        d2s.push(d2);
    }
    if proof.commitment_pk.is_identity()
        || proof.per_card_commitments.iter().any(CurvePoint::is_identity)
    {
        return Err("leave: identity commitment".into());
    }
    // Mirrors dleq_proof::append_dleq_context.
    let labels = <LeaveKind as DLEqProofKind<C>>::labels();
    let mut t = MerlinTranscript::new(proto);
    t.append_point::<C>(labels.pk, pk);
    for ct in input {
        t.append_point::<C>(labels.input_c1, &ct.c1);
        t.append_point::<C>(labels.input_c2, &ct.c2);
    }
    for ct in output {
        t.append_point::<C>(labels.output_c1, &ct.c1);
        t.append_point::<C>(labels.output_c2, &ct.c2);
    }
    for a in &proof.per_card_commitments {
        t.append_point::<C>(labels.per_card_commitment, a);
    }
    t.append_point::<C>(labels.commitment_pk, &proof.commitment_pk);
    for d2 in &d2s {
        t.append_point::<C>(labels.d2, d2);
    }
    t.append_scalar::<C>(labels.nonce, &proof.nonce);
    let c = t.challenge::<C>(labels.challenge).scalar;
    // s*G - B - c*pk = O
    eqs.push(vec![
        (proof.response, C::base_g()),
        (-Sc::one(), proof.commitment_pk),
        (-c, *pk),
    ]);
    // s*c1_i - A_i - c*d2_i = O for every card
    for i in 0..n {
        eqs.push(vec![
            (proof.response, input[i].c1),
            (-Sc::one(), proof.per_card_commitments[i]),
            (-c, d2s[i]),
        ]);
    }
    Ok(())
}

fn push_shuffle(
    eqs: &mut Vec<Equation>,
    proto: &[u8],
    input: &[Ct],
    output: &[Ct],
    pk: &Pt,
    proof: &BayerGrothShuffleProof<C>,
    key: &(Pt, Vec<Pt>),
) -> Result<(), String> {
    let n = input.len();
    let mexp = &proof.multi_exponentiation;
    let product = &proof.product;

    // validate_statement + validate_proof_shape (boolean checks stay here).
    if n < 2 || output.len() != n
        || mexp.alpha_response.len() != n
        || product.a_response.len() != n
        || product.b_response.len() != n
    {
        return Err("shuffle: shape".into());
    }
    if pk.is_identity()
        || input.iter().chain(output.iter()).any(|ct| ct.c1.is_identity() || ct.c2.is_identity())
    {
        return Err("shuffle: identity point".into());
    }
    let wire_points = [
        proof.c_permutation,
        proof.c_permuted_powers,
        mexp.c_alpha,
        mexp.c_beta,
        mexp.ciphertext_0.c1,
        mexp.ciphertext_0.c2,
        mexp.ciphertext_1.c1,
        mexp.ciphertext_1.c2,
        product.c_d,
        product.c_delta,
        product.c_capital_delta,
    ];
    if wire_points.iter().any(CurvePoint::is_identity) {
        return Err("shuffle: identity proof point".into());
    }
    let (h, gens) = key;

    // Transcript replay in the exact order of BayerGrothShuffleProof::verify.
    let mut t = MerlinTranscript::new(proto);
    t.append_message(b"bg12_protocol", BG_PROTOCOL_ID);
    t.append_message(b"bg12_deck_size", &(n as u64).to_le_bytes());
    t.append_point::<C>(b"bg12_public_key", pk);
    for ct in input {
        append_bg_ciphertext(&mut t, b"input", ct);
    }
    for ct in output {
        append_bg_ciphertext(&mut t, b"output", ct);
    }
    t.append_point::<C>(b"bg12_c_permutation", &proof.c_permutation);
    let powers_challenge = challenge_nonzero(&mut t, b"bg12_powers_challenge");
    t.append_point::<C>(b"bg12_c_permuted_powers", &proof.c_permuted_powers);
    let product_y = challenge_nonzero(&mut t, b"bg12_product_y");
    let product_z = challenge_nonzero(&mut t, b"bg12_product_z");
    t.append_point::<C>(b"bg12_mexp_c_alpha", &mexp.c_alpha);
    t.append_point::<C>(b"bg12_mexp_c_beta", &mexp.c_beta);
    append_bg_ciphertext(&mut t, b"mexp_0", &mexp.ciphertext_0);
    append_bg_ciphertext(&mut t, b"mexp_1", &mexp.ciphertext_1);
    let mexp_challenge = challenge_nonzero(&mut t, b"bg12_mexp_challenge");

    // (1) ciphertext_1 == MSM(input, x^1..x^n): one equation per component.
    {
        let mut e1 = vec![(Sc::one(), mexp.ciphertext_1.c1)];
        let mut e2 = vec![(Sc::one(), mexp.ciphertext_1.c2)];
        for i in 0..n {
            let w = scalar_pow(powers_challenge, i + 1);
            e1.push((-w, input[i].c1));
            e2.push((-w, input[i].c2));
        }
        eqs.push(e1);
        eqs.push(e2);
    }
    // (2) gamma*c_permuted_powers + c_alpha - vector_commit(alpha, commitment)
    {
        let mut e = vec![
            (mexp_challenge, proof.c_permuted_powers),
            (Sc::one(), mexp.c_alpha),
        ];
        for i in 0..n {
            e.push((-mexp.alpha_response[i], gens[i]));
        }
        e.push((-mexp.commitment_response, *h));
        eqs.push(e);
    }
    // (3) c_beta - beta*G - blinding*H
    eqs.push(vec![
        (Sc::one(), mexp.c_beta),
        (-mexp.beta, C::base_g()),
        (-mexp.beta_blinding_response, *h),
    ]);
    // (4) ciphertext transport, one equation per component.
    {
        let mut e1 = vec![
            (Sc::one(), mexp.ciphertext_0.c1),
            (mexp_challenge, mexp.ciphertext_1.c1),
            (-mexp.rerandomization_response, C::base_g()),
        ];
        let mut e2 = vec![
            (Sc::one(), mexp.ciphertext_0.c2),
            (mexp_challenge, mexp.ciphertext_1.c2),
            (-mexp.beta, C::base_g()),
            (-mexp.rerandomization_response, *pk),
        ];
        for i in 0..n {
            e1.push((-mexp.alpha_response[i], output[i].c1));
            e2.push((-mexp.alpha_response[i], output[i].c2));
        }
        eqs.push(e1);
        eqs.push(e2);
    }

    t.append_point::<C>(b"bg12_product_c_d", &product.c_d);
    t.append_point::<C>(b"bg12_product_c_delta", &product.c_delta);
    t.append_point::<C>(b"bg12_product_c_capital_delta", &product.c_capital_delta);
    let product_challenge = challenge_nonzero(&mut t, b"bg12_product_challenge");

    // (5) c_d + gamma*(y*c_permutation + c_permuted_powers - z*sum(G_i))
    //     - sum(a_i*G_i) - r*H
    {
        let mut e = vec![
            (Sc::one(), product.c_d),
            (product_challenge * product_y, proof.c_permutation),
            (product_challenge, proof.c_permuted_powers),
        ];
        for i in 0..n {
            e.push((
                -(product_challenge * product_z + product.a_response[i]),
                gens[i],
            ));
        }
        e.push((-product.r_response, *h));
        eqs.push(e);
    }
    // (6) c_delta + gamma*c_capital_delta - sum(recurrence_i*G_i) - s*H
    {
        let mut e = vec![
            (Sc::one(), product.c_delta),
            (product_challenge, product.c_capital_delta),
        ];
        for i in 0..n - 1 {
            let rec = product_challenge * product.b_response[i + 1]
                - product.b_response[i] * product.a_response[i + 1];
            e.push((-rec, gens[i]));
        }
        e.push((-product.s_response, *h));
        eqs.push(e);
    }

    // Field checks that cannot enter a group pairing.
    if product.b_response[0] != product.a_response[0] {
        return Err("shuffle: product b[0] != a[0]".into());
    }
    let mut expected = Sc::one();
    for i in 1..=n {
        let term = product_y * Sc::from_u64(i as u64) + scalar_pow(powers_challenge, i)
            - product_z;
        expected = expected * term;
    }
    if product.b_response[n - 1] != product_challenge * expected {
        return Err("shuffle: product closing value".into());
    }
    Ok(())
}

fn extract_all(h: &Hand, claim: Option<&[u8; 32]>) -> Result<Extracted, String> {
    let shuffle_proto = phase_proto(SHUFFLE_PROTO, claim);
    let reveal_proto = phase_proto(REVEAL_PROTO, claim);
    let leave_proto = phase_proto(LEAVE_PROTO, claim);

    let t = Instant::now();
    let key = bg_commitment_key(DECK);
    let key_derive = t.elapsed();

    let mut eqs = Vec::new();
    for i in 0..N_PLAYERS {
        push_ownership(&mut eqs, &h.players[i].pk, &h.ownership[i])
            .map_err(|e| format!("ownership {i}: {e}"))?;
    }
    for i in 0..N_PLAYERS {
        push_shuffle(
            &mut eqs,
            &shuffle_proto,
            &h.shuffle_inputs[i],
            &h.shuffle_outputs[i],
            &h.players[i].pk,
            &h.shuffles[i],
            &key,
        )
        .map_err(|e| format!("shuffle {i}: {e}"))?;
    }
    for j in 0..N_REVEAL {
        push_reveal(
            &mut eqs,
            &reveal_proto,
            &h.reveal_cts[j],
            &h.reveal_tokens[j],
            &h.players[0].pk,
            &h.reveal_proofs[j],
        )
        .map_err(|e| format!("reveal {j}: {e}"))?;
    }
    for f in 0..N_LEAVERS {
        let pi = N_PLAYERS - N_LEAVERS + f;
        push_leave(
            &mut eqs,
            &leave_proto,
            &h.leave_inputs[f],
            &h.leave_outputs[f],
            &h.players[pi].pk,
            &h.leave_proofs[f],
        )
        .map_err(|e| format!("leave {f}: {e}"))?;
    }
    let terms = eqs.iter().map(|e| e.len()).sum();
    Ok(Extracted { equations: eqs, terms, key_derive })
}

// ============================================================
// Hand-level folding + the two aggregated verifiers
// ============================================================

fn xpt(buf: &mut Vec<u8>, p: &Pt) {
    buf.extend_from_slice(p.compress().as_ref());
}

fn xsc(buf: &mut Vec<u8>, s: &Sc) {
    buf.extend_from_slice(&s.as_bytes());
}

/// rho = H(hand-binding domain ‖ hand_id ‖ every statement and proof encoding).
/// Derived only after all proofs are fixed (Fiat-Shamir), so the adversary
/// cannot pick which equation to break based on the folding coefficients.
/// The hand_id makes the folding coefficients themselves hand-bound.
fn hand_rho(h: &Hand, claim: Option<&[u8; 32]>) -> Sc {
    let mut buf = Vec::with_capacity(1 << 17);
    buf.extend_from_slice(HAND_DOMAIN);
    match claim {
        Some(id) => buf.extend_from_slice(id),
        None => buf.extend_from_slice(b"legacy-unbound"),
    }
    for (player, proof) in h.players.iter().zip(&h.ownership) {
        xpt(&mut buf, &player.pk);
        xpt(&mut buf, &proof.commitment);
        xsc(&mut buf, &proof.response);
    }
    for i in 0..N_PLAYERS {
        xpt(&mut buf, &h.players[i].pk);
        for ct in &h.shuffle_inputs[i] {
            xpt(&mut buf, &ct.c1);
            xpt(&mut buf, &ct.c2);
        }
        for ct in &h.shuffle_outputs[i] {
            xpt(&mut buf, &ct.c1);
            xpt(&mut buf, &ct.c2);
        }
        let proof = &h.shuffles[i];
        let mexp = &proof.multi_exponentiation;
        let product = &proof.product;
        xpt(&mut buf, &proof.c_permutation);
        xpt(&mut buf, &proof.c_permuted_powers);
        xpt(&mut buf, &mexp.c_alpha);
        xpt(&mut buf, &mexp.c_beta);
        xpt(&mut buf, &mexp.ciphertext_0.c1);
        xpt(&mut buf, &mexp.ciphertext_0.c2);
        xpt(&mut buf, &mexp.ciphertext_1.c1);
        xpt(&mut buf, &mexp.ciphertext_1.c2);
        for s in &mexp.alpha_response {
            xsc(&mut buf, s);
        }
        xsc(&mut buf, &mexp.commitment_response);
        xsc(&mut buf, &mexp.beta);
        xsc(&mut buf, &mexp.beta_blinding_response);
        xsc(&mut buf, &mexp.rerandomization_response);
        xpt(&mut buf, &product.c_d);
        xpt(&mut buf, &product.c_delta);
        xpt(&mut buf, &product.c_capital_delta);
        for s in &product.a_response {
            xsc(&mut buf, s);
        }
        for s in &product.b_response {
            xsc(&mut buf, s);
        }
        xsc(&mut buf, &product.r_response);
        xsc(&mut buf, &product.s_response);
    }
    for j in 0..N_REVEAL {
        xpt(&mut buf, &h.players[0].pk);
        xpt(&mut buf, &h.reveal_cts[j].c1);
        xpt(&mut buf, &h.reveal_cts[j].c2);
        xpt(&mut buf, &h.reveal_tokens[j]);
        let proof = &h.reveal_proofs[j];
        xpt(&mut buf, &proof.user_public_key);
        xpt(&mut buf, &proof.commitment_t1);
        xpt(&mut buf, &proof.commitment_t2);
        xsc(&mut buf, &proof.response_s);
        xsc(&mut buf, &proof.nonce);
    }
    for f in 0..N_LEAVERS {
        let pi = N_PLAYERS - N_LEAVERS + f;
        xpt(&mut buf, &h.players[pi].pk);
        for ct in &h.leave_inputs[f] {
            xpt(&mut buf, &ct.c1);
            xpt(&mut buf, &ct.c2);
        }
        for ct in &h.leave_outputs[f] {
            xpt(&mut buf, &ct.c1);
            xpt(&mut buf, &ct.c2);
        }
        let proof = &h.leave_proofs[f];
        for a in &proof.per_card_commitments {
            xpt(&mut buf, a);
        }
        xpt(&mut buf, &proof.commitment_pk);
        xsc(&mut buf, &proof.response);
        xsc(&mut buf, &proof.nonce);
    }
    C::hash_to_scalar(&buf)
}

struct FoldOut {
    l: Pt,
    n_equations: usize,
    n_terms: usize,
    t_extract: Duration,
    t_key_derive: Duration,
    t_rho: Duration,
    t_msm: Duration,
}

fn fold_hand(h: &Hand, claim: Option<&[u8; 32]>) -> Result<FoldOut, String> {
    let t = Instant::now();
    let extracted = extract_all(h, claim)?;
    let t_extract = t.elapsed();

    let t = Instant::now();
    let rho = hand_rho(h, claim);
    let t_rho = t.elapsed();

    let n_equations = extracted.equations.len();
    let n_terms = extracted.terms;
    let mut scalars = Vec::with_capacity(n_terms);
    let mut points = Vec::with_capacity(n_terms);
    let mut rpow = Sc::one();
    let t = Instant::now();
    for equation in &extracted.equations {
        for (s, p) in equation {
            scalars.push(rpow * *s);
            points.push(*p);
        }
        rpow = rpow * rho;
    }
    let l = Pt::vartime_multiscalar_mul(&scalars, &points);
    let t_msm = t.elapsed();

    Ok(FoldOut {
        l,
        n_equations,
        n_terms,
        t_extract,
        t_key_derive: extracted.key_derive,
        t_rho,
        t_msm,
    })
}

fn verify_batch(h: &Hand, claim: Option<&[u8; 32]>) -> Result<(bool, FoldOut, Duration), String> {
    let fo = fold_hand(h, claim)?;
    let t = Instant::now();
    let ok = fo.l.is_identity();
    Ok((ok, fo, t.elapsed()))
}

fn h2() -> G2Affine {
    G2Affine::from(G2::generator())
}

/// DAPV final check: e(L, H2) == 1 ⟺ L == O (BN254 G1 cofactor 1, pairing
/// non-degenerate). This is the single pairing of the whole hand.
fn verify_dapv(h: &Hand, claim: Option<&[u8; 32]>) -> Result<(bool, FoldOut, Duration), String> {
    let fo = fold_hand(h, claim)?;
    let t = Instant::now();
    let f = multi_miller_loop(&[(&G1Affine::from(fo.l), &h2())]);
    let ok = f.final_exponentiation() == Gt::identity();
    Ok((ok, fo, t.elapsed()))
}

fn pairing_selfcheck() -> Result<(), String> {
    let s = Sc::random(&mut OsRng);
    let p = C::base_g() * s;
    let q = h2();
    let mut q2 = G2::generator();
    q2 = q2 + q2;
    let e_pq = multi_miller_loop(&[(&G1Affine::from(p), &q)]).final_exponentiation();
    let e_2p_q = multi_miller_loop(&[(&G1Affine::from(p + p), &q)]).final_exponentiation();
    if e_2p_q != e_pq.double() {
        return Err("pairing bilinearity failed on the G1 side".into());
    }
    let e_p_2q =
        multi_miller_loop(&[(&G1Affine::from(p), &G2Affine::from(q2))]).final_exponentiation();
    if e_p_2q != e_pq.double() {
        return Err("pairing bilinearity failed on the G2 side".into());
    }
    let e_o_q = multi_miller_loop(&[(&G1Affine::identity(), &q)]).final_exponentiation();
    if e_o_q != Gt::identity() {
        return Err("e(O, H2) != 1".into());
    }
    Ok(())
}

// ============================================================
// Harness
// ============================================================

fn bench<F: FnMut()>(warmup: usize, iters: usize, mut f: F) -> (Duration, Duration) {
    for _ in 0..warmup {
        f();
    }
    let mut sum = Duration::ZERO;
    let mut min = Duration::MAX;
    for _ in 0..iters {
        let t = Instant::now();
        f();
        let d = t.elapsed();
        sum += d;
        if d < min {
            min = d;
        }
    }
    (sum / iters as u32, min)
}

fn ms(d: Duration) -> String {
    format!("{:8.3} ms", d.as_secs_f64() * 1e3)
}

fn expect_rejected(label: &str, h: &Hand, claim: Option<&[u8; 32]>) -> Result<(), String> {
    // A wire/field check failure inside extraction is also a rejection.
    let naive_ok = verify_naive(h, claim).is_ok();
    let batch_ok = verify_batch(h, claim).map(|(ok, _, _)| ok).unwrap_or(false);
    let dapv_ok = verify_dapv(h, claim).map(|(ok, _, _)| ok).unwrap_or(false);
    if naive_ok || batch_ok || dapv_ok {
        return Err(format!(
            "negative test '{label}' leaked: naive={naive_ok} batch={batch_ok} dapv={dapv_ok}"
        ));
    }
    println!("  [ok] {label}: naive=reject batch=reject dapv=reject");
    Ok(())
}

fn run() -> Result<(), String> {
    println!("==================================================================");
    println!("DAPV prototype - one-pairing verification of one hand (BN254)");
    println!("{} / {}", std::env::consts::OS, std::env::consts::ARCH);
    println!("==================================================================");

    pairing_selfcheck()?;
    println!("[ok] pairing self-check (bilinearity + e(O,H2)=1)\n");

    println!("building hand:");
    let t = Instant::now();
    let hand_id = {
        use sha3::digest::Digest;
        let mut h = sha3::Sha3_256::new();
        h.update(b"dapv/hand-instance/A");
        let id: [u8; 32] = h.finalize().into();
        id
    };
    println!("  hand_id: {:02x}{:02x}{:02x}{:02x}...", hand_id[0], hand_id[1], hand_id[2], hand_id[3]);
    let claim_a = Some(hand_id);
    let mut hand = build_hand(claim_a)?;
    println!("  total prove time: {:?}\n", t.elapsed());

    let n_eq_expected = N_PLAYERS + 8 * N_PLAYERS + 2 * N_REVEAL + N_LEAVERS * (1 + DECK);
    println!("hand shape:");
    println!("  ownership   : {N_PLAYERS} proofs  x 1  equation");
    println!("  BG shuffle  : {N_PLAYERS} proofs  x 8  equations (+2 field checks)");
    println!("  reveal token: {N_REVEAL} proofs  x 2  equations");
    println!("  leave DLEQ  : {N_LEAVERS} proofs  x {} equations", 1 + DECK);
    println!("  => N = {n_eq_expected} group equations, proof wire ~{:.1} KiB",
        proof_wire_bytes() as f64 / 1024.0);
    let soundness_bits = 254.0 - (n_eq_expected as f64).log2();
    println!("  => Schwartz-Zippel bound (N-1)/r ~ 2^{soundness_bits:.0}\n");

    // ---- correctness on the honest hand ----
    println!("correctness (honest hand):");
    verify_naive(&hand, claim_a.as_ref())?;
    let (batch_ok, fo, t_final) = verify_batch(&hand, claim_a.as_ref())?;
    let (dapv_ok, _, _) = verify_dapv(&hand, claim_a.as_ref())?;
    if !batch_ok {
        return Err("batch verifier rejected the honest hand".into());
    }
    if !dapv_ok {
        return Err("DAPV verifier rejected the honest hand".into());
    }
    println!("  [ok] naive / batch / dapv all accept");
    println!(
        "  folded: {} equations -> {} MSM terms, L==O check {:?}",
        fo.n_equations, fo.n_terms, t_final
    );
    if fo.n_equations != n_eq_expected {
        return Err(format!(
            "equation count mismatch: extracted {} expected {n_eq_expected}",
            fo.n_equations
        ));
    }
    println!();

    // ---- negative tests: single-equation tampering ----
    println!("negative tests (single tamper, all three verifiers must reject):");
    {
        let old = hand.ownership[3].response;
        hand.ownership[3].response = old + Sc::one();
        expect_rejected("ownership[3].response + 1", &hand, claim_a.as_ref())?;
        hand.ownership[3].response = old;
    }
    {
        let old = hand.reveal_proofs[10].commitment_t1;
        hand.reveal_proofs[10].commitment_t1 = old + C::base_g();
        expect_rejected("reveal[10].commitment_t1 + G", &hand, claim_a.as_ref())?;
        hand.reveal_proofs[10].commitment_t1 = old;
    }
    {
        let old = hand.shuffles[5].multi_exponentiation.ciphertext_1.c1;
        hand.shuffles[5].multi_exponentiation.ciphertext_1.c1 = old + C::base_g();
        expect_rejected("shuffle[5].mexp.ciphertext_1.c1 + G", &hand, claim_a.as_ref())?;
        hand.shuffles[5].multi_exponentiation.ciphertext_1.c1 = old;
    }
    {
        let old = hand.leave_proofs[1].response;
        hand.leave_proofs[1].response = old + Sc::one();
        expect_rejected("leave[1].response + 1", &hand, claim_a.as_ref())?;
        hand.leave_proofs[1].response = old;
    }
    // restore sanity
    verify_naive(&hand, claim_a.as_ref())?;
    println!("  [ok] hand restored, naive accepts again\n");

    // ---- replay protection: hand-bound transcripts ----
    println!("replay protection (hand-bound transcripts):");
    let id_b = {
        let mut id = hand_id;
        id[0] ^= 0x01;
        id
    };
    println!(
        "  attacker settles hand {:02x}.. transcript under hand {:02x}.. instance:",
        hand_id[0], id_b[0]
    );
    expect_rejected("cross-hand replay", &hand, Some(&id_b))?;
    // The same transcript still verifies under its own instance id.
    verify_naive(&hand, claim_a.as_ref())?;
    println!("  [ok] same transcript under its own hand id: accepted\n");

    // ---- performance ----
    println!("performance (verify one full hand):");

    let (naive_avg, naive_min) = bench(1, 8, || {
        let _ = verify_naive(&hand, claim_a.as_ref());
    });
    let (batch_avg, batch_min) = bench(3, 20, || {
        let _ = verify_batch(&hand, claim_a.as_ref());
    });
    let (dapv_avg, dapv_min) = bench(3, 20, || {
        let _ = verify_dapv(&hand, claim_a.as_ref());
    });

    println!("  naive per-proof verify : avg {} min {}", ms(naive_avg), ms(naive_min));
    println!("  hand batch (MSM+L==O) : avg {} min {}", ms(batch_avg), ms(batch_min));
    println!("  DAPV      (MSM+1 pair): avg {} min {}", ms(dapv_avg), ms(dapv_min));
    println!(
        "  batch vs naive speedup : {:.1}x | DAPV vs naive: {:.1}x | DAPV overhead vs batch: +{:.3} ms",
        naive_avg.as_secs_f64() / batch_avg.as_secs_f64(),
        naive_avg.as_secs_f64() / dapv_avg.as_secs_f64(),
        (dapv_avg - batch_avg).as_secs_f64() * 1e3,
    );
    println!();

    // ---- phase breakdown ----
    println!("phase breakdown (hand-batch path, one run):");
    let fo = fold_hand(&hand, claim_a.as_ref())?;
    println!("  commitment-key derive (53 x SVDW hash_to_curve): {}", ms(fo.t_key_derive));
    println!("  residual extraction (transcript replay)        : {}", ms(fo.t_extract - fo.t_key_derive));
    println!("  rho derivation (~100 KiB binding hash)         : {}", ms(fo.t_rho));
    println!("  fold + single MSM ({} terms)          : {}", fo.n_terms, ms(fo.t_msm));

    let cached = {
        let extracted = extract_all(&hand, claim_a.as_ref())?;
        let rho = hand_rho(&hand, claim_a.as_ref());
        let mut scalars = Vec::with_capacity(extracted.terms);
        let mut points = Vec::with_capacity(extracted.terms);
        let mut rpow = Sc::one();
        for equation in &extracted.equations {
            for (s, p) in equation {
                scalars.push(rpow * *s);
                points.push(*p);
            }
            rpow = rpow * rho;
        }
        (scalars, points)
    };
    let (msm_avg, _) = bench(3, 20, || {
        let _ = Pt::vartime_multiscalar_mul(&cached.0, &cached.1);
    });
    let l_nonidentity = cached.0.iter().fold(C::base_g(), |acc, s| acc + C::base_g() * *s);
    let (pair_avg, _) = bench(3, 50, || {
        let _ = multi_miller_loop(&[(&G1Affine::from(l_nonidentity), &h2())])
            .final_exponentiation();
    });
    let (key_avg, _) = bench(1, 10, || {
        let _ = bg_commitment_key(DECK);
    });
    let (rho_avg, _) = bench(2, 20, || {
        let _ = hand_rho(&hand, claim_a.as_ref());
    });
    let (extract_avg, _) = bench(2, 20, || {
        let _ = extract_all(&hand, claim_a.as_ref());
    });
    println!();
    println!("micro benchmarks (isolated):");
    println!("  residual extraction only : {}", ms(extract_avg));
    println!("  one big MSM ({} terms)   : {}", cached.0.len(), ms(msm_avg));
    println!("  single pairing e(L,H2)   : {}", ms(pair_avg));
    println!("  key derive (1x, shared)  : {}", ms(key_avg));
    println!("  rho derivation only      : {}", ms(rho_avg));

    println!();
    println!("conclusion: DAPV is algebraically equivalent to the batch check");
    println!("e(L,H2)=1 <=> L==O; the pairing is pure extra cost on top of the same");
    println!("MSM (see +overhead above). The real win of hand-level aggregation is");
    println!("batch vs naive.");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("FATAL: {e}");
        std::process::exit(1);
    }
}
