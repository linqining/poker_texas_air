//! StarkCurve 全量回归（Plan D P1.1）。
//!
//! 把协议的核心证明语句跑在 Cairo 原生 STARK 曲线上：自定义三层 Schnorr
//! 洗牌（ZKShuffleProof）、Bayer-Groth V2（VersionedShuffleProof 生产路径）、
//! DLEQ（remask/leave）、RevealToken、PKOwnership。这些语句正是
//! `poker_protocol/soundness.md` 的分析对象；secp256k1/BLS/Ristretto 的
//! 等价语句由各模块内置测试覆盖（Ristretto 直证）与 facade 层
//! DefaultCurve 切换测试覆盖。

use poker_protocol_core::{
    ec_encrypt_batch_generic, Curve, CurveScalar, ElGamalCiphertextGeneric, StarkCurve,
};
use poker_protocol_proofs::bayer_groth::BayerGrothShuffleProof;
use poker_protocol_proofs::dleq_proof::RemaskKind;
use poker_protocol_proofs::leave_proof::LeaveProof;
use poker_protocol_proofs::pk_ownership::PKOwnershipProof;
use poker_protocol_proofs::remask_proof::RemaskProof;
use poker_protocol_proofs::reveal_token_proof::RevealTokenProof;
use poker_protocol_proofs::shuffle_proof::ZKShuffleProof;
use poker_protocol_proofs::transcript_ext::{CryptoTranscript, MerlinTranscript};
use poker_protocol_proofs::versioned::VersionedShuffleProof;
use rand::seq::SliceRandom;
use rand_core::{CryptoRng, OsRng, RngCore};

type C = StarkCurve;
type Ciphertext = ElGamalCiphertextGeneric<C>;

fn scalar_from_u64(v: u64) -> <C as Curve>::Scalar {
    <C as Curve>::Scalar::from_u64(v)
}

fn gen_keypair(rng: &mut (impl CryptoRng + RngCore)) -> (<C as Curve>::Scalar, <C as Curve>::Point) {
    let sk = <C as Curve>::Scalar::random(rng);
    (sk, <C as Curve>::base_g() * sk)
}

fn make_full_encrypted_cards(pk: &<C as Curve>::Point) -> Vec<Ciphertext> {
    let n = <C as Curve>::n_cards();
    let msgs: Vec<<C as Curve>::Point> = (0..n)
        .map(|i| <C as Curve>::base_g() * scalar_from_u64(i as u64 + 1))
        .collect();
    ec_encrypt_batch_generic::<C>(&msgs, pk, &mut OsRng)
}

fn random_permute() -> Vec<usize> {
    let n = <C as Curve>::n_cards();
    let mut arr: Vec<usize> = (0..n).collect();
    arr.shuffle(&mut OsRng);
    arr
}

/// output[j] = input[permute[j]].re_encrypt(pk, r_j)（与 shuffle_proof
/// 内置测试同向）。
fn shuffle_and_reencrypt(
    input: &[Ciphertext],
    permute: &[usize],
    pk: &<C as Curve>::Point,
) -> (Vec<<C as Curve>::Scalar>, Vec<Ciphertext>) {
    let n = <C as Curve>::n_cards();
    let mut r_values = Vec::with_capacity(n);
    let mut output = Vec::with_capacity(n);
    for j in 0..n {
        let r_j = <C as Curve>::Scalar::random(&mut OsRng);
        r_values.push(r_j);
        output.push(input[permute[j]].re_encrypt(pk, &r_j));
    }
    (r_values, output)
}

// ============================================================
// ZKShuffleProof：自定义三层 GeneralizedSchnorr（soundness.md 主体）
// ============================================================

#[test]
fn zk_shuffle_honest_52_card_verifies_on_stark_curve() {
    let (_sk, pk) = gen_keypair(&mut OsRng);
    let input = make_full_encrypted_cards(&pk);
    let permute = random_permute();
    let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

    let proof = ZKShuffleProof::<C>::prove(
        &input,
        &output,
        &permute,
        &r_values,
        &pk,
        &mut OsRng,
        &mut MerlinTranscript::new(b"stark-shuffle"),
    )
    .expect("honest 52-card shuffle proof");
    proof
        .verify(&input, &output, &pk, &mut MerlinTranscript::new(b"stark-shuffle"))
        .expect("honest shuffle must verify");
}

#[test]
fn zk_shuffle_identity_permutation_passes_on_stark_curve() {
    let (_sk, pk) = gen_keypair(&mut OsRng);
    let input = make_full_encrypted_cards(&pk);
    let n = <C as Curve>::n_cards();
    let permute: Vec<usize> = (0..n).collect();
    let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

    let proof = ZKShuffleProof::<C>::prove(
        &input,
        &output,
        &permute,
        &r_values,
        &pk,
        &mut OsRng,
        &mut MerlinTranscript::new(b"stark-shuffle-identity"),
    )
    .expect("identity permutation is a valid shuffle");
    proof
        .verify(
            &input,
            &output,
            &pk,
            &mut MerlinTranscript::new(b"stark-shuffle-identity"),
        )
        .expect("identity permutation must verify");
}

#[test]
fn zk_shuffle_rejects_tampered_output_on_stark_curve() {
    let (_sk, pk) = gen_keypair(&mut OsRng);
    let input = make_full_encrypted_cards(&pk);
    let permute = random_permute();
    let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

    let proof = ZKShuffleProof::<C>::prove(
        &input,
        &output,
        &permute,
        &r_values,
        &pk,
        &mut OsRng,
        &mut MerlinTranscript::new(b"stark-shuffle-tamper"),
    )
    .expect("honest proof");

    let mut wrong_output = output.clone();
    wrong_output.swap(0, 1);
    assert!(
        proof
            .verify(&input, &wrong_output, &pk, &mut MerlinTranscript::new(b"stark-shuffle-tamper"))
            .is_err(),
        "swapped output must be rejected"
    );

    // transcript 绑定：换上下文必须拒绝（Fiat-Shamir 域分离）
    assert!(
        proof
            .verify(&input, &output, &pk, &mut MerlinTranscript::new(b"wrong-context"))
            .is_err(),
        "wrong transcript context must be rejected"
    );
}

#[test]
fn zk_shuffle_rejects_wrong_public_key_on_stark_curve() {
    let (_sk, pk) = gen_keypair(&mut OsRng);
    let input = make_full_encrypted_cards(&pk);
    let permute = random_permute();
    let (r_values, output) = shuffle_and_reencrypt(&input, &permute, &pk);

    let proof = ZKShuffleProof::<C>::prove(
        &input,
        &output,
        &permute,
        &r_values,
        &pk,
        &mut OsRng,
        &mut MerlinTranscript::new(b"stark-shuffle-wrongpk"),
    )
    .expect("honest proof");

    let (_sk2, pk2) = gen_keypair(&mut OsRng);
    assert!(
        proof
            .verify(&input, &output, &pk2, &mut MerlinTranscript::new(b"stark-shuffle-wrongpk"))
            .is_err(),
        "pk swap must be rejected (M-D13 pk binding)"
    );
}

// ============================================================
// VersionedShuffleProof / Bayer-Groth V2（生产路径）
// ============================================================

#[test]
fn versioned_bayer_groth_v2_honest_52_card_verifies_on_stark_curve() {
    let (sk, pk) = gen_keypair(&mut OsRng);
    let input = make_full_encrypted_cards(&pk);
    let permute = random_permute();
    let (rerandomizers, output) = shuffle_and_reencrypt(&input, &permute, &pk);

    let proof = VersionedShuffleProof::<C>::prove(
        &input,
        &output,
        &permute,
        &rerandomizers,
        &pk,
        &mut OsRng,
        &mut MerlinTranscript::new(b"stark-bg52"),
    )
    .expect("honest BG V2 proof");
    assert_eq!(proof.version(), poker_protocol_proofs::versioned::BAYER_GROTH_SHUFFLE_PROOF_VERSION);
    proof
        .verify(&input, &output, &pk, &mut MerlinTranscript::new(b"stark-bg52"))
        .expect("BG V2 honest verify");

    // 明文关系成立：解密后 output 明文 = input 明文的置换
    for j in 0..<C as Curve>::n_cards() {
        assert_eq!(output[j].decrypt(&sk), input[permute[j]].decrypt(&sk));
    }

    // 篡改拒绝：换 output
    let mut wrong = output.clone();
    wrong.swap(3, 4);
    assert!(proof
        .verify(&input, &wrong, &pk, &mut MerlinTranscript::new(b"stark-bg52"))
        .is_err());
}

#[test]
fn bayer_groth_direct_prove_verify_on_stark_curve() {
    let (_sk, pk) = gen_keypair(&mut OsRng);
    let n = 8;
    let msgs: Vec<<C as Curve>::Point> = (0..n)
        .map(|i| <C as Curve>::hash_to_curve(format!("bg-stark/card/{i}").as_bytes()))
        .collect();
    let input = ec_encrypt_batch_generic::<C>(&msgs, &pk, &mut OsRng);
    let mut permutation: Vec<usize> = (0..n).collect();
    permutation.shuffle(&mut OsRng);
    let rerandomizers: Vec<<C as Curve>::Scalar> =
        (0..n).map(|_| <C as Curve>::Scalar::random(&mut OsRng)).collect();
    let output: Vec<Ciphertext> = (0..n)
        .map(|i| input[permutation[i]].re_encrypt(&pk, &rerandomizers[i]))
        .collect();

    let proof = BayerGrothShuffleProof::prove(
        &input,
        &output,
        &permutation,
        &rerandomizers,
        &pk,
        &mut OsRng,
        &mut MerlinTranscript::new(b"bg-stark-direct"),
    )
    .expect("direct BG prove");
    proof
        .verify(&input, &output, &pk, &mut MerlinTranscript::new(b"bg-stark-direct"))
        .expect("direct BG verify");
}

// ============================================================
// DLEQ：remask / leave
// ============================================================

#[test]
fn dleq_remask_honest_verifies_on_stark_curve() {
    let sk = <C as Curve>::Scalar::random(&mut OsRng);
    let pk = <C as Curve>::base_g() * sk;
    let randomness = <C as Curve>::Scalar::random(&mut OsRng);
    let input = Ciphertext::encrypt(&(<C as Curve>::base_g() + <C as Curve>::base_h()), &pk, &randomness);
    let output = Ciphertext {
        c1: input.c1,
        c2: input.c2 + input.c1 * sk,
    };

    let proof = RemaskProof::<C>::prove(
        &[input],
        &[output],
        &sk,
        &pk,
        &mut MerlinTranscript::new(b"stark-remask"),
    );
    assert!(proof.verify(
        &[input],
        &[output],
        &pk,
        &mut MerlinTranscript::new(b"stark-remask")
    ));
}

#[test]
fn dleq_rejects_wrong_relation_on_stark_curve() {
    let sk = <C as Curve>::Scalar::random(&mut OsRng);
    let pk = <C as Curve>::base_g() * sk;
    let randomness = <C as Curve>::Scalar::random(&mut OsRng);
    let input = Ciphertext::encrypt(&(<C as Curve>::base_g() + <C as Curve>::base_h()), &pk, &randomness);

    // 错误关系：c2 挪用 base_h 偏移，不满足 remask 关系
    let mut malformed = input;
    malformed.c2 = malformed.c2 + <C as Curve>::base_h();
    assert!(RemaskProof::<C>::try_prove(
        &[input],
        &[malformed],
        &sk,
        &pk,
        &mut MerlinTranscript::new(b"stark-remask-bad")
    )
    .is_err());
}

#[test]
fn dleq_leave_honest_verifies_on_stark_curve() {
    let mut rng = OsRng;
    let (sk, pk) = gen_keypair(&mut rng);
    let plaintexts: Vec<<C as Curve>::Point> = (0..8)
        .map(|i| <C as Curve>::base_h() * scalar_from_u64(i as u64))
        .collect();
    let input_cts: Vec<Ciphertext> = (0..8)
        .map(|i| {
            let r = <C as Curve>::Scalar::random(&mut rng);
            Ciphertext::encrypt(&plaintexts[i], &pk, &r)
        })
        .collect();
    // 先 remask（加入本玩家的密钥层），再 leave（去掉）
    let remasked: Vec<Ciphertext> = (0..8)
        .map(|i| Ciphertext {
            c1: input_cts[i].c1,
            c2: input_cts[i].c2 + input_cts[i].c1 * sk,
        })
        .collect();
    let output: Vec<Ciphertext> = (0..8)
        .map(|i| Ciphertext {
            c1: remasked[i].c1,
            c2: remasked[i].c2 - remasked[i].c1 * sk,
        })
        .collect();

    let proof = LeaveProof::<C>::prove(
        &remasked,
        &output,
        &sk,
        &pk,
        &mut MerlinTranscript::new(b"stark-leave"),
    );
    assert!(proof.verify(
        &remasked,
        &output,
        &pk,
        &mut MerlinTranscript::new(b"stark-leave")
    ));
}

// ============================================================
// RevealToken
// ============================================================

#[test]
fn reveal_token_honest_verifies_on_stark_curve() {
    let holder_sk = <C as Curve>::Scalar::random(&mut OsRng);
    let holder_pk = <C as Curve>::base_g() * holder_sk;
    // 一张牌：聚合公钥下的加密（聚合 = 单玩家退化情形）
    let plaintext = <C as Curve>::hash_to_curve(b"stark-reveal/card-0");
    let r = <C as Curve>::Scalar::random(&mut OsRng);
    let card = Ciphertext::encrypt(&plaintext, &holder_pk, &r);
    let token = card.gen_reveal_token(&holder_sk);

    let proof = RevealTokenProof::<C>::prove(
        &holder_sk,
        &holder_pk,
        &card,
        &token,
        &mut OsRng,
        &mut MerlinTranscript::new(b"stark-reveal"),
    );
    proof
        .verify(&card, &token, &holder_pk, &mut MerlinTranscript::new(b"stark-reveal"))
        .expect("honest reveal token must verify");

    // 交给别的 pk 必须拒绝
    let (_other_sk, other_pk) = gen_keypair(&mut OsRng);
    assert!(proof
        .verify(&card, &token, &other_pk, &mut MerlinTranscript::new(b"stark-reveal"))
        .is_err());

    // 伪造 token（错误份额）必须拒绝
    let fake_token = card.gen_reveal_token(&<C as Curve>::Scalar::from_u64(42));
    assert!(RevealTokenProof::<C>::try_prove(
        &holder_sk,
        &holder_pk,
        &card,
        &fake_token,
        &mut OsRng,
        &mut MerlinTranscript::new(b"stark-reveal-fake"),
    )
    .is_err(), "wrong share must not be provable");
}

// ============================================================
// PKOwnership
// ============================================================

#[test]
fn pk_ownership_roundtrip_on_stark_curve() {
    let sk = <C as Curve>::Scalar::random(&mut OsRng);
    let pk = <C as Curve>::base_g() * sk;
    let proof = PKOwnershipProof::<C>::prove(&sk, &pk, &mut OsRng);
    assert!(proof.verify(&pk));
    let (_other_sk, other_pk) = gen_keypair(&mut OsRng);
    assert!(!proof.verify(&other_pk), "proof must not transfer to another pk");
}

// ============================================================
// 组合：两层联合洗牌（协议真实形态）
// ============================================================

#[test]
fn composite_two_layer_versioned_shuffle_on_stark_curve() {
    // 层 1：玩家 A 洗牌
    let (sk_a, pk_a) = gen_keypair(&mut OsRng);
    let input = make_full_encrypted_cards(&pk_a);
    let permute_a = random_permute();
    let (r_a, layer1) = shuffle_and_reencrypt(&input, &permute_a, &pk_a);
    let proof_a = VersionedShuffleProof::<C>::prove(
        &input,
        &layer1,
        &permute_a,
        &r_a,
        &pk_a,
        &mut OsRng,
        &mut MerlinTranscript::new(b"stark-composite-a"),
    )
    .expect("layer A proof");
    proof_a
        .verify(&input, &layer1, &pk_a, &mut MerlinTranscript::new(b"stark-composite-a"))
        .expect("layer A verify");

    // 层 2：玩家 B 对层 1 输出再洗牌（重加密到自己的密钥下不可行——
    // 密文仍是 A 的 pk 下的，B 只能置换+重随机化同一 pk；协议中 B 的
    // 层在自己的 pk 下，这里退化为同 pk 的第二层，验证组合可验证性）
    let permute_b = random_permute();
    let (r_b, layer2) = shuffle_and_reencrypt(&layer1, &permute_b, &pk_a);
    let proof_b = VersionedShuffleProof::<C>::prove(
        &layer1,
        &layer2,
        &permute_b,
        &r_b,
        &pk_a,
        &mut OsRng,
        &mut MerlinTranscript::new(b"stark-composite-b"),
    )
    .expect("layer B proof");
    proof_b
        .verify(&layer1, &layer2, &pk_a, &mut MerlinTranscript::new(b"stark-composite-b"))
        .expect("layer B verify");

    // 明文组合关系：layer2[j] ← layer1[permute_b[j]] ← input[permute_a[permute_b[j]]]
    let sk = sk_a;
    for j in 0..<C as Curve>::n_cards() {
        let src = permute_a[permute_b[j]];
        assert_eq!(layer2[j].decrypt(&sk), input[src].decrypt(&sk));
    }
}
