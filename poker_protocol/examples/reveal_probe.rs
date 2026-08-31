// 诊断探针：复现浏览器 reveal token 的原生验证（对照 ProofVerificationFailed）
use poker_protocol::crypto::{DefaultCurve, ElGamalCiphertext};
use poker_protocol::zk_shuffle::reveal_token_proof::REVEAL_TOKEN_PROOF_LABEL;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use poker_protocol::z_poker::convert::{hex_to_ecpoint, hex_to_scalar, scalar_to_hex};
use poker_protocol::z_poker::protocol::ClientPlayer;

fn main() {
    let raw = std::fs::read_to_string("/tmp/reveal_submit_frame.txt").unwrap();
    let idx = raw.find("\"pkHex\"").unwrap();
    let mut json = format!("{{{}", &raw[idx..]);
    if let Some(pos) = json.rfind('}') { json.truncate(pos + 1); }
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let pk_hex = v["pkHex"].as_str().unwrap().to_string();
    let tokens = v["revealTokens"].as_array().unwrap();
    println!("pkHex len = {}", pk_hex.len());
    println!("token count = {}", tokens.len());

    // ① native 曲线推导：hash_to_scalar(钱包地址) → pk
    let wallet = format!("0x{}", &pk_hex[..std::cmp::min(62, pk_hex.len())]);
    let _ = wallet;
    let player = ClientPlayer::new_with_wallet_address("0x6e37d33462f7319261396d7d7f669d147e40cdef91c6a8305cfde771805c782");
    let native_pk_hex = poker_protocol::z_poker::convert::ecpoint_to_hex(&player.pk);
    println!("native pk (hash_to_scalar of dev wallet) = {}", native_pk_hex);
    println!("native pk == browser pkHex: {}", native_pk_hex.to_lowercase() == pk_hex.to_lowercase());

    // ② 对每个 token：解析 → 自洽验证（proof.verify(ct, token, pk)）
    let expected_pk = hex_to_ecpoint(&pk_hex).expect("parse player pk");
    for (i, t) in tokens.iter().enumerate() {
        let c1 = t["encrypted_card"]["c1_hex"].as_str().unwrap();
        let c2 = t["encrypted_card"]["c2_hex"].as_str().unwrap();
        let ct = ElGamalCiphertext {
            c1: hex_to_ecpoint(c1).unwrap(),
            c2: hex_to_ecpoint(c2).unwrap(),
        };
        let reveal_token = hex_to_ecpoint(t["reveal_token_hex"].as_str().unwrap()).unwrap();
        let reveal_token_hex = t["reveal_token_hex"].as_str().unwrap().to_string();
        let p = &t["reveal_token_proof"];
        let sk = hex_to_scalar(p["response_s_hex"].as_str().unwrap()).unwrap();
        let nonce = hex_to_scalar(p["nonce_hex"].as_str().unwrap()).unwrap();
        let t1 = hex_to_ecpoint(p["commitment_t1_hex"].as_str().unwrap()).unwrap();
        let t2 = hex_to_ecpoint(p["commitment_t2_hex"].as_str().unwrap()).unwrap();
        let upk = hex_to_ecpoint(p["user_public_key_hex"].as_str().unwrap()).unwrap();
        println!("token[{}] upk==player_pk: {}", i, upk == expected_pk);

        let mut transcript = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof::<DefaultCurve> {
            user_public_key: upk,
            commitment_t1: t1,
            commitment_t2: t2,
            response_s: sk,
            nonce,
        };
        let res = proof.verify(&ct, &reveal_token, &expected_pk, &mut transcript);
        println!("token[{}] verify: {:?}", i, res);

        // 原生用相同 sk 重新生成 token 与 proof，对照浏览器输出
        let player = ClientPlayer::new_with_wallet_address("0x6e37d33462f7319261396d7d7f669d147e40cdef91c6a8305cfde771805c782");
        let native_token = player.generate_reveal_token(&ct);
        let native_token_hex = poker_protocol::z_poker::convert::ecpoint_to_hex(&native_token.reveal_token);
        println!("token[{}] native token == browser token: {}", i, native_token_hex.to_lowercase() == reveal_token_hex);
        let mut t2 = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let nres = native_token.proof.verify(&ct, &native_token.reveal_token, &expected_pk, &mut t2);
        println!("token[{}] native proof self-verify: {:?}", i, nres);

        // 手工重算两条 Chaum-Pedersen 等式，定位失败点
        use poker_protocol::crypto::Curve as _;
        let mut tt = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        tt.append_scalar::<DefaultCurve>(b"reveal_token_nonce", &native_token.proof.nonce);
        tt.append_point::<DefaultCurve>(b"pk", &expected_pk);
        tt.append_point::<DefaultCurve>(b"c1", &ct.c1);
        tt.append_point::<DefaultCurve>(b"c2", &ct.c2);
        tt.append_point::<DefaultCurve>(b"reveal_token", &native_token.reveal_token);
        tt.append_point::<DefaultCurve>(b"t1", &native_token.proof.commitment_t1);
        tt.append_point::<DefaultCurve>(b"t2", &native_token.proof.commitment_t2);
        let c = tt.challenge::<DefaultCurve>(b"challenge").scalar;
        let lhs_g = DefaultCurve::base_g() * native_token.proof.response_s;
        let rhs_g = native_token.proof.commitment_t1 + expected_pk * c;
        let lhs_ct = ct.c1 * native_token.proof.response_s;
        let rhs_ct = native_token.proof.commitment_t2 + native_token.reveal_token * c;
        println!("eq1 G*s==t1+pk*c: {}", lhs_g == rhs_g);
        println!("eq2 c1*s==t2+token*c: {}", lhs_ct == rhs_ct);
        println!("pk == G*sk (direct mul): {}", expected_pk == DefaultCurve::base_g() * poker_protocol::crypto::hash_to_scalar("0x6e37d33462f7319261396d7d7f669d147e40cdef91c6a8305cfde771805c782".as_bytes()));
        println!("pk == G*sk: {}", expected_pk == DefaultCurve::base_g() * poker_protocol::crypto::hash_to_scalar("0x6e37d33462f7319261396d7d7f669d147e40cdef91c6a8305cfde771805c782".as_bytes()));
    }
    // ③ scalar_to_hex 往返
    let s = hex_to_scalar("1b2a3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809").unwrap();
    println!("scalar roundtrip ok: {}", scalar_to_hex(&s).starts_with("1b2a3c4d"));
}
