use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use poker_protocol::z_poker::protocol::ClientPlayer;
use poker_protocol::crypto::{ElGamalCiphertext, Scalar, EcPoint, Plaintext, DefaultCurve, CurveScalar, CurvePoint};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::crypto::types::base_g;
use rand_core::OsRng;
use serde_wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

fn console_log(msg: &str) {
    let _ = log(&format!("[client-wasm] {}", msg));
}

pub fn scalar_to_hex(s: &Scalar) -> String {
    hex::encode(s.as_bytes())
}

fn hex_to_scalar(hex_str: &str) -> Result<Scalar, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err("Scalar must be 32 bytes".to_string());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Scalar::from_canonical_bytes(&arr)
        .ok_or_else(|| "non-canonical scalar encoding".to_string())
}

pub fn ecpoint_to_hex(p: &EcPoint) -> String {
    hex::encode(p.compress().as_ref())
}

fn hex_to_ecpoint(hex_str: &str) -> Result<EcPoint, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    // DefaultCurve = StarkCurve：压缩点为 32 字节（x 大端 + 首字节 0x80 位
    // 记 y 奇偶——StarkCompressedPoint 编码，见 stark_curve::compress）。
    // 此前按 48 字节（BLS12-381 时代）断言——Stark 迁移时漏改；2026-09-06
    // 重建 pkg 后首次进入产物，浏览器洗牌路径全部失败（hex 往返 c1/c2/pk）。
    if bytes.len() != 32 {
        return Err(format!(
            "EC point must be 32 bytes (Stark compressed x||parity), got {}",
            bytes.len()
        ));
    }
    EcPoint::from_compressed(&bytes).ok_or_else(|| "Invalid EC point".to_string())
}

fn ct_to_json(ct: &ElGamalCiphertext) -> String {
    format!(
        r#"{{"c1_hex":"{}","c2_hex":"{}"}}"#,
        ecpoint_to_hex(&ct.c1),
        ecpoint_to_hex(&ct.c2)
    )
}

fn ct_generic_to_json(ct: &poker_protocol::crypto::ElGamalCiphertextGeneric<DefaultCurve>) -> String {
    format!(
        r#"{{"c1_hex":"{}","c2_hex":"{}"}}"#,
        ecpoint_to_hex(&ct.c1),
        ecpoint_to_hex(&ct.c2)
    )
}

fn obj_string_to_ct(val: serde_json::Value) -> Result<ElGamalCiphertext, String> {
    match val {
        serde_json::Value::Object(obj) => {
            Ok(ElGamalCiphertext {
                c1: hex_to_ecpoint(obj["c1_hex"].as_str().unwrap_or(""))?,
                c2: hex_to_ecpoint(obj["c2_hex"].as_str().unwrap_or(""))?,
            })
        }
        _ => {
            console_log(&format!("obj_string_to_ct: parsed {:?}", val));
            Err("Invalid JSON object".to_string())
        }
    }
}

fn json_to_ct(json_str: &str) -> Result<ElGamalCiphertext, String> {
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    Ok(ElGamalCiphertext {
        c1: hex_to_ecpoint(val["c1_hex"].as_str().unwrap_or(""))?,
        c2: hex_to_ecpoint(val["c2_hex"].as_str().unwrap_or(""))?,
    })
}

fn ct_vec_to_json(cts: &[ElGamalCiphertext]) -> String {
    let arr: Vec<String> = cts.iter().map(ct_to_json).collect();
    format!("[{}]", arr.join(","))
}

fn scalar_vec_to_json(values: &[Scalar]) -> String {
    let encoded: Vec<String> = values.iter().map(scalar_to_hex).collect();
    serde_json::to_string(&encoded).unwrap_or_else(|_| "[]".to_string())
}

fn point_vec_to_json(values: &[EcPoint]) -> String {
    let encoded: Vec<String> = values.iter().map(ecpoint_to_hex).collect();
    serde_json::to_string(&encoded).unwrap_or_else(|_| "[]".to_string())
}

fn schnorr_proof_to_json(
    proof: &poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof<DefaultCurve>,
) -> String {
    format!(
        r#"{{"commitment_hex":"{}","responses_hex":{}}}"#,
        ecpoint_to_hex(&proof.commitment),
        scalar_vec_to_json(&proof.responses),
    )
}

fn bayer_groth_proof_to_json(
    proof: &poker_protocol::zk_shuffle::bayer_groth::BayerGrothShuffleProof<DefaultCurve>,
) -> String {
    let mexp = &proof.multi_exponentiation;
    let product = &proof.product;
    format!(
        r#"{{"c_permutation_hex":"{}","c_permuted_powers_hex":"{}","multi_exponentiation":{{"c_alpha_hex":"{}","c_beta_hex":"{}","ciphertext_0":{},"ciphertext_1":{},"alpha_response_hex":{},"commitment_response_hex":"{}","beta_hex":"{}","beta_blinding_response_hex":"{}","rerandomization_response_hex":"{}"}},"product":{{"c_d_hex":"{}","c_delta_hex":"{}","c_capital_delta_hex":"{}","a_response_hex":{},"b_response_hex":{},"r_response_hex":"{}","s_response_hex":"{}"}}}}"#,
        ecpoint_to_hex(&proof.c_permutation),
        ecpoint_to_hex(&proof.c_permuted_powers),
        ecpoint_to_hex(&mexp.c_alpha),
        ecpoint_to_hex(&mexp.c_beta),
        ct_generic_to_json(&mexp.ciphertext_0),
        ct_generic_to_json(&mexp.ciphertext_1),
        scalar_vec_to_json(&mexp.alpha_response),
        scalar_to_hex(&mexp.commitment_response),
        scalar_to_hex(&mexp.beta),
        scalar_to_hex(&mexp.beta_blinding_response),
        scalar_to_hex(&mexp.rerandomization_response),
        ecpoint_to_hex(&product.c_d),
        ecpoint_to_hex(&product.c_delta),
        ecpoint_to_hex(&product.c_capital_delta),
        scalar_vec_to_json(&product.a_response),
        scalar_vec_to_json(&product.b_response),
        scalar_to_hex(&product.r_response),
        scalar_to_hex(&product.s_response),
    )
}

fn shuffle_proof_to_json(proof: &poker_protocol::zk_shuffle::ShuffleProof) -> String {
    use poker_protocol::zk_shuffle::versioned::VersionedShuffleProof;

    match proof {
        VersionedShuffleProof::LegacyV1(proof) => format!(
            r#"{{"sum_c1_commit_hex":"{}","sum_c2_commit_hex":"{}","combined_schnorr_proof":{},"sum_c1_schnorr_proof":{},"sum_c2_schnorr_proof":{},"nonce_hex":"{}"}}"#,
            ecpoint_to_hex(&proof.sum_c1_commit),
            ecpoint_to_hex(&proof.sum_c2_commit),
            schnorr_proof_to_json(&proof.combined_schnorr_proof),
            schnorr_proof_to_json(&proof.sum_c1_schnorr_proof),
            schnorr_proof_to_json(&proof.sum_c2_schnorr_proof),
            scalar_to_hex(&proof.nonce),
        ),
        VersionedShuffleProof::BayerGrothV2(proof) => format!(
            r#"{{"version":2,"proof":{}}}"#,
            bayer_groth_proof_to_json(proof),
        ),
    }
}

fn json_to_ct_vec(json_str: &str) -> Result<Vec<ElGamalCiphertext>, String> {
    let arr: Vec<serde_json::Value> = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    let mut result:Vec<ElGamalCiphertext> = vec![];
    for v in arr {
        result.push(obj_string_to_ct(v)?);
    }
    Ok(result)
}

fn reveal_token_proof_to_json(proof: &RevealTokenProof<DefaultCurve>) -> String {
    format!(
        r#"{{"user_public_key_hex":"{}","commitment_t1_hex":"{}","commitment_t2_hex":"{}","response_s_hex":"{}","nonce_hex":"{}"}}"#,
        ecpoint_to_hex(&proof.user_public_key),
        ecpoint_to_hex(&proof.commitment_t1),
        ecpoint_to_hex(&proof.commitment_t2),
        scalar_to_hex(&proof.response_s),
        scalar_to_hex(&proof.nonce)
    )
}

fn json_to_reveal_token_proof(json_str: &str) -> Result<RevealTokenProof<DefaultCurve>, String> {
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    Ok(RevealTokenProof {
        user_public_key: hex_to_ecpoint(val["user_public_key"].as_str().unwrap_or(""))?,
        commitment_t1: hex_to_ecpoint(val["commitment_t1"].as_str().unwrap_or(""))?,
        commitment_t2: hex_to_ecpoint(val["commitment_t2"].as_str().unwrap_or(""))?,
        response_s: hex_to_scalar(val["response_s"].as_str().unwrap_or(""))?,
        nonce: hex_to_scalar(val["nonce"].as_str().unwrap_or(""))?,
    })
}

#[derive(Serialize, Deserialize)]
pub struct PlayerKeys {
    pub player_pk: String,
    pub sk: String,
    pub pk: String,
}

#[wasm_bindgen]
pub struct WasmClientPlayer {
    inner: ClientPlayer,
}

fn json_val_to_jsvalue(s: String) -> JsValue {
    JsValue::from_str(&s)
}

#[wasm_bindgen]
impl WasmClientPlayer {
    #[wasm_bindgen(constructor)]
    pub fn new(wallet_address: &str) -> WasmClientPlayer {
        console_log("Creating client player");
        WasmClientPlayer {
            inner: ClientPlayer::new_with_wallet_address(wallet_address),
        }
    }

    /// 根据钱包地址确定性生成密钥对（与 new 行为相同，显式命名）
    pub fn new_with_wallet_address(wallet_address: &str) -> WasmClientPlayer {
        console_log("Creating client player with wallet address");
        WasmClientPlayer {
            inner: ClientPlayer::new_with_wallet_address(wallet_address),
        }
    }

    /// 随机会话密钥（Part B 默认模式）：CSPRNG 生成，与钱包零派生关系。
    /// sk 经 get_sk_hex 存 localStorage，重载用 from_sk 恢复。
    pub fn new_random() -> WasmClientPlayer {
        WasmClientPlayer {
            inner: ClientPlayer::new(),
        }
    }

    /// 口令派生身份（Part B1.5，用户可选的可恢复模式）：同一口令在任何
    /// 设备派生出同一 (sk, pk)。KDF 参数冻结在 "zgame:player-key:v1"。
    /// 注意：不要用钱包助记词/恢复短语作为口令。
    pub fn new_with_passphrase(passphrase: &str) -> WasmClientPlayer {
        WasmClientPlayer {
            inner: ClientPlayer::new_with_passphrase(passphrase),
        }
    }

    pub fn from_sk(sk_hex: &str) -> Result<WasmClientPlayer, JsValue> {
        let sk = match hex_to_scalar(sk_hex) {
            Ok(s) => s,
            Err(e) => return Err(JsValue::from_str(&e)),
        };
        let pk = base_g() * &sk;
        Ok(WasmClientPlayer {
            inner: ClientPlayer { sk, pk },
        })
    }

    pub fn get_pk_hex(&self) -> String { ecpoint_to_hex(&self.inner.pk) }

    pub fn get_sk_hex(&self) -> String { scalar_to_hex(&self.inner.sk) }

    pub fn to_keys(&self) -> JsValue {
        let keys = PlayerKeys {
            player_pk: ecpoint_to_hex(&self.inner.pk),
            sk: scalar_to_hex(&self.inner.sk),
            pk: ecpoint_to_hex(&self.inner.pk),
        };
        match serde_wasm_bindgen::to_value(&keys) {
            Ok(v) => v,
            Err(_) => JsValue::NULL,
        }
    }

    pub fn generate_pk_proof(&self) -> JsValue {
        let proof = self.inner.generate_pk_proof();
        let s = format!(
            r#"{{"commitment_hex":"{}","response_hex":"{}"}}"#,
            ecpoint_to_hex(&proof.commitment),
            scalar_to_hex(&proof.response)
        );
        json_val_to_jsvalue(s)
    }

    pub fn decrypt_card(&self, ct_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let pt = self.inner.decrypt_card(&ct);
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn peek_own_card(&self, ct_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let pt = self.inner.peek_own_card(&ct);
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn peek_card(&self, ct_json: &str, tokens_json: &str, plain_cards_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens_arr: Vec<serde_json::Value> = match serde_json::from_str(tokens_json) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };

        use poker_protocol::z_poker::protocol::RevealToken as RT;
        let mut tokens: Vec<RT> = vec![];
        for tval in &tokens_arr {
            let encrypted_card = match json_to_ct(&tval.to_string()) {
                Ok(ct) => ct,
                Err(e) => return Err(JsValue::from_str(&e)),
            };
            let reveal_token = match hex_to_ecpoint(tval["reveal_token"].as_str().unwrap_or("")) {
                Ok(p) => p,
                Err(e) => return Err(JsValue::from_str(&e)),
            };
            let proof = match json_to_reveal_token_proof(&tval["proof"].to_string()) {
                Ok(p) => p,
                Err(e) => return Err(JsValue::from_str(&e)),
            };
            tokens.push(RT { user_public_key: hex_to_ecpoint(tval["user_public_key"].as_str().unwrap_or(""))?, encrypted_card, proof, reveal_token });
        }

        let pt_arr: Vec<String> = serde_json::from_str(plain_cards_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let plain_cards: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let pt = self.inner.peek_card(&ct, &tokens, &plain_cards).map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(ecpoint_to_hex(&pt.0))
    }

    pub fn generate_reveal_token(&self, ct_json: &str) -> Result<JsValue, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let token = self.inner.generate_reveal_token(&ct);

        let s = format!(
            r#"{{"encrypted_card":{},"reveal_token":"{}","proof":{}}}"#,
            ct_to_json(&token.encrypted_card),
            ecpoint_to_hex(&token.reveal_token),
            reveal_token_proof_to_json(&token.proof)
        );
        Ok(json_val_to_jsvalue(s))
    }

    pub fn batch_generate_reveal_token(&self, cts_json: &str) -> Result<JsValue, JsValue> {
        let cts = json_to_ct_vec(cts_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens = self.inner.batch_generate_reveal_token(&cts);

        let items: Vec<String> = tokens.iter().enumerate().map(|(i, token)| {
            format!(
                r#"{{"card_index":{},"encrypted_card":{},"reveal_token_proof":{},"reveal_token_hex":"{}"}}"#,
                i,
                ct_to_json(&token.encrypted_card),
                reveal_token_proof_to_json(&token.proof),
                ecpoint_to_hex(&token.reveal_token)
            )
        }).collect();
        Ok(json_val_to_jsvalue(format!("[{}]", items.join(","))))
    }

    pub fn verify_and_reveal_from_token(token_json: &str) -> Result<String, JsValue> {
        let val: serde_json::Value = match serde_json::from_str(token_json) {
            Ok(v) => v,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };
        let encrypted_card = match json_to_ct(&val["encrypted_card"].to_string()) {
            Ok(ct) => ct,
            Err(e) => return Err(JsValue::from_str(&e)),
        };
        let reveal_token = match hex_to_ecpoint(val["reveal_token"].as_str().unwrap_or("")) {
            Ok(p) => p,
            Err(e) => return Err(JsValue::from_str(&e)),
        };
        let proof = match json_to_reveal_token_proof(&val["proof"].to_string()) {
            Ok(p) => p,
            Err(e) => return Err(JsValue::from_str(&e)),
        };

        let token = poker_protocol::z_poker::protocol::RevealToken {
            user_public_key: hex_to_ecpoint(val["user_public_key_hex"].as_str().unwrap_or(""))?,
            encrypted_card,
            proof,
            reveal_token,
        };

        let pt = ClientPlayer::verify_and_reveal_from_token(&token)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn shuffle(&self, deck_encrypted_json: &str, agg_pk_hex: &str) -> Result<JsValue, JsValue> {
        let deck = json_to_ct_vec(deck_encrypted_json).map_err(|e| JsValue::from_str(&e))?;
        let agg_pk = hex_to_ecpoint(agg_pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let round = self.inner.shuffle(&deck, &agg_pk);

        let shuffle_proof_json = shuffle_proof_to_json(&round.proof);

        let s = format!(
            r#"{{"player_pk":"{}","input_cards":{},"output_cards":{},"shuffle_proof":{}}}"#,
            ecpoint_to_hex(&self.inner.pk),
            ct_vec_to_json(&round.input_cards),
            ct_vec_to_json(&round.output_cards),
            shuffle_proof_json,
        );
        Ok(json_val_to_jsvalue(s))
    }

    pub fn join_game_and_shuffle(
        &self,
        deck_encrypted_json: &str,
        agg_pk_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let deck = json_to_ct_vec(deck_encrypted_json).map_err(|e| JsValue::from_str(&e))?;
        let agg_pk = hex_to_ecpoint(agg_pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let round = self.inner.join_game_and_shuffle(&deck, &agg_pk);
        let ms = &round.mask_and_shuffle_round;
        let per_card_commitments_hex: Vec<String> = ms.remask_proof.per_card_commitments.iter()
            .map(ecpoint_to_hex).collect();
        let remask_proof_json = format!(
            r#"{{"per_card_commitments_hex":{},"commitment_pk_hex":"{}","response_hex":"{}","nonce_hex":"{}"}}"#,
            serde_json::to_string(&per_card_commitments_hex).unwrap_or("[]".to_string()),
            ecpoint_to_hex(&ms.remask_proof.commitment_pk),
            scalar_to_hex(&ms.remask_proof.response),
            scalar_to_hex(&ms.remask_proof.nonce),
        );

        let shuffle_proof_json = shuffle_proof_to_json(&ms.proof);

        let mask_and_shuffle_json = format!(
            r#"{{"mask_cards":{},"remask_proof":{},"output_cards":{},"shuffle_proof":{}}}"#,
            ct_vec_to_json(&ms.mask_cards),
            remask_proof_json,
            ct_vec_to_json(&ms.output_cards),
            shuffle_proof_json,
        );

        let proof = round.pk_ownership_proof;
        let pk_proof_json = format!(
            r#"{{"commitment_hex":"{}","response_hex":"{}"}}"#,
            ecpoint_to_hex(&proof.commitment),
            scalar_to_hex(&proof.response)
        );

        let join_game_and_shuffle_json = format!(
            r#"{{"pk_ownership_proof":{},"pk_hex":"{}","mask_and_shuffle_round":{}}}"#,
            pk_proof_json,
            round.pk_hex,
            mask_and_shuffle_json,
        );
        Ok(json_val_to_jsvalue(join_game_and_shuffle_json))
    }

    /// `excluded_indices_json`: JSON 数组，玩家自己手牌在牌组中的槽位
    /// （离开/弃牌剥层排除这些槽——剥层输出会公开 sk·c1 = reveal token，
    /// 不排除自己手牌等于向串谋者亮牌）。验证方从发牌状态推导同一集合。
    pub fn leave_game(
        &self,
        deck_encrypted_json: &str,
        excluded_indices_json: &str,
    ) -> Result<JsValue, JsValue> {
        let deck = json_to_ct_vec(deck_encrypted_json).map_err(|e| JsValue::from_str(&e))?;
        let excluded: Vec<usize> = serde_json::from_str(excluded_indices_json)
            .map_err(|e| JsValue::from_str(&format!("excluded indices JSON: {e}")))?;

        let round = self.inner.leave_game_with_exclusions(&deck, &excluded);

        let per_card_commitments_hex: Vec<String> = round.leave_proof.per_card_commitments.iter()
            .map(ecpoint_to_hex).collect();
        let leave_proof_json = format!(
            r#"{{"per_card_commitments_hex":{},"commitment_pk_hex":"{}","response_hex":"{}","nonce_hex":"{}"}}"#,
            serde_json::to_string(&per_card_commitments_hex).unwrap_or("[]".to_string()),
            ecpoint_to_hex(&round.leave_proof.commitment_pk),
            scalar_to_hex(&round.leave_proof.response),
            scalar_to_hex(&round.leave_proof.nonce),
        );

        let leave_game_json = format!(
            r#"{{"input_cards":{},"output_cards":{},"leave_proof":{}}}"#,
            ct_vec_to_json(&round.input_cards),
            ct_vec_to_json(&round.output_cards),
            leave_proof_json,
        );
        Ok(json_val_to_jsvalue(leave_game_json))
    }

    pub fn reveal_own_card(
        &self,
        hand_index: usize,
        hand_encrypted_json: &str,
        deck_plaintext_json: &str,
        agg_pk_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let hand = json_to_ct_vec(hand_encrypted_json).map_err(|e| JsValue::from_str(&e))?;

        let pt_arr: Vec<String> = match serde_json::from_str(deck_plaintext_json) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };
        let deck_pt: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let agg_pk = hex_to_ecpoint(agg_pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let token = self.inner.reveal_own_card(hand_index, &hand, &deck_pt, &agg_pk)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        let s = format!(
            r#"{{"encrypted_card":{},"reveal_token":"{}","proof":{}}}"#,
            ct_to_json(&token.encrypted_card),
            ecpoint_to_hex(&token.reveal_token),
            reveal_token_proof_to_json(&token.proof)
        );
        Ok(json_val_to_jsvalue(s))
    }

    pub fn reveal_community(&self, comm_plaintext_hex: &str) -> Result<JsValue, JsValue> {
        let comm_pt = hex_to_ecpoint(comm_plaintext_hex).map_err(|e| JsValue::from_str(&e))?;
        let token = self.inner.reveal_community(comm_pt);

        let s = format!(
            r#"{{"encrypted_card":{},"reveal_token":"{}","proof":{}}}"#,
            ct_to_json(&token.encrypted_card),
            ecpoint_to_hex(&token.reveal_token),
            reveal_token_proof_to_json(&token.proof)
        );
        Ok(json_val_to_jsvalue(s))
    }

    pub fn generate_expel_proof(
        &self,
        _hand_encrypted_json: &str,
        _agg_pk_hex: &str,
        _per_card_tokens_json: &str,
    ) -> Result<JsValue, JsValue> {
        Err(JsValue::from_str("generate_expel_proof is no longer supported"))
    }

    pub fn remask_card(&self, ct_json: &str, pk_hex: &str) -> Result<JsValue, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let pk = hex_to_ecpoint(pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let (remasked, _alpha) = self.inner.remask_card(&ct, &pk);
        Ok(json_val_to_jsvalue(ct_to_json(&remasked)))
    }

    pub fn distributed_decrypt(&self, ct_json: &str, tokens_hexes: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let token_hexes: Vec<String> = match serde_json::from_str(tokens_hexes) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };
        let tokens: Vec<EcPoint> = token_hexes.iter()
            .map(|h| hex_to_ecpoint(h))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let pt = self.inner.distributed_decrypt(&ct, &tokens);
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn distributed_decrypt_from_tokens(&self, ct_json: &str, tokens_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens_arr: Vec<serde_json::Value> = match serde_json::from_str(tokens_json) {
            Ok(arr) => arr,
            Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
        };

        use poker_protocol::z_poker::protocol::RevealToken as RT;
        let mut tokens: Vec<RT> = vec![];
        for tval in &tokens_arr {
            let encrypted_card = json_to_ct(&tval.to_string()).map_err(|e| JsValue::from_str(&e))?;
            let reveal_token = hex_to_ecpoint(tval["reveal_token"].as_str().unwrap_or(""))
                .map_err(|e| JsValue::from_str(&e))?;
            let proof = json_to_reveal_token_proof(&tval["proof"].to_string())
                .map_err(|e| JsValue::from_str(&e))?;
            tokens.push(RT { user_public_key: hex_to_ecpoint(tval["user_public_key"].as_str().unwrap_or(""))?, encrypted_card, proof, reveal_token });
        }

        let pt = ClientPlayer::distributed_decrypt_from_tokens(&ct, &tokens)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;
        Ok(ecpoint_to_hex(&pt))
    }

    pub fn mask_card(&self, plaintext_hex: &str, pk_hex: &str) -> Result<JsValue, JsValue> {
        let pt = hex_to_ecpoint(plaintext_hex).map_err(|e| JsValue::from_str(&e))?;
        let pk = hex_to_ecpoint(pk_hex).map_err(|e| JsValue::from_str(&e))?;

        let (encrypted, _r) = self.inner.mask_card(&pt, &pk);
        Ok(json_val_to_jsvalue(ct_to_json(&encrypted)))
    }

    pub fn decrypt_playing_card(&self, ct_json: &str, other_tokens_json: &str, deck_plaintext_json: &str) -> Result<String, JsValue> {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;
        let tokens_arr: Vec<serde_json::Value> = serde_json::from_str(other_tokens_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let mut other_tokens = Vec::new();
        for tval in &tokens_arr {
            let token_hex = tval.as_str().unwrap_or("");
            other_tokens.push(hex_to_ecpoint(token_hex).map_err(|e| JsValue::from_str(&e))?);
        }

        let pt_arr: Vec<String> = serde_json::from_str(deck_plaintext_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let deck_plaintext: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        self.inner.decrypt_playing_card(&ct, other_tokens, deck_plaintext)
            .map(|card| card.to_string())
            .ok_or_else(|| JsValue::from_str("Failed to decrypt playing card"))
    }

    pub fn decrypt_readable_card(&self, ct_json: &str, deck_plaintext_json: &str) -> Result<String, JsValue>  {
        let ct = json_to_ct(ct_json).map_err(|e| JsValue::from_str(&e))?;

        let pt_arr: Vec<String> = serde_json::from_str(deck_plaintext_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let deck_plaintext: Vec<Plaintext> = pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        self.inner.decrypt_readable_card(&ct, deck_plaintext)
        .map(|card| card.to_string())
        .ok_or_else(|| {
            // 诊断信息：帮助定位连续打牌场景下的解密失败原因
            // 主要触发点：relayer 未重建 player_assignments → 前端无 reveal_token → 链上 partial_decrypt_c2 错误
            console_log(&format!(
                "decrypt_readable_card failed: c1={} c2={} deck_plaintext_size={}",
                ecpoint_to_hex(&ct.c1),
                ecpoint_to_hex(&ct.c2),
                deck_plaintext_json.len()
            ));
            JsValue::from_str("Failed to decrypt readable card")
        })
    }

    pub fn reconstruct(
        &self,
        origin_cards_json: &str,
        user_readable_cards_json: &str,
        coefficient_hex: &str,
    ) -> Result<JsValue, JsValue> {
        let origin_pt_arr: Vec<String> = serde_json::from_str(origin_cards_json)
            .map_err(|e| JsValue::from_str(&format!("JSON error: {}", e)))?;
        let origin_cards: Vec<EcPoint> = origin_pt_arr.iter()
            .map(|s| hex_to_ecpoint(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| JsValue::from_str(&e))?;

        let user_readable_cards = json_to_ct_vec(user_readable_cards_json)
            .map_err(|e| JsValue::from_str(&e))?;

        let coefficient = hex_to_scalar(coefficient_hex)
            .map_err(|e| JsValue::from_str(&e))?;

        let result = self.inner.reconstruct(&origin_cards, &user_readable_cards, &coefficient)
            .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?;

        fn chaum_pedersen_proof_to_json(proof: &poker_protocol::zk_shuffle::reconstruction::ChaumPedersenDLEQProof<DefaultCurve>) -> String {
            format!(
                r#"{{"commitment_a_hex":"{}","commitment_b_hex":"{}","response_hex":"{}"}}"#,
                ecpoint_to_hex(&proof.commitment_a),
                ecpoint_to_hex(&proof.commitment_b),
                scalar_to_hex(&proof.response)
            )
        }

        fn swap_out_card_proof_to_json(proof: &poker_protocol::zk_shuffle::reconstruction::SwapOutCardProof<DefaultCurve>) -> String {
            format!(
                r#"{{"user_readable_card":{},"swap_out_card":{},"chaum_pedersen_proof":{}}}"#,
                ct_generic_to_json(&proof.user_readable_card),
                ct_generic_to_json(&proof.swap_out_card),
                chaum_pedersen_proof_to_json(&proof.chaum_pedersen_proof)
            )
        }

        let swap_out_proofs_json: Vec<String> = result.proof.swap_out_cards_proofs.iter()
            .map(swap_out_card_proof_to_json).collect();

        let ordered = &result.proof.ordered_encryption_proof;

        let proof_json = format!(
            r#"{{"version":2,"swap_out_cards_proofs":[{}],"padded_swap_cards":{},"padded_swap_shuffle_proof":{},"ordered_encryption_proof":{{"commitment_g_hex":{},"commitment_pk_hex":{},"responses_hex":{}}}}}"#,
            swap_out_proofs_json.join(","),
            ct_vec_to_json(&result.proof.padded_swap_cards),
            bayer_groth_proof_to_json(&result.proof.padded_swap_shuffle_proof),
            point_vec_to_json(&ordered.commitment_g),
            point_vec_to_json(&ordered.commitment_pk),
            scalar_vec_to_json(&ordered.responses),
        );

        let s = format!(
            r#"{{"output_cards":{},"swap_cards":{},"proof":{}}}"#,
            ct_vec_to_json(&result.output_cards),
            ct_vec_to_json(&result.swap_cards),
            proof_json
        );
        Ok(json_val_to_jsvalue(s))
    }
}

#[wasm_bindgen]
pub fn compute_aggregate_key(pk_hexes: &str) -> Result<String, JsValue> {
    let pks: Vec<String> = match serde_json::from_str(pk_hexes) {
        Ok(arr) => arr,
        Err(e) => return Err(JsValue::from_str(&format!("JSON error: {}", e))),
    };

    let mut agg = EcPoint::identity();
    for pk_hex in &pks {
        let pk = match hex_to_ecpoint(pk_hex) {
            Ok(p) => p,
            Err(e) => return Err(JsValue::from_str(&e)),
        };
        agg = agg + pk;
    }
    Ok(ecpoint_to_hex(&agg))
}

#[wasm_bindgen]
pub fn encrypt_plaintext(plaintext_hex: &str, pk_hex: &str) -> Result<JsValue, JsValue> {
    let pt = hex_to_ecpoint(plaintext_hex).map_err(|e| JsValue::from_str(&e))?;
    let pk = hex_to_ecpoint(pk_hex).map_err(|e| JsValue::from_str(&e))?;
    let r = Scalar::random(&mut OsRng);
    let ct = ElGamalCiphertext::encrypt(&pt, &pk, &r);
    Ok(json_val_to_jsvalue(ct_to_json(&ct)))
}


/// #16 抗审查动作签名：以牌局身份 SK 对 (table_id, hand_id, seq, action,
/// amount) 签名（Starknet-Poseidon 域分离同族：`zgame.action-sig.v2`，与
/// texas 服务端 `game_action.rs` 验签口径逐字节一致）。返回 `{ r_hex, s_hex }`
/// ——客户端把 `(seq, r_hex, s_hex)` 附在动作消息上；服务端按座位 pk 验签。
/// v2：hand_id 进签名域，签名升级为逐手归属凭证（endorsement 通道已删除）。
///
/// `sk_hex` 为 ClientPlayer 的 sk（32 字节大端 hex，localStorage `sk` 同源）；
/// `hand_id` 为开局广播分配的本手 id。
#[wasm_bindgen]
pub fn sign_action(
    sk_hex: &str,
    table_id: u32,
    hand_id: u32,
    seq: u64,
    action: &str,
    amount: u64,
) -> Result<JsValue, JsValue> {
    // #16：游戏身份 SK 在 Stark curve 上（与座位 pk 同域）
    let sk_bytes = hex::decode(sk_hex).map_err(|e| JsValue::from_str(&format!("sk hex: {e}")))?;
    let sk = <poker_protocol::crypto::curve::StarkCurve as poker_protocol::crypto::curve::Curve>::Scalar::from_canonical_bytes(&sk_bytes)
        .ok_or_else(|| JsValue::from_str("sk out of range"))?;
    let (r_hex, s_hex) = poker_protocol::z_poker::protocol::sign_game_action(
        &sk, table_id, hand_id, seq, action, amount, &mut rand_core::OsRng,
    );
    serde_json::to_value(serde_json::json!({ "r_hex": r_hex, "s_hex": s_hex }))
        .map_err(|e| JsValue::from_str(&format!("serialize error: {e}")))
        .map(|v| serde_wasm_bindgen::to_value(&v).unwrap_or(JsValue::NULL))
}


// =============================================================================
// P1-2 会话委托：VM 层交易签名的会话密钥（2026-09-10）
//
// 与 ElGamal 会话密钥（WasmClientPlayer）平行的第二把会话钥：它是玩家在
// VM/链运行时（TableRuntime）交易签名的**授权锚**——买入时经 vault
// `set_session_tx_pk`（非私密路径玩家 multicall / 私密路径 anonymizer 同笔
// 私交易 `set_session_tx_pk_for`）登记到链上，join 时随 payload 声明、
// 服务端 view 对拍核验。重连只需 localStorage 恢复（get_sk_hex/from_sk），
// 零钱包交互。
//
// 签名格式与 poker_l1 `signature::stark_scheme` 完全一致（Stark Schnorr，
// 确定性 nonce）：sig = R_compressed(32B) ‖ s(32B)。以下两个域分隔常量
// 必须与 poker_l1/src/signature/stark_scheme.rs 保持逐字节同步。
// =============================================================================

const TX_SCHNORR_CHALLENGE_DOMAIN: &[u8] = b"zchain.schnorr.v1";
const TX_SCHNORR_NONCE_DOMAIN: &[u8] = b"zchain.schnorr.nonce.v1";

/// VM 交易会话密钥（随机新鲜钥，与钱包地址零派生关系）。
#[wasm_bindgen]
pub struct WasmTxSession {
    sk: Scalar,
    pk: EcPoint,
}

#[wasm_bindgen]
impl WasmTxSession {
    /// 生成随机会话密钥（进入牌桌前调用一次；sk 存 localStorage）。
    #[wasm_bindgen(constructor)]
    pub fn generate() -> WasmTxSession {
        let sk = Scalar::random(&mut OsRng);
        let pk = base_g() * &sk;
        WasmTxSession { sk, pk }
    }

    /// 从 localStorage 的 sk hex 恢复（重连路径——零钱包交互）。
    pub fn from_sk(sk_hex: &str) -> Result<WasmTxSession, JsValue> {
        let sk = hex_to_scalar(sk_hex).map_err(|e| JsValue::from_str(&e))?;
        let pk = base_g() * &sk;
        Ok(WasmTxSession { sk, pk })
    }

    /// 会话公钥（32B 压缩点 hex）——join payload 的 `sessionTxPk` 字段与
    /// 链上登记 felt 使用同一编码。
    pub fn get_pk_hex(&self) -> String {
        hex::encode(self.pk.compress().as_ref())
    }

    /// 会话私钥 hex（localStorage 持久化）。
    pub fn get_sk_hex(&self) -> String {
        scalar_to_hex(&self.sk)
    }

    /// Stark Schnorr 签名（msg_hash = 32B hex；返回 64B 签名的 hex）——
    /// 消息哈希公式见 poker_l1 `dispatch::tx_message_hash`（客户端须用
    /// 同一公式构造待签哈希）。
    pub fn sign(&self, msg_hash_hex: &str) -> Result<String, JsValue> {
        let hash_bytes = hex::decode(msg_hash_hex.trim_start_matches("0x"))
            .map_err(|e| JsValue::from_str(&format!("Invalid msg hash hex: {e}")))?;
        if hash_bytes.len() != 32 {
            return Err(JsValue::from_str("msg hash must be 32 bytes"));
        }
        let mut msg = [0u8; 32];
        msg.copy_from_slice(&hash_bytes);

        // 与 stark_scheme::sign 同构：确定性 nonce + 域分离挑战。
        let mut nonce_input = Vec::with_capacity(TX_SCHNORR_NONCE_DOMAIN.len() + 64);
        nonce_input.extend_from_slice(TX_SCHNORR_NONCE_DOMAIN);
        nonce_input.extend_from_slice(&self.sk.as_bytes());
        nonce_input.extend_from_slice(&msg);
        let r = poker_protocol::crypto::hash_to_scalar(&nonce_input);
        let big_r = base_g() * &r;
        let e = schnorr_challenge(&big_r, &self.pk, &msg);
        let s = r + e * self.sk;

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(big_r.compress().as_ref());
        sig[32..].copy_from_slice(&s.to_bytes_be());
        Ok(hex::encode(sig))
    }
}

/// Schnorr 挑战标量（与 stark_scheme::schnorr_challenge 同构）。
fn schnorr_challenge(big_r: &EcPoint, pk: &EcPoint, msg_hash: &[u8; 32]) -> Scalar {
    let mut buf = Vec::with_capacity(TX_SCHNORR_CHALLENGE_DOMAIN.len() + 96);
    buf.extend_from_slice(TX_SCHNORR_CHALLENGE_DOMAIN);
    buf.extend_from_slice(big_r.compress().as_ref());
    buf.extend_from_slice(pk.compress().as_ref());
    buf.extend_from_slice(msg_hash);
    poker_protocol::crypto::hash_to_scalar(&buf)
}

#[cfg(test)]
mod curve_hex_tests {
    use super::*;

    /// 2026-09-07 回归：hex_to_ecpoint 曾按 BLS12-381 时代断言 48 字节，
    /// Stark 压缩点 33 字节 → 浏览器洗牌全挂（2026-09-06 重建 pkg 首次
    /// 把遗留代码编进产物后爆发）。roundtrip 必须闭环。
    #[test]
    fn ecpoint_hex_roundtrip() {
        use poker_protocol::crypto::curve::{Curve, CurvePoint, CurveScalar};
        let sk = Scalar::from_u64(12345);
        let p = <DefaultCurve as Curve>::base_g() * sk;
        let hex = ecpoint_to_hex(&p);
        assert_eq!(hex.len(), 64, "32 bytes = 64 hex chars");
        let back = hex_to_ecpoint(&hex).expect("roundtrip");
        assert_eq!(back, p);
    }

    #[test]
    fn ecpoint_hex_rejects_wrong_length() {
        assert!(hex_to_ecpoint(&"00".repeat(48)).is_err(), "BLS-era 48B must be rejected");
        assert!(hex_to_ecpoint(&"00".repeat(33)).is_err(), "bad point rejected");
    }

    /// 2026-09-08 回归：客户端签名 → 服务端验签的全链路（hex 编码穿过
    /// wasm/serde 边界）。线上复现：签名已到达服务端但 verify_action_sig
    /// 失败（hand 1788808419，seq 82 的 check）。
    #[test]
    fn sign_action_verifies_through_hex() {
        let player = ClientPlayer::new();
        let pk_hex = ecpoint_to_hex(&player.pk);
        let sk_hex = scalar_to_hex(&player.sk);
        // 复刻 wasm sign_action 的内部路径（sk hex → scalar → sign）
        let sk_bytes = hex::decode(&sk_hex).expect("sk hex");
        let sk = <Scalar as CurveScalar>::from_canonical_bytes(&sk_bytes).expect("sk range");
        let (r_hex, s_hex) = poker_protocol::z_poker::protocol::sign_game_action(
            &sk, 1, 1788808419, 82, "check", 0, &mut rand_core::OsRng,
        );
        assert!(
            poker_protocol::z_poker::protocol::verify_game_action_hex(
                &pk_hex, 1, 1788808419, 82, "check", 0, &r_hex, &s_hex
            ),
            "sign→verify roundtrip through hex must hold (domain: table_id, hand_id, seq, action, amount)"
        );
    }

    /// P1-2 会话委托：密钥恢复一致 + 签名确定性（与 poker_l1 stark_scheme
    /// 同公式——同 sk 同消息必得同签名，重放/对拍基准）。
    #[test]
    fn tx_session_restore_and_deterministic_sign() {
        let session = WasmTxSession::generate();
        let sk_hex = session.get_sk_hex();
        let pk_hex = session.get_pk_hex();
        let restored = WasmTxSession::from_sk(&sk_hex).expect("restore");
        assert_eq!(restored.get_pk_hex(), pk_hex, "restore derives same pk");

        let msg = [0x42u8; 32];
        let sig1 = session.sign(&hex::encode(msg)).expect("sign");
        let sig2 = restored.sign(&hex::encode(msg)).expect("sign");
        assert_eq!(sig1, sig2, "deterministic nonce: same sk+msg => same sig");
        assert_eq!(sig1.len(), 128, "64-byte signature hex");
        // 不同消息不同签名
        let other = session.sign(&hex::encode([0x43u8; 32])).expect("sign");
        assert_ne!(sig1, other);
    }
}

