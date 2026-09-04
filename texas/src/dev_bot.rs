//! dev 联调机器人（`STARKNET_RPC_URL` 配置下的本地/测试网端到端验证用）。
//!
//! POST /api/dev/bot  body: {"wallet": "0x…", "depositTxHash": "0x…", "seatId": n}
//! 启动一个进程内机器人玩家：与真实前端完全相同的客户端证明生成代码
//! （poker_protocol::ClientPlayer）+ 相同的 state 层调用路径
//! （join_player_and_shuffle / submit_verified_shuffle_for_pk /
//!  submit_reveal_tokens_for_pk / process_action），从而把
//! 「真实 deposit 校验 → 牌局 → 镜像证明 → 结算上链」在运行时完整走通。

use serde_json::{json, Value};
use std::time::Duration;

use poker_protocol::z_poker::protocol::ClientPlayer;

use crate::auth;
use crate::models::{Database, User};
use crate::pokergame::player::{GamePkHex, Player, WalletAddress};
use crate::pokergame::game_state::{ElGamalCiphertextJson, MaskAndShuffleRoundJson, PkProofJson, ShuffleProofJson};
use crate::socket::SocketState;

use poker_protocol::crypto::{hash_to_scalar, ElGamalCiphertext};

// ---- JSON 序列化辅助（与 client-wasm 逐字节一致的线格式）----

fn ec_hex(p: &poker_protocol::crypto::EcPoint) -> String {
    poker_protocol::z_poker::convert::ecpoint_to_hex(p)
}
fn sc_hex(s: &poker_protocol::crypto::Scalar) -> String {
    poker_protocol::z_poker::convert::scalar_to_hex(s)
}
fn ct_json(ct: &ElGamalCiphertext) -> Value {
    json!({"c1_hex": ec_hex(&ct.c1), "c2_hex": ec_hex(&ct.c2)})
}
fn ct_vec_json(cts: &[ElGamalCiphertext]) -> Value {
    Value::Array(cts.iter().map(ct_json).collect())
}
fn scalar_vec_json(vs: &[poker_protocol::crypto::Scalar]) -> Value {
    Value::Array(vs.iter().map(|v| Value::String(sc_hex(v))).collect())
}
fn point_vec_json(vs: &[poker_protocol::crypto::EcPoint]) -> Value {
    Value::Array(vs.iter().map(|v| Value::String(ec_hex(v))).collect())
}

/// 把 typed 洗牌证明转成与前端 wasm 输出一致的 JSON 线格式。
fn shuffle_proof_json(proof: &poker_protocol::zk_shuffle::ShuffleProof) -> Value {
    use poker_protocol::zk_shuffle::versioned::VersionedShuffleProof;
    match proof {
        VersionedShuffleProof::BayerGrothV2(p) => {
            let m = &p.multi_exponentiation;
            let pr = &p.product;
            json!({
                "version": 2,
                "proof": {
                    "c_permutation_hex": ec_hex(&p.c_permutation),
                    "c_permuted_powers_hex": ec_hex(&p.c_permuted_powers),
                    "multi_exponentiation": {
                        "c_alpha_hex": ec_hex(&m.c_alpha),
                        "c_beta_hex": ec_hex(&m.c_beta),
                        "ciphertext_0": ct_json(&m.ciphertext_0),
                        "ciphertext_1": ct_json(&m.ciphertext_1),
                        "alpha_response_hex": scalar_vec_json(&m.alpha_response),
                        "commitment_response_hex": sc_hex(&m.commitment_response),
                        "beta_hex": sc_hex(&m.beta),
                        "beta_blinding_response_hex": sc_hex(&m.beta_blinding_response),
                        "rerandomization_response_hex": sc_hex(&m.rerandomization_response),
                    },
                    "product": {
                        "c_d_hex": ec_hex(&pr.c_d),
                        "c_delta_hex": ec_hex(&pr.c_delta),
                        "c_capital_delta_hex": ec_hex(&pr.c_capital_delta),
                        "a_response_hex": scalar_vec_json(&pr.a_response),
                        "b_response_hex": scalar_vec_json(&pr.b_response),
                        "r_response_hex": sc_hex(&pr.r_response),
                        "s_response_hex": sc_hex(&pr.s_response),
                    },
                }
            })
        }
        VersionedShuffleProof::LegacyV1(_) => Value::Null,
    }
}

fn parse_proof_json(v: &Value) -> Result<ShuffleProofJson, String> {
    serde_json::from_value(v.clone()).map_err(|e| format!("shuffle proof json: {e}"))
}

// ---- bot 任务 ----

pub async fn start_bot(
    state: std::sync::Arc<SocketState>,
    wallet: String,
    deposit_tx: String,
    seat_id: u32,
) -> Result<(), String> {
    eprintln!("[bot] task started, wallet={wallet}");
    let user_id = format!("wallet:{wallet}");
    if state.db.find_user_by_id(&user_id).await.is_none() {
        state.db.save_user(&User {
            id: user_id.clone(),
            name: format!("bot-{wallet}"),
            address: wallet.clone(),
            created: chrono::Utc::now().to_rfc3339(),
            locked_chips: 0,
        }).await.map_err(|e| e)?;
    }

    eprintln!("[bot] verifying deposit on-chain…");
    // 真实链上买入校验（fetch 回执 + vault chip_balance）
    crate::starknet::chips::verify_deposit(&deposit_tx, &wallet, 100)
        .await
        .map_err(|e| format!("deposit verify: {e}"))?;

    eprintln!("[bot] deposit verified OK");
    let token = auth::create_token(&user_id, &state.config.jwt_secret, state.config.jwt_token_expires_in)
        .map_err(|e| format!("token: {e}"))?;

    eprintln!("[bot] deposit verified OK");
    let player = ClientPlayer::new();

    // 进程内 bot 的认可私钥注册（DAPV 结算需要所有参与玩家的认可；
    // 真实客户端的认可私钥在浏览器 localStorage，bot 的托管在服务器）。
    {
        use poker_protocol::crypto::curve::{Curve, CurveScalar};
        use poker_protocol::crypto::curve::StarkCurve;
        let sk = <StarkCurve as Curve>::Scalar::random(&mut rand::rngs::OsRng);
        crate::starknet::hooks::register_bot_endorsement_key(&wallet, sk);
        eprintln!("[bot] endorsement key registered for {wallet}");
    }
    let my_addr = match crate::starknet::mirror::TableMirror::addr_from_starknet(&wallet) {
        Some(a) => a,
        None => return Err("bad wallet for mirror".into()),
    };
    let my_seat_u8 = 0u8; // placeholder：真实座位由 mirror 座位表查得
    // Starknet 镜像：预缓冲 join（真实 pk 所有权证明），下一手 start_preflop_shuffle 应用
    let pk_proof_obj = player.generate_pk_proof();
    let proof_bytes = crate::relayer::proof_bytes::serialize_pk_ownership_proof(&pk_proof_obj);
    let pk_hex = poker_protocol::z_poker::convert::ecpoint_to_hex(&player.pk);
    crate::starknet::hooks::mirror_buffer_join_raw(1, &wallet, &pk_hex, proof_bytes);

    // 真实链上买入交易已发生（verify_deposit 通过）；
    // SIT_DOWN_V2 路径的入座（与 WS handler 相同的 state 方法）。
    let _pk_proof_json: PkProofJson = {
        let proof = player.generate_pk_proof();
        serde_json::from_value(json!({
            "commitment_hex": ec_hex(&proof.commitment),
            "response_hex": sc_hex(&proof.response),
        })).map_err(|e| format!("pk proof json: {e}"))?
    };

    // 读取当前 deck 并生成 join+shuffle 轮（真实客户端证明）
    let deck_json: Vec<ElGamalCiphertextJson> = {
        let gs = state.state.read().await;
        let table = gs.tables.get(&1).ok_or("table 1 missing")?;
        let deck: Vec<ElGamalCiphertextJson> = table
            .deck_encrypted()
            .iter()
            .map(|ct| ElGamalCiphertextJson::from_ciphertext(ct))
            .collect();
        deck
    };
    let deck_cts: Vec<ElGamalCiphertext> = deck_json
        .iter()
        .map(|c| c.to_ciphertext())
        .collect::<Result<Vec<_>, _>>()?;
    let agg_pk = {
        let gs = state.state.read().await;
        gs.tables.get(&1)
            .map(|t| poker_protocol::crypto::EcPoint::from(t.mental_poker_game.key_manager.get_aggregated_pk()))
            .ok_or("aggregate pk")?
    };

    let round = player.join_game_and_shuffle(&deck_cts, &agg_pk);
    let mask_and_shuffle: MaskAndShuffleRoundJson = {
        let ms = &round.mask_and_shuffle_round;
        serde_json::from_value(json!({
            "mask_cards": ct_vec_json(&ms.mask_cards),
            "output_cards": ct_vec_json(&ms.output_cards),
            "remask_proof": {
                "per_card_commitments_hex": point_vec_json(&ms.remask_proof.per_card_commitments),
                "commitment_pk_hex": ec_hex(&ms.remask_proof.commitment_pk),
                "response_hex": sc_hex(&ms.remask_proof.response),
                "nonce_hex": sc_hex(&ms.remask_proof.nonce),
            },
            "shuffle_proof": shuffle_proof_json(&ms.proof),
        })).map_err(|e| format!("round json: {e}"))?
    };
    let pk_proof_full: PkProofJson = serde_json::from_value(json!({
        "commitment_hex": ec_hex(&round.pk_ownership_proof.commitment),
        "response_hex": sc_hex(&round.pk_ownership_proof.response),
    })).map_err(|e| format!("pk proof full: {e}"))?;

    let bot_player = Player {
        socket_id: format!("bot-{seat_id}"),
        id: user_id.clone(),
        name: format!("bot-{seat_id}"),
        bankroll: 0,
        wallet_address: WalletAddress(wallet.clone()),
    };

    eprintln!("[bot] payload built, joining…");
    let join_res = state
        .join_player_and_shuffle(
            1,
            bot_player,
            player.pk.clone(),
            pk_proof_full,
            Some(mask_and_shuffle),
            seat_id,
            100,
        )
        .await;

    // 无论新入座还是已在座，都确保 game_loop 运行（推动洗牌/揭牌/下注/结算）
    let io_missing = crate::socket::get_socket_io().is_none();
    eprintln!("[bot] socket_io present = {}", !io_missing);
    if let Some(io) = crate::socket::get_socket_io() {
        state.start_game_loop(io, std::sync::Arc::clone(&state), 1).await;
        eprintln!("[bot] start_game_loop called");
    }
    // 已在座（PlayerAlreadyInGame）时重新挂载驱动循环而非退出——
    // 否则 bot 重启后 game loop 不再被拉起，牌桌永久停摆。
    let joined = match join_res {
        Ok(j) => Some(j),
        Err(e) if format!("{e:?}").contains("PlayerAlreadyInGame") => {
            println!("[bot {seat_id}] already in game — reattaching drive loop");
            None
        }
        Err(e) => return Err(format!("join: {e:?}")),
    };
    let _ = joined;
    println!("[bot {seat_id}] on table with real deposit tx {deposit_tx}");

    // 启动 game_loop（与 WS SIT_DOWN_V2 handler 相同；推进洗牌/reveal/下注/结算）
    if let Some(io) = crate::socket::get_socket_io() {
        state.start_game_loop(io, std::sync::Arc::clone(&state), 1).await;
    }
    eprintln!("[bot] joined, entering drive loop…");

    let seat_id_num = seat_id as u32;
    // 驱动循环：轮到 bot 时生成真实证明并提交
    let started = std::time::Instant::now();
    let mut step = 0usize;
    // 循环时长：默认 600s；BOT_LOOP_SECS 可覆盖——0 = 无限循环（联调
    // 常驻，联调环境 texas/.env 默认 0），避免 bot 过期导致桌面凑不齐
    // 人数、新用户买入后永远不开局。
    let loop_secs: u64 = std::env::var("BOT_LOOP_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600);
    let unlimited = loop_secs == 0;
    while unlimited || started.elapsed().as_secs() < loop_secs {
        tokio::time::sleep(Duration::from_millis(700)).await;

        // ---- 方案A：mirror 由游戏层接受点单点驱动，bot 不再平行直驱。----
        // bot 通过下方 WS 流程正常打牌（洗牌/reveal/下注），游戏层把这些
        // 已验证事件同步派发给 poker_l1 VM；ShowdownDisplay 推进与结算
        // 重试由 game_loop tick 负责。


        step += 1;
        eprintln!("[bot] step {step}");
        let gs = state.state.read().await;
        let Some(table) = gs.tables.get(&1) else { continue };

        // 洗牌轮到自己
        let shuffle_active = table.shuffle_state.is_active();
        if step % 3 == 0 {
            eprintln!("[bot] step {step}: shuffle_active={shuffle_active} phase={:?} current={:?} round={:?} reveal_active={} turn={:?}",
                table.shuffle_state.phase,
                table.shuffle_state.current_player_pk,
                table.round_state(),
                table.reveal_token_state.is_active(),
                table.turn());
        }
        if shuffle_active {
            let shuffle_state = &table.shuffle_state;
            let mine = shuffle_state.current_player_pk.as_ref() == Some(&GamePkHex(pk_hex.clone()))
                && !shuffle_state.completed_players.contains(&GamePkHex(pk_hex.clone()));
            if mine {
                // 在 drop(gs) 前捕获（table 借用 gs）
                // 2026-09-03：开局洗牌统一纯 shuffle —— 已注册玩家的层由每手
                // 基线 (G, m+agg) 预置包含，remask（join 轮）是重复加层 →
                // 牌组公钥超出 Σsk → 物化污染（双真人线上复现）。
                // join 轮仅保留给入座场景（join_player_and_shuffle）。
                let needs_join_layer = false;
                drop(gs);
                let deck: Vec<ElGamalCiphertextJson> = {
                    let gs = state.state.read().await;
                    gs.tables.get(&1).map(|t| {
                        t.deck_encrypted().iter()
                            .map(|ct| ElGamalCiphertextJson::from_ciphertext(ct))
                            .collect()
                    }).unwrap_or_default()
                };
                let deck_cts: Vec<ElGamalCiphertext> = deck.iter()
                    .map(|c| c.to_ciphertext()).collect::<Result<_, _>>()?;
                let agg = {
                    let gs = state.state.read().await;
                    gs.tables.get(&1)
                        .map(|t| poker_protocol::crypto::EcPoint::from(t.mental_poker_game.key_manager.get_aggregated_pk()))
                };
                let Some(agg) = agg else { continue };
                // 与 SHUFFLE_NOTICE 的 needs_join_layer 语义保持一致：
                // 非 Reconstruct 阶段且未贡献过层的玩家必须走 join 语义
                // （remask 自身层 + shuffle），纯 re_encrypt 会让牌组份额失衡。
                let submit = if needs_join_layer {
                    let own_pk = player.pk;
                    let curr_share_pk = agg - own_pk;
                    let join_round = player.join_game_and_shuffle(&deck_cts, &curr_share_pk);
                    let ms = &join_round.mask_and_shuffle_round;
                    let remask_json = serde_json::json!({
                        "per_card_commitments_hex": ms.remask_proof.per_card_commitments.iter()
                            .map(poker_protocol::z_poker::convert::ecpoint_to_hex)
                            .collect::<Vec<_>>(),
                        "commitment_pk_hex": poker_protocol::z_poker::convert::ecpoint_to_hex(&ms.remask_proof.commitment_pk),
                        "response_hex": poker_protocol::z_poker::convert::scalar_to_hex(&ms.remask_proof.response),
                        "nonce_hex": poker_protocol::z_poker::convert::scalar_to_hex(&ms.remask_proof.nonce),
                    });
                    let out_json: Vec<ElGamalCiphertextJson> = ms.output_cards.iter()
                        .map(|ct| ElGamalCiphertextJson::from_ciphertext(ct)).collect();
                    let proof_value = shuffle_proof_json(&ms.proof);
                    state
                        .submit_verified_shuffle_for_pk(1, &GamePkHex(pk_hex.clone()), Player {
                            socket_id: format!("bot-{seat_id}-r"),
                            id: user_id.clone(),
                            name: format!("bot-{seat_id}"),
                            bankroll: 0,
                            wallet_address: WalletAddress(wallet.clone()),
                        }, out_json, Some(parse_proof_json(&proof_value)?), Some(MaskAndShuffleRoundJson {
                            mask_cards: ms.mask_cards.iter()
                                .map(|ct| ElGamalCiphertextJson::from_ciphertext(ct)).collect(),
                            output_cards: ms.output_cards.iter()
                                .map(|ct| ElGamalCiphertextJson::from_ciphertext(ct)).collect(),
                            remask_proof: serde_json::from_value(remask_json).map_err(|e| e.to_string())?,
                            shuffle_proof: parse_proof_json(&proof_value)?,
                        }))
                        .await
                } else {
                    let round = player.shuffle(&deck_cts, &agg);
                    let out_json: Vec<ElGamalCiphertextJson> = round.output_cards.iter()
                        .map(|ct| ElGamalCiphertextJson::from_ciphertext(ct)).collect();
                    let proof_value = shuffle_proof_json(&round.proof);
                    state
                        .submit_verified_shuffle_for_pk(1, &GamePkHex(pk_hex.clone()), Player {
                            socket_id: format!("bot-{seat_id}-r"),
                            id: user_id.clone(),
                            name: format!("bot-{seat_id}"),
                            bankroll: 0,
                            wallet_address: WalletAddress(wallet.clone()),
                        }, out_json, Some(parse_proof_json(&proof_value)?), None)
                        .await
                };
                if let Err(e) = submit {
                    println!("[bot {seat_id}] shuffle submit failed: {e}");
                } else {
                    println!("[bot {seat_id}] shuffle submitted");
                }
                continue;
            }
            continue;
        }
        drop(gs);

        // reveal 阶段：仅在「pending 包含我 && completed 未包含我」时提交一次。
        // 已提交过（completed 含我）则等待服务器推进到下注，不再重复提交。
        if let Some(tokens) = pending_reveal_tokens(&state, &pk_hex, &player).await? {
            let already_done = {
                let gs = state.state.read().await;
                gs.tables.get(&1)
                    .and_then(|t| t.reveal_token_state.completed_players
                        .iter().find(|p| p.0 == pk_hex))
                    .is_some()
            };
            if already_done {
                eprintln!("[bot {seat_id}] reveal already completed for me; waiting for betting");
                tokio::time::sleep(Duration::from_millis(700)).await;
                continue;
            }
            if let Err(e) = state.submit_reveal_tokens_for_pk(1, &GamePkHex(pk_hex.clone()), tokens.clone()).await {
                println!("[bot {seat_id}] reveal submit failed: {e}");
                continue;
            }
            println!("[bot {seat_id}] reveal tokens submitted ({})", tokens.len());
            // 与 WS handler 相同：token 提交成功后标记该玩家 reveal 完成
            if let Err(e) = state.mark_reveal_complete_for_pk(1, &GamePkHex(pk_hex.clone())).await {
                println!("[bot {seat_id}] mark reveal complete failed: {e}");
            }
            continue;
        }

        // 下注轮到自己
        // 下注轮到自己：面对未跟平的下注（盲注差）call，否则 check
        let seat_id_num = seat_id as u32;
        let (mut do_call, mut do_check) = (false, false);
        {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&1) {
                let betting = matches!(table.round_state(),
                    crate::pokergame::table::RoundState::PreFlop
                    | crate::pokergame::table::RoundState::Flop
                    | crate::pokergame::table::RoundState::Turn
                    | crate::pokergame::table::RoundState::River);
                let my_turn = table.turn().and_then(|tid| table.seats().get(&tid).map(|s| s.player.as_ref().map(|p| p.pk_hex.0 == pk_hex).unwrap_or(false))).unwrap_or(false);
                if betting && my_turn {
                    // 两人桌：取另一在座玩家的 bet
                    let other_bet = table.local_seats.iter()
                        .filter(|(sid, s)| **sid != seat_id_num && s.player.is_some() && !s.folded)
                        .map(|(_, s)| s.bet)
                        .max()
                        .unwrap_or(0);
                    let my_bet = table.local_seats.get(&seat_id_num).map(|s| s.bet).unwrap_or(0);
                    if other_bet > my_bet { do_call = true; } else { do_check = true; }
                }
            }
        }
        if do_call {
            if let Some(io) = crate::socket::get_socket_io() {
                let req = crate::pokergame::table::ActionRequest { pk_hex: GamePkHex(pk_hex.clone()), action: "call".into(), amount: None, seq: None, sig: None };
                crate::socket::game_loop::process_action(&io, &state, 1, req).await;
                println!("[bot {seat_id}] call sent");
            }
        } else if do_check {
            if let Some(io) = crate::socket::get_socket_io() {
                let req = crate::pokergame::table::ActionRequest { pk_hex: GamePkHex(pk_hex.clone()), action: "check".into(), amount: None, seq: None, sig: None };
                crate::socket::game_loop::process_action(&io, &state, 1, req).await;
                println!("[bot {seat_id}] check sent");
            }
        }
    }
    Ok(())
}

type EcP = poker_protocol::crypto::EcPoint;
fn hex_to_point(s: &str) -> EcP {
    poker_protocol::z_poker::convert::hex_to_ecpoint(s).unwrap_or_else(|_| {
        use poker_protocol::crypto::curve::Curve;
        <poker_protocol::crypto::DefaultCurve as Curve>::base_g()
    })
}

/// reveal 轮到自己时生成真实 tokens（从服务器 reveal 状态取本玩家待提交的加密牌）。
async fn pending_reveal_tokens(
    state: &std::sync::Arc<SocketState>,
    pk_hex: &str,
    player: &ClientPlayer,
) -> Result<Option<Vec<poker_protocol::z_poker::protocol::RevealToken>>, String> {
    let gs = state.state.read().await;
    let Some(table) = gs.tables.get(&1) else { return Ok(None) };
        let reveal_state = &table.reveal_token_state;
    let mut hand_cts = Vec::new();
    // 服务器 reveal 状态：player_assignments 键为 pk_hex
    eprintln!("[bot-reveal] probe: active={} phase={:?} assignments={} round={:?} looking for {}",
        reveal_state.is_active(),
        reveal_state.phase,
        reveal_state.player_assignments.len(),
        table.round_state(),
        pk_hex);
    if let Some(assignment) = reveal_state.player_assignments.get(&GamePkHex(pk_hex.to_string())) {
        eprintln!("[bot-reveal] hand_card={} community_card={}",
            assignment.hand_card.len(), assignment.community_card.len());
        hand_cts.extend(assignment.hand_card.iter().cloned());
        hand_cts.extend(assignment.community_card.iter().cloned());
    }
    // 注意：只提交 assignment.hand_card（=其它玩家的卡）的 token——
    // 实测把自己 hand_encrypted 的卡混入会导致服务器整批拒绝
    // ("Invalid token in hand_reveal phase")。
    if hand_cts.is_empty() {
        return Ok(None);
    }
    Ok(Some(player.batch_generate_reveal_token(&hand_cts)))
}

use poker_protocol::crypto::Scalar;
#[allow(dead_code)]
fn _witness(_: (Scalar, ElGamalCiphertext)) {}

