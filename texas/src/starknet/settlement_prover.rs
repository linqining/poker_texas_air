//! P2-M2 服务端接缝：`SettlementPrivateStatement` 构建 → prove-hand 电路
//! inputs 导出 → `STARKNET_PROVER_URL` 客户端（prove-settlement 管线）。
//!
//! 与 P2-M1/M2 的分工：
//! - 根 crate `settlement_private_circuit.rs`：语句/参考实现（starknet_crypto）；
//! - `proving-tool/src/settlement_private.cairo` + `scripts/prove-settlement.sh` +
//!   `scripts/prover_service.py`：Cairo1 电路与 Stwo 证明（8.6s 实测）；
//! - **本模块**：从结算明文（`HandSettlement` 同源的 players/deltas/digest）构建
//!   电路请求，async 读取赢家 payout commitment（vault），把 inputs JSON 导出到
//!   workload 目录（best-effort，绝不阻塞结算），并通过 HTTP 向 prover 服务
//!   （`STARKNET_PROVER_URL`，指向 `prover_service.py`）请求证明 attestation。
//!
//! 隐私模型：只有 inputs JSON 落盘（witness，operator 主机本地）；公开段
//! `[MAGIC, hand_id, digest, n, binding, cm_0..cm_7]` 由服务端独立重算校验——
//! prover 返回的 digest 必须等于请求的 registered_digest，cms 必须等于本地
//! 推导，任何不匹配/失败都只告警（结算路径不由本模块决定）。

use starknet::core::utils::starknet_keccak;
use starknet_ff::FieldElement as Ff;

use super::submit::ff_to_felt;

/// 参与者上限（与根 crate / Cairo 电路一致）。
pub const MAX_PARTICIPANTS: usize = 8;
/// Cairo 电路的 Magic 标记（'SP2M_OK' = 0x5350324d5f4f4b）。
pub fn prove_magic() -> Ff {
    const BYTES: [u8; 32] = {
        let mut b = [0u8; 32];
        // 'SP2M_OK' = 0x5350324d5f4f4b（大端尾对齐）
        b[25] = 0x53;
        b[26] = 0x50;
        b[27] = 0x32;
        b[28] = 0x4d;
        b[29] = 0x5f;
        b[30] = 0x4f;
        b[31] = 0x4b;
        b
    };
    Ff::from_bytes_be(&BYTES).expect("canonical magic")
}

/// 证明请求（明文只在 operator 主机内存在）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementPrivateRequest {
    pub hand_id: u32,
    pub hand_binding: [u8; 32],
    pub registered_digest: [u8; 32],
    /// 固定 8 槽，未用槽位零 felt。
    pub players: [[u8; 32]; MAX_PARTICIPANTS],
    /// 规格分解 sign ∈ {0,1}（d ≥ 0 → 1）。
    pub signs: [u8; MAX_PARTICIPANTS],
    /// |delta|（wei，≤ u64）。
    pub magnitudes: [u64; MAX_PARTICIPANTS],
    pub n_participants: u32,
    /// 赢家 payout commitment；非赢家槽零。
    pub commitments: [[u8; 32]; MAX_PARTICIPANTS],
    /// 本手动作日志哈希（#18 Phase B，32 字节大端）——digest 吸收链尾词 +
    /// 公开段尾词（第 37 入参）。
    pub action_log_digest: [u8; 32],
    /// 本手动作日志打包词（每条 1 felt，#18 Phase C 切片 1：电路按 60 槽
    /// 重放整链；空 = 无动作日志）。32 字节大端。
    pub action_entries: Vec<[u8; 32]>,
}

/// 从结算明文构建请求（digest 由同一公式重算——与 register calldata 中的
/// settlement_digest 逐字节一致）。
pub fn build_request(
    hand_id: u32,
    hand_binding: Ff,
    players: &[Ff],
    deltas_wei: &[i128],
    commitments: &[[u8; 32]; MAX_PARTICIPANTS],
    action_log_digest: Ff,
    action_entries: &[Ff],
) -> Result<SettlementPrivateRequest, String> {
    use crate::pokergame::actions::ACTION_LOG_MAX_ENTRIES;
    if action_entries.len() > ACTION_LOG_MAX_ENTRIES {
        return Err(format!(
            "action log has {} entries, exceeds circuit maximum {ACTION_LOG_MAX_ENTRIES}",
            action_entries.len()
        ));
    }
    let mut padded_players = [[0u8; 32]; MAX_PARTICIPANTS];
    if players.len() > MAX_PARTICIPANTS || deltas_wei.len() > MAX_PARTICIPANTS {
        return Err("participants exceed circuit maximum of 8".into());
    }
    let mut sum: i128 = 0;
    let mut n_participants: u32 = 0;
    let mut signs = [0u8; MAX_PARTICIPANTS];
    let mut magnitudes = [0u64; MAX_PARTICIPANTS];
    for (i, delta) in deltas_wei.iter().copied().enumerate() {
        if delta.unsigned_abs() > u64::MAX as u128 {
            return Err(format!("|delta| at seat {i} exceeds u64"));
        }
        padded_players[i] = players
            .get(i)
            .map(|p| p.to_bytes_be())
            .unwrap_or([0u8; 32]);
        signs[i] = u8::from(delta >= 0);
        magnitudes[i] = delta.unsigned_abs() as u64;
        if delta != 0 {
            n_participants += 1;
        }
        sum = sum
            .checked_add(delta)
            .ok_or_else(|| format!("delta sum overflow at seat {i}"))?;
    }
    if sum != 0 {
        return Err("settlement is not zero-sum".into());
    }
    for (i, commitment) in commitments.iter().enumerate() {
        if deltas_wei.get(i).copied().unwrap_or(0) > 0 && *commitment == [0u8; 32] {
            return Err(format!("winner at seat {i} has no payout commitment"));
        }
    }

    // registered_digest = poseidon_hash_many([hand_id] ++ Σ(player, sign, |delta|)
    // ++ [action_log_digest])（与 submit.rs / 合约 compute_settlement_digest
    // 逐字段一致；#18 Phase B 尾词 = 动作日志哈希）。
    let mut fields = Vec::with_capacity(2 + 3 * MAX_PARTICIPANTS);
    fields.push(Ff::from(hand_id));
    for i in 0..MAX_PARTICIPANTS {
        fields.push(Ff::from_bytes_be(&padded_players[i]).map_err(|e| e.to_string())?);
        fields.push(Ff::from(u64::from(signs[i])));
        fields.push(Ff::from(magnitudes[i]));
    }
    fields.push(action_log_digest);
    let registered_digest = starknet_crypto::poseidon_hash_many(&fields).to_bytes_be();

    Ok(SettlementPrivateRequest {
        hand_id,
        hand_binding: hand_binding.to_bytes_be(),
        registered_digest,
        players: padded_players,
        signs,
        magnitudes,
        n_participants,
        commitments: *commitments,
        action_log_digest: action_log_digest.to_bytes_be(),
        action_entries: action_entries.iter().map(|w| w.to_bytes_be()).collect(),
    })
}

/// async 读取赢家 payout commitment（vault.payout_commitment）。
/// 非赢家槽返回零；链不可用/查询失败/赢家未注册 → Err（best-effort 调用方忽略）。
pub async fn fetch_payout_commitments(
    players: &[Ff],
    deltas_wei: &[i128],
) -> Result<[[u8; 32]; MAX_PARTICIPANTS], String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let vault_addr = super::chain::parse_felt(&chain.config.vault_address)
        .ok_or("invalid vault address")?;
    let selector = starknet_keccak(b"payout_commitment");
    let mut commitments = [[0u8; 32]; MAX_PARTICIPANTS];
    for (i, delta) in deltas_wei.iter().copied().enumerate() {
        let Some(player) = players.get(i).copied() else { break };
        if delta <= 0 {
            continue;
        }
        let felts = chain
            .call_contract(vault_addr, selector, vec![ff_to_felt(player)])
            .await
            .map_err(|e| format!("payout_commitment query failed for {player:#x}: {e}"))?;
        let value = felts.first().copied().ok_or("empty payout_commitment result")?;
        if value == starknet::core::types::Felt::ZERO {
            return Err(format!("winner {player:#x} has no payout commitment"));
        }
        commitments[i] = super::submit::felt_to_ff(&value).to_bytes_be();
    }
    Ok(commitments)
}

impl SettlementPrivateRequest {
    /// Cairo `main` 的 37 个入参（顺序与 settlement_private.cairo 签名一致；
    /// 第 37 = 动作日志哈希，#18 Phase B）。
    pub fn inputs_felts(&self) -> Vec<Ff> {
        let mut felts = Vec::with_capacity(5 + 4 * MAX_PARTICIPANTS);
        felts.push(Ff::from(self.hand_id));
        felts.push(Ff::from_bytes_be(&self.registered_digest).expect("canonical digest"));
        felts.push(Ff::from(self.n_participants));
        felts.push(Ff::from_bytes_be(&self.hand_binding).expect("canonical binding"));
        for player in &self.players {
            felts.push(Ff::from_bytes_be(player).expect("canonical player"));
        }
        for sign in &self.signs {
            felts.push(Ff::from(u64::from(*sign)));
        }
        for magnitude in &self.magnitudes {
            felts.push(Ff::from(*magnitude));
        }
        for commitment in &self.commitments {
            felts.push(Ff::from_bytes_be(commitment).expect("canonical commitment"));
        }
        felts.push(
            Ff::from_bytes_be(&self.action_log_digest).expect("canonical action log digest"),
        );
        // #18 Phase C 切片 1：词条区 = [count] ++ 60×1 打包词（不足补零）——
        // 与 Cairo 电路 main 签名逐位对齐（main 参数上限 100 实测）。
        use crate::pokergame::actions::ACTION_LOG_MAX_ENTRIES;
        let count = self.action_entries.len();
        felts.push(Ff::from(count as u64));
        for slot in 0..ACTION_LOG_MAX_ENTRIES {
            let word = self.action_entries.get(slot).copied().unwrap_or([0u8; 32]);
            felts.push(Ff::from_bytes_be(&word).expect("canonical action word"));
        }
        felts
    }

    /// prove-hand `--inputs` JSON（hex felt 数组）。
    pub fn inputs_json(&self) -> String {
        let hexes: Vec<String> = self
            .inputs_felts()
            .iter()
            .map(|f| format!("0x{f:x}"))
            .collect();
        serde_json::to_string(&hexes).expect("inputs json")
    }

    /// 本地推导赢家认领承诺（与合约公式一致：
    /// `cm = poseidon([commitment, hand_binding, amount_lo, amount_hi])`）。
    pub fn derive_claim_cms(&self) -> Vec<[u8; 32]> {
        let binding = Ff::from_bytes_be(&self.hand_binding).expect("canonical binding");
        (0..MAX_PARTICIPANTS)
            .map(|i| {
                if self.signs[i] == 1 && self.magnitudes[i] != 0 {
                    let commitment =
                        Ff::from_bytes_be(&self.commitments[i]).expect("canonical commitment");
                    starknet_crypto::poseidon_hash_many(&[
                        commitment,
                        binding,
                        Ff::from(self.magnitudes[i]),
                        Ff::ZERO,
                    ])
                    .to_bytes_be()
                } else {
                    [0u8; 32]
                }
            })
            .collect()
    }

    /// 期望公开段（felt 形态）：`[MAGIC, hand_id, digest, n, binding,
    /// cm_0..cm_7, total_winnings, action_log_digest]`（15 felt）——v2 合约
    /// 托管金额 = total_winnings（电路内累加），尾词对注册的动作日志承诺
    /// 逐 felt 比对（#18 Phase B）。
    pub fn public_segment_felts(&self) -> Vec<Ff> {
        let mut segment = vec![
            prove_magic(),
            Ff::from(self.hand_id),
            Ff::from_bytes_be(&self.registered_digest).expect("canonical digest"),
            Ff::from(self.n_participants),
            Ff::from_bytes_be(&self.hand_binding).expect("canonical binding"),
        ];
        let mut total_winnings: u64 = 0;
        for (index, cm) in self.derive_claim_cms().iter().enumerate() {
            segment.push(Ff::from_bytes_be(cm).expect("canonical cm"));
            if self.signs[index] == 1 && self.magnitudes[index] != 0 {
                total_winnings = total_winnings.saturating_add(self.magnitudes[index]);
            }
        }
        segment.push(Ff::from(total_winnings));
        segment.push(
            Ff::from_bytes_be(&self.action_log_digest).expect("canonical action log digest"),
        );
        segment
    }

    /// 期望公开段（hex 形态，供公开段比对）。
    pub fn expected_public_segment(&self) -> Vec<String> {
        self.public_segment_felts()
            .iter()
            .map(|f| format!("0x{f:x}"))
            .collect()
    }

    /// fact-registry 锚：`fact = poseidon([circuit_program_hash ++ 公开段])`。
    /// 电路 program_hash 部署时钉入合约常量，prover 侧经
    /// `register_settlement_fact` 登记，`..._v2` 结算入口校验。
    pub fn settlement_fact(&self, circuit_program_hash: [u8; 32]) -> Result<[u8; 32], String> {
        let ph = Ff::from_bytes_be(&circuit_program_hash).map_err(|e| e.to_string())?;
        let mut fields = vec![ph];
        fields.extend(self.public_segment_felts());
        Ok(starknet_crypto::poseidon_hash_many(&fields).to_bytes_be())
    }
}

/// 导出到 workload 目录（best-effort，绝不阻塞结算）：
/// `settlement-private-{hand_id}-{binding:x}.inputs.json`。
pub fn export_settlement_private_inputs(
    req: &SettlementPrivateRequest,
    dir: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let path = dir.join(format!(
        "settlement-private-{}-{:x}.inputs.json",
        req.hand_id,
        Ff::from_bytes_be(&req.hand_binding).ok()?
    ));
    let result = std::fs::create_dir_all(dir)
        .and_then(|_| std::fs::write(&path, req.inputs_json()));
    match result {
        Ok(()) => {
            tracing::info!("[settlement-private] circuit inputs exported: {}", path.display());
            Some(path)
        }
        Err(e) => {
            tracing::warn!("[settlement-private] inputs export failed (non-fatal): {e}");
            None
        }
    }
}

/// 从链上结算明文一步构建请求（ commitments 由 vault async 读取）。
pub async fn prepare_request(
    hand_id: u32,
    hand_binding: Ff,
    players: &[Ff],
    deltas_wei: &[i128],
    action_log_digest: Ff,
    action_entries: &[Ff],
) -> Result<SettlementPrivateRequest, String> {
    let commitments = fetch_payout_commitments(players, deltas_wei).await?;
    build_request(
        hand_id,
        hand_binding,
        players,
        deltas_wei,
        &commitments,
        action_log_digest,
        action_entries,
    )
}

/// prover 服务返回的 attestation：digest 与 cms 已对照本地推导校验。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementPrivateAttestation {
    pub program_hash: String,
}

/// `STARKNET_PROVER_URL` 客户端——指向 `proving-tool/scripts/prover_service.py`
/// （或任何实现了相同协议的服务）：POST
/// `{"circuit":"settlement_private","hand_id":..,"inputs":[hex..]}`，
/// 响应 `{"ok":true,"output":[hex..],"program_hash":"0x.."}`。
/// 公开段在本地重算校验：digest 必须等于请求的 registered_digest，
/// cms 必须等于本地推导——prover 无法用别的语句蒙混。
pub struct HttpSettlementProver {
    pub url: Option<String>,
}

impl HttpSettlementProver {
    pub fn new(url: Option<String>) -> Self {
        Self { url }
    }

    pub fn configured(&self) -> bool {
        self.url.as_deref().is_some_and(|u| !u.trim().is_empty())
    }

    pub async fn prove_settlement_private(
        &self,
        req: &SettlementPrivateRequest,
    ) -> Result<SettlementPrivateAttestation, String> {
        let Some(url) = self.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) else {
            return Err("settlement prover URL not configured".into());
        };
        let body = serde_json::json!({
            "circuit": "settlement_private",
            "hand_id": req.hand_id,
            "inputs": req.inputs_felts().iter().map(|f| format!("0x{f:x}")).collect::<Vec<_>>(),
        });
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(super::dual_settle::PROVER_ATTEST_TIMEOUT.as_secs() + 15))
            .build()
            .map_err(|e| format!("http client: {e}"))?;
        let resp = client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("prover unreachable: {e}"))?;
        let status = resp.status();
        let payload: serde_json::Value = resp.json().await.map_err(|e| format!("prover response: {e}"))?;
        if !status.is_success() || payload.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return Err(format!(
                "prover rejected ({status}): {}",
                payload.get("error").and_then(|v| v.as_str()).unwrap_or("unknown")
            ));
        }
        let output = payload
            .get("output")
            .and_then(|v| v.as_array())
            .ok_or("prover response missing output")?;
        let segment = output
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>();
        let magic = format!("0x{:x}", prove_magic());
        let start = segment
            .iter()
            .position(|w| *w == magic)
            .ok_or("prover public segment missing MAGIC")?;
        let want_len = 5 + MAX_PARTICIPANTS + 2; // MAGIC..binding + cms + total + action log
        if segment.len() < start + want_len {
            return Err("prover public segment too short".into());
        }
        let got = &segment[start..start + want_len];
        let expected = req.expected_public_segment();
        if got.len() < expected.len() || got[..expected.len()] != expected[..] {
            return Err(format!(
                "prover public segment mismatch: got {got:?}, expected {}",
                expected.join(",")
            ));
        }
        Ok(SettlementPrivateAttestation {
            program_hash: payload
                .get("program_hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_felt(seed: u8) -> Ff {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        Ff::from_bytes_be(&bytes).expect("canonical")
    }

    fn sample_felt_bytes(seed: u8) -> [u8; 32] {
        sample_felt(seed).to_bytes_be()
    }

    fn sample_entries() -> Vec<Ff> {
        vec![sample_felt(0xB1), sample_felt(0xB2)]
    }

    fn sample_request() -> SettlementPrivateRequest {
        let players = [sample_felt(1), sample_felt(2), sample_felt(3)];
        let deltas = [3_000_i128, -2_000, -1_000, 0, 0, 0, 0, 0]; // chips 口径做单测
        let mut commitments = [[0u8; 32]; MAX_PARTICIPANTS];
        commitments[0] = sample_felt_bytes(0x21);
        build_request(
            42,
            sample_felt(0xAA),
            &players,
            &deltas,
            &commitments,
            sample_felt(0xA7),
            &sample_entries(),
        )
        .expect("request")
    }

    #[test]
    fn inputs_match_cairo_signature_order() {
        let req = sample_request();
        let felts = req.inputs_felts();
        // 37 标量 + 1 计数 + 60×1 词条槽（#18 Phase C 切片 1）。
        assert_eq!(felts.len(), 38 + 60);
        assert_eq!(felts[0], Ff::from(42u32), "hand_id first");
        assert_eq!(felts[1], Ff::from_bytes_be(&req.registered_digest).expect("canonical"));
        assert_eq!(felts[2], Ff::from(3u32), "n_participants");
        assert_eq!(felts[3], Ff::from_bytes_be(&req.hand_binding).expect("canonical"));
        assert_eq!(felts[4], sample_felt(1), "p0");
        // signs 组在 players 组（8 个）之后
        assert_eq!(felts[12], Ff::from(1u64), "s0");
        assert_eq!(felts[13], Ff::from(0u64), "s1（负数 → 0）");
        // mags 组
        assert_eq!(felts[20], Ff::from(3_000u64), "m0");
        // commitments 组
        assert_eq!(felts[28], sample_felt(0x21), "c0");
        // 第 37 入参 = 动作日志哈希（#18 Phase B）
        assert_eq!(felts[36], sample_felt(0xA7), "action log digest last");
        // 词条区：count=2 + 槽 0/1 有词 + 槽 2..60 补零
        assert_eq!(felts[37], Ff::from(2u64), "action count");
        assert_eq!(felts[38], sample_felt(0xB1), "entry0");
        assert_eq!(felts[39], sample_felt(0xB2), "entry1");
        assert_eq!(felts[40], Ff::ZERO, "padding slot starts");
        assert_eq!(felts[37 + 60], Ff::ZERO, "last padding slot");
    }

    #[test]
    fn digest_is_stable_and_binds_players_and_deltas() {
        let req = sample_request();
        let again = sample_request();
        assert_eq!(req.registered_digest, again.registered_digest);
        // 改动任一输入必须改变 digest（digest 绑定整份语句）
        let mut tampered_players = [sample_felt(1), sample_felt(2), sample_felt(3)];
        tampered_players[0] = sample_felt(9);
        let tampered = build_request(
            42,
            sample_felt(0xAA),
            &tampered_players,
            &[3_000, -2_000, -1_000, 0, 0, 0, 0, 0],
            &req.commitments,
            sample_felt(0xA7),
            &sample_entries(),
        )
        .expect("tampered request still buildable");
        assert_ne!(req.registered_digest, tampered.registered_digest);
        // 动作日志哈希（吸收链尾词）改动必须改变 digest（#18 Phase B 绑定）。
        let other_log = build_request(
            42,
            sample_felt(0xAA),
            &[sample_felt(1), sample_felt(2), sample_felt(3)],
            &[3_000, -2_000, -1_000, 0, 0, 0, 0, 0],
            &req.commitments,
            sample_felt(0xA8),
            &sample_entries(),
        )
        .expect("other log request buildable");
        assert_ne!(req.registered_digest, other_log.registered_digest);
    }

    #[test]
    fn zero_sum_violation_rejected() {
        let players = [sample_felt(1), sample_felt(2), sample_felt(3)];
        let err = build_request(42, sample_felt(0xAA), &players, &[3_001, -2_000, -1_000, 0, 0, 0, 0, 0], &[[0u8; 32]; MAX_PARTICIPANTS], sample_felt(0xA7), &sample_entries())
            .err()
            .expect("non-zero-sum must be rejected");
        assert!(err.contains("zero-sum"));
    }

    #[test]
    fn winner_without_commitment_rejected() {
        let players = [sample_felt(1), sample_felt(2), sample_felt(3)];
        let err = build_request(42, sample_felt(0xAA), &players, &[3_000, -2_000, -1_000, 0, 0, 0, 0, 0], &[[0u8; 32]; MAX_PARTICIPANTS], sample_felt(0xA7), &sample_entries())
            .err()
            .expect("winner without commitment must be rejected");
        assert!(err.contains("payout commitment"));
    }

    #[test]
    fn expected_segment_shape() {
        let req = sample_request();
        let segment = req.expected_public_segment();
        assert_eq!(segment.len(), 7 + MAX_PARTICIPANTS);
        assert!(segment[0].starts_with("0x5350324d5f4f4b"), "MAGIC='SP2M_OK'");
        assert_eq!(segment[1], "0x2a", "hand_id=42");
        assert_eq!(segment[3], "0x3", "n_participants");
        // 非赢家 cm 全零
        for cm in &segment[6..13] {
            assert_eq!(cm, "0x0");
        }
        // 赢家 cm 与合约公式一致
        let binding = sample_felt(0xAA);
        let commitment = sample_felt(0x21);
        let expected_cm = starknet_crypto::poseidon_hash_many(&[
            commitment,
            binding,
            Ff::from(3_000u64),
            Ff::ZERO,
        ]);
        assert_eq!(segment[5], format!("0x{expected_cm:x}"));
        // total_winnings = Σ 赢家 |delta|（chips 口径样例 = 3000）
        assert_eq!(segment[13], format!("0x{:x}", Ff::from(3_000u64)));
        // #18 Phase B：尾词 = 动作日志哈希
        assert_eq!(segment[14], format!("0x{:x}", sample_felt(0xA7)));
    }

    #[test]
    fn settlement_fact_binds_program_hash_and_segment() {
        let req = sample_request();
        let fact_a = req.settlement_fact(sample_felt_bytes(1)).expect("fact");
        let fact_b = req.settlement_fact(sample_felt_bytes(1)).expect("fact");
        let fact_c = req.settlement_fact(sample_felt_bytes(2)).expect("fact");
        assert_eq!(fact_a, fact_b, "同语句同 program hash → 同 fact");
        assert_ne!(fact_a, fact_c, "program hash 不同 → fact 不同");
        let mut tampered = sample_request();
        tampered.registered_digest[31] ^= 1;
        assert_ne!(
            fact_a,
            tampered.settlement_fact(sample_felt_bytes(1)).expect("fact"),
            "语句任何字段变化 → fact 不同"
        );
    }

    #[test]
    fn inputs_json_is_hex_array() {
        let req = sample_request();
        let parsed: Vec<String> = serde_json::from_str(&req.inputs_json()).expect("json");
        assert_eq!(parsed.len(), 38 + 60);
        assert!(parsed.iter().all(|h| h.starts_with("0x")));
    }
}


#[cfg(test)]
mod selector_probe {
    #[test]
    fn print_action_selectors() {
        let names = ["transfer", "approve", "balance_of", "allowance", "mint",
            "withdraw_to", "token", "chip_to_note", "shieldable_balance", "vault", "pool",
            "set_unshield_helper", "unshield_helper", "set_authorized_helper"];
        for n in names {
            println!("SEL {} = {:x}", n, starknet::core::utils::starknet_keccak(n.as_bytes()));
        }
    }
}
