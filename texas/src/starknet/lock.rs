//! #33 在局锁定（vault v3）服务端接线。
//!
//! 资金安全模型（docs/TODO.md #33）：玩家入座即由 operator 把本手买入
//! 锁进 `vault.lock`（只可花未锁定余额）；每手结算成功后续 session 时钟
//! （`refresh_session`）；离桌后不自动解锁——玩家可在 TTL（默认 12h）后
//! 无许可 `unlock_after_deadline`，operator 保留 `force_unlock` 应急。
//!
//! 设计原则：锁定/续钟失败只告警不阻塞牌局（链下照打，链上锁定尽力而为）；
//! 所有调用都是 operator 签名的独立交易，与结算提交共用 nonce 管线
//! （operator 账户 block_id = PreConfirmed）。

use starknet::accounts::Account;
use starknet::core::types::{Call, Felt};

use super::chain::parse_felt;

fn selector(name: &str) -> Felt {
    starknet::core::utils::starknet_keccak(name.as_bytes())
}

fn vault_address() -> Result<Felt, String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let addr = chain.config.vault_address.clone();
    if addr.is_empty() {
        return Err("vault address not configured".into());
    }
    parse_felt(&addr).ok_or_else(|| format!("vault address invalid: {addr}"))
}

/// chips（服务端单位，1 chip = WEI_PER_CHIP wei = 1e15 wei）→ (lo, hi) u256 felts。
fn chips_to_u256_felts(chips: i64) -> (Felt, Felt) {
    let wei = (chips as i128)
        .checked_mul(super::config::WEI_PER_CHIP as i128)
        .expect("lock amount wei overflow") as u128;
    // u256 calldata = [lo: 低 128 位, hi: 高 128 位]；1e15/chip 的量级下
    // hi 恒为 0（i128 源值上界 2^127）。
    let lo = Felt::from(wei);
    let hi = Felt::from(0_u8);
    (lo, hi)
}

/// 玩家入座成功后锁定买入筹码（owner-gated）。异步尽力而为：
/// 失败仅告警——锁定缺失的代价是 #33 逃单窗口重新打开，日志必须显眼。
pub async fn lock_player_chips(player_address: &str, chips: i64) {
    if chips <= 0 {
        return;
    }
    match invoke_locklike(player_address, chips, "lock").await {
        Ok(tx) => tracing::info!("[in-hand-lock] locked {chips} chips for {player_address}, tx={tx:#x}"),
        Err(e) => tracing::error!(
            "[in-hand-lock] LOCK FAILED for {player_address} ({chips} chips): {e} — 逃单窗口未关闭，需人工 vault.lock 补锁"
        ),
    }
}

/// 每手结算成功后续各参与者的 session 时钟（owner-gated）。
/// 从未锁定的玩家（历史买入）会因 "No active session" 失败——仅告警。
pub async fn refresh_player_session(player_address: &str) {
    match invoke_locklike(player_address, 0, "refresh_session").await {
        Ok(tx) => tracing::debug!("[in-hand-lock] session refreshed for {player_address}, tx={tx:#x}"),
        Err(e) => tracing::warn!("[in-hand-lock] session refresh failed for {player_address}: {e}"),
    }
}

async fn invoke_locklike(player_address: &str, chips: i64, fn_name: &str) -> Result<Felt, String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let vault = vault_address()?;
    let operator = chain.operator().await.ok_or("operator account unavailable")?;
    let player = parse_felt(player_address)
        .ok_or_else(|| format!("player address invalid: {player_address}"))?;
    let calldata: Vec<Felt> = if chips > 0 {
        let (lo, hi) = chips_to_u256_felts(chips);
        vec![player, lo, hi]
    } else {
        vec![player]
    };
    let call = Call {
        to: vault,
        selector: selector(fn_name),
        calldata,
    };
    let res = operator
        .execute_v3(vec![call])
        .send()
        .await
        .map_err(|e| format!("invoke {fn_name}: {e:?}"))?;
    Ok(res.transaction_hash)
}

/// 读玩家锁定余额（chips 单位）。查询失败返回 None（调用方按 0 处理）。
pub async fn locked_balance_chips(player_address: &str) -> Option<u128> {
    let chain = super::chain()?;
    let vault = vault_address().ok()?;
    let player = parse_felt(player_address)?;
    let res = chain
        .call_contract(vault, selector("locked_balance"), vec![player])
        .await
        .ok()?;
    let lo: u128 = (*res.first()?).try_into().ok()?;
    let hi: u128 = res.get(1).copied().and_then(|h| h.try_into().ok()).unwrap_or(0);
    let wei = lo.wrapping_add(hi.wrapping_shl(128));
    Some(wei / (super::config::WEI_PER_CHIP as u128))
}
