mod poker_token;
mod poker_vault;
/// STRK20 privacy-pool anonymizer (Plan B): private buy-ins via privacy_invoke.
mod poker_swap;
mod poker_vault_anonymizer;
mod poker_settlement;
mod settlement_hash;

/// Dual-proof settlement (DUAL_PROOF_PROTOCOL.md): on-chain BN254 sigma
/// verification for the P track + Phase-1 G registration.
mod dual;
mod poker_dual_settlement;

/// Part A Phase 1 (SETTLEMENT_PRIVACY_PLAN.md): winners claim escrowed
/// payouts privately via secp256k1-signed STRK20 pool claims.
mod settlement_payout_anonymizer;

/// #25 全链路私密提现（unshield 方向第二个 anonymizer）：vault 筹码 →
/// STRK20 池 open note，不经玩家公开钱包。
mod cashout_unshield_helper;
