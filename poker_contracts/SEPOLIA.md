# Poker STRK20 contracts — Starknet Sepolia

This directory contains the contract-side first phase of the STRK20 integration.
The chain only checks the final `aggregate_digest` and the settlement state; it
does **not** execute the Stwo verifier. The operator must verify the complete
Rust `OuterAggregateBundle` before calling `register_aggregate`.

## Contracts

- `PokerToken`: OpenZeppelin ERC20 test token with owner-only `mint`/`burn`.
  Replace it with the canonical Sepolia STRK token for an integration test that
  uses real STRK.
- `PokerVault`: 1:1 STRK20 deposits/withdrawals and per-player chip balances.
  `apply_settlement` is restricted to the configured settlement contract.
- `PokerSettlement`: authorized-prover registration of aggregate digests,
  monotonic hand ranges, Poseidon settlement commitments, zero-sum checks, and
  replay-protected vault deltas.

## Build

```bash
cd poker_contracts
scarb build
scarb test
```

`scarb test` is a compile/test-runner smoke gate. The current workspace does
not pin `snforge_std`, because the old plugin version fails to compile on the
current macOS toolchain due to its transitive `size-of` Windows ABI list. Use a
matching Starknet Foundry release in CI to execute the Cairo test runner.

## Sepolia deployment

The deployment script requires explicit configuration and never defaults to a
mainnet RPC:

```bash
export SNCAST_ACCOUNT=poker-sepolia
export SNCAST_URL='https://starknet-sepolia.public.blastapi.io/rpc/v0_8'
export OWNER='0x...'
export PROVER='0x...'
export INITIAL_SUPPLY='1000000000000000000000000'
./scripts/deploy_sepolia.sh
```

Before sending transactions:

1. Fund the account with Sepolia ETH/STRK gas tokens.
2. Review the exact Sierra artifacts and constructor calldata.
3. Confirm whether the deployment uses the local `PokerToken` or the canonical
   Sepolia STRK token.
4. Deploy `PokerToken`, `PokerVault`, and `PokerSettlement`.
5. Call `set_settlement_contract(settlement_address)` on the vault as owner.
6. Update `/strk20.json` with the returned addresses and class hashes.
7. Verify the constructor and access-control state with `sncast call`.

## Runtime flow

1. Player calls STRK20 `approve(vault, amount)`.
2. Player calls vault `deposit(amount)`.
3. Rust operator verifies the complete Stwo outer aggregate off-chain.
4. Authorized prover calls `register_aggregate(...)` with the aggregate digest,
   state roots, and one settlement commitment per hand.
5. Authorized prover calls `settle_hand(...)` with the ordered participants and
   signed net chip deltas. The contract recomputes the Poseidon commitment,
   checks zero-sum, and forwards deltas to the vault.
6. Player calls `withdraw(amount)`.

## Security boundary

This is intentionally a trusted-operator bridge for the testnet phase. The
contract guarantees commitment consistency, operator authorization, replay
protection, monotonic hand ranges, and chip accounting. It does not guarantee
that the off-chain digest was generated from a valid Stwo proof. A future
permissionless phase must add a Cairo-native proof verifier or a separate
on-chain verifier before removing this trust boundary.
