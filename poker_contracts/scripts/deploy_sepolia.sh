#!/usr/bin/env bash
set -euo pipefail
: "${SNCAST_ACCOUNT:?Set SNCAST_ACCOUNT to an existing Sepolia account}"
: "${SNCAST_URL:?Set SNCAST_URL to a Starknet Sepolia RPC URL}"
: "${OWNER:?Set OWNER to the deployment owner address}"
: "${PROVER:?Set PROVER to the authorized off-chain prover address}"
: "${INITIAL_SUPPLY:?Set INITIAL_SUPPLY in base units}"
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
scarb build
TOKEN_ARTIFACT=target/dev/poker_contracts_unittest_PokerToken.test.contract_class.json
VAULT_ARTIFACT=target/dev/poker_contracts_unittest_PokerVault.test.contract_class.json
SETTLEMENT_ARTIFACT=target/dev/poker_contracts_unittest_PokerSettlement.test.contract_class.json
DUAL_SETTLEMENT_ARTIFACT=target/dev/poker_contracts_PokerDualSettlement.contract_class.json
for artifact in "$TOKEN_ARTIFACT" "$VAULT_ARTIFACT" "$SETTLEMENT_ARTIFACT"; do
  test -s "$artifact" || exit 1
done

declare_class() {
  sncast --account "$SNCAST_ACCOUNT" --url "$SNCAST_URL" declare --contract "$1" --fee-token strk
}
deploy_class() {
  local class_hash=$1
  shift
  sncast --account "$SNCAST_ACCOUNT" --url "$SNCAST_URL" deploy --class-hash "$class_hash" --constructor-calldata "$@" --fee-token strk
}
TOKEN_CLASS_HASH=$(declare_class "$TOKEN_ARTIFACT")
VAULT_CLASS_HASH=$(declare_class "$VAULT_ARTIFACT")
if [ "${USE_DUAL:-0}" = "1" ]; then
  DUAL_SETTLEMENT_CLASS_HASH=$(declare_class "$DUAL_SETTLEMENT_ARTIFACT")
  echo "DUAL_SETTLEMENT_CLASS_HASH=$DUAL_SETTLEMENT_CLASS_HASH"
fi
SETTLEMENT_CLASS_HASH=$(declare_class "$SETTLEMENT_ARTIFACT")
TOKEN_ADDRESS=$(deploy_class "$TOKEN_CLASS_HASH" "$OWNER" 0x5354524b 0x5354524b "$INITIAL_SUPPLY")
VAULT_ADDRESS=$(deploy_class "$VAULT_CLASS_HASH" "$OWNER" "$TOKEN_ADDRESS" 0)
SETTLEMENT_ADDRESS=$(deploy_class "$SETTLEMENT_CLASS_HASH" "$OWNER" "$VAULT_ADDRESS" "$PROVER")
printf "poker_token=%s\\npoker_vault=%s\\npoker_settlement=%s\\n" "$TOKEN_ADDRESS" "$VAULT_ADDRESS" "$SETTLEMENT_ADDRESS"