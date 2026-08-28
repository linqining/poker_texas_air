#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
URL=http://127.0.0.1:5051
ACC=operator
OWNER="${OWNER:-0x04e587e1fd532641641dbb0aa0001e200353e7b0f6e74cd4f26bcb2ecb9a4744}"
cd /Users/mac/projects/poker_texas_air/poker_contracts

ADDR_OF() { echo "$1" | python3 "$(dirname "$0")/parse_out.py" addr; }
CLASS_OF() { echo "$1" | python3 "$(dirname "$0")/parse_out.py" class; }
TX_OF() { echo "$1" | python3 "$(dirname "$0")/parse_out.py" tx; }

T_OUT=$(sncast --account $ACC declare --url $URL --contract-name PokerToken 2>&1 || true)
T_CLASS=$(CLASS_OF "$T_OUT")
if [ -z "$T_CLASS" ]; then
  T_OUT=$(sncast --account $ACC declare --url $URL --contract-name PokerToken 2>&1 || true)
  T_CLASS=$(echo "$T_OUT" | python3 "$(dirname "$0")/parse_out.py" already)
fi
echo "TOKEN_CLASS=$T_CLASS"
sncast --account operator deploy --url $URL --class-hash $T_CLASS --arguments "$OWNER, \"PokerSTRK\", \"pSTRK\", 0" > /tmp/dep_t.out 2>&1 || true
TOKEN=$(ADDR_OF "$(cat /tmp/dep_t.out)")
echo "TOKEN=$TOKEN"
sncast --account operator invoke --url $URL --contract-address $TOKEN --function mint --calldata $OWNER 1000000000000000000000 0 >/dev/null 2>&1

V_OUT=$(sncast --account operator declare --url $URL --contract-name PokerVault 2>&1)
V_CLASS=$(CLASS_OF "$V_OUT")
sncast --account operator deploy --url $URL --class-hash $V_CLASS --arguments "$OWNER, $TOKEN, 0" > /tmp/dep_v.out 2>&1 || true
VAULT=$(ADDR_OF "$(cat /tmp/dep_v.out)")
echo "VAULT=$VAULT"

S_OUT=$(sncast --account operator declare --url $URL --contract-name PokerSettlement 2>&1)
S_CLASS=$(CLASS_OF "$S_OUT")
sncast --account operator deploy --url $URL --class-hash $S_CLASS --arguments "$OWNER, $VAULT, $OWNER" > /tmp/dep_s.out 2>&1 || true
SETTLEMENT=$(ADDR_OF "$(cat /tmp/dep_s.out)")
echo "SETTLEMENT=$SETTLEMENT"

sncast --account operator invoke --url $URL --contract-address $VAULT --function set_settlement_contract --calldata $SETTLEMENT >/dev/null
sncast --account operator invoke --url $URL --contract-address $TOKEN --function approve --calldata $VAULT 100000000000000000000000 0 >/dev/null
DEPOSIT=$(TX_OF "$(sncast --account operator invoke --url $URL --contract-address $VAULT --function deposit --calldata 100000000000000000000 0 2>&1)")
echo "DEPOSIT_TX=$DEPOSIT"

cat > /tmp/starknet_e2e_env << EOF
STARKNET_RPC_URL=$URL
STARKNET_STRK_ADDRESS=$TOKEN
STARKNET_VAULT_ADDRESS=$VAULT
STARKNET_SETTLEMENT_ADDRESS=$SETTLEMENT
STARKNET_OPERATOR_ADDRESS=$OWNER
STARKNET_OPERATOR_PRIVATE_KEY="${OPKEY:-}"
DEPOSIT_TX=$DEPOSIT
EOF
echo "--- env written to /tmp/starknet_e2e_env ---"
cat /tmp/starknet_e2e_env
