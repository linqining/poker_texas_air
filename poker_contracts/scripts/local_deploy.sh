#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
URL="${URL:-http://127.0.0.1:5051}"
SNOPS=/Users/mac/projects/zgame/target/debug/snops
OWNER="${OWNER:?Set OWNER}"
OPKEY="${OPKEY:?Set OPKEY}"
ART=/Users/mac/projects/poker_texas_air/poker_contracts/target/dev
TX_OF() { echo "$1" | python3 /Users/mac/projects/poker_texas_air/poker_contracts/scripts/parse_out.py tx; }
ADDR_OF() { echo "$1" | python3 /Users/mac/projects/poker_texas_air/poker_contracts/scripts/parse_out.py addr; }
CLASS_OF() { echo "$1" | python3 /Users/mac/projects/poker_texas_air/poker_contracts/scripts/parse_out.py class; }

declare_one() {
  local name=$1
  local class="$ART/poker_contracts_${name}.contract_class.json"
  local compiled="$ART/poker_contracts_${name}.compiled_contract_class.json"
  local out
  out=$($SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" declare --class "$class" --compiled "$compiled" 2>&1) || {
    # 已声明过则从错误中提取 class hash
    echo "$out" | python3 /Users/mac/projects/poker_texas_air/poker_contracts/scripts/parse_out.py already
    return 0
  }
  CLASS_OF "$out"
}

T_CLASS=$(declare_one PokerToken)
echo "TOKEN_CLASS=$T_CLASS"
D_OUT=$($SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" deploy --class-hash "$T_CLASS" --calldata "$OWNER,@str:PokerSTRK,@str:pSTRK,0,0" 2>&1)
TOKEN=$(ADDR_OF "$D_OUT")
echo "TOKEN=$TOKEN"

V_CLASS=$(declare_one PokerVault)
D_OUT=$($SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" deploy --class-hash "$V_CLASS" --calldata "$OWNER,$TOKEN,0" 2>&1)
VAULT=$(ADDR_OF "$D_OUT")
echo "VAULT=$VAULT"

S_CLASS=$(declare_one PokerSettlement)
D_OUT=$($SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" deploy --class-hash "$S_CLASS" --calldata "$OWNER,$VAULT,$OWNER" 2>&1)
SETTLEMENT=$(ADDR_OF "$D_OUT")
echo "SETTLEMENT=$SETTLEMENT"

$SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" invoke --contract "$VAULT" --fn set_settlement_contract --calldata "$SETTLEMENT" >/dev/null
$SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" invoke --contract "$TOKEN" --fn mint --calldata "$OWNER,1000000000000000000000,0" >/dev/null
$SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" invoke --contract "$TOKEN" --fn approve --calldata "$VAULT,100000000000000000000000,0" >/dev/null
DEPOSIT=$(TX_OF "$($SNOPS --url "$URL" --pk "$OPKEY" --addr "$OWNER" invoke --contract "$VAULT" --fn deposit --calldata 100000000000000000000,0 2>&1)")
echo "DEPOSIT_TX=$DEPOSIT"

cat > /tmp/starknet_e2e_env << EOF
STARKNET_RPC_URL=$URL
STARKNET_STRK_ADDRESS=$TOKEN
STARKNET_VAULT_ADDRESS=$VAULT
STARKNET_SETTLEMENT_ADDRESS=$SETTLEMENT
STARKNET_OPERATOR_ADDRESS=$OWNER
STARKNET_OPERATOR_PRIVATE_KEY=$OPKEY
DEPOSIT_TX=$DEPOSIT
EOF
echo "--- env written ---"
cat /tmp/starknet_e2e_env
