#!/usr/bin/env bash
# Sepolia 全量部署（snops）：Token/Vault/Settlement/Swap 四合约、互相绑定、
# mint + swap 双侧注资。部署者/owner 用项目根 .env.dev 的 ADDRESS/PRIVATE_KEY。
#
# 用法：URL=https://starknet-sepolia-rpc.publicnode.com ./scripts/deploy_sepolia_full.sh
# 可选环境变量：
set -euo pipefail
SNOPS=/Users/mac/projects/zgame/target/debug/snops
URL="${URL:-https://starknet-sepolia-rpc.publicnode.com}"
ART=/Users/mac/projects/poker_texas_air/poker_contracts/target/dev
ENV_ROOT=/Users/mac/projects/poker_texas_air

# shellcheck disable=SC1091
. "$ENV_ROOT/.env.dev"
PK="${PRIVATE_KEY:?PRIVATE_KEY missing in .env.dev}"
OWNER="${ADDRESS:?ADDRESS missing in .env.dev}"

TX_OF() { python3 -c "import sys,re; m=re.search(r'TX=(0x[0-9a-fA-F]+)', sys.stdin.read()); print(m.group(1) if m else '')"; }
ADDR_OF() { python3 -c "import sys,re; m=re.search(r'CONTRACT_ADDRESS=(0x[0-9a-fA-F]+)', sys.stdin.read()); print(m.group(1) if m else '')"; }

get_nonce() {
  curl -s -m 15 -X POST "$URL" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"starknet_getNonce\",\"params\":[\"latest\",\"$OWNER\"]}" \
    | grep -oE '"result":"0x[0-9a-f]+"' | grep -oE '0x[0-9a-f]+' || echo 0x0
}

# 提交后等 nonce 前进（inclusion），避免下一笔撞 nonce。
wait_nonce_gt() {
  local used=$1 i cur
  for i in $(seq 1 90); do
    cur=$(get_nonce)
    if [ -n "$cur" ] && (( $cur > $used )); then return 0; fi
    sleep 2
  done
  echo "   (warn) nonce did not advance past $used in 180s"
}

# snops 从 latest 读 nonce，且交易 inclusion 需要时间：每笔提交后等 nonce 前进；
# 失败（含 nonce 过期）自动重试最多 5 次。
submit_wait() {
  local label=$1; shift
  local attempt out tx n
  for attempt in 1 2 3 4 5; do
    n=$(get_nonce)
    out=$("$@" 2>&1 || true)
    tx=$(TX_OF <<< "$out" || true)
    if [ -n "$tx" ]; then
      wait_nonce_gt "$n"
      return 0
    fi
    echo "   $label attempt $attempt failed: $(head -c 200 <<< "$out" | tr '\n' ' ')" >&2
    sleep 5
  done
  echo "   $label FAILED after 5 attempts" >&2
  return 1
}

echo "== deployer: $OWNER"
BAL=$($SNOPS --url "$URL" call --contract 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d --fn balance_of --calldata "$OWNER" 2>/dev/null | head -1 | grep -oE "0x[0-9a-f]+" || echo 0)
echo "   STRK balance(low) = $BAL"

declare_one() {
  local name=$1
  # 已声明过（历史提交轮次）会报 already declared / mismatch compiled class：
  # Sierra hash 相同即可直接复用链上 class hash 部署。
  local out
  out=$($SNOPS --url "$URL" --pk "$PK" --addr "$OWNER" declare \
    --class "$ART/poker_contracts_${name}.contract_class.json" \
    --compiled "$ART/poker_contracts_${name}.compiled_contract_class.json" 2>&1 || true)
  printf '%s' "$out" | python3 -c "
import sys, re
t = sys.stdin.read()
m = re.search(r'CLASS_HASH=(0x[0-9a-fA-F]+)', t)
if m: print(m.group(1)); sys.exit(0)
m = re.search(r'(0x[0-9a-fA-F]{60,66})', t)
print(m.group(1) if m else '', end='')
"
}

echo "== declare:"
T_CLASS=$(declare_one PokerToken); echo "TOKEN_CLASS=$T_CLASS"
V_CLASS=$(declare_one PokerVault); echo "VAULT_CLASS=$V_CLASS"
S_CLASS=$(declare_one PokerSettlement); echo "SETTLEMENT_CLASS=$S_CLASS"
# PokerDualSettlement 的 casm 字节码（81,175 felts）超过 Sepolia/Mainnet 链上
# 80,000 上限，声明会被节点拒绝——Phase 2 需先瘦身合约。此处可选。
D_CLASS=$(declare_one PokerDualSettlement); echo "DUAL_CLASS=$D_CLASS"
for c in "$T_CLASS" "$V_CLASS" "$S_CLASS"; do
  [ -n "$c" ] || { echo "empty class hash — abort"; exit 1; }
done
if [ -z "$D_CLASS" ]; then
  echo "(warn) PokerDualSettlement not declared on Sepolia (casm size > 80k limit); settlement falls back to legacy PokerSettlement"
fi

# 全部走 UDC deploy；deploy 也从 latest 读 nonce，同样 submit_wait。
deploy_wait() {
  local class_hash=$1 calldata=$2 label=$3
  local n out addr
  for attempt in 1 2 3 4 5; do
    n=$(get_nonce)
    out=$($SNOPS --url "$URL" --pk "$PK" --addr "$OWNER" deploy --class-hash "$class_hash" --calldata "$calldata" 2>&1 || true)
    addr=$(ADDR_OF <<< "$out" || true)
    if [ -n "$addr" ]; then
      wait_nonce_gt "$n"
      echo "$addr"
      return 0
    fi
    # UDC salt=0 确定性地址已部署过（历史轮次）：直接采用该地址复用合约。
    if grep -q "already deployed at address" <<< "$out"; then
      local existing
      existing=$(grep -oE "already deployed at address 0x[0-9a-fA-F]+" <<< "$out" | grep -oE "0x[0-9a-fA-F]+" | tail -1)
      # 诊断走 stderr：函数在 $( ) 内调用，stdout 必须只有地址
      echo "(reuse existing) $label at $existing" >&2
      echo "$existing"
      return 0
    fi
    echo "   deploy $label attempt $attempt failed: $(head -c 200 <<< "$out" | tr '\n' ' ')" >&2
    sleep 5
  done
  echo "   deploy $label FAILED" >&2
  return 1
}

echo "== deploy:"
TOKEN=$(deploy_wait "$T_CLASS" "$OWNER,@str:PokerSTRK,@str:pSTRK,0,0" PokerToken) || exit 1
echo "TOKEN=$TOKEN"
# pSTRK/PokerSwap 已下线：vault 直接绑定原生 STRK（1 STRK = 1000 chips）
CANONICAL_STRK=0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d
VAULT=$(deploy_wait "$V_CLASS" "$OWNER,$CANONICAL_STRK,0" PokerVault) || exit 1
echo "VAULT=$VAULT"
SETTLEMENT=$(deploy_wait "$S_CLASS" "$OWNER,$VAULT,$OWNER" PokerSettlement) || exit 1
echo "SETTLEMENT=$SETTLEMENT"
DUAL=""
if [ -n "$D_CLASS" ]; then
  DUAL=$(deploy_wait "$D_CLASS" "$OWNER,$VAULT,$OWNER" PokerDualSettlement) || exit 1
  echo "DUAL=$DUAL"
fi

echo "== bindings + mint + funding:"
# vault 的 settlement 绑定：dual 可用时指向 PokerDualSettlement（DAPV 默认路径），
# 否则指向 legacy PokerSettlement（Sepolia 当前形态：dual 超字节码上限）。
BIND_TARGET="${DUAL:-$SETTLEMENT}"
submit_wait vault.set_settlement_contract $SNOPS --url "$URL" --pk "$PK" --addr "$OWNER" invoke --contract "$VAULT" --fn set_settlement_contract --calldata "$BIND_TARGET" >/dev/null
echo "bindings+mint+fund done"

cat > /tmp/starknet_sepolia_env << EOF
STARKNET_RPC_URL=$URL
STARKNET_STRK_ADDRESS=$TOKEN
STARKNET_VAULT_ADDRESS=$VAULT
STARKNET_SETTLEMENT_ADDRESS=$SETTLEMENT
STARKNET_DUAL_SETTLEMENT_ADDRESS=$DUAL
STARKNET_OPERATOR_ADDRESS=$OWNER
STARKNET_OPERATOR_PRIVATE_KEY=$PK
EOF
cat /tmp/starknet_sepolia_env

echo "== verify:"
echo -n "  vault.token:   "; $SNOPS --url "$URL" call --contract "$VAULT" --fn token | head -1
echo -n "  vault.chips:   "; $SNOPS --url "$URL" call --contract "$VAULT" --fn total_chips | head -1
echo -n "  settle.vault:  "; $SNOPS --url "$URL" call --contract "$SETTLEMENT" --fn vault | head -1
echo -n "  pstrk owner:   "; $SNOPS --url "$URL" call --contract "$TOKEN" --fn balance_of --calldata "$OWNER" | head -1
echo "=== Sepolia full deployment complete ==="
