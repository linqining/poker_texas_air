#!/usr/bin/env bash
# P2-M3：部署 dual settlement v3（含 verify_and_settle_dapv_stark_private_v2）
# 并完成运营配置：set_claim_helper + set_circuit_program_hash。
#
# 用法：
#   URL=https://starknet-sepolia-rpc.publicnode.com \
#   HELPER=0x393f... PROGRAM_HASH=0x2ad1... \
#   ./scripts/deploy_sepolia_v3.sh
#
# 依赖：/.env.dev（PRIVATE_KEY/ADDRESS = poker-deployer）、scarb build 产物、
# zgame/target/debug/snops。
#
# ⚠️ 已知坑（2026-09-03）：sepolia 当前 Starknet 版本的 compiled-class hash
# 方案与本地 cairo 2.11.4 计算不一致——declare 会报
#   "Mismatch compiled class hash ... Actual: 0x<链上算的> Expected: 0x<sierra 声明的>"
# 脚本自动抓 Actual 并以 --compiled-hash 重试。
# gas 预算：declare 该 class 约需 l2_gas 2.86e9 单位（当前价格 ≈142 STRK），
# 部署账户余额不足时先去水龙头补充 STRK。
set -euo pipefail
ROOT=/Users/mac/projects/poker_texas_air
SNOPS=/Users/mac/projects/zgame/target/debug/snops
URL="${URL:-https://starknet-sepolia-rpc.publicnode.com}"
ART="$ROOT/poker_contracts/target/dev"
HELPER="${HELPER:?HELPER address required}"
PROGRAM_HASH="${PROGRAM_HASH:?PROGRAM_HASH required (prove-hand public_outputs.json)}"
VAULT="${VAULT:?VAULT address required}"

# shellcheck disable=SC1091
. "$ROOT/.env.dev"
PK="${PRIVATE_KEY:?PRIVATE_KEY missing}"
OWNER="${ADDRESS:?ADDRESS missing}"

get_nonce() {
  curl -s -m 15 -X POST "$URL" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"starknet_getNonce\",\"params\":[\"latest\",\"$OWNER\"]}" \
    | grep -oE '"result":"0x[0-9a-f]+"' | grep -oE '0x[0-9a-f]+' || echo 0x0
}
wait_nonce_gt() {
  local used=$1 i cur
  for i in $(seq 1 90); do
    cur=$(get_nonce)
    if [ -n "$cur" ] && (( $cur > $used )); then return 0; fi
    sleep 2
  done
  echo "   (warn) nonce did not advance past $used" >&2
}
submit_wait() {
  local label=$1; shift
  local attempt out tx n
  for attempt in 1 2 3 4 5; do
    n=$(get_nonce)
    out=$("$@" 2>&1 || true)
    tx=$(printf '%s' "$out" | grep -oE 'TX=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
    if [ -n "$tx" ]; then
      wait_nonce_gt "$n"; echo "$tx"; return 0
    fi
    echo "   $label attempt $attempt: $(head -c 200 <<< "$out" | tr '\n' ' ')" >&2
    local cls addr
    cls=$(printf '%s' "$out" | grep -oE 'CLASS_HASH=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
    if [ -n "$cls" ]; then echo "$cls"; return 0; fi
    addr=$(printf '%s' "$out" | grep -oE 'already deployed at address 0x[0-9a-fA-F]+' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
    if [ -n "$addr" ]; then echo "$addr"; return 0; fi
    sleep 5
  done
  echo "   $label FAILED after 5 attempts" >&2
  return 1
}

SN="$SNOPS --url $URL --pk $PK --addr $OWNER"

echo "== [1/5] declare PokerDualSettlement（自动处理 compiled-hash 方案差异）"
CLS=""
for attempt in 1 2 3; do
  n=$(get_nonce)
  out=$("$SN" declare \
    --class "$ART/poker_contracts_PokerDualSettlement.contract_class.json" \
    --compiled "$ART/poker_contracts_PokerDualSettlement.compiled_contract_class.json" 2>&1 || true)
  tx=$(printf '%s' "$out" | grep -oE 'TX=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
  if [ -n "$tx" ]; then wait_nonce_gt "$n"; CLS="$tx"; break; fi
  # 方案差异：抓链上 Actual 作为 --compiled-hash 重试
  actual=$(printf '%s' "$out" | grep -oE 'Actual: 0x[0-9a-fA-F]+' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
  if [ -n "$actual" ]; then
    echo "   compiled-hash scheme mismatch → retry with --compiled-hash $actual" >&2
    n=$(get_nonce)
    out=$("$SN" declare \
      --class "$ART/poker_contracts_PokerDualSettlement.contract_class.json" \
      --compiled "$ART/poker_contracts_PokerDualSettlement.compiled_contract_class.json" \
      --compiled-hash "$actual" 2>&1 || true)
    tx=$(printf '%s' "$out" | grep -oE 'TX=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
    if [ -n "$tx" ]; then wait_nonce_gt "$n"; CLS="$tx"; break; fi
    echo "   retry output: $(head -c 300 <<< "$out" | tr '\n' ' ')" >&2
    if printf '%s' "$out" | grep -q "exceed balance"; then
      echo "   FAIL: gas 预算不足——先给部署账户补 sepolia STRK（当前需 ≈142 STRK）" >&2
    fi
  else
    echo "   attempt $attempt: $(head -c 300 <<< "$out" | tr '\n' ' ')" >&2
    if printf '%s' "$out" | grep -q "exceed balance"; then
      echo "   FAIL: gas 预算不足——先给部署账户补 sepolia STRK" >&2
    fi
  fi
  sleep 10
done
[ -n "$CLS" ] || { echo "declare FAILED" >&2; exit 1; }
echo "DUAL_CLASS=$CLS"

echo "== [2/5] deploy dual v3（owner=$OWNER vault=$VAULT prover=$OWNER）"
DUAL=""
for attempt in 1 2 3 4 5; do
  n=$(get_nonce)
  out=$("$SN" deploy --class-hash "$CLS" --calldata "$OWNER,$VAULT,$OWNER" 2>&1 || true)
  addr=$(printf '%s' "$out" | grep -oE 'CONTRACT_ADDRESS=(0x[0-9a-fA-F]+)' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
  if [ -n "$addr" ]; then wait_nonce_gt "$n"; DUAL="$addr"; break; fi
  existing=$(printf '%s' "$out" | grep -oE 'already deployed at address 0x[0-9a-fA-F]+' | grep -oE '0x[0-9a-fA-F]+' | tail -1)
  if [ -n "$existing" ]; then DUAL="$existing"; break; fi
  echo "   deploy attempt $attempt: $(head -c 200 <<< "$out" | tr '\n' ' ')" >&2
  sleep 5
done
[ -n "$DUAL" ] || { echo "deploy FAILED" >&2; exit 1; }
echo "DUAL_ADDR=$DUAL"

echo "== [3/5] set_claim_helper($HELPER)"
submit_wait set_claim_helper "$SN" invoke --contract "$DUAL" --fn set_claim_helper --calldata "$HELPER" >/dev/null

echo "== [4/5] set_circuit_program_hash($PROGRAM_HASH)"
submit_wait set_program_hash "$SN" invoke --contract "$DUAL" --fn set_circuit_program_hash --calldata "$PROGRAM_HASH" >/dev/null

echo "== [5/5] 回填 texas/.env 的 STARKNET_DUAL_SETTLEMENT_ADDRESS"
sed -i.bak "s|^STARKNET_DUAL_SETTLEMENT_ADDRESS=.*|STARKNET_DUAL_SETTLEMENT_ADDRESS=$DUAL|" "$ROOT/texas/.env"
rm -f "$ROOT/texas/.env.bak"

echo "== done"
echo "DUAL_CLASS=$CLS"
echo "DUAL_ADDR=$DUAL"
