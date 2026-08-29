#!/usr/bin/env bash
# Sepolia 一键部署（snops 版）：declare+deploy 四合约、互相绑定、mint、
# 填 server/client env、链上验证。前置：deployer 账户已有 Sepolia STRK。
#
# 前置文件 /tmp/sepolia_deployer.env：
#   PRIVATE_KEY=0x...
#   ADDRESS=0x...
# 可选环境变量：
#   URL=https://starknet-sepolia-rpc.publicnode.com
#   INITIAL_SUPPLY=1000000000000000000000   # 1000 STRK（wei）
#   USE_DUAL=1                              # 同时部署 PokerDualSettlement
set -euo pipefail
SNOPS=/Users/mac/projects/zgame/target/debug/snops
URL="${URL:-https://starknet-sepolia-rpc.publicnode.com}"
INITIAL_SUPPLY="${INITIAL_SUPPLY:-1000000000000000000000}"
ART=/Users/mac/projects/poker_texas_air/poker_contracts/target/dev
ENV_OUT=/tmp/starknet_sepolia_env

# shellcheck disable=SC1091
[ -f /tmp/sepolia_deployer.env ] && . /tmp/sepolia_deployer.env
PK="${PRIVATE_KEY:?Set PRIVATE_KEY in /tmp/sepolia_deployer.env}"
OWNER="${ADDRESS:?Set ADDRESS in /tmp/sepolia_deployer.env}"

TX_OF() { python3 -c "import sys,re; m=re.search(r'TX=(0x[0-9a-fA-F]+)', sys.stdin.read()); print(m.group(1) if m else '')"; }
ADDR_OF() { python3 -c "import sys,re; m=re.search(r'CONTRACT_ADDRESS=(0x[0-9a-fA-F]+)', sys.stdin.read()); print(m.group(1) if m else '')"; }

# 0) 检查部署者账户已部署且有余额
echo "== deployer: $OWNER"
# 账户未部署则先发 deploy_account（salt=0，与 gen-key 的地址推导一致）
$SNOPS --url "$URL" --pk "$PK" deploy-acct 2>&1 | grep -E "ADDRESS|TX=" || echo "   account already deployed (or deploy failed)"
BALANCE=$($SNOPS --url "$URL" call --contract 0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d --fn balance_of --calldata "$OWNER" 2>/dev/null | head -1 | grep -oE "0x[0-9a-f]+" || echo 0)
echo "   STRK balance(low) = ${BALANCE:-<balance_of call failed>}"

# 1) declare
declare_one() {
  local name=$1
  $SNOPS --url "$URL" --pk "$PK" --addr "$OWNER" declare \
    --class "$ART/poker_contracts_${name}.contract_class.json" \
    --compiled "$ART/poker_contracts_${name}.compiled_contract_class.json" 2>&1 \
    | python3 -c "
import sys, re
t = sys.stdin.read()
m = re.search(r'CLASS_HASH=(0x[0-9a-fA-F]+)', t)
if m: print(m.group(1)); sys.exit(0)
# 已声明过：从错误文本提取 class hash
m = re.search(r'already declared.*?(0x[0-9a-fA-F]{60,66})', t) or re.search(r'(0x[0-9a-fA-F]{60,66})', t)
print(m.group(1) if m else '', end='')
"
}
T_CLASS=$(declare_one PokerToken); echo "TOKEN_CLASS=$T_CLASS"
V_CLASS=$(declare_one PokerVault); echo "VAULT_CLASS=$V_CLASS"
S_CLASS=$(declare_one PokerSettlement); echo "SETTLEMENT_CLASS=$S_CLASS"
# Sepolia：declare 交易需要 inclusion 后才能被 UDC deploy 引用
sleep 12

# 2) deploy
D_OUT=$($SNOPS --url "$URL" --pk "$PK" --addr "$OWNER" deploy --class-hash "$T_CLASS" --calldata "$OWNER,@str:PokerSTRK,@str:pSTRK,0,0" 2>&1)
TOKEN=$(ADDR_OF <<< "$D_OUT"); echo "TOKEN=$TOKEN"
D_OUT=$($SNOPS --url "$URL" --pk "$PK" --addr "$OWNER" deploy --class-hash "$V_CLASS" --calldata "$OWNER,$TOKEN,0" 2>&1)
VAULT=$(ADDR_OF <<< "$D_OUT"); echo "VAULT=$VAULT"
D_OUT=$($SNOPS --url "$URL" --pk "$PK" --addr "$OWNER" deploy --class-hash "$S_CLASS" --calldata "$OWNER,$VAULT,$OWNER" 2>&1)
SETTLEMENT=$(ADDR_OF <<< "$D_OUT"); echo "SETTLEMENT=$SETTLEMENT"

DUAL=""
if [ "${USE_DUAL:-0}" = "1" ]; then
  DS_CLASS=$(declare_one PokerDualSettlement); echo "DUAL_CLASS=$DS_CLASS"
sleep 12
  D_OUT=$($SNOPS --url "$URL" --pk "$PK" --addr "$OWNER" deploy --class-hash "$DS_CLASS" --calldata "$OWNER,$VAULT,$OWNER" 2>&1)
  DUAL=$(ADDR_OF <<< "$D_OUT"); echo "DUAL=$DUAL"
fi

# 3) 绑定 + mint + approve
$SNOPS --url "$URL" --pk "$PK" --addr "$OWNER" invoke --contract "$VAULT" --fn set_settlement_contract --calldata "$SETTLEMENT" | TX_OF >/dev/null
$SNOPS --url "$URL" --pk "$PK" --addr "$OWNER" invoke --contract "$TOKEN" --fn mint --calldata "$OWNER,$INITIAL_SUPPLY,0" | TX_OF >/dev/null
$SNOPS --url "$URL" --pk "$PK" --addr "$OWNER" invoke --contract "$TOKEN" --fn approve --calldata "$VAULT,$INITIAL_SUPPLY,0" | TX_OF >/dev/null
echo "bindings+mint done"

# 4) env 文件
cat > "$ENV_OUT" << EOF
STARKNET_RPC_URL=$URL
STARKNET_STRK_ADDRESS=$TOKEN
STARKNET_VAULT_ADDRESS=$VAULT
STARKNET_SETTLEMENT_ADDRESS=$SETTLEMENT
STARKNET_OPERATOR_ADDRESS=$OWNER
STARKNET_OPERATOR_PRIVATE_KEY=$PK
${DUAL:+STARKNET_DUAL_SETTLEMENT_ADDRESS=$DUAL
}
EOF
cat "$ENV_OUT"

# 5) server .env
python3 - << 'PY'
env = dict(l.strip().split('=', 1) for l in open('/tmp/starknet_sepolia_env') if '=' in l)
p = '/Users/mac/projects/zgame/texas/.env'
lines = [l.rstrip('\n') for l in open(p)]
want = ['STARKNET_RPC_URL', 'STARKNET_STRK_ADDRESS', 'STARKNET_VAULT_ADDRESS',
        'STARKNET_SETTLEMENT_ADDRESS', 'STARKNET_OPERATOR_ADDRESS', 'STARKNET_OPERATOR_PRIVATE_KEY']
for k in want:
    if k in env:
        if any(l.split('=', 1)[0] == k for l in lines):
            lines = [f'{k}={env[k]}' if l.split('=', 1)[0] == k else l for l in lines]
        else:
            lines.append(f'{k}={env[k]}')
open(p, 'w').write('\n'.join(lines) + '\n')
print('server .env updated')
PY

# 6) client .env.local
python3 - << 'PY'
env = dict(l.strip().split('=', 1) for l in open('/tmp/starknet_sepolia_env') if '=' in l)
p = '/Users/mac/projects/zgame/client/.env.local'
lines = [l.rstrip('\n') for l in open(p)]
setk = {
    'VITE_STARKNET_RPC_URL': env['STARKNET_RPC_URL'],
    'VITE_STRK_TOKEN_ADDRESS': env['STARKNET_STRK_ADDRESS'],
    'VITE_POKER_VAULT_ADDRESS': env['STARKNET_VAULT_ADDRESS'],
    'VITE_POKER_SETTLEMENT_ADDRESS': env['STARKNET_SETTLEMENT_ADDRESS'],
}
seen = set()
out = []
for l in lines:
    k = l.split('=', 1)[0]
    if k in setk:
        out.append(f'{k}={setk[k]}'); seen.add(k)
    else:
        out.append(l)
for k, v in setk.items():
    if k not in seen:
        out.append(f'{k}={v}')
open(p, 'w').write('\n'.join(out) + '\n')
print('client .env.local updated')
PY

# 7) strk20.json 回填
python3 - << 'PY'
import json
env = dict(l.strip().split('=', 1) for l in open('/tmp/starknet_sepolia_env') if '=' in l)
p = '/Users/mac/projects/poker_texas_air/strk20.json'
d = json.load(open(p))
d['rpc_url'] = env['STARKNET_RPC_URL']
m = {'poker_token': 'STARKNET_STRK_ADDRESS', 'poker_vault': 'STARKNET_VAULT_ADDRESS',
     'poker_settlement': 'STARKNET_SETTLEMENT_ADDRESS'}
for name, key in m.items():
    d['contracts'][name]['address'] = env[key]
if 'STARKNET_DUAL_SETTLEMENT_ADDRESS' in env:
    d['contracts']['poker_dual_settlement']['address'] = env['STARKNET_DUAL_SETTLEMENT_ADDRESS']
json.dump(d, open(p, 'w'), indent=2)
print('strk20.json updated')
PY

# 8) 链上验证
echo "== verify:"
echo -n "  vault.token:   "; $SNOPS --url "$URL" call --contract "$VAULT" --fn token | head -1
echo -n "  vault.chips:   "; $SNOPS --url "$URL" call --contract "$VAULT" --fn total_chips | head -1
echo -n "  settle.vault:  "; $SNOPS --url "$URL" call --contract "$SETTLEMENT" --fn vault | head -1
echo -n "  strk balance:  "; $SNOPS --url "$URL" call --contract "$TOKEN" --fn balance_of --calldata "$OWNER" | head -1
echo "=== Sepolia deployment complete ==="
