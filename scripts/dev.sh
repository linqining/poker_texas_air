#!/usr/bin/env bash
# 一键本地开发环境（dev 模式）。
#
# 流程：starknet-devnet（--seed 0, :5051）→ 合约构建 + devnet 部署
# → 生成 texas/.env.dev.local（地址快照）→ 以本地 prover
# （TEXAS_PROVER_MODE=dev）启动 texas 服务器，连接本地开发网提交。
#
# 用法：
#   scripts/dev.sh                  # 完整流程（构建 + 部署 + 启动）
#   scripts/dev.sh --skip-build     # 跳过 scarb/cargo 构建（复用已有产物）
#   scripts/dev.sh --skip-deploy    # 跳过部署（复用运行中的 devnet 与
#                                   # texas/.env.dev.local 里的地址快照；
#                                   # devnet 重启后地址会变，勿混用）
#   scripts/dev.sh --keep-devnet    # 脚本退出时不关 devnet
#   scripts/dev.sh --debug          # 服务器用 debug 构建（默认 release，
#                                   # 递归证明在 debug 下极慢，仅排查用）
#
# 环境变量：DEVNET_URL / DEVNET_PORT 覆盖 devnet 地址；SCARB_HOME 覆盖
# scarb 工具链位置（默认 ~/.local/opt/toolchains/scarb-2.19.4）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEVNET_URL="${DEVNET_URL:-http://127.0.0.1:5051}"
DEVNET_PORT="${DEVNET_PORT:-5051}"
SCARB_HOME="${SCARB_HOME:-$HOME/.local/opt/toolchains/scarb-2.19.4}"
ENV_FILE="$ROOT/texas/.env.dev.local"
PROFILE=release
SKIP_BUILD=0
SKIP_DEPLOY=0
KEEP_DEVNET=0

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=1 ;;
    --skip-deploy) SKIP_DEPLOY=1 ;;
    --keep-devnet) KEEP_DEVNET=1 ;;
    --debug) PROFILE=debug ;;
    *) echo "未知参数: $arg"; exit 1 ;;
  esac
done

log() { echo "[dev] $*"; }

# ---------- 1) starknet devnet ----------
DEVNET_PID=""
if curl -sf "$DEVNET_URL/is_alive" >/dev/null 2>&1; then
  log "devnet 已在运行: $DEVNET_URL"
else
  command -v starknet-devnet >/dev/null 2>&1 || {
    echo "缺少 starknet-devnet（pip install starknet-devnet）"; exit 1; }
  log "启动 starknet-devnet (seed 0, port $DEVNET_PORT)…"
  starknet-devnet --seed 0 --port "$DEVNET_PORT" >/tmp/starknet-devnet.log 2>&1 &
  DEVNET_PID=$!
  for _ in $(seq 1 60); do
    curl -sf "$DEVNET_URL/is_alive" >/dev/null 2>&1 && break
    sleep 1
  done
  curl -sf "$DEVNET_URL/is_alive" >/dev/null 2>&1 || {
    echo "devnet 启动超时，日志见 /tmp/starknet-devnet.log"; exit 1; }
  log "devnet 已启动 (pid $DEVNET_PID, 日志 /tmp/starknet-devnet.log)"
fi
cleanup() {
  if [[ -n "$DEVNET_PID" ]] && [[ "$KEEP_DEVNET" != 1 ]]; then
    kill "$DEVNET_PID" 2>/dev/null || true
    log "devnet 已停止（--keep-devnet 可保留）"
  fi
}
trap cleanup EXIT

# ---------- 2) devnet 预充值账户 #0（seed 0 固定）= owner/operator ----------
ACCOUNTS=$(python3 - "$DEVNET_URL" <<'PY'
import json, sys, urllib.request, urllib.error

def find_key(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = find_key(v, key)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find_key(v, key)
            if r is not None:
                return r
    return None

base = sys.argv[1].rstrip("/")
data = None
# 新版 devnet：/prestated_data（GET/POST 都试）；旧版：/predeployed_accounts
attempts = [
    ("/prestated_data", "GET", None),
    ("/prestated_data", "POST", b"{}"),
    ("/predeployed_accounts", "GET", None),
]
for path, method, body in attempts:
    try:
        req = urllib.request.Request(base + path, data=body, method=method,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.load(resp)
    except Exception:
        continue
    if find_key(data, "predeployed_accounts") or isinstance(data, list):
        break

accounts = find_key(data, "predeployed_accounts") if data is not None else None
if isinstance(data, list) and not accounts:
    accounts = data
if not accounts:
    sys.exit("devnet 未返回预充值账户（/prestated_data 与 /predeployed_accounts 均不可用），"
             "请确认 devnet 版本；也可手动设置 OWNER/OPKEY 后修改本脚本")
first = accounts[0]
charge = find_key(data, "charge_token_address") \
    or "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"
print(first["address"])
print(first["private_key"])
print(charge)
PY
)
OWNER=$(echo "$ACCOUNTS" | sed -n '1p')
OPKEY=$(echo "$ACCOUNTS" | sed -n '2p')
STRK=$(echo "$ACCOUNTS" | sed -n '3p')
log "owner/operator = devnet 预充值账户 #0: $OWNER"

# ---------- 3) 构建（合约 + snops + 服务器）----------
if [[ "$SKIP_BUILD" != 1 ]]; then
  if [[ -x "$SCARB_HOME/bin/scarb" ]]; then
    export PATH="$SCARB_HOME/bin:$PATH"
  fi
  command -v scarb >/dev/null 2>&1 || { echo "缺少 scarb（$SCARB_HOME）"; exit 1; }
  log "构建 Cairo 合约（scarb build）…"
  (cd "$ROOT/poker_contracts" && scarb build)
  log "构建 snops + 服务器（cargo build -p texas）…"
  cargo build -p texas --bin snops
  cargo build -p texas --"$PROFILE"
else
  log "跳过构建"
  [[ -x "$ROOT/target/debug/snops" || -x "$ROOT/target/release/snops" ]] || {
    echo "--skip-build 但没有 snops 产物，请先完整运行一次"; exit 1; }
fi

# ---------- 4) 部署合约到 devnet ----------
if [[ "$SKIP_DEPLOY" != 1 ]]; then
  log "部署合约到 devnet（poker_contracts/scripts/local_deploy.sh）…"
  OWNER="$OWNER" OPKEY="$OPKEY" URL="$DEVNET_URL" \
    "$ROOT/poker_contracts/scripts/local_deploy.sh" >/tmp/devnet-deploy.log 2>&1 || {
    echo "部署失败，日志见 /tmp/devnet-deploy.log"; tail -20 /tmp/devnet-deploy.log; exit 1; }
  # shellcheck disable=SC1091
  source /tmp/starknet_e2e_env
  log "部署完成: VAULT=$STARKNET_VAULT_ADDRESS DUAL=$STARKNET_DUAL_SETTLEMENT_ADDRESS"
else
  if [[ -f "$ENV_FILE" ]]; then
    log "跳过部署，复用 $ENV_FILE 的地址快照"
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    STARKNET_RPC_URL="$DEVNET_URL"
  else
    echo "--skip-deploy 但 $ENV_FILE 不存在，请先完整运行一次"; exit 1
  fi
fi

# ---------- 5) 生成服务器环境（本地 prover + 本地开发网提交）----------
STRK="${STARKNET_STRK_ADDRESS:-$STRK}"
DUAL="${STARKNET_DUAL_SETTLEMENT_ADDRESS:-}"
SETTLE="${STARKNET_SETTLEMENT_ADDRESS:-}"
VAULT="${STARKNET_VAULT_ADDRESS:-}"
cat > "$ENV_FILE" <<EOF
# 由 scripts/dev.sh 生成（本地 devnet 部署快照）——devnet 重建后地址会变。
# dev 模式：TEXAS_ENV=dev → TEXAS_PROVER_MODE 缺省即本地 prover；
# 这里显式写出便于对照。proved 实验入口见文件尾部注释。
PORT=9001
JWT_SECRET=devnet-secret-for-local-e2e
TEXAS_ENV=dev
TEXAS_PROVER_MODE=dev
TEXAS_DEV_BOT_ENABLED=1
RUST_LOG=info
STARKNET_RPC_URL=$DEVNET_URL
STARKNET_CHAIN_ID=SN_SEPOLIA
STARKNET_STRK_ADDRESS=$STRK
STARKNET_VAULT_ADDRESS=$VAULT
STARKNET_SETTLEMENT_ADDRESS=$SETTLE
STARKNET_DUAL_SETTLEMENT_ADDRESS=$DUAL
STARKNET_OPERATOR_ADDRESS=$OWNER
STARKNET_OPERATOR_PRIVATE_KEY=$OPKEY
STARKNET_AUTH_STRICT=false
# snip36 = 每手结束后进程内本地递归出证（hand_verify_native），失败自动
# 回退 dual 线性结算；结算提交走 register_hand + verify_and_settle_dapv_stark。
STARKNET_SETTLEMENT_MODE=snip36
STARKNET_DAPV_SETTLE_ENTRY=v2
STARKNET_TREASURY_ADDRESS=$OWNER
STARKNET_RAKE_BPS=500
STARKNET_RAKE_CAP=1000
BETTING_TIMEOUT_SECS=90
BOT_LOOP_SECS=0
# ---- proved 模式实验（本地 prover 闭环）----
# 取消注释后：批次 attestation 进程内 host ρ-fold 校验（LocalBatchProver），
# settlement 电路 fact 由 operator 直登（register_settlement_fact），
# 无需外部 prover 服务。注意 v2 私密结算入口还需要 dual.claim_helper
# 与赢家 payout commitment 接线（见 DEPLOYMENTS.md）——裸 devnet 缺这些
# 时 proved 段构建失败，结算自动回退 linear（行为与线上回退语义一致）。
# STARKNET_SETTLE_MODE=proved
EOF
log "服务器环境已生成: $ENV_FILE"

# ---------- 6) 启动服务器（前台；Ctrl-C 一并停 devnet）----------
log "启动 texas 服务器（$PROFILE，连接 $DEVNET_URL）…"
cd "$ROOT"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
cargo run -p texas --"$PROFILE"
