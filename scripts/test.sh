#!/usr/bin/env bash
# 一键测试环境（test 模式）：连接 Starknet Sepolia 测试网启动服务器。
#
# 与 dev 模式（scripts/dev.sh，本地 devnet + 本地 prover）相对：
# - 不起 devnet、不部署合约（用 poker_contracts/DEPLOYMENTS.md 记录的
#   Sepolia 在网合约）；
# - prover 走向 remote（外部 STARKNET_PROVER_URL 服务；未配置则 proved
#   自动回退 linear）；snip36 递归证明仍为进程内本地出证。
#
# 用法：
#   scripts/test.sh             # 构建（release）+ 启动
#   scripts/test.sh --debug     # debug 构建（证明极慢，仅排查用）
#
# 配置文件：texas/.env.test（可被 ENV_FILE= 覆盖）。texas/.env 里的同名
# 变量会被本脚本导出的值覆盖（dotenv 不覆盖已存在的环境变量）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT/texas/.env.test}"
PROFILE=release

for arg in "$@"; do
  case "$arg" in
    --debug) PROFILE=debug ;;
    *) echo "未知参数: $arg"; exit 1 ;;
  esac
done

[[ -f "$ENV_FILE" ]] || {
  echo "缺少配置文件 ${ENV_FILE}（参考仓库内 texas/.env.test 或 DEPLOYMENTS.md 自行填写）"
  exit 1
}

log() { echo "[test] $*"; }

log "构建服务器（cargo build -p texas --${PROFILE}）…"
cargo build -p texas --"$PROFILE"

log "启动 texas 服务器（${PROFILE}，Sepolia）…"
cd "$ROOT"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
# test 模式语义钉死：环境标记 test、prover 走向 remote（配置文件里的
# 误写以这里为准）。
export TEXAS_ENV=test
export TEXAS_PROVER_MODE=remote
set +a
cargo run -p texas --bin texas --"$PROFILE"
