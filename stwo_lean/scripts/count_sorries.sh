#!/usr/bin/env bash
# 统计源码中的 sorry/admit。构建期的 "declaration uses sorry" 警告
# 由 `lake build` 直接暴露；本脚本兜底扫描源码文本。
set -e
cd "$(dirname "$0")/.."

if grep -rnE '\bsorry\b|\badmit\b' StwoLean --include='*.lean'; then
  echo "发现 sorry/admit！以上位置必须消除。"
  exit 1
else
  echo "total sorry/admit: 0"
fi
