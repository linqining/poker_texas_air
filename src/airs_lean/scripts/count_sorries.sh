#!/usr/bin/env bash
# 审计 AirsLean：零 sorry / admit。
# 先剥离 Lean 块注释（/- ... -/，含 /-- doc -/）与行注释，再按词边界计数。
# 用法：bash scripts/count_sorries.sh
set -euo pipefail
cd "$(dirname "$0")/.."

count=0
while IFS= read -r f; do
  n=$(perl -0777 -pe 's{/-(?!/-).*?-/}{}gs; s{--.*$}{}gm' "$f" \
      | grep -cE '\b(sorry|admit)\b' || true)
  if [ "$n" -gt 0 ]; then
    echo "FAIL $f: $n"
    count=$((count + n))
  fi
done < <(find AirsLean -name '*.lean')

echo "total sorry/admit: $count"
exit $((count > 0))
