#!/usr/bin/env bash
# Count sorry/admit occurrences in PokerProtocolLean/ source tree.
# CI gate: zero-sorry policy. Only `axiom`-form assumptions are allowed
# (e.g. UnknownDL, hg bijection, Fact (q.Prime), DLP).
#
# Usage: ./scripts/count_sorries.sh
# Exit code 0 if no sorry/admit in theorem/lemma bodies; 1 otherwise.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/PokerProtocolLean"

echo "=== sorry / admit audit (excluding axiom-form assumptions) ==="
echo

# 1. Total raw occurrences (informational).
# `grep || true` so an all-clean tree (grep exits 1 on no match) does not
# abort the script under `set -euo pipefail` before it can report success.
TOTAL=$( { grep -rn -E '\b(sorry|admit)\b' "$SRC" 2>/dev/null || true; } | wc -l | tr -d ' ')
echo "Total 'sorry'/'admit' occurrences (incl. in axiom lines, comments, strings): $TOTAL"
echo

# 2. Occurrences NOT on axiom lines and NOT obviously comments.
echo "--- Offending lines (sorry/admit outside axiom definitions) ---"
OFFENDERS=$( { grep -rn -E '\b(sorry|admit)\b' "$SRC" 2>/dev/null || true; } \
  | grep -v -E '^[^:]+:[0-9]+:\s*(--|/\||axiom)' \
  | grep -v -E '^\s*--' \
  || true)
if [ -n "$OFFENDERS" ]; then
  echo "$OFFENDERS"
  echo
  echo "FAIL: $TOTAL total; offending non-axiom, non-comment sorry/admit lines found above."
  exit 1
fi

echo "OK: zero sorry/admit in theorem/lemma bodies."
exit 0
