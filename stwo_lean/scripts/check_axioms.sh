#!/usr/bin/env bash
# 公理审计：关键定理只允许依赖标准公理
# [propext, Classical.choice, Quot.sound]。
# 出现 Lean.ofReduceBool（native_decide）或 Classical.choice 之外的
# 自定义假设公理即失败。
set -e
cd "$(dirname "$0")/.."

cat > /tmp/stwo_lean_axcheck.lean <<'EOF'
import StwoLean
open StwoLean
#print axioms P_prime
#print axioms neg_one_not_square
#print axioms five_not_square
#print axioms fpow_eq_pow
#print axioms CM31.norm_eq_zero
#print axioms CM31.mul_inv_cancel
#print axioms QM31.norm_eq_zero
#print axioms QM31.mul_inv_cancel
#print axioms CirclePoint.onCircle_cpAdd
#print axioms CirclePoint.conj_cpAdd_eq_pointOne
#print axioms CirclePoint.m31Gen_onCircle
#print axioms CirclePoint.m31Gen_repeatedDouble_31
#print axioms CirclePoint.getRandomPoint_onCircle
EOF

lake env lean /tmp/stwo_lean_axcheck.lean | tee /tmp/stwo_lean_axcheck.out

if grep -qE "ofReduceBool|sorryAx" /tmp/stwo_lean_axcheck.out; then
  echo "审计失败：出现 native_decide/sorry 公理！"
  exit 1
fi
echo "公理审计通过：仅依赖 [propext, Classical.choice, Quot.sound]"
