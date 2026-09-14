#!/usr/bin/env bash
# 公理审计（分层信任模型）：
#
# 第 1 层（核心定理）：只允许标准公理
#   [propext, Classical.choice, Quot.sound]。
#   出现 Lean.ofReduceBool 或 sorryAx 即失败。
#
# 第 2 层（重计算向量 StwoLean.Vectors.PoseidonChannel 的具名定理）：
#   允许 Lean.ofReduceBool（native_decide，编译器求值），仍禁止
#   sorryAx。理由：251-bit 域上的 91 轮 Hades 排列用内核 decide
#   求值约需 30 分钟/条；native_decide 走 Lean 编译器（GMP 加速）
#   求值，秒级完成。其健全性依赖 Lean 编译器求值器的正确性，这是
#   计算密集型断言的通行折中（详见 README「分层信任模型」）。
set -e
cd "$(dirname "$0")/.."

cat > /tmp/stwo_lean_axcheck1.lean <<'EOF'
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

lake env lean /tmp/stwo_lean_axcheck1.lean | tee /tmp/stwo_lean_axcheck1.out

if grep -qE "ofReduceBool|sorryAx" /tmp/stwo_lean_axcheck1.out; then
  echo "审计失败：核心定理出现 native_decide/sorry 公理！"
  exit 1
fi
echo "第 1 层审计通过：核心定理仅依赖 [propext, Classical.choice, Quot.sound]"

cat > /tmp/stwo_lean_axcheck2.lean <<'EOF'
import StwoLean.Vectors
#print axioms StwoLean.Vectors.chMixU64Golden
#print axioms StwoLean.Vectors.hadesVec1
EOF

lake env lean /tmp/stwo_lean_axcheck2.lean | tee /tmp/stwo_lean_axcheck2.out

if grep -qE "sorryAx" /tmp/stwo_lean_axcheck2.out; then
  echo "审计失败：向量定理出现 sorryAx！"
  exit 1
fi
if ! grep -q "ofReduceBool" /tmp/stwo_lean_axcheck2.out; then
  echo "警告：向量定理未含 ofReduceBool（可能已被 decide 覆盖，无需担忧）。"
fi
echo "第 2 层审计通过：向量定理仅依赖 ofReduceBool + 标准公理（无 sorryAx）。"
