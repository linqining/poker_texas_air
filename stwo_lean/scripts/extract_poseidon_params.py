#!/usr/bin/env python3
"""从 lambdaworks-crypto 的 starknet Poseidon parameters.rs 提取
UNOPTIMIZED_ROUND_CONSTANTS（273 个），生成 StwoLean/Poseidon252Params.lean。

用法：python3 scripts/extract_poseidon_params.py
（假定 cargo registry 路径为默认；常量出处见生成文件头注释。）
"""
import re
import sys
from pathlib import Path

LW = sorted(
    Path.home().glob(
        ".cargo/registry/src/*/lambdaworks-crypto-0.10.0/src/hash/poseidon/starknet/parameters.rs"
    )
)
if not LW:
    sys.exit("lambdaworks-crypto-0.10.0 parameters.rs not found in cargo registry")
src = LW[0].read_text()

m = re.search(
    r"const OPTIMIZED_ROUND_CONSTANTS: \[FE<Stark252PrimeField>; 107\] = \[(.*?)\];",
    src,
    re.S,
)
assert m, "OPTIMIZED_ROUND_CONSTANTS not found"
hexes = re.findall(r'FE::from_hex_unchecked\("([0-9a-fA-F]+)"\)', m.group(1))
assert len(hexes) == 107, f"expected 107 constants, got {len(hexes)}"
assert all(1 <= len(h) <= 64 for h in hexes), "hex constants without zero-padding"
p = 2**251 + 17 * 2**192 + 1
assert all(int(h, 16) < p for h in hexes), "constants must be < p"

out = Path(__file__).resolve().parent.parent / "StwoLean" / "Poseidon252Params.lean"

L = []
L.append("import Mathlib")
L.append("import StwoLean.QM31")
L.append("")
L.append("/-!")
L.append("# Poseidon252Params — Starknet Poseidon 的轮常数与域参数")
L.append("")
L.append("**本文件由 `scripts/extract_poseidon_params.py` 自动生成，勿手改。**")
L.append("")
L.append("出处：`lambdaworks-crypto-0.10.0/src/hash/poseidon/starknet/parameters.rs`")
L.append("的 `OPTIMIZED_ROUND_CONSTANTS`（107 = 12 + 83 + 3 + 9：前 4 full 轮")
L.append("每轮 3 个、83 个 partial 轮每轮 1 个（含前移累积）、last full 轮")
L.append("首行 3 个 + 其余 3 轮每轮 3 个）。已验证与 starknet-crypto-codegen")
L.append("0.3.3 的 `compress_roundkeys_partial` 从 RAW_ROUND_KEYS（273）生成的")
L.append("COMP 表逐元素一致。注意：UNOPTIMIZED（273）教科书形式与该 COMP 表")
L.append("**不等价**（partial 轮 sbox 的非线性使常数前移不可交换），本库")
L.append("实现 COMP 排列——即 `poseidon_permute_comp` 的逐行对应。")
L.append("-/")
L.append("")
L.append("namespace StwoLean")
L.append("")
L.append("/-- Starknet 域素数 `p = 2^251 + 17·2^192 + 1`。Poseidon/Channel/Merkle")
L.append("只用其环结构（`ZMod P252` 的 CommRing）；素性不承担证明义务")
L.append("（本库的域运算证明义务全部在 QM31 侧）。 -/")
L.append("def P252 : Nat := 2^251 + 17 * 2^192 + 1")
L.append("")
L.append("/-- Starknet 252-bit 域（表示层；仅需环结构）。 -/")
L.append("abbrev Fp252 := ZMod P252")
L.append("")
L.append("/-- 轮常数表（107 个，COMP 压缩形式，出处见文件头）。合法索引")
L.append("0..106；越界分支返回 0 仅为补全 match 穷尽性，所有调用点的索引")
L.append("都是静态确定的（4F/83P/4F）。 -/")
L.append("def RC : Nat → Fp252")
for i, h in enumerate(hexes):
    L.append(f"  | {i} => 0x{h}")
L.append("  | _ => 0")
L.append("")
L.append("end StwoLean")

out.write_text("\n".join(L) + "\n")
print(f"wrote {out} with {len(hexes)} constants")
