import AirsLean.Fold.Chain
import AirsLean.Fold.Settlement
import AirsLean.Fold.KeyAgg

/-! # Fold — 牌桌折叠协议（fold_batch）安全属性层

对「手级 MuSig2/BDN 聚合签名 + 复用 acc 链/语句层」折叠协议设计的五条
安全属性做机器验证：

* `AirsLean.Fold.Chain` —— P1 acc 链绑定性 + P4 批根/顺序不可重组（抽象单射哈希模型）；
* `AirsLean.Fold.Settlement` —— P2 零和不变式（felt 回绕健全性 + 批守恒 + 金额绑定）；
* `AirsLean.Fold.KeyAgg` —— P3 rogue-key 代数（无系数负例 / BDN 不动点条件 /
  PoP 唯一性 / 完备性代数核）。

统一假设登记：poseidon/keccak 的（预像）抗碰撞性以「H 单射」假设进入
（H1）；MuSig2/BDN 的 ROM 归约、群阶素性、curve 参数为文献/曲线参数事实，
不在 Lean 层重证。对应真实实例的属性测试在
`poker_contracts/hand-verify-native/tests/fold_formal_props.rs`（真实
starknet poseidon + 真实 Stark 曲线，proptest 固定种子）。
-/
