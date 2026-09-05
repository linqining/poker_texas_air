# Cairo 路线性能优化报告（prove-hand 管线）

> 2026-09-06 实测，M3 Pro（12 核），release，96-bit 基线 = stwo-cairo 生产默认
> （pow_bits=26，n_queries=70，blowup=1）。基准程序：hand_verify_bench
> （148 EC ops ≈ 1 手；medium 740 ≈ 5 手；full 1,480 ≈ 10 手）。

## 成本模型（实测拟合）

```
prove(参数, n手) ≈ fixed(参数) + marginal(参数) × (n − 1)

baseline: fixed 13.63s, marginal 1.35s/手   （30.6 µs/step，9.1 ms/EC op）
fast:     fixed 12.08s, marginal 1.19s/手   （pow_bits 16，queries 40）
ultra:    fixed 10.04s, marginal ~1.0s/手   （pow_bits 10，queries 30）
```

fixed = stwo-cairo 的 preprocessed trace + 组件 setup + 小 trace 的 FRI 层；
marginal = 30.6 µs/step × ~44k steps/手。

## 杠杆 1：批摊销（最大杠杆，零代价）

固定成本 ~12–13.6s 与手数无关——**多手合入一个 Cairo 程序证明**即摊薄：

| 批大小 | 参数 | prove 总时 | **每手摊销** | 数据 |
|---|---|---|---|---|
| 1 | baseline | 13.63s | **13.6s** | 实测 |
| 5 | baseline | 17.15s | **3.4s** | 实测 |
| 10 | baseline | 25.75s | **2.6s** | 实测 |
| 10 | fast | 22.80s | **2.28s** | 实测 |
| 40 | fast | ~58.5s | **~1.5s** | 线性模型外推 |
| 64 | fast | ~87s | **~1.4s** | 外推 |

验证端不受批大小影响（9–10ms 恒定）。

## 杠杆 2：证明器参数调优（`--params` JSON）

| 参数档 | pow_bits | n_queries | 相对基线 | 适用 |
|---|---|---|---|---|
| baseline | 26 | 70 | — | 生产默认（~96-bit 安全惯例）|
| fast | 16 | 40 | **−11%**（13.63→12.08；full 25.75→22.80） | 安全评审后的生产下限 |
| ultra | 10 | 30 | **−26%**（13.63→10.04） | 仅内部审计件，需安全评审 |

verify 全部通过且恒定 9–10ms。**减参数 = 减 FRI 查询与 PoW 健全性预算**，
任何生产降档必须过安全评审并写明目标安全位数。

## 其他已排除/次要项

- witness 生成（0.076–0.6s）与 prove 流水线重叠后不可见；
- rayon 并行已预热（否则单线程慢 ~8×，prove-hand 已处理）；
- `store_polynomials_coefficients` / lifting_size_policy 变体：对 prove 无感；
- GPU（icicle/CUDA 后端）：Apple Silicon 不可用，x86 + NVIDIA 环境另测。

## 建议生产配置

**批节奏 10–40 手/证明 + fast 参数 → 1.5–2.3s/手（相对 13.6s 基线 = 6–9×）**，
比形态①（0.1s/手）仍慢 ~15–23×，但不再是 13.6s 的量级。证明延迟随批自然
后置（"证明后到"），交易路径零影响。

## 复现

```bash
cd proving-tool
./target/release/prove-hand --scale medium --out-dir /tmp/m \
  [--params /tmp/cairo-opt/params-fast.json]
```

参数档样例：`/tmp/cairo-opt/params-{fast,ultra}.json`
（schema 见 `proving-tool/src/main.rs::default_params`；注意枚举值为小写
`blake2s`/`canonical`/`auto`）。
