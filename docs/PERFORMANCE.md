# Performance — current measured record

> **Authoritative performance record.** Supersedes and replaces the former
> `docs/plan_d_perf.md`, `docs/PERFORMANCE_FOLLOWUPS.md` and
> `docs/plan-d-p3-metrics.md` (removed; full history in git). English is
> authoritative; the Chinese section is a mirror for convenience.
>
> **性能权威记录**。取代并合并原 `docs/plan_d_perf.md`、
> `docs/PERFORMANCE_FOLLOWUPS.md`、`docs/plan-d-p3-metrics.md`（已删除，
> 历史见 git）。以英文为准，中文为对照。

## Headline

| Claim | Number | Nature |
|---|---|---|
| Total cryptographic work per hand (shuffle proof + deal encryption + reveals + folding) | **~0.1 s class** | measured, release |
| Visible latency per hand (bet → showdown) | **< 1 s** — Web2-class table feel | derived from the above |
| Production recursive proving pipeline | **15–17 s/hand**, fully async, play never waits | online-measured |
| Full-table (9p) on-chain P verification cost | **≈ 0.25 STRK** — same order as one ordinary invoke | measured + extrapolated |

## 1. Release baseline — Stark-curve hot path (2026-09-05)

Apple Silicon, `--release`, pinned nightly.
Reproduce: `cargo test -p poker-protocol-proofs --release --test plan_d_perf -- --ignored --nocapture`

| Item | Measured | Notes |
|---|---|---|
| Scalar mul (double-and-add, 251 bit) | **19 µs/op** | acceptance threshold < 20 ms/op (playability) |
| 52-term vartime MSM | **3.4 ms** | not a bottleneck — see non-goals |
| ZK shuffle proof 52 cards — prove / verify | **44 ms / 23 ms** (cycle ~67 ms) | direct-Sigma, three-layer Schnorr |
| 52-card batch ElGamal deal encryption | **6.2 ms** | includes 52 scalar muls |
| `hash_to_scalar` (Poseidon) | **8 µs/op** | challenge derivation |
| `hash_to_curve` (try-and-increment + sqrt) | **118 µs/op** | plaintext-card domain derivation |
| 1540-term host folding (9p full-residual batch) | **2.0 ms** | on-chain EC_OP is faster than this simulation |

**Reading:** the direct-Sigma hot path finishes in milliseconds at human betting
rhythm. STARK proving never enters the interaction path — architecture claim
confirmed by measurement.

## 2. Production proving pipeline (asynchronous, off the interaction path)

| Stage | Cost | Where |
|---|---|---|
| Recursive proving (per hand, incl. per-prove Cairo compile) | **15–17 s**, async | `texas/src/starknet/recursion_prover.rs` (`elapsed_ms`), first e2e logs: steps 1656 / 2364, ec_ops = 16 |
| Settlement STWO prove (`settle_hand`) | ~2 s/hand, `spawn_blocking` | `texas/src/starknet/hooks.rs` |
| State-root recomputation component (Poseidon252 v2, AIR) | **2.91 s** e2e prove+verify (~237× vs v1) | `src/poseidon252_v2.rs` |

Prover parameters: production file = `canonical_small` trace + fast FRI
(pow16 / 40 queries, blake2s channel). The fast tier passes the full test gate;
a dedicated security review is still scheduled before it is used for
production proofs.

**Biggest known lever:** the 15–17 s figure includes Cairo compilation on every
prove. Compile-caching is the next engineering win, before any GPU work.

## 3. On-chain P verification — EC_OP gas, compressed (mainnet-calibrated)

Calibration: mainnet block 14056911, l2_gas_price ≈ 3.63×10¹⁰ fri/unit;
ordinary invoke observed at **0.17–0.40 STRK**.

| Table size N | l2_gas | Mainnet cost | Note |
|---|---|---|---|
| 2 | **1.60 M** | ~0.058 STRK | felt-passthrough transcripts |
| 4 | **3.12 M** | ~0.113 STRK | |
| 9 (extrapolated, linear model 0.08 M + 0.76 M×N) | **≈ 6.9 M** | **≈ 0.25 STRK** | same order as one ordinary invoke |

Pre-compression byte-stream transcripts cost 956 M–4.15×10⁹ l2_gas (35–150
STRK) — profiling showed ~95% was byte serialization and pure-Cairo keccak, not
cryptography. Switching challenges/ρ to felt lists straight into Poseidon
(shared three-way implementation: Rust core, texas, wasm, and
`hand_batch_stark.cairo`) gave a **~600× reduction**. Horner folding removed
the ρ power table and every mod-n multiplication. Regression:
`hand_batch_stark` snforge 12/12, host parity 5/5, e2e 2/2.

**Conclusion: no STARK and no sharding needed — full-table on-chain P
verification is affordable today.** Remaining headroom: `u256_mul_mod_n` λ
computation (~5.4 M gas at N=9) could roughly halve cost again; deferred until
live data demands it.

## 4. Decided non-goals (2026-09-05 dispositions)

| Candidate | Decision | Reason |
|---|---|---|
| Dedicated scalar-mul AIR | not implemented | host 19 µs/op; AIR cost exceeds benefit |
| MSM balanced tree | deferred | 3.4 ms is not a bottleneck |
| Limb backend re-selection | deferred | no current pressure |
| Streaming outer-aggregate encoding | deferred | decide after peak-memory measurement |

## 5. GPU acceleration — theoretical analysis only (no benchmarks)

The proving workload is dominated by data-parallel operations: circle-STARK
FRI field arithmetic, batched Poseidon hashing, AIR row evaluation, MSM-style
accumulations. These map naturally onto GPUs, and the design target is
second-level proofs for the recursive pipeline. **This is an engineering
estimate from the operation profile — no GPU implementation or test case
exists yet**, and no number in this document depends on it.

---

## 中文对照

**总览**：一手牌全部密码学开销 ~0.1 秒级（release 实测）→ 从下注到摊牌可见
时延 < 1 秒、Web2 手感；生产递归证明流水线 15–17 秒/手、完全异步、对局零
等待；满桌（9 人）链上 P 层验证 ≈ 0.25 STRK，与一笔普通 invoke 同量级。

**§1 release 基线（2026-09-05，Stark 曲线热路径）**：标量乘 19 µs、52 项
MSM 3.4 ms、52 卡洗牌证明 prove/verify 44/23 ms（全周期 ~67 ms）、52 卡
ElGamal 发牌加密 6.2 ms、Poseidon hash_to_scalar 8 µs、hash_to_curve
118 µs、9 人桌 1540 项 host 折叠 2.0 ms。结论：direct-Sigma 热路径在人类
下注节奏下毫秒级完成，STARK 不进交互路径——架构主张实测成立。

**§2 生产证明流水线（异步）**：递归证明 15–17 秒/手（含每次 Cairo 编译，
`texas/src/starknet/recursion_prover.rs`，首次 e2e steps 1656/2364、
ec_ops=16）；结算 STWO 证明 ~2 秒/手（`spawn_blocking`）；Poseidon252 v2
state-root 重算组件 e2e 2.91 秒（~237×）。生产参数 = canonical_small +
fast FRI（pow16/q40、blake2s）；fast 档过全量门禁、投产前仍需专项安全
评审。**最大已知优化空间：每次证明都重复 Cairo 编译，编译缓存优先于 GPU。**

**§3 链上 P 验证 EC_OP gas（主网校准）**：压缩后 N=2/4/9 ≈ 1.60M/3.12M/
6.9M l2_gas（≈ 0.058/0.113/0.25 STRK）；压缩前为 956M–4.15G（35–150
STRK），剖析显示 ~95% 花在字节序列化与纯 Cairo keccak 而非密码学本身；
challenge/ρ 改 felt 直通 Poseidon（Rust/texas/wasm/Cairo 四端共享实现）+
Horner 折叠（无 ρ 幂表、无 mod-n 乘法）合计 **~600×**。回归：snforge
12/12、parity 5/5、e2e 2/2。**结论：无需 STARK、无需分片，满桌规模链上
验证今天就可负担。**

**§4 已裁决的非目标**：标量乘专用 AIR（无净收益）、MSM 平衡树（3.4 ms 非
瓶颈）、limb 后端选型、流式 outer-aggregate（待内存实测）——均暂缓/不实施。

**§5 GPU 加速——仅理论分析、无实测**：证明负载由数据并行操作主导
（FRI 域运算、批量 Poseidon、AIR 行求值），天然适合 GPU 映射；设计目标为
递归流水线秒级证明。本文档任何数字均不依赖该目标。
