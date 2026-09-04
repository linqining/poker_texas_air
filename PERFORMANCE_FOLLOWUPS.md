> ⚠️ **状态(2026-09-05)**:新旧基线分界见 `docs/plan_d_perf.md`(曲线切换后
> 唯一 release 基线)。各项处置结论(2026-09-05 落档):① 专用标量乘 AIR
> ——host 19µs/op,进 AIR 成本远超收益,**维持 oracle 保留、不实施**;
> ② MSM 平衡树——3.4ms 不构成瓶颈,**暂缓**;③ limb backend 选型——**暂缓**;
> ④ outer_aggregate 流式编码——**暂缓**(峰值内存实测后再定);⑤ 错误分类
> ——**低优持续项**(docs/TODO.md #24⑤);⑥ /metrics 路由——**归上层
> server(texas 侧)**。文中引用的
> `ristretto_fp_program_air.rs`/`ristretto_msm_air.rs`/
> `ristretto_point_decode_air.rs` 与 11-bit limb 后端已随 Ristretto 移除
> 删除,相关小节仅存方法论价值。

# Performance follow-ups

This document records optimization candidates that require protocol-level
soundness work or clean release benchmarks before implementation.

## Dedicated scalar-multiplication AIR

`src/ristretto_fp_program_air.rs` already batches compressed fixed-window scalar
multiplication into one program STARK. The generic projective fixed-window path
still rejects schedules above the operation limit rather than silently proving
an incomplete relation. A dedicated AIR must bind the scalar windows, base,
point table, doubling/addition schedule, identity and zero-scalar cases. Keep
the current implementation as the oracle until a release benchmark and
negative soundness matrix show a net win.

## MSM accumulation tree

`src/ristretto_msm_air.rs` currently uses an ordered accumulation chain. A
balanced tree could reduce dependency depth, but it changes padding, node
indices, archive layout and transcript bindings. Benchmark N = 2, 4, 8, 16,
32, 52 in release mode before changing the wire format; test non-power-of-two
padding and sibling/level tampering.

## Workload-specific limb backend

The 11-bit limb backend is advantageous for production fixed-shape batches but
can regress very small programs because of fixed range-table cost. Establish a
release matrix over rows and operation mix before introducing a protocol-bound
backend selector. The verifier must not choose a local, unbound heuristic.

## Other resource work

- `src/outer_aggregate.rs`: evaluate bounded or streaming child encoding to
  reduce peak memory while preserving digest bytes.
- `src/ristretto_point_decode_air.rs`: isolate the legacy BigUint path or route
  production callers to the current program/fiat-crypto implementation.
- `src/state_root_binding.rs`: consider per-key single-flight after measuring
  concurrent cache misses; preserve deterministic transcript semantics.
- `src/error.rs` and `poker_l1/src/error.rs`: gradually replace generic strings
  with stable categories/source errors, starting at external-input boundaries.
- Metrics currently expose a library/RPC text exporter; the repository has no
  HTTP transport. A native `/metrics` route belongs in the upper-layer server,
  not in the transport-neutral RPC library.

All benchmarks and regression tests for these items must use the pinned nightly
and `--release`; debug proving tests are intentionally excluded because they
are prohibitively slow for this project.
