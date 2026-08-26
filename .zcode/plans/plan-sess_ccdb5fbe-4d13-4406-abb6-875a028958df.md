## 本轮目标

继续完成剩余优化，不触碰 `poker_l1` 和 `poker_contracts`。

### 1. Cross-key 位置索引绑定 + 重复 scalar window proof 复用

修改 `src/ristretto_reconstruction_relation_air.rs`：

- 不改变公开 archive wire 字段类型，保持 `scalar_windows: Vec<ArchivedRistrettoScalarWindowsProof>`。
- 在 `prove_ristretto_reconstruction_relation` 内部：

  - 按 `scalar_inputs` 的 8 个 scalar 计算一组 `(scalar, windows)` 对，去重后得到 unique 集合。
  - 对 unique 集合调用 `prove_ristretto_scalar_windows` 并保留 `(scalar -> proof)` 映射。
  - `scalar_windows` 数组按 `scalar_inputs` 顺序重建：重复 scalar 共享同一 proof，但每个 slot 都独立 clone 到 archive 中。

- `verify_ristretto_reconstruction_relation`：

  - 保留现有位置索引 zip 校验，不引入 `.find()`。
  - 保留 scalar 值绑定（防止 splice），但 `.find()` 替换为 index-aligned zip。
  - 增加 negative 测试：重复 scalar 的两处 slot 使用不同 windows 必须被拒。

注意：

- 不改变 `ScalarWindowsProof` 内部结构；
- 不公开新内部 helper；
- archive wire 仍然相同，所以下游反序列化不受影响。

### 2. Fixed-base table host cache

修改 `src/ristretto_fp_program_air.rs`：

- 新增 crate-private `point_addition_program_cache`，key 为 `(left_encoding, right_encoding)`，value 为 `(RistrettoFpProgram, output)`。
- 缓存为 `RwLock<HashMap<(CompressedPoint, CompressedPoint), …>>`，先尝试读路径。
- 修改 `build_ristretto_fp_program_compressed_point_addition`，命中时直接 clone；不命中时正常计算并写入。
- 这只影响 host 重建速度，不影响 proof 或 transcript。

### 3. 验证

- release-only：

```bash
cargo +nightly check --release -p poker_texas_air --lib
RUSTFLAGS='--cfg=texas_release_tests' \
  cargo +nightly test --release -p poker_texas_air --features test-helpers --lib \
  ristretto_reconstruction_relation_air
cargo +nightly test --release -p poker_texas_air --lib dual_proof
```

- 不运行 debug 测试，不触碰 `poker_l1` 或 `poker_contracts`。
- 性能验证：复用之前 `target-bench/results/scalar-mul-batch.txt` 风格，新增 cross-key relation 微基准对照（有/无 scalar window cache），记录 prove/verify/archive。

### 4. 不变更部分

- 协议 wire；
- 跨 layer relations、accumulator、slot-OR；
- `poker_l1` 与 `poker_contracts`。