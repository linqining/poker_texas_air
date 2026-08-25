## 目标

专注证明/AIR 优化，不修改 `poker_l1`，也不触碰用户已有的 `poker_contracts` 文件。实现 slot-OR scalar multiplication 的全局 batch，保持每个 335-row fixed-window schedule 和每行约束不变。

## 1. Archive 结构升级

修改 `src/ristretto_reconstruction_slot_or_air.rs`：

- 将 `ArchivedRistrettoReconstructionSlotOrBatchProof.scalar_multiplications` 从：
  ```rust
  Vec<ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof>
  ```
  改为单个：
  ```rust
  ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof
  ```
- 该 batch 的 `statements` 固定为 `SLOT_COUNT * SCALAR_MUL_COUNT = 416`，顺序严格为：
  ```text
  global_row = slot * 8 + input_index
  ```
- 在 archive 中增加明确的 slot-OR proof layout/version 常量；不要静默解析旧的 per-slot Borsh layout。若历史 archive 需要继续读取，提供旧结构 decoder 或明确拒绝并测试。
- 所有外层 relation/archive wire 通过现有 Borsh 嵌套自动使用新字段，但需增加版本识别或外层版本约束，防止旧/新 layout 混用。

## 2. Prove 路径合并

在 `prove_ristretto_reconstruction_slot_or_batch`：

1. 保留现有 `inputs_per_slot` 和 shared `scalar_windows` 构造。
2. 按 slot-major 顺序构造一个 `Vec<(scalar, windows, base)>`，长度 416。
3. 调用一次：
   ```rust
   prove_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(all_inputs)
   ```
4. 从全局 batch 的 statements 按 `slot * 8 + index` 切片构造 additions 输出，保留现有 point-addition batch 的 260 行顺序。
5. 保留 self-verify 入口，验证器必须验证全局 batch 一次。

## 3. Verify 路径绑定

在 `validate_slot_or_batch_cardinality`：

- 要求 `scalar_multiplications.statements.len() == 416`；
- 要求其 additions programs 数量等于 `416 * 335`；
- 保留 statements、challenge rows、scalar windows、slot statements 的 cardinality 检查。

在 `verify_ristretto_reconstruction_slot_or_batch`：

- 逐 slot、逐 input 检查：
  - global batch statement 的 scalar/base/windows 与 `scalar_inputs` 一致；
  - scalar-window row `slot * 8 + index` 一致；
- 验证全局 compressed scalar multiplication batch 一次；
- 按同样的 global statement offsets 提取每 slot 的 8 个 outputs，生成现有 `expected_additions`；
- 保持 additions 的 slot-major row binding和最终 shared STARK 验证。

## 4. Soundness 测试

更新现有 slot-OR tests 和 archive fixture：

- roundtrip 通过；
- 交换两个不同 slot 的 global statements 被拒绝；
- 交换同一 slot 的 input rows 被拒绝；
- scalar-window row 与 global statement 不匹配被拒绝；
- 删除/追加一条 global statement 被拒绝；
- global additions row slice 跨 slot 交换被拒绝；
- 旧 per-slot archive bytes 不被静默解析（明确版本错误或独立 legacy decoder）。

这些测试使用现有 release fixture；不运行 debug。

## 5. 性能验证

在 release 下记录 N=52 slot-OR：

- prove wall time；
- verify wall time；
- archive bytes；
- scalar-multiplication commitment 数量；
- peak RSS（若环境可用）。

预期：底层 139,360 行 arithmetic schedule 不变，但 52 个 scalar-multiplication STARK 合并为 1 个，显著降低固定 commitment/FRI 和序列化开销。若证明域/内存超过当前限制，则按固定 slot 分组（例如 4 或 8 个 slot 一个 batch）回退为分组方案。

## 6. Release-only 验证命令

```bash
git diff --check
cargo +nightly check --release -p poker_texas_air --lib
RUSTFLAGS='--cfg=texas_release_tests' cargo +nightly test --release \
  -p poker_texas_air --features test-helpers --lib \
  ristretto_reconstruction_slot_or_air
RUSTFLAGS='--cfg=texas_release_tests' cargo +nightly test --release \
  -p poker_texas_air --features test-helpers --lib \
  ristretto_reconstruction_relation_air
```

如果全局 416-row batch 的内存/域大小不可接受，保留每 4/8 个 slot 分组 batch，并记录 release benchmark 结果；不回退到 debug 测试。