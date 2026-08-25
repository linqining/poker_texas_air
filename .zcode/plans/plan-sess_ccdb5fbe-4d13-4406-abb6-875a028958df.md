## 本轮实施

### 1. Metrics sum/count 快照一致性

修改 `poker_l1/src/metrics/mod.rs`：

- `observe_block_time_ms` 使用 Release 顺序更新 sum/count；
- `export` 先 Acquire 读取 count，再 Acquire 读取 sum；
- 保持 Prometheus 文本格式和指标名称不变；
- 增加零耗时观察测试和多线程累加测试，验证最终 sum/count 正确。

这项改动不涉及协议和外部依赖，适合立即合并。

### 2. State-root cache 暂缓 single-flight

当前 single-flight 需要 Condvar/失败清理和 panic-safe 设计，直接修改风险较高。本轮只记录为后续项，不在没有专门并发测试的情况下改动证明缓存协调逻辑。

### 3. Release-only 验证

```bash
git diff --check
cargo +nightly check --release -p poker_l1 --lib
cargo +nightly test --release -p poker_l1 --lib metrics
```

不运行 debug 测试，不触碰 `poker_contracts/` 用户已有改动。