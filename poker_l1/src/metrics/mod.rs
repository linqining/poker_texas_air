//! Prometheus 风格指标导出（缺口 #7）。
//!
//! 提供轻量级、线程安全的指标计数器/仪表，供节点运行时记录关键运行指标，
//! 并通过 JSON-RPC `get_metrics` 方法导出为 Prometheus exposition format 文本。
//!
//! 设计目标：
//! - 无外部依赖（不引入 `prometheus` / `metrics` crate，保持 std-only）
//! - `Send + Sync`，`Arc` 共享，原子操作无锁
//! - Prometheus text exposition format（`# HELP` / `# TYPE` / `name value`）
//!
//! # 指标列表
//!
//! | 指标 | 类型 | 含义 |
//! | --- | --- | --- |
//! | `zchain_block_height` | gauge | 当前 tip 高度 |
//! | `zchain_tx_total` | counter | 累计处理的 tx 数 |
//! | `zchain_block_time_ms` | histogram(sum/count) | 出块耗时（毫秒） |
//! | `zchain_peer_count` | gauge | 当前 P2P peer 数 |
//! | `zchain_mempool_size` | gauge | 交易池当前大小 |
//! | `zchain_gas_used_total` | counter | 累计 gas 用量 |

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// 节点运行指标收集器（线程安全，`Arc` 共享）。
#[derive(Debug)]
pub struct MetricsCollector {
    /// 当前 tip 高度（gauge）。
    block_height: AtomicU64,
    /// 累计 tx 数（counter）。
    tx_total: AtomicU64,
    /// 出块耗时累计毫秒（histogram sum）。
    block_time_ms_sum: AtomicU64,
    /// 出块次数（histogram count）。
    block_time_ms_count: AtomicU64,
    /// 当前 peer 数（gauge）。
    peer_count: AtomicU64,
    /// 交易池当前大小（gauge）。
    mempool_size: AtomicU64,
    /// 累计 gas 用量（counter）。
    gas_used_total: AtomicU64,
}

impl MetricsCollector {
    /// 创建空指标收集器。
    #[must_use]
    pub fn new() -> Self {
        Self {
            block_height: AtomicU64::new(0),
            tx_total: AtomicU64::new(0),
            block_time_ms_sum: AtomicU64::new(0),
            block_time_ms_count: AtomicU64::new(0),
            peer_count: AtomicU64::new(0),
            mempool_size: AtomicU64::new(0),
            gas_used_total: AtomicU64::new(0),
        }
    }

    /// 更新 tip 高度。
    pub fn set_block_height(&self, height: u64) {
        self.block_height.store(height, Ordering::Relaxed);
    }

    /// 累加 tx 数。
    pub fn inc_tx(&self, count: u64) {
        self.tx_total.fetch_add(count, Ordering::Relaxed);
    }

    /// 记录一次出块耗时（毫秒）。
    pub fn observe_block_time_ms(&self, ms: u64) {
        self.block_time_ms_sum.fetch_add(ms, Ordering::Relaxed);
        self.block_time_ms_count.fetch_add(1, Ordering::Relaxed);
    }

    /// 更新 peer 数。
    pub fn set_peer_count(&self, count: u64) {
        self.peer_count.store(count, Ordering::Relaxed);
    }

    /// 更新交易池大小。
    pub fn set_mempool_size(&self, size: u64) {
        self.mempool_size.store(size, Ordering::Relaxed);
    }

    /// 累加 gas 用量。
    pub fn inc_gas_used(&self, gas: u64) {
        self.gas_used_total.fetch_add(gas, Ordering::Relaxed);
    }

    /// 导出为 Prometheus text exposition format。
    ///
    /// 返回可直接作为 `get_metrics` RPC 响应的文本（每行一个指标）。
    #[must_use]
    pub fn export(&self) -> String {
        let mut out = String::with_capacity(512);
        // zchain_block_height (gauge)
        out.push_str("# HELP zchain_block_height Current tip block height.\n");
        out.push_str("# TYPE zchain_block_height gauge\n");
        out.push_str(&format!(
            "zchain_block_height {}\n",
            self.block_height.load(Ordering::Relaxed)
        ));
        // zchain_tx_total (counter)
        out.push_str("# HELP zchain_tx_total Total transactions processed.\n");
        out.push_str("# TYPE zchain_tx_total counter\n");
        out.push_str(&format!(
            "zchain_tx_total {}\n",
            self.tx_total.load(Ordering::Relaxed)
        ));
        // zchain_block_time_ms (histogram summary: sum + count)
        out.push_str("# HELP zchain_block_time_ms Block production time in ms (sum/count).\n");
        out.push_str("# TYPE zchain_block_time_ms summary\n");
        out.push_str(&format!(
            "zchain_block_time_ms_sum {}\n",
            self.block_time_ms_sum.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "zchain_block_time_ms_count {}\n",
            self.block_time_ms_count.load(Ordering::Relaxed)
        ));
        // zchain_peer_count (gauge)
        out.push_str("# HELP zchain_peer_count Current P2P peer count.\n");
        out.push_str("# TYPE zchain_peer_count gauge\n");
        out.push_str(&format!(
            "zchain_peer_count {}\n",
            self.peer_count.load(Ordering::Relaxed)
        ));
        // zchain_mempool_size (gauge)
        out.push_str("# HELP zchain_mempool_size Current mempool size.\n");
        out.push_str("# TYPE zchain_mempool_size gauge\n");
        out.push_str(&format!(
            "zchain_mempool_size {}\n",
            self.mempool_size.load(Ordering::Relaxed)
        ));
        // zchain_gas_used_total (counter)
        out.push_str("# HELP zchain_gas_used_total Total gas used.\n");
        out.push_str("# TYPE zchain_gas_used_total counter\n");
        out.push_str(&format!(
            "zchain_gas_used_total {}\n",
            self.gas_used_total.load(Ordering::Relaxed)
        ));
        out
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_export_contains_all_metrics() {
        let m = MetricsCollector::new();
        m.set_block_height(42);
        m.inc_tx(10);
        m.observe_block_time_ms(500);
        m.set_peer_count(3);
        m.set_mempool_size(7);
        m.inc_gas_used(1_000_000);
        let text = m.export();
        assert!(text.contains("zchain_block_height 42"));
        assert!(text.contains("zchain_tx_total 10"));
        assert!(text.contains("zchain_block_time_ms_sum 500"));
        assert!(text.contains("zchain_block_time_ms_count 1"));
        assert!(text.contains("zchain_peer_count 3"));
        assert!(text.contains("zchain_mempool_size 7"));
        assert!(text.contains("zchain_gas_used_total 1000000"));
    }

    #[test]
    fn metrics_counters_accumulate() {
        let m = MetricsCollector::new();
        m.inc_tx(5);
        m.inc_tx(3);
        m.inc_gas_used(100);
        m.inc_gas_used(200);
        let text = m.export();
        assert!(text.contains("zchain_tx_total 8"));
        assert!(text.contains("zchain_gas_used_total 300"));
    }

    #[test]
    fn metrics_export_is_valid_prometheus_format() {
        let m = MetricsCollector::new();
        let text = m.export();
        // 每个指标应有 HELP + TYPE + 值行
        for name in [
            "zchain_block_height",
            "zchain_tx_total",
            "zchain_block_time_ms",
            "zchain_peer_count",
            "zchain_mempool_size",
            "zchain_gas_used_total",
        ] {
            assert!(
                text.contains(&format!("# HELP {name}")),
                "缺少 HELP for {name}"
            );
            assert!(
                text.contains(&format!("# TYPE {name}")),
                "缺少 TYPE for {name}"
            );
        }
    }

    #[test]
    fn metrics_thread_safe_via_arc() {
        // 验证 Arc<MetricsCollector> 可跨线程共享（编译时保证）。
        let m = Arc::new(MetricsCollector::new());
        let m2 = Arc::clone(&m);
        m.set_block_height(1);
        m2.inc_tx(1);
        assert!(m.export().contains("zchain_block_height 1"));
        assert!(m2.export().contains("zchain_tx_total 1"));
    }
}
