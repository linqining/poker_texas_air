//! 入口队列（链运行时的乱序容忍语义）。
//!
//! 游戏运行时接受异步乱序提交（reveal 令牌可早于/晚于相位窗口到达），而
//! VM 状态机是相位序敏感的。此前乱序容忍靠结算重放的两遍重排技巧
//! （texas mirror）或影子表的 deferred 缓冲实现——本模块把它升格为链
//! 运行时的正式语义：**提前到达的命令入队等待，窗口打开后按序重放**。
//!
//! 队列泛型于信封 `E`：暂存的不只是 (selector, args)，还有调用方提供的
//! 完整提交材料（签名、caller、时钟等，见 `TableRuntime` 的 `Submission`）。
//! 冲刷时**全量重验**（签名 + 重放集 + 业务语义）——不信任任何已入队状态。
//!
//! 与历史实现的本质区别是收尾语义：历史上未消化的 reveal 只告警放行
//! （mirror.rs 的静默丢弃类缺陷）；这里 [`PendingQueue::deny_unmatched`]
//! 返回显式错误——任何命令都不允许无声消失（fail-closed）。

use crate::error::{PokerL1Error, PokerL1Result};

/// 一条暂存的入口命令（相位未开，等待重放）。
#[derive(Debug, Clone)]
pub struct PendingEntry<E> {
    /// 提交信封（签名材料 / caller / 时钟——冲刷时全量重验）。
    pub envelope: E,
    pub selector: [u8; 32],
    pub args: Vec<u8>,
    /// 被重试过但仍未消化的次数。
    pub hold_count: usize,
}

/// 入口命令队列。
///
/// `apply` 闭包由持有 VM 状态的一方提供（通常是
/// [`super::table_runtime::TableRuntime`]）：收到信封 + 命令后做**全量
/// 重验并应用**：
/// - `Ok(())`：命令已应用（出队）；
/// - `Err(_)`：当前仍不可应用（典型：相位未开）→ 继续暂存，不算失败。
#[derive(Debug, Default)]
pub struct PendingQueue<E> {
    entries: Vec<PendingEntry<E>>,
    max_entries: usize,
    held_total: usize,
    flushed_total: usize,
}

impl<E: Clone> PendingQueue<E> {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
            held_total: 0,
            flushed_total: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn held_total(&self) -> usize {
        self.held_total
    }

    pub fn flushed_total(&self) -> usize {
        self.flushed_total
    }

    /// 提交一条命令：可直接应用则立即执行；暂不可应用则连信封入队
    /// （不返回错误）。队列已满时原样返回应用的错误（不吞、不挤占——
    /// 背压直通调用方）。
    pub fn submit(
        &mut self,
        envelope: E,
        selector: &[u8; 32],
        args: &[u8],
        apply: &mut dyn FnMut(&E, &[u8; 32], &[u8]) -> PokerL1Result<()>,
    ) -> PokerL1Result<()> {
        match apply(&envelope, selector, args) {
            Ok(()) => Ok(()),
            Err(e) => {
                if self.entries.len() >= self.max_entries {
                    return Err(e);
                }
                self.entries.push(PendingEntry {
                    envelope,
                    selector: *selector,
                    args: args.to_vec(),
                    hold_count: 0,
                });
                self.held_total += 1;
                Ok(())
            }
        }
    }

    /// 冲刷：按入队序全量重验重试，直到一轮内无进展（消化一条可能解锁
    /// 下一条）。返回本轮消化的条数。
    pub fn flush(
        &mut self,
        apply: &mut dyn FnMut(&E, &[u8; 32], &[u8]) -> PokerL1Result<()>,
    ) -> usize {
        let mut flushed = 0;
        let mut progressed = true;
        while progressed {
            progressed = false;
            let mut i = 0;
            while i < self.entries.len() {
                let entry = &self.entries[i];
                if apply(&entry.envelope, &entry.selector, &entry.args).is_ok() {
                    self.entries.remove(i);
                    self.flushed_total += 1;
                    flushed += 1;
                    progressed = true;
                } else {
                    self.entries[i].hold_count += 1;
                    i += 1;
                }
            }
        }
        flushed
    }

    /// fail-closed 收尾：仍有未消化命令 = 显式错误（附完整清单），
    /// 绝不静默丢弃。
    pub fn deny_unmatched(&self) -> PokerL1Result<()>
    where
        E: std::fmt::Debug,
    {
        if self.entries.is_empty() {
            return Ok(());
        }
        let detail = self
            .entries
            .iter()
            .map(|e| {
                format!(
                    "selector={:02x?} hold_count={}",
                    e.selector[0..4].to_vec(),
                    e.hold_count
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        Err(PokerL1Error::Serialization(format!(
            "pending queue has {} unmatched command(s) at hand end — fail-closed: {detail}",
            self.entries.len()
        )))
    }
}
