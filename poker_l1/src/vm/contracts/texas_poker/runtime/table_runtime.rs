//! TableRuntime——链运行时的门面（权威切换 Phase 2b 的目标入口）。
//!
//! 把 runtime 层的散件组合为一个可运行的"链"：交易认证（签名绑定
//! caller/selector/args/nonce）+ 入口队列（乱序容忍，fail-closed 收尾）+
//! `DispatchContext` 时钟供给（block_height 自增、block_timestamp 由调用方
//! 注入——runtime 不读墙钟）+ ProveTask/事件流收集。游戏运行时（texas
//! Phase 2b 起）只与本门面对话：提交签名交易、消费事件与状态视图、把
//! tasks 交给证明层。
//!
//! 重放策略：applied-nonce 集合——成功应用的 nonce 烧号，同签名重放被拒；
//! 业务失败的交易不烧号（可修正后重试）。nonce 绑定进签名消息（见
//! `dispatch::tx_message_hash`），跨槽挪用签名的交易验证不过。
//!
//! 队列冲刷是**全量重验**：暂存条目连同完整签名材料保存，每次重试都重新
//! 走签名验证 + 重放集检查 + 业务语义——不信任任何已入队状态。
//!
//! 与 texas 侧 `TableMirror` 的关系：mirror 是结算时一次性重放器（即弃），
//! 本门面是常驻权威入口——Phase 2b 完成后 mirror 退役。

use borsh::BorshDeserialize;

use super::dispatch::{dispatch_signed, tx_message_hash, SignedTx};
use super::events::TexasPokerEvent;
use super::pending::PendingQueue;
use super::prove_task::{L1DispatchOutput, L1ProveTask};
use super::types::TexasPokerTable;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::vm::contracts::dispatch::DispatchContext;
use crate::{Address, ChainId};

/// 一次提交的调用者身份（地址 + 钱包公钥——签名验证对象）。
#[derive(Debug, Clone)]
pub struct CallerIdentity {
    pub address: Address,
    pub pubkey: TaggedPubkey,
}

/// 一条待提交命令的完整材料（作为队列信封 Clone 存储）。
#[derive(Debug, Clone)]
pub struct Submission {
    pub caller: CallerIdentity,
    /// 本笔交易的共识时钟（毫秒）——由调用方注入。
    pub block_timestamp: u64,
    pub selector: [u8; 32],
    pub args: Vec<u8>,
    /// 钱包签名（ed25519 = 64B / secp256k1 = 65B，按 caller pubkey tag 路由）。
    pub signature: Vec<u8>,
    /// 发送方 nonce：进签名消息 + applied 集合防重放。
    pub nonce: u64,
}

/// 链运行时门面：一张表的权威交易入口。
pub struct TableRuntime {
    pub table: TexasPokerTable,
    chain_id: ChainId,
    block_height: u64,
    pending: PendingQueue<Submission>,
    applied_nonces: std::collections::HashSet<u64>,
    tasks: Vec<L1ProveTask>,
    events: Vec<TexasPokerEvent>,
}

impl TableRuntime {
    pub fn new(table: TexasPokerTable, chain_id: ChainId) -> Self {
        Self {
            table,
            chain_id,
            block_height: 0,
            pending: PendingQueue::new(64),
            applied_nonces: std::collections::HashSet::new(),
            tasks: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn pending(&self) -> &PendingQueue<Submission> {
        &self.pending
    }

    pub fn tasks(&self) -> &[L1ProveTask] {
        &self.tasks
    }

    pub fn events(&self) -> &[TexasPokerEvent] {
        &self.events
    }

    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    /// 未签名提交（服务器驱动方法：advance_deadline / force_fold 等管理
    /// 动作，以及 caller 身份由 host 背书的路径）。失败直接返回——不入队
    /// （服务器命令不做乱序容忍）。
    pub fn submit_unsigned(
        &mut self,
        caller: CallerIdentity,
        block_timestamp: u64,
        selector: &[u8; 32],
        args: &[u8],
    ) -> PokerL1Result<()> {
        let ctx = self.context(&caller, block_timestamp);
        let result = super::dispatch::dispatch(&ctx, &mut self.table, selector, args)?;
        collect_into(&result.return_value, &mut self.tasks, &mut self.events)?;
        Ok(())
    }

    /// 签名提交（玩家命令）：签名认证 + applied-nonce 防重放 + 乱序容忍
    /// （暂不可应用的命令连信封入队等待，不算失败；队列满则原样返回错误）。
    ///
    /// 认证（签名/重放）在入队**之前**前置校验：认证失败立即返回错误、
    /// 绝不入队——只有业务/相位类错误（典型：窗口未开）才延迟。
    pub fn submit_signed(&mut self, sub: Submission) -> PokerL1Result<()> {
        if self.applied_nonces.contains(&sub.nonce) {
            return Err(PokerL1Error::Serialization(format!(
                "tx nonce {} already applied (replay rejected)",
                sub.nonce
            )));
        }
        verify_submission(
            self.chain_id,
            &self.table.id,
            &sub.caller,
            &sub.selector,
            &sub.args,
            sub.nonce,
            &sub.signature,
        )?;
        let Self {
            table,
            chain_id,
            block_height,
            pending,
            applied_nonces,
            tasks,
            events,
        } = self;
        let mut apply = |envelope: &Submission, selector: &[u8; 32], args: &[u8]| {
            apply_submission(
                table,
                chain_id,
                block_height,
                applied_nonces,
                tasks,
                events,
                envelope,
                selector,
                args,
            )
        };
        let selector = sub.selector;
        let args = sub.args.clone();
        pending.submit(sub, &selector, &args, &mut apply)
    }

    /// 冲刷入口队列：按序全量重验重试暂存命令，返回本轮消化条数。
    pub fn flush_pending(&mut self) -> usize {
        let Self {
            table,
            chain_id,
            block_height,
            pending,
            applied_nonces,
            tasks,
            events,
        } = self;
        let mut apply = |envelope: &Submission, selector: &[u8; 32], args: &[u8]| {
            apply_submission(
                table,
                chain_id,
                block_height,
                applied_nonces,
                tasks,
                events,
                envelope,
                selector,
                args,
            )
        };
        pending.flush(&mut apply)
    }

    /// fail-closed 收尾：入口队列仍有未消化命令 = 显式错误（绝不静默丢弃）。
    pub fn finish(&self) -> PokerL1Result<()> {
        self.pending.deny_unmatched()
    }

    fn context(&mut self, caller: &CallerIdentity, block_timestamp: u64) -> DispatchContext {
        self.block_height += 1;
        DispatchContext {
            caller: caller.address,
            caller_pubkey: caller.pubkey.clone(),
            chain_id: self.chain_id,
            block_height: self.block_height,
            block_timestamp,
        }
    }
}

/// 认证前置：重放集检查 + 签名验证（无状态、可独立调用）。
#[allow(clippy::too_many_arguments)]
fn verify_submission(
    chain_id: ChainId,
    table_id: &crate::object_model::ObjectID,
    caller: &CallerIdentity,
    selector: &[u8; 32],
    args: &[u8],
    nonce: u64,
    signature: &[u8],
) -> PokerL1Result<()> {
    let msg_hash = tx_message_hash(chain_id, table_id, &caller.address, selector, args, nonce);
    crate::signature::verify_signature(&caller.pubkey, signature, &msg_hash)
}

/// 单条提交的全量重验与应用（认证 → dispatch → 产出收集）。
///
/// 在队列冲刷路径上同样**全量重跑认证**——不信任任何已入队状态。
#[allow(clippy::too_many_arguments)]
fn apply_submission(
    table: &mut TexasPokerTable,
    chain_id: &ChainId,
    block_height: &mut u64,
    applied_nonces: &mut std::collections::HashSet<u64>,
    tasks: &mut Vec<L1ProveTask>,
    events: &mut Vec<TexasPokerEvent>,
    sub: &Submission,
    selector: &[u8; 32],
    args: &[u8],
) -> PokerL1Result<()> {
    if applied_nonces.contains(&sub.nonce) {
        return Err(PokerL1Error::Serialization(format!(
            "tx nonce {} already applied (replay rejected)",
            sub.nonce
        )));
    }
    verify_submission(
        *chain_id,
        &table.id,
        &sub.caller,
        selector,
        args,
        sub.nonce,
        &sub.signature,
    )?;

    *block_height += 1;
    let ctx = DispatchContext {
        caller: sub.caller.address,
        caller_pubkey: sub.caller.pubkey.clone(),
        chain_id: *chain_id,
        block_height: *block_height,
        block_timestamp: sub.block_timestamp,
    };
    let tx = SignedTx {
        selector,
        args,
        signature: &sub.signature,
        nonce: sub.nonce,
    };
    let result = dispatch_signed(&ctx, table, tx)?;
    applied_nonces.insert(sub.nonce);
    collect_into(&result.return_value, tasks, events)?;
    Ok(())
}

/// 未签名分发（caller 身份由调用方背书的管理路径）——见 `submit_unsigned`。

fn collect_into(
    return_value: &[u8],
    tasks: &mut Vec<L1ProveTask>,
    events: &mut Vec<TexasPokerEvent>,
) -> PokerL1Result<()> {
    let output: L1DispatchOutput = borsh::from_slice(return_value)
        .map_err(|e| PokerL1Error::Serialization(format!("dispatch output decode: {e}")))?;
    if let Some(t) = output.prove_task {
        tasks.push(t);
    }
    events.extend(output.events);
    Ok(())
}
