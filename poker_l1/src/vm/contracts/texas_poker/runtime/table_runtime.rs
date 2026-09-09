//! TableRuntime——链运行时的门面（权威切换 Phase 2b 的目标入口）。
//!
//! 把 runtime 层的散件组合为一个可运行的"链"：交易完整性校验（Stark
//! Schnorr 签名绑定 caller/selector/args/nonce）+ 入口队列（乱序容忍，
//! fail-closed 收尾）+ `DispatchContext` 时钟供给（block_height 自增、
//! block_timestamp 由调用方注入——runtime 不读墙钟）+ ProveTask/事件流
//! 收集。游戏运行时（texas Phase 2b 起）只与本门面对话：提交签名交易、
//! 消费事件与状态视图、把 tasks 交给证明层。
//!
//! # 身份与信任模型（P1-2 会话委托，2026-09-10）
//!
//! **寻址**与**授权**分离：
//! - 寻址：`wallet_to_address`（felt 低 20 字节）给出座位的稳定 VM 地址——
//!   确定性派生只用于寻址，不用于授权；
//! - 授权：join 时每个座位登记**会话交易公钥**（`OccupiedSeat.tx_pk`，
//!   Stark Schnorr 32B 压缩点）。其与链上 vault 登记
//!   （`set_session_tx_pk` / 私密路径 `set_session_tx_pk_for`，买入同笔
//!   multicall/私交易完成）的一致性由游戏服务端在 join 接受点核验；
//!   之后本门面的签名交易**只按座位登记钥验证**。
//!
//! 会话钥是玩家客户端生成的随机新鲜钥（与 ElGamal 会话密钥同生命周期），
//! 知道钱包地址不再能推导出任何可用凭据——确定性身份的公开冒名面根除。
//! 未入座/未登记钥的签名提交 fail-closed 拒绝（不入队）。
//!
//! 重放策略不变：applied-nonce 集合——成功应用的 nonce 烧号，同签名重放
//! 被拒；业务失败的交易不烧号（可修正后重试）。nonce 绑定进签名消息
//! （见 `dispatch::tx_message_hash`）。
//!
//! 服务器管理路径（`submit_unsigned`）仍由 host 背书 caller 身份。
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

use super::caller_id;
use super::dispatch::{JoinTableArgs, dispatch, selectors, tx_message_hash};
use super::events::TexasPokerEvent;
use super::pending::PendingQueue;
use super::prove_task::{L1DispatchOutput, L1ProveTask};
use super::types::TexasPokerTable;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::vm::contracts::dispatch::DispatchContext;
use crate::{Address, ChainId};

/// 一次提交的调用者身份——全部字段由钱包地址确定性派生。
///
/// 字段私有 + 唯一构造器 [`CallerIdentity::from_wallet`]：外部无法注入
/// 失配的 (address, pubkey) 对（P1-2 认证缺口由构造方式根除）。
#[derive(Debug, Clone)]
pub struct CallerIdentity {
    wallet: String,
    address: Address,
    pubkey: TaggedPubkey,
}

impl CallerIdentity {
    /// 从 Starknet 钱包 felt hex 派生调用方身份。
    ///
    /// 派生公式见 [`caller_id`]（与客户端 `new_with_wallet_address` 同源）。
    pub fn from_wallet(wallet: &str) -> PokerL1Result<Self> {
        Ok(Self {
            address: caller_id::wallet_to_address(wallet)?,
            pubkey: caller_id::identity_tagged_pk(wallet),
            wallet: wallet.to_string(),
        })
    }

    /// 钱包 felt hex（唯一身份源）。
    #[must_use]
    pub fn wallet(&self) -> &str {
        &self.wallet
    }

    /// VM 20 字节地址（felt 低 20 字节）。
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// 身份公钥（Stark Schnorr tagged，32B 压缩点）。
    ///
    /// 注意：这是**确定性派生**公钥，仅供 unsigned 管理路径的
    /// `DispatchContext` 填充——签名交易的验证锚是座位登记的会话公钥
    /// （`OccupiedSeat.tx_pk`），不是它。
    #[must_use]
    pub const fn pubkey(&self) -> &TaggedPubkey {
        &self.pubkey
    }
}

/// 一条待提交命令的完整材料（作为队列信封 Clone 存储）。
#[derive(Debug, Clone)]
pub struct Submission {
    /// 发送方钱包 felt hex——身份（地址/公钥）在应用时确定性派生。
    pub wallet: String,
    /// 本笔交易的共识时钟（毫秒）——由调用方注入。
    pub block_timestamp: u64,
    pub selector: [u8; 32],
    pub args: Vec<u8>,
    /// Stark Schnorr 签名（64B = R‖s，方案见 [`crate::signature::stark_scheme`]）。
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

    /// 签名提交（玩家命令）：完整性校验（Stark Schnorr，钱包确定性身份）
    /// + applied-nonce 防重放 + 乱序容忍（暂不可应用的命令连信封入队
    /// 等待，不算失败；队列满则原样返回错误）。
    ///
    /// 认证（签名/重放/钱包格式）在入队**之前**前置校验：失败立即返回
    /// 错误、绝不入队——只有业务/相位类错误（典型：窗口未开）才延迟。
    pub fn submit_signed(&mut self, sub: Submission) -> PokerL1Result<()> {
        if self.applied_nonces.contains(&sub.nonce) {
            return Err(PokerL1Error::Serialization(format!(
                "tx nonce {} already applied (replay rejected)",
                sub.nonce
            )));
        }
        verify_submission(
            self.chain_id,
            &self.table,
            &sub.wallet,
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

/// 认证前置：钱包寻址 + 座位登记钥解析 + 签名验证。
///
/// 验签锚是 `table.seats` 里该钱包座位登记的会话交易公钥（P1-2 会话
/// 委托）——不是任何派生公钥。钱包格式非法、未入座/未登记钥、签名不
/// 匹配 = 立即失败（调用方据此拒绝入队，fail-closed）。
#[allow(clippy::too_many_arguments)]
fn verify_submission(
    chain_id: ChainId,
    table: &TexasPokerTable,
    wallet: &str,
    selector: &[u8; 32],
    args: &[u8],
    nonce: u64,
    signature: &[u8],
) -> PokerL1Result<()> {
    let address = caller_id::wallet_to_address(wallet)?;
    // 验签锚：座位登记的会话公钥。未入座钱包唯一的例外是 join_table
    // 本身——鸡生蛋问题的解：join 命令的锚取 **args 内声明的 tx_pk**
    // （生产路径该 args 由服务端经 vault `set_session_tx_pk[_for]` 核验
    // 后才放行到本门面），且声明的 player 必须与钱包派生地址一致；
    // 入座后所有命令一律按座位登记钥验证。
    let tx_pk = match table.registered_tx_pk_of(&address) {
        Some(pk) => pk.clone(),
        None => {
            if *selector != selectors::join_table() {
                return Err(PokerL1Error::Serialization(format!(
                    "no registered session tx public key for wallet {wallet} at this table"
                )));
            }
            let join: JoinTableArgs = borsh::from_slice(args).map_err(|e| {
                PokerL1Error::Serialization(format!("join_table args decode: {e}"))
            })?;
            if join.player != address {
                return Err(PokerL1Error::Serialization(
                    "join_table declared player does not match the submitting wallet".into(),
                ));
            }
            join.tx_pk
        }
    };
    let msg_hash = tx_message_hash(chain_id, &table.id, &address, selector, args, nonce);
    crate::signature::verify_signature(&tx_pk, signature, &msg_hash)
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
    verify_submission(*chain_id, table, &sub.wallet, selector, args, sub.nonce, &sub.signature)?;

    let caller = CallerIdentity::from_wallet(&sub.wallet)?;
    *block_height += 1;
    let ctx = DispatchContext {
        caller: caller.address,
        caller_pubkey: caller.pubkey.clone(),
        chain_id: *chain_id,
        block_height: *block_height,
        block_timestamp: sub.block_timestamp,
    };
    // 签名已在上方 verify_submission 按**座位登记的会话公钥**全量验证；
    // 不走 dispatch_signed 二次验签——它的锚是 context.caller_pubkey
    // （寻址派生公钥，非会话钥），会话钥签名在那里必然失败。
    let result = dispatch(&ctx, table, selector, args)?;
    applied_nonces.insert(sub.nonce);
    collect_into(&result.return_value, tasks, events)?;
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    const WALLET: &str = "0x6e37d33462f7319261396d7d7f669d147e40cdef91c6a8305cfde771805c782";
    const OTHER: &str = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    #[test]
    fn caller_identity_is_derived_only() {
        let id = CallerIdentity::from_wallet(WALLET).unwrap();
        assert_eq!(id.wallet(), WALLET);
        // address = felt 低 20 字节（与 caller_id 公式一致）
        assert_eq!(id.address(), caller_id::wallet_to_address(WALLET).unwrap());
        // pubkey = 确定性身份公钥（Stark scheme）
        assert_eq!(id.pubkey().raw, caller_id::identity_tagged_pk(WALLET).raw);
        // 同一钱包派生稳定，不同钱包不同地址
        assert_eq!(
            CallerIdentity::from_wallet(WALLET).unwrap().address(),
            id.address()
        );
        assert_ne!(
            CallerIdentity::from_wallet(OTHER).unwrap().address(),
            id.address()
        );
        // 非法钱包格式拒绝
        assert!(CallerIdentity::from_wallet("not-hex!").is_err());
    }

    #[test]
    fn signed_submission_anchors_to_seat_registered_key() {
        use crate::object_model::ObjectID;
        use crate::signature::stark_scheme;
        use crate::vm::contracts::texas_poker::runtime::dispatch::{
            selectors, tx_message_hash, CreateTableArgs, JoinTableArgs,
        };
        use poker_protocol::crypto::curve::{CurvePoint, CurveScalar};

        // 客户端会话密钥（随机新鲜钥——P1-2 会话委托的授权锚）。
        let session_sk =
            poker_protocol::crypto::types::hash_to_scalar(b"test-session-secret");
        let session_pk_raw =
            (poker_protocol::crypto::types::base_g() * session_sk)
                .compress()
                .as_ref()
                .to_vec();
        let session_pk = crate::signature::TaggedPubkey::new(
            crate::signature::SignatureScheme::Stark,
            crate::signature::CURRENT_VERSION,
            session_pk_raw,
        )
        .unwrap();

        let table = TexasPokerTable::new(
            ObjectID::new([0x5A; 20], 1),
            "t".into(),
            [0xC0; 20],
            2,
            10,
            20,
        );
        let mut rt = TableRuntime::new(table, 377);
        rt.submit_unsigned(
            CallerIdentity::from_wallet(OTHER).unwrap(),
            1,
            &selectors::create_table(),
            &borsh::to_vec(&CreateTableArgs {
                name: "t".into(),
                max_players: 2,
                small_blind: 10,
                big_blind: 20,
            })
            .unwrap(),
        )
        .expect("create_table");

        // 未入座/未登记：任何签名（含钱包确定性身份的签名）都必须被拒。
        let msg = tx_message_hash(
            377,
            &rt.table.id,
            &caller_id::wallet_to_address(WALLET).unwrap(),
            &[1u8; 32],
            &[2u8; 8],
            1,
        );
        // 用（已废弃授权职能的）确定性身份钥签名——证明派生钥不再是锚。
        let derived_sig =
            stark_scheme::sign(&caller_id::identity_sk(WALLET), &msg).to_vec();
        let sub_unregistered = Submission {
            wallet: WALLET.to_string(),
            block_timestamp: 1,
            selector: [1u8; 32],
            args: vec![2u8; 8],
            signature: derived_sig,
            nonce: 1,
        };
        assert!(
            rt.submit_signed(sub_unregistered).is_err(),
            "no seat yet: derived-identity signature must be rejected"
        );
        assert!(rt.pending().is_empty(), "auth failure must not enqueue");

        // WALLET 入座并登记会话钥（join 语义校验在 core；此处经 unsigned
        // 路径复用 dispatch，模拟服务端已核验 vault 登记后的放行）。
        let join_args = JoinTableArgs::with_key(
            caller_id::wallet_to_address(WALLET).unwrap(),
            1_000,
            poker_protocol::crypto::types::Scalar::from_u64(42),
            poker_protocol::crypto::types::Scalar::from_u64(4_242),
        )
        .unwrap()
        .with_tx_pk(session_pk);
        rt.submit_unsigned(
            CallerIdentity::from_wallet(WALLET).unwrap(),
            2,
            &selectors::join_table(),
            &borsh::to_vec(&join_args).unwrap(),
        )
        .expect("join_table registers session key");

        // 会话钥签名通过认证（selector 无效 → 业务失败 → 入队等待）。
        // 签名消息须与提交的 nonce（2）一致。
        let msg_n2 = tx_message_hash(
            377,
            &rt.table.id,
            &caller_id::wallet_to_address(WALLET).unwrap(),
            &[1u8; 32],
            &[2u8; 8],
            2,
        );
        let session_sig = stark_scheme::sign(&session_sk, &msg_n2).to_vec();
        let sub_ok = Submission {
            wallet: WALLET.to_string(),
            block_timestamp: 3,
            selector: [1u8; 32],
            args: vec![2u8; 8],
            signature: session_sig,
            nonce: 2,
        };
        rt.submit_signed(sub_ok)
            .expect("session-key signature authenticates");
        assert_eq!(rt.pending().len(), 1);

        // 他人的会话钥签名不能冒充 WALLET（跨座顶替；nonce=3 的消息）。
        let other_session_sk =
            poker_protocol::crypto::types::hash_to_scalar(b"test-session-secret-other");
        let msg_n3 = tx_message_hash(
            377,
            &rt.table.id,
            &caller_id::wallet_to_address(WALLET).unwrap(),
            &[1u8; 32],
            &[2u8; 8],
            3,
        );
        let forged_sig = stark_scheme::sign(&other_session_sk, &msg_n3).to_vec();
        let sub_forged = Submission {
            wallet: WALLET.to_string(),
            block_timestamp: 4,
            selector: [1u8; 32],
            args: vec![2u8; 8],
            signature: forged_sig,
            nonce: 3,
        };
        assert!(
            rt.submit_signed(sub_forged).is_err(),
            "cross-session substitution must be rejected"
        );
        assert_eq!(rt.pending().len(), 1, "queue unchanged on auth failure");
    }
}
