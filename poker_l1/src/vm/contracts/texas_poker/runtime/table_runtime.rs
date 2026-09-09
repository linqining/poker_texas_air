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
//! 重放策略：**按账户 nonce 水位**（Ethereum 式）——`nonce > last` 接受，
//! `nonce <= last` 判重放/陈旧拒绝（[`crate::error::PokerL1Error::StaleTxNonce`]，
//! 入口队列据此死信不重试）。nonce 绑定进签名消息（见
//! `dispatch::tx_message_hash`），跨槽挪用签名的交易验证不过。
//!
//! join 路径：签名提交**不接受** join_table（未入座无锚，P1-2 修复）——
//! join 由 host 完成 vault 登记核验（`set_session_tx_pk[_for]` 对拍）后经
//! `submit_unsigned` 背书提交；签名通道只服务已入座玩家命令。
//!
//! 服务器管理路径（`submit_unsigned`）仍由 host 背书 caller 身份。
//!
//! 队列冲刷是**全量重验**：暂存条目连同完整签名材料保存，每次重试都重新
//! 走签名验证 + nonce 水位检查 + 业务语义——不信任任何已入队状态。
//!
//! 与 texas 侧 `TableMirror` 的关系：texas 经本门面在每个接受点同步
//! dispatch（实时 VM 镜像 = 手牌唯一 VM 状态表示），结算直接取用其
//! ProveTask 链与 pre-payout 快照。

use super::caller_id;
use super::dispatch::{dispatch, tx_message_hash};
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
    /// 命令 selector（32 字节方法选择子，`dispatch::selectors` 的产出）。
    pub selector: [u8; 32],
    /// 命令参数（对应 selector 的 `*Args` 的 borsh 编码）。
    pub args: Vec<u8>,
    /// Stark Schnorr 签名（64B = R‖s，方案见 [`crate::signature::stark_scheme`]）。
    pub signature: Vec<u8>,
    /// 发送方 nonce：绑定进签名消息，应用成功后抬升账户水位（防重放）。
    pub nonce: u64,
}

/// 链运行时门面：一张表的权威交易入口。
pub struct TableRuntime {
    /// VM 权威表状态（dispatch 的唯一可变对象）。
    pub table: TexasPokerTable,
    chain_id: ChainId,
    block_height: u64,
    pending: PendingQueue<Submission>,
    /// 按账户的已应用 nonce 水位（wallet 派生地址 → last nonce）。
    /// P1-1 修复（2026-09-10）：nonce 命名空间**按账户**——全局命名空间
    /// 下两个玩家各自从 1 计数必然碰撞（误判重放 + 恶意消耗区间 DoS）。
    /// Ethereum 式语义：`nonce > last` 接受（允许跳号），`nonce <= last`
    /// 判重放拒绝。水位制同时消灭无界集合内存增长。
    account_nonces: std::collections::HashMap<Address, u64>,
    tasks: Vec<L1ProveTask>,
    events: Vec<TexasPokerEvent>,
}

impl TableRuntime {
    /// 建门面：`chain_id` 进签名消息域（防跨链签名挪用），队列容量 64。
    pub fn new(table: TexasPokerTable, chain_id: ChainId) -> Self {
        Self {
            table,
            chain_id,
            block_height: 0,
            pending: PendingQueue::new(64),
            account_nonces: std::collections::HashMap::new(),
            tasks: Vec::new(),
            events: Vec::new(),
        }
    }

    /// 入口队列（乱序容忍暂存 + 死信清单）。
    pub fn pending(&self) -> &PendingQueue<Submission> {
        &self.pending
    }

    /// 已收集的证明任务（交证明层消费）。
    pub fn tasks(&self) -> &[L1ProveTask] {
        &self.tasks
    }

    /// 已收集的表事件（广播/审计消费）。
    pub fn events(&self) -> &[TexasPokerEvent] {
        &self.events
    }

    /// 当前块高（每次 dispatch 自增；驱动 VM 内的超时/相位逻辑）。
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

    /// 签名提交（玩家命令）：完整性校验（座位登记的会话公钥）+ 按账户
    /// nonce 水位防重放 + 乱序容忍（暂不可应用的命令连信封入队等待，
    /// 不算失败；队列满则原样返回错误）。
    ///
    /// 认证（签名/重放/钱包格式）在入队**之前**前置校验：失败立即返回
    /// 错误、绝不入队——只有业务/相位类错误（典型：窗口未开）才延迟。
    pub fn submit_signed(&mut self, sub: Submission) -> PokerL1Result<()> {
        let address = caller_id::wallet_to_address(&sub.wallet)?;
        if let Some(last) = self.account_nonces.get(&address) {
            if sub.nonce <= *last {
                return Err(PokerL1Error::StaleTxNonce { nonce: sub.nonce });
            }
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
            account_nonces,
            tasks,
            events,
        } = self;
        let mut apply = |envelope: &Submission, selector: &[u8; 32], args: &[u8]| {
            apply_submission(
                table,
                chain_id,
                block_height,
                account_nonces,
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
            account_nonces,
            tasks,
            events,
        } = self;
        let mut apply = |envelope: &Submission, selector: &[u8; 32], args: &[u8]| {
            apply_submission(
                table,
                chain_id,
                block_height,
                account_nonces,
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
    // 验签锚：座位登记的会话公钥——**无例外**（P1-2 修复 2026-09-10：
    // 移除 join_table 自登记例外）。未入座钱包没有任何可验签的锚，
    // 一律拒绝——否则任何持钥者可为任意钱包构造自洽的冒名 join。
    // join 的会话钥与链上 vault 登记的一致性由 **host 在放行前核验**
    //（`verify_session_tx_pk`，vault `active_session_tx_pk` view 对拍），
    // 随后经 host 背书的 `submit_unsigned` 提交（join 即管理路径）。
    let tx_pk = table.registered_tx_pk_of(&address).ok_or_else(|| {
        PokerL1Error::Serialization(format!(
            "no registered session tx public key for wallet {wallet} at this table"
        ))
    })?;
    let msg_hash = tx_message_hash(chain_id, &table.id, &address, selector, args, nonce);
    crate::signature::verify_signature(tx_pk, signature, &msg_hash)
}

/// 单条提交的全量重验与应用（认证 → dispatch → 产出收集）。
///
/// 在队列冲刷路径上同样**全量重跑认证**——不信任任何已入队状态。
#[allow(clippy::too_many_arguments)]
fn apply_submission(
    table: &mut TexasPokerTable,
    chain_id: &ChainId,
    block_height: &mut u64,
    account_nonces: &mut std::collections::HashMap<Address, u64>,
    tasks: &mut Vec<L1ProveTask>,
    events: &mut Vec<TexasPokerEvent>,
    sub: &Submission,
    selector: &[u8; 32],
    args: &[u8],
) -> PokerL1Result<()> {
    let address = caller_id::wallet_to_address(&sub.wallet)?;
    if let Some(last) = account_nonces.get(&address) {
        if sub.nonce <= *last {
            // 陈旧/重放：确定性失败，入口队列据此死信（不重试）。
            return Err(PokerL1Error::StaleTxNonce { nonce: sub.nonce });
        }
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
    // 不做二次验签（派生公钥不是锚，会话钥签名在那种锚下必然失败）。
    let result = dispatch(&ctx, table, selector, args)?;
    account_nonces
        .entry(address)
        .and_modify(|last| *last = (*last).max(sub.nonce))
        .or_insert(sub.nonce);
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

        // P1-2 回归：自洽的签名 join 也必须被拒（未入座无锚，无例外）——
        // 否则任何持钥者可为任意钱包构造冒名入座。用**未入座**的第三方
        // 钱包 + 其自持会话钥签名（全部自洽）验证。
        const W3: &str = "0x00000000000000000000000000000000000000000000000000000000dead03";
        let w3_sk =
            poker_protocol::crypto::types::hash_to_scalar(b"test-session-secret-w3");
        let w3_pk_raw = (poker_protocol::crypto::types::base_g() * w3_sk)
            .compress()
            .as_ref()
            .to_vec();
        let w3_pk = crate::signature::TaggedPubkey::new(
            crate::signature::SignatureScheme::Stark,
            crate::signature::CURRENT_VERSION,
            w3_pk_raw,
        )
        .unwrap();
        let w3_join_args = borsh::to_vec(
            &JoinTableArgs::with_key(
                caller_id::wallet_to_address(W3).unwrap(),
                1_000,
                poker_protocol::crypto::types::Scalar::from_u64(9),
                poker_protocol::crypto::types::Scalar::from_u64(9_009),
            )
            .unwrap()
            .with_tx_pk(w3_pk),
        )
        .unwrap();
        let w3_msg = tx_message_hash(
            377,
            &rt.table.id,
            &caller_id::wallet_to_address(W3).unwrap(),
            &selectors::join_table(),
            &w3_join_args,
            1,
        );
        let w3_sig = stark_scheme::sign(&w3_sk, &w3_msg).to_vec();
        let sub_join = Submission {
            wallet: W3.to_string(),
            block_timestamp: 5,
            selector: selectors::join_table(),
            args: w3_join_args,
            signature: w3_sig,
            nonce: 1,
        };
        let join_err = rt
            .submit_signed(sub_join)
            .expect_err("signed join_table must be rejected — joins are host-endorsed");
        assert!(
            join_err.to_string().contains("no registered session tx public key"),
            "join rejection reason, got: {join_err}"
        );

        // P1-1 回归：按账户 nonce 命名空间。两家各用 nonce=1 的
        // leave_table（WAITING 态可离座，真实应用、烧号）——全局命名空间
        // 下第二家必被误判"重放"拒绝，按账户水位必须双双通过。
        let w2_session_sk =
            poker_protocol::crypto::types::hash_to_scalar(b"test-session-secret-w2");
        let w2_pk_raw = (poker_protocol::crypto::types::base_g() * w2_session_sk)
            .compress()
            .as_ref()
            .to_vec();
        let w2_pk = crate::signature::TaggedPubkey::new(
            crate::signature::SignatureScheme::Stark,
            crate::signature::CURRENT_VERSION,
            w2_pk_raw,
        )
        .unwrap();
        let w2_join = JoinTableArgs::with_key(
            caller_id::wallet_to_address(OTHER).unwrap(),
            1_000,
            poker_protocol::crypto::types::Scalar::from_u64(7),
            poker_protocol::crypto::types::Scalar::from_u64(7_007),
        )
        .unwrap()
        .with_tx_pk(w2_pk);
        rt.submit_unsigned(
            CallerIdentity::from_wallet(OTHER).unwrap(),
            6,
            &selectors::join_table(),
            &borsh::to_vec(&w2_join).unwrap(),
        )
        .expect("wallet 2 joins (seat 1)");

        // 签名一条可真实应用的命令（leave_table，座位 1）。
        let mut signed_apply = |wallet: &str, sk, seat: u8, nonce: u64| -> PokerL1Result<()> {
            let args = borsh::to_vec(&crate::vm::contracts::texas_poker::dispatch::LeaveTableArgs {
                seat_index: seat,
            })
            .unwrap();
            let msg = tx_message_hash(
                377,
                &rt.table.id,
                &caller_id::wallet_to_address(wallet).unwrap(),
                &selectors::leave_table(),
                &args,
                nonce,
            );
            let sig = stark_scheme::sign(&sk, &msg).to_vec();
            rt.submit_signed(Submission {
                wallet: wallet.to_string(),
                block_timestamp: 7,
                selector: selectors::leave_table(),
                args,
                signature: sig,
                nonce,
            })
        };
        signed_apply(OTHER, w2_session_sk, 1, 1)
            .expect("wallet 2 applies nonce=1 (per-account watermark)");
        signed_apply(WALLET, session_sk, 0, 1)
            .expect("wallet 1 applies the SAME nonce=1 — no cross-wallet collision");

        // 陈旧 nonce（<= 水位）判重放：StaleTxNonce（队列将死信不重试）。
        let stale_err = signed_apply(OTHER, w2_session_sk, 1, 1)
            .expect_err("stale nonce must be rejected");
        assert!(
            matches!(stale_err, crate::error::PokerL1Error::StaleTxNonce { nonce: 1 }),
            "stale nonce error variant, got: {stale_err}"
        );
    }
}
