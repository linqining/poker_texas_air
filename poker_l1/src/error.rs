//! 统一错误类型。覆盖 Phase 1 + Phase 2 所有错误场景，便于 validator / RPC 返回精确错误码。
//!
//! 安全路径相关错误（签名 / nonce / chain_id / ObjectID / 轮转 / assigned_validator）
//! 须包含足够上下文以供审计追溯。

use thiserror::Error;

/// 库统一错误类型。
///
/// 注意：enum 变体的命名字段（如 `tag` / `actual` / `expected` / `tx` / `account` 等）
/// 名称已自描述，且每个变体均有文档注释说明语义，故此处允许字段缺文档。
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum PokerL1Error {
    // ===== 签名相关（Task 5 / SEC-M9 / NEW-L1 / SEC2-L1） =====
    /// tagged pubkey tag 字节未识别。SEC-M9：未知 tag 返回 UnknownScheme，禁止隐式 fallback。
    #[error("unknown signature scheme tag: 0x{tag:02x}")]
    UnknownScheme { tag: u8 },
    /// tagged pubkey 长度不匹配该 tag 的预期。
    #[error("tagged pubkey length {actual} != expected {expected} for tag 0x{tag:02x}")]
    InvalidPubkeyLength {
        tag: u8,
        actual: usize,
        expected: usize,
    },
    /// secp256k1 high-s 签名（BIP-62 / NEW-L1）— 拒绝，不规范化转换。
    #[error("secp256k1 signature s > n/2 (high-s rejected per BIP-62)")]
    InvalidSignatureLowS,
    /// ed25519 签名 R 或 S 非规范化编码（SEC2-L1）。
    #[error("ed25519 signature non-canonical encoding")]
    InvalidSignatureCanonical,
    /// 签名验证失败（恢复的 pubkey 与 tagged pubkey 不匹配，或底层 verify 返回 false）。
    #[error("signature verification failed")]
    InvalidSignature,
    /// 签名字节长度错误。
    #[error("signature length {actual} != expected {expected}")]
    InvalidSignatureLength { actual: usize, expected: usize },
    /// tagged pubkey 与签名 scheme tag 不一致（pubkey 是 secp256k1，sig 却声称 ed25519）。
    #[error("curve tag mismatch: pubkey tag 0x{pub_tag:02x} vs sig tag 0x{sig_tag:02x}")]
    CurveMismatch { pub_tag: u8, sig_tag: u8 },
    /// secp256k1 底层错误（解析失败等）。
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    // ===== 对象模型相关（Task 2 / NEW-L4 / IMPL-SEC-3） =====
    /// ObjectID 已存在（NEW-L4：创建时校验，冲突返回 ObjectIDCollision）。
    #[error("ObjectID collision: {0:?}")]
    ObjectIDCollision(crate::object_model::ObjectID),
    /// ObjectID 不存在（读 / 更新时）。
    #[error("object not found: {0:?}")]
    ObjectNotFound(crate::object_model::ObjectID),
    /// 操作方非对象 owner。
    #[error("not owner of object {0:?}")]
    NotOwner(crate::object_model::ObjectID),
    /// 试图修改 Immutable 对象（结算后冻结）。
    #[error("object is immutable: {0:?}")]
    ObjectImmutable(crate::object_model::ObjectID),
    /// 对象版本号不匹配（optimistic concurrency）。
    #[error("object version mismatch: expected {expected}, got {actual}")]
    ObjectVersionMismatch { expected: u64, actual: u64 },

    // ===== 账户 / 重放保护相关（Task 6 / M10 / NEW-M9 / SEC-H7） =====
    /// chain_id 不匹配（跨链重放）。
    #[error("wrong chain_id: tx={tx}, network={network}")]
    WrongChainId { tx: u64, network: u64 },
    /// account nonce 不匹配。
    #[error("nonce too low: tx={tx}, account={account}")]
    NonceTooLow { tx: u64, account: u64 },
    /// account nonce 跳号（高于当前 +1）。
    #[error("nonce too high: tx={tx}, account={account}")]
    NonceTooHigh { tx: u64, account: u64 },
    /// GameTurn nonce 不匹配（per-game per-player）。
    #[error("gameturn_nonce mismatch: tx={tx}, game={game}")]
    GameTurnNonceMismatch { tx: u64, game: u64 },
    /// 正常 GameTurn tx 设置了 is_fallback=true（SEC-H7：validator 拒绝）。
    #[error("normal GameTurn tx must not set is_fallback=true")]
    InvalidFallbackFlag,
    /// 余额不足支付 gas。
    #[error("insufficient balance: needed={needed}, has={has}")]
    InsufficientBalance { needed: u64, has: u64 },
    /// 余额溢出（credit 时 balance + amount > u64::MAX，SEC-FIX-3）。
    #[error("balance overflow: current={current}, credit={credit}")]
    BalanceOverflow { current: u64, credit: u64 },
    /// 实际 gas 消耗超过 tx 声明的预算（VM 执行后校验）。
    #[error("gas used {used} exceeds tx budget {budget}")]
    GasExceedsBudget { used: u64, budget: u64 },

    // ===== 存储相关（Task 4） =====
    /// RocksDB 后端错误。
    #[error("rocksdb error: {0}")]
    Rocksdb(String),
    /// 序列化 / 反序列化错误。
    #[error("serialization error: {0}")]
    Serialization(String),
    /// 区块不存在（按 hash / height 查询）。
    #[error("block not found")]
    BlockNotFound,
    /// DAG vertex 不存在。
    #[error("dag vertex not found")]
    DagVertexNotFound,
    /// 输入超长（syscall / 字段长度限制）。
    #[error("input too long: {actual} > {limit}")]
    InputTooLong { actual: usize, limit: usize },

    // ===== 通用 =====
    /// 其他错误（带字符串上下文）。
    #[error("{0}")]
    Other(String),

    // ===== Phase 2: 路由 / 轮转 / 游戏分配（Task 7 / 8 / 12） =====
    /// tx 通道与路由提示不匹配（SubTask 7.2：GameTurn+CheckpointAnchor 应路由到 assigned_validator）。
    #[error(
        "wrong lane: lane={lane:?}, route={route:?}, expected assigned_validator for GameTurn/CheckpointAnchor"
    )]
    WrongLane {
        /// tx 通道。
        lane: crate::transaction::TxLane,
        /// 路由提示。
        route: crate::transaction::RouteHint,
    },
    /// GameTurn / CheckpointAnchor tx 提交给了非 assigned_validator 的 validator（SubTask 7.5）。
    #[error(
        "not assigned validator for game (game_id={game_id:?}, assigned={assigned:?}, receiver={receiver:?})"
    )]
    NotAssignedValidator {
        /// Game 对象 ID。
        game_id: crate::object_model::ObjectID,
        /// 链上记录的 assigned_validator pubkey。
        assigned: crate::signature::TaggedPubkey,
        /// 当前接收 tx 的 validator pubkey。
        receiver: crate::signature::TaggedPubkey,
    },
    /// 非当前轮次玩家提交 GameTurn tx（SubTask 7.4：轮转约束）。
    #[error(
        "not your turn (game_id={game_id:?}, phase={phase:?}, current_turn={current_turn:?}, actor={actor:?})"
    )]
    NotYourTurn {
        /// Game 对象 ID。
        game_id: crate::object_model::ObjectID,
        /// 当前游戏阶段（Betting 或 MultiPlayerSubmit）。
        phase: crate::consensus::GamePhase,
        /// 当前轮次玩家地址。
        current_turn: crate::Address,
        /// 实际提交 tx 的玩家地址。
        actor: crate::Address,
    },
    /// 多玩家提交阶段，提交者不在 pending_submitters 中（spec：NotEligibleSubmitter）。
    #[error(
        "not eligible submitter (game_id={game_id:?}, phase={phase:?}, pending={pending:?}, actor={actor:?})"
    )]
    NotEligibleSubmitter {
        /// Game 对象 ID。
        game_id: crate::object_model::ObjectID,
        /// 当前游戏阶段。
        phase: crate::consensus::GamePhase,
        /// 当前待提交者集合。
        pending: std::collections::BTreeSet<crate::Address>,
        /// 实际提交 tx 的玩家地址。
        actor: crate::Address,
    },
    /// 玩家活跃 Game 数量超限（SubTask 8.7：S8 修复，max_active_games_per_player 默认 10）。
    #[error("too many active games: player={player:?}, active={active}, limit={limit}")]
    TooManyActiveGames {
        /// 玩家地址。
        player: crate::Address,
        /// 当前活跃 Game 数。
        active: u32,
        /// 上限。
        limit: u32,
    },
    /// Game 对象不存在或未激活。
    #[error("game not found or inactive: {0:?}")]
    GameNotFound(crate::object_model::ObjectID),
    /// assigned_validator 未在指定 block 范围内装入 GameTurn tx（SubTask 8.9：NEW-H2 fallback 触发条件）。
    #[error("assigned validator timeout: game_id={game_id:?}, timeout_blocks={timeout_blocks}")]
    AssignedValidatorTimeout {
        /// Game 对象 ID。
        game_id: crate::object_model::ObjectID,
        /// 超时阈值（block 数）。
        timeout_blocks: u64,
    },
    /// fallback tx 缺少 assigned_validator_timeout_proof（SubTask 8.9：NEW-H2）。
    #[error("fallback tx missing timeout proof")]
    MissingTimeoutProof,
    /// fallback tx 的 timeout_proof 验证失败（SubTask 8.9：多副本见证签名不足 / round 范围不正确）。
    #[error("invalid timeout proof: {0}")]
    InvalidTimeoutProof(String),

    // ===== Phase 2: 时间共识（Task 11） =====
    /// block.height 不等于 prev.height + 1（S10：严格单调递增）。
    #[error("block height not strictly increasing: prev={prev}, got={got}")]
    BlockHeightNotIncreasing { prev: u64, got: u64 },
    /// block.timestamp_ms < prev.timestamp_ms（S10：单调不减）。
    #[error("block timestamp moved backwards: prev={prev}, got={got}")]
    BlockTimestampMovedBackwards { prev: u64, got: u64 },
    /// block.timestamp_ms > prev.timestamp_ms + max_interval_ms（S10：最大间隔约束）。
    #[error(
        "block timestamp interval exceeded: prev={prev}, got={got}, max_interval={max_interval}"
    )]
    BlockTimestampIntervalExceeded {
        prev: u64,
        got: u64,
        max_interval: u64,
    },

    // ===== Phase 2: DAG 共识 / Bullshark（Task 8 / 9） =====
    /// vertex 签名验证失败（SEC-C1：签名对象 = hash(chain_id || epoch || round || author_pubkey || vertex_hash || parent_hashes)）。
    #[error("dag vertex signature verification failed: vertex_hash={vertex_hash:?}")]
    InvalidVertexSignature { vertex_hash: crate::Hash },
    /// vertex parent_hashes 数量不足 2/3 validator（spec：vertex 须引用 ≥2/3 validator 的上一轮 vertex hash）。
    #[error("vertex parent count {actual} < required {required} (2/3 of validator set)")]
    InsufficientParents { actual: usize, required: usize },
    /// DAG round 从 1 开始；round 0 没有合法的共识语义。
    #[error("invalid dag vertex round {round}; rounds start at 1")]
    InvalidVertexRound { round: u64 },
    /// vertex 必须属于节点当前接受的 epoch，旧 epoch 或未来 epoch 均不得进入活跃 DAG。
    #[error("invalid dag vertex epoch {actual}; expected current epoch {expected}")]
    InvalidVertexEpoch { actual: u64, expected: u64 },
    /// 第一轮 vertex 不得引用 parent，因为不存在 round 0。
    #[error("first-round dag vertex must not contain parents (got {actual})")]
    UnexpectedFirstRoundParents { actual: usize },
    /// 同一个 parent hash 在一个 vertex 中出现多次。
    #[error("duplicate parent vertex hash: {0:?}")]
    DuplicateParentVertex(crate::Hash),
    /// parent 必须严格来自当前 vertex 的上一轮。
    #[error(
        "parent vertex {parent_hash:?} is from round {actual}; expected previous round {expected}"
    )]
    InvalidParentVertexRound {
        parent_hash: crate::Hash,
        actual: u64,
        expected: u64,
    },
    /// parent 与 child 必须属于同一 epoch，防止 round 编号跨 epoch 混用。
    #[error(
        "parent vertex {parent_hash:?} is from epoch {actual}; expected child epoch {expected}"
    )]
    InvalidParentVertexEpoch {
        parent_hash: crate::Hash,
        actual: u64,
        expected: u64,
    },
    /// parent 作者必须仍属于当前活跃 validator 集。
    #[error("parent vertex author is not an active validator: {0:?}")]
    ParentVertexAuthorNotActiveValidator(crate::signature::TaggedPubkey),
    /// 同一 validator 的多个 parent 不能重复计入 parent quorum。
    #[error("duplicate parent vertex author: {0:?}")]
    DuplicateParentVertexAuthor(crate::signature::TaggedPubkey),
    /// vertex 大小超限（max_vertex_size 默认 256KB）。
    #[error("vertex size {actual} exceeds max_vertex_size {limit}")]
    VertexTooLarge { actual: usize, limit: usize },
    /// vertex 引用的 parent 不存在于已知 DAG 中（P0-3 入库前验证）。
    #[error("parent vertex not found: {0:?}")]
    ParentVertexNotFound(crate::Hash),
    /// block prev_hash 与前一个 block 的 hash 不匹配（P0-3 入库前验证）。
    #[error("invalid prev_hash: expected={expected:?}, got={got:?}")]
    InvalidPrevHash {
        /// 期望的 prev_hash（前一个 block 的 hash）。
        expected: crate::Hash,
        /// 实际的 prev_hash。
        got: crate::Hash,
    },
    /// commit certificate 签名数不足 2/3 quorum（SubTask 9.1 / 10.7）。
    #[error("commit certificate signer count {actual} < quorum {required}")]
    InsufficientQuorum { actual: usize, required: usize },
    /// commit certificate 签名验证失败（SubTask 10.7）。
    #[error("commit certificate signature verification failed for signer index {signer_idx}")]
    InvalidCommitCertificateSignature { signer_idx: usize },
    /// commit certificate 的 signer_bitmap 置位数与 signature_list 长度不一致
    /// （P05-H-source：bitmap 紧凑对应约定被破坏）。
    #[error(
        "commit certificate signer_bitmap set-bits {bitmap_count} != signature_list len {sig_count}"
    )]
    CommitCertSignatureBitmapMismatch {
        /// signer_bitmap 中置位数。
        bitmap_count: usize,
        /// signature_list 长度。
        sig_count: usize,
    },
    /// commit certificate 同一 validator 被多次签名（P05-H-source：去重防刷 quorum）。
    #[error("duplicate commit certificate signer index {signer_idx}")]
    DuplicateCommitCertificateSigner {
        /// 重复的 validator 索引。
        signer_idx: usize,
    },
    /// commit certificate 的 epoch / prev_commit_hash / state_root 字段与本地不匹配（SEC2-C1）。
    #[error("commit certificate field mismatch: {0}")]
    CommitCertificateMismatch(String),

    // ===== Phase 2: Block 验证器（Task 10） =====
    /// Public 通道 tx 排序不合法（gas/arrival 非单调，SubTask 10.2）。
    #[error("invalid public tx ordering: tx[{idx}] gas_price={tx_price} < prev_price={prev_price}")]
    InvalidTxOrdering {
        /// 出错 tx 的索引。
        idx: usize,
        /// 出错 tx 的 gas price。
        tx_price: u64,
        /// 前一个 tx 的 gas price。
        prev_price: u64,
    },
    /// GameTurn 通道 tx 被错误计费 gas（SubTask 10.4：GameTurn 通道免 gas）。
    #[error("GameTurn tx charged gas: budget={budget}, price={price}")]
    GameTurnGasCharged {
        /// tx 声明的 gas budget。
        budget: u64,
        /// tx 声明的 gas price。
        price: u64,
    },
    /// 状态根不匹配（SubTask 10.5：两通道状态根转移校验）。
    #[error("state root mismatch: expected={expected:?}, got={got:?}")]
    StateRootMismatch {
        /// 期望的状态根。
        expected: crate::Hash,
        /// 实际的状态根。
        got: crate::Hash,
    },
    /// public_tx_root 不匹配（SubTask 10.5）。
    #[error("public_tx_root mismatch: expected={expected:?}, got={got:?}")]
    PublicTxRootMismatch {
        /// 期望的 public_tx_root。
        expected: crate::Hash,
        /// 实际的 public_tx_root。
        got: crate::Hash,
    },
    /// gameturn_tx_root 不匹配（SubTask 10.5）。
    #[error("gameturn_tx_root mismatch: expected={expected:?}, got={got:?}")]
    GameTurnTxRootMismatch {
        /// 期望的 gameturn_tx_root。
        expected: crate::Hash,
        /// 实际的 gameturn_tx_root。
        got: crate::Hash,
    },
    /// game sub-block 的 assigned_validator 签名验证失败（SubTask 10.3）。
    #[error("invalid game sub-block signature: game_id={game_id:?}")]
    InvalidGameSubBlockSignature {
        /// Game 对象 ID。
        game_id: crate::object_model::ObjectID,
    },
    /// vertex 内 tx 排序违反 S9 规则（SubTask 10.6：GameTurn 应优先于 ForceSync）。
    #[error(
        "vertex tx ordering violates S9: ForceSync tx at idx {force_idx} before GameTurn tx at idx {turn_idx}"
    )]
    InvalidVertexTxOrdering {
        /// ForceSync tx 的索引。
        force_idx: usize,
        /// GameTurn tx 的索引。
        turn_idx: usize,
    },

    // ===== Phase 2: ValidatorSet / Slashing（Task 13） =====
    /// validator 集规模不足（SEC-C2：主网 |V| < 5 时 OffChain 模式 Game 创建被拒绝）。
    #[error("validator set too small for OffChain: size={size}, required>=5")]
    ValidatorSetTooSmallForOffChain { size: usize },
    /// validator 不在当前 ValidatorSet 中。
    #[error("validator not in set: {0:?}")]
    ValidatorNotInSet(crate::signature::TaggedPubkey),
    /// 同一 (epoch, round, author_pubkey) 出现两个冲突 vertex（equivocation slashing）。
    #[error("vertex equivocation detected: epoch={epoch}, round={round}, author={author:?}")]
    VertexEquivocation {
        epoch: u64,
        round: u64,
        author: crate::signature::TaggedPubkey,
    },
    /// 同一 (epoch, commit_round) 出现两个冲突 commit certificate（commit cert equivocation slashing）。
    #[error("commit certificate equivocation: epoch={epoch}, commit_round={commit_round}")]
    CommitCertEquivocation { epoch: u64, commit_round: u64 },
    /// VRF proof 验证失败（IMPL-SEC-2：ECVRF-secp256k1，81B proof）。
    #[error("vrf proof verification failed: {0}")]
    InvalidVrfProof(String),
    /// VRF input 与链上 epoch 不匹配（SEC2-C2：VRF input = hash(chain_id || epoch || prev_epoch_randomness)）。
    #[error("vrf input mismatch: expected epoch={expected}, got={got}")]
    VrfInputMismatch { expected: u64, got: u64 },
    /// VRF output 与链上 epoch_randomness 不匹配（SEC2-M10）。
    #[error("vrf output mismatch")]
    VrfOutputMismatch,
    /// validator 处于 bonding 期，不可参与共识（NEW-L3）。
    #[error("validator in bonding period: pubkey={0:?}")]
    ValidatorInBonding(crate::signature::TaggedPubkey),
    /// validator 处于 unbonding 期，不可参与共识但可被 slashing（R5-H7）。
    #[error("validator in unbonding period: pubkey={0:?}")]
    ValidatorInUnbonding(crate::signature::TaggedPubkey),
    /// vertex author 不是当前活跃 validator（P0-4 动态 quorum：非活跃 validator 产出的 vertex 必须被拒绝）。
    #[error("vertex author is not an active validator: {0:?}")]
    VertexAuthorNotActiveValidator(crate::signature::TaggedPubkey),

    // ===== Phase 3: rBPF VM / Syscalls / 合约升级（Task 14 / 15 / 17） =====
    /// BPF 字节码验证失败（IMPL-SEC-4：强制 Verifier）。
    #[error("invalid bytecode: {0}")]
    InvalidBytecode(String),
    /// gas 耗尽（IMPL-SEC-4：指令执行前扣费，余额不足立即 trap）。
    #[error("out of gas: used={used}, limit={limit}")]
    OutOfGas { used: u64, limit: u64 },
    /// Object 序列化后超过 64KB（IMPL-SEC-4：(7)）。
    #[error("object too large: {actual} > {limit}")]
    ObjectTooLarge { actual: usize, limit: usize },
    /// 合约不存在。
    #[error("contract not found: {0:?}")]
    ContractNotFound(crate::object_model::ObjectID),
    /// 合约版本不存在。
    #[error("contract version not found: contract_id={contract_id:?}, version={version}")]
    ContractVersionNotFound {
        contract_id: crate::object_model::ObjectID,
        version: u32,
    },
    /// 非 UpgradeCap 持有者尝试升级合约（SubTask 17.2）。
    #[error("not authorized: caller is not UpgradeCap holder for contract {contract_id:?}")]
    NotAuthorized {
        contract_id: crate::object_model::ObjectID,
    },
    /// 升级处于 timelock 期，新版本不可调用（SEC-L7）。
    #[error(
        "upgrade in timelock: contract_id={contract_id:?}, remaining_blocks={remaining_blocks}"
    )]
    UpgradeInTimelock {
        contract_id: crate::object_model::ObjectID,
        remaining_blocks: u64,
    },
    /// 升级 timelock 未到期时尝试强制生效。
    #[error(
        "upgrade timelock not expired: contract_id={contract_id:?}, remaining_blocks={remaining_blocks}"
    )]
    UpgradeTimelockNotExpired {
        contract_id: crate::object_model::ObjectID,
        remaining_blocks: u64,
    },
    /// 旧版本合约已不可调用（SubTask 17.3）。
    #[error("contract version {version} is no longer callable for {contract_id:?}")]
    OldVersionNotCallable {
        contract_id: crate::object_model::ObjectID,
        version: u32,
    },
    /// 未知的合约方法选择器（P0-5：GameTurn 原生合约 dispatch）。
    #[error("unknown contract method: selector={selector:?}")]
    UnknownContractMethod { selector: crate::Hash },
    /// HandStarted 错误（手牌已在进行中 / 状态非法）。
    #[error("hand started error: {0}")]
    HandStartedError(crate::vm::contracts::hand_started::HandStartedError),
    /// ForceAdvance 错误（超时玩家不存在 / 已 fold / 未超时）。
    #[error("force advance error: {0}")]
    ForceAdvanceError(crate::vm::contracts::force_advance::ForceAdvanceError),
    /// Settle 错误（手牌未到达 showdown / 已结算）。
    #[error("settle error: {0}")]
    SettleError(crate::vm::contracts::settle::SettleError),
    /// syscall 参数无效（指针越界 / 长度非法等）。
    #[error("invalid syscall argument: {0}")]
    InvalidSyscallArgument(String),
    /// 合约 panic（SubTask 15.5）。
    #[error("contract panic: {0}")]
    SyscallPanic(String),
    /// emit_event payload 超过 16KB（IMPL-SEC-4：(6)）。
    #[error("event payload too large: {actual} > {limit}")]
    EventTooLarge { actual: usize, limit: usize },
    /// syscall 指针不在合约 heap region（IMPL-SEC-4：(4)）。
    #[error("heap access violation: ptr={ptr:#x}, len={len}")]
    HeapAccessViolation { ptr: u64, len: u64 },
    /// 合约执行失败（VM 返回错误）。
    #[error("contract execution failed: {0}")]
    ContractExecutionFailed(String),
    /// 紧急升级缺少关键漏洞证据（SEC2-M11）。
    #[error("emergency upgrade missing critical vulnerability proof")]
    MissingCriticalVulnerabilityProof,
    /// 紧急升级安全审计期内被 dispute（SEC2-M11）。
    #[error("emergency upgrade disputed during audit period")]
    EmergencyUpgradeDisputed,

    // ===== Phase 4: BLS12-381 预编译（Task 18 / 19） =====
    /// BLS12-381 子群检查失败（SubTask 18.6）。
    #[error("invalid subgroup: {0}")]
    InvalidSubgroup(&'static str),
    /// BLS12-381 compressed bytes 反序列化失败（长度错误 / 非法编码 / 不在曲线上）。
    #[error("invalid bls point: {0}")]
    InvalidBlsPoint(String),
    /// BLS12-381 标量反序列化失败。
    #[error("invalid bls scalar: {0}")]
    InvalidBlsScalar(String),

    // ===== Phase 5a: OfflineState / ZK Verifier（Task 21 / 22 / 23 / 24 / 25 / 26） =====
    /// verifier_status=Stub 时主网 chain_id 拒绝 OffChain checkout（NEW-C1）。
    #[error("offchain mode disabled on mainnet while verifier_status=Stub")]
    OffChainDisabledOnMainnet,
    /// Groth16 verifying_key 被替换：blake2b_256(stored_vk) != crs_fingerprint（SEC-M10）。
    #[error("crs fingerprint mismatch: vk_id={vk_id:?}")]
    CrsFingerprintMismatch { vk_id: crate::Hash },
    /// zk_verify 收到未知 scheme_id（SubTask 22.2）。
    #[error("unknown zk scheme_id: {0}")]
    UnknownZkScheme(u32),
    /// ZK proof 格式错误（长度 / 编码不合法）。
    #[error("invalid zk proof format: {0}")]
    InvalidZkProofFormat(String),
    /// ZK public_io 缺失或格式错误（O15：initial_commitment / final_commitment / state_delta_hash / ack_chain_hash / fold_step_count / skip_count / segment_continuity_proof）。
    #[error("invalid zk public_io: {0}")]
    InvalidZkPublicIo(String),
    /// fold_step_count 超过上限 1000（O15 修复）。
    #[error("fold_step_count {actual} exceeds limit {limit}")]
    FoldStepCountExceeded { actual: u32, limit: u32 },
    /// ack_chain 长度超过 max_ack_chain_length（SEC2-M4，默认 1000）。
    #[error("ack_chain length {actual} exceeds max_ack_chain_length {limit}")]
    AckChainLengthExceeded { actual: u32, limit: u32 },
    /// ZK verifier 未注册（scheme_id 已知但 registry 中无对应 verifier）。
    #[error("zk verifier not registered for scheme_id={0}")]
    ZkVerifierNotRegistered(u32),
    /// 共识状态尚未把指定 verifier 切换到 Production，不能把格式检查当成证明接受。
    #[error("zk verifier is not in Production: chain_id={chain_id}, scheme_id={scheme_id}")]
    ZkVerifierNotProduction {
        /// 目标链 ID。
        chain_id: crate::ChainId,
        /// 证明系统 ID。
        scheme_id: u32,
    },
    /// 节点二进制未编译指定 verifier 能力，不能注册一个运行时必然失败的适配器。
    #[error(
        "zk verifier capability is disabled at compile time: scheme_id={scheme_id}, capability={capability}"
    )]
    ZkVerifierCapabilityDisabled {
        /// 证明系统 ID。
        scheme_id: u32,
        /// 缺失的编译能力名称。
        capability: &'static str,
    },
    /// Groth16 verifying_key 未注册到 ZkVerifierRegistry（SubTask 24.3a）。
    #[error("groth16 verifying_key not registered: vk_id={0:?}")]
    Groth16VkNotRegistered(crate::Hash),
    /// partial_checkin 与 last_partial_fold 不匹配（NEW-M6：ack_chain[0..N] 哈希不匹配 / initial_commitment 不匹配 / fold_step_count 不匹配）。
    #[error("partial_checkin mismatch: {0}")]
    PartialCheckinMismatch(String),
    /// 完整 checkin 装入 vertex 后 partial_checkin 被拒绝（SEC2-M8）。
    #[error("game already checked in: game_id={0:?}")]
    GameAlreadyCheckedIn(crate::object_model::ObjectID),
    /// partial_checkin 的 folded_step_count 未严格大于上一次记录（SEC-H1）。
    #[error(
        "no progress partial_checkin: new_folded_step_count={new_count}, last_recorded={last_recorded}"
    )]
    NoProgressPartialCheckin { new_count: u32, last_recorded: u32 },
    /// partial_checkin 提交次数超过 max_partial_checkin_count（SEC-H1，默认 3）。
    #[error("partial_checkin count {actual} exceeds max_partial_checkin_count {limit}")]
    PartialCheckinLimitExceeded { actual: u32, limit: u32 },

    // ===== Phase 5a: ACK 链与签名验证（Task 27.3 / 27.10） =====
    /// checkpoint_anchor 缺少活跃参与者的 ACK 签名（SubTask 27.3）。
    #[error("missing ack for checkpoint: game_id={game_id:?}, missing_participant={participant:?}")]
    MissingAck {
        game_id: crate::object_model::ObjectID,
        participant: crate::signature::TaggedPubkey,
    },
    /// ACK 签名者 tagged pubkey 不在 Game.active_participants 集合中（SEC2-M9）。
    #[error("ack signer not participant: game_id={game_id:?}, signer={signer:?}")]
    AckSignerNotParticipant {
        game_id: crate::object_model::ObjectID,
        signer: crate::signature::TaggedPubkey,
    },
    /// 相同 (game_id, checkpoint_seq) 重复提交（R5-L2 去重）。
    #[error("duplicate checkpoint: game_id={game_id:?}, checkpoint_seq={checkpoint_seq}")]
    DuplicateCheckpoint {
        game_id: crate::object_model::ObjectID,
        checkpoint_seq: u64,
    },
    /// skip 段 ack_set 与上一正常 checkpoint 不一致（SEC-M6）。
    #[error("ack set mismatch: expected_count={expected}, got_count={got}")]
    AckSetMismatch { expected: usize, got: usize },

    // ===== Phase 5b: 审查截断防护（Task 27.5a / 27.6 / 27.7 / 27.9） =====
    /// 同一 (game_id, target_participant) 已有未过期 pending_ack_request（NEW-M7）。
    #[error("pending ack request exists: game_id={game_id:?}, target={target:?}")]
    PendingAckExists {
        game_id: crate::object_model::ObjectID,
        target: crate::signature::TaggedPubkey,
    },
    /// turn_timeout_blocks 内 request_ack 次数超限（NEW-M7）。
    #[error("request_ack too frequent: count={actual}, limit={limit}")]
    RequestAckTooFrequent { actual: u32, limit: u32 },
    /// validator 处于 under_investigation 状态（NEW-H1）。
    #[error("validator under investigation: pubkey={0:?}")]
    UnderInvestigation(crate::signature::TaggedPubkey),
    /// refuse_ack evidence 验证失败（SubTask 27.7）。
    #[error("invalid refuse_ack evidence: {0}")]
    InvalidRefuseAckEvidence(String),
    /// assigned_validator_failure_proof 验证失败（SubTask 27.5b）。
    #[error("invalid assigned_validator_failure_proof: {0}")]
    InvalidAssignedValidatorFailureProof(String),
    /// delegated_escape_authorization 凭证无效（SubTask 27.5c）。
    #[error("invalid delegated escape authorization: {0}")]
    InvalidDelegatedEscapeAuthorization(String),
    /// delegated_escape_authorization 已过期（NEW-M2）。
    #[error("delegated escape authorization expired: expiry_height={expiry}, current={current}")]
    DelegatedEscapeExpired { expiry: u64, current: u64 },
    /// delegated_escape_authorization credential_nonce 已被消费（NEW-M1）。
    #[error("delegated escape credential nonce already consumed: nonce={0}")]
    DelegatedEscapeNonceConsumed(u64),
    /// force_checkpoint evidence 验证失败（SEC2-M3）。
    #[error("force_checkpoint evidence verification failed: {0}")]
    ForceCheckpointEvidenceFailed(String),

    // ===== Phase 5c: 强制同步 / 争议解决（Task 28） =====
    /// 阶段 3 内操作方本人提交 force_revert/request_revert(reason=technical_interrupt) 被拒（R7-M6）。
    #[error("operator cannot claim technical_interrupt in stage 3: game_id={0:?}")]
    OperatorCannotClaimTechnicalInterrupt(crate::object_model::ObjectID),
    /// designated operator 任命 tx bond_amount 与治理参数不匹配（SEC2-M7）。
    #[error("invalid bond amount: expected={expected}, got={got}")]
    InvalidBondAmount { expected: u64, got: u64 },
    /// designated operator bond_amount < 桌面总 buy-in（SEC2-M7）。
    #[error("insufficient operator bond: bond={bond}, required={required}")]
    InsufficientOperatorBond { bond: u64, required: u64 },
    /// challenge_delta 失败：hash(Δ) == state_delta_hash（恶意挑战，挑战方 forfeit 保证金）。
    #[error("challenge_delta failed: delta matches state_delta_hash (malicious challenge)")]
    ChallengeFailed,
    /// challenge_delta 成立：hash(Δ) != state_delta_hash（操作方 forfeit 保证金 + 触发 request_revert）。
    #[error("challenge_delta succeeded: delta mismatch state_delta_hash (operator forfeits)")]
    ChallengeSucceeded,
    /// skip_count 超过 max_skip_segments（SubTask 27.11，默认 3）。
    #[error("skip_count {actual} exceeds max_skip_segments {limit}")]
    SkipCountExceeded { actual: u32, limit: u32 },
    /// segment_continuity_proof 验证失败（R5-H6：段间状态不连续）。
    #[error("continuity proof invalid: {0}")]
    ContinuityProofInvalid(String),
    /// checkin tx 缺少 has_partial_checkin 字段或字段与链上状态不一致（SEC2-M8）。
    #[error("partial_checkin flag mismatch: declared={declared}, actual_state={actual_state}")]
    PartialCheckinFlagMismatch { declared: bool, actual_state: bool },

    // ===== Phase 5c: 状态裁剪 / DA（Task 29） =====
    /// 历史数据不可用（Walrus blob 过期 / archive node 不足 / 裁剪后无法检索，R5-M7）。
    #[error("historical data unavailable: {0}")]
    HistoricalDataUnavailable(String),
    /// 裁剪被拒绝（archive node 数量 < archive_node_min_count，SubTask 29.4）。
    #[error("pruning rejected: archive node count {actual} < min {limit}")]
    PruningRejectedArchiveInsufficient { actual: u32, limit: u32 },

    // ===== Phase 6: 治理（Task 33） =====
    /// 参数值越界（R4-H4 / R5-H2 / R5-M3 / R7-* 修正）。
    #[error("parameter {param} out of bounds: value={value}, min={min}, max={max}")]
    ParamOutOfBounds {
        /// 参数名。
        param: &'static str,
        /// 提议值。
        value: u64,
        /// 下界。
        min: u64,
        /// 上界。
        max: u64,
    },
    /// 未知参数名。
    #[error("unknown parameter: {0}")]
    UnknownParameter(&'static str),
    /// 投票参与率不足（SEC2-M6：分母 = 当前 epoch validator 集大小，参与率下限 2/3 或 90%）。
    #[error("voting participation too low: actual={actual}, required={required}")]
    VotingParticipationTooLow { actual: usize, required: usize },
    /// 赞成票未达 quorum（普通 2/3 / 敏感 90%）。
    #[error("yes votes insufficient: yes={yes}, required={required}")]
    YesVotesInsufficient { yes: usize, required: usize },
    /// 提案不在投票期（已结束 / 未开始 / 已执行 / 已撤销）。
    #[error("proposal not in voting period: status={0:?}")]
    ProposalNotInVoting(crate::governance::ProposalStatus),
    /// 提案不在 timelock 期（无法撤销 / 无法执行）。
    #[error("proposal not in timelock: status={0:?}")]
    ProposalNotInTimelock(crate::governance::ProposalStatus),
    /// 撤销提案 quorum 不足（须 >= 90%，SEC-H8）。
    #[error("revocation quorum insufficient: yes={yes}, required={required}")]
    RevocationQuorumInsufficient { yes: usize, required: usize },
    /// validator 重复投票。
    #[error("duplicate vote: validator={0:?}")]
    DuplicateVote(crate::signature::TaggedPubkey),
    /// 提案 chain_id 与网络 chain_id 不匹配（SEC-M4：verifier_status per-chain_id）。
    #[error("proposal chain_id mismatch: proposal={proposal}, network={network}")]
    ProposalChainIdMismatch { proposal: u64, network: u64 },
    /// validator 集缩减至 < 5（SEC-C2）。
    #[error("validator set reduction below minimum: new_size={new_size}, min=5")]
    ValidatorSetReductionTooSmall { new_size: usize },
    /// 单次缩减比例超过 20%（SEC-M2）。
    #[error("single reduction ratio exceeds 20%: removed={removed}, prev_size={prev_size}")]
    SingleReductionRatioExceeded { removed: usize, prev_size: usize },
    /// 密钥轮换处于 timelock 期（SEC2-H4）。
    #[error("key rotation in timelock: remaining_blocks={0}")]
    KeyRotationInTimelock(u64),

    // ===== Phase 6: 跨链桥（Task 34） =====
    /// bridge_verify 被合约直接调用（SubTask 34.2：必须由协议层调用）。
    #[error("bridge_verify must be called by protocol layer, not contract")]
    BridgeVerifyNotAuthorized,
    /// 桥签名验证失败（SubTask 34.3）。
    #[error("bridge signature verification failed: {0}")]
    BridgeSignatureInvalid(String),
    /// 桥 nonce 已被消费（防重放，SubTask 34.3）。
    #[error("bridge nonce already consumed: nonce={0}")]
    BridgeNonceConsumed(u64),
    /// bridge_verify tx 非 recipient 本人签名（SEC2-M1 抢跑防护）。
    #[error("bridge_verify tx must be signed by recipient")]
    BridgeVerifyNotSignedByRecipient,
    /// burn proof 验证失败（SubTask 34.4）。
    #[error("burn proof verification failed: {0}")]
    BurnProofInvalid(String),
    /// 桥验证器插槽未注册（SubTask 34.5）。
    #[error("bridge validator slot not registered: {0:?}")]
    BridgeValidatorSlotNotRegistered(crate::signature::TaggedPubkey),
    /// 桥验证器签名重复（同一验证器签名出现多次，H1 修复）。
    #[error("duplicate bridge validator signature: {0:?}")]
    DuplicateBridgeValidator(crate::signature::TaggedPubkey),

    // ===== Phase 6: 网络层（Task 30） =====
    /// tx 序列化后超过 128KB（SubTask 30.6）。
    #[error("tx too large: {actual} > {limit}")]
    TxTooLarge { actual: usize, limit: usize },
    /// block 序列化后超过 4MB（SubTask 30.6）。
    #[error("block too large: {actual} > {limit}")]
    BlockTooLarge { actual: usize, limit: usize },
    /// Compact Block Relay short ID 冲突（SEC2-L3：多个 tx 匹配同一 short ID）。
    #[error("short id collision: {0:?}")]
    ShortIdCollision([u8; 8]),
    /// short ID → tx hash 映射表超限（SEC2-L3：防内存膨胀）。
    #[error("short id map full: {actual} >= {limit}")]
    ShortIdMapFull { actual: usize, limit: usize },
    /// 无 mempool 缓冲超时（SubTask 30.7：tx 在缓冲中超过 100ms 未装入 vertex）。
    #[error("mempool buffer timeout: tx={0:?}")]
    MempoolBufferTimeout(crate::Hash),
    /// 多副本广播失败（SubTask 30.8：所有副本均未接受）。
    #[error("multi-replica broadcast failed: tx={tx_hash:?}, attempts={attempts}")]
    MultiReplicaBroadcastFailed {
        /// 失败的 tx 哈希。
        tx_hash: crate::Hash,
        /// 尝试的副本数。
        attempts: usize,
    },
    /// P2P 网络传输错误。
    #[error("network transport error: {0}")]
    NetworkTransport(String),
    /// peer 未找到。
    #[error("peer not found: {0}")]
    PeerNotFound(String),
    /// sync protocol 错误（按 range 请求 blocks / DAG vertex 失败）。
    #[error("sync error: {0}")]
    SyncError(String),
    /// 轻客户端 block header 订阅：签名不足 2/3 quorum（SubTask 30.4）。
    #[error("light client header quorum insufficient: actual={actual}, required={required}")]
    LightClientQuorumInsufficient { actual: usize, required: usize },
    /// 轻客户端 block header 订阅：签名者重复（H2 修复）。
    #[error("duplicate light client signer: {0:?}")]
    DuplicateLightClientSigner(crate::signature::TaggedPubkey),

    // ===== Phase 8: 链上 Verifier Production 相关（SubTask 8.2.2） =====
    /// 外层 sumcheck 验证失败（G(r_x_L) != u'）。
    #[error("sumcheck verification failed: G(r_x_L) != u'")]
    SumcheckVerificationFailed,
    /// cross-language claim 验证失败（u'/v'/z_at_point 链断裂）。
    #[error("cross-language claim verification failed")]
    CrossLanguageClaimFailed,
    /// transcript 一致性校验失败（challenge 派生顺序不匹配）。
    #[error("transcript consistency mismatch")]
    TranscriptMismatch,
    /// PCS opening 验证失败（z'(r_y) 承诺不匹配）。
    #[error("pcs opening verification failed")]
    PcsVerificationFailed,
    /// proof abi_version 不匹配。
    #[error("abi version mismatch: expected={expected}, actual={actual}")]
    AbiVersionMismatch { expected: u8, actual: u8 },
    /// ZKVM syscall 使用无效 slot（非白名单）。
    #[error("invalid syscall slot: {0}")]
    InvalidSlot(u32),
    /// CycleFold 递归深度超限。
    #[error("recursion depth exceeded: actual={actual}, limit={limit}")]
    RecursionDepthExceeded { actual: u32, limit: u32 },
    /// proof_kind 与 scheme_id 不一致。
    #[error("proof_kind mismatch: declared={declared}, actual={actual}")]
    ProofKindMismatch { declared: u8, actual: u8 },
    /// ZKVM 未初始化内存读取。
    #[error("uninitialized memory read at slot {slot}")]
    UninitializedRead { slot: u32 },
    /// M2-003：last_partial_fold.proof_partial_hash 链上不可变（覆盖已有值）。
    #[error(
        "partial fold hash immutable: proof_partial_hash already set and cannot be overwritten"
    )]
    PartialFoldHashImmutable,
    /// M2-004：签名形式与 scheme_id 不匹配。
    #[error("signature form mismatch: scheme_id={scheme_id} expects different signature form")]
    SignatureFormMismatch { scheme_id: u32 },
}

/// 库统一 Result 别名。
pub type PokerL1Result<T> = Result<T, PokerL1Error>;

impl From<borsh::io::Error> for PokerL1Error {
    fn from(e: borsh::io::Error) -> Self {
        Self::Serialization(format!("borsh: {e}"))
    }
}

impl From<serde_json::Error> for PokerL1Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(format!("json: {e}"))
    }
}

impl From<blake2::digest::InvalidLength> for PokerL1Error {
    fn from(e: blake2::digest::InvalidLength) -> Self {
        Self::Serialization(format!("blake2 invalid length: {e}"))
    }
}

impl From<crate::vm::contracts::hand_started::HandStartedError> for PokerL1Error {
    fn from(e: crate::vm::contracts::hand_started::HandStartedError) -> Self {
        Self::HandStartedError(e)
    }
}

impl From<crate::vm::contracts::force_advance::ForceAdvanceError> for PokerL1Error {
    fn from(e: crate::vm::contracts::force_advance::ForceAdvanceError) -> Self {
        Self::ForceAdvanceError(e)
    }
}

impl From<crate::vm::contracts::settle::SettleError> for PokerL1Error {
    fn from(e: crate::vm::contracts::settle::SettleError) -> Self {
        Self::SettleError(e)
    }
}

impl From<crate::vm::contracts::texas_poker::betting::BettingError> for PokerL1Error {
    fn from(e: crate::vm::contracts::texas_poker::betting::BettingError) -> Self {
        Self::ContractExecutionFailed(format!("betting error: {e}"))
    }
}
