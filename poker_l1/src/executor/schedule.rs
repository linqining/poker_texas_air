//! 冲突检测 + 波次调度（Task P-2）。
//!
//! 把 `execute_block` 内的有序 tx 序列划分为若干**波次**（wave），波次内的 tx
//! 读写集两两不相交（可安全并发执行），波次之间按串行语义 merge。
//!
//! # 确定性
//!
//! 波次划分**仅依赖 (rwset, tx_index)**，与线程调度无关。同样的输入永远得到同样的
//! 波次划分；波次内 tx 的结果聚合顺序按 `tx_index` 升序 merge，与串行执行等价。
//!
//! # Soundness
//!
//! 波次内并发的前提是"读写集两两不相交"。但 rBPF 合约的写集在执行前不一定能完全静态
//! 确定——因此 [`ReadWriteSet`] 带 [`ReadWriteSet::forces_serial`] 标记：
//! - 对无法静态确定完整写集的 tx（如未审计的 precompile / 保守处理的 rBPF 合约），
//!   `forces_serial = true`，强制独占一个波次（不与任何 tx 并发）。
//! - 并行执行器在波次结束后还会做运行时复核（真实读写集 ⊆ 估计），未通过的降级重跑。

use std::collections::HashSet;

use crate::Address;
use crate::account::derive_address;
use crate::object_model::ObjectID;
use crate::transaction::{Transaction, TxLane};
use crate::vm::PrecompileRegistry;

/// 单 tx 的读写集。
#[derive(Debug, Clone, Default)]
pub struct ReadWriteSet {
    /// 读取的 ObjectID 集合。
    pub read: HashSet<ObjectID>,
    /// 写入的 ObjectID 集合。
    pub write: HashSet<ObjectID>,
    /// 调用者账户地址集合（需推进 nonce 的 lane：Public / ForceSync）。
    ///
    /// 用集合而非单值：[`merge`] 把波次内所有 tx 的 account 累加进来，
    /// 使后续 tx 能与波次内**任意**已加入 tx 的 account 比较冲突。
    /// 同一 caller 的多笔 tx 会因 account key 冲突落不同波次，等价于串行推进
    /// nonce（保留 `validate_public_tx` 的严格 nonce 语义）。
    pub accounts: HashSet<Address>,
    /// 是否强制独占波次（保守串行化，见模块文档 Soundness 段）。
    pub forces_serial: bool,
}

impl ReadWriteSet {
    /// 该读写集是否与另一个冲突（不可并发）。
    ///
    /// 冲突条件（任一成立即冲突）：
    /// - 任一方 `forces_serial`；
    /// - accounts 集合相交（任一共享 caller）；
    /// - (read ∪ write) 与 (read ∪ write) 相交（经典读写冲突：R-W / W-R / W-W）。
    pub fn conflicts(&self, other: &Self) -> bool {
        if self.forces_serial || other.forces_serial {
            return true;
        }
        // account 集合相交 → 冲突（同 caller nonce 串行化）
        if !self.accounts.is_disjoint(&other.accounts) {
            return true;
        }
        // read-write / write-write / write-read 交叉
        !self_union_disjoint(&self.read, &self.write, &other.read, &other.write)
    }

    /// 合并另一个读写集（用于波次累计写集）。
    pub fn merge(&mut self, other: &Self) {
        self.read.extend(other.read.iter().copied());
        self.write.extend(other.write.iter().copied());
        self.accounts.extend(other.accounts.iter().copied());
        self.forces_serial = self.forces_serial || other.forces_serial;
    }
}

/// 判定 (self_read ∪ self_write) 与 (other_read ∪ other_write) 是否不相交。
/// 任一相交则返回 false（即存在冲突）。
fn self_union_disjoint(
    self_read: &HashSet<ObjectID>,
    self_write: &HashSet<ObjectID>,
    other_read: &HashSet<ObjectID>,
    other_write: &HashSet<ObjectID>,
) -> bool {
    // 任意一对相交即冲突；为减少比较，取较小集合遍历。
    let intersect = |a: &HashSet<ObjectID>, b: &HashSet<ObjectID>| {
        let (small, big) = if a.len() <= b.len() { (a, b) } else { (b, a) };
        small.iter().any(|x| big.contains(x))
    };
    // 4 种交叉：r-r, r-w, w-r, w-w
    !(intersect(self_read, other_read)
        || intersect(self_read, other_write)
        || intersect(self_write, other_read)
        || intersect(self_write, other_write))
}

/// 估计单笔 tx 的读写集（执行前的静态部分）。
///
/// # 公式
/// - `read` = `tx.inputs` ∪ { `contract_id`（若有 contract_call） }
/// - `write`：
///   - 纯 outputs tx：`tx.outputs.ids`
///   - precompile 调用：保守纳入 `{contract_id}`（precompile 通常读写自身对象）
///   - rBPF 合约调用（非 precompile）：`tx.inputs` ∪ `tx.outputs.ids`
///     （合约可经 `object_write` 改写任意预加载 input；保守把全部 inputs 当写集）
///     并置 `forces_serial = false`（仍可与其他不相交 tx 并发）
/// - `account` = `Some(caller)` 当 lane ∈ {Public, ForceSync}
/// - `forces_serial = true` 当读集无法静态确定（当前无此情况，预留扩展点）
///
/// # 关于"未知写集"
///
/// rBPF 合约的真实写集在执行后才知道（`object_cache.keys()`），但执行前我们把
/// `tx.inputs` 全部当作潜在写集——这是**保守但完备**的：合约能写的对象必然在
/// `tx.inputs` ∪ `created_objects` 内（`object_write` 校验：caller 须拥有该对象，
/// 见 `syscalls.rs`）。因此不会漏掉 W-W 冲突。
pub fn estimate_rwset(
    tx: &Transaction,
    precompile_registry: Option<&PrecompileRegistry>,
) -> ReadWriteSet {
    let caller = derive_address(&tx.tagged_pubkey);
    let needs_account = matches!(tx.lane_hint, TxLane::Public | TxLane::ForceSync);

    let mut read: HashSet<ObjectID> = tx.inputs.iter().copied().collect();
    let mut write: HashSet<ObjectID> = tx.outputs.iter().map(|o| o.id).collect();

    let mut forces_serial = false;

    if let Some(call) = &tx.contract_call {
        // contract_id 总是被读（executor.rs:337 读合约对象；precompile 读 game/table）
        read.insert(call.contract_id);

        let is_precompile = precompile_registry
            .map(|r| r.is_precompile(call.contract_id))
            .unwrap_or(false);
        if is_precompile {
            // precompile 通常读 + 写自身对象。保守纳入写集。
            // 真实 read_objects 由 DispatchResult 在执行后回填复核。
            write.insert(call.contract_id);
            // Funded precompiles may consume declared owned Coin UTXOs. Treat every declared
            // input as potentially writable so two spends of the same coin cannot share a wave.
            write.extend(tx.inputs.iter().copied());
        } else {
            // rBPF 合约：能写的对象 ⊆ inputs ∪ created（见 syscalls 所有权校验）。
            // 把全部 inputs 当潜在写集（保守完备）。
            write.extend(tx.inputs.iter().copied());
            // created_objects 在执行前未知，但它们是新 ID，不会与既有 tx 的读集冲突
            // （ObjectID 含 creator+nonce，碰撞概率为零）。因此无需 forces_serial。
            // 不过合约可能创建 tx.outputs 之外的对象（object_create syscall），
            // 这些 ID 在 estimate 阶段不可见——运行时复核会捕获。
        }
    }

    // gas-free lane（GameTurn/CheckpointAnchor）只经 precompile 调度，
    // 但若它流入 execute_block（理论上 public_txs 不含 gas-free lane），
    // accounts 留空以免错误串行化。
    let accounts: HashSet<Address> = if needs_account {
        [caller].into_iter().collect()
    } else {
        HashSet::new()
    };

    ReadWriteSet {
        read,
        write,
        accounts,
        forces_serial,
    }
}

/// 把有序 tx 序列划分为波次（贪心调度）。
///
/// 算法（与串行语义等价）：
/// - 维护"当前波次累计读写集" `accu`。
/// - 顺序扫描 tx：
///   - 若该 tx 与 `accu` 不冲突 → 加入当前波次，`accu.merge(tx)`。
///   - 若冲突 → 结束当前波次，新开波次仅含该 tx。
/// - `forces_serial` 的 tx 独占波次（与空集比较不冲突，但 merge 后 accu=自身，
///   下一个 tx 必与之冲突 → 下一个 tx 落新波次）。
///
/// 返回 `Vec<Vec<usize>>`，每个内层 Vec 是 tx 索引（升序）。
/// 空输入返回空 Vec。
pub fn plan_waves(rwsets: &[ReadWriteSet]) -> Vec<Vec<usize>> {
    if rwsets.is_empty() {
        return Vec::new();
    }

    let mut waves: Vec<Vec<usize>> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    let mut accu = ReadWriteSet::default();

    for (idx, rw) in rwsets.iter().enumerate() {
        if current.is_empty() {
            // 波次第一个 tx：直接加入
            current.push(idx);
            accu = rw.clone();
            continue;
        }
        if accu.conflicts(rw) {
            // 冲突：结束当前波次，开启新波次
            waves.push(std::mem::take(&mut current));
            current.push(idx);
            accu = rw.clone();
        } else {
            // 不冲突：加入当前波次
            current.push(idx);
            accu.merge(rw);
        }
    }
    if !current.is_empty() {
        waves.push(current);
    }
    waves
}

/// 运行时复核：真实读写集是否 ⊆ 估计读写集。
///
/// 用于波次内执行后校验：若合约/precompile 实际访问了估计阶段未纳入的对象，
/// 则该 tx 应降级串行重跑（保证 soundness）。
///
/// - `actual_read` / `actual_write`：执行后从 WriteCaptureBackend 与 receipt 提取。
/// - `estimated`：执行前的 [`estimate_rwset`] 结果。
///
/// 返回 `false` 表示真实读写集超出估计（需降级重跑）。
pub fn within_estimate(
    actual_read: &HashSet<ObjectID>,
    actual_write: &HashSet<ObjectID>,
    estimated: &ReadWriteSet,
) -> bool {
    actual_read.iter().all(|id| estimated.read.contains(id))
        && actual_write.iter().all(|id| estimated.write.contains(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::{Object, ObjectID, Ownership};
    use crate::signature::TaggedPubkey;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{Gas, RouteHint, TxRequest};

    fn addr(b: u8) -> Address {
        [b; 20]
    }

    fn tagged() -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![0x02; 33],
        }
    }

    /// 构造纯 outputs tx 的读写集（不走 estimate_rwset，直接构造）。
    fn rw_out(creator: Address, nonce: u64) -> ReadWriteSet {
        let id = ObjectID::new(creator, nonce);
        ReadWriteSet {
            read: HashSet::new(),
            write: [id].into_iter().collect(),
            accounts: [creator].into_iter().collect(),
            forces_serial: false,
        }
    }

    fn make_output(creator: Address, nonce: u64) -> Object {
        Object::new(
            ObjectID::new(creator, nonce),
            Ownership::AddressOwned { owner: creator },
            "T",
            vec![],
            None,
        )
    }

    // ===== conflicts =====

    #[test]
    fn disjoint_writes_do_not_conflict() {
        let a = rw_out(addr(1), 0);
        let b = rw_out(addr(2), 0);
        assert!(!a.conflicts(&b));
    }

    #[test]
    fn same_write_conflicts() {
        let a = rw_out(addr(1), 0);
        let b = rw_out(addr(1), 0);
        assert!(a.conflicts(&b), "写同一对象应冲突");
    }

    #[test]
    fn same_account_conflicts() {
        // 同 caller 不同对象，但 account 相同 → 冲突（nonce 串行化）
        let a = rw_out(addr(1), 0);
        let b = rw_out(addr(1), 1);
        assert!(a.conflicts(&b), "同账户应冲突（nonce 串行化）");
    }

    #[test]
    fn read_write_cross_conflicts() {
        let id = ObjectID::new(addr(5), 9);
        let a = ReadWriteSet {
            read: [id].into_iter().collect(),
            write: HashSet::new(),
            accounts: [addr(1)].into_iter().collect(),
            forces_serial: false,
        };
        let b = ReadWriteSet {
            read: HashSet::new(),
            write: [id].into_iter().collect(),
            accounts: [addr(2)].into_iter().collect(),
            forces_serial: false,
        };
        assert!(a.conflicts(&b), "R-W 交叉应冲突");
    }

    #[test]
    fn forces_serial_conflicts_with_everything() {
        let mut a = rw_out(addr(1), 0);
        a.forces_serial = true;
        let b = rw_out(addr(9), 0); // 完全不相交
        assert!(a.conflicts(&b), "forces_serial 应与任何 tx 冲突");
    }

    #[test]
    fn gasfree_lanes_no_account_can_parallelize() {
        // 两笔 gas-free lane（account=None）写不同对象 → 可并发
        let a = ReadWriteSet {
            read: HashSet::new(),
            write: [ObjectID::new(addr(1), 0)].into_iter().collect(),
            accounts: HashSet::new(),
            forces_serial: false,
        };
        let b = ReadWriteSet {
            read: HashSet::new(),
            write: [ObjectID::new(addr(2), 0)].into_iter().collect(),
            accounts: HashSet::new(),
            forces_serial: false,
        };
        assert!(!a.conflicts(&b));
    }

    // ===== plan_waves =====

    #[test]
    fn plan_waves_independent_txs_one_wave() {
        // 三个不同 caller 各写一个对象 → 同一波次
        let rws = vec![rw_out(addr(1), 0), rw_out(addr(2), 0), rw_out(addr(3), 0)];
        let waves = plan_waves(&rws);
        assert_eq!(waves.len(), 1);
        assert_eq!(waves[0], vec![0, 1, 2]);
    }

    #[test]
    fn plan_waves_same_account_separate_waves() {
        // 同 caller 三笔 → 三个波次（nonce 链保序）
        let rws = vec![rw_out(addr(1), 0), rw_out(addr(1), 1), rw_out(addr(1), 2)];
        let waves = plan_waves(&rws);
        assert_eq!(waves.len(), 3);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1]);
        assert_eq!(waves[2], vec![2]);
    }

    #[test]
    fn plan_waves_conflict_splits_wave() {
        // tx0(tx1caller 写 objA), tx1(不同 caller 写 objA) → 不同波次
        let id = ObjectID::new(addr(5), 0);
        let a = ReadWriteSet {
            read: HashSet::new(),
            write: [id].into_iter().collect(),
            accounts: [addr(1)].into_iter().collect(),
            forces_serial: false,
        };
        let b = ReadWriteSet {
            read: HashSet::new(),
            write: [id].into_iter().collect(),
            accounts: [addr(2)].into_iter().collect(),
            forces_serial: false,
        };
        let c = rw_out(addr(3), 0); // 与 a,b 都不相交
        let waves = plan_waves(&[a, b, c]);
        // a 独占波次0（b 与 a 冲突），b 独占波次1，c 与 b 不冲突→波次1
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1, 2]);
    }

    #[test]
    fn plan_waves_empty() {
        assert!(plan_waves(&[]).is_empty());
    }

    #[test]
    fn plan_waves_forces_serial_isolates() {
        let mut a = rw_out(addr(1), 0);
        a.forces_serial = true;
        let b = rw_out(addr(2), 0); // 与 a 不相交，但 a forces_serial
        let c = rw_out(addr(3), 0);
        let waves = plan_waves(&[a, b, c]);
        // a 独占波次0；b,c 不相交且都非 forces_serial → 波次1
        assert_eq!(waves.len(), 2);
        assert_eq!(waves[0], vec![0]);
        assert_eq!(waves[1], vec![1, 2]);
    }

    // ===== estimate_rwset =====

    fn req_with_output(caller: Address, nonce_tx: u64, creation_nonce: u64) -> Transaction {
        let req = TxRequest {
            inputs: vec![],
            outputs: vec![make_output(caller, creation_nonce)],
            contract_call: None,
            gas: Gas::new(1000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: nonce_tx,
            gameturn_nonce: None,
            is_fallback: false,
        };
        req.into_transaction(tagged(), vec![0u8; 65])
    }

    #[test]
    fn estimate_rwset_pure_outputs() {
        // 注意：derive_address(tagged()) 是某个固定地址，不是 caller 形参。
        let tx = req_with_output(addr(1), 0, 7);
        let rw = estimate_rwset(&tx, None);
        assert!(rw.read.is_empty());
        assert!(rw.write.contains(&ObjectID::new(addr(1), 7)));
        assert_eq!(
            rw.accounts,
            [derive_address(&tagged())]
                .into_iter()
                .collect::<HashSet<_>>()
        );
        assert!(!rw.forces_serial);
    }

    #[test]
    fn estimate_rwset_contract_id_in_read() {
        let contract_id = ObjectID::new(addr(9), 1);
        let req = TxRequest {
            inputs: vec![ObjectID::new(addr(1), 2)],
            outputs: vec![],
            contract_call: Some(crate::transaction::ContractCall {
                contract_id,
                method_selector: [0u8; 32],
                args: vec![],
            }),
            gas: Gas::new(1000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let tx = req.into_transaction(tagged(), vec![0u8; 65]);
        let rw = estimate_rwset(&tx, None);
        // contract_id 必在 read；inputs 必在 read；rBPF（非 precompile）→ inputs 也在 write
        assert!(rw.read.contains(&contract_id));
        assert!(rw.read.contains(&ObjectID::new(addr(1), 2)));
        assert!(
            rw.write.contains(&ObjectID::new(addr(1), 2)),
            "rBPF inputs 应在写集"
        );
        assert!(!rw.forces_serial);
    }

    // ===== within_estimate =====

    #[test]
    fn within_estimate_passes_when_subset() {
        let est = rw_out(addr(1), 0);
        let actual_read: HashSet<ObjectID> = HashSet::new();
        let actual_write: HashSet<ObjectID> = [ObjectID::new(addr(1), 0)].into_iter().collect();
        assert!(within_estimate(&actual_read, &actual_write, &est));
    }

    #[test]
    fn within_estimate_fails_on_extra_write() {
        let est = rw_out(addr(1), 0);
        let actual_write: HashSet<ObjectID> = [
            ObjectID::new(addr(1), 0),
            ObjectID::new(addr(2), 0), // 估计外的写
        ]
        .into_iter()
        .collect();
        assert!(!within_estimate(&HashSet::new(), &actual_write, &est));
    }
}
