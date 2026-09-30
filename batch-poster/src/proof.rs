//! ProofSource：fold 批出证接缝。
//!
//! - [`ScriptProofSource`] 包装 `proving-tool/prove-batch.sh` 两阶段腿
//!   （阶段 A 占位链尾出证取 program_hash → 与对拍锚比对（prove-batch.sh:51
//!   EXPECTED_PH）→ 阶段 B 真实链尾二次出证 → 电路内 batch_fact/根回显与
//!   宿主镜像逐字对拍，脚本自身 fail-closed 非零退出）；
//! - [`MockProofSource`]（feature `test-mocks`）供单测。

use std::path::{Path, PathBuf};
use std::pin::Pin;

use crate::batch::FoldBatchInput;

/// 出证产物（一证一批）。
#[derive(Debug, Clone)]
pub struct ProofArtifact {
    /// 出证程序哈希（hex felt；与对拍锚核对的字段）。
    pub program_hash: String,
    /// 批 fact（hex felt）。
    pub batch_fact: String,
    /// 输出承诺（hex 32B）。
    pub output_commit: String,
    /// keccak 批根（= batch_key；与宿主派生交叉核对）。
    pub keccak_root: [u8; 32],
    /// 终证字节（Monad 工件规格：bz2 压缩形态由出证腿产出，本层透传）。
    pub proof: Vec<u8>,
    /// 每成员的 fold 公开段（18 词 hex；slot 17 = roster）。
    pub outputs: Vec<Vec<String>>,
}

/// 出证接缝（daemon 经 spawn_blocking 调用；测试用 mock）。
pub trait ProofSource: Send + Sync {
    fn prove_batch<'a>(
        &'a self,
        input: &'a FoldBatchInput,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<ProofArtifact, String>> + Send + 'a>>;
}

/// prove-batch.sh 包装（两阶段腿）。
///
/// 脚本用法（proving-tool/prove-batch.sh:26）：`<K> <base_hand_inputs.json>
/// <out_dir> [acc_hex]`；产物：`<out_dir>/manifest.json`（keccak_batch_root /
/// expected_batch_fact / acc_prev / statements）、`<out_dir>/run_b/proof.json`
/// （终证）、`<out_dir>/run_b/public_outputs.json`（program_hash/output）。
/// 退出码非 0 = 对拍/验证失败（fail-closed），本层原样报错。
///
/// **接线边界（骨架）**：现状脚本从 base 手输入**合成** K 手语料——
/// 队列条目（FoldStatement）→ base 输入的派生是 prove-batch.sh 侧的后续
/// 工作；本包装先按脚本现状调用并交叉核对批根/程序哈希。
pub struct ScriptProofSource {
    pub script: PathBuf,
    pub base_input: PathBuf,
    pub work_dir: PathBuf,
    /// program_hash 对拍锚（prove-batch.sh:51 EXPECTED_PH；不一致 = 程序
    /// 源漂移，fail-closed 拒绝上链）。
    pub expected_program_hash: String,
}

impl ScriptProofSource {
    fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
        let raw = s.trim().trim_start_matches("0x");
        let bytes = hex::decode(raw).map_err(|e| format!("hex32 解码失败: {e}"))?;
        bytes.try_into().map_err(|_| "hex32 长度非 32B".to_string())
    }

    fn parse_manifest(&self, dir: &Path) -> Result<(String, String), String> {
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("manifest.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let root = manifest["keccak_batch_root"]
            .as_str()
            .ok_or("manifest 缺 keccak_batch_root")?
            .to_string();
        let fact = manifest["expected_batch_fact"]
            .as_str()
            .ok_or("manifest 缺 expected_batch_fact")?
            .to_string();
        Ok((root, fact))
    }

    fn parse_public_outputs(&self, dir: &Path) -> Result<(String, Vec<serde_json::Value>), String> {
        let v: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("run_b").join("public_outputs.json"))
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let ph = v["program_hash"]
            .as_str()
            .ok_or("public_outputs 缺 program_hash")?
            .to_string();
        let output = v["output"]
            .as_array()
            .cloned()
            .ok_or("public_outputs 缺 output")?;
        Ok((ph, output))
    }
}

impl ProofSource for ScriptProofSource {
    fn prove_batch<'a>(
        &'a self,
        input: &'a FoldBatchInput,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<ProofArtifact, String>> + Send + 'a>> {
        Box::pin(async move {
            let k = input.statements.len();
            let out_dir = self.work_dir.join(format!("batch-k{k}"));
            std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
            let status = std::process::Command::new(&self.script)
                .arg(k.to_string())
                .arg(&self.base_input)
                .arg(&out_dir)
                .arg(input.acc_prev.trim())
                .status()
                .map_err(|e| format!("prove-batch.sh 启动失败: {e}"))?;
            if !status.success() {
                return Err(format!(
                    "prove-batch.sh 退出码 {status}（对拍/验证失败，fail-closed）"
                ));
            }
            let (root_hex, batch_fact) = self.parse_manifest(&out_dir)?;
            let (program_hash, output) = self.parse_public_outputs(&out_dir)?;
            // 对拍锚：program_hash 与钉扎值一致（prove-batch.sh:51 同值口径）。
            if !program_hash.eq_ignore_ascii_case(&self.expected_program_hash) {
                return Err(format!(
                    "program_hash {program_hash} != 钉扎 {}（程序源漂移，拒绝上链）",
                    self.expected_program_hash
                ));
            }
            // 批根交叉核对：脚本宿主派生 vs poster 宿主派生（同一
            // keccak_batch_root 公式）。
            let root = Self::parse_hex32(&root_hex)?;
            let host_root = crate::batch::compute_batch_key(&input.statements)?;
            if root != host_root {
                return Err("keccak 批根两宿主不一致（fail-closed）".into());
            }
            // proof.json 原文透传（bz2 压缩规格由出证腿升级时落地）。
            let proof = std::fs::read(out_dir.join("run_b").join("proof.json"))
                .map_err(|e| format!("proof.json 读取失败: {e}"))?;
            // 每成员 18 词 fold 公开段（K 段 × 18 词 = output 尾部切片；
            // 现状合成语料的段边界由脚本保证，此处按段长切分）。
            let words: Vec<String> = output
                .iter()
                .map(|w| w.as_str().unwrap_or_default().to_string())
                .collect();
            let seg = 18;
            if !words.len().is_multiple_of(seg) {
                return Err(format!("公开段词数 {} 非 {seg} 的倍数", words.len()));
            }
            let outputs = words.chunks(seg).map(|c| c.to_vec()).collect();
            // 输出承诺（stark_recursion::onchain::output_commit 同式由脚本
            // 侧给出；骨架以批根哈希占位字段，信封落盘时由 zchain 复核）。
            let output_commit = format!("0x{}", hex::encode(root));
            Ok(ProofArtifact {
                program_hash,
                batch_fact,
                output_commit,
                keccak_root: root,
                proof,
                outputs,
            })
        })
    }
}

#[cfg(feature = "test-mocks")]
use std::sync::Arc;
/// 测试 mock（feature `test-mocks`）：即时出证 + 调用计数（崩溃恢复测试
/// 断言「重启后不重复出证」）。
#[cfg(feature = "test-mocks")]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "test-mocks")]
pub struct MockProofSource {
    pub expected_program_hash: String,
    pub calls: Arc<AtomicUsize>,
}

#[cfg(feature = "test-mocks")]
impl MockProofSource {
    pub fn new(expected_program_hash: &str) -> Self {
        Self {
            expected_program_hash: expected_program_hash.to_string(),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[cfg(feature = "test-mocks")]
impl ProofSource for MockProofSource {
    fn prove_batch<'a>(
        &'a self,
        input: &'a FoldBatchInput,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<ProofArtifact, String>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let keccak_root = crate::batch::compute_batch_key(&input.statements)?;
            let outputs = input
                .statements
                .iter()
                .map(|s| {
                    (0..18)
                        .map(|i| {
                            if i == 5 {
                                s.hand_binding.clone()
                            } else {
                                format!("0x{:x}", i as u64 + s.fact.len() as u64)
                            }
                        })
                        .collect()
                })
                .collect();
            Ok(ProofArtifact {
                program_hash: self.expected_program_hash.clone(),
                batch_fact: format!("0x{}", hex::encode(keccak_root)),
                output_commit: format!("0x{}", hex::encode(keccak_root)),
                keccak_root,
                proof: b"mock-proof-bytes".to_vec(),
                outputs,
            })
        })
    }
}

/// Dual 路合约入口名映射（STARKNET_DAPV_SETTLE_ENTRY 取值域 → 入口函数；
/// `texas/src/starknet/config.rs:63-77`）。未知/缺省 → v2 稳定入口。
pub fn dual_settle_entry_name(dapv_entry: Option<&str>) -> &'static str {
    match dapv_entry.unwrap_or("v2") {
        "proved_private" => "verify_and_settle_dapv_proved_private",
        "snip36" => "verify_and_settle_dapv_stark_private_v3",
        "combined" => "verify_and_settle_dapv_combined_private",
        _ => "verify_and_settle_dapv_stark_private_v2",
    }
}

/// fold 批入口名（poker_contracts/src/poker_dual_settlement.cairo:255）。
pub const FOLD_SETTLE_ENTRY: &str = "verify_and_settle_dapv_fold_private";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dapv_entry_name_mapping() {
        assert_eq!(
            dual_settle_entry_name(None),
            "verify_and_settle_dapv_stark_private_v2"
        );
        assert_eq!(
            dual_settle_entry_name(Some("v2")),
            "verify_and_settle_dapv_stark_private_v2"
        );
        assert_eq!(
            dual_settle_entry_name(Some("snip36")),
            "verify_and_settle_dapv_stark_private_v3"
        );
        assert_eq!(
            dual_settle_entry_name(Some("proved_private")),
            "verify_and_settle_dapv_proved_private"
        );
        assert_eq!(
            dual_settle_entry_name(Some("combined")),
            "verify_and_settle_dapv_combined_private"
        );
        assert_eq!(
            dual_settle_entry_name(Some("junk")),
            "verify_and_settle_dapv_stark_private_v2"
        );
    }
}
