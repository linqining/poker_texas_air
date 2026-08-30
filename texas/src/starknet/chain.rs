//! Starknet RPC 客户端（provider + 操作员账户）。
//!
//! `JsonRpcClient<HttpTransport>` 处理读调用（isValidSignature / balanceOf /
//! chip_balance / tx 回执），`SingleOwnerAccount` 在结算上链时签发
//! register_aggregate / settle_hand 交易。操作员私钥只在创建账户时使用一次。

use starknet::accounts::SingleOwnerAccount;
use starknet::core::types::{BlockId, BlockTag, FunctionCall, Felt};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet::signers::{LocalWallet, SigningKey};
use std::sync::Arc;

use super::config::StarknetConfig;

pub type JsonRpcHttp = JsonRpcClient<HttpTransport>;
pub type OperatorAccount = SingleOwnerAccount<Arc<JsonRpcHttp>, LocalWallet>;

const DEVNET_RPC: &str = "http://localhost:5050";

pub struct StarknetChain {
    pub config: StarknetConfig,
    provider: Arc<JsonRpcHttp>,
    operator: tokio::sync::OnceCell<Option<Arc<OperatorAccount>>>,
}

impl StarknetChain {
    pub fn new(config: StarknetConfig) -> Self {
        let url = url::Url::parse(if config.rpc_enabled() {
            &config.rpc_url
        } else {
            DEVNET_RPC
        })
        .unwrap_or_else(|_| url::Url::parse(DEVNET_RPC).unwrap());
        Self {
            provider: Arc::new(JsonRpcClient::new(HttpTransport::new(url))),
            operator: tokio::sync::OnceCell::new(),
            config,
        }
    }

    pub fn provider(&self) -> Arc<JsonRpcHttp> {
        self.provider.clone()
    }

    /// 惰性构建操作员账户（需要地址 + 私钥 + RPC 齐备）。
    pub async fn operator(&self) -> Option<Arc<OperatorAccount>> {
        if !self.config.settlement_enabled() {
            return None;
        }
        self.operator
            .get_or_init(|| async {
                let address = parse_felt(&self.config.operator_address)?;
                let secret = parse_felt(&self.config.operator_private_key)?;
                let chain_id = self.provider.chain_id().await.ok()?;
                let account = SingleOwnerAccount::new(
                    self.provider.clone(),
                    LocalWallet::from_signing_key(SigningKey::from_secret_scalar(secret)),
                    address,
                    chain_id,
                    starknet::accounts::ExecutionEncoding::New,
                );
                // starknet-rs 0.16 默认 block_id 已是 PreConfirmed（nonce 读取
                // 包含已提交未 accepted 的交易，公共 RPC 上连续结算交易不撞
                // nonce）；显式标注仅为防止未来依赖升级改变默认值。
                let mut account = account;
                account.set_block_id(BlockId::Tag(BlockTag::PreConfirmed));
                Some(Arc::new(account))
            })
            .await
            .clone()
    }

    /// 通用合约只读调用（selector + calldata → 返回 felts）。
    pub async fn call_contract(
        &self,
        contract_address: Felt,
        entry_point: Felt,
        calldata: Vec<Felt>,
    ) -> Result<Vec<Felt>, String> {
        let request = FunctionCall {
            contract_address,
            entry_point_selector: entry_point,
            calldata,
        };
        self.provider.call(request, BlockId::Tag(BlockTag::Latest)).await
            .map_err(|e| format!("call_contract failed: {e}"))
    }
}

/// 解析 felt 字符串（0x hex 或十进制）。空串 / 非法输入返回 None。
pub fn parse_felt(s: &str) -> Option<Felt> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    Felt::from_hex(s).ok()
}

/// starknet.cairo 短字符串 → felt（"isValidSignature" 这类 selector 名用不到，
/// selector 一律用 starknet_keccak；此函数用于把 ASCII 标签编码进 calldata）。
pub fn cairo_short_string(s: &str) -> Option<Felt> {
    starknet::core::utils::cairo_short_string_to_felt(s).ok()
}
