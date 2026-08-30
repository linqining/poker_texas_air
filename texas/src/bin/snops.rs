//! Starknet 运维工具：declare / deploy / invoke / call。
use clap::{Parser, Subcommand};
use starknet::accounts::{Account, ExecutionEncoding, SingleOwnerAccount};
use starknet::contract::ContractFactory;
use starknet::core::types::{Call, Felt};
use starknet::providers::jsonrpc::HttpTransport;
use starknet::providers::{JsonRpcClient, Provider};
use starknet::signers::{LocalWallet, SigningKey};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "snops")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    #[arg(long)]
    url: String,
    #[arg(long, default_value = "")]
    pk: String,
    #[arg(long, default_value = "")]
    addr: String,
}

#[derive(Subcommand, Clone)]
enum Cmd {
    Declare {
        #[arg(long)] class: String,
        #[arg(long)] compiled: String,
        #[arg(long, default_value = "")] compiled_hash: String,
        /// 跳过链上估算，直接给定资源上限（某些公共 RPC 对 estimateFee
        /// 的请求体大小有限制，大合约会 503）。
        #[arg(long, default_value = "")] l1_gas: String,
        #[arg(long, default_value = "")] l1_data_gas: String,
        #[arg(long, default_value = "")] l2_gas: String,
    },
    Deploy {
        #[arg(long)] class_hash: String,
        #[arg(long, default_value = "")] calldata: String,
    },
    Invoke {
        #[arg(long)] contract: String,
        #[arg(long)] r#fn: String,
        #[arg(long, default_value = "")] calldata: String,
    },
    Call {
        #[arg(long)] contract: String,
        #[arg(long)] r#fn: String,
        #[arg(long, default_value = "")] calldata: String,
    },
    /// 生成随机账户密钥并计算 OZ 账户地址（不部署、不上链）。
    GenKey,
    /// 计算契约类的 sierra / casm class hash（离线，不连链）。
    ClassHash {
        #[arg(long)] class: String,
        #[arg(long)] compiled: String,
    },
    /// 部署账户（deploy_account 交易；需账户地址已有 STRK 支付费用）。
    DeployAcct {
        #[arg(long, default_value = "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564")]
        class_hash: String,
    },
}

fn felt(s: &str) -> Felt {
    let t = s.trim();
    // 0x 前缀按 hex，其余按十进制（与 starknet 生态工具惯例一致，
    // 避免 "100000000000000000000" 这类十进制金额被当成 hex 解析成 2^80）。
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Felt::from_hex(hex).expect("felt hex parse")
    } else {
        Felt::from_dec_str(t).expect("felt decimal parse")
    }
}

fn encode_byte_array(s: &str) -> Vec<Felt> {
    let bytes = s.as_bytes();
    let n_full = bytes.len() / 31;
    let rem = &bytes[n_full * 31..];
    let mut out = vec![Felt::from(n_full as u64)];
    for i in 0..n_full {
        out.push(Felt::from_bytes_be(&bytes[i*31..(i+1)*31].try_into().unwrap()));
    }
    if !rem.is_empty() {
        // ByteArray 序列化顺序：pending_word 在前，pending_word_len 在后
        let mut buf = [0u8; 32];
        buf[1..1 + rem.len()].copy_from_slice(rem);
        out.push(Felt::from_bytes_be(&buf));
        out.push(Felt::from(rem.len() as u64));
    } else {
        out.push(Felt::ZERO);
    }
    out
}

fn parse_args_mixed(s: &str) -> Vec<Felt> {
    let t = s.trim();
    if t.is_empty() { return vec![]; }
    let mut out = Vec::new();
    for part in t.split(',') {
        if let Some(rest) = part.strip_prefix("@str:") {
            out.extend(encode_byte_array(rest));
        } else {
            out.push(felt(part));
        }
    }
    out
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli: Cli = Cli::parse();

    // 无网络依赖：生成密钥 + 计算 OZ 账户地址（deployer 0、salt 0）。
    if let Cmd::GenKey = cli.cmd {
        let sk = SigningKey::from_random();
        let pubkey = sk.verifying_key().scalar();
        let oz_class = Felt::from_hex(
            "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564",
        )?;
        let address = starknet::core::utils::get_contract_address(
            Felt::ZERO,
            oz_class,
            &[pubkey],
            Felt::ZERO,
        );
        println!("PRIVATE_KEY={pk:#x}", pk = sk.secret_scalar());
        println!("PUBLIC_KEY={pubkey:#x}");
        println!("ADDRESS={address:#x}");
        return Ok(());
    }

    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        url::Url::parse(&cli.url)?,
    )));

    // deploy_account：账户尚不存在，不走 SingleOwnerAccount，直接用 factory。
    if let Cmd::DeployAcct { class_hash } = cli.cmd {
        use starknet::accounts::{AccountFactory, OpenZeppelinAccountFactory};
        let factory = OpenZeppelinAccountFactory::new(
            felt(&class_hash),
            provider.chain_id().await?,
            LocalWallet::from_signing_key(SigningKey::from_secret_scalar(felt(&cli.pk))),
            provider.clone(),
        )
        .await?;
        let res = factory.deploy_v3(Felt::ZERO).send().await?;
        println!("ADDRESS={:#x}", res.contract_address);
        println!("TX={:#x}", res.transaction_hash);
        return Ok(());
    }

    // class-hash：纯离线计算，不需要账户。
    if let Cmd::ClassHash { class, compiled } = cli.cmd {
        use starknet::core::types::contract::{CompiledClass, SierraClass};
        let sierra: SierraClass = serde_json::from_reader(std::fs::File::open(&class)?)?;
        let compiled_cls: CompiledClass = serde_json::from_reader(std::fs::File::open(&compiled)?)?;
        println!("SIERRA_CLASS_HASH={:#x}", sierra.class_hash()?);
        println!("CASM_CLASS_HASH={:#x}", compiled_cls.class_hash()?);
        return Ok(());
    }

    let Cmd::Call { contract, r#fn, calldata } = cli.cmd.clone() else {
        let signer = LocalWallet::from_signing_key(SigningKey::from_secret_scalar(felt(&cli.pk)));
        let account = Arc::new(SingleOwnerAccount::new(
            provider.clone(),
            signer,
            felt(&cli.addr),
            provider.chain_id().await?,
            starknet::accounts::ExecutionEncoding::New,
        ));
        match cli.cmd {
            Cmd::Declare { class, compiled, compiled_hash: forced_hash, l1_gas, l1_data_gas, l2_gas } => {
                use starknet::core::types::contract::{CompiledClass, SierraClass};
                let sierra: SierraClass =
                    serde_json::from_reader(std::fs::File::open(&class)?)?;
                let class_hash = sierra.class_hash()?;
                let flattened = sierra.flatten()?;
                let compiled_cls: CompiledClass =
                    serde_json::from_reader(std::fs::File::open(&compiled)?)?;
                let compiled_hash = if forced_hash.is_empty() {
                    compiled_cls.class_hash()?
                } else {
                    Felt::from_hex(&forced_hash)?
                };
                // 显式资源上限（--l*-gas 给出时跳过链上估算）：某些公共 RPC
                // 对 estimateFee 的请求体大小有限制，大合约会直接 503。
                let parse_gas = |s: &str, dflt: u64| -> u64 {
                    if s.is_empty() { dflt } else { felt(s).to_string().parse().unwrap_or(dflt) }
                };
                let manual = !l1_gas.is_empty() || !l2_gas.is_empty();
                // starknet-core 的 casm hash 与 devnet 计算可能有版本差异：
                // 首次提交失败时从错误中提取 Actual hash 重试一次。
                let declare = account.declare_v3(Arc::new(flattened.clone()), compiled_hash);
                let declare = if manual {
                    declare
                        .l1_gas(parse_gas(&l1_gas, 800))
                        .l1_data_gas(parse_gas(&l1_data_gas, 1_000))
                        .l2_gas(parse_gas(&l2_gas, 20_000_000))
                } else {
                    declare
                };
                let res = match declare.send().await {
                    Ok(r) => r,
                    Err(e) if format!("{e:?}").contains("Mismatch compiled class hash") => {
                        // 从嵌套/终态错误文本提取 devnet 计算的 casm hash
                        let text = format!("{e:?}");
                        eprintln!("[snops] mismatch error text: {text}");
                        // devnet 的 "Expected: 0x..." 才是规范 casm hash
                        // （starknet-core 0.16 的计算与 cairo-lang 有版本差异）
                        let actual = text
                            .split("Expected: ")
                            .nth(1)
                            .and_then(|s| s.split_whitespace().next())
                            .map(|s| s.trim_end_matches(|c: char| !c.is_ascii_hexdigit()).to_string())
                            .unwrap_or_default();
                        let actual_hash = Felt::from_hex(&actual)?;
                        account
                            .declare_v3(Arc::new(flattened), actual_hash)
                            .send()
                            .await?
                    }
                    Err(e) => return Err(e.into()),
                };
                println!("CLASS_HASH={class_hash:#x}");
                println!("TX={:#x}", res.transaction_hash);
            }
            Cmd::Deploy { class_hash, calldata } => {
                let factory = ContractFactory::new(felt(&class_hash), account);
                let cd = parse_args_mixed(&calldata);
                let salt = Felt::ZERO;
                let res = factory.deploy_v3(cd.clone(), salt, true).send().await?;
                // UDC deploy_v3 默认 unique 模式（deployer 地址参与地址推导）
                let address = starknet::core::utils::get_udc_deployed_address(
                    salt,
                    felt(&class_hash),
                    &starknet::core::utils::UdcUniqueness::Unique(
                        starknet::core::utils::UdcUniqueSettings {
                            deployer_address: felt(&cli.addr),
                            udc_contract_address: Felt::from_hex(
                                "0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf",
                            )?,
                        },
                    ),
                    &cd,
                );
                println!("CONTRACT_ADDRESS={address:#x}");
                println!("TX={:#x}", res.transaction_hash);
            }
            Cmd::Invoke { contract, r#fn, calldata } => {
                let call = Call {
                    to: felt(&contract),
                    selector: starknet::core::utils::starknet_keccak(r#fn.as_bytes()),
                    calldata: parse_args_mixed(&calldata),
                };
                let res = account.execute_v3(vec![call]).send().await?;
                println!("TX={:#x}", res.transaction_hash);
            }
            Cmd::DeployAcct { class_hash } => {
                use starknet::accounts::{AccountFactory, OpenZeppelinAccountFactory};
                let factory = OpenZeppelinAccountFactory::new(
                    felt(&class_hash),
                    provider.chain_id().await?,
                    LocalWallet::from_signing_key(SigningKey::from_secret_scalar(felt(&cli.pk))),
                    provider.clone(),
                )
                .await?;
                let res = factory.deploy_v3(Felt::ZERO).send().await?;
                println!("ADDRESS={:#x}", res.contract_address);
                println!("TX={:#x}", res.transaction_hash);
            }
            Cmd::GenKey | Cmd::Call { .. } | Cmd::ClassHash { .. } => unreachable!(),
        }
        return Ok(());
    };
    let request = starknet::core::types::FunctionCall {
        contract_address: felt(&contract),
        entry_point_selector: starknet::core::utils::starknet_keccak(r#fn.as_bytes()),
        calldata: parse_args_mixed(&calldata),
    };
    let res = provider
        .call(request, starknet::core::types::BlockId::Tag(starknet::core::types::BlockTag::Latest))
        .await?;
    for f in res {
        println!("OUT={f:#x}");
    }
    Ok(())
}
