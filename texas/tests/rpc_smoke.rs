use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider};
use url::Url;

#[tokio::test]
// 需要本地 Starknet devnet (127.0.0.1:5051) 与其上的历史交易；CI 跳过，本地手动验证用。
#[ignore = "requires local starknet devnet at 127.0.0.1:5051 with the seeded tx"]
async fn devnet_smoke() {
    let url = Url::parse("http://127.0.0.1:5051").unwrap();
    let client = JsonRpcClient::new(HttpTransport::new(url));
    let chain = client.chain_id().await.expect("chain_id");
    println!("chain_id = {chain:#x}");
    let hash = "0x0424d1bfb52ea422249d6b26c3b7fa46b594ae7df4416dc95e9564005d207445";
    let felt = starknet::core::types::Felt::from_hex(hash).unwrap();
    let r = client.get_transaction_receipt(felt).await.expect("receipt");
    println!("receipt ok: {:?}", r.receipt.transaction_hash());
}
