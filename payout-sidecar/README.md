# payout-sidecar（Part C3.2-M1 骨架）

结算赔付 sidecar：接收游戏服务器的赔付入队请求，按「随机延迟抖动 + 有界重试」的节奏，把赢家赔付以 STRK20 加密 note 私密转账（owner 隐藏）。链上与池内均看不出付款人与收款人的对应关系。

## 状态

- ✅ 队列 / 去重 / 延迟抖动 / 有界重试 / 快照观测
- ✅ HTTP 协议（`POST /payout`、`GET /payouts`、`GET /health`，`x-sidecar-key` 鉴权）
- ⏳ `deliverPrivateTransfer()` 的 SDK 接入（`src/queue.mjs` 唯一待替换点）——依赖
  STRK20 Privacy SDK（starkware-libs/starknet-privacy monorepo TS SDK）

## 运行

```sh
PAYOUT_SIDECAR_KEY=<random> node src/server.mjs
```

## 协议

```sh
curl -X POST localhost:9100/payout -H "x-sidecar-key: $KEY" -H 'content-type: application/json' \
  -d '{"handBinding":"0x…","seatIndex":0,"amountWei":"500000000000000","playerHint":"optional"}'
# 202 {"queued":true,"id":"payout-1","deliverAt":1735790000000}
```

## 安全

- `PAYOUT_SIDECAR_KEY` 仅服务端 ↔ sidecar 共享；对玩家不可见。
- 运营浮存密钥不进本仓库（KMS / 环境注入，见方案 §C4 分工表）。
- 每笔赔付的延迟在窗口内随机；浮存以批量 shield 补充，弱化时间关联。
