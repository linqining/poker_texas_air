// Part C3.2-M1: 赔付 sidecar HTTP 入口。
// 端点：
//   POST /payout          {handBinding, seatIndex, amountWei, noteId?, playerHint?}
//   GET  /payouts         队列快照（运营观测）
//   GET  /health          存活探针
// 鉴权：x-sidecar-key 必须等于 PAYOUT_SIDECAR_KEY（服务端调用方注入）。
import http from 'node:http';
import { PayoutQueue } from './queue.mjs';

const KEY = process.env.PAYOUT_SIDECAR_KEY;
const PORT = Number(process.env.PAYOUT_SIDECAR_PORT ?? 9100);

if (!KEY) {
  console.error('[sidecar] PAYOUT_SIDECAR_KEY is required');
  process.exit(1);
}

const queue = new PayoutQueue();

const server = http.createServer(async (req, res) => {
  const json = (code, body) => {
    res.writeHead(code, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  if ((req.headers['x-sidecar-key'] ?? '') !== KEY) {
    return json(401, { error: 'unauthorized' });
  }
  if (req.method === 'GET' && req.url === '/health') {
    return json(200, { ok: true });
  }
  if (req.method === 'GET' && req.url === '/payouts') {
    return json(200, { pending: queue.snapshot() });
  }
  if (req.method === 'POST' && req.url === '/payout') {
    let body = '';
    for await (const chunk of req) body += chunk;
    try {
      const payload = JSON.parse(body);
      const result = queue.enqueue(payload);
      return json(result.queued ? 202 : 409, result);
    } catch (e) {
      return json(400, { error: String(e?.message ?? e) });
    }
  }
  return json(404, { error: 'not found' });
});

server.listen(PORT, () => {
  console.log(`[sidecar] payout sidecar listening on :${PORT}`);
});
