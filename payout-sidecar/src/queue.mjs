// Part C3.2-M1: 赔付 sidecar 队列（SETTLEMENT_PRIVACY_PLAN.md 排期 C3.2-M2）。
//
// 职责：接收游戏服务器的赔付入队请求，按「批量浮存 + 随机延迟抖动」的
// 节奏把赢家赔付以 STRK20 加密 note 私密转账到赢家的 viewing key。
//
// ⚠️ SDK 接入点（M1 骨架的唯一外部依赖）：
// 私密转账的实际执行需要 STRK20 Privacy SDK（starkware-libs/starknet-privacy
// monorepo 的 TypeScript SDK）。`deliverPrivateTransfer()` 中的 transport
// 就是唯一的接入缝——SDK 就绪后只需替换该函数内部实现，队列/抖动/重试/
// 消费方协议均不变。
//
// 隐私纪律（与方案文档一致）：
// - 浮存一次性大额 shield，之后所有赔付在池内完成，链上无逐笔付款人；
// - 每笔赔付的延迟在 [delayMinMs, delayMaxMs] 随机，弱化时间关联；
// - 失败重试有界（3 次，指数退避），重试期间条目标记 pending 不可重复入队。

const DEFAULTS = {
  delayMinMs: 30_000,
  delayMaxMs: 180_000,
  maxRetries: 3,
};

export class PayoutQueue {
  constructor(options = {}) {
    this.opts = { ...DEFAULTS, ...options };
    /** hand_binding → payout 条目；同 hand 去重。 */
    this.pending = new Map();
    this.seq = 0;
    this.deliver = options.deliver ?? defaultDeliver;
  }

  /**
   * 入队一笔赔付。重复 (hand_binding, seat) 自动忽略（幂等）。
   * @returns {{queued:boolean, id?:string, reason?:string}}
   */
  enqueue({ handBinding, seatIndex, amountWei, noteId, playerHint }) {
    const dedup = `${handBinding}:${seatIndex}`;
    if (this.pending.has(dedup)) {
      return { queued: false, reason: 'already queued' };
    }
    const id = `payout-${++this.seq}`;
    const delay = this.opts.delayMinMs +
      Math.floor(Math.random() * (this.opts.delayMaxMs - this.opts.delayMinMs));
    const entry = {
      id,
      handBinding,
      seatIndex,
      amountWei,
      noteId,
      playerHint: playerHint ?? null, // 仅运营侧日志提示用，不参与转账
      status: 'scheduled',
      attempts: 0,
      deliverAt: Date.now() + delay,
    };
    this.pending.set(dedup, entry);
    setTimeout(() => void this.run(entry), delay);
    return { queued: true, id, deliverAt: entry.deliverAt };
  }

  async run(entry) {
    entry.status = 'delivering';
    entry.attempts += 1;
    try {
      await this.deliver(entry);
      entry.status = 'delivered';
      this.pending.delete(`${entry.handBinding}:${entry.seatIndex}`);
    } catch (err) {
      entry.status = 'failed';
      entry.error = String(err?.message ?? err);
      if (entry.attempts < this.opts.maxRetries) {
        entry.status = 'scheduled';
        const backoff = 2 ** entry.attempts * 10_000;
        entry.deliverAt = Date.now() + backoff;
        setTimeout(() => void this.run(entry), backoff);
      }
    }
  }

  snapshot() {
    return [...this.pending.values()].map(({ id, status, attempts, deliverAt }) => ({
      id, status, attempts, deliverAt,
    }));
  }
}

/**
 * SDK 接入缝（C3.2-M1 唯一待替换点）。
 *
 * 目标行为：用运营浮存的池内余额，向赢家 viewing key 私密转账
 * `amountWei`（STRK20 加密 note，owner 隐藏）。伪代码：
 *
 *   import { createPrivateTransfers } from '<STRK20 Privacy SDK>';
 *   const transfers = createPrivateTransfers(operatorConfig);
 *   await transfers.transfer({ token, recipient: winnerViewingKey, amountWei });
 *
 * 上线前核对（strk20-privacy 文档）：SDK 版本、池地址、池费
 * `get_fee_amount`（从浮存扣）、prover 依赖与密钥托管方式。
 */
async function defaultDeliver(_entry) {
  throw new Error(
    'STRK20 Privacy SDK not integrated yet — see settlement_payout_anonymizer integration notes (C3.2-M1)'
  );
}
