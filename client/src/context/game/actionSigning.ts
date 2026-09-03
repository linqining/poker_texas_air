/**
 * #16 抗审查动作签名（客户端侧）。
 *
 * 以牌局身份 SK（PlayerContext 的 skHex，Stark curve）对动作
 * (tableId, seq, action, amount) 做 wasm 签名；seq 按桌持久化在
 * localStorage（`poker.actionSeq:{tableId}`），保证服务端看到的
 * 每座位 seq 严格单调。
 *
 * 签名域与 texas/src/starknet/game_action…（poker_protocol
 * `game_action::action_msg_bytes`）逐字节一致；wasm 能力缺失或旧 pkg
 * （无 sign_action 导出）时返回 null，动作以未签名形态发出
 * （迁移期兼容，服务端按 enforcement 开关决定是否拒绝）。
 */

interface ActionSigResult {
  r_hex: string;
  s_hex: string;
}

let wasmSign: ((sk: string, tableId: number, seq: bigint, action: string, amount: bigint) => ActionSigResult) | null = null;
let wasmProbed = false;

async function loadWasmSign(): Promise<typeof wasmSign> {
  if (wasmProbed) return wasmSign;
  wasmProbed = true;
  try {
    const wasm = (await import('@linqining/client-wasm')) as unknown as Record<string, unknown>;
    const fn = wasm.sign_action;
    if (typeof fn !== 'function') {
      return null; // pkg 构建早于 #16：无动作签名导出
    }
    wasmSign = (sk: string, tableId: number, seq: bigint, action: string, amount: bigint) =>
      fn(sk, tableId, seq, action, amount) as ActionSigResult;
  } catch {
    wasmSign = null;
  }
  return wasmSign;
}

function nextSeq(tableId: number | string): number {
  const key = `poker.actionSeq:${tableId}`;
  const current = Number(localStorage.getItem(key) ?? '0') || 0;
  const next = current + 1;
  localStorage.setItem(key, String(next));
  return next;
}

export interface AttachedActionSig {
  seq: number;
  rHex: string;
  sHex: string;
}

/**
 * 为动作生成 (seq, sig)。sk/wasm 缺失或签名抛错时返回 null
 * （动作仍以未签名形态发出；是否拒绝由服务端 enforcement 开关决定）。
 */
export async function signTableAction(
  skHex: string | null,
  tableId: number | string,
  action: 'fold' | 'check' | 'call' | 'raise',
  amount = 0,
): Promise<AttachedActionSig | null> {
  if (!skHex) return null;
  const sign = await loadWasmSign();
  if (!sign) return null;
  try {
    const seq = nextSeq(tableId);
    const out = sign(skHex, Number(tableId), BigInt(seq), action, BigInt(amount));
    if (!out || typeof out.r_hex !== 'string' || typeof out.s_hex !== 'string') return null;
    return { seq, rHex: out.r_hex, sHex: out.s_hex };
  } catch {
    return null;
  }
}

/** 把签名展开为 socket 消息字段（fold/check/call/raise 通吃）。 */
export function sigToPayloadFields(sig: AttachedActionSig | null): Record<string, unknown> {
  if (!sig) return {};
  return { seq: sig.seq, rHex: sig.rHex, sHex: sig.sHex };
}
