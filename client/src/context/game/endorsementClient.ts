/**
 * Hand-batch 认可客户端（Plan D P2.1）。
 *
 * 认可私钥只在玩家客户端：首次经 client-wasm `endorsement_keypair`
 * 生成并存 localStorage；服务器每手结算时广播 ENDORSEMENT_REQUEST
 * （携带 hand_binding——认可的挑战域），本模块用
 * `endorsement_mint(sk, hand_binding)` 本地铸造并把成品
 * (pk, R, s) 经 ENDORSEMENT_SUBMIT 交回服务器。服务器全程不接触
 * 认可私钥，只做 on-curve/域校验并中继进 hand_batch 批次。
 *
 * wasm 能力探测：pkg 构建未包含 endorsement 导出时安全降级（返回
 * null，Hand-batch 结算跳过、legacy 结算照常），不破坏牌局。
 */

const ENDORSEMENT_SK_KEY = 'poker.endorsementSk';

interface WasmEndorsementModule {
  endorsement_keypair?: () => Promise<{ sk_hex: string }>;
  endorsement_mint?: (
    skHex: string,
    handBindingHex: string,
  ) => Promise<{
    pk_x_hex: string;
    pk_y_hex: string;
    r_x_hex: string;
    r_y_hex: string;
    s_hex: string;
  }>;
}

let wasmModulePromise: Promise<WasmEndorsementModule | null> | null = null;

async function loadWasmEndorsement(): Promise<WasmEndorsementModule | null> {
  if (!wasmModulePromise) {
    wasmModulePromise = (async () => {
      try {
        const wasm = (await import('@linqining/client-wasm')) as unknown as WasmEndorsementModule;
        const keypair = wasm.endorsement_keypair;
        const mint = wasm.endorsement_mint;
        if (typeof keypair !== 'function' || typeof mint !== 'function') {
          return null; // pkg 构建早于 Plan D：无认可导出
        }
        return {
          endorsement_keypair: () => keypair(),
          endorsement_mint: (sk: string, binding: string) => mint(sk, binding),
        };
      } catch {
        return null;
      }
    })();
  }
  return wasmModulePromise;
}

/** 取（或首次生成）本地认可私钥。wasm 能力缺失时返回 null。 */
export async function ensureEndorsementSk(): Promise<string | null> {
  const wasm = await loadWasmEndorsement();
  if (!wasm) return null;
  let sk = localStorage.getItem(ENDORSEMENT_SK_KEY);
  if (!sk) {
    try {
      const kp = await wasm.endorsement_keypair?.();
      if (!kp?.sk_hex) return null;
      sk = kp.sk_hex;
      localStorage.setItem(ENDORSEMENT_SK_KEY, sk);
    } catch {
      return null;
    }
  }
  return sk;
}

export interface EndorsementSubmission {
  pk_x_hex: string;
  pk_y_hex: string;
  r_x_hex: string;
  r_y_hex: string;
  s_hex: string;
}

/** 对 hand_binding 域本地铸造认可；wasm 能力缺失时返回 null。 */
export async function mintEndorsement(handBindingHex: string): Promise<EndorsementSubmission | null> {
  const wasm = await loadWasmEndorsement();
  if (!wasm) return null;
  const sk = await ensureEndorsementSk();
  if (!sk) return null;
  try {
    return (await wasm.endorsement_mint?.(sk, handBindingHex)) ?? null;
  } catch {
    return null;
  }
}
