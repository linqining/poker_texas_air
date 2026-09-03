// 私密领取奖励弹窗（SETTLEMENT_PRIVACY_PLAN.md Part C3）。
//
// 赢家筹码在 PokerVault 上，「领取」把筹码换成 STRK：
// - 私密领取（首选）：Ready 等 STRK20 钱包的两动作模式 —— 池内 burn
//   等额屏蔽 STRK + helper 烧毁 vault 筹码，产出 owner 隐藏的 open
//   note。链上只有池 envelope，看不出谁领了奖励。
// - 公开出金（回退）：vault.withdraw 直提钱包（边缘公开）。
// 私密路径需要：钱包支持 STRK20 Wallet API（capability 探测）且池内
// 屏蔽余额 ≥ 领取额（守恒在池内闭环）。
//
// UI v2（重构）：紧凑金额条 + 单个「领取条件」分组块（两张注册状态
// 行内聚，Wallet API 版本等噪音只在相关状态出现）+ 双列主行动按钮
// （按钮含义以小字注在按钮下方，不再用独立 footer 段落重复）。
// 宽度 md（480px），常规视口内不出现竖向滚动条。
import React, { useContext, useEffect, useState } from 'react';
import styled, { useTheme } from 'styled-components';
import { useAccount } from '@starknet-react/core';
import ModalShell from './ModalShell';
import Text from '../typography/Text';
import Button from '../buttons/Button';
import authContext from '../../context/auth/authContext';
import { WEI_PER_CHIP, starknetConfig } from '../../starknet/config';
import {
  claimRewardsPrivate,
  claimRewardsPublic,
  detectStrk20Support,
  ensurePayoutCommitment,
  getRegisteredPayoutCommitment,
  getShieldedBalance,
  getWalletApiVersions,
  shieldForPoolRegistration,
  STRK20_WALLET_API_MIN,
  compareVersions,
} from '../../starknet/strk20';
import { activeAccount } from '../../starknet/devAccount';
import { CANONICAL_STRK_ADDRESS } from '../../starknet/starknetGameActions';
import { logger } from '../../helpers/logger';

interface ClaimRewardsModalProps {
  isOpen: boolean;
  /** vault 可领筹码（服务端 chips 单位，1 chip = 1e15 wei）。 */
  chipsAmount: number | null;
  onClose: () => void;
}

// ===== 样式 =====

/** 紧凑金额条：左侧金额三行内聚为一行半，右侧收款地址，不再占半屏 */
const Hero = styled.div`
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 0.5rem;
  padding: 0.7rem 0.9rem;
  border-radius: ${({ theme }) => theme.radius.lg};
  background: linear-gradient(135deg, ${({ theme }) => theme.colors.primaryCta} 0%, ${({ theme }) => theme.colors.primaryCtaDarker} 100%);
  color: #fff;
  box-shadow: 0 6px 18px rgba(79, 70, 229, 0.3);
`;

const HeroLeft = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
`;

const HeroLabel = styled.span`
  font-size: 0.68rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  opacity: 0.85;
`;

const HeroAmount = styled.span`
  font-size: 1.6rem;
  font-weight: 800;
  line-height: 1.15;
  font-variant-numeric: tabular-nums;
`;

const HeroSub = styled.span`
  font-size: 0.75rem;
  opacity: 0.85;
  font-variant-numeric: tabular-nums;
`;

const HeroAddr = styled.span`
  align-self: flex-end;
  flex: none;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.68rem;
  opacity: 0.75;
`;

/** 「领取条件」分组块：两张注册状态行 + 重新校验入口内聚在一个容器里 */
const CheckBlock = styled.section`
  display: flex;
  flex-direction: column;
  gap: 0.45rem;
  padding: 0.6rem 0.8rem;
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.md};
  background: ${({ theme }) => theme.colors.successAlpha06};
`;

const CheckHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
`;

const CheckBlockTitle = styled.span`
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.05em;
  color: ${({ theme }) => theme.colors.softText};
`;

/** 单条状态行：状态点 + 名称 + 行内状态文本或一键注册按钮 */
const CheckRow = styled.div`
  display: flex;
  align-items: center;
  gap: 0.45rem;
`;

const CheckName = styled.span`
  flex: 1;
  min-width: 0;
  font-size: 0.85rem;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

const StatusDot = styled.span<{ $ok: boolean | null }>`
  width: 0.55rem;
  height: 0.55rem;
  border-radius: 50%;
  flex: none;
  background: ${({ $ok, theme }) =>
    $ok === null ? theme.colors.warning : $ok ? theme.colors.success : theme.colors.danger};
`;

const StatusText = styled.span<{ $ok: boolean | null }>`
  font-size: 0.75rem;
  font-weight: 600;
  flex: none;
  color: ${({ $ok, theme }) =>
    $ok === null ? theme.colors.warningDark : $ok ? theme.colors.successStrong : theme.colors.danger};
`;

/** 状态行下的次级信息行（仅在相关状态出现，避免噪音） */
const CheckDetail = styled.span`
  font-size: 0.72rem;
  line-height: 1.45;
  color: ${({ theme }) => theme.colors.mutedText};
  padding-left: 1rem;
`;

/** 行内的链接式小按钮（注册指引入口等） */
const CardLink = styled.button`
  align-self: flex-start;
  margin-left: 1rem;
  background: none;
  border: none;
  padding: 0;
  font-size: 0.72rem;
  color: ${({ theme }) => theme.colors.primaryCta};
  text-decoration: underline;
  cursor: pointer;
  &:disabled {
    opacity: 0.6;
    cursor: default;
  }
`;

/** 未注册池的引导区：钱包内 Shield 步骤（viewing key 只在钱包内，dapp 无法代注册） */
const GuideBox = styled.div`
  margin: 0.1rem 0 0 1rem;
  padding: 0.5rem 0.65rem;
  border-radius: ${({ theme }) => theme.radius.md};
  background: rgba(245, 158, 11, 0.08);
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 0.4rem;
`;

const GuideSteps = styled.ol`
  margin: 0;
  padding-left: 1.1rem;
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.72rem;
  line-height: 1.5;
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

const ReverifyLink = styled.button`
  background: none;
  border: none;
  padding: 0.1rem 0.3rem;
  font-size: 0.7rem;
  color: ${({ theme }) => theme.colors.mutedText};
  text-decoration: underline;
  cursor: pointer;
  &:hover:not(:disabled) {
    color: ${({ theme }) => theme.colors.fontColorDark};
  }
  &:disabled {
    opacity: 0.6;
    cursor: default;
  }
`;

/** 警告 / 错误条 */
const Notice = styled(Text)<{ $kind: 'warn' | 'error' | 'success' }>`
  text-align: center;
  font-size: 0.78rem;
  padding: 0.5rem 0.7rem;
  border-radius: ${({ theme }) => theme.radius.md};
  word-break: break-word;
  ${({ $kind, theme }) => {
    if ($kind === 'warn')
      return `background: rgba(245, 158, 11, 0.12); color: ${theme.colors.warningDark};`;
    if ($kind === 'error')
      return `background: ${theme.colors.dangerAlpha06}; color: ${theme.colors.danger};`;
    return `background: ${theme.colors.successAlpha12}; color: ${theme.colors.successStrong};`;
  }}
`;

/** 双列主行动：按钮 + 下方一句说明（取代独立 footer 段落，说明与按钮同位） */
const ActionsGrid = styled.div`
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.6rem;

  @media screen and (max-width: 479px) {
    grid-template-columns: 1fr;
  }
`;

const ActionCell = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
`;

const ActionNote = styled.span`
  font-size: 0.68rem;
  line-height: 1.4;
  color: ${({ theme }) => theme.colors.softText};
  text-align: center;
`;

const SuccessRing = styled.div`
  width: 3.2rem;
  height: 3.2rem;
  margin: 0.2rem auto;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.6rem;
  color: ${({ theme }) => theme.colors.successStrong};
  background: ${({ theme }) => theme.colors.successAlpha12};
`;

const ClaimModal: React.FC<ClaimRewardsModalProps> = ({ isOpen, chipsAmount, onClose }) => {
  const theme = useTheme();
  const { walletAddress } = useContext(authContext)!;
  const connected = useAccount();
  // 连接的钱包（Ready/Cartridge）优先，dev 直签兜底
  const account = activeAccount(connected.account);

  const [strk20Ready, setStrk20Ready] = useState<boolean | null>(null);
  const [walletApiVersions, setWalletApiVersions] = useState<string[] | null>(null);
  const [shielded, setShielded] = useState<bigint | null>(null);
  const [pending, setPending] = useState<'private' | 'public' | null>(null);
  const [done, setDone] = useState<{ hash: string; kind: 'private' | 'public' } | null>(null);
  const [error, setError] = useState('');
  // 两份注册的真实状态（null = 检测中）。payout = 我们合约的 commitment，
  // pool = Ready 隐私池 viewing key（互不等同，各占一行）。
  const [reg, setReg] = useState<{ payout: boolean | null; pool: boolean | null; fromCache: boolean }>(
    { payout: null, pool: null, fromCache: false },
  );
  const [regPending, setRegPending] = useState(false);
  const [poolRegistering, setPoolRegistering] = useState(false);
  // 池注册指引的展开态：viewing key 只在钱包内，dapp 无法代注册——
  // 未注册用户点一键注册被钱包 118 拒绝时自动展开
  const [poolGuideOpen, setPoolGuideOpen] = useState(false);
  const [checking, setChecking] = useState(false);

  const vaultAddr = starknetConfig.pokerVaultAddress || '';
  const flagsKey = `poker.claimReg:${(walletAddress || '').toLowerCase()}`;

  const readFlags = (): { vault: string; payout: boolean; pool: boolean } | null => {
    try {
      const raw = localStorage.getItem(flagsKey);
      if (!raw) return null;
      const f = JSON.parse(raw);
      if (f && f.vault === vaultAddr && vaultAddr !== '') return f;
    } catch { /* ignore */ }
    return null;
  };
  const writeFlags = (payout: boolean, pool: boolean) => {
    if (!walletAddress || !vaultAddr) return;
    try {
      localStorage.setItem(flagsKey, JSON.stringify({ vault: vaultAddr, payout, pool }));
    } catch { /* ignore */ }
  };
  const clearFlags = () => {
    if (!walletAddress) return;
    try { localStorage.removeItem(flagsKey); } catch { /* ignore */ }
  };

  const runChecks = React.useCallback(async (useCache: boolean) => {
    if (!account) return;
    setChecking(true);
    // 缓存快路径：两份注册都已确认 → 直接显示已注册态，不发任何链上查询/弹窗
    if (useCache) {
      const cached = readFlags();
      if (cached && cached.payout && cached.pool) {
        setReg({ payout: true, pool: true, fromCache: true });
        setStrk20Ready(true); // 缓存前提 = 此前钱包 API 可用（否则到不了已注册态）
        setChecking(false);
        return;
      }
    }
    let payout: boolean | null = null;
    let pool: boolean | null = null;
    let cancelled = false;
    // 版本先行：0.10.3 在列表里就点亮按钮（detectStrk20Support 的 V6 探测
    // 可能因 discovery 未就绪而慢一步，版本线是更快的权威信号）
    getWalletApiVersions().then((versions) => {
      if (cancelled) return;
      setWalletApiVersions(versions);
      if (versions.some((v) => compareVersions(v, STRK20_WALLET_API_MIN) >= 0)) {
        setStrk20Ready(true);
      }
    });
    await detectStrk20Support(account).then(async (ok) => {
      if (cancelled) return;
      setStrk20Ready((prev) => prev || ok);
      if (ok) {
        // 池内屏蔽余额按原生 STRK 查询（pSTRK 已弃用）
        await getShieldedBalance(account, CANONICAL_STRK_ADDRESS).then((bal) => {
          if (cancelled) return;
          // 查询成功 = 钱包在池内已注册（viewing key 可用；0 = 注册但无余额）
          if (bal !== null) pool = true;
          setShielded(bal);
        });
      }
      // 查询链上 payout commitment 注册状态（真实值，非客户端猜测）
      await getRegisteredPayoutCommitment(account).then((r) => {
        if (cancelled) return;
        payout = r !== null;
      });
      // 赔付承诺：打开弹窗时查询注册状态（已注册不发交易；未注册才可一键注册）
      try {
        const res = await ensurePayoutCommitment(account);
        if (!cancelled && res.status === 'registered') {
          payout = true;
        }
      } catch {
        if (!cancelled && payout === null) payout = false;
      }
    });
    if (!cancelled) {
      setReg({ payout: payout === true, pool: pool === true, fromCache: false });
    }
    setChecking(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [account, vaultAddr, walletAddress]);

  useEffect(() => {
    if (!isOpen || !account) return;
    setDone(null);
    setError('');
    setPoolGuideOpen(false);
    void runChecks(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen, account]);

  // 任一端完成注册后两份都齐 → 写一次性缓存（下次打开零查询）
  useEffect(() => {
    if (reg.payout === true && reg.pool === true) writeFlags(true, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reg.payout, reg.pool]);

  const reverify = () => {
    clearFlags();
    void runChecks(false);
  };

  if (!isOpen) return null;

  const chips = Math.max(0, Math.floor(chipsAmount ?? 0));
  const amountWei = BigInt(chips) * WEI_PER_CHIP;
  const strkText = (Number(amountWei) / 1e18).toFixed(4);
  const shieldedText = shielded !== null ? (Number(shielded) / 1e18).toFixed(4) : null;

  const close = () => {
    setPending(null);
    setDone(null);
    setError('');
    onClose();
  };

  const handleClaim = async (kind: 'private' | 'public') => {
    if (!account || pending) return;
    if (chips <= 0) {
      setError('无可领取筹码');
      return;
    }
    setPending(kind);
    setError('');
    const res =
      kind === 'private'
        ? await claimRewardsPrivate(account, { amountWei })
        : await claimRewardsPublic(account, { amountWei });
    setPending(null);
    if (res.success) {
      setDone({ hash: res.hash, kind });
    } else {
      setError(res.error || '领取失败');
      logger.warn('[ClaimModal] claim failed:', res.error);
    }
  };

  // 一键注册赔付承诺（我们合约的 payout commitment，一次性链上交易）
  const registerPayout = async () => {
    setRegPending(true);
    setError('');
    try {
      const res = await ensurePayoutCommitment(account);
      if (res.status === 'error') {
        setError(res.error);
      } else {
        setReg((r) => ({ ...r, payout: true }));
      }
    } catch (e) {
      setError(String((e as Error)?.message || e));
    } finally {
      setRegPending(false);
    }
  };

  // 一键注册隐私池：向池 shield 0.01 STRK，钱包在首笔 shield 时自动完成
  // viewing key 注册（金额留在池内余额，后续私密领取可全额使用）。
  // 未入池的钱包会回 118 NOT_REGISTERED——自动展开钱包内注册指引。
  const registerPool = async () => {
    setPoolRegistering(true);
    setError('');
    try {
      const res = await shieldForPoolRegistration(
        account as unknown as Parameters<typeof shieldForPoolRegistration>[0],
        10n ** 16n,
      ); // 0.01 STRK
      if (res.success) {
        await runChecks(false);
      } else {
        setError(res.error || 'Shield 提交失败');
        if (res.notRegistered) setPoolGuideOpen(true);
      }
    } catch (e) {
      const msg = String((e as Error)?.message || e);
      setError(msg);
      if (/NOT_REGISTERED/i.test(msg)) setPoolGuideOpen(true);
    } finally {
      setPoolRegistering(false);
    }
  };

  // 池 viewing key 行的整体状态色：已注册绿 / 钱包不支持红 / 其余（检测中、
  // 未注册但可一键修复）黄
  const poolOk: boolean | null =
    reg.pool === true ? true : strk20Ready === false ? false : null;

  const renderPayoutRow = () => (
    <>
      <CheckRow>
        <StatusDot $ok={reg.payout} aria-hidden />
        <CheckName>赔付承诺（我们合约）</CheckName>
        {reg.payout === true ? (
          <StatusText $ok>已注册 ✓</StatusText>
        ) : reg.payout === null ? (
          <StatusText $ok={null}>检测中…</StatusText>
        ) : (
          <Button
            type="button"
            variant="primary"
            small
            style={{ whiteSpace: 'nowrap' }}
            disabled={pending !== null || regPending || checking}
            onClick={() => void registerPayout()}
            title="提交 payout commitment（一次性链上交易，任何钱包均可）"
          >
            {regPending ? '注册中…' : '一键注册'}
          </Button>
        )}
      </CheckRow>
      {reg.payout === false && (
        <CheckDetail>注册后结算奖励才能私密领取（一次性，合约内的链上登记）</CheckDetail>
      )}
    </>
  );

  const renderPoolRow = () => (
    <>
      <CheckRow>
        <StatusDot $ok={poolOk} aria-hidden />
        <CheckName>池 viewing key（Ready 隐私系统）</CheckName>
        {reg.pool === true ? (
          <StatusText $ok>已注册 ✓</StatusText>
        ) : strk20Ready === false ? (
          <StatusText $ok={false}>钱包不支持</StatusText>
        ) : reg.pool === false ? (
          <Button
            type="button"
            variant="primary"
            small
            style={{ whiteSpace: 'nowrap' }}
            disabled={pending !== null || poolRegistering || checking}
            onClick={() => void registerPool()}
            title="向隐私池小额 Shield 0.01 STRK：钱包会依次弹出 approve 与 deposit 两次确认（非重复交易），确认后自动注册 viewing key（金额留在池内余额）"
          >
            {poolRegistering ? '注册中…' : '一键注册'}
          </Button>
        ) : (
          <StatusText $ok={null}>检测中…</StatusText>
        )}
      </CheckRow>
      {reg.pool === true ? (
        shieldedText !== null && (
          <CheckDetail>池内屏蔽余额 {shieldedText} STRK</CheckDetail>
        )
      ) : strk20Ready === false ? (
        <>
          <CheckDetail>
            需支持 STRK20 Wallet API ≥ {STRK20_WALLET_API_MIN} 的钱包（如 Ready）
          </CheckDetail>
          <CheckDetail>
            Wallet API{' '}
            {walletApiVersions === null
              ? '检测中…'
              : walletApiVersions.length
                ? walletApiVersions.join(', ')
                : '未报告（钱包不支持或版本过旧）'}
          </CheckDetail>
        </>
      ) : reg.pool === false ? (
        <CheckDetail>
          从未入池：一键注册会小额 Shield 0.01 STRK，金额留在池内余额
        </CheckDetail>
      ) : (
        <CheckDetail>池内屏蔽余额检测中…</CheckDetail>
      )}
      {reg.pool === false && strk20Ready !== false && (
        <>
          <CardLink type="button" onClick={() => setPoolGuideOpen((v) => !v)}>
            {poolGuideOpen ? '收起注册指引' : '注册指引（钱包内 Shield）'}
          </CardLink>
          {poolGuideOpen && (
            <GuideBox>
              <GuideSteps>
                <li>打开 Ready 钱包 → STRK 资产页「Shield / 入池」（隐私池入口）</li>
                <li>
                  小额 Shield 一次（如 0.01 STRK）；钱包会依次弹出 approve 与 deposit
                  两次确认（非重复交易）
                </li>
                <li>首次入池时钱包自动完成池注册——viewing key 只保存在钱包里，dapp 无法代注册</li>
                <li>回到本弹窗重新校验，本行变绿即可私密领取</li>
              </GuideSteps>
              <CardLink
                type="button"
                style={{ marginLeft: 0 }}
                onClick={reverify}
                disabled={checking}
              >
                {checking ? '校验中…' : '我已在钱包内完成 Shield，重新校验'}
              </CardLink>
            </GuideBox>
          )}
        </>
      )}
    </>
  );

  const privateBlockedReason = (() => {
    if (strk20Ready === false) return '当前钱包不支持 STRK20 私密交易（需 Wallet API ≥ 0.10.3，如 Ready）';
    if (walletApiVersions !== null && walletApiVersions.length > 0
        && !walletApiVersions.some((v) => compareVersions(v, STRK20_WALLET_API_MIN) >= 0)) {
      return `钱包 Wallet API 版本（${walletApiVersions.join(', ')}）低于 0.10.3，不支持 STRK20 私密交易——请更新 Ready`;
    }
    if (reg.pool === false) {
      return '隐私池尚未注册：点击上方「一键注册」完成池注册后再私密领取';
    }
    if (shielded !== null && shielded < amountWei) {
      return '池内屏蔽余额不足：请先在钱包内将 STRK shield 入隐私池（私密领取要求池内余额 ≥ 领取额，执行后等额退回）';
    }
    return null;
  })();

  return (
    <ModalShell
      width="md"
      role="dialog"
      ariaLabel="领取奖励"
      onBackdropClick={pending ? undefined : close}
    >
      <h2
        style={{
          margin: 0,
          fontFamily: theme.fonts.fontFamilySansSerif,
          fontSize: '1.2rem',
          fontWeight: 700,
          color: theme.colors.fontColorDark,
          textAlign: 'center',
        }}
      >
        领取奖励
      </h2>

      {/* Body 容器收紧弹窗内部间距（Shell 的 1rem gap 只作用在标题边界） */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
        {done ? (
          <>
            <SuccessRing aria-hidden>✓</SuccessRing>
            <Notice $kind="success">
              {done.kind === 'private'
                ? '私密领取已提交，奖励已进入你的池内保密票据'
                : '公开出金已提交，STRK 将直接到账钱包'}
            </Notice>
            <Text
              textAlign="center"
              style={{
                fontSize: '0.72rem',
                wordBreak: 'break-all',
                color: theme.colors.mutedText,
                fontFamily: 'monospace',
                background: 'rgba(0,0,0,0.04)',
                borderRadius: theme.radius.md,
                padding: '0.5rem 0.6rem',
              }}
            >
              tx: {done.hash}
            </Text>
            <Button
              variant="secondary"
              small
              onClick={close}
              fullWidth
              style={{ marginTop: '0.5rem' }}
            >
              关闭
            </Button>
          </>
        ) : (
          <>
            <Hero>
              <HeroLeft>
                <HeroLabel>可领取</HeroLabel>
                <HeroAmount>
                  {chips.toLocaleString('en-US')}{' '}
                  <span style={{ fontSize: '0.95rem', fontWeight: 600 }}>筹码</span>
                </HeroAmount>
                <HeroSub>≈ {strkText} STRK</HeroSub>
              </HeroLeft>
              {walletAddress && (
                <HeroAddr title={walletAddress}>
                  {walletAddress.slice(0, 6)}…{walletAddress.slice(-4)}
                </HeroAddr>
              )}
            </Hero>

            <CheckBlock aria-label="领取条件">
              <CheckHeader>
                <CheckBlockTitle>领取条件</CheckBlockTitle>
                <ReverifyLink type="button" onClick={reverify} disabled={checking}>
                  {checking ? '校验中…' : '重新校验'}
                </ReverifyLink>
              </CheckHeader>
              {renderPayoutRow()}
              {renderPoolRow()}
            </CheckBlock>

            {privateBlockedReason && <Notice $kind="warn">{privateBlockedReason}</Notice>}
            {error && <Notice $kind="error">{error}</Notice>}

            <ActionsGrid>
              <ActionCell>
                <Button
                  type="submit"
                  fullWidth
                  disabled={pending !== null || chips <= 0 || strk20Ready !== true}
                  onClick={() => void handleClaim('private')}
                  title={
                    strk20Ready
                      ? '池内两动作：烧筹码 + 产出隐藏归属的 STRK 票据'
                      : '需要 Ready 等支持 STRK20 Wallet API 的钱包'
                  }
                >
                  {pending === 'private' ? '提交中…' : '私密领取'}
                </Button>
                <ActionNote>归属隐藏：奖励记入只有你能扫描的池内票据</ActionNote>
              </ActionCell>
              <ActionCell>
                <Button
                  variant="secondary"
                  type="button"
                  fullWidth
                  disabled={pending !== null || chips <= 0}
                  onClick={() => void handleClaim('public')}
                  title="vault.withdraw 直提钱包地址（链上边缘公开）"
                >
                  {pending === 'public' ? '提交中…' : '公开出金'}
                </Button>
                <ActionNote>直接到钱包地址，链上任何人可查</ActionNote>
              </ActionCell>
            </ActionsGrid>
          </>
        )}
      </div>
    </ModalShell>
  );
};

export default ClaimModal;
