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
// UI（P1-3 重设计）：金额主卡 + 路径状态卡 + 单一主行动按钮；
// 技术细节（Wallet API 版本等）降级为卡片内的次级行。
import React, { useContext, useEffect, useState } from 'react';
import styled, { useTheme } from 'styled-components';
import { useAccount } from '@starknet-react/core';
import ModalShell from './ModalShell';
import Text from '../typography/Text';
import Button from '../buttons/Button';
import authContext from '../../context/auth/authContext';
import { WEI_PER_CHIP } from '../../starknet/config';
import {
  claimRewardsPrivate,
  claimRewardsPublic,
  detectStrk20Support,
  ensurePayoutCommitment,
  getRegisteredPayoutCommitment,
  getShieldedBalance,
  getWalletApiVersions,
  STRK20_WALLET_API_MIN,
  compareVersions,
} from '../../starknet/strk20';
import { activeAccount } from '../../starknet/devAccount';
import { CANONICAL_STRK_ADDRESS } from '../../starknet/starknetGameActions';
import { logger } from '../../helpers/logger';

interface ClaimRewardsModalProps {
  isOpen: boolean;
  /** vault 可领筹码（服务端 chips 单位，1 chip = 1e14 wei）。 */
  chipsAmount: number | null;
  onClose: () => void;
}

// ===== 样式 =====

/** 金额主卡：靛蓝渐变，金额是整个弹窗的视觉焦点 */
const HeroCard = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.2rem;
  padding: 1.1rem 1rem 0.9rem;
  border-radius: ${({ theme }) => theme.radius.lg};
  background: linear-gradient(135deg, ${({ theme }) => theme.colors.primaryCta} 0%, ${({ theme }) => theme.colors.primaryCtaDarker} 100%);
  color: #fff;
  box-shadow: 0 8px 24px rgba(79, 70, 229, 0.35);
`;

const HeroLabel = styled.span`
  font-size: 0.75rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  opacity: 0.85;
`;

const HeroAmount = styled.span`
  font-size: 2rem;
  font-weight: 800;
  line-height: 1.15;
  font-variant-numeric: tabular-nums;
`;

const HeroSub = styled.span`
  font-size: 0.78rem;
  opacity: 0.85;
  font-variant-numeric: tabular-nums;
`;

/** 路径状态卡：左侧状态点 + 标题行 + 次级信息行 */
const PathCard = styled.div<{ $ok: boolean | null }>`
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
  padding: 0.7rem 0.85rem;
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.md};
  background: ${({ theme }) => theme.colors.successAlpha06};
`;

const PathHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
`;

const PathTitle = styled.span`
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  font-size: 0.9rem;
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
  font-size: 0.8rem;
  font-weight: 600;
  color: ${({ $ok, theme }) =>
    $ok === null ? theme.colors.warningDark : $ok ? theme.colors.successStrong : theme.colors.danger};
`;

const PathDetail = styled.span`
  font-size: 0.72rem;
  color: ${({ theme }) => theme.colors.mutedText};
  padding-left: 1rem;
`;

/** 警告 / 错误条 */
const Notice = styled(Text)<{ $kind: 'warn' | 'error' | 'success' }>`
  text-align: center;
  font-size: 0.8rem;
  padding: 0.55rem 0.7rem;
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

const FooterNote = styled(Text)`
  text-align: center;
  font-size: 0.72rem;
  line-height: 1.5;
  color: ${({ theme }) => theme.colors.mutedText};
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
  const [commitRegistered, setCommitRegistered] = useState<boolean | null>(null);
  const [regPending, setRegPending] = useState(false);
  const [shielded, setShielded] = useState<bigint | null>(null);
  const [pending, setPending] = useState<'private' | 'public' | null>(null);
  const [done, setDone] = useState<{ hash: string; kind: 'private' | 'public' } | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isOpen || !account) return;
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
    detectStrk20Support(account).then(async (ok) => {
      if (cancelled) return;
      setStrk20Ready((prev) => prev || ok);
      if (ok) {
        // 池内屏蔽余额按原生 STRK 查询（pSTRK 已弃用）
        getShieldedBalance(account, CANONICAL_STRK_ADDRESS).then((bal) => {
          if (!cancelled) setShielded(bal);
        });
      }
      // 查询链上 payout commitment 注册状态（真实值，非客户端猜测）
      getRegisteredPayoutCommitment(account).then((reg) => {
        if (!cancelled) setCommitRegistered(reg !== null);
      });
      // 赔付承诺：打开弹窗时查询注册状态（已注册不发交易；未注册才可一键注册）
      try {
        const res = await ensurePayoutCommitment(account);
        if (!cancelled && res.status === 'registered') setCommitRegistered(true);
      } catch {
        if (!cancelled) setCommitRegistered(false);
      }
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen, account]);

  if (!isOpen) return null;

  const chips = Math.max(0, Math.floor(chipsAmount ?? 0));
  const amountWei = BigInt(chips) * WEI_PER_CHIP;
  const chipsText = chips.toLocaleString('en-US');
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

  const privateBlockedReason = (() => {
    if (strk20Ready === false) return '当前钱包不支持 STRK20 私密交易（需 Wallet API ≥ 0.10.3，如 Ready）';
    if (walletApiVersions !== null && walletApiVersions.length > 0
        && !walletApiVersions.some((v) => compareVersions(v, STRK20_WALLET_API_MIN) >= 0)) {
      return `钱包 Wallet API 版本（${walletApiVersions.join(', ')}）低于 0.10.3，不支持 STRK20 私密交易——请更新 Ready`;
    }
    if (shielded !== null && shielded < amountWei) {
      return '池内屏蔽余额不足：请先在钱包内将 STRK shield 入隐私池（私密领取要求池内余额 ≥ 领取额，执行后等额退回）';
    }
    return null;
  })();

  return (
    <ModalShell
      width="sm"
      role="dialog"
      ariaLabel="领取奖励"
      onBackdropClick={pending ? undefined : close}
    >
      <h2
        style={{
          margin: 0,
          fontFamily: theme.fonts.fontFamilySansSerif,
          fontSize: '1.4rem',
          fontWeight: 700,
          color: theme.colors.fontColorDark,
          textAlign: 'center',
        }}
      >
        领取奖励
      </h2>

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
          <HeroCard>
            <HeroLabel>可领取</HeroLabel>
            <HeroAmount>{chipsText} <span style={{ fontSize: '1rem', fontWeight: 600 }}>筹码</span></HeroAmount>
            <HeroSub>≈ {strkText} STRK</HeroSub>
            {walletAddress && (
              <HeroSub style={{ opacity: 0.7, fontFamily: 'monospace' }}>
                {walletAddress.slice(0, 6)}…{walletAddress.slice(-4)}
              </HeroSub>
            )}
          </HeroCard>

          <PathCard $ok={strk20Ready}>
            <PathHeader>
              <PathTitle>
                <StatusDot $ok={strk20Ready} />
                私密领取（推荐）
              </PathTitle>
              <StatusText $ok={strk20Ready}>
                {strk20Ready === null ? '检测中…' : strk20Ready ? '可用 ✓' : '不可用'}
              </StatusText>
            </PathHeader>
            <PathDetail>
              {shieldedText !== null
                ? `池内屏蔽余额 ${shieldedText} STRK`
                : '池内屏蔽余额检测中…'}
            </PathDetail>
            <PathDetail>
              Wallet API{' '}
              {walletApiVersions === null
                ? '检测中…'
                : walletApiVersions.length
                  ? walletApiVersions.join(', ')
                  : '未报告（钱包不支持或版本过旧）'}
              {' '}· 需 ≥ {STRK20_WALLET_API_MIN}
            </PathDetail>
          </PathCard>

          <PathCard $ok={commitRegistered}>
            <PathHeader>
              <PathTitle>
                <StatusDot $ok={commitRegistered} />
                赔付承诺
              </PathTitle>
              {commitRegistered ? (
                <StatusText $ok>已注册 ✓</StatusText>
              ) : (
                <Button
                  type="button"
                  small
                  disabled={pending !== null || regPending}
                  onClick={async () => {
                    setRegPending(true);
                    try {
                      const res = await ensurePayoutCommitment(account);
                      if (res.status === 'error') {
                        setError(res.error);
                      } else {
                        setCommitRegistered(true);
                      }
                    } catch (e) {
                      // 注册交易被拒/钱包锁定等：不再作为 uncaught rejection 逃逸
                      setError(String((e as Error)?.message || e));
                    } finally {
                      setRegPending(false);
                    }
                  }}
                  title="提交 payout commitment（一次性链上交易，任何钱包均可）"
                >
                  {regPending ? '注册中…' : '一键注册'}
                </Button>
              )}
            </PathHeader>
            <PathDetail>注册后结算奖励才能私密领取（一次性）</PathDetail>
          </PathCard>

          {privateBlockedReason && <Notice $kind="warn">{privateBlockedReason}</Notice>}
          {error && <Notice $kind="error">{error}</Notice>}

          <Button
            type="submit"
            disabled={pending !== null || chips <= 0 || strk20Ready !== true}
            fullWidth
            onClick={() => void handleClaim('private')}
            title={
              strk20Ready
                ? '池内两动作：烧筹码 + 产出隐藏归属的 STRK 票据'
                : '需要 Ready 等支持 STRK20 Wallet API 的钱包'
            }
          >
            {pending === 'private' ? '提交中…' : `私密领取 ${chipsText} 筹码`}
          </Button>

          <Button
            variant="secondary"
            small
            type="button"
            disabled={pending !== null || chips <= 0}
            onClick={() => void handleClaim('public')}
            title="vault.withdraw 直提钱包地址（链上边缘公开）"
            fullWidth
          >
            {pending === 'public' ? '提交中…' : '公开出金（直接到钱包，链上可见）'}
          </Button>

          <FooterNote>
            私密领取把奖励记入只有你能扫描的池内票据（金额公开、归属隐藏）；
            公开出金则把 STRK 直接到钱包地址，任何人可查。
          </FooterNote>
        </>
      )}
    </ModalShell>
  );
};

export default ClaimModal;
