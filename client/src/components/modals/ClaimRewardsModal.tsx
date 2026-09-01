// 私密领取奖励弹窗（SETTLEMENT_PRIVACY_PLAN.md Part C3）。
//
// 赢家筹码在 PokerVault 上，「领取」把筹码换成 STRK：
// - 私密领取（首选）：Ready 等 STRK20 钱包的两动作模式 —— 池内 burn
//   等额屏蔽 STRK + helper 烧毁 vault 筹码，产出 owner 隐藏的 open
//   note。链上只有池 envelope，看不出谁领了奖励。
// - 公开出金（回退）：vault.withdraw 直提钱包（边缘公开）。
// 私密路径需要：钱包支持 STRK20 Wallet API（capability 探测）且池内
// 屏蔽余额 ≥ 领取额（守恒在池内闭环）。
import React, { useContext, useEffect, useState } from 'react';
import styled, { useTheme } from 'styled-components';
import { useAccount } from '@starknet-react/core';
import ModalShell from './ModalShell';
import { Form } from '../forms/Form';
import { FormGroup } from '../forms/FormGroup';
import { ButtonGroup } from '../forms/ButtonGroup';
import Text from '../typography/Text';
import Button from '../buttons/Button';
import authContext from '../../context/auth/authContext';
import { WEI_PER_CHIP, starknetConfig } from '../../starknet/config';
import {
  claimRewardsPrivate,
  claimRewardsPublic,
  detectStrk20Support,
  ensurePayoutCommitment,
  getShieldedBalance,
} from '../../starknet/strk20';
import { activeAccount } from '../../starknet/devAccount';
import { logger } from '../../helpers/logger';

interface ClaimRewardsModalProps {
  isOpen: boolean;
  /** vault 可领筹码（服务端 chips 单位，1 chip = 1e14 wei）。 */
  chipsAmount: number | null;
  onClose: () => void;
}

const InfoRow = styled.div.withConfig({ displayName: 'InfoRow' })`
  display: flex;
  justify-content: space-between;
  margin-bottom: 0.5rem;
  font-size: 0.9rem;
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

const ClaimModal: React.FC<ClaimRewardsModalProps> = ({ isOpen, chipsAmount, onClose }) => {
  const theme = useTheme();
  const { walletAddress } = useContext(authContext)!;
  const connected = useAccount();
  // 连接的钱包（Ready/Cartridge）优先，dev 直签兜底
  const account = activeAccount(connected.account);

  const [strk20Ready, setStrk20Ready] = useState<boolean | null>(null);
  const [commitRegistered, setCommitRegistered] = useState<boolean | null>(null);
  const [regPending, setRegPending] = useState(false);
  const [shielded, setShielded] = useState<bigint | null>(null);
  const [pending, setPending] = useState<'private' | 'public' | null>(null);
  const [done, setDone] = useState<{ hash: string; kind: 'private' | 'public' } | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isOpen || !account) return;
    let cancelled = false;
    detectStrk20Support(account).then(async (ok) => {
      if (cancelled) return;
      setStrk20Ready(ok);
      if (ok && starknetConfig.strk20Address) {
        getShieldedBalance(account, starknetConfig.strk20Address).then((bal) => {
          if (!cancelled) setShielded(bal);
        });
      }
      // 赔付承诺：已注册则标记；未注册时弹窗内提供一键注册
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
      <div style={{ margin: '1rem 0' }}>
        <InfoRow>
          <span>钱包</span>
          <strong>{walletAddress ? `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}` : '-'}</strong>
        </InfoRow>
        <InfoRow>
          <span>可领筹码</span>
          <strong>{chips}</strong>
        </InfoRow>
        {shielded !== null && (
          <InfoRow>
            <span>池内屏蔽余额（私密领取所需）</span>
            <strong>{(Number(shielded) / 1e18).toFixed(4)} STRK</strong>
          </InfoRow>
        )}
        <InfoRow>
          <span>私密路径（STRK20）</span>
          <strong>{strk20Ready === null ? '检测中…' : strk20Ready ? '可用 ✓' : '不可用'}</strong>
        </InfoRow>
        <InfoRow>
          <span>赔付承诺（注册后结算奖励可私密领取）</span>
          <strong>{commitRegistered === null ? '检测中…' : commitRegistered ? '已注册 ✓' : '未注册'}</strong>
        </InfoRow>
      </div>
      {done ? (
        <>
          <Text textAlign="center" style={{ color: '#16a34a' }}>
            {done.kind === 'private' ? '私密领取已提交 ✓ 奖励已进入你的池内保密票据' : '公开出金已提交 ✓'}
          </Text>
          <Text
            textAlign="center"
            style={{ fontSize: '0.75rem', wordBreak: 'break-all', color: theme.colors.mutedText }}
          >
            tx: {done.hash}
          </Text>
          <ButtonGroup>
            <Button variant="secondary" small onClick={close} fullWidth>
              关闭
            </Button>
          </ButtonGroup>
        </>
      ) : (
        <Form
          onSubmit={(e) => {
            e.preventDefault();
            void handleClaim('private');
          }}
        >
          {privateBlockedReason && (
            <Text textAlign="center" style={{ fontSize: '0.8rem', color: '#b45309' }}>
              {privateBlockedReason}
            </Text>
          )}
          {error && (
            <Text textAlign="center" style={{ fontSize: '0.8rem', color: '#ef4444', wordBreak: 'break-all' }}>
              {error}
            </Text>
          )}
          <FormGroup>
            <ButtonGroup>
              <Button
                type="button"
                small
                disabled={pending !== null || commitRegistered === true}
                onClick={async () => {
                  setRegPending(true);
                  try {
                    const res = await ensurePayoutCommitment(account);
                    if (res.status === 'error') {
                      setError(res.error);
                    } else {
                      setCommitRegistered(true);
                    }
                  } finally {
                    setRegPending(false);
                  }
                }}
                title="提交 payout commitment（一次性链上交易，任何钱包均可）"
              >
                {commitRegistered ? '已注册 ✓' : regPending ? '注册中…' : '注册赔付承诺'}
              </Button>
              <Button
                type="submit"
                small
                disabled={pending !== null || chips <= 0 || strk20Ready !== true}
                title={
                  strk20Ready
                    ? '池内两动作：烧筹码 + 产出隐藏归属的 STRK 票据'
                    : '需要 Ready 等支持 STRK20 Wallet API 的钱包'
                }
              >
                {pending === 'private' ? '提交中…' : '私密领取（推荐）'}
              </Button>
              <Button
                variant="secondary"
                small
                type="button"
                disabled={pending !== null || chips <= 0}
                onClick={() => void handleClaim('public')}
                title="vault.withdraw 直提钱包地址（链上边缘公开）"
              >
                {pending === 'public' ? '提交中…' : '公开出金'}
              </Button>
            </ButtonGroup>
          </FormGroup>
          <Text textAlign="center" style={{ fontSize: '0.72rem', color: theme.colors.mutedText }}>
            私密领取把奖励记入只有你能扫描的池内票据（金额公开、归属隐藏）；
            公开出金则把 STRK 直接到钱包地址，任何人可查。
          </Text>
        </Form>
      )}
    </ModalShell>
  );
};

export default ClaimModal;
