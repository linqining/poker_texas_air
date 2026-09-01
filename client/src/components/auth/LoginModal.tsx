import React, { useContext, useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import styled from 'styled-components';
import { useAccount, useConnect, useDisconnect } from '@starknet-react/core';
import { activeAddress } from '../../starknet/devAccount';
import authContext from '../../context/auth/authContext';
import contentContext from '../../context/content/contentContext';
import CloseButton from '../buttons/CloseButton';
import ModalShell from '../modals/ModalShell';
import strkLogoSvg from '/strk-logo.svg';

const IconWrapper = styled.div`
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;
  z-index: 1;
`;

const ModalContent = styled.div`
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  gap: 0.875rem;
`;

const ModalHeading = styled.h2`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 1.2rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDark};
  letter-spacing: -0.02em;
  margin: 0;
`;

const LoginSection = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  width: 100%;
`;

const WalletButton = styled.button`
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  width: 100%;
  padding: 0.65rem 0.875rem;
  border-radius: ${({ theme }) => theme.radius.md};
  border: 1px solid #d1d5db;
  background: ${({ theme }) => theme.colors.lightestBg};
  font-size: 0.95rem;
  font-weight: 600;
  color: #1f2937;
  cursor: pointer;
  transition:
    background-color 0.2s ease,
    border-color 0.2s ease,
    transform 0.1s ease;
  min-height: 44px;

  &:hover {
    background: ${({ theme }) => theme.colors.lightBg};
    border-color: #94a3b8;
  }

  &:active {
    transform: scale(0.98);
  }

  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .login-btn-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
`;

const StrkLogo = styled.img`
  width: 18px;
  height: 18px;
  display: block;
  flex-shrink: 0;
`;

const Note = styled.div`
  font-size: 0.72rem;
  color: #94a3b8;
  text-align: center;
  margin-top: 0.25rem;
  line-height: 1.4;
`;

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose }) => {
  const isLoggedIn = useContext(authContext)!.isLoggedIn;
  const { getLocalizedString: t } = useContext(contentContext)!;
  const connected = useAccount();
  // 连接的钱包（Ready/Cartridge）优先，dev 直签账户仅作无钱包时兜底
  const address = activeAddress(connected.address);
  const { connect, connectors, connectAsync, isPending, error } = useConnect();
  const { disconnect } = useDisconnect();

  // 只渲染已安装的注入钱包（Ready 未安装时两个注入 id 都探不到 → 不显示
  // 死按钮；Cartridge 为内嵌 connector，恒可用）。
  // 登录只保留注入钱包（Ready）。Cartridge 不再作为登录选项——它在买入
  // 成功后由应用自动初始化（游戏交互签名），不承担登录/买入/swap/领取。
  const [availableConnectors, setAvailableConnectors] = useState(connectors);
  useEffect(() => {
    let cancelled = false;
    Promise.all(
      connectors.map(async (connector) => ({
        connector,
        available:
          /argentX|^ready$/i.test(connector.id) &&
          (await Promise.resolve(connector.available()).catch(() => false)),
      })),
    ).then((results) => {
      if (!cancelled) setAvailableConnectors(results.filter((r) => r.available).map((r) => r.connector));
    });
    return () => {
      cancelled = true;
    };
  }, [connectors]);

  useEffect(() => {
    if (isOpen && isLoggedIn) {
      onClose();
    }
  }, [isOpen, isLoggedIn, onClose]);

  // If a wallet is already connected but we're not logged in, the auth flow
  // will trigger automatically via useAuth. We close the modal in that case.
  // 注意：只按"真实连接的钱包地址"判断 —— dev 直签账户（VITE_DEV_ACCOUNT_*）
  // 的 address 恒非空，不能拿来关弹窗（否则弹窗一打开就闪退）。
  useEffect(() => {
    if (isOpen && connected.address) {
      onClose();
    }
  }, [isOpen, connected.address, onClose]);

  const handleConnect = async (connector: (typeof connectors)[number]) => {
    try {
      // 显式选择钱包 = 用户登录意图，解除登出压制（否则自动登录被跳过）
      sessionStorage.removeItem('poker.loggedOut');
      await connectAsync({ connector });
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[LoginModal] Starknet wallet connect failed:', e);
    }
  };

  if (!isOpen) return null;

  return ReactDOM.createPortal(
    <ModalShell
      width="360px"
      onBackdropClick={onClose}
      ariaLabel={t('login_sign-in')}
    >
      <IconWrapper>
        <CloseButton clickHandler={onClose} ariaLabel="Close login modal" />
      </IconWrapper>
      <ModalContent>
        <ModalHeading>{t('login_sign-in')}</ModalHeading>

        <LoginSection>
          {availableConnectors.map((connector) => (
            <WalletButton
              key={connector.id}
              type="button"
              onClick={() => handleConnect(connector)}
              disabled={isPending}
              aria-label={`${t('login_wallet-title')} (${connector.name ?? connector.id})`}
            >
              <span className="login-btn-icon">
                <StrkLogo src={strkLogoSvg} alt="STRK" />
              </span>
              <span>
                {connector.name ?? connector.id}
                {/* Ready 是首选钱包（登录/买入/swap/私密领取均扣 Ready 余额） */}
                {/argentX|^ready$/i.test(connector.id) && '（推荐）'}
              </span>
            </WalletButton>
          ))}

          {address && (
            <WalletButton type="button" onClick={() => disconnect()}>
              <span>{t('login_disconnect')}</span>
            </WalletButton>
          )}
        </LoginSection>

        {error && <Note>{error.message}</Note>}
        <Note>{t('login_wallet-note')}</Note>
      </ModalContent>
    </ModalShell>,
    document.getElementById('modal') as HTMLElement,
  );
};

export default LoginModal;