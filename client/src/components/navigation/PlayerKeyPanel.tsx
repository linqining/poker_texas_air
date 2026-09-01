// 牌桌身份密钥面板（SETTLEMENT_PRIVACY_PLAN.md Part B / B1.5）。
//
// 展示当前密钥模式与 pk 前缀，提供两种身份来源切换：
// - 口令派生（可恢复）：同一口令在任何设备派生出同一 pk；口令即备份，
//   忘记口令 = 身份永久丢失。禁止使用钱包助记词/恢复短语作为口令。
// - 随机密钥（默认）：CSPRNG 生成，与钱包零派生关系，无跨设备恢复。
//
// 切换身份会使当前座位的 reveal/fold 义务失效（服务器按已有超时/踢出
// 路径降级），建议在牌局间歇操作——面板常驻提示这一点。
import React, { useContext, useState } from 'react';
import styled from 'styled-components';
import { useTheme } from 'styled-components';
import Text from '../typography/Text';
import Button from '../buttons/Button';
import { Input } from '../forms/Input';
import authContext from '../../context/auth/authContext';
import { PlayerContext as playerContext } from '../../context/player/PlayerContext';
import { logger } from '../../helpers/logger';

const Panel = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding: 0.75rem;
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: 8px;
  margin: 0.5rem 0;
`;

const ModeTag = styled.span<{ $mode: string }>`
  font-size: 0.72rem;
  font-weight: 600;
  padding: 0.1rem 0.5rem;
  border-radius: 999px;
  font-family: 'JetBrains Mono', monospace;
  color: #fff;
  background: ${({ $mode }) =>
    $mode === 'passphrase' ? '#16a34a' : $mode === 'random' ? '#4da2ff' : '#94a3b8'};
`;

const MODE_LABEL: Record<string, string> = {
  random: '随机密钥',
  passphrase: '口令派生',
  legacy: '旧版钱包派生',
};

const PlayerKeyPanel: React.FC = () => {
  const theme = useTheme();
  const { isLoggedIn } = useContext(authContext)!;
  const { pkHex, keyMode, switchToPassphraseKey, switchToRandomKey } = useContext(playerContext)!;
  const [pass, setPass] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  if (!isLoggedIn) return null;

  const handleSwitch = (kind: 'passphrase' | 'random') => {
    setBusy(true);
    setMsg(null);
    try {
      const res =
        kind === 'passphrase' ? switchToPassphraseKey(pass) : switchToRandomKey();
      if (res.ok) {
        setPass('');
        setMsg({
          ok: true,
          text:
            kind === 'passphrase'
              ? '身份已切换为口令派生：请牢记口令，凭它可在任何设备恢复本身份'
              : '身份已切换为随机密钥（无跨设备恢复）',
        });
      } else {
        setMsg({ ok: false, text: res.error || '切换失败' });
      }
    } catch (e) {
      logger.error('[PlayerKeyPanel] switch failed:', e);
      setMsg({ ok: false, text: '切换失败（见控制台）' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <Text style={{ fontWeight: 700, margin: 0 }}>牌桌身份密钥</Text>
        {keyMode && <ModeTag $mode={keyMode}>{MODE_LABEL[keyMode] ?? keyMode}</ModeTag>}
      </div>
      <Text style={{ fontSize: '0.72rem', margin: 0, wordBreak: 'break-all' }}>
        当前 pk：{pkHex ? `${pkHex.slice(0, 18)}…` : '未生成'}
      </Text>
      <Input
        type="password"
        placeholder="恢复口令（≥8 字符；勿用钱包助记词）"
        value={pass}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPass(e.target.value)}
        disabled={busy}
      />
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <Button
          small
          primary
          type="button"
          disabled={busy || pass.length < 8}
          onClick={() => handleSwitch('passphrase')}
          title="同一口令在任何设备派生同一身份；忘记口令无法找回"
        >
          用口令生成/恢复
        </Button>
        <Button
          small
          variant="secondary"
          type="button"
          disabled={busy}
          onClick={() => handleSwitch('random')}
          title="生成全新随机身份（放弃口令可恢复性）"
        >
          换随机密钥
        </Button>
      </div>
      {msg && (
        <Text
          style={{
            fontSize: '0.72rem',
            margin: 0,
            color: msg.ok ? '#16a34a' : '#ef4444',
            wordBreak: 'break-word',
          }}
        >
          {msg.text}
        </Text>
      )}
      <Text style={{ fontSize: '0.68rem', margin: 0, color: theme.colors.mutedText }}>
        牌局进行中切换身份会使当前座位的义务失效（走超时/踢出降级），建议牌局间歇操作。
      </Text>
    </Panel>
  );
};

export default PlayerKeyPanel;
