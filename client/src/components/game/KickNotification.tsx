import React, { useEffect } from 'react';
import styled from 'styled-components';
import { KICK_NOTIFICATION_DISMISS_MS } from '../../clientConfig';

interface KickNotificationProps {
  kickNotification: string | null;
  clearKickNotification: () => void;
}

const Notification = styled.div`
  position: fixed;
  top: 1.5rem;
  left: 50%;
  transform: translateX(-50%);
  background: ${({ theme }) => theme.colors.dangerAlpha95};
  color: #fff;
  padding: 0.8rem 1.5rem;
  border-radius: 10px;
  font-size: 0.95rem;
  font-weight: 600;
  z-index: ${({ theme }) => theme.zIndex.toast};
  cursor: pointer;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
  max-width: 90vw;
  text-align: center;
`;

export const KickNotification: React.FC<KickNotificationProps> = ({
  kickNotification,
  clearKickNotification,
}) => {
  // Auto-dismiss kick notification after 5 seconds
  useEffect(() => {
    if (kickNotification) {
      const timer = setTimeout(() => {
        clearKickNotification();
      }, KICK_NOTIFICATION_DISMISS_MS);
      return () => clearTimeout(timer);
    }
  }, [kickNotification, clearKickNotification]);

  if (!kickNotification) return null;

  return <Notification onClick={clearKickNotification}>{kickNotification}</Notification>;
};
