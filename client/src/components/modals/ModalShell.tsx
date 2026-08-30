import React from 'react';
import styled, { css } from 'styled-components';

export interface ModalShellProps {
  /** 模态内容（React 节点） */
  children: React.ReactNode;
  /** 模态宽度：sm=320px, md=480px, lg=560px，或自定义 CSS 字符串 */
  width?: 'sm' | 'md' | 'lg' | string;
  /** 关闭回调（点击遮罩时触发，可选） */
  onBackdropClick?: () => void;
  /**
   * 是否在 mobile（< 480px）占用全屏。默认 true。
   * 注意:此 prop **不影响桌面宽度** — 桌面下弹窗始终按 `width` 渲染。
   */
  fullScreenOnMobile?: boolean;
  /** ARIA 角色，默认 dialog */
  role?: 'dialog' | 'alertdialog';
  ariaLabel?: string;
  ariaLabelledBy?: string;
  className?: string;
}

const Backdrop = styled.div`
  position: fixed;
  inset: 0;
  z-index: ${({ theme }) => theme.zIndex.modal};
  background-color: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 1rem;
  /* Prevent scroll chaining when modal scroll hits boundary */
  overscroll-behavior: contain;
`;

/**
 * Shell design:
 * - On viewports >= 480px (desktop / tablet landscape / large phone
 *   landscape), the modal always uses the caller-supplied $width. No
 *   full-screen override is applied, regardless of $fullScreen.
 * - On viewports < 480px (small phone portrait), if $fullScreen is
 *   true the modal goes full-bleed (100% of the available space inside
 *   the backdrop's 1rem padding). Otherwise the $width still applies,
 *   but capped at 100% so it never overflows the viewport.
 *
 * This is the fix for the regression where `$fullScreen=true` on
 * desktop made the dialog 100% wide — see the comment in the styled
 * template below.
 */
const Shell = styled.div<{ $width: string; $fullScreen: boolean }>`
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 1rem;
  /* Desktop / larger viewports: use the caller-supplied width as both
     the width and the max-width floor. $fullScreen is intentionally
     IGNORED here so the desktop dialog stays compact. */
  width: ${({ $width }) => $width};
  max-width: ${({ $width }) => $width};
  max-height: calc(100dvh - 2rem);
  padding: 1.5rem 1.25rem;
  background: ${({ theme }) => theme.colors.surfaceGlass};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.xl};
  box-shadow: ${({ theme }) => theme.other.cardDropShadow};
  overflow-y: auto;
  overscroll-behavior: contain;

  @media screen and (max-width: 479px) {
    ${({ $fullScreen, $width }) =>
      $fullScreen
        ? css`
            width: 100%;
            max-width: 100%;
            max-height: 100dvh;
            border-radius: 0;
            padding: 1.25rem 1rem;
          `
        : css`
            /* Don't overflow the small viewport: cap at 100% of the
               backdrop's content area (which has 1rem padding on each
               side). */
            max-width: min(${$width}, 100%);
          `}
  }
`;

const SIZE_MAP: Record<string, string> = {
  sm: '320px',
  md: '480px',
  lg: '560px',
};

/**
 * 统一模态容器
 * 替代 Modal.tsx 与 LoginModal.tsx 中重复的 ModalWrapper + StyledModal 容器。
 * 提供遮罩点击、ARIA、可访问的 max-height、safe-area 等行为。
 */
const ModalShell: React.FC<ModalShellProps> = ({
  children,
  width = 'md',
  onBackdropClick,
  fullScreenOnMobile = true,
  role = 'dialog',
  ariaLabel,
  ariaLabelledBy,
  className,
}) => {
  const resolvedWidth = SIZE_MAP[width] ?? width;
  return (
    <Backdrop
      onClick={(e) => {
        if (e.target === e.currentTarget && onBackdropClick) {
          onBackdropClick();
        }
      }}
    >
      <Shell
        $width={resolvedWidth}
        $fullScreen={fullScreenOnMobile}
        role={role}
        aria-modal="true"
        aria-label={ariaLabel}
        aria-labelledby={ariaLabelledBy}
        className={className}
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </Shell>
    </Backdrop>
  );
};

export default ModalShell;
