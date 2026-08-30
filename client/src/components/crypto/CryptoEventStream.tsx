import type { CryptoEvent, CryptoEventType } from '../../types/game'
import { Shuffle, RefreshCw, Eye, LogOut, RefreshCcw } from 'lucide-react'
import { useContentContext } from '../../context/content/contentContext'
import { OnchainVerificationBadge } from './OnchainVerificationBadge'

interface CryptoEventStreamProps {
  events: CryptoEvent[]
  onSelect?: (event: CryptoEvent) => void
  selectedTimestamp?: number // 高亮选中项
  /** 紧凑模式：适配主牌桌侧边/底部布局，单行更小行高，仅展示最近 N 条 */
  compact?: boolean
  /** 紧凑模式下展示的最大条数，默认 6 */
  compactMaxItems?: number
}

// 事件类型 → 图标映射（lucide-react）
const EVENT_ICON: Record<CryptoEventType, typeof Shuffle> = {
  shuffle: Shuffle,
  remask: RefreshCw,
  reveal_token: Eye,
  leave: LogOut,
  reconstruct: RefreshCcw,
}

// 截断玩家 pk：前 6 + 后 4 字符，如 0xab12…cd34
function truncatePk(pk: string): string {
  if (!pk) return ''
  if (pk.length <= 10) return pk
  return `${pk.slice(0, 6)}…${pk.slice(-4)}`
}

export default function CryptoEventStream({
  events,
  onSelect,
  selectedTimestamp,
}: CryptoEventStreamProps) {
  const { getLocalizedString: t } = useContentContext()
  // 最新事件在顶部：倒序展示
  const sorted = [...events].reverse()

  return (
    <div
      style={{
        maxHeight: '100%',
        overflowY: 'auto',
        background: 'rgba(248,250,252,0.6)',
        borderRadius: 8,
        padding: '0.5rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.4rem',
        fontFamily: "'JetBrains Mono', monospace",
      }}
    >
      {sorted.length === 0 ? (
        // 空状态
        <div
          style={{
            color: '#94a3b8',
            fontStyle: 'italic',
            textAlign: 'center',
            padding: '1.5rem 0',
            fontSize: '0.85rem',
          }}
        >
          {t('crypto_waiting-events')}
        </div>
      ) : (
        sorted.map((ev, i) => {
          const Icon = EVENT_ICON[ev.event_type] ?? Shuffle
          const isSelected =
            selectedTimestamp !== undefined && selectedTimestamp === ev.timestamp
          return (
            <div
              key={`${ev.timestamp}-${i}`}
              onClick={() => onSelect?.(ev)}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '0.6rem',
                background: '#ffffff',
                borderRadius: 8,
                padding: '0.55rem 0.7rem',
                cursor: onSelect ? 'pointer' : 'default',
                // 选中项加蓝色左边框高亮
                borderLeft: isSelected
                  ? '3px solid #3b82f6'
                  : '3px solid transparent',
                boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
                transition: 'background 0.15s ease',
              }}
            >
              {/* 左侧图标 */}
              <div
                style={{
                  flexShrink: 0,
                  width: 28,
                  height: 28,
                  borderRadius: 6,
                  background: 'rgba(59,130,246,0.1)',
                  color: '#3b82f6',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <Icon size={16} />
              </div>

              {/* 中间内容 */}
              <div
                style={{
                  flex: 1,
                  minWidth: 0,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.15rem',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    flexWrap: 'wrap',
                  }}
                >
                  {/* 事件类型标签（大写） */}
                  <span
                    style={{
                      fontWeight: 700,
                      fontSize: '0.78rem',
                      color: '#0f172a',
                      letterSpacing: '0.04em',
                    }}
                  >
                    {ev.event_type.toUpperCase()}
                  </span>
                  {/* 玩家 pk 截断显示 */}
                  <span style={{ fontSize: '0.72rem', color: '#64748b' }}>
                    {truncatePk(ev.player_pk)}
                  </span>
                  {/* 卡片索引 */}
                  {ev.card_index !== null && ev.card_index !== undefined && (
                    <span
                      style={{
                        fontSize: '0.72rem',
                        color: '#3b82f6',
                        fontWeight: 600,
                      }}
                    >
                      #{ev.card_index}
                    </span>
                  )}
                  {/* 验证状态 */}
                  <span
                    style={{
                      fontSize: '0.7rem',
                      fontWeight: 600,
                      color: ev.verified ? '#10b981' : '#ef4444',
                    }}
                  >
                    {ev.verified ? t('crypto_verified') : t('crypto_failed')}
                  </span>
                  {/* 链上交易 digest：点击跳转区块浏览器 */}
                  {ev.tx_digest && (
                    <span
                      onClick={(e) => e.stopPropagation()}
                      style={{ display: 'inline-flex' }}
                    >
                      <OnchainVerificationBadge
                        txDigest={ev.tx_digest}
                        verified={ev.verified}
                        compact
                      />
                    </span>
                  )}
                </div>
                {/* 消息（一行小字） */}
                {ev.message && (
                  <div
                    style={{
                      fontSize: '0.7rem',
                      color: '#64748b',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                  >
                    {ev.message}
                  </div>
                )}
              </div>

              {/* 右侧时间 */}
              <div
                style={{
                  flexShrink: 0,
                  fontSize: '0.7rem',
                  color: '#94a3b8',
                  alignSelf: 'flex-start',
                }}
              >
                {new Date(ev.timestamp * 1000).toLocaleTimeString()}
              </div>
            </div>
          )
        })
      )}
    </div>
  )
}
