import type { ReactNode } from 'react'
import { ShieldCheck, CheckCircle2 } from 'lucide-react'
import styled, { useTheme } from 'styled-components'
import { useContentContext } from '../../context/content/contentContext'

interface ShuffleProofVisualizerProps {
  proof?: {
    sum_c1_commit?: string
    sum_c2_commit?: string
    nonce?: string
  } | null
  verified?: boolean | null
}

function truncateHex(hex: string | undefined, prefix = 10): string {
  if (!hex) return '—'
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length <= prefix) return `0x${clean}`
  return `0x${clean.slice(0, prefix)}…`
}

/* ===================== styled components ===================== */

const Card = styled.div<{ $borderColor: string }>`
  background: ${({ theme }) => theme.colors.lightestBg};
  border-radius: ${({ theme }) => theme.radius.md};
  padding: 1rem;
  border: 1px solid ${({ $borderColor }) => $borderColor};
  box-shadow: 0 3px 12px rgba(0, 0, 0, 0.05);
  font-family: 'Inter', sans-serif;
  color: ${({ theme }) => theme.colors.fontColorDarkLighter};
`;

const Title = styled.h3`
  margin: 0;
  font-size: 1.05rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDarkLighter};
`;

const Subtitle = styled.p`
  margin: 0.2rem 0 0;
  font-size: 0.78rem;
  color: ${({ theme }) => theme.colors.info};
  font-weight: 600;
`;

const SectionLabel = styled.div`
  font-size: 0.7rem;
  color: ${({ theme }) => theme.colors.softerText};
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 0.4rem;
  font-weight: 600;
`;

const Empty = styled.div`
  padding: 1.2rem 0.5rem;
  text-align: center;
  color: ${({ theme }) => theme.colors.softerText};
  font-style: italic;
  font-size: 0.85rem;
`;

const HexRowContainer = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  background: rgba(248, 250, 252, 0.8);
  border-radius: 6px;
  padding: 0.35rem 0.55rem;
`;

const HexRowLabel = styled.span`
  font-size: 0.75rem;
  color: ${({ theme }) => theme.colors.mutedText};
  font-weight: 500;
`;

const HexRowValue = styled.span`
  font-size: 0.75rem;
  font-family: 'JetBrains Mono', monospace;
  color: ${({ theme }) => theme.colors.softText};
`;

const ProofRowContainer = styled.div`
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: rgba(248, 250, 252, 0.8);
  border-radius: 6px;
  padding: 0.35rem 0.55rem;
`;

const ProofIconWrap = styled.span`
  display: inline-flex;
  flex-shrink: 0;
`;

const ProofName = styled.span`
  font-size: 0.75rem;
  font-family: 'JetBrains Mono', monospace;
  color: ${({ theme }) => theme.colors.fontColorDarkLighter};
  font-weight: 600;
`;

const ProofDesc = styled.span`
  font-size: 0.72rem;
  color: ${({ theme }) => theme.colors.softText};
  margin-left: auto;
`;

const HighlightsDivider = styled.div`
  margin-top: 0.5rem;
  padding-top: 0.75rem;
  border-top: 1px dashed ${({ theme }) => theme.colors.borderSubtle};
`;

const HighlightsList = styled.ul`
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 0.3rem;
`;

const HighlightItemRow = styled.li`
  display: flex;
  align-items: center;
  gap: 0.4rem;
`;

const HighlightItemText = styled.span`
  font-size: 0.75rem;
  color: ${({ theme }) => theme.colors.mutedText};
`;

const SectionStack = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
`;

const SectionBlock = styled.div`
  margin-bottom: 0.75rem;
`;

/* ===================== component ===================== */

export default function ShuffleProofVisualizer({ proof, verified }: ShuffleProofVisualizerProps) {
  const { getLocalizedString: t } = useContentContext()
  const theme = useTheme()

  const borderColor =
    verified === true
      ? theme.colors.success
      : verified === false
        ? theme.colors.danger
        : theme.colors.borderSubtle

  return (
    <Card $borderColor={borderColor}>
      <div style={{ marginBottom: '0.75rem' }}>
        <Title>{t('shuffle-proof_title')}</Title>
        <Subtitle>{t('shuffle-proof_subtitle')}</Subtitle>
      </div>

      {proof === null || proof === undefined ? (
        <Empty>{t('shuffle-proof_placeholder')}</Empty>
      ) : (
        <>
          <SectionBlock>
            <SectionLabel>{t('shuffle-proof_commitment-layer')}</SectionLabel>
            <SectionStack>
              <HexRow label="sum_c1_commit" value={truncateHex(proof.sum_c1_commit)} />
              <HexRow label="sum_c2_commit" value={truncateHex(proof.sum_c2_commit)} />
            </SectionStack>
          </SectionBlock>

          <SectionBlock>
            <SectionLabel>{t('shuffle-proof_proof-layer')}</SectionLabel>
            <SectionStack>
              <ProofRow icon={<ShieldCheck size={16} color={theme.colors.info} />} name="combined_schnorr_proof" desc={t('shuffle-proof_combined')} />
              <ProofRow icon={<ShieldCheck size={16} color={theme.colors.info} />} name="sum_c1_schnorr_proof" desc={t('shuffle-proof_c1-only')} />
              <ProofRow icon={<ShieldCheck size={16} color={theme.colors.info} />} name="sum_c2_schnorr_proof" desc={t('shuffle-proof_c2-only')} />
            </SectionStack>
          </SectionBlock>

          <SectionBlock>
            <SectionLabel>{t('shuffle-proof_anti-replay')}</SectionLabel>
            <HexRow label="nonce" value={truncateHex(proof.nonce)} />
          </SectionBlock>
        </>
      )}

      <HighlightsDivider>
        <SectionLabel>{t('shuffle-proof_highlights')}</SectionLabel>
        <HighlightsList>
          <Highlight text={t('shuffle-proof_highlight-1')} />
          <Highlight text={t('shuffle-proof_highlight-2')} />
          <Highlight text={t('shuffle-proof_highlight-3')} />
        </HighlightsList>
      </HighlightsDivider>
    </Card>
  )
}

function HexRow({ label, value }: { label: string; value: string }) {
  return (
    <HexRowContainer>
      <HexRowLabel>{label}</HexRowLabel>
      <HexRowValue>{value}</HexRowValue>
    </HexRowContainer>
  )
}

function ProofRow({ icon, name, desc }: { icon: ReactNode; name: string; desc: string }) {
  return (
    <ProofRowContainer>
      <ProofIconWrap>{icon}</ProofIconWrap>
      <ProofName>{name}</ProofName>
      <ProofDesc>{desc}</ProofDesc>
    </ProofRowContainer>
  )
}

function Highlight({ text }: { text: string }) {
  const theme = useTheme()
  return (
    <HighlightItemRow>
      <CheckCircle2 size={14} color={theme.colors.success} style={{ flexShrink: 0 }} />
      <HighlightItemText>{text}</HighlightItemText>
    </HighlightItemRow>
  )
}
