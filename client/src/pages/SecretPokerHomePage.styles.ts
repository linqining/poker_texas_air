import styled, { keyframes, css } from 'styled-components';
import { motion } from 'framer-motion';

/* ===== Keyframes ===== */

const particleFloat = keyframes`
  0% { transform: translateY(100vh); opacity: 0; }
  10% { opacity: 1; }
  90% { opacity: 1; }
  100% { transform: translateY(-10vh); opacity: 0; }
`;

const orbFloat = keyframes`
  0%, 100% { transform: translate(0, 0); }
  50% { transform: translate(30px, -20px); }
`;

const gradientShift = keyframes`
  0%, 100% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
`;

/* ===== Particles ===== */

export const Particles = styled.div`
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 0;
  overflow: hidden;
`;

export const Particle = styled.div`
  position: absolute;
  width: 2px;
  height: 2px;
  background: ${({ theme }) => theme.colors.brandIndigoAlpha12};
  border-radius: 50%;
  animation: ${particleFloat} linear infinite;
`;

/* ===== Buttons ===== */

export const BtnPrimary = styled(motion.button)<{ $lg?: boolean }>`
  background: linear-gradient(135deg, ${(props) => props.theme.colors.secondaryCta}, ${({ theme }) => theme.colors.brandPurple});
  color: ${(props) => props.theme.colors.lightestBg};
  border: none;
  padding: 0.65rem 1.6rem;
  border-radius: 10px;
  font-weight: 500;
  font-size: 0.9rem;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  transition:
    box-shadow 0.35s cubic-bezier(0.22, 1, 0.36, 1),
    transform 0.35s cubic-bezier(0.22, 1, 0.36, 1);
  box-shadow: 0 2px 12px rgba(102, 126, 234, 0.2);

  &:hover:not(:disabled) {
    box-shadow: 0 6px 24px ${({ theme }) => theme.colors.brandIndigoAlpha35};
  }
  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  ${(props) =>
    props.$lg &&
    css`
      padding: 0.85rem 2rem;
      font-size: 0.95rem;
    `}
`;

export const BtnSecondary = styled(motion.button)<{ $lg?: boolean }>`
  background: transparent;
  color: ${({ theme }) => theme.colors.mutedText};
  border: 1px solid rgba(${({ theme }) => theme.colors.borderSubtleRgb}, 0.35);
  padding: 0.65rem 1.6rem;
  border-radius: 10px;
  font-weight: 400;
  font-size: 0.9rem;
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  transition:
    border-color 0.35s cubic-bezier(0.22, 1, 0.36, 1),
    color 0.35s cubic-bezier(0.22, 1, 0.36, 1),
    background-color 0.35s cubic-bezier(0.22, 1, 0.36, 1);

  &:hover:not(:disabled) {
    border-color: rgba(${({ theme }) => theme.colors.borderSubtleRgb}, 0.6);
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  ${(props) =>
    props.$lg &&
    css`
      padding: 0.85rem 2rem;
      font-size: 0.95rem;
    `}
`;

/* ===== Home ===== */

export const Home = styled.div`
  min-height: 100dvh;
  position: relative;
  background: ${(props) => props.theme.colors.lightestBg};
  color: ${(props) => props.theme.colors.fontColorDark};
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  /* Scroll-snap is now driven by the document (<body>) via Global.ts.
     Keeping the page itself a normal block-flow element ensures the
     browser's native scroll chain works on every platform (desktop
     wheel, mobile touch, trackpad, etc.) and avoids the "stuck"
     symptom where a nested overflow:auto island never receives the
     scroll gesture. */
  overflow-x: clip;
`;

/* ===== Hero ===== */

export const Hero = styled.section`
  position: relative;
  min-height: 100dvh;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  padding: 5rem 2rem 2rem;
  scroll-margin-top: 5rem;
  scroll-snap-align: start;

  @media (max-width: 1023px) {
    padding: 1.5rem;
    padding-top: 7rem;
    padding-bottom: 4rem;
  }
`;

export const HeroBg = styled.div`
  position: absolute;
  inset: 0;
`;

export const HeroGradient = styled.div`
  position: absolute;
  inset: 0;
  background:
    radial-gradient(circle at 20% 50%, ${({ theme }) => theme.colors.brandIndigoAlpha06} 0%, transparent 50%),
    radial-gradient(circle at 80% 50%, ${({ theme }) => theme.colors.brandPurpleAlpha04} 0%, transparent 50%);
`;

export const HeroOrb = styled.div<{ $variant: 1 | 2 }>`
  position: absolute;
  border-radius: 50%;
  filter: blur(120px);
  opacity: 0.25;
  animation: ${orbFloat} 12s ease-in-out infinite;

  ${(props) =>
    props.$variant === 1 &&
    css`
      width: 500px;
      height: 500px;
      background: ${({ theme }) => theme.colors.brandIndigoAlpha15};
      top: 10%;
      left: 10%;
    `}
  ${(props) =>
    props.$variant === 2 &&
    css`
      width: 400px;
      height: 400px;
      background: rgba(118, 75, 162, 0.1);
      bottom: 20%;
      right: 15%;
      animation-delay: -6s;
    `}
`;

export const HeroContent = styled(motion.div)`
  position: relative;
  max-width: 800px;
  text-align: center;
  z-index: 1;
  padding-top: 2rem;
`;

export const HeroBadge = styled(motion.div)`
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  background: ${({ theme }) => theme.colors.successAlpha06 ?? "rgba(16, 185, 129, 0.06)"};
  border: 1px solid ${({ theme }) => theme.colors.successAlpha12};
  color: ${({ theme }) => theme.colors.successStrong};
  padding: 0.5rem 1rem;
  border-radius: 999px;
  font-size: 0.85rem;
  font-weight: 500;
  margin-bottom: 2rem;
  letter-spacing: 0.02em;
`;

export const HeroTitle = styled(motion.h1)`
  font-size: clamp(3.2rem, 7vw, 5.5rem);
  line-height: 1.1;
  font-weight: 700;
  margin-bottom: 1.5rem;
  letter-spacing: -0.03em;

  @media (max-width: 1023px) {
    font-size: clamp(2.2rem, 8vw, 3.5rem);
  }
`;

export const GradientText = styled.span`
  background: linear-gradient(135deg, ${(props) => props.theme.colors.secondaryCta}, ${({ theme }) => theme.colors.brandPurple}, ${({ theme }) => theme.colors.infoCyan});
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  background-size: 200% 200%;
  animation: ${gradientShift} 15s ease infinite;
`;

export const HeroDesc = styled(motion.p)`
  font-size: 1.15rem;
  color: ${({ theme }) => theme.colors.mutedText};
  max-width: 520px;
  margin: 0 auto 2.5rem;
  line-height: 1.7;
  font-weight: 400;

  @media (max-width: 1023px) {
    font-size: 1rem;
  }
`;

export const HeroActions = styled(motion.div)`
  display: flex;
  gap: 0.75rem;
  justify-content: center;
  flex-wrap: wrap;
  margin-bottom: 4rem;
`;

export const HeroStats = styled(motion.div)`
  display: flex;
  justify-content: center;
  gap: 3.5rem;
  flex-wrap: wrap;

  @media (max-width: 1023px) {
    gap: 1.5rem;
  }
`;

export const Stat = styled.div`
  text-align: center;
  padding: 0.5rem 1rem;
`;

export const StatValue = styled.span`
  display: block;
  font-size: 1.2rem;
  font-weight: 600;
  color: ${(props) => props.theme.colors.fontColorDark};
  font-family: 'JetBrains Mono', monospace;
  margin-bottom: 0.3rem;
`;

export const StatLabel = styled.span`
  font-size: 0.7rem;
  color: ${({ theme }) => theme.colors.softerText};
  text-transform: uppercase;
  letter-spacing: 0.12em;
`;

export const StatDivider = styled.div`
  width: 1px;
  background: ${({ theme }) => theme.colors.borderSubtle};
  align-self: stretch;
  margin: 0.5rem 0;

  @media (max-width: 1023px) {
    display: none;
  }
`;

/* ===== Sections ===== */

export const Section = styled.section<{ $variant?: 'default' | 'alt' | 'how' | 'cta' }>`
  padding: 5.5rem 2rem 4rem;
  position: relative;
  z-index: 1;
  scroll-margin-top: 5rem;
  scroll-snap-align: start;
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  justify-content: center;

  ${(props) =>
    props.$variant === 'alt' &&
    css`
      background: ${props.theme.colors.darkBg};
    `}
  ${(props) =>
    props.$variant === 'how' &&
    css`
      background: ${props.theme.colors.lightBg};

      /* Real felt texture overlay (Transparent Textures, ~129KB) gives
         the 'how it works' section the look of a poker table surface.
         The pseudo-element ::before keeps the texture below all card
         content (which sits in the normal flow), and pointer-events
         none ensures it never intercepts clicks. */
      &::before {
        content: '';
        position: absolute;
        inset: 0;
        background-image: url('/textures/felt.png');
        background-repeat: repeat;
        background-size: 320px 320px;
        opacity: 0.06;
        mix-blend-mode: multiply;
        pointer-events: none;
        z-index: -1;
      }
    `}
  ${(props) =>
    props.$variant === 'cta' &&
    css`
      background: linear-gradient(180deg, ${({ theme }) => theme.colors.lightBg} 0%, ${({ theme }) => theme.colors.brandIndigoAlpha10} 100%);
    `}

  @media (max-width: 1023px) {
    padding: 7rem 1.5rem 5rem;
  }
`;

export const Container = styled.div`
  max-width: 1100px;
  margin: 0 auto;
`;

export const SectionHeader = styled.div`
  text-align: center;
  margin-bottom: 3rem;
`;

export const SectionTag = styled.span`
  display: inline-block;
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: none;
  letter-spacing: 0.1em;
  color: ${(props) => props.theme.colors.secondaryCta};
  margin-bottom: 1rem;
  padding: 0.4rem 1.2rem;
  border-radius: 999px;
  background: ${({ theme }) => theme.colors.brandIndigoAlpha06};
  border: 1px solid rgba(102, 126, 234, 0.1);
`;

export const SectionTitle = styled.h2`
  font-size: clamp(2rem, 4vw, 3rem);
  font-weight: 700;
  text-align: center;
  margin-bottom: 0.75rem;
  letter-spacing: -0.02em;
  line-height: 1.2;

  @media (max-width: 1023px) {
    font-size: clamp(1.6rem, 5vw, 2.2rem);
  }
`;

export const SectionSubtitle = styled.p`
  font-size: 1.05rem;
  color: ${({ theme }) => theme.colors.mutedText};
  max-width: 480px;
  margin: 0 auto;
  line-height: 1.7;
`;

/* ===== Stagger Grid (shared by feature & value grids) ===== */

export const StaggerGrid = styled(motion.div)`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
  gap: 1.75rem;

  @media (max-width: 1023px) {
    grid-template-columns: 1fr;
  }
`;

/* ===== Features ===== */

export const FeatureIcon = styled.div`
  margin-bottom: 1.25rem;
  transition: transform 0.4s ease;
`;

export const FeatureCard = styled(motion.div)`
  background: ${({ theme }) => theme.colors.surfaceGlass};
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: 16px;
  padding: 2rem;
  transition:
    border-color 0.4s cubic-bezier(0.22, 1, 0.36, 1),
    background-color 0.4s cubic-bezier(0.22, 1, 0.36, 1),
    box-shadow 0.4s cubic-bezier(0.22, 1, 0.36, 1),
    transform 0.4s cubic-bezier(0.22, 1, 0.36, 1);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.03);

  &:hover {
    border-color: rgba(102, 126, 234, 0.2);
    background: #fff;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
    transform: translateY(-4px);
  }
  &:hover ${FeatureIcon} {
    transform: translateY(-2px);
  }

  h3 {
    font-size: 1.1rem;
    margin-bottom: 0.6rem;
    font-weight: 600;
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  p {
    color: ${({ theme }) => theme.colors.mutedText};
    font-size: 0.92rem;
    line-height: 1.65;
  }
`;

/* ===== Value Section ===== */

export const ValueHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1.25rem;
`;

export const ValueIcon = styled.div`
  transition: transform 0.4s ease;
`;

export const ValueCard = styled(motion.div)`
  background: ${({ theme }) => theme.colors.surfaceGlass};
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: 16px;
  padding: 1.75rem;
  transition:
    border-color 0.4s cubic-bezier(0.22, 1, 0.36, 1),
    background-color 0.4s cubic-bezier(0.22, 1, 0.36, 1),
    box-shadow 0.4s cubic-bezier(0.22, 1, 0.36, 1),
    transform 0.4s cubic-bezier(0.22, 1, 0.36, 1);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.03);

  &:hover {
    border-color: rgba(102, 126, 234, 0.2);
    background: #fff;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
    transform: translateY(-4px);
  }
  &:hover ${ValueIcon} {
    transform: translateY(-2px);
  }

  h3 {
    font-size: 1.1rem;
    margin-bottom: 0.5rem;
    font-weight: 600;
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  p {
    color: ${({ theme }) => theme.colors.mutedText};
    font-size: 0.9rem;
    line-height: 1.6;
  }
`;

export const ValueStat = styled.div`
  text-align: right;
`;

export const StatNumber = styled.span`
  display: block;
  font-size: 1.6rem;
  font-weight: 600;
  font-family: 'JetBrains Mono', monospace;
  line-height: 1;
`;

export const StatDesc = styled.span`
  font-size: 0.7rem;
  color: ${({ theme }) => theme.colors.softerText};
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-top: 0.3rem;
`;

/* ===== Protocol Flow ===== */

export const ProtocolFlow = styled.div`
  max-width: 640px;
  margin: 0 auto;
`;

export const ProtocolStep = styled.div`
  display: flex;
  align-items: flex-start;
  gap: 1.25rem;
  position: relative;
  padding-bottom: 1.25rem;

  @media (max-width: 1023px) {
    gap: 1rem;
    padding-bottom: 1.5rem;
  }
`;

export const StepNumber = styled.div`
  width: 48px;
  height: 48px;
  border-radius: 14px;
  background: linear-gradient(135deg, ${({ theme }) => theme.colors.brandIndigoAlpha10}, ${({ theme }) => theme.colors.brandPurpleAlpha10});
  border: 1px solid ${({ theme }) => theme.colors.brandIndigoAlpha15};
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  position: relative;
  z-index: 2;
`;

export const StepNum = styled.span`
  position: absolute;
  font-size: 0.6rem;
  font-weight: 600;
  color: ${(props) => props.theme.colors.secondaryCta};
  top: 6px;
  left: 8px;
`;

export const StepIcon = styled.span`
  color: ${({ theme }) => theme.colors.softText};
`;

export const StepContent = styled.div`
  flex: 1;
  padding-top: 0.25rem;

  h4 {
    font-size: 1.1rem;
    font-weight: 600;
    margin: 0 0 0.4rem;
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  p {
    color: ${({ theme }) => theme.colors.mutedText};
    font-size: 0.92rem;
    line-height: 1.6;
    margin: 0;
  }
`;

export const StepLine = styled.div`
  position: absolute;
  left: 24px;
  top: 48px;
  bottom: 0;
  width: 1px;
  background: linear-gradient(180deg, ${({ theme }) => theme.colors.brandIndigoAlpha20}, transparent);
  z-index: 1;
`;

/* ===== CTA Section ===== */

export const CTAContent = styled.div`
  text-align: center;
  max-width: 500px;
  margin: 0 auto;

  h2 {
    font-size: clamp(2rem, 4vw, 3rem);
    font-weight: 700;
    margin-bottom: 0.75rem;
    letter-spacing: -0.02em;
  }
  p {
    color: ${({ theme }) => theme.colors.mutedText};
    font-size: 1rem;
    margin: 0 auto 2rem;
    line-height: 1.7;
  }
`;

/* ===== Footer ===== */

export const Footer = styled.footer`
  border-top: 1px solid ${({ theme }) => theme.colors.borderMuted};
  padding: 3rem 2rem;
  background: ${(props) => props.theme.colors.darkBg};
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  position: relative;
  z-index: 1;
  scroll-margin-top: 5rem;
  scroll-snap-align: start;
  min-height: 50vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
`;

export const FooterContent = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 1.5rem;
  max-width: 1100px;
  margin: 0 auto;
`;

export const FooterBrand = styled.div`
  span:first-child {
    font-size: 1.2rem;
    font-weight: 600;
    color: ${(props) => props.theme.colors.fontColorDark};
  }
  p {
    color: ${({ theme }) => theme.colors.mutedText};
    font-size: 0.8rem;
    margin-top: 0.3rem;
  }
`;

export const FooterLinks = styled.div`
  display: flex;
  gap: 0.75rem;
  align-items: center;
`;

export const FooterLink = styled(motion.button)`
  background: transparent;
  color: ${({ theme }) => theme.colors.mutedText};
  border: 1px solid rgba(${({ theme }) => theme.colors.borderSubtleRgb}, 0.25);
  padding: 0.4rem 1rem;
  border-radius: 8px;
  font-size: 0.8rem;
  font-weight: 500;
  cursor: pointer;
  transition:
    border-color 0.25s ease,
    color 0.25s ease;

  &:hover {
    border-color: rgba(${({ theme }) => theme.colors.borderSubtleRgb}, 0.45);
    color: ${(props) => props.theme.colors.fontColorDark};
  }
`;

export const FooterTech = styled.div`
  span {
    display: block;
    font-size: 0.75rem;
    color: ${({ theme }) => theme.colors.softText};
    margin-bottom: 0.4rem;
  }
`;

export const TechTags = styled.div`
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;

  span {
    background: rgba(${({ theme }) => theme.colors.surfaceMutedPlainRgb}, 0.6);
    border: 1px solid rgba(${({ theme }) => theme.colors.borderSubtleRgb}, 0.8);
    padding: 0.25rem 0.6rem;
    border-radius: 6px;
    font-size: 0.72rem;
    color: ${({ theme }) => theme.colors.mutedText};
    transition:
      border-color 0.2s ease,
      color 0.2s ease;
    cursor: default;

    &:hover {
      border-color: ${(props) => props.theme.colors.secondaryCta};
      color: ${(props) => props.theme.colors.secondaryCta};
    }
  }
`;

export const FooterRef = styled.div`
  span {
    display: block;
    font-size: 0.75rem;
    color: ${({ theme }) => theme.colors.softText};
    margin-bottom: 0.2rem;
  }
  a {
    color: ${(props) => props.theme.colors.secondaryCta};
    font-size: 0.8rem;
    transition: color 0.2s ease;

    &:hover {
      color: ${({ theme }) => theme.colors.infoCyan};
    }
  }
`;

/* ===== Scroll Nav ===== */

export const ScrollNav = styled.nav`
  position: fixed;
  right: 1.5rem;
  top: 50%;
  transform: translateY(-50%);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1rem;
  z-index: 50;

  @media (max-width: 1023px) {
    display: none;
  }
`;

export const ScrollLabel = styled.span`
  position: absolute;
  right: 1.25rem;
  top: 50%;
  transform: translateY(-50%) translateX(4px);
  white-space: nowrap;
  font-size: 0.7rem;
  font-weight: 500;
  color: ${({ theme }) => theme.colors.mutedText};
  background: ${({ theme }) => theme.colors.surfaceGlass};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  padding: 0.25rem 0.6rem;
  border-radius: 6px;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.25s ease, transform 0.25s ease;
`;

export const ScrollDot = styled.button<{ $active?: boolean }>`
  position: relative;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: ${({ theme }) => theme.colors.brandIndigoAlpha25};
  border: none;
  cursor: pointer;
  padding: 0;
  transition:
    background-color 0.3s ease,
    transform 0.3s ease,
    box-shadow 0.3s ease;

  &:hover ${ScrollLabel} {
    opacity: 1;
    transform: translateY(-50%) translateX(0);
  }

  ${(props) =>
    props.$active &&
    css`
      background: linear-gradient(135deg, ${props.theme.colors.secondaryCta}, ${({ theme }) => theme.colors.brandPurple});
      transform: scale(1.3);
      box-shadow: 0 0 0 4px ${({ theme }) => theme.colors.brandIndigoAlpha15};
    `}
`;
