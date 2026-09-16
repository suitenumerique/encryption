import { Loader } from '@gouvfr-lasuite/cunningham-react';
import type { ReactNode } from 'react';

import shieldCheck from '@encryption/src/ui/assets/illustrations/shield-check.png';
import shieldX from '@encryption/src/ui/assets/illustrations/shield-x.png';
import '@encryption/src/ui/components/layout/layout.css';

export type IllustrationName = 'shield-check' | 'shield-x';

const ILLUSTRATIONS: Record<IllustrationName, string> = {
  'shield-check': shieldCheck,
  'shield-x': shieldX,
};

export function Illustration({ name }: { name: IllustrationName }) {
  return (
    <div className="enc-screen__illustration">
      <img src={ILLUSTRATIONS[name]} alt="" />
    </div>
  );
}

interface ScreenProps {
  illustration?: IllustrationName;
  title?: ReactNode;
  titleTone?: 'default' | 'error';
  description?: ReactNode;
  /** Alerts that must stay above the title (session expired, a failed action). */
  banner?: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
  /** `stack` (full-width buttons, the default) or `row` (right-aligned Cancel/Confirm). */
  actionsLayout?: 'stack' | 'row';
  /** Add the screen's own padding; off when the host modal already pads the content. */
  padded?: boolean;
  /** Give the title the `heading` role tests and screen readers look for. */
  titleAs?: 'h1' | 'h2';
}

/**
 * The content of one interface modal: illustration, title + description, a body
 * and stacked actions. The modal chrome (card, padding, close control) belongs
 * to whoever hosts the screen: the product's modal, or the interface's own
 * Cunningham Modal in the SDK overlays.
 */
export function Screen({
  illustration,
  title,
  titleTone = 'default',
  description,
  banner,
  children,
  actions,
  actionsLayout = 'stack',
  padded = false,
  titleAs: TitleTag = 'h2',
}: ScreenProps) {
  return (
    <div className={padded ? 'enc-screen enc-screen--padded' : 'enc-screen'}>
      {banner}
      {illustration && <Illustration name={illustration} />}
      {(title || description) && (
        <div className="enc-screen__header">
          {title && (
            <TitleTag className={titleTone === 'error' ? 'enc-screen__title enc-screen__title--error' : 'enc-screen__title'}>{title}</TitleTag>
          )}
          {description && <div className="enc-screen__description">{typeof description === 'string' ? <p>{description}</p> : description}</div>}
        </div>
      )}
      {children && <div className="enc-screen__body">{children}</div>}
      {actions && <Actions layout={actionsLayout}>{actions}</Actions>}
    </div>
  );
}

export function Actions({ children, layout = 'stack' }: { children: ReactNode; layout?: 'stack' | 'row' }) {
  return <div className={layout === 'row' ? 'enc-actions enc-actions--row' : 'enc-actions'}>{children}</div>;
}

export function LoadingScreen({ label }: { label?: string }) {
  return (
    <div className="enc-loading">
      <Loader />
      {label && <p style={{ margin: 0 }}>{label}</p>}
    </div>
  );
}

/** A Material icon sized for a button or a chip. */
export function Icon({ name, size = 24 }: { name: string; size?: number }) {
  return (
    <span className="material-icons" aria-hidden="true" style={{ fontSize: size }}>
      {name}
    </span>
  );
}
