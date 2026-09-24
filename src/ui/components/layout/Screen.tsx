import { Button, Loader } from '@gouvfr-lasuite/cunningham-react';
import { Icon } from '@gouvfr-lasuite/ui-kit';
import type { ReactNode } from 'react';

import shieldCheck from '@encryption/src/ui/assets/illustrations/shield-check.png';
import shieldX from '@encryption/src/ui/assets/illustrations/shield-x.png';
import styles from '@encryption/src/ui/components/layout/layout.module.css';

export type IllustrationName = 'shield-check' | 'shield-x';

const ILLUSTRATIONS: Record<IllustrationName, string> = {
  'shield-check': shieldCheck,
  'shield-x': shieldX,
};

export function Illustration({ name }: { name: IllustrationName }) {
  return (
    <div className={styles.screenIllustration}>
      <img src={ILLUSTRATIONS[name]} alt="" />
    </div>
  );
}

interface ScreenProps {
  /** A step back inside a flow, shown as a small link above the title. */
  back?: { label: string; onClick: () => void; disabled?: boolean };
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
  back,
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
    <div className={padded ? `${styles.screen} ${styles.screenPadded}` : styles.screen}>
      {back && (
        <Button
          className={styles.screenBack}
          size="small"
          variant="tertiary"
          color="neutral"
          icon={<Icon aria-hidden name="arrow_back" size={16} />}
          onClick={back.onClick}
          disabled={back.disabled}
        >
          {back.label}
        </Button>
      )}
      {illustration && <Illustration name={illustration} />}
      {(title || description) && (
        <div className={styles.screenHeader}>
          {title && (
            <TitleTag className={titleTone === 'error' ? `${styles.screenTitle} ${styles.screenTitleError}` : styles.screenTitle}>{title}</TitleTag>
          )}
          {description && <div className={styles.screenDescription}>{typeof description === 'string' ? <p>{description}</p> : description}</div>}
        </div>
      )}
      {/* Under the header, not above it: the product's close control occupies the
          top right corner of the content, and an alert is about what follows. */}
      {banner}
      {children && <div className={styles.screenBody}>{children}</div>}
      {actions && <Actions layout={actionsLayout}>{actions}</Actions>}
    </div>
  );
}

export function Actions({ children, layout = 'stack' }: { children: ReactNode; layout?: 'stack' | 'row' }) {
  return <div className={layout === 'row' ? `${styles.actions} ${styles.actionsRow}` : styles.actions}>{children}</div>;
}

export function LoadingScreen({ label }: { label?: string }) {
  return (
    <div className={styles.loading}>
      <Loader />
      {label && <p style={{ margin: 0 }}>{label}</p>}
    </div>
  );
}
