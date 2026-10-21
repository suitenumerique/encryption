import { Alert, Button, Loader, VariantType } from '@gouvfr-lasuite/ui-components';
import { ChevronLeft, CircleCheckFilled, Info, WarningFilled } from '@gouvfr-lasuite/ui-components/icons';
import type { ReactNode } from 'react';

import shieldCheck from '@encryption/src/ui/assets/illustrations/shield-check.svg';
import shieldGear from '@encryption/src/ui/assets/illustrations/shield-gear.svg';
import shieldRestore from '@encryption/src/ui/assets/illustrations/shield-restore.svg';
import shieldX from '@encryption/src/ui/assets/illustrations/shield-x.png';
import styles from '@encryption/src/ui/components/layout/layout.module.css';

export type IllustrationName = 'shield-gear' | 'shield-check' | 'shield-restore' | 'shield-x';

const ILLUSTRATIONS: Record<IllustrationName, string> = {
  'shield-gear': shieldGear,
  'shield-check': shieldCheck,
  'shield-restore': shieldRestore,
  'shield-x': shieldX,
};

export function Illustration({ name }: { name: IllustrationName }) {
  return (
    <div className={styles.screenIllustration}>
      <img src={ILLUSTRATIONS[name]} alt="" className={name === 'shield-x' ? styles.screenIllustrationRaster : undefined} />
    </div>
  );
}

// As designed: the filled warning triangle for errors as well.
const NOTICE_ICONS: Record<VariantType, ReactNode> = {
  [VariantType.ERROR]: <WarningFilled aria-hidden size={16} />,
  [VariantType.WARNING]: <WarningFilled aria-hidden size={16} />,
  [VariantType.SUCCESS]: <CircleCheckFilled aria-hidden size={16} />,
  [VariantType.INFO]: <Info aria-hidden size={16} />,
  [VariantType.NEUTRAL]: <Info aria-hidden size={16} />,
};

/**
 * The design system's alert with the design system's SVG icons: left to itself it
 * draws a Material Icons ligature, a font the interface does not load.
 */
export function Notice({ type, children }: { type: VariantType; children: ReactNode }) {
  return (
    <Alert type={type} icon={NOTICE_ICONS[type]}>
      {children}
    </Alert>
  );
}

interface ScreenProps {
  /** A step back inside a flow, shown as a small link in the top left corner. */
  back?: { label: string; onClick: () => void; disabled?: boolean };
  illustration?: IllustrationName;
  title?: ReactNode;
  titleTone?: 'default' | 'error';
  description?: ReactNode;
  /** `sm` (14px, the default) or `xs` (12px, the settings flows of the design). */
  descriptionSize?: 'sm' | 'xs';
  /** Alerts that must stay above the body (session expired, a failed action). */
  banner?: ReactNode;
  children?: ReactNode;
  actions?: ReactNode;
  /** `stack` (full-width buttons, the default) or `row` (right-aligned Cancel/Confirm). */
  actionsLayout?: 'stack' | 'row';
  /** Add the screen's own padding, for a screen shown outside a modal. */
  padded?: boolean;
  /** Give the title the `heading` role tests and screen readers look for. */
  titleAs?: 'h1' | 'h2';
}

/**
 * The content of one interface modal: illustration, title + description, a body
 * and stacked actions. The modal chrome (card, padding, close control) belongs
 * to the design system's Modal that App.tsx draws around every screen.
 */
export function Screen({
  back,
  illustration,
  title,
  titleTone = 'default',
  description,
  descriptionSize = 'sm',
  banner,
  children,
  actions,
  actionsLayout = 'stack',
  padded = false,
  titleAs: TitleTag = 'h2',
}: ScreenProps) {
  const descriptionClass = descriptionSize === 'xs' ? `${styles.screenDescription} ${styles.screenDescriptionXs}` : styles.screenDescription;

  return (
    <div className={padded ? `${styles.screen} ${styles.screenPadded}` : styles.screen}>
      {back && (
        <Button
          className={styles.screenBack}
          size="nano"
          variant="tertiary"
          color="neutral"
          icon={<ChevronLeft aria-hidden size={16} />}
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
          {description && <div className={descriptionClass}>{typeof description === 'string' ? <p>{description}</p> : description}</div>}
        </div>
      )}
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
      {label && <p className={styles.loadingLabel}>{label}</p>}
    </div>
  );
}
