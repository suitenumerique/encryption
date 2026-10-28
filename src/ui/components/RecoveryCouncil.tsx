import { Button, Checkbox, VariantType } from '@gouvfr-lasuite/ui-components';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { mnemonicLanguageForLocale } from '@encryption/src/crypto/mnemonic';
import type { RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import { type CouncilForMe, enrollCouncilEscrow, fetchCouncilForMe } from '@encryption/src/ui/api/council-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { Chip, FingerprintBoxes, Identity } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { type CouncilAuthProps, useCouncilErrors } from '@encryption/src/ui/hooks/useCouncilErrors';
import { useCouncilVault } from '@encryption/src/ui/hooks/useCouncilVault';
import { useModalSize } from '@encryption/src/ui/hooks/useModalSize';
import type { CouncilEscrowCheck } from '@encryption/src/vault/operations/recovery-council';

interface RecoveryCouncilProps extends CouncilAuthProps {
  getIdToken: () => Promise<string | null>;
  onBack?: () => void;
  onClose: () => void;
}

type View =
  | { kind: 'loading' }
  | { kind: 'none' }
  | { kind: 'accept'; forMe: CouncilForMe; fingerprint: string | null; again: boolean }
  | { kind: 'enrolled'; forMe: CouncilForMe; check: CouncilEscrowCheck }
  | { kind: 'done'; label: string };

function head(chain: RosterVersionWire[]): RosterVersionWire {
  return chain[chain.length - 1];
}

function Members({ roster }: { roster: RosterVersionWire }) {
  return (
    <ul className={styles.people}>
      {roster.members.map((member) => (
        <li key={member.slot}>
          <Identity name={member.name ?? `#${member.slot}`} />
        </li>
      ))}
    </ul>
  );
}

/**
 * The user's side of their organization's recovery council (shamir.md §7-11):
 * accepting it once, after comparing its fingerprint with the one the
 * organization published, and its state afterwards. Changes of membership need
 * nothing from the user; only an escrow that too few custodians can still open
 * asks for an explicit new setup.
 */
export function RecoveryCouncil({ getIdToken, onBack, onClose, ...auth }: RecoveryCouncilProps) {
  const { t, i18n } = useTranslation('common');
  const vault = useCouncilVault();
  const { banner, fail, clear } = useCouncilErrors(auth);
  const [view, setView] = useState<View>({ kind: 'loading' });
  const [compared, setCompared] = useState(false);
  const [busy, setBusy] = useState(false);

  useModalSize('medium');

  const load = useCallback(async () => {
    try {
      const forMe = await withFreshIdToken(getIdToken, fetchCouncilForMe);

      if (!forMe.council) {
        setView({ kind: 'none' });

        return;
      }

      const { escrow, council } = forMe;

      // An escrow of this vault that custodians can still open: its state, audited
      // against the user's own identity and the chain it pins.
      if (escrow && escrow.vault_active && escrow.health.status !== 'lost') {
        const { status } = await vault.checkEscrow(escrow.record, council.chain);
        setView({ kind: 'enrolled', forMe, check: status });

        return;
      }

      const again = escrow !== null && escrow.vault_active;
      // Setting up again starts from what the user already signed; the first time,
      // from version 1, and the fingerprint is compared by the person.
      const verified = await vault
        .verifyRoster(council.council_id, council.chain, again ? escrow!.record.roster_hash : undefined)
        .catch((err: unknown) => {
          fail(err);

          return null;
        });
      setView({ kind: 'accept', forMe, fingerprint: verified?.fingerprint ?? null, again });
    } catch (err) {
      fail(err);
      setView({ kind: 'none' });
    }
  }, [getIdToken, vault, fail]);

  useEffect(() => {
    // Wrapped so the state writes sit behind an await: the effect itself writes
    // nothing synchronously.
    void (async () => {
      await load();
    })();
  }, [load]);

  const accept = useCallback(async () => {
    if (view.kind !== 'accept' || !view.forMe.council) return;

    const { council, escrow } = view.forMe;
    setBusy(true);
    clear();

    try {
      const body = await vault.createEscrow(
        council.council_id,
        council.chain,
        mnemonicLanguageForLocale(i18n.language),
        view.again ? escrow!.record.roster_hash : undefined
      );
      await withFreshIdToken(getIdToken, (idToken) => enrollCouncilEscrow(idToken, vault.sign, body));
      setView({ kind: 'done', label: council.label });
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  }, [view, vault, getIdToken, i18n.language, fail, clear]);

  const back = onBack ? { label: t('onboarding.btn_back'), onClick: onBack } : undefined;

  if (view.kind === 'loading') return <LoadingScreen />;

  if (view.kind === 'none') {
    return (
      <Screen
        back={back}
        title={t('council.title')}
        description={t('council.none')}
        banner={banner}
        actions={
          <Button variant="bordered" color="neutral" onClick={onClose}>
            {t('settings.done')}
          </Button>
        }
      />
    );
  }

  if (view.kind === 'done') {
    return (
      <Screen
        illustration="shield-check"
        title={t('council.done_title')}
        description={t('council.done_description', { council: view.label })}
        actions={<Button onClick={onClose}>{t('settings.done')}</Button>}
      />
    );
  }

  const council = view.forMe.council!;
  const roster = head(council.chain);
  const counts = { threshold: roster.threshold, count: roster.members.length };

  if (view.kind === 'accept') {
    return (
      <Screen
        back={back}
        title={view.again ? t('council.again_title') : t('council.accept_title', { council: council.label })}
        description={
          <>
            {view.again && <p>{t('council.again_explanation')}</p>}
            <p>{t('council.accept_explanation', { council: council.label, ...counts })}</p>
            <p>{t('council.accept_nobody_reads')}</p>
          </>
        }
        banner={banner}
        actions={
          <Button onClick={accept} disabled={busy || view.fingerprint === null || (!view.again && !compared)}>
            {busy ? t('council.accepting') : view.again ? t('council.again_button') : t('council.accept_button')}
          </Button>
        }
      >
        <div className={styles.section}>
          <p className={styles.sectionTitle}>{t('council.members', counts)}</p>
          <Members roster={roster} />
        </div>
        {view.fingerprint && !view.again && (
          <div className={styles.section}>
            <p className={styles.sectionTitle}>{t('council.fingerprint_title')}</p>
            <p className={styles.hint}>{t('council.fingerprint_hint')}</p>
            <FingerprintBoxes fingerprint={view.fingerprint} />
            <Checkbox label={t('council.fingerprint_compared')} checked={compared} onChange={() => setCompared((value) => !value)} />
          </div>
        )}
      </Screen>
    );
  }

  const escrow = view.forMe.escrow!;
  const health = escrow.health;

  return (
    <Screen
      back={back}
      title={t('council.title')}
      description={t('council.enrolled_description', { council: council.label, ...counts })}
      banner={
        <>
          {banner}
          {view.check !== 'ok' && (
            <Notice type={VariantType.ERROR}>{t(view.check === 'tampered' ? 'council.check_tampered' : 'council.check_chain_broken')}</Notice>
          )}
          {view.check === 'ok' && health.status === 'at-risk' && <Notice type={VariantType.WARNING}>{t('council.at_risk')}</Notice>}
          {view.check === 'ok' && health.outdated && <Notice type={VariantType.INFO}>{t('council.outdated')}</Notice>}
          {!council.configured && <Notice type={VariantType.INFO}>{t('council.not_configured_user')}</Notice>}
        </>
      }
      actions={<Button onClick={onClose}>{t('settings.done')}</Button>}
    >
      <div className={styles.section}>
        <div className={styles.cardHeader}>
          <p className={styles.sectionTitle}>{t('council.members', counts)}</p>
          {view.check === 'ok' && health.status === 'ok' && (
            <Chip tone="success" icon="trusted">
              {t('council.chip_protected')}
            </Chip>
          )}
        </div>
        <Members roster={roster} />
      </div>
    </Screen>
  );
}
