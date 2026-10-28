import { Button, Checkbox, VariantType } from '@gouvfr-lasuite/ui-components';
import { type ReactNode, useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import { mnemonicLanguageForLocale } from '@encryption/src/crypto/mnemonic';
import { MSG_VAULT_ACCEPT_FINGERPRINT } from '@encryption/src/shared/constants';
import type { RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import { type CouncilForMe, enrollCouncilEscrow, fetchCouncilForMe } from '@encryption/src/ui/api/council-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { Chip, FingerprintBoxes, Identity, IdentityCard } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { useCouncilAction } from '@encryption/src/ui/hooks/useCouncilAction';
import type { CouncilAuthProps } from '@encryption/src/ui/hooks/useCouncilErrors';
import { useCouncilVault } from '@encryption/src/ui/hooks/useCouncilVault';
import { useModalSize } from '@encryption/src/ui/hooks/useModalSize';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';
import type { CouncilEscrowCheck, CouncilIdentity } from '@encryption/src/vault/operations/recovery-council';

interface RecoveryCouncilProps extends CouncilAuthProps {
  getIdToken: () => Promise<string | null>;
  /** The signed-in user, left out of the custodians they could verify. */
  userId?: string | null;
  /** Open on the verification of an enrolled user's council (the settings' "verify" action). */
  startVerifying?: boolean;
  onBack?: () => void;
  onClose: () => void;
}

type View =
  | { kind: 'loading' }
  | { kind: 'none' }
  | { kind: 'accept'; forMe: CouncilForMe; identity: CouncilIdentity | null; again: boolean }
  | { kind: 'verify'; forMe: CouncilForMe; identity: CouncilIdentity; then: 'join' | 'enrolled' }
  | { kind: 'enrolled'; forMe: CouncilForMe; check: CouncilEscrowCheck; identity: CouncilIdentity | null }
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

function VerifiedChip({ verified }: { verified: boolean }) {
  const { t } = useTranslation('common');

  return verified ? (
    <Chip tone="success" icon="trusted">
      {t('council.chip_verified')}
    </Chip>
  ) : (
    <Chip tone="warning">{t('council.chip_unverified')}</Chip>
  );
}

/**
 * The user's side of their organization's recovery council (architecture.md F.2-F.4):
 * joining it, at once or after verifying it, and its state afterwards. Joining
 * without verifying trusts the list the server shows (the one trust-on-first-use
 * the project allows, F.2); verifying, then or later, takes one of two checks:
 * the council's code against the one the organization published, or the
 * personal code of one custodian of version 1 the user knows.
 */
export function RecoveryCouncil({ getIdToken, userId = null, startVerifying = false, onBack, onClose, ...auth }: RecoveryCouncilProps) {
  const { t, i18n } = useTranslation('common');
  const vault = useCouncilVault();
  const { banner, fail, busy: running, run } = useCouncilAction(auth);
  const busy = running !== null;
  const [view, setView] = useState<View>({ kind: 'loading' });

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
        const { status, council: identity } = await vault.checkEscrow(escrow.record, council.chain);
        setView(
          startVerifying && identity && !identity.verified
            ? { kind: 'verify', forMe, identity, then: 'enrolled' }
            : { kind: 'enrolled', forMe, check: status, identity }
        );

        return;
      }

      const again = escrow !== null && escrow.vault_active;
      // Setting up again starts from what the user already signed; the first time,
      // from version 1.
      const identity = await vault
        .verifyRoster(council.council_id, council.chain, again ? escrow!.record.roster_hash : undefined)
        .catch((err: unknown) => {
          fail(err);

          return null;
        });
      setView({ kind: 'accept', forMe, identity, again });
    } catch (err) {
      fail(err);
      setView({ kind: 'none' });
    }
  }, [getIdToken, vault, fail, startVerifying]);

  useEffect(() => {
    // Wrapped so the state writes sit behind an await: the effect itself writes
    // nothing synchronously.
    void (async () => {
      await load();
    })();
  }, [load]);

  const join = useCallback(
    async (forMe: CouncilForMe, again: boolean) => {
      const council = forMe.council!;

      await run(async () => {
        const body = await vault.createEscrow(
          council.council_id,
          council.chain,
          mnemonicLanguageForLocale(i18n.language),
          again ? forMe.escrow!.record.roster_hash : undefined
        );
        await withFreshIdToken(getIdToken, (idToken) => enrollCouncilEscrow(idToken, vault.sign, body));
        setView({ kind: 'done', label: council.label });
      });
    },
    [vault, getIdToken, i18n.language, run]
  );

  const verified = useCallback(
    async (forMe: CouncilForMe, then: 'join' | 'enrolled') => {
      if (then === 'join') await join(forMe, false);
      else await load();
    },
    [join, load]
  );

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

  if (view.kind === 'verify') {
    const { forMe, then } = view;

    return (
      <VerifyCouncil
        council={council}
        identity={view.identity}
        userId={userId}
        banner={banner}
        busy={busy}
        onBack={() => (then === 'join' ? setView({ kind: 'accept', forMe, identity: view.identity, again: false }) : void load())}
        onVerified={() => verified(forMe, then)}
        fail={fail}
      />
    );
  }

  if (view.kind === 'accept') {
    const { forMe, identity, again } = view;

    return (
      <Screen
        back={back}
        title={again ? t('council.again_title') : t('council.accept_title', { council: council.label })}
        description={
          <>
            {again && <p>{t('council.again_explanation')}</p>}
            <p>{t('council.accept_explanation', { council: council.label, ...counts })}</p>
            <p>{t('council.accept_nobody_reads')}</p>
            {!again && identity && !identity.verified && <p>{t('council.join_later_hint')}</p>}
          </>
        }
        banner={banner}
        actions={
          <>
            <Button onClick={() => join(forMe, again)} disabled={busy || identity === null}>
              {busy ? t('council.accepting') : again ? t('council.again_button') : t('council.join_button')}
            </Button>
            {!again && identity && !identity.verified && (
              <Button variant="bordered" color="neutral" onClick={() => setView({ kind: 'verify', forMe, identity, then: 'join' })} disabled={busy}>
                {t('council.join_verify_button')}
              </Button>
            )}
          </>
        }
      >
        <div className={styles.section}>
          <div className={styles.cardHeader}>
            <p className={styles.sectionTitle}>{t('council.members', counts)}</p>
            {!again && identity?.verified && <VerifiedChip verified />}
          </div>
          <Members roster={roster} />
        </div>
      </Screen>
    );
  }

  const { forMe, identity } = view;
  const escrow = forMe.escrow!;
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
          {view.check === 'ok' && identity && !identity.verified && <Notice type={VariantType.INFO}>{t('council.enrolled_unverified')}</Notice>}
          {!council.configured && <Notice type={VariantType.INFO}>{t('council.not_configured_user')}</Notice>}
        </>
      }
      actions={
        <>
          {view.check === 'ok' && identity && !identity.verified && (
            <Button onClick={() => setView({ kind: 'verify', forMe, identity, then: 'enrolled' })}>{t('council.verify_open')}</Button>
          )}
          <Button
            variant={identity && !identity.verified ? 'bordered' : undefined}
            color={identity && !identity.verified ? 'neutral' : undefined}
            onClick={onClose}
          >
            {t('settings.done')}
          </Button>
        </>
      }
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
      {identity && (
        <div className={styles.section}>
          <div className={styles.cardHeader}>
            <p className={styles.sectionTitle}>{t('council.fingerprint_title')}</p>
            <VerifiedChip verified={identity.verified} />
          </div>
          <FingerprintBoxes fingerprint={identity.fingerprint} />
        </div>
      )}
    </Screen>
  );
}

interface VerifyCouncilProps {
  council: NonNullable<CouncilForMe['council']>;
  identity: CouncilIdentity;
  userId: string | null;
  banner: ReactNode;
  busy: boolean;
  onBack: () => void;
  onVerified: () => Promise<void>;
  fail: (err: unknown) => void;
}

/**
 * Either check is enough. The code proves the list is the one the organization
 * published. A custodian of version 1 the user knows proves it too: each member
 * of version 1 checked the next one before signing (the circle), so one real
 * person vouches for the whole list; later members never checked the others,
 * hence version 1 only.
 */
function VerifyCouncil({ council, identity, userId, banner, busy, onBack, onVerified, fail }: VerifyCouncilProps) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const { request } = useEncryptionContext();
  const [compared, setCompared] = useState(false);
  const [working, setWorking] = useState(false);
  const [people, setPeople] = useState<Array<{ userId: string; name: string; fingerprint: string }> | null>(null);

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      const genesis = council.chain[0];
      const rows = await Promise.all(
        genesis.members
          .filter((m) => m.user_id !== userId)
          .map(async (m) => ({ userId: m.user_id, name: m.name ?? `#${m.slot}`, fingerprint: await computeKeyFingerprint(m.identity_public_key) }))
      );
      if (!cancelled) setPeople(rows);
    })().catch(fail);

    return () => {
      cancelled = true;
    };
  }, [council, userId, fail]);

  const settle = useCallback(
    async (check: () => Promise<unknown>) => {
      setWorking(true);
      try {
        await check();
        await onVerified();
      } catch (err) {
        fail(err);
      } finally {
        setWorking(false);
      }
    },
    [onVerified, fail]
  );

  const disabled = busy || working;

  return (
    <Screen
      back={{ label: t('onboarding.btn_back'), onClick: onBack, disabled }}
      title={t('council.verify_title', { council: council.label })}
      description={t('council.verify_description')}
      banner={banner}
    >
      <div className={styles.section}>
        <p className={styles.sectionTitle}>{t('council.verify_code_title')}</p>
        <p className={styles.hint}>{t('council.fingerprint_hint')}</p>
        <FingerprintBoxes fingerprint={identity.fingerprint} />
        <Checkbox label={t('council.fingerprint_compared')} checked={compared} onChange={() => setCompared((value) => !value)} />
        <div>
          <Button size="small" onClick={() => settle(() => vault.markVerified(council.council_id, council.chain))} disabled={disabled || !compared}>
            {t('council.verify_code_confirm')}
          </Button>
        </div>
      </div>
      {people && people.length > 0 && (
        <div className={styles.section}>
          <p className={styles.sectionTitle}>{t('council.verify_person_title')}</p>
          <p className={styles.hint}>{t('council.verify_person_hint')}</p>
          {people.map((person) => (
            <IdentityCard key={person.userId} name={person.name} fingerprint={person.fingerprint}>
              <div>
                <Button
                  size="nano"
                  variant="bordered"
                  onClick={() => settle(() => request(MSG_VAULT_ACCEPT_FINGERPRINT, { userId: person.userId, fingerprint: person.fingerprint }))}
                  disabled={disabled}
                >
                  {t('council.verify_person_button')}
                </Button>
              </div>
            </IdentityCard>
          ))}
        </div>
      )}
    </Screen>
  );
}
