import { Button, Checkbox, Modal, ModalSize, VariantType } from '@gouvfr-lasuite/ui-components';
import { type ReactNode, useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import { mnemonicLanguageForLocale } from '@encryption/src/crypto/mnemonic';
import { MSG_VAULT_ACCEPT_FINGERPRINT } from '@encryption/src/shared/constants';
import type { RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import { type CouncilForMe, enrollCouncilEscrow, fetchCouncilForMe, leaveCouncil } from '@encryption/src/ui/api/council-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { Chip, FingerprintBoxes, Identity } from '@encryption/src/ui/components/layout/IdentityCard';
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
  /**
   * Shown as a step of the onboarding: a shorter first screen, "later" skips it
   * (`onClose`), and joining hands back to the flow instead of a screen of its own.
   */
  onboarding?: { onJoined: (council: string) => void };
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
export function RecoveryCouncil({ getIdToken, userId = null, startVerifying = false, onBack, onClose, onboarding, ...auth }: RecoveryCouncilProps) {
  const { t, i18n } = useTranslation('common');
  const vault = useCouncilVault();
  const { banner, fail, busy: running, run } = useCouncilAction(auth);
  const busy = running !== null;
  const [view, setView] = useState<View>({ kind: 'loading' });
  const [confirmLeave, setConfirmLeave] = useState(false);

  // Wide enough for a list of people; a short message keeps the default width.
  useModalSize('medium', view.kind === 'accept' || view.kind === 'enrolled' || view.kind === 'verify');

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
        if (onboarding) onboarding.onJoined(council.label);
        else setView({ kind: 'done', label: council.label });
      });
    },
    [vault, getIdToken, i18n.language, run, onboarding]
  );

  // Signed by the vault like joining. Back to the joining screen afterwards.
  const leave = useCallback(
    () =>
      run(async () => {
        await withFreshIdToken(getIdToken, (idToken) => leaveCouncil(idToken, vault.sign));
        setConfirmLeave(false);
        await load();
      }),
    [run, getIdToken, vault, load]
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
    return <Screen back={back} title={t('council.title')} description={t('council.none')} banner={banner} />;
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
    const canVerify = !again && identity !== null && !identity.verified;

    return (
      <Screen
        back={onboarding ? undefined : back}
        illustration={onboarding ? 'shield-restore' : undefined}
        title={again ? t('council.again_title') : t('council.join_title')}
        description={again ? t('council.again_explanation') : t('council.onboarding_description', counts)}
        banner={banner}
        actions={
          <>
            <Button onClick={() => join(forMe, again)} disabled={busy || identity === null}>
              {busy ? t('council.accepting') : again ? t('council.again_button') : t('council.join_button')}
            </Button>
            {canVerify && (
              <Button variant="bordered" color="neutral" onClick={() => setView({ kind: 'verify', forMe, identity, then: 'join' })} disabled={busy}>
                {t('council.join_verify_button')}
              </Button>
            )}
            {onboarding && (
              <Button variant="tertiary" color="neutral" onClick={onClose} disabled={busy}>
                {t('council.onboarding_later')}
              </Button>
            )}
          </>
        }
      >
        <CouncilMembers council={council} chip={!again && identity?.verified ? <VerifiedChip verified /> : null} />
      </Screen>
    );
  }

  const { forMe, identity } = view;
  const health = forMe.escrow!.health;
  const unverified = view.check === 'ok' && identity !== null && !identity.verified;

  return (
    <Screen
      back={back}
      title={t('council.title')}
      description={t('council.enrolled_description', counts)}
      banner={
        <>
          {banner}
          {view.check !== 'ok' && (
            <Notice type={VariantType.ERROR}>{t(view.check === 'tampered' ? 'council.check_tampered' : 'council.check_chain_broken')}</Notice>
          )}
          {view.check === 'ok' && health.status === 'at-risk' && <Notice type={VariantType.WARNING}>{t('council.at_risk')}</Notice>}
          {view.check === 'ok' && health.outdated && <Notice type={VariantType.INFO}>{t('council.outdated')}</Notice>}
          {unverified && <Notice type={VariantType.INFO}>{t('council.enrolled_unverified')}</Notice>}
          {!council.configured && <Notice type={VariantType.INFO}>{t('council.not_configured_user')}</Notice>}
        </>
      }
      actions={
        <>
          {unverified && <Button onClick={() => setView({ kind: 'verify', forMe, identity, then: 'enrolled' })}>{t('council.verify_open')}</Button>}
          <Button variant="tertiary" color="neutral" onClick={() => setConfirmLeave(true)} disabled={busy}>
            {t('council.leave')}
          </Button>
        </>
      }
    >
      <CouncilMembers
        council={council}
        chip={
          view.check !== 'ok' ? null : identity && !identity.verified ? (
            <VerifiedChip verified={false} />
          ) : health.status === 'ok' ? (
            <Chip tone="success" icon="trusted">
              {t('council.chip_protected')}
            </Chip>
          ) : null
        }
      />

      <Modal
        isOpen={confirmLeave}
        onClose={() => setConfirmLeave(false)}
        closeOnClickOutside={false}
        size={ModalSize.SMALL}
        aria-label={t('council.leave_title')}
      >
        <Screen
          title={t('council.leave_title')}
          description={
            <>
              <p>{t('council.leave_body')}</p>
              <p>{t('council.leave_again')}</p>
            </>
          }
          banner={banner}
          actionsLayout="row"
          actions={
            <>
              <Button variant="bordered" color="neutral" onClick={() => setConfirmLeave(false)} disabled={busy}>
                {t('onboarding.btn_cancel')}
              </Button>
              <Button color="error" onClick={leave} disabled={busy}>
                {t('council.leave_confirm')}
              </Button>
            </>
          }
        />
      </Modal>
    </Screen>
  );
}

/** The council's name over the people in its current version: who can give the user their access back. */
function CouncilMembers({ council, chip }: { council: NonNullable<CouncilForMe['council']>; chip: ReactNode }) {
  return (
    <div className={styles.section}>
      <div className={styles.cardHeader}>
        <p className={styles.sectionTitle}>{council.label}</p>
        {chip}
      </div>
      <Members roster={head(council.chain)} />
    </div>
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
 * hence version 1 only. The code comes first; the custodians are the other way,
 * each one's code shown only when the user picks them.
 */
function VerifyCouncil({ council, identity, userId, banner, busy, onBack, onVerified, fail }: VerifyCouncilProps) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const { request } = useEncryptionContext();
  const [way, setWay] = useState<'code' | 'person'>('code');
  const [compared, setCompared] = useState(false);
  const [working, setWorking] = useState(false);
  const [people, setPeople] = useState<Array<{ userId: string; name: string; fingerprint: string }> | null>(null);
  const [comparing, setComparing] = useState<{ userId: string; name: string; fingerprint: string } | null>(null);

  useEffect(() => {
    let cancelled = false;

    void (async () => {
      const genesis = council.chain[0];
      const rows = await Promise.all(
        genesis.members
          .filter((m) => m.user_id !== userId)
          .map(async (m) => ({ userId: m.user_id, name: m.name ?? `#${m.slot}`, fingerprint: await computeKeyFingerprint(m.identity_public_key) }))
      );
      if (!cancelled) setPeople(rows.sort((a, b) => a.name.localeCompare(b.name)));
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
        setComparing(null);
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
  const canUsePerson = people !== null && people.length > 0;

  return (
    <Screen
      back={{ label: t('onboarding.btn_back'), onClick: onBack, disabled }}
      title={t('council.verify_title')}
      description={way === 'code' ? t('council.fingerprint_hint') : t('council.verify_person_hint')}
      banner={banner}
      actions={
        way === 'code' ? (
          <>
            <Button onClick={() => settle(() => vault.markVerified(council.council_id, council.chain))} disabled={disabled || !compared}>
              {t('council.verify_code_confirm')}
            </Button>
            {canUsePerson && (
              <Button variant="tertiary" color="neutral" onClick={() => setWay('person')} disabled={disabled}>
                {t('council.verify_with_person')}
              </Button>
            )}
          </>
        ) : (
          <Button variant="tertiary" color="neutral" onClick={() => setWay('code')} disabled={disabled}>
            {t('council.verify_with_code')}
          </Button>
        )
      }
    >
      {way === 'code' ? (
        <>
          <FingerprintBoxes fingerprint={identity.fingerprint} />
          <Checkbox label={t('council.fingerprint_compared')} checked={compared} onChange={() => setCompared((value) => !value)} />
        </>
      ) : (
        <ul className={styles.people}>
          {people!.map((person) => (
            <li key={person.userId} className={styles.cardHeader}>
              <Identity name={person.name} />
              <Button size="nano" variant="bordered" onClick={() => setComparing(person)} disabled={disabled}>
                {t('council.verify_person_compare')}
              </Button>
            </li>
          ))}
        </ul>
      )}

      <Modal
        isOpen={comparing !== null}
        onClose={() => setComparing(null)}
        closeOnClickOutside={false}
        size={ModalSize.MEDIUM}
        aria-label={t('council.verify_person_title')}
      >
        {comparing && (
          <Screen
            title={t('council.verify_person_modal_title', { name: comparing.name })}
            description={t('council.verify_person_modal_hint', { name: comparing.name })}
            banner={banner}
            actionsLayout="row"
            actions={
              <>
                <Button variant="bordered" color="neutral" onClick={() => setComparing(null)} disabled={disabled}>
                  {t('onboarding.btn_cancel')}
                </Button>
                <Button
                  onClick={() =>
                    settle(() => request(MSG_VAULT_ACCEPT_FINGERPRINT, { userId: comparing.userId, fingerprint: comparing.fingerprint }))
                  }
                  disabled={disabled}
                >
                  {t('council.verify_person_button')}
                </Button>
              </>
            }
          >
            <FingerprintBoxes fingerprint={comparing.fingerprint} />
          </Screen>
        )}
      </Modal>
    </Screen>
  );
}
