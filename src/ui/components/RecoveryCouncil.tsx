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
  | { kind: 'error' }
  | { kind: 'none' }
  | { kind: 'accept'; forMe: CouncilForMe; identity: CouncilIdentity | null; again: boolean; movingFrom?: string }
  | { kind: 'verify'; forMe: CouncilForMe; identity: CouncilIdentity; then: 'join' | 'enrolled'; movingFrom?: string }
  | { kind: 'enrolled'; forMe: CouncilForMe; check: CouncilEscrowCheck; identity: CouncilIdentity | null }
  | { kind: 'done'; label: string; movedFrom?: string };

function head(chain: RosterVersionWire[]): RosterVersionWire {
  return chain[chain.length - 1];
}

function Members({ roster, userId }: { roster: RosterVersionWire; userId: string | null }) {
  const { t } = useTranslation('common');

  return (
    <ul className={styles.people}>
      {roster.members.map((member) => (
        <li key={member.slot} className={styles.cardHeader}>
          <Identity name={member.name ?? `#${member.slot}`} />
          {member.user_id === userId && <Chip tone="info">{t('council.change_me')}</Chip>}
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

  // Joining the council the user's email maps to now, through the usual steps, on
  // a copy of what the server said with that council in place of the current one.
  const startMove = useCallback(
    async (forMe: CouncilForMe) => {
      const target: CouncilForMe = { ...forMe, council: forMe.move_to, escrow: null, move_to: null };
      const identity = await vault.verifyRoster(forMe.move_to!.council_id, forMe.move_to!.chain).catch((err: unknown) => {
        fail(err);

        return null;
      });
      setView({ kind: 'accept', forMe: target, identity, again: false, movingFrom: forMe.council?.label });
    },
    [vault, fail]
  );

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

      // Nothing left worth keeping on the previous council: joining is the move.
      if (forMe.move_to) {
        await startMove(forMe);

        return;
      }

      const again = escrow !== null && escrow.vault_active;
      // Setting up again starts from what the user already signed; the first time,
      // from version 1.
      const identity = await vault.verifyRoster(council.council_id, council.chain, again ? escrow!.record : undefined).catch((err: unknown) => {
        fail(err);

        return null;
      });
      setView({ kind: 'accept', forMe, identity, again });
    } catch (err) {
      // Not "no council": the answer did not come.
      fail(err);
      setView({ kind: 'error' });
    }
  }, [getIdToken, vault, fail, startVerifying, startMove]);

  useEffect(() => {
    // Wrapped so the state writes sit behind an await: the effect itself writes
    // nothing synchronously.
    void (async () => {
      await load();
    })();
  }, [load]);

  const join = useCallback(
    async (forMe: CouncilForMe, again: boolean, movedFrom?: string) => {
      const council = forMe.council!;

      await run(async () => {
        const body = await vault.createEscrow(
          council.council_id,
          council.chain,
          mnemonicLanguageForLocale(i18n.language),
          again ? forMe.escrow!.record : undefined
        );
        await withFreshIdToken(getIdToken, (idToken) => enrollCouncilEscrow(idToken, vault.sign, body));
        if (onboarding) onboarding.onJoined(council.label);
        else setView({ kind: 'done', label: council.label, movedFrom });
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
    async (forMe: CouncilForMe, then: 'join' | 'enrolled', movedFrom?: string) => {
      if (then === 'join') await join(forMe, false, movedFrom);
      else await load();
    },
    [join, load]
  );

  const back = onBack ? { label: t('onboarding.btn_back'), onClick: onBack } : undefined;

  if (view.kind === 'loading') return <LoadingScreen />;

  // In the onboarding, every screen ends the step.
  const later = onboarding ? (
    <Button variant="tertiary" color="neutral" onClick={onClose} disabled={busy}>
      {t('council.onboarding_later')}
    </Button>
  ) : null;

  if (view.kind === 'error') {
    return (
      <Screen
        back={back}
        title={t('council.title')}
        description={t('council.load_failed')}
        banner={banner}
        actions={
          <>
            <Button
              onClick={() => {
                setView({ kind: 'loading' });
                void load();
              }}
            >
              {t('council.retry')}
            </Button>
            {later}
          </>
        }
      />
    );
  }

  if (view.kind === 'none') {
    return (
      <Screen
        back={back}
        title={t('council.title')}
        description={t('council.none')}
        banner={banner}
        actions={onboarding ? <Button onClick={onClose}>{t('onboarding.btn_continue')}</Button> : undefined}
      />
    );
  }

  if (view.kind === 'done') {
    return (
      <Screen
        illustration="shield-check"
        title={t('council.done_title')}
        description={
          view.movedFrom
            ? t('council.done_moved_description', { council: view.label, from: view.movedFrom })
            : t('council.done_description', { council: view.label })
        }
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
        onBack={() =>
          then === 'join' ? setView({ kind: 'accept', forMe, identity: view.identity, again: false, movingFrom: view.movingFrom }) : void load()
        }
        onVerified={() => verified(forMe, then, view.movingFrom)}
        fail={fail}
      />
    );
  }

  if (view.kind === 'accept') {
    const { forMe, identity, again, movingFrom } = view;
    // Verifying ends in joining: offered only when the team can take a new setup.
    const canVerify = !again && identity !== null && !identity.verified && council.team_ready;
    const moving = movingFrom !== undefined;
    const isMember = roster.members.some((m) => m.user_id === userId);

    return (
      <Screen
        back={onboarding ? undefined : back}
        illustration={onboarding ? 'shield-restore' : undefined}
        title={moving ? t('council.move_title') : again ? t('council.again_title') : t('council.join_title')}
        description={
          moving ? (
            <>
              <p>
                {movingFrom === council.label
                  ? t('council.move_explanation_same_name')
                  : t('council.move_explanation', { from: movingFrom, to: council.label })}
              </p>
              {forMe.vaults.some((v) => !v.active) && (
                <p>{movingFrom === council.label ? t('council.move_keeps_older_same_name') : t('council.move_keeps_older', { from: movingFrom })}</p>
              )}
              <p>{t('council.onboarding_description', counts)}</p>
            </>
          ) : again ? (
            t('council.again_explanation')
          ) : (
            t('council.onboarding_description', counts)
          )
        }
        banner={
          <>
            {banner}
            {!council.team_ready && <Notice type={VariantType.WARNING}>{t('council.join_unavailable')}</Notice>}
            {isMember && (
              <Notice type={VariantType.INFO}>
                <div className={styles.alertStack}>
                  <span>{t('council.join_as_member', { threshold: roster.threshold, count: roster.members.length - 1 })}</span>
                  <span>{t('council.join_as_member_alternative')}</span>
                </div>
              </Notice>
            )}
          </>
        }
        actions={
          <>
            <Button onClick={() => join(forMe, again, movingFrom)} disabled={busy || identity === null || !council.team_ready}>
              {busy ? t('council.accepting') : moving ? t('council.move_button') : again ? t('council.again_button') : t('council.join_button')}
            </Button>
            {canVerify && (
              <Button
                variant="bordered"
                color="neutral"
                onClick={() => setView({ kind: 'verify', forMe, identity, then: 'join', movingFrom })}
                disabled={busy}
              >
                {moving ? t('council.move_verify_button') : t('council.join_verify_button')}
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
        <CouncilMembers council={council} userId={userId} chip={!again && identity?.verified ? <VerifiedChip verified /> : null} />
      </Screen>
    );
  }

  const { forMe, identity } = view;
  const health = forMe.escrow!.health;
  // With a move offered, verifying the team being left is moot: the move offers its own verification.
  const unverified = view.check === 'ok' && identity !== null && !identity.verified && !forMe.move_to;
  // One primary action per screen: the move, else the verification, else continuing.
  const secondary = forMe.move_to || unverified;

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
          {!council.configured && !forMe.move_to && <Notice type={VariantType.INFO}>{t('council.not_configured_user')}</Notice>}
          {forMe.move_to && (
            <Notice type={VariantType.INFO}>
              {forMe.move_to.label === council.label
                ? t('council.move_available_same_name')
                : t('council.move_available', { from: council.label, to: forMe.move_to.label })}
            </Notice>
          )}
        </>
      }
      actions={
        <>
          {forMe.move_to && (
            <Button onClick={() => void startMove(forMe)} disabled={busy}>
              {t('council.move_open')}
            </Button>
          )}
          {unverified && <Button onClick={() => setView({ kind: 'verify', forMe, identity, then: 'enrolled' })}>{t('council.verify_open')}</Button>}
          {onboarding ? (
            <Button variant={secondary ? 'bordered' : 'primary'} color={secondary ? 'neutral' : 'brand'} onClick={onClose}>
              {t('onboarding.btn_continue')}
            </Button>
          ) : (
            <Button variant="tertiary" color="neutral" onClick={() => setConfirmLeave(true)} disabled={busy}>
              {t('council.leave')}
            </Button>
          )}
        </>
      }
    >
      <CouncilMembers
        council={council}
        userId={userId}
        chip={
          view.check !== 'ok' ? null : unverified ? (
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
function CouncilMembers({ council, userId, chip }: { council: NonNullable<CouncilForMe['council']>; userId: string | null; chip: ReactNode }) {
  return (
    <div className={styles.section}>
      <div className={styles.cardHeader}>
        <p className={styles.sectionTitle}>{council.label}</p>
        {chip}
      </div>
      <Members roster={head(council.chain)} userId={userId} />
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
