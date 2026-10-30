import { Button, DropdownMenu, type DropdownMenuItem, Modal, ModalSize, VariantType } from '@gouvfr-lasuite/ui-components';
import { Key, More, Shield, UserAdd, XMark } from '@gouvfr-lasuite/ui-components/icons';
import type { TFunction } from 'i18next';
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';

import { mnemonicLanguageForLocale } from '@encryption/src/crypto/mnemonic';
import {
  MSG_VAULT_ACCEPT_FINGERPRINT,
  MSG_VAULT_FETCH_PUBLIC_KEYS,
  MSG_VAULT_GET_KNOWN_FINGERPRINTS,
  MSG_VAULT_REFUSE_FINGERPRINT,
  MSG_VAULT_SIGN_REQUEST,
} from '@encryption/src/shared/constants';
import type { EmergencyGrantedEntry, EmergencyTrustedEntry } from '@encryption/src/shared/schemas/emergency-access';
import type { InterfaceContext } from '@encryption/src/shared/schemas/interface-context';
import { VaultErrorCode, isVaultError } from '@encryption/src/shared/vault-error';
import {
  acceptEmergencyDesignation,
  cancelEmergencyRecovery,
  deleteEmergencyAccess,
  designateEmergencyContact,
  fetchGrantedVaults,
  fetchTrustedContacts,
  initiateEmergencyRecovery,
  rearmEmergencyEscrow,
  recoverEmergencyCapsule,
  rejectEmergencyRecovery,
  searchEmergencyContact,
} from '@encryption/src/ui/api/emergency-client';
import { SessionExpiredError, withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { TrustRefuseButtons } from '@encryption/src/ui/components/RecipientFingerprintControls';
import { RecoveryKitBackup } from '@encryption/src/ui/components/RecoveryKitBackup';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import {
  type Countdown,
  MAX_WAIT_DAYS,
  MIN_WAIT_DAYS,
  WAIT_TIME_PRESETS,
  countdownTo,
  emergencyPhase,
  granteeName,
  grantorName,
  parseWaitDays,
  personName,
  rearmBodyFromDesignation,
} from '@encryption/src/ui/components/emergency-access-logic';
import { Chip, Identity, IdentityCard } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { type VaultRegisteredUser } from '@encryption/src/ui/components/verify-recipients-logic';
import { useModalSize } from '@encryption/src/ui/hooks/useModalSize';
import { useSessionExpired } from '@encryption/src/ui/hooks/useSessionExpired';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

type EscrowAuditStatus = 'ok' | 'tampered' | 'stale-identity' | 'outdated-key';

interface EmergencyAccessProps {
  getIdToken: () => Promise<string | null>;
  onBack?: () => void;
  onClose: () => void;
  onReconnect?: () => void;
  isAuthenticating?: boolean;
  onCancelAuth?: () => void;
  currentIdToken?: string | null;
  /** Set when the SDK auto-opened the interface on actionable state: leads with a prompt modal. */
  emergencyPending?: InterfaceContext['emergencyPending'] | null;
}

// Localized "in 44 days" / "dans 3 heures" via the browser's own relative-time
// formatter (no dependency): one natural unit, most-significant first, so the
// phrase reads well from a 90-day wait down to the final minutes. The sentence
// around it must NOT re-add "in"/"dans" (the formatter owns that word).
function countdownLabel(countdown: Countdown, locale: string): string {
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'always', style: 'long' });
  if (countdown.days > 0) return rtf.format(countdown.days, 'day');
  if (countdown.hours > 0) return rtf.format(countdown.hours, 'hour');
  return rtf.format(Math.max(countdown.minutes, 1), 'minute');
}

const CHIP_TONES = { invited: 'info', confirmed: 'success', requested: 'error', approved: 'warning' } as const;
const CHIP_ICONS = { invited: 'pending', confirmed: 'trusted', requested: 'alert', approved: 'unlocked' } as const;

function StatusChip({ phase, t }: { phase: 'invited' | 'confirmed' | 'requested' | 'approved'; t: TFunction }) {
  return (
    <Chip tone={CHIP_TONES[phase]} icon={CHIP_ICONS[phase]}>
      {t(`emergency.status_${phase}`)}
    </Chip>
  );
}

/** The "⋯" of a contact row: the design system's dropdown menu. */
function RowMenu({ label, options, disabled }: { label: string; options: DropdownMenuItem[]; disabled?: boolean }) {
  const [open, setOpen] = useState(false);

  return (
    <DropdownMenu options={options} isOpen={open} onOpenChange={setOpen}>
      <Button
        size="nano"
        variant="tertiary"
        color="neutral"
        aria-label={label}
        title={label}
        disabled={disabled}
        icon={<More aria-hidden size={16} />}
        onClick={() => setOpen(true)}
      />
    </DropdownMenu>
  );
}

/**
 * One person in the trusted contacts lists: who, their status, a menu, and,
 * under it, a tinted band for what this person's state asks of the user.
 */
function ContactRow({
  name,
  email,
  secondary,
  status,
  menu,
  band,
  bandTone = 'neutral',
}: {
  name: string;
  email: string;
  secondary?: string;
  status?: ReactNode;
  menu?: ReactNode;
  band?: ReactNode;
  bandTone?: 'neutral' | 'warning' | 'error';
}) {
  const bandClass = bandTone === 'error' ? styles.contactBandError : bandTone === 'warning' ? styles.contactBandWarning : '';

  return (
    <div className={styles.contact}>
      <div className={styles.contactMain}>
        <Identity name={name} email={email} secondary={secondary} />
        <div className={styles.cardAside}>
          {status}
          {menu}
        </div>
      </div>
      {band && <div className={`${styles.contactBand} ${bandClass}`}>{band}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Designation flow (sub-screen): email search -> out-of-band verification ->
// wait-time choice -> one-step designation (the escrow is created immediately).
// ---------------------------------------------------------------------------

interface DesignateFlowProps {
  getIdToken: () => Promise<string | null>;
  /** Pre-filled contact email (renewal after a stale identity): the search runs immediately. */
  prefillEmail?: string | null;
  onBack: () => void;
  onDesignated: () => void;
  markSessionExpired: () => void;
  banner?: ReactNode;
}

function DesignateFlow({ getIdToken, prefillEmail = null, onBack, onDesignated, markSessionExpired, banner }: DesignateFlowProps) {
  const { t, i18n } = useTranslation('common');
  const { request, createEmergencyEscrow } = useEncryptionContext();

  const [step, setStep] = useState<'email' | 'verify' | 'wait' | 'success'>('email');
  const [email, setEmail] = useState(prefillEmail ?? '');
  const [searchOutcome, setSearchOutcome] = useState<'not-found' | 'not-onboarded' | null>(null);
  const [contact, setContact] = useState<{ userId: string; name: string; email: string; fingerprint: string } | null>(null);
  const [waitChoice, setWaitChoice] = useState<number>(WAIT_TIME_PRESETS[1]);
  const [customWait, setCustomWait] = useState('');
  const [useCustom, setUseCustom] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = useCallback(
    async (target?: string) => {
      const query = (target ?? email).trim();

      if (!query) return;

      setBusy(true);
      setError(null);
      setSearchOutcome(null);

      try {
        const result = await withFreshIdToken(getIdToken, (idToken) => searchEmergencyContact(idToken, query));

        if (!result.user || !result.onboarded) {
          setSearchOutcome(result.user ? 'not-onboarded' : 'not-found');

          return;
        }

        const foundId = result.user.user_id;
        // The fingerprint shown for verification comes from the vault, which
        // only surfaces binding-verified directory records.
        const { users } = (await request(MSG_VAULT_FETCH_PUBLIC_KEYS, { userIds: [foundId] })) as {
          users: Record<string, VaultRegisteredUser>;
        };
        const entry = users[foundId];

        if (!entry || !entry.verified) {
          setSearchOutcome('not-onboarded');

          return;
        }

        const { fingerprints } = (await request(MSG_VAULT_GET_KNOWN_FINGERPRINTS)) as {
          fingerprints: Record<string, { fingerprint: string; status: 'unknown' | 'trusted' | 'refused' }>;
        };
        const known = fingerprints[foundId];
        const alreadyTrusted = known?.status === 'trusted' && known.fingerprint === entry.identityFingerprint;

        setContact({
          userId: foundId,
          name: personName(result.user.name, result.user.email),
          email: result.user.email,
          fingerprint: entry.identityFingerprint,
        });
        // Skip the verification step only when the contact is ALREADY trusted
        // with this exact fingerprint (the escrow op enforces it again anyway).
        setStep(alreadyTrusted ? 'wait' : 'verify');
      } catch (err) {
        if (err instanceof SessionExpiredError) markSessionExpired();
        else setError((err as Error).message);
      } finally {
        setBusy(false);
      }
    },
    [email, getIdToken, request, markSessionExpired]
  );

  // Renewal path: the contact email is known, run the search on arrival.
  const prefillSearched = useRef(false);

  useEffect(() => {
    if (!prefillEmail || prefillSearched.current) return;

    prefillSearched.current = true;
    handleSearch(prefillEmail);
  }, [prefillEmail, handleSearch]);

  const handleTrust = useCallback(async () => {
    if (!contact) return;

    setBusy(true);
    setError(null);

    try {
      // Internal user id: the directory search this flow came through already
      // resolved it, so the `sub` form (which would have to be resolved again)
      // never applies here.
      await request(MSG_VAULT_ACCEPT_FINGERPRINT, { userId: contact.userId, fingerprint: contact.fingerprint });
      setStep('wait');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }, [contact, request]);

  const handleRefuse = useCallback(async () => {
    if (!contact) return;

    setBusy(true);

    try {
      await request(MSG_VAULT_REFUSE_FINGERPRINT, { userId: contact.userId, fingerprint: contact.fingerprint });
    } catch {
      // Best-effort: refusing the designation aborts the flow regardless.
    } finally {
      setBusy(false);
      onBack();
    }
  }, [contact, request, onBack]);

  const effectiveWaitDays = useCustom ? parseWaitDays(customWait) : waitChoice;

  const handleDesignate = useCallback(async () => {
    if (!contact || effectiveWaitDays === null) return;

    setBusy(true);
    setError(null);

    try {
      const lang = mnemonicLanguageForLocale(i18n.language);
      const body = await createEmergencyEscrow(contact.userId, effectiveWaitDays, lang);

      // Covered route: sign the EXACT body we will send, then attach it.
      const json = JSON.stringify(body);
      const { signature } = (await request(MSG_VAULT_SIGN_REQUEST, { method: 'POST', path: '/api/emergency-access', body: json })) as {
        signature: string;
      };

      await withFreshIdToken(getIdToken, (idToken) => designateEmergencyContact(idToken, body, signature));
      setStep('success');
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        markSessionExpired();
      } else if (isVaultError(err) && err.code === VaultErrorCode.UNTRUSTED_RECIPIENT) {
        // Safety net: the vault refused to build the escrow because the contact
        // is not trusted. Send the user back to the verification step.
        setStep('verify');
        setError(t('emergency.designate_untrusted'));
      } else {
        setError((err as Error).message);
      }
    } finally {
      setBusy(false);
    }
  }, [contact, effectiveWaitDays, createEmergencyEscrow, request, getIdToken, i18n.language, markSessionExpired, t]);

  const errorAlert = error && <Notice type={VariantType.ERROR}>{error}</Notice>;

  if (step === 'success' && contact) {
    return (
      <Screen
        illustration="shield-check"
        title={t('emergency.designate_title')}
        description={t('emergency.designate_success', { name: contact.name })}
        actions={<Button onClick={onDesignated}>{t('emergency.btn_back_to_list')}</Button>}
      />
    );
  }

  if (step === 'verify' && contact) {
    return (
      <Screen
        title={t('emergency.designate_title')}
        description={t('emergency.designate_verify_required')}
        banner={
          <>
            {banner}
            {errorAlert}
          </>
        }
        back={{ label: t('onboarding.btn_back'), onClick: onBack, disabled: busy }}
        actions={<TrustRefuseButtons busy={busy} onTrust={handleTrust} onRefuse={handleRefuse} />}
      >
        <IdentityCard name={contact.name} email={contact.email} fingerprint={contact.fingerprint} />
        <p className={styles.hint}>{t('profile.compare_instruction')}</p>
      </Screen>
    );
  }

  if (step === 'wait' && contact) {
    return (
      <Screen
        title={t('emergency.designate_title')}
        description={t('emergency.designate_wait_explanation')}
        banner={
          <>
            {banner}
            {errorAlert}
          </>
        }
        actions={
          <>
            <Button onClick={handleDesignate} disabled={busy || effectiveWaitDays === null}>
              {busy ? t('emergency.designating') : t('emergency.btn_designate_confirm')}
            </Button>
            <Button variant="bordered" color="neutral" onClick={onBack} disabled={busy}>
              {t('emergency.btn_cancel')}
            </Button>
          </>
        }
      >
        <IdentityCard
          name={contact.name}
          email={contact.email}
          aside={
            <Chip tone="success" icon="trusted">
              {t('verify.trusted')}
            </Chip>
          }
        />

        <div className={styles.section}>
          <p className={styles.sectionTitle}>{t('emergency.designate_wait_title')}</p>
          <div className={styles.textLinks} style={{ justifyContent: 'flex-start' }}>
            {WAIT_TIME_PRESETS.map((days) => (
              <Button
                key={days}
                size="small"
                variant={!useCustom && waitChoice === days ? 'primary' : 'bordered'}
                onClick={() => {
                  setUseCustom(false);
                  setWaitChoice(days);
                }}
              >
                {t('emergency.wait_days_option', { count: days })}
              </Button>
            ))}
            <Button size="small" variant={useCustom ? 'primary' : 'bordered'} onClick={() => setUseCustom(true)}>
              {t('emergency.wait_custom')}
            </Button>
          </div>
          {useCustom && (
            <div className={styles.section}>
              <label className={styles.label} htmlFor="emergency-custom-wait">
                {t('emergency.wait_custom_label', { min: MIN_WAIT_DAYS, max: MAX_WAIT_DAYS })}
              </label>
              <input
                id="emergency-custom-wait"
                className={styles.input}
                type="number"
                min={MIN_WAIT_DAYS}
                max={MAX_WAIT_DAYS}
                value={customWait}
                onChange={(e) => setCustomWait(e.target.value)}
                style={{ maxWidth: 140 }}
              />
            </div>
          )}
          <p className={styles.hint}>{t('emergency.designate_wait_hint')}</p>
        </div>

        <div className={styles.section}>
          <p className={styles.sectionTitle}>{t('emergency.designate_scope_title')}</p>
          <ul className={styles.list}>
            <li>{t('emergency.designate_scope_1')}</li>
            <li>{t('emergency.designate_scope_2')}</li>
            <li>{t('emergency.designate_scope_3')}</li>
          </ul>
        </div>
      </Screen>
    );
  }

  // Step 1: exact-email search.
  return (
    <Screen
      title={t('emergency.designate_title')}
      description={t('emergency.designate_intro')}
      banner={
        <>
          {banner}
          {errorAlert}
        </>
      }
      back={{ label: t('onboarding.btn_back'), onClick: onBack, disabled: busy }}
    >
      <div>
        <label className={styles.label} htmlFor="emergency-contact-email">
          {t('emergency.designate_email_label')}
        </label>
        <div className={styles.settingsRow}>
          <input
            id="emergency-contact-email"
            className={styles.input}
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleSearch();
            }}
            placeholder={t('emergency.designate_email_placeholder')}
          />
          <Button onClick={() => handleSearch()} disabled={busy || email.trim().length === 0}>
            {busy ? t('emergency.searching') : t('emergency.btn_search')}
          </Button>
        </div>
      </div>

      {searchOutcome === 'not-found' && <Notice type={VariantType.INFO}>{t('emergency.designate_not_found')}</Notice>}
      {searchOutcome === 'not-onboarded' && <Notice type={VariantType.INFO}>{t('emergency.designate_not_onboarded')}</Notice>}
    </Screen>
  );
}

// ---------------------------------------------------------------------------
// Reveal flow (contact side): pull the released capsule, open it in the vault,
// render the GRANTOR's kit for the physical handover.
// ---------------------------------------------------------------------------

interface RevealViewProps {
  entry: EmergencyGrantedEntry;
  getIdToken: () => Promise<string | null>;
  onDone: () => void;
  markSessionExpired: () => void;
  banner?: ReactNode;
}

function RevealView({ entry, getIdToken, onDone, markSessionExpired, banner }: RevealViewProps) {
  const { t } = useTranslation('common');
  const { isReady, request, revealEmergencyPhrase } = useEncryptionContext();

  const [phrase, setPhrase] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [untrustedGrantor, setUntrustedGrantor] = useState(false);
  const [grantorFingerprint, setGrantorFingerprint] = useState<string | null>(null);
  const [approving, setApproving] = useState(false);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (!isReady) return;

    let cancelled = false;

    (async () => {
      try {
        const path = `/api/emergency-access/${encodeURIComponent(entry.id)}/recover`;
        const { signature } = (await request(MSG_VAULT_SIGN_REQUEST, { method: 'POST', path })) as { signature: string };
        const released = await withFreshIdToken(getIdToken, (idToken) => recoverEmergencyCapsule(idToken, entry.id, signature));
        const { recoveryPhrase } = await revealEmergencyPhrase({
          grantorUserId: released.grantor_user_id,
          lang: released.lang,
          waitTimeDays: released.wait_time_days,
          escrow: released.escrow,
        });

        if (!cancelled) setPhrase(recoveryPhrase);
      } catch (err) {
        if (cancelled) return;
        if (err instanceof SessionExpiredError) markSessionExpired();
        else if (isVaultError(err) && err.code === VaultErrorCode.UNTRUSTED_RECIPIENT) {
          setUntrustedGrantor(true);
          // Pull the owner's fingerprint so it can be shown for verification.
          try {
            const { users } = (await request(MSG_VAULT_FETCH_PUBLIC_KEYS, { userIds: [entry.grantor_user_id] })) as {
              users: Record<string, VaultRegisteredUser>;
            };
            if (!cancelled) setGrantorFingerprint(users[entry.grantor_user_id]?.identityFingerprint ?? null);
          } catch {
            // Leave it null: the warning still shows, just without the code to compare.
          }
        } else setError((err as Error).message);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [attempt, isReady, entry.id, entry.grantor_user_id, request, getIdToken, revealEmergencyPhrase, markSessionExpired]);

  // The contact confirms the owner's identity out-of-band, then the reveal re-runs.
  const handleApproveGrantor = useCallback(async () => {
    if (!grantorFingerprint) return;
    setApproving(true);
    setError(null);

    try {
      await request(MSG_VAULT_ACCEPT_FINGERPRINT, { userId: entry.grantor_user_id, fingerprint: grantorFingerprint });
      setUntrustedGrantor(false);
      setGrantorFingerprint(null);
      setAttempt((a) => a + 1);
    } catch (err) {
      if (err instanceof SessionExpiredError) markSessionExpired();
      else setError((err as Error).message);
    } finally {
      setApproving(false);
    }
  }, [grantorFingerprint, entry.grantor_user_id, request, markSessionExpired]);

  const back = { label: t('emergency.btn_back_to_list'), onClick: onDone };
  const description = (
    <>
      <p>
        <strong>{t('emergency.reveal_grantor', { name: grantorName(entry) })}</strong>
      </p>
      <ul className={styles.list}>
        <li>{t('emergency.reveal_instruction_1')}</li>
        <li>{t('emergency.reveal_instruction_2')}</li>
        <li>{t('emergency.reveal_instruction_3')}</li>
        <li>{t('emergency.reveal_instruction_4')}</li>
      </ul>
    </>
  );

  if (error) {
    return <Screen back={back} title={t('emergency.reveal_title')} banner={<Notice type={VariantType.ERROR}>{error}</Notice>} />;
  }

  if (untrustedGrantor) {
    return (
      <Screen
        back={back}
        title={t('emergency.reveal_title')}
        description={t('emergency.reveal_untrusted_grantor', { name: grantorName(entry) })}
        banner={banner}
        actions={
          grantorFingerprint && (
            <TrustRefuseButtons
              busy={approving}
              onTrust={handleApproveGrantor}
              onRefuse={onDone}
              trustLabel={t('emergency.btn_grantor_verified')}
              refuseLabel={t('emergency.btn_back_to_list')}
            />
          )
        }
      >
        {grantorFingerprint && <IdentityCard name={grantorName(entry)} email={entry.grantor_email} fingerprint={grantorFingerprint} tone="warning" />}
      </Screen>
    );
  }

  if (!phrase) {
    return <LoadingScreen />;
  }

  return (
    <RecoveryKitBackup
      mode="handover"
      back={back}
      title={t('emergency.reveal_title')}
      description={
        <>
          {description}
          <p>{t('emergency.reveal_still_available')}</p>
        </>
      }
      banner={banner}
      passphrase={phrase}
      parentOrigin={null}
      onConfirm={onDone}
      confirmLabel={t('emergency.reveal_done')}
    />
  );
}

// ---------------------------------------------------------------------------
// Main screen: the two lists (contacts I trust with my vault / vaults
// entrusted to me), the per-row actions, the audit results and the prompt
// modal when the SDK auto-opened the interface on actionable state.
// ---------------------------------------------------------------------------

export function EmergencyAccess({
  getIdToken,
  onBack,
  onClose,
  onReconnect,
  isAuthenticating = false,
  onCancelAuth,
  currentIdToken = null,
  emergencyPending = null,
}: EmergencyAccessProps) {
  const { t, i18n } = useTranslation('common');
  const { isReady, request, createEmergencyEscrow, verifyEscrows } = useEncryptionContext();
  const { sessionExpired, markSessionExpired } = useSessionExpired(currentIdToken, isAuthenticating);

  // The lists need the wide modal, the steps of a designation or a reveal too.
  useModalSize('medium');

  const [view, setView] = useState<'list' | 'designate' | 'reveal'>('list');
  const [designatePrefill, setDesignatePrefill] = useState<string | null>(null);
  const [revealEntry, setRevealEntry] = useState<EmergencyGrantedEntry | null>(null);

  const [trusted, setTrusted] = useState<EmergencyTrustedEntry[] | null>(null);
  const [granted, setGranted] = useState<EmergencyGrantedEntry[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [audit, setAudit] = useState<Record<string, EscrowAuditStatus>>({});

  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{ kind: 'revoke' | 'decline' | 'request'; entry: EmergencyTrustedEntry | EmergencyGrantedEntry } | null>(
    null
  );

  // Coarse clock for the live countdowns (minute precision is plenty).
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 30_000);

    return () => clearInterval(interval);
  }, []);

  const fetchLists = useCallback(async () => {
    try {
      const [trustedRes, grantedRes] = await withFreshIdToken(getIdToken, (idToken) =>
        Promise.all([fetchTrustedContacts(idToken), fetchGrantedVaults(idToken)])
      );

      setTrusted(trustedRes.contacts);
      setGranted(grantedRes.grantors);
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        markSessionExpired();
        setTrusted((prev) => prev ?? []);
        setGranted((prev) => prev ?? []);
      } else {
        setLoadError((err as Error).message);
      }
    }
  }, [getIdToken, markSessionExpired]);

  const loadLists = useCallback(async () => {
    setLoadError(null);

    await fetchLists();
  }, [fetchLists]);

  useEffect(() => {
    // Wrapped in an async function rather than called directly: that puts the state
    // writes behind an await, so the effect itself writes nothing synchronously and
    // React does not have to render a second time before painting.
    void (async () => {
      await fetchLists();
    })();
  }, [fetchLists]);

  // Audit the escrow list in the vault (signature + pinned identity + key
  // version against the directory). Only rows on the ACTIVE vault are
  // auditable: a previous vault's escrows were signed by a different identity.
  useEffect(() => {
    if (!isReady || !trusted) return;

    const auditable = trusted.filter((contact) => contact.vault_active !== false);

    let cancelled = false;

    const audited =
      auditable.length === 0
        ? Promise.resolve({ results: [] as Awaited<ReturnType<typeof verifyEscrows>>['results'] })
        : verifyEscrows(auditable.map(({ id, grantee_user_id, wait_time_days, escrow }) => ({ id, grantee_user_id, wait_time_days, escrow })));

    audited
      .then(({ results }) => {
        if (!cancelled) setAudit(Object.fromEntries(results.map((r) => [r.id, r.status])));
      })
      .catch(() => {
        // No vault on this device (or the directory is unreachable): the audit
        // is a defense-in-depth surface, the lists stay usable without it.
        if (!cancelled) setAudit({});
      });

    return () => {
      cancelled = true;
    };
  }, [isReady, trusted, verifyEscrows]);

  // Lead with the prompt when the SDK auto-opened the interface on actionable state.
  const [promptDismissed, setPromptDismissed] = useState(false);
  const prompt: 'recovery' | 'invite' | null = promptDismissed
    ? null
    : emergencyPending?.recovery && trusted?.some((c) => c.status === 'recoveryRequested' || c.status === 'recoveryApproved')
      ? 'recovery'
      : emergencyPending?.invitation && granted?.some((g) => g.status === 'invited')
        ? 'invite'
        : null;

  const runRowAction = useCallback(
    async (id: string, action: () => Promise<void>) => {
      setBusyId(id);
      setActionError(null);
      setNotice(null);

      try {
        await action();
        await loadLists();
      } catch (err) {
        if (err instanceof SessionExpiredError) markSessionExpired();
        else setActionError((err as Error).message);
      } finally {
        setBusyId(null);
      }
    },
    [loadLists, markSessionExpired]
  );

  const handleReject = useCallback(
    (entry: EmergencyTrustedEntry) =>
      runRowAction(entry.id, async () => {
        await withFreshIdToken(getIdToken, (idToken) => rejectEmergencyRecovery(idToken, entry.id));
        setNotice(t('emergency.reject_done', { name: granteeName(entry) }));
      }),
    [runRowAction, getIdToken, t]
  );

  const handleRevoke = useCallback(
    (entry: EmergencyTrustedEntry | EmergencyGrantedEntry) =>
      runRowAction(entry.id, async () => {
        await withFreshIdToken(getIdToken, (idToken) => deleteEmergencyAccess(idToken, entry.id));
      }),
    [runRowAction, getIdToken]
  );

  const handleAccept = useCallback(
    (entry: EmergencyGrantedEntry) =>
      runRowAction(entry.id, async () => {
        await withFreshIdToken(getIdToken, (idToken) => acceptEmergencyDesignation(idToken, entry.id));
      }),
    [runRowAction, getIdToken]
  );

  const handleCancelRequest = useCallback(
    (entry: EmergencyGrantedEntry) =>
      runRowAction(entry.id, async () => {
        await withFreshIdToken(getIdToken, (idToken) => cancelEmergencyRecovery(idToken, entry.id));
      }),
    [runRowAction, getIdToken]
  );

  // Contact side: start a recovery. Identity-signed (empty body), so a stolen
  // session alone cannot trigger it.
  const handleRequestAccess = useCallback(
    (entry: EmergencyGrantedEntry) =>
      runRowAction(entry.id, async () => {
        const path = `/api/emergency-access/${encodeURIComponent(entry.id)}/initiate`;
        const { signature } = (await request(MSG_VAULT_SIGN_REQUEST, { method: 'POST', path })) as { signature: string };

        await withFreshIdToken(getIdToken, (idToken) => initiateEmergencyRecovery(idToken, entry.id, signature));
      }),
    [runRowAction, request, getIdToken]
  );

  // One-click re-arm after the contact rotated their encryption key: fresh
  // escrow at the same wait time, signed over the exact rearm body.
  const handleUpdateEscrow = useCallback(
    (entry: EmergencyTrustedEntry) =>
      runRowAction(entry.id, async () => {
        try {
          const lang = mnemonicLanguageForLocale(i18n.language);
          const designation = await createEmergencyEscrow(entry.grantee_user_id, entry.wait_time_days, lang);
          const rearmBody = rearmBodyFromDesignation(designation);
          const path = `/api/emergency-access/${encodeURIComponent(entry.id)}/rearm`;
          const json = JSON.stringify(rearmBody);
          const { signature } = (await request(MSG_VAULT_SIGN_REQUEST, { method: 'POST', path, body: json })) as { signature: string };

          await withFreshIdToken(getIdToken, (idToken) => rearmEmergencyEscrow(idToken, entry.id, rearmBody, signature));
        } catch (err) {
          if (isVaultError(err) && err.code === VaultErrorCode.UNTRUSTED_RECIPIENT) {
            throw new Error(t('emergency.designate_untrusted'), { cause: err });
          }
          throw err;
        }
      }),
    [runRowAction, createEmergencyEscrow, request, getIdToken, i18n.language, t]
  );

  // Stale identity: the pinned contact identity no longer matches the
  // directory, so the escrow cannot be opened by anyone. Renew = revoke, then
  // re-designate the same person (their new identity must be re-verified).
  const handleRenew = useCallback(
    (entry: EmergencyTrustedEntry) =>
      runRowAction(entry.id, async () => {
        await withFreshIdToken(getIdToken, (idToken) => deleteEmergencyAccess(idToken, entry.id));
        setDesignatePrefill(entry.grantee_email);
        setView('designate');
      }),
    [runRowAction, getIdToken]
  );

  const handlePromptRefuseAll = useCallback(async () => {
    const requests = (trusted ?? []).filter((c) => c.status === 'recoveryRequested' || c.status === 'recoveryApproved');

    setBusyId('prompt');
    setActionError(null);

    try {
      await withFreshIdToken(getIdToken, async (idToken) => {
        for (const req of requests) {
          await rejectEmergencyRecovery(idToken, req.id);
        }
      });
      setNotice(t('emergency.reject_done', { name: requests.map(granteeName).join(', ') }));
      setPromptDismissed(true);
      await loadLists();
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        markSessionExpired();
        setPromptDismissed(true);
      } else {
        setActionError((err as Error).message);
        setPromptDismissed(true);
      }
    } finally {
      setBusyId(null);
    }
  }, [trusted, getIdToken, loadLists, markSessionExpired, t]);

  const dateFormatter = new Intl.DateTimeFormat(i18n.language, { dateStyle: 'long' });
  const timeFormatter = new Intl.DateTimeFormat(i18n.language, { timeStyle: 'short' });

  // Sub-screens replace the whole view (early-return pattern).
  // When the SDK auto-opened us over a product, the host iframe is a bare
  // transparent full-viewport layer: we must draw our OWN modal chrome (backdrop
  // + centered card), exactly like VerifyRecipients, or the page sprawls
  // full-width and see-through over the product. Navigated normally (the settings
  // sub-page), we ARE the page, so the host modal already frames us.
  // The SDK sets that context only when it opened us on its own.
  const isOverlay = emergencyPending !== null;
  const frame = (children: ReactNode, open = true): ReactNode =>
    isOverlay ? (
      <Modal isOpen={open} onClose={onClose} closeOnClickOutside={false} size={ModalSize.MEDIUM} aria-label={t('emergency.title')}>
        {children}
      </Modal>
    ) : (
      children
    );

  const sessionBanner = sessionExpired && onReconnect && (
    <SessionExpiredAlert onReconnect={onReconnect} onCancel={onCancelAuth} isAuthenticating={isAuthenticating} />
  );

  if (view === 'designate') {
    return frame(
      <DesignateFlow
        getIdToken={getIdToken}
        prefillEmail={designatePrefill}
        banner={sessionBanner}
        onBack={() => {
          setDesignatePrefill(null);
          setView('list');
        }}
        onDesignated={() => {
          setDesignatePrefill(null);
          setView('list');
          loadLists();
        }}
        markSessionExpired={markSessionExpired}
      />
    );
  }

  if (view === 'reveal' && revealEntry) {
    return frame(
      <RevealView
        entry={revealEntry}
        getIdToken={getIdToken}
        banner={sessionBanner}
        onDone={() => {
          setRevealEntry(null);
          setView('list');
        }}
        markSessionExpired={markSessionExpired}
      />
    );
  }

  const loading = trusted === null || granted === null;
  const pendingRequests = (trusted ?? []).filter((c) => c.status === 'recoveryRequested' || c.status === 'recoveryApproved');

  return (
    <>
      {/* Prompt modals stay at the TOP level (outside frame) so exactly one dialog
          is open at a time: in the product overlay the frame card below is closed
          while a prompt shows (frame's isOpen={!prompt}), matching verify-recipients. */}
      <Modal
        isOpen={prompt === 'recovery'}
        onClose={busyId === 'prompt' ? () => undefined : onClose}
        closeOnClickOutside={false}
        size={ModalSize.SMALL}
        aria-label={t('emergency.prompt_recovery_title')}
      >
        <Screen
          illustration="shield-x"
          title={t('emergency.prompt_recovery_title')}
          description={pendingRequests.map((req) => (
            <p key={req.id}>
              <Trans
                t={t}
                i18nKey={
                  emergencyPhase(req, now) === 'approved' || req.deadline_millis === null
                    ? 'emergency.prompt_recovery_approved'
                    : 'emergency.prompt_recovery_body'
                }
                values={{ name: granteeName(req) }}
                components={{ strong: <strong /> }}
              />
            </p>
          ))}
          actions={
            <Button color="error" onClick={handlePromptRefuseAll} disabled={busyId === 'prompt'}>
              {busyId === 'prompt' ? t('emergency.refusing') : t('emergency.btn_prompt_refuse')}
            </Button>
          }
        >
          {/* The date is the one thing to retain: its own box, large. */}
          {pendingRequests
            .filter((req) => emergencyPhase(req, now) !== 'approved' && req.deadline_millis !== null)
            .map((req) => (
              <div key={req.id} className={styles.deadline}>
                <span className={styles.groupLabel}>{t('emergency.prompt_recovery_deadline')}</span>
                <span className={styles.deadlineValue}>{dateFormatter.format(new Date(req.deadline_millis as number))}</span>
                <span className={styles.deadlineTime}>{timeFormatter.format(new Date(req.deadline_millis as number))}</span>
              </div>
            ))}
          <p className={styles.hint}>{t('emergency.prompt_recovery_hint')}</p>
          <p className={styles.hint}>{t('emergency.prompt_recovery_hint_refuse')}</p>
        </Screen>
      </Modal>

      <Modal
        isOpen={prompt === 'invite'}
        onClose={() => setPromptDismissed(true)}
        closeOnClickOutside={false}
        size={ModalSize.SMALL}
        aria-label={t('emergency.prompt_invite_title')}
      >
        <Screen
          illustration="shield-check"
          title={t('emergency.prompt_invite_title')}
          description={t('emergency.prompt_invite_body')}
          actions={<Button onClick={() => setPromptDismissed(true)}>{t('emergency.btn_prompt_see_invite')}</Button>}
        />
      </Modal>

      {/* Shared confirmation dialog for the destructive / serious actions. */}
      <Modal
        isOpen={confirm !== null}
        onClose={() => setConfirm(null)}
        closeOnClickOutside={false}
        size={ModalSize.SMALL}
        aria-label={confirm ? t(`emergency.confirm_${confirm.kind}_title`) : undefined}
      >
        {confirm && (
          <Screen
            title={t(`emergency.confirm_${confirm.kind}_title`)}
            description={
              <p>
                {confirm.kind === 'revoke' && (
                  <Trans
                    t={t}
                    i18nKey="emergency.confirm_revoke_body"
                    values={{ name: granteeName(confirm.entry as EmergencyTrustedEntry) }}
                    components={{ strong: <strong /> }}
                  />
                )}
                {confirm.kind === 'decline' && (
                  <Trans
                    t={t}
                    i18nKey="emergency.confirm_decline_body"
                    values={{ name: grantorName(confirm.entry as EmergencyGrantedEntry) }}
                    components={{ strong: <strong /> }}
                  />
                )}
                {confirm.kind === 'request' && (
                  <Trans
                    t={t}
                    i18nKey="emergency.confirm_request_body"
                    values={{ name: grantorName(confirm.entry as EmergencyGrantedEntry), count: confirm.entry.wait_time_days }}
                    components={{ strong: <strong /> }}
                  />
                )}
              </p>
            }
            actions={
              <>
                <Button
                  color={confirm.kind === 'request' ? undefined : 'error'}
                  onClick={() => {
                    const { kind, entry } = confirm;

                    setConfirm(null);

                    if (kind === 'revoke') handleRevoke(entry as EmergencyTrustedEntry);
                    else if (kind === 'decline') handleRevoke(entry as EmergencyGrantedEntry);
                    else handleRequestAccess(entry as EmergencyGrantedEntry);
                  }}
                >
                  {t(`emergency.confirm_${confirm.kind}_button`)}
                </Button>
                <Button variant="bordered" color="neutral" onClick={() => setConfirm(null)}>
                  {t('emergency.btn_cancel')}
                </Button>
              </>
            }
          />
        )}
      </Modal>

      {frame(
        <Screen
          back={onBack && !isOverlay ? { label: t('onboarding.btn_back'), onClick: onBack } : undefined}
          title={t('emergency.title')}
          description={t('emergency.intro')}
          banner={
            <>
              {sessionBanner}
              {notice && <Notice type={VariantType.SUCCESS}>{notice}</Notice>}
              {actionError && <Notice type={VariantType.ERROR}>{actionError}</Notice>}
              {loadError && <Notice type={VariantType.ERROR}>{loadError}</Notice>}
            </>
          }
        >
          {loading && !loadError ? (
            <LoadingScreen />
          ) : (
            <>
              {/* Section A: contacts I designated (grantor side). */}
              <div className={styles.section}>
                <div className={styles.sectionHeader}>
                  <p className={styles.sectionTitle}>{t('emergency.trusted_title')}</p>
                  <p className={styles.sectionSubtitle}>{t('emergency.trusted_subtitle')}</p>
                </div>

                {trusted && trusted.length === 0 && <div className={styles.empty}>{t('emergency.trusted_empty')}</div>}

                {(trusted ?? []).map((entry) => {
                  const phase = emergencyPhase(entry, now);
                  const rowAudit = entry.vault_active === false ? undefined : audit[entry.id];
                  const countdown = entry.deadline_millis !== null ? countdownTo(entry.deadline_millis, now) : null;
                  const busy = busyId === entry.id;
                  const recoveryRunning = rowAudit !== 'tampered' && (phase === 'requested' || phase === 'approved');

                  // One band per row: what is wrong with the escrow first, then a
                  // running recovery, then what is merely informative.
                  let band: ReactNode = null;
                  let bandTone: 'neutral' | 'warning' | 'error' = 'neutral';

                  if (rowAudit === 'tampered') {
                    // A recovery running on a tampered escrow must still be stoppable.
                    band = (
                      <>
                        <span>{t('emergency.audit_tampered')}</span>
                        {(phase === 'requested' || phase === 'approved') && (
                          <Button size="nano" color="error" disabled={busy} onClick={() => handleReject(entry)}>
                            {phase === 'approved' ? t('emergency.btn_relock') : t('emergency.btn_refuse_request')}
                          </Button>
                        )}
                      </>
                    );
                    bandTone = 'error';
                  } else if (recoveryRunning) {
                    bandTone = 'error';
                    band = (
                      <>
                        <span>
                          {phase !== 'approved' && countdown && !countdown.expired ? (
                            <Trans
                              t={t}
                              i18nKey="emergency.trusted_requested_warning"
                              values={{ name: granteeName(entry), time: countdownLabel(countdown, i18n.language) }}
                              components={{ strong: <strong /> }}
                            />
                          ) : (
                            t('emergency.trusted_approved_warning', { name: granteeName(entry) })
                          )}
                        </span>
                        <Button size="nano" color="error" disabled={busy} onClick={() => handleReject(entry)}>
                          {phase === 'approved' ? t('emergency.btn_relock') : t('emergency.btn_refuse_request')}
                        </Button>
                      </>
                    );
                  } else if (rowAudit === 'stale-identity') {
                    bandTone = 'warning';
                    band = (
                      <>
                        <span>{t('emergency.audit_stale')}</span>
                        <Button size="nano" variant="secondary" color="warning" disabled={busy} onClick={() => handleRenew(entry)}>
                          {t('emergency.btn_renew')}
                        </Button>
                      </>
                    );
                  } else if (rowAudit === 'outdated-key') {
                    band = (
                      <>
                        <span>{t('emergency.audit_outdated')}</span>
                        <Button size="nano" variant="secondary" color="neutral" disabled={busy} onClick={() => handleUpdateEscrow(entry)}>
                          {t('emergency.btn_update_escrow')}
                        </Button>
                      </>
                    );
                  } else if (entry.vault_active === false) {
                    band = <span>{t('emergency.vault_inactive_note')}</span>;
                  }

                  return (
                    <ContactRow
                      key={entry.id}
                      name={granteeName(entry)}
                      email={entry.grantee_email}
                      secondary={t('emergency.wait_label', { count: entry.wait_time_days })}
                      status={phase !== 'confirmed' && <StatusChip phase={phase} t={t} />}
                      band={band}
                      bandTone={bandTone}
                      menu={
                        <RowMenu
                          label={t('emergency.row_menu', { name: granteeName(entry) })}
                          disabled={busy}
                          options={[
                            {
                              label: t('emergency.btn_revoke'),
                              icon: <XMark aria-hidden size={16} />,
                              callback: () => setConfirm({ kind: 'revoke', entry }),
                            },
                          ]}
                        />
                      }
                    />
                  );
                })}

                <Button
                  className={styles.textLink}
                  size="nano"
                  variant="bordered"
                  color="neutral"
                  onClick={() => setView('designate')}
                  icon={<UserAdd aria-hidden size={16} />}
                >
                  {t('emergency.btn_designate')}
                </Button>
              </div>

              {/* Section B: vaults entrusted to me (contact side). */}
              <div className={styles.section}>
                <div className={styles.sectionHeader}>
                  <p className={styles.sectionTitle}>{t('emergency.granted_title')}</p>
                  <p className={styles.sectionSubtitle}>{t('emergency.granted_subtitle')}</p>
                </div>

                {granted && granted.length === 0 && <div className={styles.empty}>{t('emergency.granted_empty')}</div>}

                {(granted ?? []).map((entry) => {
                  const phase = emergencyPhase(entry, now);
                  const countdown = entry.deadline_millis !== null ? countdownTo(entry.deadline_millis, now) : null;
                  const busy = busyId === entry.id;

                  let band: ReactNode = null;
                  let bandTone: 'neutral' | 'warning' = 'neutral';

                  if (phase === 'invited') {
                    band = (
                      <>
                        <span>{t('emergency.granted_invited_text', { name: grantorName(entry) })}</span>
                        <Button size="nano" variant="bordered" color="error" disabled={busy} onClick={() => setConfirm({ kind: 'decline', entry })}>
                          {t('emergency.btn_decline')}
                        </Button>
                        <Button size="nano" disabled={busy} onClick={() => handleAccept(entry)}>
                          {t('emergency.btn_accept')}
                        </Button>
                      </>
                    );
                  } else if (phase === 'requested' && countdown && !countdown.expired) {
                    bandTone = 'warning';
                    band = <span>{t('emergency.granted_requested_text', { time: countdownLabel(countdown, i18n.language) })}</span>;
                  } else if (phase === 'approved') {
                    bandTone = 'warning';
                    band = (
                      <>
                        <span>{t('emergency.granted_approved_text', { name: grantorName(entry) })}</span>
                        <Button
                          size="nano"
                          disabled={busy}
                          icon={<Key aria-hidden size={16} />}
                          onClick={() => {
                            setRevealEntry(entry);
                            setView('reveal');
                          }}
                        >
                          {t('emergency.btn_reveal')}
                        </Button>
                      </>
                    );
                  }

                  const options: DropdownMenuItem[] = [];

                  if (phase === 'confirmed') {
                    options.push({
                      label: t('emergency.btn_request_access'),
                      icon: <Shield aria-hidden size={16} />,
                      callback: () => setConfirm({ kind: 'request', entry }),
                    });
                  }
                  if (phase === 'requested') {
                    options.push({
                      label: t('emergency.btn_cancel_request'),
                      icon: <XMark aria-hidden size={16} />,
                      callback: () => handleCancelRequest(entry),
                    });
                  }
                  if (phase !== 'invited') {
                    options.push({
                      label: t('emergency.btn_stop_being_contact'),
                      icon: <XMark aria-hidden size={16} />,
                      callback: () => setConfirm({ kind: 'decline', entry }),
                    });
                  }

                  return (
                    <ContactRow
                      key={entry.id}
                      name={grantorName(entry)}
                      email={entry.grantor_email}
                      secondary={t('emergency.wait_label', { count: entry.wait_time_days })}
                      status={phase !== 'confirmed' && <StatusChip phase={phase} t={t} />}
                      band={band}
                      bandTone={bandTone}
                      menu={
                        options.length > 0 && (
                          <RowMenu label={t('emergency.row_menu', { name: grantorName(entry) })} disabled={busy} options={options} />
                        )
                      }
                    />
                  );
                })}
              </div>
            </>
          )}
        </Screen>,
        !prompt
      )}
    </>
  );
}
