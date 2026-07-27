import { Alert, Button, Loader, Modal, ModalSize, VariantType } from '@gouvfr-lasuite/cunningham-react';
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
import { SessionExpiredError, withFreshToken } from '@encryption/src/ui/auth/session-expired';
import { RecipientFingerprint, RecipientIdentity, TrustRefuseButtons } from '@encryption/src/ui/components/RecipientFingerprintControls';
import { RecoveryKitBackup } from '@encryption/src/ui/components/RecoveryKitBackup';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import {
  type Countdown,
  MAX_WAIT_DAYS,
  MIN_WAIT_DAYS,
  WAIT_TIME_PRESETS,
  countdownTo,
  emergencyPhase,
  parseWaitDays,
  rearmBodyFromDesignation,
} from '@encryption/src/ui/components/emergency-access-logic';
import { type VaultRegisteredUser } from '@encryption/src/ui/components/verify-recipients-logic';
import { useSessionExpired } from '@encryption/src/ui/hooks/useSessionExpired';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

type EscrowAuditStatus = 'ok' | 'tampered' | 'stale-identity' | 'outdated-key';

interface EmergencyAccessProps {
  getToken: () => Promise<string | null>;
  onClose: () => void;
  onReconnect?: () => void;
  isAuthenticating?: boolean;
  currentAccessToken?: string | null;
  /** Set when the SDK auto-opened the interface on actionable state: leads with a prompt modal. */
  emergencyPending?: InterfaceContext['emergencyPending'] | null;
  overlayMode?: boolean;
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

// Tinted semantic pairs (light `--secondary` background + dark `--primary` text):
// Cunningham's Alert pairing, which meets WCAG AA in BOTH themes, unlike the solid
// `X-550 + on-X` pair whose warning shade falls to ~3.9:1 in dark mode.
const CHIP_STYLES: Record<string, { background: string; color: string }> = {
  invited: {
    background: 'var(--c--contextuals--background--semantic--info--secondary)',
    color: 'var(--c--contextuals--content--semantic--info--primary)',
  },
  confirmed: {
    background: 'var(--c--contextuals--background--semantic--success--secondary)',
    color: 'var(--c--contextuals--content--semantic--success--primary)',
  },
  requested: {
    background: 'var(--c--contextuals--background--semantic--error--secondary)',
    color: 'var(--c--contextuals--content--semantic--error--primary)',
  },
  approved: {
    background: 'var(--c--contextuals--background--semantic--warning--secondary)',
    color: 'var(--c--contextuals--content--semantic--warning--primary)',
  },
};

function StatusChip({ phase, t }: { phase: 'invited' | 'confirmed' | 'requested' | 'approved'; t: TFunction }) {
  return (
    <span
      style={{
        fontSize: 11,
        fontWeight: 700,
        padding: '2px 8px',
        borderRadius: 10,
        background: CHIP_STYLES[phase].background,
        color: CHIP_STYLES[phase].color,
        whiteSpace: 'nowrap',
      }}
    >
      {t(`emergency.status_${phase}`)}
    </span>
  );
}

const rowStyle = {
  padding: 'var(--c--globals--spacings--sm)',
  background: 'var(--c--contextuals--background--surface--secondary)',
  borderRadius: 4,
} as const;

// ---------------------------------------------------------------------------
// Designation flow (sub-screen): email search -> out-of-band verification ->
// wait-time choice -> one-step designation (the escrow is created immediately).
// ---------------------------------------------------------------------------

interface DesignateFlowProps {
  getToken: () => Promise<string | null>;
  /** Pre-filled contact email (renewal after a stale identity): the search runs immediately. */
  prefillEmail?: string | null;
  onBack: () => void;
  onDesignated: () => void;
  markSessionExpired: () => void;
}

function DesignateFlow({ getToken, prefillEmail = null, onBack, onDesignated, markSessionExpired }: DesignateFlowProps) {
  const { t, i18n } = useTranslation('common');
  const { request, createEmergencyEscrow } = useEncryptionContext();

  const [step, setStep] = useState<'email' | 'verify' | 'wait' | 'success'>('email');
  const [email, setEmail] = useState(prefillEmail ?? '');
  const [searchOutcome, setSearchOutcome] = useState<'not-found' | 'not-onboarded' | null>(null);
  const [contact, setContact] = useState<{ userId: string; email: string; fingerprint: string } | null>(null);
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
        const result = await withFreshToken(getToken, (token) => searchEmergencyContact(token, query));

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

        setContact({ userId: foundId, email: result.user.email, fingerprint: entry.identityFingerprint });
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
    [email, getToken, request, markSessionExpired]
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

      await withFreshToken(getToken, (token) => designateEmergencyContact(token, body, signature));
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
  }, [contact, effectiveWaitDays, createEmergencyEscrow, request, getToken, i18n.language, markSessionExpired, t]);

  if (step === 'success' && contact) {
    return (
      <>
        <h2>{t('emergency.designate_title')}</h2>
        <Alert type={VariantType.SUCCESS}>{t('emergency.designate_success', { email: contact.email })}</Alert>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
          <Button onClick={onDesignated}>{t('emergency.btn_back_to_list')}</Button>
        </div>
      </>
    );
  }

  if (step === 'verify' && contact) {
    return (
      <>
        <h2>{t('emergency.designate_title')}</h2>
        <Alert type={VariantType.INFO}>{t('emergency.designate_verify_required')}</Alert>

        {error && (
          <div style={{ marginTop: 8 }}>
            <Alert type={VariantType.ERROR}>{error}</Alert>
          </div>
        )}

        <div style={{ ...rowStyle, marginTop: 12 }}>
          <RecipientIdentity label={{ email: contact.email }} />
          <p style={{ fontSize: 13, margin: '8px 0' }}>{t('profile.compare_instruction')}</p>
          <RecipientFingerprint fingerprint={contact.fingerprint} />
          <TrustRefuseButtons busy={busy} onTrust={handleTrust} onRefuse={handleRefuse} />
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-start', marginTop: 16 }}>
          <Button variant="secondary" onClick={onBack} disabled={busy}>
            {t('onboarding.btn_back')}
          </Button>
        </div>
      </>
    );
  }

  if (step === 'wait' && contact) {
    return (
      <>
        <h2>{t('emergency.designate_title')}</h2>
        <div style={rowStyle}>
          <RecipientIdentity label={{ email: contact.email }} />
        </div>

        <p style={{ fontSize: 13, margin: '16px 0 8px', fontWeight: 700 }}>{t('emergency.designate_wait_title')}</p>
        <p style={{ fontSize: 13, margin: '0 0 8px' }}>{t('emergency.designate_wait_explanation')}</p>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {WAIT_TIME_PRESETS.map((days) => (
            <Button
              key={days}
              size="small"
              variant={!useCustom && waitChoice === days ? 'primary' : 'secondary'}
              onClick={() => {
                setUseCustom(false);
                setWaitChoice(days);
              }}
            >
              {t('emergency.wait_days_option', { count: days })}
            </Button>
          ))}
          <Button size="small" variant={useCustom ? 'primary' : 'secondary'} onClick={() => setUseCustom(true)}>
            {t('emergency.wait_custom')}
          </Button>
        </div>

        {useCustom && (
          <div style={{ marginTop: 8 }}>
            <label style={{ fontSize: 13, display: 'block', marginBottom: 4 }} htmlFor="emergency-custom-wait">
              {t('emergency.wait_custom_label', { min: MIN_WAIT_DAYS, max: MAX_WAIT_DAYS })}
            </label>
            <input
              id="emergency-custom-wait"
              type="number"
              min={MIN_WAIT_DAYS}
              max={MAX_WAIT_DAYS}
              value={customWait}
              onChange={(e) => setCustomWait(e.target.value)}
              style={{
                width: 120,
                boxSizing: 'border-box',
                fontSize: 14,
                padding: 'var(--c--globals--spacings--t)',
                borderRadius: 4,
                border: '1px solid var(--c--contextuals--border--surface--primary)',
              }}
            />
          </div>
        )}

        <p style={{ fontSize: 12, margin: '8px 0 0', color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>
          {t('emergency.designate_wait_hint')}
        </p>

        <div style={{ marginTop: 16 }}>
          <p style={{ fontSize: 13, margin: '0 0 4px', fontWeight: 700 }}>{t('emergency.designate_scope_title')}</p>
          <ul style={{ fontSize: 13, lineHeight: 1.6, margin: 0, paddingLeft: 20 }}>
            <li>{t('emergency.designate_scope_1')}</li>
            <li>{t('emergency.designate_scope_2')}</li>
            <li>{t('emergency.designate_scope_3')}</li>
          </ul>
        </div>

        {error && (
          <div style={{ marginTop: 8 }}>
            <Alert type={VariantType.ERROR}>{error}</Alert>
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
          <Button variant="secondary" onClick={onBack} disabled={busy}>
            {t('emergency.btn_cancel')}
          </Button>
          <Button onClick={handleDesignate} disabled={busy || effectiveWaitDays === null}>
            {busy ? t('emergency.designating') : t('emergency.btn_designate_confirm')}
          </Button>
        </div>
      </>
    );
  }

  // Step 1: exact-email search.
  return (
    <>
      <h2>{t('emergency.designate_title')}</h2>
      <p style={{ fontSize: 13 }}>{t('emergency.designate_intro')}</p>

      <label style={{ fontSize: 13, display: 'block', marginBottom: 4, fontWeight: 700 }} htmlFor="emergency-contact-email">
        {t('emergency.designate_email_label')}
      </label>
      <div style={{ display: 'flex', gap: 8 }}>
        <input
          id="emergency-contact-email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') handleSearch();
          }}
          placeholder={t('emergency.designate_email_placeholder')}
          style={{
            flex: 1,
            boxSizing: 'border-box',
            fontSize: 14,
            padding: 'var(--c--globals--spacings--t)',
            borderRadius: 4,
            border: '1px solid var(--c--contextuals--border--surface--primary)',
            // Without theme tokens a raw input keeps the UA light default, which
            // is unreadable on the dark theme.
            backgroundColor: 'var(--c--contextuals--background--surface--primary)',
            color: 'var(--c--contextuals--content--semantic--neutral--primary)',
          }}
        />
        <Button onClick={() => handleSearch()} disabled={busy || email.trim().length === 0}>
          {busy ? t('emergency.searching') : t('emergency.btn_search')}
        </Button>
      </div>

      {searchOutcome === 'not-found' && (
        <div style={{ marginTop: 12 }}>
          <Alert type={VariantType.INFO}>{t('emergency.designate_not_found')}</Alert>
        </div>
      )}
      {searchOutcome === 'not-onboarded' && (
        <div style={{ marginTop: 12 }}>
          <Alert type={VariantType.INFO}>{t('emergency.designate_not_onboarded')}</Alert>
        </div>
      )}

      {error && (
        <div style={{ marginTop: 12 }}>
          <Alert type={VariantType.ERROR}>{error}</Alert>
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'flex-start', marginTop: 16 }}>
        <Button variant="secondary" onClick={onBack} disabled={busy}>
          {t('onboarding.btn_back')}
        </Button>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Reveal flow (contact side): pull the released capsule, open it in the vault,
// render the GRANTOR's kit for the physical handover.
// ---------------------------------------------------------------------------

interface RevealViewProps {
  entry: EmergencyGrantedEntry;
  getToken: () => Promise<string | null>;
  onDone: () => void;
  markSessionExpired: () => void;
}

function RevealView({ entry, getToken, onDone, markSessionExpired }: RevealViewProps) {
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
        const released = await withFreshToken(getToken, (token) => recoverEmergencyCapsule(token, entry.id, signature));
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
  }, [attempt, isReady, entry.id, entry.grantor_user_id, request, getToken, revealEmergencyPhrase, markSessionExpired]);

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

  return (
    <>
      <h2>{t('emergency.reveal_title')}</h2>
      <p style={{ fontSize: 13, fontWeight: 700 }}>{t('emergency.reveal_grantor', { email: entry.grantor_email })}</p>

      <ul style={{ fontSize: 13, lineHeight: 1.6, margin: 'var(--c--globals--spacings--sm) 0', paddingLeft: 20 }}>
        <li>{t('emergency.reveal_instruction_1')}</li>
        <li>{t('emergency.reveal_instruction_2')}</li>
        <li>{t('emergency.reveal_instruction_3')}</li>
        <li>{t('emergency.reveal_instruction_4')}</li>
      </ul>

      {untrustedGrantor && (
        <div style={{ marginTop: 12 }}>
          <Alert type={VariantType.WARNING}>{t('emergency.reveal_untrusted_grantor', { email: entry.grantor_email })}</Alert>
          {grantorFingerprint ? (
            <div style={{ marginTop: 12 }}>
              <RecipientFingerprint fingerprint={grantorFingerprint} />
              <TrustRefuseButtons
                busy={approving}
                onTrust={handleApproveGrantor}
                onRefuse={onDone}
                trustLabel={t('emergency.btn_grantor_verified')}
                refuseLabel={t('emergency.btn_back_to_list')}
              />
            </div>
          ) : (
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
              <Button variant="secondary" onClick={onDone}>
                {t('emergency.btn_back_to_list')}
              </Button>
            </div>
          )}
        </div>
      )}

      {error && (
        <>
          <Alert type={VariantType.ERROR}>{error}</Alert>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
            <Button variant="secondary" onClick={onDone}>
              {t('emergency.btn_back_to_list')}
            </Button>
          </div>
        </>
      )}

      {!untrustedGrantor && !error && !phrase && (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--c--globals--spacings--md)' }}>
          <Loader />
        </div>
      )}

      {phrase && (
        <>
          <RecoveryKitBackup passphrase={phrase} parentOrigin={null} onConfirm={onDone} confirmLabel={t('emergency.reveal_done')} mode="handover" />
          <p style={{ fontSize: 12, marginTop: 8, color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>
            {t('emergency.reveal_still_available')}
          </p>
        </>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Main screen: the two lists (contacts I trust with my vault / vaults
// entrusted to me), the per-row actions, the audit results and the prompt
// modal when the SDK auto-opened the interface on actionable state.
// ---------------------------------------------------------------------------

export function EmergencyAccess({
  getToken,
  onClose,
  onReconnect,
  isAuthenticating = false,
  currentAccessToken = null,
  emergencyPending = null,
  overlayMode = false,
}: EmergencyAccessProps) {
  const { t, i18n } = useTranslation('common');
  const { isReady, request, createEmergencyEscrow, verifyEscrows } = useEncryptionContext();
  const { sessionExpired, markSessionExpired } = useSessionExpired(currentAccessToken, isAuthenticating);

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

  const loadLists = useCallback(async () => {
    setLoadError(null);

    try {
      const [trustedRes, grantedRes] = await withFreshToken(getToken, (token) =>
        Promise.all([fetchTrustedContacts(token), fetchGrantedVaults(token)])
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
  }, [getToken, markSessionExpired]);

  useEffect(() => {
    loadLists();
  }, [loadLists]);

  // Audit the escrow list in the vault (signature + pinned identity + key
  // version against the directory). Only rows on the ACTIVE vault are
  // auditable: a previous vault's escrows were signed by a different identity.
  useEffect(() => {
    if (!isReady || !trusted) return;

    const auditable = trusted.filter((contact) => contact.vault_active !== false);

    if (auditable.length === 0) {
      setAudit({});

      return;
    }

    let cancelled = false;

    verifyEscrows(auditable.map(({ id, grantee_user_id, wait_time_days, escrow }) => ({ id, grantee_user_id, wait_time_days, escrow })))
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

  // Lead with the prompt when the SDK auto-opened the interface on actionable
  // state. Handled once per delivery (the context can be re-sent).
  const [prompt, setPrompt] = useState<'recovery' | 'invite' | null>(null);
  const promptHandled = useRef(false);

  useEffect(() => {
    if (promptHandled.current || !emergencyPending) return;

    // The vault signal only says WHICH prompt to lead with; the content always
    // comes from OUR authenticated lists. Both branches wait for the relevant
    // list and open only if it truly shows the state, so a spoofed signal can
    // conjure neither prompt.
    if (emergencyPending.recovery) {
      if (trusted === null) return;
      promptHandled.current = true;
      if (trusted.some((c) => c.status === 'recoveryRequested' || c.status === 'recoveryApproved')) setPrompt('recovery');
    } else if (emergencyPending.invitation) {
      if (granted === null) return;
      promptHandled.current = true;
      if (granted.some((g) => g.status === 'invited')) setPrompt('invite');
    }
  }, [emergencyPending, trusted, granted]);

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
        await withFreshToken(getToken, (token) => rejectEmergencyRecovery(token, entry.id));
        setNotice(t('emergency.reject_done', { email: entry.grantee_email }));
      }),
    [runRowAction, getToken, t]
  );

  const handleRevoke = useCallback(
    (entry: EmergencyTrustedEntry | EmergencyGrantedEntry) =>
      runRowAction(entry.id, async () => {
        await withFreshToken(getToken, (token) => deleteEmergencyAccess(token, entry.id));
      }),
    [runRowAction, getToken]
  );

  const handleAccept = useCallback(
    (entry: EmergencyGrantedEntry) =>
      runRowAction(entry.id, async () => {
        await withFreshToken(getToken, (token) => acceptEmergencyDesignation(token, entry.id));
      }),
    [runRowAction, getToken]
  );

  const handleCancelRequest = useCallback(
    (entry: EmergencyGrantedEntry) =>
      runRowAction(entry.id, async () => {
        await withFreshToken(getToken, (token) => cancelEmergencyRecovery(token, entry.id));
      }),
    [runRowAction, getToken]
  );

  // Contact side: start a recovery. Identity-signed (empty body), so a stolen
  // session alone cannot trigger it.
  const handleRequestAccess = useCallback(
    (entry: EmergencyGrantedEntry) =>
      runRowAction(entry.id, async () => {
        const path = `/api/emergency-access/${encodeURIComponent(entry.id)}/initiate`;
        const { signature } = (await request(MSG_VAULT_SIGN_REQUEST, { method: 'POST', path })) as { signature: string };

        await withFreshToken(getToken, (token) => initiateEmergencyRecovery(token, entry.id, signature));
      }),
    [runRowAction, request, getToken]
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

          await withFreshToken(getToken, (token) => rearmEmergencyEscrow(token, entry.id, rearmBody, signature));
        } catch (err) {
          if (isVaultError(err) && err.code === VaultErrorCode.UNTRUSTED_RECIPIENT) {
            throw new Error(t('emergency.designate_untrusted'));
          }
          throw err;
        }
      }),
    [runRowAction, createEmergencyEscrow, request, getToken, i18n.language, t]
  );

  // Stale identity: the pinned contact identity no longer matches the
  // directory, so the escrow cannot be opened by anyone. Renew = revoke, then
  // re-designate the same person (their new identity must be re-verified).
  const handleRenew = useCallback(
    (entry: EmergencyTrustedEntry) =>
      runRowAction(entry.id, async () => {
        await withFreshToken(getToken, (token) => deleteEmergencyAccess(token, entry.id));
        setDesignatePrefill(entry.grantee_email);
        setView('designate');
      }),
    [runRowAction, getToken]
  );

  const handlePromptRefuseAll = useCallback(async () => {
    const requests = (trusted ?? []).filter((c) => c.status === 'recoveryRequested' || c.status === 'recoveryApproved');

    setBusyId('prompt');
    setActionError(null);

    try {
      await withFreshToken(getToken, async (token) => {
        for (const req of requests) {
          await rejectEmergencyRecovery(token, req.id);
        }
      });
      setNotice(t('emergency.reject_done', { email: requests.map((r) => r.grantee_email).join(', ') }));
      setPrompt(null);
      await loadLists();
    } catch (err) {
      if (err instanceof SessionExpiredError) {
        markSessionExpired();
        setPrompt(null);
      } else {
        setActionError((err as Error).message);
        setPrompt(null);
      }
    } finally {
      setBusyId(null);
    }
  }, [trusted, getToken, loadLists, markSessionExpired, t]);

  const dateFormatter = new Intl.DateTimeFormat(i18n.language, { dateStyle: 'long', timeStyle: 'short' });

  // Sub-screens replace the whole view (early-return pattern).
  // When the SDK auto-opened us over a product, the host iframe is a bare
  // transparent full-viewport layer: we must draw our OWN modal chrome (backdrop
  // + centered card), exactly like VerifyRecipients, or the page sprawls
  // full-width and see-through over the product. Navigated normally (the settings
  // sub-page), we ARE the page, so render inline in a padded block.
  // `overlayMode` is the synchronous signal (URL hash); `emergencyPending` is kept
  // as a fallback for callers that pass the context directly (stories, tests).
  const isOverlay = overlayMode || emergencyPending !== null;
  const frame = (children: ReactNode, open = true): ReactNode =>
    isOverlay ? (
      <Modal isOpen={open} onClose={onClose} closeOnClickOutside={false} size={ModalSize.LARGE} aria-label={t('emergency.title')}>
        <div style={{ paddingBottom: 'var(--c--globals--spacings--base)' }}>{children}</div>
      </Modal>
    ) : (
      <div style={{ padding: 'var(--c--globals--spacings--base)' }}>{children}</div>
    );

  if (view === 'designate') {
    return frame(
      <>
        {sessionExpired && onReconnect && (
          <div style={{ marginBottom: 8 }}>
            <SessionExpiredAlert onReconnect={onReconnect} isAuthenticating={isAuthenticating} />
          </div>
        )}
        <DesignateFlow
          getToken={getToken}
          prefillEmail={designatePrefill}
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
      </>
    );
  }

  if (view === 'reveal' && revealEntry) {
    return frame(
      <>
        {sessionExpired && onReconnect && (
          <div style={{ marginBottom: 8 }}>
            <SessionExpiredAlert onReconnect={onReconnect} isAuthenticating={isAuthenticating} />
          </div>
        )}
        <RevealView
          entry={revealEntry}
          getToken={getToken}
          onDone={() => {
            setRevealEntry(null);
            setView('list');
          }}
          markSessionExpired={markSessionExpired}
        />
      </>
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
        size={ModalSize.MEDIUM}
        aria-label={t('emergency.prompt_recovery_title')}
      >
        <div style={{ paddingBottom: 'var(--c--globals--spacings--base)' }}>
          <h2 style={{ fontSize: 18, margin: '0 0 12px', textAlign: 'left' }}>{t('emergency.prompt_recovery_title')}</h2>
          {pendingRequests.map((req) => (
            <p key={req.id} style={{ fontSize: 14, margin: '0 0 12px' }}>
              {emergencyPhase(req, now) === 'approved' || req.deadline_millis === null ? (
                <Trans t={t} i18nKey="emergency.prompt_recovery_approved" values={{ email: req.grantee_email }} components={{ strong: <strong /> }} />
              ) : (
                <Trans
                  t={t}
                  i18nKey="emergency.prompt_recovery_body"
                  values={{ email: req.grantee_email, date: dateFormatter.format(new Date(req.deadline_millis)) }}
                  components={{ strong: <strong /> }}
                />
              )}
            </p>
          ))}
          <p style={{ fontSize: 13, color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>{t('emergency.prompt_recovery_hint')}</p>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16, flexWrap: 'wrap' }}>
            <Button color="error" onClick={handlePromptRefuseAll} disabled={busyId === 'prompt'}>
              {busyId === 'prompt' ? t('emergency.refusing') : t('emergency.btn_prompt_refuse')}
            </Button>
          </div>
        </div>
      </Modal>

      <Modal
        isOpen={prompt === 'invite'}
        onClose={() => setPrompt(null)}
        closeOnClickOutside={false}
        size={ModalSize.MEDIUM}
        title={t('emergency.prompt_invite_title')}
      >
        <div style={{ paddingBottom: 'var(--c--globals--spacings--base)' }}>
          <p style={{ fontSize: 14 }}>{t('emergency.prompt_invite_body')}</p>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
            <Button onClick={() => setPrompt(null)}>{t('emergency.btn_prompt_see_invite')}</Button>
          </div>
        </div>
      </Modal>

      {frame(
        <>
          <h2>{t('emergency.title')}</h2>

          {sessionExpired && onReconnect && (
            <div style={{ marginBottom: 8 }}>
              <SessionExpiredAlert onReconnect={onReconnect} isAuthenticating={isAuthenticating} />
            </div>
          )}

          {/* Shared confirmation dialog for the destructive / serious actions. */}
          <Modal
            isOpen={confirm !== null}
            onClose={() => setConfirm(null)}
            closeOnClickOutside={false}
            size={ModalSize.MEDIUM}
            aria-label={confirm ? t(`emergency.confirm_${confirm.kind}_title`) : undefined}
          >
            <div style={{ paddingBottom: 'var(--c--globals--spacings--md)' }}>
              {confirm && (
                <>
                  <h2 style={{ fontSize: 18, margin: '0 0 12px', textAlign: 'left' }}>{t(`emergency.confirm_${confirm.kind}_title`)}</h2>
                  <p style={{ fontSize: 14 }}>
                    {confirm.kind === 'revoke' && (
                      <Trans
                        t={t}
                        i18nKey="emergency.confirm_revoke_body"
                        values={{ email: (confirm.entry as EmergencyTrustedEntry).grantee_email }}
                        components={{ strong: <strong /> }}
                      />
                    )}
                    {confirm.kind === 'decline' && (
                      <Trans
                        t={t}
                        i18nKey="emergency.confirm_decline_body"
                        values={{ email: (confirm.entry as EmergencyGrantedEntry).grantor_email }}
                        components={{ strong: <strong /> }}
                      />
                    )}
                    {confirm.kind === 'request' && (
                      <Trans
                        t={t}
                        i18nKey="emergency.confirm_request_body"
                        values={{ email: (confirm.entry as EmergencyGrantedEntry).grantor_email, count: confirm.entry.wait_time_days }}
                        components={{ strong: <strong /> }}
                      />
                    )}
                  </p>
                </>
              )}
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
                <Button variant="secondary" onClick={() => setConfirm(null)}>
                  {t('emergency.btn_cancel')}
                </Button>
                {confirm && (
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
                )}
              </div>
            </div>
          </Modal>

          <p style={{ fontSize: 13, color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>{t('emergency.intro')}</p>

          {notice && (
            <div style={{ marginBottom: 8 }}>
              <Alert type={VariantType.SUCCESS}>{notice}</Alert>
            </div>
          )}

          {actionError && (
            <div style={{ marginBottom: 8 }}>
              <Alert type={VariantType.ERROR}>{actionError}</Alert>
            </div>
          )}

          {loadError && (
            <div style={{ marginBottom: 8 }}>
              <Alert type={VariantType.ERROR}>{loadError}</Alert>
            </div>
          )}

          {loading && !loadError ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--c--globals--spacings--md)' }}>
              <Loader />
            </div>
          ) : (
            <>
              {/* Section A: contacts I designated (grantor side). */}
              <h3 style={{ fontSize: 16, margin: '16px 0 2px' }}>{t('emergency.trusted_title')}</h3>
              <p style={{ fontSize: 13, margin: '0 0 8px', color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>
                {t('emergency.trusted_subtitle')}
              </p>

              {trusted && trusted.length === 0 && (
                <p style={{ fontSize: 13, color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>{t('emergency.trusted_empty')}</p>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {(trusted ?? []).map((entry) => {
                  const phase = emergencyPhase(entry, now);
                  const rowAudit = entry.vault_active === false ? undefined : audit[entry.id];
                  const countdown = entry.deadline_millis !== null ? countdownTo(entry.deadline_millis, now) : null;
                  const busy = busyId === entry.id;

                  return (
                    <div key={entry.id} style={rowStyle}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span style={{ fontSize: 13, fontWeight: 700, wordBreak: 'break-all', flex: 1, minWidth: 0 }}>{entry.grantee_email}</span>
                        <StatusChip phase={phase} t={t} />
                      </div>

                      <p style={{ fontSize: 12, margin: '4px 0 0', color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>
                        {t('emergency.wait_label', { count: entry.wait_time_days })}
                      </p>

                      {entry.vault_active === false && (
                        <p style={{ fontSize: 12, margin: '4px 0 0', color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>
                          {t('emergency.vault_inactive_note')}
                        </p>
                      )}

                      {rowAudit === 'tampered' && (
                        <div style={{ marginTop: 8 }}>
                          <Alert type={VariantType.ERROR}>{t('emergency.audit_tampered')}</Alert>
                        </div>
                      )}

                      {rowAudit === 'stale-identity' && (
                        <div style={{ marginTop: 8 }}>
                          <Alert type={VariantType.WARNING}>{t('emergency.audit_stale')}</Alert>
                          <div style={{ marginTop: 8 }}>
                            <Button size="small" variant="secondary" disabled={busy} onClick={() => handleRenew(entry)}>
                              {t('emergency.btn_renew')}
                            </Button>
                          </div>
                        </div>
                      )}

                      {rowAudit === 'outdated-key' && (
                        <div style={{ marginTop: 8 }}>
                          <Alert type={VariantType.INFO}>{t('emergency.audit_outdated')}</Alert>
                          <div style={{ marginTop: 8 }}>
                            <Button size="small" variant="secondary" disabled={busy} onClick={() => handleUpdateEscrow(entry)}>
                              {t('emergency.btn_update_escrow')}
                            </Button>
                          </div>
                        </div>
                      )}

                      {rowAudit !== 'tampered' && phase === 'requested' && countdown && !countdown.expired && (
                        <div style={{ marginTop: 8 }}>
                          <Alert type={VariantType.WARNING}>
                            {t('emergency.trusted_requested_warning', { email: entry.grantee_email, time: countdownLabel(countdown, i18n.language) })}
                          </Alert>
                        </div>
                      )}

                      {rowAudit !== 'tampered' && phase === 'approved' && (
                        <div style={{ marginTop: 8 }}>
                          <Alert type={VariantType.WARNING}>{t('emergency.trusted_approved_warning', { email: entry.grantee_email })}</Alert>
                        </div>
                      )}

                      <div style={{ display: 'flex', gap: 8, marginTop: 8, flexWrap: 'wrap' }}>
                        {(phase === 'requested' || phase === 'approved') && (
                          <Button size="small" color="error" disabled={busy} onClick={() => handleReject(entry)}>
                            {phase === 'approved' ? t('emergency.btn_relock') : t('emergency.btn_refuse_request')}
                          </Button>
                        )}
                        <Button size="small" variant="tertiary" color="error" disabled={busy} onClick={() => setConfirm({ kind: 'revoke', entry })}>
                          {t('emergency.btn_revoke')}
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>

              <div style={{ marginTop: 12 }}>
                <Button variant="secondary" onClick={() => setView('designate')}>
                  {t('emergency.btn_designate')}
                </Button>
              </div>

              {/* Section B: vaults entrusted to me (contact side). */}
              <h3 style={{ fontSize: 16, margin: '24px 0 2px' }}>{t('emergency.granted_title')}</h3>
              <p style={{ fontSize: 13, margin: '0 0 8px', color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>
                {t('emergency.granted_subtitle')}
              </p>

              {granted && granted.length === 0 && (
                <p style={{ fontSize: 13, color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>{t('emergency.granted_empty')}</p>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {(granted ?? []).map((entry) => {
                  const phase = emergencyPhase(entry, now);
                  const countdown = entry.deadline_millis !== null ? countdownTo(entry.deadline_millis, now) : null;
                  const busy = busyId === entry.id;

                  return (
                    <div key={entry.id} style={rowStyle}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span style={{ fontSize: 13, fontWeight: 700, wordBreak: 'break-all', flex: 1, minWidth: 0 }}>{entry.grantor_email}</span>
                        <StatusChip phase={phase} t={t} />
                      </div>

                      <p style={{ fontSize: 12, margin: '4px 0 0', color: 'var(--c--contextuals--content--semantic--neutral--secondary)' }}>
                        {t('emergency.wait_label', { count: entry.wait_time_days })}
                      </p>

                      {phase === 'invited' && (
                        <>
                          <p style={{ fontSize: 13, margin: '8px 0 0' }}>{t('emergency.granted_invited_text', { email: entry.grantor_email })}</p>
                          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                            <Button size="small" disabled={busy} onClick={() => handleAccept(entry)}>
                              {t('emergency.btn_accept')}
                            </Button>
                            <Button
                              size="small"
                              variant="secondary"
                              color="error"
                              disabled={busy}
                              onClick={() => setConfirm({ kind: 'decline', entry })}
                            >
                              {t('emergency.btn_decline')}
                            </Button>
                          </div>
                        </>
                      )}

                      {phase === 'confirmed' && (
                        <div style={{ marginTop: 8 }}>
                          <Button size="small" variant="secondary" disabled={busy} onClick={() => setConfirm({ kind: 'request', entry })}>
                            {t('emergency.btn_request_access')}
                          </Button>
                        </div>
                      )}

                      {phase === 'requested' && countdown && !countdown.expired && (
                        <>
                          <p style={{ fontSize: 13, margin: '8px 0 0' }}>
                            {t('emergency.granted_requested_text', { time: countdownLabel(countdown, i18n.language) })}
                          </p>
                          <div style={{ marginTop: 8 }}>
                            <Button size="small" variant="secondary" disabled={busy} onClick={() => handleCancelRequest(entry)}>
                              {t('emergency.btn_cancel_request')}
                            </Button>
                          </div>
                        </>
                      )}

                      {phase === 'approved' && (
                        <>
                          <p style={{ fontSize: 13, margin: '8px 0 0' }}>{t('emergency.granted_approved_text', { email: entry.grantor_email })}</p>
                          <div style={{ marginTop: 8 }}>
                            <Button
                              size="small"
                              disabled={busy}
                              onClick={() => {
                                setRevealEntry(entry);
                                setView('reveal');
                              }}
                            >
                              {t('emergency.btn_reveal')}
                            </Button>
                          </div>
                        </>
                      )}
                    </div>
                  );
                })}
              </div>
            </>
          )}

          <div style={{ marginTop: 'var(--c--globals--spacings--base)' }}>
            <Button variant="secondary" onClick={onClose}>
              {t('settings.close')}
            </Button>
          </div>
        </>,
        !prompt
      )}
    </>
  );
}
