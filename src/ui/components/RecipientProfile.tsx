import { Alert, Loader, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  MSG_VAULT_ACCEPT_FINGERPRINT,
  MSG_VAULT_FETCH_PUBLIC_KEYS,
  MSG_VAULT_GET_KNOWN_FINGERPRINTS,
  MSG_VAULT_REFUSE_FINGERPRINT,
} from '@encryption/src/shared/constants';
import { type RecipientLabel } from '@encryption/src/shared/schemas/interface-context';
import { SessionExpiredError } from '@encryption/src/ui/auth/session-expired';
import { FingerprintDisplay } from '@encryption/src/ui/components/FingerprintDisplay';
import { TrustRefuseButtons, recipientLabel } from '@encryption/src/ui/components/RecipientFingerprintControls';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import { type VaultRegisteredUser } from '@encryption/src/ui/components/verify-recipients-logic';
import { useSessionExpired } from '@encryption/src/ui/hooks/useSessionExpired';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

interface RecipientProfileProps {
  /** The recipient to inspect (their OIDC sub, passed via the context channel). */
  userId: string | null;
  /** Product-supplied display label (email, name optional) for the recipient. */
  label?: RecipientLabel;
  onReconnect?: () => void;
  isAuthenticating?: boolean;
  currentAccessToken?: string | null;
}

/** The persisted TOFU decision for a recipient (never 'mismatch': that is transient). */
type Decision = 'unknown' | 'trusted' | 'refused';

/** Initials avatar for the identity card (from the recipient's name or email). */
function ProfileAvatar({ label }: { label: string }) {
  const initials =
    label
      .split(/\s+/)
      .map((p) => p[0])
      .join('')
      .slice(0, 2)
      .toUpperCase() || '?';

  return (
    <div
      style={{
        width: 48,
        height: 48,
        borderRadius: '50%',
        flexShrink: 0,
        background: 'var(--c--globals--colors--brand-400, #000091)',
        color: 'white',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontSize: 18,
        fontWeight: 700,
      }}
    >
      {initials}
    </div>
  );
}

/**
 * Per-recipient "Encryption Identity" card, opened explicitly by the product
 * (e.g. clicking a person in its share UI). Shows who the recipient is
 * (avatar + product-supplied name/email), their 40-digit identity fingerprint
 * from the registry for out-of-band comparison, and Trust / Refuse controls.
 * There is no "not verified" note: the fingerprint and the actions carry that.
 */
export function RecipientProfile({ userId, label, onReconnect, isAuthenticating = false, currentAccessToken = null }: RecipientProfileProps) {
  const { t } = useTranslation('common');
  const { isReady, request } = useEncryptionContext();

  const [phase, setPhase] = useState<'loading' | 'ready' | 'error'>('loading');
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [decision, setDecision] = useState<Decision>('unknown');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { sessionExpired, markSessionExpired } = useSessionExpired(currentAccessToken, isAuthenticating);

  const onError = useCallback(
    (err: unknown) => {
      if (err instanceof SessionExpiredError) {
        markSessionExpired();
      } else {
        setError((err as Error).message);
        setPhase('error');
      }
    },
    [markSessionExpired]
  );

  // Resolve the recipient's CURRENT identity fingerprint (directory) and the
  // recorded decision (local registry). Kept in a callback so the trust/refuse
  // actions can re-run it to reflect the new decision.
  const load = useCallback(async () => {
    if (!userId) return;

    // `userId` is the recipient's OIDC sub (what the product passed); the vault
    // resolves it and echoes it back as the map key. The internal id on the
    // entry is what the TOFU registry keys on.
    const { users } = (await request(MSG_VAULT_FETCH_PUBLIC_KEYS, { subs: [userId] })) as { users: Record<string, VaultRegisteredUser> };
    const entry = users[userId];
    setFingerprint(entry?.verified ? entry.identityFingerprint : null);

    const { fingerprints } = (await request(MSG_VAULT_GET_KNOWN_FINGERPRINTS)) as {
      fingerprints: Record<string, { fingerprint: string; status: Decision }>;
    };
    setDecision(entry ? (fingerprints[entry.userId]?.status ?? 'unknown') : 'unknown');
  }, [userId, request]);

  useEffect(() => {
    if (!isReady) return;

    let cancelled = false;

    (async () => {
      try {
        await load();
        if (!cancelled) setPhase('ready');
      } catch (err) {
        if (!cancelled) onError(err);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [isReady, load, onError]);

  const act = useCallback(
    async (type: typeof MSG_VAULT_ACCEPT_FINGERPRINT | typeof MSG_VAULT_REFUSE_FINGERPRINT) => {
      if (!userId || !fingerprint) return;

      setBusy(true);
      setError(null);

      try {
        await request(type, { sub: userId, fingerprint });
        await load();
      } catch (err) {
        onError(err);
      } finally {
        setBusy(false);
      }
    },
    [userId, fingerprint, request, load, onError]
  );

  const { primary, secondary } = userId ? recipientLabel(userId, label) : { primary: '', secondary: null };

  return (
    <div style={{ padding: '4px 16px 16px' }}>
      <h2 style={{ margin: '0 0 12px' }}>{t('profile.title')}</h2>

      {sessionExpired && onReconnect && (
        <div style={{ marginBottom: 8 }}>
          <SessionExpiredAlert onReconnect={onReconnect} isAuthenticating={isAuthenticating} />
        </div>
      )}

      {phase === 'loading' ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--c--globals--spacings--6, 24px)' }}>
          <Loader />
        </div>
      ) : (
        <>
          {/* Identity header: avatar + name (prominent) + email. */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 4 }}>
            <ProfileAvatar label={primary} />
            <div style={{ minWidth: 0 }}>
              <p style={{ fontSize: 18, fontWeight: 700, margin: 0, wordBreak: 'break-word' }}>{primary}</p>
              {secondary && (
                <p
                  style={{
                    fontSize: 13,
                    margin: '2px 0 0',
                    color: 'var(--c--contextuals--content--surface--secondary, #666)',
                    wordBreak: 'break-all',
                  }}
                >
                  {secondary}
                </p>
              )}
            </div>
          </div>

          {error && (
            <div style={{ margin: '12px 0 0' }}>
              <Alert type={VariantType.ERROR}>{error}</Alert>
            </div>
          )}

          {fingerprint ? (
            <>
              <p style={{ fontSize: 13, textAlign: 'left', margin: '20px 0 12px' }}>{t('profile.compare_instruction')}</p>
              <div style={{ display: 'flex', justifyContent: 'center' }}>
                <FingerprintDisplay fingerprint={fingerprint} style={{ fontSize: 22, lineHeight: 1.5, textAlign: 'center' }} />
              </div>

              {(decision === 'trusted' || decision === 'refused') && (
                <p
                  style={{
                    fontSize: 13,
                    fontWeight: 600,
                    margin: '16px 0 0',
                    color:
                      decision === 'trusted' ? 'var(--c--globals--colors--success-600, #18753c)' : 'var(--c--globals--colors--error-500, #ce0500)',
                  }}
                >
                  {t(`profile.decision_${decision}`)}
                </p>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 32 }}>
                <TrustRefuseButtons
                  busy={busy}
                  size="medium"
                  onTrust={() => act(MSG_VAULT_ACCEPT_FINGERPRINT)}
                  onRefuse={() => act(MSG_VAULT_REFUSE_FINGERPRINT)}
                  trustLabel={t('profile.btn_trust')}
                  refuseLabel={t('profile.btn_refuse')}
                />
              </div>
            </>
          ) : (
            <p style={{ fontSize: 13, textAlign: 'center', margin: '24px 0 0', color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
              {t('profile.no_key')}
            </p>
          )}
        </>
      )}
    </div>
  );
}
