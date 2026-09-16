import { Alert, VariantType } from '@gouvfr-lasuite/cunningham-react';
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
import { TrustRefuseButtons, recipientLabel } from '@encryption/src/ui/components/RecipientFingerprintControls';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import { Chip, IdentityCard } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Screen } from '@encryption/src/ui/components/layout/Screen';
import { type VaultRegisteredUser } from '@encryption/src/ui/components/verify-recipients-logic';
import { useSessionExpired } from '@encryption/src/ui/hooks/useSessionExpired';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

interface RecipientProfileProps {
  /** The recipient to inspect (their OIDC sub, passed via the context channel). */
  userId: string | null;
  /** Product-supplied display label. Required: a raw OIDC sub is not a profile. */
  label: RecipientLabel;
  onReconnect?: () => void;
  isAuthenticating?: boolean;
  currentAccessToken?: string | null;
}

/** The persisted TOFU decision for a recipient (never 'mismatch': that is transient). */
type Decision = 'unknown' | 'trusted' | 'refused';

/**
 * Per-recipient "Encryption Identity" card, opened explicitly by the product
 * (e.g. clicking a person in its share UI). Shows who the recipient is
 * (avatar + product-supplied name/email), their 40-digit identity fingerprint
 * from the registry for out-of-band comparison, and Trust / Don't trust
 * controls. The recorded decision, if any, is the chip on the card.
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

  const { primary, secondary } = userId ? recipientLabel(label) : { primary: '', secondary: null };

  if (phase === 'loading') {
    return <LoadingScreen />;
  }

  return (
    <Screen
      title={t('profile.title')}
      description={fingerprint ? t('profile.compare_instruction') : undefined}
      banner={
        <>
          {sessionExpired && onReconnect && <SessionExpiredAlert onReconnect={onReconnect} isAuthenticating={isAuthenticating} />}
          {error && <Alert type={VariantType.ERROR}>{error}</Alert>}
        </>
      }
      actions={
        fingerprint && (
          <TrustRefuseButtons
            busy={busy}
            onTrust={() => act(MSG_VAULT_ACCEPT_FINGERPRINT)}
            onRefuse={() => act(MSG_VAULT_REFUSE_FINGERPRINT)}
            trustLabel={t('profile.btn_trust')}
            refuseLabel={t('profile.btn_refuse')}
          />
        )
      }
    >
      {fingerprint ? (
        <IdentityCard
          name={primary}
          secondary={secondary}
          fingerprint={fingerprint}
          tone={decision === 'trusted' ? 'success' : decision === 'refused' ? 'error' : 'default'}
          aside={
            decision === 'trusted' ? (
              <Chip tone="success" icon="check_circle">
                {t('profile.decision_trusted')}
              </Chip>
            ) : decision === 'refused' ? (
              <Chip tone="error" icon="block">
                {t('profile.decision_refused')}
              </Chip>
            ) : undefined
          }
        />
      ) : (
        <>
          <IdentityCard name={primary} secondary={secondary} />
          <p className="enc-hint">{t('profile.no_key')}</p>
        </>
      )}
    </Screen>
  );
}
