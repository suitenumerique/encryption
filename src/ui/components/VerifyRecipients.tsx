import { Alert, Button, Loader, Modal, ModalSize, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  MSG_VAULT_ACCEPT_FINGERPRINT,
  MSG_VAULT_CHECK_FINGERPRINTS,
  MSG_VAULT_FETCH_PUBLIC_KEYS,
  MSG_VAULT_REFUSE_FINGERPRINT,
} from '@encryption/src/shared/constants';
import { type RecipientLabel } from '@encryption/src/shared/schemas/interface-context';
import { SessionExpiredError } from '@encryption/src/ui/auth/session-expired';
import { RecipientFingerprint, RecipientIdentity, TrustRefuseButtons } from '@encryption/src/ui/components/RecipientFingerprintControls';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import {
  type FingerprintCheckResult,
  type SurfacedRecipient,
  type VaultRegisteredUser,
  allRecipientsTrusted,
  buildUserFingerprints,
  surfaceUntrustedRecipients,
} from '@encryption/src/ui/components/verify-recipients-logic';
import { useSessionExpired } from '@encryption/src/ui/hooks/useSessionExpired';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

interface VerifyRecipientsProps {
  /**
   * The recipients (userId → display label) the share targeted, passed via the
   * context channel. Only the ones that block the share get surfaced below; the
   * label is used for display.
   */
  recipients: Record<string, RecipientLabel>;
  /** The sharing user's own id, so the vault never surfaces "self" as untrusted. */
  currentUserId: string | null;
  /** Report the outcome to the SDK: all trusted, or refused/cancelled/closed. */
  onComplete: (outcome: 'resolved' | 'cancelled') => void;
  onReconnect?: () => void;
  isAuthenticating?: boolean;
  currentAccessToken?: string | null;
}

/**
 * One shared trust-decision modal, owned by the interface. The SDK opens this at
 * /verify-recipients whenever a share is blocked because some recipients are not
 * shareable (their key changed, or they were refused). It surfaces each blocking
 * recipient's safety fingerprint for out-of-band comparison and enforces
 * all-or-nothing: the share proceeds only if the user trusts EVERY surfaced
 * recipient; refusing any (or cancelling) aborts the whole share.
 *
 * The whole modal chrome (backdrop + card) is drawn HERE, by a Cunningham Modal,
 * so it matches the rest of the interface; the SDK only mounts this iframe in a
 * transparent full-viewport overlay.
 */
export function VerifyRecipients({
  recipients: recipientLabels,
  currentUserId,
  onComplete,
  onReconnect,
  isAuthenticating = false,
  currentAccessToken = null,
}: VerifyRecipientsProps) {
  const { t } = useTranslation('common');
  const { isReady, request } = useEncryptionContext();

  const [phase, setPhase] = useState<'loading' | 'ready' | 'error'>('loading');
  const [recipients, setRecipients] = useState<SurfacedRecipient[]>([]);
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

  // Resolve each recipient's current identity fingerprint (directory) and its
  // TOFU status (local registry), then surface only the ones that BLOCK the share
  // (mismatch / refused). Runs once per recipient list.
  const recipientKey = Object.keys(recipientLabels).join(',');

  useEffect(() => {
    if (!isReady) return;

    let cancelled = false;

    (async () => {
      try {
        const userIds = recipientKey.length > 0 ? recipientKey.split(',') : [];

        if (userIds.length === 0) {
          if (!cancelled) {
            setRecipients([]);
            setPhase('ready');
          }

          return;
        }

        const { users } = (await request(MSG_VAULT_FETCH_PUBLIC_KEYS, { userIds })) as { users: Record<string, VaultRegisteredUser> };
        const userFingerprints = buildUserFingerprints(userIds, users);

        const { results } = (await request(MSG_VAULT_CHECK_FINGERPRINTS, { userFingerprints, currentUserId })) as {
          results: FingerprintCheckResult[];
        };

        if (cancelled) return;

        setRecipients(surfaceUntrustedRecipients(results));
        setPhase('ready');
      } catch (err) {
        if (!cancelled) onError(err);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [isReady, recipientKey, currentUserId, request, onError]);

  const handleTrust = useCallback(
    async (recipient: SurfacedRecipient) => {
      setBusy(true);
      setError(null);

      try {
        await request(MSG_VAULT_ACCEPT_FINGERPRINT, { userId: recipient.userId, fingerprint: recipient.fingerprint });
        setRecipients((prev) => prev.map((r) => (r.userId === recipient.userId ? { ...r, trusted: true } : r)));
      } catch (err) {
        onError(err);
      } finally {
        setBusy(false);
      }
    },
    [request, onError]
  );

  // Refusing a single recipient aborts the WHOLE share (all-or-nothing). Record
  // the refusal in the registry (shown in red elsewhere) so a suspected key swap
  // keeps failing future shares until the user re-verifies out of band.
  const handleRefuse = useCallback(
    async (recipient: SurfacedRecipient) => {
      setBusy(true);

      try {
        await request(MSG_VAULT_REFUSE_FINGERPRINT, { userId: recipient.userId, fingerprint: recipient.fingerprint });
      } catch {
        // Best-effort: abort regardless of whether the refusal persisted.
      } finally {
        onComplete('cancelled');
      }
    },
    [request, onComplete]
  );

  const allTrusted = allRecipientsTrusted(recipients);

  // Closing the modal (backdrop click / close button) aborts the whole share.
  const close = useCallback(() => {
    if (!busy) onComplete('cancelled');
  }, [busy, onComplete]);

  return (
    <Modal isOpen onClose={close} closeOnClickOutside={!busy} size={ModalSize.MEDIUM} title={t('verify.title')}>
      <div style={{ paddingBottom: 'var(--c--globals--spacings--4, 16px)' }}>
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
            <p style={{ fontSize: 13 }}>{t('verify.explanation')}</p>

            {error && (
              <div style={{ marginTop: 8 }}>
                <Alert type={VariantType.ERROR}>{error}</Alert>
              </div>
            )}

            {recipients.length === 0 ? (
              // Nothing left to verify (e.g. all became trusted concurrently): let the
              // share proceed immediately.
              <Alert type={VariantType.INFO}>{t('verify.nothing_to_verify')}</Alert>
            ) : (
              <>
                <Alert type={VariantType.WARNING}>{t('verify.refuse_aborts')}</Alert>
                <p style={{ fontSize: 13, marginTop: 12 }}>{t('verify.compare_instruction')}</p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 12 }}>
                  {recipients.map((recipient) => (
                    <div
                      key={recipient.userId}
                      style={{
                        padding: 'var(--c--globals--spacings--3, 12px)',
                        background: 'var(--c--contextuals--background--surface--secondary, #f5f5fe)',
                        borderRadius: 4,
                      }}
                    >
                      <RecipientIdentity userId={recipient.userId} label={recipientLabels[recipient.userId]} />
                      <p style={{ fontSize: 12, margin: '0 0 8px', color: 'var(--c--globals--colors--error-500, #ce0500)' }}>
                        {recipient.status === 'mismatch' ? t('verify.note_changed') : t('verify.note_refused')}
                      </p>
                      <RecipientFingerprint fingerprint={recipient.fingerprint} />

                      {recipient.trusted ? (
                        <Alert type={VariantType.SUCCESS}>{t('verify.trusted')}</Alert>
                      ) : (
                        <TrustRefuseButtons busy={busy} onTrust={() => handleTrust(recipient)} onRefuse={() => handleRefuse(recipient)} />
                      )}
                    </div>
                  ))}
                </div>
              </>
            )}

            <div style={{ display: 'flex', gap: 8, justifyContent: 'space-between', marginTop: 16 }}>
              <Button variant="secondary" disabled={busy} onClick={() => onComplete('cancelled')}>
                {t('verify.btn_cancel')}
              </Button>
              <Button disabled={busy || !allTrusted} onClick={() => onComplete('resolved')}>
                {t('verify.btn_confirm')}
              </Button>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
