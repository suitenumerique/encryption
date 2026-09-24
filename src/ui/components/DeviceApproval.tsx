import { Alert, Button, Loader, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { Icon } from '@gouvfr-lasuite/ui-kit';
import type { TFunction } from 'i18next';
import jsQR from 'jsqr';
import QRCode from 'qrcode';
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { MSG_VAULT_SIGN_REQUEST } from '@encryption/src/shared/constants';
import { ApiError, approveDevicePath } from '@encryption/src/ui/api/client';
import { approveDeviceRequest, fetchDeviceApproval, fetchPendingDeviceApprovals, requestDeviceApproval } from '@encryption/src/ui/api/vault-client';
import { SessionExpiredError, withFreshToken } from '@encryption/src/ui/auth/session-expired';
import { DecimalCodeInput } from '@encryption/src/ui/components/DecimalCodeInput';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import { FingerprintBoxes } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { useSessionExpired } from '@encryption/src/ui/hooks/useSessionExpired';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

interface DeviceApprovalProps {
  getToken: () => Promise<string | null>;
  onBack?: () => void;
  onClose: () => void;
  onAdopted?: () => void;
  onReconnect?: () => void;
  isAuthenticating?: boolean;
  currentAccessToken?: string | null;
}

const POLL_INTERVAL_MS = 3000;
// The server's approval row is one-shot: once polled, the wrapped VRK exists only
// in this tab. Completion is therefore retried across ticks before giving up.
const COMPLETION_MAX_FAILURES = 5;

// --- Camera QR scanner: streams the rear camera and decodes with jsQR ---
function QrScanner({ onDecode, onUnavailable, t }: { onDecode: (text: string) => void; onUnavailable: () => void; t: TFunction }) {
  const videoRef = useRef<HTMLVideoElement | null>(null);

  useEffect(() => {
    let stream: MediaStream | null = null;
    let raf = 0;
    let cancelled = false;
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });

    const tick = () => {
      if (cancelled) return;
      const video = videoRef.current;

      if (video && ctx && video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

        const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const found = jsQR(img.data, img.width, img.height);

        if (found?.data) {
          onDecode(found.data);

          return; // stop the loop; the parent unmounts the scanner
        }
      }

      raf = requestAnimationFrame(tick);
    };

    (async () => {
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        if (cancelled) {
          stream.getTracks().forEach((tr) => tr.stop());

          return;
        }
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          await videoRef.current.play();
        }
        raf = requestAnimationFrame(tick);
      } catch {
        // No camera / permission denied — fall back to manual entry.
        onUnavailable();
      }
    })();

    return () => {
      cancelled = true;
      cancelAnimationFrame(raf);
      stream?.getTracks().forEach((tr) => tr.stop());
    };
  }, [onDecode, onUnavailable]);

  return (
    <div className={styles.center}>
      <video
        ref={videoRef}
        muted
        playsInline
        style={{ width: '100%', maxWidth: 302, borderRadius: 8, background: '#000', aspectRatio: '1 / 1', objectFit: 'cover' }}
      />
      <p className={`${styles.hint} ${styles.hintCenter}`}>{t('device_approval.scan_hint')}</p>
    </div>
  );
}

export function DeviceApproval({
  getToken,
  onBack,
  onClose,
  onAdopted,
  onReconnect,
  isAuthenticating = false,
  currentAccessToken = null,
}: DeviceApprovalProps) {
  const { t } = useTranslation('common');
  const { hasKeys, startDeviceApproval, completeDeviceApproval, approveDevice, request } = useEncryptionContext();

  const [role, setRole] = useState<'loading' | 'new' | 'enrolled'>('loading');
  const [error, setError] = useState<string | null>(null);
  const { sessionExpired, markSessionExpired } = useSessionExpired(currentAccessToken, isAuthenticating);

  // Decide the role: a device with no keys is the NEW device to enroll; a device
  // that already has keys can APPROVE another.
  useEffect(() => {
    hasKeys()
      .then(({ hasKeys: has }) => setRole(has ? 'enrolled' : 'new'))
      .catch(() => setRole('new'));
  }, [hasKeys]);

  const onError = useCallback(
    (err: unknown) => {
      if (err instanceof SessionExpiredError) {
        markSessionExpired();
      } else {
        setError((err as Error).message);
      }
    },
    [markSessionExpired]
  );

  // Ask the vault (which holds the identity key) to sign a covered request; the
  // interface only holds the OIDC token.
  const signRequest = useCallback(
    async (method: string, path: string, body?: string): Promise<string> => {
      const { signature } = (await request(MSG_VAULT_SIGN_REQUEST, { method, path, body })) as { signature: string };

      return signature;
    },
    [request]
  );

  if (role === 'loading') {
    return <LoadingScreen />;
  }

  const banner = (
    <>
      {sessionExpired && onReconnect && <SessionExpiredAlert onReconnect={onReconnect} isAuthenticating={isAuthenticating} />}
      {error && <Alert type={VariantType.ERROR}>{error}</Alert>}
    </>
  );

  return role === 'new' ? (
    <NewDeviceSide
      getToken={getToken}
      onError={onError}
      onBack={onBack}
      onClose={onClose}
      onAdopted={onAdopted}
      startDeviceApproval={startDeviceApproval}
      completeDeviceApproval={completeDeviceApproval}
      banner={banner}
      t={t}
    />
  ) : (
    <EnrolledDeviceSide
      getToken={getToken}
      onError={onError}
      onBack={onBack}
      onClose={onClose}
      approveDevice={approveDevice}
      signRequest={signRequest}
      banner={banner}
      t={t}
    />
  );
}

// --- New device: show a pairing code, wait for the enrolled device to forward the VRK ---
function NewDeviceSide({
  getToken,
  onError,
  onBack,
  onClose,
  onAdopted,
  startDeviceApproval,
  completeDeviceApproval,
  banner,
  t,
}: {
  getToken: () => Promise<string | null>;
  onError: (err: unknown) => void;
  onBack?: () => void;
  onClose: () => void;
  onAdopted?: () => void;
  startDeviceApproval: () => Promise<{ devicePublicKey: string; decimalFingerprint: string }>;
  completeDeviceApproval: (wrapped: string, token: string | null) => Promise<{ adopted: boolean }>;
  banner: ReactNode;
  t: TFunction;
}) {
  const backLink = onBack ? { label: t('onboarding.btn_back'), onClick: onBack } : undefined;
  const [started, setStarted] = useState(false);
  const [qr, setQr] = useState<string | null>(null);
  const [decimalFingerprint, setDecimalFingerprint] = useState<string | null>(null);
  const [revealCode, setRevealCode] = useState(false);
  const [copied, setCopied] = useState(false);
  const [done, setDone] = useState(false);
  const requestIdRef = useRef<string | null>(null);
  // Once poll returns the wrapped VRK, the server row is consumed; keep the only
  // copy here so completion can be retried (in refs so effect re-runs keep them).
  const wrappedVrkRef = useRef<string | null>(null);
  const completionFailuresRef = useRef(0);
  const tickBusyRef = useRef(false);

  const start = useCallback(async () => {
    try {
      const { devicePublicKey, decimalFingerprint: dfp } = await startDeviceApproval();
      const requestId = await withFreshToken(getToken, async (token) => {
        const data = await requestDeviceApproval(token, { device_public_key: devicePublicKey });

        return data.request_id;
      });

      requestIdRef.current = requestId;

      // The QR encodes the 128-bit decimal fingerprint (small QR). Scanning it is
      // the same verification as typing it: the enrolled device fetches the key
      // from the server and refuses to wrap unless its fingerprint matches.
      setQr(await QRCode.toDataURL(dfp, { width: 220, margin: 2 }));
      setDecimalFingerprint(dfp);
      setStarted(true);
    } catch (err) {
      onError(err);
    }
  }, [getToken, startDeviceApproval, onError]);

  // Poll for the forwarded VRK once the request is registered. Polling consumes
  // the one-shot server row, so a completion failure must NOT drop the payload:
  // it is retained in a ref and completion is retried on later ticks (the vault
  // keeps its ephemeral key on failure), giving up only after several
  // consecutive failures.
  useEffect(() => {
    if (!started || !requestIdRef.current || done) return;

    let cancelled = false;
    const tick = async () => {
      if (tickBusyRef.current) return;
      tickBusyRef.current = true;

      try {
        if (wrappedVrkRef.current === null) {
          // 425 means "still pending", which is a normal poll outcome, not a failure.
          const forwarded = await withFreshToken(getToken, async (token) => {
            try {
              const data = await fetchDeviceApproval(token, requestIdRef.current!);

              return data ?? null;
            } catch (err) {
              if (err instanceof ApiError && err.status === 425) return null;
              throw err;
            }
          });
          // Store before the cancellation check: if the effect re-ran mid-poll,
          // the next interval picks the payload up instead of losing it.
          if (forwarded) wrappedVrkRef.current = forwarded.wrapped_device_bootstrap;
          if (cancelled || !forwarded) return;
        }

        await withFreshToken(getToken, (token) => completeDeviceApproval(wrappedVrkRef.current!, token));

        if (cancelled) return;

        clearInterval(timer);
        setDone(true);
        onAdopted?.();
      } catch (err) {
        if (cancelled) return;

        if (wrappedVrkRef.current === null) {
          // Poll failed before anything was consumed server-side: abort as before.
          clearInterval(timer);
          onError(err);
        } else if (err instanceof SessionExpiredError) {
          // Show the reconnect banner but keep retrying: completion goes through
          // once a fresh token is available.
          onError(err);
        } else {
          completionFailuresRef.current += 1;
          if (completionFailuresRef.current >= COMPLETION_MAX_FAILURES) {
            clearInterval(timer);
            onError(err);
          }
        }
      } finally {
        tickBusyRef.current = false;
      }
    };

    // The approval may already be there (the other device was quick, or this is
    // a re-render): ask at once, then on the interval.
    void tick();
    const timer = setInterval(() => void tick(), POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [started, done, getToken, completeDeviceApproval, onAdopted, onError]);

  if (done) {
    return (
      <Screen
        illustration="shield-check"
        title={t('device_approval.new_success_title')}
        description={t('device_approval.new_success')}
        actions={<Button onClick={onClose}>{t('device_approval.btn_done')}</Button>}
      />
    );
  }

  if (!started) {
    return (
      <Screen
        back={backLink}
        title={t('device_approval.new_title')}
        description={t('device_approval.new_intro')}
        banner={banner}
        actions={
          <Button onClick={start} icon={<Icon aria-hidden name="qr_code_2" />}>
            {t('device_approval.btn_start')}
          </Button>
        }
      />
    );
  }

  return (
    <Screen back={backLink} title={t('device_approval.new_title')} description={t('device_approval.new_code_hint')} banner={banner}>
      <div className={styles.center}>
        {qr && (
          <img
            src={qr}
            alt="pairing QR code"
            style={{ display: 'block', borderRadius: 8, border: '1px solid var(--c--contextuals--border--surface--primary)' }}
          />
        )}

        {/* No-camera fallback: reveal the long decimal code to type by hand. */}
        {decimalFingerprint &&
          (!revealCode ? (
            <Button size="small" variant="tertiary" className={styles.linkButton} onClick={() => setRevealCode(true)}>
              {t('device_approval.new_reveal_code')}
            </Button>
          ) : (
            <>
              <p className={`${styles.hint} ${styles.hintCenter}`}>{t('device_approval.new_manual_hint')}</p>
              <FingerprintBoxes fingerprint={decimalFingerprint} />
              <Button
                size="small"
                variant="tertiary"
                color={copied ? 'success' : 'neutral'}
                icon={<Icon aria-hidden name={copied ? 'check' : 'content_copy'} size={16} />}
                onClick={() => {
                  void navigator.clipboard.writeText(decimalFingerprint).then(() => {
                    setCopied(true);
                    window.setTimeout(() => setCopied(false), 1500);
                  });
                }}
              >
                {copied ? t('device_approval.copied') : t('device_approval.copy_code')}
              </Button>
            </>
          ))}

        <div className={styles.waiting}>
          <Loader />
          <span>{t('device_approval.new_waiting')}</span>
        </div>
      </div>
    </Screen>
  );
}

// --- Enrolled device: scan (or type) the new device's code and forward the VRK ---
function EnrolledDeviceSide({
  getToken,
  onError,
  onBack,
  onClose,
  approveDevice,
  signRequest,
  banner,
  t,
}: {
  getToken: () => Promise<string | null>;
  onError: (err: unknown) => void;
  onBack?: () => void;
  onClose: () => void;
  approveDevice: (devicePublicKey: string, expectedDecimal: string) => Promise<{ wrappedDeviceBootstrap: string }>;
  signRequest: (method: string, path: string, body?: string) => Promise<string>;
  banner: ReactNode;
  t: TFunction;
}) {
  const backLink = onBack ? { label: t('onboarding.btn_back'), onClick: onBack } : undefined;
  const [mode, setMode] = useState<'scan' | 'manual'>('scan');
  const [cameraAvailable, setCameraAvailable] = useState(true);
  const [codeInput, setCodeInput] = useState('');
  const [codeComplete, setCodeComplete] = useState(false);
  const [isPending, setIsPending] = useState(false);
  const [noMatch, setNoMatch] = useState(false);
  const [done, setDone] = useState(false);

  // Start each visit to the manual screen with an empty code.
  const enterManualEntry = useCallback(() => {
    setMode('manual');
    setCodeInput('');
    setCodeComplete(false);
    setNoMatch(false);
  }, []);

  // One path for both scan and manual: the code is the new device's decimal
  // fingerprint. We fetch this account's pending requests, and the vault confirms
  // which one's server-provided key has that fingerprint (refusing to wrap unless
  // one matches). A tampered/substituted key from the server would not match, so
  // it is rejected. Camera scanning just auto-fills the same digits.
  const submitCode = useCallback(
    async (rawCode: string) => {
      const normalized = rawCode.replace(/\D/g, '');
      if (normalized.length === 0 || isPending) return;

      setIsPending(true);
      setNoMatch(false);

      try {
        const pendingSig = await signRequest('GET', '/api/vault/approvals/pending');
        const { approvals } = await withFreshToken(getToken, (token) => fetchPendingDeviceApprovals(token, pendingSig));

        let matched: { requestId: string; wrappedDeviceBootstrap: string } | null = null;
        for (const a of approvals) {
          try {
            const { wrappedDeviceBootstrap } = await approveDevice(a.device_public_key, normalized);
            matched = { requestId: a.request_id, wrappedDeviceBootstrap };

            break;
          } catch {
            // Fingerprint mismatch for this pending request; try the next one.
          }
        }

        if (!matched) {
          // Stop the camera so it does not re-scan the same code
          if (mode === 'scan') enterManualEntry();
          setNoMatch(true);

          return;
        }

        // Sign the exact body the request helper will send (same serialization).
        const approveBody = JSON.stringify({ wrapped_device_bootstrap: matched.wrappedDeviceBootstrap });
        const approveSig = await signRequest('POST', approveDevicePath(matched.requestId), approveBody);
        await withFreshToken(getToken, (token) =>
          approveDeviceRequest(token, matched!.requestId, { wrapped_device_bootstrap: matched!.wrappedDeviceBootstrap }, approveSig)
        );

        setDone(true);
      } catch (err) {
        onError(err);
        enterManualEntry();
      } finally {
        setIsPending(false);
      }
    },
    [isPending, getToken, approveDevice, signRequest, onError, mode, enterManualEntry]
  );

  if (done) {
    return (
      <Screen
        illustration="shield-check"
        title={t('device_approval.approve_success_title')}
        description={t('device_approval.approve_success')}
        actions={<Button onClick={onClose}>{t('device_approval.btn_done')}</Button>}
      />
    );
  }

  return (
    <Screen
      back={backLink}
      title={t('device_approval.approve_title')}
      description={mode === 'manual' ? t('device_approval.manual_intro') : t('device_approval.approve_intro')}
      banner={banner}
      actions={
        mode === 'manual' ? (
          <Button onClick={() => submitCode(codeInput)} disabled={isPending || !codeComplete}>
            {isPending ? t('device_approval.approving') : t('device_approval.btn_approve')}
          </Button>
        ) : undefined
      }
    >
      {mode === 'scan' && !isPending && (
        <>
          <QrScanner
            onDecode={submitCode}
            onUnavailable={() => {
              setCameraAvailable(false);
              enterManualEntry();
            }}
            t={t}
          />
          <div style={{ textAlign: 'center' }}>
            <Button size="small" variant="tertiary" color="neutral" onClick={enterManualEntry}>
              {t('device_approval.enter_code_instead')}
            </Button>
          </div>
        </>
      )}

      {mode === 'manual' && (
        <>
          <DecimalCodeInput
            onChange={(digits, complete) => {
              setCodeInput(digits);
              setCodeComplete(complete);
              setNoMatch(false);
            }}
          />
          {noMatch && <Alert type={VariantType.ERROR}>{t('device_approval.code_no_match')}</Alert>}
          {cameraAvailable && (
            <div style={{ textAlign: 'center' }}>
              <Button
                size="small"
                variant="tertiary"
                color="neutral"
                icon={<Icon aria-hidden name="qr_code_scanner" size={16} />}
                onClick={() => {
                  setNoMatch(false);
                  setMode('scan');
                }}
              >
                {t('device_approval.scan_instead')}
              </Button>
            </div>
          )}
        </>
      )}
    </Screen>
  );
}
