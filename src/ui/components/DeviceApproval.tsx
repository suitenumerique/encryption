import { Button, Loader, VariantType } from '@gouvfr-lasuite/ui-components';
import { Checkmark, Copy } from '@gouvfr-lasuite/ui-components/icons';
import type { TFunction } from 'i18next';
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { MSG_VAULT_SIGN_REQUEST } from '@encryption/src/shared/constants';
import { ApiError, approveDevicePath } from '@encryption/src/ui/api/client';
import { approveDeviceRequest, fetchDeviceApproval, fetchPendingDeviceApprovals, requestDeviceApproval } from '@encryption/src/ui/api/vault-client';
import { SessionExpiredError, withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { DecimalCodeInput } from '@encryption/src/ui/components/DecimalCodeInput';
import { SessionExpiredAlert } from '@encryption/src/ui/components/SessionExpiredAlert';
import { FingerprintBoxes } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { useSessionExpired } from '@encryption/src/ui/hooks/useSessionExpired';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';
import { toTrustedMarkup } from '@encryption/src/ui/trusted-markup';

interface DeviceApprovalProps {
  getIdToken: () => Promise<string | null>;
  onBack?: () => void;
  onClose: () => void;
  onAdopted?: () => void;
  onReconnect?: () => void;
  isAuthenticating?: boolean;
  currentIdToken?: string | null;
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

    // The decoder is only needed while the camera runs: its own chunk.
    let decode: ((data: Uint8ClampedArray, width: number, height: number) => { data: string } | null) | null = null;

    const tick = () => {
      if (cancelled) return;
      const video = videoRef.current;

      if (video && ctx && video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

        const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const found = decode?.(img.data, img.width, img.height);

        if (found?.data) {
          onDecode(found.data);

          return; // stop the loop; the parent unmounts the scanner
        }
      }

      raf = requestAnimationFrame(tick);
    };

    (async () => {
      try {
        decode = (await import('jsqr')).default;
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

  return <video ref={videoRef} muted playsInline className={styles.scanner} aria-label={t('device_approval.scan_hint')} />;
}

export function DeviceApproval({
  getIdToken,
  onBack,
  onClose,
  onAdopted,
  onReconnect,
  isAuthenticating = false,
  currentIdToken = null,
}: DeviceApprovalProps) {
  const { t } = useTranslation('common');
  const { hasKeys, startDeviceApproval, completeDeviceApproval, approveDevice, request } = useEncryptionContext();

  const [role, setRole] = useState<'loading' | 'new' | 'enrolled'>('loading');
  const [error, setError] = useState<string | null>(null);
  const { sessionExpired, markSessionExpired } = useSessionExpired(currentIdToken, isAuthenticating);

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
  // interface only holds the ID token.
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
      {error && <Notice type={VariantType.ERROR}>{error}</Notice>}
    </>
  );

  return role === 'new' ? (
    <NewDeviceSide
      getIdToken={getIdToken}
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
      getIdToken={getIdToken}
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
  getIdToken,
  onError,
  onBack,
  onClose,
  onAdopted,
  startDeviceApproval,
  completeDeviceApproval,
  banner,
  t,
}: {
  getIdToken: () => Promise<string | null>;
  onError: (err: unknown) => void;
  onBack?: () => void;
  onClose: () => void;
  onAdopted?: () => void;
  startDeviceApproval: () => Promise<{ devicePublicKey: string; decimalFingerprint: string }>;
  completeDeviceApproval: (wrapped: string, idToken: string | null) => Promise<{ adopted: boolean }>;
  banner: ReactNode;
  t: TFunction;
}) {
  const backLink = onBack ? { label: t('onboarding.btn_back'), onClick: onBack } : undefined;
  const [started, setStarted] = useState(false);
  const [startFailed, setStartFailed] = useState(false);
  const startRequested = useRef(false);
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
      const requestId = await withFreshIdToken(getIdToken, async (idToken) => {
        const data = await requestDeviceApproval(idToken, { device_public_key: devicePublicKey });

        return data.request_id;
      });

      requestIdRef.current = requestId;

      // The QR encodes the 128-bit decimal fingerprint (small QR). Scanning it is
      // the same verification as typing it: the enrolled device fetches the key
      // from the server and refuses to wrap unless its fingerprint matches.
      // Inline SVG markup rather than a `data:` PNG: the interface CSP keeps
      // `img-src 'self'`, which blocks data URIs.
      const { default: QRCode } = await import('qrcode');

      setQr(await QRCode.toString(dfp, { type: 'svg', width: 220, margin: 2 }));
      setDecimalFingerprint(dfp);
      setStarted(true);
    } catch (err) {
      // The banner explains the failure (a lapsed session offers Reconnect); the
      // retry below starts again once the cause is dealt with.
      setStartFailed(true);
      onError(err);
    }
  }, [getIdToken, startDeviceApproval, onError]);

  // The pairing request is made at once: the screen exists to show its code.
  useEffect(() => {
    if (startRequested.current) return;

    startRequested.current = true;
    void start();
  }, [start]);

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
          const forwarded = await withFreshIdToken(getIdToken, async (idToken) => {
            try {
              const data = await fetchDeviceApproval(idToken, requestIdRef.current!);

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

        await withFreshIdToken(getIdToken, (idToken) => completeDeviceApproval(wrappedVrkRef.current!, idToken));

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
  }, [started, done, getIdToken, completeDeviceApproval, onAdopted, onError]);

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

  return (
    <Screen
      back={backLink}
      title={t('device_approval.new_title')}
      description={revealCode ? t('device_approval.new_code_intro') : t('device_approval.new_qr_intro')}
      banner={banner}
    >
      <div className={styles.codeCard}>
        {!started && startFailed ? (
          <Button
            onClick={() => {
              setStartFailed(false);
              void start();
            }}
          >
            {t('auth.retry')}
          </Button>
        ) : !started ? (
          <LoadingScreen />
        ) : revealCode && decimalFingerprint ? (
          // No-camera fallback: the same code, in digits to type by hand.
          <>
            <FingerprintBoxes fingerprint={decimalFingerprint} />
            <div className={styles.textLinks}>
              <Button
                size="nano"
                variant="tertiary"
                color={copied ? 'success' : 'neutral'}
                icon={copied ? <Checkmark aria-hidden size={16} /> : <Copy aria-hidden size={16} />}
                onClick={() => {
                  void navigator.clipboard.writeText(decimalFingerprint).then(() => {
                    setCopied(true);
                    window.setTimeout(() => setCopied(false), 1500);
                  });
                }}
              >
                {copied ? t('device_approval.copied') : t('device_approval.copy_code')}
              </Button>
              <Button size="nano" variant="tertiary" color="neutral" onClick={() => setRevealCode(false)}>
                {t('device_approval.show_qr')}
              </Button>
            </div>
          </>
        ) : (
          <>
            {qr && (
              <div
                role="img"
                aria-label={t('device_approval.qr_label')}
                className={styles.qr}
                dangerouslySetInnerHTML={{ __html: toTrustedMarkup(qr) }}
              />
            )}
            <Button size="nano" variant="tertiary" color="neutral" onClick={() => setRevealCode(true)}>
              {t('device_approval.show_code')}
            </Button>
          </>
        )}
      </div>

      {started && (
        <div className={styles.waiting}>
          <Loader size="small" />
          <span>{t('device_approval.new_waiting')}</span>
        </div>
      )}
    </Screen>
  );
}

// --- Enrolled device: scan (or type) the new device's code and forward the VRK ---
function EnrolledDeviceSide({
  getIdToken,
  onError,
  onBack,
  onClose,
  approveDevice,
  signRequest,
  banner,
  t,
}: {
  getIdToken: () => Promise<string | null>;
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
        const { approvals } = await withFreshIdToken(getIdToken, (idToken) => fetchPendingDeviceApprovals(idToken, pendingSig));

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
        await withFreshIdToken(getIdToken, (idToken) =>
          approveDeviceRequest(idToken, matched!.requestId, { wrapped_device_bootstrap: matched!.wrappedDeviceBootstrap }, approveSig)
        );

        setDone(true);
      } catch (err) {
        onError(err);
        enterManualEntry();
      } finally {
        setIsPending(false);
      }
    },
    [isPending, getIdToken, approveDevice, signRequest, onError, mode, enterManualEntry]
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
      description={t('device_approval.approve_intro')}
      descriptionSize="xs"
      banner={banner}
      actions={
        mode === 'manual' ? (
          <Button onClick={() => submitCode(codeInput)} disabled={isPending || !codeComplete || noMatch}>
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
          <Button className={styles.textLink} size="nano" variant="tertiary" color="neutral" onClick={enterManualEntry}>
            {t('device_approval.enter_code_instead')}
          </Button>
        </>
      )}

      {mode === 'scan' && isPending && <LoadingScreen label={t('device_approval.approving')} />}

      {mode === 'manual' && (
        <>
          <DecimalCodeInput
            invalid={noMatch}
            onChange={(digits, complete) => {
              setCodeInput(digits);
              setCodeComplete(complete);
              setNoMatch(false);
            }}
          />
          {noMatch && (
            <p className={styles.errorText} role="alert">
              {t('device_approval.code_no_match')}
            </p>
          )}
          {cameraAvailable && (
            <Button
              className={styles.textLink}
              size="nano"
              variant="tertiary"
              color="neutral"
              onClick={() => {
                setNoMatch(false);
                setMode('scan');
              }}
            >
              {t('device_approval.scan_instead')}
            </Button>
          )}
        </>
      )}
    </Screen>
  );
}
