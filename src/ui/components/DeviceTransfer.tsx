import { Alert, Button, Loader, VariantType } from '@gouvfr-lasuite/cunningham-react';
import jsQR from 'jsqr';
import QRCode from 'qrcode';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { claimDeviceTransfer, initiateDeviceTransfer, pollDeviceTransfer } from '@encryption/src/ui/api/server-client';

type TransferMode = 'choose' | 'export' | 'import';
type ExportStatus = 'preparing' | 'waiting' | 'claimed' | 'error';
type ImportStatus = 'input' | 'claiming' | 'success' | 'error';

interface DeviceTransferProps {
  getToken: () => Promise<string | null>;
  /** Start directly in import or export mode, skipping the choose screen */
  initialMode?: TransferMode;
  /** Called on old device: vault encrypts key material, returns encrypted payload + transfer key */
  onExportPayload: () => Promise<{ encryptedPayload: string; transferPassphrase: string }>;
  /** Called on new device: vault decrypts key material using transfer key */
  onImportPayload: (encryptedPayload: string, transferPassphrase: string) => Promise<void>;
  onClose: () => void;
}

/**
 * Device transfer flow:
 *
 * EXPORT (old device):
 * 1. Vault generates a temporary AES-256 key and encrypts: private key + public key + known public keys
 * 2. Encrypted payload → sent to server → gets a 6-digit code
 * 3. Transfer key (AES) → displayed as QR code + text (NEVER sent to server)
 * 4. User sees: the 6-digit code (for server lookup) + the transfer key (for decryption)
 *
 * IMPORT (new device):
 * 1. User enters the 6-digit code → gets encrypted payload from server
 * 2. User enters/scans the transfer key
 * 3. Vault decrypts and imports all key material
 */
export function DeviceTransfer({ getToken, initialMode = 'choose', onExportPayload, onImportPayload, onClose }: DeviceTransferProps) {
  const [mode, setMode] = useState<TransferMode>(initialMode);
  // Back always goes to the caller — the choose screen is only used as a fallback for direct route access
  const handleBack = initialMode === 'choose' ? () => setMode('choose') : onClose;

  return (
    <div style={{ padding: 'var(--c--globals--spacings--4, 16px)' }}>
      {mode === 'choose' && <ChooseMode onExport={() => setMode('export')} onImport={() => setMode('import')} onClose={onClose} />}
      {mode === 'export' && <ExportFlow getToken={getToken} onExportPayload={onExportPayload} onBack={handleBack} />}
      {mode === 'import' && <ImportFlow getToken={getToken} onImportPayload={onImportPayload} onBack={handleBack} />}
    </div>
  );
}

function ChooseMode({ onExport, onImport, onClose }: { onExport: () => void; onImport: () => void; onClose: () => void }) {
  const { t } = useTranslation('common');

  return (
    <>
      <h2>{t('device_transfer.title')}</h2>
      <p>{t('device_transfer.description')}</p>
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 'var(--c--globals--spacings--3, 12px)',
          marginTop: 'var(--c--globals--spacings--4, 16px)',
        }}
      >
        <button
          onClick={onExport}
          style={{
            display: 'block',
            width: '100%',
            textAlign: 'left',
            padding: 'var(--c--globals--spacings--4, 16px)',
            border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
            borderRadius: 8,
            background: 'var(--c--contextuals--background--surface--primary, #fff)',
            cursor: 'pointer',
          }}
        >
          <strong style={{ fontSize: 14 }}>{t('device_transfer.btn_export')}</strong>
          <p style={{ fontSize: 12, margin: '4px 0 0', color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
            {t('device_transfer.btn_export_description')}
          </p>
        </button>
        <button
          onClick={onImport}
          style={{
            display: 'block',
            width: '100%',
            textAlign: 'left',
            padding: 'var(--c--globals--spacings--4, 16px)',
            border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
            borderRadius: 8,
            background: 'var(--c--contextuals--background--surface--primary, #fff)',
            cursor: 'pointer',
          }}
        >
          <strong style={{ fontSize: 14 }}>{t('device_transfer.btn_import')}</strong>
          <p style={{ fontSize: 12, margin: '4px 0 0', color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
            {t('device_transfer.btn_import_description')}
          </p>
        </button>
        <Button variant="tertiary" fullWidth onClick={onClose}>
          {t('device_transfer.btn_cancel')}
        </Button>
      </div>
    </>
  );
}

function ExportFlow({
  getToken,
  onExportPayload,
  onBack,
}: {
  getToken: () => Promise<string | null>;
  onExportPayload: () => Promise<{ encryptedPayload: string; transferPassphrase: string }>;
  onBack: () => void;
}) {
  const { t } = useTranslation('common');
  const [status, setStatus] = useState<ExportStatus>('preparing');
  const [showManual, setShowManual] = useState(false);
  const [code, setCode] = useState<string | null>(null);
  const [transferPassphrase, setTransferKey] = useState<string | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const startExport = useCallback(async () => {
    const token = await getToken();

    if (!token) {
      setError(t('errors.api.unauthorized'));
      setStatus('error');

      return;
    }

    try {
      setStatus('preparing');

      // 1. Vault encrypts key material with a temporary AES key
      const { encryptedPayload, transferPassphrase: key } = await onExportPayload();
      setTransferKey(key);

      // 2. Send encrypted payload to server, get a 6-digit code
      const session = await initiateDeviceTransfer(token, encryptedPayload);
      setCode(session.code);
      setExpiresAt(session.expiresAt);

      // 3. Generate QR code containing BOTH the code and the transfer key
      //    so the new device can scan everything at once
      const qrContent = JSON.stringify({ code: session.code, key });
      const qr = await QRCode.toDataURL(qrContent, { width: 200, margin: 2 });
      setQrDataUrl(qr);
      setStatus('waiting');

      // 4. Poll until claimed (refresh token for each poll to handle long waits)
      pollRef.current = setInterval(async () => {
        try {
          const pollToken = await getToken();

          if (!pollToken) return;

          const result = await pollDeviceTransfer(pollToken, session.code);

          if (result.status === 'claimed') {
            setStatus('claimed');

            if (pollRef.current) clearInterval(pollRef.current);
          } else if (result.status === 'expired') {
            setError(t('errors.api.transfer_code_expired'));
            setStatus('error');

            if (pollRef.current) clearInterval(pollRef.current);
          }
        } catch {
          // Polling error, will retry
        }
      }, 2000);
    } catch (err) {
      setError((err as Error).message);
      setStatus('error');
    }
  }, [getToken, onExportPayload]);

  useEffect(() => {
    startExport();

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [startExport]);

  return (
    <>
      <h2>{t('device_transfer.export_title')}</h2>

      {status === 'preparing' && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
          <Loader />
          <p>{t('device_transfer.export_preparing')}</p>
        </div>
      )}

      {status === 'waiting' && code && transferPassphrase && (
        <div>
          <p>{t('device_transfer.export_scan_instruction')}</p>

          {/* QR Code — primary method */}
          {qrDataUrl && (
            <div
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                margin: 'var(--c--globals--spacings--4, 16px) 0',
                padding: 'var(--c--globals--spacings--4, 16px)',
                border: '2px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
                borderRadius: 8,
                background: 'var(--c--contextuals--background--surface--primary, #fff)',
              }}
            >
              <img src={qrDataUrl} alt="QR Code" style={{ borderRadius: 4, width: 200, height: 200 }} />
            </div>
          )}

          {/* Manual fallback — hidden by default */}
          {!showManual ? (
            <div style={{ textAlign: 'center', marginBottom: 'var(--c--globals--spacings--3, 12px)' }}>
              <Button variant="tertiary" onClick={() => setShowManual(true)}>
                {t('device_transfer.export_show_manual')}
              </Button>
            </div>
          ) : (
            <>
              {/* Code */}
              <div
                style={{
                  padding: 'var(--c--globals--spacings--3, 12px)',
                  background: 'var(--c--contextuals--background--surface--secondary, #f5f5fe)',
                  borderRadius: 8,
                  border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
                  marginBottom: 'var(--c--globals--spacings--3, 12px)',
                }}
              >
                <p style={{ fontSize: 13, fontWeight: 700, margin: '0 0 8px' }}>{t('device_transfer.export_code_label')}</p>
                <div
                  style={{
                    fontSize: 32,
                    fontWeight: 700,
                    letterSpacing: 12,
                    fontFamily: 'monospace',
                    textAlign: 'center',
                    padding: 'var(--c--globals--spacings--3, 12px)',
                    background: 'var(--c--contextuals--background--surface--primary, #fff)',
                    borderRadius: 6,
                    border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
                  }}
                >
                  {code}
                </div>
              </div>

              {/* Passphrase */}
              <div
                style={{
                  padding: 'var(--c--globals--spacings--3, 12px)',
                  background: 'var(--c--contextuals--background--surface--secondary, #f5f5fe)',
                  borderRadius: 8,
                  border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
                  marginBottom: 'var(--c--globals--spacings--3, 12px)',
                }}
              >
                <p style={{ fontSize: 13, fontWeight: 700, margin: '0 0 8px' }}>{t('device_transfer.export_passphrase_label')}</p>
                <textarea
                  readOnly
                  value={transferPassphrase}
                  rows={2}
                  style={{
                    width: '100%',
                    boxSizing: 'border-box',
                    fontFamily: 'monospace',
                    fontSize: 11,
                    padding: 'var(--c--globals--spacings--2, 8px)',
                    borderRadius: 4,
                    border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
                    userSelect: 'all',
                  }}
                />
              </div>
            </>
          )}

          <Alert type={VariantType.INFO}>
            {t('device_transfer.export_expires_at', { time: expiresAt ? new Date(expiresAt).toLocaleTimeString() : '...' })}
          </Alert>

          <p
            style={{
              marginTop: 'var(--c--globals--spacings--3, 12px)',
              fontStyle: 'italic',
              color: 'var(--c--contextuals--content--surface--secondary, #666)',
            }}
          >
            {t('device_transfer.export_waiting')}
          </p>
        </div>
      )}

      {status === 'claimed' && <Alert type={VariantType.SUCCESS}>{t('device_transfer.export_success')}</Alert>}
      {status === 'error' && <Alert type={VariantType.ERROR}>{error}</Alert>}

      <div style={{ marginTop: 'var(--c--globals--spacings--4, 16px)' }}>
        <Button variant="secondary" onClick={onBack}>
          {t('device_transfer.btn_back')}
        </Button>
      </div>
    </>
  );
}

/**
 * Webcam-based QR code scanner using jsQR.
 * Requests camera access, draws frames to a hidden canvas, and decodes QR codes.
 */
function QrScanner({
  onScanned,
  onError,
  onSwitchManual,
}: {
  onScanned: (data: string) => void;
  onError: (message: string) => void;
  onSwitchManual: () => void;
}) {
  const { t } = useTranslation('common');
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const rafRef = useRef<number | null>(null);
  const onScannedRef = useRef(onScanned);
  onScannedRef.current = onScanned;
  const [cameraError, setCameraError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(true);

  useEffect(() => {
    let stopped = false;

    async function startCamera() {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'environment', width: { ideal: 640 }, height: { ideal: 480 } },
        });

        if (stopped) {
          stream.getTracks().forEach((track) => track.stop());

          return;
        }

        streamRef.current = stream;

        const video = videoRef.current;

        if (video) {
          video.srcObject = stream;

          // Wait for video to actually start playing before scanning
          video.onloadeddata = () => {
            if (!stopped) scanLoop();
          };

          video.play().catch(() => {
            // Autoplay may be blocked
          });
        }
      } catch (err) {
        console.error('Camera error:', err);
        setCameraError(t('device_transfer.import_camera_denied'));
      }
    }

    function scanLoop() {
      if (stopped) return;

      const video = videoRef.current;
      const canvas = canvasRef.current;

      if (!video || !canvas || video.videoWidth === 0 || video.videoHeight === 0) {
        rafRef.current = requestAnimationFrame(scanLoop);

        return;
      }

      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;

      const ctx = canvas.getContext('2d', { willReadFrequently: true });

      if (!ctx) {
        rafRef.current = requestAnimationFrame(scanLoop);

        return;
      }

      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const qrResult = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'dontInvert',
      });

      if (qrResult?.data) {
        stopped = true;
        setScanning(false);

        // Stop camera before calling back
        streamRef.current?.getTracks().forEach((track) => track.stop());

        onScannedRef.current(qrResult.data);

        return;
      }

      rafRef.current = requestAnimationFrame(scanLoop);
    }

    startCamera();

    return () => {
      stopped = true;

      if (rafRef.current) cancelAnimationFrame(rafRef.current);

      streamRef.current?.getTracks().forEach((track) => track.stop());
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 'var(--c--globals--spacings--3, 12px)' }}>
      {cameraError ? (
        <>
          <Alert type={VariantType.ERROR}>{cameraError}</Alert>
          <Button variant="secondary" onClick={onSwitchManual}>
            {t('device_transfer.import_switch_manual')}
          </Button>
        </>
      ) : (
        <>
          <p style={{ textAlign: 'center', fontSize: 13, color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
            {t('device_transfer.import_scan_instruction')}
          </p>
          <div
            style={{
              position: 'relative',
              width: '100%',
              maxWidth: 320,
              borderRadius: 8,
              overflow: 'hidden',
              border: '2px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
              background: '#000',
            }}
          >
            <video ref={videoRef} style={{ width: '100%', display: 'block' }} playsInline muted />
            {/* Scan overlay */}
            <div
              style={{
                position: 'absolute',
                inset: '15%',
                border: '2px solid rgba(255, 255, 255, 0.6)',
                borderRadius: 8,
                pointerEvents: 'none',
              }}
            />
          </div>
          <canvas ref={canvasRef} style={{ display: 'none' }} />
          <Button variant="tertiary" onClick={onSwitchManual}>
            {t('device_transfer.import_switch_manual')}
          </Button>
        </>
      )}
    </div>
  );
}

function ImportFlow({
  getToken,
  onImportPayload,
  onBack,
}: {
  getToken: () => Promise<string | null>;
  onImportPayload: (encryptedPayload: string, transferPassphrase: string) => Promise<void>;
  onBack: () => void;
}) {
  const { t } = useTranslation('common');
  const [importMode, setImportMode] = useState<'choose' | 'scan' | 'manual'>('choose');
  const [status, setStatus] = useState<ImportStatus>('input');
  const [code, setCode] = useState('');
  const [transferPassphrase, setTransferKey] = useState('');
  const [error, setError] = useState<string | null>(null);

  const executeClaim = useCallback(
    async (claimCode: string, claimPassphrase: string) => {
      const token = await getToken();

      if (!token) {
        setError(t('errors.api.unauthorized'));
        setStatus('error');

        return;
      }

      setStatus('claiming');
      setError(null);

      try {
        const result = await claimDeviceTransfer(token, claimCode);

        await onImportPayload(result.encryptedPayload, claimPassphrase.trim());

        setStatus('success');
      } catch (err) {
        setError((err as Error).message);
        setStatus('error');
      }
    },
    [getToken, onImportPayload, t]
  );

  const handleClaim = useCallback(() => {
    if (code.length !== 6) {
      setError(t('device_transfer.import_code_length_error'));

      return;
    }

    if (!transferPassphrase.trim()) {
      setError(t('device_transfer.import_passphrase_required'));

      return;
    }

    executeClaim(code, transferPassphrase);
  }, [code, transferPassphrase, executeClaim, t]);

  return (
    <>
      <h2>{t('device_transfer.import_title')}</h2>

      {/* Step 1: Choose method */}
      {importMode === 'choose' && status !== 'success' && (
        <>
          <p>{t('device_transfer.import_choose_method')}</p>
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--c--globals--spacings--3, 12px)',
              marginTop: 'var(--c--globals--spacings--4, 16px)',
            }}
          >
            <button
              onClick={() => setImportMode('scan')}
              style={{
                display: 'block',
                width: '100%',
                textAlign: 'left',
                padding: 'var(--c--globals--spacings--4, 16px)',
                border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
                borderRadius: 8,
                background: 'var(--c--contextuals--background--surface--primary, #fff)',
                cursor: 'pointer',
              }}
            >
              <strong style={{ fontSize: 14 }}>{t('device_transfer.import_scan_qr')}</strong>
              <p style={{ fontSize: 12, margin: '4px 0 0', color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
                {t('device_transfer.import_scan_qr_description')}
              </p>
            </button>
            <button
              onClick={() => setImportMode('manual')}
              style={{
                display: 'block',
                width: '100%',
                textAlign: 'left',
                padding: 'var(--c--globals--spacings--4, 16px)',
                border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
                borderRadius: 8,
                background: 'var(--c--contextuals--background--surface--primary, #fff)',
                cursor: 'pointer',
              }}
            >
              <strong style={{ fontSize: 14 }}>{t('device_transfer.import_manual')}</strong>
              <p style={{ fontSize: 12, margin: '4px 0 0', color: 'var(--c--contextuals--content--surface--secondary, #666)' }}>
                {t('device_transfer.import_manual_description')}
              </p>
            </button>
          </div>
        </>
      )}

      {/* Step 2a: QR scan via webcam */}
      {importMode === 'scan' && status === 'input' && (
        <QrScanner
          onScanned={(data) => {
            try {
              const parsed = JSON.parse(data) as { code?: string; key?: string };

              if (parsed.code && parsed.key) {
                executeClaim(parsed.code, parsed.key);
              } else {
                setError(t('device_transfer.import_scan_invalid'));
                setImportMode('manual');
              }
            } catch {
              setError(t('device_transfer.import_scan_invalid'));
              setImportMode('manual');
            }
          }}
          onError={(msg) => {
            setError(msg);
            setImportMode('manual');
          }}
          onSwitchManual={() => setImportMode('manual')}
        />
      )}

      {/* Claiming state — shown after scan or manual submit */}
      {status === 'claiming' && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 24 }}>
          <Loader />
          <p>{t('device_transfer.import_verifying')}</p>
        </div>
      )}

      {/* Error state — shown after failed claim */}
      {status === 'error' && (
        <div style={{ marginTop: 'var(--c--globals--spacings--3, 12px)' }}>
          {error && <Alert type={VariantType.ERROR}>{error}</Alert>}
          <div style={{ display: 'flex', gap: 'var(--c--globals--spacings--2, 8px)', marginTop: 'var(--c--globals--spacings--3, 12px)' }}>
            <Button
              variant="secondary"
              onClick={() => {
                setStatus('input');
                setError(null);
                setImportMode('choose');
              }}
            >
              {t('onboarding.btn_back')}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setStatus('input');
                setError(null);
                setImportMode('manual');
              }}
            >
              {t('device_transfer.import_switch_manual')}
            </Button>
          </div>
        </div>
      )}

      {/* Step 2b: Manual entry */}
      {importMode === 'manual' && status === 'input' && (
        <>
          <p>{t('device_transfer.import_instructions')}</p>

          <div style={{ marginBottom: 'var(--c--globals--spacings--3, 12px)' }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 700, marginBottom: 4 }}>{t('device_transfer.import_code_label')}</label>
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="000000"
              style={{
                width: '100%',
                boxSizing: 'border-box',
                fontSize: 24,
                fontWeight: 700,
                letterSpacing: 8,
                textAlign: 'center',
                fontFamily: 'monospace',
                padding: 'var(--c--globals--spacings--2, 8px)',
                borderRadius: 4,
                border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
              }}
            />
          </div>

          <div style={{ marginBottom: 'var(--c--globals--spacings--3, 12px)' }}>
            <label style={{ display: 'block', fontSize: 13, fontWeight: 700, marginBottom: 4 }}>{t('device_transfer.import_passphrase_label')}</label>
            <textarea
              value={transferPassphrase}
              onChange={(e) => setTransferKey(e.target.value)}
              placeholder={t('device_transfer.import_passphrase_placeholder')}
              rows={2}
              style={{
                width: '100%',
                boxSizing: 'border-box',
                fontFamily: 'monospace',
                fontSize: 11,
                padding: 'var(--c--globals--spacings--2, 8px)',
                borderRadius: 4,
                border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
              }}
            />
          </div>

          {error && <Alert type={VariantType.ERROR}>{error}</Alert>}

          <div style={{ display: 'flex', gap: 'var(--c--globals--spacings--2, 8px)' }}>
            <Button
              variant="secondary"
              onClick={() => {
                setImportMode('choose');
                setError(null);
              }}
            >
              {t('onboarding.btn_back')}
            </Button>
            <Button onClick={handleClaim} disabled={code.length !== 6 || !transferPassphrase.trim()}>
              {t('device_transfer.import_validate')}
            </Button>
          </div>
        </>
      )}

      {/* Success */}
      {status === 'success' && (
        <div style={{ marginTop: 'var(--c--globals--spacings--3, 12px)' }}>
          <Alert type={VariantType.SUCCESS}>{t('device_transfer.import_success')}</Alert>
        </div>
      )}

      <div style={{ marginTop: 'var(--c--globals--spacings--4, 16px)' }}>
        <Button variant={status === 'success' ? 'primary' : 'secondary'} onClick={onBack}>
          {status === 'success' ? t('device_transfer.btn_done', 'Done') : t('device_transfer.btn_back')}
        </Button>
      </div>
    </>
  );
}
