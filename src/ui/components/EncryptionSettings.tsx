import { Alert, Button, Checkbox, Loader, VariantType } from '@gouvfr-lasuite/cunningham-react';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { computeKeyFingerprint, formatFingerprint } from '@encryption/src/crypto/fingerprint';
import type { UserInfo } from '@encryption/src/ui/App';
import { disablePublicKey } from '@encryption/src/ui/api/server-client';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

interface EncryptionSettingsProps {
  userInfo?: UserInfo | null;
  getToken: () => Promise<string | null>;
  onClose: () => void;
  onKeysDestroyed: () => void;
  onOpenDeviceTransferExport?: () => void;
}

export function EncryptionSettings({ userInfo = null, getToken, onClose, onKeysDestroyed, onOpenDeviceTransferExport }: EncryptionSettingsProps) {
  const { t } = useTranslation('common');
  const { isReady, hasKeys, getPublicKey, request } = useEncryptionContext();

  const [keysExist, setKeysExist] = useState<boolean | null>(null);
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [showDangerZone, setShowDangerZone] = useState(false);
  const [confirmDataLoss, setConfirmDataLoss] = useState(false);
  const [alsoDisableServer, setAlsoDisableServer] = useState(false);
  const [confirmServerDisable, setConfirmServerDisable] = useState(false);
  const [confirmFingerprint, setConfirmFingerprint] = useState('');
  const [isPending, setIsPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isReady) return;

    hasKeys()
      .then(({ hasKeys: exists }) => {
        setKeysExist(exists);

        if (exists) {
          getPublicKey().then(({ signaturePublicKey }) => {
            if (signaturePublicKey) {
              computeKeyFingerprint(signaturePublicKey).then(setFingerprint);
            } else {
              setFingerprint(null);
            }
          });
        }
      })
      .catch(() => {
        // Auth may not be set yet — will retry when isReady changes
      });
  }, [isReady, hasKeys, getPublicKey]);

  const fingerprintMatch = !!fingerprint && confirmFingerprint.toLowerCase().replace(/\s/g, '') === fingerprint;
  const canDelete = confirmDataLoss && (!alsoDisableServer || confirmServerDisable) && fingerprintMatch;

  const handleDeleteKeys = useCallback(async () => {
    if (!canDelete) return;

    setIsPending(true);
    setError(null);

    try {
      // Optionally disable the public key on the server first
      if (alsoDisableServer) {
        const freshToken = await getToken();
        if (freshToken) await disablePublicKey(freshToken);
      }

      // Delete local keys
      await request('vault:destroy-keys');
      setKeysExist(false);
      setFingerprint(null);
      setShowDangerZone(false);
      onKeysDestroyed();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setIsPending(false);
    }
  }, [canDelete, alsoDisableServer, getToken, request, onKeysDestroyed]);

  const resetDangerZone = useCallback(() => {
    setShowDangerZone(false);
    setConfirmDataLoss(false);
    setAlsoDisableServer(false);
    setConfirmServerDisable(false);
    setConfirmFingerprint('');
    setError(null);
  }, []);

  if (keysExist === null) {
    return (
      <div
        style={{
          padding: 'var(--c--globals--spacings--4, 16px)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Loader />
        <p>{t('settings.loading')}</p>
      </div>
    );
  }

  return (
    <div style={{ padding: 'var(--c--globals--spacings--4, 16px)' }}>
      <h2>{t('settings.title')}</h2>

      {userInfo?.name && (
        <p style={{ color: 'var(--c--contextuals--content--surface--secondary, #666)', marginBottom: 'var(--c--globals--spacings--3, 12px)' }}>
          {userInfo.name}
          {userInfo.email ? ` (${userInfo.email})` : ''}
        </p>
      )}

      {!keysExist && (
        <div style={{ marginBottom: 'var(--c--globals--spacings--4, 16px)' }}>
          <Alert type={VariantType.INFO}>{t('settings.no_keys')}</Alert>
        </div>
      )}

      {keysExist && fingerprint && (
        <>
          {/* Fingerprint (read-only) */}
          <div
            style={{
              padding: 'var(--c--globals--spacings--4, 16px)',
              background: 'var(--c--contextuals--background--surface--secondary, #f5f5fe)',
              borderRadius: 4,
              marginBottom: 'var(--c--globals--spacings--4, 16px)',
            }}
          >
            <p style={{ fontSize: 13, fontWeight: 700, margin: '0 0 4px' }}>{t('settings.fingerprint_label')}</p>
            <div
              style={{
                fontFamily: 'monospace',
                fontSize: 16,
                letterSpacing: '0.05em',
                padding: 'var(--c--globals--spacings--2, 8px)',
                background: 'var(--c--contextuals--background--surface--primary, #fff)',
                borderRadius: 4,
              }}
            >
              {formatFingerprint(fingerprint)}
            </div>
          </div>

          {/* Transfer to another device */}
          {onOpenDeviceTransferExport && (
            <div style={{ marginBottom: 'var(--c--globals--spacings--4, 16px)' }}>
              <Button variant="secondary" onClick={onOpenDeviceTransferExport}>
                {t('settings.transfer_to_device')}
              </Button>
            </div>
          )}

          {/* Danger zone — hidden by default */}
          {!showDangerZone && (
            <Button variant="tertiary" color="error" onClick={() => setShowDangerZone(true)}>
              {t('settings.show_danger_zone')}
            </Button>
          )}

          {showDangerZone && (
            <div
              style={{
                padding: 'var(--c--globals--spacings--4, 16px)',
                border: '1px solid var(--c--globals--colors--error-500, #ce0500)',
                borderRadius: 4,
              }}
            >
              <p style={{ fontWeight: 700, color: 'var(--c--globals--colors--error-500, #ce0500)', margin: '0 0 12px' }}>
                {t('settings.delete_title')}
              </p>

              <Alert type={VariantType.WARNING}>{t('settings.delete_warning_backup')}</Alert>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 16 }}>
                <Checkbox label={t('settings.confirm_data_loss')} checked={confirmDataLoss} onChange={() => setConfirmDataLoss(!confirmDataLoss)} />

                <div style={{ marginTop: 8, borderTop: '1px solid var(--c--contextuals--border--surface--primary, #ddd)', paddingTop: 12 }}>
                  <Checkbox
                    label={t('settings.also_disable_server', { fingerprint: fingerprint ? formatFingerprint(fingerprint) : '' })}
                    checked={alsoDisableServer}
                    onChange={() => {
                      setAlsoDisableServer(!alsoDisableServer);
                      setConfirmServerDisable(false);
                    }}
                  />
                  {alsoDisableServer && (
                    <div style={{ marginLeft: 24, marginTop: 8 }}>
                      <Alert type={VariantType.ERROR}>{t('settings.disable_server_warning')}</Alert>
                      <div style={{ marginTop: 8 }}>
                        <Checkbox
                          label={t('settings.confirm_server_disable')}
                          checked={confirmServerDisable}
                          onChange={() => setConfirmServerDisable(!confirmServerDisable)}
                        />
                      </div>
                    </div>
                  )}
                </div>

                <div style={{ marginTop: 8, borderTop: '1px solid var(--c--contextuals--border--surface--primary, #ddd)', paddingTop: 12 }}>
                  <p style={{ fontSize: 13, margin: '0 0 8px' }}>{t('settings.confirm_fingerprint_prompt')}</p>
                  <input
                    type="text"
                    value={confirmFingerprint}
                    onChange={(e) => setConfirmFingerprint(e.target.value)}
                    placeholder={fingerprint ? formatFingerprint(fingerprint) : ''}
                    style={{
                      width: '100%',
                      boxSizing: 'border-box',
                      fontFamily: 'monospace',
                      fontSize: 13,
                      padding: 'var(--c--globals--spacings--2, 8px)',
                      borderRadius: 4,
                      border: '1px solid var(--c--contextuals--border--surface--primary, #e5e5e5)',
                    }}
                  />
                </div>
              </div>

              {error && (
                <div style={{ marginTop: 8 }}>
                  <Alert type={VariantType.ERROR}>{error}</Alert>
                </div>
              )}

              <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
                <Button variant="secondary" onClick={resetDangerZone}>
                  {t('onboarding.btn_cancel')}
                </Button>
                <Button color="error" onClick={handleDeleteKeys} disabled={isPending || !canDelete}>
                  {isPending ? t('settings.deleting') : t('settings.delete_button')}
                </Button>
              </div>
            </div>
          )}
        </>
      )}

      <div style={{ marginTop: 'var(--c--globals--spacings--4, 16px)' }}>
        <Button variant="secondary" onClick={onClose}>
          {t('settings.close')}
        </Button>
      </div>
    </div>
  );
}
