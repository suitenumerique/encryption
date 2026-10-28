import { Button, VariantType } from '@gouvfr-lasuite/ui-components';
import { useCallback, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { VaultErrorCode, isVaultError } from '@encryption/src/shared/vault-error';
import { type CouncilRequestSummary, contributeToCouncilRequest, fetchCustodianRequest } from '@encryption/src/ui/api/council-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { DecimalCodeInput } from '@encryption/src/ui/components/DecimalCodeInput';
import { QrScanner } from '@encryption/src/ui/components/QrScanner';
import { Identity } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { type CouncilAuthProps, useCouncilErrors } from '@encryption/src/ui/hooks/useCouncilErrors';
import { useCouncilVault } from '@encryption/src/ui/hooks/useCouncilVault';

interface CouncilHandOverProps extends CouncilAuthProps {
  getIdToken: () => Promise<string | null>;
  councilLabel: string;
  request: CouncilRequestSummary;
  /** `remote`: an approval from afar; `in-person`: the share goes to the code read on the person's screen. */
  mode: 'remote' | 'in-person';
  onBack: () => void;
  onDone: () => void;
}

/**
 * A custodian hands over their share of one request (shamir.md §7.3). Remotely,
 * it is an approval ("I know this request is legitimate"), worth nothing alone.
 * In person, the custodian scans or types the code on the person's own screen,
 * and the vault refuses to hand the share to any other key.
 */
export function CouncilHandOver({ getIdToken, councilLabel, request, mode, onBack, onDone, ...auth }: CouncilHandOverProps) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const { banner, fail, clear } = useCouncilErrors(auth);
  const [scan, setScan] = useState(true);
  const [cameraAvailable, setCameraAvailable] = useState(true);
  const [code, setCode] = useState('');
  const [complete, setComplete] = useState(false);
  const [mismatch, setMismatch] = useState(false);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);

  const name = request.user_name ?? request.user_email;

  const handOver = useCallback(
    async (meetingCode?: string) => {
      if (busy) return;

      setBusy(true);
      setMismatch(false);
      clear();

      try {
        const result = await withFreshIdToken(getIdToken, async (idToken) => {
          const detail = await fetchCustodianRequest(idToken, request.id);
          const body = await vault.contribute(detail, mode === 'in-person', meetingCode);

          return contributeToCouncilRequest(idToken, vault.sign, request.id, body);
        });
        setDone(result.stage);
      } catch (err) {
        if (isVaultError(err) && err.code === VaultErrorCode.INVALID_KEY_BINDING) {
          setMismatch(true);
          setScan(false);
        } else {
          fail(err);
        }
      } finally {
        setBusy(false);
      }
    },
    [busy, getIdToken, request.id, vault, mode, fail, clear]
  );

  const back = { label: t('onboarding.btn_back'), onClick: onBack, disabled: busy };

  if (done) {
    return (
      <Screen
        illustration="shield-check"
        title={t('council.handed_over_title')}
        description={done === 'released' ? t('council.handed_over_released', { name }) : t('council.handed_over_waiting', { name })}
        actions={<Button onClick={onDone}>{t('settings.done')}</Button>}
      />
    );
  }

  const person = (
    <div className={styles.card}>
      <Identity name={name} email={request.user_email} />
      <p className={styles.hint}>{t('council.request_for', { council: councilLabel, date: new Date(request.created_at_millis) })}</p>
    </div>
  );

  if (mode === 'remote') {
    return (
      <Screen
        back={back}
        title={t('council.remote_title')}
        description={
          <>
            <p>{t('council.remote_description', { name })}</p>
            <p>{t('council.remote_worthless_alone')}</p>
          </>
        }
        banner={banner}
        actions={
          <Button onClick={() => handOver()} disabled={busy}>
            {busy ? t('council.handing_over') : t('council.remote_button')}
          </Button>
        }
      >
        {person}
      </Screen>
    );
  }

  return (
    <Screen
      back={back}
      title={t('council.in_person_title')}
      description={t('council.in_person_description', { name })}
      descriptionSize="xs"
      banner={
        <>
          {banner}
          <Notice type={VariantType.WARNING}>{t('council.in_person_check_person')}</Notice>
        </>
      }
      actions={
        !scan ? (
          <Button onClick={() => handOver(code)} disabled={busy || !complete || mismatch}>
            {busy ? t('council.handing_over') : t('council.in_person_button')}
          </Button>
        ) : undefined
      }
    >
      {person}
      {scan && !busy && (
        <>
          <QrScanner
            onDecode={(text) => void handOver(text)}
            onUnavailable={() => {
              setCameraAvailable(false);
              setScan(false);
            }}
            label={t('council.scan_label')}
          />
          <Button className={styles.textLink} size="nano" variant="tertiary" color="neutral" onClick={() => setScan(false)}>
            {t('device_approval.enter_code_instead')}
          </Button>
        </>
      )}
      {scan && busy && <LoadingScreen label={t('council.handing_over')} />}
      {!scan && (
        <>
          <DecimalCodeInput
            invalid={mismatch}
            onChange={(digits, isComplete) => {
              setCode(digits);
              setComplete(isComplete);
              setMismatch(false);
            }}
          />
          {mismatch && (
            <p className={styles.errorText} role="alert">
              {t('council.code_mismatch')}
            </p>
          )}
          {cameraAvailable && (
            <Button className={styles.textLink} size="nano" variant="tertiary" color="neutral" onClick={() => setScan(true)}>
              {t('device_approval.scan_instead')}
            </Button>
          )}
        </>
      )}
    </Screen>
  );
}
