import { Button, Checkbox, VariantType } from '@gouvfr-lasuite/ui-components';
import { useCallback, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { base64ToUint8 } from '@encryption/src/crypto/encryption-backup';
import { DOMAIN_COUNCIL_REQUEST_FINGERPRINT } from '@encryption/src/shared/crypto-domains';
import { computeDecimalFingerprint, normalizeDecimalFingerprint } from '@encryption/src/shared/decimal-fingerprint';
import { VaultErrorCode, isVaultError } from '@encryption/src/shared/vault-error';
import {
  type CouncilRequestSummary,
  type CustodianRequestDetail,
  contributeToCouncilRequest,
  fetchCustodianRequest,
} from '@encryption/src/ui/api/council-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { DecimalCodeInput } from '@encryption/src/ui/components/DecimalCodeInput';
import { QrScanner } from '@encryption/src/ui/components/QrScanner';
import { Identity } from '@encryption/src/ui/components/layout/IdentityCard';
import { Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { useCouncilAction } from '@encryption/src/ui/hooks/useCouncilAction';
import type { CouncilAuthProps } from '@encryption/src/ui/hooks/useCouncilErrors';
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

/** A code read on the person's screen that is the request's: the hand-over waits for the custodian's confirmation. */
interface MatchedCode {
  detail: CustodianRequestDetail;
  code: string;
}

/**
 * A custodian hands over their share of one request (architecture.md F.3). Remotely,
 * it is an approval ("I know this request is legitimate"), worth nothing alone.
 * In person, the custodian scans or types the code on the person's own screen;
 * a matching code only unlocks the hand-over, which the custodian confirms after
 * checking who is in front of them. The vault checks the code again and refuses
 * to hand the share to any other key.
 */
export function CouncilHandOver({ getIdToken, councilLabel, request, mode, onBack, onDone, ...auth }: CouncilHandOverProps) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const { banner, clear, busy, run } = useCouncilAction(auth);
  const [scan, setScan] = useState(true);
  const [cameraAvailable, setCameraAvailable] = useState(true);
  const [code, setCode] = useState('');
  const [complete, setComplete] = useState(false);
  const [mismatch, setMismatch] = useState(false);
  const [matched, setMatched] = useState<MatchedCode | null>(null);
  const [identityChecked, setIdentityChecked] = useState(false);
  const [done, setDone] = useState<string | null>(null);
  // A scanner keeps decoding the same QR while it stays in view: only the first one counts.
  const decoded = useRef(false);

  const name = request.user_name ?? request.user_email;

  const readAgain = useCallback(
    (withCamera: boolean) => {
      decoded.current = false;
      setMatched(null);
      setIdentityChecked(false);
      setMismatch(false);
      setScan(withCamera);
      clear();
    },
    [clear]
  );

  const checkCode = useCallback(
    async (read: string) => {
      setScan(false);
      setMismatch(false);

      await run(async () => {
        const detail = await withFreshIdToken(getIdToken, (idToken) => fetchCustodianRequest(idToken, request.id));
        const expected = await computeDecimalFingerprint(DOMAIN_COUNCIL_REQUEST_FINGERPRINT, base64ToUint8(detail.ephemeral_public_key));
        const digits = normalizeDecimalFingerprint(read);

        if (digits === expected) setMatched({ detail, code: digits });
        else setMismatch(true);
      }, 'check');
    },
    [run, getIdToken, request.id]
  );

  const handOver = useCallback(
    async (match: MatchedCode | null) => {
      await run(async () => {
        try {
          const result = await withFreshIdToken(getIdToken, async (idToken) => {
            const detail = match?.detail ?? (await fetchCustodianRequest(idToken, request.id));
            const body = await vault.contribute(detail, mode === 'in-person', match?.code);

            return contributeToCouncilRequest(idToken, vault.sign, request.id, body);
          });
          setDone(result.stage);
        } catch (err) {
          // The request's key changed after the code was read: read it again.
          if (!isVaultError(err) || err.code !== VaultErrorCode.INVALID_KEY_BINDING) throw err;
          setMatched(null);
          setIdentityChecked(false);
          setMismatch(true);
        }
      }, 'hand-over');
    },
    [run, getIdToken, request.id, vault, mode]
  );

  const back = { label: t('onboarding.btn_back'), onClick: onBack, disabled: busy !== null };

  if (done) {
    return (
      <Screen
        illustration="shield-check"
        title={t('council.handed_over_title')}
        description={
          done === 'released'
            ? t('council.handed_over_released', { name })
            : done === 'cooldown'
              ? t('council.handed_over_cooldown', { name })
              : t('council.handed_over_waiting', { name })
        }
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
          <Button onClick={() => handOver(null)} disabled={busy !== null}>
            {busy ? t('council.handing_over') : t('council.remote_button')}
          </Button>
        }
      >
        {person}
      </Screen>
    );
  }

  const screenBanner = (
    <>
      {banner}
      <Notice type={VariantType.WARNING}>{t('council.in_person_check_person')}</Notice>
    </>
  );

  if (matched) {
    return (
      <Screen
        back={back}
        title={t('council.in_person_title')}
        description={t('council.in_person_description', { name })}
        descriptionSize="xs"
        banner={screenBanner}
        actions={
          <Button onClick={() => handOver(matched)} disabled={busy !== null || !identityChecked}>
            {busy ? t('council.handing_over') : t('council.in_person_button')}
          </Button>
        }
      >
        {person}
        <Notice type={VariantType.SUCCESS}>{t('council.code_matches', { name })}</Notice>
        <Checkbox
          label={t('council.identity_checked', { name })}
          checked={identityChecked}
          onChange={() => setIdentityChecked((value) => !value)}
          disabled={busy !== null}
        />
        <Button className={styles.textLink} size="nano" variant="tertiary" color="neutral" onClick={() => readAgain(false)} disabled={busy !== null}>
          {t('council.read_another_code')}
        </Button>
      </Screen>
    );
  }

  return (
    <Screen
      back={back}
      title={t('council.in_person_title')}
      description={t('council.in_person_description', { name })}
      descriptionSize="xs"
      banner={screenBanner}
      actions={
        !scan ? (
          <Button onClick={() => checkCode(code)} disabled={busy !== null || !complete || mismatch}>
            {busy ? t('council.checking_code') : t('council.check_code')}
          </Button>
        ) : undefined
      }
    >
      {person}
      {scan && busy === null && (
        <>
          <QrScanner
            onDecode={(text) => {
              if (decoded.current) return;
              decoded.current = true;
              void checkCode(text);
            }}
            onUnavailable={() => {
              setCameraAvailable(false);
              setScan(false);
            }}
            label={t('council.scan_label')}
          />
          <Button className={styles.textLink} size="nano" variant="tertiary" color="neutral" onClick={() => readAgain(false)}>
            {t('device_approval.enter_code_instead')}
          </Button>
        </>
      )}
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
            <Button
              className={styles.textLink}
              size="nano"
              variant="tertiary"
              color="neutral"
              onClick={() => readAgain(true)}
              disabled={busy !== null}
            >
              {t('device_approval.scan_instead')}
            </Button>
          )}
        </>
      )}
    </Screen>
  );
}
