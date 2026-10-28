import { Button, VariantType } from '@gouvfr-lasuite/ui-components';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  type MyCouncilRequest,
  askCouncilRecovery,
  fetchCouncilForMe,
  fetchMyCouncilRequest,
  fetchReleasedShares,
  refuseCouncilRequest,
} from '@encryption/src/ui/api/council-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { FingerprintBoxes, Identity } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { type CouncilAuthProps, useCouncilErrors } from '@encryption/src/ui/hooks/useCouncilErrors';
import { useCouncilVault } from '@encryption/src/ui/hooks/useCouncilVault';
import { toTrustedMarkup } from '@encryption/src/ui/trusted-markup';

// Only the meeting screen polls: that is where the person waits for the custodian
// in front of them to hand over the last share.
const MEETING_POLL_MS = 4000;

export interface CouncilRecoveryResult {
  publicKey: string;
  isActiveVault: boolean;
  vaultCreatedAtMillis: number;
  contributors: Array<{ name: string | null; inPerson: boolean }>;
}

interface CouncilRecoveryProps extends CouncilAuthProps {
  getIdToken: () => Promise<string | null>;
  onBack?: () => void;
  /** The vault is open again: the caller runs the forced change of the user's own phrase. */
  onRecovered: (result: CouncilRecoveryResult) => void;
}

type View =
  | { kind: 'loading' }
  | { kind: 'intro'; council: string }
  | { kind: 'unavailable' }
  | { kind: 'request'; request: MyCouncilRequest; fingerprint: string; qr: string | null }
  | { kind: 'other-browser'; request: MyCouncilRequest }
  | { kind: 'recovering' };

async function qrFor(fingerprint: string): Promise<string | null> {
  try {
    const { default: QRCode } = await import('qrcode');

    return await QRCode.toString(fingerprint, { type: 'svg', width: 202, margin: 0 });
  } catch {
    return null;
  }
}

/**
 * A locked-out user asks their council (shamir.md §7). They are told little on
 * purpose: "in progress", then "go and see one of these people", whose names
 * appear only once the remote approvals are in. The last custodian reads the
 * code this browser shows before handing over the last share; the shares meet
 * here, and nowhere else.
 */
export function CouncilRecovery({ getIdToken, onBack, onRecovered, ...auth }: CouncilRecoveryProps) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const { banner, fail, clear } = useCouncilErrors(auth);
  const [view, setView] = useState<View>({ kind: 'loading' });
  const [busy, setBusy] = useState(false);
  const recovering = useRef(false);

  const recover = useCallback(
    async (requestId: string) => {
      if (recovering.current) return;

      recovering.current = true;
      setView({ kind: 'recovering' });

      try {
        const result = await withFreshIdToken(getIdToken, async (idToken) =>
          vault.completeRecovery(await fetchReleasedShares(idToken, requestId), idToken)
        );
        onRecovered(result);
      } catch (err) {
        recovering.current = false;
        fail(err);
        setView({ kind: 'unavailable' });
      }
    },
    [getIdToken, vault, onRecovered, fail]
  );

  const load = useCallback(async () => {
    try {
      const request = await withFreshIdToken(getIdToken, fetchMyCouncilRequest);

      if (!request) {
        const { council, escrow } = await withFreshIdToken(getIdToken, fetchCouncilForMe);
        setView(council && escrow && escrow.health.status !== 'lost' ? { kind: 'intro', council: council.label } : { kind: 'unavailable' });

        return;
      }

      if (request.stage === 'released') {
        await recover(request.id);

        return;
      }

      const key = await vault.requestKey();
      if (!key) {
        setView({ kind: 'other-browser', request });

        return;
      }

      setView((previous) =>
        previous.kind === 'request' && previous.fingerprint === key.fingerprint
          ? { ...previous, request }
          : { kind: 'request', request, fingerprint: key.fingerprint, qr: null }
      );
      if (request.stage === 'meet') {
        const qr = await qrFor(key.fingerprint);
        setView((previous) => (previous.kind === 'request' ? { ...previous, qr } : previous));
      }
    } catch (err) {
      fail(err);
      setView((previous) => (previous.kind === 'loading' ? { kind: 'unavailable' } : previous));
    }
  }, [getIdToken, vault, recover, fail]);

  useEffect(() => {
    // Wrapped so the state writes sit behind an await: the effect itself writes
    // nothing synchronously.
    void (async () => {
      await load();
    })();
  }, [load]);

  // A check when the page comes back, and short polling while the person is at
  // the meeting: no push needed.
  useEffect(() => {
    const onFocus = () => void load();
    window.addEventListener('focus', onFocus);

    const meeting = view.kind === 'request' && view.request.stage === 'meet';
    const timer = meeting ? window.setInterval(() => void load(), MEETING_POLL_MS) : undefined;

    return () => {
      window.removeEventListener('focus', onFocus);
      if (timer) window.clearInterval(timer);
    };
  }, [load, view]);

  const ask = useCallback(async () => {
    setBusy(true);
    clear();

    try {
      const { ephemeralPublicKey } = await vault.startRequest();
      await withFreshIdToken(getIdToken, (idToken) => askCouncilRecovery(idToken, ephemeralPublicKey));
      await load();
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  }, [vault, getIdToken, load, fail, clear]);

  const refuse = useCallback(
    async (requestId: string) => {
      setBusy(true);
      clear();

      try {
        await withFreshIdToken(getIdToken, (idToken) => refuseCouncilRequest(idToken, requestId));
        await load();
      } catch (err) {
        fail(err);
      } finally {
        setBusy(false);
      }
    },
    [getIdToken, load, fail, clear]
  );

  const back = onBack ? { label: t('onboarding.btn_back'), onClick: onBack, disabled: busy } : undefined;

  if (view.kind === 'loading') return <LoadingScreen />;
  if (view.kind === 'recovering') return <LoadingScreen label={t('council.recovering')} />;

  if (view.kind === 'unavailable') {
    return <Screen back={back} title={t('council.recovery_title')} description={t('council.recovery_unavailable')} banner={banner} />;
  }

  if (view.kind === 'intro') {
    return (
      <Screen
        back={back}
        illustration="shield-restore"
        title={t('council.recovery_title')}
        description={
          <>
            <p>{t('council.recovery_intro', { council: view.council })}</p>
            <p>{t('council.recovery_intro_meeting')}</p>
          </>
        }
        banner={banner}
        actions={
          <Button onClick={ask} disabled={busy}>
            {busy ? t('council.asking') : t('council.ask_button', { council: view.council })}
          </Button>
        }
      />
    );
  }

  if (view.kind === 'other-browser') {
    return (
      <Screen
        back={back}
        title={t('council.recovery_title')}
        description={t('council.other_browser')}
        banner={banner}
        actions={
          <Button color="error" variant="bordered" onClick={() => refuse(view.request.id)} disabled={busy}>
            {t('council.refuse_and_restart')}
          </Button>
        }
      />
    );
  }

  const { request } = view;
  const refuseButton = (
    <Button variant="tertiary" color="neutral" onClick={() => refuse(request.id)} disabled={busy}>
      {t('council.refuse_request')}
    </Button>
  );

  if (request.stage === 'meet') {
    return (
      <Screen back={back} title={t('council.meet_title')} description={t('council.meet_description')} banner={banner} actions={refuseButton}>
        <ul className={styles.people}>
          {request.meet.map((person) => (
            <li key={person.name}>
              <Identity name={person.name} />
            </li>
          ))}
        </ul>
        <div className={styles.codeCard}>
          {view.qr && (
            <div
              role="img"
              aria-label={t('council.meet_qr_label')}
              className={styles.qr}
              dangerouslySetInnerHTML={{ __html: toTrustedMarkup(view.qr) }}
            />
          )}
          <FingerprintBoxes fingerprint={view.fingerprint} />
          <p className={`${styles.hint} ${styles.hintCenter}`}>{t('council.meet_code_hint')}</p>
        </div>
      </Screen>
    );
  }

  return (
    <Screen
      back={back}
      illustration="shield-gear"
      title={t('council.in_progress_title')}
      description={
        <>
          <p>{t('council.in_progress_description', { council: request.council_label })}</p>
          <p>{t('council.in_progress_email')}</p>
        </>
      }
      banner={
        <>
          {banner}
          <Notice type={VariantType.INFO}>{t('council.in_progress_expires', { date: new Date(request.expires_at_millis) })}</Notice>
        </>
      }
      actions={
        <>
          <Button variant="bordered" color="neutral" onClick={() => void load()} disabled={busy}>
            {t('council.check_again')}
          </Button>
          {refuseButton}
        </>
      }
    />
  );
}
