import { Button, Modal, ModalSize, VariantType } from '@gouvfr-lasuite/ui-components';
import { History, ShieldCheck } from '@gouvfr-lasuite/ui-components/icons';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  type CouncilForMe,
  type EndedCouncilRequest,
  type MyCouncilRequest,
  askCouncilRecovery,
  fetchCouncilForMe,
  fetchMyCouncilRequestState,
  fetchReleasedShares,
  refuseCouncilRequest,
} from '@encryption/src/ui/api/council-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { FingerprintBoxes, Identity } from '@encryption/src/ui/components/layout/IdentityCard';
import { OptionCard } from '@encryption/src/ui/components/layout/OptionCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { useCouncilAction } from '@encryption/src/ui/hooks/useCouncilAction';
import type { CouncilAuthProps } from '@encryption/src/ui/hooks/useCouncilErrors';
import { useCouncilVault } from '@encryption/src/ui/hooks/useCouncilVault';
import { toTrustedMarkup } from '@encryption/src/ui/trusted-markup';

// The meeting screen polls fast (the custodian in front of the person hands over
// the first share), the in-progress one slowly (the remote approvals follow).
const MEETING_POLL_MS = 4000;
const APPROVALS_POLL_MS = 30_000;

export interface CouncilRecoveryResult {
  publicKey: string;
  isActiveVault: boolean;
  vaultCreatedAtMillis: number;
  /** When the user asked the council. */
  requestedAtMillis: number;
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
  | { kind: 'intro'; vaults: CouncilForMe['vaults'] }
  | { kind: 'unavailable' }
  | { kind: 'request'; request: MyCouncilRequest; fingerprint: string; qr: string | null }
  | { kind: 'other-browser'; request: MyCouncilRequest }
  | { kind: 'recovering' }
  | { kind: 'combine-failed'; request: MyCouncilRequest };

async function qrFor(fingerprint: string): Promise<string | null> {
  try {
    const { default: QRCode } = await import('qrcode');

    return await QRCode.toString(fingerprint, { type: 'svg', width: 202, margin: 0 });
  } catch {
    return null;
  }
}

/**
 * A locked-out user asks their council (architecture.md F.3). They are told little on
 * purpose: "go and see one of these people", then "in progress" while the
 * others approve remotely. The custodian they meet reads the code this browser
 * shows before handing over the first share, which every remote vault requires;
 * the shares meet here, and nowhere else.
 */
export function CouncilRecovery({ getIdToken, onBack, onRecovered, ...auth }: CouncilRecoveryProps) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const { banner, fail, busy: running, run } = useCouncilAction(auth);
  const busy = running !== null;
  const [view, setView] = useState<View>({ kind: 'loading' });
  const recovering = useRef(false);
  // A released request whose parts did not combine: not tried again on every check, only on Retry.
  const failedRequestId = useRef<string | null>(null);
  // This browser's last request, ended without the user: told once, kept while the screen is open.
  const [ended, setEnded] = useState<EndedCouncilRequest | null>(null);
  const [revealCode, setRevealCode] = useState(false);
  const [confirmCancel, setConfirmCancel] = useState<string | null>(null);
  // Which vault to ask for, when the council holds more than one: the current one by default.
  const [escrowId, setEscrowId] = useState<string | null>(null);

  const recover = useCallback(
    async (request: MyCouncilRequest) => {
      if (recovering.current) return;

      recovering.current = true;
      setView({ kind: 'recovering' });

      try {
        const result = await withFreshIdToken(getIdToken, async (idToken) =>
          vault.completeRecovery(await fetchReleasedShares(idToken, request.id), idToken)
        );
        onRecovered({ ...result, requestedAtMillis: request.created_at_millis });
      } catch (err) {
        recovering.current = false;
        failedRequestId.current = request.id;
        fail(err);
        setView({ kind: 'combine-failed', request });
      }
    },
    [getIdToken, vault, onRecovered, fail]
  );

  const load = useCallback(async () => {
    try {
      const { request, ended: last } = await withFreshIdToken(getIdToken, fetchMyCouncilRequestState);

      if (!request) {
        // No request open: a key this browser kept from an earlier one is stale.
        // Read first, to tell whether the request that just ended was this browser's.
        const kept = last ? await vault.requestKey() : null;
        if (last && kept && kept.fingerprint === last.ephemeral_fingerprint) setEnded(last);
        await vault.requestKey(null);
        const { vaults } = await withFreshIdToken(getIdToken, fetchCouncilForMe);
        setView(vaults.length > 0 ? { kind: 'intro', vaults } : { kind: 'unavailable' });

        return;
      }

      // A key that is not the open request's means the request was opened elsewhere
      // (or this browser lost it): only cancelling and asking again helps here.
      const key = await vault.requestKey(request.ephemeral_fingerprint);
      if (!key) {
        setView({ kind: 'other-browser', request });

        return;
      }

      if (request.stage === 'released') {
        if (failedRequestId.current === request.id) setView({ kind: 'combine-failed', request });
        else await recover(request);

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

  // A check when the page comes back, short polling while the person is at the
  // meeting, slower while the remote approvals come in: no push needed.
  useEffect(() => {
    const onFocus = () => void load();
    window.addEventListener('focus', onFocus);

    const stage = view.kind === 'request' ? view.request.stage : null;
    const every = stage === 'meet' ? MEETING_POLL_MS : stage === 'in_progress' ? APPROVALS_POLL_MS : null;
    const timer = every ? window.setInterval(() => void load(), every) : undefined;

    return () => {
      window.removeEventListener('focus', onFocus);
      if (timer) window.clearInterval(timer);
    };
  }, [load, view]);

  const ask = useCallback(
    () =>
      run(async () => {
        const { ephemeralPublicKey } = await vault.startRequest();
        await withFreshIdToken(getIdToken, (idToken) => askCouncilRecovery(idToken, ephemeralPublicKey, escrowId ?? undefined));
        setEnded(null);
        await load();
      }),
    [run, vault, getIdToken, load, escrowId]
  );

  const refuse = useCallback(
    (requestId: string) =>
      run(async () => {
        await withFreshIdToken(getIdToken, (idToken) => refuseCouncilRequest(idToken, requestId));
        setConfirmCancel(null);
        failedRequestId.current = null;
        await load();
      }),
    [run, getIdToken, load]
  );

  const back = onBack ? { label: t('onboarding.btn_back'), onClick: onBack, disabled: busy } : undefined;

  // Cancelling covers both a request the user no longer needs and one they never
  // made; it cannot be undone, so it is confirmed first.
  const cancelDialog = (
    <Modal
      isOpen={confirmCancel !== null}
      onClose={() => setConfirmCancel(null)}
      closeOnClickOutside={false}
      size={ModalSize.SMALL}
      aria-label={t('council.cancel_title')}
    >
      <Screen
        title={t('council.cancel_title')}
        description={t('council.cancel_body')}
        banner={banner}
        actionsLayout="row"
        actions={
          <>
            <Button variant="bordered" color="neutral" onClick={() => setConfirmCancel(null)} disabled={busy}>
              {t('council.cancel_keep')}
            </Button>
            <Button color="error" onClick={() => confirmCancel && refuse(confirmCancel)} disabled={busy}>
              {t('council.cancel_confirm')}
            </Button>
          </>
        }
      />
    </Modal>
  );

  // Polled stage changes, read out without moving the focus.
  const liveStage = (
    <p className={styles.visuallyHidden} aria-live="polite">
      {view.kind === 'request' ? (view.request.stage === 'meet' ? t('council.meet_title') : t('council.in_progress_title')) : ''}
    </p>
  );

  if (view.kind === 'loading') return <LoadingScreen />;
  if (view.kind === 'recovering') return <LoadingScreen label={t('council.recovering')} />;

  if (view.kind === 'combine-failed') {
    const { request } = view;

    return (
      <>
        <Screen
          back={back}
          title={t('council.combine_failed_title')}
          description={t('council.combine_failed_description')}
          banner={banner}
          actions={
            <>
              <Button
                onClick={() => {
                  failedRequestId.current = null;
                  void recover(request);
                }}
                disabled={busy}
              >
                {t('council.retry')}
              </Button>
              <Button variant="bordered" color="error" onClick={() => setConfirmCancel(request.id)} disabled={busy}>
                {t('council.combine_restart')}
              </Button>
            </>
          }
        />
        {cancelDialog}
      </>
    );
  }

  if (view.kind === 'unavailable') {
    return <Screen back={back} title={t('council.recovery_title')} description={t('council.recovery_unavailable')} banner={banner} />;
  }

  if (view.kind === 'intro') {
    const chosen = view.vaults.find((v) => v.escrow_id === escrowId) ?? view.vaults[0];
    const date = (millis: number) => new Date(millis);

    return (
      <Screen
        back={back}
        illustration="shield-restore"
        title={t('council.recovery_title')}
        description={
          <>
            <p>{t('council.recovery_intro')}</p>
            <p>{t('council.recovery_intro_meeting')}</p>
            {view.vaults.length > 1 && <p>{t('council.vault_choice')}</p>}
          </>
        }
        banner={
          <>
            {banner}
            {ended && (
              <Notice type={ended.reason === 'expired' ? VariantType.INFO : VariantType.WARNING}>
                {ended.reason === 'expired'
                  ? t('council.ended_expired', { council: ended.council_label, date: date(ended.ended_at_millis) })
                  : t('council.ended_aborted', { council: ended.council_label })}
              </Notice>
            )}
          </>
        }
        actions={
          <Button onClick={ask} disabled={busy}>
            {busy ? t('council.asking') : ended ? t('council.ask_again_button') : t('council.ask_button')}
          </Button>
        }
      >
        <div className={styles.card}>
          <Identity name={chosen.council_label} />
        </div>
        {/* Someone who started over may want back what came before, not the vault of the last few hours. */}
        {view.vaults.length > 1 && (
          <>
            <div className={styles.options} role="radiogroup" aria-label={t('council.vault_choice')}>
              {view.vaults.map((v) => (
                <OptionCard
                  key={v.escrow_id}
                  name="council-vault"
                  selected={chosen.escrow_id === v.escrow_id}
                  onSelect={() => setEscrowId(v.escrow_id)}
                  icon={v.disabled_at_millis === null ? <ShieldCheck aria-hidden size={20} /> : <History aria-hidden size={20} />}
                  title={
                    v.disabled_at_millis === null ? t('council.vault_current') : t('council.vault_retired', { date: date(v.disabled_at_millis) })
                  }
                  description={t('council.vault_created', { date: date(v.created_at_millis) })}
                />
              ))}
            </div>
          </>
        )}
      </Screen>
    );
  }

  if (view.kind === 'other-browser') {
    return (
      <>
        <Screen
          back={back}
          title={t('council.recovery_title')}
          description={t('council.other_browser')}
          banner={banner}
          actions={
            <Button variant="bordered" color="neutral" onClick={() => setConfirmCancel(view.request.id)} disabled={busy}>
              {t('council.cancel_request')}
            </Button>
          }
        />
        {cancelDialog}
      </>
    );
  }

  const { request } = view;
  const cancelButton = (
    <Button variant="bordered" color="error" onClick={() => setConfirmCancel(request.id)} disabled={busy}>
      {t('council.cancel_request')}
    </Button>
  );

  if (request.stage === 'meet') {
    return (
      <>
        <Screen back={back} title={t('council.meet_title')} description={t('council.meet_description')} banner={banner} actions={cancelButton}>
          <ul className={styles.people}>
            {request.meet.map((person, index) => (
              <li key={`${index}:${person.name}`}>
                <Identity name={person.name} />
              </li>
            ))}
          </ul>
          {/* The QR code first, its digits on demand, as for pairing a device. */}
          <div className={styles.codeCard}>
            {view.qr && !revealCode ? (
              <>
                <div
                  role="img"
                  aria-label={t('council.meet_qr_label')}
                  className={styles.qr}
                  dangerouslySetInnerHTML={{ __html: toTrustedMarkup(view.qr) }}
                />
                <Button size="nano" variant="tertiary" color="neutral" onClick={() => setRevealCode(true)}>
                  {t('device_approval.show_code')}
                </Button>
              </>
            ) : (
              <>
                <FingerprintBoxes fingerprint={view.fingerprint} />
                {view.qr && (
                  <Button size="nano" variant="tertiary" color="neutral" onClick={() => setRevealCode(false)}>
                    {t('device_approval.show_qr')}
                  </Button>
                )}
              </>
            )}
            <p className={`${styles.hint} ${styles.hintCenter}`}>{t('council.meet_code_hint')}</p>
          </div>
        </Screen>
        {liveStage}
        {cancelDialog}
      </>
    );
  }

  // The live region and the dialog beside the screen, not in its body: an empty body would still add its gap.
  // Same shape as the meeting screen's, so the live region stays mounted across the change.
  return (
    <>
      <Screen
        back={back}
        illustration="shield-gear"
        title={t('council.in_progress_title')}
        description={t('council.in_progress_description')}
        banner={
          <>
            {banner}
            <Notice type={VariantType.INFO}>{t('council.in_progress_expires', { date: new Date(request.expires_at_millis) })}</Notice>
          </>
        }
        actions={cancelButton}
      />
      {liveStage}
      {cancelDialog}
    </>
  );
}
