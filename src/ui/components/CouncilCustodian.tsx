import { Button, VariantType } from '@gouvfr-lasuite/ui-components';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  type CouncilRequestSummary,
  type CouncilsMine,
  type CustodianCouncil,
  abortCouncilRequest,
  fetchMyCouncils,
  fetchReshareBatch,
  fetchSharesToCheck,
  startCouncilReshare,
  uploadReshareKeys,
  uploadReshareSubShares,
  uploadSharesChecked,
} from '@encryption/src/ui/api/council-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { CouncilCode } from '@encryption/src/ui/components/CouncilCode';
import { CouncilHandOver } from '@encryption/src/ui/components/CouncilHandOver';
import { CouncilRequestRow } from '@encryption/src/ui/components/CouncilRequestRow';
import { CouncilReshareStart } from '@encryption/src/ui/components/CouncilReshareStart';
import { CouncilSignChange } from '@encryption/src/ui/components/CouncilSignChange';
import { rosterHead } from '@encryption/src/ui/components/council-roster';
import { Chip } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { useCloseGuard } from '@encryption/src/ui/hooks/useCloseRequest';
import { useCouncilAction } from '@encryption/src/ui/hooks/useCouncilAction';
import type { CouncilAuthProps } from '@encryption/src/ui/hooks/useCouncilErrors';
import { useCouncilVault } from '@encryption/src/ui/hooks/useCouncilVault';
import { useModalSize } from '@encryption/src/ui/hooks/useModalSize';

interface CouncilCustodianProps extends CouncilAuthProps {
  getIdToken: () => Promise<string | null>;
  userId: string | null;
  onBack?: () => void;
  onClose: () => void;
}

type View =
  | { kind: 'home' }
  | { kind: 'sign'; councilId: string }
  | { kind: 'hand-over'; councilId: string; request: CouncilRequestSummary; mode: 'remote' | 'in-person' }
  | { kind: 'reshare'; councilId: string; sourceVersion: number };

// A server that never runs out of batches must not keep a vault busy forever.
const MAX_BATCHES = 10_000;

/** False once the remaining count stops going down, or after MAX_BATCHES. */
function untilStalled(): (remaining: number) => boolean {
  let previous = Infinity;
  let batches = 0;

  return (remaining) => {
    batches += 1;
    const progressing = remaining < previous && batches <= MAX_BATCHES;
    previous = remaining;

    return progressing;
  };
}

/**
 * The custodian space (architecture.md F.5): one card per council the user sits in, or
 * is invited to, with what waits on them. Several councils share one page, and
 * every action names the council it acts on. Each action is the person's own
 * click here, signed by their vault, with a fresh authentication where the
 * provider reports one.
 */
export function CouncilCustodian({ getIdToken, userId, onBack, onClose, ...auth }: CouncilCustodianProps) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const { banner, fail, busy, run } = useCouncilAction(auth);
  const [data, setData] = useState<CouncilsMine | null>(null);
  const [view, setView] = useState<View>({ kind: 'home' });
  const [confirmAbort, setConfirmAbort] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [closeBlocked, setCloseBlocked] = useState(false);

  useModalSize('large', view.kind === 'home');

  // Closing between the upload of the transfer keys and the sub-shares leaves
  // the batch to redo: the product's close control waits for the run to end.
  const resharing = progress !== null;
  useCloseGuard(resharing, () => setCloseBlocked(true));

  const load = useCallback(async () => {
    try {
      setData(await withFreshIdToken(getIdToken, fetchMyCouncils));
    } catch (err) {
      fail(err);
      setData((previous) => previous ?? { mfa_enforced: true, councils: [] });
    }
  }, [getIdToken, fail]);

  useEffect(() => {
    // Wrapped so the state writes sit behind an await: the effect itself writes
    // nothing synchronously.
    void (async () => {
      await load();
    })();
  }, [load]);

  // The shares a resharing gave this custodian, checked in the background on
  // each visit: a helper that sent invalid ones is named while the council can
  // still act, not on the day someone needs a recovery.
  const checkStarted = useRef(false);
  useEffect(() => {
    const councilIds = data?.councils.filter((c) => c.role === 'custodian' && c.shares_to_check > 0).map((c) => c.council_id) ?? [];
    if (councilIds.length === 0 || checkStarted.current) return;
    checkStarted.current = true;

    void (async () => {
      try {
        await withFreshIdToken(getIdToken, async (idToken) => {
          for (const councilId of councilIds) {
            const progressing = untilStalled();

            for (;;) {
              const batch = await fetchSharesToCheck(idToken, councilId);
              if (batch.escrows.length === 0 || !progressing(batch.remaining)) break;

              // Nothing judged (no record verified): the rest waits for the next visit.
              const { results } = await vault.checkShares(batch);
              if (results.length === 0) break;

              await uploadSharesChecked(idToken, vault.sign, councilId, { results });
            }
          }
        });
        await load();
      } catch {
        // Not a decision of the custodian's: retried on the next visit.
      }
    })();
  }, [data, getIdToken, vault, load]);

  const home = useCallback(() => {
    setView({ kind: 'home' });
    void load();
  }, [load]);

  const abort = useCallback(
    (requestId: string) =>
      run(async () => {
        await withFreshIdToken(getIdToken, (idToken) => abortCouncilRequest(idToken, vault.sign, requestId));
        setConfirmAbort(null);
        await load();
      }, requestId),
    [run, getIdToken, vault, load]
  );

  // A helper's part of a resharing: batch after batch from this vault, until the
  // server has nothing left for it, or stops taking any.
  const reshareFromVault = useCallback(
    async (sessionId: string) => {
      try {
        await withFreshIdToken(getIdToken, async (idToken) => {
          const progressing = untilStalled();
          let total: number | null = null;

          for (;;) {
            const batch = await fetchReshareBatch(idToken, sessionId);
            if (!progressing(batch.remaining)) throw new Error(t('council.reshare_stalled'));
            total ??= batch.remaining;
            setProgress({ done: total - batch.remaining, total });

            const out = await vault.reshareBatch(batch);
            if (out.keys) await uploadReshareKeys(idToken, vault.sign, sessionId, out.keys);
            if (!out.subShares) break;

            await uploadReshareSubShares(idToken, vault.sign, sessionId, out.subShares);
          }
        });
        await load();
      } finally {
        setProgress(null);
        setCloseBlocked(false);
      }
    },
    [getIdToken, vault, load, t]
  );

  const processReshare = useCallback((sessionId: string) => run(() => reshareFromVault(sessionId), sessionId), [run, reshareFromVault]);

  const startReshare = useCallback(
    (council: CustodianCouncil, sourceVersion: number, helperSlots: number[]) =>
      run(async () => {
        const { session_id } = await withFreshIdToken(getIdToken, (idToken) =>
          startCouncilReshare(idToken, vault.sign, council.council_id, sourceVersion, helperSlots)
        );
        setView({ kind: 'home' });
        if (council.my_slot !== null && helperSlots.includes(council.my_slot)) await reshareFromVault(session_id);
        else await load();
      }, council.council_id),
    [run, getIdToken, vault, reshareFromVault, load]
  );

  if (!data) return <LoadingScreen />;

  const councilOf = (id: string) => data.councils.find((c) => c.council_id === id)!;

  if (view.kind === 'sign') {
    return <CouncilSignChange {...auth} getIdToken={getIdToken} userId={userId} council={councilOf(view.councilId)} onBack={home} onSigned={home} />;
  }

  if (view.kind === 'hand-over') {
    return (
      <CouncilHandOver
        {...auth}
        getIdToken={getIdToken}
        councilLabel={councilOf(view.councilId).label}
        request={view.request}
        mode={view.mode}
        onBack={home}
        onDone={home}
      />
    );
  }

  if (view.kind === 'reshare') {
    return (
      <CouncilReshareStart
        council={councilOf(view.councilId)}
        sourceVersion={view.sourceVersion}
        busy={busy !== null}
        banner={banner}
        onBack={home}
        onStart={(helpers) => startReshare(councilOf(view.councilId), view.sourceVersion, helpers)}
      />
    );
  }

  return (
    <Screen
      back={onBack ? { label: t('onboarding.btn_back'), onClick: onBack, disabled: resharing } : undefined}
      title={t('council.custodian_title')}
      description={t('council.custodian_description')}
      banner={
        <>
          {banner}
          {!data.mfa_enforced && <Notice type={VariantType.WARNING}>{t('council.mfa_not_enforced')}</Notice>}
          {progress && <Notice type={VariantType.INFO}>{t('council.reshare_progress', progress)}</Notice>}
          {progress && closeBlocked && <Notice type={VariantType.WARNING}>{t('council.reshare_close_blocked')}</Notice>}
        </>
      }
      actions={
        <Button variant="bordered" color="neutral" onClick={onClose} disabled={resharing}>
          {t('settings.done')}
        </Button>
      }
    >
      {data.councils.length === 0 && <p className={styles.empty}>{t('council.custodian_none')}</p>}
      {data.councils.map((council) => {
        const head = rosterHead(council.chain);

        return (
          <div key={council.council_id} className={`${styles.card} ${styles.section}`}>
            <div className={styles.cardHeader}>
              <div>
                <p className={styles.sectionTitle}>{council.label}</p>
                {head && (
                  <p className={styles.hint}>
                    {t('council.version_line', { version: head.version, threshold: head.threshold, count: head.members.length })}
                  </p>
                )}
              </div>
              <Chip tone={council.role === 'custodian' ? 'success' : 'warning'}>
                {t(council.role === 'custodian' ? 'council.role_custodian' : 'council.role_invited')}
              </Chip>
            </div>

            {!council.configured && <Notice type={VariantType.INFO}>{t('council.not_configured')}</Notice>}
            {council.blocked.length > 0 && (
              <Notice type={VariantType.WARNING}>
                <div className={styles.alertStack}>
                  <span>{t('council.blocked')}</span>
                  <ul className={styles.list}>
                    {council.blocked.map((b) => (
                      <li key={b.email}>
                        {t(`council.blocked_${b.reason.replace('-', '_')}` as 'council.blocked_unknown_user', { email: b.email })}
                      </li>
                    ))}
                  </ul>
                </div>
              </Notice>
            )}

            {council.proposal && (
              <div className={styles.settingsRow}>
                <div className={styles.settingsRowText}>
                  <p className={styles.settingsRowTitle}>
                    {head ? t('council.proposal_title', { version: council.proposal.roster.version }) : t('council.invitation_title')}
                  </p>
                  <p className={styles.settingsRowDescription}>
                    {council.proposal.signed_by_me
                      ? t('council.proposal_waiting', { count: council.proposal.quorum_missing + council.proposal.pending_members.length })
                      : head
                        ? t('council.proposal_description')
                        : t('council.invitation_description', {
                            threshold: council.proposal.roster.threshold,
                            count: council.proposal.roster.members.length,
                          })}
                  </p>
                </div>
                {council.proposal.may_sign && !council.proposal.signed_by_me && (
                  <Button size="nano" onClick={() => setView({ kind: 'sign', councilId: council.council_id })}>
                    {head ? t('council.review_and_sign') : t('council.review_and_accept')}
                  </Button>
                )}
              </div>
            )}

            {council.role === 'custodian' && (
              <>
                {council.chain.length > 0 && <CouncilCode councilId={council.council_id} chain={council.chain} />}
                <HealthLine council={council} />
                {council.faulty_reshares.map((faulty) => (
                  <Notice key={faulty.helper_name} type={VariantType.ERROR}>
                    <strong>{t('council.faulty_reshare_title', { name: faulty.helper_name, count: faulty.escrows })}</strong>
                    <br />
                    {t('council.faulty_reshare_description')}
                  </Notice>
                ))}
                {council.health.outdated.map((entry) => (
                  <div key={entry.version} className={styles.settingsRow}>
                    <div className={styles.settingsRowText}>
                      <p className={styles.settingsRowTitle}>{t('council.outdated_title', { count: entry.escrows, version: entry.version })}</p>
                      <p className={styles.settingsRowDescription}>{t('council.outdated_description')}</p>
                    </div>
                    {!council.reshare && (
                      <Button
                        size="nano"
                        variant="bordered"
                        onClick={() => setView({ kind: 'reshare', councilId: council.council_id, sourceVersion: entry.version })}
                      >
                        {t('council.reshare_button')}
                      </Button>
                    )}
                  </div>
                ))}
                {council.reshare && (
                  <div className={styles.settingsRow}>
                    <div className={styles.settingsRowText}>
                      <p className={styles.settingsRowTitle}>
                        {t('council.reshare_running', { from: council.reshare.source_version, to: council.reshare.target_version })}
                      </p>
                      <p className={styles.settingsRowDescription}>
                        {council.reshare.i_am_helper && council.reshare.remaining_for_me > 0
                          ? t('council.reshare_my_part', { count: council.reshare.remaining_for_me })
                          : t('council.reshare_waiting_others', { count: council.reshare.remaining })}
                      </p>
                    </div>
                    {council.reshare.i_am_helper && council.reshare.remaining_for_me > 0 && (
                      <Button size="nano" onClick={() => processReshare(council.reshare!.session_id)} disabled={busy !== null}>
                        {t('council.reshare_process')}
                      </Button>
                    )}
                  </div>
                )}

                <p className={styles.sectionTitle}>{t('council.requests_title')}</p>
                {council.requests.length === 0 && <p className={styles.hint}>{t('council.requests_none')}</p>}
                {council.requests.map((request) => (
                  <CouncilRequestRow
                    key={request.id}
                    request={request}
                    busy={busy === request.id}
                    confirmingAbort={confirmAbort === request.id}
                    onRemote={() => setView({ kind: 'hand-over', councilId: council.council_id, request, mode: 'remote' })}
                    onInPerson={() => setView({ kind: 'hand-over', councilId: council.council_id, request, mode: 'in-person' })}
                    onAbort={() => (confirmAbort === request.id ? abort(request.id) : setConfirmAbort(request.id))}
                    onCancelAbort={() => setConfirmAbort(null)}
                  />
                ))}
              </>
            )}
          </div>
        );
      })}
    </Screen>
  );
}

function HealthLine({ council }: { council: CustodianCouncil }) {
  const { t } = useTranslation('common');
  const { health } = council;

  if (health.escrows === 0) return <p className={styles.hint}>{t('council.health_empty')}</p>;

  return (
    <div className={styles.cardHeader}>
      <p className={styles.hint}>{t('council.health_line', { count: health.escrows })}</p>
      <div className={styles.textLinks}>
        {health.at_risk > 0 && <Chip tone="warning">{t('council.health_at_risk', { count: health.at_risk })}</Chip>}
        {health.lost > 0 && <Chip tone="error">{t('council.health_lost', { count: health.lost })}</Chip>}
        {health.at_risk === 0 && health.lost === 0 && (
          <Chip tone="success" icon="trusted">
            {t('council.health_ok')}
          </Chip>
        )}
      </div>
    </div>
  );
}
