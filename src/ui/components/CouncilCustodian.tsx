import { Button, Checkbox, VariantType } from '@gouvfr-lasuite/ui-components';
import { type ReactNode, useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import type { RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import {
  type CouncilRequestSummary,
  type CouncilsMine,
  type CustodianCouncil,
  abortCouncilRequest,
  fetchMyCouncils,
  fetchReshareBatch,
  startCouncilReshare,
  uploadReshareKeys,
  uploadReshareSubShares,
} from '@encryption/src/ui/api/council-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { CouncilHandOver } from '@encryption/src/ui/components/CouncilHandOver';
import { CouncilSignChange } from '@encryption/src/ui/components/CouncilSignChange';
import { Chip, Identity } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { type CouncilAuthProps, useCouncilErrors } from '@encryption/src/ui/hooks/useCouncilErrors';
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

const STAGE_TONE = { collecting: 'neutral', awaiting_meeting: 'warning', cooldown: 'info', released: 'success' } as const;

function headOf(council: CustodianCouncil): RosterVersionWire | null {
  return council.chain.length > 0 ? council.chain[council.chain.length - 1] : null;
}

/**
 * The custodian space (shamir.md §8): one card per council the user sits in, or
 * is invited to, with what waits on them. Several councils share one page, and
 * every action names the council it acts on. Each action is the person's own
 * click here, signed by their vault, with a fresh authentication where the
 * provider reports one.
 */
export function CouncilCustodian({ getIdToken, userId, onBack, onClose, ...auth }: CouncilCustodianProps) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const { banner, fail, clear } = useCouncilErrors(auth);
  const [data, setData] = useState<CouncilsMine | null>(null);
  const [view, setView] = useState<View>({ kind: 'home' });
  const [busy, setBusy] = useState<string | null>(null);
  const [confirmAbort, setConfirmAbort] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);

  useModalSize('large', view.kind === 'home');

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

  const home = useCallback(() => {
    setView({ kind: 'home' });
    void load();
  }, [load]);

  const abort = useCallback(
    async (requestId: string) => {
      setBusy(requestId);
      clear();

      try {
        await withFreshIdToken(getIdToken, (idToken) => abortCouncilRequest(idToken, vault.sign, requestId));
        setConfirmAbort(null);
        await load();
      } catch (err) {
        fail(err);
      } finally {
        setBusy(null);
      }
    },
    [getIdToken, vault, load, fail, clear]
  );

  // A helper's part of a resharing: batch after batch from this vault, until the
  // server has nothing left for it.
  const processReshare = useCallback(
    async (sessionId: string) => {
      setBusy(sessionId);
      clear();

      try {
        await withFreshIdToken(getIdToken, async (idToken) => {
          let total: number | null = null;

          for (;;) {
            const batch = await fetchReshareBatch(idToken, sessionId);
            total ??= batch.remaining;
            setProgress({ done: total - batch.remaining, total });

            const out = await vault.reshareBatch(batch);
            if (out.keys) await uploadReshareKeys(idToken, vault.sign, sessionId, out.keys);
            if (!out.subShares) break;

            await uploadReshareSubShares(idToken, vault.sign, sessionId, out.subShares);
          }
        });
        await load();
      } catch (err) {
        fail(err);
      } finally {
        setBusy(null);
        setProgress(null);
      }
    },
    [getIdToken, vault, load, fail, clear]
  );

  const startReshare = useCallback(
    async (council: CustodianCouncil, sourceVersion: number, helperSlots: number[]) => {
      setBusy(council.council_id);
      clear();

      try {
        const { session_id } = await withFreshIdToken(getIdToken, (idToken) =>
          startCouncilReshare(idToken, vault.sign, council.council_id, sourceVersion, helperSlots)
        );
        setView({ kind: 'home' });
        if (council.my_slot !== null && helperSlots.includes(council.my_slot)) await processReshare(session_id);
        else await load();
      } catch (err) {
        fail(err);
      } finally {
        setBusy(null);
      }
    },
    [getIdToken, vault, processReshare, load, fail, clear]
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
      <ReshareStart
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
      back={onBack ? { label: t('onboarding.btn_back'), onClick: onBack } : undefined}
      title={t('council.custodian_title')}
      description={t('council.custodian_description')}
      banner={
        <>
          {banner}
          {!data.mfa_enforced && <Notice type={VariantType.WARNING}>{t('council.mfa_not_enforced')}</Notice>}
          {progress && <Notice type={VariantType.INFO}>{t('council.reshare_progress', progress)}</Notice>}
        </>
      }
      actions={
        <Button variant="bordered" color="neutral" onClick={onClose}>
          {t('settings.done')}
        </Button>
      }
    >
      {data.councils.length === 0 && <p className={styles.empty}>{t('council.custodian_none')}</p>}
      {data.councils.map((council) => {
        const head = headOf(council);

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
                <HealthLine council={council} />
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
                  <RequestRow
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

function RequestRow({
  request,
  busy,
  confirmingAbort,
  onRemote,
  onInPerson,
  onAbort,
  onCancelAbort,
}: {
  request: CouncilRequestSummary;
  busy: boolean;
  confirmingAbort: boolean;
  onRemote: () => void;
  onInPerson: () => void;
  onAbort: () => void;
  onCancelAbort: () => void;
}) {
  const { t } = useTranslation('common');
  const stage = request.stage as keyof typeof STAGE_TONE;
  const contributors = request.contributors.map((c) => (c.in_person ? t('council.contributor_in_person', { name: c.name }) : c.name)).join(', ');

  return (
    <div className={styles.card}>
      <div className={styles.cardHeader}>
        <Identity name={request.user_name ?? request.user_email} email={request.user_email} />
        <Chip tone={STAGE_TONE[stage] ?? 'neutral'}>{t(`council.stage_${stage}` as 'council.stage_collecting')}</Chip>
      </div>
      <p className={styles.hint}>
        {request.contributors.length > 0 ? t('council.request_contributors', { names: contributors }) : t('council.request_no_contributor')}
        {' · '}
        {t('council.request_expires', { date: new Date(request.expires_at_millis) })}
      </p>
      {request.my_contribution !== 'none' && (
        <Chip tone="success" icon="trusted">
          {t(request.my_contribution === 'in_person' ? 'council.my_contribution_in_person' : 'council.my_contribution_remote')}
        </Chip>
      )}
      <div className={`${styles.actions} ${styles.actionsRow}`}>
        {confirmingAbort ? (
          <>
            <Button size="nano" variant="bordered" color="neutral" onClick={onCancelAbort} disabled={busy}>
              {t('onboarding.btn_cancel')}
            </Button>
            <Button size="nano" color="error" onClick={onAbort} disabled={busy}>
              {t('council.abort_confirm')}
            </Button>
          </>
        ) : (
          <>
            <Button size="nano" variant="tertiary" color="error" onClick={onAbort} disabled={busy}>
              {t('council.abort')}
            </Button>
            {request.can_contribute && request.stage === 'collecting' && (
              <Button size="nano" variant="bordered" onClick={onRemote} disabled={busy}>
                {t('council.approve_remotely')}
              </Button>
            )}
            {request.can_contribute && (
              <Button size="nano" onClick={onInPerson} disabled={busy}>
                {t('council.hand_over_in_person')}
              </Button>
            )}
          </>
        )}
      </div>
    </div>
  );
}

/**
 * Choosing who moves the escrows still split over an older version: exactly as
 * many custodians as that version's threshold, all still in the council with
 * the same key. Each then processes the escrows from their own vault.
 */
function ReshareStart({
  council,
  sourceVersion,
  busy,
  banner,
  onBack,
  onStart,
}: {
  council: CustodianCouncil;
  sourceVersion: number;
  busy: boolean;
  banner: ReactNode;
  onBack: () => void;
  onStart: (helperSlots: number[]) => void;
}) {
  const { t } = useTranslation('common');
  const source = council.chain.find((v) => v.version === sourceVersion)!;
  const head = headOf(council)!;
  const eligible = source.members.filter((m) => head.members.some((h) => h.slot === m.slot && h.identity_public_key === m.identity_public_key));
  const [chosen, setChosen] = useState<number[]>(() => {
    const mine = eligible.filter((m) => m.slot === council.my_slot).map((m) => m.slot);
    const others = eligible.filter((m) => m.slot !== council.my_slot).map((m) => m.slot);

    return [...mine, ...others].slice(0, source.threshold);
  });

  const toggle = (slot: number) =>
    setChosen((previous) =>
      previous.includes(slot) ? previous.filter((s) => s !== slot) : previous.length < source.threshold ? [...previous, slot] : previous
    );

  return (
    <Screen
      back={{ label: t('onboarding.btn_back'), onClick: onBack, disabled: busy }}
      title={t('council.reshare_title', { from: sourceVersion, to: head.version })}
      description={
        <>
          <p>{t('council.reshare_description', { threshold: source.threshold })}</p>
          <p>{t('council.reshare_nobody_sees')}</p>
        </>
      }
      banner={
        <>
          {banner}
          {eligible.length < source.threshold && <Notice type={VariantType.ERROR}>{t('council.reshare_impossible')}</Notice>}
        </>
      }
      actions={
        <Button onClick={() => onStart(chosen)} disabled={busy || chosen.length !== source.threshold}>
          {busy ? t('council.reshare_starting') : t('council.reshare_start')}
        </Button>
      }
    >
      <div className={styles.section}>
        {eligible.map((member) => (
          <Checkbox
            key={member.slot}
            label={member.slot === council.my_slot ? t('council.reshare_me', { name: member.name }) : (member.name ?? `#${member.slot}`)}
            checked={chosen.includes(member.slot)}
            onChange={() => toggle(member.slot)}
          />
        ))}
      </div>
    </Screen>
  );
}
