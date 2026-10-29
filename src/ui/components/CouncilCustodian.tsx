import { Button, DropdownMenu, Input, Modal, ModalSize, VariantType } from '@gouvfr-lasuite/ui-components';
import { ChevronLeft, ChevronRight, Filter, User } from '@gouvfr-lasuite/ui-components/icons';
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
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
import {
  REQUESTS_PAGE_SIZE,
  REQUEST_FILTERS,
  type RequestFilter,
  countByFilter,
  membershipChanges,
  pendingActions,
  selectRequests,
  sortCouncils,
} from '@encryption/src/ui/components/council-custodian-logic';
import { rosterHead } from '@encryption/src/ui/components/council-roster';
import { Chip, Identity } from '@encryption/src/ui/components/layout/IdentityCard';
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
 * The custodian space (architecture.md F.5): the councils the user sits in, or is
 * invited to, those with something waiting first, each on a page of its own
 * (opened at once when there is only one). Each action is the person's own
 * click here, signed by their vault, with a fresh authentication where the
 * provider reports one.
 */
export function CouncilCustodian({ getIdToken, userId, onBack, ...auth }: CouncilCustodianProps) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const { banner, fail, busy, run } = useCouncilAction(auth);
  const [data, setData] = useState<CouncilsMine | null>(null);
  const [view, setView] = useState<View>({ kind: 'home' });
  const [openId, setOpenId] = useState<string | null>(null);
  const [confirmAbort, setConfirmAbort] = useState<CouncilRequestSummary | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [closeBlocked, setCloseBlocked] = useState(false);

  // A council's page is wide (its requests); the list of councils less so; a
  // message alone keeps the default width.
  const councilCount = data?.councils.length ?? 0;
  const onPage = councilCount === 1 || (councilCount > 1 && openId !== null);
  useModalSize(onPage ? 'large' : 'medium', view.kind === 'home' && councilCount > 0);

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

  const banners = (
    <>
      {banner}
      {!data.mfa_enforced && <Notice type={VariantType.WARNING}>{t('council.mfa_not_enforced')}</Notice>}
      {progress && <Notice type={VariantType.INFO}>{t('council.reshare_progress', progress)}</Notice>}
      {progress && closeBlocked && <Notice type={VariantType.WARNING}>{t('council.reshare_close_blocked')}</Notice>}
    </>
  );
  const leave = onBack ? { label: t('onboarding.btn_back'), onClick: onBack, disabled: resharing } : undefined;

  if (data.councils.length === 0) {
    return <Screen back={leave} title={t('council.custodian_title')} description={t('council.custodian_none')} banner={banners} />;
  }

  // One council: its page at once. Several: pick one first, so each keeps a page
  // of its own instead of one long list where the one waiting gets lost.
  const opened = data.councils.length === 1 ? data.councils[0] : data.councils.find((c) => c.council_id === openId);

  if (!opened) {
    return (
      <Screen back={leave} title={t('council.custodian_title')} banner={banners}>
        {sortCouncils(data.councils).map((council) => {
          const head = rosterHead(council.chain);
          const pending = pendingActions(council);

          return (
            <button
              key={council.council_id}
              type="button"
              className={`${styles.card} ${styles.cardButton}`}
              aria-label={t('council.open_council', { council: council.label })}
              onClick={() => setOpenId(council.council_id)}
            >
              <div className={styles.cardHeader}>
                <div>
                  <p className={styles.sectionTitle}>{council.label}</p>
                  <p className={styles.hint}>
                    {head ? t('council.custodians_line', { count: head.threshold, total: head.members.length }) : t('council.role_invited')}
                  </p>
                </div>
                <div className={styles.cardAside}>
                  {pending > 0 && <Chip tone="warning">{t('council.pending_chip', { count: pending })}</Chip>}
                  <ChevronRight aria-hidden size={16} />
                </div>
              </div>
            </button>
          );
        })}
      </Screen>
    );
  }

  const council = opened;
  const head = rosterHead(council.chain);

  const proposal = council.proposal;
  const delta = proposal && head ? membershipChanges(head, proposal.roster) : null;
  const changes = delta
    ? [
        delta.joining.length > 0 && t('council.change_joining', { names: delta.joining.join(', ') }),
        delta.leaving.length > 0 && t('council.change_leaving', { names: delta.leaving.join(', ') }),
        delta.newKey.length > 0 && t('council.change_new_keys', { names: delta.newKey.join(', ') }),
      ]
        .filter(Boolean)
        .join(' · ') || t('council.proposal_description')
    : null;
  const reshare = council.reshare;
  const reshareHelpers = reshare
    ? (council.chain.find((v) => v.version === reshare.source_version)?.members ?? [])
        .filter((m) => reshare.helper_slots.includes(m.slot))
        .map((m) => m.name ?? `#${m.slot}`)
        .join(', ')
    : '';

  return (
    <Screen
      back={data.councils.length > 1 ? { label: t('council.all_councils'), onClick: () => setOpenId(null), disabled: resharing } : leave}
      title={council.label}
      description={
        head ? (
          <>
            <p>{t('council.custodians_line', { count: head.threshold, total: head.members.length })}</p>
            {council.role === 'custodian' && (
              <div className={styles.filters}>
                <CouncilMembersButton roster={head} userId={userId} />
                <CouncilCode councilId={council.council_id} chain={council.chain} />
              </div>
            )}
          </>
        ) : (
          // Possibly the first time this person hears of a council.
          t('council.invitation_intro')
        )
      }
      banner={
        <>
          {banners}
          {!council.configured && <Notice type={VariantType.INFO}>{t('council.not_configured')}</Notice>}
          {council.blocked.length > 0 && (
            <Notice type={VariantType.WARNING}>
              <div className={styles.alertStack}>
                <strong>{t('council.blocked')}</strong>
                {council.blocked.map((b) => (
                  <span key={b.email}>
                    {t(`council.blocked_${b.reason.replace('-', '_')}` as 'council.blocked_unknown_user', { email: b.email })}
                  </span>
                ))}
              </div>
            </Notice>
          )}
          {council.faulty_reshares.map((faulty) => (
            <Notice key={faulty.helper_name} type={VariantType.ERROR}>
              <div className={styles.alertStack}>
                <strong>{t('council.faulty_reshare_title', { name: faulty.helper_name, count: faulty.escrows })}</strong>
                <span>{t('council.faulty_reshare_description')}</span>
              </div>
            </Notice>
          ))}
        </>
      }
    >
      {proposal && (
        <Task
          title={head ? t('council.proposal_title') : t('council.invitation_title')}
          description={
            proposal.signed_by_me
              ? t('council.proposal_waiting', { count: proposal.quorum_missing + proposal.pending_members.length })
              : changes
                ? changes
                : t('council.invitation_description', { threshold: proposal.roster.threshold, count: proposal.roster.members.length })
          }
          action={
            proposal.may_sign &&
            !proposal.signed_by_me && (
              <Button size="small" onClick={() => setView({ kind: 'sign', councilId: council.council_id })}>
                {head ? t('council.review_and_sign') : t('council.review_and_accept')}
              </Button>
            )
          }
        />
      )}

      {council.role === 'custodian' && (
        <>
          <HealthLine council={council} explained={council.health.outdated.length === 0 && !reshare} />

          {/* A version being moved shows as its move only. */}
          {council.health.outdated
            .filter((entry) => entry.version !== reshare?.source_version)
            .map((entry) => (
              <Task
                key={entry.version}
                title={t('council.outdated_title', { count: entry.escrows, to: head?.version })}
                description={t('council.outdated_description')}
                action={
                  !reshare && (
                    <Button size="small" onClick={() => setView({ kind: 'reshare', councilId: council.council_id, sourceVersion: entry.version })}>
                      {t('council.reshare_button')}
                    </Button>
                  )
                }
              />
            ))}
          {reshare && (
            <Task
              title={t('council.reshare_running', { to: reshare.target_version })}
              description={
                <>
                  {reshare.i_am_helper && reshare.remaining_for_me > 0
                    ? t('council.reshare_my_part', { count: reshare.remaining_for_me })
                    : t('council.reshare_waiting_others', { count: reshare.remaining })}{' '}
                  {t('council.reshare_helpers', { names: reshareHelpers })}
                </>
              }
              action={
                reshare.i_am_helper &&
                reshare.remaining_for_me > 0 && (
                  <Button size="small" onClick={() => processReshare(reshare.session_id)} disabled={busy !== null}>
                    {t('council.reshare_process')}
                  </Button>
                )
              }
            />
          )}

          <CouncilRequests
            key={council.council_id}
            requests={council.requests}
            busy={busy}
            onRemote={(request) => setView({ kind: 'hand-over', councilId: council.council_id, request, mode: 'remote' })}
            onInPerson={(request) => setView({ kind: 'hand-over', councilId: council.council_id, request, mode: 'in-person' })}
            onAbort={setConfirmAbort}
          />
        </>
      )}

      <Modal
        isOpen={confirmAbort !== null}
        onClose={() => setConfirmAbort(null)}
        closeOnClickOutside={false}
        size={ModalSize.SMALL}
        aria-label={t('council.abort')}
      >
        {confirmAbort && (
          <Screen
            title={t('council.abort_title', { name: confirmAbort.user_name ?? confirmAbort.user_email })}
            description={t('council.abort_body')}
            actionsLayout="row"
            actions={
              <>
                <Button variant="bordered" color="neutral" onClick={() => setConfirmAbort(null)} disabled={busy !== null}>
                  {t('onboarding.btn_cancel')}
                </Button>
                <Button color="error" onClick={() => abort(confirmAbort.id)} disabled={busy !== null}>
                  {t('council.abort_confirm')}
                </Button>
              </>
            }
          />
        )}
      </Modal>
    </Screen>
  );
}

/**
 * A council's recovery requests, those the custodian can act on first. A long
 * list gets a search, a filter and pages, all in the browser: the server already
 * sends every live request of the council.
 */
function CouncilRequests({
  requests,
  busy,
  onRemote,
  onInPerson,
  onAbort,
}: {
  requests: CouncilRequestSummary[];
  busy: string | null;
  onRemote: (request: CouncilRequestSummary) => void;
  onInPerson: (request: CouncilRequestSummary) => void;
  onAbort: (request: CouncilRequestSummary) => void;
}) {
  const { t } = useTranslation('common');
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<RequestFilter>('all');
  const [page, setPage] = useState(1);
  const [filtering, setFiltering] = useState(false);
  // Read once per render of the list: "open for long" needs a clock, not a live one.
  const [now] = useState(() => Date.now());

  const long = requests.length > REQUESTS_PAGE_SIZE;
  const selected = selectRequests(requests, filter, query, now);
  const pagesCount = Math.max(1, Math.ceil(selected.length / REQUESTS_PAGE_SIZE));
  const current = Math.min(page, pagesCount);
  const shown = selected.slice((current - 1) * REQUESTS_PAGE_SIZE, current * REQUESTS_PAGE_SIZE);
  const counts = countByFilter(requests, now);
  const filterLabel = (value: RequestFilter) =>
    t(`council.requests_filter_${value.replace('-', '_')}` as 'council.requests_filter_all', { count: counts[value] });

  return (
    <div className={styles.cardBlock}>
      <p className={styles.cardBlockTitle}>
        {filter !== 'all' || query.trim()
          ? t('council.requests_title_filtered', { shown: selected.length, count: requests.length })
          : t('council.requests_title_count', { count: requests.length })}
      </p>
      {requests.length === 0 && <p className={styles.hint}>{t('council.requests_none')}</p>}
      {long && (
        <div className={styles.searchRow}>
          <Input
            fullWidth
            variant="classic"
            hideLabel
            placeholder={t('council.requests_search')}
            label={t('council.requests_search')}
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
              setPage(1);
            }}
          />
          <DropdownMenu
            isOpen={filtering}
            onOpenChange={setFiltering}
            options={REQUEST_FILTERS.filter((value) => value === 'all' || counts[value] > 0).map((value) => ({
              label: filterLabel(value),
              isChecked: filter === value,
              callback: () => {
                setFilter(value);
                setPage(1);
              },
            }))}
          >
            {/* Icon only, so the search keeps its width; an active filter tints it
                and shows in the title's count. */}
            <Button
              variant={filter === 'all' ? 'bordered' : 'secondary'}
              color={filter === 'all' ? 'neutral' : 'brand'}
              icon={<Filter aria-hidden size={16} />}
              aria-label={filter === 'all' ? t('council.requests_filter') : `${t('council.requests_filter')} : ${filterLabel(filter)}`}
              title={filter === 'all' ? t('council.requests_filter') : filterLabel(filter)}
              onClick={() => setFiltering(true)}
            />
          </DropdownMenu>
        </div>
      )}
      {long && selected.length === 0 && <p className={styles.hint}>{t('council.requests_no_match')}</p>}
      {shown.map((request) => (
        <CouncilRequestRow
          key={request.id}
          request={request}
          busy={busy === request.id}
          onRemote={() => onRemote(request)}
          onInPerson={() => onInPerson(request)}
          onAbort={() => onAbort(request)}
        />
      ))}
      {pagesCount > 1 && (
        <div className={styles.pager}>
          <Button
            size="nano"
            variant="bordered"
            color="neutral"
            aria-label={t('council.requests_previous')}
            icon={<ChevronLeft aria-hidden size={16} />}
            onClick={() => setPage(current - 1)}
            disabled={current === 1}
          />
          <span className={styles.hint}>{t('council.requests_page', { page: current, count: pagesCount })}</span>
          <Button
            size="nano"
            variant="bordered"
            color="neutral"
            aria-label={t('council.requests_next')}
            icon={<ChevronRight aria-hidden size={16} />}
            onClick={() => setPage(current + 1)}
            disabled={current === pagesCount}
          />
        </div>
      )}
    </div>
  );
}

/**
 * How many people the council can still help. The chips only inform: what a
 * custodian can do about a setup at risk (move it once custodians are added)
 * or lost (nothing: the person sets it up again) is said under them, unless a
 * move to show instead already is that remedy.
 */
function HealthLine({ council, explained }: { council: CustodianCouncil; explained: boolean }) {
  const { t } = useTranslation('common');
  const { health } = council;

  if (health.escrows === 0) return <p className={styles.hint}>{t('council.health_empty')}</p>;

  return (
    <div className={styles.section}>
      <div className={styles.cardHeader}>
        <p className={styles.hint}>{t('council.health_line', { count: health.escrows })}</p>
        <div className={styles.cardAside}>
          {health.at_risk > 0 && (
            <Chip tone="warning" icon="warning">
              {t('council.health_at_risk', { count: health.at_risk })}
            </Chip>
          )}
          {health.lost > 0 && (
            <Chip tone="error" icon="alert">
              {t('council.health_lost', { count: health.lost })}
            </Chip>
          )}
          {health.at_risk === 0 && health.lost === 0 && (
            <Chip tone="success" icon="trusted">
              {t('council.health_ok')}
            </Chip>
          )}
        </div>
      </div>
      {explained && health.at_risk > 0 && <p className={styles.hint}>{t('council.health_at_risk_explained', { count: health.at_risk })}</p>}
      {health.lost > 0 && <p className={styles.hint}>{t('council.health_lost_explained', { count: health.lost })}</p>}
    </div>
  );
}

/** The custodians of the version in force, for a custodian who wants to know who they share the council with. */
function CouncilMembersButton({ roster, userId }: { roster: NonNullable<ReturnType<typeof rosterHead>>; userId: string | null }) {
  const { t } = useTranslation('common');
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button size="nano" variant="bordered" color="neutral" icon={<User aria-hidden size={16} />} onClick={() => setOpen(true)}>
        {t('council.members_button')}
      </Button>
      <Modal isOpen={open} onClose={() => setOpen(false)} size={ModalSize.SMALL} aria-label={t('council.members_button')}>
        <Screen
          title={t('council.members_button')}
          description={t('council.custodians_line', { count: roster.threshold, total: roster.members.length })}
        >
          <ul className={styles.people}>
            {[...roster.members]
              .sort((a, b) => Number(b.user_id === userId) - Number(a.user_id === userId) || (a.name ?? '').localeCompare(b.name ?? ''))
              .map((member) => (
                <li key={member.slot} className={styles.cardHeader}>
                  <Identity name={member.name ?? `#${member.slot}`} />
                  {member.user_id === userId && <Chip tone="info">{t('council.change_me')}</Chip>}
                </li>
              ))}
          </ul>
        </Screen>
      </Modal>
    </>
  );
}

/** Something that waits on the custodians: tinted, with its action at hand. */
function Task({ title, description, action }: { title: string; description: ReactNode; action?: ReactNode }) {
  return (
    <div className={styles.task}>
      <div className={styles.settingsRowText}>
        <p className={styles.settingsRowTitle}>{title}</p>
        <p className={styles.settingsRowDescription}>{description}</p>
      </div>
      {action}
    </div>
  );
}
