import { Button, DropdownMenu, Input, Modal, ModalSize, VariantType } from '@gouvfr-lasuite/ui-components';
import { ChevronLeft, ChevronRight, Filter, User } from '@gouvfr-lasuite/ui-components/icons';
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { REQUEST_FILTERS, type RequestFilter } from '@encryption/src/shared/council-request-filters';
import {
  type CouncilRequestSummary,
  type CouncilRequestsPage,
  type CouncilsMine,
  type CustodianCouncil,
  abortCouncilRequest,
  fetchCouncilRequests,
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
import { REQUESTS_PAGE_SIZE, membershipChanges, pendingActions, sortCouncils } from '@encryption/src/ui/components/council-custodian-logic';
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
  const { t, i18n } = useTranslation('common');
  const vault = useCouncilVault();
  const { banner, fail, busy, run } = useCouncilAction(auth);
  const [data, setData] = useState<CouncilsMine | null>(null);
  const [view, setView] = useState<View>({ kind: 'home' });
  const [openId, setOpenId] = useState<string | null>(null);
  const [confirmAbort, setConfirmAbort] = useState<CouncilRequestSummary | null>(null);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [closeBlocked, setCloseBlocked] = useState(false);
  // The first load failed: an error to retry, never "you are not a member".
  const [loadFailed, setLoadFailed] = useState(false);

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
      setLoadFailed(false);
    } catch (err) {
      fail(err);
      setLoadFailed(true);
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

            const { remaining_for_me } = await uploadReshareSubShares(idToken, vault.sign, sessionId, out.subShares);
            if (remaining_for_me === 0) break;
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

  if (!data && loadFailed) {
    return (
      <Screen
        back={onBack ? { label: t('onboarding.btn_back'), onClick: onBack } : undefined}
        title={t('council.custodian_title')}
        description={t('council.custodian_load_failed')}
        banner={banner}
        actions={
          <Button
            onClick={() => {
              setLoadFailed(false);
              void load();
            }}
          >
            {t('council.retry')}
          </Button>
        }
      />
    );
  }

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
        members={rosterHead(councilOf(view.councilId).chain)?.members ?? []}
        userId={userId}
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
      {/* While the stop is being confirmed, its outcome (a step-up asked, an error) shows in that dialog. */}
      {!confirmAbort && banner}
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
              // The label names the action; the card's lines (custodians, what waits) still reach screen readers.
              aria-describedby={`council-card-${council.council_id}`}
              onClick={() => setOpenId(council.council_id)}
            >
              <div className={styles.cardHeader} id={`council-card-${council.council_id}`}>
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
  const inactiveMembers = council.blocked.filter((b) => b.member);
  const newcomersBlocked = council.blocked.filter((b) => !b.member);
  const head = rosterHead(council.chain);

  const proposal = council.proposal;
  // Named by a change to a team already in force: an invitation for them, not a change to review.
  const joiningMe = head !== null && proposal !== null && !head.members.some((m) => m.user_id === userId);
  // Started over: the change names this member again under their new identity, theirs to accept.
  const returningMe =
    head !== null &&
    proposal !== null &&
    head.members.some(
      (h) => h.user_id === userId && proposal.roster.members.some((m) => m.user_id === userId && m.identity_public_key !== h.identity_public_key)
    );
  const delta = proposal && head ? membershipChanges(head, proposal.roster, userId) : null;
  // Removed by the configuration: still confirms, since the team changes only once enough current members agree.
  const leavingMe = delta?.me === 'leaving';
  const list = (names: string[], type: 'conjunction' | 'disjunction') => new Intl.ListFormat(i18n.language, { type }).format(names);
  // What the change still waits for: newcomers (or members back under a new
  // identity) accepting it, and members in force confirming it.
  const awaiting = (() => {
    if (!proposal || !head) return [];
    // A member back under a new identity accepts as a newcomer: the identity they left can no longer confirm.
    const renewed = new Set(
      proposal.roster.members
        .filter((m) => head.members.some((h) => h.user_id === m.user_id && h.identity_public_key !== m.identity_public_key))
        .map((m) => m.user_id)
    );
    const unsigned = head.members
      .filter((m) => !renewed.has(m.user_id))
      .filter((m) => !proposal.roster.signatures.some((s) => s.identity_public_key === m.identity_public_key))
      .map((m) => m.name ?? `#${m.slot}`);
    const lines: string[] = [];
    if (proposal.pending_members.length > 0)
      lines.push(
        t('council.proposal_to_accept', {
          names: list(
            proposal.pending_members.map((m) => m.name),
            'conjunction'
          ),
        })
      );
    if (proposal.quorum_missing >= unsigned.length && unsigned.length > 0)
      lines.push(t('council.proposal_to_confirm', { names: list(unsigned, 'conjunction') }));
    else if (proposal.quorum_missing > 0)
      lines.push(t('council.proposal_to_confirm_some', { count: proposal.quorum_missing, names: list(unsigned, 'disjunction') }));

    return lines;
  })();
  const changeLines = delta
    ? [
        delta.joining.length > 0 && t('council.change_joining', { names: delta.joining.join(', ') }),
        delta.leaving.length > 0 && t('council.change_leaving', { names: delta.leaving.join(', ') }),
        delta.newKey.length > 0 && t('council.change_new_keys', { names: delta.newKey.join(', ') }),
        head!.threshold !== proposal!.roster.threshold &&
          t('council.change_threshold', { before: head!.threshold, count: proposal!.roster.threshold }),
      ].filter((line): line is string => typeof line === 'string')
    : [];
  const reshare = council.reshare;
  // The helpers other than this custodian: the ones a move still waits for once their own part is done.
  const otherHelpers = reshare
    ? list(
        (council.chain.find((v) => v.version === reshare.source_version)?.members ?? [])
          .filter((m) => reshare.helper_slots.includes(m.slot) && m.user_id !== userId)
          .map((m) => m.name ?? `#${m.slot}`),
        'conjunction'
      )
    : '';

  return (
    <Screen
      back={data.councils.length > 1 ? { label: t('council.all_councils'), onClick: () => setOpenId(null), disabled: resharing } : leave}
      title={council.label}
      description={
        head && !joiningMe ? (
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
          {!council.configured && (
            <Notice type={VariantType.WARNING}>
              <div className={styles.alertStack}>
                <strong>{t('council.not_configured_title')}</strong>
                {council.replaced_by === null ? (
                  <span>{t('council.not_configured')}</span>
                ) : (
                  <>
                    <span>
                      {council.replaced_by === council.label
                        ? t('council.not_configured_replaced_same_name', { count: council.health.escrows })
                        : t('council.not_configured_replaced', { to: council.replaced_by, count: council.health.escrows })}
                    </span>
                    <ul className={styles.alertCases}>
                      <li>{t('council.not_configured_move_offered', { count: council.health.escrows })}</li>
                      <li>{t('council.not_configured_keep_handling', { count: council.health.escrows })}</li>
                      <li>{t('council.not_configured_remind', { count: council.health.escrows })}</li>
                      <li>{t('council.not_configured_closes')}</li>
                    </ul>
                  </>
                )}
              </div>
            </Notice>
          )}
          {inactiveMembers.length > 0 && (
            <Notice type={VariantType.WARNING}>
              <div className={styles.alertStack}>
                <strong>
                  {t('council.inactive_members_title', {
                    count: inactiveMembers.length,
                    names: new Intl.ListFormat(i18n.language, { type: 'conjunction' }).format(inactiveMembers.map((b) => b.name ?? b.email)),
                  })}
                </strong>
                <span>{t('council.inactive_members_description', { count: inactiveMembers.length })}</span>
                <ul className={styles.alertCases}>
                  <li>{t('council.inactive_members_if_back', { count: inactiveMembers.length })}</li>
                  <li>{t('council.inactive_members_if_start_over', { count: inactiveMembers.length })}</li>
                  <li>{t('council.inactive_members_if_left', { count: inactiveMembers.length })}</li>
                </ul>
              </div>
            </Notice>
          )}
          {newcomersBlocked.length > 0 && (
            <Notice type={VariantType.WARNING}>
              <div className={styles.alertStack}>
                <strong>{t('council.blocked')}</strong>
                {newcomersBlocked.map((b) => (
                  <span key={b.email}>
                    {t(`council.blocked_${b.reason.replace('-', '_')}` as 'council.blocked_unknown_user', {
                      email: b.email,
                      name: b.name ?? b.email,
                    })}
                  </span>
                ))}
              </div>
            </Notice>
          )}
          {council.health.absent.length > 0 && (
            <Notice type={VariantType.WARNING}>
              <div className={styles.alertStack}>
                <strong>{t('council.absent_title', { count: council.health.absence_days })}</strong>
                <span>{council.health.absent.join(', ')}</span>
                <span>{t('council.absent_description')}</span>
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
      {proposal?.signed_by_me && (
        <Notice type={VariantType.SUCCESS}>
          <div className={styles.alertStack}>
            <strong>
              {returningMe
                ? t('council.return_signed_title')
                : leavingMe
                  ? t('council.leave_signed_title')
                  : head && !joiningMe
                    ? t('council.proposal_signed_title')
                    : t('council.invitation_signed_title')}
            </strong>
            {returningMe ? (
              awaiting.map((line) => <span key={line}>{line}</span>)
            ) : head && !joiningMe ? (
              <>
                <ul className={styles.alertCases}>
                  {changeLines.map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
                {awaiting.map((line) => (
                  <span key={line}>{line}</span>
                ))}
              </>
            ) : (
              <span>
                {t('council.invitation_signed', {
                  count: proposal.pending_members.length,
                  names: list(
                    proposal.pending_members.map((m) => m.name),
                    'conjunction'
                  ),
                })}
              </span>
            )}
          </div>
        </Notice>
      )}

      {proposal && !proposal.signed_by_me && (
        <Task
          title={
            returningMe
              ? t('council.return_title')
              : leavingMe
                ? t('council.leave_title')
                : head && !joiningMe
                  ? t('council.proposal_title')
                  : t('council.invitation_title')
          }
          description={
            returningMe
              ? t('council.return_description')
              : leavingMe
                ? t('council.leave_description')
                : joiningMe
                  ? t('council.invitation_join_description', { threshold: proposal.roster.threshold, count: proposal.roster.members.length })
                  : head
                    ? null
                    : t('council.invitation_description', { threshold: proposal.roster.threshold, count: proposal.roster.members.length })
          }
          items={returningMe || joiningMe ? [] : changeLines}
          itemsHeading={leavingMe && changeLines.length > 0 ? t('council.leave_also') : null}
          action={
            proposal.may_sign && (
              <Button size="small" onClick={() => setView({ kind: 'sign', councilId: council.council_id })}>
                {head && !joiningMe && !returningMe ? t('council.review_and_sign') : t('council.review_and_accept')}
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
                title={t('council.outdated_title', { count: entry.escrows })}
                description={(() => {
                  // Only added members: the setups stay as safe, the newcomers just hold no part of them yet.
                  const from = council.chain.find((v) => v.version === entry.version);
                  const changes = from && head ? membershipChanges(from, head) : null;

                  return t(
                    changes && changes.leaving.length + changes.newKey.length === 0 ? 'council.outdated_added' : 'council.outdated_description'
                  );
                })()}
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
              title={t('council.reshare_running', { count: reshare.remaining })}
              description={
                !reshare.i_am_helper
                  ? t('council.reshare_waiting_for', { names: otherHelpers })
                  : reshare.remaining_for_me > 0
                    ? `${t('council.reshare_my_part', { count: reshare.remaining_for_me })} ${t('council.reshare_also', { names: otherHelpers })}`
                    : t('council.reshare_done_waiting', { names: otherHelpers })
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
            getIdToken={getIdToken}
            councilId={council.council_id}
            mySlot={council.my_slot}
            // A new answer of /mine (after an action, a return to the page) reloads the list too.
            reload={council}
            onError={fail}
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
            banner={banner}
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

// Typing in the search asks the server once the person pauses.
const SEARCH_DELAY_MS = 300;

/**
 * A council's recovery requests, those the custodian can act on first. A long
 * list gets a search, a filter and pages; the server applies all three and
 * sends one page.
 */
function CouncilRequests({
  getIdToken,
  councilId,
  mySlot,
  reload,
  onError,
  busy,
  onRemote,
  onInPerson,
  onAbort,
}: {
  getIdToken: () => Promise<string | null>;
  councilId: string;
  mySlot: number | null;
  reload: unknown;
  onError: (err: unknown) => void;
  busy: string | null;
  onRemote: (request: CouncilRequestSummary) => void;
  onInPerson: (request: CouncilRequestSummary) => void;
  onAbort: (request: CouncilRequestSummary) => void;
}) {
  const { t } = useTranslation('common');
  const [query, setQuery] = useState('');
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState<RequestFilter>('all');
  const [page, setPage] = useState(1);
  const [filtering, setFiltering] = useState(false);
  const [list, setList] = useState<CouncilRequestsPage | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => setSearch(query), SEARCH_DELAY_MS);

    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    let current = true;
    void (async () => {
      try {
        const next = await withFreshIdToken(getIdToken, (idToken) =>
          fetchCouncilRequests(idToken, councilId, { page, page_size: REQUESTS_PAGE_SIZE, filter, query: search })
        );
        if (!current) return;
        // The last request of the last page went (handled, stopped): show the new last page.
        if (next.items.length === 0 && next.total_count > 0 && page > 1) setPage(Math.ceil(next.total_count / REQUESTS_PAGE_SIZE));
        else setList(next);
      } catch (err) {
        if (current) onError(err);
      }
    })();

    return () => {
      current = false;
    };
  }, [getIdToken, councilId, page, filter, search, reload, onError]);

  if (!list) return null;

  const { counts } = list;
  const long = counts.all > REQUESTS_PAGE_SIZE;
  const pagesCount = Math.max(1, Math.ceil(list.total_count / REQUESTS_PAGE_SIZE));
  const filterLabel = (value: RequestFilter) =>
    t(`council.requests_filter_${value.replace('-', '_')}` as 'council.requests_filter_all', { count: counts[value] });

  return (
    <div className={styles.cardBlock}>
      <p className={styles.cardBlockTitle}>
        {filter !== 'all' || search.trim()
          ? t('council.requests_title_filtered', { shown: list.total_count, count: counts.all })
          : t('council.requests_title_count', { count: counts.all })}
      </p>
      {counts.all === 0 && <p className={styles.hint}>{t('council.requests_none')}</p>}
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
      {long && list.total_count === 0 && <p className={styles.hint}>{t('council.requests_no_match')}</p>}
      {list.items.map((request) => (
        <CouncilRequestRow
          key={request.id}
          request={request}
          mySlot={mySlot}
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
            onClick={() => setPage(page - 1)}
            disabled={page === 1}
          />
          <span className={styles.hint}>{t('council.requests_page', { page, count: pagesCount })}</span>
          <Button
            size="nano"
            variant="bordered"
            color="neutral"
            aria-label={t('council.requests_next')}
            icon={<ChevronRight aria-hidden size={16} />}
            onClick={() => setPage(page + 1)}
            disabled={page === pagesCount}
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
  const { t, i18n } = useTranslation('common');
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
          {/* Recoverable, but setups still split over an earlier version are not done until moved. */}
          {health.at_risk === 0 && health.lost === 0 && health.outdated.length > 0 && <Chip tone="info">{t('council.health_to_move')}</Chip>}
          {health.at_risk === 0 && health.lost === 0 && health.outdated.length === 0 && (
            <Chip tone="success" icon="trusted">
              {t('council.health_ok')}
            </Chip>
          )}
        </div>
      </div>
      {explained && health.at_risk > 0 && <p className={styles.hint}>{t('council.health_at_risk_explained', { count: health.at_risk })}</p>}
      {/* Joining needs every custodian active: until then, nobody can be told to join again. */}
      {health.lost > 0 && (
        <p className={styles.hint}>{t(health.team_ready ? 'council.health_lost_explained' : 'council.health_lost_repair', { count: health.lost })}</p>
      )}
      {health.team_ready && health.lost_names.length > 0 && (
        <p className={styles.hint}>
          {t('council.health_lost_names', {
            names: new Intl.ListFormat(i18n.language, { type: 'conjunction' }).format(health.lost_names),
            count: health.lost_names.length,
          })}
        </p>
      )}
      {/* The rest protect an access its owner replaced by starting over: only worth anything if they want it back. */}
      {health.lost > health.lost_names.length && (
        <p className={styles.hint}>{t('council.health_lost_replaced', { count: health.lost - health.lost_names.length })}</p>
      )}
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
function Task({
  title,
  description,
  items = [],
  itemsHeading = null,
  action,
}: {
  title: string;
  description: ReactNode;
  items?: string[];
  itemsHeading?: string | null;
  action?: ReactNode;
}) {
  return (
    <div className={styles.task}>
      <div className={styles.settingsRowText}>
        <p className={styles.settingsRowTitle}>{title}</p>
        {description && <p className={styles.settingsRowDescription}>{description}</p>}
        {itemsHeading && <p className={styles.settingsRowDescription}>{itemsHeading}</p>}
        {items.length > 0 && (
          <ul className={`${styles.alertCases} ${styles.settingsRowDescription}`}>
            {items.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        )}
      </div>
      {action}
    </div>
  );
}
