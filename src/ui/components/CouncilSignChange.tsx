import { Button, Checkbox, Tooltip, VariantType } from '@gouvfr-lasuite/ui-components';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import { MSG_VAULT_ACCEPT_FINGERPRINT, MSG_VAULT_GET_KNOWN_FINGERPRINTS } from '@encryption/src/shared/constants';
import { changeQuorum, genesisPeer } from '@encryption/src/shared/council-quorum';
import { API_ERROR_COUNCIL_ROSTER_CHANGED, API_ERROR_COUNCIL_SIGNATURE_INVALID } from '@encryption/src/shared/error-codes';
import type { RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import { ApiError } from '@encryption/src/ui/api/client';
import { type CustodianCouncil, fetchMyCouncils, signCouncilVersion } from '@encryption/src/ui/api/council-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { membershipChanges } from '@encryption/src/ui/components/council-custodian-logic';
import { Chip, IdentityCard } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { useCouncilAction } from '@encryption/src/ui/hooks/useCouncilAction';
import type { CouncilAuthProps } from '@encryption/src/ui/hooks/useCouncilErrors';
import { useCouncilVault } from '@encryption/src/ui/hooks/useCouncilVault';
import { useModalSize } from '@encryption/src/ui/hooks/useModalSize';
import { useEncryptionContext } from '@encryption/src/ui/providers/EncryptionProvider';

interface CouncilSignChangeProps extends CouncilAuthProps {
  getIdToken: () => Promise<string | null>;
  userId: string | null;
  council: CustodianCouncil;
  onBack: () => void;
  onSigned: (activated: boolean) => void;
}

type MemberChange = 'kept' | 'new' | 'new-key' | 'me';

interface Row {
  slot: number;
  userId: string;
  name: string;
  change: MemberChange;
  fingerprint: string;
}

function changeOf(member: RosterVersionWire['members'][number], head: RosterVersionWire | null, userId: string | null): MemberChange {
  if (member.user_id === userId) return 'me';
  // Everyone founds a first version: nobody is new to it.
  if (!head) return 'kept';

  const before = head?.members.find((m) => m.slot === member.slot);
  if (before && before.user_id === member.user_id && before.identity_public_key === member.identity_public_key) return 'kept';

  return head?.members.some((m) => m.user_id === member.user_id) ? 'new-key' : 'new';
}

/**
 * Review and sign a change of a council's membership (architecture.md F.2). Signing is
 * what makes it take effect, never the configuration: the custodian checks, with
 * each newcomer directly, the fingerprint shown here, and the vault refuses to
 * sign until every newcomer is marked checked. A first version is accepted by
 * each person it names, each vouching for their own key.
 */
export function CouncilSignChange({ getIdToken, userId, council, onBack, onSigned, ...auth }: CouncilSignChangeProps) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const { request } = useEncryptionContext();
  const { banner, fail, clear, busy: running, run } = useCouncilAction(auth);
  const busy = running !== null;
  const [rows, setRows] = useState<Row[] | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  // Confirming a change that loses escrows takes an explicit acknowledgement.
  const [lossAccepted, setLossAccepted] = useState(false);

  useModalSize('medium');

  const proposal = council.proposal!.roster;
  const head = council.chain.length > 0 ? council.chain[council.chain.length - 1] : null;

  useEffect(() => {
    let cancelled = false;

    (async () => {
      const built = await Promise.all(
        proposal.members.map(async (member) => ({
          slot: member.slot,
          userId: member.user_id,
          name: member.name ?? `#${member.slot}`,
          change: changeOf(member, head, userId),
          fingerprint: await computeKeyFingerprint(member.identity_public_key),
        }))
      );

      const { fingerprints } = (await request(MSG_VAULT_GET_KNOWN_FINGERPRINTS)) as {
        fingerprints: Record<string, { fingerprint: string; status: string }>;
      };

      if (cancelled) return;
      setRows(built);
      setChecked(
        new Set(
          built
            .filter((r) => fingerprints[r.userId]?.status === 'trusted' && fingerprints[r.userId]?.fingerprint === r.fingerprint)
            .map((r) => r.userId)
        )
      );
    })().catch((err: unknown) => {
      if (cancelled) return;
      fail(err);
      setLoadFailed(true);
    });

    return () => {
      cancelled = true;
    };
  }, [proposal, head, userId, request, fail]);

  const markChecked = useCallback(
    async (row: Row) => {
      clear();
      try {
        await request(MSG_VAULT_ACCEPT_FINGERPRINT, { userId: row.userId, fingerprint: row.fingerprint });
        setChecked((previous) => new Set(previous).add(row.userId));
      } catch (err) {
        fail(err);
      }
    },
    [request, fail, clear]
  );

  const proposalReplaced = useCallback(
    async (idToken: string) => {
      const current = (await fetchMyCouncils(idToken)).councils.find((c) => c.council_id === council.council_id)?.proposal?.roster;
      const keys = (roster: RosterVersionWire | undefined) => JSON.stringify(roster?.members.map((m) => [m.slot, m.identity_public_key]) ?? null);

      return keys(current) !== keys(proposal);
    },
    [council.council_id, proposal]
  );

  const sign = useCallback(
    () =>
      run(async () => {
        const { signature } = await vault.signRoster(council.council_id, council.chain, proposal);
        const { activated } = await withFreshIdToken(getIdToken, async (idToken) => {
          try {
            return await signCouncilVersion(idToken, vault.sign, council.council_id, proposal.version, signature);
          } catch (err) {
            // The proposal was replaced under the same version (a member's key changed meanwhile):
            // the signature covers the one shown, so say what happened rather than "invalid signature".
            if (err instanceof ApiError && err.code === API_ERROR_COUNCIL_SIGNATURE_INVALID && (await proposalReplaced(idToken))) {
              throw new ApiError(409, API_ERROR_COUNCIL_ROSTER_CHANGED);
            }
            throw err;
          }
        });
        onSigned(activated);
      }),
    [run, vault, council, proposal, getIdToken, onSigned, proposalReplaced]
  );

  if (!rows && loadFailed) {
    return <Screen back={{ label: t('onboarding.btn_back'), onClick: onBack }} title={t('council.sign_title')} banner={banner} />;
  }

  if (!rows) return <LoadingScreen />;

  // A first version: each member checks the next one by slot (the circle the
  // vault enforces). After that, only newcomers, by the custodians who approve them.
  // Once signed, nothing is left to check: a different key would be another proposal.
  const signed = council.proposal!.signed_by_me;
  const peer = head || signed ? null : genesisPeer(rows, userId ?? '');
  const toCheck = signed ? [] : head ? rows.filter((r) => r.change === 'new' || r.change === 'new-key') : peer ? [peer] : [];
  const escrowsLost = signed ? 0 : council.proposal!.escrows_lost;
  const ready = toCheck.every((r) => checked.has(r.userId)) && (escrowsLost === 0 || lossAccepted);
  const first = head === null;
  // A newcomer to a council in force accepts the role, like a member of version 1.
  const joining = head !== null && !head.members.some((m) => m.user_id === userId);
  // Started over: named again under a new identity, this member accepts their own return.
  const returning =
    head !== null &&
    head.members.some(
      (h) => h.user_id === userId && proposal.members.some((m) => m.user_id === userId && m.identity_public_key !== h.identity_public_key)
    );
  const accepting = first || joining || returning;
  const leaving = head !== null && head.members.some((m) => m.user_id === userId) && !proposal.members.some((m) => m.user_id === userId);
  // What changes, shown above everything: the button confirms it.
  const delta = head && !accepting ? membershipChanges(head, proposal, userId) : null;
  const thresholdChanged = head !== null && head.threshold !== proposal.threshold;
  // Leaving, the custodian's own departure comes first: the button confirms it.
  const changeLines = delta
    ? [
        leaving && t('council.change_you_leave'),
        delta.joining.length > 0 && t('council.change_joining', { names: delta.joining.join(', ') }),
        delta.leaving.length > 0 && t('council.change_leaving', { names: delta.leaving.join(', ') }),
        delta.newKey.length > 0 && t('council.change_new_keys', { names: delta.newKey.join(', ') }),
        thresholdChanged && t('council.change_threshold', { before: head!.threshold, count: proposal.threshold }),
      ].filter((line): line is string => typeof line === 'string')
    : [];
  // The custodian first, then whoever is still to check, then the rest by name.
  const rank = (row: Row) => (row.change === 'me' ? 0 : toCheck.includes(row) ? (checked.has(row.userId) ? 2 : 1) : 3);
  const ordered = [...rows].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));

  return (
    <Screen
      back={{ label: t('onboarding.btn_back'), onClick: onBack, disabled: busy }}
      title={
        returning
          ? t('council.sign_return_title')
          : leaving
            ? t('council.sign_leave_title')
            : accepting
              ? t('council.sign_first_title')
              : t('council.sign_title')
      }
      description={
        <>
          {/* A new threshold is said once, among the changes. */}
          {(returning || leaving || accepting || !thresholdChanged) && (
            <p>
              {returning
                ? t('council.sign_return_description')
                : leaving
                  ? t('council.sign_leave_description')
                  : accepting
                    ? t('council.sign_first_description', { threshold: proposal.threshold, count: proposal.members.length })
                    : t('council.sign_description', { count: proposal.threshold, total: proposal.members.length })}
            </p>
          )}
          {head && !joining && <p>{t('council.sign_quorum', { quorum: changeQuorum(head), count: head.members.length })}</p>}
          {(peer || (head && toCheck.length > 0)) && (
            // A div: the tooltip's arrow is one, never allowed inside a paragraph.
            <div>
              {peer ? t('council.sign_check_peer', { name: peer.name }) : t('council.sign_check_newcomers')}{' '}
              <Tooltip content={t(peer ? 'council.sign_check_why_peer' : 'council.sign_check_why_newcomers')} placement="bottom">
                <span className={styles.whyLink} tabIndex={0}>
                  {t('council.sign_check_why')}
                </span>
              </Tooltip>
            </div>
          )}
        </>
      }
      banner={
        <>
          {banner}
          {signed && <Notice type={VariantType.SUCCESS}>{t('council.sign_already')}</Notice>}
          {escrowsLost > 0 && head && (
            <Notice type={VariantType.ERROR}>
              <div className={styles.alertStack}>
                <strong>{t('council.sign_loses_title', { count: escrowsLost })}</strong>
                <span>{t('council.sign_loses_description', { count: escrowsLost, threshold: head.threshold })}</span>
                <Checkbox
                  label={t('council.sign_loses_accept', { count: escrowsLost })}
                  checked={lossAccepted}
                  onChange={() => setLossAccepted((value) => !value)}
                  disabled={busy}
                />
              </div>
            </Notice>
          )}
          {changeLines.length > 0 && (
            <Notice type={VariantType.INFO}>
              <div className={styles.alertStack}>
                <strong>{t('council.sign_change_heading')}</strong>
                {changeLines.map((line) => (
                  <span key={line}>{line}</span>
                ))}
              </div>
            </Notice>
          )}
        </>
      }
      actions={
        <Button onClick={sign} disabled={busy || !ready || signed}>
          {busy
            ? t('council.signing')
            : accepting
              ? t('council.sign_first_button')
              : leaving
                ? t('council.sign_leave_button')
                : t('council.sign_button')}
        </Button>
      }
    >
      <div className={styles.section}>
        <p className={styles.sectionTitle}>{council.label}</p>
        {ordered.map((row) => {
          const needsCheck = toCheck.includes(row);
          const isChecked = checked.has(row.userId);

          return (
            <IdentityCard
              key={row.slot}
              name={row.name}
              fingerprint={needsCheck && !isChecked ? row.fingerprint : null}
              tone={needsCheck && !isChecked ? 'warning' : 'default'}
              aside={
                row.change === 'me' ? (
                  <>
                    <Chip tone="info">{t('council.change_me')}</Chip>
                    {returning && <Chip tone="warning">{t('council.change_new_key')}</Chip>}
                  </>
                ) : row.change === 'new' ? (
                  <Chip tone="warning">{t('council.change_new')}</Chip>
                ) : row.change === 'new-key' ? (
                  <Chip tone="warning">{t('council.change_new_key')}</Chip>
                ) : null
              }
            >
              {needsCheck &&
                (isChecked ? (
                  <Chip tone="success" icon="trusted">
                    {t('council.checked')}
                  </Chip>
                ) : (
                  <div>
                    <Button size="nano" variant="bordered" onClick={() => markChecked(row)}>
                      {t('council.mark_checked')}
                    </Button>
                  </div>
                ))}
            </IdentityCard>
          );
        })}
      </div>
    </Screen>
  );
}
