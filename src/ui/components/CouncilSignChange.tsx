import { Button, VariantType } from '@gouvfr-lasuite/ui-components';
import { useCallback, useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import { MSG_VAULT_ACCEPT_FINGERPRINT, MSG_VAULT_GET_KNOWN_FINGERPRINTS } from '@encryption/src/shared/constants';
import type { RosterVersionWire } from '@encryption/src/shared/schemas/recovery-council';
import { type CustodianCouncil, signCouncilVersion } from '@encryption/src/ui/api/council-client';
import { withFreshIdToken } from '@encryption/src/ui/auth/session-expired';
import { Chip, IdentityCard } from '@encryption/src/ui/components/layout/IdentityCard';
import { LoadingScreen, Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';
import { type CouncilAuthProps, useCouncilErrors } from '@encryption/src/ui/hooks/useCouncilErrors';
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

  const before = head?.members.find((m) => m.slot === member.slot);
  if (before && before.user_id === member.user_id && before.identity_public_key === member.identity_public_key) return 'kept';

  return head?.members.some((m) => m.user_id === member.user_id) ? 'new-key' : 'new';
}

/**
 * Review and sign a change of a council's membership (shamir.md §10). Signing is
 * what makes it take effect, never the configuration: the custodian checks, with
 * each newcomer directly, the fingerprint shown here, and the vault refuses to
 * sign until every newcomer is marked checked. A first version is accepted by
 * each person it names, each vouching for their own key.
 */
export function CouncilSignChange({ getIdToken, userId, council, onBack, onSigned, ...auth }: CouncilSignChangeProps) {
  const { t } = useTranslation('common');
  const vault = useCouncilVault();
  const { request } = useEncryptionContext();
  const { banner, fail, clear } = useCouncilErrors(auth);
  const [rows, setRows] = useState<Row[] | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  useModalSize('medium');

  const proposal = council.proposal!.roster;
  const head = council.chain.length > 0 ? council.chain[council.chain.length - 1] : null;
  const removed = useMemo(() => (head ? head.members.filter((m) => !proposal.members.some((p) => p.user_id === m.user_id)) : []), [head, proposal]);

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
    })().catch(fail);

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

  const sign = useCallback(async () => {
    setBusy(true);
    clear();

    try {
      const { signature } = await vault.signRoster(council.council_id, council.chain, proposal);
      const { activated } = await withFreshIdToken(getIdToken, (idToken) =>
        signCouncilVersion(idToken, vault.sign, council.council_id, proposal.version, signature)
      );
      onSigned(activated);
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  }, [vault, council, proposal, getIdToken, onSigned, fail, clear]);

  if (!rows) return <LoadingScreen />;

  // A first version: everyone vouches for themselves. After that, only newcomers
  // need checking, by the custodians who approve them.
  const toCheck = head ? rows.filter((r) => r.change === 'new' || r.change === 'new-key') : [];
  const ready = toCheck.every((r) => checked.has(r.userId));
  const first = head === null;

  return (
    <Screen
      back={{ label: t('onboarding.btn_back'), onClick: onBack, disabled: busy }}
      title={first ? t('council.sign_first_title', { council: council.label }) : t('council.sign_title', { council: council.label })}
      description={
        <>
          <p>
            {first
              ? t('council.sign_first_description', { threshold: proposal.threshold, count: proposal.members.length })
              : t('council.sign_description', { threshold: proposal.threshold, count: proposal.members.length })}
          </p>
          {toCheck.length > 0 && <p>{t('council.sign_check_newcomers')}</p>}
        </>
      }
      banner={
        <>
          {banner}
          {council.proposal!.signed_by_me && <Notice type={VariantType.SUCCESS}>{t('council.sign_already')}</Notice>}
          {removed.length > 0 && (
            <Notice type={VariantType.INFO}>
              {t('council.sign_removed', { names: removed.map((m) => m.name ?? `#${m.slot}`).join(', '), count: removed.length })}
            </Notice>
          )}
        </>
      }
      actions={
        <Button onClick={sign} disabled={busy || !ready || council.proposal!.signed_by_me}>
          {busy ? t('council.signing') : first ? t('council.sign_first_button') : t('council.sign_button')}
        </Button>
      }
    >
      <div className={styles.section}>
        {rows.map((row) => {
          const needsCheck = toCheck.includes(row);
          const isChecked = checked.has(row.userId);

          return (
            <IdentityCard
              key={row.slot}
              name={row.name}
              fingerprint={needsCheck || row.change === 'me' ? row.fingerprint : null}
              tone={needsCheck && !isChecked ? 'warning' : 'default'}
              aside={
                row.change === 'me' ? (
                  <Chip tone="info">{t('council.change_me')}</Chip>
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
