import { Button } from '@gouvfr-lasuite/ui-components';
import { XMark } from '@gouvfr-lasuite/ui-components/icons';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

import type { CouncilRequestSummary } from '@encryption/src/ui/api/council-client';
import { Chip } from '@encryption/src/ui/components/layout/IdentityCard';
import { PersonRow } from '@encryption/src/ui/components/layout/PersonRow';
import { RowMenu } from '@encryption/src/ui/components/layout/RowMenu';

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

const STAGE_TONE = { collecting: 'neutral', awaiting_meeting: 'warning', cooldown: 'info', released: 'success' } as const;

/**
 * One recovery request on a council's page, laid out like a trusted contact:
 * the person, the stage, a menu for stopping it, and a band for what it asks of
 * this custodian. One way at each stage: the meeting first, then remote
 * approvals, which the meeting's signed share already vouches for.
 */
export function CouncilRequestRow({
  request,
  busy,
  onRemote,
  onInPerson,
  onAbort,
}: {
  request: CouncilRequestSummary;
  busy: boolean;
  onRemote: () => void;
  onInPerson: () => void;
  onAbort: () => void;
}) {
  const { t } = useTranslation('common');
  // The hour counts on the last day; before it, the date and hour.
  const expiry = (at: number) => {
    const left = at - Date.now();

    return left < DAY_MS
      ? t('council.request_expires_in', { count: Math.max(1, Math.ceil(left / HOUR_MS)) })
      : t('council.request_expires', { date: new Date(at) });
  };
  const stage = request.stage as keyof typeof STAGE_TONE;
  const name = request.user_name ?? request.user_email;
  const metBy = request.contributors
    .filter((c) => c.in_person)
    .map((c) => c.name)
    .join(', ');
  const approvedBy = request.contributors
    .filter((c) => !c.in_person)
    .map((c) => c.name)
    .join(', ');
  // Who met the person, who approved since, and how far from the threshold.
  const progress = [
    metBy ? t('council.request_met_by', { names: metBy }) : t('council.request_met'),
    approvedBy && t('council.request_approved_by', { names: approvedBy }),
    t('council.request_parts', { count: request.contributors.length, threshold: request.threshold }),
  ]
    .filter(Boolean)
    .join(' · ');

  let band: ReactNode = null;
  let bandTone: 'neutral' | 'warning' = 'neutral';

  if (request.my_contribution !== 'none') {
    band = (
      <span>
        {t(request.my_contribution === 'in_person' ? 'council.my_contribution_in_person' : 'council.my_contribution_remote')} {progress}
      </span>
    );
  } else if (request.can_contribute && request.stage === 'awaiting_meeting') {
    bandTone = 'warning';
    band = (
      <>
        <span>{t('council.request_nobody_met')}</span>
        <Button size="nano" onClick={onInPerson} disabled={busy}>
          {t('council.hand_over_in_person')}
        </Button>
      </>
    );
  } else if (request.can_contribute) {
    band = (
      <>
        <span>{progress}</span>
        <Button size="nano" onClick={onRemote} disabled={busy}>
          {t('council.approve_remotely')}
        </Button>
      </>
    );
  } else if (request.contributors.length > 0) {
    band = <span>{progress}</span>;
  }

  return (
    <PersonRow
      name={name}
      email={request.user_email}
      secondary={expiry(request.expires_at_millis)}
      status={<Chip tone={STAGE_TONE[stage] ?? 'neutral'}>{t(`council.stage_${stage}` as 'council.stage_collecting')}</Chip>}
      menu={
        <RowMenu
          label={t('council.request_menu', { name })}
          disabled={busy}
          options={[{ label: t('council.abort'), icon: <XMark aria-hidden size={16} />, variant: 'danger', callback: onAbort }]}
        />
      }
      band={band}
      bandTone={bandTone}
    />
  );
}
