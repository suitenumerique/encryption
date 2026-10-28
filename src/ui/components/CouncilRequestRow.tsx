import { Button } from '@gouvfr-lasuite/ui-components';
import { useTranslation } from 'react-i18next';

import type { CouncilRequestSummary } from '@encryption/src/ui/api/council-client';
import { Chip, Identity } from '@encryption/src/ui/components/layout/IdentityCard';
import styles from '@encryption/src/ui/components/layout/layout.module.css';

const STAGE_TONE = { collecting: 'neutral', awaiting_meeting: 'warning', cooldown: 'info', released: 'success' } as const;

/** One recovery request in a custodian's council card, with what the custodian can do about it. */
export function CouncilRequestRow({
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
