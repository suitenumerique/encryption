import { Button, Checkbox, VariantType } from '@gouvfr-lasuite/ui-components';
import { type ReactNode, useState } from 'react';
import { useTranslation } from 'react-i18next';

import type { CustodianCouncil } from '@encryption/src/ui/api/council-client';
import { rosterHead } from '@encryption/src/ui/components/council-roster';
import { Notice, Screen } from '@encryption/src/ui/components/layout/Screen';
import styles from '@encryption/src/ui/components/layout/layout.module.css';

/**
 * Choosing who moves the escrows still split over an older version: exactly as
 * many custodians as that version's threshold, all still in the council with
 * the same key. Each then processes the escrows from their own vault.
 */
export function CouncilReshareStart({
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
  const head = rosterHead(council.chain)!;
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
