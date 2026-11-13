import type { ReactNode } from 'react';

import styles from '@encryption/src/ui/components/layout/layout.module.css';

/**
 * One choice of a `radiogroup`, as a selectable card. A native radio inside it:
 * arrow keys move between the options and the group is a single tab stop, as
 * screen reader users expect.
 */
export function OptionCard({
  name,
  selected,
  onSelect,
  icon,
  title,
  description,
}: {
  name: string;
  selected: boolean;
  onSelect: () => void;
  icon: ReactNode;
  title: string;
  description: string;
}) {
  return (
    <label className={selected ? `${styles.option} ${styles.optionSelected}` : styles.option}>
      <input type="radio" name={name} className={styles.optionInput} checked={selected} onChange={onSelect} />
      <span className={styles.optionIcon}>{icon}</span>
      <span className={styles.optionText}>
        <span className={styles.optionTitle}>{title}</span>
        <span className={styles.optionDescription}>{description}</span>
      </span>
    </label>
  );
}
