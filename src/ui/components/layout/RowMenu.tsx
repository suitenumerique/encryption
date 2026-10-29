import { Button, DropdownMenu, type DropdownMenuItem } from '@gouvfr-lasuite/ui-components';
import { More } from '@gouvfr-lasuite/ui-components/icons';
import { useState } from 'react';

/** The "⋯" of a row: the actions that are not the usual next step, in the design system's dropdown menu. */
export function RowMenu({ label, options, disabled }: { label: string; options: DropdownMenuItem[]; disabled?: boolean }) {
  const [open, setOpen] = useState(false);

  return (
    <DropdownMenu options={options} isOpen={open} onOpenChange={setOpen}>
      <Button
        size="nano"
        variant="tertiary"
        color="neutral"
        aria-label={label}
        title={label}
        disabled={disabled}
        icon={<More aria-hidden size={16} />}
        onClick={() => setOpen(true)}
      />
    </DropdownMenu>
  );
}
