import { useCallback, useMemo, useRef, useState } from 'react';

interface DecimalCodeInputProps {
  groupCount?: number;
  groupSize?: number;
  // Emits the concatenated digits plus whether every group is full, so the caller
  // can keep its submit button disabled until the whole code is entered.
  onChange: (digits: string, complete: boolean) => void;
}

/**
 * A row of fixed-width, digits-only boxes for typing the device pairing code, in
 * the style of the recovery-phrase grid: typing the last digit of a group jumps to
 * the next box, Backspace on an empty box steps back, and pasting the whole code
 * distributes it across the boxes. `inputMode="numeric"` asks phones/keyboards for
 * a number pad and non-digits are dropped, so the code is always well-formed.
 */
export function DecimalCodeInput({ groupCount = 8, groupSize = 5, onChange }: DecimalCodeInputProps) {
  const [groups, setGroups] = useState<string[]>(() => Array(groupCount).fill(''));
  const refs = useRef<Array<HTMLInputElement | null>>([]);

  const emit = useCallback(
    (next: string[]) => {
      setGroups(next);
      onChange(
        next.join(''),
        next.every((g) => g.length === groupSize)
      );
    },
    [onChange, groupSize]
  );

  const focus = useCallback(
    (i: number) => {
      refs.current[Math.max(0, Math.min(i, groupCount - 1))]?.focus();
    },
    [groupCount]
  );

  const handleChange = useCallback(
    (index: number, raw: string) => {
      // `maxLength` caps the value at one group's worth before React sees it, so
      // no fan-out is needed here; multi-group paste is handled in handlePaste.
      const digits = raw.replace(/\D/g, '');

      const next = [...groups];
      next[index] = digits;
      emit(next);

      // Advance to the next box once this group is full.
      if (digits.length === groupSize && index < groupCount - 1) focus(index + 1);
    },
    [groups, groupCount, groupSize, emit, focus]
  );

  const handlePaste = useCallback(
    (index: number, e: React.ClipboardEvent<HTMLInputElement>) => {
      // `maxLength` on the input truncates a pasted string to one group's worth
      // before React sees it, so paste-to-distribute never fires through onChange.
      // Intercept the paste directly and fan the digits out from this box onward.
      const digits = e.clipboardData.getData('text').replace(/\D/g, '');
      if (digits.length <= groupSize) return;

      e.preventDefault();
      const next = [...groups];
      let rest = digits;
      let i = index;
      while (rest.length > 0 && i < groupCount) {
        next[i] = rest.slice(0, groupSize);
        rest = rest.slice(groupSize);
        i += 1;
      }
      emit(next);
      focus(Math.min(i, groupCount - 1));
    },
    [groups, groupCount, groupSize, emit, focus]
  );

  const handleKeyDown = useCallback(
    (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Backspace' && groups[index] === '' && index > 0) {
        e.preventDefault();
        focus(index - 1);
      } else if (e.key === 'ArrowLeft' && index > 0 && e.currentTarget.selectionStart === 0) {
        e.preventDefault();
        focus(index - 1);
      } else if (e.key === 'ArrowRight' && index < groupCount - 1 && e.currentTarget.selectionStart === groups[index].length) {
        e.preventDefault();
        focus(index + 1);
      }
    },
    [groups, groupCount, focus]
  );

  const indices = useMemo(() => Array.from({ length: groupCount }, (_, i) => i), [groupCount]);

  // Fixed 4 columns so the boxes always lay out as even rows (8 groups -> 2 rows
  // of 4) regardless of the iframe width, instead of wrapping unevenly.
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8 }}>
      {indices.map((i) => (
        <input
          key={i}
          ref={(el) => {
            refs.current[i] = el;
          }}
          type="text"
          inputMode="numeric"
          pattern="[0-9]*"
          autoComplete="off"
          maxLength={groupSize}
          value={groups[i]}
          onChange={(e) => handleChange(i, e.target.value)}
          onKeyDown={(e) => handleKeyDown(i, e)}
          onPaste={(e) => handlePaste(i, e)}
          aria-label={`code group ${i + 1}`}
          style={{
            width: '100%',
            boxSizing: 'border-box',
            textAlign: 'left',
            fontFamily: 'monospace',
            fontSize: 20,
            letterSpacing: '0.12em',
            padding: '10px 10px',
            borderRadius: 4,
            border: '1px solid var(--c--contextuals--border--surface--primary)',
          }}
        />
      ))}
    </div>
  );
}
