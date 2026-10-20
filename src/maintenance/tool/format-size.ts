const UNITS = ['byte', 'kilobyte', 'megabyte', 'gigabyte'] as const;

/** A byte count with its unit, in the reader's language: "830 bytes", "1.2 kB", "1,2 ko". */
export function formatSize(bytes: number, locale: string): string {
  let value = bytes;
  let unit = 0;

  while (value >= 1000 && unit < UNITS.length - 1) {
    value /= 1000;
    unit++;
  }

  return new Intl.NumberFormat(locale, {
    style: 'unit',
    unit: UNITS[unit],
    // The short form gives "830 byte" in English: bytes are spelled out.
    unitDisplay: unit === 0 ? 'long' : 'short',
    maximumFractionDigits: unit === 0 ? 0 : 1,
  }).format(value);
}
