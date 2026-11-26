// VAULT_DEVICE_INACTIVITY_DAYS, parsed the same way by the server's env schema and
// by the vault's dev server (whose Vite config cannot import the aliased schema).
// No import on purpose, for that second reader.

const DEFAULT_DAYS = 365;
// A holiday must never cost a re-enrollment.
const MIN_DAYS = 30;

/** Empty means unset (the default), never 0: coercing '' would silently turn the delay off. */
export function parseDeviceInactivityDays(raw: string | undefined): number {
  if (raw === undefined || raw === '') return DEFAULT_DAYS;

  const days = Number(raw);

  if (!Number.isInteger(days) || (days !== 0 && days < MIN_DAYS)) {
    throw new Error(`expects 0 (never de-enroll) or at least ${MIN_DAYS} days, got "${raw}"`);
  }

  return days;
}
