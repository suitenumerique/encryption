// Pure formatting helpers for the device-pairing decimal fingerprint, shared by
// the vault (which computes/compares it) and the UI (which displays it).

// Group the decimal fingerprint in blocks of five for readable display.
export function formatDecimalFingerprint(digits: string): string {
  return digits.replace(/(\d{5})(?=\d)/g, '$1 ').trim();
}

// Strip spaces/formatting so a typed value can be compared to the canonical form.
export function normalizeDecimalFingerprint(text: string): string {
  return text.replace(/\D/g, '');
}
