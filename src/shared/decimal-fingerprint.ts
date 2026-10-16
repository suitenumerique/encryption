// The decimal fingerprints people compare (identities, device pairing): computed
// here once, with WebCrypto, so the vault, the interface and the client SDK can
// never drift apart. Formatting helpers for display and typed input live here too.

// Leading digit of every fingerprint: which scheme produced it. A 128-bit value
// needs at most 39 digits, so the 40th is free to name the scheme, readable by a
// person comparing codes as well as by code. Bump it, and only it, if the hash,
// the truncation or the encoding below ever changes.
export const FINGERPRINT_SCHEME = '1';

const FINGERPRINT_BYTES = 16;
const FINGERPRINT_VALUE_DIGITS = 39;

/**
 * `scheme digit` + the first 128 bits of SHA-256(domain label | 0x00 | key),
 * read big-endian as 39 zero-padded decimal digits: 40 digits in all, groupable
 * in 8 blocks of 5. The domain keeps fingerprints of different kinds of key from
 * ever matching each other.
 */
export async function computeDecimalFingerprint(domain: string, key: Uint8Array): Promise<string> {
  const label = new TextEncoder().encode(domain);
  const input = new Uint8Array(label.length + 1 + key.length);
  input.set(label, 0);
  input.set(key, label.length + 1);

  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', input)).slice(0, FINGERPRINT_BYTES);

  let n = 0n;
  for (const b of hash) n = (n << 8n) | BigInt(b);

  return `${FINGERPRINT_SCHEME}${n.toString().padStart(FINGERPRINT_VALUE_DIGITS, '0')}`;
}

// Group the decimal fingerprint in blocks of five for readable display.
export function formatDecimalFingerprint(digits: string): string {
  return digits.replace(/(\d{5})(?=\d)/g, '$1 ').trim();
}

// Strip spaces/formatting so a typed value can be compared to the canonical form.
export function normalizeDecimalFingerprint(text: string): string {
  return text.replace(/\D/g, '');
}
