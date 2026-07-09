/**
 * At-rest protection for the cached VRK, using a non-extractable WebCrypto key.
 *
 * The device key is an AES-GCM key generated with `extractable: false`: its raw
 * bytes can never be read back by script, and the browser persists the handle in
 * IndexedDB. We wrap the VRK under it before caching, so a copied IndexedDB or a
 * cold disk is useless without the live key, and an XSS payload can't lift it.
 *
 * Why the VRK itself is not the non-extractable key: WebCrypto refuses to export
 * a non-extractable key, so a non-extractable VRK could neither be forwarded to
 * a new device during approval nor fed to libsodium's item sealing. The VRK
 * therefore stays usable (raw bytes) in memory for the session; the device key
 * is what guards the persisted copy.
 */
const ALGORITHM = 'AES-GCM';
const IV_BYTES = 12;

const subtle = crypto.subtle;

// Normalize to a fresh ArrayBuffer-backed view; WebCrypto's BufferSource type is
// stricter than the ArrayBufferLike-backed arrays libsodium hands us.
function view(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

export async function generateDeviceKey(): Promise<CryptoKey> {
  return subtle.generateKey({ name: ALGORITHM, length: 256 }, false, ['encrypt', 'decrypt']);
}

export async function wrapVrkForDevice(vrk: Uint8Array, deviceKey: CryptoKey): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ciphertext = new Uint8Array(await subtle.encrypt({ name: ALGORITHM, iv }, deviceKey, view(vrk)));

  const blob = new Uint8Array(iv.length + ciphertext.length);
  blob.set(iv, 0);
  blob.set(ciphertext, iv.length);

  return blob;
}

export async function unwrapVrkForDevice(blob: Uint8Array, deviceKey: CryptoKey): Promise<Uint8Array> {
  const iv = view(blob.slice(0, IV_BYTES));
  const ciphertext = view(blob.slice(IV_BYTES));

  return new Uint8Array(await subtle.decrypt({ name: ALGORITHM, iv }, deviceKey, ciphertext));
}
