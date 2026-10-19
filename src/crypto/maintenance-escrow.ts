/**
 * Maintenance escrow: one extra wrapped copy of a resource key, for an
 * operator-held key pair.
 *
 * A deployment may configure maintenance public keys, one per group of email
 * domains (one per organization). When it does, every wrap-for-recipients
 * operation of the vault (create a root resource, share it) also wraps the same
 * symmetric key under the key of the resource's OWNER and returns the copy in a
 * field of its own. The product stores it next to the ciphertext, and that
 * organization's custodians can later decrypt the resource with the matching
 * secret key, without any user device taking part (see architecture.md,
 * Appendix E).
 *
 * The copy is the X-Wing wrap every recipient gets (`encryptSymmetricKeyForUsers`),
 * under a label of its own (`DOMAIN_KEM_MAINTENANCE_KEY`) so a maintenance copy and
 * a user's copy can never be accepted as each other, behind a header naming the
 * key it was made for:
 *
 *   [version:1][keyId:16][X-Wing wrap]
 *
 * The key id is the 128 bits the key's fingerprint writes in digits, so a copy
 * says which custodians can open it (the tool sets aside another organization's
 * items instead of reporting them as damaged) and an export can be filtered per
 * key in SQL, without a column of its own.
 *
 * The secret key is an X-Wing seed, 32 bytes, so its custodians hold it as a
 * 24-word BIP-39 phrase: written on paper, typed on the isolated machine, never a
 * file to carry around. The public key is derived from it.
 */
import sodium from 'libsodium-wrappers-sumo';

import {
  type HybridKeyPair,
  type HybridPublicKey,
  type HybridSecretKey,
  decryptSymmetricKeyForUser,
  encryptSymmetricKeyForUsers,
  ensureSodium,
} from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64, importPublicKeyFromBase64 } from '@encryption/src/crypto/encryption-backup';
import { type MnemonicLanguage, keyToMnemonic, mnemonicToKey } from '@encryption/src/crypto/mnemonic';
import { DOMAIN_KEM_MAINTENANCE_KEY, DOMAIN_MAINTENANCE_KEY_FINGERPRINT } from '@encryption/src/shared/crypto-domains';
import { FINGERPRINT_BYTES, computeFingerprintBytes, fingerprintBytesToDecimal } from '@encryption/src/shared/decimal-fingerprint';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

/** X-Wing public key size (crypto_kem_xwing_PUBLICKEYBYTES), plus the wire version byte. */
export const MAINTENANCE_PUBLIC_KEY_WIRE_BYTES = 1 + 1216;

/**
 * Parse the configured maintenance public key (base64 wire format). Shape only,
 * no libsodium needed: the server validates its environment with it at boot, and
 * the vault runs it once at startup. A wrong length or version fails loud, since a
 * malformed key would otherwise surface as a failed wrap on every document.
 */
export function parseMaintenancePublicKey(base64: string): HybridPublicKey {
  let key: HybridPublicKey;

  try {
    key = importPublicKeyFromBase64(base64);
  } catch (error) {
    // importPublicKeyFromBase64 reports a bad version byte or a truncated blob
    // with its own codes; a non-base64 string throws from atob.
    if (error instanceof VaultError) throw new VaultError(VaultErrorCode.INVALID_MAINTENANCE_KEY, `Invalid maintenance public key: ${error.message}`);

    throw new VaultError(VaultErrorCode.INVALID_MAINTENANCE_KEY, 'Invalid maintenance public key: not base64');
  }

  if (key.length !== MAINTENANCE_PUBLIC_KEY_WIRE_BYTES - 1) {
    throw new VaultError(
      VaultErrorCode.INVALID_MAINTENANCE_KEY,
      `Invalid maintenance public key: expected ${MAINTENANCE_PUBLIC_KEY_WIRE_BYTES - 1} bytes, got ${key.length}`
    );
  }

  return key;
}

/** A maintenance public key with the id its copies carry. */
export interface MaintenancePublicKey {
  publicKey: HybridPublicKey;
  keyId: Uint8Array;
}

/** A maintenance key pair, as its phrase gives it. */
export interface MaintenanceKeyPair extends HybridKeyPair {
  keyId: Uint8Array;
}

export const MAINTENANCE_COPY_VERSION = 0x01;

const COPY_HEADER_BYTES = 1 + FINGERPRINT_BYTES;

/** The id copies carry: the fingerprint's 128 bits, over the public key's wire form. */
export async function computeMaintenanceKeyId(publicKey: HybridPublicKey): Promise<Uint8Array> {
  return computeFingerprintBytes(DOMAIN_MAINTENANCE_KEY_FINGERPRINT, base64ToUint8(exportPublicKeyAsBase64(publicKey)));
}

export function maintenanceKeyIdToFingerprint(keyId: Uint8Array): string {
  return fingerprintBytesToDecimal(keyId);
}

/**
 * The key id in hexadecimal, from the 40-digit fingerprint: what a product team
 * matches bytes 2 to 17 of the stored copies against to export one key's resources
 * (`substring(copy from 2 for 16) = decode('<hex>', 'hex')`).
 */
export function maintenanceFingerprintToKeyIdHex(fingerprint: string): string {
  return BigInt(fingerprint.slice(1)).toString(16).padStart(32, '0');
}

export async function importMaintenancePublicKey(base64: string): Promise<MaintenancePublicKey> {
  const publicKey = parseMaintenancePublicKey(base64);

  return { publicKey, keyId: await computeMaintenanceKeyId(publicKey) };
}

export async function wrapKeyForMaintenance(symmetricKey: Uint8Array, key: MaintenancePublicKey): Promise<Uint8Array> {
  const { maintenance } = await encryptSymmetricKeyForUsers(symmetricKey, { maintenance: key.publicKey }, DOMAIN_KEM_MAINTENANCE_KEY);
  const copy = new Uint8Array(COPY_HEADER_BYTES + maintenance.length);

  copy[0] = MAINTENANCE_COPY_VERSION;
  copy.set(key.keyId, 1);
  copy.set(maintenance, COPY_HEADER_BYTES);

  return copy;
}

/** The id of the key a copy was made for, read from its header without opening it. */
export function readMaintenanceCopyKeyId(copy: Uint8Array): Uint8Array {
  if (copy.length <= COPY_HEADER_BYTES) {
    throw new VaultError(VaultErrorCode.CIPHERTEXT_TOO_SHORT, 'Maintenance copy is too short to be valid');
  }

  if (copy[0] !== MAINTENANCE_COPY_VERSION) {
    throw new VaultError(VaultErrorCode.UNSUPPORTED_CRYPTO_VERSION, `Unsupported maintenance copy version ${copy[0]}`);
  }

  return copy.slice(1, COPY_HEADER_BYTES);
}

/**
 * Open a copy with the custodians' key. A copy made for another key fails with
 * OTHER_MAINTENANCE_KEY before any decryption, naming that key's fingerprint; a
 * copy that names this key but does not open is damaged, or relabelled: the id is
 * a routing hint, and naming this key does not make another key's copy open
 * (WRONG_SECRET_KEY either way). Binding it into the wrap would add nothing, since
 * anyone who can rewrite the header can replace the whole copy with one wrapped
 * for any public key.
 */
export async function unwrapMaintenanceKey(key: { secretKey: HybridSecretKey; keyId: Uint8Array }, copy: Uint8Array): Promise<Uint8Array> {
  const keyId = readMaintenanceCopyKeyId(copy);

  // Public ids, nothing to keep constant-time.
  if (keyId.length !== key.keyId.length || keyId.some((byte, index) => byte !== key.keyId[index])) {
    throw new VaultError(VaultErrorCode.OTHER_MAINTENANCE_KEY, `Escrowed for the maintenance key ${maintenanceKeyIdToFingerprint(keyId)}`);
  }

  return decryptSymmetricKeyForUser(key.secretKey, copy.slice(COPY_HEADER_BYTES), DOMAIN_KEM_MAINTENANCE_KEY);
}

// ============================================================================
// The custodians' phrase
// ============================================================================

export async function maintenanceKeyPairFromSeed(seed: Uint8Array): Promise<MaintenanceKeyPair> {
  await ensureSodium();

  if (seed.length !== sodium.crypto_kem_xwing_SEEDBYTES) {
    throw new VaultError(VaultErrorCode.INVALID_MAINTENANCE_KEY, `A maintenance seed is ${sodium.crypto_kem_xwing_SEEDBYTES} bytes`);
  }

  const { publicKey, privateKey } = sodium.crypto_kem_xwing_seed_keypair(seed);

  return { publicKey, secretKey: privateKey, keyId: await computeMaintenanceKeyId(publicKey) };
}

/** A fresh seed and its phrase. `seed` is injectable so a demonstration can be reproducible. */
export async function generateMaintenancePhrase(language: MnemonicLanguage, seed?: Uint8Array): Promise<string> {
  await ensureSodium();

  return keyToMnemonic(seed ?? sodium.randombytes_buf(sodium.crypto_kem_xwing_SEEDBYTES), language);
}

/** The key pair a phrase stands for, in either wordlist. Throws INVALID_MNEMONIC on a typo (BIP-39 checksum). */
export async function maintenanceKeyPairFromPhrase(phrase: string): Promise<MaintenanceKeyPair> {
  return maintenanceKeyPairFromSeed(mnemonicToKey(phrase));
}

/** The value to configure as a `publicKey` of MAINTENANCE_ESCROW_KEYS. */
export function exportMaintenancePublicKey(publicKey: HybridPublicKey): string {
  return exportPublicKeyAsBase64(publicKey);
}

/**
 * What the custodians compare: the tool shows it for the phrase they typed, the
 * server logs it at boot for every key it was configured with.
 */
export async function computeMaintenanceKeyFingerprint(publicKeyBase64: string): Promise<string> {
  return maintenanceKeyIdToFingerprint(await computeFingerprintBytes(DOMAIN_MAINTENANCE_KEY_FINGERPRINT, base64ToUint8(publicKeyBase64)));
}
