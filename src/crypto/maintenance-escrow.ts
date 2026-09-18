/**
 * Maintenance escrow: one extra wrapped copy of a resource key, for an
 * operator-held key pair.
 *
 * A deployment may configure a maintenance public key. When it does, every
 * wrap-for-recipients operation of the vault (create a root resource, share it)
 * also wraps the same symmetric key under that public key and returns the copy
 * in a field of its own. The product stores it next to the ciphertext, and the
 * operator can later read or re-encode that resource with the matching secret
 * key, without any user device taking part (see architecture.md, Appendix C).
 *
 * No new cryptography: the copy is a standard wrap-for-user blob
 * (`encryptSymmetricKeyForUsers`), so the tooling that opens it is the same
 * X-Wing decapsulation every device runs. The public key travels in the same
 * wire format as a user's registered encryption key (`[version:1][xwing:1216]`).
 */
import {
  type HybridKeyPair,
  type HybridPublicKey,
  type HybridSecretKey,
  decryptSymmetricKeyForUser,
  encryptSymmetricKeyForUsers,
  generateUserKeyPair,
} from '@encryption/src/crypto/encryption';
import { base64ToUint8, exportPublicKeyAsBase64, importPublicKeyFromBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
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

export async function wrapKeyForMaintenance(symmetricKey: Uint8Array, maintenancePublicKey: HybridPublicKey): Promise<Uint8Array> {
  const { maintenance } = await encryptSymmetricKeyForUsers(symmetricKey, { maintenance: maintenancePublicKey });

  return maintenance;
}

export async function unwrapMaintenanceKey(maintenanceSecretKey: HybridSecretKey, maintenanceKey: Uint8Array): Promise<Uint8Array> {
  return decryptSymmetricKeyForUser(maintenanceSecretKey, maintenanceKey);
}

// ============================================================================
// The operator's key file
// ============================================================================

const MAINTENANCE_KEY_FILE_VERSION = 1;

/**
 * On-disk shape of the operator's key pair. `publicKey` is the exact value to
 * put in `MAINTENANCE_ESCROW_PUBLIC_KEY`; `secretKey` never leaves the machine
 * that runs the maintenance CLI.
 */
export interface MaintenanceKeyFile {
  version: number;
  publicKey: string;
  secretKey: string;
}

export async function generateMaintenanceKeyPair(): Promise<HybridKeyPair> {
  return generateUserKeyPair();
}

export function serializeMaintenanceKeyPair(pair: HybridKeyPair): string {
  const file: MaintenanceKeyFile = {
    version: MAINTENANCE_KEY_FILE_VERSION,
    publicKey: exportPublicKeyAsBase64(pair.publicKey),
    secretKey: uint8ToBase64(pair.secretKey),
  };

  return `${JSON.stringify(file, null, 2)}\n`;
}

export function parseMaintenanceKeyPair(text: string): HybridKeyPair {
  let file: Partial<MaintenanceKeyFile>;

  try {
    file = JSON.parse(text) as Partial<MaintenanceKeyFile>;
  } catch {
    throw new VaultError(VaultErrorCode.INVALID_MAINTENANCE_KEY, 'Invalid maintenance key file: not JSON');
  }

  if (file.version !== MAINTENANCE_KEY_FILE_VERSION || typeof file.publicKey !== 'string' || typeof file.secretKey !== 'string') {
    throw new VaultError(VaultErrorCode.INVALID_MAINTENANCE_KEY, 'Invalid maintenance key file: unexpected shape');
  }

  return { publicKey: parseMaintenancePublicKey(file.publicKey), secretKey: base64ToUint8(file.secretKey) };
}
