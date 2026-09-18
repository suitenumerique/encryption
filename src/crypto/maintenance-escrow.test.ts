import sodium from 'libsodium-wrappers-sumo';
import { describe, expect, it } from 'vitest';

import { ensureSodium, generateSymmetricKey, generateUserKeyPair } from '@encryption/src/crypto/encryption';
import { exportPublicKeyAsBase64, uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import {
  MAINTENANCE_PUBLIC_KEY_WIRE_BYTES,
  generateMaintenanceKeyPair,
  parseMaintenanceKeyPair,
  parseMaintenancePublicKey,
  serializeMaintenanceKeyPair,
  unwrapMaintenanceKey,
  wrapKeyForMaintenance,
} from '@encryption/src/crypto/maintenance-escrow';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

describe('maintenance escrow primitives', () => {
  it('pins the wire size to the X-Wing public key size libsodium reports', async () => {
    await ensureSodium();

    expect(MAINTENANCE_PUBLIC_KEY_WIRE_BYTES).toBe(1 + sodium.crypto_kem_xwing_PUBLICKEYBYTES);
  });

  it('accepts a registered-format public key and rejects every other shape with INVALID_MAINTENANCE_KEY', async () => {
    const pair = await generateUserKeyPair();
    const wire = exportPublicKeyAsBase64(pair.publicKey);

    expect(parseMaintenancePublicKey(wire)).toEqual(pair.publicKey);

    const truncated = uint8ToBase64(new Uint8Array([1, 2, 3]));
    const wrongVersion = uint8ToBase64(new Uint8Array([9, ...pair.publicKey]));

    for (const bad of ['not base64!!', '', truncated, wrongVersion, wire.slice(0, -8)]) {
      let thrown: unknown;

      try {
        parseMaintenancePublicKey(bad);
      } catch (error) {
        thrown = error;
      }

      expect(thrown, bad.slice(0, 16)).toBeInstanceOf(VaultError);
      expect((thrown as VaultError).code).toBe(VaultErrorCode.INVALID_MAINTENANCE_KEY);
    }
  });

  it('wraps a resource key that only the matching secret key opens', async () => {
    const maintenance = await generateMaintenanceKeyPair();
    const other = await generateMaintenanceKeyPair();
    const key = await generateSymmetricKey();

    const blob = await wrapKeyForMaintenance(key, maintenance.publicKey);

    expect(await unwrapMaintenanceKey(maintenance.secretKey, blob)).toEqual(key);
    await expect(unwrapMaintenanceKey(other.secretKey, blob)).rejects.toMatchObject({ code: VaultErrorCode.WRONG_SECRET_KEY });
  });

  it('round-trips the operator key file and rejects a malformed one', async () => {
    const pair = await generateMaintenanceKeyPair();
    const text = serializeMaintenanceKeyPair(pair);
    const file = JSON.parse(text) as { version: number; publicKey: string; secretKey: string };

    expect(file.version).toBe(1);
    expect(parseMaintenancePublicKey(file.publicKey)).toEqual(pair.publicKey);
    expect(parseMaintenanceKeyPair(text)).toEqual(pair);

    for (const bad of ['{', '{"version":2}', JSON.stringify({ ...file, publicKey: 'AAAA' })]) {
      expect(() => parseMaintenanceKeyPair(bad)).toThrow(VaultError);
    }
  });
});
