import sodium from 'libsodium-wrappers-sumo';
import { describe, expect, it } from 'vitest';

import {
  decryptSymmetricKeyForUser,
  encryptSymmetricKeyForUsers,
  ensureSodium,
  generateSymmetricKey,
  generateUserKeyPair,
} from '@encryption/src/crypto/encryption';
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
import { DOMAIN_KEM_DOCUMENT_KEY } from '@encryption/src/shared/crypto-domains';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

const seq = (length: number, start = 0) => Uint8Array.from({ length }, (_, i) => (start + i) & 0xff);

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

  it('never accepts a maintenance copy as a user copy, or the other way round', async () => {
    const pair = await generateMaintenanceKeyPair();
    const key = await generateSymmetricKey();
    const { user } = await encryptSymmetricKeyForUsers(key, { user: pair.publicKey }, DOMAIN_KEM_DOCUMENT_KEY);

    await expect(unwrapMaintenanceKey(pair.secretKey, user)).rejects.toMatchObject({ code: VaultErrorCode.WRONG_SECRET_KEY });
    await expect(
      decryptSymmetricKeyForUser(pair.secretKey, await wrapKeyForMaintenance(key, pair.publicKey), DOMAIN_KEM_DOCUMENT_KEY)
    ).rejects.toMatchObject({
      code: VaultErrorCode.WRONG_SECRET_KEY,
    });
  });

  // A fixed copy for a seeded key pair: stored copies only keep opening while the
  // wrap format and its label stay unchanged.
  it('opens a known-answer maintenance copy', async () => {
    await ensureSodium();
    const maintenance = sodium.crypto_kem_xwing_seed_keypair(seq(32));
    const copy = Uint8Array.from(
      Buffer.from(
        'AWAEl35PnbmHzxqwdgFT2ZSi13p+XFdMh81nPoDtxGg3QPHMIpTFYV5B95dgUrp4UdEdbJ4Toh/PjIHdV9USRy9tdElXwbbyqlqct6XqoQIkTlybEQv30pGDNxd1v1mFF04/1iQIXTLGbrsn/761XOEGHw8/RGAeKNZEcU1b7pl5TEHsCJBABUOMYKYsWNMWTWr5hQTOz9qWRSpRDXG2NiFxT/gwDdvswLPF5nrsAi+dzwm433FLsDOC8Q99LfAocHqa2kK2Dbl7AuqLZyV7nCytcQJdoK3tnUNMfueRNJzSdLOLNazB2mng367Drb+peytTQPEpngEXW+jHI9ph2Ol2LDK/tfLEXenWVefOPu1J7uzN6KA+OKk5vmzXmXBI3eRV4FJSPNABG9WYq4PcbWPzgJUpPtawFFImmP6mTHcUhw4du4vL9PDhIiaA6RBs3v76bdTVIQBLw5RnHGn72u/mK4543Ima+5LuqmOm8T2HNJd1Apy0MQyiocbS/FfuA28Ku3tsrDD1nDlb+2JHW08kt9ytURcUEeVTaFotws4vL3c9sOw5K210ur+QEA8BdZmgwlyd+mNqu5HazPAOyavoGpBbC6lQPQLMlwEb8rpgYDuD/OQFqwXH5MO+ZvBjZg311IbCxCZcVAFZ8nEVY3BbR3b1c0dppWkGbLC0t/Gbtaz/mXeqknwqKKFPMWPRw6sSkwiaU1z63C6yZgLyHqk0sJp80IZ/ERJX3wkK3CocU1t7o8hGKa2MwPwhwKClOp8j/6Yijgg0HenGEqBzzXAQMO73dZUQGC0IsZIYAALbbmyNjR2SlMXnLxZiVVZNgUWgLPzjkhNrFNkCptDa3j7Ur6A5bKVi3qbpRDNX3WZybIifGwFgfJ56NZlRSCOTrz52KBNsO/SE+G6tm+ACBUd5S+j+UB6sD1RHXDCMciNL9JaXuUSnedy5SbfB/sHq0fnskpGPXLr1YieVeUB5FHLe9mGjBOncLrpL5UAX+7kRSYzTDvK5IiUMlhp6nKwqDhT2dTajooaBBJ50U97IM/H1BualurZmmUA+jh36qWT1+e9Z8gJtVDfXcYZdKNKo8QXTfBa7X6Kk983R5mW9EDqYRYLt9nkryUAdu+MJyI9vQ9FTxVqqvp33dtRN6asA3fx3Oq5m9Cva7Rb2GbX2aJmtOz39Nq6pIaOmAYmfNS3e9vGbeK2/ldD2dh+gyW8KquzMzH4I4seRMZpX4+BjyPTh5UvvJiAeuaJxjNjB3ZlgzDpoBsI8p2HPxmGHGlyt4etw3e3tfiSa84NnRuOij8zZWK2L98zDQ2g1LPCxE/CSjYrN3Gxwooz0Rhdcbiw8ghKSAGby6p5NRTaBKRmd4f8kbRhNk8u30vP6lNYGNtQGPE17pu81sxD5i34oDM+cQ/qZ+DdGAmA6/xSYaG76sz6oJ2cnTmCqeCtfnO06AIK80fJuhy1aJN9q6ZnDg41TEcAkFc2/YdwvWEAeGZVvkscZKwHY4mqMAi9gFmtytit4DzxW+UVpXol8+fh06vQohBzVgI+r/KfDqVtQn/3dneCaQBbZAon5/+N71uPSrLHCazJ09rEjA8a8ZaM=',
        'base64'
      )
    );

    expect(await unwrapMaintenanceKey(maintenance.privateKey, copy)).toEqual(seq(32, 100));
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
