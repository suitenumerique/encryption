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
import { computeKeyFingerprint } from '@encryption/src/crypto/fingerprint';
import {
  MAINTENANCE_PUBLIC_KEY_WIRE_BYTES,
  computeMaintenanceKeyFingerprint,
  computeMaintenanceKeyId,
  exportMaintenancePublicKey,
  generateMaintenancePhrase,
  importMaintenancePublicKey,
  maintenanceKeyIdToFingerprint,
  maintenanceKeyPairFromPhrase,
  maintenanceKeyPairFromSeed,
  parseMaintenancePublicKey,
  readMaintenanceCopyKeyId,
  unwrapMaintenanceKey,
  wrapKeyForMaintenance,
} from '@encryption/src/crypto/maintenance-escrow';
import { DEV_MAINTENANCE_PHRASE, DEV_MAINTENANCE_PUBLIC_KEY } from '@encryption/src/maintenance/dev-maintenance-key';
import { DOMAIN_KEM_DOCUMENT_KEY } from '@encryption/src/shared/crypto-domains';
import { VaultError, VaultErrorCode } from '@encryption/src/shared/vault-error';

const generateMaintenanceKeyPair = async () => maintenanceKeyPairFromPhrase(await generateMaintenancePhrase('english'));

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

  it('wraps a resource key that only the matching secret key opens, behind a header naming that key', async () => {
    const maintenance = await generateMaintenanceKeyPair();
    const key = await generateSymmetricKey();

    const copy = await wrapKeyForMaintenance(key, maintenance);

    expect(copy[0]).toBe(1);
    expect(readMaintenanceCopyKeyId(copy)).toEqual(maintenance.keyId);
    expect(await unwrapMaintenanceKey(maintenance, copy)).toEqual(key);
  });

  it("sets aside another organization's copy by its key id, naming that key's fingerprint", async () => {
    const ours = await generateMaintenanceKeyPair();
    const theirs = await generateMaintenanceKeyPair();
    const copy = await wrapKeyForMaintenance(await generateSymmetricKey(), theirs);

    await expect(unwrapMaintenanceKey(ours, copy)).rejects.toMatchObject({
      code: VaultErrorCode.OTHER_MAINTENANCE_KEY,
      message: expect.stringContaining(maintenanceKeyIdToFingerprint(theirs.keyId)),
    });
  });

  it('refuses a copy whose header was rewritten to name another key, since the id is bound as associated data', async () => {
    const ours = await generateMaintenanceKeyPair();
    const copy = await wrapKeyForMaintenance(await generateSymmetricKey(), ours);
    const relabelled = copy.slice();
    const forged = { ...ours, keyId: Uint8Array.from(ours.keyId, (byte) => byte ^ 0xff) };

    relabelled.set(forged.keyId, 1);

    await expect(unwrapMaintenanceKey(forged, relabelled)).rejects.toBeInstanceOf(VaultError);
  });

  it('rejects a truncated copy or one of an unknown version before trying to open it', async () => {
    const pair = await generateMaintenanceKeyPair();
    const copy = await wrapKeyForMaintenance(await generateSymmetricKey(), pair);

    expect(() => readMaintenanceCopyKeyId(copy.slice(0, 17))).toThrow(expect.objectContaining({ code: VaultErrorCode.CIPHERTEXT_TOO_SHORT }));
    expect(() => readMaintenanceCopyKeyId(Uint8Array.from([2, ...copy.slice(1)]))).toThrow(
      expect.objectContaining({ code: VaultErrorCode.UNSUPPORTED_CRYPTO_VERSION })
    );
  });

  it('never accepts a maintenance copy as a user copy, or the other way round', async () => {
    const pair = await generateMaintenanceKeyPair();
    const key = await generateSymmetricKey();
    const { user } = await encryptSymmetricKeyForUsers(key, { user: pair.publicKey }, DOMAIN_KEM_DOCUMENT_KEY);
    const header = Uint8Array.from([1, ...pair.keyId]);

    await expect(unwrapMaintenanceKey(pair, Uint8Array.from([...header, ...user]))).rejects.toMatchObject({ code: VaultErrorCode.WRONG_SECRET_KEY });
    await expect(
      decryptSymmetricKeyForUser(pair.secretKey, (await wrapKeyForMaintenance(key, pair)).slice(header.length), DOMAIN_KEM_DOCUMENT_KEY)
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
        'ARR2Mqh8qYKsyA2Afjf1EOMBYAQIljVWJ3cxqYYbZSWUndmh6Yca09CN8rAJ1du0AAwuxW4mjzVJ62XuY9WjmBTyrFkAHavcmf8afgy1C/j7mKPwMlzA1zxURSbcydECwUeLM9P5MkzungSeicKI57T0gtp/cdayfORtpA2BLMcbQkXgmIkdEEmTU21t/0JGIXlLr4B1bAKh2J0eQWhCDokmMjIVFI9OTD8pLCBjqz5GJbqQejCTbcUGpDt7Nlt10Iy0g26fdoDbwQTVHrlf8c4E6IC3hoMtgiMwbHAEAwV0QKCNOHvuC07LifGIAeP6PNXBQ9XxxNES4My9GNvA0AuKW1cxIgidNmoCkQUSQ1uxAH07XUx9gSsXIq51xEOtrZgq45WRq7tvc07rZZz/rAVV2Z6T+Xh+EChK31YZ1sM/3cWZ3noJWQjRr7wAbW3bwlhcA/UCx7d9fdosWfAQrV1X0lR1b0C5lUUGnj19Lahkgw29xjJXR8gPWZdySsn6WS2pj0arscmjntKWlh7WkMs/IdMFZC49xPSOo1tXtjJBlJEIxaB40gAEZa8mZUrplWq034tYE5NlDwyzMzYw2lLYJGIc2f1BXtgyiLTNOpY6x5aQSJg88dg9IEyUWQuywx0mbBaAR9fxDbMBVCOcA56NCJPX16mMmby2YuOwdFDQox+VCrsqgtzEo+KLdVtQSDACYP1OOZu2LENpX1bQgHhNKXPKbUOai6IyGfw8ubQ6AsqcRn5Vib3DEJcHmguFcdzA3+6j+eJG/lsvQCtr7cK1lg5EEguhXRWHBijdgpv8a3Iw/B91mYlgTpsxLQOYTP0xfQ93v0UF4Ok90kKlYGzNDqwW5idl3dRe0mUpcz010qS/H+xDYow4f7g4HEzyss9w8ox2gcmd6mFBKODaUbjFpocDIu3Wvrw16JgJ8l+NKZ1O6JwgtNWGD0Rv3f2UB1BSzlMJiMczPOCiNrmz0i8CfkNgaS7VgeMqbIqQbtHB4iLeTMUgQ1lTderA16rhAncfV61ekBfzAtc0H8mIiEhiHj/9TwTMXabX/h692bGIdWB6u9O2ZYTy+QiMosRJqDfxWpIn7Yx/I3KdIHTGhTAm3zjkx93+BTot6fYuhSV+OkSEkdTfJgypb1Q6PBy4ZbAyMyO+xxyWSWWFHgIo4+RH+4DrpzbMx8P9yGrJm4ft0qb4s7I/8rNych0uLG0dDO+k1aCrCPec7vFBxrARJSeA3v5OCKDKka/1d7NaROObay6p441tfXpb09RTjafFzIGJGgKceUqDarKfvwlih8D7uHK3j3qzBsGiLhnQxMWrkgHYeny5SiPjlP88hcXyqGWbjgemnrGfGk0jwF+ntYjMvgBqUFianDJVDkjmgsj77xdC6EiL4el6p6T/e6J/gIsZkXZLQWFGsGiz0hTYwbx6Q1EuC43QkORRGQdGHvrisyqqx+C2jJaKDnBoGGv2sainWWyhJEJhMaZVxoB15POqq42bMS9BLGF1narLeWvnLakiAQqjJ+CP7ISTZRn/7hN4RYri1uOgYkLjjeYIBYAyAr1PgeGi85gWCuyqMschpkCztfIBpKZKsuPjZi3XucPfOzvbF3f2HbEarg==',
        'base64'
      )
    );

    expect(
      await unwrapMaintenanceKey({ secretKey: maintenance.privateKey, keyId: await computeMaintenanceKeyId(maintenance.publicKey) }, copy)
    ).toEqual(seq(32, 100));
  });

  it('derives the same key pair from a phrase in either wordlist, and the public key from the seed alone', async () => {
    const seed = seq(32, 7);
    const pair = await maintenanceKeyPairFromSeed(seed);

    expect(pair.secretKey).toEqual(seed);
    expect(await maintenanceKeyPairFromPhrase(await generateMaintenancePhrase('french', seed))).toEqual(pair);
    expect(await maintenanceKeyPairFromPhrase(await generateMaintenancePhrase('english', seed))).toEqual(pair);
    await expect(maintenanceKeyPairFromSeed(seq(31))).rejects.toMatchObject({ code: VaultErrorCode.INVALID_MAINTENANCE_KEY });
  });

  it('refuses a phrase with a typo instead of deriving another key', async () => {
    const words = (await generateMaintenancePhrase('french', seq(32))).split(' ');
    words[3] = words[3] === 'abaisser' ? 'abandon' : 'abaisser';

    await expect(maintenanceKeyPairFromPhrase(words.join(' '))).rejects.toMatchObject({ code: VaultErrorCode.INVALID_MNEMONIC });
  });

  it('keeps the committed development phrase and the public key .env.test configures together', async () => {
    const pair = await maintenanceKeyPairFromPhrase(DEV_MAINTENANCE_PHRASE);

    expect(exportMaintenancePublicKey(pair.publicKey)).toBe(DEV_MAINTENANCE_PUBLIC_KEY);
  });

  it('fingerprints the configured value as 40 digits, distinct from an identity fingerprint of the same bytes', async () => {
    const fingerprint = await computeMaintenanceKeyFingerprint(DEV_MAINTENANCE_PUBLIC_KEY);

    expect(fingerprint).toMatch(/^1\d{39}$/);
    expect(maintenanceKeyIdToFingerprint((await importMaintenancePublicKey(DEV_MAINTENANCE_PUBLIC_KEY)).keyId)).toBe(fingerprint);
    expect(fingerprint).not.toBe(await computeKeyFingerprint(DEV_MAINTENANCE_PUBLIC_KEY));
  });
});
