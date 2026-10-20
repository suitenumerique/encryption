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
import {
  DEV_MAINTENANCE_PHRASE,
  DEV_MAINTENANCE_PUBLIC_KEY,
  DEV_NEXT_MAINTENANCE_PHRASE,
  DEV_NEXT_MAINTENANCE_PUBLIC_KEY,
} from '@encryption/src/maintenance/dev-maintenance-key';
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

  it("does not open another key's copy relabelled with this key's id: the id routes, the key decides", async () => {
    const ours = await generateMaintenanceKeyPair();
    const theirs = await generateMaintenanceKeyPair();
    const relabelled = await wrapKeyForMaintenance(await generateSymmetricKey(), theirs);

    relabelled.set(ours.keyId, 1);

    await expect(unwrapMaintenanceKey(ours, relabelled)).rejects.toMatchObject({ code: VaultErrorCode.WRONG_SECRET_KEY });
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
        'ARR2Mqh8qYKsyA2Afjf1EOMBYAQEVRIkkcj6IlVRkeXfSmAUEDS354CR6RtgfS0ZoMJW/oADDVM6z+qyCsCVIM/sHVsN9Un0mBtOZeZMh+iK4wRljB2Dvqq2yEOVg+E2sHufutDwKh/hV9QP8HUIp7leupes4WSmNqhOnMWKZx6YjPUlWv6XULpBGeuokMZY0FEhnisteJsW9Xhr/Yc6I5fAixVEEsbv8jXQRhPRtrzg1vOsTD63Jcl3oQX+prGTfr0n+hB2axqGuT7xzhjenrvoLEcgB1D72fp9lI5jhpOJ4QaKlRHRoQe+UQyWIf3PbrT6lw/qgXsp3tvBw7eG6gbpgRF8tkH+P+msVmnVuyLove+sehQEZea3o3b6XgRwqIT0eTka9GwO/yWbhM05PCFe3Y0cu+TluzLueypKNlqULgjGkHtWFxjjJfmf3MpIzkkTul5jYvBAUoX4xvATl9Bp8YGMg8uJtV4x8+F19xTkUXVV36jxTui+0AYS+V4b1QllxGQbRLaolO/8YN+f9p2UqYN/strsIf67ogHtU7x5WS4NJfJpIeMgaIlUQ9A5A22bkoUXL9RU0H8mBFoP3xViCFLAAiA8TchM905cGZhMePLVES2KnibcqUJjMGguxnx397yjCi29B3l7Az8Bh5EM6nOnjZ1jUd8UTow6EUrFCaV+lWlaKeDnuf2t2r1jtRaoZjSQAZjjzq1p9UNeTvCCAg4PlECMpboF9k7nmqYWAEskgSv8Y1P751EIu44wRisXO6DOPJ58dWzf2pnId8Tho+0ccp89ZQ7kBudpkvcIMpJ3cBWgAeDiXb6tcKW3Rxvxs33GaflAOrPiyb8Yuewj2JmkITGS3nsKyjBTpu1zrJ03Pig8pZZtw5uRZXy1cqaJG0A2abXBpy3pp4q3Mt74hYph/Tk0xHhuowZKCrEYUlWpE72cqmgizPsL3iPgaPV5NCNKR+6+CaN35UP4m1JUYSevCIu9t63W7qlMCOCvjAqyh0m9H8QnRObk1BOl/7gwkHhCnKN1tqzM/JXkespwIonCfhHFVGwTl3sK39Fu5Y+YEJP0rzYcEIph6Ga0PSPAMC2iFui4/WuLaAGXj+cAMlF0nYHsAeedHPZOQkqe4noMTqIcDSVJ52Q+nBSLXX527t2qkyjQzsDph+5HeV8liLlv9bM2s2K8YyKWKv24GJGH/AuBm3OzlbY9KzuBCgjRtkDnCRXur2qe56+FMcTBSftMX5VPYOdJMQtlozLk1/AjxnOc2TCCiAzmqFioRDSvktRn3M0d0WOdu1O/3qJxsMzCSW+wLPXYSO9ILm2T0FWa8d5qunBz444lslK3bUi5ntgwuLqrrXTdMizUyIIE3rtBdfSD6EeoSJDyqpTmGlF4iMo8D2YHGdWat/CtIqKcMJhzhgs2pcr8MYwZiTI+kUGI0cPDCOWc8JMrt6gDK12EzkqTOe8YxEiZ8JBhQu1BSBQq8T+3nbKrkqAgtMmXR+atlgDy67Oc/3EWRcNUBzhDASAagHvfLfCg04B+OnJEnUSVtPlg8He9bl2tphxC+1CrXV8AK5TY2v/DBmrfeoT9NOVavSmsWfSUpB76SDEujt27UA+GPIQz1A==',
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

  it('keeps the second development phrase and its public key together, a key distinct from the first', async () => {
    const pair = await maintenanceKeyPairFromPhrase(DEV_NEXT_MAINTENANCE_PHRASE);

    expect(exportMaintenancePublicKey(pair.publicKey)).toBe(DEV_NEXT_MAINTENANCE_PUBLIC_KEY);
    expect(DEV_NEXT_MAINTENANCE_PUBLIC_KEY).not.toBe(DEV_MAINTENANCE_PUBLIC_KEY);
  });

  it('fingerprints the configured value as 40 digits, distinct from an identity fingerprint of the same bytes', async () => {
    const fingerprint = await computeMaintenanceKeyFingerprint(DEV_MAINTENANCE_PUBLIC_KEY);

    expect(fingerprint).toMatch(/^1\d{39}$/);
    expect(maintenanceKeyIdToFingerprint((await importMaintenancePublicKey(DEV_MAINTENANCE_PUBLIC_KEY)).keyId)).toBe(fingerprint);
    expect(fingerprint).not.toBe(await computeKeyFingerprint(DEV_MAINTENANCE_PUBLIC_KEY));
  });
});
