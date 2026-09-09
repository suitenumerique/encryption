import fc from 'fast-check';
import sodium from 'libsodium-wrappers-sumo';
import { beforeAll, describe, expect, it } from 'vitest';

import { uint8ToBase64 } from '@encryption/src/crypto/encryption-backup';
import { generateSignatureKeyPair } from '@encryption/src/crypto/signature';
import { itemTypeSchema } from '@encryption/src/crypto/vault-items';
import {
  type SealedItem,
  type VaultManifest,
  buildManifest,
  isRollback,
  manifestBytes,
  parseManifest,
  sealedItemsMatchManifest,
  signManifest,
  verifyManifest,
} from '@encryption/src/crypto/vault-manifest';

const seal = (id: string, type: SealedItem['type'], revisionDate: number, body: string): SealedItem => ({
  id,
  type,
  revisionDate,
  ciphertext: uint8ToBase64(sodium.from_string(body)),
});

function sampleItems(): SealedItem[] {
  return [seal('enc:1', 'encryptionKey', 10, 'ct-1'), seal('tofu:bob', 'tofu', 30, 'ct-bob'), seal('active', 'active', 10, 'ct-active')];
}

beforeAll(async () => {
  await sodium.ready;
});

describe('signed manifest', () => {
  it('verifies against the signing identity and covers every item', async () => {
    const identity = await generateSignatureKeyPair();
    const items = sampleItems();
    const manifest = buildManifest(5, 1, items);
    const sig = await signManifest(manifest, identity.secretKey);

    expect(await verifyManifest(manifest, sig, identity.publicKey)).toBe(true);
    expect(sealedItemsMatchManifest(items, manifest)).toBe(true);
  });

  it('rejects a manifest signed by another identity', async () => {
    const identity = await generateSignatureKeyPair();
    const attacker = await generateSignatureKeyPair();
    const manifest = buildManifest(5, 1, sampleItems());
    const sig = await signManifest(manifest, attacker.secretKey);

    expect(await verifyManifest(manifest, sig, identity.publicKey)).toBe(false);
  });

  it('detects a tampered ciphertext, a spliced item, and a dropped item', async () => {
    const manifest = buildManifest(5, 1, sampleItems());

    const tampered = sampleItems();
    tampered[0] = seal('enc:1', 'encryptionKey', 10, 'ct-1-EVIL');
    expect(sealedItemsMatchManifest(tampered, manifest)).toBe(false);

    const spliced = [...sampleItems(), seal('enc:2', 'encryptionKey', 20, 'ct-2')];
    expect(sealedItemsMatchManifest(spliced, manifest)).toBe(false);

    const dropped = sampleItems().slice(1);
    expect(sealedItemsMatchManifest(dropped, manifest)).toBe(false);
  });

  it('detects a modified manifest via the signature', async () => {
    const identity = await generateSignatureKeyPair();
    const manifest = buildManifest(5, 1, sampleItems());
    const sig = await signManifest(manifest, identity.secretKey);

    const rolledBack = { ...manifest, revision: 4 };
    expect(await verifyManifest(rolledBack, sig, identity.publicKey)).toBe(false);
  });

  it('flags a revision below the last seen', () => {
    expect(isRollback(4, 5)).toBe(true);
    expect(isRollback(5, 5)).toBe(false);
    expect(isRollback(6, 5)).toBe(false);
  });

  it('parseManifest returns null on non-JSON and wrong shape, and the object on a valid manifest', () => {
    expect(parseManifest('not json')).toBeNull();
    expect(parseManifest(JSON.stringify({ revision: 1 }))).toBeNull(); // missing schema/identityGen/items
    expect(parseManifest(JSON.stringify({ schema: 1, revision: 1, identityGen: 1, items: [{ id: 'a' }] }))).toBeNull(); // malformed item

    const good = buildManifest(3, 1, sampleItems());
    expect(parseManifest(JSON.stringify(good))).toEqual(good);
  });
});

describe('manifest encoding (property)', () => {
  const manifest: fc.Arbitrary<VaultManifest> = fc.record({
    schema: fc.nat(),
    revision: fc.nat(),
    identityGen: fc.nat(),
    items: fc.array(
      fc.record({
        id: fc.string({ unit: 'grapheme', maxLength: 12 }),
        type: fc.constantFrom(...itemTypeSchema.options),
        contentHash: fc.string({ unit: 'grapheme', maxLength: 12 }),
        revisionDate: fc.nat(),
      }),
      { maxLength: 4 }
    ),
  });

  // The identity signature covers these bytes: two different manifests must
  // never share them, or a signature over one would validate the other.
  it('manifestBytes is injective', () => {
    fc.assert(
      fc.property(manifest, manifest, (a, b) => {
        expect(sodium.to_string(manifestBytes(a)) === sodium.to_string(manifestBytes(b))).toBe(JSON.stringify(a) === JSON.stringify(b));
      })
    );
  });

  it('parseManifest round-trips any manifest and never throws on arbitrary text', () => {
    fc.assert(
      fc.property(manifest, (m) => {
        expect(parseManifest(JSON.stringify(m))).toEqual(m);
      })
    );
    fc.assert(
      fc.property(fc.oneof(fc.string({ unit: 'grapheme' }), fc.json()), (text) => {
        expect(() => parseManifest(text)).not.toThrow();
      })
    );
  });
});
