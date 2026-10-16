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

  it('refuses, without throwing, a manifest with a field too long to frame', async () => {
    const identity = await generateSignatureKeyPair();
    const manifest = buildManifest(5, 1, [seal('x'.repeat(70_000), 'tofu', 1, 'ct')]);

    expect(await verifyManifest(manifest, uint8ToBase64(new Uint8Array(64)), identity.publicKey)).toBe(false);
  });

  it('refuses, without throwing, a signature that is not base64', async () => {
    const identity = await generateSignatureKeyPair();

    expect(await verifyManifest(buildManifest(5, 1, sampleItems()), 'not base64!', identity.publicKey)).toBe(false);
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

  it('names its algorithms, and refuses a hash or a signature algorithm it does not know', () => {
    const good = buildManifest(3, 1, sampleItems());

    expect(good.signatureAlgorithm).toBe('ed25519');
    expect(good.items.every((item) => item.contentHash.startsWith('blake2b-256:'))).toBe(true);

    const unnamedHash = { ...good, items: good.items.map((item) => ({ ...item, contentHash: item.contentHash.slice('blake2b-256:'.length) })) };
    expect(parseManifest(JSON.stringify(unnamedHash))).toBeNull();
    expect(parseManifest(JSON.stringify({ ...good, signatureAlgorithm: 'none' }))).toBeNull();
  });

  it('refuses a content hash that is not 32 bytes of base64 after its prefix', () => {
    const good = buildManifest(3, 1, sampleItems());
    const withHash = (contentHash: string) => ({ ...good, items: good.items.map((item) => ({ ...item, contentHash })) });

    expect(parseManifest(JSON.stringify(withHash('blake2b-256:')))).toBeNull();
    expect(parseManifest(JSON.stringify(withHash('blake2b-256:not-base64')))).toBeNull();
    expect(parseManifest(JSON.stringify(withHash(`blake2b-256:${uint8ToBase64(new Uint8Array(16))}`)))).toBeNull();
  });

  // Known answer, computed independently of this code: identity keys sign
  // manifests over exactly these bytes, so any change here breaks every stored
  // manifest signature.
  it('signs the known framed bytes, starting with its own domain label', () => {
    const manifest = buildManifest(7, 2, [seal('enc:1', 'encryptionKey', 10, 'ct')]);
    const expected = [
      '2400',
      sodium.to_hex(sodium.from_string('lasuite-encryption/vault-manifest/v1')),
      '01000000', // schema
      '0700',
      sodium.to_hex(sodium.from_string('ed25519')),
      '07000000', // revision
      '02000000', // identity generation
      '01000000', // item count
      '0500',
      sodium.to_hex(sodium.from_string('enc:1')),
      '0d00',
      sodium.to_hex(sodium.from_string('encryptionKey')),
      '3800',
      sodium.to_hex(sodium.from_string('blake2b-256:96P1rMgGoNSPvExwXY3WM8MyeIRKwGVJA4HG/TIuwqw=')),
      '0a00000000000000', // revision date
    ].join('');

    expect(sodium.to_hex(manifestBytes(manifest))).toBe(expected);
    expect(expected).toBe(
      '24006c6173756974652d656e6372797074696f6e2f7661756c742d6d616e69666573742f7631010000000700656432353531390700000002000000010000000500656e633a310d00656e6372797074696f6e4b65793800626c616b6532622d3235363a39365031724d67476f4e535076457877585933574d384d796549524b7747564a413448472f5449757771773d0a00000000000000'
    );
  });
});

describe('manifest encoding (property)', () => {
  const manifest: fc.Arbitrary<VaultManifest> = fc.record({
    schema: fc.nat(),
    signatureAlgorithm: fc.constant('ed25519' as const),
    revision: fc.nat(),
    identityGen: fc.nat(),
    items: fc.array(
      fc.record({
        id: fc.string({ unit: 'grapheme', maxLength: 12 }),
        type: fc.constantFrom(...itemTypeSchema.options),
        contentHash: fc.uint8Array({ minLength: 32, maxLength: 32 }).map((hash) => `blake2b-256:${uint8ToBase64(hash)}`),
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
        expect(sodium.to_hex(manifestBytes(a)) === sodium.to_hex(manifestBytes(b))).toBe(JSON.stringify(a) === JSON.stringify(b));
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
