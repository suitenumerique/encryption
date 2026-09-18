/**
 * End-to-end proof of the maintenance escrow, on the real moving parts:
 *
 *   - a PRODUCT TABLE in a real PostgreSQL (PGlite): documents and their access
 *     rows stored as `bytea`, exported and written back with the SQL an operator
 *     would type, so the base64 and NULL handling is the real one;
 *   - the real PUBLIC DIRECTORY route over the same engine, reached through the
 *     generated SDK, with users whose registrations are genuinely signed;
 *   - the real VAULT OPERATIONS playing the users' devices (only IndexedDB is
 *     stubbed: each call is routed to the key pair of the device being simulated).
 *
 * The operator only ever holds what `npm run maintenance` holds: the key file and
 * the exported rows.
 */
import Fastify from 'fastify';
import { randomUUID } from 'node:crypto';
import { type Mock, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  type HybridKeyPair,
  base64ToUint8,
  encodeKeyRegistrationPayload,
  exportPublicKeyAsBase64,
  generateMaintenanceKeyPair,
  generateSignatureKeyPair,
  generateUserKeyPair,
  signDetached,
  uint8ToBase64,
} from '@encryption/src/crypto';
import {
  type RewrapResult,
  checkRows,
  decryptRow,
  fetchVerifiedPublicKeys,
  parseRows,
  resolveRowRecipients,
  rewrapRow,
} from '@encryption/src/maintenance/escrow';
import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import { publicKeysRoute } from '@encryption/src/server/routes/public-keys';
import { createTestApiClient } from '@encryption/src/server/testing/inject-client';
import { VaultErrorCode } from '@encryption/src/shared/vault-error';
import { handleDecryptWithKey } from '@encryption/src/vault/operations/decrypt';
import { handleEncryptWithoutKey } from '@encryption/src/vault/operations/encrypt';
import { getStoredKeyPair } from '@encryption/src/vault/operations/key-management';
import { handleShareKeys } from '@encryption/src/vault/operations/share-keys';

const ISSUER = 'https://issuer.example';

vi.mock('@encryption/src/server/env', () => ({ env: { OIDC_ISSUER: 'https://issuer.example' } }));
vi.mock('@encryption/src/prisma/client', async () => ({
  prisma: (await vi.importActual<typeof import('@encryption/src/prisma/testing')>('@encryption/src/prisma/testing')).testPrisma,
}));
vi.mock('@encryption/src/vault/operations/key-management', () => ({ getStoredKeyPair: vi.fn() }));

useTestDatabase();

// ----- The product side: a Docs-like schema, binary columns -----------------------

beforeAll(async () => {
  await testPrisma.$executeRawUnsafe('CREATE SCHEMA product');
  await testPrisma.$executeRawUnsafe(
    'CREATE TABLE product.documents (id uuid PRIMARY KEY, title text NOT NULL, encrypted_content bytea NOT NULL, maintenance_key bytea)'
  );
  await testPrisma.$executeRawUnsafe(
    `CREATE TABLE product.document_accesses (
       document_id uuid NOT NULL REFERENCES product.documents (id) ON DELETE CASCADE,
       sub text NOT NULL,
       encrypted_key bytea NOT NULL,
       PRIMARY KEY (document_id, sub)
     )`
  );
});

beforeEach(async () => {
  (getStoredKeyPair as Mock).mockReset();
  await testPrisma.$executeRawUnsafe('TRUNCATE product.documents CASCADE');
});

// What an operator runs with `psql -At`: one JSON object per line. `encode(..., 'base64')`
// wraps its output every 76 characters, hence the `translate`.
const EXPORT_SQL = `
  SELECT json_build_object(
    'id', d.id,
    'maintenanceKey', translate(encode(d.maintenance_key, 'base64'), E'\\n', ''),
    'encryptedContent', translate(encode(d.encrypted_content, 'base64'), E'\\n', ''),
    'recipients', COALESCE((SELECT json_agg(a.sub ORDER BY a.sub) FROM product.document_accesses a WHERE a.document_id = d.id), '[]'::json)
  )::text AS line
  FROM product.documents d
  WHERE d.maintenance_key IS NOT NULL
  ORDER BY d.title`;

async function exportRows(sql = EXPORT_SQL): Promise<string> {
  const lines = await testPrisma.$queryRawUnsafe<{ line: string }[]>(sql);

  return lines.map(({ line }) => line).join('\n');
}

// The product's write-back of one `rewrap` result, atomically.
async function writeBack(result: RewrapResult): Promise<void> {
  await testPrisma.$transaction(async (tx) => {
    await tx.$executeRaw`UPDATE product.documents SET maintenance_key = decode(${result.maintenanceKey}, 'base64') WHERE id = ${result.id}::uuid`;

    if (result.encryptedContent) {
      await tx.$executeRaw`UPDATE product.documents SET encrypted_content = decode(${result.encryptedContent}, 'base64') WHERE id = ${result.id}::uuid`;
    }

    for (const [sub, key] of Object.entries(result.encryptedKeys)) {
      await tx.$executeRaw`
        INSERT INTO product.document_accesses (document_id, sub, encrypted_key) VALUES (${result.id}::uuid, ${sub}, decode(${key}, 'base64'))
        ON CONFLICT (document_id, sub) DO UPDATE SET encrypted_key = EXCLUDED.encrypted_key`;
    }
  });
}

// ----- The encryption service side: a registered user, signed for real ----------

interface Person {
  sub: string;
  pair: HybridKeyPair;
}

async function register(name: string): Promise<Person> {
  const pair = await generateUserKeyPair();
  const signature = await generateSignatureKeyPair();
  const userId = randomUUID();
  const createdAt = new Date(1_700_000_000_000);
  const encryptionPublicKeyWire = base64ToUint8(exportPublicKeyAsBase64(pair.publicKey));
  const signaturePublicKeyWire = base64ToUint8(exportPublicKeyAsBase64(signature.publicKey));
  const binding = await signDetached(
    encodeKeyRegistrationPayload({ userId, version: 1, createdAtMillis: createdAt.getTime(), encryptionPublicKeyWire, signaturePublicKeyWire }),
    signature.secretKey
  );

  await testPrisma.user.create({ data: { id: userId, email: `${name}@example.org` } });
  await testPrisma.oidcAccount.create({ data: { userId, issuer: ISSUER, subject: `sub-${name}` } });
  const identity = await testPrisma.identity.create({ data: { userId, signaturePublicKey: Buffer.from(signaturePublicKeyWire), generation: 1 } });
  await testPrisma.encryptionKey.create({
    data: {
      userId,
      identityId: identity.id,
      encryptionPublicKey: Buffer.from(encryptionPublicKeyWire),
      keyBindingSignature: Buffer.from(binding),
      version: 1,
      createdAt,
    },
  });

  return { sub: `sub-${name}`, pair };
}

function directory() {
  const app = Fastify();

  // The directory read is public; the decorator only has to exist for the route module to register.
  app.decorate('verifyJWT', async () => {});
  app.register(publicKeysRoute);

  return createTestApiClient(app);
}

// ----- The devices: real vault operations, routed to one person's key pair ------

const toBuffer = (bytes: Uint8Array): ArrayBuffer => bytes.slice().buffer as ArrayBuffer;
const text = (s: string): ArrayBuffer => new TextEncoder().encode(s).buffer as ArrayBuffer;

function actAs(person: Person): void {
  (getStoredKeyPair as Mock).mockResolvedValue({ ...person.pair, version: 1 });
}

// Recipient keys reach the wrap operations the way the vault gets them: from the directory, in wire format.
async function recipientKeys(people: Person[]): Promise<Record<string, ArrayBuffer>> {
  const keys = await fetchVerifiedPublicKeys(
    directory(),
    people.map((person) => person.sub)
  );

  return Object.fromEntries(Object.entries(keys).map(([sub, key]) => [sub, toBuffer(base64ToUint8(key))]));
}

async function createDocument(author: Person, title: string, content: string, maintenance: HybridKeyPair | null): Promise<string> {
  actAs(author);

  const created = await handleEncryptWithoutKey(author.sub, {
    data: text(content),
    userPublicKeys: await recipientKeys([author]),
    maintenancePublicKey: maintenance?.publicKey ?? null,
  });
  const id = randomUUID();

  // The product's rule: persist `maintenanceKey` whenever the SDK returned one.
  await testPrisma.$executeRaw`
    INSERT INTO product.documents (id, title, encrypted_content, maintenance_key)
    VALUES (${id}::uuid, ${title}, ${Buffer.from(created.encryptedContent)}, ${created.maintenanceKey ? Buffer.from(created.maintenanceKey) : null})`;
  await testPrisma.$executeRaw`
    INSERT INTO product.document_accesses (document_id, sub, encrypted_key) VALUES (${id}::uuid, ${author.sub}, ${Buffer.from(created.encryptedKeys[author.sub])})`;

  return id;
}

async function shareDocument(id: string, from: Person, to: Person[], maintenance: HybridKeyPair | null): Promise<void> {
  actAs(from);

  const [{ encrypted_key: mine }] = await testPrisma.$queryRaw<{ encrypted_key: Uint8Array }[]>`
    SELECT encrypted_key FROM product.document_accesses WHERE document_id = ${id}::uuid AND sub = ${from.sub}`;
  const shared = await handleShareKeys(from.sub, {
    encryptedSymmetricKey: toBuffer(mine),
    userPublicKeys: await recipientKeys(to),
    maintenancePublicKey: maintenance?.publicKey ?? null,
  });

  for (const [sub, key] of Object.entries(shared.encryptedKeys)) {
    await testPrisma.$executeRaw`INSERT INTO product.document_accesses (document_id, sub, encrypted_key) VALUES (${id}::uuid, ${sub}, ${Buffer.from(key)})`;
  }
  if (shared.maintenanceKey) {
    await testPrisma.$executeRaw`UPDATE product.documents SET maintenance_key = ${Buffer.from(shared.maintenanceKey)} WHERE id = ${id}::uuid`;
  }
}

async function openDocument(id: string, reader: Person): Promise<string> {
  actAs(reader);

  const [row] = await testPrisma.$queryRaw<{ encrypted_content: Uint8Array; encrypted_key: Uint8Array }[]>`
    SELECT d.encrypted_content, a.encrypted_key
    FROM product.documents d JOIN product.document_accesses a ON a.document_id = d.id
    WHERE d.id = ${id}::uuid AND a.sub = ${reader.sub}`;
  const { data } = await handleDecryptWithKey(reader.sub, {
    encryptedData: toBuffer(row.encrypted_content),
    encryptedSymmetricKey: toBuffer(row.encrypted_key),
    keyVersion: 1,
  });

  return new TextDecoder().decode(data);
}

describe('maintenance escrow, end to end', () => {
  let alice: Person;
  let bob: Person;
  let maintenance: HybridKeyPair;

  beforeEach(async () => {
    [alice, bob, maintenance] = await Promise.all([register('alice'), register('bob'), generateMaintenanceKeyPair()]);
  });

  it('stores the escrow copy in its own column, and the operator audits and reads the export', async () => {
    const id = await createDocument(alice, 'notes', 'hello from alice', maintenance);
    await shareDocument(id, alice, [bob], maintenance);

    // Never a recipient: the access table only knows the two people.
    const accesses = await testPrisma.$queryRaw<{ sub: string }[]>`SELECT sub FROM product.document_accesses ORDER BY sub`;
    expect(accesses.map((access) => access.sub)).toEqual([alice.sub, bob.sub]);
    expect(await openDocument(id, bob)).toBe('hello from alice');

    const rows = parseRows(await exportRows());
    expect(rows).toEqual([{ id, maintenanceKey: expect.any(String), encryptedContent: expect.any(String), recipients: [alice.sub, bob.sub] }]);

    expect(await checkRows(maintenance.secretKey, rows)).toEqual([{ id, ok: true }]);
    expect(await decryptRow(maintenance.secretKey, rows[0], 'utf8')).toEqual({ id, plaintext: 'hello from alice' });

    // Another key file opens nothing, and says so per row instead of throwing.
    const stranger = await generateMaintenanceKeyPair();
    expect(await checkRows(stranger.secretKey, rows)).toEqual([{ id, ok: false, error: expect.stringMatching(/wrong secret key/i) }]);
  });

  it('leaves the column NULL without a configured key, and an empty share backfills it later', async () => {
    const id = await createDocument(alice, 'legacy', 'created before the escrow existed', null);

    expect(parseRows(await exportRows())).toEqual([]);

    // The deployment enables the escrow; the product backfills from any holder, adding nobody.
    await shareDocument(id, alice, [], maintenance);

    const rows = parseRows(await exportRows());
    expect(rows[0].recipients).toEqual([alice.sub]);
    expect(await decryptRow(maintenance.secretKey, rows[0], 'utf8')).toMatchObject({ plaintext: 'created before the escrow existed' });
  });

  it("repairs a holder's corrupted copy from the escrow alone, resolving recipients through the directory", async () => {
    const id = await createDocument(alice, 'shared', 'still readable after the repair', maintenance);
    await shareDocument(id, alice, [bob], maintenance);

    // The "huge problem": every wrapped copy of this document is damaged in the product table.
    await testPrisma.$executeRaw`UPDATE product.document_accesses SET encrypted_key = set_byte(encrypted_key, 40, get_byte(encrypted_key, 40) # 255)`;
    await expect(openDocument(id, alice)).rejects.toMatchObject({ code: VaultErrorCode.WRONG_SECRET_KEY });
    await expect(openDocument(id, bob)).rejects.toMatchObject({ code: VaultErrorCode.WRONG_SECRET_KEY });

    const registry = directory();

    for (const [index, row] of parseRows(await exportRows()).entries()) {
      const recipients = await resolveRowRecipients(row, registry);

      await writeBack(
        await rewrapRow(maintenance.secretKey, row, { maintenancePublicKey: maintenance.publicKey, recipients, rotateKey: false }, index)
      );
    }

    // Same ciphertext, fresh copies: both devices read again, and the escrow still opens.
    expect(await openDocument(id, alice)).toBe('still readable after the repair');
    expect(await openDocument(id, bob)).toBe('still readable after the repair');
    expect(await checkRows(maintenance.secretKey, parseRows(await exportRows()))).toEqual([{ id, ok: true }]);
  });

  it('rotates the resource key and the maintenance key in one pass, replacing the whole row', async () => {
    const id = await createDocument(alice, 'rotate', 'rotate me', maintenance);
    await shareDocument(id, alice, [bob], maintenance);

    const [before] = await testPrisma.$queryRaw<{ encrypted_content: Uint8Array }[]>`SELECT encrypted_content FROM product.documents`;
    const [staleCopy] = await testPrisma.$queryRaw<{ encrypted_key: Uint8Array }[]>`
      SELECT encrypted_key FROM product.document_accesses WHERE sub = ${alice.sub}`;
    const next = await generateMaintenanceKeyPair();
    const registry = directory();

    for (const row of parseRows(await exportRows())) {
      const recipients = await resolveRowRecipients(row, registry);

      await writeBack(await rewrapRow(maintenance.secretKey, row, { maintenancePublicKey: next.publicKey, recipients, rotateKey: true }));
    }

    const [after] = await testPrisma.$queryRaw<{ encrypted_content: Uint8Array }[]>`SELECT encrypted_content FROM product.documents`;
    expect(Buffer.from(after.encrypted_content).equals(Buffer.from(before.encrypted_content))).toBe(false);

    expect(await openDocument(id, alice)).toBe('rotate me');
    expect(await openDocument(id, bob)).toBe('rotate me');

    // A copy kept from before the rotation no longer opens the new ciphertext.
    actAs(alice);
    await expect(
      handleDecryptWithKey(alice.sub, {
        encryptedData: toBuffer(after.encrypted_content),
        encryptedSymmetricKey: toBuffer(staleCopy.encrypted_key),
        keyVersion: 1,
      })
    ).rejects.toMatchObject({ code: VaultErrorCode.WRONG_SECRET_KEY });

    // The escrow now belongs to the successor key only.
    const rows = parseRows(await exportRows());
    expect((await checkRows(maintenance.secretKey, rows))[0].ok).toBe(false);
    expect(await decryptRow(next.secretKey, rows[0], 'utf8')).toMatchObject({ plaintext: 'rotate me' });
  });

  it('refuses to wrap for a directory record tampered with in the database, or for a sub with no registration', async () => {
    const id = await createDocument(alice, 'guarded', 'not for a forged key', maintenance);
    await shareDocument(id, alice, [bob], maintenance);

    const [row] = parseRows(await exportRows());

    await expect(resolveRowRecipients({ ...row, recipients: [alice.sub, 'sub-ghost'] }, directory())).rejects.toThrow(/sub-ghost/);

    // A database attacker swaps bob's encryption key for their own: the binding no longer verifies.
    const attacker = await generateUserKeyPair();
    await testPrisma.encryptionKey.updateMany({
      where: { user: { oidcAccounts: { some: { subject: bob.sub } } } },
      data: { encryptionPublicKey: Buffer.from(base64ToUint8(exportPublicKeyAsBase64(attacker.publicKey))) },
    });

    await expect(resolveRowRecipients(row, directory())).rejects.toThrow(/binding signature/);
    await expect(resolveRowRecipients(row, undefined)).rejects.toThrow(/--registry/);
  });

  it('refuses to rotate or decrypt a row exported without its ciphertext', async () => {
    await createDocument(alice, 'keys-only', 'x', maintenance);

    const [{ maintenanceKey }] = parseRows(await exportRows());
    const row = { maintenanceKey };

    await expect(decryptRow(maintenance.secretKey, row, 'utf8')).rejects.toThrow(/encryptedContent is required/);
    await expect(
      rewrapRow(maintenance.secretKey, row, { maintenancePublicKey: maintenance.publicKey, recipients: {}, rotateKey: true })
    ).rejects.toThrow(/encryptedContent is required/);
  });

  describe('row parsing', () => {
    it('reads NDJSON and a JSON array alike, and names the offending row', () => {
      const one = { id: 'a', maintenanceKey: 'AAAA' };
      const two = { id: 'b', maintenanceKey: 'BBBB', recipients: ['sub-1'] };
      const three = { id: 'c', maintenanceKey: 'CCCC', recipients: { 'sub-1': uint8ToBase64(new Uint8Array(4)) } };

      expect(parseRows(`${JSON.stringify(one)}\n${JSON.stringify(two)}\n`)).toEqual([one, two]);
      expect(parseRows(JSON.stringify([one, two, three]))).toEqual([one, two, three]);
      expect(parseRows('  \n')).toEqual([]);
      expect(() => parseRows(JSON.stringify([one, { id: 'd' }]))).toThrow(/row 2/);
    });

    it("rejects PostgreSQL's line-wrapped base64 instead of decoding garbage", async () => {
      await createDocument(alice, 'wrapped', 'x', maintenance);

      // The export an operator writes first: `encode` alone breaks lines every 76 characters.
      const naive = EXPORT_SQL.replaceAll(/translate\((encode\([^)]*\)), E'\\n', ''\)/g, '$1');

      const wrapped = await exportRows(naive);

      expect(wrapped).toContain('\\n');
      expect(() => parseRows(wrapped)).toThrow(/base64/);
    });
  });
});
