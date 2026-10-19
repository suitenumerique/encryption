/**
 * End-to-end proof of the batch recovery, on the real moving parts:
 *
 *   - a Docs-like PRODUCT in a real PostgreSQL (PGlite): documents, their access
 *     rows, comments, and attachments whose bytes sit in an object storage, all
 *     encrypted, exported and written back with the SQL a product team would type,
 *     so the base64, NULL and binary handling is the real one;
 *   - the real VAULT OPERATIONS playing the users' devices (only IndexedDB is
 *     stubbed: each call is routed to the key pair of the device being simulated);
 *   - the maintenance tool's own code, holding nothing but the custodians' phrase
 *     and the export folder.
 */
import { randomUUID } from 'node:crypto';
import { type Mock, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  type HybridKeyPair,
  type MaintenanceKeyPair,
  exportPublicKeyAsBase64,
  generateMaintenancePhrase,
  generateUserKeyPair,
  maintenanceKeyPairFromPhrase,
} from '@encryption/src/crypto';
import { base64ToUint8 } from '@encryption/src/crypto/encryption-backup';
import { maintenanceKeyIdToFingerprint } from '@encryption/src/crypto/maintenance-escrow';
import { MANIFEST_FILE, OTHER_KEYS_FOLDER, parseManifest } from '@encryption/src/maintenance/export-format';
import { writeDecryptedExport } from '@encryption/src/maintenance/export-writer';
import { recoverItems } from '@encryption/src/maintenance/recover';
import { mapSink } from '@encryption/src/maintenance/testing';
import { testPrisma, useTestDatabase } from '@encryption/src/prisma/testing';
import { handleDecryptWithKey } from '@encryption/src/vault/operations/decrypt';
import { handleEncryptNestedWithoutKey, handleEncryptWithKey, handleEncryptWithoutKey } from '@encryption/src/vault/operations/encrypt';
import { getStoredKeyPair } from '@encryption/src/vault/operations/key-management';
import { handleShareKeys } from '@encryption/src/vault/operations/share-keys';

vi.mock('@encryption/src/vault/operations/key-management', () => ({ getStoredKeyPair: vi.fn() }));

useTestDatabase();

// ----- The product: a Docs-like schema, binary columns, an object storage ------------

// The bucket attachments live in, keyed by object key.
const objectStorage = new Map<string, Uint8Array>();

beforeAll(async () => {
  await testPrisma.$executeRawUnsafe('CREATE SCHEMA product');
  await testPrisma.$executeRawUnsafe(
    `CREATE TABLE product.documents (
       id uuid PRIMARY KEY,
       title text NOT NULL,
       encrypted_content bytea,
       content bytea,
       maintenance_key bytea,
       updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
     )`
  );
  await testPrisma.$executeRawUnsafe(
    `CREATE TABLE product.document_accesses (
       document_id uuid NOT NULL REFERENCES product.documents (id) ON DELETE CASCADE,
       sub text NOT NULL,
       encrypted_key bytea NOT NULL,
       key_version int NOT NULL,
       PRIMARY KEY (document_id, sub)
     )`
  );
  await testPrisma.$executeRawUnsafe(
    `CREATE TABLE product.attachments (
       id uuid PRIMARY KEY,
       document_id uuid NOT NULL REFERENCES product.documents (id) ON DELETE CASCADE,
       file_name text NOT NULL,
       wrapped_key bytea,
       object_key text NOT NULL
     )`
  );
  await testPrisma.$executeRawUnsafe(
    `CREATE TABLE product.comments (
       id uuid PRIMARY KEY,
       document_id uuid NOT NULL REFERENCES product.documents (id) ON DELETE CASCADE,
       encrypted_body bytea,
       body text
     )`
  );
});

beforeEach(async () => {
  (getStoredKeyPair as Mock).mockReset();
  objectStorage.clear();
  await testPrisma.$executeRawUnsafe('TRUNCATE product.documents CASCADE');
});

// The product team's export: one query for the manifest (`psql -At`, one JSON object
// per line), then a copy of each object the manifest names, under its own key.
// `encode(..., 'base64')` wraps its output every 76 characters, hence the `translate`.
const MANIFEST_SQL = `
  SELECT line FROM (
    SELECT 0 AS rank, d.id AS sort, json_build_object(
      'id', d.id, 'type', 'document', 'title', d.title, 'updatedAt', d.updated_at,
      'maintenanceKey', translate(encode(d.maintenance_key, 'base64'), E'\\n', ''),
      'content', translate(encode(d.encrypted_content, 'base64'), E'\\n', '')
    )::text AS line
    FROM product.documents d WHERE d.maintenance_key IS NOT NULL
  UNION ALL
    SELECT 1, a.id, json_build_object(
      'id', a.id, 'type', 'attachment', 'parent', a.document_id, 'fileName', a.file_name,
      'wrappedKey', translate(encode(a.wrapped_key, 'base64'), E'\\n', ''),
      'file', a.object_key
    )::text
    FROM product.attachments a JOIN product.documents d ON d.id = a.document_id WHERE d.maintenance_key IS NOT NULL
  UNION ALL
    SELECT 2, c.id, json_build_object(
      'id', c.id, 'type', 'comment', 'parent', c.document_id,
      'content', translate(encode(c.encrypted_body, 'base64'), E'\\n', '')
    )::text
    FROM product.comments c JOIN product.documents d ON d.id = c.document_id WHERE d.maintenance_key IS NOT NULL
  ) export ORDER BY rank, sort`;

async function exportFolder(manifestSql = MANIFEST_SQL): Promise<Map<string, Uint8Array>> {
  const lines = await testPrisma.$queryRawUnsafe<{ line: string }[]>(manifestSql);
  const folder = new Map<string, Uint8Array>([[MANIFEST_FILE, new TextEncoder().encode(lines.map(({ line }) => line).join('\n'))]]);
  for (const { line } of lines) {
    const { file } = JSON.parse(line) as { file?: string };

    if (file) folder.set(file, objectStorage.get(file) as Uint8Array);
  }

  return folder;
}

// What the custodians do on the isolated machine: type the phrase, pick the folder.
async function runTool(phrase: string, folder: Map<string, Uint8Array>): Promise<Map<string, Uint8Array>> {
  const key = await maintenanceKeyPairFromPhrase(phrase);
  const items = parseManifest(new TextDecoder().decode(folder.get(MANIFEST_FILE)));
  const readFile = async (path: string) => folder.get(path);
  const sink = mapSink();

  await writeDecryptedExport(recoverItems(key, items, readFile), readFile, sink);

  return sink.files;
}

const manifestOf = (folder: Map<string, Uint8Array>) =>
  new TextDecoder()
    .decode(folder.get(MANIFEST_FILE))
    .trim()
    .split('\n')
    .filter((line) => line !== '')
    .map((line) => JSON.parse(line) as Record<string, string>);

// The product team's write-back: the plaintext replaces the ciphertext, and a document
// edited since the export (its `updatedAt` moved) is left alone, to be exported again.
async function writeBack(output: Map<string, Uint8Array>): Promise<{ skipped: string[] }> {
  const skipped: string[] = [];

  await testPrisma.$transaction(async (tx) => {
    for (const line of manifestOf(output)) {
      if (line.error) {
        skipped.push(line.id);
      } else if (line.type === 'document') {
        const updated = await tx.$executeRaw`
          UPDATE product.documents SET content = decode(${line.content}, 'base64'), encrypted_content = NULL, maintenance_key = NULL
          WHERE id = ${line.id}::uuid AND updated_at = ${line.updatedAt}::timestamptz`;

        if (updated === 0) skipped.push(line.id);
      } else if (line.type === 'attachment') {
        // `file` is the object's key: the plaintext goes back where the ciphertext was.
        objectStorage.set(line.file, output.get(line.file) as Uint8Array);
        await tx.$executeRaw`UPDATE product.attachments SET wrapped_key = NULL WHERE id = ${line.id}::uuid`;
      } else if (line.type === 'comment') {
        await tx.$executeRaw`
          UPDATE product.comments SET body = convert_from(decode(${line.content}, 'base64'), 'UTF8'), encrypted_body = NULL
          WHERE id = ${line.id}::uuid`;
      }
    }
  });

  return { skipped };
}

// ----- The devices: real vault operations, routed to one person's key pair ------

interface Person {
  sub: string;
  pair: HybridKeyPair;
}

async function person(name: string): Promise<Person> {
  return { sub: `sub-${name}`, pair: await generateUserKeyPair() };
}

const toBuffer = (bytes: Uint8Array): ArrayBuffer => bytes.slice().buffer as ArrayBuffer;
const text = (s: string): ArrayBuffer => new TextEncoder().encode(s).buffer as ArrayBuffer;
const wire = (people: Person[]) => Object.fromEntries(people.map((p) => [p.sub, toBuffer(base64ToUint8(exportPublicKeyAsBase64(p.pair.publicKey)))]));

function actAs(someone: Person): void {
  (getStoredKeyPair as Mock).mockResolvedValue({ ...someone.pair, version: 1 });
}

async function myCopy(documentId: string, someone: Person): Promise<ArrayBuffer> {
  const [{ encrypted_key: key }] = await testPrisma.$queryRaw<{ encrypted_key: Uint8Array }[]>`
    SELECT encrypted_key FROM product.document_accesses WHERE document_id = ${documentId}::uuid AND sub = ${someone.sub}`;

  return toBuffer(key);
}

// `maintenance`: the key the deployment's table assigns to the author's email domain.
async function createDocument(author: Person, title: string, content: string, maintenance: MaintenanceKeyPair | null): Promise<string> {
  actAs(author);

  const created = await handleEncryptWithoutKey(author.sub, {
    data: text(content),
    userPublicKeys: wire([author]),
    maintenanceEscrowKey: maintenance,
  });
  const id = randomUUID();

  // The product's rule: persist `maintenanceKey` whenever the SDK returned one.
  await testPrisma.$executeRaw`
    INSERT INTO product.documents (id, title, encrypted_content, maintenance_key)
    VALUES (${id}::uuid, ${title}, ${Buffer.from(created.encryptedContent)}, ${created.maintenanceKey ? Buffer.from(created.maintenanceKey) : null})`;
  await testPrisma.$executeRaw`
    INSERT INTO product.document_accesses (document_id, sub, encrypted_key, key_version)
    VALUES (${id}::uuid, ${author.sub}, ${Buffer.from(created.encryptedKeys[author.sub])}, 1)`;

  return id;
}

// `maintenance`: the key assigned to the document's OWNER, whoever shares it.
async function shareDocument(id: string, from: Person, to: Person[], maintenance: MaintenanceKeyPair | null): Promise<void> {
  actAs(from);

  const shared = await handleShareKeys(from.sub, {
    encryptedSymmetricKey: await myCopy(id, from),
    userPublicKeys: wire(to),
    maintenanceEscrowKey: maintenance,
  });

  for (const [sub, key] of Object.entries(shared.encryptedKeys)) {
    await testPrisma.$executeRaw`
      INSERT INTO product.document_accesses (document_id, sub, encrypted_key, key_version) VALUES (${id}::uuid, ${sub}, ${Buffer.from(key)}, 1)`;
  }

  if (shared.maintenanceKey) {
    await testPrisma.$executeRaw`UPDATE product.documents SET maintenance_key = ${Buffer.from(shared.maintenanceKey)} WHERE id = ${id}::uuid`;
  }
}

// An attachment has a key of its own, wrapped by the document's key (the nested create).
async function attach(documentId: string, someone: Person, fileName: string, bytes: Uint8Array): Promise<string> {
  actAs(someone);

  const { encryptedContent, wrappedKey } = await handleEncryptNestedWithoutKey(someone.sub, {
    data: toBuffer(bytes),
    encryptedSymmetricKey: await myCopy(documentId, someone),
  });
  const id = randomUUID();
  const objectKey = `${documentId}/attachments/${id}`;

  objectStorage.set(objectKey, new Uint8Array(encryptedContent));
  await testPrisma.$executeRaw`
    INSERT INTO product.attachments (id, document_id, file_name, wrapped_key, object_key)
    VALUES (${id}::uuid, ${documentId}::uuid, ${fileName}, ${Buffer.from(wrappedKey)}, ${objectKey})`;

  return id;
}

// A comment is encrypted with the document's key itself.
async function comment(documentId: string, someone: Person, body: string): Promise<string> {
  actAs(someone);

  const { encryptedData } = await handleEncryptWithKey(someone.sub, { data: text(body), encryptedSymmetricKey: await myCopy(documentId, someone) });
  const id = randomUUID();

  await testPrisma.$executeRaw`
    INSERT INTO product.comments (id, document_id, encrypted_body) VALUES (${id}::uuid, ${documentId}::uuid, ${Buffer.from(encryptedData)})`;

  return id;
}

async function openDocument(id: string, reader: Person): Promise<string> {
  actAs(reader);

  const [row] = await testPrisma.$queryRaw<
    { encrypted_content: Uint8Array }[]
  >`SELECT encrypted_content FROM product.documents WHERE id = ${id}::uuid`;
  const { data } = await handleDecryptWithKey(reader.sub, {
    encryptedData: toBuffer(row.encrypted_content),
    encryptedSymmetricKey: await myCopy(id, reader),
    keyVersion: 1,
  });

  return new TextDecoder().decode(data);
}

describe('batch recovery, end to end', () => {
  let alice: Person;
  let bob: Person;
  let phrase: string;
  let maintenance: MaintenanceKeyPair;

  beforeEach(async () => {
    [alice, bob, phrase] = await Promise.all([person('alice'), person('bob'), generateMaintenancePhrase('french')]);
    maintenance = await maintenanceKeyPairFromPhrase(phrase);
  });

  it('turns a whole product back into plaintext: documents, attachments in object storage and comments', async () => {
    const notes = await createDocument(alice, 'notes', 'hello from alice', maintenance);
    await shareDocument(notes, alice, [bob], maintenance);
    const photo = Uint8Array.from({ length: 3000 }, (_, i) => (i * 7) & 0xff);
    const attachment = await attach(notes, bob, 'photo.png', photo);
    const remark = await comment(notes, bob, 'une remarque de bob');
    const plan = await createDocument(bob, 'plan', 'le plan de bob', maintenance);

    // Never a recipient: the access table only knows the two people.
    const accesses = await testPrisma.$queryRaw<
      { sub: string }[]
    >`SELECT sub FROM product.document_accesses WHERE document_id = ${notes}::uuid ORDER BY sub`;
    expect(accesses.map((access) => access.sub)).toEqual([alice.sub, bob.sub]);
    expect(await openDocument(notes, bob)).toBe('hello from alice');

    const output = await runTool(phrase, await exportFolder());

    // The decrypted export mirrors the input: same ids and paths, no key material left.
    expect(manifestOf(output)).toEqual(
      expect.arrayContaining([
        { id: notes, type: 'document', title: 'notes', updatedAt: expect.any(String), content: expect.any(String) },
        { id: attachment, type: 'attachment', parent: notes, fileName: 'photo.png', file: `${notes}/attachments/${attachment}` },
        { id: remark, type: 'comment', parent: notes, content: expect.any(String) },
      ])
    );
    expect(output.get(`${notes}/attachments/${attachment}`)).toEqual(photo);

    expect(await writeBack(output)).toEqual({ skipped: [] });

    const documents = await testPrisma.$queryRaw<{ id: string; content: Uint8Array; encrypted_content: Uint8Array | null }[]>`
      SELECT id, content, encrypted_content FROM product.documents`;
    expect(Object.fromEntries(documents.map((d) => [d.id, [Buffer.from(d.content).toString(), d.encrypted_content]]))).toEqual({
      [notes]: ['hello from alice', null],
      [plan]: ['le plan de bob', null],
    });
    expect(await testPrisma.$queryRaw`SELECT body FROM product.comments`).toEqual([{ body: 'une remarque de bob' }]);
    expect([...objectStorage.values()]).toEqual([photo]);
  });

  it('carries the product fields through, so a document edited after the export is not overwritten', async () => {
    const id = await createDocument(alice, 'live', 'version exported', maintenance);
    const output = await runTool(phrase, await exportFolder());

    // Someone keeps editing between the export and the write-back.
    actAs(alice);
    const { encryptedData } = await handleEncryptWithKey(alice.sub, {
      data: text('edited meanwhile'),
      encryptedSymmetricKey: await myCopy(id, alice),
    });
    await testPrisma.$executeRaw`UPDATE product.documents SET encrypted_content = ${Buffer.from(encryptedData)}, updated_at = clock_timestamp() WHERE id = ${id}::uuid`;

    expect(await writeBack(output)).toEqual({ skipped: [id] });
    expect(await openDocument(id, alice)).toBe('edited meanwhile');

    // Exported again, it goes through.
    expect(await writeBack(await runTool(phrase, await exportFolder()))).toEqual({ skipped: [] });
  });

  it('leaves the column NULL without a configured key, and an empty share backfills it later', async () => {
    const id = await createDocument(alice, 'legacy', 'created before the escrow existed', null);

    expect(manifestOf(await exportFolder())).toEqual([]);

    // The deployment enables the escrow; the product backfills from any holder, adding nobody.
    await shareDocument(id, alice, [], maintenance);

    const output = await runTool(phrase, await exportFolder());
    expect(Buffer.from(manifestOf(output)[0].content, 'base64').toString()).toBe('created before the escrow existed');
    expect(await testPrisma.$queryRaw`SELECT count(*)::int AS n FROM product.document_accesses`).toEqual([{ n: 1 }]);
  });

  it("sets aside another organization's documents, still encrypted, as an export its custodians open", async () => {
    const otherPhrase = await generateMaintenancePhrase('english');
    const interieur = await maintenanceKeyPairFromPhrase(otherPhrase);
    const ours = await createDocument(alice, 'agriculture', 'chez alice', maintenance);
    const theirs = await createDocument(bob, 'interieur', 'chez bob', interieur);
    const attachment = await attach(theirs, bob, 'a.bin', new Uint8Array([1, 2, 3]));
    // Alice shares bob's document onwards: the copy stays with its owner's organization.
    await shareDocument(theirs, bob, [alice], interieur);
    await shareDocument(theirs, alice, [], interieur);

    const output = await runTool(phrase, await exportFolder());
    const folder = `${OTHER_KEYS_FOLDER}/${maintenanceKeyIdToFingerprint(interieur.keyId)}`;

    expect(manifestOf(output)).toEqual([
      { id: ours, type: 'document', title: 'agriculture', updatedAt: expect.any(String), content: expect.any(String) },
    ]);
    expect([...output.keys()]).toEqual([`${folder}/${theirs}/attachments/${attachment}`, `${folder}/${MANIFEST_FILE}`, MANIFEST_FILE]);

    // The set-aside folder is an export in its own right, for the other custodians.
    const handedOver = new Map(
      [...output].filter(([path]) => path.startsWith(`${folder}/`)).map(([path, data]) => [path.slice(folder.length + 1), data])
    );
    const theirOutput = await runTool(otherPhrase, handedOver);

    expect(manifestOf(theirOutput).map((line) => line.id)).toEqual([theirs, attachment]);
    expect(theirOutput.get(`${theirs}/attachments/${attachment}`)).toEqual(new Uint8Array([1, 2, 3]));
    expect(await writeBack(output)).toEqual({ skipped: [] });
    expect(await writeBack(theirOutput)).toEqual({ skipped: [] });
  });

  it("exports one organization at a time with SQL alone, the key id being the copy's bytes 2 to 17", async () => {
    const interieur = await maintenanceKeyPairFromPhrase(await generateMaintenancePhrase('english'));
    const ours = await createDocument(alice, 'agriculture', 'chez alice', maintenance);
    await createDocument(bob, 'interieur', 'chez bob', interieur);

    const keyId = Buffer.from(maintenance.keyId).toString('hex');
    const scoped = MANIFEST_SQL.replaceAll(
      'WHERE d.maintenance_key IS NOT NULL',
      `WHERE substring(d.maintenance_key from 2 for 16) = decode('${keyId}', 'hex')`
    );

    expect(manifestOf(await exportFolder(scoped)).map((line) => line.id)).toEqual([ours]);
  });

  it("refuses PostgreSQL's line-wrapped base64 instead of decoding garbage", async () => {
    await createDocument(alice, 'wrapped', 'x'.repeat(200), maintenance);

    // The export a team writes first: `encode` alone breaks lines every 76 characters.
    const naive = MANIFEST_SQL.replaceAll(/translate\((encode\([^)]*\)), E'\\n', ''\)/g, '$1');
    const folder = await exportFolder(naive);

    expect(new TextDecoder().decode(folder.get(MANIFEST_FILE))).toContain('\\n');
    await expect(runTool(phrase, folder)).rejects.toThrow(/translate/);
  });
});
