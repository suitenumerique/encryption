import { beforeAll, describe, expect, it } from 'vitest';

import {
  type MaintenanceKeyPair,
  base64ToUint8,
  encryptContent,
  generateSymmetricKey,
  uint8ToBase64,
  unwrapMaintenanceKey,
  wrapKeyForMaintenance,
} from '@encryption/src/crypto';
import { maintenanceKeyIdToFingerprint, maintenanceKeyPairFromPhrase, readMaintenanceCopyKeyId } from '@encryption/src/crypto/maintenance-escrow';
import { DEV_MAINTENANCE_PHRASE } from '@encryption/src/maintenance/dev-maintenance-key';
import { MANIFEST_FILE, parseManifest } from '@encryption/src/maintenance/export-format';
import { rotateCopies, writeRotatedExport } from '@encryption/src/maintenance/rotate';
import { SAMPLE_OTHER_ORGANIZATION_PHRASE, mapSink } from '@encryption/src/maintenance/testing';
import { DOMAIN_CONTENT, DOMAIN_WRAPPED_KEY } from '@encryption/src/shared/crypto-domains';

const NEW_PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art';

let oldKey: MaintenanceKeyPair;
let newKey: MaintenanceKeyPair;
let otherOrganization: MaintenanceKeyPair;

beforeAll(async () => {
  [oldKey, newKey, otherOrganization] = await Promise.all([
    maintenanceKeyPairFromPhrase(DEV_MAINTENANCE_PHRASE),
    maintenanceKeyPairFromPhrase(NEW_PHRASE),
    maintenanceKeyPairFromPhrase(SAMPLE_OTHER_ORGANIZATION_PHRASE),
  ]);
});

async function rotate(lines: Record<string, unknown>[]): Promise<Record<string, unknown>[]> {
  const sink = mapSink();

  await writeRotatedExport(rotateCopies(oldKey, newKey, parseManifest(lines.map((line) => JSON.stringify(line)).join('\n'))), sink);

  return new TextDecoder()
    .decode(sink.files.get(MANIFEST_FILE))
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe('rotateCopies', () => {
  it('wraps each root key again for the new key, keeping the copy it replaces and the product fields', async () => {
    const rootKey = await generateSymmetricKey();
    const copy = uint8ToBase64(await wrapKeyForMaintenance(rootKey, oldKey));

    const [line] = await rotate([{ id: 'doc', type: 'document', title: 'Rapport', maintenanceKey: copy }]);

    expect(line).toEqual({ id: 'doc', type: 'document', title: 'Rapport', maintenanceKey: expect.any(String), previousMaintenanceKey: copy });

    const rotated = base64ToUint8(line.maintenanceKey as string);

    expect(maintenanceKeyIdToFingerprint(readMaintenanceCopyKeyId(rotated))).toBe(maintenanceKeyIdToFingerprint(newKey.keyId));
    expect(await unwrapMaintenanceKey(newKey, rotated)).toEqual(rootKey);
    // The old phrase no longer opens what the product will store.
    await expect(unwrapMaintenanceKey(oldKey, rotated)).rejects.toThrow(/OTHER_MAINTENANCE_KEY|Escrowed for the maintenance key/);
  });

  it('hands back the roots alone, without the ciphertext a full export carries', async () => {
    const rootKey = await generateSymmetricKey();
    const childKey = await generateSymmetricKey();

    const lines = await rotate([
      {
        id: 'doc',
        maintenanceKey: uint8ToBase64(await wrapKeyForMaintenance(rootKey, oldKey)),
        content: uint8ToBase64(await encryptContent(new TextEncoder().encode('secret'), rootKey, DOMAIN_CONTENT)),
      },
      { id: 'attachment', parent: 'doc', wrappedKey: uint8ToBase64(await encryptContent(childKey, rootKey, DOMAIN_WRAPPED_KEY)), file: 'a/b' },
    ]);

    expect(lines.map((line) => Object.keys(line).sort())).toEqual([['id', 'maintenanceKey', 'previousMaintenanceKey']]);
  });

  it("reports another key's copy and a damaged copy, with no new copy", async () => {
    const theirs = uint8ToBase64(await wrapKeyForMaintenance(await generateSymmetricKey(), otherOrganization));
    const damaged = await wrapKeyForMaintenance(await generateSymmetricKey(), oldKey);

    damaged[damaged.length - 1] ^= 1;

    const lines = await rotate([
      { id: 'theirs', maintenanceKey: theirs },
      { id: 'damaged', maintenanceKey: uint8ToBase64(damaged) },
    ]);

    expect(lines).toEqual([
      { id: 'theirs', previousMaintenanceKey: theirs, error: expect.stringMatching(/escrowed for another maintenance key/) },
      { id: 'damaged', previousMaintenanceKey: uint8ToBase64(damaged), error: expect.stringMatching(/^WRONG_SECRET_KEY: /) },
    ]);
  });
});
