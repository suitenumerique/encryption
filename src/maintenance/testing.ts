import {
  type MaintenancePublicKey,
  base64ToUint8,
  encryptContent,
  generateSymmetricKey,
  uint8ToBase64,
  wrapKeyForMaintenance,
} from '@encryption/src/crypto';
import { maintenanceKeyPairFromPhrase } from '@encryption/src/crypto/maintenance-escrow';
import { MANIFEST_FILE } from '@encryption/src/maintenance/export-format';
import { DOMAIN_CONTENT, DOMAIN_WRAPPED_KEY } from '@encryption/src/shared/crypto-domains';

// 1x1 PNGs, so attachments are real images a preview shows, at a few bytes each.
export const SAMPLE_PIXELS = {
  red: base64ToUint8('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR42mO4o6EBAAMQAS0Qc/Z2AAAAAElFTkSuQmCC'),
  blue: base64ToUint8('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR42mNgYJgIAACVAJLm/w0TAAAAAElFTkSuQmCC'),
  green: base64ToUint8('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR42mOQ63EDAAG8APHZPG7qAAAAAElFTkSuQmCC'),
  grey: base64ToUint8('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR42mOoqKgAAALUAWngtuJXAAAAAElFTkSuQmCC'),
};

/** Another organization's maintenance phrase, fixed, so its fingerprint is the same on every run and its items can be opened too. */
export const SAMPLE_OTHER_ORGANIZATION_PHRASE =
  'alpha deal scrub asthma idea logic bright thought alpha deal scrub asthma idea logic bright thought alpha deal scrub asthma idea logic bright truly';

export const sampleOtherOrganizationKey = () => maintenanceKeyPairFromPhrase(SAMPLE_OTHER_ORGANIZATION_PHRASE);

export const SAMPLE_IDS = {
  report: 'a1000000-0000-4000-8000-000000000001',
  logo: 'a1000000-0000-4000-8000-000000000002',
  chart: 'a1000000-0000-4000-8000-000000000003',
  remark: 'a1000000-0000-4000-8000-000000000004',
  budget: 'b1000000-0000-4000-8000-000000000001',
  annexes: 'b1000000-0000-4000-8000-000000000002',
  invoice: 'b1000000-0000-4000-8000-000000000003',
  elsewhere: 'c1000000-0000-4000-8000-000000000001',
  elsewherePhoto: 'c1000000-0000-4000-8000-000000000002',
  damaged: 'd1000000-0000-4000-8000-000000000001',
};

const ids = SAMPLE_IDS;

/** Where each attachment sits, its object key in the product's bucket. */
export const SAMPLE_FILES = {
  logo: `${ids.report}/attachments/${ids.logo}.png`,
  chart: `${ids.report}/attachments/${ids.chart}.png`,
  invoice: `drive/${ids.invoice}`,
  elsewherePhoto: `${ids.elsewhere}/attachments/${ids.elsewherePhoto}.png`,
};

const text = (value: string) => new TextEncoder().encode(value);

/** What each item decrypts to, by id; an item absent here carries only a key (a folder) or cannot be opened. */
export const SAMPLE_PLAINTEXTS: Record<string, Uint8Array> = {
  [ids.report]: text(
    '# Compte rendu du comité de pilotage\n\nLe déploiement continue au premier trimestre. Décision : ouvrir aux directions régionales.\n'
  ),
  [ids.logo]: SAMPLE_PIXELS.red,
  [ids.chart]: SAMPLE_PIXELS.blue,
  [ids.remark]: text('Penser à joindre le planning détaillé.'),
  [ids.invoice]: SAMPLE_PIXELS.green,
  [ids.elsewhere]: text("Note de l'autre organisation."),
  [ids.elsewherePhoto]: SAMPLE_PIXELS.grey,
};

export const SAMPLE_TEXTS = { report: new TextDecoder().decode(SAMPLE_PLAINTEXTS[ids.report]) };

/**
 * An export as a product team would hand it over, encrypted for `maintenancePublicKey`
 * the way the vault and the products encrypt:
 *
 *   - a Docs-like document with two image attachments (each its own key, wrapped by
 *     the document's, the bytes in files named by their object key) and a comment
 *     (under the document's key);
 *   - a Drive-like tree: a root folder that only carries a key, a subfolder, and a
 *     file two levels down;
 *   - a document with an attachment owned in another organization, escrowed for
 *     its key (`sampleOtherOrganizationKey`);
 *   - a document whose escrow copy is damaged.
 *
 * Product fields (titles, file names, `updatedAt`) ride along, as they would.
 */
export async function buildSampleExport(maintenancePublicKey: MaintenancePublicKey): Promise<Record<string, Uint8Array>> {
  const theirs = await sampleOtherOrganizationKey();
  const [report, logo, chart, budget, annexes, invoice, elsewhere, elsewherePhoto] = await Promise.all(
    Array.from({ length: 8 }, () => generateSymmetricKey())
  );
  const damaged = await wrapKeyForMaintenance(await generateSymmetricKey(), maintenancePublicKey);
  const sealed = async (id: string, key: Uint8Array) => uint8ToBase64(await encryptContent(SAMPLE_PLAINTEXTS[id], key, DOMAIN_CONTENT));
  const wrapped = async (child: Uint8Array, parent: Uint8Array) => uint8ToBase64(await encryptContent(child, parent, DOMAIN_WRAPPED_KEY));
  const updatedAt = '2026-10-19T09:30:00.000Z';

  damaged[damaged.length - 1] ^= 1;

  const lines = [
    {
      id: ids.report,
      type: 'document',
      title: 'Compte rendu du comité de pilotage',
      updatedAt,
      maintenanceKey: uint8ToBase64(await wrapKeyForMaintenance(report, maintenancePublicKey)),
      content: await sealed(ids.report, report),
    },
    { id: ids.logo, type: 'attachment', parent: ids.report, fileName: 'logo.png', wrappedKey: await wrapped(logo, report), file: SAMPLE_FILES.logo },
    {
      id: ids.chart,
      type: 'attachment',
      parent: ids.report,
      fileName: 'graphique.png',
      wrappedKey: await wrapped(chart, report),
      file: SAMPLE_FILES.chart,
    },
    { id: ids.remark, type: 'comment', parent: ids.report, content: await sealed(ids.remark, report) },
    {
      id: ids.budget,
      type: 'folder',
      title: 'Budget 2027',
      maintenanceKey: uint8ToBase64(await wrapKeyForMaintenance(budget, maintenancePublicKey)),
    },
    { id: ids.annexes, type: 'folder', title: 'Annexes', parent: ids.budget, wrappedKey: await wrapped(annexes, budget) },
    {
      id: ids.invoice,
      type: 'file',
      title: 'facture.png',
      parent: ids.annexes,
      wrappedKey: await wrapped(invoice, annexes),
      file: SAMPLE_FILES.invoice,
    },
    {
      id: ids.elsewhere,
      type: 'document',
      title: "Note de l'autre organisation",
      updatedAt,
      maintenanceKey: uint8ToBase64(await wrapKeyForMaintenance(elsewhere, theirs)),
      content: await sealed(ids.elsewhere, elsewhere),
    },
    {
      id: ids.elsewherePhoto,
      type: 'attachment',
      parent: ids.elsewhere,
      fileName: 'photo.png',
      wrappedKey: await wrapped(elsewherePhoto, elsewhere),
      file: SAMPLE_FILES.elsewherePhoto,
    },
    { id: ids.damaged, type: 'document', title: 'Copie endommagée', updatedAt, maintenanceKey: uint8ToBase64(damaged) },
  ];
  const seal = (id: string, key: Uint8Array) => encryptContent(SAMPLE_PLAINTEXTS[id], key, DOMAIN_CONTENT);

  return {
    [MANIFEST_FILE]: text(`${lines.map((line) => JSON.stringify(line)).join('\n')}\n`),
    [SAMPLE_FILES.logo]: await seal(ids.logo, logo),
    [SAMPLE_FILES.chart]: await seal(ids.chart, chart),
    [SAMPLE_FILES.invoice]: await seal(ids.invoice, invoice),
    [SAMPLE_FILES.elsewherePhoto]: await seal(ids.elsewherePhoto, elsewherePhoto),
  };
}

/** Reads an archive the way an unzip tool does: from the end record, through the central directory, to each local header. */
export function readZip(archive: Uint8Array): { name: string; flags: number; crc: number; data: Uint8Array }[] {
  const view = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);
  const end = archive.length - 22;

  if (view.getUint32(end, true) !== 0x06054b50) throw new Error('no end of central directory record');

  const count = view.getUint16(end + 10, true);
  let cursor = view.getUint32(end + 16, true);
  const entries = [];

  for (let i = 0; i < count; i++) {
    if (view.getUint32(cursor, true) !== 0x02014b50) throw new Error(`no central directory record ${i}`);

    const flags = view.getUint16(cursor + 8, true);
    const crc = view.getUint32(cursor + 16, true);
    const size = view.getUint32(cursor + 24, true);
    const nameLength = view.getUint16(cursor + 28, true);
    const offset = view.getUint32(cursor + 42, true);
    const name = new TextDecoder().decode(archive.subarray(cursor + 46, cursor + 46 + nameLength));

    if (view.getUint32(offset, true) !== 0x04034b50) throw new Error(`no local header for ${name}`);
    if (view.getUint32(offset + 14, true) !== crc) throw new Error(`local and central CRC of ${name} differ`);

    const dataStart = offset + 30 + view.getUint16(offset + 26, true) + view.getUint16(offset + 28, true);

    entries.push({ name, flags, crc, data: archive.slice(dataStart, dataStart + size) });
    cursor += 46 + nameLength;
  }

  return entries;
}
