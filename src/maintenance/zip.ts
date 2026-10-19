/**
 * The smallest ZIP writer that every operating system opens: entries stored
 * uncompressed (the content is mostly already compressed or small), UTF-8 names,
 * no ZIP64. It exists so the maintenance tool stays one file with no dependency
 * beyond the code it decrypts with, and so a browser without the File System
 * Access API (Firefox, Safari) can still hand back a whole folder.
 *
 * Without ZIP64 an archive holds at most 65,535 entries and 4 GiB: past that the
 * writer refuses with a message, and the export is split into batches.
 */

const MAX_ENTRIES = 0xffff;
const MAX_OFFSET = 0xffffffff;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);

  for (let n = 0; n < 256; n++) {
    let c = n;

    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;

    table[n] = c >>> 0;
  }

  return table;
})();

export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;

  for (let i = 0; i < data.length; i++) crc = CRC_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);

  return (crc ^ 0xffffffff) >>> 0;
}

// MS-DOS date and time, local time, two-second resolution, from 1980.
function dosDateTime(date: Date): { time: number; date: number } {
  const year = Math.max(date.getFullYear(), 1980);

  return {
    time: (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2),
    date: ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate(),
  };
}

export class ZipLimitError extends Error {}

interface CentralEntry {
  name: Uint8Array;
  crc: number;
  size: number;
  offset: number;
}

const UTF8_FLAG = 0x0800;
const VERSION = 20;

export class ZipWriter {
  private readonly parts: Uint8Array[] = [];
  private readonly entries: CentralEntry[] = [];
  private readonly names = new Set<string>();
  private readonly stamp: { time: number; date: number };
  private offset = 0;

  constructor(date: Date = new Date()) {
    this.stamp = dosDateTime(date);
  }

  add(path: string, data: Uint8Array): void {
    if (this.names.has(path)) throw new Error(`${path} is in the archive twice`);
    if (this.entries.length === MAX_ENTRIES) throw new ZipLimitError(`An archive holds at most ${MAX_ENTRIES} files: split the export into batches`);

    const name = new TextEncoder().encode(path);
    const header = new Uint8Array(30 + name.length);
    const view = new DataView(header.buffer);
    const crc = crc32(data);

    if (this.offset + header.length + data.length > MAX_OFFSET) {
      throw new ZipLimitError('An archive holds at most 4 GiB: split the export into batches');
    }

    view.setUint32(0, 0x04034b50, true);
    view.setUint16(4, VERSION, true);
    view.setUint16(6, UTF8_FLAG, true);
    view.setUint16(8, 0, true); // stored
    view.setUint16(10, this.stamp.time, true);
    view.setUint16(12, this.stamp.date, true);
    view.setUint32(14, crc, true);
    view.setUint32(18, data.length, true);
    view.setUint32(22, data.length, true);
    view.setUint16(26, name.length, true);
    view.setUint16(28, 0, true);
    header.set(name, 30);

    this.names.add(path);
    this.entries.push({ name, crc, size: data.length, offset: this.offset });
    this.parts.push(header, data);
    this.offset += header.length + data.length;
  }

  /** The archive, as parts to hand to `new Blob(...)` without copying them into one buffer. */
  finish(): Uint8Array[] {
    const directoryOffset = this.offset;
    let directorySize = 0;

    for (const entry of this.entries) {
      const record = new Uint8Array(46 + entry.name.length);
      const view = new DataView(record.buffer);

      view.setUint32(0, 0x02014b50, true);
      view.setUint16(4, VERSION, true);
      view.setUint16(6, VERSION, true);
      view.setUint16(8, UTF8_FLAG, true);
      view.setUint16(10, 0, true);
      view.setUint16(12, this.stamp.time, true);
      view.setUint16(14, this.stamp.date, true);
      view.setUint32(16, entry.crc, true);
      view.setUint32(20, entry.size, true);
      view.setUint32(24, entry.size, true);
      view.setUint16(28, entry.name.length, true);
      // extra, comment, disk number, internal and external attributes: all zero
      view.setUint32(42, entry.offset, true);
      record.set(entry.name, 46);

      this.parts.push(record);
      directorySize += record.length;
    }

    if (directoryOffset + directorySize > MAX_OFFSET) {
      throw new ZipLimitError('An archive holds at most 4 GiB: split the export into batches');
    }

    const end = new Uint8Array(22);
    const view = new DataView(end.buffer);

    view.setUint32(0, 0x06054b50, true);
    view.setUint16(8, this.entries.length, true);
    view.setUint16(10, this.entries.length, true);
    view.setUint32(12, directorySize, true);
    view.setUint32(16, directoryOffset, true);
    this.parts.push(end);

    return this.parts;
  }
}
