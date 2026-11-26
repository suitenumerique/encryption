/**
 * The smallest ZIP writer that every operating system opens: entries stored
 * uncompressed (the content is mostly already compressed or small), UTF-8 names.
 * It exists so the maintenance tool stays one file with no dependency beyond the
 * code it decrypts with, and so a browser without a folder picker (Firefox,
 * Safari) can still hand back a whole folder.
 *
 * It STREAMS: `add` and `finish` hand back the bytes to write, and the writer only
 * keeps the central directory (a few dozen bytes per entry), so an archive can be
 * written to disk as it is built, whatever its size. Past 4 GiB or 65,535 entries
 * it switches to ZIP64, which every current unzip tool reads.
 */

const ZIP64_ENTRIES = 0xffff;
const ZIP64_BYTES = 0xffffffff;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);

  for (let n = 0; n < 256; n++) {
    let c = n;

    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;

    table[n] = c >>> 0;
  }

  return table;
})();

/** CRC-32 of `data`, or of everything before it too when `previous` is the CRC so far. */
export function crc32(data: Uint8Array, previous = 0): number {
  let crc = (previous ^ 0xffffffff) >>> 0;

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

interface CentralEntry {
  name: Uint8Array;
  crc: number;
  size: number;
  offset: number;
  streamed: boolean;
}

const UTF8_FLAG = 0x0800;
// Sizes and CRC follow the data, in a descriptor: the entry is written before it is known.
const DESCRIPTOR_FLAG = 0x0008;
const VERSION = 20;
const VERSION_ZIP64 = 45;

/** Where ZIP64 starts; lowered only by tests, which cannot write 4 GiB to prove it. */
export interface ZipLimits {
  bytes: number;
  entries: number;
}

export class ZipWriter {
  private readonly entries: CentralEntry[] = [];
  private readonly names = new Set<string>();
  private readonly stamp: { time: number; date: number };
  private offset = 0;

  constructor(
    date: Date = new Date(),
    private readonly limits: ZipLimits = { bytes: ZIP64_BYTES, entries: ZIP64_ENTRIES }
  ) {
    this.stamp = dosDateTime(date);
  }

  /** One entry: its header and data, in the order to write them. */
  add(path: string, data: Uint8Array): Uint8Array[] {
    if (this.names.has(path)) throw new Error(`${path} is in the archive twice`);

    const name = new TextEncoder().encode(path);
    const crc = crc32(data);
    const big = data.length >= this.limits.bytes;
    // The local header names the sizes in its ZIP64 field when they do not fit.
    const header = new Uint8Array(30 + name.length + (big ? 20 : 0));
    const view = new DataView(header.buffer);

    view.setUint32(0, 0x04034b50, true);
    view.setUint16(4, big ? VERSION_ZIP64 : VERSION, true);
    view.setUint16(6, UTF8_FLAG, true);
    view.setUint16(8, 0, true); // stored
    view.setUint16(10, this.stamp.time, true);
    view.setUint16(12, this.stamp.date, true);
    view.setUint32(14, crc, true);
    view.setUint32(18, big ? 0xffffffff : data.length, true);
    view.setUint32(22, big ? 0xffffffff : data.length, true);
    view.setUint16(26, name.length, true);
    view.setUint16(28, big ? 20 : 0, true);
    header.set(name, 30);

    if (big) {
      view.setUint16(30 + name.length, 0x0001, true);
      view.setUint16(32 + name.length, 16, true);
      view.setBigUint64(34 + name.length, BigInt(data.length), true);
      view.setBigUint64(42 + name.length, BigInt(data.length), true);
    }

    this.names.add(path);
    this.entries.push({ name, crc, size: data.length, offset: this.offset, streamed: false });
    this.offset += header.length + data.length;

    return [header, data];
  }

  /**
   * One entry whose content arrives in chunks of unknown total size (a manifest
   * spooled to disk): each chunk is handed back as it comes, never gathered.
   */
  async *addStream(path: string, chunks: AsyncIterable<Uint8Array>): AsyncGenerator<Uint8Array> {
    if (this.names.has(path)) throw new Error(`${path} is in the archive twice`);

    const name = new TextEncoder().encode(path);
    const offset = this.offset;
    // Sizes unknown yet: 0xffffffff with an empty ZIP64 field, the descriptor says them.
    const header = new Uint8Array(30 + name.length + 20);
    const view = new DataView(header.buffer);

    view.setUint32(0, 0x04034b50, true);
    view.setUint16(4, VERSION_ZIP64, true);
    view.setUint16(6, UTF8_FLAG | DESCRIPTOR_FLAG, true);
    view.setUint16(10, this.stamp.time, true);
    view.setUint16(12, this.stamp.date, true);
    view.setUint32(18, 0xffffffff, true);
    view.setUint32(22, 0xffffffff, true);
    view.setUint16(26, name.length, true);
    view.setUint16(28, 20, true);
    header.set(name, 30);
    view.setUint16(30 + name.length, 0x0001, true);
    view.setUint16(32 + name.length, 16, true);

    this.names.add(path);
    yield header;

    let crc = 0;
    let size = 0;

    for await (const chunk of chunks) {
      crc = crc32(chunk, crc);
      size += chunk.length;
      yield chunk;
    }

    const descriptor = new Uint8Array(24);
    const descriptorView = new DataView(descriptor.buffer);

    descriptorView.setUint32(0, 0x08074b50, true);
    descriptorView.setUint32(4, crc, true);
    descriptorView.setBigUint64(8, BigInt(size), true);
    descriptorView.setBigUint64(16, BigInt(size), true);
    yield descriptor;

    this.entries.push({ name, crc, size, offset, streamed: true });
    this.offset += header.length + size + descriptor.length;
  }

  /** The central directory and the end records, to write after the last entry. */
  finish(): Uint8Array[] {
    const parts: Uint8Array[] = [];
    const directoryOffset = this.offset;
    let directorySize = 0;

    for (const entry of this.entries) {
      const bigSize = entry.size >= this.limits.bytes;
      const bigOffset = entry.offset >= this.limits.bytes;
      const extra = (bigSize ? 16 : 0) + (bigOffset ? 8 : 0);
      const record = new Uint8Array(46 + entry.name.length + (extra ? 4 + extra : 0));
      const view = new DataView(record.buffer);

      view.setUint32(0, 0x02014b50, true);
      view.setUint16(4, extra || entry.streamed ? VERSION_ZIP64 : VERSION, true);
      view.setUint16(6, extra || entry.streamed ? VERSION_ZIP64 : VERSION, true);
      view.setUint16(8, entry.streamed ? UTF8_FLAG | DESCRIPTOR_FLAG : UTF8_FLAG, true);
      view.setUint16(10, 0, true);
      view.setUint16(12, this.stamp.time, true);
      view.setUint16(14, this.stamp.date, true);
      view.setUint32(16, entry.crc, true);
      view.setUint32(20, bigSize ? 0xffffffff : entry.size, true);
      view.setUint32(24, bigSize ? 0xffffffff : entry.size, true);
      view.setUint16(28, entry.name.length, true);
      view.setUint16(30, extra ? 4 + extra : 0, true);
      // comment, disk number, internal and external attributes: all zero
      view.setUint32(42, bigOffset ? 0xffffffff : entry.offset, true);
      record.set(entry.name, 46);

      if (extra) {
        // The ZIP64 field holds only the values its record could not, in this order.
        let cursor = 46 + entry.name.length;

        view.setUint16(cursor, 0x0001, true);
        view.setUint16(cursor + 2, extra, true);
        cursor += 4;

        if (bigSize) {
          view.setBigUint64(cursor, BigInt(entry.size), true);
          view.setBigUint64(cursor + 8, BigInt(entry.size), true);
          cursor += 16;
        }

        if (bigOffset) view.setBigUint64(cursor, BigInt(entry.offset), true);
      }

      parts.push(record);
      directorySize += record.length;
    }

    const zip64 = this.entries.length >= this.limits.entries || directoryOffset >= this.limits.bytes || directorySize >= this.limits.bytes;

    if (zip64) {
      const record = new Uint8Array(56);
      const view = new DataView(record.buffer);

      view.setUint32(0, 0x06064b50, true);
      view.setBigUint64(4, 44n, true); // size of the rest of this record
      view.setUint16(12, VERSION_ZIP64, true);
      view.setUint16(14, VERSION_ZIP64, true);
      view.setBigUint64(24, BigInt(this.entries.length), true);
      view.setBigUint64(32, BigInt(this.entries.length), true);
      view.setBigUint64(40, BigInt(directorySize), true);
      view.setBigUint64(48, BigInt(directoryOffset), true);

      const locator = new Uint8Array(20);
      const locatorView = new DataView(locator.buffer);

      locatorView.setUint32(0, 0x07064b50, true);
      locatorView.setBigUint64(8, BigInt(directoryOffset + directorySize), true);
      locatorView.setUint32(16, 1, true); // one disk in all
      parts.push(record, locator);
    }

    const end = new Uint8Array(22);
    const view = new DataView(end.buffer);

    view.setUint32(0, 0x06054b50, true);
    view.setUint16(8, zip64 ? 0xffff : this.entries.length, true);
    view.setUint16(10, zip64 ? 0xffff : this.entries.length, true);
    view.setUint32(12, zip64 ? 0xffffffff : directorySize, true);
    view.setUint32(16, zip64 ? 0xffffffff : directoryOffset, true);
    parts.push(end);

    return parts;
  }
}
