// What the preview can show of a decrypted item without interpreting it: text when
// it is text, an image when its first bytes say so, a description otherwise. A
// document's own format (a Yjs update for Docs) is the product's to convert.

export type Preview =
  | { kind: 'text'; text: string; truncated: boolean }
  | { kind: 'image'; mime: string }
  | { kind: 'binary'; format: 'pdf' | 'zip' | 'unknown'; size: number; head: string };

const MAX_TEXT = 20_000;

const startsWith = (data: Uint8Array, signature: number[], offset = 0) => signature.every((byte, i) => data[offset + i] === byte);

function imageType(data: Uint8Array): string | null {
  if (startsWith(data, [0x89, 0x50, 0x4e, 0x47])) return 'image/png';
  if (startsWith(data, [0xff, 0xd8, 0xff])) return 'image/jpeg';
  if (startsWith(data, [0x47, 0x49, 0x46, 0x38])) return 'image/gif';
  if (startsWith(data, [0x52, 0x49, 0x46, 0x46]) && startsWith(data, [0x57, 0x45, 0x42, 0x50], 8)) return 'image/webp';

  return null;
}

export function previewOf(data: Uint8Array): Preview {
  const mime = imageType(data);

  if (mime) return { kind: 'image', mime };

  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(data);

    // Valid UTF-8 is not enough: binary formats often are. Text has no control
    // characters but tabs and line breaks.
    // eslint-disable-next-line no-control-regex
    if (!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) {
      return { kind: 'text', text: text.slice(0, MAX_TEXT), truncated: text.length > MAX_TEXT };
    }
  } catch {
    // not UTF-8
  }

  const format = startsWith(data, [0x25, 0x50, 0x44, 0x46]) ? 'pdf' : startsWith(data, [0x50, 0x4b, 0x03, 0x04]) ? 'zip' : 'unknown';
  const head = [...data.subarray(0, 16)].map((byte) => byte.toString(16).padStart(2, '0')).join(' ');

  return { kind: 'binary', format, size: data.length, head };
}
