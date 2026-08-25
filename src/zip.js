/* Aperture — minimal ZIP reader, no dependencies.
 *
 * Uses the platform's DecompressionStream('deflate-raw') rather than shipping an
 * inflate implementation. The archive is read from an ArrayBuffer already in
 * memory; nothing is uploaded, and there is no network call anywhere in this file.
 */

const EOCD_SIG = 0x06054b50;
const EOCD64_LOCATOR_SIG = 0x07064b50;
const CD_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;

function findEOCD(dv) {
  // EOCD is at the end, but a trailing comment can push it back up to 64 KiB.
  const max = Math.min(dv.byteLength, 0xffff + 22);
  for (let i = 22; i <= max; i++) {
    const off = dv.byteLength - i;
    if (off < 0) break;
    if (dv.getUint32(off, true) === EOCD_SIG) return off;
  }
  return -1;
}

/** List entries without decompressing anything. Cheap enough for huge archives. */
export function listEntries(buffer) {
  const dv = new DataView(buffer);
  const eocd = findEOCD(dv);
  if (eocd < 0) throw new Error('Not a ZIP archive (no end-of-central-directory record)');

  let count = dv.getUint16(eocd + 10, true);
  let cdOffset = dv.getUint32(eocd + 16, true);

  // ZIP64: the 32-bit fields saturate and the real values live in the ZIP64 EOCD.
  if (cdOffset === 0xffffffff || count === 0xffff) {
    for (let i = eocd - 20; i >= 0; i--) {
      if (dv.getUint32(i, true) === EOCD64_LOCATOR_SIG) {
        const z64 = Number(dv.getBigUint64(i + 8, true));
        count = Number(dv.getBigUint64(z64 + 32, true));
        cdOffset = Number(dv.getBigUint64(z64 + 48, true));
        break;
      }
    }
  }

  const dec = new TextDecoder();
  const entries = [];
  let p = cdOffset;
  for (let i = 0; i < count && p + 46 <= dv.byteLength; i++) {
    if (dv.getUint32(p, true) !== CD_SIG) break;
    const method = dv.getUint16(p + 10, true);
    const compressed = dv.getUint32(p + 20, true);
    const uncompressed = dv.getUint32(p + 24, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const localOffset = dv.getUint32(p + 42, true);
    const name = dec.decode(new Uint8Array(buffer, p + 46, nameLen));
    const dosTime = dv.getUint16(p + 12, true);
    const dosDate = dv.getUint16(p + 14, true);
    entries.push({
      name, method, compressed, uncompressed, localOffset,
      isDir: name.endsWith('/'),
      modified: dosDate ? new Date(
        1980 + ((dosDate >> 9) & 0x7f), ((dosDate >> 5) & 0x0f) - 1, dosDate & 0x1f,
        (dosTime >> 11) & 0x1f, (dosTime >> 5) & 0x3f, (dosTime & 0x1f) * 2) : null,
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

/** Decompress one entry to bytes. */
export async function readEntry(buffer, entry) {
  const dv = new DataView(buffer);
  const lo = entry.localOffset;
  if (dv.getUint32(lo, true) !== LFH_SIG) throw new Error(`Bad local header for ${entry.name}`);
  const nameLen = dv.getUint16(lo + 26, true);
  const extraLen = dv.getUint16(lo + 28, true);
  const dataStart = lo + 30 + nameLen + extraLen;
  const raw = new Uint8Array(buffer, dataStart, entry.compressed);

  if (entry.method === 0) return raw.slice();           // stored
  if (entry.method !== 8) throw new Error(`Unsupported compression method ${entry.method}`);

  const ds = new DecompressionStream('deflate-raw');
  const stream = new Blob([raw]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export async function readEntryText(buffer, entry) {
  return new TextDecoder().decode(await readEntry(buffer, entry));
}
