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
const ZIP64_EXTRA_ID = 0x0001;

// Code page 437, high half. ZIP stores names in CP437 unless general-purpose bit
// 11 says UTF-8, and TextDecoder has no cp437 label, so carry the table.
const CP437_HIGH =
  'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»' +
  '░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀' +
  'αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u00a0';

function decodeName(bytes, utf8) {
  if (utf8) return new TextDecoder().decode(bytes);
  let out = '';
  for (const b of bytes) out += b < 0x80 ? String.fromCharCode(b) : CP437_HIGH[b - 0x80];
  return out;
}

/**
 * Read the ZIP64 extended-information extra field.
 *
 * The 32-bit size and offset fields saturate at 0xffffffff and the real 64-bit
 * values move into this extra field. Only the saturated fields are present, in a
 * fixed order, so which ones to read depends on the base record.
 */
function zip64Extra(dv, start, len, base) {
  let p = start;
  const end = start + len;
  while (p + 4 <= end) {
    const id = dv.getUint16(p, true);
    const size = dv.getUint16(p + 2, true);
    if (id === ZIP64_EXTRA_ID) {
      let q = p + 4;
      const out = {};
      if (base.uncompressed === 0xffffffff && q + 8 <= end) { out.uncompressed = Number(dv.getBigUint64(q, true)); q += 8; }
      if (base.compressed === 0xffffffff && q + 8 <= end) { out.compressed = Number(dv.getBigUint64(q, true)); q += 8; }
      if (base.localOffset === 0xffffffff && q + 8 <= end) { out.localOffset = Number(dv.getBigUint64(q, true)); q += 8; }
      return out;
    }
    p += 4 + size;
  }
  return {};
}

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

  const entries = [];
  let p = cdOffset;
  for (let i = 0; i < count && p + 46 <= dv.byteLength; i++) {
    if (dv.getUint32(p, true) !== CD_SIG) break;
    const flags = dv.getUint16(p + 8, true);
    const method = dv.getUint16(p + 10, true);
    const compressed = dv.getUint32(p + 20, true);
    const uncompressed = dv.getUint32(p + 24, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const localOffset = dv.getUint32(p + 42, true);
    if (p + 46 + nameLen + extraLen + commentLen > dv.byteLength) break;
    const name = decodeName(new Uint8Array(buffer, p + 46, nameLen), (flags & 0x800) !== 0);
    const z64 = zip64Extra(dv, p + 46 + nameLen, extraLen,
                           { compressed, uncompressed, localOffset });
    const dosTime = dv.getUint16(p + 12, true);
    const dosDate = dv.getUint16(p + 14, true);
    entries.push({
      name, method,
      compressed: z64.compressed ?? compressed,
      uncompressed: z64.uncompressed ?? uncompressed,
      localOffset: z64.localOffset ?? localOffset,
      encrypted: (flags & 0x1) !== 0,
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
  if (entry.encrypted) throw new Error(`${entry.name} is encrypted; Aperture cannot read password-protected archives`);
  if (lo + 30 > dv.byteLength) throw new Error(`Local header for ${entry.name} is past the end of the archive`);
  if (dv.getUint32(lo, true) !== LFH_SIG) throw new Error(`Bad local header for ${entry.name}`);
  const nameLen = dv.getUint16(lo + 26, true);
  const extraLen = dv.getUint16(lo + 28, true);
  const dataStart = lo + 30 + nameLen + extraLen;
  if (dataStart + entry.compressed > dv.byteLength) {
    throw new Error(`${entry.name} is truncated: the archive ends before its data does`);
  }
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
