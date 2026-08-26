/* Aperture — HEIC / HEIF / AVIF metadata reader and scrubber.
 *
 * HEIC is what an iPhone shoots by default, so a photo privacy tool that cannot
 * read it has a hole where most of its users are.
 *
 * The reason this is tractable without a HEVC decoder: none of the metadata lives
 * in the compressed image. A HEIC file is ISOBMFF, the same box container as MP4.
 * The picture is one *item*, the EXIF block is another item, XMP is a third, and a
 * table called `iloc` says where each item's bytes sit in the file. So reading the
 * EXIF means walking boxes and following an offset. The HEVC bitstream is never
 * touched or understood.
 *
 * AVIF uses the identical container with an av01 image item, so the same code
 * reads it for free.
 */

import { parseExif, exifCarrier } from './exif.js';

// Brands that mean "ISOBMFF still image", from ISO/IEC 23008-12 and the AVIF spec.
const HEIF_BRANDS = new Set(['heic', 'heix', 'hevc', 'hevx', 'heim', 'heis', 'hevm',
                             'hevs', 'mif1', 'msf1', 'miaf']);
const AVIF_BRANDS = new Set(['avif', 'avis']);

const fourcc = (b, o) => String.fromCharCode(b[o], b[o + 1], b[o + 2], b[o + 3]);

/** Identify a HEIF-family file from its ftyp brands. Returns 'heic', 'avif' or null. */
export function detectIsobmff(b) {
  if (b.length < 16 || fourcc(b, 4) !== 'ftyp') return null;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const size = Math.min(dv.getUint32(0), b.length);
  const brands = [fourcc(b, 8)];
  for (let o = 16; o + 4 <= size; o += 4) brands.push(fourcc(b, o));
  if (brands.some(x => AVIF_BRANDS.has(x))) return 'avif';
  if (brands.some(x => HEIF_BRANDS.has(x))) return 'heic';
  return null;
}

/** Walk sibling boxes in [start, end). Tolerates truncation by stopping early. */
function* boxes(b, start, end) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let off = start;
  while (off + 8 <= end) {
    let size = dv.getUint32(off);
    const type = fourcc(b, off + 4);
    let hdr = 8;
    if (size === 1) {
      if (off + 16 > end) break;
      size = Number(dv.getBigUint64(off + 8));
      hdr = 16;
    }
    if (size === 0) size = end - off;              // "extends to end of file"
    if (size < hdr || off + size > end) break;     // malformed; stop before trusting it
    yield { type, start: off, size, body: off + hdr, end: off + size };
    off += size;
  }
}

function findBox(b, start, end, type) {
  for (const box of boxes(b, start, end)) if (box.type === type) return box;
  return null;
}

const cstr = (b, p, limit) => {
  let e = p;
  while (e < limit && b[e] !== 0) e++;
  return [new TextDecoder().decode(b.subarray(p, e)), e + 1];
};

/** iinf: item id -> { type, name, contentType } */
function parseIinf(b, meta) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const iinf = findBox(b, meta.body + 4, meta.end, 'iinf');   // meta is a FullBox
  const items = new Map();
  if (!iinf) return items;
  const ver = b[iinf.body];
  let p = iinf.body + 4;
  p += ver === 0 ? 2 : 4;                                     // entry_count
  for (const inf of boxes(b, p, iinf.end)) {
    if (inf.type !== 'infe') continue;
    const v = b[inf.body];
    let q = inf.body + 4;
    let id;
    if (v < 2) continue;                                      // v0/v1 predate item_type
    if (v === 2) { id = dv.getUint16(q); q += 2; }
    else { id = dv.getUint32(q); q += 4; }
    q += 2;                                                   // protection index
    const type = fourcc(b, q); q += 4;
    let name, contentType = null;
    [name, q] = cstr(b, q, inf.end);
    if (type === 'mime') [contentType, q] = cstr(b, q, inf.end);
    items.set(id, { type, name, contentType });
  }
  return items;
}

/** iloc: item id -> [{ offset, length }], absolute file offsets. */
function parseIloc(b, meta) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const iloc = findBox(b, meta.body + 4, meta.end, 'iloc');
  const locs = new Map();
  if (!iloc) return locs;
  const ver = b[iloc.body];
  let p = iloc.body + 4;
  const offSize = b[p] >> 4, lenSize = b[p] & 15;
  const baseSize = b[p + 1] >> 4, idxSize = b[p + 1] & 15;
  p += 2;
  let count;
  if (ver < 2) { count = dv.getUint16(p); p += 2; } else { count = dv.getUint32(p); p += 4; }
  const rd = (n) => { if (n === 0) return 0; let v = 0; for (let i = 0; i < n; i++) v = v * 256 + b[p + i]; p += n; return v; };
  for (let i = 0; i < count && p < iloc.end; i++) {
    let id;
    if (ver < 2) { id = dv.getUint16(p); p += 2; } else { id = dv.getUint32(p); p += 4; }
    let construction = 0;
    if (ver === 1 || ver === 2) { construction = dv.getUint16(p); p += 2; }
    p += 2;                                                   // data_reference_index
    const base = rd(baseSize);
    const extCount = dv.getUint16(p); p += 2;
    const extents = [];
    for (let e = 0; e < extCount; e++) {
      if (idxSize > 0 && (ver === 1 || ver === 2)) rd(idxSize);
      const offset = base + rd(offSize);
      const length = rd(lenSize);
      extents.push({ offset, length });
    }
    // construction_method 1 means the bytes live inside an idat box rather than at a
    // file offset. We do not follow that; reporting it is better than guessing.
    locs.set(id, { extents, construction });
  }
  return locs;
}

const XMP_TYPE = 'application/rdf+xml';

/**
 * True if an item's bytes carry nothing. After stripHeic the items are still
 * declared by the container but their payloads are blank, and reporting a blank
 * payload as a finding would tell the user metadata is still there when it is not.
 */
function isBlank(b, offset, length) {
  for (let i = offset; i < offset + length; i++) {
    const v = b[i];
    if (v !== 0 && v !== 0x20) return false;
  }
  return true;
}

/** Locate the metadata items and where their bytes are. */
function metaItems(b) {
  const meta = findBox(b, 0, b.length, 'meta');
  if (!meta) return [];
  const items = parseIinf(b, meta);
  const locs = parseIloc(b, meta);
  const out = [];
  for (const [id, info] of items) {
    const loc = locs.get(id);
    if (!loc) continue;
    let kind = null;
    if (info.type === 'Exif') kind = 'exif';
    else if (info.type === 'mime' && info.contentType === XMP_TYPE) kind = 'xmp';
    else if (info.type === 'mime') kind = 'mime';
    if (!kind) continue;
    for (const ext of loc.extents) {
      if (ext.offset + ext.length > b.length) continue;       // truncated file
      out.push({ id, kind, info, ...ext, construction: loc.construction });
    }
  }
  return out;
}

/**
 * The EXIF item payload is an ExifDataBlock: a four-byte big-endian count of bytes
 * to skip before the TIFF header, then usually the "Exif\0\0" magic, then TIFF.
 */
function exifTiffRange(b, offset, length) {
  if (length < 8) return null;
  const skip = new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(offset);
  const at = offset + 4 + skip;
  const len = length - 4 - skip;
  return (len > 0 && at + len <= b.length) ? { at, len } : null;
}

/** An EXIF item that is blank, or whose IFD0 declares zero entries, holds nothing. */
function emptyExif(b, it, r) {
  if (isBlank(b, it.offset + 10, it.length - 10)) return true;   // past the magic
  if (!r || r.len < 10) return false;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const be = b[r.at] === 0x4d;
  const ifd = be ? dv.getUint32(r.at + 4) : dv.getUint32(r.at + 4, true);
  if (ifd + 2 > r.len) return false;
  const n = be ? dv.getUint16(r.at + ifd) : dv.getUint16(r.at + ifd, true);
  return n === 0;
}

export function analyseHeic(b, format = 'heic') {
  const items = metaItems(b);
  const findings = [];
  let coords = null;

  for (const it of items) {
    if (it.construction !== 0) {
      findings.push({ name: `${it.kind.toUpperCase()} item (stored in idat)`, value: `${it.length} bytes` });
      continue;
    }
    if (it.kind === 'exif') {
      const r = exifTiffRange(b, it.offset, it.length);
      const carrier = r && exifCarrier(b, r.at, r.len);
      const parsed = carrier && parseExif(carrier, { start: 0 });
      const tags = parsed ? [...parsed.tiff, ...parsed.exif, ...parsed.gps] : [];
      if (tags.length) { findings.push(...tags); coords = parsed.coords || coords; }
      else if (!emptyExif(b, it, r)) {
        findings.push({ name: 'HEIC EXIF item (unparsed)', value: `${it.length} bytes` });
      }
    } else if (it.kind === 'xmp') {
      if (isBlank(b, it.offset, it.length)) continue;
      const text = new TextDecoder().decode(b.subarray(it.offset, it.offset + Math.min(it.length, 400)));
      findings.push({ name: 'HEIC XMP packet', value: text.replace(/\s+/g, ' ').slice(0, 300) });
    } else {
      if (isBlank(b, it.offset, it.length)) continue;
      findings.push({ name: `HEIC ${it.info.contentType || 'mime'} item`, value: `${it.length} bytes` });
    }
  }

  const top = [...boxes(b, 0, b.length)].map(x => ({
    name: `${x.type} box`, length: x.size, isMeta: x.type === 'meta',
  }));
  return {
    format,
    segments: top,
    metaSegments: items.map(i => ({ name: `${i.kind} item`, length: i.length })),
    metaBytes: items.reduce((n, i) => n + i.length, 0),
    findings, coords,
  };
}

/**
 * Scrub metadata in place, leaving every box and offset untouched.
 *
 * iloc stores *absolute file offsets*, and in a real iPhone file the image item
 * usually sits after the EXIF item. Deleting bytes would shift the picture and
 * invalidate every offset in the table, so a "remove the segment" strip like the
 * JPEG one would mean rewriting iloc, iinf and iref and hoping nothing else in the
 * file refers to a position. Overwriting the payload where it lies removes exactly
 * the same information with none of that risk: the file stays the same length, the
 * boxes stay valid, and the HEVC bitstream is untouched.
 *
 * The file therefore still declares an EXIF item. That item just no longer contains
 * anything about you, which is the property that matters.
 */
export function stripHeic(b) {
  const out = b.slice();
  const items = metaItems(b);
  let removedBytes = 0;
  const removed = [];

  for (const it of items) {
    if (it.construction !== 0) continue;                       // not at a file offset
    out.fill(0, it.offset, it.offset + it.length);
    if (it.kind === 'exif' && it.length >= 24) {
      // Leave a well-formed but empty EXIF block so strict readers do not choke:
      // skip-count 6, "Exif\0\0", big-endian TIFF header, an IFD with zero entries.
      const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
      dv.setUint32(it.offset, 6);
      out.set([0x45, 0x78, 0x69, 0x66, 0, 0], it.offset + 4);
      out.set([0x4d, 0x4d, 0x00, 0x2a], it.offset + 10);
      dv.setUint32(it.offset + 14, 8);                         // IFD0 at offset 8
      dv.setUint16(it.offset + 18, 0);                         // zero entries
      dv.setUint32(it.offset + 20, 0);                         // no next IFD
    }
    removedBytes += it.length;
    removed.push(`${it.kind.toUpperCase()} item`);
  }
  return { bytes: out, removedBytes, removed, inPlace: true };
}
