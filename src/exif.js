/* Aperture — JPEG metadata reader and stripper.
 *
 * No dependencies. Parses the JPEG segment structure directly, reads EXIF/TIFF
 * IFDs, and strips metadata by *removing marker segments* rather than re-encoding
 * through a canvas. That distinction matters: canvas re-encode changes every pixel
 * and degrades the image; segment removal leaves the compressed scan data
 * byte-identical.
 */

// ---------------------------------------------------------------- tag tables

// Only the tags that carry privacy weight. A full EXIF table would be noise.
const TIFF_TAGS = {
  0x010f: 'Camera make',
  0x0110: 'Camera model',
  0x0131: 'Software',
  0x0132: 'Date and time',
  0x013b: 'Artist',
  0x8298: 'Copyright',
  0x8769: '__EXIF_IFD',
  0x8825: '__GPS_IFD',
};

const EXIF_TAGS = {
  0x9003: 'Date taken (original)',
  0x9004: 'Date digitised',
  0x9286: 'User comment',
  0xa420: 'Image unique ID',
  0xa430: 'Camera owner name',
  0xa431: 'Body serial number',
  0xa432: 'Lens specification',
  0xa433: 'Lens make',
  0xa434: 'Lens model',
  0xa435: 'Lens serial number',
};

const GPS_TAGS = {
  0x0001: 'GPS latitude ref',
  0x0002: 'GPS latitude',
  0x0003: 'GPS longitude ref',
  0x0004: 'GPS longitude',
  0x0005: 'GPS altitude ref',
  0x0006: 'GPS altitude',
  0x0007: 'GPS timestamp',
  0x001d: 'GPS date',
  0x001b: 'GPS processing method',
};

// Bytes per TIFF component type, indexed by type id.
const TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8 };

const SEGMENT_NAMES = {
  0xe0: 'JFIF (APP0)', 0xe1: 'EXIF / XMP (APP1)', 0xe2: 'ICC profile (APP2)',
  0xe3: 'APP3', 0xe4: 'APP4', 0xe5: 'APP5', 0xe6: 'APP6', 0xe7: 'APP7',
  0xe8: 'APP8', 0xe9: 'APP9', 0xea: 'APP10', 0xeb: 'APP11',
  0xec: 'Picture info (APP12)', 0xed: 'Photoshop IRB (APP13)',
  0xee: 'Adobe (APP14)', 0xef: 'APP15', 0xfe: 'Comment',
};

// ---------------------------------------------------------------- segment scan

/** Walk the JPEG marker structure. Returns segments up to the start of scan. */
export function scanSegments(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (dv.getUint16(0) !== 0xffd8) throw new Error('Not a JPEG (no SOI marker)');

  const segments = [];
  let off = 2;
  while (off < bytes.length - 1) {
    if (dv.getUint8(off) !== 0xff) break;          // desync; stop rather than guess
    const marker = dv.getUint8(off + 1);
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      off += 2; continue;                           // standalone markers, no length
    }
    if (marker === 0xda || marker === 0xd9) {       // SOS / EOI: image data follows
      segments.push({ marker, start: off, length: 0, name: 'Scan data', isMeta: false });
      break;
    }
    const length = dv.getUint16(off + 2);
    segments.push({
      marker,
      start: off,
      length: length + 2,
      name: SEGMENT_NAMES[marker] || `Marker 0x${marker.toString(16)}`,
      isMeta: (marker >= 0xe0 && marker <= 0xef) || marker === 0xfe,
    });
    off += 2 + length;
  }
  return segments;
}

// ---------------------------------------------------------------- EXIF parsing

function readRational(dv, off, little) {
  const n = dv.getUint32(off, little);
  const d = dv.getUint32(off + 4, little);
  return d === 0 ? 0 : n / d;
}

function readValue(dv, entryOff, tiffStart, little) {
  const type = dv.getUint16(entryOff + 2, little);
  const count = dv.getUint32(entryOff + 4, little);
  const size = (TYPE_SIZE[type] || 1) * count;
  const valOff = size <= 4 ? entryOff + 8 : tiffStart + dv.getUint32(entryOff + 8, little);
  if (valOff + size > dv.byteLength) return null;    // malformed; refuse to guess

  switch (type) {
    case 2: {                                        // ASCII
      let s = '';
      for (let i = 0; i < count - 1; i++) s += String.fromCharCode(dv.getUint8(valOff + i));
      return s.replace(/\0+$/, '').trim();
    }
    case 1: case 6: case 7:
      return count === 1 ? dv.getUint8(valOff) : `${count} bytes`;
    case 3: case 8:
      return dv.getUint16(valOff, little);
    case 4: case 9:
      return dv.getUint32(valOff, little);
    case 5: case 10: {                               // RATIONAL
      if (count === 1) return readRational(dv, valOff, little);
      const arr = [];
      for (let i = 0; i < Math.min(count, 3); i++) arr.push(readRational(dv, valOff + i * 8, little));
      return arr;
    }
    default:
      return null;
  }
}

function parseIFD(dv, ifdOff, tiffStart, little, table, out, pointers) {
  if (ifdOff + 2 > dv.byteLength) return;
  const count = dv.getUint16(ifdOff, little);
  for (let i = 0; i < count; i++) {
    const e = ifdOff + 2 + i * 12;
    if (e + 12 > dv.byteLength) return;
    const tag = dv.getUint16(e, little);
    const name = table[tag];
    if (!name) continue;
    if (name.startsWith('__')) {
      pointers[name] = tiffStart + dv.getUint32(e + 8, little);
      continue;
    }
    const value = readValue(dv, e, tiffStart, little);
    if (value !== null && value !== '') out.push({ tag, name, value });
  }
}

/** Convert EXIF GPS rationals to signed decimal degrees. */
function toDecimal(dms, ref) {
  if (!Array.isArray(dms) || dms.length < 2) return null;
  const [d, m, s = 0] = dms;
  let dec = d + m / 60 + s / 3600;
  if (ref === 'S' || ref === 'W') dec = -dec;
  return dec;
}

/** Read EXIF from an APP1 segment. Returns { tiff, exif, gps, coords }. */
export function parseExif(bytes, seg) {
  const base = seg.start + 4;                        // skip marker + length
  // "Exif\0\0"
  const isExif = bytes[base] === 0x45 && bytes[base + 1] === 0x78 &&
                 bytes[base + 2] === 0x69 && bytes[base + 3] === 0x66;
  if (!isExif) return null;

  const tiffStart = base + 6;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const bom = dv.getUint16(tiffStart);
  if (bom !== 0x4949 && bom !== 0x4d4d) return null;
  const little = bom === 0x4949;
  if (dv.getUint16(tiffStart + 2, little) !== 0x002a) return null;

  const ifd0 = tiffStart + dv.getUint32(tiffStart + 4, little);
  const tiff = [], exif = [], gps = [], pointers = {};
  parseIFD(dv, ifd0, tiffStart, little, TIFF_TAGS, tiff, pointers);
  if (pointers.__EXIF_IFD) parseIFD(dv, pointers.__EXIF_IFD, tiffStart, little, EXIF_TAGS, exif, pointers);
  if (pointers.__GPS_IFD) parseIFD(dv, pointers.__GPS_IFD, tiffStart, little, GPS_TAGS, gps, pointers);

  // Resolve coordinates if both value and hemisphere are present.
  let coords = null;
  const lat = gps.find(g => g.tag === 0x0002), latRef = gps.find(g => g.tag === 0x0001);
  const lon = gps.find(g => g.tag === 0x0004), lonRef = gps.find(g => g.tag === 0x0003);
  if (lat && lon) {
    const la = toDecimal(lat.value, latRef?.value);
    const lo = toDecimal(lon.value, lonRef?.value);
    if (la !== null && lo !== null) coords = { lat: la, lon: lo };
  }
  return { tiff, exif, gps, coords };
}

// ---------------------------------------------------------------- stripping

/**
 * Remove every metadata segment. Scan data is copied verbatim, so the decoded
 * image is bit-identical to the original — unlike a canvas round-trip.
 */
export function strip(bytes) {
  const segments = scanSegments(bytes);
  const keep = [];
  let removedBytes = 0;
  const removed = [];

  keep.push(bytes.subarray(0, 2));                   // SOI
  for (const s of segments) {
    if (s.name === 'Scan data') {
      keep.push(bytes.subarray(s.start));            // rest of file, verbatim
      break;
    }
    if (s.isMeta) {
      removedBytes += s.length;
      removed.push(s.name);
    } else {
      keep.push(bytes.subarray(s.start, s.start + s.length));
    }
  }

  const total = keep.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const a of keep) { out.set(a, o); o += a.length; }
  return { bytes: out, removedBytes, removed };
}

/** Full analysis of one file. */
export function analyse(bytes) {
  const segments = scanSegments(bytes);
  const app1 = segments.find(s => s.marker === 0xe1);
  const exifData = app1 ? parseExif(bytes, app1) : null;
  const metaSegments = segments.filter(s => s.isMeta);
  return {
    segments,
    metaSegments,
    metaBytes: metaSegments.reduce((n, s) => n + s.length, 0),
    exif: exifData,
    findings: exifData
      ? [...exifData.tiff, ...exifData.exif, ...exifData.gps]
      : [],
    coords: exifData?.coords || null,
  };
}

const EXIF_MAGIC = [0x45, 0x78, 0x69, 0x66, 0x00, 0x00];

/**
 * Wrap a raw EXIF payload so the JPEG parser can read it.
 *
 * parseExif expects a JPEG APP1 segment: two marker bytes, two length bytes,
 * "Exif\0\0", then the TIFF block. PNG eXIf chunks hold a bare TIFF block, but
 * WebP encoders disagree with each other about whether to include the "Exif\0\0"
 * magic. Prefixing unconditionally double-prefixed the ones that already had it,
 * so those parsed as nothing and were reported as an unreadable blob.
 */
export function exifCarrier(b, start, len) {
  const hasMagic = len >= 6 && EXIF_MAGIC.every((v, i) => b[start + i] === v);
  const tiffAt = hasMagic ? start + 6 : start;
  const tiffLen = hasMagic ? len - 6 : len;
  if (tiffLen <= 0) return null;
  const carrier = new Uint8Array(4 + 6 + tiffLen);
  carrier.set(EXIF_MAGIC, 4);
  carrier.set(b.subarray(tiffAt, tiffAt + tiffLen), 10);
  return carrier;
}

export function detectFormat(b) {
  if (b.length > 3 && b[0] === 0xff && b[1] === 0xd8) return 'jpeg';
  if (b.length > 8 && PNG_SIG.every((v, i) => b[i] === v)) return 'png';
  if (b.length > 12 &&
      b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return 'webp';
  return null;
}
