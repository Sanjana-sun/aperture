/* Aperture — format dispatcher for PNG and WebP, alongside the JPEG reader.
 *
 * PNG carries text in tEXt / zTXt / iTXt chunks and may carry a full EXIF block in
 * eXIf. WebP is a RIFF container whose EXIF, XMP and ICCP chunks hold the same
 * information. Both are stripped the same way as JPEG: drop the metadata chunks,
 * copy the image data verbatim.
 */

import { analyse as analyseJpeg, strip as stripJpeg, parseExif, exifCarrier } from './exif.js';
import { detectIsobmff, analyseHeic, stripHeic } from './heic.js';

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

export function detectFormat(b) {
  if (b.length > 3 && b[0] === 0xff && b[1] === 0xd8) return 'jpeg';
  if (b.length > 8 && PNG_SIG.every((v, i) => b[i] === v)) return 'png';
  if (b.length > 12 &&
      b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return 'webp';
  return detectIsobmff(b);
}
// ---------------------------------------------------------------- PNG

// Chunks that carry metadata rather than pixels.
// iCCP is included deliberately: an ICC profile often names the capture device or
// scanner, and WebP's ICCP was already being stripped. Leaving PNG's in place made
// the same profile survive in one format and vanish in the other.
const PNG_META = new Set(['tEXt', 'zTXt', 'iTXt', 'eXIf', 'tIME', 'pHYs', 'sPLT', 'iCCP']);

function pngChunks(b) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const out = [];
  let off = 8;
  while (off + 8 <= b.length) {
    const len = dv.getUint32(off);
    const type = String.fromCharCode(b[off + 4], b[off + 5], b[off + 6], b[off + 7]);
    if (off + 12 + len > b.length) break;         // malformed; stop before trusting it
    out.push({ type, start: off, length: 12 + len, dataStart: off + 8, dataLen: len });
    if (type === 'IEND') break;
    off += 12 + len;
  }
  return out;
}

function pngText(b, c) {
  const dec = new TextDecoder('latin1');
  const raw = b.subarray(c.dataStart, c.dataStart + c.dataLen);
  const nul = raw.indexOf(0);
  if (nul < 0) return null;
  const key = dec.decode(raw.subarray(0, nul));
  if (c.type === 'tEXt') return { key, value: dec.decode(raw.subarray(nul + 1)) };
  if (c.type === 'iTXt') {
    // key \0 compressionFlag compressionMethod langTag \0 translatedKey \0 text
    const flag = raw[nul + 1];
    if (flag !== 0) return { key, value: '(compressed text)' };
    let p = nul + 3;
    const l1 = raw.indexOf(0, p); if (l1 < 0) return null;
    const l2 = raw.indexOf(0, l1 + 1); if (l2 < 0) return null;
    return { key, value: dec.decode(raw.subarray(l2 + 1)) };
  }
  return { key, value: '(compressed text)' };
}

function analysePng(b) {
  const chunks = pngChunks(b);
  const meta = chunks.filter(c => PNG_META.has(c.type));
  const findings = [];
  let coords = null;

  for (const c of meta) {
    if (c.type === 'tEXt' || c.type === 'iTXt' || c.type === 'zTXt') {
      const t = pngText(b, c);
      if (t && t.value) findings.push({ name: `PNG text: ${t.key}`, value: t.value.slice(0, 300) });
    } else if (c.type === 'eXIf') {
      const carrier = exifCarrier(b, c.dataStart, c.dataLen);
      const parsed = carrier && parseExif(carrier, { start: 0 });
      const tags = parsed ? [...parsed.tiff, ...parsed.exif, ...parsed.gps] : [];
      if (tags.length) { findings.push(...tags); coords = parsed.coords || coords; }
      else findings.push({ name: 'PNG eXIf block (unparsed)', value: `${c.dataLen} bytes` });
    } else {
      findings.push({ name: `PNG ${c.type} chunk`, value: `${c.dataLen} bytes` });
    }
  }
  return {
    format: 'png',
    segments: chunks.map(c => ({ name: `${c.type} chunk`, length: c.length, isMeta: PNG_META.has(c.type) })),
    metaSegments: meta.map(c => ({ name: `${c.type} chunk`, length: c.length })),
    metaBytes: meta.reduce((n, c) => n + c.length, 0),
    findings, coords,
  };
}

function stripPng(b) {
  const chunks = pngChunks(b);
  const keep = [b.subarray(0, 8)];
  let removedBytes = 0;
  const removed = [];
  for (const c of chunks) {
    if (PNG_META.has(c.type)) { removedBytes += c.length; removed.push(`${c.type} chunk`); }
    else keep.push(b.subarray(c.start, c.start + c.length));
  }
  const total = keep.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let o = 0; for (const a of keep) { out.set(a, o); o += a.length; }
  return { bytes: out, removedBytes, removed };
}

// ---------------------------------------------------------------- WebP

const WEBP_META = new Set(['EXIF', 'XMP ', 'ICCP']);

function webpChunks(b) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const out = [];
  let off = 12;
  while (off + 8 <= b.length) {
    const type = String.fromCharCode(b[off], b[off + 1], b[off + 2], b[off + 3]);
    const len = dv.getUint32(off + 4, true);
    const padded = len + (len % 2);
    if (off + 8 + padded > b.length) break;       // truncated final chunk
    out.push({ type, start: off, length: 8 + padded, dataStart: off + 8, dataLen: len });
    off += 8 + padded;
  }
  return out;
}

function analyseWebp(b) {
  const chunks = webpChunks(b);
  const meta = chunks.filter(c => WEBP_META.has(c.type));
  const findings = [];
  let coords = null;
  for (const c of meta) {
    if (c.type === 'EXIF') {
      const carrier = exifCarrier(b, c.dataStart, c.dataLen);
      const parsed = carrier && parseExif(carrier, { start: 0 });
      const tags = parsed ? [...parsed.tiff, ...parsed.exif, ...parsed.gps] : [];
      if (tags.length) { findings.push(...tags); coords = parsed.coords || coords; }
      // Always report the chunk itself. Removing bytes while reporting nothing
      // found reads as a contradiction to the user.
      else findings.push({ name: 'WebP EXIF chunk (unparsed)', value: `${c.dataLen} bytes` });
    } else {
      findings.push({ name: `WebP ${c.type.trim()} chunk`, value: `${c.dataLen} bytes` });
    }
  }
  return {
    format: 'webp',
    segments: chunks.map(c => ({ name: `${c.type.trim()} chunk`, length: c.length, isMeta: WEBP_META.has(c.type) })),
    metaSegments: meta.map(c => ({ name: `${c.type.trim()} chunk`, length: c.length })),
    metaBytes: meta.reduce((n, c) => n + c.length, 0),
    findings, coords,
  };
}

function stripWebp(b) {
  const chunks = webpChunks(b);
  const keep = [];
  let removedBytes = 0;
  const removed = [];
  for (const c of chunks) {
    if (WEBP_META.has(c.type)) { removedBytes += c.length; removed.push(`${c.type.trim()} chunk`); }
    else keep.push(b.subarray(c.start, c.start + c.length));
  }
  const body = keep.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(12 + body);
  out.set(b.subarray(0, 12));
  let o = 12; for (const a of keep) { out.set(a, o); o += a.length; }
  new DataView(out.buffer).setUint32(4, out.length - 8, true);   // fix RIFF size

  // An extended WebP announces which optional chunks exist in the VP8X feature
  // byte. Removing the chunks without clearing those bits leaves a file that
  // claims metadata it no longer carries, which some decoders reject.
  // Bit layout, MSB first: Rsv Rsv ICC Alpha EXIF XMP Anim Rsv.
  if (out.length >= 21 && String.fromCharCode(out[12], out[13], out[14], out[15]) === 'VP8X') {
    out[20] &= ~(0x20 | 0x08 | 0x04);            // ICC, EXIF, XMP
  }
  return { bytes: out, removedBytes, removed };
}

// ---------------------------------------------------------------- dispatch

export function analyseImage(b) {
  const f = detectFormat(b);
  if (f === 'jpeg') return { format: 'jpeg', ...analyseJpeg(b) };
  if (f === 'png') return analysePng(b);
  if (f === 'webp') return analyseWebp(b);
  if (f === 'heic' || f === 'avif') return analyseHeic(b, f);
  throw new Error('Unsupported format. Aperture reads JPEG, PNG, WebP, HEIC and AVIF.');
}

export function stripImage(b) {
  const f = detectFormat(b);
  if (f === 'jpeg') return stripJpeg(b);
  if (f === 'png') return stripPng(b);
  if (f === 'webp') return stripWebp(b);
  if (f === 'heic' || f === 'avif') return stripHeic(b);
  throw new Error('Unsupported format');
}

export const MIME = { jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp',
                      heic: 'image/heic', avif: 'image/avif' };
