/* Adversarial tests, part 3: the HEIF/HEIC container.
 *
 * All fixtures built in memory by helpers.mjs, so these run anywhere.
 */
import { analyseImage, stripImage, detectFormat } from '../src/image.js';
import { makeHeic, exifItem, tinyTiff, ftyp, box } from './helpers.mjs';

let bugs = 0;
const bug = (id, m) => { bugs++; console.log(`BUG ${id}: ${m}`); };
const ok = (id, note = '') => console.log(`ok  ${id}${note ? '  ' + note : ''}`);

// P. Brand detection across the HEIF family, and AVIF sharing the container.
{
  for (const [brand, want] of [['heic','heic'], ['heix','heic'], ['mif1','heic'],
                               ['msf1','heic'], ['avif','avif'], ['mp42', null]]) {
    // mp42 is the negative case, so it must not also advertise a HEIF brand.
    const b = makeHeic({ exif: exifItem(tinyTiff('X')), brand,
                         compat: want === null ? [brand] : [brand, 'mif1'] });
    const got = detectFormat(b);
    if (got !== want) { bug('P', `brand ${brand} detected as ${got}, expected ${want}`); }
  }
  ok('P', 'brand detection incl. avif');
}

// Q. EXIF is found and stripped, and the file length never changes.
{
  const b = makeHeic({ exif: exifItem(tinyTiff('Hasselblad')) });
  const a = analyseImage(b);
  if (!a.findings.some(f => /Hasselblad/.test(String(f.value)))) {
    bug('Q', `EXIF not read from a hand-built HEIC: ${JSON.stringify(a.findings)}`);
  } else {
    const s = stripImage(b);
    const after = analyseImage(s.bytes);
    if (s.bytes.length !== b.length) bug('Q', `strip changed file length ${b.length} -> ${s.bytes.length}, which invalidates every iloc offset`);
    else if (after.findings.length) bug('Q', `metadata survived: ${JSON.stringify(after.findings)}`);
    else ok('Q', `exif read and scrubbed, ${b.length}B unchanged`);
  }
}

// R. XMP too.
{
  const b = makeHeic({ exif: exifItem(tinyTiff('X')), xmp: '<x:xmpmeta>lat 42.36</x:xmpmeta>' });
  const a = analyseImage(b);
  if (!a.findings.some(f => /xmpmeta/.test(String(f.value)))) bug('R', 'XMP item not surfaced');
  else if (analyseImage(stripImage(b).bytes).findings.length) bug('R', 'XMP survived stripping');
  else ok('R', 'xmp read and scrubbed');
}

// S. iloc version 1 adds a construction_method field; misreading it shifts every
//    subsequent field and yields garbage offsets.
{
  for (const v of [0, 1, 2]) {
    const b = makeHeic({ exif: exifItem(tinyTiff('Sigma')), ilocVersion: v });
    const a = analyseImage(b);
    if (!a.findings.some(f => /Sigma/.test(String(f.value)))) {
      bug('S', `iloc version ${v} not parsed: ${JSON.stringify(a.findings)}`);
    }
  }
  ok('S', 'iloc versions 0, 1, 2');
}

// T. construction_method 1 means the bytes are in an idat box, not at a file
//    offset. Following the offset anyway would read unrelated bytes.
{
  const b = makeHeic({ exif: exifItem(tinyTiff('Ricoh')), ilocVersion: 1, construction: 1 });
  const a = analyseImage(b);
  const claimsTag = a.findings.some(f => /Ricoh/.test(String(f.value)));
  if (claimsTag) bug('T', 'read an idat-stored item as if it were at a file offset');
  else if (!a.findings.some(f => /idat/i.test(f.name))) bug('T', `idat-stored item not reported at all: ${JSON.stringify(a.findings)}`);
  else ok('T', 'idat construction reported, not guessed');
}

// U. Truncated and malformed containers must not throw.
{
  const full = makeHeic({ exif: exifItem(tinyTiff('Pentax')) });
  const cases = {
    'truncated mid-mdat': full.slice(0, full.length - 20),
    'truncated mid-meta': full.slice(0, 60),
    'header only': full.slice(0, 16),
    'ftyp with no meta': ftyp('heic', ['heic']),
    'meta with no iloc': (() => {
      const f = ftyp('heic', ['heic']);
      const m = box('meta', new Uint8Array(4));
      const out = new Uint8Array(f.length + m.length);
      out.set(f); out.set(m, f.length); return out;
    })(),
  };
  let clean = true;
  for (const [name, b] of Object.entries(cases)) {
    try {
      if (detectFormat(b) === 'heic') { analyseImage(b); stripImage(b); }
    } catch (e) { bug('U', `${name} threw ${e.constructor.name}: ${e.message}`); clean = false; }
  }
  if (clean) ok('U', 'truncated and malformed containers handled');
}

// V. A declared extent running past the end of the file must be ignored, not read.
{
  const b = makeHeic({ exif: exifItem(tinyTiff('Nikon')) });
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  // find the iloc extent_length field and inflate it well past EOF
  let patched = false;
  for (let i = 0; i + 4 <= b.length; i++) {
    if (String.fromCharCode(b[i], b[i+1], b[i+2], b[i+3]) === 'iloc') {
      dv.setUint32(i + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 4, 0x7fffffff);  // extent_length
      patched = true; break;
    }
  }
  try {
    const a = analyseImage(b);
    ok('V', `oversized extent ignored (${a.findings.length} findings, patched=${patched})`);
  } catch (e) { bug('V', `oversized extent threw ${e.constructor.name}: ${e.message}`); }
}

console.log(bugs ? `\n${bugs} bug(s) confirmed` : '\nno bugs in this batch');
process.exit(bugs ? 1 : 0);
