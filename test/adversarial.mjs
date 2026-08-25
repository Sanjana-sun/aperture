import { scanText, redactText } from '../src/pii.js';
import { plotPoints } from '../src/deepscan.js';
import { detectFormat, analyseImage, stripImage } from '../src/image.js';
import { listEntries } from '../src/zip.js';

let bugs = 0;
const bug = (id, msg) => { bugs++; console.log(`BUG ${id}: ${msg}`); };
const ok  = (id) => console.log(`ok  ${id}`);

// A. severity inversion: an earlier LOW match must not suppress a later HIGH one.
{
  const t = 'ref 90210 and card 4111 1111 1111 1111 here';
  const f = scanText(t);
  const labels = f.map(x => x.label);
  const t2 = 'zip 02115-1234 born 12/05/1999';
  const f2 = scanText(t2);
  console.log('   A1', JSON.stringify(f.map(x=>[x.label,x.start,x.end])));
  console.log('   A2', JSON.stringify(f2.map(x=>[x.label,x.start,x.end])));
  // synthesise a guaranteed inversion: postcode(low) immediately followed by overlap
  // Force the inversion: a low-severity postcode starting one char before a
  // high-severity SSN that overlaps it.
  const t4 = '0123-45-6789';
  const f4 = scanText(t4);
  const hasSsn = f4.some(x => x.label.includes('SSN'));
  if (!hasSsn && f4.length) bug('A', `low-severity match suppressed a higher-severity overlap: ${JSON.stringify(f4.map(x=>[x.label,x.value]))}`);
  else ok('A severity ordering');
}

// B. plotPoints with a realistic large export
{
  const pts = Array.from({length: 150000}, (_,i) => ({lat:42+Math.sin(i)*0.1, lon:-71+Math.cos(i)*0.1}));
  try { const s = plotPoints(pts); ok('B plotPoints 150k'); }
  catch (e) { bug('B', `plotPoints crashes on 150k points: ${e.constructor.name}: ${e.message}`); }
}

// C. redactText given overlapping / unsorted findings
{
  const t = 'aaaa bbbb cccc';
  const out = redactText(t, [{label:'X',start:5,end:9},{label:'Y',start:0,end:4}]);
  console.log('   C  ', JSON.stringify(out));
  const out2 = redactText(t, [{label:'X',start:0,end:9},{label:'Y',start:5,end:14}]);
  if (out2.includes('cccc') === false || /bbbb/.test(out2)) bug('C', `overlapping findings corrupt output: ${JSON.stringify(out2)}`);
  else ok('C redact overlap');
}

// D. PNG with a corrupt chunk length
{
  const sig = [0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a];
  const b = new Uint8Array(40); b.set(sig);
  const dv = new DataView(b.buffer);
  dv.setUint32(8, 0xfffffff0);                       // absurd length
  b.set([0x74,0x45,0x58,0x74], 12);                  // 'tEXt'
  try {
    const a = analyseImage(b); const s = stripImage(b);
    if (s.bytes.length > b.length) bug('D', `corrupt PNG length inflates output ${b.length} -> ${s.bytes.length}`);
    else ok('D corrupt PNG chunk length');
  } catch (e) { bug('D', `corrupt PNG throws ${e.constructor.name}: ${e.message}`); }
}

// E. truncated / non-ZIP inputs
{
  for (const [name, buf] of [
    ['empty', new ArrayBuffer(0)],
    ['tiny', new ArrayBuffer(4)],
    ['garbage', new Uint8Array(500).fill(0x41).buffer],
  ]) {
    try { listEntries(buf); bug('E', `${name} did not throw`); }
    catch (e) {
      if (e instanceof RangeError || /offset is outside|out of bounds/i.test(e.message))
        bug('E', `${name} throws raw ${e.constructor.name} instead of a readable error: ${e.message}`);
      else ok(`E ${name} -> "${e.message}"`);
    }
  }
}

// F. WebP whose EXIF chunk already carries the "Exif\0\0" prefix (some encoders do)
{
  // little-endian TIFF, one Make tag, value inline
  const tiff = [0x49,0x49,0x2a,0x00,0x08,0x00,0x00,0x00,
                0x01,0x00,                                  // 1 entry
                0x0f,0x01, 0x02,0x00, 0x04,0x00,0x00,0x00,  // Make, ASCII, 4
                0x41,0x42,0x43,0x00,                        // "ABC"
                0x00,0x00,0x00,0x00];                       // next IFD = 0
  const payload = [0x45,0x78,0x69,0x66,0,0, ...tiff];        // Exif\0\0 + TIFF
  const len = payload.length; const pad = len % 2;
  const b = new Uint8Array(12 + 8 + len + pad);
  b.set([0x52,0x49,0x46,0x46], 0);
  b.set([0x57,0x45,0x42,0x50], 8);
  b.set([0x45,0x58,0x49,0x46], 12);
  new DataView(b.buffer).setUint32(16, len, true);
  b.set(payload, 20);
  new DataView(b.buffer).setUint32(4, b.length - 8, true);
  const a = analyseImage(b);
  const unparsed = a.findings.some(f => /unparsed/.test(f.name));
  if (unparsed) bug('F', `WebP EXIF with an "Exif\\0\\0" prefix is not parsed (double-prefixed) -> ${JSON.stringify(a.findings)}`);
  else ok('F webp prefixed EXIF');
}

console.log(bugs ? `\n${bugs} bug(s) confirmed` : '\nno bugs in this batch');
