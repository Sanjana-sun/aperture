import { readFileSync } from 'fs';
import { analyseImage, stripImage, detectFormat } from '../src/image.js';

// iphone.heic was produced by macOS `sips -s format heic` from with-gps.jpg, so it
// is a real encoder's output rather than something hand-assembled. It carries the
// same EXIF and GPS as the JPEG, plus an XMP packet sips adds of its own accord.
let bad = 0;
for (const f of ['with-gps.jpg', 'meta.png', 'meta.webp', 'iphone.heic']) {
  const b = new Uint8Array(readFileSync(new URL('./' + f, import.meta.url)));
  const fmt = detectFormat(b);
  try {
    const a = analyseImage(b), s = stripImage(b);
    const after = analyseImage(s.bytes);
    const ok = after.findings.length === 0 && !after.coords;
    if (!ok) bad++;
    const size = s.inPlace ? `${b.length}B in place` : `${b.length}->${s.bytes.length}B`;
    console.log(`${f.padEnd(14)} ${String(fmt).padEnd(5)} findings ${String(a.findings.length).padStart(2)} -> ${after.findings.length}  meta ${String(a.metaBytes).padStart(4)}B  ${size.padEnd(16)} ${ok ? 'PASS' : 'FAIL'}`);
    for (const x of a.findings.slice(0, 3)) console.log(`                 ${x.name}: ${String(x.value).slice(0, 50)}`);
  } catch (e) { console.log(`${f.padEnd(14)} ERROR ${e.message}`); bad++; }
}
process.exit(bad ? 1 : 0);
