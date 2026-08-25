import { readFileSync } from 'fs';
import { analyseImage, stripImage, detectFormat } from '../src/image.js';
for (const f of ['with-gps.jpg','meta.png','meta.webp']) {
  const b = new Uint8Array(readFileSync(new URL('./'+f, import.meta.url)));
  const fmt = detectFormat(b);
  try {
    const a = analyseImage(b), s = stripImage(b);
    const after = analyseImage(s.bytes);
    console.log(`${f.padEnd(14)} ${String(fmt).padEnd(5)} findings ${String(a.findings.length).padStart(2)} -> ${after.findings.length}  meta ${String(a.metaBytes).padStart(4)}B  ${b.length}->${s.bytes.length}B  ${after.findings.length===0?'PASS':'FAIL'}`);
    for (const x of a.findings.slice(0,3)) console.log(`                 ${x.name}: ${String(x.value).slice(0,50)}`);
  } catch(e){ console.log(`${f.padEnd(14)} ERROR ${e.message}`); }
}
