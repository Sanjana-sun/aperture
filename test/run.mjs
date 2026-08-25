import { readFileSync } from 'fs';
import { analyse, strip } from '../src/exif.js';

const buf = new Uint8Array(readFileSync(new URL('./with-gps.jpg', import.meta.url)));
const a = analyse(buf);

console.log('=== segments ===');
for (const s of a.segments) console.log(`  ${s.name.padEnd(22)} ${String(s.length).padStart(5)} bytes`);

console.log(`\n=== findings (${a.findings.length}) ===`);
for (const f of a.findings) {
  const v = Array.isArray(f.value) ? f.value.map(x=>+x.toFixed(4)).join(', ') : f.value;
  console.log(`  ${f.name.padEnd(28)} ${v}`);
}

console.log('\n=== resolved coordinates ===');
if (a.coords) {
  console.log(`  ${a.coords.lat.toFixed(5)}, ${a.coords.lon.toFixed(5)}`);
  const okLat = Math.abs(a.coords.lat - 40.758) < 0.01;
  const okLon = Math.abs(a.coords.lon - (-73.9855)) < 0.01;
  console.log(`  expected ~40.75800, -73.98550  ->  ${okLat && okLon ? 'PASS' : 'FAIL'}`);
} else console.log('  none  -> FAIL');

const s = strip(buf);
console.log('\n=== strip ===');
console.log(`  before ${buf.length} bytes, after ${s.bytes.length} bytes`);
console.log(`  removed ${s.removedBytes} bytes: ${s.removed.join(', ')}`);
const after = analyse(s.bytes);
console.log(`  findings after strip: ${after.findings.length} -> ${after.findings.length === 0 ? 'PASS' : 'FAIL'}`);
console.log(`  coords after strip: ${after.coords ? 'STILL PRESENT -> FAIL' : 'none -> PASS'}`);

// The critical property: scan data must be untouched.
const soiToScan = buf.indexOf(0xDA, 2);
const origScan = buf.subarray(buf.length - 64);
const newScan = s.bytes.subarray(s.bytes.length - 64);
const identical = origScan.every((b, i) => b === newScan[i]);
console.log(`  final 64 bytes of scan data identical: ${identical ? 'PASS' : 'FAIL'}`);
