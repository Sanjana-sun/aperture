import { readFileSync } from 'fs';
import { listEntries } from '../src/zip.js';
import { deepScan, plotPoints } from '../src/deepscan.js';

const b = readFileSync(new URL('./export.zip', import.meta.url));
const ab = b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
const entries = listEntries(ab);
const d = await deepScan(ab, entries);

console.log(`files read: ${d.filesRead}, ${(d.bytesRead/1024).toFixed(1)} KB, parse failures: ${d.parseFailures}`);
console.log(`advertisers : ${d.advertisers.length}`);
console.log(`interests   : ${d.interests.length}  ${JSON.stringify(d.interests.slice(0,6))}`);
console.log(`IPs         : ${d.ips.length}  ${JSON.stringify(d.ips.slice(0,3))}`);
console.log(`location pts: ${d.points.length}`);
console.log(`PII hits    : ${d.pii.length}`);
for (const p of d.pii.slice(0,6)) console.log(`   [${p.severity}] ${p.label}: ${p.value}`);
const svg = plotPoints(d.points);
console.log(`\nplot: ${svg.length} chars, circles: ${(svg.match(/<circle/g)||[]).length}`);
console.log(`\nchecks:`);
console.log(`  advertisers found       ${d.advertisers.length >= 300 ? 'PASS' : 'FAIL ('+d.advertisers.length+')'}`);
console.log(`  location points found   ${d.points.length >= 1000 ? 'PASS' : 'FAIL ('+d.points.length+')'}`);
console.log(`  email PII found         ${d.pii.some(p=>p.label==='Email address') ? 'PASS' : 'FAIL'}`);
console.log(`  plot renders            ${svg.includes('<svg') ? 'PASS' : 'FAIL'}`);
