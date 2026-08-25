import { readFileSync } from 'fs';
import { listEntries, readEntryText } from '../src/zip.js';
import { auditEntries, fmtBytes, LETTERS } from '../src/audit.js';

const buf = readFileSync(new URL('./export.zip', import.meta.url));
const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
const entries = listEntries(ab);
console.log(`entries: ${entries.length}`);

const a = auditEntries(entries);
console.log(`\n${a.totalFiles} files, ${fmtBytes(a.totalBytes)}, ${a.highCount} high-sensitivity categories\n`);
for (const g of a.groups) {
  console.log(`  [${g.severity.padEnd(6)}] ${g.label.padEnd(28)} ${String(g.files.length).padStart(2)} files  ${fmtBytes(g.bytes).padStart(9)}`);
}

console.log('\n=== decompression check ===');
const profile = entries.find(e => e.name.includes('profile.json'));
const txt = await readEntryText(ab, profile);
console.log(`  read ${profile.name}: ${txt.length} chars`);
console.log(`  parses as JSON: ${(() => { try { JSON.parse(txt); return 'PASS'; } catch { return 'FAIL'; } })()}`);

console.log('\n=== letter generation ===');
for (const L of LETTERS) {
  const body = L.build({ name: 'Sanjana Injamuri', email: 'injamuri.s@northeastern.edu', platform: 'ExamplePlatform', audit: a });
  console.log(`  ${L.label.padEnd(30)} ${String(body.split('\n').length).padStart(3)} lines, ${body.length} chars`);
}
console.log('\n--- GDPR Art.17 excerpt ---');
console.log(LETTERS[1].build({ name:'Sanjana Injamuri', email:'injamuri.s@northeastern.edu', platform:'ExamplePlatform', audit:a }).split('\n').slice(0,16).join('\n'));
