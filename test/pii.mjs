import { scanText, redactText, DETECTOR_COUNT } from '../src/pii.js';
const sample = `Just moved! New place is 1600 Pennsylvania Avenue, DC 20500.
Reach me at sanjana.test@example.com or (774) 465-9562.
Shot this at 40.758024, -73.985542 — amazing view.
Old card 4111 1111 1111 1111 is cancelled so whatever.
My server is at 192.168.1.42. Follow @sanjana_builds
Random long number that is not a card: 1234567890123456`;

const f = scanText(sample);
console.log(`detectors: ${DETECTOR_COUNT}, findings: ${f.length}\n`);
for (const x of f) console.log(`  [${x.severity.padEnd(6)}] ${x.label.padEnd(26)} "${x.value}"`);
const ids = f.map(x=>x.id);
const need = ['email','phone','coords','card','ip','handle','address'];
console.log(`\nexpected categories present: ${need.every(n=>ids.includes(n)) ? 'PASS' : 'FAIL — missing ' + need.filter(n=>!ids.includes(n))}`);
const luhnFalsePositive = f.some(x => x.id==='card' && x.value.includes('1234567890123456'));
console.log(`Luhn rejects non-card long digits: ${luhnFalsePositive ? 'FAIL' : 'PASS'}`);
console.log('\n=== redacted ===');
console.log(redactText(sample, f));
