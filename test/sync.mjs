/* Fails if docs/ has drifted from src/. See sync.sh. */
import { readdirSync, readFileSync } from 'node:fs';
let bad = 0;
for (const f of readdirSync('src').filter(n => n.endsWith('.js'))) {
  const a = readFileSync(`src/${f}`, 'utf8'), b = readFileSync(`docs/${f}`, 'utf8');
  if (a !== b) { console.log(`DRIFT ${f}: docs/ copy differs from src/. Run ./sync.sh`); bad++; }
  else console.log(`ok    ${f}`);
}
process.exit(bad ? 1 : 0);
