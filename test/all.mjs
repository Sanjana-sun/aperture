/* Runs every test file and reports a single pass/fail. */
import { execFileSync } from 'node:child_process';
const files = ['sync', 'run', 'pii', 'audit', 'formats', 'deep', 'adversarial', 'adv2', 'adv3'];
let failed = [];
for (const f of files) {
  let out = '';
  try { out = execFileSync('node', [`test/${f}.mjs`], { encoding: 'utf8', stdio: ['ignore','pipe','pipe'] }); }
  catch (e) { out = (e.stdout || '') + (e.stderr || ''); failed.push(f); }
  const bad = /\bFAIL\b|^BUG |\nBUG |DRIFT /.test(out);
  if (bad && !failed.includes(f)) failed.push(f);
  console.log(`${bad || failed.includes(f) ? 'FAIL' : 'pass'}  test/${f}.mjs`);
}
console.log(failed.length ? `\n${failed.length} failing: ${failed.join(', ')}` : '\nall tests pass');
process.exit(failed.length ? 1 : 0);
