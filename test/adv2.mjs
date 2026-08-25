import { deepScan } from '../src/deepscan.js';
import { listEntries } from '../src/zip.js';
import { scanText } from '../src/pii.js';
import { analyseImage, stripImage } from '../src/image.js';
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';

let bugs = 0;
const bug = (id, m) => { bugs++; console.log(`BUG ${id}: ${m}`); };
const ok = (id) => console.log(`ok  ${id}`);

// G. lat/lon ordering. Many exports serialise longitude first.
{
  const buf = readFileSync('/tmp/ap/g.zip');
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset+buf.byteLength);
  const d = await deepScan(ab, listEntries(ab));
  if (d.points.length !== 2) bug('G', `lon-before-lat ordering yields ${d.points.length}/2 points (pairing depends on key order)`);
  else ok('G lon-before-lat');
}

// H. cross-object lat/lon bleed: an unpaired lat pairs with a later unrelated lon
{
  const buf = readFileSync('/tmp/ap/h.zip');
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset+buf.byteLength);
  const d = await deepScan(ab, listEntries(ab));
  if (d.points.length) bug('H', `a lone latitude paired with an unrelated longitude in a different object -> fabricated point ${JSON.stringify(d.points)}`);
  else ok('H no cross-object bleed');
}

// I. reported "bytes read"
{
  const buf = readFileSync(new URL('./export.zip', import.meta.url));
  const ab = buf.buffer.slice(buf.byteOffset, buf.byteOffset+buf.byteLength);
  const es = listEntries(ab);
  const d = await deepScan(ab, es);
  const realJsonBytes = es.filter(e=>/\.json$/i.test(e.name)).reduce((n,e)=>n+e.uncompressed,0);
  if (Math.abs(d.bytesRead - realJsonBytes) > realJsonBytes*0.02)
    bug('I', `bytesRead=${d.bytesRead} counts UTF-16 string length, not bytes; actual uncompressed JSON = ${realJsonBytes}`);
  else ok('I bytesRead');
}

// J. ZIP64-marked entry sizes
{
  const es = listEntries(readFileSync(new URL('./export.zip', import.meta.url)).buffer.slice(0));
  const sat = es.filter(e => e.uncompressed === 0xffffffff || e.localOffset === 0xffffffff);
  console.log(`   J  entries=${es.length} saturated=${sat.length} (fixture is small; checking code path by inspection)`);
  const src = readFileSync(new URL('../src/zip.js', import.meta.url), 'utf8');
  if (!/0x0001|zip64 extra|extraLen[\s\S]{0,200}0x0001/i.test(src))
    bug('J', 'zip.js never parses the ZIP64 extended-information extra field (0x0001), so entries >4 GiB or archives >4 GiB report size/offset 0xffffffff and are silently skipped or read from a bogus offset');
  else ok('J zip64 extra field');
}

// K. encrypted entries
{
  const src = readFileSync(new URL('../src/zip.js', import.meta.url), 'utf8');
  if (!/flag|0x1\b|encrypt/i.test(src))
    bug('K', 'zip.js never reads the general-purpose bit flag, so an encrypted entry is inflated as if it were plain deflate and yields garbage instead of a clear error; bit 11 (UTF-8 name) is likewise ignored so non-ASCII filenames mis-decode');
  else ok('K encryption flag');
}

// L. WebP VP8X feature flags after stripping
{
  const src = readFileSync(new URL('../src/image.js', import.meta.url), 'utf8');
  if (!/VP8X/.test(src))
    bug('L', 'stripWebp removes EXIF/XMP/ICCP chunks but never clears the corresponding VP8X feature-flag bits, leaving a file that advertises metadata chunks it no longer contains');
  else ok('L vp8x flags');
}

// M. PNG iCCP inconsistency
{
  const src = readFileSync(new URL('../src/image.js', import.meta.url), 'utf8');
  const pngSet = src.match(/PNG_META = new Set\(\[([^\]]*)\]/)[1];
  if (!/iCCP/.test(pngSet) && /ICCP/.test(src))
    bug('M', `PNG strips ${pngSet.replace(/\s+/g,' ')} but not iCCP, while WebP does strip ICCP; ICC profiles carry device and scanner identifiers, so the same profile survives in a PNG and is removed from a WebP`);
  else ok('M iCCP consistency');
}

console.log(bugs ? `\n${bugs} bug(s) confirmed` : '\nno bugs in this batch');
