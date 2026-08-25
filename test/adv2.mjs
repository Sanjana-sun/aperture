/* Adversarial tests, part 2: archive and container edge cases.
 *
 * Every fixture is built in memory by test/helpers.mjs. An earlier version of
 * this file read zips from /tmp that had been created by hand in a shell, so it
 * only passed on the machine where those files happened to exist, and several
 * checks were regexes over the source rather than tests of behaviour. A regex
 * over the source passes if someone writes the identifier in a comment.
 */
import { deepScan } from '../src/deepscan.js';
import { listEntries, readEntryText } from '../src/zip.js';
import { analyseImage, stripImage } from '../src/image.js';
import { makeZip, zipOfJson, makePng, makeWebp, tinyTiff } from './helpers.mjs';

let bugs = 0;
const bug = (id, m) => { bugs++; console.log(`BUG ${id}: ${m}`); };
const ok = (id, note = '') => console.log(`ok  ${id}${note ? '  ' + note : ''}`);

// G. Longitude serialised before latitude. Pairing must not depend on key order.
{
  const ab = zipOfJson('loc.json', {
    points: [{ longitude: -71.05, latitude: 42.36 }, { longitude: -71.06, latitude: 42.37 }],
  });
  const d = await deepScan(ab, listEntries(ab));
  const got = JSON.stringify(d.points);
  const want = JSON.stringify([{ lat: 42.36, lon: -71.05 }, { lat: 42.37, lon: -71.06 }]);
  if (got !== want) bug('G', `lon-before-lat pairing wrong: ${got}`);
  else ok('G', 'lon-before-lat');
}

// H. A latitude with no matching longitude must not pair across objects.
{
  const ab = zipOfJson('a.json', { home: { latitude: 42.36 }, office: { longitude: -71.05 } });
  const d = await deepScan(ab, listEntries(ab));
  if (d.points.length) bug('H', `fabricated a location from two unrelated objects: ${JSON.stringify(d.points)}`);
  else ok('H', 'no cross-object bleed');
}

// H2. Google Takeout stores degrees scaled by 1e7.
{
  const ab = zipOfJson('t.json', { locations: [{ latitudeE7: 423601000, longitudeE7: -710589000 }] });
  const d = await deepScan(ab, listEntries(ab));
  const p = d.points[0];
  if (!p || Math.abs(p.lat - 42.3601) > 1e-6 || Math.abs(p.lon + 71.0589) > 1e-6)
    bug('H2', `e7-scaled coordinates not decoded: ${JSON.stringify(d.points)}`);
  else ok('H2', 'e7 coordinates');
}

// I. Octet-range validation, so 999.999.999.999 is not reported as an address.
{
  const ab = zipOfJson('l.json', { logins: [{ ip: '999.999.999.999' }, { ip: '73.114.28.9' }] });
  const d = await deepScan(ab, listEntries(ab));
  const found = d.ips.map(([ip]) => ip);
  if (found.includes('999.999.999.999')) bug('I', `accepted an out-of-range IP: ${found.join(', ')}`);
  else if (!found.includes('73.114.28.9')) bug('I', `dropped a valid IP: ${found.join(', ')}`);
  else ok('I', 'IP octet range');
}

// J. ZIP64 extended-information extra field: the 32-bit fields saturate and the
//    real sizes and offset live in the extra field.
{
  const ab = makeZip([{ name: 'big.json', data: '{"a":1}', zip64: true }]);
  const e = listEntries(ab)[0];
  if (e.uncompressed === 0xffffffff || e.localOffset === 0xffffffff)
    bug('J', `saturated fields not resolved from the ZIP64 extra field: unc=${e.uncompressed} off=${e.localOffset}`);
  else if (await readEntryText(ab, e) !== '{"a":1}')
    bug('J', 'ZIP64 entry did not read back correctly');
  else ok('J', `zip64 extra field (unc=${e.uncompressed}, off=${e.localOffset})`);
}

// K. Encrypted entries must be refused, not inflated into garbage.
{
  const ab = makeZip([{ name: 'secret.json', data: '{"a":1}', flags: 0x1 }]);
  const e = listEntries(ab)[0];
  if (!e.encrypted) bug('K', 'general-purpose bit 0 not read, so encryption goes undetected');
  else {
    try { await readEntryText(ab, e); bug('K', 'read an encrypted entry instead of refusing it'); }
    catch (err) {
      if (!/encrypted/i.test(err.message)) bug('K', `unclear error for an encrypted entry: ${err.message}`);
      else ok('K', 'encrypted entry refused');
    }
  }
}

// K2. Filenames are CP437 unless general-purpose bit 11 says UTF-8.
{
  // "caf<e-acute>.json": 0x82 is e-acute in CP437, and invalid as UTF-8.
  const cp437 = new Uint8Array([0x63, 0x61, 0x66, 0x82, 0x2e, 0x6a, 0x73, 0x6f, 0x6e]);
  const ab = makeZip([{ nameBytes: cp437, data: '{}', flags: 0 }]);
  const name = listEntries(ab)[0].name;
  if (name !== 'café.json') bug('K2', `CP437 filename mis-decoded as ${JSON.stringify(name)}`);
  else ok('K2', 'cp437 filename');
}

// K3. A truncated archive should say so rather than throw a RangeError.
{
  const full = makeZip([{ name: 'a.json', data: 'x'.repeat(400) }]);
  const e = listEntries(full)[0];
  const cut = full.slice(0, 60);                 // header survives, data does not
  try { await readEntryText(cut, e); bug('K3', 'read past the end of a truncated archive'); }
  catch (err) {
    if (err instanceof RangeError) bug('K3', `truncated archive throws a raw RangeError: ${err.message}`);
    else ok('K3', `truncated archive: "${err.message}"`);
  }
}

// L. Removing WebP metadata must clear the matching VP8X feature bits.
{
  const vp8x = new Uint8Array(10);
  vp8x[0] = 0x20 | 0x08 | 0x04;                  // claims ICC, EXIF and XMP
  const b = makeWebp([
    ['VP8X', vp8x],
    ['VP8 ', new Uint8Array(4)],
    ['EXIF', tinyTiff()],
    ['XMP ', '<x:xmpmeta/>'],
  ]);
  const s = stripImage(b);
  const flags = s.bytes[20];
  const riffOk = new DataView(s.bytes.buffer, s.bytes.byteOffset).getUint32(4, true) === s.bytes.length - 8;
  if (flags & (0x20 | 0x08 | 0x04)) bug('L', `VP8X still advertises removed chunks: 0x${flags.toString(16)}`);
  else if (!riffOk) bug('L', 'RIFF size not corrected after stripping');
  else ok('L', 'vp8x flags cleared, riff size fixed');
}

// M. PNG must strip iCCP, as WebP already strips ICCP.
{
  const b = makePng([['iCCP', 'sRGB\0\0dummy'], ['tEXt', 'Author\0Sanjana']]);
  const before = analyseImage(b);
  const s = stripImage(b);
  const after = analyseImage(s.bytes);
  const kept = after.segments.filter(x => /iCCP/.test(x.name));
  if (kept.length) bug('M', 'iCCP survived stripping, so an ICC profile naming the capture device is still attached');
  else if (!before.segments.some(x => /iCCP/.test(x.name))) bug('M', 'iCCP was not detected in the first place');
  else ok('M', `iCCP stripped (${before.findings.length} findings -> ${after.findings.length})`);
}

// N. A WebP EXIF chunk that already carries the Exif\0\0 magic must not be
//    double-prefixed, and one without it must still parse.
{
  const magic = new Uint8Array([0x45, 0x78, 0x69, 0x66, 0, 0]);
  const tiff = tinyTiff('Nikon');
  const withMagic = new Uint8Array(magic.length + tiff.length);
  withMagic.set(magic); withMagic.set(tiff, magic.length);
  for (const [label, payload] of [['bare', tiff], ['prefixed', withMagic]]) {
    const a = analyseImage(makeWebp([['VP8 ', new Uint8Array(4)], ['EXIF', payload]]));
    const make = a.findings.find(f => /make/i.test(f.name));
    if (!make || !/Nikon/.test(make.value)) bug('N', `${label} EXIF payload not parsed: ${JSON.stringify(a.findings)}`);
    else ok('N', `${label} EXIF payload`);
  }
}

console.log(bugs ? `\n${bugs} bug(s) confirmed` : '\nno bugs in this batch');
process.exit(bugs ? 1 : 0);
