/* Aperture — deep archive scan.
 *
 * The shallow audit categorises filenames. This opens the files.
 *
 * It decompresses the JSON inside a platform export and extracts the things people
 * do not know are in there: inferred advertising attributes, the third parties
 * holding a customer list you appear on, location traces, and login IP history.
 *
 * Inferred attributes matter disproportionately. They are personal data under GDPR
 * Art. 4(1) and CCPA s.1798.140(v)(1)(K), they are the most commercially valuable
 * category, and exports routinely omit or bury them. A rights request that names
 * them specifically is much harder to answer with boilerplate.
 */

import { readEntryText } from './zip.js';
import { scanText } from './pii.js';

const MAX_BYTES = 12 * 1024 * 1024;   // don't stall the tab on a huge single file
const MAX_FILES = 400;

/** Recursively pull every string and number out of a parsed JSON value. */
function* walk(node, path = '') {
  if (node === null || node === undefined) return;
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) yield* walk(node[i], `${path}[]`);
  } else if (typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) yield* walk(v, path ? `${path}.${k}` : k);
  } else {
    yield { path, value: node };
  }
}

// Heuristics for the categories worth surfacing on their own.
const ADVERTISER_KEYS = /advertis|custom_audience|data_file|business/i;
const INTEREST_KEYS   = /interest|topic|preference|inferred|category|ad_topic|segment/i;
const LAT_KEYS        = /^(lat|latitude)$/i;
const LON_KEYS        = /^(lon|lng|longitude)$/i;
const IP_KEYS         = /ip|address/i;
const TS_KEYS         = /time|date|ts$|timestamp|created/i;

function looksLikeEpoch(n) {
  return typeof n === 'number' && n > 946684800 && n < 4102444800;   // 2000..2100
}

/**
 * Scan the archive. Returns structured findings plus raw PII hits.
 * `onProgress(done, total)` lets the UI stay responsive.
 */
export async function deepScan(buffer, entries, onProgress) {
  const json = entries.filter(e =>
    !e.isDir && /\.json$/i.test(e.name) && e.uncompressed < MAX_BYTES
  ).slice(0, MAX_FILES);

  const advertisers = new Set();
  const interests = new Set();
  const ips = new Map();          // ip -> count
  const points = [];              // {lat, lon, t}
  const piiHits = [];             // {file, label, value, severity}
  const timestamps = [];
  let filesRead = 0, bytesRead = 0, parseFailures = 0;

  for (let i = 0; i < json.length; i++) {
    const e = json[i];
    let text;
    try { text = await readEntryText(buffer, e); }
    catch { parseFailures++; continue; }
    filesRead++; bytesRead += text.length;

    let data;
    try { data = JSON.parse(text); }
    catch { parseFailures++; continue; }

    // Structured extraction
    let pendingLat = null;
    for (const { path, value } of walk(data)) {
      const leaf = path.split('.').pop().replace('[]', '');

      if (typeof value === 'string') {
        if (ADVERTISER_KEYS.test(path) && /name$/i.test(leaf) && value.length < 120) {
          advertisers.add(value);
        } else if (INTEREST_KEYS.test(path) && value.length < 60 && !/^https?:/.test(value)) {
          interests.add(value);
        }
      }
      if (LAT_KEYS.test(leaf) && typeof value === 'number' && Math.abs(value) <= 90) {
        pendingLat = value;
      } else if (LON_KEYS.test(leaf) && typeof value === 'number' && Math.abs(value) <= 180) {
        if (pendingLat !== null) { points.push({ lat: pendingLat, lon: value }); pendingLat = null; }
      }
      if (IP_KEYS.test(leaf) && typeof value === 'string' &&
          /^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
        ips.set(value, (ips.get(value) || 0) + 1);
      }
      if (TS_KEYS.test(leaf) && looksLikeEpoch(value)) timestamps.push(value * 1000);
    }

    // PII over *string values only*, not the serialised text.
    //
    // Scanning raw JSON produces false positives: adjacent numeric fields run
    // together across punctuation and coincidentally satisfy Luhn, so timestamps
    // and coordinates get reported as payment cards. Walking values is both more
    // precise and cheaper.
    let perFile = 0;
    for (const { value } of walk(data)) {
      if (perFile >= 25) break;
      if (typeof value !== 'string' || value.length > 500) continue;
      for (const h of scanText(value)) {
        piiHits.push({ file: e.name, label: h.label, value: h.value, severity: h.severity });
        if (++perFile >= 25) break;
      }
    }

    if (onProgress && i % 5 === 0) { onProgress(i + 1, json.length); await new Promise(r => setTimeout(r)); }
  }

  timestamps.sort((a, b) => a - b);
  const uniquePii = [];
  const seen = new Set();
  for (const h of piiHits) {
    const k = h.label + '|' + h.value;
    if (seen.has(k)) continue;
    seen.add(k); uniquePii.push(h);
  }
  const rank = { high: 3, medium: 2, low: 1 };
  uniquePii.sort((a, b) => rank[b.severity] - rank[a.severity]);

  return {
    filesRead, bytesRead, parseFailures,
    advertisers: [...advertisers],
    interests: [...interests],
    ips: [...ips.entries()].sort((a, b) => b[1] - a[1]),
    points,
    pii: uniquePii,
    span: timestamps.length
      ? { from: new Date(timestamps[0]), to: new Date(timestamps[timestamps.length - 1]),
          days: Math.round((timestamps[timestamps.length - 1] - timestamps[0]) / 86400000) }
      : null,
  };
}

/** Render location points as a standalone SVG. No map tiles, so no network call. */
export function plotPoints(points, width = 560, height = 300) {
  if (!points.length) return '';
  const lats = points.map(p => p.lat), lons = points.map(p => p.lon);
  let minLat = Math.min(...lats), maxLat = Math.max(...lats);
  let minLon = Math.min(...lons), maxLon = Math.max(...lons);
  // Pad degenerate extents so a single cluster doesn't divide by zero.
  const padLat = Math.max((maxLat - minLat) * 0.12, 0.002);
  const padLon = Math.max((maxLon - minLon) * 0.12, 0.002);
  minLat -= padLat; maxLat += padLat; minLon -= padLon; maxLon += padLon;

  const x = lon => ((lon - minLon) / (maxLon - minLon)) * width;
  const y = lat => height - ((lat - minLat) / (maxLat - minLat)) * height;

  const step = Math.max(1, Math.floor(points.length / 2500));   // cap DOM nodes
  const dots = points.filter((_, i) => i % step === 0)
    .map(p => `<circle cx="${x(p.lon).toFixed(1)}" cy="${y(p.lat).toFixed(1)}" r="2"/>`)
    .join('');

  const kmWide = (maxLon - minLon) * 111 * Math.cos(((minLat + maxLat) / 2) * Math.PI / 180);
  const kmTall = (maxLat - minLat) * 111;

  return `<svg viewBox="0 0 ${width} ${height}" class="plot" role="img"
    aria-label="Scatter plot of ${points.length} recorded location points">
    <rect width="${width}" height="${height}" fill="#fbfbfc"/>
    <g fill="#b3341f" fill-opacity="0.5">${dots}</g>
    <text x="8" y="${height - 8}" font-size="10" fill="#7b828c"
      font-family="ui-monospace, monospace">${points.length.toLocaleString()} points ·
      about ${kmWide.toFixed(1)} x ${kmTall.toFixed(1)} km</text>
  </svg>`;
}
