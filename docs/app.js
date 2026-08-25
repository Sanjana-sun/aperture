/* Aperture UI. No network calls anywhere in this file, by design. */
import { analyseImage, stripImage, MIME, detectFormat } from './image.js';
import { scanText, redactText } from './pii.js';
import { listEntries } from './zip.js';
import { deepScan, plotPoints } from './deepscan.js';
import { auditEntries, fmtBytes, LETTERS, deadlines } from './audit.js';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---------------------------------------------------------------- tabs
$('tabs').addEventListener('click', (e) => {
  const b = e.target.closest('.tab'); if (!b) return;
  for (const t of $('tabs').children) t.setAttribute('aria-selected', t === b);
  for (const p of ['p1', 'p2', 'p3']) $(p).hidden = p !== b.dataset.p;
});

// ---------------------------------------------------------------- drop helper
function wireDrop(dropId, inputId, pickId, handler) {
  const drop = $(dropId), input = $(inputId);
  $(pickId).onclick = () => input.click();
  input.onchange = () => input.files[0] && handler(input.files[0]);
  drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
  drop.addEventListener('dragleave', () => drop.classList.remove('over'));
  drop.addEventListener('drop', e => {
    e.preventDefault(); drop.classList.remove('over');
    if (e.dataTransfer.files[0]) handler(e.dataTransfer.files[0]);
  });
}

// ================================================================ PILLAR 1: image
let lastClean = null, lastName = '';

wireDrop('imgdrop', 'imgfile', 'imgpick', async (file) => {
  lastName = file.name;
  const bytes = new Uint8Array(await file.arrayBuffer());
  let a;
  try { a = analyseImage(bytes); }
  catch (err) {
    $('imgout').innerHTML = `<div class="result"><p class="verdict bad">Could not read this file</p>
      <p class="fine">${esc(err.message)}</p></div>`;
    return;
  }
  const fmt = detectFormat(bytes);
  const s = stripImage(bytes);
  lastClean = s.bytes;

  // GPS latitude and longitude arrive as [degrees, minutes, seconds]. Printing
  // them through a plain toFixed rendered "40.0000, 45.0000, 28.8800", which reads
  // like three decimal degrees rather than one angle.
  const dms = (v) => `${v[0]}\u00b0 ${v[1]}' ${(+v[2]).toFixed(2)}"`;
  const rows = a.findings.map(f => {
    const v = !Array.isArray(f.value) ? f.value
      : (f.value.length === 3 && /latitude|longitude/i.test(f.name)) ? dms(f.value)
      : f.value.map(x => (+x).toFixed(4)).join(', ');
    const sev = /GPS|serial|owner|unique/i.test(f.name) ? 'high' : 'medium';
    return `<tr><td><span class="sev ${sev}">${sev}</span></td>
      <td>${esc(f.name)}</td><td class="v">${esc(v)}</td></tr>`;
  }).join('');

  const gps = a.coords ? `<div class="gps">
      <strong>This photo contains your exact location.</strong><br>
      <span class="mono">${a.coords.lat.toFixed(6)}, ${a.coords.lon.toFixed(6)}</span> ·
      <a href="https://www.openstreetmap.org/?mlat=${a.coords.lat}&mlon=${a.coords.lon}#map=17/${a.coords.lat}/${a.coords.lon}"
         target="_blank" rel="noopener noreferrer">see it on a map</a>
      <p class="fine" style="margin:6px 0 0">Accurate to roughly a building. This is
      attached to the file itself, so it travels with the image wherever it is
      forwarded.</p></div>` : '';

  $('imgout').innerHTML = `
    <div class="result">
      <p class="verdict ${a.findings.length ? 'bad' : 'good'}">
        ${a.findings.length
          ? `${a.findings.length} pieces of hidden information found`
          : 'No embedded metadata found'}</p>
      <p class="fine">${esc(file.name)} · ${String(fmt).toUpperCase()} · ${fmtBytes(bytes.length)} ·
        ${a.metaSegments.length} metadata segment(s), ${fmtBytes(a.metaBytes)}</p>
      ${gps}
      ${rows ? `<table><thead><tr><th></th><th>What</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>` : ''}
      ${s.removedBytes ? `
        <p class="fine">Removing ${esc(s.removed.join(', '))} saves ${fmtBytes(s.removedBytes)}.
        The compressed image data is copied byte for byte, so the picture itself is
        unchanged. This is not a re-encode.</p>
        <button class="btn" id="dl">Download cleaned image</button>` : ''}
    </div>`;

  const dl = $('dl');
  if (dl) dl.onclick = () => {
    const url = URL.createObjectURL(new Blob([lastClean], { type: MIME[fmt] || 'application/octet-stream' }));
    const a2 = document.createElement('a');
    const ext = fmt === 'jpeg' ? 'jpg' : fmt;
    a2.href = url; a2.download = lastName.replace(/\.[^.]+$/, '') + '-cleaned.' + ext;
    a2.click(); URL.revokeObjectURL(url);
  };
});

// ================================================================ PILLAR 1: text
let txtTimer = null;
$('txt').addEventListener('input', () => {
  clearTimeout(txtTimer);
  txtTimer = setTimeout(runText, 120);
});

function runText() {
  const text = $('txt').value;
  if (!text.trim()) { $('txtout').innerHTML = ''; return; }
  const f = scanText(text);
  if (!f.length) {
    $('txtout').innerHTML = `<div class="result"><p class="verdict good">Nothing obvious found</p>
      <p class="fine">No patterns matched. That is not a guarantee. See the limits below.</p></div>`;
    return;
  }
  let html = '', cur = 0;
  for (const x of [...f].sort((a, b) => a.start - b.start)) {
    html += esc(text.slice(cur, x.start)) + `<mark title="${esc(x.label)}">${esc(x.value)}</mark>`;
    cur = x.end;
  }
  html += esc(text.slice(cur));

  const rows = f.map(x => `<tr><td><span class="sev ${x.severity}">${x.severity}</span></td>
    <td>${esc(x.label)}</td><td class="v">${esc(x.value)}</td></tr>`).join('');

  $('txtout').innerHTML = `
    <div class="result">
      <p class="verdict bad">${f.length} thing${f.length > 1 ? 's' : ''} you may not want to post</p>
      <pre class="red" style="background:#fff;color:var(--ink);border:1px solid var(--rule)">${html}</pre>
      <table><thead><tr><th></th><th>What</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>
      <button class="btn" id="redact">Show redacted version</button>
      <div id="redout"></div>
    </div>`;
  $('redact').onclick = () => {
    $('redout').innerHTML = `<pre class="red">${esc(redactText(text, f))}</pre>`;
  };
}

// ================================================================ PILLAR 2: archive
wireDrop('zipdrop', 'zipfile', 'zippick', async (file) => {
  $('zipout').innerHTML = `<div class="result"><p class="fine">Reading ${esc(file.name)} (${fmtBytes(file.size)})…</p></div>`;
  let entries, ab;
  try {
    ab = await file.arrayBuffer();
    entries = listEntries(ab);
  } catch (err) {
    $('zipout').innerHTML = `<div class="result"><p class="verdict bad">Could not read this archive</p>
      <p class="fine">${esc(err.message)}</p></div>`;
    return;
  }
  const a = auditEntries(entries);
  const max = Math.max(...a.groups.map(g => g.bytes), 1);
  const dl = deadlines();

  const rows = a.groups.map(g => `<tr>
      <td><span class="sev ${g.severity}">${g.severity}</span></td>
      <td><strong>${esc(g.label)}</strong><br><span class="fine">${esc(g.why)}</span></td>
      <td class="num">${g.files.length}</td>
      <td class="num">${fmtBytes(g.bytes)}<div class="bar"><span class="${g.severity}"
        style="width:${Math.max(3, 100 * g.bytes / max)}%"></span></div></td>
    </tr>`).join('');

  const span = (a.earliest && a.latest)
    ? `${a.earliest.toISOString().slice(0, 10)} to ${a.latest.toISOString().slice(0, 10)}` : 'none';

  $('zipout').innerHTML = `
    <div class="result">
      <p class="verdict ${a.highCount ? 'bad' : 'good'}">
        ${a.highCount} high-sensitivity categor${a.highCount === 1 ? 'y' : 'ies'} in this export</p>
      <div class="stats">
        <div class="stat"><div class="k">files</div><div class="v">${a.totalFiles}</div></div>
        <div class="stat"><div class="k">uncompressed</div><div class="v">${fmtBytes(a.totalBytes)}</div></div>
        <div class="stat"><div class="k">categories</div><div class="v">${a.groups.length}</div></div>
        <div class="stat"><div class="k">high sensitivity</div><div class="v ${a.highCount ? 'bad' : ''}">${a.highCount}</div></div>
      </div>
      <p class="fine">File dates span ${span}.</p>
      <table><thead><tr><th></th><th>Category</th><th>Files</th><th>Size</th></tr></thead><tbody>${rows}</tbody></table>
      <button class="btn" id="deep">Open the files and look inside</button>
      <p class="fine" style="margin-top:8px">So far this only reads filenames. The deep
        scan decompresses the JSON and extracts what is actually recorded.</p>
      <div id="deepout"></div>
    </div>

    <div class="result">
      <p class="verdict">Ask for it back</p>
      <p class="fine">These are drafted from what is actually in your archive. Fill in
        your details, read them before sending, and send them yourself. Aperture never
        contacts a platform on your behalf.</p>
      <p class="fine"><strong>If you send today:</strong> a GDPR response is due by
        <span class="mono">${dl.gdpr}</span> (Art. 12(3), one month) and a CCPA response by
        <span class="mono">${dl.ccpa}</span> (s.1798.130(a)(2), 45 days). If the deadline
        passes, the Art. 77 letter is the escalation.</p>
      <table style="max-width:560px"><tbody>
        <tr><td style="width:110px">Your name</td><td><input id="lname" value="" placeholder="Full name" style="width:100%;padding:7px;border:1px solid var(--rule);border-radius:4px;font:inherit"></td></tr>
        <tr><td>Your email</td><td><input id="lemail" value="" placeholder="the address on the account" style="width:100%;padding:7px;border:1px solid var(--rule);border-radius:4px;font:inherit"></td></tr>
        <tr><td>Platform</td><td><input id="lplat" value="" placeholder="e.g. Meta Platforms Ireland Ltd" style="width:100%;padding:7px;border:1px solid var(--rule);border-radius:4px;font:inherit"></td></tr>
      </tbody></table>
      <div>${LETTERS.map(L => `<button class="btn ghost" data-l="${L.id}">${esc(L.label)}</button>`).join('')}</div>
      <div id="letterout"></div>
    </div>`;

  $('deep').onclick = async () => {
    const btn = $('deep'); btn.disabled = true;
    $('deepout').innerHTML = `<p class="fine" id="dprog">Reading…</p>`;
    const d = await deepScan(ab, entries, (i, n) => {
      const el = $('dprog'); if (el) el.textContent = `Reading file ${i} of ${n}…`;
    });
    btn.disabled = false;

    const chip = (arr, n = 24) => arr.slice(0, n).map(x =>
      `<span class="chip">${esc(x)}</span>`).join('') +
      (arr.length > n ? `<span class="chip more">+${arr.length - n} more</span>` : '');

    $('deepout').innerHTML = `
      <div class="stats" style="margin-top:16px">
        <div class="stat"><div class="k">files opened</div><div class="v">${d.filesRead}</div></div>
        <div class="stat"><div class="k">third parties</div><div class="v ${d.advertisers.length ? 'bad' : ''}">${d.advertisers.length}</div></div>
        <div class="stat"><div class="k">location points</div><div class="v ${d.points.length ? 'bad' : ''}">${d.points.length.toLocaleString()}</div></div>
        <div class="stat"><div class="k">identifiers found</div><div class="v ${d.pii.length ? 'bad' : ''}">${d.pii.length}</div></div>
      </div>

      ${d.points.length ? `<h3>Where you have been</h3>
        <p class="fine">Every point below is a location this platform recorded and kept.
        ${d.span ? `Records span ${d.span.days} days.` : ''}</p>
        ${plotPoints(d.points)}` : ''}

      ${d.advertisers.length ? `<h3>Third parties who uploaded a list with you on it</h3>
        <p class="fine">These businesses gave the platform a customer list that matched
        you. You have no relationship with most of them.</p>
        <div class="chips">${chip(d.advertisers)}</div>` : ''}

      ${d.interests.length ? `<h3>What they have inferred about you</h3>
        <p class="fine">Inferred attributes are personal data under GDPR Art. 4(1) and
        CCPA s.1798.140(v)(1)(K). Exports routinely bury them, which is why the letters
        below demand them by name.</p>
        <div class="chips">${chip(d.interests, 40)}</div>` : ''}

      ${d.ips.length ? `<h3>Where you logged in from</h3>
        <table><thead><tr><th>IP address</th><th>Times seen</th></tr></thead><tbody>
        ${d.ips.slice(0, 8).map(([ip, n]) => `<tr><td class="v">${esc(ip)}</td><td class="num">${n}</td></tr>`).join('')}
        </tbody></table>` : ''}

      ${d.pii.length ? `<h3>Identifiers sitting in the archive</h3>
        <table><thead><tr><th></th><th>What</th><th>Value</th></tr></thead><tbody>
        ${d.pii.slice(0, 12).map(p => `<tr><td><span class="sev ${p.severity}">${p.severity}</span></td>
          <td>${esc(p.label)}</td><td class="v">${esc(p.value)}</td></tr>`).join('')}
        </tbody></table>` : ''}

      ${d.parseFailures ? `<p class="fine">${d.parseFailures} file(s) could not be parsed and were skipped.</p>` : ''}`;
  };

  for (const b of document.querySelectorAll('[data-l]')) {
    b.onclick = () => {
      const L = LETTERS.find(x => x.id === b.dataset.l);
      const body = L.build({
        name: $('lname').value || '[YOUR NAME]',
        email: $('lemail').value || '[YOUR EMAIL]',
        platform: $('lplat').value || '[PLATFORM]',
        audit: a,
      });
      $('letterout').innerHTML = `<pre class="red">${esc(body)}</pre>
        <button class="btn" id="copy">Copy to clipboard</button>
        <button class="btn ghost" id="save">Download as .txt</button>`;
      $('copy').onclick = async () => {
        await navigator.clipboard.writeText(body);
        $('copy').textContent = 'Copied';
        setTimeout(() => ($('copy').textContent = 'Copy to clipboard'), 1600);
      };
      $('save').onclick = () => {
        const url = URL.createObjectURL(new Blob([body], { type: 'text/plain' }));
        const el = document.createElement('a');
        el.href = url; el.download = `${L.id}-request.txt`; el.click();
        URL.revokeObjectURL(url);
      };
    };
  }
});

// A #demo hash preloads the bundled fixtures so the page can be screenshotted or
// shared in a fully populated state. It touches only local files.
if (location.hash.startsWith('#demo')) {
  window.addEventListener('load', async () => {
    const jb = await (await fetch('./with-gps.jpg')).blob();
    const dt = new DataTransfer();
    dt.items.add(new File([jb], 'holiday-photo.jpg', { type: 'image/jpeg' }));
    const inp = $('imgfile'); inp.files = dt.files; inp.dispatchEvent(new Event('change'));
    $('txt').value = "New apartment! 1600 Pennsylvania Avenue, DC 20500. Reach me at sanjana.test@example.com or (774) 465-9562. Shot at 40.758024, -73.985542.";
    $('txt').dispatchEvent(new Event('input'));
    const zb = await (await fetch('./export.zip')).blob();
    const dt2 = new DataTransfer();
    dt2.items.add(new File([zb], 'instagram-export.zip', { type: 'application/zip' }));
    const zi = $('zipfile'); zi.files = dt2.files; zi.dispatchEvent(new Event('change'));
    if (location.hash === '#demo2') {
      await new Promise(r => setTimeout(r, 400));
      document.querySelector('[data-p="p2"]').click();
      $('lname').value = 'Sanjana Injamuri';
      $('lemail').value = 'injamuri.s@northeastern.edu';
      $('lplat').value = 'Meta Platforms Ireland Ltd';
      $('deep').click();
      await new Promise(r => setTimeout(r, 1200));
      document.querySelector('[data-l="gdpr17"]').click();
    }
  });
}
