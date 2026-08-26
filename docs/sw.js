/* Aperture service worker.
 *
 * The page claimed it worked offline, which was not true: without this, going
 * offline and reloading just failed. For a tool whose whole argument is that it
 * needs nothing from the network, that was the wrong claim to leave unbacked.
 *
 * Precaching the shell also makes the claim demonstrable rather than rhetorical.
 * Load it once, turn off the network, and it keeps working: strip a photo, open an
 * export, draft a letter, with no connection at all.
 *
 * Only the app's own files are cached. Nothing a user opens is ever stored.
 */
const VERSION = 'aperture-v3';
const SHELL = [
  './', './index.html', './style.css', './app.js',
  './exif.js', './image.js', './heic.js', './pii.js', './zip.js',
  './audit.js', './deepscan.js',
  './manifest.json', './icon-192.png', './icon-512.png',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(VERSION).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== VERSION).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  e.respondWith(
    caches.match(e.request).then(hit => {
      // Serve from cache, then refresh it in the background so a redeploy lands on
      // the next visit rather than requiring a hard reload.
      const live = fetch(e.request).then(res => {
        if (res && res.ok) caches.open(VERSION).then(c => c.put(e.request, res.clone()));
        return res;
      }).catch(() => hit);
      return hit || live;
    })
  );
});
