const CACHE = 'ops-pwa-v16';
const ASSETS = ['/', '/index.html', '/manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  const url = new URL(req.url);

  // Let the browser handle non-GET requests, cross-origin, and the service worker file itself.
  // (Not intercepting POST is important: it lets the app correctly detect a failed send
  //  when offline, instead of thinking an entry was saved when it wasn't.)
  if (req.method !== 'GET' || url.origin !== location.origin || url.pathname === '/sw.js') return;

  // API data: network-first. If there's no connection, return a small "offline" marker
  // so the app keeps running on its locally stored data.
  if (url.pathname.startsWith('/api/')) {
    e.respondWith(
      fetch(req).catch(() =>
        new Response(JSON.stringify({ error: 'offline' }), {
          headers: { 'Content-Type': 'application/json' }
        })
      )
    );
    return;
  }

  // App pages (navigations) and the main HTML: network-first, so a fresh deploy is picked up
  // when online; fall back to the cached app when offline.
  if (req.mode === 'navigate' || url.pathname === '/' || url.pathname === '/index.html') {
    e.respondWith(
      fetch(req)
        .then(res => {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put('/index.html', clone));
          return res;
        })
        .catch(() => caches.match('/index.html').then(r => r || caches.match('/')))
    );
    return;
  }

  // Everything else (static files): cache-first, then network.
  e.respondWith(
    caches.match(req).then(cached =>
      cached ||
      fetch(req).then(res => {
        if (res.ok) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(req, clone));
        }
        return res;
      }).catch(() => cached)
    )
  );
});
