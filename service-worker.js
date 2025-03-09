const CACHE_NAME = 'calculator-cache-v1';
const urlsToCache = [
  '/fire/',
  '/fire/index.html',
  '/fire/manifest.json',
  '/fire/service-worker.js',
  'https://www.gstatic.com/firebasejs/9.6.1/firebase-app.js',
  'https://www.gstatic.com/firebasejs/9.6.1/firebase-auth.js',
  'https://www.gstatic.com/firebasejs/9.6.1/firebase-firestore.js',
  'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.15/jspdf.plugin.autotable.min.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(urlsToCache))
  );
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request)
      .then((response) => response || fetch(event.request))
      .catch(() => caches.match('/fire/index.html'))
  );
});
