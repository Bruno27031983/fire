// Verzia cache
const CACHE_NAME = 'brunos-calculator-v1';

// Zoznam súborov na cachovanie
const urlsToCache = [
  '/fire/',              // Root adresár podpriečinka
  '/fire/index.html',    // Hlavný HTML súbor
  '/fire/manifest.json', // Manifest súbor
  'https://fonts.googleapis.com/css2?family=Roboto&display=swap&subset=latin-ext',
  'https://www.gstatic.com/firebasejs/9.22.1/firebase-app-compat.js',
  'https://www.gstatic.com/firebasejs/9.22.1/firebase-firestore-compat.js',
  'https://www.gstatic.com/firebasejs/9.22.1/firebase-auth-compat.js',
  'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.15/jspdf.plugin.autotable.min.js'
];

// Inštalácia Service Worker-a
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('Otvorená cache a ukladám súbory');
        return cache.addAll(urlsToCache);
      })
      .catch((error) => {
        console.error('Chyba pri cachovaní:', error);
      })
  );
});

// Aktivácia Service Worker-a
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            console.log('Odstraňujem starú cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// Zachytávanie požiadaviek
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request)
      .then((response) => {
        if (response) {
          return response;
        }
        return fetch(event.request)
          .then((response) => {
            if (!response || response.status !== 200 || response.type !== 'basic') {
              return response;
            }
            const responseToCache = response.clone();
            caches.open(CACHE_NAME)
              .then((cache) => {
                cache.put(event.request, responseToCache);
              });
            return response;
          })
          .catch(() => {
            return caches.match('/fire/index.html'); // Fallback na index.html v podpriečinku
          });
      })
  );
});
