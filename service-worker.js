// Definovanie názvu cache a zoznamu URL, ktoré chceme cache-ovať
const CACHE_NAME = 'brunos-calculator-cache-v16';
const urlsToCache = [
  './',               // Hlavná stránka
  './index.html',
  './styles.css',     // Štýly
  './app.js',         // Aplikačná logika
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png'
];

// Inštalácia Service Worker a cacheovanie zdrojov
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('Cache otvorená');
        return cache.addAll(urlsToCache);
      })
  );
});

// Obsluha požiadaviek - cache-first s offline fallback
self.addEventListener('fetch', (event) => {
  // Interceptuj len same-origin requesty (vlastná doména)
  if (!event.request.url.startsWith(self.location.origin)) {
    return; // Cross-origin requesty necháme bez interceptu
  }

  event.respondWith(
    caches.match(event.request)
      .then((cachedResponse) => {
        // Cache hit - vráť z cache
        if (cachedResponse) {
          return cachedResponse;
        }

        // Cache miss - pokús sa fetch zo siete
        return fetch(event.request)
          .catch(() => {
            // Fetch zlyhal (offline) - skús znova z cache (fallback)
            // Zabráni "Uncaught (in promise) Failed to fetch" v konzole
            return caches.match(event.request);
          });
      })
  );
});

// Aktivácia Service Worker a odstraňovanie starých cache
self.addEventListener('activate', (event) => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (!cacheWhitelist.includes(cacheName)) {
            console.log('Odstraňujem starú cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});



