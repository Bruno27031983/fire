// Definovanie názvu cache a zoznamu URL, ktoré chceme cache-ovať
const CACHE_NAME = 'brunos-calculator-cache-v2';
const urlsToCache = [
  './',               // Hlavná stránka
  './index.html',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png'
  // Pridajte ďalšie súbory, ktoré chcete cache-ovať (CSS, JS, obrázky, ...)
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

// Obsluha požiadaviek - vrátenie odpovede z cache, ak je k dispozícii
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request)
      .then((response) => {
        // Ak je odpoveď v cache, vrátime ju, inak získame zo siete
        return response || fetch(event.request);
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
