// service-worker.js

const CACHE_VERSION = 'v19'; // Nezabudni zvýšiť verziu!
const STATIC_CACHE = `brunos-calculator-static-${CACHE_VERSION}`;
// Spojíme fonty a CDN do jednej "extern" cache, alebo ich necháme oddelené,
// ale pre jednoduchosť stačí STATIC pre core app a RUNTIME pre zvyšok.
const RUNTIME_CACHE = `brunos-calculator-runtime-${CACHE_VERSION}`;

// 1. ZMENA: Do STATIC cache musíme dať VŠETKO kritické pre štart appky
const urlsToCache = [
  './',
  './index.html',
  './styles.css',
  './app.js',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png',

  // DÔLEŽITÉ: Tieto musia byť tu, aby sme mali istotu, že sú stiahnuté
  'https://fonts.googleapis.com/css2?family=Roboto&display=swap&subset=latin-ext',
  'https://www.gstatic.com/firebasejs/9.22.1/firebase-app-compat.js',
  'https://www.gstatic.com/firebasejs/9.22.1/firebase-firestore-compat.js',
  'https://www.gstatic.com/firebasejs/9.22.1/firebase-auth-compat.js',
  'https://www.gstatic.com/firebasejs/9.22.1/firebase-app-check-compat.js',
  'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.15/jspdf.plugin.autotable.min.js'
];

// Inštalácia - Pre-caching (Stiahni všetko dôležité)
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => {
        console.log('Sťahujem kritické súbory...');
        return cache.addAll(urlsToCache);
      })
      .then(() => self.skipWaiting())
  );
});

// Fetch - Stratégie
self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Ignorujeme requesty, ktoré nie sú GET (napr. POST do Firestore)
  if (request.method !== 'GET') return;

  // Stratégia: Cache-First, falling back to Network
  // Toto je najlepšie pre tvoju appku, pretože verzie súborov (v19, 9.22.1) sa nemenia.
  event.respondWith(
    caches.match(request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }

      // Ak nie je v cache, skús sieť a ulož do Runtime cache
      return fetch(request).then((networkResponse) => {
        // Cache len platné odpovede a len externé skripty/fonty/obrázky
        if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic' && networkResponse.type !== 'cors') {
          return networkResponse;
        }

        // Klonujeme odpoveď, lebo stream sa dá prečítať len raz
        const responseToCache = networkResponse.clone();

        caches.open(RUNTIME_CACHE).then((cache) => {
          cache.put(request, responseToCache);
        });

        return networkResponse;
      }).catch(() => {
        // Offline fallback (voliteľné - napr. offline.html)
        console.warn('Offline a súbor nie je v cache:', request.url);
      });
    })
  );
});

// Aktivácia - Čistenie
self.addEventListener('activate', (event) => {
  const cacheWhitelist = [STATIC_CACHE, RUNTIME_CACHE];
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
    }).then(() => self.clients.claim())
  );
});
