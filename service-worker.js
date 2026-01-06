// service-worker.js

// Zakaždým, keď niečo zmeníš v kóde (HTML, JS, CSS) alebo v tomto súbore,
// ZVÝŠ TOTO ČÍSLO (v19 -> v20). Donúti to prehliadač stiahnuť novú verziu.
const CACHE_VERSION = 'v37';
const STATIC_CACHE = `brunos-calculator-static-${CACHE_VERSION}`;
const RUNTIME_CACHE = `brunos-calculator-runtime-${CACHE_VERSION}`;

// Zoznam VŠETKÝCH súborov, ktoré aplikácia potrebuje pre offline beh.
// Musia tu byť lokálne súbory AJ externé CDN linky (presne ako v index.html).
const urlsToCache = [
  './',
  './index.html',
  './styles.css',
  './app.js',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png',

  // EXTERNÉ KNIŽNICE (Firebase Modular SDK, PDF, Fonty)
  'https://fonts.googleapis.com/css2?family=Roboto&display=swap&subset=latin-ext',
  'https://www.gstatic.com/firebasejs/12.7.0/firebase-app.js',
  'https://www.gstatic.com/firebasejs/12.7.0/firebase-firestore.js',
  'https://www.gstatic.com/firebasejs/12.7.0/firebase-auth.js',
  'https://www.gstatic.com/firebasejs/12.7.0/firebase-app-check.js',
  'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js',
  'https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.5.15/jspdf.plugin.autotable.min.js'
];

// 1. INŠTALÁCIA: Stiahni všetko dôležité hneď na začiatku
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => {
        console.log('[SW] Sťahujem kritické súbory...');
        // addAll je atómová operácia - ak zlyhá jeden súbor, zlyhá celá inštalácia.
        return cache.addAll(urlsToCache);
      })
      .then(() => self.skipWaiting()) // Okamžite aktivuj nový SW
      .catch((error) => {
        console.error('[SW] Chyba pri inštalácii:', error);
      })
  );
});

// 2. FETCH: Stratégia Cache-First (Rýchlosť a Stabilita)
self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Ignorujeme POST požiadavky (zápisy do databázy) a iné ako GET
  if (request.method !== 'GET') return;

  event.respondWith(
    caches.match(request).then((cachedResponse) => {
      // A) Máme to v cache? Super, vráť to. (Najrýchlejšie)
      if (cachedResponse) {
        return cachedResponse;
      }

      // B) Nemáme to? Stiahni zo siete.
      return fetch(request).then((networkResponse) => {
        // Skontrolujeme, či je odpoveď platná
        if (!networkResponse || networkResponse.status !== 200 || (networkResponse.type !== 'basic' && networkResponse.type !== 'cors')) {
          return networkResponse;
        }

        // Ak je to platná odpoveď (napr. obrázok alebo nový skript), ulož ju do Runtime cache pre budúcnosť
        const responseToCache = networkResponse.clone();
        caches.open(RUNTIME_CACHE).then((cache) => {
          cache.put(request, responseToCache);
        });

        return networkResponse;
      }).catch(() => {
        // C) Sme offline a nemáme to v cache?
        console.warn('[SW] Offline a súbor chýba v cache:', request.url);
        
        // OPRAVA CHYBY Z KONZOLY:
        // Vrátime "falošnú" odpoveď, aby prehliadač nevyhodil "Uncaught TypeError"
        // 408 Request Timeout je vhodný kód pre offline stav
        return new Response('Offline - resource not available', {
          status: 408,
          statusText: 'Request Timeout (Offline)',
          headers: { 'Content-Type': 'text/plain; charset=utf-8' }
        });
      });
    })
  );
});

// 3. AKTIVÁCIA: Vyčisti starý bordel (v19, v18...)
self.addEventListener('activate', (event) => {
  const cacheWhitelist = [STATIC_CACHE, RUNTIME_CACHE];
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (!cacheWhitelist.includes(cacheName)) {
            console.log('[SW] Odstraňujem starú cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => self.clients.claim()) // Prevezmi kontrolu nad stránkou ihneď
  );

});

