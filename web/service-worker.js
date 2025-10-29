// GOUZEPE eFOOTBALL - Service Worker PWA
const CACHE_NAME = 'gouzepe-efoot-v1.1.0';
const API_CACHE = 'gouzepe-api-cache-v1';

// Fichiers essentiels à mettre en cache (chemins relatifs)
const STATIC_ASSETS = [
  './',
  './Accueil.html',
  './login.html',
  './Duel.html',
  './Classement-general.html',
  './Panel-Membre.html',
  './Admin-Joueurs.html',
  './Admin-Utilisateurs.html',
  './common.js',
  './theme.css',
  './common.css',
  './mobile.css',
  './manifest.json',
  './assets/fond.png',
  './assets/icons/apple-touch-icon.png'
];

// Installation du service worker
self.addEventListener('install', event => {
  console.log('[SW] Installation...');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('[SW] Mise en cache des assets statiques');
        return cache.addAll(STATIC_ASSETS.map(url => new Request(url, { cache: 'reload' })));
      })
      .then(() => self.skipWaiting())
      .catch(err => console.error('[SW] Erreur installation:', err))
  );
});

// Activation et nettoyage des anciens caches
self.addEventListener('activate', event => {
  console.log('[SW] Activation...');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames
          .filter(name => name !== CACHE_NAME && name !== API_CACHE)
          .map(name => {
            console.log('[SW] Suppression ancien cache:', name);
            return caches.delete(name);
          })
      );
    }).then(() => self.clients.claim())
  );
});

// Stratégie de cache
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Ignorer les requêtes non-HTTP
  if (!url.protocol.startsWith('http')) return;

  // Stratégie pour les API calls
  if (url.pathname.includes('/api/') || url.port === '3000' || url.port === '10000') {
    event.respondWith(networkFirstThenCache(request));
    return;
  }

  // Stratégie pour les assets statiques
  event.respondWith(cacheFirstThenNetwork(request));
});

// Network First (pour API) - essaie le réseau d'abord, puis cache
async function networkFirstThenCache(request) {
  try {
    const response = await fetch(request);
    // Mise en cache uniquement pour GET
    if (request.method === 'GET' && response.ok) {
      const cache = await caches.open(API_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    const cached = await caches.match(request);
    if (cached) {
      console.log('[SW] API depuis cache:', request.url);
      return cached;
    }
    // Retourner une réponse offline
    return new Response(JSON.stringify({ error: 'Offline', offline: true }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Cache First (pour assets) - cherche dans le cache d'abord
async function cacheFirstThenNetwork(request) {
  const cached = await caches.match(request);
  if (cached) {
    // Refresh en arrière-plan
    fetch(request).then(response => {
      if (response.ok) {
        caches.open(CACHE_NAME).then(cache => cache.put(request, response));
      }
    }).catch(() => {});
    return cached;
  }

  try {
    const response = await fetch(request);
    if (response.ok && request.method === 'GET') {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    // Page offline de secours
    if (request.destination === 'document') {
      return new Response(`
        <!DOCTYPE html>
        <html lang="fr">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
          <title>Offline - GOUZEPE</title>
          <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
              font-family: system-ui, -apple-system, sans-serif;
              display: flex;
              align-items: center;
              justify-content: center;
              min-height: 100vh;
              background: linear-gradient(135deg, #0b1119 0%, #1a2332 100%);
              color: #e5e7eb;
              text-align: center;
              padding: env(safe-area-inset-top, 20px) env(safe-area-inset-right, 20px) env(safe-area-inset-bottom, 20px) env(safe-area-inset-left, 20px);
            }
            .container { max-width: 400px; padding: 20px; }
            h1 { font-size: 64px; margin: 0 0 20px; }
            h2 { font-size: 24px; margin: 0 0 12px; font-weight: 700; }
            p { font-size: 16px; line-height: 1.6; opacity: 0.9; margin: 0 0 24px; }
            .btn {
              display: inline-block;
              padding: 14px 28px;
              background: #16a34a;
              color: white;
              border-radius: 12px;
              text-decoration: none;
              font-weight: 600;
              font-size: 16px;
              transition: transform 0.2s;
            }
            .btn:active { transform: scale(0.95); }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>⚽</h1>
            <h2>Vous êtes hors ligne</h2>
            <p>Impossible de charger cette page. Vérifiez votre connexion Internet.</p>
            <a href="./login.html" class="btn">Réessayer</a>
          </div>
        </body>
        </html>
      `, {
        status: 503,
        headers: { 'Content-Type': 'text/html' }
      });
    }
    throw error;
  }
}

// Messages depuis l'application
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
