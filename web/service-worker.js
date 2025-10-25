// GOUZEPE eFOOTBALL - Service Worker PWA
const CACHE_NAME = 'gouzepe-efoot-v1.0.0';
const API_CACHE = 'gouzepe-api-cache-v1';

// Fichiers essentiels à mettre en cache
const STATIC_ASSETS = [
  '/web/Accueil.html',
  '/web/login.html',
  '/web/Duel.html',
  '/web/Classement-general.html',
  '/web/Panel-Membre.html',
  '/web/Admin-Joueurs.html',
  '/web/Admin-Utilisateurs.html',
  '/web/common.js',
  '/web/theme.css',
  '/web/common.css',
  '/web/manifest.json',
  '/web/assets/fond.png'
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
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Offline - GOUZEPE</title>
          <style>
            body {
              font-family: system-ui;
              display: flex;
              align-items: center;
              justify-content: center;
              height: 100vh;
              margin: 0;
              background: linear-gradient(135deg, #0b1119 0%, #1a2332 100%);
              color: #e5e7eb;
              text-align: center;
              padding: 20px;
            }
            .container { max-width: 400px; }
            h1 { font-size: 48px; margin: 0 0 20px; }
            p { font-size: 18px; line-height: 1.6; opacity: 0.9; }
            .btn {
              display: inline-block;
              margin-top: 20px;
              padding: 12px 24px;
              background: #16a34a;
              color: white;
              border-radius: 8px;
              text-decoration: none;
              font-weight: 600;
            }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>⚽</h1>
            <h2>Vous êtes hors ligne</h2>
            <p>Impossible de charger cette page. Vérifiez votre connexion Internet.</p>
            <a href="/web/Accueil.html" class="btn">Réessayer</a>
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
