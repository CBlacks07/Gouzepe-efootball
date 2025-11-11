/* ===== common.js (refactorisé - sans duplications) ===== */

(() => {
  // ---------- Utils & accès globaux ----------
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));

  const DEF_API = () =>
    (location.protocol.startsWith('http') ? location.protocol : 'http:') +
    '//' + location.hostname + ':3000';

  const getAPI = () => (localStorage.getItem('efoot.api') || DEF_API()).replace(/\/+$/, '');
  const getTok = () => localStorage.getItem('efoot.token') || '';
  const getRole = () => (localStorage.getItem('efoot.role') || 'member').toLowerCase();
  const getExp = () => +localStorage.getItem('efoot.expAt') || 0;

  function toast(msg) {
    const s = document.querySelector('#status');
    if (!s) { console.log(msg); return; }
    s.textContent = msg;
    s.style.opacity = 1;
    setTimeout(() => s.style.opacity = .75, 1200);
  }

  async function safeFetch(url, opt = {}, ms = 8000) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), ms);
    try {
      return await fetch(url, { signal: ctrl.signal, ...opt });
    } finally {
      clearTimeout(t);
    }
  }

  async function clearCaches() {
    try {
      // Préserver quelques clés utiles
      const preserve = new Set(['efoot.theme', 'efoot.api']);
      for (let i = localStorage.length - 1; i >= 0; i--) {
        const k = localStorage.key(i);
        if (!preserve.has(k)) localStorage.removeItem(k);
      }
      try { sessionStorage.clear(); } catch (_) { }
      if ('caches' in window) {
        const keys = await caches.keys();
        for (const k of keys) await caches.delete(k);
      }
    } catch (_) { }
  }

  async function logout() {
    const token = getTok();
    try {
      await fetch(getAPI() + '/auth/logout', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + token }
      });
    } catch (_) { }
    await clearCaches();
    setTimeout(() => location.replace('login.html'), 180);
  }

  function requireAdmin() {
    if (getRole() !== 'admin') location.replace('Accueil.html');
  }

  // Expose minimal API globale
  window.$ = $;
  window.$$ = $$;
  window.API = getAPI();
  window.token = getTok();
  window.role = getRole();
  window.expAt = getExp();
  window.App = { $, $$, getAPI, getToken: getTok, getRole, getExp, toast, safeFetch, logout, requireAdmin };

  // ---------- Inject favicon/logo pour toutes les pages ----------
  (function ensureFavicon() {
    const head = document.head || document.getElementsByTagName('head')[0];
    if (!head) return;

    // Si une icône existe déjà, ne rien faire
    if (head.querySelector('link[rel~="icon"], link[rel="shortcut icon"]')) return;

    const href = 'assets/fond.png';
    const sizes = ['32x32', '192x192'];
    const links = [
      ['icon', 'image/png', sizes[0], href],
      ['icon', 'image/png', sizes[1], href],
      ['apple-touch-icon', 'image/png', '180x180', href],
      ['shortcut icon', 'image/png', '', href]
    ];

    links.forEach(([rel, type, size, url]) => {
      const l = document.createElement('link');
      l.setAttribute('rel', rel);
      if (type) l.setAttribute('type', type);
      if (size) l.setAttribute('sizes', size);
      l.setAttribute('href', url);
      head.appendChild(l);
    });

    // Couleur de thème pour adresse barre mobile
    if (!head.querySelector('meta[name="theme-color"]')) {
      const m = document.createElement('meta');
      m.setAttribute('name', 'theme-color');
      m.setAttribute('content', '#0b1119');
      head.appendChild(m);
    }
  })();

  // ---------- Auto-discovery de l'API (simplifié) ----------
  (function initAPI() {
    if (!localStorage.getItem('efoot.api')) {
      localStorage.setItem('efoot.api', DEF_API());
    }
  })();

  // ---------- Auth guard (toutes pages sauf login) ----------
  // NOTE: login.html ne doit PAS charger common.js pour éviter les boucles
  (function guard() {
    // Protection absolue contre les boucles: vérifier qu'on peut rediriger
    if (sessionStorage.getItem('_guard_running')) {
      console.warn('[Guard] Boucle détectée, abandon du guard');
      return;
    }
    sessionStorage.setItem('_guard_running', '1');
    setTimeout(() => sessionStorage.removeItem('_guard_running'), 500);

    // Vérification du token et redirection si nécessaire
    const tok = getTok(), exp = getExp();

    // Si pas de token OU token expiré
    if (!tok || (exp > 0 && Date.now() >= exp)) {
      // Éviter les boucles: ne rediriger que si on n'est pas déjà en train de rediriger
      if (!sessionStorage.getItem('_redirecting')) {
        sessionStorage.setItem('_redirecting', '1');
        setTimeout(() => sessionStorage.removeItem('_redirecting'), 1000);
        location.replace('login.html');
      }
      return;
    }

    // Pages admin : vérification + redirection si non-admin
    const pathname = location.pathname.toLowerCase();
    const filename = pathname.split('/').pop() || '';
    if (filename.startsWith('admin-')) {
      const isAdmin = getRole() === 'admin';
      const isPlayersAdmin = filename === 'admin-joueurs.html';

      // Admin-Joueurs accessible aux membres, autres pages admin réservées
      if (!isAdmin && !isPlayersAdmin) {
        if (!sessionStorage.getItem('_redirecting')) {
          sessionStorage.setItem('_redirecting', '1');
          setTimeout(() => sessionStorage.removeItem('_redirecting'), 1000);
          location.replace('Accueil.html');
        }
        return;
      }
    }
  })();

  // ---------- Affichage "adminOnly" ----------
  $$('.adminOnly').forEach(el => el.style.display = (getRole() === 'admin') ? 'inline-flex' : 'none');

  // ---------- Thème ----------
  (function theme() {
    const k = 'efoot.theme';
    const btn = document.querySelector('#theme');
    const apply = (m) => {
      document.documentElement.classList.toggle('light', m === 'light');
      localStorage.setItem(k, m);
      if (btn) btn.textContent = (m === 'light') ? '🌙' : '☀️';
    };
    apply(localStorage.getItem(k) || 'dark');
    if (btn) btn.addEventListener('click', () =>
      apply(document.documentElement.classList.contains('light') ? 'dark' : 'light'));
  })();

  // ---------- Menu mobile ----------
  (function menu() {
    const btn = document.querySelector('#menuToggle');
    const menu = document.querySelector('#menu');
    if (!btn || !menu) return;
    btn.addEventListener('click', () => {
      const open = menu.classList.toggle('open');
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      btn.setAttribute('aria-label', open ? 'Fermer le menu' : 'Ouvrir le menu');
    });
    document.addEventListener('click', (e) => {
      if (!menu.classList.contains('open')) return;
      if (e.target === btn || menu.contains(e.target)) return;
      menu.classList.remove('open');
      btn.setAttribute('aria-expanded', 'false');
      btn.setAttribute('aria-label', 'Ouvrir le menu');
    });
  })();

  // ---------- Logout ----------
  const logoutBtn = document.querySelector('#logoutBtn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      if (!confirm('Voulez-vous vraiment vous déconnecter ?')) return;
      await logout();
    });
  }
})();
