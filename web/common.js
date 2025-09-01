/* ===== common.js (factorisé) ===== */
(() => {
  // ---------- Utils & accès globaux ----------
  const $  = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));

  const DEF_API = () =>
    (location.protocol.startsWith('http') ? location.protocol : 'http:') +
    '//' + location.hostname + ':3000';

  const getAPI  = () => (localStorage.getItem('efoot.api') || DEF_API()).replace(/\/+$/, '');
  const getTok  = () => localStorage.getItem('efoot.token') || '';
  const getRole = () => (localStorage.getItem('efoot.role') || 'member').toLowerCase();
  const getExp  = () => +localStorage.getItem('efoot.expAt') || 0;

  function toast(msg){
    const s = document.querySelector('#status');
    if (!s) { console.log(msg); return; }
    s.textContent = msg; s.style.opacity = 1; setTimeout(() => s.style.opacity = .75, 1200);
  }

  async function safeFetch(url, opt = {}, ms = 8000){
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), ms);
    try { return await fetch(url, { signal: ctrl.signal, ...opt }); }
    finally { clearTimeout(t); }
  }

  function logout(){
    ['efoot.token','efoot.role','efoot.expAt'].forEach(k => localStorage.removeItem(k));
    location.href = 'login.html';
  }

  function requireAdmin(){
    if (getRole() !== 'admin') location.replace('accueil.html');
  }

  // Expose minimal API globale
  window.$ = $; window.$$ = $$;
  window.API  = getAPI();
  window.token = getTok();
  window.role  = getRole();
  window.expAt = getExp();
  window.App = { $, $$, getAPI, getToken: getTok, getRole, getExp, toast, safeFetch, logout, requireAdmin };

  /* auto-discovery de l’API (premier chargement, sans action utilisateur) */
  (async function autoDiscoverAPI(){
    if (localStorage.getItem('efoot.api')) return;
    const candidates = [];
    const h = location.hostname;
    if (h.endsWith('.onrender.com')) {
      if (h.includes('-static')) candidates.push('https://' + h.replace('-static', '-api'));
      candidates.push('https://' + h.replace('-static', ''));
    }
    candidates.push(DEF_API());
    for (const base of candidates) {
      try {
        const r = await safeFetch(base.replace(/\/+$/,'') + '/health', { cache:'no-store' }, 2500);
        if (r && r.ok) {
          localStorage.setItem('efoot.api', base.replace(/\/+$/,''));
          location.reload();
          return;
        }
      } catch (_) {}
    }
  })();

  // ---------- Auth guard (toutes pages sauf login) ----------
  (function guard(){
    const here = (location.pathname.split('/').pop() || '').toLowerCase();
    const isLogin = here === '' || here === 'login.html';
    if (isLogin) return;

    const tok = getTok(), exp = getExp();
    if (!tok || Date.now() >= exp) { location.replace('login.html'); return; }

    // Pages admin : tout sauf Admin-Joueurs reste réservé aux admins
    if (here.startsWith('admin-')) {
      const isAdmin = (getRole() || '').toLowerCase() === 'admin';
      const isPlayersAdmin = here === 'admin-joueurs.html';
      
    }
})();

  // ---------- Affichage "adminOnly" ----------
  $$('.adminOnly').forEach(el => el.style.display = (getRole() === 'admin') ? 'inline-flex' : 'none');

  // ---------- Thème ----------
  (function theme(){
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
  (function menu(){
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
  if (logoutBtn) logoutBtn.addEventListener('click', logout);
})();


