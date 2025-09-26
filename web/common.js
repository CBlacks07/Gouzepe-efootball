/* ===== common.js (factorisÃ©) ===== */
(() => {
  // ---------- Utils & accÃ¨s globaux ----------
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
    if (getRole() !== 'admin') location.replace('Accueil.html');
  }

  // Expose minimal API globale
  window.$ = $; window.$$ = $$;
  window.API  = getAPI();
  window.token = getTok();
  window.role  = getRole();
  window.expAt = getExp();
  window.App = { $, $$, getAPI, getToken: getTok, getRole, getExp, toast, safeFetch, logout, requireAdmin };

  /* auto-discovery de lâ€™API (premier chargement, sans action utilisateur) */
  (async function autoDiscoverAPI(){
    if (localStorage.getItem('efoot.api')) return;
    const candidates = [PROD_API];
    const h = location.hostname;
    if (h.endsWith('.onrender.com')) {
      if (/-app\b/.test(h)) candidates.unshift('https://' + h.replace('-app','-api'));
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

    // Pages admin : tout sauf Admin-Joueurs reste rÃ©servÃ© aux admins
    if (here.startsWith('admin-')) {
      const isAdmin = (getRole() || '').toLowerCase() === 'admin';
      const isPlayersAdmin = here === 'admin-joueurs.html';
      
    }
})();

  // ---------- Affichage "adminOnly" ----------
  $$('.adminOnly').forEach(el => el.style.display = (getRole() === 'admin') ? 'inline-flex' : 'none');

  // ---------- ThÃ¨me ----------
  (function theme(){
    const k = 'efoot.theme';
    const btn = document.querySelector('#theme');
    const apply = (m) => {
      document.documentElement.classList.toggle('light', m === 'light');
      localStorage.setItem(k, m);
      if (btn) btn.textContent = (m === 'light') ? 'ðŸŒ™' : 'â˜€ï¸';
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



(async function bindLogout(){
  const btn = document.getElementById('logoutBtn');
  if(!btn) return;

  // utilitaires
  const isPrivateNet = (h)=>/^(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)$/.test(h);
  const API = (localStorage.getItem('efoot.api')||DEF_API()).replace(/\/+$/,'');

  async function clearCaches(){
    try{
      // PrÃ©server quelques clÃ©s utiles
      const preserve = new Set(['efoot.theme','efoot.api']);
      for(let i=localStorage.length-1; i>=0; i--){
        const k = localStorage.key(i);
        if(!preserve.has(k)) localStorage.removeItem(k);
      }
      try{ sessionStorage.clear(); }catch(_){}
      if('caches' in window){
        const keys = await caches.keys();
        for(const k of keys) await caches.delete(k);
      }
    }catch(_){}
  }

  async function fullLogout(){
    const token = localStorage.getItem('efoot.token');
    try{
      await fetch(API+'/auth/logout',{ method:'POST', headers:{ Authorization:'Bearer '+token } });
    }catch(_){}
    await clearCaches();
    // petite latence pour flush
    setTimeout(()=> location.replace('login.html'), 180);
  }

  btn.addEventListener('click', async ()=>{
    if(!confirm('Voulez-vous vraiment vous dÃ©connecter ?')) return;
    await fullLogout();
  });
})();
