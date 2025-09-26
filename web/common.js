/* ===== common.js (Render-ready, API par défaut: https://gouzepe-api.onrender.com) ===== */
(() => {
  const $  = (s) => document.querySelector(s);
  const $$ = (s) => Array.from(document.querySelectorAll(s));

  const PROD_DEFAULT = "https://gouzepe-api.onrender.com".replace(/\/+$/,''); // ← ton API Render
  const isPrivateNet = (h)=>/^(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)$/.test(h);

  function DEF_API(){
    const host = location.hostname || 'localhost';
    if(isPrivateNet(host)){
      const proto = location.protocol.startsWith('http') ? location.protocol : 'http:';
      return proto + '//' + host + ':3000';
    }
    // En prod: on utilise directement ton API Render
    return PROD_DEFAULT;
  }

  function getAPI(){ return (localStorage.getItem('efoot.api') || DEF_API()).replace(/\/+$/,''); }
  function setAPI(v){ localStorage.setItem('efoot.api', (v||'').replace(/\/+$/,'')); }
  function getTok(){ return localStorage.getItem('efoot.token') || ''; }
  function getRole(){ return (localStorage.getItem('efoot.role')||'member').toLowerCase(); }
  function getExp(){ return +localStorage.getItem('efoot.expAt') || 0; }

  async function safeFetch(url, opt = {}, ms = 10000){
    const ctrl = new AbortController();
    const t = setTimeout(()=>ctrl.abort(), ms);
    try { return await fetch(url, { signal: ctrl.signal, ...opt }); }
    finally { clearTimeout(t); }
  }

  async function waitForHealth(base, maxMs=45000){
    const start = Date.now();
    let delay = 900;
    while(Date.now()-start < maxMs){
      try{
        const r = await safeFetch(base + '/health', { cache:'no-store' }, Math.min(4000, delay));
        if(r && r.ok) return true;
      }catch(_){}
      await new Promise(res=>setTimeout(res, delay));
      delay = Math.min(5000, Math.round(delay*1.5));
    }
    return false;
  }

  async function logout(){
    try{
      const token = getTok();
      if(token) await safeFetch(getAPI()+'/auth/logout', { method:'POST', headers:{Authorization:'Bearer '+token} }, 6000);
    }catch(_){}
    const keep = new Map([['efoot.theme', localStorage.getItem('efoot.theme')], ['efoot.api', getAPI()]]);
    localStorage.clear();
    keep.forEach((v,k)=> v!=null && localStorage.setItem(k,v));
    location.replace('login.html');
  }

  // Expose
  window.$ = $; window.$$ = $$;
  window.API = getAPI;     // ATTENTION : c'est une FONCTION => toujours faire API()
  window.token = getTok();
  window.role  = getRole();
  window.expAt = getExp();
  window.App = { $, $$, getAPI, setAPI, getToken:getTok, getRole, getExp, waitForHealth, logout };

  // Auto-config première visite : impose ton API Render si rien n'est défini
  (function ensureAPI(){
    if(!localStorage.getItem('efoot.api')){
      localStorage.setItem('efoot.api', PROD_DEFAULT);
      // pas de reload obligatoire; les prochains fetch utiliseront API()
    }
  })();

  // Auth guard (toutes pages sauf login)
  (function guard(){
    const here = (location.pathname.split('/').pop() || '').toLowerCase();
    const isLogin = here === '' || here === 'login.html';
    if (isLogin) return;
    const tok = getTok(), exp = getExp();
    if (!tok || Date.now() >= exp) { location.replace('login.html'); return; }
    if (here.startsWith('admin-') && getRole() !== 'admin') { location.replace('Accueil.html'); return; }
    $$('.adminOnly').forEach(el => el.style.display = (getRole() === 'admin') ? 'inline-flex' : 'none');
  })();

  // Thème
  (function theme(){
    const k='efoot.theme'; const btn = document.querySelector('#theme');
    const apply = (m)=>{ document.documentElement.classList.toggle('light', m==='light'); localStorage.setItem(k,m); if(btn) btn.textContent=(m==='light')?'🌙':'☀️'; };
    apply(localStorage.getItem(k)||'dark');
    btn?.addEventListener('click', ()=> apply(document.documentElement.classList.contains('light') ? 'dark' : 'light'));
  })();

  // Menu mobile
  (function menu(){
    const btn=$('#menuToggle'), menu=$('#menu'); if(!btn||!menu) return;
    btn.addEventListener('click', (ev)=>{ ev.stopPropagation(); const open=menu.classList.toggle('open'); btn.setAttribute('aria-expanded', open?'true':'false'); }, {passive:true});
    document.addEventListener('click', (e)=>{ if(!menu.classList.contains('open')) return; if(e.target===btn||menu.contains(e.target)) return; menu.classList.remove('open'); btn.setAttribute('aria-expanded','false'); }, true);
    document.addEventListener('keydown', (e)=>{ if(e.key==='Escape'&&menu.classList.contains('open')){ menu.classList.remove('open'); btn.setAttribute('aria-expanded','false'); } });
  })();

  // Logout button (si présent)
  document.querySelector('#logoutBtn')?.addEventListener('click', (e)=>{ e.preventDefault(); logout(); });
})();
