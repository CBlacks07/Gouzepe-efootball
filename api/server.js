// server.js — GOUZEPE eFOOT API (Express + PostgreSQL + Socket.IO)
require('dotenv').config();

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const helmet = require('helmet');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const dayjs = require('dayjs');

const PORT = parseInt(process.env.PORT || '3000', 10);
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const JWT_SECRET = process.env.JWT_SECRET || '1XS1r4QJNp6AtkjORvKUU01RZRfzbGV+echJsio9gq8lAOc2NW7sSYsQuncE6+o9';
const EMAIL_DOMAIN = process.env.EMAIL_DOMAIN || 'gz.local';

const useSSL = (process.env.PGSSL === 'true') || process.env.RENDER === 'true' || process.env.NODE_ENV === 'production';
const pool = new Pool({
  host: process.env.PGHOST || '127.0.0.1',
  port: +(process.env.PGPORT || 5432),
  database: process.env.PGDATABASE || 'EFOOTBALL',
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || 'Admin123',
  ssl: useSSL ? { rejectUnauthorized: false } : false,
});

const app = express();
const server = http.createServer(app);
const io = require('socket.io')(server, {
  cors: { origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN, methods: ['GET','POST','PUT','DELETE'] }
});

app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN, credentials: true }));
app.use(express.json({ limit: '2mb' }));

/* ---------- uploads (photos profils joueurs) ---------- */
const UP = path.join(__dirname, 'uploads');
const UP_PLAYERS = path.join(UP, 'players');
if(!fs.existsSync(UP)) fs.mkdirSync(UP);
if(!fs.existsSync(UP_PLAYERS)) fs.mkdirSync(UP_PLAYERS);
app.use('/uploads', express.static(UP));

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb)=> cb(null, UP_PLAYERS),
    filename: (req, file, cb)=>{
      const ext = (file.originalname||'jpg').toLowerCase().split('.').pop();
      const who = req.user?.player_id || 'unknown';
      cb(null, `${who}_${Date.now().toString(36)}.${ext}`);
    }
  }),
  fileFilter: (_req,file,cb)=> cb(/^image\/(png|jpe?g|webp|gif)$/i.test(file.mimetype||'')?null:new Error('image requise'), true),
  limits:{ fileSize: 2*1024*1024 }
});

/* ---------- helpers ---------- */
const q   = (sql, params=[]) => pool.query(sql, params);
const ok  = (res, data={}) => res.json(data);
const bad = (res, code=400, msg='Bad request') => res.status(code).json({ error: String(msg) });
const normEmail = (x)=>{ x=String(x||'').trim().toLowerCase(); if(!x) return x; if(!x.includes('@')) x=`${x}@${EMAIL_DOMAIN}`; return x; };

/* === présence (soft, en mémoire) === */
const PRESENCE_TTL_MS = 70 * 1000;
const presence = { players: new Map() }; // player_id -> lastSeen (ms)

/* === Equipes différentes (basées sur "Champion avec ...") === */
const TEAM_KEY_LEN = parseInt(process.env.TEAM_KEY_LEN || '6', 10);
function teamKey(raw){
  if(!raw) return '';
  let s = String(raw)
    .normalize('NFD').replace(/[\u0300-\u036f]/g,'')                 // accents
    .replace(/\p{Emoji_Presentation}|\p{Extended_Pictographic}/gu,'')// emoji/drapeaux
    .toUpperCase()
    .replace(/\b(FC|CF|SC|AC|REAL|THE)\b/g, ' ')                    // mots vides fréquents
    .replace(/[^A-Z0-9]+/g,'')                                      // garde lettres/chiffres
    .trim();
  return s.slice(0, TEAM_KEY_LEN);                                  // ex: 6 premières lettres
}

/* ---------- schéma & seed ---------- */
async function ensureSchema(){
  await q(`CREATE TABLE IF NOT EXISTS players(
    player_id TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    role      TEXT NOT NULL DEFAULT 'MEMBRE',
    profile_pic_url TEXT,
    created_at TIMESTAMP DEFAULT now()
  )`);
  await q(`ALTER TABLE players ADD COLUMN IF NOT EXISTS profile_pic_url TEXT`);

  await q(`CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    player_id TEXT,
    created_at TIMESTAMP DEFAULT now()
  )`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS player_id TEXT`);
  await q(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE constraint_name='users_player_id_fkey'
      ) THEN
        ALTER TABLE users
          ADD CONSTRAINT users_player_id_fkey
          FOREIGN KEY (player_id) REFERENCES players(player_id)
          ON DELETE SET NULL;
      END IF;
    END$$
  `);
  await q(`CREATE UNIQUE INDEX IF NOT EXISTS users_player_id_uniq ON users(player_id) WHERE player_id IS NOT NULL`);

  await q(`CREATE TABLE IF NOT EXISTS seasons(
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ,
    is_closed BOOLEAN NOT NULL DEFAULT false
  )`);
  await q(`CREATE TABLE IF NOT EXISTS matchday(
    day DATE PRIMARY KEY,
    season_id INTEGER REFERENCES seasons(id),
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS draft(
    day DATE PRIMARY KEY,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now()
  )`);

  // admin par défaut
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@gz.local';
  const adminPass  = process.env.ADMIN_PASSWORD || 'admin';
  const row = await q(`SELECT id FROM users WHERE email=$1`,[adminEmail]);
  if(row.rowCount===0){
    const hash = await bcrypt.hash(adminPass,10);
    await q(`INSERT INTO users(email,password_hash,role) VALUES ($1,$2,'admin')`,[adminEmail,hash]);
    console.log(`Seed admin: ${adminEmail} / ${adminPass}`);
  }

  // saison ouverte si aucune
  const s = await q(`SELECT id FROM seasons WHERE is_closed=false ORDER BY id DESC LIMIT 1`);
  if(s.rowCount===0){
    await q(`INSERT INTO seasons(name,is_closed) VALUES ('Saison courante', false)`);
  }
}

/* ---------- auth middlewares ---------- */
function signToken(user){
  return jwt.sign({ uid:user.id, role:user.role, email:user.email }, JWT_SECRET, { expiresIn: '48h' });
}
function auth(req,res,next){
  try{
    const h=req.headers.authorization||'';
    const tok=h.startsWith('Bearer ')?h.slice(7):'';
    if(!tok) return bad(res,401,'No token');
    req.user = jwt.verify(tok, JWT_SECRET);
    next();
  }catch(e){ return bad(res,401,'Invalid token'); }
}
function adminOnly(req,res,next){
  if((req.user?.role||'member')!=='admin') return bad(res,403,'Admin only');
  next();
}

/* ---------- helpers saisons ---------- */
async function currentSeasonId(){
  const r=await q(`SELECT id FROM seasons WHERE is_closed=false ORDER BY id DESC LIMIT 1`);
  return r.rows[0]?.id;
}
async function previousSeasonId(){
  const r=await q(`SELECT id FROM seasons WHERE is_closed=true ORDER BY id DESC LIMIT 1`);
  return r.rows[0]?.id || null;
}
async function resolveSeasonId(qv){
  if(!qv || String(qv).toLowerCase()==='current') return await currentSeasonId();
  if(String(qv).toLowerCase()==='previous') {
    const p = await previousSeasonId(); return p || await currentSeasonId();
  }
  if(/^\d+$/.test(String(qv))){
    const sid = +qv;
    const r=await q(`SELECT id FROM seasons WHERE id=$1`,[sid]);
    return r.rowCount ? sid : await currentSeasonId();
  }
  const r=await q(`SELECT id FROM seasons WHERE name ILIKE $1 ORDER BY id DESC LIMIT 1`, ['%'+qv+'%']);
  return r.rowCount ? r.rows[0].id : await currentSeasonId();
}
async function getPlayersRoles(){
  const r=await q(`SELECT player_id,role FROM players`);
  const map=new Map(); r.rows.forEach(p=>map.set(p.player_id,(p.role||'MEMBRE').toUpperCase())); return map;
}

/* ---------- calculs standings (par journée) ---------- */
function computeStandings(matches){
  // matches: [{p1,p2,a1,a2,r1,r2}]
  const agg={};
  function add(A,B,ga,gb){
    if(ga==null||gb==null) return;
    if(!agg[A]) agg[A]={J:0,V:0,N:0,D:0,BP:0,BC:0};
    if(!agg[B]) agg[B]={J:0,V:0,N:0,D:0,BP:0,BC:0};
    agg[A].J++; agg[B].J++;
    agg[A].BP+=ga; agg[A].BC+=gb;
    agg[B].BP+=gb; agg[B].BC+=ga;
    if(ga>gb){ agg[A].V++; agg[B].D++; }
    else if(ga<gb){ agg[B].V++; agg[A].D++; }
    else { agg[A].N++; agg[B].N++; }
  }
  for(const m of matches||[]){
    if(!m.p1||!m.p2) continue;
    if(m.a1!=null&&m.a2!=null) add(m.p1,m.p2,m.a1,m.a2);
    if(m.r1!=null&&m.r2!=null) add(m.p2,m.p1,m.r2,m.r1); // retour inversé
  }
  const arr = Object.entries(agg).map(([id,x])=>({id,...x,PTS:x.V*3+x.N,DIFF:x.BP-x.BC}));
  arr.sort((a,b)=>b.PTS-a.PTS||b.DIFF-a.DIFF||b.BP-a.BP||a.id.localeCompare(b.id));
  return arr;
}

/* ---------- barème saison & outils ---------- */
const BONUS_D1_CHAMPION = 1;
function pointsD1(nPlayers, rank){ if(rank<1||rank>nPlayers) return 0; return 9+(nPlayers-rank); }
function pointsD2(rank){ const table=[10,8,7,6,5,4,3,2,1,1,1]; return rank>0 && rank<=table.length ? table[rank-1] : 1; }

/* ---------- standings de la saison (tri = Moyenne puis Total) ---------- */
async function computeSeasonStandings(seasonId){
  const days = await q(`SELECT day,payload FROM matchday WHERE season_id=$1 ORDER BY day ASC`,[seasonId]);
  const roles = await getPlayersRoles();
  const seasonDaysCount = days.rowCount;

  // cumuls "points/participations/gains/équipes"
  const totals = new Map(); // id -> {id,total,participations,won_d1,won_d2,teams:Set}
  const ensure = id=>{
    if(!totals.has(id)) totals.set(id,{id,total:0,participations:0,won_d1:0,won_d2:0,teams:new Set()});
    return totals.get(id);
  };

  // agrégat "forme & win%" sur toutes les manches de la saison
  const legsAgg = new Map(); // id -> {J,V,N,D,BP,BC,form:[]}
  const addLeg = (id)=>{ if(!legsAgg.has(id)) legsAgg.set(id,{J:0,V:0,N:0,D:0,BP:0,BC:0,form:[]}); return legsAgg.get(id); };

  for(const row of days.rows){
    const p=row.payload||{};
    const st1Full=computeStandings(p.d1||[]);
    const st2Full=computeStandings(p.d2||[]);

    // classement jour : seulement MEMBRE
    const st1 = st1Full.filter(r => (roles.get(r.id)||'MEMBRE')!=='INVITE');
    const st2 = st2Full.filter(r => (roles.get(r.id)||'MEMBRE')!=='INVITE');
    const n1=st1.length, n2=st2.length;

    st1.forEach((r,idx)=>{ const o=ensure(r.id); o.total += pointsD1(n1, idx+1); o.participations+=1; });
    st2.forEach((r,idx)=>{ const o=ensure(r.id); o.total += pointsD2(idx+1);   o.participations+=1; });

    // Bonus & compte de titres
    const champD1=p?.champions?.d1?.id||null;
    if(champD1 && (roles.get(champD1)||'MEMBRE')!=='INVITE'){ ensure(champD1).total += BONUS_D1_CHAMPION; ensure(champD1).won_d1++; }
    const champD2=p?.champions?.d2?.id||null;
    if(champD2 && (roles.get(champD2)||'MEMBRE')!=='INVITE'){ ensure(champD2).won_d2++; }

    // Equipes différentes (via "Champion avec ...")
    const teamD1 = p?.champions?.d1?.team;
    if (champD1 && teamD1){ const k=teamKey(teamD1); if(k) ensure(champD1).teams.add(k); }
    const teamD2 = p?.champions?.d2?.team;
    if (champD2 && teamD2){ const k=teamKey(teamD2); if(k) ensure(champD2).teams.add(k); }

    // === agrégat des manches pour Win% & Forme ===
    const applyLegs = (rows, div)=>{
      for(const m of rows||[]){
        if(!m.p1||!m.p2) continue;
        const A=m.p1, B=m.p2;
        const a = addLeg(A), b = addLeg(B);
        if(m.a1!=null && m.a2!=null){
          a.J++; b.J++; a.BP+=m.a1; a.BC+=m.a2; b.BP+=m.a2; b.BC+=m.a1;
          if(m.a1>m.a2){ a.V++; b.D++; a.form.push('W'); b.form.push('L'); }
          else if(m.a1<m.a2){ b.V++; a.D++; b.form.push('W'); a.form.push('L'); }
          else { a.N++; b.N++; a.form.push('D'); b.form.push('D'); }
        }
        if(m.r1!=null && m.r2!=null){
          // match retour: joueurs inversés pour "sens domicile"
          a.J++; b.J++; a.BP+=m.r2; a.BC+=m.r1; b.BP+=m.r1; b.BC+=m.r2;
          if(m.r2>m.r1){ a.V++; b.D++; a.form.push('W'); b.form.push('L'); }
          else if(m.r2<m.r1){ b.V++; a.D++; b.form.push('W'); a.form.push('L'); }
          else { a.N++; b.N++; a.form.push('D'); b.form.push('D'); }
        }
      }
    };
    applyLegs(p.d1||[],1);
    applyLegs(p.d2||[],2);
  }

  // noms + métriques dérivées
  const allIds=[...totals.keys()];
  const nameById = new Map();
  if(allIds.length){
    const r=await q(`SELECT player_id,name FROM players WHERE player_id=ANY($1::text[])`,[allIds]);
    r.rows.forEach(x=> nameById.set(x.player_id, x.name));
  }

  const threshold = Math.ceil(seasonDaysCount*0.25) || 0;
  const arr=[...totals.values()].map(o=>{
    const L = legsAgg.get(o.id) || {J:0,V:0,N:0,D:0,BP:0,BC:0,form:[]};
    const moyenne = o.participations>0 ? +(o.total/o.participations).toFixed(2) : 0;
    const win_pct = L.J ? Math.round((L.V*100)/L.J) : 0;
    const form5   = (L.form||[]).slice(-5).join('');
    const participation_pct = seasonDaysCount ? Math.round(o.participations*100/seasonDaysCount) : 0;
    return {
      id:o.id,
      name: nameById.get(o.id)||o.id,
      total:o.total,
      participations:o.participations,
      moyenne,
      won_d1:o.won_d1,
      won_d2:o.won_d2,
      teams_used:o.teams?o.teams.size:0,
      win_pct,
      form5,
      participation_pct,
      classified: o.participations >= threshold
    };
  });

  // >>> TRI PRINCIPAL : Moyenne DESC, puis Total DESC, puis Win% DESC, puis Nom ASC
 arr.sort((a,b)=>
  (b.moyenne - a.moyenne) ||
  (b.total   - a.total)   ||
  (a.name || a.id).localeCompare(b.name || b.id)
);
  return arr;
}

/* ---------- health ---------- */
app.get('/health', (_req,res)=> ok(res,{ ok:true, service:'gouzepe-api', ts:Date.now() }));

/* ---------- auth ---------- */
app.post('/auth/login', async (req,res)=>{
  let {email,password}=req.body||{};
  email = normEmail(email);
  if(!email||!password) return bad(res,400,'email/password requis');
  const r=await q(`SELECT * FROM users WHERE email=$1`,[email]);
  if(r.rowCount===0) return bad(res,401,'Utilisateur inconnu');
  const u=r.rows[0];
  const match = await bcrypt.compare(password, u.password_hash);
  if(!match) return bad(res,401,'Mot de passe incorrect');
  const token = signToken(u);
  ok(res,{ token, user:{id:u.id,email:u.email,role:u.role}, expHours:48 });
});
app.get('/auth/me', auth, async (req,res)=>{
  const r=await q(`SELECT id,email,role,player_id FROM users WHERE id=$1`,[req.user.uid]);
  if(r.rowCount===0) return bad(res,404,'User not found');
  ok(res,{ user:r.rows[0] });
});

/* ---------- presence ---------- */
async function getLinkedPlayerId(userId){
  const r=await q(`SELECT player_id FROM users WHERE id=$1`,[userId]);
  return r.rows[0]?.player_id || null;
}
app.post('/presence/ping', auth, async (req,res)=>{
  const pid = await getLinkedPlayerId(req.user.uid);
  if(pid){ presence.players.set(pid, Date.now()); }
  ok(res,{ ok:true, now:Date.now() });
});
app.get('/presence/online', auth, async (_req,res)=>{
  const now=Date.now();
  const online=[];
  for(const [pid,ts] of presence.players){
    if(now - ts < PRESENCE_TTL_MS) online.push({ player_id:pid, lastSeen:ts });
  }
  ok(res,{ online });
});

/* ---------- admin users ---------- */
app.get('/admin/users', auth, adminOnly, async (_req,res)=>{
  const r=await q(`SELECT id,email,role,created_at FROM users ORDER BY created_at DESC NULLS LAST, id DESC`);
  ok(res,{ users:r.rows });
});
app.post('/admin/users', auth, adminOnly, async (req,res)=>{
  let { email, password, role } = req.body||{};
  email = normEmail(email);
  role = (role||'member').toLowerCase()==='admin'?'admin':'member';
  if(!email||!password) return bad(res,400,'email/password requis');
  try{
    const hash=await bcrypt.hash(password,10);
    const r=await q(`INSERT INTO users(email,password_hash,role) VALUES ($1,$2,$3)
                     ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash, role=EXCLUDED.role
                     RETURNING id,email,role,created_at`,[email,hash,role]);
    ok(res,{ user:r.rows[0] });
  }catch(e){
    if(e.code==='23505') return bad(res,409,'email déjà utilisé');
    throw e;
  }
});
app.put('/admin/users/:id', auth, adminOnly, async (req,res)=>{
  const id=+req.params.id;
  let { email, role, password } = req.body||{};
  email = email ? normEmail(email) : undefined;
  const u=(await q(`SELECT id,email,role FROM users WHERE id=$1`,[id])).rows[0];
  if(!u) return bad(res,404,'introuvable');
  const newEmail = email || u.email;
  const newRole  = (role||u.role)==='admin'?'admin':'member';
  if(password){
    const hash=await bcrypt.hash(password,10);
    await q(`UPDATE users SET email=$1, role=$2, password_hash=$3 WHERE id=$4`,[newEmail,newRole,hash,id]);
  }else{
    await q(`UPDATE users SET email=$1, role=$2 WHERE id=$3`,[newEmail,newRole,id]);
  }
  const r=await q(`SELECT id,email,role,created_at FROM users WHERE id=$1`,[id]);
  ok(res,{ user:r.rows[0] });
});
app.delete('/admin/users/:id', auth, adminOnly, async (req,res)=>{
  await q(`DELETE FROM users WHERE id=$1`,[+req.params.id]);
  ok(res,{ ok:true });
});

/* ---------- players (list/search/profile) ---------- */
function markOnlineField(rows){
  const now=Date.now();
  return rows.map(p=>{
    const ts = presence.players.get(p.player_id);
    const online = ts && (now - ts < PRESENCE_TTL_MS);
    return { ...p, online: !!online };
  });
}
app.get('/players', auth, async (_req,res)=>{
  const r = await q(`
    SELECT p.player_id, p.name, p.role, p.profile_pic_url, u.email AS user_email
    FROM players p
    LEFT JOIN users u ON u.player_id = p.player_id
    ORDER BY p.name ASC
  `);
  ok(res,{ players: markOnlineField(r.rows) });
});
app.get('/players/search', auth, async (req,res)=>{
  const qv=(req.query.q||'').trim();
  if(!qv) return ok(res,{ players:[] });
  const r=await q(`
    SELECT p.player_id, p.name, p.role, p.profile_pic_url, u.email AS user_email
    FROM players p
    LEFT JOIN users u ON u.player_id = p.player_id
    WHERE p.player_id ILIKE $1 OR p.name ILIKE $1
    ORDER BY p.name ASC
    LIMIT 20
  `, ['%'+qv+'%']);
  ok(res,{ players: markOnlineField(r.rows) });
});
app.get('/players/:pid', auth, async (req,res)=>{
  const r=await q(`SELECT player_id,name,role,profile_pic_url FROM players WHERE player_id=$1`,[req.params.pid]);
  if(!r.rowCount) return bad(res,404,'not found');
  const row = r.rows[0];
  const ts = presence.players.get(row.player_id);
  const online = ts && (Date.now()-ts < PRESENCE_TTL_MS);
  ok(res,{ player:{...row, online: !!online} });
});

/* résumé & matches d’un joueur (panel membre) */
app.get('/players/:pid/summary', auth, async (req,res)=>{
  const sid = await resolveSeasonId(req.query.season);
  const r=await q(`SELECT name FROM players WHERE player_id=$1`,[req.params.pid]);
  if(!r.rowCount) return bad(res,404,'not found');

  const days = await q(`SELECT day,payload FROM matchday WHERE season_id=$1 ORDER BY day ASC`,[sid]);
  let legs=0,gf=0,ga=0,best={gf:0,ga:0,date:null,leg:null,division:null};

  for(const d of days.rows){
    const P=d.payload||{};
    for(const div of ['d1','d2']){
      for(const m of (P[div]||[])){
        if(!m?.p1 || !m?.p2) continue;
        const pid=req.params.pid;
        if(m.p1!==pid && m.p2!==pid) continue;
        const home=(m.p1===pid);
        const aller =(m.a1!=null&&m.a2!=null)?{gf:home?m.a1:m.a2,ga:home?m.a2:m.a1}:null;
        const retour=(m.r1!=null&&m.r2!=null)?{gf:home?m.r1:m.r2,ga:home?m.r2:m.r1}:null;
        if(aller){legs++;gf+=aller.gf;ga+=aller.ga;if(aller.gf>best.gf)best={gf:aller.gf,ga:aller.ga,date:d.day,leg:'Aller',division:div.toUpperCase()};}
        if(retour){legs++;gf+=retour.gf;ga+=retour.ga;if(retour.gf>best.gf)best={gf:retour.gf,ga:retour.ga,date:d.day,leg:'Retour',division:div.toUpperCase()};}
      }
    }
  }

  // rang/points + titres D1/D2 + équipes diff.
  let rank=null,points=null,moyenne=null, won_d1=null, won_d2=null, teams_used=null;
  try{
    const st=await computeSeasonStandings(sid);
    const ix=st.findIndex(x=>x.id===req.params.pid);
    if(ix>=0){
      rank=ix+1;
      points=st[ix].total;
      moyenne=st[ix].moyenne;
      won_d1=st[ix].won_d1 ?? 0;
      won_d2=st[ix].won_d2 ?? 0;
      teams_used=st[ix].teams_used ?? 0;
    }
  }catch(_){}

  ok(res,{
    season_id:sid,
    player:{ player_id:req.params.pid, name:r.rows[0].name },
    legs, goals_for:gf, goals_against:ga, best,
    rank, points, moyenne,
    won_d1, won_d2, teams_used
  });
});


app.get('/players/:pid/matches', auth, async (req,res)=>{
  const sid = await resolveSeasonId(req.query.season);
  const days = await q(`SELECT day,payload FROM matchday WHERE season_id=$1 ORDER BY day ASC`,[sid]);
  const out=[];
  for(const d of days.rows){
    const P=d.payload||{};
    for(const div of ['d1','d2']){
      for(const m of (P[div]||[])){
        if(!m?.p1 || !m?.p2) continue;
        const pid=req.params.pid;
        if(m.p1!==pid && m.p2!==pid) continue;
        const home=(m.p1===pid);
        const opp  =home?m.p2:m.p1;
        const aller=(m.a1!=null&&m.a2!=null)?{gf:home?m.a1:m.a2,ga:home?m.a2:m.a1}:null;
        const retour=(m.r1!=null&&m.r2!=null)?{gf:home?m.r1:m.r2,ga:home?m.r2:m.r1}:null;
        out.push({date:d.day, division:div.toUpperCase(), opponent:opp, aller, retour});
      }
    }
  }
  ok(res,{ season_id:sid, matches: out });
});

/* ---------- admin players CRUD ---------- */
app.post('/admin/players', auth, adminOnly, async (req,res)=>{
  const { player_id, name, role } = req.body||{};
  if(!player_id||!name) return bad(res,400,'player_id et name requis');
  await q(`INSERT INTO players(player_id,name,role) VALUES ($1,$2,$3)
           ON CONFLICT (player_id) DO UPDATE SET name=EXCLUDED.name, role=EXCLUDED.role`,
           [player_id, name, (role||'MEMBRE').toUpperCase()]);
  const r=await q(`SELECT player_id,name,role FROM players WHERE player_id=$1`,[player_id]);
  ok(res,{ player:r.rows[0] });
});
app.put('/admin/players/:id', auth, adminOnly, async (req,res)=>{
  const oldId = req.params.id;
  let { player_id, name, role } = req.body || {};
  player_id = (player_id || '').trim();
  name = (name || '').trim();
  role = (role || 'MEMBRE').toUpperCase();
  if(!name) return bad(res,400,'name requis');

  if(player_id && player_id !== oldId){
    await q(`INSERT INTO players(player_id,name,role)
             VALUES ($1,$2,$3)
             ON CONFLICT (player_id) DO UPDATE SET name=EXCLUDED.name, role=EXCLUDED.role`,
             [player_id, name, role]);
    await q(`UPDATE users SET player_id=$1 WHERE player_id=$2`,[player_id, oldId]);
    await q(`DELETE FROM players WHERE player_id=$1`,[oldId]);
    const r=await q(`SELECT player_id,name,role FROM players WHERE player_id=$1`,[player_id]);
    return ok(res,{ player:r.rows[0] });
  }

  const r=await q(`UPDATE players SET name=$1, role=$2 WHERE player_id=$3
                   RETURNING player_id,name,role`, [name,role,oldId]);
  if(!r.rowCount) return bad(res,404,'introuvable');
  ok(res,{ player:r.rows[0] });
});
app.delete('/admin/players/:id', auth, adminOnly, async (req,res)=>{
  await q(`DELETE FROM players WHERE player_id=$1`,[req.params.id]);
  ok(res,{ ok:true });
});

/* ---------- lier/délier user <-> player ---------- */
app.get('/admin/players/:pid/user', auth, adminOnly, async (req,res)=>{
  const r = await q(`SELECT id,email,role,player_id FROM users WHERE player_id=$1`,[req.params.pid]);
  ok(res, { user: r.rows[0] || null });
});
async function linkUserToPlayer(pid, emailRaw, passwordRaw){
  const email = normEmail(emailRaw);
  if(!email) throw new Error('email requis');
  const pj = await q(`SELECT 1 FROM players WHERE player_id=$1`,[pid]);
  if(!pj.rowCount) throw new Error('joueur introuvable');

  await q(`UPDATE users SET player_id=NULL WHERE player_id=$1`,[pid]); // libère l’ancienne liaison

  const u = await q(`SELECT id FROM users WHERE email=$1`,[email]);
  if(u.rowCount===0){
    const pwd = (passwordRaw && passwordRaw.length>=6) ? passwordRaw : Math.random().toString(36).slice(-10);
    const hash = await bcrypt.hash(pwd,10);
    const ins = await q(
      `INSERT INTO users(email,password_hash,role,player_id)
       VALUES ($1,$2,'member',$3)
       RETURNING id,email,role,player_id`,
      [email,hash,pid]
    );
    return { user: ins.rows[0], created:true };
  }else{
    const id = u.rows[0].id;
    if(passwordRaw && passwordRaw.length>=6){
      const hash = await bcrypt.hash(passwordRaw,10);
      await q(`UPDATE users SET password_hash=$2 WHERE id=$1`, [id,hash]);
    }
    await q(`UPDATE users SET role='member', player_id=$2 WHERE id=$1`, [id,pid]);
    const out = await q(`SELECT id,email,role,player_id FROM users WHERE id=$1`,[id]);
    return { user: out.rows[0], created:false };
  }
}
app.post('/admin/players/:pid/attach_user', auth, adminOnly, async (req,res)=>{
  try{
    const { email, password } = req.body||{};
    const r = await linkUserToPlayer(req.params.pid, email, password);
    ok(res, r);
  }catch(e){ bad(res,400,e.message||'erreur liaison'); }
});
app.post('/admin/players/:pid/link-user', auth, adminOnly, async (req,res)=>{
  try{
    const { email, password } = req.body||{};
    const r = await linkUserToPlayer(req.params.pid, email, password);
    ok(res, r);
  }catch(e){ bad(res,400,e.message||'erreur liaison'); }
});
app.post('/admin/players/:pid/link', auth, adminOnly, async (req,res)=>{
  try{
    const { email, password } = req.body||{};
    const r = await linkUserToPlayer(req.params.pid, email, password);
    ok(res, r);
  }catch(e){ bad(res,400,e.message||'erreur liaison'); }
});
app.delete('/admin/players/:pid/attach_user', auth, adminOnly, async (req,res)=>{
  await q(`UPDATE users SET player_id=NULL WHERE player_id=$1`,[req.params.pid]);
  ok(res,{ ok:true });
});

/* ---------- Panel Membre (/me*) ---------- */
async function loadDaysForSeason(seasonId){
  const r = await q(`SELECT day,payload FROM matchday WHERE season_id=$1 ORDER BY day ASC`, [seasonId]);
  return { season_id: seasonId, rows: r.rows };
}
function rowsForPlayer(payload, pid, date){
  const out=[];
  for(const div of ['d1','d2']){
    for(const m of (payload?.[div]||[])){
      if(!m?.p1 || !m?.p2) continue;
      if(m.p1!==pid && m.p2!==pid) continue;
      const home=(m.p1===pid), opp=home?m.p2:m.p1;
      const aller =(m.a1!=null&&m.a2!=null)?{gf:home?m.a1:m.a2,ga:home?m.a2:m.a1}:null;
      const retour=(m.r1!=null&&m.r2!=null)?{gf:home?m.r1:m.r2,ga:home?m.r2:m.r1}:null;
      out.push({date, division:div.toUpperCase(), opponent:opp, aller, retour});
    }
  }
  return out;
}

app.get('/me/player', auth, async (req,res)=>{
  const r=await q(`SELECT id,email,role,player_id FROM users WHERE id=$1`,[req.user.uid]);
  const user = r.rows[0];
  if(!user?.player_id) return bad(res,404,'Aucun joueur lié');
  const p = await q(`SELECT player_id,name,role,profile_pic_url FROM players WHERE player_id=$1`,[user.player_id]);
  ok(res,{ player:p.rows[0]||null });
});
app.get('/me/matches', auth, async (req,res)=>{
  const pid = await getLinkedPlayerId(req.user.uid);
  if(!pid) return bad(res,404,'Aucun joueur lié');
  const sid = await resolveSeasonId(req.query.season);
  const { rows } = await loadDaysForSeason(sid);
  const out=[];
  for(const d of rows) out.push(...rowsForPlayer(d.payload, pid, d.day));
  const uniq=[...new Set(out.map(x=>x.opponent))];
  if(uniq.length){
    const r=await q(`SELECT player_id,name FROM players WHERE player_id=ANY($1::text[])`,[uniq]);
    const map=new Map(r.rows.map(x=>[x.player_id,x.name]));
    out.forEach(x=> x.opponent_name = map.get(x.opponent)||x.opponent);
  }
  ok(res,{ season_id:sid, matches: out });
});
app.get('/me/stats', auth, async (req,res)=>{
  const pid = await getLinkedPlayerId(req.user.uid);
  if(!pid) return bad(res,404,'player not linked');
  const sid = await resolveSeasonId(req.query.season);
  const { rows } = await loadDaysForSeason(sid);

  let played=0, GF=0, GA=0;
  let best={gf:0,ga:0,date:null,opp:null,leg:null,division:null};
  for(const d of rows){
    const R = rowsForPlayer(d.payload, pid, d.day);
    for(const r of R){
      if(r.aller){ played++; GF+=r.aller.gf; GA+=r.aller.ga;
        if(r.aller.gf>best.gf) best={gf:r.aller.gf,ga:r.aller.ga,date:r.date,opp:r.opponent,leg:'Aller',division:r.division}; }
      if(r.retour){ played++; GF+=r.retour.gf; GA+=r.retour.ga;
        if(r.retour.gf>best.gf) best={gf:r.retour.gf,ga:r.retour.ga,date:r.date,opp:r.opponent,leg:'Retour',division:r.division}; }
    }
  }

  let rank=null, points=null, moyenne=null;
  try{
    const st=await computeSeasonStandings(sid);
    const ix=st.findIndex(x=>x.id===pid);
    if(ix>=0){ rank=ix+1; points=st[ix].total; moyenne=st[ix].moyenne; }
  }catch(_){}

  if(best.opp){
    const r=await q(`SELECT name FROM players WHERE player_id=$1`,[best.opp]);
    best.opp_name = r.rows[0]?.name || best.opp;
  }
  ok(res,{ season_id:sid, played_legs:played, goals_for:GF, goals_against:GA, best_single:best, season_rank:rank, season_points:points, season_average:moyenne });
});
app.put('/me/name', auth, async (req,res)=>{
  const { name } = req.body||{};
  if(!name || name.trim().length<2) return bad(res,400,'nom invalide');
  const pid = await getLinkedPlayerId(req.user.uid);
  if(!pid) return bad(res,404,'player not linked');
  const r = await q(`UPDATE players SET name=$2 WHERE player_id=$1 RETURNING player_id,name,role,profile_pic_url`, [pid, name.trim()]);
  ok(res,{ player:r.rows[0] });
});
app.put('/me/password', auth, async (req,res)=>{
  const { currentPassword, newPassword } = req.body||{};
  if(!newPassword || newPassword.length<6) return bad(res,400,'mot de passe trop court');
  const u = await q(`SELECT id,password_hash FROM users WHERE id=$1`,[req.user.uid]);
  if(!u.rowCount) return bad(res,404,'user not found');
  if(currentPassword){
    const okc = await bcrypt.compare(currentPassword, u.rows[0].password_hash);
    if(!okc) return bad(res,403,'mot de passe actuel incorrect');
  }
  const newHash = await bcrypt.hash(newPassword,10);
  await q(`UPDATE users SET password_hash=$2 WHERE id=$1`,[req.user.uid,newHash]);
  ok(res,{ ok:true });
});
app.post('/me/photo', auth, upload.single('photo'), async (req,res)=>{
  const pid = await getLinkedPlayerId(req.user.uid);
  if(!pid) return bad(res,404,'player not linked');
  if(!req.file) return bad(res,400,'fichier requis');
  const url = `/uploads/players/${req.file.filename}`;
  const r = await q(`UPDATE players SET profile_pic_url=$2 WHERE player_id=$1 RETURNING player_id,name,role,profile_pic_url`, [pid, url]);
  ok(res,{ player:r.rows[0] });
});

/* ---------- presence (en ligne) ---------- */
app.post('/presence/beat', auth, async (req,res)=>{
  const r = await q(`SELECT player_id FROM users WHERE id=$1`,[req.user.uid]);
  const pid = r.rows[0]?.player_id;
  if(pid){ presence.players.set(pid, Date.now()); }
  ok(res,{ ok:true });
});
app.get('/presence/players', auth, async (_req,res)=>{
  const now=Date.now(), TTL=PRESENCE_TTL_MS;
  const online=[];
  for(const [pid,ts] of presence.players.entries()){
    if(now - ts <= TTL) online.push(pid);
  }
  ok(res,{ online });
});

/* ---------- matchdays (saisies) ---------- */
app.get('/matchdays', auth, async (req,res)=>{
  const sid = await resolveSeasonId(req.query.season);
  const r = await q(`SELECT day FROM matchday WHERE season_id=$1 ORDER BY day ASC`,[sid]);
  ok(res, { season_id: sid, days: r.rows.map(x=>dayjs(x.day).format('YYYY-MM-DD')) });
});
app.get('/matchdays/:date', auth, async (req,res)=>{
  const d = req.params.date;
  const r = await q(`SELECT payload FROM matchday WHERE day=$1`,[d]);
  if (!r.rowCount) return bad(res,404,'introuvable');
  res.json(r.rows[0].payload);
});

/* ---------- drafts (brouillons temps réel) ---------- */
app.get('/matchdays/draft/:date', auth, async (req,res)=>{
  const d = req.params.date;
  try{
    const r = await q('SELECT payload FROM draft WHERE day=$1',[d]);
    if(!r.rowCount) return bad(res,404,'no draft');
    ok(res,{ payload: r.rows[0].payload });
  }catch(e){ bad(res,500,'draft get error'); }
});
app.put('/matchdays/draft/:date', auth, async (req,res)=>{
  const d = req.params.date;
  const payload = req.body || {};
  try{
    await q(`INSERT INTO draft(day,payload,updated_at)
             VALUES ($1,$2,now())
             ON CONFLICT (day) DO UPDATE SET payload=EXCLUDED.payload, updated_at=now()`,
             [d, payload]);
    io.to(`draft:${d}`).emit('draft:update', { date:d });
    ok(res,{ ok:true });
  }catch(e){ bad(res,500,'draft save error'); }
});
app.delete('/matchdays/draft/:date', auth, async (req,res)=>{
  try{
    await q('DELETE FROM draft WHERE day=$1',[req.params.date]);
    ok(res,{ ok:true });
  }catch(e){ bad(res,500,'draft delete error'); }
});

app.put('/matchdays/:day/season', auth, adminOnly, async (req,res)=>{
  const day = req.params.day;
  const { season_id } = req.body||{};
  if(!season_id) return bad(res,400,'season_id requis');
  const chk = await q(`SELECT 1 FROM seasons WHERE id=$1`,[+season_id]);
  if(!chk.rowCount) return bad(res,404,'saison inconnue');
  await q(`UPDATE matchday SET season_id=$2 WHERE day=$1`,[day,+season_id]);
  ok(res,{ ok:true });
});
app.post('/matchdays/confirm', auth, adminOnly, async (req,res)=>{
  const { date, d1=[], d2=[], barrage={}, champions={}, season_id } = req.body||{};
  if(!date) return bad(res,400,'date requise');
  const sid = season_id ? +season_id : await currentSeasonId();
  const payload = { d1, d2, barrage, champions };
  await q(`INSERT INTO matchday(day,season_id,payload,created_at)
           VALUES ($1,$2,$3,now())
           ON CONFLICT (day) DO UPDATE SET season_id=EXCLUDED.season_id, payload=EXCLUDED.payload`,
           [date, sid, payload]);
  await q('DELETE FROM draft WHERE day=$1',[date]);
  io.to(`draft:${date}`).emit('day:confirmed', { date });
  io.emit('season:changed');
  ok(res,{ ok:true });
});
app.delete('/matchdays/:date', auth, adminOnly, async (req,res)=>{
  await q(`DELETE FROM matchday WHERE day=$1`,[req.params.date]);
  ok(res,{ ok:true });
});

/* ---------- standings ---------- */
app.get('/standings', auth, async (req,res)=>{
  const sid = await resolveSeasonId(req.query.season);
  const list = await computeSeasonStandings(sid);
  ok(res,{ season_id:sid, standings:list });
});
app.get('/season/standings', auth, async (req,res)=>{
  const sid = await resolveSeasonId(req.query.season);
  const list = await computeSeasonStandings(sid);
  ok(res,{ season_id:sid, standings:list });
});
app.get('/seasons/:id/standings', auth, async (req,res)=>{
  const sid = +req.params.id;
  const chk = await q(`SELECT 1 FROM seasons WHERE id=$1`,[sid]);
  if(!chk.rowCount) return bad(res,404,'saison inconnue');
  const list = await computeSeasonStandings(sid);
  ok(res,{ season_id:sid, standings:list });
});

/* ---------- saisons (liste + création + fallbacks) ---------- */
app.get('/seasons', auth, async (_req,res)=>{
  const r=await q(`SELECT id,name,is_closed,started_at,ended_at FROM seasons ORDER BY id DESC`);
  ok(res,{ seasons:r.rows });
});
app.get('/season/list', auth, async (_req,res)=>{
  const r=await q(`SELECT id,name FROM seasons ORDER BY id DESC`);
  ok(res,{ seasons:r.rows });
});
app.get('/season/ids', auth, async (_req,res)=>{
  const r=await q(`SELECT id FROM seasons ORDER BY id DESC`);
  ok(res, r.rows.map(x=>x.id));
});
app.post('/seasons', auth, adminOnly, async (req,res)=>{
  const { name } = req.body||{};
  if(!name || !name.trim()) return bad(res,400,'nom requis');
  const r=await q(`INSERT INTO seasons(name,is_closed) VALUES ($1,false) RETURNING id,name,is_closed,started_at,ended_at`,[name.trim()]);
  ok(res,{ season:r.rows[0] });
});
app.get('/season/current', auth, async (_req,res)=>{
  const r=await q(`SELECT id,name FROM seasons WHERE is_closed=false ORDER BY id DESC LIMIT 1`);
  if(!r.rowCount) return bad(res,404,'aucune saison en cours');
  ok(res, r.rows[0]);
});
app.get('/seasons/:id/matchdays', auth, async (req,res)=>{
  const sid = +req.params.id;
  const chk = await q(`SELECT 1 FROM seasons WHERE id=$1`,[sid]);
  if(!chk.rowCount) return bad(res,404,'saison inconnue');
  const r = await q(`SELECT day FROM matchday WHERE season_id=$1 ORDER BY day ASC`,[sid]);
  ok(res,{ days: r.rows.map(x=>dayjs(x.day).format('YYYY-MM-DD')) });
});

/* ---------- face-à-face (membre connecté vs opp) ---------- */
app.get('/faceoff/:oppId', auth, async (req,res)=>{
  const mePid = await getLinkedPlayerId(req.user.uid);
  const oppId = req.params.oppId;
  if(!mePid) return bad(res,404,'Aucun joueur lié');
  if(!oppId) return bad(res,400,'oppId requis');

  const sid = await resolveSeasonId(req.query.season);
  const days = await q(`SELECT day,payload FROM matchday WHERE season_id=$1 ORDER BY day ASC`,[sid]);

  const legs=[];
  let totals={legs:0,wins:0,draws:0,losses:0,gf:0,ga:0};
  let best_me=null, best_opp=null;

  function pushLeg(date, division, leg, gf, ga){
    const result = gf>ga?'W':(gf<ga?'L':'D');
    legs.push({date,division,leg,gf,ga,result});
    totals.legs++; totals.gf+=gf; totals.ga+=ga;
    if(result==='W') totals.wins++; else if(result==='L') totals.losses++; else totals.draws++;
  }

  for(const d of days.rows){
    const P=d.payload||{};
    for(const div of ['d1','d2']){
      for(const m of (P[div]||[])){
        if(!m?.p1 || !m?.p2) continue;
        const a = m.p1, b = m.p2;
        const matchAB = (a===mePid && b===oppId);
        const matchBA = (a===oppId && b===mePid);
        if(!matchAB && !matchBA) continue;

        const homeIsMe = matchAB;
        if(m.a1!=null && m.a2!=null){
          const gf = homeIsMe? m.a1 : m.a2;
          const ga = homeIsMe? m.a2 : m.a1;
          pushLeg(d.day, div.toUpperCase(), 'Aller', gf, ga);
          if(!best_me || gf>best_me.gf){ best_me={gf,ga,leg:'Aller',division:div.toUpperCase(),date:d.day}; }
          if(!best_opp || ga>best_opp.gf){ best_opp={gf:ga,ga:gf,leg:'Aller',division:div.toUpperCase(),date:d.day}; }
        }
        if(m.r1!=null && m.r2!=null){
          const gf = homeIsMe? m.r1 : m.r2;
          const ga = homeIsMe? m.r2 : m.r1;
          pushLeg(d.day, div.toUpperCase(), 'Retour', gf, ga);
          if(!best_me || gf>best_me.gf){ best_me={gf,ga,leg:'Retour',division:div.toUpperCase(),date:d.day}; }
          if(!best_opp || ga>best_opp.gf){ best_opp={gf:ga,ga:gf,leg:'Retour',division:div.toUpperCase(),date:d.day}; }
        }
      }
    }
  }

  const meName  = (await q(`SELECT name FROM players WHERE player_id=$1`,[mePid])).rows[0]?.name || mePid;
  const oppName = (await q(`SELECT name FROM players WHERE player_id=$1`,[oppId])).rows[0]?.name || oppId;

  let leader='draw';
  if(totals.wins>totals.losses) leader='me';
  else if(totals.losses>totals.wins) leader='opponent';

  ok(res,{
    me:{ id:mePid, name:meName },
    opponent:{ id:oppId, name:oppName },
    totals, legs, best_me, best_opp, leader
  });
});

/* ---------- websockets ---------- */
io.on('connection', (socket)=>{
  socket.on('join', ({room})=>{
    if(room && typeof room === 'string') socket.join(room);
  });
  socket.on('draft:update', ({date})=>{
    if(!date) return;
    io.to(`draft:${date}`).emit('draft:update', { date });
  });
});

/* ---------- start ---------- */
(async ()=>{
  try{
    await ensureSchema();
    server.listen(PORT, ()=> console.log('API OK on :'+PORT));
  }catch(e){
    console.error('Schema init error', e);
    process.exit(1);
  }
})();
