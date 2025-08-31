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

const APP_PORT = parseInt(process.env.PORT || '3000', 10);
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const DB_URL = process.env.DATABASE_URL;
const TEAM_KEY_LEN = parseInt(process.env.TEAM_KEY_LEN || '6', 10);

const app = express();
const server = http.createServer(app);
const io = require('socket.io')(server, { cors: { origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN } });

/* ---------- DB ---------- */
const pool = new Pool({
  connectionString: DB_URL,
  ssl: (process.env.PGSSL || 'false') === 'true' ? { rejectUnauthorized: false } : false
});
async function q(sql, params = []) {
  const client = await pool.connect();
  try {
    const res = await client.query(sql, params);
    return res;
  } finally {
    client.release();
  }
}

/* ---------- utils ---------- */
function ok(res, data) { res.json(data); }
function bad(res, code, msg) { res.status(code).json({ error: msg }); }

function normEmail(e) {
  const s = String(e || '').trim().toLowerCase();
  return s || null;
}

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
    profile_pic_url TEXT
  )`);
  await q(`CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    player_id TEXT REFERENCES players(player_id)
  )`);
  await q(`CREATE TABLE IF NOT EXISTS seasons(
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    is_closed BOOLEAN NOT NULL DEFAULT false
  )`);
  await q(`CREATE TABLE IF NOT EXISTS matchday(
    day DATE PRIMARY KEY,
    season_id INTEGER REFERENCES seasons(id) ON DELETE SET NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
  )`);
}

async function currentSeasonId(){
  const r = await q(`SELECT id FROM seasons WHERE NOT is_closed ORDER BY id DESC LIMIT 1`);
  return r.rowCount ? r.rows[0].id : null;
}
async function resolveSeasonId(hint){
  if(hint && String(hint).trim()) return +hint;
  const r = await q(`SELECT id FROM seasons WHERE NOT is_closed ORDER BY id DESC LIMIT 1`);
  return r.rowCount ? r.rows[0].id : await currentSeasonId();
}

/* ---------- middlewares ---------- */
function auth(req,res,next){
  const h = req.headers['authorization']||'';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if(!m) return bad(res,401,'token manquant');
  try{
    const payload = jwt.verify(m[1], JWT_SECRET);
    req.user = payload;
    next();
  }catch(_){
    return bad(res,401,'token invalide');
  }
}

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
  })
});

/* ---------- seed admin ---------- */
async function ensureAdmin(){
  const email = process.env.ADMIN_EMAIL || 'admin@gz.local';
  const pass  = process.env.ADMIN_PASSWORD || 'admin';
  const r = await q(`SELECT * FROM users WHERE email=$1`, [email]);
  if(r.rowCount) return;
  const ph = await bcrypt.hash(pass, 10);
  await q(`INSERT INTO users(email,password_hash,role) VALUES($1,$2,$3)`, [email, ph, 'admin']);
  console.log('Admin seed ok:', email);
}

/* ---------- ROUTES ---------- */

/* health */
app.get('/health', (_req,res)=> ok(res,{ ok:true, service:'gouzepe-api', ts:Date.now() }));

/* auth */
app.post('/auth/login', async (req,res)=>{
  let {email,password}=req.body||{};
  email = normEmail(email);
  if(!email||!password) return bad(res,400,'email/password requis');
  const r=await q(`SELECT * FROM users WHERE email=$1`,[email]);
  if(r.rowCount===0) return bad(res,401,'Utilisateur inconnu');
  const u=r.rows[0];
  const match = await bcrypt.compare(password, u.password_hash);
  if(!match) return bad(res,401,'Mot de passe incorrect');
  const token = jwt.sign({ uid:u.id, email:u.email, role:u.role, player_id:u.player_id }, JWT_SECRET, { expiresIn:'24h' });
  ok(res,{ token, user:{ id:u.id, email:u.email, role:u.role, player_id:u.player_id }, expHours:24 });
});

/* players */
app.get('/players', auth, async (_req,res)=>{
  const r=await q(`SELECT player_id,name,role,profile_pic_url FROM players ORDER BY name ASC`);
  ok(res,{ players:r.rows });
});
app.post('/players', auth, async (req,res)=>{
  if((req.user?.role||'member')!=='admin') return bad(res,403,'admin uniquement');
  const {player_id,name,role}=req.body||{};
  if(!player_id||!name) return bad(res,400,'player_id/name requis');
  await q(`INSERT INTO players(player_id,name,role) VALUES($1,$2,$3)
           ON CONFLICT(player_id) DO UPDATE SET name=EXCLUDED.name, role=EXCLUDED.role`,
    [player_id, name, (role||'MEMBRE').toUpperCase()]);
  ok(res,{ ok:true });
});
app.post('/players/:id/photo', auth, upload.single('photo'), async (req,res)=>{
  const id=req.params.id;
  if(!req.file) return bad(res,400,'photo requise');
  const url = `/uploads/players/${req.file.filename}`;
  await q(`UPDATE players SET profile_pic_url=$2 WHERE player_id=$1`,[id,url]);
  ok(res,{ ok:true, profile_pic_url:url });
});

/* seasons */
app.get('/seasons', auth, async (_req,res)=>{
  const r = await q(`SELECT id,name,is_closed FROM seasons ORDER BY id DESC`);
  ok(res,{ seasons:r.rows });
});
app.post('/seasons', auth, async (req,res)=>{
  if((req.user?.role||'member')!=='admin') return bad(res,403,'admin uniquement');
  const {name}=req.body||{};
  if(!name) return bad(res,400,'nom requis');
  const r=await q(`INSERT INTO seasons(name,is_closed) VALUES($1,false) RETURNING id`,[name]);
  ok(res,{ ok:true, id:r.rows[0].id });
});
app.get('/season/current', auth, async (_req,res)=>{
  const id = await currentSeasonId();
  if(!id) return ok(res,null);
  const r = await q(`SELECT id,name FROM seasons WHERE id=$1`,[id]);
  ok(res, r.rows[0]||null);
});
app.put('/seasons/:id/status', auth, async (req,res)=>{
  if((req.user?.role||'member')!=='admin') return bad(res,403,'admin uniquement');
  const sid=+req.params.id;
  const { is_closed } = req.body||{};
  await q(`UPDATE seasons SET is_closed=$2 WHERE id=$1`,[sid,!!is_closed]);
  ok(res,{ ok:true });
});

/* matchdays */
app.get('/matchdays', auth, async (_req,res)=>{
  const r=await q(`SELECT day FROM matchday ORDER BY day DESC`);
  ok(res,{ days:r.rows.map(x=>x.day) });
});
app.get('/seasons/:id/matchdays', auth, async (req,res)=>{
  const sid=+req.params.id;
  const r=await q(`SELECT day FROM matchday WHERE season_id=$1 ORDER BY day ASC`,[sid]);
  ok(res,{ days:r.rows.map(x=>x.day) });
});
app.get('/matchdays/:date', auth, async (req,res)=>{
  const d=req.params.date;
  const r=await q(`SELECT day,season_id,payload FROM matchday WHERE day=$1`,[d]);
  if(!r.rowCount) return bad(res,404,'introuvable');
  ok(res, r.rows[0]);
});
app.post('/matchdays', auth, async (req,res)=>{
  if((req.user?.role||'member')!=='admin') return bad(res,403,'admin uniquement');
  const { day, season_id, payload } = req.body||{};
  if(!day) return bad(res,400,'date requise');
  await q(`INSERT INTO matchday(day,season_id,payload) VALUES($1,$2,$3)
           ON CONFLICT(day) DO UPDATE SET season_id=EXCLUDED.season_id, payload=EXCLUDED.payload`,
    [day, season_id||null, payload||{}]);
  ok(res,{ ok:true });
  io.emit('day:confirmed', { date: day });
});
app.put('/matchdays/:date/season', auth, async (req,res)=>{
  if((req.user?.role||'member')!=='admin') return bad(res,403,'admin uniquement');
  const d=req.params.date;
  const { season_id } = req.body||{};
  await q(`UPDATE matchday SET season_id=$2 WHERE day=$1`,[d, season_id||null]);
  ok(res,{ ok:true });
  io.emit('day:confirmed', { date: d });
});
app.delete('/matchdays/:date', auth, async (req,res)=>{
  if((req.user?.role||'member')!=='admin') return bad(res,403,'admin uniquement');
  const d=req.params.date;
  await q(`DELETE FROM matchday WHERE day=$1`,[d]);
  ok(res,{ ok:true });
  io.emit('day:deleted', { date: d });
});

/* ---------- helpers joueurs ---------- */
async function getPlayersRoles(){
  const r=await q(`SELECT player_id,role FROM players`);
  const map=new Map(); r.rows.forEach(p=>map.set(p.player_id,(p.role||'MEMBRE').toUpperCase())); return map;
}

// Tous les MEMBRES (pour compléter le classement même à 0 participation)
async function getAllMembers(){
  const r = await q(`SELECT player_id,name FROM players WHERE UPPER(COALESCE(role,'MEMBRE'))='MEMBRE'`);
  return r.rows.map(x => ({ id: x.player_id, name: x.name || x.player_id }));
}

/* ---------- calculs standings ---------- */
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
  (matches||[]).forEach(m=>{
    if(!m.p1||!m.p2) return;
    if(m.a1!=null&&m.a2!=null) add(m.p1,m.p2,m.a1,m.a2);
    if(m.r1!=null&&m.r2!=null) add(m.p2,m.p1,m.r2,m.r1); // retour inversé
  });
  const arr = Object.entries(agg).map(([id,x])=>({id,...x,PTS:x.V*3+x.N,DIFF:x.BP-x.BC}));
  arr.sort((a,b)=>b.PTS-a.PTS||b.DIFF-a.DIFF||b.BP-a.BP||a.id.localeCompare(b.id));
  return arr;
}

// D1 : barème fixe demandé
function pointsD1Fixed(rank){
  if (rank === 1) return 15;
  if (rank === 2) return 13;
  if (rank === 3) return 12;
  if (rank === 4) return 11;
  if (rank === 5) return 10;
  return 9; // 6e et au-delà
}

// D2 : on garde le tableau existant (adapter si besoin)
function pointsD2(rank){ const table=[10,8,7,6,5,4,3,2,1,1,1]; return rank>0 && rank<=table.length ? table[rank-1] : 1; }

async function computeSeasonStandings(seasonId){
  const days = await q(`SELECT day,payload FROM matchday WHERE season_id=$1 ORDER BY day ASC`,[seasonId]);
  const roles = await getPlayersRoles();

  const totals = new Map(); // id -> {id,total,participations,won_d1,won_d2,teams:Set}
  const ensure = id=>{ if(!totals.has(id)) totals.set(id,{id,total:0,participations:0,won_d1:0,won_d2:0,teams:new Set()}); return totals.get(id); };

  for(const row of days.rows){
    const p=row.payload||{};
    const st1Full=computeStandings(p.d1||[]);
    const st2Full=computeStandings(p.d2||[]);

    const st1 = st1Full.filter(r => (roles.get(r.id)||'MEMBRE')!=='INVITE');
    const st2 = st2Full.filter(r => (roles.get(r.id)||'MEMBRE')!=='INVITE');

    st1.forEach((r,idx)=>{ const o=ensure(r.id); o.total += pointsD1Fixed(idx+1); o.participations+=1; });
    st2.forEach((r,idx)=>{ const o=ensure(r.id); o.total += pointsD2(idx+1);   o.participations+=1; });

    // Gagnants (compteurs uniquement — plus de bonus de points)
    const champD1=p?.champions?.d1?.id||null;
    if(champD1 && (roles.get(champD1)||'MEMBRE')!=='INVITE'){ ensure(champD1).won_d1++; }
    const champD2=p?.champions?.d2?.id||null;
    if(champD2 && (roles.get(champD2)||'MEMBRE')!=='INVITE'){ ensure(champD2).won_d2++; }

    // Equipes différentes (depuis “Champion avec …”)
    const teamD1 = p?.champions?.d1?.team;
    if (champD1 && teamD1){
      const k = teamKey(teamD1);
      if (k) ensure(champD1).teams.add(k);
    }
    const teamD2 = p?.champions?.d2?.team;
    if (champD2 && teamD2){
      const k = teamKey(teamD2);
      if (k) ensure(champD2).teams.add(k);
    }
  }

  // Ajouter tous les membres (même sans participation)
  try{
    const members = await getAllMembers();
    for (const m of members){
      if(!totals.has(m.id)){
        totals.set(m.id, { id: m.id, name: m.name, total:0, participations:0, won_d1:0, won_d2:0, teams:new Set() });
      }else{
        const o = totals.get(m.id);
        if (!o.name) o.name = m.name;
      }
    }
  }catch(_){}

  const arr=[...totals.values()].map(o=>({
    id:o.id,
    name:o.name || o.id,
    total:o.total||0,
    participations:o.participations||0,
    moyenne:(o.participations>0 ? (o.total/o.participations) : 0),
    won_d1:o.won_d1||0,
    won_d2:o.won_d2||0,
    teams_used: o.teams ? o.teams.size : 0
  }));
  // Tri par défaut (le front peut re-trier également)
  arr.sort((a,b)=> 
    (b.moyenne - a.moyenne) ||
    (b.total - a.total) ||
    ((b.participations||0) - (a.participations||0)) ||
    (((b.won_d1||0)*100 + (b.won_d2||0)) - ((a.won_d1||0)*100 + (a.won_d2||0))) ||
    (a.name||a.id||'').localeCompare(b.name||b.id||'')
  );
  return arr;
}

/* ---------- standings endpoints ---------- */
app.get('/seasons/:id/standings', auth, async (req,res)=>{
  const sid = +req.params.id;
  const chk = await q(`SELECT 1 FROM seasons WHERE id=$1`, [sid]);
  if(!chk.rowCount) return bad(res,404,'saison inconnue');
  const rows = await computeSeasonStandings(sid);
  ok(res, { season_id: sid, standings: rows });
});
app.get('/season/standings', auth, async (req,res)=>{
  const sid = await resolveSeasonId(req.query.season);
  const rows = await computeSeasonStandings(sid);
  ok(res, { season_id: sid, standings: rows });
});
app.get('/standings', auth, async (req,res)=>{
  const sid = await resolveSeasonId(req.query.season);
  const rows = await computeSeasonStandings(sid);
  ok(res, { season_id: sid, standings: rows });
});

/* ---------- présence (optionnel) ---------- */
app.post('/presence/ping', auth, async (_req,res)=> ok(res,{ ok:true, ts:Date.now() }));

/* ---------- static (si nécessaire) ---------- */
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- start ---------- */
(async ()=>{
  await ensureSchema();
  await ensureAdmin();
  server.listen(APP_PORT, ()=> console.log('API OK on :'+APP_PORT));
})();
