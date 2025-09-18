// server.js — GOUZEPE eFOOT API (Express + PostgreSQL + Socket.IO) — Render-ready, NO HANDOFF
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
const crypto = require('crypto');

/* ====== Config ====== */
const PORT = parseInt(process.env.PORT || '10000', 10);
const JWT_SECRET = process.env.JWT_SECRET || '1XS1r4QJNp6AtkjORvKUU01RZRfzbGV+echJsio9gq8lAOc2NW7sSYsQuncE6+o9';
const EMAIL_DOMAIN = process.env.EMAIL_DOMAIN || 'gz.local';

/* Database (Render-friendly) */
const useSSL =
  process.env.PGSSL === 'true' ||
  process.env.RENDER === 'true' ||
  process.env.NODE_ENV === 'production';

const pgOpts = process.env.DATABASE_URL
  ? { connectionString: process.env.DATABASE_URL, ssl: useSSL ? { rejectUnauthorized:false } : false }
  : {
      host: process.env.PGHOST || '127.0.0.1',
      port: +(process.env.PGPORT || 5432),
      database: process.env.PGDATABASE || 'EFOOTBALL',
      user: process.env.PGUSER || 'postgres',
      password: process.env.PGPASSWORD || 'Admin123',
      ssl: useSSL ? { rejectUnauthorized:false } : false,
    };

const pool = new Pool(pgOpts);

const app = express();
const server = http.createServer(app);
const allowedOrigins = (process.env.CORS_ORIGIN || '*').split(',').map(s => s.trim()).filter(Boolean);
const io = require('socket.io')(server, {
  cors: {
    origin: (origin, cb) => {
      if (!origin || allowedOrigins.includes('*')) return cb(null, true);
      cb(null, allowedOrigins.includes(origin));
    },
    methods: ['GET','POST','PUT','DELETE','OPTIONS']
  }
});

/* ====== Middlewares ====== */
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
const corsOptions = {
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes('*')) return cb(null, true);
    return cb(null, allowedOrigins.includes(origin));
  },
  credentials: false, // we use Authorization: Bearer, not cookies
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Authorization','Content-Type'],
  exposedHeaders: ['Content-Length'],
  maxAge: 86400
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '2mb' }));

/* ====== Uploads ====== */
const UP = path.join(__dirname, 'uploads');
const UP_PLAYERS = path.join(UP, 'players');
fs.mkdirSync(UP_PLAYERS, { recursive:true });
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

/* ====== Helpers ====== */
const q   = (sql, params=[]) => pool.query(sql, params);
const ok  = (res, data={}) => res.json(data);
const bad = (res, code=400, msg='Bad request') => res.status(code).json({ error: String(msg) });
const normEmail = (x)=>{ x=String(x||'').trim().toLowerCase(); if(!x) return x; if(!x.includes('@')) x=`${x}@${EMAIL_DOMAIN}`; return x; };
const newId = ()=> (crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString(36)+Math.random().toString(36).slice(2,10)));
const clientIp = (req)=> (req.headers['x-forwarded-for']||req.socket.remoteAddress||'').toString().split(',')[0].trim();
const deviceLabel = (req)=> { const d=(req.headers['x-device-name']||'').toString().trim(); const ua=(req.headers['user-agent']||'').toString().trim(); return [d,ua].filter(Boolean).join(' • ').slice(0,180) || 'Appareil'; };

/* ====== Presence (in-memory) ====== */
const PRESENCE_TTL_MS = 70 * 1000;
const presence = { players: new Map() }; // player_id -> lastSeen (ms)

/* ====== Schema bootstrap ====== */
async function ensureSchema(){
  // users
  await q(`CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    player_id TEXT,
    created_at TIMESTAMP DEFAULT now()
  )`);

  // users.id backfill for very old DBs (keep id stable)
  await q(`DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name='users' AND column_name='id'
  ) THEN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relkind='S' AND relname='users_id_seq') THEN
      CREATE SEQUENCE users_id_seq;
    END IF;
    ALTER TABLE users ADD COLUMN id INTEGER;
    UPDATE users SET id = nextval('users_id_seq') WHERE id IS NULL;
    ALTER TABLE users ALTER COLUMN id SET DEFAULT nextval('users_id_seq');
    ALTER TABLE users ADD PRIMARY KEY (id);
  END IF;
END$$;`);

  // sessions (no FK to avoid deploy crashes on existing DBs)
  await q(`CREATE TABLE IF NOT EXISTS sessions(
    id TEXT PRIMARY KEY,
    user_id INTEGER,
    device TEXT,
    user_agent TEXT,
    ip TEXT,
    created_at TIMESTAMP DEFAULT now(),
    last_seen TIMESTAMP DEFAULT now(),
    is_active BOOLEAN NOT NULL DEFAULT true,
    revoked_at TIMESTAMP,
    logout_at TIMESTAMP,
    cleaned_after_logout BOOLEAN NOT NULL DEFAULT false
  )`);
  await q(`CREATE INDEX IF NOT EXISTS sessions_user_active ON sessions(user_id) WHERE is_active`);

  // seasons
  await q(`CREATE TABLE IF NOT EXISTS seasons(
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ,
    is_closed BOOLEAN NOT NULL DEFAULT false
  )`);

  // matchday
  await q(`CREATE TABLE IF NOT EXISTS matchday(
    day DATE PRIMARY KEY,
    season_id INTEGER,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);

  // draft
  await q(`CREATE TABLE IF NOT EXISTS draft(
    day DATE PRIMARY KEY,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now(),
    author_user_id INTEGER
  )`);
  await q(`CREATE INDEX IF NOT EXISTS draft_author_idx ON draft(author_user_id)`);

  // players
  await q(`CREATE TABLE IF NOT EXISTS players(
    player_id TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    role      TEXT NOT NULL DEFAULT 'MEMBRE',
    profile_pic_url TEXT,
    created_at TIMESTAMP DEFAULT now()
  )`);
  await q(`ALTER TABLE players ADD COLUMN IF NOT EXISTS profile_pic_url TEXT`);

  // seed admin
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@gz.local';
  const adminPass  = process.env.ADMIN_PASSWORD || 'admin';
  const row = await q(`SELECT id FROM users WHERE email=$1`,[adminEmail]);
  if(row.rowCount===0){
    const hash = await bcrypt.hash(adminPass,10);
    await q(`INSERT INTO users(email,password_hash,role) VALUES ($1,$2,'admin')`,[adminEmail,hash]);
    console.log(`Seed admin: ${adminEmail} / ${adminPass}`);
  }

  // season default
  const s = await q(`SELECT id FROM seasons WHERE is_closed=false ORDER BY id DESC LIMIT 1`);
  if(s.rowCount===0){
    await q(`INSERT INTO seasons(name,is_closed) VALUES ('Saison courante', false)`);
  }
}

/* ====== Auth & sessions ====== */
function signToken(user, sessionId){
  return jwt.sign(
    { uid:user.id, role:user.role, email:user.email, sid:sessionId },
    JWT_SECRET,
    { expiresIn: '24h' }
  );
}

function auth(req,res,next){
  (async ()=>{
    try{
      const h=req.headers.authorization||'';
      const tok=h.startsWith('Bearer ')?h.slice(7):'';
      if(!tok) return bad(res,401,'No token');
      const p = jwt.verify(tok, JWT_SECRET);

      const r = await q(`SELECT is_active,last_seen FROM sessions WHERE id=$1`, [p.sid]);
      if(!r.rowCount || !r.rows[0].is_active) return bad(res,401,'Session revoked');

      // inactivity auto-revoke (24h)
      const last = r.rows[0].last_seen;
      if (last && Date.now() - new Date(last).getTime() > 24*3600*1000){
        await q(`UPDATE sessions SET is_active=false, revoked_at=now() WHERE id=$1`, [p.sid]);
        return bad(res,401,'Session expired');
      }

      req.user = p;
      q(`UPDATE sessions SET last_seen=now(), ip=$2, user_agent=$3 WHERE id=$1`,
        [p.sid, clientIp(req), (req.headers['user-agent']||'').slice(0,200)]).catch(()=>{});
      next();
    }catch(e){ return bad(res,401,'Invalid token'); }
  })();
}

function adminOnly(req,res,next){
  if((req.user?.role||'member')!=='admin') return bad(res,403,'Admin only');
  next();
}

/* ====== Health ====== */
app.get('/healthz', (_req,res)=> ok(res,{ ok:true, service:'gouzepe-api', ts:Date.now() }));
app.get('/health', (_req,res)=> ok(res,{ ok:true, service:'gouzepe-api', ts:Date.now() }));

/* ====== Auth (NO HANDOFF) ====== */
app.post('/auth/login', async (req,res)=>{
  let {email,password}=req.body||{};
  email = normEmail(email);
  if(!email||!password) return bad(res,400,'email/password requis');

  const r=await q(`SELECT id,email,role,password_hash FROM users WHERE email=$1`,[email]);
  if(r.rowCount===0) return bad(res,401,'Utilisateur inconnu');
  const u=r.rows[0];
  const match = await bcrypt.compare(password, u.password_hash);
  if(!match) return bad(res,401,'Mot de passe incorrect');

  const sid = newId();
  await q(`INSERT INTO sessions(id,user_id,device,user_agent,ip) VALUES ($1,$2,$3,$4,$5)`,[
    sid, u.id, deviceLabel(req), (req.headers['user-agent']||'').slice(0,200), clientIp(req)
  ]);

  return ok(res,{
    token: signToken(u, sid),
    user: { id:u.id, email:u.email, role:u.role },
    expHours: 24
  });
});

app.post('/auth/logout', auth, async (req,res)=>{
  try{
    await q(`UPDATE sessions SET is_active=false, logout_at=now() WHERE id=$1`,[req.user.sid]);
    ok(res,{ ok:true });
  }catch(e){ bad(res,500,'logout error'); }
});

/* ====== Admin: users & players ====== */
app.get('/admin/users', auth, adminOnly, async (_req,res)=>{
  const r=await q(`SELECT id,email,role,player_id,created_at FROM users ORDER BY id DESC`);
  ok(res,{ users:r.rows });
});
app.post('/admin/users', auth, adminOnly, async (req,res)=>{
  const { email, password, role, player_id } = req.body||{};
  if(!email||!password) return bad(res,400,'email/password requis');
  try{
    const hash = await bcrypt.hash(password,10);
    await q(`INSERT INTO users(email,password_hash,role,player_id) VALUES ($1,$2,$3,$4)`,[normEmail(email),hash,role||'member',player_id||null]);
    ok(res,{ ok:true });
  }catch(e){
    if(String(e.message||'').includes('duplicate')) return bad(res,409,'user exists');
    bad(res,500,'create error');
  }
});

app.get('/players', auth, async (_req,res)=>{
  const r=await q(`SELECT player_id,name,role,profile_pic_url FROM players ORDER BY created_at DESC`);
  ok(res,{ players:r.rows });
});
app.post('/players', auth, adminOnly, async (req,res)=>{
  const { player_id, name, role } = req.body||{};
  if(!player_id||!name) return bad(res,400,'player_id & name requis');
  try{
    await q(`INSERT INTO players(player_id,name,role) VALUES ($1,$2,$3)`,[player_id,name,role||'MEMBRE']);
    ok(res,{ ok:true });
  }catch(e){ if(String(e.message||'').includes('duplicate')) return bad(res,409,'exists'); bad(res,500,'create error'); }
});
app.put('/players/:id', auth, adminOnly, async (req,res)=>{
  try{
    const { name, role } = req.body||{};
    await q(`UPDATE players SET name=COALESCE($2,name), role=COALESCE($3,role) WHERE player_id=$1`,[req.params.id,name,role]);
    ok(res,{ ok:true });
  }catch(e){ bad(res,500,'update error'); }
});
app.delete('/players/:id', auth, adminOnly, async (req,res)=>{
  try{ await q(`DELETE FROM players WHERE player_id=$1`,[req.params.id]); ok(res,{ ok:true }); }
  catch(e){ bad(res,500,'delete error'); }
});

/* ====== Member panel (/me*) ====== */
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
  }catch(_){ }

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

/* ====== Presence (beat & list) ====== */
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

/* ====== Matchdays ====== */
app.get('/matchdays', auth, async (req,res)=>{
  const sid = await resolveSeasonId(req.query.season);
  const r = await q(
    `SELECT day FROM matchday
     WHERE season_id=$1
     ORDER BY day ASC`,
    [sid]
  );
  ok(res, { season_id: sid, days: r.rows.map(x=>dayjs(x.day).format('YYYY-MM-DD')) });
});
app.get('/matchdays/:date', auth, async (req,res)=>{
  const d = req.params.date;
  const r = await q(`SELECT payload FROM matchday WHERE day=$1`,[d]);
  if (!r.rowCount) return bad(res,404,'introuvable');
  res.json(r.rows[0].payload);
});

/* ====== Drafts temps réel ====== */
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
    await q(`INSERT INTO draft(day,payload,updated_at,author_user_id)
         VALUES ($1,$2,now(),$3)
         ON CONFLICT (day) DO UPDATE
         SET payload=EXCLUDED.payload, updated_at=now(), author_user_id=EXCLUDED.author_user_id`,
       [d, payload, req.user?.uid || null]);
    io.to(`draft:${d}`).emit('draft:update', { date:d });
    ok(res,{ ok:true });
  }catch(e){ bad(res,500,'draft save error'); }
});
app.post('/matchdays/draft/:date/subscribe', auth, async (req,res)=>{
  const d = req.params.date; io.to(`draft:${d}`).emit('draft:update', { date:d }); ok(res,{ ok:true });
});

/* ====== Standings helpers ====== */
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
function computeStandings(matches){
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
  const arr = Object.entries(agg).map(([id,x])=>({id,x,PTS:x.V*3+x.N,DIFF:x.BP-x.BC}));
  arr.sort((a,b)=>b.PTS-a.PTS||b.DIFF-a.DIFF||b.BP-a.BP||a.id.localeCompare(b.id));
  return arr;
}
const BONUS_D1_CHAMPION = 1;
function pointsD1(nPlayers, rank){ if(rank<1||rank>nPlayers) return 0; return 9+(nPlayers-rank); }
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

    const n1=st1.length, n2=st2.length;

    st1.forEach((r,idx)=>{ const o=ensure(r.id); o.total += pointsD1(n1, idx+1); o.participations+=1; });
    st2.forEach((r,idx)=>{ const o=ensure(r.id); o.total += pointsD2(idx+1);   o.participations+=1; });

    const champD1=p?.champions?.d1?.id||null;
    if(champD1 && (roles.get(champD1)||'MEMBRE')!=='INVITE'){ ensure(champD1).total += BONUS_D1_CHAMPION; ensure(champD1).won_d1++; }
    const champD2=p?.champions?.d2?.id||null;
    if(champD2 && (roles.get(champD2)||'MEMBRE')!=='INVITE'){ ensure(champD2).won_d2++; }

    const teamD1 = p?.champions?.d1?.team;
    if (champD1 && teamD1){ const k = teamKey(teamD1); if (k) ensure(champD1).teams.add(k); }
    const teamD2 = p?.champions?.d2?.team;
    if (champD2 && teamD2){ const k = teamKey(teamD2); if (k) ensure(champD2).teams.add(k); }
  }

  const allIds=[...totals.keys()];
  if(allIds.length){
    const r=await q(`SELECT player_id,name FROM players WHERE player_id=ANY($1::text[])`,[allIds]);
    const nameById=new Map(r.rows.map(x=>[x.player_id,x.name]));
    for(const o of totals.values()){
      o.name = nameById.get(o.id)||o.id;
      o.moyenne = o.participations>0 ? +(o.total/o.participations).toFixed(2) : 0;
    }
  }
  const arr=[...totals.values()].map(o=>({
    id:o.id, name:o.name, total:o.total, participations:o.participations,
    moyenne:o.moyenne, won_d1:o.won_d1, won_d2:o.won_d2,
    teams_used: o.teams ? o.teams.size : 0
  }));
  arr.sort((a,b)=> b.moyenne-a.moyenne || b.total-a.total || a.name.localeCompare(b.name));
  return arr;
}

/* ====== Duel ====== */
function teamKey(t){
  if(!t) return null; const s=String(t).toLowerCase();
  const m = s.match(/^(?:club )?(.+?)(?:\s*(?:fc|cf|ac|sc|united|city))?$/i); // soft key
  return (m?m[1]:s).trim();
}
app.get('/duel', auth, async (req,res)=>{
  const mePid = await getLinkedPlayerId(req.user.uid);
  const oppId = String(req.query.opp||'').trim();
  if(!mePid || !oppId) return bad(res,400,'missing');

  const sid = await resolveSeasonId(req.query.season);
  const { rows } = await loadDaysForSeason(sid);

  const legs=[]; const totals={ wins:0, losses:0, draws:0 };
  let best_me=null, best_opp=null;
  function pushLeg(date, division, leg, gf, ga){ legs.push({date,division,leg,gf,ga}); if(gf>ga) totals.wins++; else if(gf<ga) totals.losses++; else totals.draws++; }

  for(const d of rows){
    for(const div of ['d1','d2']){
      const M=d?.payload?.[div]||[];
      for(const m of M){
        if(!m?.p1 || !m?.p2) continue;
        const homeIsMe = (m.p1===mePid && m.p2===oppId);
        const awayIsMe = (m.p2===mePid && m.p1===oppId);
        if(!homeIsMe && !awayIsMe) continue;
        const allerDone  = m.a1!=null && m.a2!=null;
        const retourDone = m.r1!=null && m.r2!=null;
        if(allerDone){
          const gf = homeIsMe? m.a1 : m.a2;
          const ga = homeIsMe? m.a2 : m.a1;
          pushLeg(d.day, div.toUpperCase(), 'Aller', gf, ga);
          if(!best_me || gf>best_me.gf){ best_me={gf,ga,leg:'Aller',division:div.toUpperCase(),date:d.day}; }
          if(!best_opp || ga>best_opp.gf){ best_opp={gf:ga,ga:gf,leg:'Aller',division:div.toUpperCase(),date:d.day}; }
        }
        if(retourDone){
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

/* ====== WebSockets (no handoff) ====== */
io.on('connection', (socket)=>{
  socket.on('join', ({room})=>{
    if(room && typeof room === 'string') socket.join(room);
  });

  // relais des notifications de brouillon
  socket.on('draft:update', ({date})=>{
    if(!date) return;
    io.to(`draft:${date}`).emit('draft:update', { date });
  });
});

/* ====== Start ====== */
(async ()=>{
  try{
    await ensureSchema();
    server.listen(PORT, ()=> console.log('API OK on :'+PORT));
  }catch(e){
    console.error('Schema init error', e);
    process.exit(1);
  }
})();

/* ====== Janitor ====== */
const JANITOR_EVERY_MS = 60*1000;
setInterval(async ()=>{
  try{
    await q(`UPDATE sessions
             SET is_active=false, revoked_at=now()
             WHERE is_active=true AND last_seen < now() - interval '24 hours'`);

    const uids = await q(`
      SELECT DISTINCT user_id
      FROM sessions
      WHERE logout_at IS NOT NULL
        AND cleaned_after_logout = false
        AND logout_at < now() - interval '5 minutes'
    `);

    for(const row of uids.rows){
      await q(`DELETE FROM draft WHERE author_user_id=$1`, [row.user_id]);
      await q(`UPDATE sessions
               SET cleaned_after_logout=true
               WHERE user_id=$1
                 AND logout_at IS NOT NULL
                 AND logout_at < now() - interval '5 minutes'`,
              [row.user_id]);
    }
  }catch(e){ console.error('janitor error', e); }
}, JANITOR_EVERY_MS);
