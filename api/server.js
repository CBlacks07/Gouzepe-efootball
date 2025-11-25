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
const crypto = require('crypto');

/* ====== Config ====== */
const PORT = parseInt(process.env.PORT || '3005', 10);
const HOST = process.env.HOST || '0.0.0.0'; // 0.0.0.0 pour accepter les connexions réseau, localhost pour local uniquement
const JWT_SECRET = process.env.JWT_SECRET || '1XS1r4QJNp6AtkjORvKUU01RZRfzbGV+echJsio9gq8lAOc2NW7sSYsQuncE6+o9';
const EMAIL_DOMAIN = process.env.EMAIL_DOMAIN || 'gz.local';

/* ====== Database ====== */
const localHosts = new Set(['localhost','127.0.0.1']);
const parsedDbUrl = (()=>{ try { return process.env.DATABASE_URL ? new URL(process.env.DATABASE_URL) : null; } catch(_) { return null; } })();
const inferLocal = parsedDbUrl ? localHosts.has(parsedDbUrl.hostname) : localHosts.has(String(process.env.PGHOST||'').toLowerCase());

const forceSSL = process.env.PGSSL_FORCE === 'true';
const useSSL = forceSSL ? true : (inferLocal ? false : process.env.PGSSL === 'true');

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

/* ====== App ====== */
const app = express();
const server = http.createServer(app);

// Configuration CORS
const allowedOrigins = (process.env.CORS_ORIGIN ||
  'http://localhost:3000,http://localhost:5173'
).split(',').map(s=>s.trim()).filter(Boolean);

// ✅ FIX: Configuration CORS unique (suppression de la duplication)
const corsOptions = {
  origin: (origin, cb) => {
    // Pas d'origin = requête depuis le même serveur ou Electron
    if (!origin) return cb(null, true);

    // Wildcard autorisé
    if (allowedOrigins.includes('*')) return cb(null, true);

    // Origin dans la liste autorisée
    if (allowedOrigins.includes(origin)) return cb(null, true);

    // Autoriser les connexions depuis le réseau local (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    try {
      const originUrl = new URL(origin);
      const hostname = originUrl.hostname;

      // Localhost
      if (hostname === 'localhost' || hostname === '127.0.0.1') {
        return cb(null, true);
      }

      // Réseau local
      if (
        /^192\.168\.\d+\.\d+$/.test(hostname) ||
        /^10\.\d+\.\d+\.\d+$/.test(hostname) ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$/.test(hostname)
      ) {
        return cb(null, true);
      }
    } catch (e) {
      // Invalid origin URL
    }

    return cb(null, false);
  },
  credentials: false,
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Authorization','Content-Type'],
  exposedHeaders: ['Content-Length'],
  maxAge: 86400
};

const io = require('socket.io')(server, {
  cors: {
    origin: (origin, cb) => {
      // Pas d'origin = requête depuis le même serveur ou Electron
      if (!origin) return cb(null, true);

      // Wildcard autorisé
      if (allowedOrigins.includes('*')) return cb(null, true);

      // Origin dans la liste autorisée
      if (allowedOrigins.includes(origin)) return cb(null, true);

      // Autoriser les connexions depuis le réseau local
      try {
        const originUrl = new URL(origin);
        const hostname = originUrl.hostname;

        // Localhost
        if (hostname === 'localhost' || hostname === '127.0.0.1') {
          return cb(null, true);
        }

        // Réseau local
        if (
          /^192\.168\.\d+\.\d+$/.test(hostname) ||
          /^10\.\d+\.\d+\.\d+$/.test(hostname) ||
          /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$/.test(hostname)
        ) {
          return cb(null, true);
        }
      } catch (e) {
        // Invalid origin URL
      }

      cb(null, false);
    },
    methods: ['GET','POST','PUT','DELETE','OPTIONS']
  }
});

/* ====== Middlewares ====== */
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

/* ====== Uploads ====== */
const UP = path.join(__dirname, 'uploads');
const UP_PLAYERS = path.join(UP, 'players');
fs.mkdirSync(UP_PLAYERS, { recursive:true });
app.use('/uploads', express.static(UP));

/* ====== Static files (web) ====== */
app.use('/web', express.static(path.join(__dirname, '../web')));

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

/* ====== Team key helper ====== */
const TEAM_KEY_LEN = parseInt(process.env.TEAM_KEY_LEN || '4', 10);
function teamKey(raw){
  if(!raw) return '';
  let s = String(raw)
    .normalize('NFD').replace(/[\u0300-\u036f]/g,'')                 // accents
    .replace(/\p{Emoji_Presentation}|\p{Extended_Pictographic}/gu,'')// emoji/drapeaux
    .toUpperCase()
    .replace(/\b(FC|CF|SC|AC|REAL|THE)\b/g, ' ')
    .replace(/[^A-Z0-9]+/g,'')
    .trim();
  return s.slice(0, TEAM_KEY_LEN);
}

/* ====== Schema (tolérant) ====== */
async function ensureSchema(){

  /* duels */
  await q(`CREATE TABLE IF NOT EXISTS duels(
    id SERIAL PRIMARY KEY,
    p1_id TEXT NOT NULL,
    p2_id TEXT NOT NULL,
    score_a INT NOT NULL,
    score_b INT NOT NULL,
    played_at TIMESTAMPTZ DEFAULT now(),
    created_at TIMESTAMPTZ DEFAULT now()
  )`);

  /* users (ajouts “soft”) */
  await q(`CREATE TABLE IF NOT EXISTS users(
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    player_id TEXT,
    created_at TIMESTAMP DEFAULT now(),
    last_login TIMESTAMP
  )`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT now()`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS player_id TEXT`);
  await q(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT`);
  await q(`
  DO $$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='id') THEN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relkind='S' AND relname='users_id_seq') THEN
        CREATE SEQUENCE users_id_seq;
      END IF;
      ALTER TABLE users ADD COLUMN id INTEGER;
      ALTER TABLE users ALTER COLUMN id SET DEFAULT nextval('users_id_seq');
      UPDATE users SET id = nextval('users_id_seq') WHERE id IS NULL;
      BEGIN
        ALTER TABLE users ADD PRIMARY KEY (id);
      EXCEPTION WHEN duplicate_table THEN
      END;
    END IF;
  END$$;
  `);

  /* sessions */
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

  /* seasons */
  await q(`CREATE TABLE IF NOT EXISTS seasons(
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ,
    is_closed BOOLEAN NOT NULL DEFAULT false
  )`);

  /* matchday */
  await q(`CREATE TABLE IF NOT EXISTS matchday(
    day DATE PRIMARY KEY,
    season_id INTEGER,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);

  /* draft */
  await q(`CREATE TABLE IF NOT EXISTS draft(
    day DATE PRIMARY KEY,
    payload JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now(),
    author_user_id INTEGER
  )`);
  await q(`CREATE INDEX IF NOT EXISTS draft_author_idx ON draft(author_user_id)`);

  /* players */
  await q(`CREATE TABLE IF NOT EXISTS players(
    player_id TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    role      TEXT NOT NULL DEFAULT 'MEMBRE',
    profile_pic_url TEXT,
    created_at TIMESTAMP DEFAULT now()
  )`);
  await q(`ALTER TABLE players ADD COLUMN IF NOT EXISTS profile_pic_url TEXT`);

  /* seed admin */
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@gz.local';
  const adminPass  = process.env.ADMIN_PASSWORD || 'admin';
  const row = await q(`SELECT id FROM users WHERE email=$1`,[adminEmail]);
  if(row.rowCount===0){
    const hash = await bcrypt.hash(adminPass,10);
    await q(`INSERT INTO users(email,password_hash,role) VALUES ($1,$2,'admin')`,[adminEmail,hash]);
    console.log(`Seed admin: ${adminEmail} / ${adminPass}`);
  }

  /* season par défaut */
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
app.get('/health',  (_req,res)=> ok(res,{ ok:true, service:'gouzepe-api', ts:Date.now() }));

/* ====== Auth (single-session simple) ====== */
app.post('/auth/login', async (req,res)=>{
  let {email,password}=req.body||{};
  email = normEmail(email);
  if(!email||!password) return bad(res,400,'email/password requis');

  const r=await q(`SELECT id,email,role,password_hash FROM users WHERE email=$1`,[email]);
  if(r.rowCount===0) return bad(res,401,'Utilisateur inconnu');
  const u=r.rows[0];
  const match = await bcrypt.compare(password, u.password_hash);
  if(!match) return bad(res,401,'Mot de passe incorrect');

  await q(`UPDATE sessions SET is_active=false, revoked_at=now() WHERE user_id=$1 AND is_active=true`, [u.id]);

  const sid = newId();
  await q(`INSERT INTO sessions(id,user_id,device,user_agent,ip) VALUES ($1,$2,$3,$4,$5)`,
    [sid, u.id, deviceLabel(req), (req.headers['user-agent']||'').slice(0,200), clientIp(req)]);

  const token = signToken(u, sid);
  await q(`UPDATE users SET last_login=now() WHERE id=$1`, [u.id]);
  ok(res,{ token, user:{id:u.id,email:u.email,role:u.role}, expHours:24 });
});
app.get('/auth/me', auth, async (req,res)=>{
  const r=await q(`SELECT id,email,role,player_id FROM users WHERE id=$1`,[req.user.uid]);
  if(!r.rowCount) return bad(res,404,'User not found');
  ok(res,{ user:r.rows[0] });
});
app.post('/auth/logout', auth, async (req,res)=>{
  await q(`UPDATE sessions SET is_active=false, revoked_at=now(), logout_at=now() WHERE id=$1`, [req.user.sid]);
  ok(res,{ ok:true });
});

/* ====== Presence ====== */
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

/* ====== Admin users ====== */
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

/* ====== Players ====== */
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

// Mettre à jour un joueur (admin seulement)
app.put('/admin/players/:oldId', auth, adminOnly, async (req, res) => {
  const oldId = req.params.oldId;
  const { player_id: newId, name, role } = req.body || {};

  // Vérifier que le joueur existe
  const existing = await q(`SELECT player_id, name, role FROM players WHERE player_id = $1`, [oldId]);
  if (!existing.rowCount) return bad(res, 404, 'Joueur introuvable');

  const player = existing.rows[0];
  const updatedName = name !== undefined ? name : player.name;
  const updatedRole = role !== undefined ? role : player.role;

  // Si l'ID change
  if (newId && newId !== oldId) {
    // Vérifier que le nouvel ID n'existe pas déjà
    const conflict = await q(`SELECT player_id FROM players WHERE player_id = $1`, [newId]);
    if (conflict.rowCount) return bad(res, 409, 'Ce nouvel ID existe déjà');

    // Fonction helper pour mettre à jour les player_id dans un JSONB
    function updatePlayerIdInPayload(payload, oldId, newId) {
      if (!payload) return payload;
      let updated = false;

      // Mettre à jour d1 et d2 (matchs)
      for (const div of ['d1', 'd2']) {
        if (Array.isArray(payload[div])) {
          payload[div].forEach(match => {
            if (match.p1 === oldId) { match.p1 = newId; updated = true; }
            if (match.p2 === oldId) { match.p2 = newId; updated = true; }
          });
        }
      }

      // Mettre à jour champions
      if (payload.champions) {
        if (payload.champions.d1?.id === oldId) {
          payload.champions.d1.id = newId;
          updated = true;
        }
        if (payload.champions.d2?.id === oldId) {
          payload.champions.d2.id = newId;
          updated = true;
        }
      }

      // Mettre à jour barrage
      if (payload.barrage?.winner === oldId) {
        payload.barrage.winner = newId;
        updated = true;
      }

      return updated ? payload : null;
    }

    // Mettre à jour les matchdays
    const matchdays = await q(`SELECT day, payload FROM matchday ORDER BY day ASC`);
    for (const row of matchdays.rows) {
      const updatedPayload = updatePlayerIdInPayload(JSON.parse(JSON.stringify(row.payload)), oldId, newId);
      if (updatedPayload) {
        await q(`UPDATE matchday SET payload = $1 WHERE day = $2`, [JSON.stringify(updatedPayload), row.day]);
      }
    }

    // Mettre à jour les drafts
    const drafts = await q(`SELECT day, payload FROM draft ORDER BY day ASC`);
    for (const row of drafts.rows) {
      const updatedPayload = updatePlayerIdInPayload(JSON.parse(JSON.stringify(row.payload)), oldId, newId);
      if (updatedPayload) {
        await q(`UPDATE draft SET payload = $1 WHERE day = $2`, [JSON.stringify(updatedPayload), row.day]);
      }
    }

    // Mettre à jour la table players (CASCADE vers users et champion_result)
    await q(`UPDATE players SET player_id = $1, name = $2, role = $3 WHERE player_id = $4`,
      [newId, updatedName, updatedRole, oldId]);

    // Mettre à jour la présence
    if (presence.players.has(oldId)) {
      const ts = presence.players.get(oldId);
      presence.players.delete(oldId);
      presence.players.set(newId, ts);
    }

    ok(res, { player: { player_id: newId, name: updatedName, role: updatedRole } });
  } else {
    // Mise à jour simple sans changement d'ID
    await q(`UPDATE players SET name = $1, role = $2 WHERE player_id = $3`,
      [updatedName, updatedRole, oldId]);
    ok(res, { player: { player_id: oldId, name: updatedName, role: updatedRole } });
  }
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
  const arr = Object.entries(agg).map(([id,x])=>({id,...x,PTS:x.V*3+x.N,DIFF:x.BP-x.BC}));
  arr.sort((a,b)=>b.PTS-a.PTS||b.DIFF-a.DIFF||b.BP-a.BP||a.id.localeCompare(b.id));
  return arr;
}
const BONUS_D1_CHAMPION = 1;
function pointsD1(nPlayers, rank){
  if(rank<1||rank>nPlayers) return 0;
  const basePoints = nPlayers > 10 ? 17 : 15;
  if(rank === 1) return basePoints;
  return basePoints - rank;
}
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

/* ====== /leaderboard (alias pour tes pages) ====== */
app.get('/leaderboard', auth, async (req,res)=>{
  const sid = await resolveSeasonId(req.query.season);
  const list = await computeSeasonStandings(sid);
  // adapte aux besoins front : name, player_id, points (=total), games (=participations)
  const leaderboard = list.map(x=>({
    player_id: x.id,
    name: x.name,
    points: x.total,
    games: x.participations,
    wins: undefined, draws: undefined, losses: undefined, // non calculés au niveau saison (optionnel)
    gf: undefined, ga: undefined, gd: undefined
  }));
  ok(res,{ season_id:sid, leaderboard });
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
  // ✅ FIX: Validation de la date et du payload
  if(!/^\d{4}-\d{2}-\d{2}$/.test(d)) return bad(res,400,'Invalid date format (YYYY-MM-DD expected)');
  if(!req.body || typeof req.body !== 'object') return bad(res,400,'Invalid payload');

  const payload = req.body;
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

  // ✅ FIX: Utiliser une transaction pour garantir l'atomicité
  try{
    await q('BEGIN');

    const sid = season_id ? +season_id : await currentSeasonId();
    const payload = { d1, d2, barrage, champions };

    await q(`INSERT INTO matchday(day,season_id,payload,created_at)
             VALUES ($1,$2,$3,now())
             ON CONFLICT (day) DO UPDATE SET season_id=EXCLUDED.season_id, payload=EXCLUDED.payload`,
             [date, sid, payload]);

    await q('DELETE FROM draft WHERE day=$1',[date]);

    await q('COMMIT');

    io.to(`draft:${date}`).emit('day:confirmed', { date });
    io.emit('season:changed');
    ok(res,{ ok:true });
  }catch(e){
    await q('ROLLBACK');
    console.error('[matchdays/confirm] Error:', e);
    bad(res,500,'Failed to confirm matchday');
  }
});
app.delete('/matchdays/:date', auth, async (req,res)=>{
  await q(`DELETE FROM matchday WHERE day=$1`,[req.params.date]);
  ok(res,{ ok:true });
});

/* ====== Standings exposés ====== */
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

/* ====== Saisons (CRUD & helpers) ====== */
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
  // ✅ FIX: Retourner un objet JSON cohérent avec les autres endpoints
  ok(res, { ids: r.rows.map(x=>x.id) });
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

/* ====== Face-à-face ====== */
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

/* ====== Duels (additive) ====== */
function normalizeDuelBody(body){
  const src = body && typeof body==='object' ? (body.duel && typeof body.duel==='object' ? body.duel : body) : {};
  const val = (v)=> (v===undefined || v===null ? undefined : (typeof v==='string' ? v.trim() : v));
  const pick = (o, ...keys)=>{ for(const k of keys){ const v = val(o[k]); if(v!==undefined && v!=='') return v; } return undefined; };
  const p1 = pick(src, 'p1','player_a','A','a','p1_id','id1','idA','id_a','joueur1','player1');
  const p2 = pick(src, 'p2','player_b','B','b','p2_id','id2','idB','id_b','joueur2','player2');
  let sa = pick(src, 'score_a','score1','but1','sA','sa','a_score','goals1');
  let sb = pick(src, 'score_b','score2','but2','sB','sb','b_score','goals2');
  const when = pick(src, 'played_at','date','when','playedAt','match_date');
  const n = (x)=>{ const i = parseInt(x,10); return Number.isFinite(i) ? i : NaN; };
  return { p1, p2, score_a: n(sa), score_b: n(sb), played_at: when };
}
/* Create duel */
app.post('/duels', async (req,res)=>{
  try{
    const { p1, p2, score_a, score_b, played_at } = normalizeDuelBody(req.body);
    if(!p1 || !p2 || !Number.isFinite(score_a) || !Number.isFinite(score_b)){
      return bad(res,400,'Missing fields: p1, p2, score_a, score_b');
    }
    const dt = played_at ? new Date(played_at) : null;
    const r = await q(
      'INSERT INTO duels(p1_id,p2_id,score_a,score_b,played_at) VALUES($1,$2,$3,$4,COALESCE($5, now())) RETURNING id',
      [String(p1), String(p2), score_a, score_b, (dt && !isNaN(dt)) ? dt : null]
    );
    ok(res,{ ok:true, id: r.rows[0].id });
  }catch(e){
    console.error('POST /duels error', e);
    bad(res,500,'Server error');
  }
});
/* Recent duels */
app.get('/duels/recent', async (req,res)=>{
  try{
    const { player, from, to, limit } = req.query;
    const lim = Math.max(1, Math.min(parseInt(limit||'20',10), 200));
    const cond = []; const vals = [];
    if(player){ cond.push('(p1_id = $'+(vals.length+1)+' OR p2_id = $'+(vals.length+1)+')'); vals.push(String(player)); }
    if(from){ cond.push('played_at >= $'+(vals.length+1)); vals.push(new Date(from)); }
    if(to){ cond.push('played_at <= $'+(vals.length+1)); vals.push(new Date(to)); }
    const where = cond.length ? ('WHERE '+cond.join(' AND ')) : '';

    const sql = `SELECT d.id, d.p1_id, d.p2_id, d.score_a, d.score_b, d.played_at,
                        p1.name AS p1_name, p2.name AS p2_name
                 FROM duels d
                 LEFT JOIN players p1 ON p1.player_id = d.p1_id
                 LEFT JOIN players p2 ON p2.player_id = d.p2_id
                 ${where}
                 ORDER BY d.played_at DESC, d.id DESC
                 LIMIT ${lim}`;
    const r = await q(sql, vals);
    ok(res,{ duels: r.rows });
  }catch(e){
    console.error('GET /duels/recent error', e);
    bad(res,500,'Server error');
  }
});
/* Head-to-head */
app.get('/duels/compare', async (req,res)=>{
  try{
    const p1 = req.query.p1 || req.query.A || req.query.a || req.query.player_a;
    const p2 = req.query.p2 || req.query.B || req.query.b || req.query.player_b;
    if(!p1 || !p2) return bad(res,400,'p1 and p2 required');

    const names = await q(
      `SELECT 
         (SELECT name FROM players WHERE player_id=$1) AS p1_name,
         (SELECT name FROM players WHERE player_id=$2) AS p2_name`,
      [String(p1), String(p2)]
    );
    const n = names.rows[0] || {};

    const stats = await q(
      `SELECT
         SUM(CASE WHEN p1_id=$1 AND score_a>score_b THEN 1 WHEN p2_id=$1 AND score_b>score_a THEN 1 ELSE 0 END) AS wins_p1,
         SUM(CASE WHEN score_a=score_b THEN 1 ELSE 0 END) AS draws,
         SUM(CASE WHEN p1_id=$2 AND score_a>score_b THEN 1 WHEN p2_id=$2 AND score_b>score_a THEN 1 ELSE 0 END) AS wins_p2,
         SUM(score_a) FILTER (WHERE p1_id=$1) + SUM(score_b) FILTER (WHERE p2_id=$1) AS gf_p1,
         SUM(score_b) FILTER (WHERE p1_id=$1) + SUM(score_a) FILTER (WHERE p2_id=$1) AS ga_p1,
         COUNT(*) AS legs
       FROM duels
       WHERE (p1_id=$1 AND p2_id=$2) OR (p1_id=$2 AND p2_id=$1)`,
      [String(p1), String(p2)]
    );
    const s = stats.rows[0] || {};
    const wins = Number(s.wins_p1||0);
    const draws = Number(s.draws||0);
    const losses = Number(s.wins_p2||0);
    const gf = Number(s.gf_p1||0);
    const ga = Number(s.ga_p1||0);
    const legs = Number(s.legs||0);

    ok(res,{
      p1: { id:String(p1), name: n.p1_name || null },
      p2: { id:String(p2), name: n.p2_name || null },
      totals: { wins, draws, losses, gf, ga, legs }
    });
  }catch(e){
    console.error('GET /duels/compare error', e);
    bad(res,500,'Server error');
  }
});
/* Delete duel (admin) */
app.delete('/duels/:id', auth, adminOnly, async (req,res)=>{
  try{
    const id = parseInt(req.params.id, 10);
    if(!id) return bad(res,400,'Invalid id');
    await q('DELETE FROM duels WHERE id=$1', [id]);
    ok(res,{ ok:true });
  }catch(e){
    console.error('DELETE /duels/:id error', e);
    bad(res,500,'Server error');
  }
});

/* ====== WebSockets (no handoff) ====== */
io.on('connection', (socket)=>{
  socket.on('join', ({room})=>{
    if(room && typeof room === 'string') socket.join(room);
  });
  socket.on('draft:update', ({date})=>{
    if(!date) return;
    io.to(`draft:${date}`).emit('draft:update', { date });
  });
});

/* ====== Start ====== */
(async ()=>{
  try{
    await ensureSchema();
    server.listen(PORT, HOST, ()=> {
      console.log(`API OK on ${HOST}:${PORT}`);

      // Afficher l'IP locale pour les connexions réseau
      if (HOST === '0.0.0.0') {
        const os = require('os');
        const networkInterfaces = os.networkInterfaces();
        const localIPs = [];

        Object.keys(networkInterfaces).forEach(interfaceName => {
          networkInterfaces[interfaceName].forEach(iface => {
            if (iface.family === 'IPv4' && !iface.internal) {
              localIPs.push(iface.address);
            }
          });
        });

        if (localIPs.length > 0) {
          console.log('\n📡 Serveur accessible depuis le réseau local :');
          localIPs.forEach(ip => {
            console.log(`   http://${ip}:${PORT}`);
          });
          console.log('\n💡 Les autres appareils peuvent se connecter avec ces URLs\n');
        }
      }
    });
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
