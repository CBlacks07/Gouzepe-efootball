// server.js — GOUZEPE eFOOT API (Express + PostgreSQL + Socket.IO) — 2025-09-16
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
const crypto = require('crypto');

/* ====== Config ====== */
const PORT = parseInt(process.env.PORT || '10000', 10);
const JWT_SECRET = process.env.JWT_SECRET || '1XS1r4QJNp6AtkjORvKUU01RZRfzbGV+echJsio9gq8lAOc2NW7sSYsQuncE6+o9';

// CORS: par défaut * ; restreins avec CORS_ORIGIN="https://front1,..."
const allowedOrigins = (process.env.CORS_ORIGIN || '*')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const useSSL =
  process.env.PGSSL === 'true' ||
  process.env.RENDER === 'true' ||
  process.env.NODE_ENV === 'production';

const pgOpts = process.env.DATABASE_URL
  ? { connectionString: process.env.DATABASE_URL, ssl: useSSL ? { rejectUnauthorized:false } : false }
  : {
      host: process.env.PGHOST || 'localhost',
      user: process.env.PGUSER || 'postgres',
      password: process.env.PGPASSWORD || 'postgres',
      database: process.env.PGDATABASE || 'efoot',
      port: parseInt(process.env.PGPORT || '5432', 10),
      ssl: useSSL ? { rejectUnauthorized:false } : false
    };

const pool = new Pool(pgOpts);
const app = express();
const server = http.createServer(app);
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
  credentials: false,
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

const storage = multer.diskStorage({
  destination:(req,file,cb)=> cb(null, UP_PLAYERS),
  filename:(req,file,cb)=>{
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, crypto.randomBytes(8).toString('hex') + ext);
  }
});
const upload = multer({
  storage,
  limits:{ fileSize:2*1024*1024 },
  fileFilter:(req,file,cb)=>{
    const ok = ['.png','.jpg','.jpeg','.webp','.gif'].includes(path.extname(file.originalname).toLowerCase());
    cb(ok ? null : new Error('Invalid file type'), ok);
  }
});

/* ====== Utils ====== */
const ok  = (res, data)=> res.json({ ok:true, ...data });
const bad = (res, code, msg)=> res.status(code).json({ ok:false, error:msg });
async function q(sql, params=[]){ const c = await pool.connect(); try{ return await c.query(sql, params); } finally{ c.release(); } }
const newId = ()=> crypto.randomUUID();
const normEmail = s => (s||'').trim().toLowerCase();
const clientIp = req => (req.headers['x-forwarded-for']||req.socket.remoteAddress||'').toString().split(',')[0].trim();
const deviceLabel = req => ((req.headers['user-agent']||'').slice(0,200) || 'Appareil');

/* ====== Static ====== */
app.use('/uploads', express.static(UP));

/* ====== DB schema (auto + migrations tolérantes) ====== */
async function ensureSchema(){
  // users
  await q(`CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    player_id TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    last_login TIMESTAMPTZ
  )`);

  // sessions
  await q(`CREATE TABLE IF NOT EXISTS sessions(
     id TEXT PRIMARY KEY,
     user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
     created_at TIMESTAMPTZ DEFAULT now()
  )`);
  // Colonnes possiblement manquantes selon anciennes versions
  await q(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device TEXT`);
  await q(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT`);
  await q(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip TEXT`);
  await q(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ DEFAULT now()`);
  await q(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true`);
  await q(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ`);
  await q(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS logout_at TIMESTAMPTZ`);
  await q(`ALTER TABLE sessions ADD COLUMN IF NOT EXISTS cleaned_after_logout BOOLEAN NOT NULL DEFAULT false`);
  await q(`CREATE INDEX IF NOT EXISTS sessions_user_active ON sessions(user_id) WHERE is_active`);

  // seasons
  await q(`CREATE TABLE IF NOT EXISTS seasons(
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    is_closed BOOLEAN NOT NULL DEFAULT false,
    started_at TIMESTAMPTZ DEFAULT now(),
    ended_at TIMESTAMPTZ
  )`);
  const s = await q(`SELECT id FROM seasons WHERE is_closed=false ORDER BY id DESC LIMIT 1`);
  if(s.rowCount===0){ await q(`INSERT INTO seasons(name,is_closed) VALUES ('Saison courante', false)`); }

  // players (anciennes bases peuvent ne pas avoir user_id etc.)
  await q(`CREATE TABLE IF NOT EXISTS players(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);
  await q(`ALTER TABLE players ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES users(id) ON DELETE SET NULL`);
  await q(`ALTER TABLE players ADD COLUMN IF NOT EXISTS nickname TEXT`);
  await q(`ALTER TABLE players ADD COLUMN IF NOT EXISTS number INTEGER`);
  await q(`ALTER TABLE players ADD COLUMN IF NOT EXISTS photo TEXT`);
  await q(`ALTER TABLE players ADD COLUMN IF NOT EXISTS role TEXT`);
  await q(`CREATE INDEX IF NOT EXISTS players_user_idx ON players(user_id)`);

  // matches
  await q(`CREATE TABLE IF NOT EXISTS matches(
    id SERIAL PRIMARY KEY,
    season_id INTEGER REFERENCES seasons(id) ON DELETE CASCADE,
    matchday INTEGER NOT NULL,
    team_a TEXT NOT NULL,
    team_b TEXT NOT NULL,
    score_a INTEGER NOT NULL DEFAULT 0,
    score_b INTEGER NOT NULL DEFAULT 0,
    played_at TIMESTAMPTZ DEFAULT now(),
    created_at TIMESTAMPTZ DEFAULT now()
  )`);

  // standings
  await q(`CREATE TABLE IF NOT EXISTS standings(
    id SERIAL PRIMARY KEY,
    season_id INTEGER REFERENCES seasons(id) ON DELETE CASCADE,
    player_id TEXT REFERENCES players(id) ON DELETE CASCADE,
    played INTEGER NOT NULL DEFAULT 0,
    won INTEGER NOT NULL DEFAULT 0,
    draw INTEGER NOT NULL DEFAULT 0,
    lost INTEGER NOT NULL DEFAULT 0,
    goals_for INTEGER NOT NULL DEFAULT 0,
    goals_against INTEGER NOT NULL DEFAULT 0,
    points INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ DEFAULT now()
  )`);
  await q(`CREATE INDEX IF NOT EXISTS standings_season_player_idx ON standings(season_id, player_id)`);

  // draft
  await q(`CREATE TABLE IF NOT EXISTS draft(
    id SERIAL PRIMARY KEY,
    author_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    date DATE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);
  await q(`ALTER TABLE draft ADD COLUMN IF NOT EXISTS author_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL`);
  await q(`CREATE INDEX IF NOT EXISTS draft_author_idx ON draft(author_user_id)`);
}

/* ====== Auth helpers ====== */
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
      if(!p.sid) return bad(res,401,'Session missing');

      const r = await q(`SELECT is_active,last_seen FROM sessions WHERE id=$1`, [p.sid]);
      if(!r.rowCount || !r.rows[0].is_active) return bad(res,401,'Session revoked');

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

/* ====== Auth ====== */
app.post('/auth/login', async (req,res)=>{
  try{
    let { email, password } = req.body || {};
    email = normEmail(email);
    if(!email || !password) return bad(res,400,'email/password requis');

    const r = await q(`SELECT id, email, password_hash, role FROM users WHERE email=$1`, [email]);
    if(r.rowCount===0) return bad(res,401,'Utilisateur inconnu');
    const u = r.rows[0];

    const okPass = await bcrypt.compare(password, u.password_hash);
    if(!okPass) return bad(res,401,'Mot de passe incorrect');

    const sid = newId();
    await q(`INSERT INTO sessions(id,user_id,device,user_agent,ip) VALUES ($1,$2,$3,$4,$5)`,
      [sid, u.id, deviceLabel(req), (req.headers['user-agent']||'').slice(0,200), clientIp(req)]);

    const token = signToken(u, sid);
    await q(`UPDATE users SET last_login=now() WHERE id=$1`, [u.id]);

    return ok(res, { token, user:{ id:u.id, email:u.email, role:u.role } });
  }catch(e){
    console.error('login error', e);
    return bad(res,500,'Erreur serveur');
  }
});

app.get('/auth/me', auth, async (req,res)=>{
  const r = await q(`SELECT id,email,role,player_id FROM users WHERE id=$1`,[req.user.uid]);
  if(!r.rowCount) return bad(res,404,'User not found');
  ok(res,{ user:r.rows[0] });
});

app.post('/auth/logout', auth, async (req,res)=>{
  await q(`UPDATE sessions SET is_active=false, revoked_at=now(), logout_at=now() WHERE id=$1`, [req.user.sid]);
  ok(res,{ ok:true });
});

/* ====== Users (admin) ====== */
app.get('/admin/users', auth, adminOnly, async (_req,res)=>{
  const r = await q(`SELECT id,email,role,player_id,created_at,last_login FROM users ORDER BY id DESC`);
  ok(res,{ users:r.rows });
});
app.post('/admin/users', auth, adminOnly, async (req,res)=>{
  const { email, password, role } = req.body || {};
  if(!email || !password) return bad(res,400,'email/password requis');
  const ph = await bcrypt.hash(password, 10);
  try{
    const r = await q(`INSERT INTO users(email,password_hash,role) VALUES($1,$2,$3) RETURNING id,email,role`, [normEmail(email), ph, role||'member']);
    ok(res,{ user:r.rows[0] });
  }catch(e){
    if((e.code||'')==='23505') return bad(res,409,'Email déjà utilisé');
    throw e;
  }
});
app.put('/admin/users/:id', auth, adminOnly, async (req,res)=>{
  const id = parseInt(req.params.id, 10);
  const { role, player_id } = req.body || {};
  await q(`UPDATE users SET role=COALESCE($2,role), player_id=COALESCE($3,player_id) WHERE id=$1`, [id, role, player_id]);
  ok(res,{ ok:true });
});
app.delete('/admin/users/:id', auth, adminOnly, async (req,res)=>{
  const id = parseInt(req.params.id, 10);
  await q(`DELETE FROM users WHERE id=$1`, [id]);
  ok(res,{ ok:true });
});

/* ====== Players ====== */
app.get('/players', auth, async (_req,res)=>{
  const r=await q(`SELECT id,name,nickname,number,photo,role FROM players ORDER BY name ASC`);
  ok(res,{ players:r.rows });
});
app.get('/players/:pid', auth, async (req,res)=>{
  const r=await q(`SELECT id,name,nickname,number,photo,role,user_id FROM players WHERE id=$1`, [req.params.pid]);
  if(!r.rowCount) return bad(res,404,'Joueur introuvable');
  ok(res,{ player:r.rows[0] });
});
app.get('/players/:pid/matches', auth, async (req,res)=>{
  const r=await q(`SELECT * FROM matches WHERE team_a=$1 OR team_b=$1 ORDER BY played_at DESC`, [req.params.pid]);
  ok(res,{ matches:r.rows });
});
app.get('/players/:pid/summary', auth, async (req,res)=>{
  const pid = req.params.pid;
  const sum = await q(`SELECT
    SUM(CASE WHEN (team_a=$1 AND score_a>score_b) OR (team_b=$1 AND score_b>score_a) THEN 1 ELSE 0 END) AS won,
    SUM(CASE WHEN score_a=score_b THEN 1 ELSE 0 END) AS draw,
    SUM(CASE WHEN (team_a=$1 AND score_a<score_b) OR (team_b=$1 AND score_b<score_a) THEN 1 ELSE 0 END) AS lost
  FROM matches`, [pid]);
  ok(res,{ summary:sum.rows[0]||{} });
});
app.post('/admin/players', auth, adminOnly, upload.single('photo'), async (req,res)=>{
  const { id, name, nickname, number, role } = req.body || {};
  if(!id || !name) return bad(res,400,'id/name requis');
  let photo = null;
  if(req.file){ photo = '/uploads/players/'+req.file.filename; }
  await q(`INSERT INTO players(id,name,nickname,number,photo,role) VALUES($1,$2,$3,$4,$5,$6)
           ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, nickname=EXCLUDED.nickname, number=EXCLUDED.number, photo=COALESCE(EXCLUDED.photo, players.photo), role=EXCLUDED.role`,
           [id, name, nickname||null, number?parseInt(number,10):null, photo, role||null]);
  ok(res,{ ok:true, photo });
});
app.delete('/admin/players/:pid', auth, adminOnly, async (req,res)=>{
  await q(`DELETE FROM players WHERE id=$1`, [req.params.pid]);
  ok(res,{ ok:true });
});

/* ====== Matches ====== */
app.get('/matches', auth, async (_req,res)=>{
  const r=await q(`SELECT * FROM matches ORDER BY played_at DESC`);
  ok(res,{ matches:r.rows });
});
app.post('/admin/matches', auth, adminOnly, async (req,res)=>{
  const { season_id, matchday, team_a, team_b, score_a, score_b, played_at } = req.body || {};
  if(!season_id || !matchday || !team_a || !team_b) return bad(res,400,'champs requis');
  await q(`INSERT INTO matches(season_id,matchday,team_a,team_b,score_a,score_b,played_at)
           VALUES($1,$2,$3,$4,COALESCE($5,0),COALESCE($6,0),COALESCE($7, now()))`,
           [season_id, matchday, team_a, team_b, score_a, score_b, played_at]);
  ok(res,{ ok:true });
});

/* ====== Standings ====== */
async function recomputeSeasonStandings(seasonId){
  await q(`DELETE FROM standings WHERE season_id=$1`, [seasonId]);
  await q(`
    INSERT INTO standings(season_id,player_id,played,won,draw,lost,goals_for,goals_against,points)
    SELECT $1 AS season_id, p.id AS player_id,
      COUNT(m.*) AS played,
      SUM(CASE WHEN (m.team_a=p.id AND m.score_a>m.score_b) OR (m.team_b=p.id AND m.score_b>m.score_a) THEN 1 ELSE 0 END) AS won,
      SUM(CASE WHEN m.score_a=m.score_b THEN 1 ELSE 0 END) AS draw,
      SUM(CASE WHEN (m.team_a=p.id AND m.score_a<m.score_b) OR (m.team_b=p.id AND m.score_b<m.score_a) THEN 1 ELSE 0 END) AS lost,
      SUM(CASE WHEN m.team_a=p.id THEN m.score_a WHEN m.team_b=p.id THEN m.score_b ELSE 0 END) AS goals_for,
      SUM(CASE WHEN m.team_a=p.id THEN m.score_b WHEN m.team_b=p.id THEN m.score_a ELSE 0 END) AS goals_against,
      SUM(CASE WHEN (m.team_a=p.id AND m.score_a>m.score_b) OR (m.team_b=p.id AND m.score_b>m.score_a) THEN 3 WHEN m.score_a=m.score_b THEN 1 ELSE 0 END) AS points
    FROM players p
    LEFT JOIN matches m ON (m.team_a=p.id OR m.team_b=p.id) AND m.season_id=$1
    GROUP BY p.id
  `, [seasonId]);
}
async function SeasonStandings(seasonId){
  const r=await q(`SELECT s.*, p.name FROM standings s JOIN players p ON p.id=s.player_id WHERE s.season_id=$1 ORDER BY points DESC, (goals_for - goals_against) DESC`, [seasonId]);
  return r.rows;
}
app.get('/standings/:seasonId', auth, async (req,res)=>{
  const sid = parseInt(req.params.seasonId, 10);
  const list = await SeasonStandings(sid);
  ok(res,{ season_id:sid, standings:list });
});

/* ====== Saisons ====== */
app.get('/seasons', auth, async (_req,res)=>{
  const r=await q(`SELECT id,name,is_closed,started_at,ended_at FROM seasons ORDER BY id DESC`);
  ok(res,{ seasons:r.rows });
});
app.get('/season/list', auth, async (_req,res)=>{
  const r=await q(`SELECT id,name FROM seasons ORDER BY id DESC`);
  ok(res,{ seasons:r.rows });
});
app.get('/season/current', auth, async (_req,res)=>{
  const r=await q(`SELECT id,name FROM seasons WHERE is_closed=false ORDER BY id DESC LIMIT 1`);
  ok(res,{ season:r.rows[0]||null });
});
app.post('/admin/seasons', auth, adminOnly, async (req,res)=>{
  const { name } = req.body || {};
  if(!name) return bad(res,400,'name requis');
  const r=await q(`INSERT INTO seasons(name,is_closed) VALUES($1,false) RETURNING id,name,is_closed,started_at`, [name]);
  ok(res,{ season:r.rows[0] });
});
app.post('/admin/seasons/:id/close', auth, adminOnly, async (req,res)=>{
  const sid = parseInt(req.params.id, 10);
  await q(`UPDATE seasons SET is_closed=true, ended_at=now() WHERE id=$1`, [sid]);
  await recomputeSeasonStandings(sid);
  ok(res,{ ok:true });
});

/* ====== Presence (Socket relays) ====== */
io.on('connection', (socket)=>{
  socket.on('presence:join', ({room})=>{ if(room) socket.join('presence:'+room); });
  socket.on('presence:leave', ({room})=>{ if(room) socket.leave('presence:'+room); });
  socket.on('presence:pulse', ({room, user})=>{
    if(room) io.to('presence:'+room).emit('presence:pulse', { user, at:Date.now() });
  });
});

/* ====== Healthcheck ====== */
app.get('/healthz', (_req,res)=> res.json({ ok:true, time:Date.now() }));

/* ====== Start ====== */
(async ()=>{
  try{
    await ensureSchema();
    server.listen(PORT, ()=> console.log('API OK on :' + PORT));
  }catch(e){
    console.error('Schema init error', e);
    process.exit(1);
  }
})();

/* ====== Janitor (post-logout cleanups) ====== */
const JANITOR_EVERY_MS = 60*1000;
setInterval(async ()=>{
  try{
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
