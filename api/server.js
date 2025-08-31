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

/* ---------- auth ---------- */
function auth(req,res,next){
  const h=req.headers.authorization||''; const m=h.match(/^Bearer\s+(.+)$/i);
  if(!m) return bad(res,401,'token manquant');
  try{
    req.user = jwt.verify(m[1], JWT_SECRET);
    next();
  }catch(_){ return bad(res,401,'token invalide'); }
}
function adminOnly(req,res,next){
  if((req.user?.role||'member')!=='admin') return bad(res,403,'admin uniquement');
  next();
}

/* ---------- schema (au besoin) ---------- */
async function ensureSchema(){
  await q(`CREATE TABLE IF NOT EXISTS players(
    player_id TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    role      TEXT NOT NULL DEFAULT 'MEMBRE',
    profile_pic_url TEXT
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
      IF NOT EXISTS 
        (SELECT 1 FROM information_schema.columns 
          WHERE table_name='users' AND column_name='created_at') THEN
        ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT now();
      END IF;
    END
    $$;
  `);

  await q(`CREATE TABLE IF NOT EXISTS seasons(
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    is_closed BOOLEAN NOT NULL DEFAULT false
  )`);

  await q(`CREATE TABLE IF NOT EXISTS matchday(
    day DATE PRIMARY KEY,
    season_id INTEGER REFERENCES seasons(id) ON DELETE SET NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP DEFAULT now()
  )`);

  await q(`CREATE TABLE IF NOT EXISTS draft(
    day DATE PRIMARY KEY,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb
  )`);
}

async function currentSeasonId(){
  const r=await q(`SELECT id FROM seasons WHERE NOT is_closed ORDER BY id DESC LIMIT 1`);
  return r.rowCount ? r.rows[0].id : null;
}
async function resolveSeasonId(qv){
  if(qv && String(qv).trim()){
    if(/^\d+$/.test(String(qv).trim())) return +qv;
    const r=await q(`SELECT id FROM seasons WHERE name ILIKE $1 ORDER BY id DESC LIMIT 1`, ['%'+qv+'%']);
    return r.rowCount ? r.rows[0].id : await currentSeasonId();
  }
  return await currentSeasonId();
}
async function getPlayersRoles(){
  const r=await q(`SELECT player_id,role FROM players`);
  const map=new Map(); r.rows.forEach(p=>map.set(p.player_id,(p.role||'MEMBRE').toUpperCase())); return map;
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
  for(const m of (matches||[])){
    if(!m.p1||!m.p2) continue;
    if(m.a1!=null&&m.a2!=null) add(m.p1,m.p2,m.a1,m.a2);
    if(m.r1!=null&&m.r2!=null) add(m.p2,m.p1,m.r2,m.r1); // retour inversé
  }
  const arr = Object.entries(agg).map(([id,x])=>({id,...x,PTS:x.V*3+x.N,DIFF:x.BP-x.BC}));
  arr.sort((a,b)=>b.PTS-a.PTS||b.DIFF-a.DIFF||b.BP-a.BP||a.id.localeCompare(b.id));
  return arr;
}

// Barème saison : D1 fixe (1=15, 2=13, 3=12, 4=11, 5=10, 6+=9), bonus champion D1 supprimé ; D2 table fixe
const BONUS_D1_CHAMPION = 0;
function pointsD1(rank){ if(rank===1) return 15; if(rank===2) return 13; if(rank===3) return 12; if(rank===4) return 11; if(rank===5) return 10; return 9; }
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

    st1.forEach((r,idx)=>{ const o=ensure(r.id); o.total += pointsD1(idx+1); o.participations+=1; });
    st2.forEach((r,idx)=>{ const o=ensure(r.id); o.total += pointsD2(idx+1);   o.participations+=1; });

    // gagnants (compteurs titres ; bonus supprimé)
    const champD1=p?.champions?.d1?.id||null;
    if(champD1 && (roles.get(champD1)||'MEMBRE')!=='INVITE'){ ensure(champD1).won_d1++; }
    const champD2=p?.champions?.d2?.id||null;
    if(champD2 && (roles.get(champD2)||'MEMBRE')!=='INVITE'){ ensure(champD2).won_d2++; }

    // équipes (depuis "Champion avec …")
    const teamD1 = p?.champions?.d1?.team;
    if (champD1 && teamD1){
      const k = String(teamD1||'').trim().toUpperCase();
      if (k) ensure(champD1).teams.add(k);
    }
    const teamD2 = p?.champions?.d2?.team;
    if (champD2 && teamD2){
      const k = String(teamD2||'').trim().toUpperCase();
      if (k) ensure(champD2).teams.add(k);
    }
  }

  // noms + moyenne (2 décimales ici)
  const allIds=[...totals.keys()];
  if(allIds.length){
    const r=await q(`SELECT player_id,name FROM players WHERE player_id=ANY($1::text[])`,[allIds]);
    const nameById=new Map(r.rows.map(x=>[x.player_id,x.name]));
    for(const o of totals.values()){
      o.name = nameById.get(o.id)||o.id;
      o.moyenne = o.participations>0 ? +(o.total/o.participations).toFixed(2) : 0;
    }
  }

  // Inclure tous les MEMBRES (même sans participation)
  try{
    const rAll = await q(`SELECT player_id,name FROM players WHERE UPPER(COALESCE(role,'MEMBRE'))='MEMBRE'`);
    for(const row of rAll.rows){
      if(!totals.has(row.player_id)){
        totals.set(row.player_id, {
          id: row.player_id, name: row.name||row.player_id,
          total: 0, participations: 0, won_d1: 0, won_d2: 0, teams: new Set(), moyenne: 0
        });
      }else{
        const o = totals.get(row.player_id);
        if(!o.name) o.name = row.name||row.player_id;
        if(typeof o.moyenne!=='number') o.moyenne = o.participations>0 ? +(o.total/o.participations).toFixed(2) : 0;
      }
    }
  }catch(_){}

  const arr=[...totals.values()].map(o=>({
    id:o.id, name:o.name, total:o.total, participations:o.participations,
    moyenne:o.moyenne, won_d1:o.won_d1, won_d2:o.won_d2,
    teams_used: o.teams ? o.teams.size : 0
  }));

  // Tri : moyenne ↓, total ↓, participations ↓, titres (D1 puis D2), puis nom
  arr.sort((a,b)=>
    (b.moyenne - a.moyenne) ||
    (b.total   - a.total)   ||
    ((b.participations||0) - (a.participations||0)) ||
    (((b.won_d1||0)*100 + (b.won_d2||0)) - ((a.won_d1||0)*100 + (a.won_d2||0))) ||
    (a.name||a.id).localeCompare(b.name||b.id)
  );
  return arr;
  }

/* ---------- health ---------- */
app.get('/health', (_req,res)=> ok(res,{ ok:true, service:'gouzepe-api', ts:Date.now() }));

/* ---------- auth ---------- */
app.post('/auth/login', async (req,res)=>{
  try{
    let {email,password}=req.body||{};
    email = normEmail(email);
    if(!email||!password) return bad(res,400,'email/password requis');
    const r=await q(`SELECT * FROM users WHERE email=$1`,[email]);
    if(r.rowCount===0) return bad(res,401,'Utilisateur inconnu');
    const u=r.rows[0];
    const match=await bcrypt.compare(password, u.password_hash);
    if(!match) return bad(res,401,'Mot de passe incorrect');
    const token=jwt.sign({ uid:u.id, email:u.email, role:u.role, player_id:u.player_id }, JWT_SECRET, { expiresIn:'48h' });
    ok(res,{ token, user:{id:u.id,email:u.email,role:u.role}, expHours:48 });
  }catch(err){ console.error(err); return bad(res,500,'auth échouée'); }
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
  if(!pid) return ok(res,{ ok:true });
  ok(res,{ ok:true, ts:Date.now() });
});

/* ---------- players ---------- */
app.get('/players', auth, async (_req,res)=>{
  const r=await q(`SELECT player_id,name,UPPER(COALESCE(role,'MEMBRE')) AS role,profile_pic_url FROM players ORDER BY name ASC`);
  ok(res,{ players:r.rows });
});
app.get('/players/:pid', auth, async (req,res)=>{
  const r=await q(`SELECT player_id,name,role,profile_pic_url FROM players WHERE player_id=$1`,[req.params.pid]);
  if(!r.rowCount) return bad(res,404,'introuvable');
  ok(res,{ player:r.rows[0] });
});
app.post('/players', auth, adminOnly, async (req,res)=>{
  const {player_id,name,role}=req.body||{};
  if(!player_id||!name) return bad(res,400,'player_id/name requis');
  await q(`INSERT INTO players(player_id,name,role) VALUES($1,$2,$3)
           ON CONFLICT(player_id) DO UPDATE SET name=EXCLUDED.name, role=EXCLUDED.role`,
          [player_id,name,(role||'MEMBRE').toUpperCase()]);
  ok(res,{ ok:true });
});
app.put('/players/:id', auth, adminOnly, async (req,res)=>{
  const { name, role } = req.body||{};
  if(!name && !role) return bad(res,400,'rien à modifier');
  const r=await q(`SELECT player_id,name,role FROM players WHERE player_id=$1`,[req.params.id]);
  if(!r.rowCount) return bad(res,404,'introuvable');
  await q(`UPDATE players SET name=COALESCE($2,name), role=COALESCE($3,role) WHERE player_id=$1`,[req.params.id, name, role]);
  ok(res,{ ok:true });
});
app.post('/players/:id/photo', auth, upload.single('photo'), async (req,res)=>{
  if(!req.file) return bad(res,400,'photo requise');
  const url = `/uploads/players/${req.file.filename}`;
  await q(`UPDATE players SET profile_pic_url=$2 WHERE player_id=$1`,[req.params.id,url]);
  ok(res,{ ok:true, profile_pic_url:url });
});

/* ---------- seasons ---------- */
app.get('/seasons', auth, async (_req,res)=>{
  const r=await q(`SELECT id,name,is_closed FROM seasons ORDER BY id DESC`);
  ok(res,{ seasons:r.rows });
});
app.post('/seasons', auth, adminOnly, async (req,res)=>{
  const {name}=req.body||{};
  if(!name) return bad(res,400,'nom requis');
  const r=await q(`INSERT INTO seasons(name,is_closed) VALUES($1,false) RETURNING id`,[name]);
  ok(res,{ ok:true, id:r.rows[0].id });
});
app.put('/seasons/:id/status', auth, adminOnly, async (req,res)=>{
  const sid=+req.params.id;
  const { is_closed } = req.body||{};
  await q(`UPDATE seasons SET is_closed=$2 WHERE id=$1`,[sid,!!is_closed]);
  ok(res,{ ok:true });
});
app.get('/season/current', auth, async (_req,res)=>{
  const id=await currentSeasonId();
  if(!id) return ok(res,null);
  const r=await q(`SELECT id,name FROM seasons WHERE id=$1`,[id]);
  ok(res, r.rows[0]||null);
});

/* ---------- matchdays ---------- */
app.get('/matchdays', auth, async (_req,res)=>{
  const r=await q(`SELECT day FROM matchday ORDER BY day DESC`);
  ok(res,{ days:r.rows.map(x=>x.day) });
});
app.get('/matchdays/:date', auth, async (req,res)=>{
  const d=req.params.date;
  const r=await q(`SELECT day,season_id,payload FROM matchday WHERE day=$1`,[d]);
  if(!r.rowCount) return bad(res,404,'introuvable');
  ok(res, r.rows[0]);
});
app.get('/matchdays/draft/:date', auth, async (req,res)=>{
  const r=await q(`SELECT day,payload FROM draft WHERE day=$1`,[req.params.date]);
  if(!r.rowCount) return ok(res,{ draft:null });
  ok(res,{ draft:r.rows[0] });
});
app.put('/matchdays/draft/:date', auth, async (req,res)=>{
  const { payload } = req.body||{};
  await q(`INSERT INTO draft(day,payload) VALUES($1,$2)
           ON CONFLICT(day) DO UPDATE SET payload=EXCLUDED.payload`,
          [req.params.date, payload||{}]);
  io.to(`draft:${req.params.date}`).emit('draft:update', { date:req.params.date });
  ok(res,{ ok:true });
});
app.delete('/matchdays/draft/:date', auth, async (req,res)=>{
  await q(`DELETE FROM draft WHERE day=$1`,[req.params.date]);
  io.to(`draft:${req.params.date}`).emit('draft:deleted', { date:req.params.date });
  ok(res,{ ok:true });
});
app.put('/matchdays/:day/season', auth, adminOnly, async (req,res)=>{
  const { season_id } = req.body||{};
  const day = req.params.day;
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
  // supprimer un éventuel brouillon et notifier tout le monde
  await q('DELETE FROM draft WHERE day=$1',[date]);
  io.to(`draft:${date}`).emit('day:confirmed', { date });
  io.emit('season:changed');
  ok(res,{ ok:true });
});
app.delete('/matchdays/:date', auth, adminOnly, async (req,res)=>{
  await q(`DELETE FROM matchday WHERE day=$1`,[req.params.date]);
  io.emit('day:deleted', { date: req.params.date });
  ok(res,{ ok:true });
});
app.get('/seasons/:id/matchdays', auth, async (req,res)=>{
  const sid=+req.params.id;
  const r=await q(`SELECT day FROM matchday WHERE season_id=$1 ORDER BY day ASC`,[sid]);
  ok(res,{ days:r.rows.map(x=>x.day) });
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
  const chk=await q(`SELECT 1 FROM seasons WHERE id=$1`,[sid]);
  if(!chk.rowCount) return bad(res,404,'saison inconnue');
  const list = await computeSeasonStandings(sid);
  ok(res,{ season_id:sid, standings:list });
});

/* ---------- admin: users ---------- */
app.get('/admin/users', auth, adminOnly, async (_req,res)=>{
  const r=await q(`SELECT id,email,role,created_at FROM users ORDER BY created_at DESC NULLS LAST, id DESC`);
  ok(res,{ users:r.rows });
});
app.post('/admin/users', auth, adminOnly, async (req,res)=>{
  let { email, password, role } = req.body||{};
  email = normEmail(email);
  if(!email||!password) return bad(res,400,'email/password requis');
  role = (role||'member').toLowerCase();
  const hash = await bcrypt.hash(password, 10);
  try{
    const r=await q(`INSERT INTO users(email,password_hash,role) VALUES($1,$2,$3) RETURNING id`,[email,hash,role]);
    ok(res,{ ok:true, id:r.rows[0].id });
  }catch(err){
    if(String(err.message||'').includes('duplicate')) return bad(res,409,'email déjà utilisé');
    console.error(err); return bad(res,500,'création échouée');
  }
});
app.put('/admin/users/:id', auth, adminOnly, async (req,res)=>{
  const id=+req.params.id;
  let { password, role } = req.body||{};
  if(!password && !role) return bad(res,400,'rien à modifier');
  const fields=[]; const vals=[];
  if(password){ fields.push(`password_hash=$${fields.length+1}`); vals.push(await bcrypt.hash(password,10)); }
  if(role){ fields.push(`role=$${fields.length+1}`); vals.push(role); }
  if(!fields.length) return ok(res,{ ok:true });
  vals.push(id);
  await q(`UPDATE users SET ${fields.join(', ')} WHERE id=$${vals.length}`, vals);
  ok(res,{ ok:true });
});
app.delete('/admin/users/:id', auth, adminOnly, async (req,res)=>{
  const id=+req.params.id;
  await q(`DELETE FROM users WHERE id=$1`,[id]);
  ok(res,{ ok:true });
});

/* ---------- static ---------- */
app.use(express.static(path.join(__dirname,'public')));

/* ---------- start ---------- */
(async ()=>{
  await ensureSchema();
  server.listen(PORT, ()=> console.log(`API OK on :${PORT}`));
})();
