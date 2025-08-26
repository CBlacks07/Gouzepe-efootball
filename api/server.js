/* GOUZEPE API — serveur complet (JWT, joueurs, utilisateurs, journées, saison)
 * Sync temps réel via Socket.IO.
 * PostgreSQL obligatoire.
 *
 * ENV:
 *  PORT, CORS_ORIGIN="*"
 *  JWT_SECRET="change-me"
 *  PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD
 *  ADMIN_EMAIL="admin@gz.local", ADMIN_PASSWORD="admin"
 */
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const dayjs = require('dayjs');
require('dotenv').config();

/* ---------- config ---------- */
const PORT = process.env.PORT || 3000;
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const JWT_SECRET = process.env.JWT_SECRET || '1XS1r4QJNp6AtkjORvKUU01RZRfzbGV+echJsio9gq8lAOc2NW7sSYsQuncE6+o9';

// ✅ Version corrigée
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // <-- Lit l'URL fournie par Render
  ssl: {
    rejectUnauthorized: false // <-- Très important pour les connexions sur Render
  }
});

const app = express();
const server = http.createServer(app);
const io = require('socket.io')(server, {
  cors: { origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN, methods: ['GET','POST','PUT','DELETE'] }
});

app.use(express.json({ limit: '1mb' }));
app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN }));

/* ---------- helpers SQL / HTTP ---------- */
const q   = (text, params=[]) => pool.query(text, params);
const ok  = (res, payload={}) => res.json(payload);
const bad = (res, code=400, msg='Bad request') => res.status(code).json({ error: msg });

/* ---------- auth middlewares ---------- */
function signToken(user){
  const expHours = 24;
  const token = jwt.sign({ uid:user.id, role:user.role, email:user.email }, JWT_SECRET, { expiresIn: `${expHours}h` });
  return { token, expHours };
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
  if(req.user?.role!=='admin') return bad(res,403,'Admin only');
  next();
}

/* ---------- schéma ---------- */
async function ensureSchema(){
  await q(`CREATE TABLE IF NOT EXISTS users(
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMP DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS players(
    player_id TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    role      TEXT NOT NULL DEFAULT 'MEMBRE', -- MEMBRE / INVITE
    created_at TIMESTAMP DEFAULT now()
  )`);
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

  // seed admin si manquant
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@gz.local';
  const adminPass  = process.env.ADMIN_PASSWORD || 'admin';
  const row = await q(`SELECT id FROM users WHERE email=$1`,[adminEmail]);
  if(row.rowCount===0){
    const hash = await bcrypt.hash(adminPass,10);
    await q(`INSERT INTO users(email,password_hash,role) VALUES ($1,$2,'admin')`,[adminEmail,hash]);
    console.log(`Seed admin: ${adminEmail} / ${adminPass}`);
  }

  // saison ouverte par défaut
  const s = await q(`SELECT id FROM seasons WHERE is_closed=false ORDER BY id DESC LIMIT 1`);
  if(s.rowCount===0){
    await q(`INSERT INTO seasons(name,is_closed) VALUES ('Saison courante', false)`);
  }
}
async function currentSeasonId(){
  const r=await q(`SELECT id FROM seasons WHERE is_closed=false ORDER BY id DESC LIMIT 1`);
  return r.rows[0]?.id;
}

/* ---------- logique de calcul ---------- */
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
    if(m.r1!=null&&m.r2!=null) add(m.p2,m.p1,m.r2,m.r1);
  }
  const arr = Object.entries(agg).map(([id,x])=>({id,...x,PTS:x.V*3+x.N,DIFF:x.BP-x.BC}));
  arr.sort((a,b)=>b.PTS-a.PTS||b.DIFF-a.DIFF||b.BP-a.BP||a.id.localeCompare(b.id));
  return arr;
}

/* --- Barème saison (convenu) --- */
// D1 : dernier = 9 pts (quelque soit le nombre), puis +1 par rang en remontant.
// Le champion reçoit en plus un BONUS séparé (+1).
const BONUS_D1_CHAMPION = 1;
function pointsD1(nPlayers, rank){
  if(rank<1 || rank>nPlayers) return 0;
  return 9 + (nPlayers - rank); // bonus du champion ajouté à part
}
// D2 : barème fixe (adapté à ta ligue). Tu peux ajuster si besoin.
function pointsD2(rank){
  const table = [10,8,7,6,5,4,3,2,1,1,1];
  if(rank<=0) return 0;
  return rank<=table.length ? table[rank-1] : 1;
}

async function getPlayersRoles(){
  const r=await q(`SELECT player_id, role FROM players`);
  const map=new Map();
  r.rows.forEach(p=>map.set(p.player_id, (p.role||'MEMBRE').toUpperCase()));
  return map;
}

/* ---------- auth ---------- */
app.post('/auth/login', async (req,res)=>{
  const {email,password}=req.body||{};
  if(!email||!password) return bad(res,400,'email/password requis');
  const r=await q(`SELECT * FROM users WHERE email=$1`,[email.trim().toLowerCase()]);
  if(r.rowCount===0) return bad(res,401,'Utilisateur inconnu');
  const u=r.rows[0];
  const match = await bcrypt.compare(password, u.password_hash);
  if(!match) return bad(res,401,'Mot de passe incorrect');
  const {token,expHours} = signToken(u);
  ok(res,{ token, user:{id:u.id,email:u.email,role:u.role}, expHours });
});
app.get('/auth/me', auth, async (req,res)=>{
  const r=await q(`SELECT id,email,role FROM users WHERE id=$1`,[req.user.uid]);
  if(r.rowCount===0) return bad(res,404,'User not found');
  ok(res,{ user:r.rows[0] });
});

/* ---------- admin users ---------- */
app.get('/admin/users', auth, adminOnly, async (req,res)=>{
  const r=await q(`SELECT id,email,role,created_at FROM users ORDER BY id ASC`);
  ok(res,{ users:r.rows });
});
app.post('/admin/users', auth, adminOnly, async (req,res)=>{
  let {email,password,role}=req.body||{};
  if(!email||!password) return bad(res,400,'email/password requis');
  role=(role||'member').toLowerCase()==='admin'?'admin':'member';
  try{
    const hash=await bcrypt.hash(password,10);
    const r=await q(`INSERT INTO users(email,password_hash,role) VALUES ($1,$2,$3) RETURNING id,email,role,created_at`,
      [email.trim().toLowerCase(),hash,role]);
    ok(res,{ user:r.rows[0] });
  }catch(e){
    if(e.code==='23505') return bad(res,409,'email déjà utilisé');
    throw e;
  }
});
app.put('/admin/users/:id', auth, adminOnly, async (req,res)=>{
  const id=+req.params.id;
  let {role,password}=req.body||{};
  const u=(await q(`SELECT id,email,role FROM users WHERE id=$1`,[id])).rows[0];
  if(!u) return bad(res,404,'introuvable');
  const newRole=(role||u.role)==='admin'?'admin':'member';
  if(password){
    const hash=await bcrypt.hash(password,10);
    await q(`UPDATE users SET role=$1, password_hash=$2 WHERE id=$3`,[newRole,hash,id]);
  }else{
    await q(`UPDATE users SET role=$1 WHERE id=$2`,[newRole,id]);
  }
  const r=await q(`SELECT id,email,role,created_at FROM users WHERE id=$1`,[id]);
  ok(res,{ user:r.rows[0] });
});
app.delete('/admin/users/:id', auth, adminOnly, async (req,res)=>{
  await q(`DELETE FROM users WHERE id=$1`,[+req.params.id]);
  ok(res,{ ok:true });
});

/* ---------- players ---------- */
app.get('/players', auth, async (req,res)=>{
  const r=await q(`SELECT player_id,name,role,created_at FROM players ORDER BY name ASC`);
  ok(res,{ players:r.rows });
});
app.post('/admin/players', auth, adminOnly, async (req,res)=>{
  const { player_id, name, role } = req.body||{};
  if(!player_id||!name) return bad(res,400,'player_id et name requis');
  await q(`INSERT INTO players(player_id,name,role) VALUES ($1,$2,$3)
           ON CONFLICT (player_id) DO UPDATE SET name=EXCLUDED.name, role=EXCLUDED.role`,
           [player_id, name, role||'MEMBRE']);
  const r=await q(`SELECT player_id,name,role,created_at FROM players WHERE player_id=$1`,[player_id]);
  ok(res,{ player:r.rows[0] });
});
// NEW: modifier aussi l'ID (évite le 404 côté front)
app.put('/admin/players/:id', auth, adminOnly, async (req,res)=>{
  const oldId = req.params.id;
  let { player_id, name, role } = req.body||{};
  const newId = (player_id||'').trim() || oldId;
  if(!name) return bad(res,400,'name requis');

  // 1) si l'ID change, on remplace la clé primaire
  if(newId !== oldId){
    // créer/maj la nouvelle ligne puis supprimer l'ancienne
    await q(`INSERT INTO players(player_id,name,role) VALUES ($1,$2,$3)
             ON CONFLICT (player_id) DO UPDATE SET name=EXCLUDED.name, role=EXCLUDED.role`,
             [newId, name, role||'MEMBRE']);
    await q(`DELETE FROM players WHERE player_id=$1`,[oldId]);
  }else{
    await q(`UPDATE players SET name=$1, role=$2 WHERE player_id=$3`,[name, role||'MEMBRE', oldId]);
  }
  const r=await q(`SELECT player_id,name,role,created_at FROM players WHERE player_id=$1`,[newId]);
  ok(res,{ player:r.rows[0] });
});
app.delete('/admin/players/:id', auth, adminOnly, async (req,res)=>{
  await q(`DELETE FROM players WHERE player_id=$1`,[req.params.id]);
  ok(res,{ ok:true });
});

/* ---------- drafts (brouillons) ---------- */
app.get('/matchdays/draft/:date', auth, async (req,res)=>{
  const d=req.params.date;
  const r=await q(`SELECT payload FROM draft WHERE day=$1`,[d]);
  if(r.rowCount===0) return bad(res,404,'No draft');
  ok(res,{ payload:r.rows[0].payload });
});
app.put('/matchdays/draft/:date', auth, async (req,res)=>{
  const d=req.params.date;
  const payload = req.body||{};
  await q(`INSERT INTO draft(day,payload,updated_at) VALUES ($1,$2,now())
           ON CONFLICT (day) DO UPDATE SET payload=EXCLUDED.payload, updated_at=now()`,
           [d,payload]);
  io.to(`draft:${d}`).emit('draft:update',{date:d});
  ok(res,{ ok:true });
});
app.delete('/matchdays/draft/:date', auth, async (req,res)=>{
  await q(`DELETE FROM draft WHERE day=$1`,[req.params.date]);
  ok(res,{ ok:true });
});

/* ---------- matchdays ---------- */
app.post('/matchdays/confirm', auth, adminOnly, async (req,res)=>{
  const { date, d1=[], d2=[], barrage={}, champions={} } = req.body||{};
  if(!date) return bad(res,400,'date requise');
  const seasonId = await currentSeasonId();
  const payload = { d1, d2, barrage, champions };
  await q(`INSERT INTO matchday(day,season_id,payload,created_at)
           VALUES ($1,$2,$3,now())
           ON CONFLICT (day) DO UPDATE SET season_id=EXCLUDED.season_id, payload=EXCLUDED.payload`,
           [date, seasonId, payload]);
  await q(`DELETE FROM draft WHERE day=$1`,[date]);
  io.emit('day:confirmed',{ date });
  io.emit('season:updated');
  ok(res,{ ok:true });
});
app.get('/matchdays', auth, async (req,res)=>{
  const seasonId = await currentSeasonId();
  const r=await q(`SELECT day FROM matchday WHERE season_id=$1 ORDER BY day ASC`,[seasonId]);
  ok(res,{ days:r.rows.map(x=>dayjs(x.day).format('YYYY-MM-DD')) });
});
app.get('/matchdays/:date', auth, async (req,res)=>{
  const d=req.params.date;
  const r=await q(`SELECT payload FROM matchday WHERE day=$1`,[d]);
  if(r.rowCount===0) return bad(res,404,'introuvable');
  ok(res, r.rows[0].payload);
});
app.delete('/matchdays/:date', auth, adminOnly, async (req,res)=>{
  const d=req.params.date;
  await q(`DELETE FROM matchday WHERE day=$1`,[d]);
  await q(`DELETE FROM draft WHERE day=$1`,[d]);
  io.emit('day:deleted',{ date:d });
  io.emit('season:updated');
  ok(res,{ ok:true });
});

/* ---------- saisons (standings + close + sélection) ---------- */
app.get('/seasons', auth, async (req,res)=>{
  const r=await q(`SELECT id,name,is_closed,started_at,ended_at FROM seasons ORDER BY id DESC`);
  ok(res,{ seasons:r.rows });
});

async function computeSeasonStandings(seasonId){
  const days = await q(`SELECT day,payload FROM matchday WHERE season_id=$1 ORDER BY day ASC`,[seasonId]);
  const roles = await getPlayersRoles();

  const totals = new Map(); // id -> {id,total,participations,won_d1,won_d2,teams:Set}
  const ensure = id=>{
    if(!totals.has(id)) totals.set(id,{id,total:0,participations:0,won_d1:0,won_d2:0,teams:new Set()});
    return totals.get(id);
  };

  for(const row of days.rows){
    const p=row.payload||{};
    const st1Full=computeStandings(p.d1||[]);
    const st2Full=computeStandings(p.d2||[]);

    // Exclure INVITÉS pour le calcul de saison
    const st1 = st1Full.filter(r => (roles.get(r.id)||'MEMBRE')!=='INVITE');
    const st2 = st2Full.filter(r => (roles.get(r.id)||'MEMBRE')!=='INVITE');

    const n1=st1.length, n2=st2.length;

    st1.forEach((r,idx)=>{ const o=ensure(r.id); o.total += pointsD1(n1, idx+1); o.participations+=1; });
    st2.forEach((r,idx)=>{ const o=ensure(r.id); o.total += pointsD2(idx+1);   o.participations+=1; });

    // Bonus champion D1 (+1)
    const champD1=p?.champions?.d1?.id||null;
    const teamD1 =(p?.champions?.d1?.team||'').toUpperCase();
    if(champD1 && (roles.get(champD1)||'MEMBRE')!=='INVITE'){
      const o=ensure(champD1); o.won_d1++; if(teamD1) o.teams.add(teamD1);
      o.total += BONUS_D1_CHAMPION;
    }
    // On ne donne PAS de bonus au champion D2 (selon ta consigne finale)
    const champD2=p?.champions?.d2?.id||null;
    const teamD2 =(p?.champions?.d2?.team||'').toUpperCase();
    if(champD2 && (roles.get(champD2)||'MEMBRE')!=='INVITE'){
      const o=ensure(champD2); o.won_d2++; if(teamD2) o.teams.add(teamD2);
    }
  }

  // enrichir noms
  const allIds=[...totals.keys()];
  if(allIds.length){
    const r=await q(`SELECT player_id,name FROM players WHERE player_id=ANY($1::text[])`,[allIds]);
    const nameById=new Map(r.rows.map(x=>[x.player_id,x.name]));
    for(const o of totals.values()){
      o.name = nameById.get(o.id)||o.id;
      o.teams_used = o.teams.size;
      delete o.teams;
      o.moyenne = o.participations>0 ? +(o.total/o.participations).toFixed(2) : 0;
    }
  }
  const arr=[...totals.values()];
  arr.sort((a,b)=> b.total-a.total || b.moyenne-a.moyenne || a.name.localeCompare(b.name));
  return arr;
}

app.get('/season/standings', auth, async (req,res)=>{
  const seasonId = await currentSeasonId();
  const standings = await computeSeasonStandings(seasonId);
  ok(res,{ standings });
});
app.get('/seasons/:id/standings', auth, async (req,res)=>{
  const seasonId = +req.params.id;
  const exists = await q(`SELECT 1 FROM seasons WHERE id=$1`,[seasonId]);
  if(!exists.rowCount) return bad(res,404,'saison inconnue');
  const standings = await computeSeasonStandings(seasonId);
  ok(res,{ standings });
});
app.get('/seasons/:id/matchdays', auth, async (req,res)=>{
  const seasonId = +req.params.id;
  const r=await q(`SELECT day FROM matchday WHERE season_id=$1 ORDER BY day ASC`,[seasonId]);
  ok(res,{ days:r.rows.map(x=>dayjs(x.day).format('YYYY-MM-DD')) });
});

app.post('/season/close', auth, adminOnly, async (req,res)=>{
  const cur = await currentSeasonId();
  if(cur){
    await q(`UPDATE seasons SET is_closed=true, ended_at=now() WHERE id=$1`,[cur]);
  }
  await q(`INSERT INTO seasons(name,is_closed) VALUES ($1,false)`, ['Saison courante']);
  io.emit('season:updated');
  ok(res,{ ok:true });
});

/* ---------- Socket.IO ---------- */
io.on('connection', (socket)=>{
  socket.on('join', ({room}) => room && socket.join(room));
});

/* ---------- start ---------- */
(async ()=>{
  try{
    await ensureSchema();
    server.listen(PORT, ()=>console.log(`API OK on :${PORT}`));
  }catch(e){
    console.error('Schema init error', e);
    process.exit(1);
  }
})();

// [AJOUT] Créer une saison (ouverte)
app.post('/seasons', auth, adminOnly, async (req,res)=>{
  const name = (req.body?.name||'').trim();
  if(!name) return bad(res,400,'name requis');
  const r = await q(`INSERT INTO seasons(name,is_closed,started_at) VALUES ($1,false,now()) RETURNING id,name,is_closed,started_at,ended_at`,[name]);
  io.emit('season:updated');
  ok(res,{ season:r.rows[0] });
});

// [AJOUT] Rattacher une journée à une saison
app.put('/matchdays/:date/season', auth, adminOnly, async (req,res)=>{
  const d = req.params.date;
  const season_id = +req.body?.season_id;
  if(!season_id) return bad(res,400,'season_id requis');
  const sx = await q(`SELECT id FROM seasons WHERE id=$1`,[season_id]);
  if(!sx.rowCount) return bad(res,404,'saison inconnue');
  const mx = await q(`UPDATE matchday SET season_id=$1 WHERE day=$2 RETURNING day`,[season_id,d]);
  if(!mx.rowCount) return bad(res,404,'journée inconnue');
  io.emit('season:updated');
  ok(res,{ ok:true });
});

// [MODIF légère] Confirmer une journée avec season_id optionnel
app.post('/matchdays/confirm', auth, adminOnly, async (req,res)=>{
  const { date, d1=[], d2=[], barrage={}, champions={}, season_id } = req.body||{};
  if(!date) return bad(res,400,'date requise');
  const seasonId = season_id ? +season_id : await currentSeasonId();
  const payload = { d1, d2, barrage, champions };
  await q(`INSERT INTO matchday(day,season_id,payload,created_at)
           VALUES ($1,$2,$3,now())
           ON CONFLICT (day) DO UPDATE SET season_id=EXCLUDED.season_id, payload=EXCLUDED.payload`,
           [date, seasonId, payload]);
  await q(`DELETE FROM draft WHERE day=$1`,[date]);
  io.emit('day:confirmed',{ date });
  io.emit('season:updated');
  ok(res,{ ok:true });
});
