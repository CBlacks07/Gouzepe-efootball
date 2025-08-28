// Crée (ou met à jour) un admin dans la table users.
// Usage 1 (via env) : ADMIN_EMAIL="admin@gz.local" ADMIN_PASSWORD="admin" node create_admin.js
// Usage 2 (via args) : node create_admin.js admin@gz.local monpassword

require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const emailArg = (process.argv[2] || '').trim();
const passArg  = (process.argv[3] || '').trim();

const EMAIL = emailArg || (process.env.ADMIN_EMAIL || '').trim();
const PASS  = passArg  || (process.env.ADMIN_PASSWORD || '').trim();

if (!EMAIL || !PASS) {
  console.error('❌ EMAIL et MOT DE PASSE requis.\n' +
    'Exemples:\n' +
    '  ADMIN_EMAIL="admin@gz.local" ADMIN_PASSWORD="admin" node create_admin.js\n' +
    '  node create_admin.js admin@gz.local monpassword');
  process.exit(1);
}

const useSSL = (process.env.PGSSL === 'true') || process.env.RENDER === 'true' || process.env.NODE_ENV === 'production';
const pool = new Pool({
  host: process.env.PGHOST || '127.0.0.1',
  port: +(process.env.PGPORT || 5432),
  database: process.env.PGDATABASE || 'gz_efoot',
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || 'postgres',
  ssl: useSSL ? { rejectUnauthorized: false } : false,
});

async function run() {
  const client = await pool.connect();
  try {
    // table users (au cas où)
    await client.query(`CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      created_at TIMESTAMP DEFAULT now()
    )`);

    const hash = await bcrypt.hash(PASS, 10);
    const up = await client.query(
      `INSERT INTO users(email,password_hash,role)
       VALUES ($1,$2,'admin')
       ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash, role='admin'
       RETURNING id,email,role,created_at`,
      [EMAIL.toLowerCase(), hash]
    );
    console.log('✅ Admin OK :', up.rows[0]);
  } catch (e) {
    console.error('❌ Erreur seed admin:', e.message);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

run();
