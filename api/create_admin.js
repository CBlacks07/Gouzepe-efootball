// Usage: node create_admin.js <email> <password> [role]
// ex: node create_admin.js admin@gz.local Admin123 admin
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const email = (process.argv[2]||'').toLowerCase().trim();
const password = process.argv[3]||'';
const role = (process.argv[4]||'admin').toLowerCase();

if(!email || !password){
  console.log('Usage: node create_admin.js <email> <password> [role]');
  process.exit(1);
}

const pool = new Pool({
  host: process.env.PGHOST,
  port: process.env.PGPORT,
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD
});

(async ()=>{
  try{
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users(email,password_hash,role)
       VALUES($1,$2,$3)
       ON CONFLICT(email) DO UPDATE SET password_hash=$2, role=$3
       RETURNING id,email,role,created_at`,
      [email, hash, role]
    );
    console.log('OK:', r.rows[0]);
  }catch(e){
    console.error('ERR:', e.message);
  }finally{
    await pool.end();
  }
})();
