const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const parsedDbUrl = (()=>{
  try {
    return process.env.DATABASE_URL ? new URL(process.env.DATABASE_URL) : null;
  } catch(_) {
    return null;
  }
})();

const localHosts = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);
const inferLocal = parsedDbUrl ? localHosts.has(parsedDbUrl.hostname) : localHosts.has(String(process.env.PGHOST||'').toLowerCase());
const useSSL = !inferLocal && !!parsedDbUrl;

const pgOpts = process.env.DATABASE_URL
  ? { connectionString: process.env.DATABASE_URL, ssl: useSSL ? { rejectUnauthorized:false } : false }
  : {
      host: process.env.PGHOST || '127.0.0.1',
      port: +(process.env.PGPORT||5432),
      database: process.env.PGDATABASE || 'efootball',
      user: process.env.PGUSER || 'postgres',
      password: process.env.PGPASSWORD || 'postgres'
    };

const pool = new Pool(pgOpts);

async function runMigration() {
  try {
    console.log('🔄 Exécution de la migration...');
    const migrationPath = path.join(__dirname, '..', 'db', 'migration_add_cascade_to_users.sql');
    const migration = fs.readFileSync(migrationPath, 'utf8');
    await pool.query(migration);
    console.log('✅ Migration exécutée avec succès');
  } catch(e) {
    console.error('❌ Erreur migration:', e.message);
    throw e;
  } finally {
    await pool.end();
  }
}

runMigration();
