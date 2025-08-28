// Test rapide de connexion PostgreSQL + présence des tables clés
require('dotenv').config();
const { Pool } = require('pg');

const useSSL = (process.env.PGSSL === 'true') || process.env.RENDER === 'true' || process.env.NODE_ENV === 'production';
const pool = new Pool({
  host: process.env.PGHOST || '127.0.0.1',
  port: +(process.env.PGPORT || 5432),
  database: process.env.PGDATABASE || 'gz_efoot',
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || 'postgres',
  ssl: useSSL ? { rejectUnauthorized: false } : false,
});

(async ()=>{
  const cli = await pool.connect();
  try {
    const now = await cli.query('SELECT now() AS ts, version()');
    console.log('✅ Connecté à PostgreSQL');
    console.log('   Time:', now.rows[0].ts);
    console.log('   Version:', now.rows[0].version.split('\n')[0]);

    // Voir si les tables existent
    const tables = ['users','players','seasons','matchday','draft'];
    const res = await cli.query(`
      SELECT tablename FROM pg_catalog.pg_tables
      WHERE schemaname='public' AND tablename = ANY($1)
      ORDER BY tablename ASC
    `, [tables]);
    const found = res.rows.map(r=>r.tablename);
    tables.forEach(t => {
      console.log(found.includes(t) ? `   • ${t}: OK` : `   • ${t}: (absente)`);
    });

    console.log('ℹ️ Si des tables sont absentes, lance le serveur pour qu’il crée le schéma, ou exécute tes migrations.');
  } catch (e) {
    console.error('❌ Erreur DB:', e.message);
    process.exitCode = 1;
  } finally {
    cli.release();
    await pool.end();
  }
})();
