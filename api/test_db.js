// ...existing code...
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.PGHOST || '127.0.0.1',
  port: process.env.PGPORT ? parseInt(process.env.PGPORT, 10) : 5432,
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || '',
  database: process.env.PGDATABASE || 'postgres'
});

(async () => {
  try {
    const r = await pool.query('SELECT current_database() AS db, current_user AS usr');
    console.log('OK ->', r.rows[0]);

    const criticalTables = [
      'users',
      'players',
      'drafts',
      'matchdays',
      'season_totals',
      'champion_result'
    ];

    for (const tableName of criticalTables) {
      const tableCheck = await pool.query(
        `SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2 LIMIT 1`,
        ['public', tableName]
      );
      if (tableCheck.rowCount === 0) {
        console.error(`Table manquante: ${tableName}`);
        process.exitCode = 1;
      } else {
        console.log(`Table présente: ${tableName}`);
      }
    }
  } catch (e) {
    console.error('KO ->', e.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
})();
// ...existing code...