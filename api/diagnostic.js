// Script de diagnostic pour tester la connexion à PostgreSQL
require('dotenv').config();
const { Pool } = require('pg');

console.log('🔍 Diagnostic de connexion PostgreSQL...\n');

// Afficher la configuration
console.log('Configuration détectée :');
console.log('  PGHOST:', process.env.PGHOST || process.env.DB_HOST || '127.0.0.1');
console.log('  PGPORT:', process.env.PGPORT || process.env.DB_PORT || 5432);
console.log('  PGDATABASE:', process.env.PGDATABASE || process.env.DB_NAME || 'EFOOTBALL');
console.log('  PGUSER:', process.env.PGUSER || process.env.DB_USER || 'postgres');
console.log('  PGPASSWORD:', process.env.PGPASSWORD || process.env.DB_PASSWORD ? '***masqué***' : 'NON DÉFINI');
console.log('');

const pgOpts = {
  host: process.env.PGHOST || process.env.DB_HOST || '127.0.0.1',
  port: +(process.env.PGPORT || process.env.DB_PORT || 5432),
  database: process.env.PGDATABASE || process.env.DB_NAME || 'EFOOTBALL',
  user: process.env.PGUSER || process.env.DB_USER || 'postgres',
  password: process.env.PGPASSWORD || process.env.DB_PASSWORD || 'Admin123',
  ssl: false
};

const pool = new Pool(pgOpts);

async function testConnection() {
  try {
    console.log('⏳ Tentative de connexion...');
    const result = await pool.query('SELECT NOW() as now, version() as version');

    console.log('✅ Connexion réussie !');
    console.log('   Heure du serveur:', result.rows[0].now);
    console.log('   Version PostgreSQL:', result.rows[0].version.split(',')[0]);
    console.log('');

    // Tester si la base de données EFOOTBALL existe
    const dbCheck = await pool.query(`
      SELECT datname FROM pg_database WHERE datname = $1
    `, [pgOpts.database]);

    if (dbCheck.rows.length > 0) {
      console.log('✅ La base de données "' + pgOpts.database + '" existe');
    } else {
      console.log('❌ La base de données "' + pgOpts.database + '" n\'existe PAS');
      console.log('   Créez-la avec : CREATE DATABASE "EFOOTBALL";');
    }

    // Lister les tables existantes
    const tables = await pool.query(`
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = 'public'
      ORDER BY table_name
    `);

    console.log('');
    if (tables.rows.length > 0) {
      console.log('📊 Tables existantes (' + tables.rows.length + ') :');
      tables.rows.forEach(row => {
        console.log('   - ' + row.table_name);
      });
    } else {
      console.log('📊 Aucune table trouvée (normal pour une nouvelle installation)');
      console.log('   Les tables seront créées automatiquement au premier démarrage');
    }

    await pool.end();
    console.log('\n✅ Diagnostic terminé avec succès');
    process.exit(0);

  } catch (error) {
    console.error('\n❌ ERREUR DE CONNEXION :');
    console.error('   Message:', error.message);
    console.error('   Code:', error.code || 'N/A');
    console.error('');

    if (error.code === 'ECONNREFUSED') {
      console.error('💡 SOLUTION :');
      console.error('   PostgreSQL n\'est pas démarré ou n\'écoute pas sur ce port');
      console.error('   1. Vérifiez que PostgreSQL est démarré');
      console.error('   2. Vérifiez le port (par défaut 5432)');
    } else if (error.code === '28P01') {
      console.error('💡 SOLUTION :');
      console.error('   Mot de passe incorrect');
      console.error('   1. Vérifiez PGPASSWORD dans le fichier .env');
      console.error('   2. Ou changez le mot de passe : Admin123 par défaut');
    } else if (error.code === '3D000') {
      console.error('💡 SOLUTION :');
      console.error('   La base de données n\'existe pas');
      console.error('   Exécutez : CREATE DATABASE "EFOOTBALL";');
    } else if (error.code === '28000') {
      console.error('💡 SOLUTION :');
      console.error('   Utilisateur invalide');
      console.error('   1. Vérifiez PGUSER dans le fichier .env');
      console.error('   2. Par défaut : postgres');
    }

    console.error('');
    await pool.end();
    process.exit(1);
  }
}

testConnection();
