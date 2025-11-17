/**
 * Script de migration pour corriger la numérotation des rounds dans les tournois existants
 * Ce script inverse les round_number pour que Round 1 = premier tour au lieu de la finale
 */

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function fixTournamentRounds() {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    console.log('🔧 Correction de la numérotation des rounds...\n');

    // Récupérer tous les tournois avec des matchs
    const tournamentsResult = await client.query(`
      SELECT DISTINCT t.id, t.name, t.type, t.status
      FROM tournaments t
      JOIN tournament_matches tm ON tm.tournament_id = t.id
      WHERE t.status IN ('draft', 'in_progress', 'completed')
      ORDER BY t.id
    `);

    console.log(`📋 ${tournamentsResult.rows.length} tournoi(s) trouvé(s)\n`);

    for (const tournament of tournamentsResult.rows) {
      console.log(`\n🎯 Tournoi: "${tournament.name}" (ID: ${tournament.id})`);
      console.log(`   Type: ${tournament.type}, Statut: ${tournament.status}`);

      // Récupérer les rounds du tournoi
      const roundsResult = await client.query(`
        SELECT DISTINCT round_number, bracket_type
        FROM tournament_matches
        WHERE tournament_id = $1
        ORDER BY round_number
      `, [tournament.id]);

      for (const bracketInfo of roundsResult.rows) {
        const bracketType = bracketInfo.bracket_type || 'winner';

        // Compter le nombre total de rounds pour ce bracket
        const totalRoundsResult = await client.query(`
          SELECT MAX(round_number) as max_round
          FROM tournament_matches
          WHERE tournament_id = $1 AND (bracket_type = $2 OR bracket_type IS NULL)
        `, [tournament.id, bracketType]);

        const totalRounds = parseInt(totalRoundsResult.rows[0].max_round);

        if (totalRounds > 0) {
          console.log(`\n   Bracket: ${bracketType}`);
          console.log(`   Nombre total de rounds: ${totalRounds}`);

          // Vérifier si les rounds sont inversés (Round 1 devrait avoir le plus de matchs)
          const round1Count = await client.query(`
            SELECT COUNT(*) as count
            FROM tournament_matches
            WHERE tournament_id = $1 AND round_number = 1 AND (bracket_type = $2 OR bracket_type IS NULL)
          `, [tournament.id, bracketType]);

          const roundMaxCount = await client.query(`
            SELECT COUNT(*) as count
            FROM tournament_matches
            WHERE tournament_id = $1 AND round_number = $2 AND (bracket_type = $3 OR bracket_type IS NULL)
          `, [tournament.id, totalRounds, bracketType]);

          const round1MatchCount = parseInt(round1Count.rows[0].count);
          const roundMaxMatchCount = parseInt(roundMaxCount.rows[0].count);

          console.log(`   Round 1: ${round1MatchCount} matchs`);
          console.log(`   Round ${totalRounds}: ${roundMaxMatchCount} matchs`);

          // Si Round 1 a moins de matchs que le dernier round, c'est inversé
          if (round1MatchCount < roundMaxMatchCount) {
            console.log(`   ⚠️  INVERSION DÉTECTÉE - Correction en cours...`);

            // Créer une table temporaire pour stocker les nouveaux numéros
            await client.query(`
              UPDATE tournament_matches
              SET round_number = $1 - round_number + 1
              WHERE tournament_id = $2 AND (bracket_type = $3 OR bracket_type IS NULL)
            `, [totalRounds, tournament.id, bracketType]);

            console.log(`   ✅ Rounds corrigés!`);

            // Vérification post-correction
            const verifyResult = await client.query(`
              SELECT round_number, COUNT(*) as count
              FROM tournament_matches
              WHERE tournament_id = $1 AND (bracket_type = $2 OR bracket_type IS NULL)
              GROUP BY round_number
              ORDER BY round_number
            `, [tournament.id, bracketType]);

            console.log(`   📊 Nouvelle distribution:`);
            verifyResult.rows.forEach(row => {
              console.log(`      Round ${row.round_number}: ${row.count} matchs`);
            });
          } else {
            console.log(`   ✓ Numérotation déjà correcte`);
          }
        }
      }
    }

    await client.query('COMMIT');
    console.log('\n\n✅ Migration terminée avec succès!');
    console.log('🔄 Veuillez actualiser votre page web pour voir les changements.\n');

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('\n❌ Erreur lors de la migration:', error);
    throw error;
  } finally {
    client.release();
    await pool.end();
  }
}

// Exécuter le script
fixTournamentRounds().catch(err => {
  console.error('Erreur fatale:', err);
  process.exit(1);
});
