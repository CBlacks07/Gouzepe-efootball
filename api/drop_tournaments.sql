-- Script de suppression des tables de tournois
-- Exécuter ce script pour nettoyer la base de données

-- Supprimer les tables de tournois dans l'ordre (dépendances)
DROP TABLE IF EXISTS tournament_games CASCADE;
DROP TABLE IF EXISTS tournament_matches CASCADE;
DROP TABLE IF EXISTS tournament_phase_standings CASCADE;
DROP TABLE IF EXISTS tournament_participants CASCADE;
DROP TABLE IF EXISTS tournament_pools CASCADE;
DROP TABLE IF EXISTS tournament_phases CASCADE;
DROP TABLE IF EXISTS tournament_events CASCADE;
DROP TABLE IF EXISTS tournaments CASCADE;

-- Message de confirmation
SELECT 'Toutes les tables de tournois ont été supprimées avec succès' AS status;
