-- Script pour supprimer toutes les anciennes tables de tournois
-- À exécuter AVANT de démarrer le nouveau système

-- Supprimer les tables dans l'ordre (contraintes de clés étrangères)
DROP TABLE IF EXISTS match_comments CASCADE;
DROP TABLE IF EXISTS match_attachments CASCADE;
DROP TABLE IF EXISTS match_games CASCADE;
DROP TABLE IF EXISTS tournament_groups CASCADE;
DROP TABLE IF EXISTS tournament_matches CASCADE;
DROP TABLE IF EXISTS tournament_participants CASCADE;
DROP TABLE IF EXISTS tournaments CASCADE;

-- Message de confirmation
SELECT 'Anciennes tables de tournois supprimées avec succès' as status;
