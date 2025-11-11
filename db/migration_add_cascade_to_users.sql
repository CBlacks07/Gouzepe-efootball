-- Migration: Ajouter ON UPDATE CASCADE à la contrainte de clé étrangère users.player_id
-- Cette migration permet de modifier l'ID d'un joueur sans perdre l'association avec son compte utilisateur

-- Étape 1: Supprimer la contrainte existante
ALTER TABLE users
DROP CONSTRAINT IF EXISTS users_player_id_fkey;

-- Étape 2: Recréer la contrainte avec ON UPDATE CASCADE
ALTER TABLE users
ADD CONSTRAINT users_player_id_fkey
FOREIGN KEY (player_id)
REFERENCES players(player_id)
ON UPDATE CASCADE
ON DELETE SET NULL;

-- Note: champion_result a déjà ON UPDATE CASCADE, donc pas besoin de modification
