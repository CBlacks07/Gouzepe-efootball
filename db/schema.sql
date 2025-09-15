-- Schéma eFootball -- Version corrigée et alignée avec server.js

-- Table pour les utilisateurs de l'application (admins, membres)
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'member', -- 'admin' ou 'member'
  created_at    TIMESTAMP DEFAULT now()
);

-- Table pour les joueurs (respecte la structure du code)
CREATE TABLE IF NOT EXISTS players (
  player_id  TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  role       TEXT NOT NULL DEFAULT 'MEMBRE',
  created_at TIMESTAMP DEFAULT now()
);

-- Table pour les brouillons de journées (stockage JSONB)
CREATE TABLE IF NOT EXISTS drafts (
  date        DATE PRIMARY KEY,
  payload     JSONB NOT NULL,
  updated_at  TIMESTAMP DEFAULT now()
);

-- Table pour les journées confirmées
CREATE TABLE IF NOT EXISTS matchdays (
  date        DATE PRIMARY KEY,
  payload     JSONB NOT NULL,
  confirmed   BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at  TIMESTAMP DEFAULT now()
);

-- Table pour les totaux de la saison (une seule ligne "current")
CREATE TABLE IF NOT EXISTS season_totals (
  id          SERIAL PRIMARY KEY,
  tag         TEXT UNIQUE NOT NULL DEFAULT 'current',
  standings   JSONB NOT NULL DEFAULT '[]'::jsonb,
  closed      BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at  TIMESTAMP DEFAULT now()
);

-- Insertion de la ligne unique pour gérer la saison courante si elle n'existe pas
INSERT INTO season_totals(tag) VALUES('current')
ON CONFLICT(tag) DO NOTHING;

CREATE TABLE IF NOT EXISTS champion_result (
  day           DATE NOT NULL,
  division      TEXT NOT NULL CHECK (division IN ('D1','D2')),
  champion_name TEXT NOT NULL,
  champion_id   TEXT,
  team_code     TEXT,

  PRIMARY KEY (day, division),
  FOREIGN KEY (champion_id) REFERENCES players(player_id) ON UPDATE CASCADE ON DELETE SET NULL,
  CHECK (team_code IS NULL OR char_length(team_code) >= 4)
);

CREATE INDEX IF NOT EXISTS idx_champion_name ON champion_result(champion_name);
