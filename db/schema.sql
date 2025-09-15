-- Schéma eFootball — tables alignées avec api/server.js
-- Convention: les tables métier historiquement au pluriel (users, players...) conservent
-- leur nom, tandis que les tables de journée utilisent le singulier (`matchday`, `draft`)
-- comme dans le code Node.js. Ce fichier reflète donc l'état réellement consommé
-- par l'API Express.

-- Table pour les joueurs
CREATE TABLE IF NOT EXISTS players (
  player_id       TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  role            TEXT NOT NULL DEFAULT 'MEMBRE',
  profile_pic_url TEXT,
  created_at      TIMESTAMP DEFAULT now()
);

-- Table pour les comptes utilisateurs (membres + administrateurs)
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'member',
  player_id     TEXT REFERENCES players(player_id) ON DELETE SET NULL,
  created_at    TIMESTAMP DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_player_id_uniq
  ON users(player_id)
  WHERE player_id IS NOT NULL;

-- Table des saisons sportives
CREATE TABLE IF NOT EXISTS seasons (
  id         SERIAL PRIMARY KEY,
  name       TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at   TIMESTAMPTZ,
  is_closed  BOOLEAN NOT NULL DEFAULT FALSE
);

-- Journées officielles confirmées
CREATE TABLE IF NOT EXISTS matchday (
  day        DATE PRIMARY KEY,
  season_id  INTEGER REFERENCES seasons(id),
  payload    JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Brouillons de journées (édition collaborative)
CREATE TABLE IF NOT EXISTS draft (
  day            DATE PRIMARY KEY,
  payload        JSONB NOT NULL,
  updated_at     TIMESTAMPTZ DEFAULT now(),
  author_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS draft_author_idx ON draft(author_user_id);

-- Sessions d'authentification persistantes
CREATE TABLE IF NOT EXISTS sessions (
  id                   TEXT PRIMARY KEY,
  user_id              INTEGER REFERENCES users(id) ON DELETE CASCADE,
  device               TEXT,
  user_agent           TEXT,
  ip                   TEXT,
  created_at           TIMESTAMPTZ DEFAULT now(),
  last_seen            TIMESTAMPTZ DEFAULT now(),
  is_active            BOOLEAN NOT NULL DEFAULT TRUE,
  revoked_at           TIMESTAMPTZ,
  logout_at            TIMESTAMPTZ,
  cleaned_after_logout BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS sessions_user_active
  ON sessions(user_id)
  WHERE is_active;

-- Demandes de transfert d'une session vers un nouvel appareil
CREATE TABLE IF NOT EXISTS handoff_requests (
  id          TEXT PRIMARY KEY,
  user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
  nonce       TEXT NOT NULL,
  new_device  TEXT,
  created_at  TIMESTAMPTZ DEFAULT now(),
  status      TEXT NOT NULL DEFAULT 'pending', -- pending | approved | denied | expired
  approved_at TIMESTAMPTZ,
  denied_at   TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ
);

-- Table optionnelle pour l'ancien suivi cumulé de la saison
CREATE TABLE IF NOT EXISTS season_totals (
  id         SERIAL PRIMARY KEY,
  tag        TEXT UNIQUE NOT NULL DEFAULT 'current',
  standings  JSONB NOT NULL DEFAULT '[]'::jsonb,
  closed     BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMP DEFAULT now()
);

INSERT INTO season_totals(tag) VALUES('current')
ON CONFLICT(tag) DO NOTHING;

-- Historique des champions par division
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
