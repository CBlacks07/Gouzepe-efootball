/**
 * GOUZEPE TOURNAMENTS MODULE
 * Système de gestion de tournois moderne inspiré de Challonge et start.gg
 *
 * Architecture:
 * - Tournaments: Conteneur principal
 * - Events: Sous-compétitions (Singles, Doubles, Teams)
 * - Phases: Étapes d'un event (Pools, Bracket, Swiss)
 * - Participants: Joueurs/Équipes
 * - Pools: Groupes dans les phases de poules
 * - Matches: Rencontres avec support Best of X
 * - Games: Sous-matchs dans un Best of
 */

const express = require('express');
const crypto = require('crypto');

module.exports = function(pool, io, auth, adminOnly) {
  const router = express.Router();

  // Helper query
  const q = (text, params) => pool.query(text, params);

  // Response helpers
  const ok = (res, data) => res.json({ success: true, ...data });
  const bad = (res, code, message) => res.status(code).json({ success: false, error: message });

  /**
   * ========================================
   * SCHEMA DE BASE DE DONNÉES
   * ========================================
   */
  async function ensureTournamentSchema() {
    console.log('🏆 Initializing tournament schema...');

    // ===== TOURNAMENTS =====
    await q(`CREATE TABLE IF NOT EXISTS tournaments(
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      game_title TEXT NOT NULL,
      description TEXT,
      start_date TIMESTAMPTZ,
      end_date TIMESTAMPTZ,
      timezone TEXT DEFAULT 'UTC',

      -- Settings
      is_public BOOLEAN DEFAULT true,
      registration_enabled BOOLEAN DEFAULT true,
      registration_cap INTEGER,
      check_in_enabled BOOLEAN DEFAULT false,
      check_in_duration INTEGER DEFAULT 30,

      -- Status
      status TEXT NOT NULL DEFAULT 'draft',

      -- Metadata
      created_by_user_id INTEGER REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now(),

      -- Stats
      total_participants INTEGER DEFAULT 0,
      total_matches INTEGER DEFAULT 0,

      -- URLs
      banner_url TEXT,
      rules_url TEXT,

      CONSTRAINT tournaments_status_check CHECK (status IN ('draft', 'registration', 'check_in', 'in_progress', 'completed', 'cancelled'))
    )`);

    // ===== EVENTS (sous-compétitions dans un tournoi) =====
    await q(`CREATE TABLE IF NOT EXISTS tournament_events(
      id SERIAL PRIMARY KEY,
      tournament_id INTEGER NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      slug TEXT NOT NULL,
      type TEXT NOT NULL,
      description TEXT,

      -- Settings
      team_size INTEGER DEFAULT 1,
      min_participants INTEGER DEFAULT 2,
      max_participants INTEGER,

      -- Status
      status TEXT NOT NULL DEFAULT 'draft',

      -- Order
      display_order INTEGER DEFAULT 0,

      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now(),

      UNIQUE(tournament_id, slug),
      CONSTRAINT event_type_check CHECK (type IN ('singles', 'doubles', 'teams', 'crew', 'custom')),
      CONSTRAINT event_status_check CHECK (status IN ('draft', 'registration', 'seeding', 'in_progress', 'completed', 'cancelled'))
    )`);

    // ===== PHASES (étapes d'un event: pools, bracket, etc.) =====
    await q(`CREATE TABLE IF NOT EXISTS tournament_phases(
      id SERIAL PRIMARY KEY,
      event_id INTEGER NOT NULL REFERENCES tournament_events(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      phase_order INTEGER NOT NULL,
      phase_type TEXT NOT NULL,

      -- Configuration
      bracket_type TEXT,
      num_pools INTEGER,
      pool_size INTEGER,
      best_of INTEGER DEFAULT 1,

      -- Seeding
      seeding_locked BOOLEAN DEFAULT false,

      -- Status
      status TEXT NOT NULL DEFAULT 'pending',

      -- Progression
      advancement_count INTEGER,

      created_at TIMESTAMPTZ DEFAULT now(),
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,

      CONSTRAINT phase_type_check CHECK (phase_type IN ('pools', 'single_elimination', 'double_elimination', 'round_robin', 'swiss', 'custom')),
      CONSTRAINT bracket_type_check CHECK (bracket_type IS NULL OR bracket_type IN ('winner', 'loser', 'grand_final')),
      CONSTRAINT phase_status_check CHECK (status IN ('pending', 'seeding', 'in_progress', 'completed', 'cancelled'))
    )`);

    // ===== PARTICIPANTS =====
    await q(`CREATE TABLE IF NOT EXISTS tournament_participants(
      id SERIAL PRIMARY KEY,
      tournament_id INTEGER NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
      event_id INTEGER REFERENCES tournament_events(id) ON DELETE CASCADE,

      -- Info
      name TEXT NOT NULL,
      tag TEXT,
      player_id INTEGER REFERENCES players(id),
      user_id INTEGER REFERENCES users(id),

      -- Team (pour les events teams/doubles)
      team_name TEXT,
      team_members JSONB,

      -- Seeding
      seed INTEGER,
      seed_locked BOOLEAN DEFAULT false,

      -- Check-in
      checked_in BOOLEAN DEFAULT false,
      checked_in_at TIMESTAMPTZ,

      -- Status
      status TEXT DEFAULT 'registered',
      disqualified BOOLEAN DEFAULT false,
      disqualified_reason TEXT,

      -- Final results
      final_placement INTEGER,

      created_at TIMESTAMPTZ DEFAULT now(),

      UNIQUE(tournament_id, event_id, name),
      CONSTRAINT participant_status_check CHECK (status IN ('registered', 'checked_in', 'active', 'eliminated', 'disqualified'))
    )`);

    // ===== POOLS (groupes pour les phases de poules) =====
    await q(`CREATE TABLE IF NOT EXISTS tournament_pools(
      id SERIAL PRIMARY KEY,
      phase_id INTEGER NOT NULL REFERENCES tournament_phases(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      pool_number INTEGER NOT NULL,

      -- Config
      wave_number INTEGER DEFAULT 1,
      station_identifier TEXT,

      created_at TIMESTAMPTZ DEFAULT now(),

      UNIQUE(phase_id, pool_number)
    )`);

    // ===== POOL PARTICIPANTS (assignment aux pools) =====
    await q(`CREATE TABLE IF NOT EXISTS tournament_pool_participants(
      id SERIAL PRIMARY KEY,
      pool_id INTEGER NOT NULL REFERENCES tournament_pools(id) ON DELETE CASCADE,
      participant_id INTEGER NOT NULL REFERENCES tournament_participants(id) ON DELETE CASCADE,
      seed_in_pool INTEGER,

      UNIQUE(pool_id, participant_id)
    )`);

    // ===== MATCHES =====
    await q(`CREATE TABLE IF NOT EXISTS tournament_matches(
      id SERIAL PRIMARY KEY,
      phase_id INTEGER NOT NULL REFERENCES tournament_phases(id) ON DELETE CASCADE,
      pool_id INTEGER REFERENCES tournament_pools(id) ON DELETE SET NULL,

      -- Identification
      round_number INTEGER,
      match_number INTEGER,
      identifier TEXT,

      -- Bracket info
      bracket_type TEXT DEFAULT 'winner',

      -- Participants
      participant1_id INTEGER REFERENCES tournament_participants(id) ON DELETE SET NULL,
      participant2_id INTEGER REFERENCES tournament_participants(id) ON DELETE SET NULL,

      -- Scores
      score1 INTEGER,
      score2 INTEGER,

      -- Best of tracking
      best_of INTEGER DEFAULT 1,
      games_won_p1 INTEGER DEFAULT 0,
      games_won_p2 INTEGER DEFAULT 0,

      -- Winner
      winner_id INTEGER REFERENCES tournament_participants(id) ON DELETE SET NULL,
      loser_id INTEGER REFERENCES tournament_participants(id) ON DELETE SET NULL,

      -- Progression
      next_match_winner_id INTEGER REFERENCES tournament_matches(id) ON DELETE SET NULL,
      next_match_loser_id INTEGER REFERENCES tournament_matches(id) ON DELETE SET NULL,

      -- Status
      status TEXT DEFAULT 'pending',

      -- Scheduling
      scheduled_time TIMESTAMPTZ,
      called_at TIMESTAMPTZ,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,

      -- Station
      station_identifier TEXT,

      -- Metadata
      is_grand_final BOOLEAN DEFAULT false,
      requires_reset BOOLEAN DEFAULT false,

      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ DEFAULT now(),

      CONSTRAINT match_status_check CHECK (status IN ('pending', 'ready', 'called', 'in_progress', 'completed', 'bye', 'dq'))
    )`);

    // ===== GAMES (sous-matchs dans un Best of X) =====
    await q(`CREATE TABLE IF NOT EXISTS tournament_games(
      id SERIAL PRIMARY KEY,
      match_id INTEGER NOT NULL REFERENCES tournament_matches(id) ON DELETE CASCADE,
      game_number INTEGER NOT NULL,

      -- Scores
      score1 INTEGER,
      score2 INTEGER,

      -- Winner
      winner_id INTEGER REFERENCES tournament_participants(id) ON DELETE SET NULL,

      -- Timing
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,

      -- Stage/character info (pour les jeux de combat)
      stage_selected TEXT,
      p1_character TEXT,
      p2_character TEXT,

      created_at TIMESTAMPTZ DEFAULT now(),

      UNIQUE(match_id, game_number)
    )`);

    // ===== MATCH ATTACHMENTS (preuves, screenshots) =====
    await q(`CREATE TABLE IF NOT EXISTS tournament_match_attachments(
      id SERIAL PRIMARY KEY,
      match_id INTEGER NOT NULL REFERENCES tournament_matches(id) ON DELETE CASCADE,
      uploaded_by_user_id INTEGER REFERENCES users(id),
      uploaded_by_participant_id INTEGER REFERENCES tournament_participants(id),

      attachment_type TEXT NOT NULL,
      url TEXT NOT NULL,
      description TEXT,

      verified BOOLEAN DEFAULT false,
      verified_by_user_id INTEGER REFERENCES users(id),
      verified_at TIMESTAMPTZ,

      created_at TIMESTAMPTZ DEFAULT now(),

      CONSTRAINT attachment_type_check CHECK (attachment_type IN ('screenshot', 'video', 'link', 'other'))
    )`);

    // ===== MATCH COMMENTS =====
    await q(`CREATE TABLE IF NOT EXISTS tournament_match_comments(
      id SERIAL PRIMARY KEY,
      match_id INTEGER NOT NULL REFERENCES tournament_matches(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id),
      participant_id INTEGER REFERENCES tournament_participants(id),

      comment_text TEXT NOT NULL,

      created_at TIMESTAMPTZ DEFAULT now()
    )`);

    // ===== PARTICIPANT STATS =====
    await q(`CREATE TABLE IF NOT EXISTS tournament_participant_stats(
      id SERIAL PRIMARY KEY,
      participant_id INTEGER NOT NULL REFERENCES tournament_participants(id) ON DELETE CASCADE,
      phase_id INTEGER REFERENCES tournament_phases(id) ON DELETE CASCADE,

      -- Stats globales
      matches_played INTEGER DEFAULT 0,
      matches_won INTEGER DEFAULT 0,
      matches_lost INTEGER DEFAULT 0,

      -- Games
      games_won INTEGER DEFAULT 0,
      games_lost INTEGER DEFAULT 0,

      -- Points (pour Round Robin, Swiss)
      points INTEGER DEFAULT 0,
      buchholz REAL DEFAULT 0,

      -- Placements
      pool_placement INTEGER,
      phase_placement INTEGER,

      updated_at TIMESTAMPTZ DEFAULT now(),

      UNIQUE(participant_id, phase_id)
    )`);

    // ===== INDEXES =====
    await q(`CREATE INDEX IF NOT EXISTS idx_tournaments_slug ON tournaments(slug)`);
    await q(`CREATE INDEX IF NOT EXISTS idx_tournaments_status ON tournaments(status)`);
    await q(`CREATE INDEX IF NOT EXISTS idx_events_tournament ON tournament_events(tournament_id)`);
    await q(`CREATE INDEX IF NOT EXISTS idx_phases_event ON tournament_phases(event_id)`);
    await q(`CREATE INDEX IF NOT EXISTS idx_participants_tournament ON tournament_participants(tournament_id)`);
    await q(`CREATE INDEX IF NOT EXISTS idx_participants_event ON tournament_participants(event_id)`);
    await q(`CREATE INDEX IF NOT EXISTS idx_matches_phase ON tournament_matches(phase_id)`);
    await q(`CREATE INDEX IF NOT EXISTS idx_matches_pool ON tournament_matches(pool_id)`);
    await q(`CREATE INDEX IF NOT EXISTS idx_games_match ON tournament_games(match_id)`);

    console.log('✅ Tournament schema initialized');
  }

  /**
   * ========================================
   * UTILITIES
   * ========================================
   */

  function generateSlug(name) {
    return name
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      + '-' + crypto.randomBytes(3).toString('hex');
  }

  /**
   * ========================================
   * ROUTES: TOURNAMENTS
   * ========================================
   */

  // GET /tournaments - Liste tous les tournois
  router.get('/', auth, async (req, res) => {
    try {
      const { status, game_title, is_public } = req.query;

      let query = `
        SELECT t.*,
               u.email as creator_email,
               (SELECT COUNT(*) FROM tournament_participants WHERE tournament_id = t.id) as participant_count,
               (SELECT COUNT(*) FROM tournament_events WHERE tournament_id = t.id) as event_count
        FROM tournaments t
        LEFT JOIN users u ON t.created_by_user_id = u.id
        WHERE 1=1
      `;
      const params = [];

      if (status) {
        params.push(status);
        query += ` AND t.status = $${params.length}`;
      }

      if (game_title) {
        params.push(`%${game_title}%`);
        query += ` AND t.game_title ILIKE $${params.length}`;
      }

      if (is_public !== undefined) {
        params.push(is_public === 'true');
        query += ` AND t.is_public = $${params.length}`;
      }

      query += ` ORDER BY t.created_at DESC`;

      const result = await q(query, params);
      ok(res, { tournaments: result.rows });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to fetch tournaments');
    }
  });

  // GET /tournaments/:id - Détails d'un tournoi
  router.get('/:id', auth, async (req, res) => {
    try {
      const { id } = req.params;

      const tResult = await q(`
        SELECT t.*,
               u.email as creator_email
        FROM tournaments t
        LEFT JOIN users u ON t.created_by_user_id = u.id
        WHERE t.id = $1
      `, [id]);

      if (!tResult.rows.length) return bad(res, 404, 'Tournament not found');

      const tournament = tResult.rows[0];

      // Charger les events
      const eventsResult = await q(`
        SELECT e.*,
               (SELECT COUNT(*) FROM tournament_participants WHERE event_id = e.id) as participant_count
        FROM tournament_events e
        WHERE e.tournament_id = $1
        ORDER BY e.display_order, e.created_at
      `, [id]);

      tournament.events = eventsResult.rows;

      // Charger les participants
      const participantsResult = await q(`
        SELECT p.*
        FROM tournament_participants p
        WHERE p.tournament_id = $1
        ORDER BY p.seed NULLS LAST, p.created_at
      `, [id]);

      tournament.participants = participantsResult.rows;

      ok(res, { tournament });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to fetch tournament');
    }
  });

  // POST /tournaments - Créer un tournoi
  router.post('/', auth, adminOnly, async (req, res) => {
    try {
      const {
        name,
        game_title,
        description,
        start_date,
        end_date,
        timezone,
        is_public,
        registration_enabled,
        registration_cap,
        check_in_enabled,
        check_in_duration,
        banner_url,
        rules_url
      } = req.body;

      if (!name || !game_title) {
        return bad(res, 400, 'Missing required fields: name, game_title');
      }

      const slug = generateSlug(name);

      const result = await q(`
        INSERT INTO tournaments(
          name, slug, game_title, description,
          start_date, end_date, timezone,
          is_public, registration_enabled, registration_cap,
          check_in_enabled, check_in_duration,
          banner_url, rules_url,
          created_by_user_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        RETURNING *
      `, [
        name, slug, game_title, description,
        start_date, end_date, timezone || 'UTC',
        is_public !== false, registration_enabled !== false, registration_cap,
        check_in_enabled || false, check_in_duration || 30,
        banner_url, rules_url,
        req.user.uid
      ]);

      const tournament = result.rows[0];

      io.emit('tournament:created', { tournament });
      ok(res, { tournament });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to create tournament');
    }
  });

  // PUT /tournaments/:id - Modifier un tournoi
  router.put('/:id', auth, adminOnly, async (req, res) => {
    try {
      const { id } = req.params;
      const updates = req.body;

      const allowed = [
        'name', 'game_title', 'description',
        'start_date', 'end_date', 'timezone',
        'is_public', 'registration_enabled', 'registration_cap',
        'check_in_enabled', 'check_in_duration',
        'status', 'banner_url', 'rules_url'
      ];

      const fields = [];
      const values = [];
      let paramCount = 1;

      for (const [key, value] of Object.entries(updates)) {
        if (allowed.includes(key)) {
          fields.push(`${key} = $${paramCount}`);
          values.push(value);
          paramCount++;
        }
      }

      if (fields.length === 0) {
        return bad(res, 400, 'No valid fields to update');
      }

      fields.push(`updated_at = now()`);
      values.push(id);

      const result = await q(`
        UPDATE tournaments
        SET ${fields.join(', ')}
        WHERE id = $${paramCount}
        RETURNING *
      `, values);

      if (!result.rows.length) return bad(res, 404, 'Tournament not found');

      const tournament = result.rows[0];
      io.emit('tournament:updated', { tournament });
      ok(res, { tournament });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to update tournament');
    }
  });

  // DELETE /tournaments/:id - Supprimer un tournoi
  router.delete('/:id', auth, adminOnly, async (req, res) => {
    try {
      const { id } = req.params;

      await q(`DELETE FROM tournaments WHERE id = $1`, [id]);

      io.emit('tournament:deleted', { tournament_id: parseInt(id) });
      ok(res, { message: 'Tournament deleted' });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to delete tournament');
    }
  });

  /**
   * ========================================
   * ROUTES: EVENTS
   * ========================================
   */

  // POST /tournaments/:id/events - Créer un event
  router.post('/:id/events', auth, adminOnly, async (req, res) => {
    try {
      const { id } = req.params;
      const { name, type, description, team_size, min_participants, max_participants } = req.body;

      if (!name || !type) {
        return bad(res, 400, 'Missing required fields: name, type');
      }

      const slug = generateSlug(name);

      const result = await q(`
        INSERT INTO tournament_events(
          tournament_id, name, slug, type, description,
          team_size, min_participants, max_participants
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
      `, [id, name, slug, type, description, team_size || 1, min_participants || 2, max_participants]);

      const event = result.rows[0];
      io.emit('tournament:event_created', { tournament_id: parseInt(id), event });
      ok(res, { event });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to create event');
    }
  });

  // GET /tournaments/:id/events - Liste des events
  router.get('/:id/events', auth, async (req, res) => {
    try {
      const { id } = req.params;

      const result = await q(`
        SELECT e.*,
               (SELECT COUNT(*) FROM tournament_participants WHERE event_id = e.id) as participant_count,
               (SELECT COUNT(*) FROM tournament_phases WHERE event_id = e.id) as phase_count
        FROM tournament_events e
        WHERE e.tournament_id = $1
        ORDER BY e.display_order, e.created_at
      `, [id]);

      ok(res, { events: result.rows });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to fetch events');
    }
  });

  /**
   * ========================================
   * ROUTES: PARTICIPANTS
   * ========================================
   */

  // POST /tournaments/:id/participants - Ajouter un participant
  router.post('/:id/participants', auth, async (req, res) => {
    try {
      const { id } = req.params;
      const { name, tag, event_id, player_id, team_name, team_members, seed } = req.body;

      if (!name) {
        return bad(res, 400, 'Missing required field: name');
      }

      const result = await q(`
        INSERT INTO tournament_participants(
          tournament_id, event_id, name, tag, player_id,
          team_name, team_members, seed, status
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'registered')
        RETURNING *
      `, [id, event_id, name, tag, player_id, team_name, team_members ? JSON.stringify(team_members) : null, seed]);

      const participant = result.rows[0];

      // Update tournament participant count
      await q(`UPDATE tournaments SET total_participants = (SELECT COUNT(*) FROM tournament_participants WHERE tournament_id = $1) WHERE id = $1`, [id]);

      io.emit('tournament:participant_added', { tournament_id: parseInt(id), participant });
      ok(res, { participant });
    } catch (err) {
      console.error(err);
      if (err.code === '23505') {
        bad(res, 400, 'Participant already registered');
      } else {
        bad(res, 500, 'Failed to add participant');
      }
    }
  });

  // GET /tournaments/:id/participants - Liste des participants
  router.get('/:id/participants', auth, async (req, res) => {
    try {
      const { id } = req.params;
      const { event_id } = req.query;

      let query = `
        SELECT p.*,
               e.name as event_name
        FROM tournament_participants p
        LEFT JOIN tournament_events e ON p.event_id = e.id
        WHERE p.tournament_id = $1
      `;
      const params = [id];

      if (event_id) {
        params.push(event_id);
        query += ` AND p.event_id = $${params.length}`;
      }

      query += ` ORDER BY p.seed NULLS LAST, p.created_at`;

      const result = await q(query, params);
      ok(res, { participants: result.rows });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to fetch participants');
    }
  });

  // PUT /tournaments/:id/participants/:pid/seed - Mettre à jour le seed
  router.put('/:id/participants/:pid/seed', auth, adminOnly, async (req, res) => {
    try {
      const { id, pid } = req.params;
      const { seed } = req.body;

      const result = await q(`
        UPDATE tournament_participants
        SET seed = $1
        WHERE id = $2 AND tournament_id = $3
        RETURNING *
      `, [seed, pid, id]);

      if (!result.rows.length) return bad(res, 404, 'Participant not found');

      io.emit('tournament:participant_updated', { tournament_id: parseInt(id), participant: result.rows[0] });
      ok(res, { participant: result.rows[0] });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to update seed');
    }
  });

  // POST /tournaments/:id/participants/:pid/check-in - Check-in
  router.post('/:id/participants/:pid/check-in', auth, async (req, res) => {
    try {
      const { id, pid } = req.params;

      const result = await q(`
        UPDATE tournament_participants
        SET checked_in = true, checked_in_at = now(), status = 'checked_in'
        WHERE id = $1 AND tournament_id = $2
        RETURNING *
      `, [pid, id]);

      if (!result.rows.length) return bad(res, 404, 'Participant not found');

      io.emit('tournament:participant_checked_in', { tournament_id: parseInt(id), participant: result.rows[0] });
      ok(res, { participant: result.rows[0] });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to check-in');
    }
  });

  // DELETE /tournaments/:id/participants/:pid - Retirer un participant
  router.delete('/:id/participants/:pid', auth, adminOnly, async (req, res) => {
    try {
      const { id, pid } = req.params;

      await q(`DELETE FROM tournament_participants WHERE id = $1 AND tournament_id = $2`, [pid, id]);

      // Update tournament participant count
      await q(`UPDATE tournaments SET total_participants = (SELECT COUNT(*) FROM tournament_participants WHERE tournament_id = $1) WHERE id = $1`, [id]);

      io.emit('tournament:participant_removed', { tournament_id: parseInt(id), participant_id: parseInt(pid) });
      ok(res, { message: 'Participant removed' });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to remove participant');
    }
  });

  /**
   * ========================================
   * ROUTES: PHASES
   * ========================================
   */

  // POST /tournaments/:id/events/:eid/phases - Créer une phase
  router.post('/:id/events/:eid/phases', auth, adminOnly, async (req, res) => {
    try {
      const { id, eid } = req.params;
      const { name, phase_type, bracket_type, num_pools, best_of, advancement_count } = req.body;

      if (!name || !phase_type) {
        return bad(res, 400, 'Missing required fields: name, phase_type');
      }

      // Get current phase count for ordering
      const countResult = await q(`SELECT COUNT(*) as count FROM tournament_phases WHERE event_id = $1`, [eid]);
      const phase_order = parseInt(countResult.rows[0].count) + 1;

      const result = await q(`
        INSERT INTO tournament_phases(
          event_id, name, phase_order, phase_type,
          bracket_type, num_pools, best_of, advancement_count
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
      `, [eid, name, phase_order, phase_type, bracket_type, num_pools, best_of || 1, advancement_count]);

      const phase = result.rows[0];
      io.emit('tournament:phase_created', { tournament_id: parseInt(id), event_id: parseInt(eid), phase });
      ok(res, { phase });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to create phase');
    }
  });

  // GET /tournaments/:id/events/:eid/phases - Liste des phases
  router.get('/:id/events/:eid/phases', auth, async (req, res) => {
    try {
      const { eid } = req.params;

      const result = await q(`
        SELECT p.*,
               (SELECT COUNT(*) FROM tournament_matches WHERE phase_id = p.id) as match_count
        FROM tournament_phases p
        WHERE p.event_id = $1
        ORDER BY p.phase_order
      `, [eid]);

      ok(res, { phases: result.rows });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to fetch phases');
    }
  });

  /**
   * ========================================
   * ROUTES: MATCHES
   * ========================================
   */

  // GET /tournaments/:id/matches - Liste des matchs
  router.get('/:id/matches', auth, async (req, res) => {
    try {
      const { id } = req.params;
      const { event_id, phase_id, status } = req.query;

      let query = `
        SELECT m.*,
               p1.name as participant1_name, p1.tag as participant1_tag,
               p2.name as participant2_name, p2.tag as participant2_tag,
               w.name as winner_name,
               ph.name as phase_name, ph.phase_type,
               e.name as event_name
        FROM tournament_matches m
        LEFT JOIN tournament_participants p1 ON m.participant1_id = p1.id
        LEFT JOIN tournament_participants p2 ON m.participant2_id = p2.id
        LEFT JOIN tournament_participants w ON m.winner_id = w.id
        LEFT JOIN tournament_phases ph ON m.phase_id = ph.id
        LEFT JOIN tournament_events e ON ph.event_id = e.id
        WHERE e.tournament_id = $1
      `;
      const params = [id];

      if (event_id) {
        params.push(event_id);
        query += ` AND e.id = $${params.length}`;
      }

      if (phase_id) {
        params.push(phase_id);
        query += ` AND m.phase_id = $${params.length}`;
      }

      if (status) {
        params.push(status);
        query += ` AND m.status = $${params.length}`;
      }

      query += ` ORDER BY ph.phase_order, m.round_number, m.match_number`;

      const result = await q(query, params);
      ok(res, { matches: result.rows });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to fetch matches');
    }
  });

  // PUT /tournaments/:id/matches/:mid - Mettre à jour un match
  router.put('/:id/matches/:mid', auth, adminOnly, async (req, res) => {
    try {
      const { id, mid } = req.params;
      const { score1, score2, winner_id, status } = req.body;

      const updates = [];
      const values = [];
      let paramCount = 1;

      if (score1 !== undefined) {
        values.push(score1);
        updates.push(`score1 = $${paramCount++}`);
      }

      if (score2 !== undefined) {
        values.push(score2);
        updates.push(`score2 = $${paramCount++}`);
      }

      if (winner_id !== undefined) {
        values.push(winner_id);
        updates.push(`winner_id = $${paramCount++}`);

        // Determine loser
        const matchResult = await q(`SELECT participant1_id, participant2_id FROM tournament_matches WHERE id = $1`, [mid]);
        if (matchResult.rows.length) {
          const match = matchResult.rows[0];
          const loser_id = match.participant1_id === winner_id ? match.participant2_id : match.participant1_id;
          values.push(loser_id);
          updates.push(`loser_id = $${paramCount++}`);
        }
      }

      if (status !== undefined) {
        values.push(status);
        updates.push(`status = $${paramCount++}`);
      }

      updates.push(`updated_at = now()`);

      if (status === 'completed') {
        updates.push(`completed_at = now()`);
      }

      values.push(mid);

      const result = await q(`
        UPDATE tournament_matches
        SET ${updates.join(', ')}
        WHERE id = $${paramCount}
        RETURNING *
      `, values);

      if (!result.rows.length) return bad(res, 404, 'Match not found');

      const match = result.rows[0];

      // Auto-progress winner to next match if applicable
      if (winner_id && match.next_match_winner_id) {
        const nextMatch = await q(`SELECT * FROM tournament_matches WHERE id = $1`, [match.next_match_winner_id]);
        if (nextMatch.rows.length) {
          const next = nextMatch.rows[0];
          if (!next.participant1_id) {
            await q(`UPDATE tournament_matches SET participant1_id = $1 WHERE id = $2`, [winner_id, match.next_match_winner_id]);
          } else if (!next.participant2_id) {
            await q(`UPDATE tournament_matches SET participant2_id = $1 WHERE id = $2`, [winner_id, match.next_match_winner_id]);
          }
        }
      }

      io.emit('tournament:match_updated', { tournament_id: parseInt(id), match });
      ok(res, { match });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to update match');
    }
  });

  /**
   * ========================================
   * ROUTES: GAMES (Best of X)
   * ========================================
   */

  // POST /tournaments/:id/matches/:mid/games - Ajouter un game
  router.post('/:id/matches/:mid/games', auth, adminOnly, async (req, res) => {
    try {
      const { id, mid } = req.params;
      const { game_number, score1, score2, winner_id, stage_selected, p1_character, p2_character } = req.body;

      const result = await q(`
        INSERT INTO tournament_games(
          match_id, game_number, score1, score2, winner_id,
          stage_selected, p1_character, p2_character, completed_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
        RETURNING *
      `, [mid, game_number, score1, score2, winner_id, stage_selected, p1_character, p2_character]);

      const game = result.rows[0];

      // Update match games won count
      const matchResult = await q(`SELECT participant1_id, participant2_id, best_of FROM tournament_matches WHERE id = $1`, [mid]);
      if (matchResult.rows.length) {
        const match = matchResult.rows[0];

        const gamesResult = await q(`
          SELECT winner_id, COUNT(*) as count
          FROM tournament_games
          WHERE match_id = $1
          GROUP BY winner_id
        `, [mid]);

        let p1_wins = 0;
        let p2_wins = 0;

        gamesResult.rows.forEach(row => {
          if (row.winner_id === match.participant1_id) p1_wins = parseInt(row.count);
          if (row.winner_id === match.participant2_id) p2_wins = parseInt(row.count);
        });

        await q(`UPDATE tournament_matches SET games_won_p1 = $1, games_won_p2 = $2 WHERE id = $3`, [p1_wins, p2_wins, mid]);

        // Check if match is won
        const needed_wins = Math.ceil(match.best_of / 2);
        if (p1_wins >= needed_wins || p2_wins >= needed_wins) {
          const match_winner = p1_wins >= needed_wins ? match.participant1_id : match.participant2_id;
          await q(`UPDATE tournament_matches SET winner_id = $1, status = 'completed', completed_at = now() WHERE id = $2`, [match_winner, mid]);
        }
      }

      io.emit('tournament:game_added', { tournament_id: parseInt(id), match_id: parseInt(mid), game });
      ok(res, { game });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to add game');
    }
  });

  // GET /tournaments/:id/matches/:mid/games - Liste des games
  router.get('/:id/matches/:mid/games', auth, async (req, res) => {
    try {
      const { mid } = req.params;

      const result = await q(`
        SELECT g.*,
               p1.name as participant1_name,
               p2.name as participant2_name,
               w.name as winner_name
        FROM tournament_games g
        JOIN tournament_matches m ON g.match_id = m.id
        LEFT JOIN tournament_participants p1 ON m.participant1_id = p1.id
        LEFT JOIN tournament_participants p2 ON m.participant2_id = p2.id
        LEFT JOIN tournament_participants w ON g.winner_id = w.id
        WHERE g.match_id = $1
        ORDER BY g.game_number
      `, [mid]);

      ok(res, { games: result.rows });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to fetch games');
    }
  });

  /**
   * ========================================
   * ROUTES: COMMENTS & ATTACHMENTS
   * ========================================
   */

  // POST /tournaments/:id/matches/:mid/comments - Ajouter un commentaire
  router.post('/:id/matches/:mid/comments', auth, async (req, res) => {
    try {
      const { id, mid } = req.params;
      const { comment_text } = req.body;

      if (!comment_text) {
        return bad(res, 400, 'Missing required field: comment_text');
      }

      const result = await q(`
        INSERT INTO tournament_match_comments(match_id, user_id, comment_text)
        VALUES ($1, $2, $3)
        RETURNING *
      `, [mid, req.user.uid, comment_text]);

      const comment = result.rows[0];
      io.emit('tournament:comment_added', { tournament_id: parseInt(id), match_id: parseInt(mid), comment });
      ok(res, { comment });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to add comment');
    }
  });

  // GET /tournaments/:id/matches/:mid/comments - Liste des commentaires
  router.get('/:id/matches/:mid/comments', auth, async (req, res) => {
    try {
      const { mid } = req.params;

      const result = await q(`
        SELECT c.*, u.email as user_email
        FROM tournament_match_comments c
        LEFT JOIN users u ON c.user_id = u.id
        WHERE c.match_id = $1
        ORDER BY c.created_at DESC
      `, [mid]);

      ok(res, { comments: result.rows });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to fetch comments');
    }
  });

  // POST /tournaments/:id/matches/:mid/attachments - Ajouter une pièce jointe
  router.post('/:id/matches/:mid/attachments', auth, async (req, res) => {
    try {
      const { id, mid } = req.params;
      const { attachment_type, url, description } = req.body;

      if (!attachment_type || !url) {
        return bad(res, 400, 'Missing required fields: attachment_type, url');
      }

      const result = await q(`
        INSERT INTO tournament_match_attachments(match_id, uploaded_by_user_id, attachment_type, url, description)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
      `, [mid, req.user.uid, attachment_type, url, description]);

      const attachment = result.rows[0];
      io.emit('tournament:attachment_added', { tournament_id: parseInt(id), match_id: parseInt(mid), attachment });
      ok(res, { attachment });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to add attachment');
    }
  });

  // GET /tournaments/:id/matches/:mid/attachments - Liste des pièces jointes
  router.get('/:id/matches/:mid/attachments', auth, async (req, res) => {
    try {
      const { mid } = req.params;

      const result = await q(`
        SELECT a.*, u.email as uploader_email
        FROM tournament_match_attachments a
        LEFT JOIN users u ON a.uploaded_by_user_id = u.id
        WHERE a.match_id = $1
        ORDER BY a.created_at DESC
      `, [mid]);

      ok(res, { attachments: result.rows });
    } catch (err) {
      console.error(err);
      bad(res, 500, 'Failed to fetch attachments');
    }
  });

  /**
   * ========================================
   * EXPORTS
   * ========================================
   */

  return {
    router,
    ensureTournamentSchema
  };
};
