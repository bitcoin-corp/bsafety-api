// Cases, items, the action log and the denylist in SQLite (node:sqlite, no native build), as bdrivex-api does.
// No images are ever stored here: hashes, references and metadata only.
import { DatabaseSync } from 'node:sqlite';

export function openDb(file) {
  const db = new DatabaseSync(file);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS nonces (
      nonce TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS revoked (sid TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);

    -- One row per item a marketplace has told us about or someone has reported. ref = where a reviewer can open the
    -- server-made preview (set by the marketplace, never by a reporter). status: unscreened | in_review | screened | blocked.
    CREATE TABLE IF NOT EXISTS items (
      service TEXT NOT NULL, item_id TEXT NOT NULL, seller TEXT, ref TEXT,
      status TEXT NOT NULL DEFAULT 'unscreened', screened_sha256 TEXT, dhash TEXT, screened_at INTEGER, screen_detail TEXT,
      removed_at INTEGER, removed_reason TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
      PRIMARY KEY (service, item_id));
    CREATE INDEX IF NOT EXISTS items_seller ON items(seller);

    -- Reports, notices, requests, complaints, appeals, hash matches and screening flags: one store, one queue.
    -- status: open | quarantined (known-hash match: never viewable) | closed. hides = this case hides the item while
    -- it is open. viewable = 0 means no image reference is ever returned for it.
    CREATE TABLE IF NOT EXISTS cases (
      id TEXT PRIMARY KEY, service TEXT NOT NULL, item_id TEXT, type TEXT NOT NULL, category TEXT,
      priority INTEGER NOT NULL, status TEXT NOT NULL, hides INTEGER NOT NULL DEFAULT 0, viewable INTEGER NOT NULL DEFAULT 1,
      due_by INTEGER NOT NULL, created_at INTEGER NOT NULL, closed_at INTEGER, resolution TEXT, decided_by TEXT,
      details TEXT, contact TEXT, ip_hash TEXT, ack TEXT, parent_id TEXT, restore_eligible_at INTEGER,
      sha256 TEXT, dhash TEXT);
    CREATE INDEX IF NOT EXISTS cases_item ON cases(service, item_id);
    CREATE INDEX IF NOT EXISTS cases_queue ON cases(status, priority, due_by);
    CREATE INDEX IF NOT EXISTS cases_ip ON cases(ip_hash, created_at);

    -- Append-only: who, when, what, why. The triggers refuse any change or deletion.
    CREATE TABLE IF NOT EXISTS actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, actor TEXT NOT NULL, case_id TEXT,
      service TEXT, item_id TEXT, action TEXT NOT NULL, reason TEXT, detail TEXT);
    CREATE INDEX IF NOT EXISTS actions_case ON actions(case_id);
    CREATE TRIGGER IF NOT EXISTS actions_no_update BEFORE UPDATE ON actions BEGIN SELECT RAISE(ABORT, 'the action log is append-only'); END;
    CREATE TRIGGER IF NOT EXISTS actions_no_delete BEFORE DELETE ON actions BEGIN SELECT RAISE(ABORT, 'the action log is append-only'); END;

    -- Hashes that can never be listed again by anyone (§9.2). removed_* is set if an appeal succeeds; rows stay.
    CREATE TABLE IF NOT EXISTS denylist (
      id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT, dhash TEXT, category TEXT, source TEXT NOT NULL,
      case_id TEXT, service TEXT, item_id TEXT, added_at INTEGER NOT NULL, added_by TEXT NOT NULL,
      removed_at INTEGER, removed_by TEXT);
    CREATE INDEX IF NOT EXISTS denylist_sha ON denylist(sha256);

    CREATE TABLE IF NOT EXISTS bans (
      identity_key TEXT PRIMARY KEY, at INTEGER NOT NULL, by TEXT NOT NULL, reason TEXT, case_id TEXT);

    -- Acknowledgements and outcomes waiting to be emailed (phase 2 sends them; phase 1 only stores them).
    CREATE TABLE IF NOT EXISTS outbox (
      id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, to_contact TEXT NOT NULL, body TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL);
  `);
  const q = (sql) => db.prepare(sql);
  return {
    db,
    tx(fn) {
      db.exec('BEGIN IMMEDIATE');
      try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; }
    },
    nonces: {
      put: q('INSERT OR REPLACE INTO nonces (nonce, data, expires_at) VALUES (?, ?, ?)'),
      get: q('SELECT data, expires_at FROM nonces WHERE nonce = ?'),
      del: q('DELETE FROM nonces WHERE nonce = ?'),
      prune: q('DELETE FROM nonces WHERE expires_at < ?'),
    },
    sessions: {
      revoke: q('INSERT OR IGNORE INTO revoked (sid, expires_at) VALUES (?, ?)'),
      isRevoked: q('SELECT 1 AS r FROM revoked WHERE sid = ?'),
      prune: q('DELETE FROM revoked WHERE expires_at < ?'),
    },
    items: {
      get: q('SELECT * FROM items WHERE service = ? AND item_id = ?'),
      touch: q('INSERT OR IGNORE INTO items (service, item_id, created_at, updated_at) VALUES (?, ?, ?, ?)'),
      register: q(`INSERT INTO items (service, item_id, seller, ref, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?5)
        ON CONFLICT(service, item_id) DO UPDATE SET seller = COALESCE(?3, seller), ref = COALESCE(?4, ref), updated_at = ?5`),
      screenResult: q('UPDATE items SET status = ?, screened_sha256 = ?, dhash = ?, screened_at = ?, screen_detail = ?, updated_at = ? WHERE service = ? AND item_id = ?'),
      remove: q('UPDATE items SET removed_at = ?, removed_reason = ?, updated_at = ? WHERE service = ? AND item_id = ?'),
      unremove: q('UPDATE items SET removed_at = NULL, removed_reason = NULL, updated_at = ? WHERE service = ? AND item_id = ?'),
      setStatus: q('UPDATE items SET status = ?, updated_at = ? WHERE service = ? AND item_id = ?'),
      bySeller: q('SELECT service, item_id FROM items WHERE seller = ?'),
      hidden: q(`SELECT
        EXISTS (SELECT 1 FROM items WHERE service = ?1 AND item_id = ?2
          AND (removed_at IS NOT NULL OR status = 'blocked' OR seller IN (SELECT identity_key FROM bans)))
        OR EXISTS (SELECT 1 FROM cases WHERE service = ?1 AND item_id = ?2 AND hides = 1 AND status IN ('open', 'quarantined'))
        AS hidden`),
    },
    cases: {
      add: q(`INSERT INTO cases (id, service, item_id, type, category, priority, status, hides, viewable, due_by, created_at,
        details, contact, ip_hash, ack, parent_id, restore_eligible_at, sha256, dhash)
        VALUES (:id, :service, :item_id, :type, :category, :priority, :status, :hides, :viewable, :due_by, :created_at,
        :details, :contact, :ip_hash, :ack, :parent_id, :restore_eligible_at, :sha256, :dhash)`),
      get: q('SELECT * FROM cases WHERE id = ?'),
      queue: q('SELECT * FROM cases WHERE status = ? ORDER BY priority ASC, due_by ASC, created_at ASC LIMIT ?'),
      forItem: q('SELECT * FROM cases WHERE service = ? AND item_id = ? ORDER BY created_at ASC'),
      close: q('UPDATE cases SET status = \'closed\', closed_at = ?, resolution = ?, decided_by = ? WHERE id = ?'),
      setResolution: q('UPDATE cases SET resolution = ?, decided_by = ? WHERE id = ?'),
      extend: q('UPDATE cases SET due_by = ? WHERE id = ?'),
      byIpSince: q("SELECT COUNT(*) AS n FROM cases WHERE ip_hash = ? AND created_at > ? AND type IN ('report', 'hash_mismatch', 'copyright_notice', 'privacy_request', 'complaint', 'appeal')"),
      byItemSince: q("SELECT COUNT(*) AS n FROM cases WHERE service = ? AND item_id = ? AND created_at > ? AND type IN ('report', 'hash_mismatch', 'privacy_request')"),
      duplicate: q("SELECT id FROM cases WHERE service = ? AND item_id = ? AND ip_hash = ? AND category = ? AND type = 'report' AND created_at > ? LIMIT 1"),
      // §8.2 row 4 "already flagged": another open case on the item from someone else.
      flaggedByOthers: q("SELECT 1 AS n FROM cases WHERE service = ? AND item_id = ? AND status IN ('open', 'quarantined') AND (ip_hash IS NULL OR ip_hash <> ?) LIMIT 1"),
      openMismatch: q("SELECT id FROM cases WHERE service = ? AND item_id = ? AND type = 'hash_mismatch' AND status = 'open' LIMIT 1"),
      upheldCopyright: q(`SELECT COUNT(*) AS n FROM cases c JOIN items i ON i.service = c.service AND i.item_id = c.item_id
        WHERE i.seller = ? AND c.type = 'copyright_notice' AND c.resolution IN ('rejected', 'rejected_reported')`),
    },
    actions: {
      add: q('INSERT INTO actions (at, actor, case_id, service, item_id, action, reason, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'),
      forCase: q('SELECT * FROM actions WHERE case_id = ? ORDER BY id ASC'),
      recent: q('SELECT * FROM actions ORDER BY id DESC LIMIT ?'),
    },
    denylist: {
      add: q('INSERT INTO denylist (sha256, dhash, category, source, case_id, service, item_id, added_at, added_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'),
      bySha: q('SELECT * FROM denylist WHERE sha256 = ? AND removed_at IS NULL LIMIT 1'),
      live: q('SELECT id, sha256, dhash, category, source FROM denylist WHERE removed_at IS NULL AND dhash IS NOT NULL'),
      forItem: q("SELECT * FROM denylist WHERE service = ? AND item_id = ? AND removed_at IS NULL AND source = 'reviewer'"),
      remove: q('UPDATE denylist SET removed_at = ?, removed_by = ? WHERE id = ?'),
    },
    bans: {
      add: q('INSERT OR IGNORE INTO bans (identity_key, at, by, reason, case_id) VALUES (?, ?, ?, ?, ?)'),
      get: q('SELECT * FROM bans WHERE identity_key = ?'),
    },
    outbox: {
      add: q('INSERT INTO outbox (case_id, to_contact, body, created_at) VALUES (?, ?, ?, ?)'),
      forCase: q('SELECT * FROM outbox WHERE case_id = ?'),
    },
  };
}
