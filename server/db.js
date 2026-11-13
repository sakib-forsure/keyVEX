/**
 * SQLite storage layer (`server/db.js`).
 *
 * Issue E Repairs:
 *   1. Production mode (`production: true`) strictly requires Node.js >= 22.5.0 with built-in
 *      `node:sqlite` (`DatabaseSync`) when opening a file-backed database. It NEVER silently
 *      falls back to a JSON file in production; it fails fast with an actionable startup error.
 *   2. Note on topology: SQLite is a single-node embedded database retained only for optional
 *      single-instance legacy migration / local server mode. Cloud Firestore is the canonical
 *      multi-device vault store.
 *   3. In non-production test environments running on older Node runtimes without `node:sqlite`,
 *      `JsDatabaseSync._persist()` never swallows write errors; any I/O failure throws a
 *      `DatabasePersistenceError` immediately.
 */
import { createRequire } from "node:module";
import { mkdirSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export class UnsupportedProductionRuntimeError extends Error {
  constructor(message) {
    super(message);
    this.code = "UNSUPPORTED_DB_RUNTIME";
  }
}

export class DatabasePersistenceError extends Error {
  constructor(message, extra = {}) {
    super(message);
    this.code = "DB_PERSISTENCE_FAILED";
    Object.assign(this, extra);
  }
}

let DatabaseSync = null;
try {
  DatabaseSync = createRequire(import.meta.url)("node:sqlite").DatabaseSync;
} catch {
  DatabaseSync = null;
}

export function hasNativeSqlite() {
  return typeof DatabaseSync === "function";
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS accounts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  lookup     TEXT NOT NULL UNIQUE,
  auth_salt  TEXT NOT NULL,
  auth_hash  TEXT NOT NULL,
  meta       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  id         TEXT NOT NULL,
  iv         TEXT NOT NULL,
  data       TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (account_id, id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_account ON sessions(account_id);
CREATE TABLE IF NOT EXISTS throttle (
  key     TEXT PRIMARY KEY,
  fails   INTEGER NOT NULL,
  until   INTEGER NOT NULL,
  touched INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deletion_jobs (
  job_id     TEXT PRIMARY KEY,
  uid        TEXT NOT NULL,
  state      TEXT NOT NULL,
  updated_at INTEGER NOT NULL,
  details    TEXT NOT NULL
);
`;

/** Non-production test fallback database for Node < 22.5 where `node:sqlite` is absent. */
export class JsDatabaseSync {
  constructor(path = ":memory:") {
    this.path = path;
    this.isNativeSqlite = false;
    this.state = { nextAccountId: 1, accounts: [], entries: [], sessions: [], throttle: [], deletion_jobs: [] };
    this._snapshot = null;
    if (path !== ":memory:" && existsSync(path)) {
      const raw = readFileSync(path, "utf8");
      if (raw.startsWith("SQLite format 3")) {
        throw new UnsupportedProductionRuntimeError(
          `Database file "${path}" is a native SQLite 3 database, which requires Node.js >= 22.5.0 (built-in node:sqlite).`
        );
      }
      try {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === "object" && Array.isArray(parsed.accounts)) {
          this.state = { deletion_jobs: [], ...parsed };
        }
      } catch (err) {
        throw new DatabasePersistenceError(`Corrupted database file at "${path}": ${err.message}`);
      }
    }
  }

  _persist() {
    if (this.path === ":memory:" || this._snapshot !== null) return;
    try {
      writeFileSync(this.path, JSON.stringify(this.state));
    } catch (err) {
      throw new DatabasePersistenceError(`Failed to persist database state to "${this.path}": ${err.message}`, { cause: err });
    }
  }

  exec(sql) {
    const s = String(sql).trim().toUpperCase();
    if (s.startsWith("BEGIN")) {
      this._snapshot = JSON.stringify(this.state);
    } else if (s.startsWith("COMMIT")) {
      const snap = this._snapshot;
      this._snapshot = null;
      try {
        this._persist();
      } catch (err) {
        if (snap !== null) this.state = JSON.parse(snap);
        throw err;
      }
    } else if (s.startsWith("ROLLBACK")) {
      if (this._snapshot !== null) {
        this.state = JSON.parse(this._snapshot);
        this._snapshot = null;
      }
    }
  }

  close() { this._persist(); }

  prepare(sql) {
    const norm = sql.replace(/\s+/g, " ").trim();
    const self = this;
    return {
      get(...args) { return self._query(norm, args, "get"); },
      all(...args) { return self._query(norm, args, "all"); },
      run(...args) { return self._query(norm, args, "run"); }
    };
  }

  _query(norm, args, mode) {
    const st = this.state;
    if (norm === "SELECT id, auth_salt, auth_hash, meta FROM accounts WHERE lookup = ?") {
      const r = st.accounts.find((a) => a.lookup === args[0]);
      return r ? { id: r.id, auth_salt: r.auth_salt, auth_hash: r.auth_hash, meta: r.meta } : undefined;
    }
    if (norm === "SELECT id, lookup, auth_salt, auth_hash, meta FROM accounts WHERE id = ?") {
      const r = st.accounts.find((a) => a.id === args[0]);
      return r ? { id: r.id, lookup: r.lookup, auth_salt: r.auth_salt, auth_hash: r.auth_hash, meta: r.meta } : undefined;
    }
    if (norm.startsWith("INSERT INTO accounts")) {
      const [lookup, auth_salt, auth_hash, meta, created_at, updated_at] = args;
      if (st.accounts.some((a) => a.lookup === lookup)) throw new Error("UNIQUE constraint failed: accounts.lookup");
      const id = st.nextAccountId++;
      st.accounts.push({ id, lookup, auth_salt, auth_hash, meta, created_at, updated_at });
      this._persist();
      return { lastInsertRowid: id, changes: 1 };
    }
    if (norm.startsWith("UPDATE accounts SET lookup = ?")) {
      const [lookup, auth_salt, auth_hash, meta, updated_at, id] = args;
      const r = st.accounts.find((a) => a.id === id);
      if (r) { Object.assign(r, { lookup, auth_salt, auth_hash, meta, updated_at }); this._persist(); }
      return { changes: r ? 1 : 0 };
    }
    if (norm === "DELETE FROM accounts WHERE id = ?") {
      const id = args[0];
      st.accounts = st.accounts.filter((a) => a.id !== id);
      st.entries = st.entries.filter((e) => e.account_id !== id);
      st.sessions = st.sessions.filter((s) => s.account_id !== id);
      this._persist();
      return { changes: 1 };
    }
    if (/^SELECT COUNT\(\*\) (AS )?n FROM accounts$/i.test(norm)) return { n: st.accounts.length };
    if (norm === "SELECT * FROM accounts") return st.accounts.map((a) => ({ ...a }));
    if (norm === "SELECT lookup, auth_hash FROM accounts") {
      const r = st.accounts[0];
      return r ? { lookup: r.lookup, auth_hash: r.auth_hash } : undefined;
    }

    if (norm === "SELECT id, iv, data FROM entries WHERE account_id = ?") {
      return st.entries.filter((e) => e.account_id === args[0]).map((e) => ({ id: e.id, iv: e.iv, data: e.data }));
    }
    if (norm === "SELECT COUNT(*) AS n FROM entries WHERE account_id = ?") {
      return { n: st.entries.filter((e) => e.account_id === args[0]).length };
    }
    if (/^SELECT COUNT\(\*\) (AS )?n FROM entries$/i.test(norm)) return { n: st.entries.length };
    if (norm === "SELECT 1 FROM entries WHERE account_id = ? AND id = ?") {
      return st.entries.some((e) => e.account_id === args[0] && e.id === args[1]) ? { 1: 1 } : undefined;
    }
    if (norm.startsWith("INSERT INTO entries")) {
      const [account_id, id, iv, data, updated_at] = args;
      const existing = st.entries.find((e) => e.account_id === account_id && e.id === id);
      if (existing) Object.assign(existing, { iv, data, updated_at });
      else st.entries.push({ account_id, id, iv, data, updated_at });
      this._persist();
      return { changes: 1 };
    }
    if (norm === "DELETE FROM entries WHERE account_id = ? AND id = ?") {
      st.entries = st.entries.filter((e) => !(e.account_id === args[0] && e.id === args[1]));
      this._persist();
      return { changes: 1 };
    }
    if (norm === "SELECT * FROM entries") return st.entries.map((e) => ({ ...e }));
    if (norm === "SELECT id, iv, data FROM entries") return st.entries.map((e) => ({ id: e.id, iv: e.iv, data: e.data }));
    if (norm === "UPDATE entries SET iv = ?, data = ? WHERE id = ?") {
      const [iv, data, id] = args;
      for (const e of st.entries) if (e.id === id) { e.iv = iv; e.data = data; }
      this._persist();
      return { changes: 1 };
    }
    if (norm === "UPDATE entries SET data = ? WHERE id = ?") {
      const [data, id] = args;
      for (const e of st.entries) if (e.id === id) e.data = data;
      this._persist();
      return { changes: 1 };
    }

    if (norm.startsWith("INSERT INTO sessions")) {
      const [token_hash, account_id, created_at, expires_at] = args;
      st.sessions = st.sessions.filter((s) => s.token_hash !== token_hash);
      st.sessions.push({ token_hash, account_id, created_at, expires_at });
      this._persist();
      return { changes: 1 };
    }
    if (norm === "SELECT account_id, created_at, expires_at FROM sessions WHERE token_hash = ?") {
      const s = st.sessions.find((x) => x.token_hash === args[0]);
      return s ? { account_id: s.account_id, created_at: s.created_at, expires_at: s.expires_at } : undefined;
    }
    if (norm === "UPDATE sessions SET expires_at = ? WHERE token_hash = ?") {
      const [expires_at, token_hash] = args;
      const s = st.sessions.find((x) => x.token_hash === token_hash);
      if (s) s.expires_at = expires_at;
      this._persist();
      return { changes: s ? 1 : 0 };
    }
    if (norm === "UPDATE sessions SET expires_at = ?") {
      for (const s of st.sessions) s.expires_at = args[0];
      this._persist();
      return { changes: st.sessions.length };
    }
    if (norm === "DELETE FROM sessions WHERE token_hash = ?") {
      st.sessions = st.sessions.filter((s) => s.token_hash !== args[0]);
      this._persist();
      return { changes: 1 };
    }
    if (norm === "DELETE FROM sessions WHERE account_id = ? AND token_hash != ?") {
      st.sessions = st.sessions.filter((s) => !(s.account_id === args[0] && s.token_hash !== args[1]));
      this._persist();
      return { changes: 1 };
    }
    if (norm.startsWith("DELETE FROM sessions WHERE account_id = ? AND token_hash NOT IN")) {
      const [accountId, , limit] = args;
      const keep = new Set(
        st.sessions
          .filter((s) => s.account_id === accountId)
          .sort((a, b) => b.created_at - a.created_at)
          .slice(0, limit)
          .map((s) => s.token_hash)
      );
      st.sessions = st.sessions.filter((s) => s.account_id !== accountId || keep.has(s.token_hash));
      this._persist();
      return { changes: 1 };
    }
    if (norm === "DELETE FROM sessions WHERE expires_at < ?") {
      st.sessions = st.sessions.filter((s) => s.expires_at >= args[0]);
      this._persist();
      return { changes: 1 };
    }
    if (norm === "DELETE FROM sessions") {
      st.sessions = [];
      this._persist();
      return { changes: 1 };
    }
    if (norm === "SELECT * FROM sessions") return st.sessions.map((s) => ({ ...s }));

    if (norm === "SELECT fails, until FROM throttle WHERE key = ?") {
      const r = st.throttle.find((t) => t.key === args[0]);
      return r ? { fails: r.fails, until: r.until } : undefined;
    }
    if (norm.startsWith("INSERT INTO throttle")) {
      const [key, fails, until, touched] = args;
      const r = st.throttle.find((t) => t.key === key);
      if (r) Object.assign(r, { fails, until, touched });
      else st.throttle.push({ key, fails, until, touched });
      this._persist();
      return { changes: 1 };
    }
    if (norm === "DELETE FROM throttle WHERE key = ?") {
      st.throttle = st.throttle.filter((t) => t.key !== args[0]);
      this._persist();
      return { changes: 1 };
    }
    if (norm === "DELETE FROM throttle WHERE touched < ?") {
      st.throttle = st.throttle.filter((t) => t.touched >= args[0]);
      this._persist();
      return { changes: 1 };
    }
    if (/^SELECT COUNT\(\*\) (AS )?n FROM throttle$/i.test(norm)) return { n: st.throttle.length };

    return mode === "all" ? [] : undefined;
  }
}

export function openDb(path = ":memory:", { production = false, requireNativeSqlite = false } = {}) {
  const needsNative = requireNativeSqlite || (production && path !== ":memory:");
  if (needsNative && !DatabaseSync) {
    throw new UnsupportedProductionRuntimeError(
      `FATAL: Production database requires Node.js >= 22.5.0 with built-in "node:sqlite" (DatabaseSync). Current runtime (${process.version}) does not provide node:sqlite. Refusing to use unsafe JSON file fallback in production.`
    );
  }
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  if (DatabaseSync) {
    const db = new DatabaseSync(path);
    db.isNativeSqlite = true;
    db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;");
    db.exec(SCHEMA);
    return db;
  }
  return new JsDatabaseSync(path);
}

/** Runs fn inside a transaction; rolls back if it throws. */
export function tx(db, fn) {
  db.exec("BEGIN IMMEDIATE");
  try { const r = fn(); db.exec("COMMIT"); return r; }
  catch (e) { db.exec("ROLLBACK"); throw e; }
}
