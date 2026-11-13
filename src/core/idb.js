/**
 * Browser IndexedDB storage engine for KeyVEX:
 *   1. Encrypted local cache (`v6_accounts`, `v6_entries`) for offline access.
 *   2. Layer-1 User Profile & Active Session store (`v6_users`) for Gmail / Google 2-Layer Auth,
 *      plus synchronous non-secret session routing hint (`getSyncSessionHint`) in `sessionStorage` ONLY
 *      to eliminate startup login flash without ever touching `localStorage`.
 *   3. Non-extractable AES-256-GCM device key (`wrapDeviceVaultEntropy` / `unwrapDeviceVaultEntropy`)
 *      so raw `vaultEntropy` is never stored in plaintext in IndexedDB (B1).
 *   4. Persistent per-UID Passkey lockout counter (`getPasskeyLockState`, `recordPasskeyFailure`,
 *      `clearPasskeyLockState`) with exponential lock durations surviving page reloads (B2).
 *   5. Outbox queue (`v6_sync_queue`) for offline mutations synchronized when online.
 *   6. Safe, non-destructive legacy migration (`discoverLegacyVault`, `savePreMigrationBackup`,
 *      `finalizeLegacyMigration`) with pre-migration backups (`v6_migration_backups`) and
 *      strict zero-silent-skip entry decryption.
 *
 * Security invariants:
 *   - Never uses `localStorage` for accounts, session hints, tokens, keys, or encrypted vault records.
 *   - Never persists plaintext `vaultEntropy` or `totpSecret` in IndexedDB.
 *   - Hashes `auth` proofs and account passwords with salted PBKDF2-HMAC-SHA256.
 *   - Stores only SHA-256 hashes of session tokens with 30-min idle / 12-h max expiry.
 */
import { enc, dec, rand, b64, ub64 } from "./bytes.js";
import { deriveCredentials, kdfIterations, unwrapKey, open, sameBytes } from "./crypto.js";

const DB_NAME = "keyvex";
const ACC_STORE = "v6_accounts";
const ENT_STORE = "v6_entries";
const SYNC_STORE = "v6_sync_queue";
const MIG_BACKUP_STORE = "v6_migration_backups";
const USER_STORE = "v6_users";
const SYNC_HINT_KEY = "keyvex.session_hint.v1";

const SESSION_IDLE_MS = 30 * 60_000;
const SESSION_MAX_MS = 12 * 3_600_000;
const MAX_SESSIONS = 10;

export const PASSKEY_LOCK_DURATIONS_MS = [30_000, 60_000, 300_000, 900_000, 3_600_000];

export class LegacyMigrationError extends Error {
  constructor(code, message, extra = {}) {
    super(message || code);
    this.code = code;
    Object.assign(this, extra);
  }
}

/* ---------- In-memory fallback (used ONLY when indexedDB API is absent in bare Node tests) ---------- */
const mem = {
  nextId: 1,
  nextQid: 1,
  accounts: [],
  entries: [],
  syncQueue: [],
  migrationBackups: [],
  users: new Map(), // key -> record
  activeSession: null,
  sessionHint: null, // non-secret synchronous UI hint for instant 0ms startup routing
  sessions: new Map(),
  legacySim: new Map(),
  deviceKey: null
};

function sanitizeSessionHint(session) {
  if (!session || !session.email) return null;
  const rawLen = session.pinLength ?? session.meta?.pinLength;
  const pinLen = (rawLen === 4 || rawLen === 6 || rawLen === 8 || rawLen === "strong") ? rawLen : 6;
  return {
    uid: String(session.uid || "").trim(),
    email: String(session.email || "").trim().toLowerCase(),
    name: String(session.name || session.email.split("@")[0]).trim(),
    provider: session.provider || "password",
    providers: Array.isArray(session.providers) ? [...session.providers] : [session.provider || "password"],
    hasVault: Boolean(session.hasVault || session.meta),
    pinLength: pinLen,
    emailVerified: Boolean(session.emailVerified),
    hasPassword: Boolean(session.hasPassword),
    totpEnabled: Boolean(session.totpEnabled),
    rememberDevice: Boolean(session.rememberDevice),
    hasRefreshToken: Boolean(session.refreshToken),
    tokenExpiresAt: Number(session.tokenExpiresAt) || 0,
    updatedAt: Date.now()
  };
}

/**
 * Synchronous non-secret session hint used on initial app boot (`0ms`) so returning signed-in
 * users go directly to the Passkey screen without a 1–2s Login screen flash.
 * Stored ONLY in `sessionStorage` (and in-memory); never touches `localStorage` (B15).
 */
export function setSyncSessionHint(session) {
  const hint = sanitizeSessionHint(session);
  mem.sessionHint = hint;
  try {
    if (typeof sessionStorage !== "undefined") {
      if (hint) sessionStorage.setItem(SYNC_HINT_KEY, JSON.stringify(hint));
      else sessionStorage.removeItem(SYNC_HINT_KEY);
    }
  } catch { /* ignore storage errors */ }
  try {
    // Proactively remove any legacy localStorage copy from older versions
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(SYNC_HINT_KEY);
    }
  } catch { /* ignore */ }
  return hint;
}

export function getSyncSessionHint() {
  if (mem.sessionHint && mem.sessionHint.email) {
    return { ...mem.sessionHint };
  }
  try {
    if (typeof sessionStorage !== "undefined") {
      const raw = sessionStorage.getItem(SYNC_HINT_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        const hint = sanitizeSessionHint(parsed);
        if (hint) {
          mem.sessionHint = hint;
          return { ...hint };
        }
      }
    }
  } catch {
    /* ignore */
  }
  return null;
}

function hasIdb() {
  return typeof indexedDB !== "undefined" && indexedDB !== null;
}

function reqPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error("IndexedDB request failed"));
  });
}

function txDone(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error || new Error("IndexedDB transaction aborted"));
    tx.onerror = () => reject(tx.error || new Error("IndexedDB transaction failed"));
  });
}

let dbPromise = null;

function ensureStores(db) {
  if (!db.objectStoreNames.contains(ACC_STORE)) {
    const acc = db.createObjectStore(ACC_STORE, { keyPath: "id", autoIncrement: true });
    acc.createIndex("by_lookup", "lookup", { unique: true });
  }
  if (!db.objectStoreNames.contains(ENT_STORE)) {
    const ent = db.createObjectStore(ENT_STORE, { keyPath: "pk" });
    ent.createIndex("by_account", "account_id", { unique: false });
  }
  if (!db.objectStoreNames.contains(SYNC_STORE)) {
    const sq = db.createObjectStore(SYNC_STORE, { keyPath: "qid", autoIncrement: true });
    sq.createIndex("by_lookup", "lookup", { unique: false });
  }
  if (!db.objectStoreNames.contains(MIG_BACKUP_STORE)) {
    db.createObjectStore(MIG_BACKUP_STORE, { keyPath: "backupId" });
  }
  if (!db.objectStoreNames.contains(USER_STORE)) {
    db.createObjectStore(USER_STORE, { keyPath: "key" });
  }
}

function hasAllV6Stores(db) {
  return [ACC_STORE, ENT_STORE, SYNC_STORE, MIG_BACKUP_STORE, USER_STORE].every((s) => db.objectStoreNames.contains(s));
}

export function openIdb() {
  if (!hasIdb()) return Promise.resolve(null);
  if (dbPromise) return dbPromise;

  dbPromise = (async () => {
    try {
      const initial = await new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME);
        req.onupgradeneeded = () => ensureStores(req.result);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
        req.onblocked = () => reject(new Error("IndexedDB blocked"));
      });

      if (hasAllV6Stores(initial)) {
        initial.onversionchange = () => { initial.close(); dbPromise = null; };
        return initial;
      }

      const nextVersion = (initial.version || 1) + 1;
      initial.close();

      const upgraded = await new Promise((resolve, reject) => {
        const req = indexedDB.open(DB_NAME, nextVersion);
        req.onupgradeneeded = () => ensureStores(req.result);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
        req.onblocked = () => reject(new Error("IndexedDB upgrade blocked"));
      });
      upgraded.onversionchange = () => { upgraded.close(); dbPromise = null; };
      return upgraded;
    } catch {
      dbPromise = null;
      return null;
    }
  })();

  return dbPromise;
}

/* ---------- Non-Extractable Device CryptoKey for Wrapping `vaultEntropy` (B1) ---------- */
const DEVICE_KEY_RECORD = "device_entropy_key_v1";

async function getOrCreateDeviceCryptoKey(createIfMissing = true) {
  if (mem.deviceKey) return mem.deviceKey;
  const db = await openIdb();
  if (db) {
    try {
      const tx = db.transaction(USER_STORE, "readonly");
      const rec = await reqPromise(tx.objectStore(USER_STORE).get(DEVICE_KEY_RECORD));
      if (rec?.cryptoKey) {
        mem.deviceKey = rec.cryptoKey;
        return rec.cryptoKey;
      }
    } catch { /* ignore */ }
  } else {
    const rec = mem.users.get(DEVICE_KEY_RECORD);
    if (rec?.cryptoKey) {
      mem.deviceKey = rec.cryptoKey;
      return rec.cryptoKey;
    }
  }

  if (!createIfMissing) return null;

  // Generate a non-extractable AES-256-GCM CryptoKey bound to this browser profile
  const cryptoKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  mem.deviceKey = cryptoKey;
  const record = { key: DEVICE_KEY_RECORD, cryptoKey, createdAt: Date.now() };
  mem.users.set(DEVICE_KEY_RECORD, record);

  if (db) {
    try {
      const tx = db.transaction(USER_STORE, "readwrite");
      tx.objectStore(USER_STORE).put(record);
      await txDone(tx);
    } catch {
      /* if fake-indexeddb cannot structured-clone CryptoKey, mem.deviceKey still holds it */
    }
  }
  return cryptoKey;
}

export async function wrapDeviceVaultEntropy(vaultEntropy, uid = "") {
  if (!vaultEntropy || typeof vaultEntropy !== "string") return null;
  const key = await getOrCreateDeviceCryptoKey(true);
  const iv = rand(12);
  const aad = enc.encode(`keyvex:device-entropy:${String(uid || "")}`);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    key,
    enc.encode(vaultEntropy)
  );
  return {
    iv: b64(iv),
    data: b64(new Uint8Array(ct)),
    uid: String(uid || "")
  };
}

export async function unwrapDeviceVaultEntropy(wrappedBlob, uid = "") {
  if (!wrappedBlob || typeof wrappedBlob !== "object" || !wrappedBlob.iv || !wrappedBlob.data) return null;
  const key = await getOrCreateDeviceCryptoKey(false);
  if (!key) return null;
  try {
    const aad = enc.encode(`keyvex:device-entropy:${String(wrappedBlob.uid ?? uid ?? "")}`);
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ub64(wrappedBlob.iv), additionalData: aad },
      key,
      ub64(wrappedBlob.data)
    );
    return dec.decode(pt);
  } catch {
    return null;
  }
}

export async function clearDeviceVaultEntropy(email, uid = null) {
  const prof = (email ? await getUserProfile(email) : null) || (uid ? await getUserProfileByUid(uid) : null);
  if (prof) {
    const cleaned = { ...prof, deviceVaultEntropy: null, wrappedDeviceEntropy: null };
    await saveUserProfile(cleaned);
  }
}

/* ---------- Persistent Per-UID Wrong-Passkey Lockout Counter (B2) ---------- */
function passkeyLockKey(uid) {
  return `pklock:${String(uid || "default").trim()}`;
}

export function computePasskeyLockDurationMs(fails, maxFreeFails = 5) {
  if (fails < maxFreeFails) return 0;
  const tier = Math.min(PASSKEY_LOCK_DURATIONS_MS.length - 1, Math.max(0, fails - maxFreeFails));
  return PASSKEY_LOCK_DURATIONS_MS[tier];
}

export async function getPasskeyLockState(uid, now = Date.now()) {
  const key = passkeyLockKey(uid);
  const db = await openIdb();
  let rec = null;
  if (!db) {
    rec = mem.users.get(key) || null;
  } else {
    const tx = db.transaction(USER_STORE, "readonly");
    rec = (await reqPromise(tx.objectStore(USER_STORE).get(key))) || null;
  }
  const fails = Number(rec?.fails) || 0;
  const lockedUntil = Number(rec?.lockedUntil) || 0;
  return {
    fails,
    lockedUntil,
    retryAfter: lockedUntil > now ? Math.max(1, Math.ceil((lockedUntil - now) / 1000)) : 0
  };
}

export async function recordPasskeyFailure(uid, maxFreeFails = 5, now = Date.now()) {
  const key = passkeyLockKey(uid);
  const cur = await getPasskeyLockState(uid, now);
  const fails = cur.fails + 1;
  const durationMs = computePasskeyLockDurationMs(fails, maxFreeFails);
  const lockedUntil = durationMs > 0 ? now + durationMs : cur.lockedUntil;
  const record = {
    key,
    uid: String(uid || "default").trim(),
    fails,
    lockedUntil,
    updatedAt: now
  };
  mem.users.set(key, record);
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(USER_STORE, "readwrite");
    tx.objectStore(USER_STORE).put(record);
    await txDone(tx);
  }
  return {
    fails,
    lockedUntil,
    durationMs,
    retryAfter: lockedUntil > now ? Math.max(1, Math.ceil((lockedUntil - now) / 1000)) : 0
  };
}

export async function clearPasskeyLockState(uid) {
  const key = passkeyLockKey(uid);
  mem.users.delete(key);
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(USER_STORE, "readwrite");
    tx.objectStore(USER_STORE).delete(key);
    await txDone(tx);
  }
}

/* ---------- Cryptographic Auth Proof & Session Token Hashing ---------- */
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(String(str)));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function hashSecretPBKDF2(secret, saltBytes = rand(16), iter = kdfIterations()) {
  const base = await crypto.subtle.importKey("raw", enc.encode(String(secret)), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: iter, hash: "SHA-256" },
    base,
    256
  );
  return { salt: b64(saltBytes), hash: b64(new Uint8Array(bits)), iter };
}

export async function verifySecretPBKDF2(saltB64, hashB64, iter, secret) {
  if (!saltB64 || !hashB64) return false;
  const rounds = Number(iter) || kdfIterations();
  const { hash } = await hashSecretPBKDF2(secret, ub64(saltB64), rounds);
  return sameBytes(ub64(hash), ub64(hashB64));
}

async function verifyAuthSecret(row, auth) {
  if (!row || !row.auth_salt || !row.auth_hash) return false;
  return verifySecretPBKDF2(row.auth_salt, row.auth_hash, row.auth_iter, auth);
}

function makeErr(status, code, message, extra = {}) {
  const e = new Error(message || code);
  e.status = status;
  e.code = code;
  Object.assign(e, extra);
  return e;
}

/* ---------- Layer-1 User Profile & Active Session Persistence (IndexedDB) ---------- */
export async function getUserProfile(email) {
  const norm = String(email || "").trim().toLowerCase();
  if (!norm) return null;
  const key = `user:${norm}`;
  const db = await openIdb();
  if (!db) return mem.users.get(key) || null;
  const tx = db.transaction(USER_STORE, "readonly");
  return (await reqPromise(tx.objectStore(USER_STORE).get(key))) || null;
}

export async function getUserProfileByUid(uid) {
  const cleanUid = String(uid || "").trim();
  if (!cleanUid) return null;
  const uidKey = `uid:${cleanUid}`;
  const db = await openIdb();
  if (!db) {
    const ptr = mem.users.get(uidKey);
    if (ptr?.email) return mem.users.get(`user:${ptr.email}`) || null;
    for (const [k, v] of mem.users.entries()) {
      if (k.startsWith("user:") && v?.uid === cleanUid) return v;
    }
    return null;
  }
  const tx = db.transaction(USER_STORE, "readonly");
  const store = tx.objectStore(USER_STORE);
  const ptr = await reqPromise(store.get(uidKey));
  if (ptr?.email) {
    return (await reqPromise(store.get(`user:${ptr.email}`))) || null;
  }
  const all = (await reqPromise(store.getAll())) || [];
  return all.find((r) => r?.key?.startsWith("user:") && r?.uid === cleanUid) || null;
}

export async function saveUserProfile(profile) {
  const norm = String(profile?.email || "").trim().toLowerCase();
  if (!norm) return null;
  const key = `user:${norm}`;
  const existing = await getUserProfile(norm);
  const mergedProviders = [...new Set([
    ...(Array.isArray(existing?.providers) ? existing.providers : (existing?.provider ? [existing.provider] : [])),
    ...(Array.isArray(profile?.providers) ? profile.providers : (profile?.provider ? [profile.provider] : []))
  ])].filter(Boolean);
  const cleanUid = String(profile?.uid || existing?.uid || "").trim();
  const oldUid = existing?.uid && existing.uid !== cleanUid ? existing.uid : null;

  // B1 & F5 enforcement: Never persist raw `deviceVaultEntropy`, `totpSecret`, or passkey reset tokens in IndexedDB!
  let wrappedDeviceEntropy = profile?.wrappedDeviceEntropy !== undefined
    ? profile.wrappedDeviceEntropy
    : (existing?.wrappedDeviceEntropy || null);

  if (typeof profile?.deviceVaultEntropy === "string" && profile.deviceVaultEntropy) {
    wrappedDeviceEntropy = await wrapDeviceVaultEntropy(profile.deviceVaultEntropy, cleanUid || norm);
  } else if (profile?.deviceVaultEntropy === null) {
    wrappedDeviceEntropy = null;
  }

  const record = {
    ...existing,
    ...profile,
    key,
    email: norm,
    uid: cleanUid || existing?.uid || null,
    providers: mergedProviders.length ? mergedProviders : ["password"],
    wrappedDeviceEntropy,
    updatedAt: Date.now()
  };
  delete record.deviceVaultEntropy;
  delete record.totpSecret;

  mem.users.set(key, record);
  if (oldUid) mem.users.delete(`uid:${oldUid}`);
  if (cleanUid) mem.users.set(`uid:${cleanUid}`, { key: `uid:${cleanUid}`, uid: cleanUid, email: norm, updatedAt: record.updatedAt });
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(USER_STORE, "readwrite");
    const store = tx.objectStore(USER_STORE);
    store.put(record);
    if (oldUid) store.delete(`uid:${oldUid}`);
    if (cleanUid) store.put({ key: `uid:${cleanUid}`, uid: cleanUid, email: norm, updatedAt: record.updatedAt });
    await txDone(tx);
  }
  return record;
}

export async function deleteUserProfile(email, uid = null) {
  const norm = String(email || "").trim().toLowerCase();
  const existing = norm ? await getUserProfile(norm) : null;
  const targetUid = String(uid || existing?.uid || "").trim();
  if (norm) mem.users.delete(`user:${norm}`);
  if (targetUid) {
    mem.users.delete(`uid:${targetUid}`);
    mem.users.delete(passkeyLockKey(targetUid));
  }
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(USER_STORE, "readwrite");
    const store = tx.objectStore(USER_STORE);
    if (norm) store.delete(`user:${norm}`);
    if (targetUid) {
      store.delete(`uid:${targetUid}`);
      store.delete(passkeyLockKey(targetUid));
    }
    await txDone(tx);
  }
}

export async function getActiveAccountSession() {
  const db = await openIdb();
  if (!db) return mem.activeSession;
  const tx = db.transaction(USER_STORE, "readonly");
  const rec = await reqPromise(tx.objectStore(USER_STORE).get("active_session"));
  return rec?.session || null;
}

export async function setActiveAccountSession(session) {
  let cleanSession = null;
  if (session) {
    cleanSession = { ...session };
    delete cleanSession.totpSecret;
    delete cleanSession.deviceVaultEntropy;
  }
  mem.activeSession = cleanSession;
  setSyncSessionHint(cleanSession);
  const db = await openIdb();
  if (!db) return;
  const tx = db.transaction(USER_STORE, "readwrite");
  if (cleanSession) {
    tx.objectStore(USER_STORE).put({ key: "active_session", session: cleanSession, updatedAt: Date.now() });
  } else {
    tx.objectStore(USER_STORE).delete("active_session");
  }
  await txDone(tx);
}

/* ---------- Core IndexedDB Cache & Offline Store ---------- */
export class IdbBackend {
  async #getAccountByLookup(db, lookup) {
    if (!db) return mem.accounts.find((a) => a.lookup === lookup) || null;
    const tx = db.transaction(ACC_STORE, "readonly");
    const idx = tx.objectStore(ACC_STORE).index("by_lookup");
    return (await reqPromise(idx.get(lookup))) || null;
  }

  async #getAccountById(db, id) {
    if (!db) return mem.accounts.find((a) => a.id === id) || null;
    const tx = db.transaction(ACC_STORE, "readonly");
    return (await reqPromise(tx.objectStore(ACC_STORE).get(id))) || null;
  }

  async #getEntries(db, accountId) {
    if (!db) {
      return mem.entries
        .filter((e) => e.account_id === accountId)
        .map((r) => ({ id: r.id, iv: r.iv, data: r.data, updatedAt: r.updated_at }));
    }
    const tx = db.transaction(ENT_STORE, "readonly");
    const idx = tx.objectStore(ENT_STORE).index("by_account");
    const rows = (await reqPromise(idx.getAll(accountId))) || [];
    return rows.map((r) => ({ id: r.id, iv: r.iv, data: r.data, updatedAt: r.updated_at }));
  }

  async #createSession(accountId, lookup) {
    const token = b64(rand(32));
    const th = await sha256Hex(token);
    const t = Date.now();
    mem.sessions.set(th, { accountId, lookup, createdAt: t, expiresAt: t + SESSION_IDLE_MS });
    const acctSessions = [...mem.sessions.entries()]
      .filter(([, s]) => s.accountId === accountId)
      .sort((a, b) => b[1].createdAt - a[1].createdAt);
    for (const [oldTh] of acctSessions.slice(MAX_SESSIONS)) {
      mem.sessions.delete(oldTh);
    }
    return { token, expiresIn: Math.floor(SESSION_IDLE_MS / 1000) };
  }

  async #requireSession(token) {
    if (!token) throw makeErr(401, "UNAUTHENTICATED", "Please sign in.");
    const th = await sha256Hex(token);
    const s = mem.sessions.get(th);
    const t = Date.now();
    if (!s || s.expiresAt < t || s.createdAt + SESSION_MAX_MS < t) {
      if (s) mem.sessions.delete(th);
      throw makeErr(401, "SESSION_EXPIRED", "Your session expired. Sign in again.");
    }
    s.expiresAt = Math.min(s.createdAt + SESSION_MAX_MS, t + SESSION_IDLE_MS);
    return { ...s, th };
  }

  async register({ lookup, auth, meta, synced = false }) {
    const db = await openIdb();
    const existing = await this.#getAccountByLookup(db, lookup);
    if (existing) {
      throw makeErr(409, "ACCOUNT_EXISTS", "Unable to create account with those credentials.");
    }
    const { salt, hash, iter } = await hashSecretPBKDF2(auth);
    const now = Date.now();
    const metaObj = typeof meta === "string" ? JSON.parse(meta) : meta;

    let accountId;
    if (!db) {
      accountId = mem.nextId++;
      mem.accounts.push({
        id: accountId, lookup, auth_salt: salt, auth_hash: hash, auth_iter: iter,
        meta: metaObj, synced: !!synced, created_at: now, updated_at: now
      });
    } else {
      const tx = db.transaction(ACC_STORE, "readwrite");
      accountId = await reqPromise(tx.objectStore(ACC_STORE).add({
        lookup, auth_salt: salt, auth_hash: hash, auth_iter: iter,
        meta: metaObj, synced: !!synced, created_at: now, updated_at: now
      }));
      await txDone(tx);
    }
    if (!synced) {
      await this.enqueueSync(lookup, { op: "register", lookup, auth, meta: metaObj });
    }
    return this.#createSession(Number(accountId), lookup);
  }

  async login({ lookup, auth }) {
    const db = await openIdb();
    const row = await this.#getAccountByLookup(db, lookup);
    if (!(await verifyAuthSecret(row, auth))) {
      throw makeErr(401, "BAD_CREDENTIALS", "Passkey or Master Password is incorrect.");
    }
    const entries = await this.#getEntries(db, row.id);
    const meta = typeof row.meta === "string" ? JSON.parse(row.meta) : row.meta;
    return {
      ...(await this.#createSession(row.id, lookup)),
      meta,
      entries: entries.map(({ id, iv, data }) => ({ id, iv, data }))
    };
  }

  async logout(token) {
    if (!token) return;
    const th = await sha256Hex(token);
    mem.sessions.delete(th);
  }

  async fetchVault(token) {
    const { accountId } = await this.#requireSession(token);
    const db = await openIdb();
    const row = await this.#getAccountById(db, accountId);
    if (!row) throw makeErr(401, "SESSION_EXPIRED", "Your session expired. Sign in again.");
    const entries = await this.#getEntries(db, accountId);
    const meta = typeof row.meta === "string" ? JSON.parse(row.meta) : row.meta;
    return { meta, entries: entries.map(({ id, iv, data }) => ({ id, iv, data })) };
  }

  async getVaultByLookup(lookup) {
    if (!lookup) return null;
    const db = await openIdb();
    const row = await this.#getAccountByLookup(db, lookup);
    if (!row) return null;
    const entries = await this.#getEntries(db, row.id);
    const meta = typeof row.meta === "string" ? JSON.parse(row.meta) : row.meta;
    return { meta, entries: entries.map(({ id, iv, data }) => ({ id, iv, data })) };
  }

  async putEntry(token, rec, { synced = false } = {}) {
    const { accountId, lookup } = await this.#requireSession(token);
    const db = await openIdb();
    const now = Date.now();
    const item = {
      pk: `${accountId}:${rec.id}`,
      account_id: accountId,
      id: rec.id,
      iv: rec.iv,
      data: rec.data,
      updated_at: now,
      dirty: !synced
    };
    if (!db) {
      const idx = mem.entries.findIndex((e) => e.pk === item.pk);
      if (idx >= 0) mem.entries[idx] = item;
      else mem.entries.push(item);
    } else {
      const tx = db.transaction(ENT_STORE, "readwrite");
      tx.objectStore(ENT_STORE).put(item);
      await txDone(tx);
    }
    if (!synced) {
      await this.enqueueSync(lookup, { op: "put", entry: { id: rec.id, iv: rec.iv, data: rec.data } });
    }
    return { ok: true };
  }

  async putEntries(token, entries, { synced = false } = {}) {
    const { accountId, lookup } = await this.#requireSession(token);
    const db = await openIdb();
    const now = Date.now();
    if (!db) {
      for (const rec of entries) {
        const item = {
          pk: `${accountId}:${rec.id}`,
          account_id: accountId,
          id: rec.id,
          iv: rec.iv,
          data: rec.data,
          updated_at: now,
          dirty: !synced
        };
        const idx = mem.entries.findIndex((e) => e.pk === item.pk);
        if (idx >= 0) mem.entries[idx] = item;
        else mem.entries.push(item);
      }
    } else {
      const tx = db.transaction(ENT_STORE, "readwrite");
      const store = tx.objectStore(ENT_STORE);
      for (const rec of entries) {
        store.put({
          pk: `${accountId}:${rec.id}`,
          account_id: accountId,
          id: rec.id,
          iv: rec.iv,
          data: rec.data,
          updated_at: now,
          dirty: !synced
        });
      }
      await txDone(tx);
    }
    if (!synced && entries.length) {
      await this.enqueueSync(lookup, {
        op: "batch",
        entries: entries.map((r) => ({ id: r.id, iv: r.iv, data: r.data }))
      });
    }
    return { saved: entries.length };
  }

  async deleteEntry(token, id, { synced = false } = {}) {
    const { accountId, lookup } = await this.#requireSession(token);
    const db = await openIdb();
    const pk = `${accountId}:${id}`;
    if (!db) {
      mem.entries = mem.entries.filter((e) => e.pk !== pk);
    } else {
      const tx = db.transaction(ENT_STORE, "readwrite");
      tx.objectStore(ENT_STORE).delete(pk);
      await txDone(tx);
    }
    if (!synced) {
      await this.enqueueSync(lookup, { op: "delete", entryId: id });
    }
  }

  /**
   * Direct single-entry upsert/delete in the local cache by `lookup` without re-hashing `auth` via PBKDF2
   * or rewriting the entire entry table (B10).
   */
  async upsertCachedEntryByLookup(lookup, rec, meta = null) {
    if (!lookup || !rec?.id) return;
    const db = await openIdb();
    const row = await this.#getAccountByLookup(db, lookup);
    if (!row) return;
    const now = Date.now();
    const item = {
      pk: `${row.id}:${rec.id}`,
      account_id: row.id,
      id: rec.id,
      iv: rec.iv,
      data: rec.data,
      updated_at: now,
      dirty: false
    };
    if (!db) {
      if (meta) row.meta = typeof meta === "string" ? JSON.parse(meta) : meta;
      const idx = mem.entries.findIndex((e) => e.pk === item.pk);
      if (idx >= 0) mem.entries[idx] = item;
      else mem.entries.push(item);
    } else {
      const stores = meta ? [ACC_STORE, ENT_STORE] : [ENT_STORE];
      const tx = db.transaction(stores, "readwrite");
      if (meta) {
        tx.objectStore(ACC_STORE).put({ ...row, meta: typeof meta === "string" ? JSON.parse(meta) : meta, updated_at: now });
      }
      tx.objectStore(ENT_STORE).put(item);
      await txDone(tx);
    }
  }

  async deleteCachedEntryByLookup(lookup, entryId, meta = null) {
    if (!lookup || !entryId) return;
    const db = await openIdb();
    const row = await this.#getAccountByLookup(db, lookup);
    if (!row) return;
    const pk = `${row.id}:${entryId}`;
    const now = Date.now();
    if (!db) {
      if (meta) row.meta = typeof meta === "string" ? JSON.parse(meta) : meta;
      mem.entries = mem.entries.filter((e) => e.pk !== pk);
    } else {
      const stores = meta ? [ACC_STORE, ENT_STORE] : [ENT_STORE];
      const tx = db.transaction(stores, "readwrite");
      if (meta) {
        tx.objectStore(ACC_STORE).put({ ...row, meta: typeof meta === "string" ? JSON.parse(meta) : meta, updated_at: now });
      }
      tx.objectStore(ENT_STORE).delete(pk);
      await txDone(tx);
    }
  }

  async changeCredentials(token, { auth, lookup, newAuth, meta }, { synced = false } = {}) {
    const { accountId, th, lookup: oldLookup } = await this.#requireSession(token);
    const db = await openIdb();
    const row = await this.#getAccountById(db, accountId);
    if (!(await verifyAuthSecret(row, auth))) {
      throw makeErr(401, "BAD_CREDENTIALS", "Passkey or Master Password is incorrect.");
    }
    const other = await this.#getAccountByLookup(db, lookup);
    if (other && other.id !== accountId) {
      throw makeErr(409, "ACCOUNT_EXISTS", "Unable to update credentials.");
    }
    const next = await hashSecretPBKDF2(newAuth);
    const metaObj = typeof meta === "string" ? JSON.parse(meta) : meta;
    const updated = {
      ...row,
      lookup,
      auth_salt: next.salt,
      auth_hash: next.hash,
      auth_iter: next.iter,
      meta: metaObj,
      synced: !!synced,
      updated_at: Date.now()
    };
    if (!db) {
      const idx = mem.accounts.findIndex((a) => a.id === accountId);
      if (idx >= 0) mem.accounts[idx] = updated;
    } else {
      const tx = db.transaction(ACC_STORE, "readwrite");
      tx.objectStore(ACC_STORE).put(updated);
      await txDone(tx);
    }
    for (const [k, s] of mem.sessions.entries()) {
      if (s.accountId === accountId && k !== th) mem.sessions.delete(k);
    }
    const curSession = mem.sessions.get(th);
    if (curSession) curSession.lookup = lookup;
    await this.clearSyncQueue(oldLookup);
    return { ok: true };
  }

  async deleteAccount(token, auth) {
    const { accountId, lookup } = await this.#requireSession(token);
    const db = await openIdb();
    const row = await this.#getAccountById(db, accountId);
    if (!(await verifyAuthSecret(row, auth))) {
      throw makeErr(401, "BAD_CREDENTIALS", "Passkey or Master Password is incorrect.");
    }
    await this.removeAccountByLookup(lookup);
    for (const [k, s] of mem.sessions.entries()) {
      if (s.accountId === accountId) mem.sessions.delete(k);
    }
  }

  async removeAccountByLookup(lookup) {
    const db = await openIdb();
    const row = await this.#getAccountByLookup(db, lookup);
    if (!row) return;
    const accountId = row.id;
    if (!db) {
      mem.accounts = mem.accounts.filter((a) => a.id !== accountId);
      mem.entries = mem.entries.filter((e) => e.account_id !== accountId);
    } else {
      const tx = db.transaction([ACC_STORE, ENT_STORE], "readwrite");
      tx.objectStore(ACC_STORE).delete(accountId);
      const idx = tx.objectStore(ENT_STORE).index("by_account");
      const keys = (await reqPromise(idx.getAllKeys(accountId))) || [];
      const entStore = tx.objectStore(ENT_STORE);
      for (const k of keys) entStore.delete(k);
      await txDone(tx);
    }
    await this.clearSyncQueue(lookup);
  }

  async mirrorAccount({ lookup, auth, meta, entries = [] }) {
    const db = await openIdb();
    const existing = await this.#getAccountByLookup(db, lookup);
    const metaObj = typeof meta === "string" ? JSON.parse(meta) : meta;
    const now = Date.now();
    let salt = existing?.auth_salt;
    let hash = existing?.auth_hash;
    let iter = existing?.auth_iter;
    if (!salt || !hash) {
      const h = await hashSecretPBKDF2(auth || "");
      salt = h.salt; hash = h.hash; iter = h.iter;
    }

    let accountId;
    if (!db) {
      if (existing) {
        Object.assign(existing, { auth_salt: salt, auth_hash: hash, auth_iter: iter, meta: metaObj, synced: true, updated_at: now });
        accountId = existing.id;
      } else {
        accountId = mem.nextId++;
        mem.accounts.push({
          id: accountId, lookup, auth_salt: salt, auth_hash: hash, auth_iter: iter,
          meta: metaObj, synced: true, created_at: now, updated_at: now
        });
      }
      mem.entries = mem.entries.filter((e) => e.account_id !== accountId);
      for (const rec of entries) {
        mem.entries.push({
          pk: `${accountId}:${rec.id}`,
          account_id: accountId,
          id: rec.id,
          iv: rec.iv,
          data: rec.data,
          updated_at: now,
          dirty: false
        });
      }
    } else {
      const tx = db.transaction([ACC_STORE, ENT_STORE], "readwrite");
      const accStore = tx.objectStore(ACC_STORE);
      if (existing) {
        accountId = existing.id;
        accStore.put({ ...existing, auth_salt: salt, auth_hash: hash, auth_iter: iter, meta: metaObj, synced: true, updated_at: now });
      } else {
        accountId = await reqPromise(accStore.add({
          lookup, auth_salt: salt, auth_hash: hash, auth_iter: iter,
          meta: metaObj, synced: true, created_at: now, updated_at: now
        }));
      }
      const entStore = tx.objectStore(ENT_STORE);
      const oldKeys = (await reqPromise(entStore.index("by_account").getAllKeys(accountId))) || [];
      for (const k of oldKeys) entStore.delete(k);
      for (const rec of entries) {
        entStore.put({
          pk: `${accountId}:${rec.id}`,
          account_id: accountId,
          id: rec.id,
          iv: rec.iv,
          data: rec.data,
          updated_at: now,
          dirty: false
        });
      }
      await txDone(tx);
    }
    return this.#createSession(Number(accountId), lookup);
  }

  /* ---------- Offline Outbox Sync Queue ---------- */
  async enqueueSync(lookup, item) {
    if (!lookup) return;
    const db = await openIdb();
    const record = { ...item, lookup, createdAt: Date.now() };
    if (!db) {
      mem.syncQueue.push({ ...record, qid: mem.nextQid++ });
    } else {
      const tx = db.transaction(SYNC_STORE, "readwrite");
      tx.objectStore(SYNC_STORE).add(record);
      await txDone(tx);
    }
  }

  async getSyncQueue(lookup) {
    if (!lookup) return [];
    const db = await openIdb();
    if (!db) {
      return mem.syncQueue.filter((q) => q.lookup === lookup).sort((a, b) => a.qid - b.qid);
    }
    const tx = db.transaction(SYNC_STORE, "readonly");
    const rows = (await reqPromise(tx.objectStore(SYNC_STORE).index("by_lookup").getAll(lookup))) || [];
    return rows.sort((a, b) => a.qid - b.qid);
  }

  async clearSyncQueue(lookup) {
    if (!lookup) return;
    const db = await openIdb();
    if (!db) {
      mem.syncQueue = mem.syncQueue.filter((q) => q.lookup !== lookup);
      return;
    }
    const tx = db.transaction(SYNC_STORE, "readwrite");
    const store = tx.objectStore(SYNC_STORE);
    const keys = (await reqPromise(store.index("by_lookup").getAllKeys(lookup))) || [];
    for (const k of keys) store.delete(k);
    await txDone(tx);
  }
}

/* ============================================================================
 * Safe, Non-Destructive Legacy Vault Discovery, Backup & Migration
 * ============================================================================ */

export function seedSimulatedLegacyVault(name, { meta, entries }) {
  mem.legacySim.set(name, {
    meta: JSON.parse(JSON.stringify(meta)),
    entries: JSON.parse(JSON.stringify(entries))
  });
}

export function getSimulatedLegacyVault(name) {
  return mem.legacySim.get(name) || null;
}

export function clearSimulatedLegacyVaults() {
  mem.legacySim.clear();
}

async function unlockAndVerifyV5(meta, entries, passkey, master) {
  const candidates = [];
  if (master) {
    candidates.push({ salt: meta.saltName, wrapped: meta.wrappedName, secret: "mp2:" + master });
    candidates.push({ salt: meta.saltName, wrapped: meta.wrappedName, secret: "name:" + String(master).normalize("NFKC").trim().replace(/\s+/g, " ").toLowerCase() });
    candidates.push({ salt: meta.saltName, wrapped: meta.wrappedName, secret: String(master) });
  }
  if (passkey) {
    candidates.push({ salt: meta.saltPin, wrapped: meta.wrappedPin, secret: String(passkey).trim() });
  }
  const iterations = Number(meta.kdf?.iterations) || 600_000;
  let unlockedVk = null;

  for (const c of candidates) {
    if (!c.salt || !c.wrapped || !c.secret) continue;
    try {
      const base = await crypto.subtle.importKey("raw", enc.encode(c.secret.normalize("NFKC")), "PBKDF2", false, ["deriveKey"]);
      const kek = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: ub64(c.salt), iterations, hash: "SHA-256" },
        base, { name: "AES-KW", length: 256 }, false, ["unwrapKey"]
      );
      const vk = await unwrapKey(ub64(c.wrapped), kek);
      if (meta.verifier) {
        const v = await open(vk, meta.verifier, `keyvex:${meta.vaultId}:verify:`);
        if (v?.ok !== true) continue;
      }
      unlockedVk = vk;
      break;
    } catch { /* try next candidate secret */ }
  }

  if (!unlockedVk) return null;

  const out = [];
  let failedCount = 0;
  for (let i = 0; i < entries.length; i++) {
    const r = entries[i];
    if (!r || typeof r.iv !== "string" || typeof r.data !== "string") {
      failedCount++;
      continue;
    }
    let decrypted = null;
    try {
      decrypted = await open(unlockedVk, r, `keyvex:${meta.vaultId}:entry:${r.id}`);
    } catch {
      try {
        const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ub64(r.iv) }, unlockedVk, ub64(r.data));
        decrypted = JSON.parse(dec.decode(pt));
      } catch {
        decrypted = null;
      }
    }
    if (!decrypted || typeof decrypted !== "object") {
      failedCount++;
    } else {
      out.push({
        id: r.id || decrypted.id,
        service: decrypted.service || decrypted.title || decrypted.name || "Saved Password",
        website: decrypted.website || decrypted.url || "",
        username: decrypted.username || decrypted.user || decrypted.email || "",
        password: decrypted.password || decrypted.pass || "",
        category: decrypted.category || "Other",
        notes: decrypted.notes || decrypted.note || "",
        favorite: !!decrypted.favorite,
        createdAt: decrypted.createdAt || Date.now(),
        updatedAt: decrypted.updatedAt || decrypted.createdAt || Date.now()
      });
    }
  }

  if (failedCount > 0) {
    throw new LegacyMigrationError(
      "MIGRATION_CORRUPT_ENTRY",
      `Migration aborted to prevent data loss: ${failedCount} of ${entries.length} password record(s) in your previous vault could not be decrypted. Your original vault has been preserved untouched.`,
      { failedCount, totalCount: entries.length }
    );
  }
  return out;
}

async function unlockAndVerifyKeepSafe(meta, entries, passkey, master) {
  const ROUNDS = Number(meta.iterations || meta.kdf?.iterations) || 600_000;
  const normName = (s) => String(s || "").trim().replace(/\s+/g, " ").toLowerCase();
  const candidates = [
    passkey && { salt: meta.saltPin, wrapped: meta.wrappedPin, mat: enc.encode(String(passkey).trim()) },
    master && { salt: meta.saltRec || meta.saltName, wrapped: meta.wrappedRec || meta.wrappedName, mat: enc.encode(normName(master)) },
    master && { salt: meta.saltRec || meta.saltName, wrapped: meta.wrappedRec || meta.wrappedName, mat: enc.encode(String(master)) }
  ].filter(Boolean);

  let unlockedVk = null;
  for (const c of candidates) {
    if (!c.salt || !c.wrapped) continue;
    try {
      const base = await crypto.subtle.importKey("raw", c.mat, "PBKDF2", false, ["deriveKey"]);
      const kek = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: ub64(c.salt), iterations: ROUNDS, hash: "SHA-256" },
        base, { name: "AES-KW", length: 256 }, false, ["unwrapKey"]
      );
      const vk = await crypto.subtle.unwrapKey("raw", ub64(c.wrapped), kek, "AES-KW", { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
      if (meta.verifier?.iv && meta.verifier?.data) {
        const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ub64(meta.verifier.iv) }, vk, ub64(meta.verifier.data));
        const txt = dec.decode(pt);
        if (txt !== "keep-safe-vault-ok" && !txt.includes("ok")) continue;
      }
      unlockedVk = vk;
      break;
    } catch { /* try next candidate */ }
  }

  if (!unlockedVk) return null;

  const out = [];
  let failedCount = 0;
  for (let i = 0; i < entries.length; i++) {
    const r = entries[i];
    if (!r || typeof r.iv !== "string" || typeof r.data !== "string") {
      failedCount++;
      continue;
    }
    try {
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ub64(r.iv) }, unlockedVk, ub64(r.data));
      const e = JSON.parse(dec.decode(pt));
      out.push({
        id: r.id || e.id,
        service: e.service || e.title || e.name || "Saved Password",
        website: e.website || e.url || "",
        username: e.username || e.user || e.email || "",
        password: e.password || e.pass || "",
        category: e.category || "Other",
        notes: e.notes || e.note || "",
        favorite: !!e.favorite,
        createdAt: e.createdAt || Date.now(),
        updatedAt: e.updatedAt || e.createdAt || Date.now()
      });
    } catch {
      failedCount++;
    }
  }

  if (failedCount > 0) {
    throw new LegacyMigrationError(
      "MIGRATION_CORRUPT_ENTRY",
      `Migration aborted to prevent data loss: ${failedCount} of ${entries.length} password record(s) in your legacy vault could not be decrypted. Your original vault has been preserved untouched.`,
      { failedCount, totalCount: entries.length }
    );
  }
  return out;
}

async function unlockAndVerifySingleV6(meta, entries, passkey, master) {
  let unlockedVk = null;
  try {
    const creds = await deriveCredentials(passkey, master, meta?.kdf?.salt ? { salt: meta.kdf.salt } : {});
    const vk = await unwrapKey(ub64(meta.wrapped), creds.kek, false);
    const v = await open(vk, meta.verifier, `keyvex:${meta.vaultId}:verify:`);
    if (v?.ok === true) unlockedVk = vk;
  } catch {
    unlockedVk = null;
  }
  if (!unlockedVk) return null;

  const out = [];
  let failedCount = 0;
  for (let i = 0; i < entries.length; i++) {
    const r = entries[i];
    if (!r || typeof r.iv !== "string" || typeof r.data !== "string") {
      failedCount++;
      continue;
    }
    try {
      const item = await open(unlockedVk, r, `keyvex:${meta.vaultId}:entry:${r.id}`);
      out.push({ ...item, id: r.id || item.id });
    } catch {
      failedCount++;
    }
  }

  if (failedCount > 0) {
    throw new LegacyMigrationError(
      "MIGRATION_CORRUPT_ENTRY",
      `Migration aborted to prevent data loss: ${failedCount} of ${entries.length} password record(s) could not be decrypted. Your original vault has been preserved untouched.`,
      { failedCount, totalCount: entries.length }
    );
  }
  return out;
}

async function tryUnlockCandidate(m, entries, passkey, master) {
  if (m.format === 6 && m.wrapped) {
    return unlockAndVerifySingleV6(m, entries, passkey, master);
  }
  if (m.format === 5 || m.wrappedName || m.saltName) {
    return unlockAndVerifyV5(m, entries, passkey, master);
  }
  if (m.wrappedPin || m.wrappedRec) {
    return unlockAndVerifyKeepSafe(m, entries, passkey, master);
  }
  return null;
}

const RESERVED_STORES = new Set([ACC_STORE, ENT_STORE, SYNC_STORE, MIG_BACKUP_STORE, USER_STORE]);

async function inspectDatabaseNonDestructive(dbName, passkey, master) {
  let db;
  try {
    db = await new Promise((resolve, reject) => {
      const req = indexedDB.open(dbName);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error("blocked"));
    });
  } catch {
    return null;
  }

  try {
    const names = [...db.objectStoreNames];
    const metaCandidates = [];
    const entryCandidates = [];
    const entryStores = [];

    for (const storeName of names) {
      if (RESERVED_STORES.has(storeName)) continue;
      try {
        const tx = db.transaction(storeName, "readonly");
        const all = (await reqPromise(tx.objectStore(storeName).getAll())) || [];
        for (const item of all) {
          if (!item || typeof item !== "object" || item.migratedToV6) continue;
          const m = item.meta && typeof item.meta === "object" ? item.meta : item;
          if (m.wrapped || m.wrappedPin || m.wrappedName || m.wrappedRec || m.format === 5 || m.format === 6) {
            metaCandidates.push({
              storeName,
              rawMetaRecord: item,
              meta: m,
              embeddedEntries: Array.isArray(item.entries) ? item.entries : null
            });
          } else if (item.iv && item.data) {
            entryCandidates.push(item);
            if (!entryStores.includes(storeName)) entryStores.push(storeName);
          }
        }
      } catch { /* skip unreadable store */ }
    }

    for (const cand of metaCandidates) {
      const rawEntries = cand.embeddedEntries || entryCandidates;
      const items = await tryUnlockCandidate(cand.meta, rawEntries, passkey, master);
      if (items !== null) {
        return {
          kind: "idb",
          dbName,
          metaStore: cand.storeName,
          entryStores: cand.embeddedEntries ? [] : entryStores,
          vaultId: cand.meta.vaultId || "legacy",
          rawMeta: cand.rawMetaRecord,
          rawEntries,
          items
        };
      }
    }
  } finally {
    try { db.close(); } catch { /* ignore */ }
  }
  return null;
}

export async function discoverLegacyVault(passkey, master) {
  for (const [simName, sim] of mem.legacySim.entries()) {
    if (sim.migratedToV6) continue;
    const m = sim.meta?.meta || sim.meta;
    const rawEntries = Array.isArray(sim.entries) ? sim.entries : (Array.isArray(sim.meta?.entries) ? sim.meta.entries : []);
    const items = await tryUnlockCandidate(m, rawEntries, passkey, master);
    if (items !== null) {
      return {
        kind: "sim",
        simName,
        vaultId: m.vaultId || simName,
        rawMeta: sim.meta,
        rawEntries,
        items
      };
    }
  }

  if (!hasIdb()) return null;
  const dbNames = new Set(["keyvex", "keep-safe", "keyvex-vault", "keyvex-db", "keyvex_vault"]);
  try {
    if (typeof indexedDB.databases === "function") {
      const list = await indexedDB.databases();
      for (const d of list || []) if (d?.name) dbNames.add(d.name);
    }
  } catch { /* ignore */ }

  for (const name of dbNames) {
    const found = await inspectDatabaseNonDestructive(name, passkey, master);
    if (found) return found;
  }
  return null;
}

export async function savePreMigrationBackup(legacy) {
  const backupId = `mig_${legacy.vaultId || "legacy"}_${Date.now()}`;
  const record = {
    backupId,
    vaultId: legacy.vaultId || "legacy",
    createdAt: Date.now(),
    source: legacy.kind === "idb" ? `${legacy.dbName}:${legacy.metaStore}` : `sim:${legacy.simName}`,
    rawMeta: JSON.parse(JSON.stringify(legacy.rawMeta)),
    rawEntries: JSON.parse(JSON.stringify(legacy.rawEntries))
  };
  mem.migrationBackups.push(record);
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(MIG_BACKUP_STORE, "readwrite");
    tx.objectStore(MIG_BACKUP_STORE).put(record);
    await txDone(tx);
  }
  return backupId;
}

export async function getPreMigrationBackups() {
  const db = await openIdb();
  if (!db) return [...mem.migrationBackups];
  const tx = db.transaction(MIG_BACKUP_STORE, "readonly");
  return (await reqPromise(tx.objectStore(MIG_BACKUP_STORE).getAll())) || [];
}

export async function finalizeLegacyMigration(legacy) {
  if (!legacy) return;
  if (legacy.kind === "sim") {
    const sim = mem.legacySim.get(legacy.simName);
    if (sim) sim.migratedToV6 = true;
    return;
  }
  if (legacy.kind === "idb" && hasIdb()) {
    try {
      const db = await new Promise((resolve, reject) => {
        const req = indexedDB.open(legacy.dbName);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
        req.onblocked = () => reject(new Error("blocked"));
      });
      try {
        const stores = [legacy.metaStore, ...(legacy.entryStores || [])].filter((s) => db.objectStoreNames.contains(s));
        if (stores.length) {
          const tx = db.transaction(stores, "readwrite");
          for (const s of stores) tx.objectStore(s).clear();
          await txDone(tx);
        }
      } finally {
        db.close();
      }
    } catch { /* original data already backed up in v6_migration_backups */ }
  }
}

export async function resetLocalVaultStorage() {
  mem.accounts = [];
  mem.entries = [];
  mem.syncQueue = [];
  mem.migrationBackups = [];
  mem.users.clear();
  mem.activeSession = null;
  mem.deviceKey = null;
  setSyncSessionHint(null);
  mem.sessions.clear();
  mem.legacySim.clear();
  if (!hasIdb()) return;
  try {
    const db = await openIdb();
    if (db) {
      const stores = [ACC_STORE, ENT_STORE, SYNC_STORE, MIG_BACKUP_STORE, USER_STORE].filter((s) => db.objectStoreNames.contains(s));
      if (stores.length) {
        const tx = db.transaction(stores, "readwrite");
        for (const s of stores) tx.objectStore(s).clear();
        await txDone(tx);
      }
    }
  } catch { /* ignore */ }
}

/**
 * Inspects all records in IndexedDB `v6_users` and in-memory fallback (for tests verifying B1/F5).
 */
export async function getAllUserStoreRecordsForTest() {
  const db = await openIdb();
  if (!db) {
    return [...mem.users.values()];
  }
  const tx = db.transaction(USER_STORE, "readonly");
  return (await reqPromise(tx.objectStore(USER_STORE).getAll())) || [];
}

/* ============================================================================
 * Durable Cloud Outbox, Tombstones, Conflict Store & Account Deletion Jobs
 * ============================================================================ */

export async function computeCiphertextHash(iv, data) {
  if (!iv || !data) return "";
  return sha256Hex(`${iv}:${data}`);
}

function outboxKey(uid) {
  return `outbox:${String(uid || "").trim()}`;
}

export async function getCloudOutbox(uid) {
  const cleanUid = String(uid || "").trim();
  if (!cleanUid) return [];
  const key = outboxKey(cleanUid);
  const db = await openIdb();
  let rec;
  if (!db) {
    rec = mem.users.get(key);
  } else {
    const tx = db.transaction(USER_STORE, "readonly");
    rec = await reqPromise(tx.objectStore(USER_STORE).get(key));
  }
  return Array.isArray(rec?.items) ? rec.items.map((x) => ({ ...x })) : [];
}

async function saveCloudOutboxList(uid, items) {
  const cleanUid = String(uid || "").trim();
  if (!cleanUid) return;
  const key = outboxKey(cleanUid);
  const record = { key, uid: cleanUid, items, updatedAt: Date.now() };
  mem.users.set(key, record);
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(USER_STORE, "readwrite");
    tx.objectStore(USER_STORE).put(record);
    await txDone(tx);
  }
}

/**
 * Enqueues a durable cloud mutation (upsert, delete tombstone, or meta update).
 * Preserves the original baseHash/baseRev when coalescing multiple offline edits to the same entry.
 */
export async function enqueueCloudOutbox(uid, opInput) {
  const cleanUid = String(uid || "").trim();
  if (!cleanUid) return null;
  const items = await getCloudOutbox(cleanUid);
  const now = Date.now();
  const opId = opInput.opId || `op_${now}_${b64(rand(6))}`;

  if (opInput.op === "meta") {
    const filtered = items.filter((i) => i.op !== "meta");
    const item = {
      opId,
      uid: cleanUid,
      op: "meta",
      meta: opInput.meta,
      attempts: 0,
      lastError: null,
      createdAt: now,
      updatedAt: now
    };
    filtered.push(item);
    await saveCloudOutboxList(cleanUid, filtered);
    return item;
  }

  const entryId = String(opInput.entryId || opInput.record?.id || "");
  const existingIdx = items.findIndex((i) => i.entryId === entryId && (i.op === "upsert" || i.op === "delete"));
  const existing = existingIdx >= 0 ? items[existingIdx] : null;

  // Preserve the baseHash and baseRev from before the first unacknowledged local edit
  const baseRev = existing ? existing.baseRev : (Number(opInput.baseRev) || 0);
  const baseHash = existing ? existing.baseHash : String(opInput.baseHash || "");

  const nextItem = {
    opId,
    uid: cleanUid,
    op: opInput.op, // "upsert" | "delete"
    entryId,
    tombstone: opInput.op === "delete",
    record: opInput.op === "upsert" ? { ...opInput.record } : null,
    baseRev,
    baseHash,
    deletedRev: opInput.op === "delete" ? (Number(opInput.deletedRev) || baseRev + 1) : null,
    deletedAt: opInput.op === "delete" ? (Number(opInput.deletedAt) || now) : null,
    attempts: 0,
    lastError: null,
    createdAt: existing?.createdAt || now,
    updatedAt: now
  };

  if (existingIdx >= 0) {
    items[existingIdx] = nextItem;
  } else {
    items.push(nextItem);
  }
  await saveCloudOutboxList(cleanUid, items);
  return nextItem;
}

export async function ackCloudOutbox(uid, opId) {
  const cleanUid = String(uid || "").trim();
  if (!cleanUid || !opId) return;
  const items = await getCloudOutbox(cleanUid);
  const next = items.filter((i) => i.opId !== opId);
  await saveCloudOutboxList(cleanUid, next);
}

export async function updateCloudOutboxAttempt(uid, opId, errCode) {
  const cleanUid = String(uid || "").trim();
  if (!cleanUid || !opId) return;
  const items = await getCloudOutbox(cleanUid);
  const target = items.find((i) => i.opId === opId);
  if (target) {
    target.attempts = (target.attempts || 0) + 1;
    target.lastError = String(errCode || "SYNC_ERROR");
    target.updatedAt = Date.now();
    await saveCloudOutboxList(cleanUid, items);
  }
}

export async function clearCloudOutbox(uid) {
  const cleanUid = String(uid || "").trim();
  if (!cleanUid) return;
  const key = outboxKey(cleanUid);
  mem.users.delete(key);
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(USER_STORE, "readwrite");
    tx.objectStore(USER_STORE).delete(key);
    await txDone(tx);
  }
}

export async function getPendingTombstones(uid) {
  const items = await getCloudOutbox(uid);
  const map = new Map();
  for (const item of items) {
    if (item.op === "delete" && item.entryId) {
      map.set(item.entryId, item);
    }
  }
  return map;
}

/* ---------- Deterministic Conflict Preservation Store ---------- */
function conflictStoreKey(uid) {
  return `conflicts:${String(uid || "").trim()}`;
}

export async function getSyncConflicts(uid) {
  const cleanUid = String(uid || "").trim();
  if (!cleanUid) return [];
  const key = conflictStoreKey(cleanUid);
  const db = await openIdb();
  let rec;
  if (!db) {
    rec = mem.users.get(key);
  } else {
    const tx = db.transaction(USER_STORE, "readonly");
    rec = await reqPromise(tx.objectStore(USER_STORE).get(key));
  }
  return Array.isArray(rec?.conflicts) ? rec.conflicts.map((c) => ({ ...c })) : [];
}

export async function saveSyncConflict(uid, conflict) {
  const cleanUid = String(uid || "").trim();
  if (!cleanUid || !conflict?.entryId) return null;
  const list = await getSyncConflicts(cleanUid);
  const existingIdx = list.findIndex((c) => c.entryId === conflict.entryId);
  const record = {
    conflictId: conflict.conflictId || `conf_${conflict.entryId}_${Date.now()}`,
    uid: cleanUid,
    entryId: conflict.entryId,
    reason: conflict.reason || "concurrent_modification",
    localRecord: conflict.localRecord || null,
    remoteRecord: conflict.remoteRecord || null,
    detectedAt: Date.now()
  };
  if (existingIdx >= 0) list[existingIdx] = record;
  else list.push(record);

  const key = conflictStoreKey(cleanUid);
  const wrapper = { key, uid: cleanUid, conflicts: list, updatedAt: Date.now() };
  mem.users.set(key, wrapper);
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(USER_STORE, "readwrite");
    tx.objectStore(USER_STORE).put(wrapper);
    await txDone(tx);
  }
  return record;
}

export async function resolveSyncConflictRecord(uid, entryId) {
  const cleanUid = String(uid || "").trim();
  if (!cleanUid || !entryId) return;
  const list = (await getSyncConflicts(cleanUid)).filter((c) => c.entryId !== entryId);
  const key = conflictStoreKey(cleanUid);
  const wrapper = { key, uid: cleanUid, conflicts: list, updatedAt: Date.now() };
  mem.users.set(key, wrapper);
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(USER_STORE, "readwrite");
    tx.objectStore(USER_STORE).put(wrapper);
    await txDone(tx);
  }
}

/* ---------- Durable Account Deletion Job Store ---------- */
function deletionJobKey(uid) {
  return `deljob:${String(uid || "").trim()}`;
}

export async function getDeletionJob(uid) {
  const cleanUid = String(uid || "").trim();
  if (!cleanUid) return null;
  const key = deletionJobKey(cleanUid);
  const db = await openIdb();
  if (!db) return mem.users.get(key) || null;
  const tx = db.transaction(USER_STORE, "readonly");
  return (await reqPromise(tx.objectStore(USER_STORE).get(key))) || null;
}

export async function saveDeletionJob(job) {
  const cleanUid = String(job?.uid || "").trim();
  if (!cleanUid) return null;
  const key = deletionJobKey(cleanUid);
  const record = {
    ...job,
    key,
    uid: cleanUid,
    updatedAt: Date.now()
  };
  mem.users.set(key, record);
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(USER_STORE, "readwrite");
    tx.objectStore(USER_STORE).put(record);
    await txDone(tx);
  }
  return record;
}

export async function clearDeletionJob(uid) {
  const cleanUid = String(uid || "").trim();
  if (!cleanUid) return;
  const key = deletionJobKey(cleanUid);
  mem.users.delete(key);
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(USER_STORE, "readwrite");
    tx.objectStore(USER_STORE).delete(key);
    await txDone(tx);
  }
}

/* ---------- Encrypted Generator History & Separate External Imports Stores ---------- */
function genHistoryKey(ownerKey) {
  return `genhist:${String(ownerKey || "default").trim()}`;
}

export async function getEncryptedGeneratorHistory(ownerKey) {
  const key = genHistoryKey(ownerKey);
  const db = await openIdb();
  let rec;
  if (!db) {
    rec = mem.users.get(key);
  } else {
    const tx = db.transaction(USER_STORE, "readonly");
    rec = await reqPromise(tx.objectStore(USER_STORE).get(key));
  }
  return Array.isArray(rec?.records) ? rec.records.map((r) => ({ ...r })) : [];
}

export async function saveEncryptedGeneratorHistory(ownerKey, records = []) {
  const key = genHistoryKey(ownerKey);
  const wrapper = {
    key,
    ownerKey: String(ownerKey || "default").trim(),
    records: Array.isArray(records) ? records.map((r) => ({ ...r })) : [],
    updatedAt: Date.now()
  };
  mem.users.set(key, wrapper);
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(USER_STORE, "readwrite");
    tx.objectStore(USER_STORE).put(wrapper);
    await txDone(tx);
  }
  return wrapper.records;
}

function externalImportsKey(ownerKey) {
  return `extimp:${String(ownerKey || "default").trim()}`;
}

export async function getEncryptedExternalImports(ownerKey) {
  const key = externalImportsKey(ownerKey);
  const db = await openIdb();
  let rec;
  if (!db) {
    rec = mem.users.get(key);
  } else {
    const tx = db.transaction(USER_STORE, "readonly");
    rec = await reqPromise(tx.objectStore(USER_STORE).get(key));
  }
  return Array.isArray(rec?.records) ? rec.records.map((r) => ({ ...r })) : [];
}

export async function saveEncryptedExternalImports(ownerKey, records = []) {
  const key = externalImportsKey(ownerKey);
  const wrapper = {
    key,
    ownerKey: String(ownerKey || "default").trim(),
    records: Array.isArray(records) ? records.map((r) => ({ ...r })) : [],
    updatedAt: Date.now()
  };
  mem.users.set(key, wrapper);
  const db = await openIdb();
  if (db) {
    const tx = db.transaction(USER_STORE, "readwrite");
    tx.objectStore(USER_STORE).put(wrapper);
    await txDone(tx);
  }
  return wrapper.records;
}
