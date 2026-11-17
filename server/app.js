/**
 * KeyVEX server (`server/app.js`):
 *   - Serves production static assets with strict CSP (`scripts/csp.mjs`) & security headers.
 *   - B6: Marks ONLY content-hashed files under `/assets/*-[A-Za-z0-9_-]{8,}.(js|css|woff2)` as `immutable`;
 *     all other static files use `Cache-Control: no-cache`.
 *   - B9c: Logs a startup warning when `production && trustProxy === 0`.
 *   - B9e: Checks `Authorization` header / session BEFORE parsing JSON request bodies on authenticated routes.
 *   - B9f: Returns a generic credential error message on `/api/register` collision to avoid credential-pair enumeration.
 */
import http from "node:http";
import { createHash, randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { join, normalize, extname, basename, sep, resolve } from "node:path";
import { openDb, tx } from "./db.js";
import { HttpError, LIMITS, secret32, entryId, entry as checkEntry, meta as checkMeta } from "./validate.js";
import { createRateLimiter, AUTH_FREE_TRIES } from "./rateLimit.js";
import { HEADER_CSP } from "../scripts/csp.mjs";

const now = () => Date.now();
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
const scryptAsync = (pw, salt) => new Promise((ok, no) => scrypt(pw, salt, 32, { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 }, (e, k) => (e ? no(e) : ok(k))));

const SESSION_IDLE_MS = 30 * 60_000;
const SESSION_MAX_MS = 12 * 3_600_000;
const MAX_SESSIONS = 10;

const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".webmanifest": "application/manifest+json", ".woff2": "font/woff2", ".woff": "font/woff", ".png": "image/png", ".ico": "image/x-icon", ".json": "application/json; charset=utf-8", ".txt": "text/plain; charset=utf-8" };

// B6: Match content-hashed asset filenames under /assets/ (e.g. index-D8xK2a9B.js, inter-latin-wght-normal-B9f3c1D2.woff2)
export const HASHED_ASSET_RE = /-[A-Za-z0-9_-]{8,}\.(?:js|css|woff2?)$/i;

export const CSP = HEADER_CSP;

export function createApp({
  dbPath = ":memory:",
  staticDir = null,
  production = false,
  requireNativeSqlite = false,
  multiInstance = false,
  distributedRateLimitStore = null,
  trustProxy = 0,
  allowedOrigin = "",
  log = () => {}
} = {}) {
  if (production && (!Number.isInteger(trustProxy) || trustProxy === 0)) {
    log("warn", {
      code: "TRUST_PROXY_ZERO_IN_PRODUCTION",
      message: "WARNING: TRUST_PROXY is 0 in production. Behind Render/Netlify/Cloudflare, set TRUST_PROXY=1 so rate limiting uses client IPs instead of the shared proxy IP."
    });
  }

  const db = openDb(dbPath, { production, requireNativeSqlite });
  const q = {
    byLookup: db.prepare("SELECT id, auth_salt, auth_hash, meta FROM accounts WHERE lookup = ?"),
    byId: db.prepare("SELECT id, lookup, auth_salt, auth_hash, meta FROM accounts WHERE id = ?"),
    insertAccount: db.prepare("INSERT INTO accounts (lookup, auth_salt, auth_hash, meta, created_at, updated_at) VALUES (?,?,?,?,?,?)"),
    updateCreds: db.prepare("UPDATE accounts SET lookup = ?, auth_salt = ?, auth_hash = ?, meta = ?, updated_at = ? WHERE id = ?"),
    deleteAccount: db.prepare("DELETE FROM accounts WHERE id = ?"),
    entries: db.prepare("SELECT id, iv, data FROM entries WHERE account_id = ?"),
    countEntries: db.prepare("SELECT COUNT(*) AS n FROM entries WHERE account_id = ?"),
    hasEntry: db.prepare("SELECT 1 FROM entries WHERE account_id = ? AND id = ?"),
    putEntry: db.prepare("INSERT INTO entries (account_id, id, iv, data, updated_at) VALUES (?,?,?,?,?) ON CONFLICT(account_id, id) DO UPDATE SET iv = excluded.iv, data = excluded.data, updated_at = excluded.updated_at"),
    delEntry: db.prepare("DELETE FROM entries WHERE account_id = ? AND id = ?"),
    addSession: db.prepare("INSERT INTO sessions (token_hash, account_id, created_at, expires_at) VALUES (?,?,?,?)"),
    session: db.prepare("SELECT account_id, created_at, expires_at FROM sessions WHERE token_hash = ?"),
    touchSession: db.prepare("UPDATE sessions SET expires_at = ? WHERE token_hash = ?"),
    delSession: db.prepare("DELETE FROM sessions WHERE token_hash = ?"),
    countSessions: db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE account_id = ? AND expires_at >= ?"),
    delOtherSessions: db.prepare("DELETE FROM sessions WHERE account_id = ? AND token_hash != ?"),
    trimSessions: db.prepare("DELETE FROM sessions WHERE account_id = ? AND token_hash NOT IN (SELECT token_hash FROM sessions WHERE account_id = ? ORDER BY created_at DESC LIMIT ?)"),
    purgeSessions: db.prepare("DELETE FROM sessions WHERE expires_at < ?"),
    getThrottle: db.prepare("SELECT fails, until FROM throttle WHERE key = ?"),
    putThrottle: db.prepare("INSERT INTO throttle (key, fails, until, touched) VALUES (?,?,?,?) ON CONFLICT(key) DO UPDATE SET fails = excluded.fails, until = excluded.until, touched = excluded.touched"),
    delThrottle: db.prepare("DELETE FROM throttle WHERE key = ?"),
    purgeThrottle: db.prepare("DELETE FROM throttle WHERE touched < ?")
  };

  const limiter = createRateLimiter({
    q,
    production,
    multiInstance,
    distributedStore: distributedRateLimitStore,
    onAbuseEvent: (ev) => log("rate_limit", ev),
    onWarn: (w) => log("warn", w)
  });

  const dummySalt = randomBytes(16);
  const dummyHash = scryptAsync("dummy", dummySalt);

  /* ---------- helpers ---------- */
  const clientIp = (req) => {
    const validHopCount = Number.isInteger(trustProxy) && trustProxy > 0 ? trustProxy : 0;
    if (validHopCount > 0) {
      const parts = String(req.headers["x-forwarded-for"] || "")
        .split(",")
        .map((s) => s.trim())
        .filter((s) => /^[0-9a-fA-F:.,]+$/.test(s));
      if (parts.length) return parts[Math.max(0, parts.length - validHopCount)];
    }
    return req.socket.remoteAddress || "unknown";
  };

  async function checkAuth(row, auth) {
    const hash = await scryptAsync(auth, Buffer.from(row ? row.auth_salt : dummySalt.toString("hex"), "hex"));
    const stored = row ? Buffer.from(row.auth_hash, "hex") : await dummyHash;
    return timingSafeEqual(hash, stored) && !!row;
  }

  async function hashAuth(auth) {
    const salt = randomBytes(16);
    return { salt: salt.toString("hex"), hash: (await scryptAsync(auth, salt)).toString("hex") };
  }

  function newSession(accountId) {
    const token = randomBytes(32).toString("base64url");
    const t = now();
    q.addSession.run(sha256(token), accountId, t, t + SESSION_IDLE_MS);
    q.trimSessions.run(accountId, accountId, MAX_SESSIONS);
    return { token, expiresIn: Math.floor(SESSION_IDLE_MS / 1000) };
  }

  function session(req) {
    const m = /^Bearer ([A-Za-z0-9_-]{43})$/.exec(req.headers.authorization || "");
    if (!m) { req.resume(); throw new HttpError(401, "UNAUTHENTICATED", "Please sign in."); }
    const th = sha256(m[1]); const s = q.session.get(th); const t = now();
    if (!s || s.expires_at < t || s.created_at + SESSION_MAX_MS < t) {
      if (s) q.delSession.run(th);
      req.resume();
      throw new HttpError(401, "SESSION_EXPIRED", "Your session expired. Sign in again.");
    }
    q.touchSession.run(Math.min(s.created_at + SESSION_MAX_MS, t + SESSION_IDLE_MS), th);
    return { accountId: s.account_id, th };
  }

  const vaultOf = (accountId, metaText) => ({ meta: JSON.parse(metaText), entries: q.entries.all(accountId).map((r) => ({ id: r.id, iv: r.iv, data: r.data })) });

  /* ---------- API ---------- */
  async function api(req, res, path, ip) {
    const method = req.method;

    if (method === "GET" && path === "/api/health") {
      return send(res, 200, {
        ok: true,
        nativeSqlite: Boolean(db.isNativeSqlite),
        distributedRateLimit: limiter.isDistributed,
        productionReady: Boolean(db.isNativeSqlite && (limiter.isDistributed || !production))
      });
    }

    if (method === "POST" && path === "/api/register") {
      await limiter.windowLimit(`reg:${ip}`, 10, 3_600_000);
      const body = await readJson(req);
      const lookup = secret32(body?.lookup, "lookup"), auth = secret32(body?.auth, "auth"), metaText = checkMeta(body?.meta);
      const { salt, hash } = await hashAuth(auth);
      const id = tx(db, () => {
        // B9f: Generic message on registration collision
        if (q.byLookup.get(lookup)) throw new HttpError(409, "ACCOUNT_EXISTS", "Registration could not be completed. Please sign in or try again.");
        const t = now();
        return Number(q.insertAccount.run(lookup, salt, hash, metaText, t, t).lastInsertRowid);
      });
      return send(res, 201, newSession(id));
    }

    if (method === "POST" && path === "/api/login") {
      const body = await readJson(req);
      const lookup = secret32(body?.lookup, "lookup"), auth = secret32(body?.auth, "auth");
      const a = await limiter.checkLoginThrottle(ip, lookup);
      const row = q.byLookup.get(lookup);
      if (!(await checkAuth(row, auth))) {
        throw new HttpError(401, "BAD_CREDENTIALS", "Passkey or Master Password is incorrect.", {
          retryAfter: a.retryAfter,
          attemptsLeft: Math.max(0, AUTH_FREE_TRIES - a.fails)
        });
      }
      await limiter.clearLoginThrottle(ip, lookup);
      return send(res, 200, { ...newSession(row.id), ...vaultOf(row.id, row.meta) });
    }

    /* B9e: Everything below requires a valid session BEFORE parsing the request body! */
    const s = session(req);
    const needBody = method === "POST" || method === "PUT" || (method === "DELETE" && path === "/api/account");
    const body = needBody ? await readJson(req) : null;

    if (method === "POST" && path === "/api/logout") { q.delSession.run(s.th); return send(res, 204); }
    if (method === "GET" && path === "/api/sessions") {
      const activeSessions = q.countSessions.get(s.accountId, now())?.n || 1;
      return send(res, 200, { activeSessions });
    }
    if (method === "POST" && path === "/api/sessions/revoke-others") {
      if (body?.auth !== undefined) {
        const auth = secret32(body.auth, "auth");
        const row = q.byId.get(s.accountId);
        const a = await limiter.checkLoginThrottle(ip, row?.lookup || String(s.accountId));
        if (!(await checkAuth(row, auth))) throw new HttpError(401, "BAD_CREDENTIALS", "Passkey or Master Password is incorrect.", { retryAfter: a.retryAfter });
        await limiter.clearLoginThrottle(ip, row?.lookup || String(s.accountId));
      }
      const beforeCount = q.countSessions.get(s.accountId, now())?.n || 1;
      q.delOtherSessions.run(s.accountId, s.th);
      const afterCount = q.countSessions.get(s.accountId, now())?.n || 1;
      return send(res, 200, { ok: true, revoked: Math.max(0, beforeCount - afterCount), activeSessions: afterCount });
    }
    if (method === "GET" && path === "/api/vault") { const row = q.byId.get(s.accountId); return send(res, 200, vaultOf(s.accountId, row.meta)); }

    if (method === "POST" && path === "/api/entries/batch") {
      if (!Array.isArray(body?.entries) || !body.entries.length || body.entries.length > LIMITS.batch) throw new HttpError(400, "BAD_REQUEST", "Invalid batch.");
      const recs = body.entries.map(checkEntry);
      tx(db, () => {
        const fresh = recs.filter((r) => !q.hasEntry.get(s.accountId, r.id)).length;
        if (q.countEntries.get(s.accountId).n + fresh > LIMITS.entriesPerAccount) throw new HttpError(413, "TOO_MANY_ENTRIES", "This vault is full.");
        const t = now(); for (const r of recs) q.putEntry.run(s.accountId, r.id, r.iv, r.data, t);
      });
      return send(res, 200, { saved: recs.length });
    }

    const m = /^\/api\/entries\/([^/]+)$/.exec(path);
    if (m && method === "PUT") {
      const id = entryId(decodeURIComponent(m[1])); const rec = checkEntry({ ...body, id });
      tx(db, () => {
        if (!q.hasEntry.get(s.accountId, id) && q.countEntries.get(s.accountId).n >= LIMITS.entriesPerAccount) throw new HttpError(413, "TOO_MANY_ENTRIES", "This vault is full.");
        q.putEntry.run(s.accountId, id, rec.iv, rec.data, now());
      });
      return send(res, 200, { ok: true });
    }
    if (m && method === "DELETE") { q.delEntry.run(s.accountId, entryId(decodeURIComponent(m[1]))); return send(res, 204); }

    if (method === "POST" && path === "/api/account/credentials") {
      const auth = secret32(body?.auth, "auth"), lookup = secret32(body?.lookup, "lookup"), newAuth = secret32(body?.newAuth, "newAuth"), metaText = checkMeta(body?.meta);
      const row = q.byId.get(s.accountId);
      const a = await limiter.checkLoginThrottle(ip, row?.lookup || String(s.accountId));
      if (!(await checkAuth(row, auth))) throw new HttpError(401, "BAD_CREDENTIALS", "Passkey or Master Password is incorrect.", { retryAfter: a.retryAfter });
      await limiter.clearLoginThrottle(ip, row?.lookup || String(s.accountId));
      const next = await hashAuth(newAuth);
      tx(db, () => {
        const other = q.byLookup.get(lookup);
        if (other && other.id !== s.accountId) throw new HttpError(409, "ACCOUNT_EXISTS", "Unable to update credentials.");
        q.updateCreds.run(lookup, next.salt, next.hash, metaText, now(), s.accountId);
        q.delOtherSessions.run(s.accountId, s.th);
      });
      return send(res, 200, { ok: true });
    }

    if (method === "DELETE" && path === "/api/account") {
      const auth = secret32(body?.auth, "auth");
      const row = q.byId.get(s.accountId);
      const a = await limiter.checkLoginThrottle(ip, row?.lookup || String(s.accountId));
      if (!(await checkAuth(row, auth))) throw new HttpError(401, "BAD_CREDENTIALS", "Passkey or Master Password is incorrect.", { retryAfter: a.retryAfter });
      await limiter.clearLoginThrottle(ip, row?.lookup || String(s.accountId));
      q.deleteAccount.run(s.accountId);
      return send(res, 204);
    }

    throw new HttpError(404, "NOT_FOUND", "Not found.");
  }

  /* ---------- static files (production build) ---------- */
  const root = staticDir ? resolve(staticDir) : null;
  async function serveStatic(req, res, path) {
    if (!root || (req.method !== "GET" && req.method !== "HEAD")) throw new HttpError(404, "NOT_FOUND", "Not found.");
    let rel; try { rel = normalize(decodeURIComponent(path)); } catch { throw new HttpError(400, "BAD_REQUEST", "Bad path."); }
    if (rel.includes("\0")) throw new HttpError(400, "BAD_REQUEST", "Bad path.");
    let file = join(root, rel);
    if (file !== root && !file.startsWith(root + sep)) throw new HttpError(403, "FORBIDDEN", "Forbidden.");
    let info = await stat(file).catch(() => null);
    if (info?.isDirectory()) { file = join(file, "index.html"); info = await stat(file).catch(() => null); }
    if (!info) { if (extname(rel)) throw new HttpError(404, "NOT_FOUND", "Not found."); file = join(root, "index.html"); info = await stat(file).catch(() => null); if (!info) throw new HttpError(404, "NOT_FOUND", "Not found."); }
    const type = MIME[extname(file).toLowerCase()] || "application/octet-stream";
    // B6: ONLY files under /assets/ whose filename contains an 8+ char content hash get `immutable`!
    const inAssetsDir = file.includes(`${sep}assets${sep}`);
    const isHashedImmutable = inAssetsDir && HASHED_ASSET_RE.test(basename(file));
    res.writeHead(200, {
      "Content-Type": type, "Content-Length": info.size,
      "Cache-Control": isHashedImmutable ? "public, max-age=31536000, immutable" : "no-cache"
    });
    if (req.method === "HEAD") return res.end();
    res.end(await readFile(file));
  }

  /* ---------- plumbing ---------- */
  function secureHeaders(res) {
    res.setHeader("Content-Security-Policy", CSP);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    if (production) res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  }

  function send(res, status, obj, headers = {}) {
    if (res.headersSent) return;
    const text = obj === undefined ? "" : JSON.stringify(obj);
    res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...(text ? { "Content-Length": Buffer.byteLength(text) } : {}), ...headers });
    res.end(text);
  }

  function readJson(req) {
    return new Promise((ok, no) => {
      const type = String(req.headers["content-type"] || "");
      if (!/^application\/json\b/i.test(type)) { req.resume(); return no(new HttpError(415, "UNSUPPORTED", "Send JSON.")); }
      const chunks = []; let size = 0, over = false;
      req.on("data", (c) => { if (over) return; size += c.length; if (size > LIMITS.body) { over = true; chunks.length = 0; no(new HttpError(413, "TOO_LARGE", "Request too large.")); } else chunks.push(c); });
      req.on("end", () => { try { ok(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); } catch { no(new HttpError(400, "BAD_JSON", "Invalid JSON.")); } });
      req.on("error", no);
    });
  }
  const server = http.createServer(async (req, res) => {
    secureHeaders(res);
    try {
      const url = new URL(req.url, "http://x"); const path = url.pathname;
      const ip = clientIp(req);
      if (path.startsWith("/api/")) {
        await limiter.windowLimit(`api:${ip}`, 300, 60_000);
        const origin = req.headers.origin;
        if (origin && req.method !== "GET") {
          const ok = allowedOrigin ? origin === allowedOrigin : (() => { try { return new URL(origin).host === req.headers.host; } catch { return false; } })();
          if (!ok) throw new HttpError(403, "BAD_ORIGIN", "Cross-origin request refused.");
        }
        return await api(req, res, path, ip);
      }
      await limiter.windowLimit(`web:${ip}`, 600, 60_000);
      return await serveStatic(req, res, path);
    } catch (err) {
      if (err instanceof HttpError) {
        if (err.status === 413) { res.setHeader("Connection", "close"); req.resume(); }
        const headers = err.extra?.retryAfter ? { "Retry-After": String(err.extra.retryAfter) } : {};
        if (req.url?.startsWith("/api/")) return send(res, err.status, { error: err.code, message: err.message, ...err.extra }, headers);
        res.writeHead(err.status, { "Content-Type": "text/plain; charset=utf-8", ...headers }); return res.end(err.message);
      }
      log("error", err);
      return send(res, 500, { error: "SERVER_ERROR", message: "Something went wrong on our side." });
    }
  });
  server.requestTimeout = 30_000; server.headersTimeout = 15_000; server.keepAliveTimeout = 5_000;

  const janitor = setInterval(() => {
    const t = now();
    q.purgeSessions.run(t);
    q.purgeThrottle.run(t - 24 * 3_600_000);
    limiter.purgeExpired(t);
  }, 60_000);
  janitor.unref();

  return {
    server,
    db,
    limiter,
    close: () => new Promise((ok) => { clearInterval(janitor); server.close(() => { db.close(); ok(); }); server.closeAllConnections?.(); })
  };
}
