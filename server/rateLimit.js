/**
 * Distributed & Layered Rate-Limit Adapter for KeyVEX (`server/rateLimit.js`).
 *
 * B9 Repairs:
 *   a) Atomic Redis operations: `incrThrottle` uses atomic `EVAL` Lua script (or atomic `INCR` + `PEXPIRE`)
 *      instead of non-atomic GET -> compute -> SET so parallel guesses across instances can never beat the counter.
 *   b) Per-IP lockout uses `IP_FREE_TRIES = 25` while per-account lookup uses `AUTH_FREE_TRIES = 5`, so shared
 *      NAT/office users do not lock each other out after 5 tries.
 *   c) Outage handling: `windowLimit` fails open with a logged warning if Redis throws; `checkLoginThrottle` /
 *      `countAttempt` fails closed with HTTP 503 `SERVICE_UNAVAILABLE` if Redis throws.
 */
import { createHash } from "node:crypto";
import { HttpError } from "./validate.js";

const sha256Hex = (s) => createHash("sha256").update(String(s)).digest("hex");

export const AUTH_FREE_TRIES = 5;
export const IP_FREE_TRIES = 25;
export const lockMs = (fails, freeTries = AUTH_FREE_TRIES) =>
  fails < freeTries ? 0 : Math.min(3_600_000, 30_000 * (2 ** Math.min(8, fails - freeTries)));

const LUA_ATOMIC_THROTTLE = `
local k = KEYS[1]
local now = tonumber(ARGV[1])
local freeTries = tonumber(ARGV[2])
local raw = redis.call("GET", k)
local fails = 0
local untilMs = 0
if raw then
  local obj = cjson.decode(raw)
  fails = tonumber(obj.fails) or 0
  untilMs = tonumber(obj.until) or 0
end
if untilMs > now then
  return {fails, untilMs, 1}
end
fails = fails + 1
local lockDuration = 0
if fails >= freeTries then
  local exp = math.min(8, fails - freeTries)
  lockDuration = math.min(3600000, 30000 * (2 ^ exp))
end
untilMs = now + lockDuration
local ttl = math.max(60000, lockDuration + 3600000)
redis.call("SET", k, cjson.encode({fails = fails, ["until"] = untilMs, touched = now}), "PX", ttl)
return {fails, untilMs, 0}
`;

export class RedisRestRateLimitStore {
  constructor({ url, token, fetchFn = fetch } = {}) {
    if (!url) throw new Error("RedisRestRateLimitStore requires a valid Redis URL.");
    this.url = String(url).replace(/\/$/, "");
    this.token = token || "";
    this.fetchFn = fetchFn;
    this.distributed = true;
  }

  async #cmd(command) {
    const res = await this.fetchFn(this.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(this.token ? { Authorization: `Bearer ${this.token}` } : {})
      },
      body: JSON.stringify(command)
    });
    if (!res.ok) throw new Error(`Redis rate-limit store error: HTTP ${res.status}`);
    const data = await res.json();
    return data.result;
  }

  async incrWindow(key, windowMs) {
    const now = Date.now();
    const bucket = Math.floor(now / windowMs);
    const rKey = `kvx:win:${key}:${bucket}`;
    const count = Number(await this.#cmd(["INCR", rKey])) || 1;
    if (count === 1) {
      await this.#cmd(["PEXPIRE", rKey, String(windowMs * 2)]).catch(() => {});
    }
    return { count, resetAt: (bucket + 1) * windowMs };
  }

  /**
   * Atomic credential-guess increment via Redis EVAL Lua script (or atomic INCR + PEXPIRE fallback).
   */
  async incrThrottle(key, freeTries = AUTH_FREE_TRIES, now = Date.now()) {
    const rKey = `kvx:thr:${key}`;
    try {
      const res = await this.#cmd(["EVAL", LUA_ATOMIC_THROTTLE, "1", rKey, String(now), String(freeTries)]);
      if (Array.isArray(res) && res.length >= 3) {
        return {
          fails: Number(res[0]) || 1,
          until: Number(res[1]) || 0,
          locked: Number(res[2]) === 1
        };
      }
    } catch {
      /* Fall back to atomic INCR + PEXPIRE when EVAL is not supported by minimal REST proxy */
    }
    const lockKey = `${rKey}:until`;
    const lockedUntil = Number(await this.#cmd(["GET", lockKey])) || 0;
    if (lockedUntil > now) {
      return { fails: freeTries + 1, until: lockedUntil, locked: true };
    }
    const fails = Number(await this.#cmd(["INCR", `${rKey}:fails`])) || 1;
    await this.#cmd(["PEXPIRE", `${rKey}:fails`, "3600000"]).catch(() => {});
    const duration = lockMs(fails, freeTries);
    const until = duration > 0 ? now + duration : 0;
    if (duration > 0) {
      await this.#cmd(["SET", lockKey, String(until), "PX", String(duration)]).catch(() => {});
    }
    return { fails, until, locked: false };
  }

  async getThrottle(key) {
    const raw = await this.#cmd(["GET", `kvx:thr:${key}`]);
    if (!raw) return { fails: 0, until: 0 };
    try { return typeof raw === "string" ? JSON.parse(raw) : raw; } catch { return { fails: 0, until: 0 }; }
  }

  async putThrottle(key, fails, until, touched) {
    const ttlMs = Math.max(60_000, (until - touched) + 3_600_000);
    await this.#cmd(["SET", `kvx:thr:${key}`, JSON.stringify({ fails, until, touched }), "PX", String(ttlMs)]);
  }

  async delThrottle(key) {
    await this.#cmd(["DEL", `kvx:thr:${key}`, `kvx:thr:${key}:fails`, `kvx:thr:${key}:until`]);
  }
}

export function createRateLimiter({
  q,
  production = false,
  multiInstance = process.env.MULTI_INSTANCE === "true",
  distributedStore = null,
  onAbuseEvent = null,
  onWarn = null
} = {}) {
  const redisUrl = process.env.REDIS_REST_URL || process.env.UPSTASH_REDIS_REST_URL || "";
  const redisToken = process.env.REDIS_REST_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || "";

  let store = distributedStore;
  if (!store && redisUrl) {
    store = new RedisRestRateLimitStore({ url: redisUrl, token: redisToken });
  }

  if (production && multiInstance && !store) {
    throw new Error(
      "FATAL: MULTI_INSTANCE production mode requires a distributed rate-limit store (REDIS_REST_URL or distributedStore). Refusing to fall back to process-local rate limiting."
    );
  }

  const isDistributed = Boolean(store?.distributed);
  const windows = new Map();
  const telemetry = [];
  const MAX_TELEMETRY = 200;
  // Per-key serialization queue for injected stores that only implement getThrottle/putThrottle
  const keyLocks = new Map();

  function normalizeThrottleKey(key) {
    return `auth:${sha256Hex(key).slice(0, 32)}`;
  }

  function recordAbuse(event) {
    const safeEvent = {
      type: event.type,
      reason: event.reason,
      keyHash: sha256Hex(event.key || "unknown").slice(0, 16),
      retryAfter: event.retryAfter || 0,
      timestamp: Date.now()
    };
    telemetry.push(safeEvent);
    if (telemetry.length > MAX_TELEMETRY) telemetry.shift();
    onAbuseEvent?.(safeEvent);
  }

  function windowLimitSync(key, limit, ms) {
    const t = Date.now();
    const w = windows.get(key);
    if (!w || w.reset <= t) {
      windows.set(key, { n: 1, reset: t + ms });
      return;
    }
    if (++w.n > limit) {
      const retryAfter = Math.ceil((w.reset - t) / 1000);
      recordAbuse({ type: "window_limit", reason: "RATE_LIMITED", key, retryAfter });
      throw new HttpError(429, "RATE_LIMITED", "Too many requests. Slow down.", { retryAfter });
    }
  }

  /**
   * B9d: Window limiter fails OPEN with a warning if the distributed store throws an outage error.
   */
  async function windowLimit(key, limit, ms) {
    if (store?.incrWindow) {
      let res;
      try {
        res = await store.incrWindow(key, ms);
      } catch (storeErr) {
        onWarn?.({ type: "redis_window_outage", message: storeErr?.message || "Window limiter store unavailable; failing open." });
        return;
      }
      if (res.count > limit) {
        const retryAfter = Math.max(1, Math.ceil((res.resetAt - Date.now()) / 1000));
        recordAbuse({ type: "window_limit", reason: "RATE_LIMITED", key, retryAfter });
        throw new HttpError(429, "RATE_LIMITED", "Too many requests. Slow down.", { retryAfter });
      }
      return;
    }
    windowLimitSync(key, limit, ms);
  }

  function countAttemptSync(key, freeTries = AUTH_FREE_TRIES) {
    const t = Date.now();
    const hashedKey = normalizeThrottleKey(key);
    const row = q.getThrottle.get(hashedKey) || { fails: 0, until: 0 };
    if (row.until > t) {
      const retryAfter = Math.ceil((row.until - t) / 1000);
      recordAbuse({ type: "auth_lockout", reason: "LOCKED_OUT", key: hashedKey, retryAfter });
      throw new HttpError(429, "LOCKED_OUT", "Too many attempts. Try again later.", { retryAfter });
    }
    const fails = row.fails + 1;
    const lockDuration = lockMs(fails, freeTries);
    q.putThrottle.run(hashedKey, fails, t + lockDuration, t);
    if (lockDuration > 0) {
      recordAbuse({ type: "auth_lockout_triggered", reason: "BAD_CREDENTIALS_THRESHOLD", key: hashedKey, retryAfter: Math.ceil(lockDuration / 1000) });
    }
    return { fails, retryAfter: Math.ceil(lockDuration / 1000), hashedKey };
  }

  function clearAttemptsSync(key) {
    const hashedKey = normalizeThrottleKey(key);
    q.delThrottle.run(hashedKey);
  }

  async function withSerializedKey(hashedKey, fn) {
    const prev = keyLocks.get(hashedKey) || Promise.resolve();
    let release;
    const next = new Promise((r) => { release = r; });
    keyLocks.set(hashedKey, prev.then(() => next));
    await prev;
    try {
      return await fn();
    } finally {
      release();
      if (keyLocks.get(hashedKey) === next) keyLocks.delete(hashedKey);
    }
  }

  /**
   * B9a & B9d: Atomic distributed credential-guess throttle; fails CLOSED with HTTP 503 if store is down.
   */
  async function countAttempt(key, freeTries = AUTH_FREE_TRIES) {
    const hashedKey = normalizeThrottleKey(key);

    if (store?.incrThrottle) {
      const t = Date.now();
      let res;
      try {
        res = await store.incrThrottle(hashedKey, freeTries, t);
      } catch (err) {
        if (err instanceof HttpError) throw err;
        throw new HttpError(503, "SERVICE_UNAVAILABLE", "Authentication rate-limit service is temporarily unavailable. Please try again shortly.");
      }
      if (res.locked) {
        const retryAfter = Math.max(1, Math.ceil((res.until - t) / 1000));
        recordAbuse({ type: "auth_lockout", reason: "LOCKED_OUT", key: hashedKey, retryAfter });
        throw new HttpError(429, "LOCKED_OUT", "Too many attempts. Try again later.", { retryAfter });
      }
      const lockDuration = Math.max(0, (res.until || 0) - t);
      if (lockDuration > 0) {
        recordAbuse({ type: "auth_lockout_triggered", reason: "BAD_CREDENTIALS_THRESHOLD", key: hashedKey, retryAfter: Math.ceil(lockDuration / 1000) });
      }
      return { fails: res.fails, retryAfter: Math.ceil(lockDuration / 1000), hashedKey };
    }

    if (store?.getThrottle && store?.putThrottle) {
      return withSerializedKey(hashedKey, async () => {
        const t = Date.now();
        let row;
        try {
          row = (await store.getThrottle(hashedKey)) || { fails: 0, until: 0 };
        } catch {
          throw new HttpError(503, "SERVICE_UNAVAILABLE", "Authentication rate-limit service is temporarily unavailable. Please try again shortly.");
        }
        if (row.until > t) {
          const retryAfter = Math.ceil((row.until - t) / 1000);
          recordAbuse({ type: "auth_lockout", reason: "LOCKED_OUT", key: hashedKey, retryAfter });
          throw new HttpError(429, "LOCKED_OUT", "Too many attempts. Try again later.", { retryAfter });
        }
        const fails = (Number(row.fails) || 0) + 1;
        const lockDuration = lockMs(fails, freeTries);
        try {
          await store.putThrottle(hashedKey, fails, t + lockDuration, t);
        } catch {
          throw new HttpError(503, "SERVICE_UNAVAILABLE", "Authentication rate-limit service is temporarily unavailable. Please try again shortly.");
        }
        if (lockDuration > 0) {
          recordAbuse({ type: "auth_lockout_triggered", reason: "BAD_CREDENTIALS_THRESHOLD", key: hashedKey, retryAfter: Math.ceil(lockDuration / 1000) });
        }
        return { fails, retryAfter: Math.ceil(lockDuration / 1000), hashedKey };
      });
    }

    return countAttemptSync(key, freeTries);
  }

  async function clearAttempts(key) {
    if (store?.delThrottle) {
      const hashedKey = normalizeThrottleKey(key);
      await store.delThrottle(hashedKey).catch(() => {});
      return;
    }
    clearAttemptsSync(key);
  }

  /**
   * Layered login throttle (B9b):
   *   1. Per-IP lockout (`auth:ip:${ip}`) uses `IP_FREE_TRIES = 25` so shared NAT/office users don't lock each other out.
   *   2. Per-account lookup lockout (`auth:lookup:${lookup}`) uses `AUTH_FREE_TRIES = 5`.
   *   3. Per-IP+account lockout (`auth:acct:${ip}:${lookup}`) uses `AUTH_FREE_TRIES = 5`.
   */
  async function checkLoginThrottle(ip, lookup) {
    const ipRes = await countAttempt(`auth:ip:${ip}`, IP_FREE_TRIES);
    if (lookup) {
      const acctRes = await countAttempt(`auth:lookup:${lookup}`, AUTH_FREE_TRIES);
      return {
        fails: Math.max(acctRes.fails, ipRes.fails >= IP_FREE_TRIES ? ipRes.fails : acctRes.fails),
        retryAfter: Math.max(ipRes.retryAfter, acctRes.retryAfter)
      };
    }
    return ipRes;
  }

  async function clearLoginThrottle(ip, lookup) {
    await clearAttempts(`auth:ip:${ip}`);
    if (lookup) {
      await clearAttempts(`auth:lookup:${lookup}`);
    }
  }

  function purgeExpired(nowMs) {
    for (const [k, w] of windows) {
      if (w.reset <= nowMs) windows.delete(k);
    }
  }

  return {
    isDistributed,
    productionReady: isDistributed || !multiInstance,
    windowLimit,
    windowLimitSync,
    countAttempt,
    countAttemptSync,
    clearAttempts,
    clearAttemptsSync,
    checkLoginThrottle,
    clearLoginThrottle,
    purgeExpired,
    getAbuseTelemetry: () => [...telemetry]
  };
}
