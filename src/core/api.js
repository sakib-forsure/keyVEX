/**
 * Server-First + IndexedDB Offline Cache API Client for KeyVEX.
 *
 * Architecture:
 *   1. Always attempts to communicate with the KeyVEX server (`/api/*`) first so vaults
 *      synchronize across devices (PC, phone, tablet).
 *   2. Mirrors authenticated encrypted vault state into browser IndexedDB (`IdbBackend`)
 *      so previously accessed accounts remain available offline.
 *   3. When `allowOffline` is enabled (default in browser `new Api()`, or `{ allowOffline: true }`),
 *      gracefully handles server unavailability (`NETWORK` errors) by reading/writing the local
 *      IndexedDB cache and queuing mutations in `v6_sync_queue` to synchronize when reconnected.
 */
import { IdbBackend } from "./idb.js";

export class ApiError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message || code);
    this.status = status;
    this.code = code;
    Object.assign(this, extra);
  }
}

function wrapIdbErr(err) {
  if (err instanceof ApiError) return err;
  return new ApiError(err?.status || 400, err?.code || "ERROR", err?.message || "Operation could not be completed.", err);
}

export class Api {
  #token = null;
  #idbToken = null;
  #lookup = null;
  #auth = null;
  #idb = new IdbBackend();
  offline = false;
  allowOffline = false;
  /** Called when the server says the session is gone (expired or revoked on another device). */
  onExpire = null;

  constructor(base = "", { allowOffline } = {}) {
    this.base = base.replace(/\/$/, "");
    this.allowOffline = allowOffline !== undefined ? !!allowOffline : this.base === "";
  }

  get signedIn() { return !!(this.#token || this.#idbToken); }
  forget() { this.#token = null; this.#idbToken = null; this.#lookup = null; this.#auth = null; this.offline = false; }

  async #call(method, path, body, { quiet = false } = {}) {
    let res;
    try {
      res = await fetch(this.base + path, {
        method,
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        headers: {
          "Content-Type": "application/json",
          ...(this.#token ? { Authorization: `Bearer ${this.#token}` } : {})
        },
        body: body === undefined ? undefined : JSON.stringify(body)
      });
    } catch {
      throw new ApiError(0, "NETWORK", "Can’t reach the server. Check your connection and try again.");
    }

    if (res.status === 204) return {};

    const ctype = String(res.headers?.get?.("content-type") || "").toLowerCase();
    const isJson = ctype.includes("application/json");
    const data = isJson ? await res.json().catch(() => null) : null;

    if (res.ok && data !== null) return data;

    if (!isJson && (res.status === 404 || res.status === 405 || res.status >= 500)) {
      throw new ApiError(0, "NETWORK", "Can’t reach the server. Check your connection and try again.");
    }

    const safeData = data || {};
    if (res.status === 401 && this.#token && (safeData.error === "SESSION_EXPIRED" || safeData.error === "UNAUTHENTICATED") && !quiet) {
      this.#token = null;
      this.onExpire?.();
    }
    const { error, message, ...extra } = safeData;
    const defaultMsg = res.status === 404 ? "Requested endpoint was not found on server." : "Server request failed. Please try again.";
    throw new ApiError(res.status, error || "ERROR", message || defaultMsg, extra);
  }

  async #flushSyncQueue(lookup, auth, currentMeta) {
    const queue = await this.#idb.getSyncQueue(lookup);
    if (!queue.length) return false;

    for (const item of queue) {
      if (item.op === "register") {
        try {
          const r = await this.#call("POST", "/api/register", {
            lookup: item.lookup,
            auth: item.auth || auth,
            meta: item.meta || currentMeta
          }, { quiet: true });
          this.#token = r.token;
        } catch (err) {
          if (err?.code === "ACCOUNT_EXISTS") {
            const r = await this.#call("POST", "/api/login", { lookup: item.lookup, auth: item.auth || auth }, { quiet: true });
            this.#token = r.token;
          } else {
            throw err;
          }
        }
      } else if (item.op === "put" && item.entry) {
        await this.#call("PUT", `/api/entries/${encodeURIComponent(item.entry.id)}`, {
          iv: item.entry.iv,
          data: item.entry.data
        }, { quiet: true });
      } else if (item.op === "batch" && Array.isArray(item.entries) && item.entries.length) {
        await this.#call("POST", "/api/entries/batch", { entries: item.entries }, { quiet: true });
      } else if (item.op === "delete" && item.entryId) {
        await this.#call("DELETE", `/api/entries/${encodeURIComponent(item.entryId)}`, undefined, { quiet: true });
      }
    }
    await this.#idb.clearSyncQueue(lookup);
    return true;
  }

  async register({ lookup, auth, meta }) {
    try {
      const r = await this.#call("POST", "/api/register", { lookup, auth, meta });
      this.#token = r.token;
      this.#lookup = lookup;
      this.#auth = auth;
      this.offline = false;
      const localSession = await this.#idb.mirrorAccount({ lookup, auth, meta, entries: [] });
      this.#idbToken = localSession.token;
    } catch (err) {
      if (err?.code === "NETWORK" && this.allowOffline) {
        try {
          const local = await this.#idb.register({ lookup, auth, meta, synced: false });
          this.#idbToken = local.token;
          this.#token = null;
          this.#lookup = lookup;
          this.#auth = auth;
          this.offline = true;
          return;
        } catch (idbErr) {
          throw wrapIdbErr(idbErr);
        }
      }
      throw err;
    }
  }

  /**
   * Mirrors an already-verified cloud vault (e.g. from Cloud Firestore) into local IndexedDB
   * and establishes an active session so offline caching and local operations work seamlessly.
   */
  async mirrorVault({ lookup, auth, meta, entries = [] }) {
    const localSession = await this.#idb.mirrorAccount({ lookup, auth, meta, entries });
    this.#idbToken = localSession.token;
    this.#lookup = lookup;
    this.#auth = auth;
    return { meta, entries };
  }

  /**
   * Fast single-record local cache update without re-mirroring the entire vault (B10).
   */
  async upsertCachedEntry(lookup, rec, meta = null) {
    return this.#idb.upsertCachedEntryByLookup(lookup || this.#lookup, rec, meta);
  }

  async deleteCachedEntry(lookup, entryId, meta = null) {
    return this.#idb.deleteCachedEntryByLookup(lookup || this.#lookup, entryId, meta);
  }

  async login({ lookup, auth }) {
    try {
      let r;
      try {
        r = await this.#call("POST", "/api/login", { lookup, auth });
      } catch (loginErr) {
        if (loginErr?.code === "BAD_CREDENTIALS" && this.allowOffline) {
          const queue = await this.#idb.getSyncQueue(lookup);
          if (queue.some((q) => q.op === "register")) {
            const local = await this.#idb.login({ lookup, auth });
            this.#idbToken = local.token;
            await this.#flushSyncQueue(lookup, auth, local.meta);
            const remoteVault = await this.#call("GET", "/api/vault");
            this.#lookup = lookup;
            this.#auth = auth;
            this.offline = false;
            const mirrored = await this.#idb.mirrorAccount({ lookup, auth, meta: remoteVault.meta, entries: remoteVault.entries });
            this.#idbToken = mirrored.token;
            return { meta: remoteVault.meta, entries: remoteVault.entries };
          }
        }
        throw loginErr;
      }

      this.#token = r.token;
      this.#lookup = lookup;
      this.#auth = auth;
      this.offline = false;

      let meta = r.meta;
      let entries = r.entries;
      const flushed = await this.#flushSyncQueue(lookup, auth, meta).catch(() => false);
      if (flushed) {
        const refreshed = await this.#call("GET", "/api/vault");
        meta = refreshed.meta;
        entries = refreshed.entries;
      }

      const localSession = await this.#idb.mirrorAccount({ lookup, auth, meta, entries });
      this.#idbToken = localSession.token;
      return { meta, entries };
    } catch (err) {
      if (err?.code === "NETWORK" && this.allowOffline) {
        try {
          const local = await this.#idb.login({ lookup, auth });
          this.#idbToken = local.token;
          this.#token = null;
          this.#lookup = lookup;
          this.#auth = auth;
          this.offline = true;
          return { meta: local.meta, entries: local.entries };
        } catch (idbErr) {
          if (idbErr?.code === "BAD_CREDENTIALS") throw err;
          throw wrapIdbErr(idbErr);
        }
      }
      throw err;
    }
  }

  async logout() {
    const tok = this.#token;
    const idbTok = this.#idbToken;
    this.forget();
    if (idbTok) await this.#idb.logout(idbTok).catch(() => {});
    if (tok) {
      try {
        await fetch(this.base + "/api/logout", {
          method: "POST",
          cache: "no-store",
          credentials: "omit",
          referrerPolicy: "no-referrer",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${tok}` }
        });
      } catch { /* best effort */ }
    }
  }

  async fetchVault() {
    if (!this.offline && this.#token) {
      try {
        if (this.#lookup) await this.#flushSyncQueue(this.#lookup, this.#auth).catch(() => {});
        const data = await this.#call("GET", "/api/vault");
        if (this.#lookup) {
          const localSession = await this.#idb.mirrorAccount({
            lookup: this.#lookup,
            auth: this.#auth,
            meta: data.meta,
            entries: data.entries
          });
          this.#idbToken = localSession.token;
        }
        return data;
      } catch (err) {
        if (err?.code === "NETWORK" && this.allowOffline && this.#idbToken) {
          this.offline = true;
          return this.#idb.fetchVault(this.#idbToken);
        }
        throw err;
      }
    }
    if (this.allowOffline && this.#idbToken) {
      try { return await this.#idb.fetchVault(this.#idbToken); }
      catch (err) { throw wrapIdbErr(err); }
    }
    return this.#call("GET", "/api/vault");
  }

  async getVaultByLookup(lookup) {
    if (!lookup) return null;
    return this.#idb.getVaultByLookup(lookup);
  }

  async sync() {
    if (!this.#lookup || !this.#auth) {
      return this.fetchVault();
    }
    if (!this.#token) {
      try {
        const r = await this.#call("POST", "/api/login", { lookup: this.#lookup, auth: this.#auth }, { quiet: true });
        this.#token = r.token;
      } catch (err) {
        if (err?.code === "BAD_CREDENTIALS") {
          await this.#flushSyncQueue(this.#lookup, this.#auth);
        } else {
          throw err;
        }
      }
    }
    await this.#flushSyncQueue(this.#lookup, this.#auth);
    const remote = await this.#call("GET", "/api/vault");
    this.offline = false;
    const localSession = await this.#idb.mirrorAccount({
      lookup: this.#lookup,
      auth: this.#auth,
      meta: remote.meta,
      entries: remote.entries
    });
    this.#idbToken = localSession.token;
    return remote;
  }

  async putEntry(rec) {
    if (!this.offline && this.#token) {
      try {
        const r = await this.#call("PUT", `/api/entries/${encodeURIComponent(rec.id)}`, { iv: rec.iv, data: rec.data });
        if (this.#idbToken) await this.#idb.putEntry(this.#idbToken, rec, { synced: true }).catch(() => {});
        return r;
      } catch (err) {
        if (err?.code === "NETWORK" && this.allowOffline && this.#idbToken) {
          this.offline = true;
          return this.#idb.putEntry(this.#idbToken, rec, { synced: false });
        }
        throw err;
      }
    }
    if (this.allowOffline && this.#idbToken) {
      try { return await this.#idb.putEntry(this.#idbToken, rec, { synced: false }); }
      catch (err) { throw wrapIdbErr(err); }
    }
    return this.#call("PUT", `/api/entries/${encodeURIComponent(rec.id)}`, { iv: rec.iv, data: rec.data });
  }

  async putEntries(entries) {
    if (!this.offline && this.#token) {
      try {
        const r = await this.#call("POST", "/api/entries/batch", { entries });
        if (this.#idbToken) await this.#idb.putEntries(this.#idbToken, entries, { synced: true }).catch(() => {});
        return r;
      } catch (err) {
        if (err?.code === "NETWORK" && this.allowOffline && this.#idbToken) {
          this.offline = true;
          return this.#idb.putEntries(this.#idbToken, entries, { synced: false });
        }
        throw err;
      }
    }
    if (this.allowOffline && this.#idbToken) {
      try { return await this.#idb.putEntries(this.#idbToken, entries, { synced: false }); }
      catch (err) { throw wrapIdbErr(err); }
    }
    return this.#call("POST", "/api/entries/batch", { entries });
  }

  async deleteEntry(id) {
    if (!this.offline && this.#token) {
      try {
        const r = await this.#call("DELETE", `/api/entries/${encodeURIComponent(id)}`);
        if (this.#idbToken) await this.#idb.deleteEntry(this.#idbToken, id, { synced: true }).catch(() => {});
        return r;
      } catch (err) {
        if (err?.code === "NETWORK" && this.allowOffline && this.#idbToken) {
          this.offline = true;
          return this.#idb.deleteEntry(this.#idbToken, id, { synced: false });
        }
        throw err;
      }
    }
    if (this.allowOffline && this.#idbToken) {
      try { return await this.#idb.deleteEntry(this.#idbToken, id, { synced: false }); }
      catch (err) { throw wrapIdbErr(err); }
    }
    return this.#call("DELETE", `/api/entries/${encodeURIComponent(id)}`);
  }

  async changeCredentials(payload) {
    if (!this.offline && this.#token) {
      const r = await this.#call("POST", "/api/account/credentials", payload);
      if (this.#idbToken) {
        await this.#idb.changeCredentials(this.#idbToken, payload, { synced: true }).catch(() => {});
      }
      this.#lookup = payload.lookup;
      this.#auth = payload.newAuth;
      return r;
    }
    if (this.allowOffline && this.#idbToken) {
      try {
        const r = await this.#idb.changeCredentials(this.#idbToken, payload, { synced: false });
        this.#lookup = payload.lookup;
        this.#auth = payload.newAuth;
        return r;
      } catch (err) { throw wrapIdbErr(err); }
    }
    return this.#call("POST", "/api/account/credentials", payload);
  }

  async getSessions() {
    if (!this.offline && this.#token) {
      return this.#call("GET", "/api/sessions");
    }
    return { activeSessions: 1, offline: true };
  }

  async revokeOtherSessions(auth) {
    if (!this.offline && this.#token) {
      return this.#call("POST", "/api/sessions/revoke-others", auth ? { auth } : {});
    }
    return { ok: true, revoked: 0, activeSessions: 1 };
  }

  async deleteAccount(auth) {
    const lookup = this.#lookup;
    if (!this.offline && this.#token) {
      await this.#call("DELETE", "/api/account", { auth });
      if (lookup) await this.#idb.removeAccountByLookup(lookup).catch(() => {});
      this.forget();
      return;
    }
    if (this.allowOffline && this.#idbToken) {
      try {
        await this.#idb.deleteAccount(this.#idbToken, auth);
        this.forget();
        return;
      } catch (err) { throw wrapIdbErr(err); }
    }
    await this.#call("DELETE", "/api/account", { auth });
    this.forget();
  }
}
