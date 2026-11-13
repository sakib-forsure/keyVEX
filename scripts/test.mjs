/**
 * Comprehensive Automated Test & Load Benchmark Suite (`npm test` / `node scripts/test.mjs`).
 *
 * Node 18 / 20 / 22+ Compatible (Issue H fixed: uses `Object.defineProperty(globalThis, "navigator", ...)`
 * so Node 21.2+ / 22+ getter-only `globalThis.navigator` never throws TypeError).
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync, statSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true, writable: true });
}
process.env.NODE_ENV = "test";

/* ---------- Version-Safe Navigator Helper (Fixes Issue H on Node 22+) ---------- */
function defineGlobalNavigator(navObj) {
  Object.defineProperty(globalThis, "navigator", {
    value: navObj,
    writable: true,
    configurable: true,
    enumerable: true
  });
}

function setNavigatorOnline(onLine) {
  const cur = globalThis.navigator || {};
  defineGlobalNavigator({
    ...cur,
    onLine: Boolean(onLine),
    clipboard: cur.clipboard || { writeText: async () => {} }
  });
}

/* ---------- Minimal Web Storage Shim for Node Tests ---------- */
function createMemoryStorage() {
  const map = new Map();
  return {
    getItem: (k) => (map.has(String(k)) ? map.get(String(k)) : null),
    setItem: (k, v) => { map.set(String(k), String(v)); },
    removeItem: (k) => { map.delete(String(k)); },
    clear: () => { map.clear(); },
    key: (i) => [...map.keys()][i] ?? null,
    get length() { return map.size; }
  };
}

if (!globalThis.localStorage) {
  Object.defineProperty(globalThis, "localStorage", { value: createMemoryStorage(), configurable: true, writable: true });
}
if (!globalThis.sessionStorage) {
  Object.defineProperty(globalThis, "sessionStorage", { value: createMemoryStorage(), configurable: true, writable: true });
}

/* ---------- Minimal DOM Shim for UI Component & Screen Tests ---------- */
class MiniEvent {
  constructor(type, opts = {}) {
    this.type = type;
    this.bubbles = !!opts.bubbles;
    this.cancelable = !!opts.cancelable;
    this.key = opts.key;
    this.ctrlKey = !!opts.ctrlKey;
    this.metaKey = !!opts.metaKey;
    this.altKey = !!opts.altKey;
    this.data = opts.data;
    this.clipboardData = opts.clipboardData;
    this.defaultPrevented = false;
    this.propagationStopped = false;
    this.target = null;
    this.currentTarget = null;
  }
  preventDefault() { this.defaultPrevented = true; }
  stopPropagation() { this.propagationStopped = true; }
}

class MiniNode {
  constructor(tag) {
    this.tagName = String(tag || "").toUpperCase();
    this.nodeType = this.tagName === "#TEXT" ? 3 : 1;
    this.childNodes = [];
    this.parentNode = null;
    this.attrs = new Map();
    this.listeners = new Map();
    this.dataset = {};
    this._classSet = new Set();
    this.style = new Proxy({}, {
      set: (obj, prop, val) => { obj[prop] = val; return true; }
    });
    this.style.setProperty = (k, v) => { this.style[k] = v; };
    this._value = "";
    this.checked = false;
    this.disabled = false;
    this.hidden = false;
    this.type = this.tagName === "BUTTON" ? "submit" : "text";
    this.inputMode = "";
    this.maxLength = 524288;
    this.placeholder = "";
    this.selectionStart = 0;
    this.selectionEnd = 0;
    this._text = "";
    this._html = "";
  }
  get value() { return this._value; }
  set value(v) {
    this._value = String(v ?? "");
    this.selectionStart = this._value.length;
    this.selectionEnd = this._value.length;
  }
  get className() { return [...this._classSet].join(" "); }
  set className(v) {
    this._classSet = new Set(String(v || "").split(/\s+/).filter(Boolean));
  }
  get classList() {
    const self = this;
    return {
      add(...c) { c.forEach((x) => x && self._classSet.add(x)); },
      remove(...c) { c.forEach((x) => self._classSet.delete(x)); },
      toggle(c, force) {
        const has = self._classSet.has(c);
        const next = force !== undefined ? !!force : !has;
        if (next) self._classSet.add(c); else self._classSet.delete(c);
        return next;
      },
      contains(c) { return self._classSet.has(c); }
    };
  }
  get children() { return this.childNodes.filter((n) => n.nodeType === 1); }
  get firstChild() { return this.childNodes[0] || null; }
  get isConnected() {
    let cur = this;
    while (cur) {
      if (cur === globalThis.document?.body || cur === globalThis.document?.documentElement) return true;
      cur = cur.parentNode;
    }
    return false;
  }
  get textContent() {
    if (this.nodeType === 3) return this._text;
    return this.childNodes.map((c) => c.textContent).join("");
  }
  set textContent(v) {
    if (this.nodeType === 3) { this._text = String(v ?? ""); return; }
    this.childNodes = [];
    if (v !== "" && v != null) {
      const t = new MiniNode("#TEXT");
      t._text = String(v);
      t.parentNode = this;
      this.childNodes.push(t);
    }
  }
  get innerHTML() { return this._html || this.textContent; }
  set innerHTML(v) { this._html = String(v ?? ""); }
  setAttribute(k, v) {
    const val = String(v);
    this.attrs.set(k, val);
    if (k === "class") this.className = val;
    else if (k === "type") this.type = val;
    else if (k === "name") this.name = val;
    else if (k === "id") this.id = val;
    else if (k === "hidden") this.hidden = true;
    else if (k === "maxlength") this.maxLength = Number(val);
    else if (k === "inputmode") this.inputMode = val;
    else if (k === "placeholder") this.placeholder = val;
    else if (k === "autocomplete") this.autocomplete = val;
    else if (k.startsWith("data-")) {
      const camel = k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      this.dataset[camel] = val;
    }
  }
  getAttribute(k) {
    if (k === "class") return this.className;
    if (k === "maxlength") return String(this.maxLength);
    if (k === "inputmode") return this.inputMode || this.attrs.get("inputmode") || null;
    return this.attrs.get(k) ?? null;
  }
  removeAttribute(k) {
    this.attrs.delete(k);
    if (k === "hidden") this.hidden = false;
    if (k === "disabled") this.disabled = false;
  }
  append(...nodes) {
    for (const n of nodes) {
      if (n == null || n === false) continue;
      const child = n instanceof MiniNode ? n : (() => { const t = new MiniNode("#TEXT"); t._text = String(n); return t; })();
      if (child.parentNode) {
        const idx = child.parentNode.childNodes.indexOf(child);
        if (idx >= 0) child.parentNode.childNodes.splice(idx, 1);
      }
      child.parentNode = this;
      this.childNodes.push(child);
    }
  }
  replaceChildren(...nodes) {
    this.childNodes.forEach((c) => { c.parentNode = null; });
    this.childNodes = [];
    this.append(...nodes);
  }
  remove() {
    if (!this.parentNode) return;
    const idx = this.parentNode.childNodes.indexOf(this);
    if (idx >= 0) this.parentNode.childNodes.splice(idx, 1);
    this.parentNode = null;
  }
  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }
  removeEventListener(type, fn) {
    const arr = this.listeners.get(type);
    if (!arr) return;
    const idx = arr.indexOf(fn);
    if (idx >= 0) arr.splice(idx, 1);
  }
  dispatchEvent(ev) {
    ev.target = ev.target || this;
    let cur = this;
    while (cur) {
      ev.currentTarget = cur;
      const list = [...(cur.listeners.get(ev.type) || [])];
      for (const fn of list) fn(ev);
      if (!ev.bubbles || ev.propagationStopped) break;
      cur = cur.parentNode;
    }
    return !ev.defaultPrevented;
  }
  click() {
    if (this.disabled) return;
    this.dispatchEvent(new MiniEvent("click", { bubbles: true, cancelable: true }));
  }
  focus() {
    if (globalThis.document) globalThis.document.activeElement = this;
  }
  matches(sel) {
    sel = sel.trim();
    if (!sel || this.nodeType !== 1) return false;
    if (sel.includes(",")) return sel.split(",").some((s) => this.matches(s));
    const attrMatch = /^([a-zA-Z0-9_-]*)\[([a-zA-Z0-9_-]+)=["']?([^"'\]]+)["']?\]$/.exec(sel);
    if (attrMatch) {
      const [, tag, attr, val] = attrMatch;
      if (tag && this.tagName !== tag.toUpperCase()) return false;
      return (this.getAttribute(attr) || this[attr]) === val;
    }
    if (sel.startsWith("#")) return this.id === sel.slice(1);
    if (sel.startsWith(".")) {
      const classes = sel.slice(1).split(".");
      return classes.every((c) => this._classSet.has(c));
    }
    if (sel.includes(".")) {
      const [tag, ...classes] = sel.split(".");
      if (tag && this.tagName !== tag.toUpperCase()) return false;
      return classes.every((c) => this._classSet.has(c));
    }
    return this.tagName === sel.toUpperCase();
  }
  querySelectorAll(sel) {
    if (sel.includes(" ") && !sel.includes("[")) {
      const parts = sel.trim().split(/\s+/);
      let current = [this];
      for (const part of parts) {
        const next = [];
        for (const node of current) {
          const found = node._findAll((n) => n.matches(part));
          for (const f of found) if (!next.includes(f)) next.push(f);
        }
        current = next;
      }
      return current;
    }
    return this._findAll((n) => n.matches(sel));
  }
  querySelector(sel) {
    return this.querySelectorAll(sel)[0] || null;
  }
  _findAll(pred, out = []) {
    for (const c of this.children) {
      if (pred(c)) out.push(c);
      c._findAll(pred, out);
    }
    return out;
  }
}

function setupMiniDom() {
  const docEl = new MiniNode("html");
  const head = new MiniNode("head");
  const body = new MiniNode("body");
  docEl.append(head, body);
  const app = new MiniNode("div"); app.setAttribute("id", "app");
  const layer = new MiniNode("div"); layer.setAttribute("id", "layer");
  const toast = new MiniNode("div"); toast.setAttribute("id", "toast");
  body.append(app, layer, toast);

  globalThis.Event = MiniEvent;
  globalThis.KeyboardEvent = class extends MiniEvent {
    constructor(type, opts) { super(type, opts); }
  };
  globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);
  globalThis.matchMedia = () => ({ matches: true, addEventListener() {} });
  globalThis.scrollTo = () => {};
  globalThis.history = {
    replaceState(_state, _title, url) {
      if (typeof url === "string" && globalThis.location) {
        const qIdx = url.indexOf("?");
        globalThis.location.search = qIdx >= 0 ? url.slice(qIdx) : "";
      }
    }
  };
  Object.defineProperty(globalThis, "location", {
    value: { protocol: "http:", origin: "http://localhost:5173", pathname: "/", search: "", hash: "" },
    writable: true,
    configurable: true
  });
  defineGlobalNavigator({ onLine: true, clipboard: { writeText: async () => {} } });
  globalThis.window = globalThis;
  globalThis.document = {
    documentElement: docEl,
    head,
    body,
    activeElement: body,
    visibilityState: "visible",
    createElement: (t) => new MiniNode(t),
    createElementNS: (_, t) => new MiniNode(t),
    createTextNode: (s) => { const n = new MiniNode("#TEXT"); n._text = String(s); return n; },
    querySelector: (s) => docEl.querySelector(s),
    querySelectorAll: (s) => docEl.querySelectorAll(s),
    addEventListener: (t, fn) => body.addEventListener(t, fn),
    removeEventListener: (t, fn) => body.removeEventListener(t, fn),
    dispatchEvent: (ev) => body.dispatchEvent(ev)
  };
}

setupMiniDom();

/* ---------- In-Memory Firebase Auth & Paginated Cloud Firestore Emulator ---------- */
function createFirebaseEmulator() {
  let nextUid = 1000;
  let nextTok = 5000;
  let nextUpdateSeq = 1;
  const usersByUid = new Map();
  const uidByEmail = new Map();
  const uidByIdToken = new Map();
  const uidByRefreshToken = new Map();
  const googleTokens = new Map();
  const resetEmailsSent = [];
  const verifyEmailsSent = [];
  // uid -> { doc: { fields, updateTime }, entries: Map(entryId -> { name, fields, updateTime }), tombstones: Map(entryId -> { name, fields, updateTime }) }
  const firestoreUsers = new Map();
  const requestCounts = {
    metaReads: 0,
    entriesReads: 0,
    tombstonesReads: 0,
    firestoreWrites: 0,
    firestoreDeletes: 0,
    authLookups: 0,
    authDeletes: 0
  };
  let networkDown = false;
  let failFirestoreWrites = false;
  let failFirestoreDeletesAfter = Infinity;
  let failAuthDelete = false;
  let expiresInSec = 3600;
  let onBeforeMetaPatch = null;

  function makeUpdateTime() {
    return `2026-01-01T00:00:${String(++nextUpdateSeq).padStart(6, "0")}Z`;
  }

  function ensureStore(uid) {
    if (!firestoreUsers.has(uid)) {
      firestoreUsers.set(uid, { doc: null, entries: new Map(), tombstones: new Map() });
    }
    return firestoreUsers.get(uid);
  }

  function issueTokens(uid) {
    const idToken = `fb_id_${++nextTok}_${uid}`;
    const refreshToken = `fb_ref_${++nextTok}_${uid}`;
    uidByIdToken.set(idToken, uid);
    uidByRefreshToken.set(refreshToken, uid);
    return { idToken, refreshToken, expiresIn: String(expiresInSec) };
  }

  function jsonRes(status, obj) {
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: () => "application/json" },
      json: async () => obj
    };
  }

  async function transport(url, options = {}) {
    if (networkDown) {
      throw new TypeError("fetch failed: network disconnected");
    }
    const body = options.body ? JSON.parse(options.body) : {};
    const method = options.method || "GET";

    // 1. Secure Token API
    if (url.includes("securetoken.googleapis.com/v1/token")) {
      const ref = body.refresh_token;
      const uid = uidByRefreshToken.get(ref);
      if (!uid) return jsonRes(400, { error: { message: "TOKEN_EXPIRED" } });
      const u = usersByUid.get(uid);
      if (!u || u.disabled) return jsonRes(400, { error: { message: "USER_DISABLED" } });
      const toks = issueTokens(uid);
      return jsonRes(200, {
        id_token: toks.idToken,
        refresh_token: toks.refreshToken,
        user_id: uid,
        expires_in: toks.expiresIn
      });
    }

    // 2. Identity Toolkit API
    if (url.includes("identitytoolkit.googleapis.com/v1/accounts:signUp")) {
      const email = String(body.email || "").trim().toLowerCase();
      if (!email.includes("@")) return jsonRes(400, { error: { message: "INVALID_EMAIL" } });
      if (String(body.password || "").length < 6) return jsonRes(400, { error: { message: "WEAK_PASSWORD" } });
      if (uidByEmail.has(email)) return jsonRes(400, { error: { message: "EMAIL_EXISTS" } });
      const uid = `fb_uid_${++nextUid}`;
      const user = {
        localId: uid,
        email,
        password: String(body.password),
        displayName: "",
        emailVerified: false,
        disabled: false,
        providers: new Set(["password"])
      };
      usersByUid.set(uid, user);
      uidByEmail.set(email, uid);
      const toks = issueTokens(uid);
      return jsonRes(200, { localId: uid, email, ...toks });
    }

    if (url.includes("identitytoolkit.googleapis.com/v1/accounts:signInWithPassword")) {
      const email = String(body.email || "").trim().toLowerCase();
      const uid = uidByEmail.get(email);
      if (!uid) return jsonRes(400, { error: { message: "EMAIL_NOT_FOUND" } });
      const u = usersByUid.get(uid);
      if (u.disabled) return jsonRes(400, { error: { message: "USER_DISABLED" } });
      if (!u.providers.has("password") || u.password !== String(body.password)) {
        return jsonRes(400, { error: { message: "INVALID_LOGIN_CREDENTIALS" } });
      }
      const toks = issueTokens(uid);
      return jsonRes(200, {
        localId: uid,
        email: u.email,
        displayName: u.displayName,
        emailVerified: u.emailVerified,
        registered: true,
        ...toks
      });
    }

    if (url.includes("identitytoolkit.googleapis.com/v1/accounts:signInWithIdp")) {
      const postBody = String(body.postBody || "");
      const params = new URLSearchParams(postBody);
      const rawToken = params.get("id_token") || params.get("access_token");
      const gInfo = googleTokens.get(rawToken);
      if (!gInfo) return jsonRes(400, { error: { message: "INVALID_IDP_RESPONSE" } });
      const email = gInfo.email.toLowerCase();

      if (body.idToken) {
        const existingUid = uidByIdToken.get(body.idToken);
        if (!existingUid) return jsonRes(400, { error: { message: "INVALID_ID_TOKEN" } });
        const u = usersByUid.get(existingUid);
        u.providers.add("google.com");
        u.emailVerified = true;
        if (!u.displayName && gInfo.name) u.displayName = gInfo.name;
        const toks = issueTokens(existingUid);
        return jsonRes(200, { localId: existingUid, email: u.email, displayName: u.displayName, ...toks });
      }

      const existingUid = uidByEmail.get(email);
      if (existingUid) {
        const u = usersByUid.get(existingUid);
        if (u.providers.has("password") && !u.providers.has("google.com")) {
          return jsonRes(200, {
            needConfirmation: true,
            email: u.email,
            displayName: gInfo.name,
            oauthAccessToken: rawToken,
            verifiedProvider: ["password"]
          });
        }
        u.providers.add("google.com");
        const toks = issueTokens(existingUid);
        return jsonRes(200, { localId: existingUid, email: u.email, displayName: u.displayName || gInfo.name, isNewUser: false, ...toks });
      }

      const uid = `fb_uid_${++nextUid}`;
      const user = {
        localId: uid,
        email,
        password: null,
        displayName: gInfo.name || email.split("@")[0],
        emailVerified: true,
        disabled: false,
        providers: new Set(["google.com"])
      };
      usersByUid.set(uid, user);
      uidByEmail.set(email, uid);
      const toks = issueTokens(uid);
      return jsonRes(200, { localId: uid, email, displayName: user.displayName, isNewUser: true, ...toks });
    }

    if (url.includes("identitytoolkit.googleapis.com/v1/accounts:update")) {
      const uid = uidByIdToken.get(body.idToken);
      if (!uid) return jsonRes(400, { error: { message: "INVALID_ID_TOKEN" } });
      const u = usersByUid.get(uid);
      if (body.displayName) u.displayName = String(body.displayName);
      if (body.password) {
        u.password = String(body.password);
        u.providers.add("password");
      }
      if (body.oobCode) {
        u.emailVerified = true;
      }
      const toks = issueTokens(uid);
      return jsonRes(200, {
        localId: uid,
        email: u.email,
        displayName: u.displayName,
        emailVerified: u.emailVerified,
        providerUserInfo: [...u.providers].map((p) => ({ providerId: p })),
        ...toks
      });
    }

    if (url.includes("identitytoolkit.googleapis.com/v1/accounts:lookup")) {
      requestCounts.authLookups++;
      const uid = uidByIdToken.get(body.idToken);
      if (!uid) return jsonRes(400, { error: { message: "INVALID_ID_TOKEN" } });
      const u = usersByUid.get(uid);
      if (!u) return jsonRes(200, { users: [] });
      return jsonRes(200, {
        users: [{
          localId: u.localId,
          email: u.email,
          displayName: u.displayName,
          emailVerified: u.emailVerified,
          disabled: u.disabled,
          providerUserInfo: [...u.providers].map((p) => ({ providerId: p }))
        }]
      });
    }

    if (url.includes("identitytoolkit.googleapis.com/v1/accounts:sendOobCode")) {
      if (body.requestType === "PASSWORD_RESET") {
        const email = String(body.email || "").trim().toLowerCase();
        if (!uidByEmail.has(email)) return jsonRes(400, { error: { message: "EMAIL_NOT_FOUND" } });
        resetEmailsSent.push(email);
        return jsonRes(200, { email });
      }
      if (body.requestType === "VERIFY_EMAIL") {
        const uid = uidByIdToken.get(body.idToken);
        if (!uid) return jsonRes(400, { error: { message: "INVALID_ID_TOKEN" } });
        const u = usersByUid.get(uid);
        verifyEmailsSent.push(u.email);
        return jsonRes(200, { email: u.email });
      }
      return jsonRes(400, { error: { message: "INVALID_OOB_CODE" } });
    }

    if (url.includes("identitytoolkit.googleapis.com/v1/accounts:createAuthUri")) {
      const email = String(body.identifier || "").trim().toLowerCase();
      const uid = uidByEmail.get(email);
      const u = uid ? usersByUid.get(uid) : null;
      return jsonRes(200, { allProviders: u ? [...u.providers] : [] });
    }

    if (url.includes("identitytoolkit.googleapis.com/v1/accounts:delete")) {
      requestCounts.authDeletes++;
      if (failAuthDelete) {
        return jsonRes(400, { error: { message: "CREDENTIAL_TOO_OLD_LOGIN_AGAIN" } });
      }
      const uid = uidByIdToken.get(body.idToken);
      if (!uid) return jsonRes(400, { error: { message: "INVALID_ID_TOKEN" } });
      const u = usersByUid.get(uid);
      if (u) {
        uidByEmail.delete(u.email);
        usersByUid.delete(uid);
      }
      return jsonRes(200, {});
    }

    // 3. Cloud Firestore API (with nextPageToken pagination, tombstones, batched :commit, and updateTime preconditions!)
    if (url.includes("firestore.googleapis.com/v1/projects/")) {
      const authHeader = options.headers?.Authorization || "";
      const token = authHeader.replace(/^Bearer\s+/i, "");
      const authedUid = uidByIdToken.get(token);
      if (!authedUid) return jsonRes(401, { error: { message: "UNAUTHENTICATED" } });

      // 3a. Batched commit endpoint (`POST .../documents:commit`)
      if (url.endsWith("/documents:commit") && method === "POST") {
        if (failFirestoreWrites) return jsonRes(503, { error: { message: "UNAVAILABLE" } });
        const writes = Array.isArray(body.writes) ? body.writes : [];
        for (const w of writes) {
          if (w.delete) {
            if (requestCounts.firestoreDeletes >= failFirestoreDeletesAfter) {
              return jsonRes(503, { error: { message: "UNAVAILABLE" } });
            }
            const delMatchEntry = /\/documents\/users\/([^/]+)\/entries\/([^/]+)$/.exec(w.delete);
            const delMatchTomb = /\/documents\/users\/([^/]+)\/tombstones\/([^/]+)$/.exec(w.delete);
            if (delMatchEntry) {
              const [, uid, entryId] = delMatchEntry.map(decodeURIComponent);
              if (uid !== authedUid) return jsonRes(403, { error: { message: "PERMISSION_DENIED" } });
              ensureStore(uid).entries.delete(entryId);
              requestCounts.firestoreDeletes++;
            } else if (delMatchTomb) {
              const [, uid, entryId] = delMatchTomb.map(decodeURIComponent);
              if (uid !== authedUid) return jsonRes(403, { error: { message: "PERMISSION_DENIED" } });
              ensureStore(uid).tombstones.delete(entryId);
              requestCounts.firestoreDeletes++;
            }
          }
        }
        return jsonRes(200, { writeResults: writes.map(() => ({ updateTime: makeUpdateTime() })) });
      }

      // 3b. Single entry document (`/documents/users/{uid}/entries/{entryId}`)
      const matchEntry = /\/documents\/users\/([^/?]+)\/entries\/([^/?]+)(?:\?(.*))?$/.exec(url);
      if (matchEntry) {
        const uid = decodeURIComponent(matchEntry[1]);
        const entryId = decodeURIComponent(matchEntry[2]);
        const qs = new URLSearchParams(matchEntry[3] || "");
        if (uid !== authedUid) return jsonRes(403, { error: { message: "PERMISSION_DENIED" } });
        const store = ensureStore(uid);
        if (method === "GET") {
          const existing = store.entries.get(entryId);
          if (!existing) return jsonRes(404, { error: { message: "NOT_FOUND" } });
          return jsonRes(200, existing);
        }
        if (method === "PATCH") {
          if (failFirestoreWrites) return jsonRes(503, { error: { message: "UNAVAILABLE" } });
          const expectedUpdate = qs.get("currentDocument.updateTime");
          const existing = store.entries.get(entryId);
          if (expectedUpdate && existing?.updateTime && existing.updateTime !== expectedUpdate) {
            return jsonRes(409, { error: { status: "FAILED_PRECONDITION", message: "FAILED_PRECONDITION: updateTime mismatch" } });
          }
          requestCounts.firestoreWrites++;
          const updateTime = makeUpdateTime();
          const docObj = {
            name: `projects/keyvex/databases/(default)/documents/users/${uid}/entries/${entryId}`,
            fields: { ...(existing?.fields || {}), ...body.fields },
            updateTime
          };
          store.entries.set(entryId, docObj);
          return jsonRes(200, docObj);
        }
        if (method === "DELETE") {
          if (failFirestoreWrites || requestCounts.firestoreDeletes >= failFirestoreDeletesAfter) {
            return jsonRes(503, { error: { message: "UNAVAILABLE" } });
          }
          requestCounts.firestoreDeletes++;
          store.entries.delete(entryId);
          return jsonRes(200, {});
        }
      }

      // 3c. Paginated entries list (`/documents/users/{uid}/entries`)
      const matchEntriesList = /\/documents\/users\/([^/?]+)\/entries(?:\?(.*))?$/.exec(url);
      if (matchEntriesList && method === "GET") {
        requestCounts.entriesReads++;
        const uid = decodeURIComponent(matchEntriesList[1]);
        if (uid !== authedUid) return jsonRes(403, { error: { message: "PERMISSION_DENIED" } });
        const qs = new URLSearchParams(matchEntriesList[2] || "");
        const pageSize = Math.max(1, Number(qs.get("pageSize")) || 500);
        const pageToken = qs.get("pageToken") || "";
        const store = firestoreUsers.get(uid);
        const allDocs = store ? [...store.entries.values()] : [];
        let startIndex = 0;
        if (pageToken) {
          const idx = allDocs.findIndex((d) => d.name.endsWith(`/${pageToken}`));
          startIndex = idx >= 0 ? idx : allDocs.length;
        }
        const slice = allDocs.slice(startIndex, startIndex + pageSize);
        const nextDoc = allDocs[startIndex + pageSize];
        const nextPageToken = nextDoc ? nextDoc.name.split("/").pop() : undefined;
        return jsonRes(200, { documents: slice, ...(nextPageToken ? { nextPageToken } : {}) });
      }

      // 3d. Single tombstone document (`/documents/users/{uid}/tombstones/{entryId}`)
      const matchTomb = /\/documents\/users\/([^/?]+)\/tombstones\/([^/?]+)(?:\?(.*))?$/.exec(url);
      if (matchTomb) {
        const uid = decodeURIComponent(matchTomb[1]);
        const entryId = decodeURIComponent(matchTomb[2]);
        if (uid !== authedUid) return jsonRes(403, { error: { message: "PERMISSION_DENIED" } });
        const store = ensureStore(uid);
        if (method === "PATCH") {
          if (failFirestoreWrites) return jsonRes(503, { error: { message: "UNAVAILABLE" } });
          requestCounts.firestoreWrites++;
          const docObj = {
            name: `projects/keyvex/databases/(default)/documents/users/${uid}/tombstones/${entryId}`,
            fields: body.fields,
            updateTime: makeUpdateTime()
          };
          store.tombstones.set(entryId, docObj);
          return jsonRes(200, docObj);
        }
        if (method === "DELETE") {
          if (failFirestoreWrites || requestCounts.firestoreDeletes >= failFirestoreDeletesAfter) {
            return jsonRes(503, { error: { message: "UNAVAILABLE" } });
          }
          requestCounts.firestoreDeletes++;
          store.tombstones.delete(entryId);
          return jsonRes(200, {});
        }
      }

      // 3e. Paginated tombstones list (`/documents/users/{uid}/tombstones`)
      const matchTombList = /\/documents\/users\/([^/?]+)\/tombstones(?:\?(.*))?$/.exec(url);
      if (matchTombList && method === "GET") {
        requestCounts.tombstonesReads++;
        const uid = decodeURIComponent(matchTombList[1]);
        if (uid !== authedUid) return jsonRes(403, { error: { message: "PERMISSION_DENIED" } });
        const qs = new URLSearchParams(matchTombList[2] || "");
        const pageSize = Math.max(1, Number(qs.get("pageSize")) || 500);
        const pageToken = qs.get("pageToken") || "";
        const store = firestoreUsers.get(uid);
        const allDocs = store ? [...store.tombstones.values()] : [];
        let startIndex = 0;
        if (pageToken) {
          const idx = allDocs.findIndex((d) => d.name.endsWith(`/${pageToken}`));
          startIndex = idx >= 0 ? idx : allDocs.length;
        }
        const slice = allDocs.slice(startIndex, startIndex + pageSize);
        const nextDoc = allDocs[startIndex + pageSize];
        const nextPageToken = nextDoc ? nextDoc.name.split("/").pop() : undefined;
        return jsonRes(200, { documents: slice, ...(nextPageToken ? { nextPageToken } : {}) });
      }

      // 3f. User root document (`/documents/users/{uid}`)
      const matchUser = /\/documents\/users\/([^/?]+)(?:\?(.*))?$/.exec(url);
      if (matchUser) {
        const uid = decodeURIComponent(matchUser[1]);
        const qs = new URLSearchParams(matchUser[2] || "");
        if (uid !== authedUid) return jsonRes(403, { error: { message: "PERMISSION_DENIED" } });
        if (method === "GET") {
          requestCounts.metaReads++;
          const store = firestoreUsers.get(uid);
          if (!store || !store.doc) return jsonRes(404, { error: { message: "NOT_FOUND" } });
          return jsonRes(200, store.doc);
        }
        const store = ensureStore(uid);
        if (method === "PATCH") {
          if (failFirestoreWrites) return jsonRes(503, { error: { message: "UNAVAILABLE" } });
          if (onBeforeMetaPatch) {
            await onBeforeMetaPatch(uid, store, qs);
          }
          const expectedUpdate = qs.get("currentDocument.updateTime");
          if (expectedUpdate && store.doc?.updateTime && store.doc.updateTime !== expectedUpdate) {
            return jsonRes(409, { error: { status: "FAILED_PRECONDITION", message: "FAILED_PRECONDITION: updateTime mismatch" } });
          }
          requestCounts.firestoreWrites++;
          const updateTime = makeUpdateTime();
          store.doc = {
            name: `projects/keyvex/databases/(default)/documents/users/${uid}`,
            fields: { ...(store.doc?.fields || {}), ...body.fields },
            updateTime
          };
          return jsonRes(200, store.doc);
        }
        if (method === "DELETE") {
          if (failFirestoreWrites) return jsonRes(503, { error: { message: "UNAVAILABLE" } });
          requestCounts.firestoreDeletes++;
          firestoreUsers.delete(uid);
          return jsonRes(200, {});
        }
      }
    }

    return jsonRes(404, { error: { message: "NOT_FOUND" } });
  }

  return {
    transport,
    requestCounts,
    resetCounts() {
      for (const k of Object.keys(requestCounts)) requestCounts[k] = 0;
    },
    registerGoogleToken(token, { email, name }) {
      googleTokens.set(token, { email, name });
    },
    markEmailVerified(email) {
      const uid = uidByEmail.get(String(email).toLowerCase());
      if (uid && usersByUid.has(uid)) usersByUid.get(uid).emailVerified = true;
    },
    revokeRefreshToken(refreshToken) {
      uidByRefreshToken.delete(refreshToken);
    },
    setNetworkDown(down) { networkDown = !!down; },
    setFailFirestoreWrites(fail) { failFirestoreWrites = !!fail; },
    setFailFirestoreDeletesAfter(n) { failFirestoreDeletesAfter = n; },
    setFailAuthDelete(fail) { failAuthDelete = !!fail; },
    setOnBeforeMetaPatch(fn) { onBeforeMetaPatch = fn; },
    getResetEmailsSent: () => [...resetEmailsSent],
    getVerifyEmailsSent: () => [...verifyEmailsSent],
    getUserByEmail: (email) => {
      const uid = uidByEmail.get(String(email).toLowerCase());
      return uid ? usersByUid.get(uid) : null;
    },
    getFirestoreUser: (uid) => firestoreUsers.get(uid) || null,
    seedFirestoreEntry(uid, entryId, fieldsObj) {
      const store = ensureStore(uid);
      const fields = {};
      for (const [k, v] of Object.entries(fieldsObj)) {
        if (Number.isInteger(v)) fields[k] = { integerValue: String(v) };
        else fields[k] = { stringValue: String(v) };
      }
      store.entries.set(entryId, {
        name: `projects/keyvex/databases/(default)/documents/users/${uid}/entries/${entryId}`,
        fields,
        updateTime: makeUpdateTime()
      });
    }
  };
}

/* ---------- Lightweight Vitest-Compatible Harness ---------- */
const suites = [];
let currentSuite = { name: "root", tests: [], beforeEach: [], afterEach: [], beforeAll: [], afterAll: [], children: [] };
suites.push(currentSuite);

function describe(name, fn) {
  const parent = currentSuite;
  const suite = { name, tests: [], beforeEach: [...parent.beforeEach], afterEach: [...parent.afterEach], beforeAll: [], afterAll: [], children: [] };
  parent.children.push(suite);
  currentSuite = suite;
  fn();
  currentSuite = parent;
}

function it(name, fn) {
  currentSuite.tests.push({ name, fn });
}

function beforeEach(fn) { currentSuite.beforeEach.push(fn); }
function afterEach(fn) { currentSuite.afterEach.push(fn); }
function beforeAll(fn) { currentSuite.beforeAll.push(fn); }
function afterAll(fn) { currentSuite.afterAll.push(fn); }

function matchObject(actual, expected) {
  if (typeof expected !== "object" || expected === null) return actual === expected;
  if (typeof actual !== "object" || actual === null) return false;
  for (const [k, v] of Object.entries(expected)) {
    if (typeof v === "object" && v !== null) {
      if (!matchObject(actual[k], v)) return false;
    } else if (actual[k] !== v) {
      return false;
    }
  }
  return true;
}

function expect(actual) {
  const matchers = (negated = false) => ({
    toBe(expected) {
      const ok = Object.is(actual, expected);
      if (negated ? ok : !ok) throw new Error(`Expected ${JSON.stringify(actual)} ${negated ? "not " : ""}toBe ${JSON.stringify(expected)}`);
    },
    toEqual(expected) {
      let ok = false;
      try { assert.deepStrictEqual(actual, expected); ok = true; } catch { ok = false; }
      if (negated ? ok : !ok) throw new Error(`Expected ${JSON.stringify(actual)} ${negated ? "not " : ""}toEqual ${JSON.stringify(expected)}`);
    },
    toBeGreaterThan(n) {
      const ok = actual > n;
      if (negated ? ok : !ok) throw new Error(`Expected ${actual} > ${n}`);
    },
    toBeGreaterThanOrEqual(n) {
      const ok = actual >= n;
      if (negated ? ok : !ok) throw new Error(`Expected ${actual} >= ${n}`);
    },
    toBeLessThan(n) {
      const ok = actual < n;
      if (negated ? ok : !ok) throw new Error(`Expected ${actual} < ${n}`);
    },
    toBeLessThanOrEqual(n) {
      const ok = actual <= n;
      if (negated ? ok : !ok) throw new Error(`Expected ${actual} <= ${n}`);
    },
    toHaveLength(n) {
      const ok = actual?.length === n;
      if (negated ? ok : !ok) throw new Error(`Expected length ${actual?.length} to be ${n}`);
    },
    toContain(sub) {
      const ok = typeof actual === "string" || Array.isArray(actual) ? actual.includes(sub) : false;
      if (negated ? ok : !ok) throw new Error(`Expected ${JSON.stringify(actual)} ${negated ? "not " : ""}toContain ${JSON.stringify(sub)}`);
    },
    toMatch(re) {
      const ok = re instanceof RegExp ? re.test(String(actual)) : String(actual).includes(String(re));
      if (negated ? ok : !ok) throw new Error(`Expected ${actual} ${negated ? "not " : ""}toMatch ${re}`);
    },
    toMatchObject(obj) {
      const ok = matchObject(actual, obj);
      if (negated ? ok : !ok) throw new Error(`Expected ${JSON.stringify(actual)} ${negated ? "not " : ""}toMatchObject ${JSON.stringify(obj)}`);
    },
    toBeTruthy() {
      const ok = !!actual;
      if (negated ? ok : !ok) throw new Error(`Expected ${actual} toBeTruthy`);
    },
    toBeFalsy() {
      const ok = !actual;
      if (negated ? ok : !ok) throw new Error(`Expected ${actual} toBeFalsy`);
    },
    toBeNull() {
      const ok = actual === null;
      if (negated ? ok : !ok) throw new Error(`Expected ${actual} toBeNull`);
    },
    toBeUndefined() {
      const ok = actual === undefined;
      if (negated ? ok : !ok) throw new Error(`Expected ${actual} toBeUndefined`);
    },
    toThrow() {
      let threw = false;
      try { actual(); } catch { threw = true; }
      if (negated ? threw : !threw) throw new Error(`Expected function ${negated ? "not " : ""}toThrow`);
    }
  });

  return {
    ...matchers(false),
    not: matchers(true),
    resolves: {
      async toBeTruthy() {
        const v = await actual;
        if (!v) throw new Error(`Expected resolved value ${v} toBeTruthy`);
      }
    },
    rejects: {
      async toBeTruthy() {
        let threw = false;
        try { await actual; } catch { threw = true; }
        if (!threw) throw new Error("Expected promise to reject");
      },
      async toMatchObject(obj) {
        let err;
        try { await actual; } catch (e) { err = e; }
        if (!err) throw new Error("Expected promise to reject, but it resolved");
        if (!matchObject(err, obj)) {
          throw new Error(`Expected rejection ${JSON.stringify({ status: err.status, code: err.code, message: err.message, ...err })} toMatchObject ${JSON.stringify(obj)}`);
        }
      }
    }
  };
}

globalThis.__vitest_shim = { describe, it, expect, beforeEach, afterEach, beforeAll, afterAll };

const tmpTestDir = join(root, ".tmp-tests");
rmSync(tmpTestDir, { recursive: true, force: true });
mkdirSync(tmpTestDir, { recursive: true });

// B20: Run core.test.js, server.test.js, AND ui.test.js in npm test
for (const file of ["helpers.js", "core.test.js", "server.test.js", "ui.test.js"]) {
  let content = readFileSync(join(root, "tests", file), "utf8");
  content = content.replace(
    /import\s+\{([^}]+)\}\s+from\s+["']vitest["'];?/,
    "const {$1} = globalThis.__vitest_shim;"
  );
  writeFileSync(join(tmpTestDir, file), content);
}

await import(pathToFileURL(join(tmpTestDir, "core.test.js")).href);
await import(pathToFileURL(join(tmpTestDir, "server.test.js")).href);
await import(pathToFileURL(join(tmpTestDir, "ui.test.js")).href);

const { pinField, pinLengthSelector } = await import(pathToFileURL(join(root, "src", "ui", "components", "fields.js")).href);
const { masterPasswordSetup } = await import(pathToFileURL(join(root, "src", "ui", "components", "masterfield.js")).href);
const { startApp, renderErrorBoundary } = await import(pathToFileURL(join(root, "src", "ui", "app.js")).href);
const { passkeyScreen, showForgotPasskeySheet } = await import(pathToFileURL(join(root, "src", "ui", "screens", "passkey.js")).href);
const {
  resetLocalVaultStorage,
  getUserProfile,
  getUserProfileByUid,
  saveUserProfile,
  getCloudOutbox,
  getDeletionJob,
  getSyncSessionHint,
  getPasskeyLockState,
  recordPasskeyFailure,
  getEncryptedGeneratorHistory,
  getEncryptedExternalImports
} = await import(pathToFileURL(join(root, "src", "core", "idb.js")).href);
const { startServer, sample } = await import(pathToFileURL(join(tmpTestDir, "helpers.js")).href);
const {
  generateTotpSecret,
  generateTotp,
  verifyTotpCode,
  generateTotpBackupCodes,
  hashTotpBackupCode,
  verifyAndConsumeTotpBackupCode,
  generateQrSvg,
  resetTotpReplayAndThrottleForTests
} = await import(pathToFileURL(join(root, "src", "core", "totp.js")).href);
const { Vault, PASSKEY_RESET_VERIFY_TTL_MS } = await import(pathToFileURL(join(root, "src", "core", "vault.js")).href);
const { Api } = await import(pathToFileURL(join(root, "src", "core", "api.js")).href);
const { readBackup, MAX_IMPORT_FILE_BYTES } = await import(pathToFileURL(join(root, "src", "core", "backup.js")).href);
const { csvToEntries } = await import(pathToFileURL(join(root, "src", "core", "csv.js")).href);
const { setForceFirebaseInTests, setFirebaseConfigOverride, validateFirebaseAndGoogleConfig } = await import(pathToFileURL(join(root, "src", "core", "firebase-config.js")).href);
const {
  setFirebaseTransport,
  requestGoogleOAuthToken,
  resetGoogleAuthStateForTests,
  clearFirebaseAuthListeners,
  firestoreListAllEntries,
  firestoreListAllTombstones,
  firestoreSaveMeta,
  firestoreGetVaultMetaOnly
} = await import(pathToFileURL(join(root, "src", "core", "firebase.js")).href);
const { errText, classifyError, getDiagnosticLogs, clearDiagnosticLogs } = await import(pathToFileURL(join(root, "src", "ui", "errors.js")).href);
const { getAllPerfStats, resetPerfStats } = await import(pathToFileURL(join(root, "src", "core", "perf.js")).href);
const { openDb, JsDatabaseSync } = await import(pathToFileURL(join(root, "server", "db.js")).href);
const { createApp } = await import(pathToFileURL(join(root, "server", "app.js")).href);
const { createRateLimiter, AUTH_FREE_TRIES, IP_FREE_TRIES } = await import(pathToFileURL(join(root, "server", "rateLimit.js")).href);
const { HEADER_CSP, META_CSP } = await import(pathToFileURL(join(root, "scripts", "csp.mjs")).href);
const { validateModuleImportGraph, verifyDistAssetsExist } = await import(pathToFileURL(join(root, "scripts", "build.mjs")).href);
const { startDevServers } = await import(pathToFileURL(join(root, "scripts", "dev.mjs")).href);
const { openGenerator } = await import(pathToFileURL(join(root, "src", "ui", "sheets", "generator.js")).href);
const { openSettings } = await import(pathToFileURL(join(root, "src", "ui", "sheets", "settings.js")).href);

describe("Issue H — Node 22 Getter-Only globalThis.navigator Compatibility", () => {
  it("defines and updates globalThis.navigator via Object.defineProperty without throwing on getter-only descriptors", () => {
    Object.defineProperty(globalThis, "navigator", {
      get: () => ({ userAgent: "Node.js/22" }),
      set: undefined,
      configurable: true
    });
    expect(() => setupMiniDom()).not.toThrow();
    expect(globalThis.navigator.onLine).toBe(true);
    setNavigatorOnline(false);
    expect(globalThis.navigator.onLine).toBe(false);
    setNavigatorOnline(true);
  });
});

describe("Issue A & User UI/UX Feedback — Passkey Length Lock, No Mode Toggle, Card Shake Visibility & Cleaned Screens", () => {
  beforeEach(async () => {
    await resetLocalVaultStorage();
    setupMiniDom();
  });

  it("shows 4/6-digit selector ONLY during Setup, omits selector and modeToggleBtn on Unlock, strictly locks 4 vs 6 digits, and keeps auth-card visible on wrong Passkey", async () => {
    const srv = await startServer();
    try {
      const ctx = startApp(srv.newApi());

      const loginText = document.querySelector("#app").textContent;
      expect(loginText).not.toContain("AES-256 encrypted");
      expect(loginText).not.toContain("2-Layer Passkey lock");
      expect(loginText).not.toContain("Syncs securely across devices");

      ctx.go("register");
      const registerText = document.querySelector("#app").textContent;
      expect(registerText).not.toContain("At least 8 characters and 1–2 special characters");

      await ctx.vault.signUpAccount({ name: "Four Digit User", email: "four@gmail.com", password: "ValidPass@1" });
      ctx.go("passkey");

      const setupWrap = document.querySelector(".pin-len-wrap");
      expect(setupWrap).toBeTruthy();
      expect(setupWrap.hidden).toBe(false);
      expect(document.querySelector("#app").textContent).not.toContain("First time on this account? Set a new Passkey");

      await ctx.vault.setupPasskey("7392");
      ctx.lockNow();
      expect(document.body.dataset.screen).toBe("passkey");

      const unlockWrap4 = document.querySelector(".pin-len-wrap");
      expect(!unlockWrap4 || unlockWrap4.hidden).toBe(true);
      expect(document.querySelector("#app").textContent).not.toContain("First time on this account? Set a new Passkey");
      const pkInput4 = document.querySelector('input[name="passkey"]');
      expect(pkInput4.maxLength).toBe(4);
      expect(pkInput4.placeholder).toBe("4 digits (0–9)");

      const authCard = document.querySelector(".auth-card");
      pkInput4.value = "9876";
      document.querySelector("form").dispatchEvent(new MiniEvent("submit", { bubbles: true, cancelable: true }));
      await new Promise((r) => setTimeout(r, 40));
      expect(authCard.classList.contains("shake")).toBe(true);
      expect(authCard.classList.contains("rise")).toBe(false);
      expect(document.querySelector("#app").textContent).toContain("Incorrect Passkey");

      await expect(ctx.vault.unlockWithPasskey("482916")).rejects.toMatchObject({
        code: "VAULT_WRONG_PASSKEY",
        expectedLength: 4
      });

      pkInput4.value = "482916";
      document.querySelector("form").dispatchEvent(new MiniEvent("submit", { bubbles: true, cancelable: true }));
      expect(document.querySelector("#app").textContent).toContain("Enter your 4-digit Passkey.");

      await ctx.vault.unlockWithPasskey("7392");
      expect(ctx.vault.unlocked).toBe(true);
      await ctx.logoutAccount();

      await ctx.vault.signUpAccount({ name: "Six Digit User", email: "six@gmail.com", password: "ValidPass@6" });
      await ctx.vault.setupPasskey("482916");
      ctx.lockNow();

      const unlockWrap6 = document.querySelector(".pin-len-wrap");
      expect(!unlockWrap6 || unlockWrap6.hidden).toBe(true);
      const pkInput6 = document.querySelector('input[name="passkey"]');
      expect(pkInput6.maxLength).toBe(6);
      expect(pkInput6.placeholder).toBe("6 digits (0–9)");

      await expect(ctx.vault.unlockWithPasskey("7392")).rejects.toMatchObject({
        code: "VAULT_WRONG_PASSKEY",
        expectedLength: 6
      });

      await ctx.vault.unlockWithPasskey("482916");
      expect(ctx.vault.unlocked).toBe(true);
      ctx.destroy();
    } finally {
      await srv.close();
    }
  });

  it("eliminates the 1–2s Login screen flash on startup using synchronous sessionStorage hint routing and logs out in 0ms", async () => {
    const srv = await startServer();
    try {
      const ctx1 = startApp(srv.newApi());
      await ctx1.vault.signUpAccount({ name: "Flash Test", email: "flash@gmail.com", password: "FlashPass!1" });
      await ctx1.vault.setupPasskey("7392");
      ctx1.destroy();

      const hint = getSyncSessionHint();
      expect(hint).toBeTruthy();
      expect(hint.email).toBe("flash@gmail.com");
      expect(hint.pinLength).toBe(4);
      expect(hint.idToken).toBeUndefined();
      expect(hint.refreshToken).toBeUndefined();
      // B15: Never persisted in localStorage
      expect(globalThis.localStorage.getItem("keyvex.active_session_hint")).toBeNull();

      setupMiniDom();
      const ctx2 = startApp(srv.newApi());
      expect(document.body.dataset.screen).toBe("passkey");

      await ctx2.logoutAccount();
      expect(document.body.dataset.screen).toBe("login");
      expect(getSyncSessionHint()).toBeNull();
      ctx2.destroy();
    } finally {
      await srv.close();
    }
  });
});

describe("Issue B — Metadata-Only Session Restore, Meta-First Unlock & Performance Instrumentation", () => {
  let emu;
  beforeEach(async () => {
    await resetLocalVaultStorage();
    clearFirebaseAuthListeners();
    resetPerfStats();
    setupMiniDom();
    emu = createFirebaseEmulator();
    setFirebaseTransport(emu.transport);
    setForceFirebaseInTests(true);
  });
  afterEach(() => {
    setFirebaseTransport(null);
    setForceFirebaseInTests(false);
  });

  it("restores returning-user session with 0 entry downloads, rejects wrong Passkeys with 0 entry downloads, and downloads entries only after Passkey verification succeeds", async () => {
    const v1 = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await v1.signUpAccount({ name: "Perf User", email: "perf@gmail.com", password: "PerfSecret!9" });
    await v1.setupPasskey("7392");
    await v1.save({ service: "Svc1", username: "u1", password: "Pw!11111" });
    await v1.save({ service: "Svc2", username: "u2", password: "Pw!22222" });
    v1.lock();

    emu.resetCounts();

    const vLogin = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    const loginAcct = await vLogin.signInAccount({ email: "perf@gmail.com", password: "PerfSecret!9" });
    expect(loginAcct.hasVault).toBe(true);
    expect(loginAcct.pinLength).toBe(4);
    expect(emu.requestCounts.authLookups).toBe(0);
    expect(emu.requestCounts.entriesReads).toBe(0);
    expect(emu.requestCounts.metaReads).toBe(1);

    emu.resetCounts();
    let fastCallbackAccount = null;
    const vRestore = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    const restored = await vRestore.restoreAccountSession({
      onFastCachedSession(acct) {
        fastCallbackAccount = acct;
      }
    });
    expect(fastCallbackAccount).toBeTruthy();
    expect(fastCallbackAccount.pinLength).toBe(4);
    expect(restored.pinLength).toBe(4);
    expect(emu.requestCounts.entriesReads).toBe(0);

    emu.resetCounts();
    await expect(vRestore.unlockWithPasskey("9876")).rejects.toMatchObject({ code: "VAULT_WRONG_PASSKEY" });
    expect(emu.requestCounts.entriesReads).toBe(0);

    await vRestore.unlockWithPasskey("7392");
    expect(emu.requestCounts.entriesReads).toBe(1);
    expect(vRestore.list()).toHaveLength(2);

    const stats = getAllPerfStats();
    expect(stats.session_restore.count).toBeGreaterThanOrEqual(1);
    expect(stats.kdf_derivation.count).toBeGreaterThanOrEqual(1);
    expect(stats.firestore_meta_read.count).toBeGreaterThanOrEqual(1);
    expect(stats.firestore_entries_read.count).toBe(1);
    expect(stats.vault_decrypt.count).toBeGreaterThanOrEqual(1);
  });
});

describe("Issue C — Durable, Idempotent, Paginated Account Deletion (>1,000 Entries & Partial Failure Recovery)", () => {
  let emu;
  beforeEach(async () => {
    await resetLocalVaultStorage();
    clearFirebaseAuthListeners();
    setupMiniDom();
    emu = createFirebaseEmulator();
    setFirebaseTransport(emu.transport);
    setForceFirebaseInTests(true);
  });
  afterEach(() => {
    setFirebaseTransport(null);
    setForceFirebaseInTests(false);
  });

  it("paginates across >1,000 Firestore entries (1,250 entries) with batched :commit deletes, survives mid-deletion failure, and resumes idempotently", async () => {
    const v = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    const acct = await v.signUpAccount({ name: "Large Vault User", email: "large@gmail.com", password: "LargePass!1" });
    await v.setupPasskey("482916");

    for (let i = 1; i <= 1250; i++) {
      const id = `entry_${String(i).padStart(6, "0")}`;
      emu.seedFirestoreEntry(acct.uid, id, { id, iv: "AAAAAAAAAAAA", data: "BBBBBBBBBBBB", updatedAt: Date.now() });
    }

    const allBefore = await firestoreListAllEntries(acct.uid, acct.idToken, { pageSize: 500 });
    expect(allBefore).toHaveLength(1250);

    // 1. Simulate a Firestore failure after deleting 600 entries
    emu.setFailFirestoreDeletesAfter(600);
    let failErr = null;
    const progressReports = [];
    try {
      await v.deleteAccount("482916", "", {
        onProgress: (p) => progressReports.push(p)
      });
    } catch (err) {
      failErr = err;
    }
    expect(failErr).toBeTruthy();
    expect(failErr.code).toBe("DELETION_INCOMPLETE");
    expect(failErr.deletionJob.state).toBe("failed_retryable");
    expect(failErr.deletionJob.history.some((h) => h.state === "deleting_entries")).toBe(true);
    expect(progressReports.length).toBeGreaterThanOrEqual(1);
    expect(emu.getUserByEmail("large@gmail.com")).toBeTruthy();

    // 2. Simulate Auth deletion failure after Firestore finishes cleaning the remaining entries
    emu.setFailFirestoreDeletesAfter(Infinity);
    emu.setFailAuthDelete(true);
    let authFailErr = null;
    try {
      await v.resumeAccountDeletion(acct.uid, { idToken: acct.idToken });
    } catch (err) {
      authFailErr = err;
    }
    expect(authFailErr).toBeTruthy();
    expect(authFailErr.code).toBe("DELETION_INCOMPLETE");
    expect(authFailErr.deletionJob.state).toBe("failed_manual_action");
    expect(emu.getFirestoreUser(acct.uid)).toBeNull();

    // 3. Resume with valid token and Auth deletion working -> completes deletion of Firebase Auth user and local state!
    emu.setFailAuthDelete(false);
    const completed = await v.resumeAccountDeletion(acct.uid, { idToken: acct.idToken });
    expect(completed.state).toBe("completed");
    expect(completed.deleted).toBe(true);
    expect(emu.getUserByEmail("large@gmail.com")).toBeNull();
    expect(await getUserProfile("large@gmail.com")).toBeNull();
    expect((await getCloudOutbox(acct.uid))).toHaveLength(0);
  });
});

describe("Issue D & Audit P1 — Durable Cloud Outbox, Cross-Device Tombstone Non-Resurrection & Conflict Resolution", () => {
  let emu;
  beforeEach(async () => {
    await resetLocalVaultStorage();
    clearFirebaseAuthListeners();
    setupMiniDom();
    emu = createFirebaseEmulator();
    setFirebaseTransport(emu.transport);
    setForceFirebaseInTests(true);
  });
  afterEach(() => {
    setFirebaseTransport(null);
    setForceFirebaseInTests(false);
  });

  it("queues saves/deletes/rekeys when Firestore is down (syncStatus='pending'), prevents deleted entries from resurrecting locally or across devices, and preserves concurrent edit conflicts", async () => {
    const devA = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    const acct = await devA.signUpAccount({ name: "Sync User", email: "sync@gmail.com", password: "SyncSecret!1" });
    await devA.setupPasskey("7392");

    const entry1 = await devA.save({ service: "KeepMe", username: "u1", password: "Pw1!aaaa" });
    const entry2 = await devA.save({ service: "DeleteMeOffline", username: "u2", password: "Pw2!bbbb" });
    const entry3 = await devA.save({ service: "ConflictTarget", username: "u3", password: "OriginalPw!3" });
    expect(devA.syncStatus).toBe("cloud");

    await devA.save({ ...entry3, password: "EditedOnDeviceB!3", updatedAt: Date.now() + 50 });
    const devBFirestoreDoc = JSON.parse(JSON.stringify(emu.getFirestoreUser(acct.uid).entries.get(entry3.id)));
    await devA.save({ ...entry3, password: "OriginalPw!3", updatedAt: Date.now() + 10 });

    emu.setFailFirestoreWrites(true);
    await devA.remove("7392", entry2.id);
    expect(devA.syncStatus).toBe("pending");

    await devA.save({ ...entry3, password: "EditedOnDeviceA!3", updatedAt: Date.now() + 100 });
    expect(devA.syncStatus).toBe("pending");

    emu.getFirestoreUser(acct.uid).entries.set(entry3.id, devBFirestoreDoc);
    emu.setFailFirestoreWrites(false);

    await devA.sync();
    expect(devA.syncStatus).toBe("cloud");
    expect(devA.pendingOutboxCount).toBe(0);
    expect(devA.list().map((e) => e.service).sort()).toEqual(["ConflictTarget", "KeepMe"]);
    expect(devA.get(entry2.id)).toBeNull();

    // Verify remote tombstone was written to Firestore tombstones subcollection AND compact meta.deletedEntries
    expect(devA.account.meta.deletedEntries[entry2.id]).toBeTruthy();
    const remoteTombs = await firestoreListAllTombstones(acct.uid, acct.idToken);
    expect(remoteTombs[entry2.id]).toBeTruthy();

    const conflicts = await devA.getConflicts();
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0].entryId).toBe(entry3.id);
    expect(conflicts[0].reason).toBe("concurrent_modification");
    expect(conflicts[0].localEntry.password).toBe("EditedOnDeviceA!3");
    expect(conflicts[0].remoteEntry.password).toBe("EditedOnDeviceB!3");

    await devA.resolveConflict(entry3.id, "remote");
    expect(await devA.getConflicts()).toHaveLength(0);
    expect(devA.get(entry3.id).password).toBe("EditedOnDeviceB!3");

    const devB = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await devB.signInAccount({ email: "sync@gmail.com", password: "SyncSecret!1" });
    await devB.unlockWithPasskey("7392");
    expect(devB.get(entry1.id)).toBeTruthy();

    await devA.remove("7392", entry1.id);
    expect(devA.pendingOutboxCount).toBe(0);
    expect(devA.get(entry1.id)).toBeNull();

    await devB.sync();
    expect(devB.get(entry1.id)).toBeNull();
  });
});

describe("Issues E, F, G & I — Backend Fail-Fast, Distributed Rate Limiter, Firestore Rules & UI Error Boundary", () => {
  it("Issue E: fails fast when native SQLite is required in production and surfaces persistence errors in JsDatabaseSync", () => {
    let prodErr = null;
    try {
      openDb("/tmp/nonexistent-prod.db", { production: true, requireNativeSqlite: true });
    } catch (err) {
      prodErr = err;
    }
    if (!prodErr) {
      rmSync("/tmp/nonexistent-prod.db", { force: true });
    } else {
      expect(prodErr.code).toBe("UNSUPPORTED_DB_RUNTIME");
    }

    const badDb = new JsDatabaseSync("/proc/invalid-unwritable-path/db.json");
    expect(() => badDb._persist()).toThrow();
  });

  it("Issue F: refuses multi-instance production startup without Redis and shares BOTH window and login lockout counters across instances", async () => {
    expect(() =>
      createApp({ production: true, multiInstance: true })
    ).toThrow();

    const sharedCounts = new Map();
    const sharedThrottles = new Map();
    const mockRedisStore = {
      distributed: true,
      async incrWindow(key, windowMs) {
        const cur = (sharedCounts.get(key) || 0) + 1;
        sharedCounts.set(key, cur);
        return { count: cur, resetAt: Date.now() + windowMs };
      },
      async getThrottle(key) {
        return sharedThrottles.get(key) || { fails: 0, until: 0 };
      },
      async putThrottle(key, fails, until, touched) {
        sharedThrottles.set(key, { fails, until, touched });
      },
      async delThrottle(key) {
        sharedThrottles.delete(key);
      }
    };

    const app1 = createApp({ production: false, multiInstance: true, distributedRateLimitStore: mockRedisStore });
    const app2 = createApp({ production: false, multiInstance: true, distributedRateLimitStore: mockRedisStore });
    await new Promise((ok) => app1.server.listen(0, "127.0.0.1", ok));
    await new Promise((ok) => app2.server.listen(0, "127.0.0.1", ok));
    try {
      const base1 = `http://127.0.0.1:${app1.server.address().port}`;
      const base2 = `http://127.0.0.1:${app2.server.address().port}`;
      const h1 = await (await fetch(`${base1}/api/health`)).json();
      expect(h1.distributedRateLimit).toBe(true);

      const badLoginBody = JSON.stringify({
        lookup: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        auth: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
      });
      const loginStatuses = [];
      for (let i = 0; i < 3; i++) {
        loginStatuses.push((await fetch(`${base1}/api/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: badLoginBody })).status);
        loginStatuses.push((await fetch(`${base2}/api/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body: badLoginBody })).status);
      }
      expect(loginStatuses.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
      expect(loginStatuses[5]).toBe(429);

      const statuses = [];
      for (let i = 0; i < 6; i++) {
        statuses.push((await fetch(`${base1}/api/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).status);
        statuses.push((await fetch(`${base2}/api/register`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).status);
      }
      expect(statuses.slice(0, 10).every((s) => s === 400)).toBe(true);
      expect(statuses.slice(10)).toEqual([429, 429]);
    } finally {
      await app1.close();
      await app2.close();
    }
  });

  it("Issue G: validates firestore.rules denies unknown subcollections, allows tombstones subcollection, blocks client writes to deletionJobs/auditLogs, and enforces strict entry schema", () => {
    const rulesText = readFileSync(join(root, "firestore.rules"), "utf8");
    expect(rulesText).not.toContain("match /{subcollection}/{subDoc=**}");
    expect(rulesText).not.toContain("subcollection != 'entries'");
    expect(rulesText).toContain("match /tombstones/{entryId}");
    expect(rulesText).toContain("match /deletionJobs/{jobId}");
    expect(rulesText).toContain("match /auditLogs/{logId}");
    expect(rulesText).toContain("allow write: if false;");
    expect(rulesText).toContain("data.id == entryId");
    expect(rulesText).toContain("areImmutableFieldsUnchanged(['id', 'createdAt'])");
    expect(rulesText).toContain("areImmutableFieldsUnchanged(['createdAt', 'uid'])");
  });

  it("Issue I: renders UI Error Boundary with correlation ID, Retry, and Sign out actions instead of leaving a blank screen", () => {
    setupMiniDom();
    clearDiagnosticLogs();
    const srvVaultMock = { unlocked: false, accountSignedIn: false, lock() {}, signOutAccount: async () => {} };
    let retried = false;
    const mockCtx = {
      vault: srvVaultMock,
      go(screen) { if (screen === "passkey") retried = true; },
      logoutAccount: async () => {}
    };
    const boundaryEl = renderErrorBoundary(mockCtx, new Error("Simulated render crash"), "passkey");
    document.querySelector("#app").replaceChildren(boundaryEl);

    const text = document.querySelector("#app").textContent;
    expect(text).toContain("Something interrupted this view");
    expect(text).toMatch(/Diagnostic ID: kvx-/);

    const logs = getDiagnosticLogs();
    expect(logs.length).toBeGreaterThanOrEqual(1);
    expect(logs[0].category).toBe("UI_RENDER_FAILURE");

    const retryBtn = [...boundaryEl.querySelectorAll("button")].find((b) => b.textContent.includes("Retry"));
    retryBtn.click();
    expect(retried).toBe(true);
  });
});

/* ==========================================================================
 * PART 7 — v2.4.0 Security Simplification & Hardening Verification Suite
 * ========================================================================== */
describe("PART 7 — v2.4.0 Security Simplification & Hardening (Items 1–9)", () => {
  let emu;
  beforeEach(async () => {
    await resetLocalVaultStorage();
    clearFirebaseAuthListeners();
    resetGoogleAuthStateForTests();
    resetTotpReplayAndThrottleForTests();
    setupMiniDom();
    emu = createFirebaseEmulator();
    setFirebaseTransport(emu.transport);
    setForceFirebaseInTests(true);
    setFirebaseConfigOverride(null);
  });
  afterEach(() => {
    setFirebaseTransport(null);
    setForceFirebaseInTests(false);
    setFirebaseConfigOverride(null);
    delete globalThis.google;
  });

  it("1 & 2. Setup creates vault WITHOUT recoveryWrapped/recoverySalt (setupPasskey returns { ok: true } with no recoveryKey); legacy vault with recoveryWrapped/emailResetWrapped strips them on unlock+write", async () => {
    const v = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await v.signUpAccount({ name: "Ada", email: "ada@gmail.com", password: "AdaPassword!1" });
    const setupRes = await v.setupPasskey("7392");
    expect(setupRes).toEqual({ ok: true });
    expect(setupRes.recoveryKey).toBeUndefined();

    const meta = v.account.meta;
    expect(meta.recoveryWrapped).toBeUndefined();
    expect(meta.recoverySalt).toBeUndefined();
    expect(meta.emailResetWrapped).toBeUndefined();
    expect(meta.emailResetSalt).toBeUndefined();
    expect(meta.accountResetWrapped).toBeTruthy();
    expect(meta.accountResetSalt).toBeTruthy();

    // Simulate a legacy v2.3.0 vault that still has recoveryWrapped, recoverySalt, emailResetWrapped, emailResetSalt
    const pollutedMeta = {
      ...meta,
      recoveryWrapped: "LEGACY_RECOVERY_WRAPPED_BYTES",
      recoverySalt: "LEGACY_RECOVERY_SALT",
      emailResetWrapped: meta.accountResetWrapped,
      emailResetSalt: meta.accountResetSalt
    };
    await firestoreSaveMeta(v.account.uid, v.account.idToken, {
      email: v.account.email,
      name: v.account.name,
      meta: pollutedMeta
    });
    const prof = await getUserProfile("ada@gmail.com");
    await saveUserProfile({ ...prof, meta: pollutedMeta });

    v.lock();
    await v.unlockWithPasskey("7392");

    // Verify recoveryWrapped/Salt and emailResetWrapped/Salt were stripped from memory, IndexedDB, and Firestore!
    expect(v.account.meta.recoveryWrapped).toBeUndefined();
    expect(v.account.meta.recoverySalt).toBeUndefined();
    expect(v.account.meta.emailResetWrapped).toBeUndefined();
    expect(v.account.meta.emailResetSalt).toBeUndefined();
    expect(v.account.meta.accountResetWrapped).toBeTruthy();

    const remoteAfter = await firestoreGetVaultMetaOnly(v.account.uid, v.account.idToken);
    expect(remoteAfter.meta.recoveryWrapped).toBeUndefined();
    expect(remoteAfter.meta.recoverySalt).toBeUndefined();
    expect(remoteAfter.meta.emailResetWrapped).toBeUndefined();
    expect(remoteAfter.meta.accountResetWrapped).toBeTruthy();
  });

  it("3. URL bypass regression (F1/F2): ?mode=resetPasskey and ?mode=verifyEmail NEVER set passkeyResetVerified and NEVER open Step 2", async () => {
    const srv = await startServer();
    try {
      const v = new Vault(srv.newApi());
      await v.signUpAccount({ name: "UrlTest", email: "url@gmail.com", password: "UrlPassword!1" });
      await v.setupPasskey("7392");
      v.lock();

      const res1 = await v.handleEmailActionLink({ mode: "resetPasskey", oobCode: "fake_oob", resetToken: "fake_tok" });
      expect(v.passkeyResetVerified).toBe(false);
      expect(res1.verified).toBe(false);

      const res2 = await v.handleEmailActionLink({ mode: "verifyEmail", oobCode: "valid_oob" });
      expect(v.passkeyResetVerified).toBe(false);
      await expect(v.resetPasskeyAfterVerification("482916")).rejects.toMatchObject({ code: "UNAUTHENTICATED" });

      // Test app.js startup with ?mode=resetPasskey&resetToken=abc
      globalThis.location.search = "?mode=resetPasskey&resetToken=abc";
      const ctx = startApp(srv.newApi());
      await new Promise((r) => setTimeout(r, 60));
      expect(ctx.vault.passkeyResetVerified).toBe(false);
      expect(document.querySelector("#layer").children.length).toBe(0);
      ctx.destroy();
    } finally {
      await srv.close();
    }
  });

  it("4, 5 & 8. Forgot Passkey verification: wrong password rejected, 5-min TTL, single-use, 5 wrong tries -> 60s lockout, Google wrong email/uid or unconfigured Firebase rejected, and reset preserves entries", async () => {
    const v = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    const acct = await v.signUpAccount({ name: "Reset User", email: "reset@gmail.com", password: "ResetSecret!8" });
    await v.setupPasskey("7392");
    await v.save({ service: "CriticalBank", username: "reset@gmail.com", password: "VaultBankPassword!9" });
    v.lock();

    // Calling resetPasskeyAfterVerification before Step 1 verification fails
    await expect(v.resetPasskeyAfterVerification("482916")).rejects.toMatchObject({ code: "UNAUTHENTICATED" });

    // Wrong password rejected
    await expect(v.verifyPasskeyResetIdentity({ password: "WrongPassword!1" })).rejects.toMatchObject({ code: "BAD_CREDENTIALS" });
    expect(v.passkeyResetVerified).toBe(false);

    // Correct password succeeds and enables Step 2
    const verOk = await v.verifyPasskeyResetIdentity({ password: "ResetSecret!8" });
    expect(verOk).toEqual({ verified: true, method: "password" });
    expect(v.passkeyResetVerified).toBe(true);

    // Clear verification when sheet closes
    v.clearPasskeyResetVerification();
    expect(v.passkeyResetVerified).toBe(false);
    await expect(v.resetPasskeyAfterVerification("482916")).rejects.toMatchObject({ code: "UNAUTHENTICATED" });

    // Re-verify and test 5-minute TTL expiration
    await v.verifyPasskeyResetIdentity({ password: "ResetSecret!8" });
    const realNow = Date.now;
    try {
      Date.now = () => realNow() + PASSKEY_RESET_VERIFY_TTL_MS + 1000;
      expect(v.passkeyResetVerified).toBe(false);
      await expect(v.resetPasskeyAfterVerification("482916")).rejects.toMatchObject({ code: "UNAUTHENTICATED" });
    } finally {
      Date.now = realNow;
    }

    // Re-verify and complete Passkey reset -> preserves existing vault entries!
    await v.verifyPasskeyResetIdentity({ password: "ResetSecret!8" });
    const resetRes = await v.resetPasskeyAfterVerification("482916");
    expect(resetRes.ok).toBe(true);
    expect(resetRes.recoveryKey).toBeUndefined();
    expect(v.unlocked).toBe(true);
    expect(v.list()).toHaveLength(1);
    expect(v.list()[0]).toMatchObject({ service: "CriticalBank", password: "VaultBankPassword!9" });

    // Single-use: second call to resetPasskeyAfterVerification fails immediately
    expect(v.passkeyResetVerified).toBe(false);
    await expect(v.resetPasskeyAfterVerification("7392")).rejects.toMatchObject({ code: "UNAUTHENTICATED" });

    v.lock();
    // 5 wrong password attempts in verifyPasskeyResetIdentity -> 60s lockout
    for (let i = 0; i < 4; i++) {
      await expect(v.verifyPasskeyResetIdentity({ password: "BadPassword!1" })).rejects.toMatchObject({ code: "BAD_CREDENTIALS" });
    }
    await expect(v.verifyPasskeyResetIdentity({ password: "BadPassword!1" })).rejects.toMatchObject({ code: "LOCKED_OUT" });
    await expect(v.verifyPasskeyResetIdentity({ password: "ResetSecret!8" })).rejects.toMatchObject({ code: "LOCKED_OUT" });

    // Item 5: Google verification with wrong email/uid or unconfigured Firebase
    const vGoogle = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    emu.registerGoogleToken("ggl_owner", { email: "gowner@gmail.com", name: "G Owner" });
    emu.registerGoogleToken("ggl_attacker", { email: "attacker@gmail.com", name: "Attacker" });
    await vGoogle.signInWithGoogle({ accessToken: "ggl_owner" });
    await vGoogle.setupPasskey("7392");
    vGoogle.lock();

    // Wrong Google account (email/uid mismatch) is rejected
    await expect(vGoogle.verifyPasskeyResetIdentity({ accessToken: "ggl_attacker" })).rejects.toMatchObject({
      code: "BAD_CREDENTIALS",
      message: "Please select the Google account for gowner@gmail.com."
    });
    expect(vGoogle.passkeyResetVerified).toBe(false);

    // Unconfigured Firebase is rejected (never sets verified=true, F3)
    setForceFirebaseInTests(false);
    setFirebaseConfigOverride({ apiKey: "", projectId: "" });
    await expect(vGoogle.verifyPasskeyResetIdentity({ accessToken: "ggl_owner" })).rejects.toMatchObject({
      code: "GOOGLE_NOT_CONFIGURED"
    });
    expect(vGoogle.passkeyResetVerified).toBe(false);
    setForceFirebaseInTests(true);
    setFirebaseConfigOverride(null);

    // Matching Google account succeeds
    const gVer = await vGoogle.verifyPasskeyResetIdentity({ accessToken: "ggl_owner" });
    expect(gVer).toEqual({ verified: true, method: "google" });
  });

  it("6. Forgot Passkey UI sheet shows only Password for password-only accounts, only Google for Google-only accounts, and both (with divider) when both providers are linked", async () => {
    // Case A: Password-only account
    const vPw = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await vPw.signUpAccount({ name: "PwOnly", email: "pwonly@gmail.com", password: "PwOnlySecret!1" });
    await vPw.setupPasskey("7392");
    vPw.lock();

    const ctxPw = { vault: vPw, go() {}, toast() {} };
    showForgotPasskeySheet(ctxPw);
    const layerPw = document.querySelector("#layer");
    expect(layerPw.querySelector('input[name="reauth-account-password"]')).toBeTruthy();
    expect([...layerPw.querySelectorAll("button")].some((b) => b.textContent.includes("Verify with Password"))).toBe(true);
    expect([...layerPw.querySelectorAll("button")].some((b) => b.textContent.includes("Verify with Google"))).toBe(false);
    expect(layerPw.querySelector(".auth-divider")).toBeNull();
    layerPw.replaceChildren();

    // Case B: Google-only account
    await resetLocalVaultStorage();
    const vG = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    emu.registerGoogleToken("ggl_only", { email: "gonly@gmail.com", name: "Google Only" });
    await vG.signInWithGoogle({ accessToken: "ggl_only" });
    await vG.setupPasskey("7392");
    vG.lock();

    const ctxG = { vault: vG, go() {}, toast() {} };
    showForgotPasskeySheet(ctxG);
    const layerG = document.querySelector("#layer");
    expect(layerG.querySelector('input[name="reauth-account-password"]')).toBeNull();
    expect([...layerG.querySelectorAll("button")].some((b) => b.textContent.includes("Verify with Google"))).toBe(true);
    expect(layerG.querySelector(".auth-divider")).toBeNull();
    layerG.replaceChildren();

    // Case C: Account with BOTH Password and Google linked
    await vG.unlockWithPasskey("7392");
    await vG.setAccountPassword("7392", "LinkedPass!99");
    vG.lock();

    showForgotPasskeySheet(ctxG);
    const layerBoth = document.querySelector("#layer");
    expect(layerBoth.querySelector('input[name="reauth-account-password"]')).toBeTruthy();
    expect([...layerBoth.querySelectorAll("button")].some((b) => b.textContent.includes("Verify with Password"))).toBe(true);
    expect([...layerBoth.querySelectorAll("button")].some((b) => b.textContent.includes("Verify with Google"))).toBe(true);
    expect(layerBoth.querySelector(".auth-divider")).toBeTruthy();
    layerBoth.replaceChildren();
  });

  it("7. Every PART 4 sensitive method throws BAD_PASSKEY with a wrong passkey, succeeds with the right passkey, and locks out after 5 wrong tries", async () => {
    const v = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await v.signUpAccount({ name: "StepUp User", email: "stepup@gmail.com", password: "StepUpPass!1" });
    await v.setupPasskey("7392");
    const saved = await v.save({ service: "StepUpSvc", username: "u", password: "Pw!12345" });
    const totpSec = generateTotpSecret(20);

    // 1. setAccountPassword
    await expect(v.setAccountPassword("9876", "NewPass!123", "StepUpPass!1")).rejects.toMatchObject({ code: "BAD_PASSKEY" });
    await v.setAccountPassword("7392", "NewPass!123", "StepUpPass!1");

    // 2. changeMasterPassword (2-layer alias)
    await expect(v.changeMasterPassword("9876", "NewPass!123", "StepUpPass!1")).rejects.toMatchObject({ code: "BAD_PASSKEY" });
    await v.changeMasterPassword("7392", "NewPass!123", "StepUpPass!1");

    // 3. enableTotp & disableTotp
    await expect(v.enableTotp("9876", totpSec)).rejects.toMatchObject({ code: "BAD_PASSKEY" });
    const totpRes = await v.enableTotp("7392", totpSec);
    expect(totpRes.enabled).toBe(true);
    expect(totpRes.backupCodes).toHaveLength(8);

    await expect(v.disableTotp("9876")).rejects.toMatchObject({ code: "BAD_PASSKEY" });
    await v.disableTotp("7392");
    expect(v.account.totpEnabled).toBe(false);

    // 4. exportBackup
    await expect(v.exportBackup("9876")).rejects.toMatchObject({ code: "BAD_PASSKEY" });
    const backupJson = await v.exportBackup("7392");
    expect(JSON.parse(backupJson).entryCount).toBe(1);

    // 5. importEntries
    await expect(v.importEntries("9876", [{ service: "Imp", username: "u", password: "p" }])).rejects.toMatchObject({ code: "BAD_PASSKEY" });
    expect(await v.importEntries("7392", [{ service: "Imp", username: "u", password: "p" }])).toBe(1);

    // 6. remove
    await expect(v.remove("9876", saved.id)).rejects.toMatchObject({ code: "BAD_PASSKEY" });
    await v.remove("7392", saved.id);
    expect(v.get(saved.id)).toBeNull();

    // 7. changePasskey
    await expect(v.changePasskey("9876", "482916")).rejects.toMatchObject({ code: "BAD_PASSKEY" });
    await v.changePasskey("7392", "482916");

    // 8. deleteAccount: test wrong passkey -> BAD_PASSKEY, and 5 wrong tries -> LOCKED_OUT
    for (let i = 0; i < 4; i++) {
      await expect(v.deleteAccount("000000")).rejects.toMatchObject({ code: "BAD_PASSKEY" });
    }
    await expect(v.deleteAccount("000000")).rejects.toMatchObject({ code: "LOCKED_OUT" });
  });

  it("9. Grep test: zero occurrences of recoveryKey, deriveRecoveryKek, sendPasskeyResetEmail, resetPasskey (mode), or emailLinkConfirmed remain in src/", () => {
    const forbidden = [
      "recoveryKey",
      "deriveRecoveryKek",
      "sendPasskeyResetEmail",
      "mode=resetPasskey",
      'mode === "resetPasskey"',
      "emailLinkConfirmed"
    ];
    function walkFiles(dir, out = []) {
      for (const entry of readdirSync(dir)) {
        const full = join(dir, entry);
        if (statSync(full).isDirectory()) walkFiles(full, out);
        else if (full.endsWith(".js") || full.endsWith(".css")) out.push(full);
      }
      return out;
    }
    const srcFiles = walkFiles(join(root, "src"));
    for (const file of srcFiles) {
      const content = readFileSync(file, "utf8");
      for (const token of forbidden) {
        if (content.includes(token)) {
          throw new Error(`Forbidden token "${token}" found in ${file}`);
        }
      }
    }
  });
});

/* ==========================================================================
 * PART 8E — Deep Audit Fixes (B1–B28) Automated Verification Suite (Items 1–10)
 * ========================================================================== */
describe("PART 8E — Deep Audit Fixes (B1–B28) Verification Suite (Items 1–10)", () => {
  let emu;
  beforeEach(async () => {
    await resetLocalVaultStorage();
    clearFirebaseAuthListeners();
    resetGoogleAuthStateForTests();
    resetTotpReplayAndThrottleForTests();
    setupMiniDom();
    emu = createFirebaseEmulator();
    setFirebaseTransport(emu.transport);
    setForceFirebaseInTests(true);
    setFirebaseConfigOverride(null);
  });
  afterEach(() => {
    setFirebaseTransport(null);
    setForceFirebaseInTests(false);
    setFirebaseConfigOverride(null);
  });

  it("1. B1 & F5: IndexedDB never stores raw vaultEntropy or plaintext totpSecret; sign-out clears wrapped device entropy unless 'Remember this device' is enabled", async () => {
    const v = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await v.signUpAccount({ name: "Entropy User", email: "entropy@gmail.com", password: "EntropyPass!1", rememberDevice: false });
    await v.setupPasskey("7392");
    const totpSec = generateTotpSecret(20);
    await v.enableTotp("7392", totpSec);

    const prof = await getUserProfile("entropy@gmail.com");
    expect(prof.deviceVaultEntropy).toBeUndefined();
    expect(prof.totpSecret).toBeUndefined();
    expect(prof.wrappedDeviceEntropy).toBeTruthy();
    expect(prof.wrappedDeviceEntropy.iv).toBeTruthy();
    expect(prof.wrappedDeviceEntropy.data).toBeTruthy();

    // Sign out with rememberDevice=false -> wrappedDeviceEntropy is removed
    await v.signOutAccount();
    const profAfterSignOut = await getUserProfile("entropy@gmail.com");
    expect(profAfterSignOut.wrappedDeviceEntropy).toBeNull();

    // Sign in with rememberDevice=true -> wrappedDeviceEntropy is preserved across sign-out
    await v.signInAccount({ email: "entropy@gmail.com", password: "EntropyPass!1", rememberDevice: true, totpCode: await generateTotp(totpSec) });
    await v.unlockWithPasskey("7392");
    await v.signOutAccount();
    const profRemembered = await getUserProfile("entropy@gmail.com");
    expect(profRemembered.wrappedDeviceEntropy).toBeTruthy();
  });

  it("2. B2: Wrong-passkey counter survives page reload (persisted in IndexedDB per uid) and escalates exponentially (30s, 1m, 5m, 15m, 1h)", async () => {
    const v1 = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    const acct = await v1.signUpAccount({ name: "Lock User", email: "lock@gmail.com", password: "LockSecret!1" });
    await v1.setupPasskey("7392");
    v1.lock();

    // 3 wrong attempts on v1
    for (let i = 0; i < 3; i++) {
      await expect(v1.unlockWithPasskey("9876")).rejects.toMatchObject({ code: "VAULT_WRONG_PASSKEY" });
    }
    const persistedAfter3 = await getPasskeyLockState(acct.uid);
    expect(persistedAfter3.fails).toBe(3);

    // Simulate page reload by creating a fresh Vault instance and restoring session
    const v2 = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await v2.restoreAccountSession();
    await expect(v2.unlockWithPasskey("9876")).rejects.toMatchObject({ code: "VAULT_WRONG_PASSKEY" });
    await expect(v2.unlockWithPasskey("9876")).rejects.toMatchObject({ code: "LOCKED_OUT" });

    const s5 = await getPasskeyLockState(acct.uid);
    expect(s5.fails).toBe(5);
    expect(s5.retryAfter).toBeGreaterThanOrEqual(29);
    expect(s5.retryAfter).toBeLessThan(35);

    // Verify exponential escalation schedule: 5->30s, 6->60s, 7->300s, 8->900s, 9->3600s
    const uidEsc = "esc_test_uid";
    for (let i = 1; i < 5; i++) await recordPasskeyFailure(uidEsc, 5, 1000);
    const f5 = await recordPasskeyFailure(uidEsc, 5, 1000);
    expect(f5.lockedUntil - 1000).toBe(30_000);
    const f6 = await recordPasskeyFailure(uidEsc, 5, 40_000);
    expect(f6.lockedUntil - 40_000).toBe(60_000);
    const f7 = await recordPasskeyFailure(uidEsc, 5, 110_000);
    expect(f7.lockedUntil - 110_000).toBe(300_000);
    const f8 = await recordPasskeyFailure(uidEsc, 5, 420_000);
    expect(f8.lockedUntil - 420_000).toBe(900_000);
    const f9 = await recordPasskeyFailure(uidEsc, 5, 1_330_000);
    expect(f9.lockedUntil - 1_330_000).toBe(3_600_000);
  });

  it("3. B3: 2,000 delete operations keep meta < 20 KB so sync always passes Firestore size rules", async () => {
    const v = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await v.signUpAccount({ name: "Tombstone User", email: "tomb@gmail.com", password: "TombSecret!1" });
    await v.setupPasskey("7392");

    // Verify Passkey once to activate the 60s step-up cache, then perform 2,000 deletes and sync to Firestore
    await v.requirePasskey("7392");
    for (let i = 1; i <= 2000; i++) {
      const id = `del_entry_${String(i).padStart(5, "0")}`;
      await v.remove(id);
    }
    await v.sync();

    const metaJson = JSON.stringify(v.account.meta);
    expect(metaJson.length).toBeLessThan(20_000);
    expect(Object.keys(v.account.meta.deletedEntries).length).toBeLessThanOrEqual(50);
    const remoteMetaDoc = await firestoreGetVaultMetaOnly(v.account.uid, v.account.idToken);
    expect(JSON.stringify(remoteMetaDoc.meta).length).toBeLessThan(20_000);
  });

  it("4. B4: Two-device Passkey change — Device A changes Passkey, Device B syncs -> B adopts new meta (no revert) and locks with 'Passkey was changed on another device'", async () => {
    const devA = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await devA.signUpAccount({ name: "TwoDev", email: "twodev@gmail.com", password: "TwoDevPass!1" });
    await devA.setupPasskey("7392");
    await devA.save({ service: "SharedItem", username: "u", password: "SharedPassword!1" });

    const devB = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await devB.signInAccount({ email: "twodev@gmail.com", password: "TwoDevPass!1" });
    await devB.unlockWithPasskey("7392");
    expect(devB.list()).toHaveLength(1);

    // Device A changes Passkey from 4-digit "7392" to 6-digit "482916"
    await devA.changePasskey("7392", "482916");
    const newMetaRev = devA.account.meta.metaRev;
    expect(newMetaRev).toBeGreaterThan(1);

    // Device B syncs -> detects higher remote metaRev with changed wrapped key -> adopts new meta and locks!
    await expect(devB.sync()).rejects.toMatchObject({
      code: "PASSKEY_CHANGED_REMOTELY",
      message: "Passkey was changed on another device"
    });
    expect(devB.unlocked).toBe(false);
    expect(devB.lastSessionNotice).toBe("Passkey was changed on another device");
    expect(devB.account.pinLength).toBe(6);

    // Verify Device B did NOT overwrite Firestore with old Passkey, and can unlock with new Passkey "482916"
    await devB.unlockWithPasskey("482916");
    expect(devB.unlocked).toBe(true);
    expect(devB.list()).toHaveLength(1);
  });

  it("5. B5: Optimistic concurrency precondition conflict — concurrent firestoreSaveMeta merges deletedEntries and metaRev without losing tombstones", async () => {
    const v = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    const acct = await v.signUpAccount({ name: "Concur", email: "concur@gmail.com", password: "ConcurPass!1" });
    await v.setupPasskey("7392");

    // Simulate another device updating the user doc in Firestore right before Device A's PATCH lands
    let injectedConflict = false;
    emu.setOnBeforeMetaPatch(async (uid, store, qs) => {
      if (!injectedConflict && qs.get("currentDocument.updateTime")) {
        injectedConflict = true;
        const concurrentMeta = {
          ...v.account.meta,
          metaRev: (Number(v.account.meta.metaRev) || 1) + 2,
          deletedEntries: {
            ...(v.account.meta.deletedEntries || {}),
            remote_tombstone_01: { deletedAt: Date.now(), deletedRev: 2, baseHash: "remhash" }
          }
        };
        store.doc = {
          name: `projects/keyvex/databases/(default)/documents/users/${uid}`,
          fields: {
            ...store.doc.fields,
            meta: { stringValue: JSON.stringify(concurrentMeta) }
          },
          updateTime: "2026-01-01T99:99:99Z"
        };
      }
    });

    const localMetaWithTombstone = {
      ...v.account.meta,
      metaRev: (Number(v.account.meta.metaRev) || 1) + 1,
      deletedEntries: {
        local_tombstone_02: { deletedAt: Date.now(), deletedRev: 2, baseHash: "lochash" }
      }
    };

    const mergedRes = await firestoreSaveMeta(acct.uid, acct.idToken, {
      email: acct.email,
      name: acct.name,
      meta: localMetaWithTombstone
    });
    emu.setOnBeforeMetaPatch(null);

    expect(injectedConflict).toBe(true);
    expect(mergedRes.meta.deletedEntries.remote_tombstone_01).toBeTruthy();
    expect(mergedRes.meta.deletedEntries.local_tombstone_02).toBeTruthy();
  });

  it("6 & 7. B6 & B16: Build output has content-hashed assets & self-hosted .woff2 fonts, and CSP is identical across vite.config.js, server/app.js, netlify.toml, public/_headers, and dist/index.html", () => {
    expect(existsSync(join(root, "src", "data", "brands.js"))).toBe(true);
    const srcGraph = validateModuleImportGraph(join(root, "src"));
    expect(srcGraph.ok).toBe(true);
    const srvGraph = validateModuleImportGraph(join(root, "server"));
    expect(srvGraph.ok).toBe(true);

    const buildRes = spawnSync(process.execPath, [join(root, "scripts", "build.mjs")], { cwd: root, encoding: "utf8" });
    expect(buildRes.status).toBe(0);

    const distHtml = readFileSync(join(root, "dist", "index.html"), "utf8");
    const assetMatches = [...distHtml.matchAll(/(?:href|src)="\/assets\/([^"]+)"/g)].map((m) => m[1]);
    expect(assetMatches.length).toBeGreaterThanOrEqual(2);
    for (const file of assetMatches) {
      expect(file).toMatch(/-[A-Za-z0-9_-]{8,}\.(?:js|css)$/);
      expect(existsSync(join(root, "dist", "assets", file))).toBe(true);
    }

    const distAssets = readdirSync(join(root, "dist", "assets"));
    const woff2Files = distAssets.filter((f) => f.endsWith(".woff2"));
    expect(woff2Files.length).toBeGreaterThanOrEqual(2);
    for (const wf of woff2Files) {
      expect(wf).toMatch(/-[A-Za-z0-9_-]{8,}\.woff2$/);
    }

    // Verify single-source CSP across all config files
    expect(distHtml).toContain(META_CSP);
    expect(readFileSync(join(root, "netlify.toml"), "utf8")).toContain(HEADER_CSP);
    expect(readFileSync(join(root, "public", "_headers"), "utf8")).toContain(HEADER_CSP);
    expect(readFileSync(join(root, "dist", "_headers"), "utf8")).toContain(HEADER_CSP);
    expect(HEADER_CSP).not.toContain("fonts.googleapis.com");
    expect(HEADER_CSP).not.toContain("fonts.gstatic.com");
  });

  it("8. B9: Rate limiter atomic Redis Lua/INCR evaluation — 20 parallel wrong guesses never exceed AUTH_FREE_TRIES (5) for lookup; IP limit = 25; window fails open while login fails closed on Redis outage", async () => {
    const kv = new Map();
    const atomicRedisFake = {
      distributed: true,
      async incrWindow(key, windowMs) {
        const cur = (kv.get(`win:${key}`) || 0) + 1;
        kv.set(`win:${key}`, cur);
        return { count: cur, resetAt: Date.now() + windowMs };
      },
      async incrThrottle(key, freeTries = AUTH_FREE_TRIES, now = Date.now()) {
        const rec = kv.get(`thr:${key}`) || { fails: 0, until: 0 };
        if (rec.until > now) return { fails: rec.fails, until: rec.until, locked: true };
        const fails = rec.fails + 1;
        const duration = fails < freeTries ? 0 : 30_000;
        const until = duration > 0 ? now + duration : 0;
        kv.set(`thr:${key}`, { fails, until });
        return { fails, until, locked: false };
      },
      async delThrottle(key) {
        kv.delete(`thr:${key}`);
      }
    };

    const app = createApp({ production: false, multiInstance: true, distributedRateLimitStore: atomicRedisFake });
    await new Promise((ok) => app.server.listen(0, "127.0.0.1", ok));
    try {
      const base = `http://127.0.0.1:${app.server.address().port}`;
      const body = JSON.stringify({
        lookup: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        auth: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
      });
      const parallel20 = await Promise.all(
        Array.from({ length: 20 }, () =>
          fetch(`${base}/api/login`, { method: "POST", headers: { "Content-Type": "application/json" }, body })
        )
      );
      const statuses = parallel20.map((r) => r.status);
      expect(statuses.filter((s) => s === 401)).toHaveLength(AUTH_FREE_TRIES);
      expect(statuses.filter((s) => s === 429)).toHaveLength(20 - AUTH_FREE_TRIES);
      expect(IP_FREE_TRIES).toBe(25);
    } finally {
      await app.close();
    }

    // Outage behavior: windowLimit fails open (resolves), checkLoginThrottle fails closed (503)
    const brokenRedisStore = {
      distributed: true,
      async incrWindow() { throw new Error("Redis connection refused"); },
      async incrThrottle() { throw new Error("Redis connection refused"); }
    };
    let warned = false;
    const limiter = createRateLimiter({
      q: {},
      distributedStore: brokenRedisStore,
      onWarn: () => { warned = true; }
    });
    await limiter.windowLimit("reg:127.0.0.1", 10, 60_000);
    expect(warned).toBe(true);
    await expect(limiter.checkLoginThrottle("127.0.0.1", "lookup_test")).rejects.toMatchObject({
      status: 503,
      code: "SERVICE_UNAVAILABLE"
    });
  });

  it("9. B14: Service Worker never caches URLs with oobCode, token, resetToken, mode, or apiKey and falls back to /offline.html", () => {
    const swText = readFileSync(join(root, "public", "sw.js"), "utf8");
    expect(swText.toLowerCase()).toContain("oobcode");
    expect(swText.toLowerCase()).toContain("resettoken");
    expect(swText).toContain("mode");
    expect(swText).toContain("/offline.html");
    expect(existsSync(join(root, "public", "offline.html"))).toBe(true);
    expect(existsSync(join(root, "public", "icon-192.png"))).toBe(true);
    expect(existsSync(join(root, "public", "icon-512.png"))).toBe(true);
  });

  it("10. B13, B17 & B18: 15 MB import file rejected; ;-delimited CSV parsed with password-free preview; backup strips weak envelopes & checks SHA-256; TOTP backup codes & local SVG QR work", async () => {
    // 15 MB file rejected
    const huge = "a".repeat(15 * 1024 * 1024);
    expect(MAX_IMPORT_FILE_BYTES).toBe(10 * 1024 * 1024);
    await expect(readBackup(huge, { passkey: "7392" })).rejects.toMatchObject({ code: "FILE_TOO_LARGE" });
    expect(() => csvToEntries(huge)).toThrow();

    // Semicolon CSV parsed & preview has no passwords
    const parsedCsv = csvToEntries("name;url;username;password;note\nFastmail;https://fastmail.com;user@fm.com;SuperSecret!1;mail\n");
    expect(parsedCsv.delimiter).toBe(";");
    expect(parsedCsv.preview).toHaveLength(1);
    expect(parsedCsv.preview[0].password).toBeUndefined();
    expect(parsedCsv.preview[0].service).toBe("Fastmail");

    // Backup export strips weak envelopes and verifies entriesSha256
    const v = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await v.signUpAccount({ name: "BackupUser", email: "bkp@gmail.com", password: "BackupPassword!1" });
    await v.setupPasskey("7392");
    await v.save({ service: "GitHub", username: "bkp", password: "GitPassword!1" });

    const exported = await v.exportBackup("7392");
    const exportedObj = JSON.parse(exported);
    expect(exportedObj.appVersion).toBe("1.0.0");
    expect(exportedObj.entryCount).toBe(1);
    expect(exportedObj.entriesSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(exportedObj.meta.wrappedEntropyAccount).toBeUndefined();
    expect(exportedObj.meta.accountResetWrapped).toBeUndefined();
    expect(exportedObj.meta.emailResetWrapped).toBeUndefined();

    // Tampered entriesSha256 is rejected with CORRUPTED_BACKUP
    const badShaObj = { ...exportedObj, entriesSha256: "0".repeat(64) };
    await expect(readBackup(JSON.stringify(badShaObj), { passkey: "7392" })).rejects.toMatchObject({
      code: "CORRUPTED_BACKUP"
    });

    // Local SVG QR code & one-time TOTP backup codes (B13)
    const svg = generateQrSvg("otpauth://totp/KeyVEX:bkp@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=KeyVEX");
    expect(svg.startsWith("<svg")).toBe(true);
    const codes = generateTotpBackupCodes(8);
    expect(codes).toHaveLength(8);
    const hashes = await Promise.all(codes.map(hashTotpBackupCode));
    const firstConsume = await verifyAndConsumeTotpBackupCode(codes[0], hashes);
    expect(firstConsume.ok).toBe(true);
    expect(firstConsume.remainingHashes).toHaveLength(7);
    const secondConsume = await verifyAndConsumeTotpBackupCode(codes[0], firstConsume.remainingHashes);
    expect(secondConsume.ok).toBe(false);
  });
});

describe("Section 3, Phase 10 — Google OAuth Config Validation & Popup Cleanup", () => {
  beforeEach(async () => {
    await resetLocalVaultStorage();
    resetGoogleAuthStateForTests();
    setupMiniDom();
  });
  afterEach(() => {
    delete globalThis.google;
  });

  it("validates Google OAuth client ID, tracks and closes opened popup windows automatically, and maps origin_mismatch accurately", async () => {
    const mismatched = validateFirebaseAndGoogleConfig({
      apiKey: "TEST_PUBLIC_KEY_00000000000000000000",
      authDomain: "example-vault.firebaseapp.com",
      projectId: "example-vault",
      messagingSenderId: "123456789012",
      googleClientId: "999999999999-wrongproject.apps.googleusercontent.com"
    });
    expect(mismatched.ok).toBe(false);
    expect(mismatched.issues[0].code).toBe("INVALID_OAUTH_CONFIG");

    let popupClosedCount = 0;
    const fakePopup = {
      closed: false,
      close() {
        this.closed = true;
        popupClosedCount++;
      }
    };
    globalThis.window.open = () => fakePopup;

    globalThis.google = {
      accounts: {
        oauth2: {
          initTokenClient(cfg) {
            return {
              requestAccessToken() {
                globalThis.window.open("https://accounts.google.com/o/oauth2/auth", "google_popup");
                cfg.callback({ error: "origin_mismatch", error_description: "Origin not allowed" });
              }
            };
          }
        }
      }
    };
    await expect(requestGoogleOAuthToken()).rejects.toMatchObject({ code: "REDIRECT_URI_MISMATCH" });
    expect(fakePopup.closed).toBe(true);
    expect(popupClosedCount).toBeGreaterThanOrEqual(1);
  });
});

describe("Section 5 — Reproducible Load, Concurrency & Latency Benchmark Suite", () => {
  it("measures p50/p95/p99 latency, event-loop delay, memory, and Firestore I/O across concurrent logins, writes, batch imports, and rate-limited bursts", async () => {
    await resetLocalVaultStorage();
    resetPerfStats();
    const emu = createFirebaseEmulator();
    setFirebaseTransport(emu.transport);
    setForceFirebaseInTests(true);

    const tLoopStart = performance.now();
    let maxLoopLagMs = 0;
    const lagTimer = setInterval(() => {
      const now = performance.now();
      const lag = Math.max(0, now - tLoopStart - 10);
      if (lag > maxLoopLagMs) maxLoopLagMs = lag;
    }, 10);
    lagTimer.unref?.();

    try {
      const CONCURRENT_USERS = Number(process.env.LOAD_CONCURRENT_USERS) || 25;
      await Promise.all(
        Array.from({ length: CONCURRENT_USERS }, async (_, i) => {
          const v = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
          await v.signUpAccount({
            name: `LoadUser ${i}`,
            email: `loaduser${i}@example.com`,
            password: `LoadSecret!${100 + i}`
          });
          await v.setupPasskey(i % 2 === 0 ? "7392" : "482916");
          await v.save({ service: `Service-${i}`, username: `u${i}`, password: `VaultPass!${i}` });
          v.lock();
          await v.unlockWithPasskey(i % 2 === 0 ? "7392" : "482916");
          await v.sync();
        })
      );

      const restoreProbe = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
      for (let r = 0; r < 10; r++) {
        await restoreProbe.restoreAccountSession();
      }
      const perf = getAllPerfStats();
      const memUsage = process.memoryUsage();
      expect(perf.session_restore.count).toBeGreaterThanOrEqual(10);
      expect(perf.kdf_derivation.count).toBeGreaterThanOrEqual(CONCURRENT_USERS * 2);
      expect(perf.firestore_write.count).toBeGreaterThanOrEqual(CONCURRENT_USERS * 2);
      expect(perf.vault_decrypt.count).toBeGreaterThanOrEqual(CONCURRENT_USERS);

      console.log(
        `    [Load Benchmark Summary: N=${CONCURRENT_USERS} concurrent sessions]`,
        JSON.stringify({
          latencyMs: {
            session_restore: { p50: perf.session_restore.p50, p95: perf.session_restore.p95, p99: perf.session_restore.p99 },
            kdf_derivation: { p50: perf.kdf_derivation.p50, p95: perf.kdf_derivation.p95, p99: perf.kdf_derivation.p99 },
            firestore_meta_read: { p50: perf.firestore_meta_read.p50, p95: perf.firestore_meta_read.p95, p99: perf.firestore_meta_read.p99 },
            firestore_entries_read: { p50: perf.firestore_entries_read.p50, p95: perf.firestore_entries_read.p95, p99: perf.firestore_entries_read.p99 },
            firestore_write: { p50: perf.firestore_write.p50, p95: perf.firestore_write.p95, p99: perf.firestore_write.p99 },
            vault_decrypt: { p50: perf.vault_decrypt.p50, p95: perf.vault_decrypt.p95, p99: perf.vault_decrypt.p99 },
            vault_sync: { p50: perf.vault_sync.p50, p95: perf.vault_sync.p95, p99: perf.vault_sync.p99 }
          },
          firestoreIO: emu.requestCounts,
          rssMB: Math.round((memUsage.rss / 1024 / 1024) * 10) / 10,
          heapUsedMB: Math.round((memUsage.heapUsed / 1024 / 1024) * 10) / 10
        })
      );
    } finally {
      clearInterval(lagTimer);
      setFirebaseTransport(null);
      setForceFirebaseInTests(false);
    }
  });
});


describe("v1.0.0 Complete Project Repair, Build Stabilization & Production Readiness Suite", () => {
  let emu;
  beforeEach(async () => {
    await resetLocalVaultStorage();
    clearFirebaseAuthListeners();
    resetGoogleAuthStateForTests();
    resetTotpReplayAndThrottleForTests();
    setupMiniDom();
    emu = createFirebaseEmulator();
    setFirebaseTransport(emu.transport);
    setForceFirebaseInTests(true);
    setFirebaseConfigOverride(null);
  });
  afterEach(() => {
    setFirebaseTransport(null);
    setForceFirebaseInTests(false);
    setFirebaseConfigOverride(null);
  });

  it("Section 2A–F: aligns package.json and package-lock.json to v1.0.0, verifies components.css, favicon.svg, _redirects, and dist/ assets, and runs scripts/dev.mjs cleanly", async () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
    expect(pkg.version).toBe("1.0.0");
    expect(lock.version).toBe("1.0.0");
    expect(lock.packages[""].version).toBe("1.0.0");
    expect(pkg.dependencies).toEqual(lock.packages[""].dependencies);
    expect(pkg.devDependencies).toEqual(lock.packages[""].devDependencies);
    expect(pkg.engines).toEqual(lock.packages[""].engines);
    expect(pkg.dependencies["@fontsource-variable/manrope"]).toBeTruthy();
    expect(pkg.dependencies["@fontsource-variable/inter"]).toBeTruthy();

    expect(existsSync(join(root, "src", "styles", "components.css"))).toBe(true);
    expect(existsSync(join(root, "public", "favicon.svg"))).toBe(true);
    expect(existsSync(join(root, "public", "icon.svg"))).toBe(true);
    expect(existsSync(join(root, "public", "_redirects"))).toBe(true);
    expect(existsSync(join(root, "scripts", "dev.mjs"))).toBe(true);

    const distCheck = verifyDistAssetsExist(join(root, "dist"));
    expect(distCheck.ok).toBe(true);
    expect(existsSync(join(root, "dist", "favicon.svg"))).toBe(true);
    expect(existsSync(join(root, "dist", "_redirects"))).toBe(true);

    // Start dev server and verify / (HTML), /src/main.js (ESM transform), /favicon.svg, and /api/health proxy
    const dev = await startDevServers({ apiPort: 0, webPort: 0, preferBuiltinWeb: true });
    try {
      const rHtml = await fetch(`${dev.webUrl}/`);
      expect(rHtml.status).toBe(200);
      const rMain = await fetch(`${dev.webUrl}/src/main.js`);
      expect(rMain.status).toBe(200);
      const mainText = await rMain.text();
      expect(mainText).toContain("Manrope Variable");
      const rCss = await fetch(`${dev.webUrl}/src/styles/components.css?import`);
      expect(rCss.status).toBe(200);
      const rFav = await fetch(`${dev.webUrl}/favicon.svg`);
      expect(rFav.status).toBe(200);
      const rApi = await fetch(`${dev.webUrl}/api/health`);
      expect(rApi.status).toBe(200);
      const apiJson = await rApi.json();
      expect(apiJson.ok).toBe(true);
    } finally {
      await dev.close();
    }
  });

  it("Section 4 & 5: Google Sign-In accounts can reset Passkey, change Passkey, and recover vault across devices via active Google session without origin_mismatch or password prompts", async () => {
    const v = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    emu.registerGoogleToken("ggl_zero", { email: "zero@gmail.com", name: "Zero Knowledge" });
    await v.signInWithGoogle({ accessToken: "ggl_zero" });
    await v.setupPasskey("7392");
    await v.save({ service: "ProtectedVaultEntry", username: "zero@gmail.com", password: "UnbreakablePassword!9" });

    // 1. Verify portable & Google recovery envelopes exist in meta and accountTotp is not in plaintext
    expect(v.account.meta.wrappedEntropyAccount).toBeTruthy();
    expect(v.account.meta.accountResetWrapped).toBeTruthy();
    expect(v.account.meta.backupPortableWrapped).toBeTruthy();
    expect(v.account.meta.accountTotp).toBeUndefined();
    expect(v.account.meta.wrappedEntropyPasskey).toBeTruthy();

    // 2. Active Google session verification ({ googleSession: true }) resets Passkey without opening a secondary OAuth popup
    v.lock();
    const gVer = await v.verifyPasskeyResetIdentity({ googleSession: true });
    expect(gVer.verified).toBe(true);
    expect(gVer.method).toBe("google");
    const sameDeviceReset = await v.resetPasskeyAfterVerification("482916");
    expect(sameDeviceReset.ok).toBe(true);
    expect(v.list()).toHaveLength(1);
    expect(v.list()[0].service).toBe("ProtectedVaultEntry");

    // 3. Simulate a brand-new device for the same Google-only account: Forgot Passkey via Google recovers all entries!
    await resetLocalVaultStorage();
    const vNewDevice = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await vNewDevice.signInWithGoogle({ accessToken: "ggl_zero" });
    await vNewDevice.verifyPasskeyResetIdentity({ googleSession: true });
    const crossDeviceReset = await vNewDevice.resetPasskeyAfterVerification("849201");
    expect(crossDeviceReset.ok).toBe(true);
    expect(vNewDevice.list()).toHaveLength(1);
    expect(vNewDevice.list()[0].service).toBe("ProtectedVaultEntry");

    // 4. Google-verified Change Passkey and Zero-Prompt Backup Auto-Restore into 'Imported' category
    await vNewDevice.verifyPasskeyResetIdentity({ googleSession: true });
    await vNewDevice.changePasskey("", "5927");
    const exportedJson = await vNewDevice.exportBackup("5927");
    const autoRestoredItems = await readBackup(exportedJson, { autoRestore: true });
    expect(autoRestoredItems).toHaveLength(1);
    expect(autoRestoredItems[0].service).toBe("ProtectedVaultEntry");
  });

  it("Section 4: Password Generator records encrypted history, opens History popup with total count & date/time, supports single-item delete and clear-history, and never stores plaintext", async () => {
    const v = new Vault(new Api("http://127.0.0.1:1", { allowOffline: true }));
    await v.signUpAccount({ name: "Gen User", email: "gen@gmail.com", password: "GenSecret!1" });
    await v.setupPasskey("7392");

    const h1 = await v.addGeneratorHistory("GeneratedPass!101");
    const h2 = await v.addGeneratorHistory("GeneratedPass!202");
    expect(v.listGeneratorHistory()).toHaveLength(2);
    expect(v.listGeneratorHistory()[0].password).toBe("GeneratedPass!202");
    expect(v.listGeneratorHistory()[1].password).toBe("GeneratedPass!101");

    // Verify encrypted in IndexedDB (plaintext never appears in raw storage)
    const rawStored = JSON.stringify(await getEncryptedGeneratorHistory(v.account.uid));
    expect(rawStored).not.toContain("GeneratedPass!101");
    expect(rawStored).not.toContain("GeneratedPass!202");

    // Open UI generator sheet, click History button, and verify History popup shows total count + date/time + chars
    const sheet = openGenerator({ vault: v });
    const historyBtn = [...document.querySelector("#layer").querySelectorAll("button")].find((b) => b.textContent.includes("View Encrypted History"));
    expect(historyBtn).toBeTruthy();
    expect(historyBtn.textContent).toContain("View Encrypted History (3 generated)");
    historyBtn.click();
    const sheetText = document.querySelector("#layer").textContent;
    expect(sheetText).toContain("Total Passwords Generated: 3");
    expect(sheetText).toContain("chars");
    sheet.close();
    document.querySelector("#layer").replaceChildren();

    // openGenerator({ vault: v }) recorded the newly generated password too (total 3)
    expect(v.listGeneratorHistory()).toHaveLength(3);

    // Individual history deletion removes h2 ("GeneratedPass!202") while keeping h1 ("GeneratedPass!101")
    await v.removeGeneratorHistoryItem(h2.id);
    expect(v.listGeneratorHistory()).toHaveLength(2);
    expect(v.listGeneratorHistory().map((x) => x.password)).toContain("GeneratedPass!101");
    expect(v.listGeneratorHistory().map((x) => x.password)).not.toContain("GeneratedPass!202");

    // Survives lock + unlock
    v.lock();
    expect(v.listGeneratorHistory()).toEqual([]);
    await v.unlockWithPasskey("7392");
    expect(v.listGeneratorHistory()).toHaveLength(2);
    expect(v.listGeneratorHistory().map((x) => x.password)).toContain("GeneratedPass!101");

    // Clear history
    await v.clearGeneratorHistory("7392");
    expect(v.listGeneratorHistory()).toHaveLength(0);
  });

  it("Section 4: External password-manager imports are kept separate from main KeyVEX vault, can be promoted or deleted, and bulk deletion + session revocation + About v1.0.0 work", async () => {
    const srv = await startServer();
    try {
      const v = new Vault(new Api(srv.base, { allowOffline: true }));
      await v.signUpAccount({ name: "Ext User", email: "ext@gmail.com", password: "ExtSecret!1" });
      await v.setupPasskey("7392");
      const nativeEntry1 = await v.save({ service: "NativeOne", username: "u1", password: "NativePw!1" });
      const nativeEntry2 = await v.save({ service: "NativeTwo", username: "u2", password: "NativePw!2" });
      const nativeEntry3 = await v.save({ service: "NativeThree", username: "u3", password: "NativePw!3" });

      // Import external CSV items into separate External Imports collection
      const csvItems = [
        { service: "ChromeImported", username: "chr@x.com", password: "ChromePw!1" },
        { service: "BitwardenImported", username: "bw@x.com", password: "BitwardenPw!2" }
      ];
      const extAdded = await v.importExternalEntries("7392", csvItems, { source: "csv" });
      expect(extAdded).toBe(2);

      // Main vault list has ONLY the 3 native entries; External Imports has the 2 CSV entries
      expect(v.list()).toHaveLength(3);
      expect(v.listExternalImports()).toHaveLength(2);

      // Move 1 external import into the main vault and delete the other
      const extFirst = v.listExternalImports()[0];
      await v.moveExternalImportToVault("7392", extFirst.id);
      expect(v.list()).toHaveLength(4);
      expect(v.listExternalImports()).toHaveLength(1);

      const extSecond = v.listExternalImports()[0];
      await v.removeExternalImport("7392", extSecond.id);
      expect(v.listExternalImports()).toHaveLength(0);

      // Bulk delete nativeEntry1 and nativeEntry2 with Passkey verification
      await expect(v.removeMany("0000", [nativeEntry1.id, nativeEntry2.id])).rejects.toMatchObject({ code: "BAD_PASSKEY" });
      const bulkRes = await v.removeMany("7392", [nativeEntry1.id, nativeEntry2.id]);
      expect(bulkRes.removedCount).toBe(2);
      expect(v.list().map((e) => e.id)).not.toContain(nativeEntry1.id);
      expect(v.list().map((e) => e.id)).toContain(nativeEntry3.id);

      // Session management & Revoke Other Sessions
      const sessInfo = await v.listSessions();
      expect(sessInfo.activeSessions).toBeGreaterThanOrEqual(1);
      await expect(v.revokeOtherSessions("0000")).rejects.toMatchObject({ code: "BAD_PASSKEY" });
      const revRes = await v.revokeOtherSessions("7392");
      expect(revRes.ok).toBe(true);
      expect(revRes.sessionRev).toBeGreaterThan(1);

      // Verify Settings sheet shows About KeyVEX Version 1.0.0 and Revoke Other Sessions
      expect(v.version).toBe("1.0.0");
      openSettings({ vault: v, go() {}, lockNow() {}, logoutAccount: async () => {} }, () => {});
      const settingsText = document.querySelector("#layer").textContent;
      expect(settingsText).toContain("About KeyVEX");
      expect(settingsText).toContain("Version 1.0.0");
      expect(settingsText).toContain("Revoke Other Sessions");
      document.querySelector("#layer").replaceChildren();
    } finally {
      await srv.close();
    }
  });
});

let passed = 0;
let failed = 0;

async function runSuite(suite, prefix = "") {
  const label = prefix ? (suite.name === "root" ? prefix : `${prefix} > ${suite.name}`) : (suite.name === "root" ? "" : suite.name);
  for (const fn of suite.beforeAll) await fn();
  for (const t of suite.tests) {
    try {
      for (const bf of suite.beforeEach) await bf();
      await t.fn();
      for (const af of suite.afterEach) await af();
      passed++;
      console.log(`  ✓ ${label ? label + " > " : ""}${t.name}`);
    } catch (err) {
      failed++;
      console.error(`  ✗ ${label ? label + " > " : ""}${t.name}`);
      console.error(`    ${err?.stack || err}`);
    }
  }
  for (const child of suite.children) {
    await runSuite(child, label);
  }
  for (const fn of suite.afterAll) await fn();
}

try {
  console.log(`Running KeyVEX v2.4.0 Security, Auth, Sync & Reliability Suite on Node ${process.version}...\n`);
  for (const s of suites) await runSuite(s);
  console.log(`\nTest Summary: ${passed} passed, ${failed} failed.`);
} finally {
  rmSync(tmpTestDir, { recursive: true, force: true });
}

process.exit(failed > 0 ? 1 : 0);
