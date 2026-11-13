/** Strict input validation. The server treats every field as untrusted. */
export class HttpError extends Error {
  constructor(status, code, message, extra = {}) { super(message || code); this.status = status; this.code = code; this.extra = extra; }
}

const B64_32 = /^[A-Za-z0-9_-]{43}$/;           // 32 bytes, url-safe base64, no padding
const ID = /^[A-Za-z0-9_-]{8,64}$/;
const B64 = /^[A-Za-z0-9_-]+$/;

export const LIMITS = { body: 2 * 1024 * 1024, meta: 8 * 1024, entryData: 128 * 1024, batch: 500, entriesPerAccount: 10_000 };

const bad = (msg) => { throw new HttpError(400, "BAD_REQUEST", msg); };
const isObj = (v) => v && typeof v === "object" && !Array.isArray(v);

export function secret32(v, name) { if (typeof v !== "string" || !B64_32.test(v)) bad(`Invalid ${name}.`); return v; }
export function entryId(v) { if (typeof v !== "string" || !ID.test(v)) bad("Invalid entry id."); return v; }

const sealed = (o, name) => { if (!isObj(o) || typeof o.iv !== "string" || typeof o.data !== "string" || !B64.test(o.iv) || !B64.test(o.data) || o.iv.length > 32 || o.data.length > 1024) bad(`Invalid ${name}.`); };

export function entry(rec) {
  if (!isObj(rec)) bad("Invalid entry.");
  entryId(rec.id);
  if (typeof rec.iv !== "string" || !B64.test(rec.iv) || rec.iv.length > 32) bad("Invalid entry.");
  if (typeof rec.data !== "string" || !B64.test(rec.data) || rec.data.length > LIMITS.entryData) bad("Invalid entry.");
  return { id: rec.id, iv: rec.iv, data: rec.data };
}

/** The vault header is ciphertext + public parameters. We check its shape, never its contents. */
export function meta(m) {
  if (!isObj(m)) bad("Invalid vault header.");
  const s = JSON.stringify(m);
  if (s.length > LIMITS.meta) bad("Vault header too large.");
  if (m.format !== 6 || typeof m.vaultId !== "string" || !B64.test(m.vaultId) || m.vaultId.length > 32) bad("Invalid vault header.");
  if (![4, 6].includes(m.pinLength)) bad("Invalid vault header.");
  if (!isObj(m.kdf) || !Number.isInteger(m.kdf.iterations) || m.kdf.iterations < 1 || m.kdf.iterations > 10_000_000) bad("Invalid vault header.");
  if (typeof m.wrapped !== "string" || !B64.test(m.wrapped) || m.wrapped.length > 128) bad("Invalid vault header.");
  sealed(m.verifier, "vault header"); sealed(m.sealedMaster, "vault header");
  if (!Number.isInteger(m.createdAt)) bad("Invalid vault header.");
  return s;
}
