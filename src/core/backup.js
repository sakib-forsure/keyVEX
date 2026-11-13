/**
 * Reads KeyVEX backup files (read-only: nothing here writes anything).
 *   v6 — this version: supports automatic zero-prompt restore for v6 backups (via embedded portable backup wrapper)
 *        as well as credential-verified restore when passkey/master are explicitly provided.
 *   v5 — previous local-only build: key wrapped separately under the Passkey and under the Master Password.
 */
import { enc, ub64 } from "./bytes.js";
import { deriveCredentials, deriveEnvelopeGcmKey, deriveAccountResetKek, unwrapKey, open } from "./crypto.js";
import { getUserProfile, unwrapDeviceVaultEntropy } from "./idb.js";

export const SEALED_FORMAT = 6;
export const MAX_IMPORT_FILE_BYTES = 10 * 1024 * 1024; // 10 MB cap (B17)
export const PORTABLE_BACKUP_UID = "keyvex-portable-backup-v1";
export const PORTABLE_BACKUP_EMAIL = "backup@keyvex.local";

export class BackupError extends Error { constructor(code, message) { super(message); this.code = code; } }

const isStr = (v) => typeof v === "string" && v.length > 0;
const sealedOk = (r) => r && isStr(r.iv) && isStr(r.data);
const entriesOk = (a) => Array.isArray(a) && a.length <= 50_000 && a.every((r) => r && isStr(r.id) && sealedOk(r));

export async function computeBackupEntriesSha256(entries = []) {
  const canonical = JSON.stringify(
    (entries || []).map((r) => ({ id: String(r.id || ""), iv: String(r.iv || ""), data: String(r.data || "") }))
  );
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(canonical));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function stripWeakBackupEnvelopes(meta) {
  if (!meta || typeof meta !== "object") return meta;
  const clean = { ...meta };
  delete clean.wrappedEntropyAccount;
  delete clean.entropyAccountSalt;
  delete clean.accountResetWrapped;
  delete clean.accountResetSalt;
  delete clean.emailResetWrapped;
  delete clean.emailResetSalt;
  delete clean.recoveryWrapped;
  delete clean.recoverySalt;
  return clean;
}

export function parseBackup(text) {
  if (typeof text === "string" && text.length > MAX_IMPORT_FILE_BYTES) {
    throw new BackupError("FILE_TOO_LARGE", "Backup file exceeds the 10 MB safety limit.");
  }
  let o;
  try { o = JSON.parse(text); } catch { throw new BackupError("BAD_BACKUP", "That file is not a valid KeyVEX backup."); }
  if (o?.app === "keyvex" && Number.isInteger(o.v) && o.v !== 5 && o.v !== 6) {
    throw new BackupError("INCOMPATIBLE_BACKUP", `This backup was created by an incompatible version of KeyVEX (format v${o.v}).`);
  }
  const m = o?.meta;
  const v6 = o?.app === "keyvex" && o.v === 6 && m?.format === 6 && isStr(m.vaultId) && isStr(m.wrapped) && sealedOk(m.verifier) && entriesOk(o.entries);
  const v5 = o?.app === "keyvex" && o.v === 5 && m?.format === 5 && isStr(m.vaultId) && isStr(m.saltPin) && isStr(m.wrappedPin) && isStr(m.saltName) && isStr(m.wrappedName)
    && sealedOk(m.verifier) && Number.isInteger(m.kdf?.iterations) && m.kdf.iterations >= 1_000 && m.kdf.iterations <= 10_000_000 && entriesOk(o.entries);
  if (!v6 && !v5) throw new BackupError("BAD_BACKUP", "That file is not a valid KeyVEX backup.");
  if (Number.isInteger(o.entryCount) && o.entryCount !== o.entries.length) {
    throw new BackupError("CORRUPTED_BACKUP", "Backup entry count does not match the integrity header.");
  }
  return {
    version: o.v,
    appVersion: o.appVersion || null,
    entryCount: Number.isInteger(o.entryCount) ? o.entryCount : o.entries.length,
    entriesSha256: typeof o.entriesSha256 === "string" ? o.entriesSha256 : null,
    meta: m,
    entries: o.entries
  };
}

async function v5Key(meta, { passkey, master }) {
  const useMaster = !!master;
  const secret = useMaster ? (meta.mpVersion >= 2 ? "mp2:" + master : "name:" + String(master).normalize("NFKC").trim().replace(/\s+/g, " ").toLowerCase()) : String(passkey || "");
  const base = await crypto.subtle.importKey("raw", enc.encode(secret.normalize("NFKC")), "PBKDF2", false, ["deriveKey"]);
  const kek = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: ub64(useMaster ? meta.saltName : meta.saltPin), iterations: meta.kdf.iterations, hash: "SHA-256" }, base, { name: "AES-KW", length: 256 }, false, ["unwrapKey"]);
  return unwrapKey(ub64(useMaster ? meta.wrappedName : meta.wrappedPin), kek);
}

async function tryUnwrapV6(meta, passkey, secretCandidates) {
  const kdfOpts = meta?.kdf?.version === 2 && meta?.kdf?.salt
    ? { salt: meta.kdf.salt, version: 2, iterations: meta.kdf.iterations }
    : {};
  for (const secret of secretCandidates) {
    if (!secret) continue;
    try {
      const creds = await deriveCredentials(passkey, secret, kdfOpts);
      const vk = await unwrapKey(ub64(meta.wrapped), creds.kek);
      if ((await open(vk, meta.verifier, `keyvex:${meta.vaultId}:verify:`)).ok === true) {
        return vk;
      }
    } catch {
      /* try next candidate */
    }
    if (kdfOpts.salt) {
      try {
        const creds = await deriveCredentials(passkey, secret);
        const vk = await unwrapKey(ub64(meta.wrapped), creds.kek);
        if ((await open(vk, meta.verifier, `keyvex:${meta.vaultId}:verify:`)).ok === true) {
          return vk;
        }
      } catch {
        /* try next candidate */
      }
    }
  }
  throw new Error("unwrap_failed");
}

/**
 * Decrypts a backup in the browser and returns plain entries.
 *   - When called from the Restore UI with no passkey/master (`autoRestore: true` or both empty),
 *     automatically unwraps `meta.backupPortableWrapped` so the user does not need to enter any Backup Passkey or Master Password.
 *   - When called with explicit `passkey` or `master` (e.g. unit tests), strictly verifies the supplied credentials.
 */
export async function readBackup(text, { passkey = "", master = "", email = "", vaultEntropy = "", autoRestore = false } = {}) {
  const b = parseBackup(text);
  if (b.entriesSha256) {
    const actualSha = await computeBackupEntriesSha256(b.entries);
    if (actualSha !== b.entriesSha256) {
      throw new BackupError("CORRUPTED_BACKUP", "Backup integrity check failed (SHA-256 mismatch).");
    }
  }

  let vk = null;
  const noCredentialsSupplied = !passkey && !master;

  try {
    if (b.version === 6) {
      // Zero-prompt restore when no credentials were supplied (or autoRestore === true)
      if ((autoRestore || noCredentialsSupplied) && b.meta?.backupPortableWrapped && b.meta?.backupPortableSalt) {
        try {
          const portableKek = await deriveAccountResetKek(PORTABLE_BACKUP_UID, PORTABLE_BACKUP_EMAIL, b.meta.backupPortableSalt);
          const unwrapped = await unwrapKey(ub64(b.meta.backupPortableWrapped), portableKek);
          if ((await open(unwrapped, b.meta.verifier, `keyvex:${b.meta.vaultId}:verify:`)).ok === true) {
            vk = unwrapped;
          }
        } catch {
          vk = null;
        }
      }

      if (!vk) {
        const candidates = [];
        if (vaultEntropy) candidates.push(vaultEntropy);
        if (master) candidates.push(master);
        const acctEmail = String(b.meta?.accountEmail || email || "").trim().toLowerCase();
        if (b.meta?.kdf?.version === 2) {
          if (passkey && b.meta.wrappedEntropyPasskey && b.meta.entropyPasskeySalt) {
            try {
              const pkKey = await deriveEnvelopeGcmKey(String(passkey), b.meta.entropyPasskeySalt, "keyvex:v6:pk-entropy");
              const opened = await open(pkKey, b.meta.wrappedEntropyPasskey, `keyvex:${b.meta.vaultId}:pk-entropy:`);
              if (opened?.entropy) candidates.unshift(opened.entropy);
            } catch { /* ignore */ }
          }
          if (master && b.meta.wrappedEntropyPassword && b.meta.entropyPasswordSalt) {
            try {
              const pwKey = await deriveEnvelopeGcmKey(master, b.meta.entropyPasswordSalt, "keyvex:v6:pw-entropy");
              const opened = await open(pwKey, b.meta.wrappedEntropyPassword, `keyvex:${b.meta.vaultId}:pw-entropy:`);
              if (opened?.entropy) candidates.unshift(opened.entropy);
            } catch { /* ignore */ }
          }
          if (acctEmail) {
            const prof = await getUserProfile(acctEmail).catch(() => null);
            if (prof?.wrappedDeviceEntropy) {
              const unwrapped = await unwrapDeviceVaultEntropy(prof.wrappedDeviceEntropy, prof.uid || acctEmail);
              if (unwrapped) candidates.unshift(unwrapped);
            }
            if (prof?.uid && b.meta.wrappedEntropyAccount && b.meta.entropyAccountSalt) {
              try {
                const acctKey = await deriveEnvelopeGcmKey(`acct:${prof.uid}:${acctEmail}`, b.meta.entropyAccountSalt, "keyvex:v6:acct-entropy");
                const opened = await open(acctKey, b.meta.wrappedEntropyAccount, `keyvex:${b.meta.vaultId}:acct-entropy:`);
                if (opened?.entropy) candidates.unshift(opened.entropy);
              } catch { /* ignore */ }
            }
          }
        }
        if (b.meta?.accountEmail) {
          candidates.push(`keyvex:gmail-vault:${String(b.meta.accountEmail).trim().toLowerCase()}`);
        }
        if (email) {
          candidates.push(`keyvex:gmail-vault:${String(email).trim().toLowerCase()}`);
        }
        if (master && String(master).includes("@")) {
          candidates.push(`keyvex:gmail-vault:${String(master).trim().toLowerCase()}`);
        }
        vk = await tryUnwrapV6(b.meta, passkey, candidates);
      }
    } else {
      vk = await v5Key(b.meta, { passkey, master });
      if ((await open(vk, b.meta.verifier, `keyvex:${b.meta.vaultId}:verify:`)).ok !== true) throw new Error("verify");
    }
  } catch {
    throw new BackupError("BAD_SECRET", b.version === 6 ? "That Passkey and Master Password don’t open this backup." : "That Passkey or Master Password doesn’t open this backup.");
  }

  const items = [];
  for (const r of b.entries) {
    try {
      const dec = await open(vk, r, `keyvex:${b.meta.vaultId}:entry:${r.id}`);
      items.push({ ...dec, id: dec.id || r.id });
    } catch {
      throw new BackupError("CORRUPTED_BACKUP", "This backup file is corrupted or incomplete — one or more records could not be decrypted.");
    }
  }
  return items;
}
