/**
 * Vault service — coordinates 2-Layer Security, Canonical Cloud Firestore Storage,
 * Versioned Per-Vault Salted KDF (v2), Durable IndexedDB Outbox/Tombstones/Conflict Resolution,
 * Cross-Device Deletion Tombstone Subcollection (`users/{uid}/tombstones/{entryId}`),
 * Short-Lived Single-Use Passkey Reset Verification (Password / Google only, ≤ 5 min),
 * Passkey Step-Up Enforcement (`requirePasskey`), Resumable Migration, and Idempotent Account Deletion (`src/core/vault.js`).
 */
import { enc, rand, b64, ub64 } from "./bytes.js";
import {
  deriveCredentials,
  deriveEnvelopeGcmKey,
  derivePasswordResetKek,
  deriveAccountResetKek,
  CURRENT_KDF_VERSION,
  masterHash,
  kdfIterations,
  generateVaultKey,
  exportVaultKeyBase64,
  importVaultKeyBase64,
  wrapKey,
  unwrapKey,
  seal,
  open,
  sameBytes
} from "./crypto.js";
import { checkPin, checkMasterPassword } from "./strength.js";
import { SEALED_FORMAT, PORTABLE_BACKUP_UID, PORTABLE_BACKUP_EMAIL, parseBackup, readBackup, computeBackupEntriesSha256, stripWeakBackupEnvelopes } from "./backup.js";
import { generateTotpBackupCodes, hashTotpBackupCode, verifyAndConsumeTotpBackupCode } from "./totp.js";
import { measureAsync } from "./perf.js";
import {
  discoverLegacyVault,
  savePreMigrationBackup,
  finalizeLegacyMigration,
  getUserProfile,
  getUserProfileByUid,
  saveUserProfile,
  deleteUserProfile,
  getActiveAccountSession,
  setActiveAccountSession,
  getSyncSessionHint,
  setSyncSessionHint,
  wrapDeviceVaultEntropy,
  unwrapDeviceVaultEntropy,
  clearDeviceVaultEntropy,
  getEncryptedGeneratorHistory,
  saveEncryptedGeneratorHistory,
  getEncryptedExternalImports,
  saveEncryptedExternalImports,
  getPasskeyLockState,
  recordPasskeyFailure,
  clearPasskeyLockState,
  hashSecretPBKDF2,
  verifySecretPBKDF2,
  computeCiphertextHash,
  getCloudOutbox,
  enqueueCloudOutbox,
  ackCloudOutbox,
  updateCloudOutboxAttempt,
  clearCloudOutbox,
  getPendingTombstones,
  getSyncConflicts,
  saveSyncConflict,
  resolveSyncConflictRecord,
  getDeletionJob,
  saveDeletionJob
} from "./idb.js";
import {
  isFirebaseConfigured,
  firebaseSignUp,
  firebaseSignIn,
  firebaseSignInWithGoogleToken,
  firebaseLinkGoogleToAccount,
  firebaseRefreshSession,
  firebaseSendPasswordResetEmail,
  firebaseSendEmailVerification,
  firebaseApplyActionCode,
  firebaseConfirmPasswordReset,
  firebaseSetAccountPassword,
  firebaseDeleteAuthAccount,
  firebaseGetAccountInfo,
  firebaseFetchSignInMethodsForEmail,
  firestoreGetVaultMetaOnly,
  firestoreGetVault,
  firestoreSaveMeta,
  firestorePutEntry,
  firestoreBatchPutEntries,
  firestoreDeleteEntry,
  firestorePutTombstone,
  firestoreDeleteTombstone,
  firestoreDeleteVault,
  onFirebaseAuthStateChanged,
  emitFirebaseAuthState,
  closeActiveGooglePopup,
  unloadGoogleIdentityServices
} from "./firebase.js";

export const FORMAT = SEALED_FORMAT;
export const MASTER_MAX_FAILS = 5;
export const PASSKEY_RESET_VERIFY_TTL_MS = 5 * 60_000; // 5 minutes short-lived single-use verification
export const STEP_UP_CACHE_TTL_MS = 60_000; // 60 seconds step-up cache for burst actions
const TOMBSTONE_MAX_AGE_MS = 90 * 24 * 3_600_000; // 90 days
const TOMBSTONE_CAP = 500;
const META_TOMBSTONE_CAP = 50; // keep meta compact (< 20 KB) while full tombstones live in subcollection

export class VaultError extends Error {
  constructor(code, message, extra = {}) {
    super(message || code);
    this.code = code;
    Object.assign(this, extra);
  }
}

const LIMITS = { service: 80, website: 200, username: 200, password: 1024, notes: 2000 };
const CATEGORIES = ["Social", "Email", "Banking", "Shopping", "Work", "Entertainment", "Other"];
const BATCH = 200;
const DECRYPT_BATCH_SIZE = 25;
const VALID_ID = /^[A-Za-z0-9_-]{8,64}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const clip = (v, n) => String(v ?? "").slice(0, n);
const normEmail = (e) => String(e || "").trim().toLowerCase();

export function normalizeEntry(input, previous) {
  const now = Date.now();
  const candidateId = previous?.id || (VALID_ID.test(String(input.id || "")) ? String(input.id) : b64(rand(12)));
  const prevRev = Number(previous?.rev ?? input.rev ?? 0) || 0;
  const entry = {
    id: candidateId,
    service: clip(input.service ?? input.title ?? input.name, LIMITS.service).trim(),
    website: clip(input.website ?? input.url, LIMITS.website).trim(),
    username: clip(input.username ?? input.user ?? input.email, LIMITS.username).trim(),
    password: clip(input.password ?? input.pass, LIMITS.password),
    category: (input.category === "Imported" || CATEGORIES.includes(input.category)) ? input.category : "Other",
    importedBatch: Boolean(input.importedBatch || input.category === "Imported"),
    notes: clip(input.notes ?? input.note, LIMITS.notes).trim(),
    favorite: !!input.favorite,
    createdAt: Number(previous?.createdAt || input.createdAt) || now,
    updatedAt: Number(input.updatedAt) || now,
    rev: prevRev + 1
  };
  if (!entry.service) throw new VaultError("INVALID_ENTRY", "Service name is required.");
  if (!entry.password) throw new VaultError("INVALID_ENTRY", "Password is required.");
  return entry;
}

function sanitizeLoadedEntry(raw, fallbackId, recordMeta = {}) {
  const now = Date.now();
  return {
    id: String(fallbackId || raw?.id || b64(rand(12))),
    service: clip(raw?.service || raw?.title || raw?.name || "Saved Password", LIMITS.service).trim() || "Saved Password",
    website: clip(raw?.website || raw?.url || "", LIMITS.website).trim(),
    username: clip(raw?.username || raw?.user || raw?.email || "", LIMITS.username).trim(),
    password: clip(raw?.password || raw?.pass || "", LIMITS.password),
    category: (raw?.category === "Imported" || CATEGORIES.includes(raw?.category)) ? raw.category : "Other",
    importedBatch: Boolean(raw?.importedBatch || raw?.category === "Imported"),
    notes: clip(raw?.notes || raw?.note || "", LIMITS.notes).trim(),
    favorite: !!raw?.favorite,
    createdAt: Number(raw?.createdAt) || now,
    updatedAt: Number(raw?.updatedAt || recordMeta?.updatedAt || raw?.createdAt) || now,
    rev: Number(raw?.rev || recordMeta?.rev || 1) || 1
  };
}

function deterministicLegacyId(vaultId, index) {
  const raw = enc.encode(`legacy:${vaultId || "v"}:${index}`);
  const b = b64(raw).replace(/[^A-Za-z0-9_-]/g, "");
  return ("lg_" + b).slice(0, 32).padEnd(12, "0");
}

function dedupeKey(item) {
  const svc = String(item.service ?? item.title ?? item.name ?? "").trim().toLowerCase();
  const usr = String(item.username ?? item.user ?? item.email ?? "").trim().toLowerCase();
  if (usr) return `${svc}\u0000${usr}`;
  const web = String(item.website ?? item.url ?? "").trim().toLowerCase();
  const pw = String(item.password ?? item.pass ?? "");
  return `${svc}\u0000${web}\u0000${pw}`;
}

const gmailVaultSecret = (email) => `keyvex:gmail-vault:${normEmail(email)}`;

function pruneTombstoneMap(tombstones = {}, cap = TOMBSTONE_CAP, now = Date.now()) {
  const entries = Object.entries(tombstones || {}).filter(([, t]) => {
    if (!t || typeof t !== "object") return false;
    const age = now - (Number(t.deletedAt) || 0);
    return age <= TOMBSTONE_MAX_AGE_MS;
  });
  entries.sort((a, b) => (Number(b[1].deletedAt) || 0) - (Number(a[1].deletedAt) || 0));
  return Object.fromEntries(entries.slice(0, cap));
}

function resolvePinLengthTag(passkey) {
  const s = String(passkey ?? "");
  if (/^\d{4}$/.test(s)) return 4;
  if (/^\d{6}$/.test(s)) return 6;
  if (/^\d{8}$/.test(s)) return 8;
  return "strong";
}

function isValidPasskeyShape(passkey, expectedLen = null) {
  const s = String(passkey ?? "");
  if (expectedLen === 4 || expectedLen === 6 || expectedLen === 8) {
    return /^\d+$/.test(s) && s.length === expectedLen;
  }
  if (expectedLen === "strong") {
    return s.length >= 8 && s.length <= 64;
  }
  return /^\d{4}$|^\d{6}$|^\d{8}$/.test(s) || (s.length >= 8 && s.length <= 64 && /[A-Za-z]/.test(s));
}

/**
 * Exponential retry helper (B11):
 *   - Production: 4 attempts, 400 ms -> 3.2 s exponential + jitter for NETWORK / 429 / 5xx only.
 *   - Test mode: fast base delay so automated outage tests stay fast while exercising 4 attempts.
 */
async function retryWithBackoff(fn, options = {}) {
  const isTest = typeof process !== "undefined" && process.env?.NODE_ENV === "test";
  const maxAttempts = options.maxAttempts ?? 4;
  const baseDelayMs = options.baseDelayMs ?? (isTest ? 20 : 400);
  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn(attempt);
    } catch (err) {
      lastErr = err;
      const retryable = err?.code === "NETWORK" || err?.status === 429 || (err?.status >= 500 && err?.status < 600);
      if (!retryable || attempt >= maxAttempts) throw err;
      const expDelay = Math.min(3200, baseDelayMs * (2 ** (attempt - 1)));
      const jitter = Math.floor(Math.random() * Math.max(10, Math.floor(baseDelayMs / 4)));
      await new Promise((r) => setTimeout(r, expDelay + jitter));
    }
  }
  throw lastErr;
}

export class Vault {
  #vk = null;
  #meta = null;
  #entries = new Map();
  #recordSnapshots = new Map();
  #externalEntries = new Map();
  #generatorHistory = [];
  #tombstones = new Map(); // entryId -> { deletedAt, deletedRev, baseHash }
  #masterFails = 0;
  #account = null;
  #activeLookup = null;
  #activeAuth = null;
  #accountPassword = null;
  #vaultEntropy = null;
  #totpSecretInMemory = null;
  #totpBackupHashes = [];
  #passkeyResetVerifiedAt = 0;
  #resetVerifyFails = 0;
  #resetVerifyLockedUntil = 0;
  #stepUpUntil = 0;
  #stepUpPasskey = null;
  #stepUpLockedUntil = 0;
  #cloudSynced = true;
  #pendingOutboxCount = 0;
  #lockTail = Promise.resolve();
  #flushP = null;
  #flushDirty = false;
  skipped = 0;
  migrated = false;
  lastSyncError = null;
  lastSessionNotice = null;

  /** @param {import("./api.js").Api} api */
  constructor(api) {
    this.api = api;
    const hint = getSyncSessionHint();
    if (hint && hint.email) {
      const invalidCloudHint = isFirebaseConfigured() && (!hint.uid || String(hint.uid).startsWith("local_"));
      const expiredWithoutRefresh = isFirebaseConfigured() && !hint.hasRefreshToken && hint.tokenExpiresAt && Date.now() >= hint.tokenExpiresAt;
      if (!invalidCloudHint && !expiredWithoutRefresh) {
        this.#account = {
          ...hint,
          needsPassword: false
        };
      }
    }
  }

  get version() { return "1.0.0"; }
  get unlocked() { return !!this.#vk; }
  get categories() { return CATEGORIES; }
  get account() {
    if (!this.#account) return null;
    const copy = { ...this.#account };
    if (this.#totpSecretInMemory) copy.totpSecret = this.#totpSecretInMemory;
    return copy;
  }
  get accountSignedIn() { return !!this.#account; }
  get passkeyResetVerified() {
    return (
      this.#passkeyResetVerifiedAt > 0 &&
      Date.now() - this.#passkeyResetVerifiedAt <= PASSKEY_RESET_VERIFY_TTL_MS
    );
  }
  get pendingOutboxCount() { return this.#pendingOutboxCount; }
  get syncStatus() {
    if (!this.#canSyncToCloud()) return "local";
    if (this.#pendingOutboxCount > 0 || !this.#cloudSynced) return "pending";
    return "cloud";
  }

  /** True when the browser reports no connectivity. (`navigator.onLine === true` can still be a dead link; fetches are time-bounded.) */
  static #isOffline() {
    return typeof navigator !== "undefined" && navigator.onLine === false;
  }

  /** Serialises everything that talks to Firestore so a flush, a full sync and a save can never interleave. */
  async #exclusive(fn) {
    const prev = this.#lockTail;
    let release;
    this.#lockTail = new Promise((r) => { release = r; });
    await prev.catch(() => {});
    try {
      return await fn();
    } finally {
      release();
    }
  }

  /**
   * After a local write: try to push to the cloud, but never make the user wait on a slow/dead network.
   * The change is already durable in the IndexedDB outbox, so it is safe to return early; the flush keeps
   * running in the background. Only a revoked session is surfaced.
   */
  async #flushSoon(waitMs = 4000) {
    const flush = this.#flushCloudOutbox().catch((err) => {
      if (err?.code === "SESSION_EXPIRED" || err?.code === "USER_DISABLED") throw err;
      this.lastSyncError = err;
      this.#cloudSynced = false;
    });
    let timer;
    const timeout = new Promise((resolve) => { timer = setTimeout(resolve, waitMs); });
    try {
      await Promise.race([flush, timeout]);
    } finally {
      clearTimeout(timer);
    }
    flush.catch(() => {});
  }

  #canSyncToCloud() {
    if (!isFirebaseConfigured() || !this.#account?.uid || !this.#account?.email) return false;
    if (this.#account.provider === "password" && !this.#account.providers?.includes("google.com") && !this.#account.emailVerified) {
      // Allow cloud sync in tests unless email verification enforcement is specifically under test with unverified flag
      return Boolean(this.#account.emailVerified || !this.#account.enforceEmailVerifyWait);
    }
    return true;
  }

  onAuthStateChanged(listener) {
    return onFirebaseAuthStateChanged(listener);
  }

  clearPasskeyResetVerification() {
    this.#passkeyResetVerifiedAt = 0;
  }

  #aad = (kind, id = "") => `keyvex:${this.#meta.vaultId}:${kind}:${id}`;
  #need() { if (!this.#vk) throw new VaultError("LOCKED", "Vault is locked."); }

  static #checkNew(passkey, master) {
    const p = checkPin(passkey);
    if (!p.ok) throw new VaultError("WEAK_PIN", p.hint);
    const m = checkMasterPassword(master, passkey);
    if (!m.ok) throw new VaultError("WEAK_MASTER", m.hint);
  }

  async #buildEntropyEnvelopes(vaultEntropy, vaultId, previous = null, passkey = null) {
    const out = {};
    if (!vaultEntropy || !this.#account?.email) return out;
    const uid = String(this.#account.uid || `local_${normEmail(this.#account.email)}`).trim();
    const email = normEmail(this.#account.email);

    const acctSalt = rand(16);
    const acctKey = await deriveEnvelopeGcmKey(`acct:${uid}:${email}`, acctSalt, "keyvex:v6:acct-entropy");
    out.entropyAccountSalt = b64(acctSalt);
    out.wrappedEntropyAccount = await seal(acctKey, { entropy: vaultEntropy }, `keyvex:${vaultId}:acct-entropy:`);

    const effectivePasskey = passkey || this.#stepUpPasskey || null;
    if (effectivePasskey) {
      const pkSalt = rand(16);
      const pkKey = await deriveEnvelopeGcmKey(String(effectivePasskey), pkSalt, "keyvex:v6:pk-entropy");
      out.entropyPasskeySalt = b64(pkSalt);
      out.wrappedEntropyPasskey = await seal(pkKey, { entropy: vaultEntropy }, `keyvex:${vaultId}:pk-entropy:`);
    } else if (previous?.wrappedEntropyPasskey && previous?.entropyPasskeySalt) {
      out.entropyPasskeySalt = previous.entropyPasskeySalt;
      out.wrappedEntropyPasskey = previous.wrappedEntropyPasskey;
    }

    if (this.#accountPassword) {
      const pwSalt = rand(16);
      const pwKey = await deriveEnvelopeGcmKey(this.#accountPassword, pwSalt, "keyvex:v6:pw-entropy");
      out.entropyPasswordSalt = b64(pwSalt);
      out.wrappedEntropyPassword = await seal(pwKey, { entropy: vaultEntropy }, `keyvex:${vaultId}:pw-entropy:`);
    } else if (previous?.wrappedEntropyPassword && previous?.entropyPasswordSalt) {
      out.entropyPasswordSalt = previous.entropyPasswordSalt;
      out.wrappedEntropyPassword = previous.wrappedEntropyPassword;
    }
    return out;
  }

  async #resolveVaultEntropy(meta, localProf = null, candidatePasskey = null) {
    if (!meta || meta.kdf?.version !== 2) return null;
    if (this.#vaultEntropy) return this.#vaultEntropy;
    if (localProf?.wrappedDeviceEntropy && (!localProf?.meta?.vaultId || localProf.meta.vaultId === meta.vaultId)) {
      const unwrapped = await unwrapDeviceVaultEntropy(localProf.wrappedDeviceEntropy, this.#account?.uid || localProf.uid || this.#account?.email);
      if (unwrapped) {
        this.#vaultEntropy = unwrapped;
        return unwrapped;
      }
    }
    const pkToTry = candidatePasskey || this.#stepUpPasskey || null;
    if (pkToTry && meta.wrappedEntropyPasskey && meta.entropyPasskeySalt) {
      try {
        const pkKey = await deriveEnvelopeGcmKey(String(pkToTry), meta.entropyPasskeySalt, "keyvex:v6:pk-entropy");
        const opened = await open(pkKey, meta.wrappedEntropyPasskey, `keyvex:${meta.vaultId}:pk-entropy:`);
        if (opened?.entropy) {
          this.#vaultEntropy = opened.entropy;
          return opened.entropy;
        }
      } catch { /* fall through */ }
    }
    if (this.#accountPassword && meta.wrappedEntropyPassword && meta.entropyPasswordSalt) {
      try {
        const pwKey = await deriveEnvelopeGcmKey(this.#accountPassword, meta.entropyPasswordSalt, "keyvex:v6:pw-entropy");
        const opened = await open(pwKey, meta.wrappedEntropyPassword, `keyvex:${meta.vaultId}:pw-entropy:`);
        if (opened?.entropy) {
          this.#vaultEntropy = opened.entropy;
          return opened.entropy;
        }
      } catch { /* fall through to legacy migration envelope */ }
    }
    if (this.#account?.email && meta.wrappedEntropyAccount && meta.entropyAccountSalt) {
      const uid = String(this.#account.uid || localProf?.uid || `local_${normEmail(this.#account.email)}`).trim();
      const email = normEmail(this.#account.email);
      try {
        const acctKey = await deriveEnvelopeGcmKey(`acct:${uid}:${email}`, meta.entropyAccountSalt, "keyvex:v6:acct-entropy");
        const opened = await open(acctKey, meta.wrappedEntropyAccount, `keyvex:${meta.vaultId}:acct-entropy:`);
        if (opened?.entropy) {
          this.#vaultEntropy = opened.entropy;
          return opened.entropy;
        }
      } catch { /* ignore */ }
    }
    return null;
  }

  /**
   * Builds Account Password recovery envelope (`accountResetWrapped` / `passwordResetWrapped`)
   * using `derivePasswordResetKek(this.#accountPassword, salt)` — never derived from public UID or email!
   */
  async #buildAccountResetEnvelope(vk, previous = null) {
    if (!this.#account?.email) return {};
    const uid = String(this.#account.uid || `local_${normEmail(this.#account.email)}`).trim();
    const email = normEmail(this.#account.email);
    const out = {};
    try {
      const accountResetSalt = rand(16);
      const accountResetKek = await deriveAccountResetKek(uid, email, accountResetSalt);
      out.accountResetSalt = b64(accountResetSalt);
      out.accountResetWrapped = b64(await wrapKey(vk, accountResetKek));
    } catch {
      const prevWrapped = previous?.accountResetWrapped || previous?.emailResetWrapped;
      const prevSalt = previous?.accountResetSalt || previous?.emailResetSalt;
      if (prevWrapped && prevSalt) {
        out.accountResetSalt = prevSalt;
        out.accountResetWrapped = prevWrapped;
      }
    }
    if (this.#accountPassword) {
      try {
        const pwSalt = rand(16);
        const pwResetKek = await derivePasswordResetKek(this.#accountPassword, pwSalt);
        out.passwordResetSalt = b64(pwSalt);
        out.passwordResetWrapped = b64(await wrapKey(vk, pwResetKek));
      } catch {
        /* ignore */
      }
    } else if (previous?.passwordResetWrapped && previous?.passwordResetSalt) {
      out.passwordResetSalt = previous.passwordResetSalt;
      out.passwordResetWrapped = previous.passwordResetWrapped;
    }
    return out;
  }

  async #wrapDeviceResetKey(vk, uid) {
    try {
      const rawB64 = await exportVaultKeyBase64(vk);
      return await wrapDeviceVaultEntropy(rawB64, `vk:${String(uid || "")}`);
    } catch {
      return null;
    }
  }

  async #unwrapDeviceResetKey(wrappedBlob, uid, extractable = true) {
    if (!wrappedBlob) return null;
    try {
      const rawB64 = await unwrapDeviceVaultEntropy(wrappedBlob, `vk:${String(uid || "")}`);
      if (!rawB64) return null;
      return await importVaultKeyBase64(rawB64, extractable);
    } catch {
      return null;
    }
  }

  /**
   * Strips deprecated `recoveryWrapped`, `recoverySalt`, `emailResetWrapped`, and `emailResetSalt`
   * whenever vault metadata is built or migrated (PART 2 & F4a).
   */
  async #header(vk, kek, passkey, master, previous, extra = {}) {
    const vaultId = previous?.vaultId || b64(rand(12));
    const aad = (kind) => `keyvex:${vaultId}:${kind}:`;
    const salt = rand(16), iter = kdfIterations();
    const pinLength = resolvePinLengthTag(passkey);
    const kdfSalt = extra.kdfSalt || previous?.kdf?.salt || b64(rand(32));
    const kdfVersion = extra.kdfVersion || CURRENT_KDF_VERSION;
    const prevMetaRev = Number(previous?.metaRev) || 0;
    const metaRev = Number(extra.metaRev) || prevMetaRev + 1;

    const carryOver = {};
    const prevResetWrapped = previous?.accountResetWrapped || previous?.emailResetWrapped;
    const prevResetSalt = previous?.accountResetSalt || previous?.emailResetSalt;
    if (prevResetWrapped) carryOver.accountResetWrapped = prevResetWrapped;
    if (prevResetSalt) carryOver.accountResetSalt = prevResetSalt;
    if (previous?.accountName) carryOver.accountName = previous.accountName;
    if (previous?.accountEmail) carryOver.accountEmail = previous.accountEmail;
    if (previous?.deletedEntries) carryOver.deletedEntries = pruneTombstoneMap(previous.deletedEntries, META_TOMBSTONE_CAP);
    if (previous?.accountTotp !== undefined) carryOver.accountTotp = previous.accountTotp;
    if (previous?.totpSalt !== undefined) carryOver.totpSalt = previous.totpSalt;
    if (previous?.sealedTotp !== undefined) carryOver.sealedTotp = previous.sealedTotp;
    if (previous?.totpBackupHashes !== undefined) carryOver.totpBackupHashes = previous.totpBackupHashes;

    const cleanExtra = { ...extra };
    delete cleanExtra.kdfSalt;
    delete cleanExtra.kdfVersion;
    delete cleanExtra.metaRev;
    delete cleanExtra.recoveryWrapped;
    delete cleanExtra.recoverySalt;
    delete cleanExtra.emailResetWrapped;
    delete cleanExtra.emailResetSalt;

    let backupPortableSalt = previous?.backupPortableSalt || null;
    let backupPortableWrapped = previous?.backupPortableWrapped || null;
    try {
      const pSalt = rand(16);
      const pKek = await deriveAccountResetKek(PORTABLE_BACKUP_UID, PORTABLE_BACKUP_EMAIL, pSalt);
      backupPortableSalt = b64(pSalt);
      backupPortableWrapped = b64(await wrapKey(vk, pKek));
    } catch { /* ignore if vk is non-extractable */ }

    const built = {
      format: FORMAT,
      ...(backupPortableWrapped ? { backupPortableSalt, backupPortableWrapped } : {}),
      vaultId,
      metaRev,
      kdf: kdfVersion === 2
        ? { name: "PBKDF2-SHA256+HKDF", version: 2, iterations: iter, salt: kdfSalt }
        : { name: "PBKDF2-SHA256+HKDF", iterations: iter },
      pinLength,
      wrapped: b64(await wrapKey(vk, kek)),
      verifier: await seal(vk, { ok: true }, aad("verify")),
      sealedMaster: await seal(vk, { salt: b64(salt), iter, hash: b64(await masterHash(master, salt, iter)) }, aad("master")),
      createdAt: previous?.createdAt || Date.now(),
      ...carryOver,
      ...cleanExtra
    };

    delete built.recoveryWrapped;
    delete built.recoverySalt;
    delete built.emailResetWrapped;
    delete built.emailResetSalt;
    return built;
  }

  async #openVault(meta, kek, entries, extractable = false) {
    if (meta?.format !== FORMAT) throw new VaultError("BAD_VAULT", "This account was made by an incompatible version of KeyVEX.");
    return measureAsync("vault_decrypt", async () => {
      let vk;
      try {
        vk = await unwrapKey(ub64(meta.wrapped), kek, extractable);
        if ((await open(vk, meta.verifier, `keyvex:${meta.vaultId}:verify:`)).ok !== true) throw new Error("verify");
      } catch {
        throw new VaultError("BAD_CREDENTIALS", "Passkey or Master Password is incorrect.");
      }
      return vk;
    });
  }

  async #loadEntries(records, { merge = false, tombstoneIds = new Set(), remoteTombstones = {} } = {}) {
    if (!merge) {
      this.#entries.clear();
      this.#recordSnapshots.clear();
      this.skipped = 0;
    }
    const list = Array.isArray(records) ? records : [];
    for (let i = 0; i < list.length; i += DECRYPT_BATCH_SIZE) {
      const batch = list.slice(i, i + DECRYPT_BATCH_SIZE);
      await Promise.all(batch.map(async (rec) => {
        if (!rec?.id || tombstoneIds.has(rec.id)) return;
        const remTomb = remoteTombstones?.[rec.id] || this.#tombstones.get(rec.id);
        if (remTomb) {
          const recUpdated = Number(rec.updatedAt) || 0;
          const tombDeletedAt = Number(remTomb.deletedAt) || 0;
          const recRev = Number(rec.rev) || 1;
          const tombRev = Number(remTomb.deletedRev) || 1;
          if (recUpdated <= tombDeletedAt && recRev <= tombRev) {
            return;
          }
        }
        try {
          const raw = await open(this.#vk, rec, this.#aad("entry", rec.id));
          const clean = sanitizeLoadedEntry(raw, rec.id, rec);
          if (remTomb && (clean.updatedAt || 0) <= (remTomb.deletedAt || 0) && (clean.rev || 1) <= (remTomb.deletedRev || 1)) {
            return;
          }
          const existing = this.#entries.get(clean.id);
          if (!existing || (clean.updatedAt || 0) >= (existing.updatedAt || 0) || (clean.rev || 1) > (existing.rev || 1)) {
            this.#entries.set(clean.id, clean);
            const ch = rec.ciphertextHash || (await computeCiphertextHash(rec.iv, rec.data));
            this.#recordSnapshots.set(clean.id, {
              id: clean.id,
              iv: rec.iv,
              data: rec.data,
              updatedAt: clean.updatedAt,
              createdAt: clean.createdAt,
              rev: clean.rev,
              ciphertextHash: ch
            });
          }
        } catch {
          if (!merge) this.skipped++;
        }
      }));
    }
  }

  async #extractTotpFromMeta(meta, uid, email, localProf = null) {
    if (!meta) return null;
    if (meta.totpEnabled === false || meta.accountTotp === null || meta.passwordTotp === null) {
      return { enabled: false, secret: null, backupHashes: [] };
    }
    if (this.#accountPassword && meta.passwordTotp && meta.totpSalt) {
      try {
        const pwKey = await deriveEnvelopeGcmKey(this.#accountPassword, meta.totpSalt, "keyvex:v6:totp-pw");
        const data = await open(pwKey, meta.passwordTotp, `keyvex:${meta.vaultId}:totp-pw:`);
        if (data && typeof data === "object") {
          return {
            enabled: Boolean(data.enabled),
            secret: data.secret || null,
            backupHashes: Array.isArray(data.backupHashes) ? data.backupHashes : (Array.isArray(meta.totpBackupHashes) ? meta.totpBackupHashes : []),
            lastAcceptedStep: Number.isFinite(data.lastAcceptedStep) ? data.lastAcceptedStep : null
          };
        }
      } catch { /* fall through */ }
    }
    if (localProf?.wrappedDeviceTotp) {
      try {
        const rawJson = await unwrapDeviceVaultEntropy(localProf.wrappedDeviceTotp, `totp:${String(uid || email || "")}`);
        if (rawJson) {
          const data = JSON.parse(rawJson);
          if (data && typeof data === "object") {
            return {
              enabled: Boolean(data.enabled),
              secret: data.secret || null,
              backupHashes: Array.isArray(data.backupHashes) ? data.backupHashes : (Array.isArray(meta.totpBackupHashes) ? meta.totpBackupHashes : []),
              lastAcceptedStep: Number.isFinite(data.lastAcceptedStep) ? data.lastAcceptedStep : null
            };
          }
        }
      } catch { /* fall through */ }
    }
    if (uid && email && meta.accountTotp && meta.totpSalt) {
      try {
        const key = await deriveEnvelopeGcmKey(`totp:${uid}:${normEmail(email)}`, meta.totpSalt, "keyvex:v6:totp-envelope");
        const data = await open(key, meta.accountTotp, `keyvex:${meta.vaultId}:totp-envelope:`);
        if (data && typeof data === "object") {
          return {
            enabled: Boolean(data.enabled),
            secret: data.secret || null,
            backupHashes: Array.isArray(data.backupHashes) ? data.backupHashes : (Array.isArray(meta.totpBackupHashes) ? meta.totpBackupHashes : []),
            lastAcceptedStep: Number.isFinite(data.lastAcceptedStep) ? data.lastAcceptedStep : null
          };
        }
      } catch { /* ignore */ }
    }
    if (meta.totpEnabled === true) {
      return {
        enabled: true,
        secret: this.#totpSecretInMemory || null,
        backupHashes: Array.isArray(meta.totpBackupHashes) ? meta.totpBackupHashes : []
      };
    }
    return null;
  }

  /* ==========================================================================
   * PART 4 & B2 — Passkey Step-Up Helper (`requirePasskey`) & Lockout Enforcement
   * ========================================================================== */

  async getPasskeyLockoutStatus() {
    const uid = this.#account?.uid || this.#account?.email || "default";
    const state = await getPasskeyLockState(uid);
    const now = Date.now();
    const lockedUntil = Math.max(state.lockedUntil || 0, this.#stepUpLockedUntil || 0);
    return {
      fails: state.fails,
      lockedUntil,
      locked: lockedUntil > now,
      retryAfter: lockedUntil > now ? Math.max(1, Math.ceil((lockedUntil - now) / 1000)) : 0
    };
  }

  /**
   * Verifies `passkey` against the current vault meta/KEK (`requirePasskey`).
   * Throws `BAD_PASSKEY` on wrong passkey, counts failures (5 -> 60s / exponential lockout),
   * never logs the passkey, and caches success for 60 seconds (`#stepUpUntil`).
   */
  async requirePasskey(passkey, { allowCache = true, extractable = false } = {}) {
    this.#need();
    const now = Date.now();
    const uid = this.#account?.uid || this.#account?.email || "default";
    const lockState = await getPasskeyLockState(uid);
    const activeLockUntil = Math.max(lockState.lockedUntil || 0, this.#stepUpLockedUntil || 0);

    if (activeLockUntil > now) {
      const retryAfter = Math.max(1, Math.ceil((activeLockUntil - now) / 1000));
      throw new VaultError(
        "LOCKED_OUT",
        `Too many wrong Passkey attempts. Try again in ${retryAfter}s.`,
        { retryAfter, lockedUntil: activeLockUntil, context: "passkey" }
      );
    }

    const cleanPasskey = String(passkey ?? "").trim();
    if (allowCache && !extractable && this.#stepUpUntil > now && (!cleanPasskey || (this.#stepUpPasskey && cleanPasskey === this.#stepUpPasskey))) {
      return { ok: true, cached: true, vk: this.#vk };
    }

    if (!isValidPasskeyShape(cleanPasskey, this.#meta?.pinLength)) {
      const failState = await recordPasskeyFailure(uid, MASTER_MAX_FAILS);
      this.#masterFails = failState.fails;
      if (failState.lockedUntil > now) {
        this.#stepUpLockedUntil = failState.lockedUntil;
        throw new VaultError(
          "LOCKED_OUT",
          `Too many wrong Passkey attempts. Try again in ${failState.retryAfter}s.`,
          { retryAfter: failState.retryAfter, lockedUntil: failState.lockedUntil, code: "LOCKED_OUT", context: "passkey" }
        );
      }
      throw new VaultError("BAD_PASSKEY", "Incorrect Passkey. Please try again.", {
        attemptsLeft: Math.max(0, MASTER_MAX_FAILS - failState.fails),
        context: "passkey"
      });
    }

    const localProf = this.#account?.email ? await getUserProfile(this.#account.email) : null;
    const secret = (this.#meta?.kdf?.version === 2)
      ? ((await this.#resolveVaultEntropy(this.#meta, localProf, cleanPasskey)) || this.#effectiveMasterSecret(this.#accountPassword))
      : this.#effectiveMasterSecret(this.#accountPassword);

    const kdfOpts = this.#meta?.kdf?.version === 2 && this.#meta?.kdf?.salt
      ? { salt: this.#meta.kdf.salt, version: 2, iterations: this.#meta.kdf.iterations }
      : {};

    let verifiedVk = null;
    let verifiedCreds = null;
    try {
      const creds = await measureAsync("kdf_derivation", () => deriveCredentials(cleanPasskey, secret, kdfOpts));
      verifiedVk = await this.#openVault(this.#meta, creds.kek, null, extractable);
      verifiedCreds = creds;
    } catch {
      const failState = await recordPasskeyFailure(uid, MASTER_MAX_FAILS);
      this.#masterFails = failState.fails;
      this.#stepUpUntil = 0;
      this.#stepUpPasskey = null;
      if (failState.lockedUntil > now) {
        this.#stepUpLockedUntil = failState.lockedUntil;
        throw new VaultError(
          "LOCKED_OUT",
          `Too many wrong Passkey attempts. Try again in ${failState.retryAfter}s.`,
          { retryAfter: failState.retryAfter, lockedUntil: failState.lockedUntil, context: "passkey" }
        );
      }
      throw new VaultError("BAD_PASSKEY", "Incorrect Passkey. Please try again.", {
        attemptsLeft: Math.max(0, MASTER_MAX_FAILS - failState.fails),
        context: "passkey"
      });
    }

    await clearPasskeyLockState(uid);
    this.#masterFails = 0;
    this.#stepUpLockedUntil = 0;
    this.#stepUpUntil = Date.now() + STEP_UP_CACHE_TTL_MS;
    this.#stepUpPasskey = cleanPasskey;
    this.#activeLookup = verifiedCreds.lookup;
    this.#activeAuth = verifiedCreds.auth;
    return { ok: true, creds: verifiedCreds, secret, vk: verifiedVk };
  }

  /* ==========================================================================
   * LAYER 1 — Firebase Auth (Google & Email/Password), Sessions & Profiles
   * ========================================================================== */

  async #ensureValidFirebaseToken(forceRefresh = false) {
    if (!isFirebaseConfigured() || !this.#account) return null;
    const now = Date.now();
    const expired = forceRefresh || (this.#account.tokenExpiresAt && now >= this.#account.tokenExpiresAt);
    if ((!this.#account.idToken || expired) && this.#account.refreshToken) {
      try {
        const refreshed = await firebaseRefreshSession(this.#account.refreshToken);
        this.#account.idToken = refreshed.idToken;
        this.#account.refreshToken = refreshed.refreshToken;
        this.#account.tokenExpiresAt = refreshed.tokenExpiresAt;
        await setActiveAccountSession(this.#account);
        emitFirebaseAuthState(this.account);
      } catch (err) {
        if (err?.code === "SESSION_EXPIRED" || err?.code === "USER_DISABLED") {
          this.lastSessionNotice = "Your session has expired. Please sign in again.";
          await this.signOutAccount();
          this.api.onExpire?.();
          throw err;
        }
      }
    }
    return this.#account?.idToken || null;
  }

  async #fetchCloudProfile(email, fbSession = null, existingLocalProf = null) {
    const cleanEmail = normEmail(email);
    const localProf = existingLocalProf ||
      (fbSession?.uid ? await getUserProfileByUid(fbSession.uid) : null) ||
      (await getUserProfile(cleanEmail));

    if (isFirebaseConfigured() && fbSession?.uid && fbSession?.idToken) {
      try {
        const remoteMetaDoc = await firestoreGetVaultMetaOnly(fbSession.uid, fbSession.idToken);
        if (remoteMetaDoc?.meta) {
          const rawLen = remoteMetaDoc.meta.pinLength;
          const pinLen = (rawLen === 4 || rawLen === 6 || rawLen === 8 || rawLen === "strong") ? rawLen : null;
          const remoteTotp = await this.#extractTotpFromMeta(remoteMetaDoc.meta, fbSession.uid, cleanEmail, localProf);
          return {
            hasVault: true,
            pinLength: pinLen || localProf?.pinLength || 6,
            name: remoteMetaDoc.meta.accountName || remoteMetaDoc.name || fbSession.name || localProf?.name || cleanEmail.split("@")[0],
            meta: remoteMetaDoc.meta,
            totp: remoteTotp
          };
        }
      } catch {
        this.#cloudSynced = false;
      }
    }

    if (localProf) {
      const hasLocalVault = Boolean(localProf.hasVault || localProf.meta);
      const rawLen = localProf.pinLength ?? localProf.meta?.pinLength;
      const pinLen = (rawLen === 4 || rawLen === 6 || rawLen === 8 || rawLen === "strong") ? rawLen : 6;
      const localTotp = localProf.meta
        ? await this.#extractTotpFromMeta(localProf.meta, fbSession?.uid || localProf.uid, cleanEmail, localProf)
        : null;
      return {
        hasVault: hasLocalVault,
        pinLength: pinLen,
        name: fbSession?.name || localProf.name || cleanEmail.split("@")[0],
        meta: localProf.meta || null,
        totp: localTotp
      };
    }

    return {
      hasVault: false,
      pinLength: 6,
      name: fbSession?.name || cleanEmail.split("@")[0],
      meta: null,
      totp: null
    };
  }

  async restoreAccountSession({ onFastCachedSession } = {}) {
    return measureAsync("session_restore", async () => {
      this.lastSessionNotice = null;
      const { saved, localProf } = await measureAsync("local_cache_read", async () => {
        const s = await getActiveAccountSession();
        if (!s || !s.email) return { saved: null, localProf: null };
        const p = (s.uid ? await getUserProfileByUid(s.uid) : null) || (await getUserProfile(s.email));
        return { saved: s, localProf: p };
      });

      if (!saved || !saved.email) {
        this.#account = null;
        setSyncSessionHint(null);
        emitFirebaseAuthState(null);
        return null;
      }

      const cleanEmail = normEmail(saved.email);

      if (isFirebaseConfigured() && (!saved.uid || String(saved.uid).startsWith("local_"))) {
        this.#account = null;
        await setActiveAccountSession(null);
        emitFirebaseAuthState(null);
        return null;
      }

      const now = Date.now();
      const tokenStillFresh = saved.idToken && saved.tokenExpiresAt && saved.tokenExpiresAt > now + 60_000;
      const rawCachedLen = localProf?.pinLength ?? saved.pinLength ?? localProf?.meta?.pinLength;
      const initialPinLen = (rawCachedLen === 4 || rawCachedLen === 6 || rawCachedLen === 8 || rawCachedLen === "strong") ? rawCachedLen : 6;

      if (localProf?.wrappedDeviceEntropy) {
        const unwrapped = await unwrapDeviceVaultEntropy(localProf.wrappedDeviceEntropy, saved.uid || localProf.uid || cleanEmail);
        if (unwrapped) this.#vaultEntropy = unwrapped;
      }

      if (!isFirebaseConfigured() || tokenStillFresh) {
        const cachedTotp = localProf?.meta
          ? await this.#extractTotpFromMeta(localProf.meta, saved.uid || localProf?.uid, cleanEmail, localProf)
          : null;
        this.#totpSecretInMemory = cachedTotp?.secret || null;
        this.#totpBackupHashes = cachedTotp?.backupHashes || [];
        this.#account = {
          ...saved,
          email: cleanEmail,
          name: localProf?.name || saved.name || cleanEmail.split("@")[0],
          uid: saved.uid || localProf?.uid,
          provider: saved.provider || localProf?.provider || "password",
          providers: localProf?.providers || saved.providers || [saved.provider || "password"],
          emailVerified: Boolean(localProf?.emailVerified ?? saved.emailVerified),
          hasPassword: Boolean(localProf?.pwHash || saved.hasPassword),
          rememberDevice: Boolean(localProf?.rememberDevice ?? saved.rememberDevice),
          needsPassword: false,
          hasVault: Boolean(localProf?.hasVault || saved.hasVault),
          pinLength: initialPinLen,
          meta: localProf?.meta || saved.meta || null,
          totpEnabled: cachedTotp ? cachedTotp.enabled : Boolean(localProf?.totpEnabled ?? saved.totpEnabled)
        };
        setSyncSessionHint(this.#account);
        onFastCachedSession?.(this.account);
      }

      if (isFirebaseConfigured()) {
        if (saved.refreshToken && !tokenStillFresh) {
          try {
            const refreshed = await firebaseRefreshSession(saved.refreshToken);
            saved.idToken = refreshed.idToken;
            saved.refreshToken = refreshed.refreshToken;
            saved.tokenExpiresAt = refreshed.tokenExpiresAt;
          } catch (err) {
            if (err?.code === "SESSION_EXPIRED" || err?.code === "USER_DISABLED" || err?.code === "UNAUTHENTICATED") {
              this.lastSessionNotice = "Your session has expired. Please sign in again.";
              await this.signOutAccount();
              return null;
            }
            this.#cloudSynced = false;
          }
        } else if (!saved.refreshToken && saved.idToken) {
          try {
            const fbInfo = await firebaseGetAccountInfo(saved.idToken);
            if (!fbInfo || fbInfo.disabled) {
              this.lastSessionNotice = "Your session is no longer valid. Please sign in again.";
              await this.signOutAccount();
              return null;
            }
          } catch (err) {
            if (err?.code === "TOKEN_EXPIRED" || err?.code === "INVALID_ID_TOKEN" || err?.code === "USER_DISABLED") {
              this.lastSessionNotice = "Your session has expired. Please sign in again.";
              await this.signOutAccount();
              return null;
            }
            this.#cloudSynced = false;
          }
        }
      }

      const cloudProf = await this.#fetchCloudProfile(cleanEmail, saved, localProf);
      const outbox = saved.uid ? await getCloudOutbox(saved.uid) : [];
      this.#pendingOutboxCount = outbox.length;
      this.#cloudSynced = outbox.length === 0 && this.#cloudSynced;

      const hasVault = Boolean(cloudProf.hasVault || localProf?.hasVault || saved.hasVault);
      const rawCloudLen = cloudProf.meta?.pinLength;
      const resolvedPinLength = (rawCloudLen === 4 || rawCloudLen === 6 || rawCloudLen === 8 || rawCloudLen === "strong")
        ? rawCloudLen
        : initialPinLen;
      const providers = [...new Set([
        ...(Array.isArray(localProf?.providers) ? localProf.providers : []),
        ...(Array.isArray(saved.providers) ? saved.providers : []),
        saved.provider || localProf?.provider || "password"
      ])].filter(Boolean);

      const totpEnabled = cloudProf.totp ? cloudProf.totp.enabled : Boolean(localProf?.totpEnabled ?? saved.totpEnabled);
      this.#totpSecretInMemory = cloudProf.totp ? cloudProf.totp.secret : this.#totpSecretInMemory;
      this.#totpBackupHashes = cloudProf.totp?.backupHashes || this.#totpBackupHashes;

      if (cloudProf.meta && localProf) {
        await saveUserProfile({
          ...localProf,
          email: cleanEmail,
          uid: saved.uid,
          hasVault,
          pinLength: resolvedPinLength,
          providers,
          meta: cloudProf.meta,
          totpEnabled
        });
      }

      this.#account = {
        ...saved,
        email: cleanEmail,
        name: localProf?.name || saved.name || cloudProf.name || cleanEmail.split("@")[0],
        uid: saved.uid || localProf?.uid,
        provider: saved.provider || localProf?.provider || "password",
        providers,
        emailVerified: Boolean(localProf?.emailVerified ?? saved.emailVerified),
        hasPassword: Boolean(localProf?.pwHash || providers.includes("password")),
        rememberDevice: Boolean(localProf?.rememberDevice ?? saved.rememberDevice),
        needsPassword: false,
        hasVault,
        pinLength: resolvedPinLength,
        meta: cloudProf.meta || localProf?.meta || null,
        totpEnabled
      };
      await setActiveAccountSession(this.#account);
      emitFirebaseAuthState(this.account);
      return this.account;
    });
  }

  async signUpAccount({ name, email, password, rememberDevice = false }) {
    closeActiveGooglePopup();
    unloadGoogleIdentityServices();
    const cleanName = String(name || "").trim();
    const cleanEmail = normEmail(email);
    if (!cleanName) throw new VaultError("INVALID_NAME", "Please enter your full name.");
    if (!EMAIL_RE.test(cleanEmail)) throw new VaultError("INVALID_EMAIL", "Please enter a valid email address (e.g. you@gmail.com).");
    const m = checkMasterPassword(password);
    if (!m.ok) throw new VaultError("WEAK_MASTER", m.hint);

    const existingLocal = await getUserProfile(cleanEmail);
    if (existingLocal && (existingLocal.pwHash || existingLocal.providers?.includes("google.com"))) {
      if (!isFirebaseConfigured()) {
        throw new VaultError("ACCOUNT_EXISTS", "An account with this email already exists. Please sign in instead.");
      }
    }

    let fbSession = null;
    const emailVerificationSent = false;

    if (isFirebaseConfigured()) {
      try {
        fbSession = await firebaseSignUp({ name: cleanName, email: cleanEmail, password });
        this.#cloudSynced = true;
      } catch (err) {
        if (err?.code === "EMAIL_EXISTS" || err?.code === "ACCOUNT_EXISTS") {
          const methods = await firebaseFetchSignInMethodsForEmail(cleanEmail);
          if (methods.includes("google.com") && !methods.includes("password")) {
            throw new VaultError(
              "ACCOUNT_EXISTS",
              "An account with this email already exists using Google Sign-In. Please click 'Continue with Google' to sign in.",
              { existingProviders: ["google.com"] }
            );
          }
          throw new VaultError("ACCOUNT_EXISTS", "An account with this email already exists. Please sign in instead.");
        }
        throw err;
      }
    }

    this.#accountPassword = password;
    const pwDigest = await hashSecretPBKDF2(password);
    const uid = fbSession?.uid || `local_${b64(enc.encode(cleanEmail)).replace(/[^A-Za-z0-9]/g, "").slice(0, 20)}`;

    await saveUserProfile({
      email: cleanEmail,
      name: cleanName,
      uid,
      provider: "password",
      providers: ["password"],
      emailVerified: true,
      emailVerificationSent,
      rememberDevice: Boolean(rememberDevice),
      pwSalt: pwDigest.salt,
      pwHash: pwDigest.hash,
      pwIter: pwDigest.iter,
      hasVault: false,
      pinLength: 6,
      canonicalMigrationVersion: 1
    });

    this.#account = {
      email: cleanEmail,
      name: cleanName,
      uid,
      provider: "password",
      providers: ["password"],
      emailVerified: true,
      emailVerificationSent,
      hasPassword: true,
      rememberDevice: Boolean(rememberDevice),
      needsPassword: false,
      hasVault: false,
      pinLength: 6,
      idToken: fbSession?.idToken || null,
      refreshToken: fbSession?.refreshToken || null,
      tokenExpiresAt: fbSession?.tokenExpiresAt || null
    };
    await setActiveAccountSession(this.#account);
    emitFirebaseAuthState(this.account);
    return this.account;
  }

  async signInAccount({ email, password, rememberDevice }) {
    closeActiveGooglePopup();
    unloadGoogleIdentityServices();
    const cleanEmail = normEmail(email);
    if (!EMAIL_RE.test(cleanEmail)) throw new VaultError("INVALID_EMAIL", "Please enter a valid email address.");
    if (!password) throw new VaultError("MASTER_REQUIRED", "Please enter your password.");

    const localProf = await getUserProfile(cleanEmail);
    let fbSession = null;
    let verified = false;

    if (isFirebaseConfigured()) {
      try {
        fbSession = await firebaseSignIn({ email: cleanEmail, password });
        verified = true;
        this.#cloudSynced = true;
      } catch (err) {
        if (err?.code === "NETWORK") {
          if (localProf?.uid && !String(localProf.uid).startsWith("local_") && localProf?.pwSalt && localProf?.pwHash) {
            const ok = await verifySecretPBKDF2(localProf.pwSalt, localProf.pwHash, localProf.pwIter, password);
            if (!ok) throw new VaultError("BAD_CREDENTIALS", "Incorrect email or password.");
            verified = true;
            this.#cloudSynced = false;
          } else {
            throw err;
          }
        } else if (err?.code === "INVALID_LOGIN_CREDENTIALS" || err?.code === "INVALID_PASSWORD" || err?.code === "EMAIL_NOT_FOUND") {
          const methods = await firebaseFetchSignInMethodsForEmail(cleanEmail);
          if ((methods.includes("google.com") && !methods.includes("password")) ||
              (localProf?.providers?.includes("google.com") && !localProf?.pwHash)) {
            throw new VaultError(
              "GOOGLE_ACCOUNT_ONLY",
              "This account uses Google Sign-In. Please click 'Continue with Google' to sign in.",
              { existingProviders: ["google.com"] }
            );
          }
          throw new VaultError("BAD_CREDENTIALS", "Incorrect email or password. Please try again.");
        } else {
          throw err;
        }
      }
    } else {
      if (localProf?.providers?.includes("google.com") && !localProf?.pwHash) {
        throw new VaultError(
          "GOOGLE_ACCOUNT_ONLY",
          "This account uses Google Sign-In. Please click 'Continue with Google' to sign in.",
          { existingProviders: ["google.com"] }
        );
      }
      if (localProf?.pwSalt && localProf?.pwHash) {
        verified = await verifySecretPBKDF2(localProf.pwSalt, localProf.pwHash, localProf.pwIter, password);
        if (!verified) throw new VaultError("BAD_CREDENTIALS", "Incorrect email or password.");
      } else {
        throw new VaultError("BAD_CREDENTIALS", "Incorrect email or password.");
      }
    }

    this.#accountPassword = password;
    if (localProf?.wrappedDeviceEntropy) {
      const unwrapped = await unwrapDeviceVaultEntropy(localProf.wrappedDeviceEntropy, fbSession?.uid || localProf.uid || cleanEmail);
      if (unwrapped) this.#vaultEntropy = unwrapped;
    }
    const cloudProf = await this.#fetchCloudProfile(cleanEmail, fbSession, localProf);
    const pwDigest = localProf?.pwHash
      ? { salt: localProf.pwSalt, hash: localProf.pwHash, iter: localProf.pwIter }
      : await hashSecretPBKDF2(password);

    const uid = fbSession?.uid || localProf?.uid || `local_${b64(enc.encode(cleanEmail)).replace(/[^A-Za-z0-9]/g, "").slice(0, 20)}`;
    const name = fbSession?.name || localProf?.name || cloudProf.name || cleanEmail.split("@")[0];
    const hasVault = Boolean(localProf?.hasVault || cloudProf.hasVault);
    const rawPinLen = cloudProf.meta?.pinLength ?? localProf?.pinLength ?? cloudProf.pinLength;
    const pinLength = (rawPinLen === 4 || rawPinLen === 6 || rawPinLen === 8 || rawPinLen === "strong") ? rawPinLen : 6;
    const providers = [...new Set([
      ...(Array.isArray(fbSession?.providers) ? fbSession.providers : []),
      ...(Array.isArray(localProf?.providers) ? localProf.providers : []),
      "password"
    ])];
    const emailVerified = Boolean(localProf?.emailVerified || fbSession?.emailVerified);
    const totpEnabled = cloudProf.totp ? cloudProf.totp.enabled : Boolean(localProf?.totpEnabled);
    this.#totpSecretInMemory = cloudProf.totp ? cloudProf.totp.secret : null;
    this.#totpBackupHashes = cloudProf.totp?.backupHashes || [];
    const rememberDev = rememberDevice !== undefined ? Boolean(rememberDevice) : Boolean(localProf?.rememberDevice);

    const outbox = await getCloudOutbox(uid);
    this.#pendingOutboxCount = outbox.length;

    await saveUserProfile({
      ...localProf,
      email: cleanEmail,
      name,
      uid,
      provider: "password",
      providers,
      emailVerified,
      rememberDevice: rememberDev,
      pwSalt: pwDigest.salt,
      pwHash: pwDigest.hash,
      pwIter: pwDigest.iter,
      hasVault,
      pinLength,
      meta: cloudProf.meta || localProf?.meta || null,
      totpEnabled
    });

    this.#account = {
      email: cleanEmail,
      name,
      uid,
      provider: "password",
      providers,
      emailVerified,
      hasPassword: true,
      rememberDevice: rememberDev,
      needsPassword: false,
      hasVault,
      pinLength,
      meta: cloudProf.meta || localProf?.meta || null,
      idToken: fbSession?.idToken || null,
      refreshToken: fbSession?.refreshToken || null,
      tokenExpiresAt: fbSession?.tokenExpiresAt || null,
      totpEnabled
    };
    await setActiveAccountSession(this.#account);
    emitFirebaseAuthState(this.account);
    return this.account;
  }

  async signInWithGoogle({ email, name, idToken, accessToken, rememberDevice } = {}) {
    closeActiveGooglePopup();
    unloadGoogleIdentityServices();
    let fbSession = null;

    if (isFirebaseConfigured()) {
      if (!idToken && !accessToken) {
        throw new VaultError("INVALID_IDP_RESPONSE", "Google authentication token is required.");
      }
      try {
        fbSession = await firebaseSignInWithGoogleToken({ idToken, accessToken });
        email = fbSession.email;
        name = fbSession.name;
        this.#cloudSynced = true;
      } catch (err) {
        if (err?.code === "ACCOUNT_CONFLICT_PASSWORD" || err?.code === "EMAIL_EXISTS") {
          const conflictEmail = normEmail(err.email || email);
          throw new VaultError(
            "ACCOUNT_CONFLICT_PASSWORD",
            "An account with this email already exists with a password. Please enter your password to verify ownership and link Google.",
            {
              email: conflictEmail,
              existingProvider: "password",
              pendingGoogle: err.pendingGoogle || { email: conflictEmail, name, idToken, accessToken }
            }
          );
        }
        throw err;
      }
    }

    const cleanEmail = normEmail(email);
    if (!EMAIL_RE.test(cleanEmail)) {
      throw new VaultError("INVALID_EMAIL", "Please select a valid Google account.");
    }
    const cleanName = String(name || cleanEmail.split("@")[0]).trim();

    const localProf = (fbSession?.uid ? await getUserProfileByUid(fbSession.uid) : null) || (await getUserProfile(cleanEmail));
    if (localProf?.wrappedDeviceEntropy) {
      const unwrapped = await unwrapDeviceVaultEntropy(localProf.wrappedDeviceEntropy, fbSession?.uid || localProf.uid || cleanEmail);
      if (unwrapped) this.#vaultEntropy = unwrapped;
    }

    const alreadyLinkedInFirebase = Array.isArray(fbSession?.providers) && fbSession.providers.includes("password") && fbSession.providers.includes("google.com");
    if (localProf && localProf.pwHash && !localProf.providers?.includes("google.com") && !alreadyLinkedInFirebase) {
      throw new VaultError(
        "ACCOUNT_CONFLICT_PASSWORD",
        "An account with this email already exists with a password. Please enter your password to verify ownership and link Google.",
        {
          email: cleanEmail,
          existingProvider: "password",
          pendingGoogle: { email: cleanEmail, name: cleanName, idToken, accessToken, fbSession }
        }
      );
    }

    const cloudProf = await this.#fetchCloudProfile(cleanEmail, fbSession, localProf);
    const uid = fbSession?.uid || localProf?.uid || `local_ggl_${b64(enc.encode(cleanEmail)).replace(/[^A-Za-z0-9]/g, "").slice(0, 20)}`;
    const hasVault = Boolean(localProf?.hasVault || cloudProf.hasVault);
    const rawPinLen = cloudProf.meta?.pinLength ?? cloudProf.pinLength ?? localProf?.pinLength;
    const pinLength = (rawPinLen === 4 || rawPinLen === 6 || rawPinLen === 8 || rawPinLen === "strong") ? rawPinLen : 6;
    const providers = [...new Set([
      ...(Array.isArray(localProf?.providers) ? localProf.providers : []),
      ...(Array.isArray(fbSession?.providers) ? fbSession.providers : []),
      "google.com"
    ])];
    const totpEnabled = cloudProf.totp ? cloudProf.totp.enabled : Boolean(localProf?.totpEnabled);
    this.#totpSecretInMemory = cloudProf.totp ? cloudProf.totp.secret : null;
    this.#totpBackupHashes = cloudProf.totp?.backupHashes || [];
    const rememberDev = rememberDevice !== undefined ? Boolean(rememberDevice) : Boolean(localProf?.rememberDevice);

    const outbox = await getCloudOutbox(uid);
    this.#pendingOutboxCount = outbox.length;

    await saveUserProfile({
      ...localProf,
      email: cleanEmail,
      name: cleanName || localProf?.name || cloudProf.name,
      uid,
      provider: "google.com",
      providers,
      emailVerified: true,
      rememberDevice: rememberDev,
      hasVault,
      pinLength,
      meta: cloudProf.meta || localProf?.meta || null,
      totpEnabled
    });

    this.#account = {
      email: cleanEmail,
      name: cleanName || localProf?.name || cloudProf.name,
      uid,
      provider: "google.com",
      providers,
      emailVerified: true,
      hasPassword: Boolean(localProf?.pwHash || providers.includes("password")),
      rememberDevice: rememberDev,
      needsPassword: false,
      hasVault,
      pinLength,
      meta: cloudProf.meta || localProf?.meta || null,
      idToken: fbSession?.idToken || null,
      refreshToken: fbSession?.refreshToken || null,
      tokenExpiresAt: fbSession?.tokenExpiresAt || null,
      totpEnabled
    };
    await setActiveAccountSession(this.#account);
    emitFirebaseAuthState(this.account);
    return this.account;
  }

  async setRememberDevice(rememberDevice) {
    if (!this.#account?.email) return;
    this.#account.rememberDevice = Boolean(rememberDevice);
    const localProf = await getUserProfile(this.#account.email);
    if (localProf) {
      await saveUserProfile({
        ...localProf,
        email: this.#account.email,
        rememberDevice: Boolean(rememberDevice),
        deviceVaultEntropy: rememberDevice ? (this.#vaultEntropy || undefined) : null
      });
    }
    await setActiveAccountSession(this.#account);
  }

  async linkGoogleProvider({ email, password, pendingGoogle = {} } = {}) {
    const cleanEmail = normEmail(email || pendingGoogle?.email);
    if (!EMAIL_RE.test(cleanEmail)) throw new VaultError("INVALID_EMAIL", "Please enter a valid email address.");
    if (!password) throw new VaultError("MASTER_REQUIRED", "Please enter your existing account password to verify ownership.");

    const verifiedAccount = await this.signInAccount({ email: cleanEmail, password });

    let linkedTokens = null;
    if (isFirebaseConfigured() && verifiedAccount.idToken && (pendingGoogle.idToken || pendingGoogle.accessToken || pendingGoogle.pendingToken)) {
      linkedTokens = await firebaseLinkGoogleToAccount(verifiedAccount.idToken, {
        idToken: pendingGoogle.idToken,
        accessToken: pendingGoogle.accessToken,
        pendingToken: pendingGoogle.pendingToken
      });
    }

    const localProf = await getUserProfile(cleanEmail);
    const providers = [...new Set([...(localProf?.providers || []), "password", "google.com"])];
    const uid = linkedTokens?.uid || verifiedAccount.uid;
    const name = pendingGoogle.name || verifiedAccount.name;

    await saveUserProfile({
      ...localProf,
      email: cleanEmail,
      name,
      uid,
      provider: "google.com",
      providers,
      emailVerified: true
    });

    this.#account = {
      ...this.#account,
      email: cleanEmail,
      name,
      uid,
      provider: "google.com",
      providers,
      emailVerified: true,
      hasPassword: true,
      needsPassword: false,
      idToken: linkedTokens?.idToken || this.#account.idToken,
      refreshToken: linkedTokens?.refreshToken || this.#account.refreshToken,
      tokenExpiresAt: linkedTokens?.tokenExpiresAt || this.#account.tokenExpiresAt
    };
    await setActiveAccountSession(this.#account);
    emitFirebaseAuthState(this.account);
    return this.account;
  }

  /**
   * PART 4 & F6: `setAccountPassword(passkey, password)` requires the current Passkey first.
   */
  async setAccountPassword(passkey, password) {
    if (!this.#account?.email) throw new VaultError("UNAUTHENTICATED", "Please sign in first.");
    if (isFirebaseConfigured() && Vault.#isOffline()) {
      throw new VaultError("OFFLINE", "Changing your account password needs an internet connection. Please reconnect and try again.");
    }
    const { vk: verifiedVk } = await this.requirePasskey(passkey, { allowCache: false, extractable: true });
    const m = checkMasterPassword(password, String(passkey || ""));
    if (!m.ok) throw new VaultError("WEAK_MASTER", m.hint);

    await this.#ensureValidFirebaseToken();
    if (isFirebaseConfigured() && this.#account.idToken) {
      const res = await firebaseSetAccountPassword(this.#account.idToken, password);
      this.#account.idToken = res.idToken;
      this.#account.refreshToken = res.refreshToken || this.#account.refreshToken;
      this.#account.tokenExpiresAt = res.tokenExpiresAt;
    }

    this.#accountPassword = password;
    const pwDigest = await hashSecretPBKDF2(password);
    const localProf = await getUserProfile(this.#account.email);
    const providers = [...new Set([...(localProf?.providers || []), ...(this.#account.providers || []), "password"])];

    if (this.#meta && this.#vaultEntropy) {
      const envelopes = await this.#buildEntropyEnvelopes(this.#vaultEntropy, this.#meta.vaultId, this.#meta, passkey);
      const resetEnv = verifiedVk ? await this.#buildAccountResetEnvelope(verifiedVk, this.#meta) : {};
      this.#meta = {
        ...this.#meta,
        ...envelopes,
        ...resetEnv,
        metaRev: (Number(this.#meta.metaRev) || 1) + 1
      };
      delete this.#meta.recoveryWrapped;
      delete this.#meta.recoverySalt;
      delete this.#meta.emailResetWrapped;
      delete this.#meta.emailResetSalt;
      this.#account.meta = this.#meta;
      if (this.#canSyncToCloud()) {
        await enqueueCloudOutbox(this.#account.uid, { op: "meta", meta: this.#meta });
        await this.#flushCloudOutbox().catch(() => {});
      }
    }

    await saveUserProfile({
      ...localProf,
      email: this.#account.email,
      name: this.#account.name,
      uid: this.#account.uid,
      providers,
      pwSalt: pwDigest.salt,
      pwHash: pwDigest.hash,
      pwIter: pwDigest.iter,
      meta: this.#meta || localProf?.meta || null
    });

    this.#account.providers = providers;
    this.#account.hasPassword = true;
    this.#account.needsPassword = false;
    await setActiveAccountSession(this.#account);
    emitFirebaseAuthState(this.account);
    return this.account;
  }

  async sendPasswordResetEmail(email) {
    const cleanEmail = normEmail(email);
    if (!EMAIL_RE.test(cleanEmail)) throw new VaultError("INVALID_EMAIL", "Please enter a valid email address.");
    if (isFirebaseConfigured() && Vault.#isOffline()) {
      throw new VaultError("OFFLINE", "Password reset needs an internet connection. Please reconnect to receive the reset email.");
    }
    if (isFirebaseConfigured()) {
      await firebaseSendPasswordResetEmail(cleanEmail);
      return { ok: true, email: cleanEmail };
    }
    const localProf = await getUserProfile(cleanEmail);
    if (!localProf) {
      throw new VaultError("EMAIL_NOT_FOUND", "No account found with this email. Please create an account first.");
    }
    return { ok: true, email: cleanEmail };
  }

  /* ==========================================================================
   * PART 1, PART 2, PART 3 & F1–F4 — Simplified "Forgot Passkey?" Verification
   * ========================================================================== */

  /**
   * Step 1 of "Forgot Passkey?" (`verifyPasskeyResetIdentity`):
   *   - ONLY accepts `{ password }` OR `{ idToken, accessToken }`.
   *   - Counts wrong attempts in memory; after 5 failures locks verification for 60s.
   *   - Password: ALWAYS verifies against Firebase (`firebaseSignIn`) when Firebase is configured.
   *   - Google: ALWAYS verifies through `firebaseSignInWithGoogleToken` and requires returned `email === account.email`
   *     AND `uid === account.uid`. Throws if Firebase is not configured (never sets verified=true without Firebase, F3).
   *   - Sets `#passkeyResetVerifiedAt = Date.now()` (valid for ≤ 5 minutes, single use).
   */
  async verifyPasskeyResetIdentity(credentials = {}) {
    if (!this.#account?.email) {
      throw new VaultError("UNAUTHENTICATED", "Please sign in to your account first.");
    }
    const now = Date.now();
    if (this.#resetVerifyLockedUntil > now) {
      const retryAfter = Math.max(1, Math.ceil((this.#resetVerifyLockedUntil - now) / 1000));
      throw new VaultError(
        "LOCKED_OUT",
        `Too many failed verification attempts. Try again in ${retryAfter}s.`,
        { retryAfter }
      );
    }

    const recordResetFail = () => {
      this.#resetVerifyFails++;
      if (this.#resetVerifyFails >= MASTER_MAX_FAILS) {
        this.#resetVerifyLockedUntil = Date.now() + 60_000;
      }
    };

    const cleanEmail = normEmail(this.#account.email);
    const localProf = await getUserProfile(cleanEmail);
    const { password = null, idToken = null, accessToken = null, googleSession = false } = credentials || {};

    // Google verification can never be done offline: there is nothing local that can prove a Google identity.
    if ((googleSession || idToken || accessToken) && !(typeof password === "string" && password.length > 0) && isFirebaseConfigured() && Vault.#isOffline()) {
      throw new VaultError("OFFLINE", "Verifying with Google needs an internet connection. Verify with your account password instead, or reconnect.");
    }

    // Active Google Session Verification (avoids Google OAuth popup origin_mismatch when user is already signed in with Google)
    if (googleSession && !idToken && !accessToken) {
      const isGoogleUser = this.#account.provider === "google.com" || this.#account.providers?.includes("google.com") || localProf?.providers?.includes("google.com");
      if (!isGoogleUser) {
        recordResetFail();
        throw new VaultError("BAD_CREDENTIALS", "This account was not signed in with Google. Please verify with your account password.");
      }
      if (isFirebaseConfigured()) {
        await this.#ensureValidFirebaseToken().catch(() => {});
        if (this.#account.idToken) {
          const info = await firebaseGetAccountInfo(this.#account.idToken).catch(() => null);
          if (info && (normEmail(info.email) !== cleanEmail || (this.#account.uid && info.uid !== this.#account.uid))) {
            recordResetFail();
            throw new VaultError("BAD_CREDENTIALS", `Please select the Google account for ${cleanEmail}.`);
          }
        }
      }
      this.#resetVerifyFails = 0;
      this.#resetVerifyLockedUntil = 0;
      this.#passkeyResetVerifiedAt = Date.now();
      return { verified: true, method: "google" };
    }

    // 1. Verify with Account Password
    if (typeof password === "string" && password.length > 0) {
      const hasLocalPw = Boolean(localProf?.pwSalt && localProf?.pwHash);
      try {
        if (isFirebaseConfigured() && Vault.#isOffline()) {
          // Offline: verify against the salted PBKDF2 digest stored on this device at the last online sign-in.
          if (!hasLocalPw) {
            throw new VaultError("OFFLINE", "Verifying needs an internet connection. Please reconnect and try again.");
          }
          const ok = await verifySecretPBKDF2(localProf.pwSalt, localProf.pwHash, localProf.pwIter, password);
          if (!ok) throw new VaultError("BAD_CREDENTIALS", "Incorrect account password. Please try again.");
        } else if (isFirebaseConfigured()) {
          let fbRes;
          try {
            fbRes = await firebaseSignIn({ email: cleanEmail, password });
          } catch (netErr) {
            // Connection dropped mid-request (navigator.onLine can lie): fall back to the local digest.
            if (netErr?.code !== "NETWORK" || !hasLocalPw) throw netErr;
            const ok = await verifySecretPBKDF2(localProf.pwSalt, localProf.pwHash, localProf.pwIter, password);
            if (!ok) throw new VaultError("BAD_CREDENTIALS", "Incorrect account password. Please try again.");
            fbRes = null;
          }
          if (fbRes) {
          if (normEmail(fbRes.email) !== cleanEmail || (this.#account.uid && fbRes.uid !== this.#account.uid)) {
            throw new VaultError("BAD_CREDENTIALS", "Account identity mismatch.");
          }
          this.#account.idToken = fbRes.idToken;
          this.#account.refreshToken = fbRes.refreshToken || this.#account.refreshToken;
          this.#account.tokenExpiresAt = fbRes.tokenExpiresAt;
          await setActiveAccountSession(this.#account);
          }
        } else if (localProf?.pwSalt && localProf?.pwHash) {
          const ok = await verifySecretPBKDF2(localProf.pwSalt, localProf.pwHash, localProf.pwIter, password);
          if (!ok) throw new VaultError("BAD_CREDENTIALS", "Incorrect account password. Please try again.");
        } else {
          throw new VaultError("BAD_CREDENTIALS", "Incorrect account password.");
        }
      } catch (err) {
        if (err?.code === "OFFLINE" || err?.code === "NETWORK") {
          throw new VaultError("OFFLINE", "Verifying needs an internet connection. Please reconnect and try again.");
        }
        recordResetFail();
        if (this.#resetVerifyLockedUntil > Date.now()) {
          const retryAfter = Math.max(1, Math.ceil((this.#resetVerifyLockedUntil - Date.now()) / 1000));
          throw new VaultError("LOCKED_OUT", `Too many failed verification attempts. Try again in ${retryAfter}s.`, { retryAfter });
        }
        throw err instanceof VaultError
          ? err
          : new VaultError("BAD_CREDENTIALS", "Incorrect account password. Please try again.", {
              attemptsLeft: Math.max(0, MASTER_MAX_FAILS - this.#resetVerifyFails)
            });
      }

      this.#accountPassword = password;
      this.#resetVerifyFails = 0;
      this.#resetVerifyLockedUntil = 0;
      this.#passkeyResetVerifiedAt = Date.now();
      return { verified: true, method: "password" };
    }

    // 2. Verify with Google
    if (idToken || accessToken) {
      if (!isFirebaseConfigured()) {
        recordResetFail();
        throw new VaultError("GOOGLE_NOT_CONFIGURED", "Google verification requires Firebase Authentication to be configured.");
      }
      try {
        const gRes = await firebaseSignInWithGoogleToken({ idToken, accessToken });
        if (normEmail(gRes.email) !== cleanEmail) {
          throw new VaultError("BAD_CREDENTIALS", `Please select the Google account for ${cleanEmail}.`);
        }
        if (this.#account.uid && gRes.uid !== this.#account.uid) {
          throw new VaultError("BAD_CREDENTIALS", "Google account UID does not match the signed-in account.");
        }
        this.#account.idToken = gRes.idToken;
        this.#account.refreshToken = gRes.refreshToken || this.#account.refreshToken;
        this.#account.tokenExpiresAt = gRes.tokenExpiresAt;
        await setActiveAccountSession(this.#account);
      } catch (err) {
        recordResetFail();
        if (this.#resetVerifyLockedUntil > Date.now()) {
          const retryAfter = Math.max(1, Math.ceil((this.#resetVerifyLockedUntil - Date.now()) / 1000));
          throw new VaultError("LOCKED_OUT", `Too many failed verification attempts. Try again in ${retryAfter}s.`, { retryAfter });
        }
        throw err instanceof VaultError
          ? err
          : new VaultError("BAD_CREDENTIALS", err?.message || "Google verification failed.", {
              attemptsLeft: Math.max(0, MASTER_MAX_FAILS - this.#resetVerifyFails)
            });
      }

      this.#resetVerifyFails = 0;
      this.#resetVerifyLockedUntil = 0;
      this.#passkeyResetVerifiedAt = Date.now();
      return { verified: true, method: "google" };
    }

    throw new VaultError("UNAUTHENTICATED", "Please verify your identity with your Account Password or Google first.");
  }

  /**
   * Step 2 of "Forgot Passkey?" (`resetPasskeyAfterVerification`):
   *   - Requires fresh Step 1 verification (`#passkeyResetVerifiedAt` ≤ 5 minutes old).
   *   - Single-use: clears `#passkeyResetVerifiedAt` immediately upon acceptance.
   *   - Unwraps the existing vault key (`vk`) using `meta.accountResetWrapped` (or legacy `meta.emailResetWrapped`),
   *     preserving all existing encrypted entries.
   *   - Strips any legacy `recoveryWrapped`, `recoverySalt`, `emailResetWrapped`, and `emailResetSalt`.
   *   - Returns `{ ok: true, pinLength }`.
   */
  async resetPasskeyAfterVerification(newPasskey) {
    if (!this.#account?.email) {
      throw new VaultError("UNAUTHENTICATED", "Please sign in to your account first.");
    }
    const verifiedAt = this.#passkeyResetVerifiedAt;
    if (!verifiedAt || Date.now() - verifiedAt > PASSKEY_RESET_VERIFY_TTL_MS) {
      this.#passkeyResetVerifiedAt = 0;
      throw new VaultError("UNAUTHENTICATED", "Verification expired or missing. Please verify with your password or Google again.");
    }

    const p = checkPin(newPasskey);
    if (!p.ok) throw new VaultError("WEAK_PIN", p.hint);

    // Consume single-use verification token immediately
    this.#passkeyResetVerifiedAt = 0;

    await this.#ensureValidFirebaseToken().catch(() => {});

    const cleanEmail = normEmail(this.#account.email);
    const localProf = await getUserProfile(cleanEmail);

    let remoteVault = null;
    if (isFirebaseConfigured() && this.#account.uid && this.#account.idToken) {
      remoteVault = await firestoreGetVault(this.#account.uid, this.#account.idToken).catch(() => null);
    }

    const candidateMeta = remoteVault?.meta || this.#meta || localProf?.meta || this.#account.meta || null;
    let candidateEntries = remoteVault?.entries || [];
    if (!candidateEntries.length && localProf?.vaultLookup) {
      const localCached = await this.api.getVaultByLookup(localProf.vaultLookup).catch(() => null);
      if (localCached?.entries?.length) candidateEntries = localCached.entries;
    }

    const uid = String(this.#account.uid || localProf?.uid || `local_${cleanEmail}`).trim();
    let vk = this.#vk;

    const pwResetWrapped = candidateMeta?.passwordResetWrapped || candidateMeta?.accountResetWrapped;
    const pwResetSalt = candidateMeta?.passwordResetSalt || candidateMeta?.accountResetSalt;

    // 1. Unwrap using secret Account Password recovery envelope (derivePasswordResetKek)
    if (!vk && this.#accountPassword && pwResetWrapped && pwResetSalt && candidateMeta) {
      try {
        const pwResetKek = await measureAsync("kdf_derivation", () =>
          derivePasswordResetKek(this.#accountPassword, pwResetSalt)
        );
        const unwrapped = await unwrapKey(ub64(pwResetWrapped), pwResetKek, true);
        if ((await open(unwrapped, candidateMeta.verifier, `keyvex:${candidateMeta.vaultId}:verify:`)).ok === true) {
          vk = unwrapped;
        }
      } catch {
        vk = null;
      }
    }

    // 2. Unwrap using local trusted-device non-extractable CryptoKey envelope (wrappedDeviceResetKey)
    if (!vk && localProf?.wrappedDeviceResetKey && candidateMeta) {
      try {
        const unwrapped = await this.#unwrapDeviceResetKey(localProf.wrappedDeviceResetKey, uid, true);
        if (unwrapped && (await open(unwrapped, candidateMeta.verifier, `keyvex:${candidateMeta.vaultId}:verify:`)).ok === true) {
          vk = unwrapped;
        }
      } catch {
        vk = null;
      }
    }

    // 3. Read-only legacy migration fallback for pre-v1.0.0 vaults
    const legacyResetWrapped = candidateMeta?.accountResetWrapped || candidateMeta?.emailResetWrapped;
    const legacyResetSalt = candidateMeta?.accountResetSalt || candidateMeta?.emailResetSalt;
    if (!vk && legacyResetWrapped && legacyResetSalt && candidateMeta) {
      try {
        const legacyKek = await measureAsync("kdf_derivation", () =>
          deriveAccountResetKek(uid, cleanEmail, legacyResetSalt)
        );
        const unwrapped = await unwrapKey(ub64(legacyResetWrapped), legacyKek, true);
        if ((await open(unwrapped, candidateMeta.verifier, `keyvex:${candidateMeta.vaultId}:verify:`)).ok === true) {
          vk = unwrapped;
        }
      } catch {
        vk = null;
      }
    }

    // If an older or un-migrated vault had no valid wrapper, allow re-initializing vk so the user is never permanently locked out

    if (vk && candidateMeta) {
      this.#vk = vk;
      this.#meta = candidateMeta;
      await this.#resolveVaultEntropy(candidateMeta, localProf);
      const tombstones = this.#account?.uid ? await getPendingTombstones(this.#account.uid) : new Map();
      const mergedTombstones = {
        ...(candidateMeta.deletedEntries || {}),
        ...(remoteVault?.tombstones || {})
      };
      for (const [id, t] of Object.entries(mergedTombstones)) {
        this.#tombstones.set(id, t);
      }
      await this.#loadEntries(candidateEntries, {
        tombstoneIds: new Set([...tombstones.keys(), ...Object.keys(mergedTombstones)]),
        remoteTombstones: mergedTombstones
      });
    } else {
      // Never silently replace a vault that still holds data (or one we cannot fully see because we're offline):
      // a brand-new key would orphan every existing entry and then overwrite the cloud copy.
      if (candidateEntries.length > 0 || (candidateMeta && isFirebaseConfigured() && !remoteVault && Vault.#isOffline())) {
        throw new VaultError(
          "RESET_UNAVAILABLE",
          Vault.#isOffline()
            ? "Passkey reset could not unlock your vault key on this device while offline. Please reconnect and try again."
            : "Passkey reset could not unlock your vault key. Your passwords were left untouched."
        );
      }
      this.#vk = await generateVaultKey();
      this.#entries.clear();
      this.#recordSnapshots.clear();
    }

    const kdfSalt = b64(rand(32));
    const vaultEntropy = this.#account?.email
      ? (this.#vaultEntropy || b64(rand(32)))
      : (this.#accountPassword || String(newPasskey));
    if (this.#account?.email) this.#vaultEntropy = vaultEntropy;

    const newCreds = await measureAsync("kdf_derivation", () =>
      this.#account?.email
        ? deriveCredentials(newPasskey, vaultEntropy, { salt: kdfSalt, version: 2 })
        : deriveCredentials(newPasskey, vaultEntropy)
    );

    const vaultId = this.#meta?.vaultId || b64(rand(12));
    const entropyEnvelopes = await this.#buildEntropyEnvelopes(vaultEntropy, vaultId, this.#meta, newPasskey);
    const accountResetEnvelope = await this.#buildAccountResetEnvelope(this.#vk, this.#meta);
    const wrappedDeviceResetKey = await this.#wrapDeviceResetKey(this.#vk, uid);

    const meta = await this.#header(this.#vk, newCreds.kek, newPasskey, vaultEntropy, { ...this.#meta, vaultId }, {
      kdfSalt,
      kdfVersion: this.#account?.email ? 2 : 1,
      ...entropyEnvelopes,
      ...accountResetEnvelope,
      accountName: this.#account?.name,
      accountEmail: this.#account?.email
    });

    const recs = await Promise.all(
      [...this.#entries.values()].map(async (e) => {
        const sealed = await seal(this.#vk, e, `keyvex:${meta.vaultId}:entry:${e.id}`);
        const ciphertextHash = await computeCiphertextHash(sealed.iv, sealed.data);
        return { id: e.id, ...sealed, updatedAt: e.updatedAt, createdAt: e.createdAt, rev: e.rev || 1, ciphertextHash };
      })
    );

    await this.api.mirrorVault({ lookup: newCreds.lookup, auth: newCreds.auth, meta, entries: recs });
    if (!isFirebaseConfigured() && recs.length > 0) {
      await this.api.putEntries(recs).catch(() => {});
    }

    this.#meta = meta;
    this.#activeLookup = newCreds.lookup;
    this.#activeAuth = newCreds.auth;
    this.#stepUpPasskey = String(newPasskey);
    await clearPasskeyLockState(uid);
    this.#masterFails = 0;
    this.#stepUpLockedUntil = 0;

    const pinLength = resolvePinLengthTag(newPasskey);
    if (this.#account) {
      this.#account.pinLength = pinLength;
      this.#account.hasVault = true;
      this.#account.meta = meta;

      const updatedProf = await getUserProfile(cleanEmail);
      await saveUserProfile({
        ...updatedProf,
        email: cleanEmail,
        uid: this.#account.uid,
        pinLength,
        hasVault: true,
        vaultLookup: newCreds.lookup,
        deviceVaultEntropy: this.#vaultEntropy,
        wrappedDeviceResetKey: wrappedDeviceResetKey || updatedProf?.wrappedDeviceResetKey || null,
        meta
      });
      await setActiveAccountSession(this.#account);
      emitFirebaseAuthState(this.account);
      await this.#loadSideCollections();

      if (this.#canSyncToCloud()) {
        await enqueueCloudOutbox(this.#account.uid, { op: "meta", meta });
        await this.#flushCloudOutbox();
      }
    }

    return { ok: true, pinLength };
  }

  /**
   * PART 1 & F1: `handleEmailActionLink` ONLY handles `mode=verifyEmail` to apply the Firebase OOB code
   * and refresh email verification status. It NEVER sets `#passkeyResetVerifiedAt`.
   */
  async handleEmailActionLink({ mode, oobCode } = {}) {
    if (mode === "verifyEmail" && oobCode && isFirebaseConfigured()) {
      await firebaseApplyActionCode(oobCode).catch(() => {});
      await this.refreshEmailVerificationStatus().catch(() => {});
      return { mode: "verifyEmail", verified: Boolean(this.#account?.emailVerified) };
    }
    return { mode: mode || "", verified: false };
  }

  async confirmPasswordResetWithOobCode(oobCode, newPassword) {
    const m = checkMasterPassword(newPassword);
    if (!m.ok) throw new VaultError("WEAK_MASTER", m.hint);
    const res = await firebaseConfirmPasswordReset(oobCode, newPassword);
    return { ok: true, email: res?.email || "" };
  }

  async resendVerificationEmail() {
    if (!this.#account?.email) throw new VaultError("UNAUTHENTICATED", "Please sign in first.");
    await this.#ensureValidFirebaseToken();
    if (isFirebaseConfigured() && this.#account.idToken) {
      try {
        await firebaseSendEmailVerification(this.#account.idToken);
      } catch (err) {
        if (err?.code === "INVALID_ID_TOKEN" || err?.code === "TOKEN_EXPIRED") {
          await this.#ensureValidFirebaseToken(true);
          await firebaseSendEmailVerification(this.#account.idToken);
        } else {
          throw err;
        }
      }
    }
    this.#account.emailVerificationSent = true;
    await setActiveAccountSession(this.#account);
    return { ok: true, email: this.#account.email };
  }

  /**
   * F8 & B8: `refreshEmailVerificationStatus`:
   *   - In Firebase mode: queries `firebaseGetAccountInfo`; if newly verified, force-refreshes the ID token
   *     so Firestore rules immediately see `request.auth.token.email_verified == true`.
   *   - In non-Firebase (local) mode: returns `{ emailVerified: false, local: true }` and never falsely sets
   *     `emailVerified = true`.
   */
  async refreshEmailVerificationStatus() {
    if (!this.#account?.email) throw new VaultError("UNAUTHENTICATED", "Please sign in first.");
    if (!isFirebaseConfigured()) {
      return { emailVerified: false, local: true };
    }
    await this.#ensureValidFirebaseToken();
    if (this.#account.idToken) {
      let info = null;
      try {
        info = await firebaseGetAccountInfo(this.#account.idToken);
      } catch (err) {
        if (err?.code === "INVALID_ID_TOKEN" || err?.code === "TOKEN_EXPIRED") {
          await this.#ensureValidFirebaseToken(true);
          info = await firebaseGetAccountInfo(this.#account.idToken);
        } else {
          throw err;
        }
      }
      if (info) {
        const wasVerified = Boolean(this.#account.emailVerified);
        this.#account.emailVerified = !!info.emailVerified;
        if (this.#account.emailVerified && !wasVerified && this.#account.refreshToken) {
          // Force-refresh ID token so Firestore security rules see email_verified: true (B8)
          await this.#ensureValidFirebaseToken(true).catch(() => {});
        }
        const localProf = await getUserProfile(this.#account.email);
        if (localProf) {
          await saveUserProfile({ ...localProf, emailVerified: this.#account.emailVerified });
        }
        await setActiveAccountSession(this.#account);
        emitFirebaseAuthState(this.account);
        if (this.#account.emailVerified && this.unlocked) {
          await this.#flushCloudOutbox().catch(() => {});
        }
      }
    }
    return { emailVerified: !!this.#account.emailVerified, local: false };
  }

  /**
   * PART 4, F5, F6 & B13: `enableTotp(passkey, secret)` requires current Passkey first,
   * never stores `totpSecret` in plaintext IndexedDB, generates 8 one-time backup codes,
   * and stores hashed backup codes inside the sealed envelope.
   */
  async enableTotp(passkey, secret) {
    if (!this.#account?.email) throw new VaultError("UNAUTHENTICATED", "Please sign in first.");
    await this.requirePasskey(passkey);
    const cleanEmail = normEmail(this.#account.email);
    const uid = String(this.#account.uid || `local_${cleanEmail}`).trim();

    const backupCodes = generateTotpBackupCodes(8);
    const backupHashes = await Promise.all(backupCodes.map((c) => hashTotpBackupCode(c)));

    this.#account.totpEnabled = true;
    this.#totpSecretInMemory = secret;
    this.#totpBackupHashes = backupHashes;

    const totpPayload = { enabled: true, secret, backupHashes, updatedAt: Date.now() };
    const wrappedDeviceTotp = await wrapDeviceVaultEntropy(JSON.stringify(totpPayload), `totp:${String(uid || cleanEmail)}`);

    if (this.#meta) {
      const totpSalt = rand(16);
      let passwordTotp = null;
      if (this.#accountPassword) {
        const pwKey = await deriveEnvelopeGcmKey(this.#accountPassword, totpSalt, "keyvex:v6:totp-pw");
        passwordTotp = await seal(pwKey, totpPayload, `keyvex:${this.#meta.vaultId}:totp-pw:`);
      }
      const sealedTotp = this.#vk
        ? await seal(this.#vk, totpPayload, this.#aad("totp"))
        : (this.#meta.sealedTotp || null);
      this.#meta = {
        ...this.#meta,
        metaRev: (Number(this.#meta.metaRev) || 1) + 1,
        totpEnabled: true,
        totpSalt: b64(totpSalt),
        passwordTotp,
        sealedTotp,
        totpBackupHashes: backupHashes
      };
      delete this.#meta.accountTotp;
      this.#account.meta = this.#meta;
      if (this.#canSyncToCloud()) {
        await enqueueCloudOutbox(this.#account.uid, { op: "meta", meta: this.#meta });
        await this.#flushCloudOutbox().catch(() => {});
      }
    }

    const localProf = await getUserProfile(cleanEmail);
    await saveUserProfile({
      ...localProf,
      email: cleanEmail,
      totpEnabled: true,
      wrappedDeviceTotp,
      meta: this.#meta || localProf?.meta || null
    });
    await setActiveAccountSession(this.#account);
    return { ok: true, enabled: true, backupCodes };
  }

  /**
   * PART 4, F5 & F6: `disableTotp(passkey)` requires current Passkey first.
   */
  async disableTotp(passkey) {
    if (!this.#account?.email) throw new VaultError("UNAUTHENTICATED", "Please sign in first.");
    await this.requirePasskey(passkey);
    const cleanEmail = normEmail(this.#account.email);
    this.#account.totpEnabled = false;
    this.#totpSecretInMemory = null;
    this.#totpBackupHashes = [];

    if (this.#meta) {
      this.#meta = {
        ...this.#meta,
        metaRev: (Number(this.#meta.metaRev) || 1) + 1,
        totpEnabled: false,
        totpSalt: null,
        passwordTotp: null,
        accountTotp: null,
        sealedTotp: null,
        totpBackupHashes: []
      };
      this.#account.meta = this.#meta;
      if (this.#canSyncToCloud()) {
        await enqueueCloudOutbox(this.#account.uid, { op: "meta", meta: this.#meta });
        await this.#flushCloudOutbox().catch(() => {});
      }
    }

    const localProf = await getUserProfile(cleanEmail);
    await saveUserProfile({
      ...localProf,
      email: cleanEmail,
      totpEnabled: false,
      wrappedDeviceTotp: null,
      meta: this.#meta || localProf?.meta || null
    });
    await setActiveAccountSession(this.#account);
    return { ok: true };
  }

  /**
   * Consumes one of the 8 one-time TOTP backup codes during login when the user cannot access their authenticator app (B13).
   */
  async verifyTotpBackupCode(code) {
    if (!this.#account?.email) return false;
    const hashes = this.#totpBackupHashes?.length
      ? this.#totpBackupHashes
      : (this.#account.meta?.totpBackupHashes || []);
    const { ok, remainingHashes } = await verifyAndConsumeTotpBackupCode(code, hashes);
    if (!ok) return false;
    this.#totpBackupHashes = remainingHashes;
    if (this.#account.meta) {
      this.#account.meta = { ...this.#account.meta, totpBackupHashes: remainingHashes };
    }
    if (this.#meta) {
      this.#meta = { ...this.#meta, totpBackupHashes: remainingHashes };
    }
    const localProf = await getUserProfile(this.#account.email);
    if (localProf) {
      await saveUserProfile({ ...localProf, email: this.#account.email, meta: this.#account.meta || localProf.meta });
    }
    return true;
  }

  async signOutAccount() {
    closeActiveGooglePopup();
    unloadGoogleIdentityServices();
    const email = this.#account?.email;
    const uid = this.#account?.uid;
    const rememberDevice = Boolean(this.#account?.rememberDevice);
    this.lock();
    this.#accountPassword = null;
    this.#vaultEntropy = null;
    this.#totpSecretInMemory = null;
    this.#totpBackupHashes = [];
    this.#passkeyResetVerifiedAt = 0;
    this.#resetVerifyFails = 0;
    this.#resetVerifyLockedUntil = 0;
    this.#stepUpUntil = 0;
    this.#stepUpPasskey = null;
    this.#account = null;
    this.#pendingOutboxCount = 0;
    if (!rememberDevice && (email || uid)) {
      await clearDeviceVaultEntropy(email, uid).catch(() => {});
    }
    setSyncSessionHint(null);
    await setActiveAccountSession(null);
    emitFirebaseAuthState(null);
  }

  /* ==========================================================================
   * LAYER 2 — Passkey Setup, Unlock, Canonical Firestore Outbox & Migration
   * ========================================================================== */

  /**
   * Flushes queued mutations to Cloud Firestore in strict FIFO order, stopping at the first failure (B11).
   */
  /**
   * Pushes queued offline changes to the cloud. Works even while the vault is locked (the queue only holds
   * already-encrypted records), so changes sync the moment the connection returns, not only after the next unlock.
   */
  async syncPending() {
    if (!this.#account?.uid) return { flushed: 0, remaining: 0 };
    return this.#flushCloudOutbox();
  }

  async #flushCloudOutbox() {
    if (this.#flushP) {
      // A flush is already running: ask it to go around once more so ops queued meanwhile are not left behind.
      this.#flushDirty = true;
      return this.#flushP;
    }
    this.#flushP = this.#exclusive(async () => {
      let result;
      do {
        this.#flushDirty = false;
        result = await this.#flushCloudOutboxOnce();
      } while (this.#flushDirty && result.remaining > 0 && result.flushed > 0);
      return result;
    }).finally(() => { this.#flushP = null; this.#flushDirty = false; });
    return this.#flushP;
  }

  async #flushCloudOutboxOnce() {
    if (!this.#canSyncToCloud() || Vault.#isOffline()) {
      const items = this.#account?.uid ? await getCloudOutbox(this.#account.uid) : [];
      this.#pendingOutboxCount = items.length;
      this.#cloudSynced = items.length === 0;
      return { flushed: 0, remaining: items.length };
    }
    await this.#ensureValidFirebaseToken();
    const uid = this.#account.uid;
    const idToken = this.#account.idToken;
    const items = await getCloudOutbox(uid);
    if (!items.length) {
      this.#pendingOutboxCount = 0;
      this.#cloudSynced = true;
      return { flushed: 0, remaining: 0 };
    }
    if (!idToken) {
      this.#pendingOutboxCount = items.length;
      this.#cloudSynced = false;
      return { flushed: 0, remaining: items.length };
    }

    let flushed = 0;
    for (const item of items) {
      try {
        if (item.op === "meta" && item.meta) {
          const saved = await retryWithBackoff(() => firestoreSaveMeta(uid, idToken, {
            email: this.#account.email,
            name: this.#account.name,
            meta: item.meta
          }));
          if (saved?.meta) {
            this.#meta = saved.meta;
            if (this.#account) this.#account.meta = saved.meta;
          }
          await ackCloudOutbox(uid, item.opId);
          flushed++;
        } else if (item.op === "upsert" && item.record) {
          await retryWithBackoff(() => firestorePutEntry(uid, idToken, item.record));
          await firestoreDeleteTombstone(uid, idToken, item.record.id).catch(() => {});
          await ackCloudOutbox(uid, item.opId);
          flushed++;
        } else if (item.op === "delete" && item.entryId) {
          await retryWithBackoff(() => firestoreDeleteEntry(uid, idToken, item.entryId));
          await retryWithBackoff(() => firestorePutTombstone(uid, idToken, item.entryId, {
            deletedAt: item.deletedAt || Date.now(),
            deletedRev: item.deletedRev || 1,
            baseHash: item.baseHash || ""
          }));
          await ackCloudOutbox(uid, item.opId);
          flushed++;
        }
      } catch (err) {
        this.lastSyncError = err;
        await updateCloudOutboxAttempt(uid, item.opId, err?.code || "FIRESTORE_ERROR");
        // B11: Stop at the first failure so later operations are never applied out of order!
        break;
      }
    }

    const remainingList = await getCloudOutbox(uid);
    this.#pendingOutboxCount = remainingList.length;
    this.#cloudSynced = remainingList.length === 0;
    if (this.#cloudSynced) this.lastSyncError = null;
    return { flushed, remaining: remainingList.length };
  }

  /**
   * PART 2: `setupPasskey` creates vault WITHOUT `recoveryWrapped`/`recoverySalt` and returns `{ ok: true }`.
   */
  async setupPasskey(passkey) {
    if (!this.#account?.email) throw new VaultError("UNAUTHENTICATED", "Please sign in to your account first.");
    const p = checkPin(passkey);
    if (!p.ok) throw new VaultError("WEAK_PIN", p.hint);

    await this.#ensureValidFirebaseToken();

    const localProf = await getUserProfile(this.#account.email);
    if (this.#account.hasVault || localProf?.hasVault) {
      throw new VaultError("ACCOUNT_EXISTS", "A vault already exists for this account. Enter your existing Passkey to unlock it.");
    }
    if (isFirebaseConfigured() && this.#account.uid && this.#account.idToken) {
      const existingRemote = await firestoreGetVaultMetaOnly(this.#account.uid, this.#account.idToken).catch(() => null);
      if (existingRemote?.meta) {
        this.#account.hasVault = true;
        this.#account.pinLength = existingRemote.meta.pinLength || 6;
        this.#account.meta = existingRemote.meta;
        await saveUserProfile({
          ...localProf,
          email: this.#account.email,
          uid: this.#account.uid,
          hasVault: true,
          pinLength: this.#account.pinLength,
          meta: existingRemote.meta
        });
        await setActiveAccountSession(this.#account);
        throw new VaultError("ACCOUNT_EXISTS", "A vault already exists for this account. Enter your existing Passkey to unlock it.");
      }
    }

    const kdfSalt = b64(rand(32));
    const vaultEntropy = b64(rand(32));
    this.#vaultEntropy = vaultEntropy;

    const creds = await measureAsync("kdf_derivation", () =>
      deriveCredentials(passkey, vaultEntropy, { salt: kdfSalt, version: 2 })
    );
    const vk = await generateVaultKey();
    const vaultId = b64(rand(12));
    const entropyEnvelopes = await this.#buildEntropyEnvelopes(vaultEntropy, vaultId, null, passkey);
    const accountResetEnvelope = await this.#buildAccountResetEnvelope(vk, null);
    const wrappedDeviceResetKey = await this.#wrapDeviceResetKey(vk, this.#account.uid || this.#account.email);

    const meta = await this.#header(vk, creds.kek, passkey, vaultEntropy, { vaultId }, {
      kdfSalt,
      kdfVersion: 2,
      metaRev: 1,
      ...entropyEnvelopes,
      ...accountResetEnvelope,
      deletedEntries: {},
      accountName: this.#account.name,
      accountEmail: this.#account.email
    });

    if (isFirebaseConfigured()) {
      await this.api.mirrorVault({ lookup: creds.lookup, auth: creds.auth, meta, entries: [] });
    } else {
      await this.api.register({ lookup: creds.lookup, auth: creds.auth, meta });
    }

    this.#meta = meta;
    this.#vk = await unwrapKey(ub64(meta.wrapped), creds.kek, false);
    this.#entries.clear();
    this.#recordSnapshots.clear();
    this.#externalEntries.clear();
    this.#generatorHistory = [];
    this.#tombstones.clear();
    this.skipped = 0;
    this.migrated = false;
    this.#masterFails = 0;
    this.#activeLookup = creds.lookup;
    this.#activeAuth = creds.auth;
    this.#stepUpPasskey = String(passkey);

    const pinLength = resolvePinLengthTag(passkey);
    this.#account.hasVault = true;
    this.#account.pinLength = pinLength;
    this.#account.meta = this.#meta;

    await saveUserProfile({
      ...localProf,
      email: this.#account.email,
      name: this.#account.name,
      uid: this.#account.uid,
      provider: this.#account.provider,
      providers: this.#account.providers || [this.#account.provider],
      hasVault: true,
      pinLength,
      vaultLookup: creds.lookup,
      deviceVaultEntropy: vaultEntropy,
      wrappedDeviceResetKey,
      meta: this.#meta,
      canonicalMigrationVersion: 1
    });
    await setActiveAccountSession(this.#account);
    emitFirebaseAuthState(this.account);
    await this.#loadSideCollections();

    if (this.#canSyncToCloud()) {
      await enqueueCloudOutbox(this.#account.uid, { op: "meta", meta: this.#meta });
      await this.#flushCloudOutbox();
    }

    return { ok: true };
  }

  async #verifyPasskeyAgainstMeta(passkey, secret, candidateMeta, kdfOptions = {}) {
    if (candidateMeta?.wrapped && candidateMeta?.verifier) {
      try {
        const creds = await measureAsync("kdf_derivation", () => deriveCredentials(passkey, secret, kdfOptions));
        const vk = await this.#openVault(candidateMeta, creds.kek, null, false);
        return { unlocked: true, vk, creds, meta: candidateMeta };
      } catch (err) {
        if (err?.code !== "BAD_CREDENTIALS") throw err;
        return { unlocked: false };
      }
    }

    try {
      const creds = await measureAsync("kdf_derivation", () => deriveCredentials(passkey, secret, kdfOptions));
      const { meta, entries } = await this.api.login({ lookup: creds.lookup, auth: creds.auth });
      const vk = await this.#openVault(meta, creds.kek, entries, false);
      return { unlocked: true, vk, creds, meta, entries };
    } catch (err) {
      if (err?.code === "BAD_CREDENTIALS" || err?.code === "NETWORK") {
        if (!candidateMeta) {
          const creds = await deriveCredentials(passkey, secret, kdfOptions);
          const migrated = await this.#migrateLegacy(passkey, secret, creds);
          if (migrated) {
            return { unlocked: true, vk: this.#vk, creds, meta: this.#meta, entries: [...this.#recordSnapshots.values()] };
          }
        }
        return { unlocked: false };
      }
      throw err;
    }
  }

  async #tryVerifyPasskeyAllSchemes(cleanPasskey, candidateMeta, localProf) {
    let verifyRes = { unlocked: false };
    let activeSecret = null;
    let needsV2Upgrade = false;

    if (candidateMeta?.kdf?.version === 2 && candidateMeta?.kdf?.salt) {
      const entropy = await this.#resolveVaultEntropy(candidateMeta, localProf, cleanPasskey);
      if (entropy) {
        verifyRes = await this.#verifyPasskeyAgainstMeta(cleanPasskey, entropy, candidateMeta, {
          salt: candidateMeta.kdf.salt,
          version: 2,
          iterations: candidateMeta.kdf.iterations
        });
        if (verifyRes.unlocked) {
          activeSecret = entropy;
        }
      }
    }

    const legacyEmailSecret = gmailVaultSecret(this.#account.email);
    if (!verifyRes.unlocked) {
      verifyRes = await this.#verifyPasskeyAgainstMeta(cleanPasskey, legacyEmailSecret, candidateMeta);
      if (verifyRes.unlocked) {
        activeSecret = legacyEmailSecret;
        needsV2Upgrade = true;
      }
    }

    if (!verifyRes.unlocked && this.#accountPassword && this.#accountPassword !== legacyEmailSecret) {
      verifyRes = await this.#verifyPasskeyAgainstMeta(cleanPasskey, this.#accountPassword, candidateMeta);
      if (verifyRes.unlocked) {
        activeSecret = this.#accountPassword;
        needsV2Upgrade = true;
        this.migrated = true;
      }
    }

    return { verifyRes, activeSecret, needsV2Upgrade };
  }

  async #runCanonicalFirestoreMigration(creds, localProf, remoteVault) {
    if (!this.#canSyncToCloud() || !this.#account?.idToken) return false;
    if (localProf?.canonicalMigrationVersion === 1 && remoteVault?.meta) return false;

    const localCached = await this.api.getVaultByLookup(creds.lookup).catch(() => null);
    const sourceEntries = localCached?.entries || [];
    if (!sourceEntries.length && remoteVault?.meta) {
      await saveUserProfile({ ...localProf, email: this.#account.email, uid: this.#account.uid, canonicalMigrationVersion: 1 });
      return false;
    }

    await savePreMigrationBackup({
      kind: "sim",
      simName: `firestore_mig_${this.#account.uid}`,
      vaultId: this.#meta?.vaultId || "v6",
      rawMeta: this.#meta,
      rawEntries: [...this.#recordSnapshots.values()]
    });

    const remoteMap = new Map((remoteVault?.entries || []).map((r) => [r.id, r]));
    for (const localRec of sourceEntries) {
      if (!localRec?.id || !localRec?.iv || !localRec?.data) continue;
      const localHash = await computeCiphertextHash(localRec.iv, localRec.data);
      const remRec = remoteMap.get(localRec.id);
      if (remRec) {
        const remHash = remRec.ciphertextHash || (await computeCiphertextHash(remRec.iv, remRec.data));
        if (remHash !== localHash) {
          await saveSyncConflict(this.#account.uid, {
            entryId: localRec.id,
            reason: "migration_divergence",
            localRecord: { ...localRec, ciphertextHash: localHash },
            remoteRecord: { ...remRec, ciphertextHash: remHash }
          });
        }
      }
    }

    await firestoreSaveMeta(this.#account.uid, this.#account.idToken, {
      email: this.#account.email,
      name: this.#account.name,
      meta: this.#meta
    });

    const missingRemote = [...this.#recordSnapshots.values()].filter((snap) => !remoteMap.has(snap.id));
    if (missingRemote.length) {
      await firestoreBatchPutEntries(this.#account.uid, this.#account.idToken, missingRemote);
    }

    const verifiedRemote = await firestoreGetVault(this.#account.uid, this.#account.idToken);
    if (!verifiedRemote?.meta || verifiedRemote.meta.vaultId !== this.#meta.vaultId) {
      throw new VaultError("MIGRATION_INCOMPLETE", "Firestore read-back verification failed for vault header.");
    }
    const verifiedMap = new Map((verifiedRemote.entries || []).map((r) => [r.id, r]));
    for (const [id] of this.#entries.entries()) {
      const r = verifiedMap.get(id);
      if (!r) {
        throw new VaultError("MIGRATION_INCOMPLETE", `Firestore read-back verification failed: missing entry ${id}.`);
      }
      await open(this.#vk, r, this.#aad("entry", id));
    }

    await saveUserProfile({
      ...localProf,
      email: this.#account.email,
      uid: this.#account.uid,
      canonicalMigrationVersion: 1
    });
    return true;
  }

  async unlockWithPasskey(passkey) {
    if (!this.#account?.email) throw new VaultError("UNAUTHENTICATED", "Please sign in to your account first.");
    const cleanPasskey = String(passkey ?? "");
    const uid = this.#account.uid || this.#account.email;

    // B2: Check persistent per-UID lockout in IndexedDB before deriving KDF
    const lockState = await getPasskeyLockState(uid);
    const now = Date.now();
    if (lockState.lockedUntil > now) {
      const retryAfter = Math.max(1, Math.ceil((lockState.lockedUntil - now) / 1000));
      throw new VaultError(
        "LOCKED_OUT",
        `Too many wrong Passkey attempts. Try again in ${retryAfter}s.`,
        { retryAfter, lockedUntil: lockState.lockedUntil, context: "passkey" }
      );
    }

    await this.#ensureValidFirebaseToken();

    const localProf = await getUserProfile(this.#account.email);
    let candidateMeta = this.#account.meta || localProf?.meta || null;
    let fetchedFreshMeta = false;

    if (!candidateMeta && isFirebaseConfigured() && this.#account.uid && this.#account.idToken) {
      try {
        const metaDoc = await firestoreGetVaultMetaOnly(this.#account.uid, this.#account.idToken);
        candidateMeta = metaDoc?.meta || null;
        fetchedFreshMeta = true;
      } catch (err) {
        if (err?.code === "PERMISSION_DENIED") throw err;
        this.#cloudSynced = false;
      }
    }

    const rawExpectedLen = candidateMeta?.pinLength ?? this.#account.pinLength;
    const expectedLen = (rawExpectedLen === 4 || rawExpectedLen === 6 || rawExpectedLen === 8 || rawExpectedLen === "strong")
      ? rawExpectedLen
      : null;

    if (expectedLen && (expectedLen === 4 || expectedLen === 6 || expectedLen === 8)) {
      if (!/^\d+$/.test(cleanPasskey) || cleanPasskey.length !== expectedLen) {
        throw new VaultError("VAULT_WRONG_PASSKEY", `Enter your ${expectedLen}-digit Passkey.`, { context: "passkey", expectedLength: expectedLen });
      }
    } else if (!isValidPasskeyShape(cleanPasskey, expectedLen)) {
      throw new VaultError("VAULT_WRONG_PASSKEY", "Passkey must be 4 or 6 digits.", { context: "passkey" });
    }

    let { verifyRes, activeSecret, needsV2Upgrade } = await this.#tryVerifyPasskeyAllSchemes(cleanPasskey, candidateMeta, localProf);

    if (!verifyRes.unlocked && !fetchedFreshMeta && isFirebaseConfigured() && this.#account.uid && this.#account.idToken) {
      try {
        const freshMetaDoc = await firestoreGetVaultMetaOnly(this.#account.uid, this.#account.idToken);
        if (freshMetaDoc?.meta && JSON.stringify(freshMetaDoc.meta) !== JSON.stringify(candidateMeta)) {
          candidateMeta = freshMetaDoc.meta;
          this.#vaultEntropy = null;
          ({ verifyRes, activeSecret, needsV2Upgrade } = await this.#tryVerifyPasskeyAllSchemes(cleanPasskey, candidateMeta, localProf));
        }
      } catch {
        /* ignore network errors during fallback meta check */
      }
    }

    if (!verifyRes.unlocked) {
      const failState = await recordPasskeyFailure(uid, MASTER_MAX_FAILS);
      this.#masterFails = failState.fails;
      const left = Math.max(0, MASTER_MAX_FAILS - failState.fails);
      if (failState.fails >= MASTER_MAX_FAILS) {
        throw new VaultError(
          "LOCKED_OUT",
          `Too many wrong Passkey attempts. Try again in ${failState.retryAfter}s.`,
          { retryAfter: failState.retryAfter, lockedUntil: failState.lockedUntil, attemptsLeft: 0, context: "passkey" }
        );
      }
      throw new VaultError("VAULT_WRONG_PASSKEY", "Incorrect Passkey. Please try again.", { attemptsLeft: left, context: "passkey" });
    }

    await clearPasskeyLockState(uid);
    this.#vk = verifyRes.vk;
    this.#meta = verifyRes.meta;
    this.#masterFails = 0;
    this.#stepUpLockedUntil = 0;
    this.#activeLookup = verifyRes.creds.lookup;
    this.#activeAuth = verifyRes.creds.auth;
    this.#stepUpPasskey = cleanPasskey;
    if (activeSecret && verifyRes.meta?.kdf?.version === 2) {
      this.#vaultEntropy = activeSecret;
    }
    this.#passkeyResetVerifiedAt = 0;
    let activeCreds = verifyRes.creds;

    // Extract TOTP secret into memory if sealed in meta (F5b)
    if (this.#meta?.sealedTotp) {
      try {
        const openedTotp = await open(this.#vk, this.#meta.sealedTotp, this.#aad("totp"));
        if (openedTotp?.secret) this.#totpSecretInMemory = openedTotp.secret;
        if (Array.isArray(openedTotp?.backupHashes)) this.#totpBackupHashes = openedTotp.backupHashes;
      } catch { /* ignore */ }
    }

    const localCached = verifyRes.entries
      ? { entries: verifyRes.entries }
      : (await this.api.getVaultByLookup(activeCreds.lookup).catch(() => null)) ||
        (localProf?.vaultLookup ? await this.api.getVaultByLookup(localProf.vaultLookup).catch(() => null) : null);

    let remoteVault = null;
    if (isFirebaseConfigured() && this.#account.uid && this.#account.idToken) {
      try {
        remoteVault = await firestoreGetVault(this.#account.uid, this.#account.idToken);
      } catch (err) {
        if (err?.code === "PERMISSION_DENIED") throw err;
        this.#cloudSynced = false;
      }
    }

    const rawTombstones = {
      ...(this.#meta?.deletedEntries || {}),
      ...(remoteVault?.meta?.deletedEntries || {}),
      ...(remoteVault?.tombstones || {})
    };
    const prunedTombstones = pruneTombstoneMap(rawTombstones, TOMBSTONE_CAP);
    this.#tombstones.clear();
    for (const [id, t] of Object.entries(prunedTombstones)) {
      this.#tombstones.set(id, t);
    }

    // Keep meta.deletedEntries compact (< 50 recent tombstones) while migrating old meta.deletedEntries to subcollection (B3)
    const compactMetaTombstones = pruneTombstoneMap(prunedTombstones, META_TOMBSTONE_CAP);
    const hasLegacyRecoveryFields = Boolean(
      this.#meta?.recoveryWrapped ||
      this.#meta?.recoverySalt ||
      this.#meta?.emailResetWrapped ||
      this.#meta?.emailResetSalt ||
      remoteVault?.meta?.recoveryWrapped ||
      remoteVault?.meta?.recoverySalt ||
      remoteVault?.meta?.emailResetWrapped ||
      remoteVault?.meta?.emailResetSalt
    );

    this.#meta = {
      ...this.#meta,
      metaRev: Math.max(Number(this.#meta?.metaRev) || 1, Number(remoteVault?.meta?.metaRev) || 1),
      deletedEntries: compactMetaTombstones
    };
    delete this.#meta.recoveryWrapped;
    delete this.#meta.recoverySalt;
    delete this.#meta.emailResetWrapped;
    delete this.#meta.emailResetSalt;

    const tombstones = this.#account?.uid ? await getPendingTombstones(this.#account.uid) : new Map();
    const tombstoneIds = new Set([...tombstones.keys(), ...Object.keys(prunedTombstones)]);

    const baseEntries = localCached?.entries || [];
    await this.#loadEntries(baseEntries, {
      merge: false,
      tombstoneIds,
      remoteTombstones: prunedTombstones
    });

    if (remoteVault?.entries?.length) {
      await this.#loadEntries(remoteVault.entries, {
        merge: true,
        tombstoneIds,
        remoteTombstones: prunedTombstones
      });
    }

    if (this.#account?.uid) {
      const outbox = await getCloudOutbox(this.#account.uid);
      const pendingUpserts = outbox.filter((o) => o.op === "upsert" && o.record).map((o) => o.record);
      if (pendingUpserts.length) {
        await this.#loadEntries(pendingUpserts, {
          merge: true,
          tombstoneIds,
          remoteTombstones: prunedTombstones
        });
      }
    }

    // Upgrade v1 vaults, add accountResetWrapped if missing, or strip legacy recoveryWrapped/emailResetWrapped (PART 2 & F4a)
    let wrappedDeviceResetKey = localProf?.wrappedDeviceResetKey || null;
    if (needsV2Upgrade || !this.#meta?.accountResetWrapped || !this.#meta?.wrappedEntropyAccount || hasLegacyRecoveryFields) {
      try {
        const rekeyVk = await this.#openVault(
          this.#meta,
          activeCreds.kek,
          null,
          true
        );
        const kdfSalt = this.#meta?.kdf?.version === 2 && this.#meta?.kdf?.salt
          ? this.#meta.kdf.salt
          : b64(rand(32));
        const vaultEntropy = this.#vaultEntropy || b64(rand(32));
        this.#vaultEntropy = vaultEntropy;
        const newCreds = await measureAsync("kdf_derivation", () =>
          deriveCredentials(cleanPasskey, vaultEntropy, { salt: kdfSalt, version: 2 })
        );
        const entropyEnvelopes = await this.#buildEntropyEnvelopes(vaultEntropy, this.#meta.vaultId, this.#meta, cleanPasskey);
        const accountResetEnvelope = await this.#buildAccountResetEnvelope(rekeyVk, this.#meta);
        wrappedDeviceResetKey = (await this.#wrapDeviceResetKey(rekeyVk, this.#account.uid || this.#account.email)) || wrappedDeviceResetKey;
        const newMeta = await this.#header(rekeyVk, newCreds.kek, cleanPasskey, vaultEntropy, this.#meta, {
          kdfSalt,
          kdfVersion: 2,
          metaRev: (Number(this.#meta.metaRev) || 1) + 1,
          ...entropyEnvelopes,
          ...accountResetEnvelope,
          deletedEntries: compactMetaTombstones,
          accountName: this.#account.name,
          accountEmail: this.#account.email
        });
        this.#meta = newMeta;
        activeCreds = newCreds;
        this.#activeLookup = newCreds.lookup;
        this.#activeAuth = newCreds.auth;
        activeSecret = vaultEntropy;
        if (this.#canSyncToCloud()) {
          await enqueueCloudOutbox(this.#account.uid, { op: "meta", meta: newMeta });
        }
      } catch {
        /* keep unlocked vault operational if non-critical header upgrade fails */
      }
    }

    await this.api.mirrorVault({
      lookup: activeCreds.lookup,
      auth: activeCreds.auth,
      meta: this.#meta,
      entries: [...this.#recordSnapshots.values()]
    });

    const pinLength = resolvePinLengthTag(cleanPasskey);
    this.#account.hasVault = true;
    this.#account.pinLength = pinLength;
    this.#account.meta = this.#meta;

    if (this.#canSyncToCloud()) {
      try {
        await this.#runCanonicalFirestoreMigration(activeCreds, localProf, remoteVault);
      } catch (migErr) {
        this.lastSyncError = migErr;
        this.#cloudSynced = false;
      }
      await this.#flushCloudOutbox().catch((flushErr) => {
        this.lastSyncError = flushErr;
        this.#cloudSynced = false;
      });
    }

    await saveUserProfile({
      ...localProf,
      email: this.#account.email,
      name: this.#account.name,
      uid: this.#account.uid,
      hasVault: true,
      pinLength,
      vaultLookup: activeCreds.lookup,
      deviceVaultEntropy: this.#vaultEntropy || undefined,
      wrappedDeviceResetKey: wrappedDeviceResetKey || undefined,
      meta: this.#meta
    });
    await setActiveAccountSession(this.#account);
    emitFirebaseAuthState(this.account);
    await this.#loadSideCollections();
  }

  /* ==========================================================================
   * Core Cryptographic Vault Operations (1-Layer & 2-Layer)
   * ========================================================================== */

  async #migrateLegacy(passkey, master, creds) {
    const legacy = await discoverLegacyVault(passkey, master);
    if (!legacy) return false;

    await savePreMigrationBackup(legacy);

    try {
      const vk = await generateVaultKey();
      const meta = await this.#header(vk, creds.kek, passkey, master, null, { kdfVersion: 1 });
      await this.api.register({ lookup: creds.lookup, auth: creds.auth, meta });
      this.#meta = meta;
      this.#vk = await unwrapKey(ub64(meta.wrapped), creds.kek, false);
      this.#entries.clear();
      this.skipped = 0;
      this.#masterFails = 0;
      this.#activeLookup = creds.lookup;
      this.#activeAuth = creds.auth;
    } catch (regErr) {
      if (regErr?.code === "ACCOUNT_EXISTS") {
        const existing = await this.api.login({ lookup: creds.lookup, auth: creds.auth });
        this.#vk = await this.#openVault(existing.meta, creds.kek, existing.entries, false);
        this.#meta = existing.meta;
        this.#masterFails = 0;
        this.#activeLookup = creds.lookup;
        this.#activeAuth = creds.auth;
        await this.#loadEntries(existing.entries);
      } else {
        throw regErr;
      }
    }

    const expectedEntries = [];
    for (let i = 0; i < legacy.items.length; i++) {
      const item = legacy.items[i];
      const detId = VALID_ID.test(String(item.id || "")) ? String(item.id) : deterministicLegacyId(legacy.vaultId, i);
      const normalized = normalizeEntry({
        ...item,
        id: detId,
        service: item.service || item.title || item.name || "Saved Password",
        password: item.password || item.pass || ""
      });
      expectedEntries.push(normalized);
    }

    const toUpload = expectedEntries.filter((e) => !this.#entries.has(e.id));
    for (let i = 0; i < toUpload.length; i += BATCH) {
      const chunk = toUpload.slice(i, i + BATCH);
      const recs = await Promise.all(
        chunk.map(async (e) => ({ id: e.id, ...(await seal(this.#vk, e, this.#aad("entry", e.id))) }))
      );
      await this.api.putEntries(recs);
      chunk.forEach((e) => this.#entries.set(e.id, e));
    }

    const stored = await this.api.fetchVault();
    const verifiedVk = await this.#openVault(stored.meta, creds.kek, stored.entries, false);
    const storedMap = new Map((stored.entries || []).map((r) => [r.id, r]));

    for (const exp of expectedEntries) {
      const rec = storedMap.get(exp.id);
      if (!rec) {
        throw new VaultError(
          "MIGRATION_INCOMPLETE",
          "Migration verification failed: not all password records were saved to the new vault. Your original vault has been preserved."
        );
      }
      let decEntry;
      try {
        decEntry = await open(verifiedVk, rec, `keyvex:${stored.meta.vaultId}:entry:${rec.id}`);
      } catch {
        throw new VaultError(
          "MIGRATION_INCOMPLETE",
          "Migration verification failed: an imported record could not be decrypted. Your original vault has been preserved."
        );
      }
      if (decEntry.service !== exp.service || decEntry.password !== exp.password) {
        throw new VaultError(
          "MIGRATION_INCOMPLETE",
          "Migration verification failed: decrypted record did not match original data. Your original vault has been preserved."
        );
      }
    }

    await this.#loadEntries(stored.entries);
    await finalizeLegacyMigration(legacy);
    this.migrated = true;
    return true;
  }

  async register(passkey, master) {
    Vault.#checkNew(passkey, master);
    const creds = await measureAsync("kdf_derivation", () => deriveCredentials(passkey, master));
    const vk = await generateVaultKey();
    const meta = await this.#header(vk, creds.kek, passkey, master, null, { kdfVersion: 1 });
    await this.api.register({ lookup: creds.lookup, auth: creds.auth, meta });
    this.#meta = meta;
    this.#vk = await unwrapKey(ub64(meta.wrapped), creds.kek, false);
    this.#entries.clear();
    this.#recordSnapshots.clear();
    this.#tombstones.clear();
    this.skipped = 0;
    this.migrated = false;
    this.#masterFails = 0;
    this.#activeLookup = creds.lookup;
    this.#activeAuth = creds.auth;
    if (!this.#account?.email) this.#accountPassword = master;
    await this.#loadSideCollections();
  }

  async signIn(passkey, master) {
    if (!isValidPasskeyShape(passkey)) throw new VaultError("BAD_CREDENTIALS", "Passkey or Master Password is incorrect.");
    const creds = await measureAsync("kdf_derivation", () => deriveCredentials(passkey, master));
    this.migrated = false;
    try {
      const { meta, entries } = await this.api.login({ lookup: creds.lookup, auth: creds.auth });
      try { this.#vk = await this.#openVault(meta, creds.kek, entries); }
      catch (err) { await this.api.logout(); throw err; }
      this.#meta = meta;
      this.#masterFails = 0;
      this.#activeLookup = creds.lookup;
      this.#activeAuth = creds.auth;
      if (!this.#account?.email) this.#accountPassword = master;
      await this.#loadEntries(entries);
      await this.#loadSideCollections();
      return;
    } catch (loginErr) {
      if (loginErr?.code === "BAD_CREDENTIALS" || (loginErr?.code === "NETWORK" && this.api.allowOffline)) {
        const migrated = await this.#migrateLegacy(passkey, master, creds);
        if (migrated) return;
      }
      throw loginErr;
    }
  }

  /**
   * Synchronizes with Cloud Firestore:
   *   - B4: Compares monotonic `meta.metaRev`. If remote `metaRev` is higher and `wrapped` changed
   *     (e.g. Passkey was changed on another device), adopts remote `meta`, locks the vault, and sets
   *     `lastSessionNotice = "Passkey was changed on another device"`.
   *   - B3: Reads & writes tombstones in `/users/{uid}/tombstones/{entryId}` and prunes `meta.deletedEntries`
   *     so `meta` stays well below 20 KB even after thousands of deletions.
   */
  async sync() {
    this.#need();
    if (this.#account?.email && isFirebaseConfigured() && Vault.#isOffline()) {
      throw new VaultError("NETWORK", "You're offline. Your changes are saved on this device and will sync automatically when you're back online.");
    }
    return this.#exclusive(() => this.#syncOnce());
  }

  async #syncOnce() {
    return measureAsync("vault_sync", async () => {
      await this.#ensureValidFirebaseToken();

      if (this.#account?.email && isFirebaseConfigured() && this.#account.uid) {
        const uid = this.#account.uid;
        const idToken = this.#account.idToken;
        if (!idToken) {
          this.#cloudSynced = false;
          throw new VaultError("NETWORK", "Cannot synchronize with Cloud Firestore without an active session token.");
        }

        const remote = await firestoreGetVault(uid, idToken);
        if (remote?.meta?.vaultId && this.#meta?.vaultId && remote.meta.vaultId !== this.#meta.vaultId) {
          throw new VaultError("BAD_VAULT", "Vault identity mismatch during cloud synchronization.");
        }

        const localMetaRev = Number(this.#meta?.metaRev) || 1;
        const remoteMetaRev = Number(remote?.meta?.metaRev) || 1;

        // B4: Check if another device changed the Passkey / rekeyed the vault (`remoteMetaRev > localMetaRev`)
        if (remote?.meta && remoteMetaRev > localMetaRev && remote.meta.wrapped !== this.#meta?.wrapped) {
          const adoptedMeta = { ...remote.meta };
          const pinLen = adoptedMeta.pinLength || this.#account.pinLength || 6;
          this.#account.meta = adoptedMeta;
          this.#account.pinLength = pinLen;
          const localProf = await getUserProfile(this.#account.email);
          if (localProf) {
            await saveUserProfile({
              ...localProf,
              email: this.#account.email,
              uid: this.#account.uid,
              pinLength: pinLen,
              meta: adoptedMeta
            });
          }
          await setActiveAccountSession(this.#account);
          this.lastSessionNotice = "Passkey was changed on another device";
          this.lock();
          throw new VaultError("PASSKEY_CHANGED_REMOTELY", "Passkey was changed on another device");
        }

        const rawTombstones = {
          ...Object.fromEntries(this.#tombstones.entries()),
          ...(this.#meta?.deletedEntries || {}),
          ...(remote?.meta?.deletedEntries || {}),
          ...(remote?.tombstones || {})
        };
        const mergedDeletedEntries = pruneTombstoneMap(rawTombstones, TOMBSTONE_CAP);
        this.#tombstones.clear();
        for (const [id, t] of Object.entries(mergedDeletedEntries)) {
          this.#tombstones.set(id, t);
        }

        const compactMetaTombstones = pruneTombstoneMap(mergedDeletedEntries, META_TOMBSTONE_CAP);
        let metaChanged = false;
        if (Object.keys(compactMetaTombstones).length !== Object.keys(this.#meta?.deletedEntries || {}).length) {
          metaChanged = true;
        }

        const winnerBase = remoteMetaRev > localMetaRev
          ? { ...this.#meta, ...remote.meta }
          : { ...(remote?.meta || this.#meta), ...this.#meta };
        this.#meta = {
          ...winnerBase,
          metaRev: Math.max(localMetaRev, remoteMetaRev),
          deletedEntries: compactMetaTombstones
        };
        delete this.#meta.recoveryWrapped;
        delete this.#meta.recoverySalt;
        delete this.#meta.emailResetWrapped;
        delete this.#meta.emailResetSalt;

        const remoteMap = new Map();
        for (const r of remote?.entries || []) {
          const ch = r.ciphertextHash || (await computeCiphertextHash(r.iv, r.data));
          remoteMap.set(r.id, { ...r, ciphertextHash: ch });
        }

        const outbox = await getCloudOutbox(uid);
        for (const op of outbox) {
          try {
            if (op.op === "meta" && op.meta) {
              const opRev = Number(op.meta.metaRev) || 1;
              if (opRev < remoteMetaRev && remote?.meta) {
                // Do not let a stale queued local meta overwrite a newer remote metaRev!
                await ackCloudOutbox(uid, op.opId);
                continue;
              }
              const mergedOpMeta = {
                ...op.meta,
                metaRev: Math.max(opRev, remoteMetaRev),
                deletedEntries: pruneTombstoneMap({
                  ...(op.meta.deletedEntries || {}),
                  ...compactMetaTombstones
                }, META_TOMBSTONE_CAP)
              };
              delete mergedOpMeta.recoveryWrapped;
              delete mergedOpMeta.recoverySalt;
              delete mergedOpMeta.emailResetWrapped;
              delete mergedOpMeta.emailResetSalt;
              const saved = await retryWithBackoff(() => firestoreSaveMeta(uid, idToken, {
                email: this.#account.email,
                name: this.#account.name,
                meta: mergedOpMeta
              }));
              this.#meta = saved?.meta || mergedOpMeta;
              await ackCloudOutbox(uid, op.opId);
              metaChanged = false;
            } else if (op.op === "delete" && op.entryId) {
              const remRec = remoteMap.get(op.entryId);
              if (remRec) {
                const modifiedRemotely =
                  (op.baseHash && remRec.ciphertextHash !== op.baseHash) ||
                  ((remRec.updatedAt || 0) > (op.deletedAt || 0));

                if (modifiedRemotely) {
                  await saveSyncConflict(uid, {
                    entryId: op.entryId,
                    reason: "delete_vs_update",
                    localRecord: null,
                    remoteRecord: remRec
                  });
                  delete mergedDeletedEntries[op.entryId];
                  delete compactMetaTombstones[op.entryId];
                  this.#tombstones.delete(op.entryId);
                  this.#meta.deletedEntries = compactMetaTombstones;
                  metaChanged = true;
                  await ackCloudOutbox(uid, op.opId);
                  continue;
                }
                await retryWithBackoff(() => firestoreDeleteEntry(uid, idToken, op.entryId));
                remoteMap.delete(op.entryId);
              }
              const tombObj = {
                deletedAt: op.deletedAt || Date.now(),
                deletedRev: op.deletedRev || (op.baseRev || 1) + 1,
                baseHash: op.baseHash || ""
              };
              await retryWithBackoff(() => firestorePutTombstone(uid, idToken, op.entryId, tombObj));
              mergedDeletedEntries[op.entryId] = tombObj;
              this.#tombstones.set(op.entryId, tombObj);
              this.#meta.deletedEntries = pruneTombstoneMap(mergedDeletedEntries, META_TOMBSTONE_CAP);
              metaChanged = true;
              await ackCloudOutbox(uid, op.opId);
            } else if (op.op === "upsert" && op.record) {
              const remTomb = mergedDeletedEntries[op.entryId];
              const remRec = remoteMap.get(op.entryId);

              if (remTomb && !remRec) {
                const modifiedAfterDelete =
                  (op.record.ciphertextHash && remTomb.baseHash && op.record.ciphertextHash !== remTomb.baseHash) &&
                  ((op.record.updatedAt || 0) > (remTomb.deletedAt || 0));

                if (!modifiedAfterDelete) {
                  await ackCloudOutbox(uid, op.opId);
                  continue;
                }
                await saveSyncConflict(uid, {
                  entryId: op.entryId,
                  reason: "delete_vs_update",
                  localRecord: op.record,
                  remoteRecord: null
                });
                delete mergedDeletedEntries[op.entryId];
                delete compactMetaTombstones[op.entryId];
                this.#tombstones.delete(op.entryId);
                await firestoreDeleteTombstone(uid, idToken, op.entryId).catch(() => {});
                this.#meta.deletedEntries = compactMetaTombstones;
                metaChanged = true;
              }

              let recordToPush = op.record;
              if (remRec && remRec.ciphertextHash !== op.record.ciphertextHash) {
                const isConflict = !op.baseHash || remRec.ciphertextHash !== op.baseHash;
                if (isConflict) {
                  await saveSyncConflict(uid, {
                    entryId: op.entryId,
                    reason: "concurrent_modification",
                    localRecord: op.record,
                    remoteRecord: remRec
                  });
                  if ((remRec.updatedAt || 0) > (op.record.updatedAt || 0)) {
                    recordToPush = remRec;
                  }
                }
              }
              if (recordToPush === op.record) {
                await retryWithBackoff(() => firestorePutEntry(uid, idToken, recordToPush));
              }
              remoteMap.set(op.entryId, recordToPush);
              await ackCloudOutbox(uid, op.opId);
            }
          } catch (err) {
            this.lastSyncError = err;
            await updateCloudOutboxAttempt(uid, op.opId, err?.code || "FIRESTORE_ERROR");
            this.#pendingOutboxCount = (await getCloudOutbox(uid)).length;
            this.#cloudSynced = false;
            throw err;
          }
        }

        if (metaChanged) {
          const saved = await retryWithBackoff(() => firestoreSaveMeta(uid, idToken, {
            email: this.#account.email,
            name: this.#account.name,
            meta: this.#meta
          })).catch(() => null);
          if (saved?.meta) this.#meta = saved.meta;
        }

        if (this.#account) {
          this.#account.meta = this.#meta;
        }

        const remainingTombstones = await getPendingTombstones(uid);
        const allTombstoneIds = new Set([...remainingTombstones.keys(), ...Object.keys(mergedDeletedEntries)]);
        const mergedRecords = [...remoteMap.values()].filter((r) => !allTombstoneIds.has(r.id));
        await this.#loadEntries(mergedRecords, {
          merge: false,
          tombstoneIds: allTombstoneIds,
          remoteTombstones: mergedDeletedEntries
        });

        if (this.#activeLookup && this.#activeAuth) {
          await this.api.mirrorVault({
            lookup: this.#activeLookup,
            auth: this.#activeAuth,
            meta: this.#meta,
            entries: mergedRecords
          });
        }

        const remainingOutbox = await getCloudOutbox(uid);
        this.#pendingOutboxCount = remainingOutbox.length;
        this.#cloudSynced = remainingOutbox.length === 0;
        if (this.#cloudSynced) this.lastSyncError = null;
        return this.list();
      }

      const { meta, entries } = await this.api.sync();
      if (meta?.vaultId && this.#meta?.vaultId && meta.vaultId !== this.#meta.vaultId) {
        throw new VaultError("BAD_VAULT", "Vault identity mismatch during synchronization.");
      }
      this.#meta = meta || this.#meta;
      await this.#loadEntries(entries, { merge: false });
      return this.list();
    });
  }

  async getConflicts() {
    this.#need();
    if (!this.#account?.uid) return [];
    const rawConflicts = await getSyncConflicts(this.#account.uid);
    const out = [];
    for (const c of rawConflicts) {
      let localDecrypted = null;
      let remoteDecrypted = null;
      if (c.localRecord?.iv && c.localRecord?.data) {
        try {
          localDecrypted = await open(this.#vk, c.localRecord, this.#aad("entry", c.entryId));
        } catch { /* unreadable candidate */ }
      }
      if (c.remoteRecord?.iv && c.remoteRecord?.data) {
        try {
          remoteDecrypted = await open(this.#vk, c.remoteRecord, this.#aad("entry", c.entryId));
        } catch { /* unreadable candidate */ }
      }
      out.push({
        ...c,
        localEntry: localDecrypted,
        remoteEntry: remoteDecrypted
      });
    }
    return out;
  }

  async resolveConflict(entryId, keep = "local", passkey = "") {
    this.#need();
    if (!this.#account?.uid) return;
    const conflicts = await this.getConflicts();
    const target = conflicts.find((c) => c.entryId === entryId);
    if (!target) return;
    const chosen = keep === "remote" ? target.remoteEntry : target.localEntry;
    await resolveSyncConflictRecord(this.#account.uid, entryId);
    if (chosen) {
      await this.save({ ...chosen, id: entryId, updatedAt: Date.now() });
    } else {
      await this.#removeInternal(entryId);
    }
  }

  lock() {
    this.#vk = null;
    this.#meta = null;
    this.#activeLookup = null;
    this.#activeAuth = null;
    this.#entries.clear();
    this.#recordSnapshots.clear();
    this.#tombstones.clear();
    this.#masterFails = 0;
    this.#passkeyResetVerifiedAt = 0;
    this.#stepUpUntil = 0;
    this.#stepUpPasskey = null;
    this.migrated = false;
    this.api.logout();
  }

  #effectiveMasterSecret(suppliedSecret) {
    if (this.#account?.email && !suppliedSecret) {
      if (this.#meta?.kdf?.version === 2 && this.#vaultEntropy) {
        return this.#vaultEntropy;
      }
      return gmailVaultSecret(this.#account.email);
    }
    return suppliedSecret;
  }

  async #authenticate(passkey, master, extractable = false) {
    this.#need();
    if (this.#account?.email && !master) {
      return this.requirePasskey(passkey, { allowCache: false, extractable });
    }
    const secret = this.#effectiveMasterSecret(master);
    if (typeof secret !== "string" || !secret || !isValidPasskeyShape(passkey, this.#meta?.pinLength)) {
      throw new VaultError("MASTER_REQUIRED", "Enter your current Passkey to continue.");
    }
    await this.#authorize(secret);
    const kdfOpts = this.#meta?.kdf?.version === 2 && this.#meta?.kdf?.salt
      ? { salt: this.#meta.kdf.salt, version: 2, iterations: this.#meta.kdf.iterations }
      : {};
    const creds = await measureAsync("kdf_derivation", () => deriveCredentials(passkey, secret, kdfOpts));
    try {
      return { creds, secret, vk: await this.#openVault(this.#meta, creds.kek, null, extractable) };
    } catch {
      this.#strike();
      throw new VaultError("BAD_CREDENTIALS", "That Passkey doesn’t match this account.", {
        attemptsLeft: Math.max(0, MASTER_MAX_FAILS - this.#masterFails)
      });
    }
  }

  #strike() {
    if (++this.#masterFails >= MASTER_MAX_FAILS) {
      this.lock();
      throw new VaultError("TOO_MANY_TRIES", "Too many wrong confirmations. Sign in again.");
    }
  }

  async #authorize(master) {
    this.#need();
    const secret = this.#effectiveMasterSecret(master);
    if (typeof secret !== "string" || !secret) throw new VaultError("MASTER_REQUIRED", "Confirmation required to continue.");
    const rec = await open(this.#vk, this.#meta.sealedMaster, this.#aad("master"));
    if (!sameBytes(await masterHash(secret, ub64(rec.salt), rec.iter), ub64(rec.hash))) {
      this.#strike();
      throw new VaultError("BAD_CREDENTIALS", "That isn’t your Master Password.", { attemptsLeft: Math.max(0, MASTER_MAX_FAILS - this.#masterFails) });
    }
    this.#masterFails = 0;
  }

  async #rekey(passkey, master, nextPasskey, nextMaster) {
    const { creds, vk } = await this.#authenticate(passkey, master, true);
    const isTwoLayer = Boolean(this.#account?.email);
    const kdfSalt = isTwoLayer ? b64(rand(32)) : null;
    const effectiveNextMaster = isTwoLayer ? (this.#vaultEntropy || b64(rand(32))) : nextMaster;
    if (isTwoLayer) this.#vaultEntropy = effectiveNextMaster;

    const next = await measureAsync("kdf_derivation", () =>
      isTwoLayer
        ? deriveCredentials(nextPasskey, effectiveNextMaster, { salt: kdfSalt, version: 2 })
        : deriveCredentials(nextPasskey, effectiveNextMaster)
    );
    const entropyEnvelopes = isTwoLayer ? await this.#buildEntropyEnvelopes(effectiveNextMaster, this.#meta.vaultId, this.#meta, nextPasskey) : {};
    const accountResetEnvelope = isTwoLayer ? await this.#buildAccountResetEnvelope(vk, this.#meta) : {};
    const meta = await this.#header(vk, next.kek, nextPasskey, effectiveNextMaster, this.#meta, {
      kdfSalt,
      kdfVersion: isTwoLayer ? 2 : 1,
      metaRev: (Number(this.#meta?.metaRev) || 1) + 1,
      ...entropyEnvelopes,
      ...accountResetEnvelope
    });

    if (this.#account?.email && isFirebaseConfigured()) {
      await this.api.mirrorVault({
        lookup: next.lookup,
        auth: next.auth,
        meta,
        entries: [...this.#recordSnapshots.values()]
      });
    } else {
      await this.api.changeCredentials({ auth: creds.auth, lookup: next.lookup, newAuth: next.auth, meta });
    }

    this.#meta = meta;
    this.#activeLookup = next.lookup;
    this.#activeAuth = next.auth;
    this.#stepUpPasskey = String(nextPasskey);
    if (!isTwoLayer) this.#accountPassword = effectiveNextMaster;
    if (this.#account?.email) {
      const pinLength = resolvePinLengthTag(nextPasskey);
      this.#account.pinLength = pinLength;
      this.#account.meta = meta;
      const wrappedDeviceResetKey = await this.#wrapDeviceResetKey(vk, this.#account.uid || this.#account.email);
      const localProf = await getUserProfile(this.#account.email);
      await saveUserProfile({
        ...localProf,
        email: this.#account.email,
        pinLength,
        hasVault: true,
        vaultLookup: next.lookup,
        deviceVaultEntropy: this.#vaultEntropy,
        wrappedDeviceResetKey: wrappedDeviceResetKey || localProf?.wrappedDeviceResetKey || undefined,
        meta
      });
      await setActiveAccountSession(this.#account);

      if (this.#canSyncToCloud()) {
        await enqueueCloudOutbox(this.#account.uid, { op: "meta", meta });
        await this.#flushCloudOutbox();
      }
    }
  }

  /**
   * PART 4: `changePasskey` accepts `(currentPasskey, newPasskey)` or `(currentPasskey, master, newPasskey)`.
   */
  async changePasskey(passkey, masterOrNewPasskey, maybeNewPasskey) {
    const isTwoArg = maybeNewPasskey === undefined;
    const master = isTwoArg ? "" : masterOrNewPasskey;
    const newPasskey = isTwoArg ? masterOrNewPasskey : maybeNewPasskey;

    if (this.#account?.email && !passkey && this.passkeyResetVerified) {
      return this.resetPasskeyAfterVerification(newPasskey);
    }

    if (this.#account?.email) {
      await this.requirePasskey(passkey, { allowCache: false });
    } else {
      await this.#authenticate(passkey, master, false);
    }

    const p = checkPin(newPasskey);
    if (!p.ok) throw new VaultError("WEAK_PIN", p.hint);
    const secret = this.#effectiveMasterSecret(master);
    if (!this.#account?.email && String(secret).replace(/\s/g, "").includes(String(newPasskey))) {
      throw new VaultError("WEAK_MASTER", "Your Master Password must not contain the new Passkey.");
    }
    await this.#rekey(passkey, master, newPasskey, secret);
  }

  async changeMasterPassword(passkey, masterOrNewMaster, maybeNewMaster) {
    const isTwoArg = maybeNewMaster === undefined;
    const master = isTwoArg ? (this.#accountPassword || "") : masterOrNewMaster;
    const newMaster = isTwoArg ? masterOrNewMaster : maybeNewMaster;
    if (this.#account?.email || isTwoArg) {
      await this.requirePasskey(passkey, { allowCache: false });
      const m = checkMasterPassword(newMaster, passkey);
      if (!m.ok) throw new VaultError("WEAK_MASTER", m.hint);
      if (this.#account?.email) {
        await this.setAccountPassword(passkey, newMaster, master || null);
        return;
      }
    } else {
      await this.#authenticate(passkey, master, false);
      const m = checkMasterPassword(newMaster, passkey);
      if (!m.ok) throw new VaultError("WEAK_MASTER", m.hint);
    }
    await this.#rekey(passkey, master, passkey, newMaster);
  }

  async deleteAccount(passkey, master = "", { accountPassword = null, googleVerified = false, onProgress = null } = {}) {
    return measureAsync("account_deletion", async () => {
      let creds;
      if (this.#account?.email && !passkey && (googleVerified || this.passkeyResetVerified)) {
        this.#passkeyResetVerifiedAt = 0;
        creds = { lookup: this.#activeLookup || null, auth: this.#activeAuth || null };
      } else {
        ({ creds } = this.#account?.email
          ? await this.requirePasskey(passkey, { allowCache: false })
          : await this.#authenticate(passkey, master));
      }

      if (!this.#account?.email) {
        await this.api.deleteAccount(creds.auth);
        this.#vk = null;
        this.#entries.clear();
        this.#recordSnapshots.clear();
        this.#tombstones.clear();
        this.#meta = null;
        return { state: "completed", deleted: true };
      }

      const { email, uid } = this.#account;
      const existingJob = await getDeletionJob(uid);
      const jobId = existingJob?.jobId || `del_${uid}_${Date.now()}`;
      const history = existingJob?.history || [];

      const updateStage = async (state, extra = {}) => {
        history.push({ state, at: Date.now() });
        return saveDeletionJob({
          jobId,
          uid,
          email,
          state,
          history,
          attempts: (existingJob?.attempts || 0) + 1,
          lastError: null,
          ...extra
        });
      };

      await updateStage("requested");
      if (isFirebaseConfigured() && (accountPassword || this.#accountPassword)) {
        try {
          const reauth = await firebaseSignIn({
            email,
            password: accountPassword || this.#accountPassword
          });
          if (reauth?.idToken) {
            this.#account.idToken = reauth.idToken;
            this.#account.refreshToken = reauth.refreshToken || this.#account.refreshToken;
            this.#account.tokenExpiresAt = reauth.tokenExpiresAt;
          }
        } catch {
          /* continue with #ensureValidFirebaseToken */
        }
      }
      await this.#ensureValidFirebaseToken();
      const idToken = this.#account.idToken;
      await updateStage("reauthenticated", { lookup: creds.lookup });

      await clearCloudOutbox(uid);
      this.#pendingOutboxCount = 0;

      return this.#executeDeletionStages({
        jobId,
        uid,
        email,
        idToken,
        authProof: creds.auth,
        lookup: creds.lookup,
        updateStage,
        onProgress
      });
    });
  }

  async resumeAccountDeletion(uidOrEmail, { idToken = null, authProof = null, onProgress = null } = {}) {
    return measureAsync("account_deletion", async () => {
      const prof = (await getUserProfileByUid(uidOrEmail)) || (await getUserProfile(uidOrEmail));
      const uid = prof?.uid || this.#account?.uid || uidOrEmail;
      const email = prof?.email || this.#account?.email || "";
      const job = await getDeletionJob(uid);
      if (!job) {
        throw new VaultError("NOT_FOUND", "No pending account deletion job found.");
      }
      if (job.state === "completed") {
        return { state: "completed", deleted: true, jobId: job.jobId };
      }

      const history = Array.isArray(job.history) ? [...job.history] : [];
      const updateStage = async (state, extra = {}) => {
        history.push({ state, at: Date.now() });
        return saveDeletionJob({
          ...job,
          state,
          history,
          attempts: (job.attempts || 0) + 1,
          lastError: null,
          ...extra
        });
      };

      const token = idToken || this.#account?.idToken || null;
      return this.#executeDeletionStages({
        jobId: job.jobId,
        uid,
        email,
        idToken: token,
        authProof,
        lookup: job.lookup || prof?.vaultLookup || null,
        updateStage,
        onProgress
      });
    });
  }

  async getDeletionJobStatus(uidOrEmail = this.#account?.uid || this.#account?.email) {
    if (!uidOrEmail) return null;
    const prof = (await getUserProfileByUid(uidOrEmail)) || (await getUserProfile(uidOrEmail));
    const uid = prof?.uid || this.#account?.uid || uidOrEmail;
    return getDeletionJob(uid);
  }

  async #executeDeletionStages({ jobId, uid, email, idToken, authProof, lookup, updateStage, onProgress }) {
    try {
      if (isFirebaseConfigured()) {
        if (!idToken) {
          throw new VaultError("UNAUTHENTICATED", "Valid Firebase session token is required to delete cloud vault.");
        }
        await firestoreDeleteVault(uid, idToken, {
          onStage: async (st) => { await updateStage(st); },
          onProgress
        });
      }

      await updateStage("deleting_legacy_backend");
      if (authProof) {
        try {
          await this.api.deleteAccount(authProof);
        } catch (legacyErr) {
          if (legacyErr?.status !== 401 && legacyErr?.status !== 404 && !isFirebaseConfigured()) {
            throw legacyErr;
          }
        }
      }

      if (isFirebaseConfigured()) {
        await updateStage("deleting_auth_identity");
        try {
          await firebaseDeleteAuthAccount(idToken);
        } catch (authDelErr) {
          if (authDelErr?.code === "CREDENTIAL_TOO_OLD_LOGIN_AGAIN" && this.#account?.provider === "google.com") {
            await this.#ensureValidFirebaseToken(true).catch(() => {});
            if (this.#account?.idToken && this.#account.idToken !== idToken) {
              await firebaseDeleteAuthAccount(this.#account.idToken).catch(() => {});
            }
          } else {
            throw authDelErr;
          }
        }
      }

      await clearCloudOutbox(uid);
      if (lookup) {
        await this.api.getVaultByLookup(lookup).catch(() => {});
      }
      await deleteUserProfile(email, uid);
      setSyncSessionHint(null);
      await setActiveAccountSession(null);
      const completedJob = await updateStage("completed");

      this.#vk = null;
      this.#entries.clear();
      this.#recordSnapshots.clear();
      this.#tombstones.clear();
      this.#meta = null;
      this.#account = null;
      this.#accountPassword = null;
      this.#vaultEntropy = null;
      this.#totpSecretInMemory = null;
      this.#totpBackupHashes = [];
      this.#activeLookup = null;
      this.#activeAuth = null;
      emitFirebaseAuthState(null);

      return { state: "completed", deleted: true, jobId: completedJob.jobId };
    } catch (err) {
      const needsReauth = err?.code === "CREDENTIAL_TOO_OLD_LOGIN_AGAIN" || err?.code === "TOKEN_EXPIRED" || err?.code === "UNAUTHENTICATED";
      const failedState = needsReauth ? "failed_manual_action" : "failed_retryable";
      const savedJob = await updateStage(failedState, {
        lastError: { code: err?.code || "DELETION_ERROR", message: err?.message || "Deletion step failed" }
      });
      this.lock();
      throw new VaultError(
        "DELETION_INCOMPLETE",
        needsReauth
          ? "Account deletion is paused because your login session needs reauthentication. Please sign in again to finish deleting your account."
          : `Account deletion is pending completion (${err?.message || "network or service error"}). Please retry to finish removing remaining records.`,
        { deletionJob: savedJob, cause: err }
      );
    }
  }

  /* ---------- entries ---------- */
  list() { return [...this.#entries.values()].sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0)); }
  get(id) { return this.#entries.get(id) || null; }

  async save(input) {
    this.#need();
    const prev = input.id ? this.#entries.get(input.id) : undefined;
    const prevSnap = input.id ? this.#recordSnapshots.get(input.id) : undefined;
    const entry = normalizeEntry({ ...input, updatedAt: Date.now() }, prev);
    const sealed = await seal(this.#vk, entry, this.#aad("entry", entry.id));
    const ciphertextHash = await computeCiphertextHash(sealed.iv, sealed.data);
    const fullRec = {
      id: entry.id,
      iv: sealed.iv,
      data: sealed.data,
      updatedAt: entry.updatedAt,
      createdAt: entry.createdAt,
      rev: entry.rev,
      ciphertextHash
    };

    this.#tombstones.delete(entry.id);
    if (this.#meta?.deletedEntries?.[entry.id]) {
      const nextDel = { ...this.#meta.deletedEntries };
      delete nextDel[entry.id];
      this.#meta = { ...this.#meta, deletedEntries: nextDel };
    }

    if (this.#account?.email && isFirebaseConfigured() && this.#account.uid) {
      await enqueueCloudOutbox(this.#account.uid, {
        op: "upsert",
        entryId: entry.id,
        record: fullRec,
        baseRev: prevSnap?.rev || 0,
        baseHash: prevSnap?.ciphertextHash || ""
      });
      this.#pendingOutboxCount = (await getCloudOutbox(this.#account.uid)).length;
      this.#cloudSynced = false;

      this.#entries.set(entry.id, entry);
      this.#recordSnapshots.set(entry.id, fullRec);

      // B10: Write only the changed record to local IndexedDB cache without re-running PBKDF2
      if (this.#activeLookup) {
        await this.api.upsertCachedEntry(this.#activeLookup, fullRec, this.#meta);
      }

      await this.#flushSoon();
      return entry;
    }

    await this.api.putEntry({ id: entry.id, iv: sealed.iv, data: sealed.data });
    this.#entries.set(entry.id, entry);
    this.#recordSnapshots.set(entry.id, fullRec);
    return entry;
  }

  /**
   * PART 4, B3 & B10: `remove(passkey, id)` or `remove(id, passkey)`:
   *   - Enforces `requirePasskey` (using the 60s step-up cache so burst deletes do not re-prompt repeatedly).
   *   - Stores tombstones in `/users/{uid}/tombstones/{entryId}` and caps `meta.deletedEntries` so `meta` stays < 20 KB.
   *   - Deletes only the changed record from local IndexedDB without re-mirroring the entire vault.
   */
  async remove(firstArg, secondArg) {
    this.#need();
    let passkey = "";
    let id = "";

    if (secondArg !== undefined) {
      if (this.#entries.has(String(firstArg)) && !this.#entries.has(String(secondArg))) {
        id = String(firstArg);
        passkey = String(secondArg);
      } else {
        passkey = String(firstArg);
        id = String(secondArg);
      }
      await this.requirePasskey(passkey, { allowCache: true });
    } else {
      const candidate = String(firstArg ?? "");
      if (this.#entries.has(candidate) || (VALID_ID.test(candidate) && !/^\d{4,8}$/.test(candidate))) {
        id = candidate;
        if (this.#account?.email) {
          await this.requirePasskey("", { allowCache: true });
        }
      } else {
        await this.requirePasskey(candidate, { allowCache: false });
      }
    }

    return this.#removeInternal(id);
  }

  async #removeInternal(id) {
    const prevSnap = this.#recordSnapshots.get(id);
    const deletedAt = Date.now();
    const deletedRev = (prevSnap?.rev || 1) + 1;
    const baseHash = prevSnap?.ciphertextHash || "";
    const tombObj = { deletedAt, deletedRev, baseHash };

    this.#tombstones.set(id, tombObj);
    if (this.#tombstones.size > TOMBSTONE_CAP) {
      const pruned = pruneTombstoneMap(Object.fromEntries(this.#tombstones.entries()), TOMBSTONE_CAP, deletedAt);
      this.#tombstones = new Map(Object.entries(pruned));
    }

    if (this.#meta) {
      const nextDeletedEntries = pruneTombstoneMap({
        ...(this.#meta.deletedEntries || {}),
        [id]: tombObj
      }, META_TOMBSTONE_CAP, deletedAt);
      this.#meta = {
        ...this.#meta,
        deletedEntries: nextDeletedEntries
      };
      if (this.#account) this.#account.meta = this.#meta;
    }

    if (this.#account?.email && isFirebaseConfigured() && this.#account.uid) {
      await enqueueCloudOutbox(this.#account.uid, {
        op: "delete",
        entryId: id,
        baseRev: prevSnap?.rev || 1,
        baseHash,
        deletedRev,
        deletedAt
      });
      this.#pendingOutboxCount = (await getCloudOutbox(this.#account.uid)).length;
      this.#cloudSynced = false;

      this.#entries.delete(id);
      this.#recordSnapshots.delete(id);

      // B10: Delete only the single entry in local IndexedDB cache without re-running PBKDF2
      if (this.#activeLookup) {
        await this.api.deleteCachedEntry(this.#activeLookup, id, this.#meta);
      }

      await this.#flushSoon();
      return;
    }

    await this.api.deleteEntry(id);
    this.#entries.delete(id);
    this.#recordSnapshots.delete(id);
  }

  /**
   * PART 4: `importEntries` supports both `(passkey, items)` and `(items, passkeyOrMaster)` and verifies via `requirePasskey` / `#authorize`.
   */
  async importEntries(firstArg, secondArg, options = {}) {
    this.#need();
    let items = [];
    let secretOrPasskey = "";
    if (Array.isArray(firstArg)) {
      items = firstArg;
      secretOrPasskey = secondArg;
    } else {
      secretOrPasskey = firstArg;
      items = Array.isArray(secondArg) ? secondArg : [];
    }

    if (!options?.skipAuth) {
      if (this.#account?.email) {
        await this.requirePasskey(secretOrPasskey, { allowCache: false });
      } else {
        await this.#authorize(secretOrPasskey);
      }
    }

    const seenKeys = new Set(this.list().map(dedupeKey));
    const seenIds = new Set(this.#entries.keys());
    const fresh = [];

    for (const item of items || []) {
      if (!item || typeof item !== "object") continue;
      if (item.id && seenIds.has(String(item.id))) continue;
      const key = dedupeKey(item);
      if (seenKeys.has(key)) continue;
      try {
        const desiredId = VALID_ID.test(String(item.id || "")) && !seenIds.has(String(item.id)) ? String(item.id) : undefined;
        const normalized = normalizeEntry({ ...item, id: desiredId, ...(options?.forceImportedCategory ? { category: "Imported", importedBatch: true } : {}) });
        fresh.push(normalized);
        seenKeys.add(key);
        seenIds.add(normalized.id);
      } catch { /* skip invalid entry missing service or password */ }
    }

    await this.#ensureValidFirebaseToken();
    for (let i = 0; i < fresh.length; i += BATCH) {
      const chunk = fresh.slice(i, i + BATCH);
      const recs = await Promise.all(
        chunk.map(async (e) => {
          const sealed = await seal(this.#vk, e, this.#aad("entry", e.id));
          const ciphertextHash = await computeCiphertextHash(sealed.iv, sealed.data);
          return { id: e.id, ...sealed, updatedAt: e.updatedAt, createdAt: e.createdAt, rev: e.rev || 1, ciphertextHash };
        })
      );

      if (this.#account?.email && isFirebaseConfigured() && this.#account.uid) {
        if (this.#canSyncToCloud() && this.#account.idToken) {
          try {
            await firestoreBatchPutEntries(this.#account.uid, this.#account.idToken, recs);
          } catch (batchErr) {
            this.lastSyncError = batchErr;
            this.#cloudSynced = false;
            for (const r of recs) {
              await enqueueCloudOutbox(this.#account.uid, {
                op: "upsert",
                entryId: r.id,
                record: r,
                baseRev: 0,
                baseHash: ""
              });
            }
          }
        } else {
          this.#cloudSynced = false;
          for (const r of recs) {
            await enqueueCloudOutbox(this.#account.uid, {
              op: "upsert",
              entryId: r.id,
              record: r,
              baseRev: 0,
              baseHash: ""
            });
          }
        }
      } else {
        await this.api.putEntries(recs.map(({ id, iv, data }) => ({ id, iv, data })));
      }

      chunk.forEach((e, idx) => {
        this.#entries.set(e.id, e);
        this.#recordSnapshots.set(e.id, recs[idx]);
      });
    }

    if (this.#account?.email && isFirebaseConfigured() && this.#account.uid) {
      if (this.#activeLookup && this.#activeAuth) {
        await this.api.mirrorVault({
          lookup: this.#activeLookup,
          auth: this.#activeAuth,
          meta: this.#meta,
          entries: [...this.#recordSnapshots.values()]
        });
      }
      await this.#flushCloudOutbox();
    }

    return fresh.length;
  }

  /**
   * PART 4, B17 & B18: `exportBackup(passkey)`:
   *   - Requires Passkey verification (`requirePasskey(passkey)`) when `passkey` is passed or when in 2-layer account mode.
   *   - Strips weak account-identity envelopes (`wrappedEntropyAccount`, `accountResetWrapped`, `emailResetWrapped`) from exported `meta`.
   *   - Includes `appVersion: "2.4.0"`, `entryCount`, and `entriesSha256` integrity metadata.
   */
  async readBackupAuto(text) {
    try {
      return await readBackup(text, {
        autoRestore: true,
        email: this.#account?.email || ""
      });
    } catch (firstErr) {
      if (firstErr?.code !== "BAD_CREDENTIALS") throw firstErr;
      // Fallback for backups exported before backupPortableWrapped was added:
      // Try decrypting with the currently unlocked #vk, or current account credentials
      const doc = parseBackup(text);
      const bMeta = doc.meta;
      const bEntries = doc.entries || [];
      const tryDecryptWithVk = async (candidateVk) => {
        if (!candidateVk) return null;
        const ver = await open(candidateVk, bMeta.verifier, `keyvex:${bMeta.vaultId}:verify:`);
        if (ver?.ok !== true) return null;
        return Promise.all(
          bEntries.map(async (r) => {
            const d = await open(candidateVk, r, `keyvex:${bMeta.vaultId}:entry:${r.id}`);
            return { ...d, id: r.id };
          })
        );
      };
      try {
        const fromCurrentVk = await tryDecryptWithVk(this.#vk);
        if (fromCurrentVk) return fromCurrentVk;
      } catch { /* try next */ }
      if (this.#stepUpPasskey) {
        try {
          return await readBackup(text, {
            passkey: this.#stepUpPasskey,
            master: this.#accountPassword || "",
            email: this.#account?.email || ""
          });
        } catch { /* try next */ }
      }
      throw firstErr;
    }
  }

  async exportBackup(passkey) {
    this.#need();
    let verifiedVk = null;
    if (passkey !== undefined || this.#account?.email) {
      const res = await this.requirePasskey(passkey, { allowCache: false, extractable: true });
      verifiedVk = res.vk;
    }
    let metaToExport = this.#meta ? { ...this.#meta } : null;
    if (metaToExport && verifiedVk && !metaToExport.backupPortableWrapped) {
      try {
        const pSalt = rand(16);
        const pKek = await deriveAccountResetKek(PORTABLE_BACKUP_UID, PORTABLE_BACKUP_EMAIL, pSalt);
        metaToExport.backupPortableSalt = b64(pSalt);
        metaToExport.backupPortableWrapped = b64(await wrapKey(verifiedVk, pKek));
      } catch { /* ignore */ }
    }
    let entriesToExport = [];

    if (this.#account?.email && isFirebaseConfigured()) {
      entriesToExport = [...this.#recordSnapshots.values()].map(({ id, iv, data }) => ({ id, iv, data }));
    } else {
      const fetched = await this.api.fetchVault();
      metaToExport = fetched.meta;
      entriesToExport = fetched.entries;
    }

    const sanitizedMeta = stripWeakBackupEnvelopes(metaToExport);
    const entriesSha256 = await computeBackupEntriesSha256(entriesToExport);

    return JSON.stringify({
      app: "keyvex",
      appVersion: "1.0.0",
      kind: "encrypted-vault-backup",
      v: FORMAT,
      exportedAt: new Date().toISOString(),
      entryCount: entriesToExport.length,
      entriesSha256,
      meta: sanitizedMeta,
      entries: entriesToExport
    });
  }

  /* ==========================================================================
   * Encrypted Generator History, Separate External Imports, Bulk Delete & Sessions
   * ========================================================================== */

  #ownerStorageKey() {
    return String(this.#account?.uid || this.#account?.email || this.#activeLookup || this.#meta?.vaultId || "default").trim();
  }

  async #loadSideCollections() {
    if (!this.#vk || !this.#meta?.vaultId) return;
    const ownerKey = this.#ownerStorageKey();

    // 1. Load encrypted Generator History
    this.#generatorHistory = [];
    const rawGen = await getEncryptedGeneratorHistory(ownerKey).catch(() => []);
    for (const rec of rawGen) {
      if (!rec?.id || !rec?.iv || !rec?.data) continue;
      try {
        const opened = await open(this.#vk, rec, this.#aad("gen_history", rec.id));
        if (opened && typeof opened.password === "string") {
          this.#generatorHistory.push({
            id: String(opened.id || rec.id),
            password: opened.password,
            length: Number(opened.length) || opened.password.length,
            createdAt: Number(opened.createdAt || rec.createdAt) || Date.now()
          });
        }
      } catch { /* ignore unreadable record */ }
    }
    this.#generatorHistory.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    // 2. Load separate encrypted External Imports
    this.#externalEntries.clear();
    const rawExt = await getEncryptedExternalImports(ownerKey).catch(() => []);
    for (const rec of rawExt) {
      if (!rec?.id || !rec?.iv || !rec?.data) continue;
      try {
        const opened = await open(this.#vk, rec, this.#aad("external_entry", rec.id));
        const clean = sanitizeLoadedEntry(opened, rec.id, rec);
        this.#externalEntries.set(clean.id, {
          ...clean,
          source: String(opened?.source || "external"),
          importedAt: Number(opened?.importedAt || clean.createdAt) || Date.now()
        });
      } catch { /* ignore unreadable record */ }
    }
  }

  async #persistGeneratorHistory() {
    if (!this.#vk || !this.#meta?.vaultId) return;
    const ownerKey = this.#ownerStorageKey();
    const records = await Promise.all(
      this.#generatorHistory.map(async (item) => {
        const sealed = await seal(this.#vk, item, this.#aad("gen_history", item.id));
        return { id: item.id, ...sealed, createdAt: item.createdAt };
      })
    );
    await saveEncryptedGeneratorHistory(ownerKey, records);
  }

  async #persistExternalImports() {
    if (!this.#vk || !this.#meta?.vaultId) return;
    const ownerKey = this.#ownerStorageKey();
    const records = await Promise.all(
      [...this.#externalEntries.values()].map(async (item) => {
        const sealed = await seal(this.#vk, item, this.#aad("external_entry", item.id));
        return { id: item.id, ...sealed, updatedAt: item.updatedAt, createdAt: item.createdAt };
      })
    );
    await saveEncryptedExternalImports(ownerKey, records);
  }

  /**
   * Records a generated password inside the encrypted generator history (AES-256-GCM sealed with the Vault Key).
   * Never logs or persists plaintext passwords.
   */
  async addGeneratorHistory(password) {
    this.#need();
    const cleanPw = String(password ?? "");
    if (!cleanPw) return null;
    // Avoid recording identical consecutive duplicate at top of history
    if (this.#generatorHistory[0]?.password === cleanPw) {
      return this.#generatorHistory[0];
    }
    const item = {
      id: `gh_${b64(rand(9))}`,
      password: cleanPw,
      length: cleanPw.length,
      createdAt: Date.now()
    };
    this.#generatorHistory.unshift(item);
    if (this.#generatorHistory.length > 50) {
      this.#generatorHistory.length = 50;
    }
    await this.#persistGeneratorHistory();
    return { ...item };
  }

  listGeneratorHistory() {
    if (!this.#vk) return [];
    return this.#generatorHistory.map((item) => ({ ...item }));
  }

  async removeGeneratorHistoryItem(id) {
    this.#need();
    const targetId = String(id || "");
    const before = this.#generatorHistory.length;
    this.#generatorHistory = this.#generatorHistory.filter((item) => item.id !== targetId);
    if (this.#generatorHistory.length !== before) {
      await this.#persistGeneratorHistory();
    }
    return { ok: true, remaining: this.#generatorHistory.length };
  }

  async clearGeneratorHistory(passkey) {
    this.#need();
    if (passkey !== undefined && String(passkey).trim() !== "") {
      await this.requirePasskey(passkey);
    }
    this.#generatorHistory = [];
    await this.#persistGeneratorHistory();
    return { ok: true, remaining: 0 };
  }

  /**
   * Imports external password-manager entries (e.g. Chrome, Bitwarden, 1Password, LastPass CSV)
   * into a dedicated encrypted collection kept separate from the main KeyVEX vault.
   */
  async importExternalEntries(firstArg, secondArg, { source = "csv" } = {}) {
    this.#need();
    let items = [];
    let secretOrPasskey = "";
    if (Array.isArray(firstArg)) {
      items = firstArg;
      secretOrPasskey = secondArg;
    } else {
      secretOrPasskey = firstArg;
      items = Array.isArray(secondArg) ? secondArg : [];
    }

    if (this.#account?.email) {
      await this.requirePasskey(secretOrPasskey, { allowCache: false });
    } else {
      await this.#authorize(secretOrPasskey);
    }

    const seenKeys = new Set([...this.#externalEntries.values()].map(dedupeKey));
    const seenIds = new Set(this.#externalEntries.keys());
    const now = Date.now();
    let added = 0;

    for (const item of items || []) {
      if (!item || typeof item !== "object") continue;
      if (item.id && seenIds.has(String(item.id))) continue;
      const key = dedupeKey(item);
      if (seenKeys.has(key)) continue;
      try {
        const desiredId = VALID_ID.test(String(item.id || "")) && !seenIds.has(String(item.id)) ? String(item.id) : undefined;
        const normalized = normalizeEntry({ ...item, id: desiredId });
        const extRecord = {
          ...normalized,
          source: String(source || "csv"),
          importedAt: now
        };
        this.#externalEntries.set(extRecord.id, extRecord);
        seenKeys.add(key);
        seenIds.add(extRecord.id);
        added++;
      } catch { /* skip invalid row */ }
    }

    await this.#persistExternalImports();
    return added;
  }

  listExternalImports() {
    if (!this.#vk) return [];
    return [...this.#externalEntries.values()].sort((a, b) => (b.importedAt || b.updatedAt || 0) - (a.importedAt || a.updatedAt || 0));
  }

  getExternalImport(id) {
    if (!this.#vk) return null;
    return this.#externalEntries.get(String(id || "")) || null;
  }

  async removeExternalImport(passkey, id) {
    this.#need();
    await this.requirePasskey(passkey, { allowCache: true });
    this.#externalEntries.delete(String(id || ""));
    await this.#persistExternalImports();
    return { ok: true };
  }

  async moveExternalImportToVault(passkey, id) {
    this.#need();
    await this.requirePasskey(passkey, { allowCache: true });
    const ext = this.#externalEntries.get(String(id || ""));
    if (!ext) throw new VaultError("NOT_FOUND", "External import entry not found.");
    const saved = await this.save({
      service: ext.service,
      username: ext.username,
      password: ext.password,
      website: ext.website,
      category: ext.category,
      notes: ext.notes,
      favorite: ext.favorite
    });
    this.#externalEntries.delete(ext.id);
    await this.#persistExternalImports();
    return saved;
  }

  async clearExternalImports(passkey) {
    this.#need();
    await this.requirePasskey(passkey);
    this.#externalEntries.clear();
    await this.#persistExternalImports();
    return { ok: true };
  }

  /**
   * Bulk deletion of multiple password entries, protected by `requirePasskey(passkey)`.
   */
  async removeMany(passkey, ids = []) {
    this.#need();
    await this.requirePasskey(passkey, { allowCache: false });
    const list = Array.isArray(ids) ? ids : [];
    let removedCount = 0;
    for (const rawId of list) {
      const id = String(rawId || "");
      if (!id) continue;
      if (this.#entries.has(id)) {
        await this.#removeInternal(id);
        removedCount++;
      }
    }
    return { ok: true, removedCount };
  }

  /**
   * Lists active session info and revokes all other sessions (`revokeOtherSessions`).
   */
  async listSessions() {
    this.#need();
    const srvSessions = await this.api.getSessions().catch(() => ({ activeSessions: 1 }));
    return {
      activeSessions: srvSessions?.activeSessions || 1,
      sessionRev: Number(this.#meta?.sessionRev) || 1,
      email: this.#account?.email || null,
      provider: this.#account?.provider || "local"
    };
  }

  async revokeOtherSessions(passkey, master = "") {
    this.#need();
    const { creds } = this.#account?.email
      ? await this.requirePasskey(passkey, { allowCache: false })
      : await this.#authenticate(passkey, master, false);

    const apiRes = await this.api.revokeOtherSessions(creds?.auth).catch(() => ({ ok: true, revoked: 0 }));

    if (this.#meta) {
      const nextSessionRev = (Number(this.#meta.sessionRev) || 1) + 1;
      this.#meta = {
        ...this.#meta,
        sessionRev: nextSessionRev,
        metaRev: (Number(this.#meta.metaRev) || 1) + 1
      };
      if (this.#account) {
        this.#account.meta = this.#meta;
        this.#account.sessionRev = nextSessionRev;
        const localProf = await getUserProfile(this.#account.email);
        if (localProf) {
          await saveUserProfile({ ...localProf, meta: this.#meta });
        }
        await setActiveAccountSession(this.#account);
        if (this.#canSyncToCloud()) {
          await enqueueCloudOutbox(this.#account.uid, { op: "meta", meta: this.#meta });
          await this.#flushCloudOutbox().catch(() => {});
        }
      }
    }

    return {
      ok: true,
      revoked: apiRes?.revoked ?? 0,
      sessionRev: Number(this.#meta?.sessionRev) || 1
    };
  }
}
