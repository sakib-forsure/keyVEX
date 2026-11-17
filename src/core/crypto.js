/**
 * Cryptographic primitives (WebCrypto only — no third-party crypto).
 *
 *   Passkey + Vault Secret ──PBKDF2-SHA256 (600k, per-vault random salt in v2)──▶ root
 *                                                                 ├──▶ lookup   (public account id)
 *                                                                 ├──▶ auth     (proof sent to the server; it stores only a hash)
 *                                                                 └──▶ KEK      (never leaves the browser) ──AES-KW──▶ wraps vault key
 *   every entry = AES-256-GCM(vault key, random 96-bit IV, AAD = vault id + entry id)
 *
 * The vault key is random, so changing a credential only re-wraps it; entries are not re-encrypted.
 * Encryption keys are NEVER derived from public UID, email address, or identity tokens.
 */
import { enc, dec, rand, b64, ub64 } from "./bytes.js";

export const KDF_ITERATIONS = 600_000; // OWASP guidance for PBKDF2-HMAC-SHA256
export const CURRENT_KDF_VERSION = 2;
let iterations = KDF_ITERATIONS;
const subtle = () => crypto.subtle;

/** Test runs only: a cheap KDF keeps the suite fast. Refuses to run outside the test environment. */
export function useFastKdfForTests() {
  const isTest = import.meta.env?.MODE === "test" || (typeof process !== "undefined" && process.env?.NODE_ENV === "test");
  if (!isTest) throw new Error("useFastKdfForTests is for tests only");
  iterations = 1_000;
}
export const kdfIterations = () => iterations;

const normalize = (s) => String(s).normalize("NFKC");

/** Passkey and Master Password joined with a NUL separator so the pair is unambiguous. */
const joinSecrets = (passkey, master) => enc.encode(`${String(passkey)}\u0000${normalize(master)}`);

/**
 * Derives `{ lookup, auth, kek }` using PBKDF2-HMAC-SHA256 (600,000 iterations) + HKDF-SHA256.
 *   - v1 (`options.salt` omitted): uses legacy static salt `"keyvex:v6:root"` for backward compatibility.
 *   - v2 (`options.salt` provided): uses a unique per-vault 256-bit random salt (`kdf.salt`) so no two vaults
 *     share PBKDF2 salt material.
 */
export async function deriveCredentials(passkey, master, options = {}) {
  const saltBytes = options?.salt
    ? (options.salt instanceof Uint8Array ? options.salt : ub64(String(options.salt)))
    : enc.encode("keyvex:v6:root");
  const rounds = Number(options?.iterations) || iterations;
  const base = await subtle().importKey("raw", joinSecrets(passkey, master), "PBKDF2", false, ["deriveBits"]);
  const rootBits = await subtle().deriveBits({ name: "PBKDF2", salt: saltBytes, iterations: rounds, hash: "SHA-256" }, base, 256);
  const hk = await subtle().importKey("raw", rootBits, "HKDF", false, ["deriveBits", "deriveKey"]);
  const info = (s) => ({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(s) });
  const lookup = b64(new Uint8Array(await subtle().deriveBits(info("keyvex:v6:lookup"), hk, 256)));
  const auth = b64(new Uint8Array(await subtle().deriveBits(info("keyvex:v6:auth"), hk, 256)));
  const kek = await subtle().deriveKey(info("keyvex:v6:kek"), hk, { name: "AES-KW", length: 256 }, false, ["wrapKey", "unwrapKey"]);
  return { lookup, auth, kek };
}

/**
 * Derives an AES-256-GCM envelope key for wrapping/unwrapping the high-entropy 256-bit per-vault secret
 * (`vaultEntropy`) or authenticated secret envelopes using a secret Passkey or Account Password.
 */
export async function deriveEnvelopeGcmKey(secretMaterial, saltInput, infoLabel = "keyvex:v6:entropy-envelope", rounds = iterations) {
  const saltBytes = saltInput instanceof Uint8Array
    ? saltInput
    : (typeof saltInput === "string" ? ub64(saltInput) : enc.encode("keyvex:v6:envelope-salt"));
  const base = await subtle().importKey("raw", enc.encode(normalize(secretMaterial)), "PBKDF2", false, ["deriveBits"]);
  const rootBits = await subtle().deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: Number(rounds) || iterations, hash: "SHA-256" },
    base,
    256
  );
  const hk = await subtle().importKey("raw", rootBits, "HKDF", false, ["deriveKey"]);
  return subtle().deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(infoLabel) },
    hk,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Derives a 256-bit AES-KW KEK from the user's secret Account Password (`derivePasswordResetKek`).
 * Never derives keys from public UID, email address, or OAuth identity tokens.
 */
export async function derivePasswordResetKek(accountPassword, saltInput, rounds = iterations) {
  const cleanPw = normalize(String(accountPassword || ""));
  if (!cleanPw) throw new Error("A non-empty Account Password is required to derive the password reset KEK.");
  const saltBytes = saltInput instanceof Uint8Array
    ? saltInput
    : (typeof saltInput === "string" ? ub64(saltInput) : enc.encode("keyvex:pw-reset:v1"));
  const base = await subtle().importKey(
    "raw",
    enc.encode(`keyvex:pw-reset:v2\u0000${cleanPw}`),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const rootBits = await subtle().deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: Number(rounds) || iterations, hash: "SHA-256" },
    base,
    256
  );
  const hk = await subtle().importKey("raw", rootBits, "HKDF", false, ["deriveKey"]);
  return subtle().deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode("keyvex:pw-reset:kek") },
    hk,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"]
  );
}

/**
 * Legacy read-only migration helper for pre-v1.0.0 vaults that used `emailResetWrapped`.
 * New vaults NEVER write keys derived from UID or email.
 */
export async function deriveAccountResetKek(uid, email, saltInput, rounds = iterations) {
  const cleanUid = String(uid || "").trim();
  const cleanEmail = String(email || "").trim().toLowerCase();
  if (!cleanUid || !cleanEmail) throw new Error("Valid account UID and email are required for legacy migration KEK.");
  const saltBytes = saltInput instanceof Uint8Array
    ? saltInput
    : (typeof saltInput === "string" ? ub64(saltInput) : enc.encode("keyvex:email-reset:v1"));
  const base = await subtle().importKey(
    "raw",
    enc.encode(`keyvex:email-reset:v2:${cleanUid}\u0000${cleanEmail}`),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const rootBits = await subtle().deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: Number(rounds) || iterations, hash: "SHA-256" },
    base,
    256
  );
  const hk = await subtle().importKey("raw", rootBits, "HKDF", false, ["deriveKey"]);
  return subtle().deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode("keyvex:email-reset:kek") },
    hk,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"]
  );
}

export { deriveAccountResetKek as deriveEmailResetKek };

/** Salted hash of the Master Password alone — sealed inside the vault and used to re-confirm sensitive actions. */
export async function masterHash(master, salt, rounds = iterations) {
  const base = await subtle().importKey("raw", enc.encode(normalize(master)), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await subtle().deriveBits({ name: "PBKDF2", salt, iterations: rounds, hash: "SHA-256" }, base, 256));
}

export const generateVaultKey = () =>
  subtle().generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);

export async function exportVaultKeyBase64(vaultKey) {
  const raw = new Uint8Array(await subtle().exportKey("raw", vaultKey));
  return b64(raw);
}

export async function importVaultKeyBase64(rawB64, extractable = false) {
  return subtle().importKey("raw", ub64(rawB64), { name: "AES-GCM", length: 256 }, extractable, ["encrypt", "decrypt"]);
}

export async function wrapKey(vaultKey, kek) {
  return new Uint8Array(await subtle().wrapKey("raw", vaultKey, kek, "AES-KW"));
}

/** extractable=false for normal use; true only for the short moment a re-wrap needs it. */
export function unwrapKey(wrapped, kek, extractable = false) {
  return subtle().unwrapKey("raw", wrapped, kek, "AES-KW", { name: "AES-GCM", length: 256 }, extractable, ["encrypt", "decrypt"]);
}

export async function seal(key, value, aad) {
  const iv = rand(12);
  const ct = await subtle().encrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(aad) }, key, enc.encode(JSON.stringify(value)));
  return { iv: b64(iv), data: b64(new Uint8Array(ct)) };
}

export async function open(key, record, aad) {
  const pt = await subtle().decrypt(
    { name: "AES-GCM", iv: ub64(record.iv), additionalData: enc.encode(aad) }, key, ub64(record.data));
  return JSON.parse(dec.decode(pt));
}

/** Constant-time comparison for two equal-purpose byte arrays. */
export function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
