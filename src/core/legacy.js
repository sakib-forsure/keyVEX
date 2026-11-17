/**
 * Reads a backup made by the ORIGINAL single-file KeyVEX / "keep-safe" app (PIN based)
 * so existing passwords can be moved into the new vault. Read-only: nothing is written here.
 */
import { enc, dec, ub64 } from "./bytes.js";

const ROUNDS = 600_000;
const VERIFY_TEXT = "keep-safe-vault-ok";
const normName = (s) => String(s || "").trim().replace(/\s+/g, " ").toLowerCase();

export class LegacyError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

/** @param via "pin" (4–6 digit passkey) or "name" (the old recovery word) */
export async function readLegacyBackup(text, secret, via = "pin") {
  let p;
  try { p = JSON.parse(text); } catch { throw new LegacyError("NOT_LEGACY", "That file is not valid JSON."); }
  const m = p?.meta;
  if (!p || p.app !== "keep-safe" || !m || !m.wrappedPin || !Array.isArray(p.entries)) {
    throw new LegacyError("NOT_LEGACY", "That is not a backup from the old KeyVEX app.");
  }
  const [salt, wrapped, material] = via === "pin"
    ? [m.saltPin, m.wrappedPin, enc.encode(String(secret).trim())]
    : [m.saltRec, m.wrappedRec, enc.encode(normName(secret))];
  if (!salt || !wrapped) throw new LegacyError("NOT_LEGACY", "This backup has no recovery data.");
  let vk;
  try {
    const base = await crypto.subtle.importKey("raw", material, "PBKDF2", false, ["deriveKey"]);
    const kek = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: ub64(salt), iterations: ROUNDS, hash: "SHA-256" },
      base, { name: "AES-KW", length: 256 }, false, ["unwrapKey"]);
    vk = await crypto.subtle.unwrapKey("raw", ub64(wrapped), kek, "AES-KW", { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ub64(m.verifier.iv) }, vk, ub64(m.verifier.data));
    if (dec.decode(pt) !== VERIFY_TEXT) throw new Error("verify");
  } catch { throw new LegacyError("BAD_SECRET", via === "pin" ? "That PIN did not open the old backup." : "That recovery name did not open the old backup."); }

  const out = [];
  for (const rec of p.entries) {
    try {
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ub64(rec.iv) }, vk, ub64(rec.data));
      const e = JSON.parse(dec.decode(pt));
      out.push({
        id: rec.id || e.id,
        service: e.service, website: e.website, username: e.username, password: e.password,
        category: e.category, notes: e.notes, favorite: !!e.favorite, createdAt: e.createdAt
      });
    } catch {
      throw new LegacyError("CORRUPTED_BACKUP", "This legacy backup file contains corrupted records that could not be decrypted.");
    }
  }
  return out;
}
