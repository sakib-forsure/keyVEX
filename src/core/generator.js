import { randInt } from "./bytes.js";

const SETS = {
  lower: "abcdefghijkmnopqrstuvwxyz",   // no l
  upper: "ABCDEFGHJKLMNPQRSTUVWXYZ",     // no I, O
  digits: "23456789",                    // no 0, 1
  symbols: "!@#$%^&*()-_=+[]{}<>?"
};

/** Cryptographically random password; guarantees one character from every enabled set. */
export function generatePassword({ length = 18, lower = true, upper = true, digits = true, symbols = true } = {}) {
  const enabled = Object.entries({ lower, upper, digits, symbols }).filter(([, on]) => on).map(([k]) => SETS[k]);
  if (!enabled.length) throw new Error("Enable at least one character set");
  length = Math.min(128, Math.max(enabled.length, Math.floor(length)));
  const pool = enabled.join("");
  const out = enabled.map((set) => set[randInt(set.length)]);
  while (out.length < length) out.push(pool[randInt(pool.length)]);
  for (let i = out.length - 1; i > 0; i--) { const j = randInt(i + 1); [out[i], out[j]] = [out[j], out[i]]; }
  return out.join("");
}
