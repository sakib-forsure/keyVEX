import { isWeak } from "./strength.js";

const OLD_MS = 180 * 24 * 3600 * 1000;

/** Scans decrypted entries for weak, reused and stale passwords. */
export function auditEntries(entries, now = Date.now()) {
  const byPw = new Map();
  for (const e of entries) {
    if (!e.password) continue;
    if (!byPw.has(e.password)) byPw.set(e.password, []);
    byPw.get(e.password).push(e);
  }
  return {
    weak: entries.filter((e) => e.password && isWeak(e.password)),
    reused: [...byPw.values()].filter((g) => g.length > 1).flat(),
    old: entries.filter((e) => e.password && now - (e.updatedAt || e.createdAt || now) > OLD_MS)
  };
}
