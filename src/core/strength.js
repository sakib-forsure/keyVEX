const COMMON = ["password", "123456", "qwerty", "letmein", "admin", "welcome", "iloveyou", "abc123", "monkey", "dragon", "football", "baseball", "master", "login", "princess", "sunshine", "passw0rd", "111111", "000000", "trustno1"];

function isCommonPassword(pw) {
  const lower = String(pw || "").toLowerCase().trim();
  const lettersOnly = lower.replace(/[^a-z]/g, "");
  return COMMON.includes(lower) || COMMON.includes(lettersOnly);
}

/** Entropy estimate that ignores repeated characters and simple ascending runs. */
export function strength(pw) {
  if (!pw) return { score: 0, bits: 0, pct: 0, label: "", color: "#FF6B5E" };
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  let effective = 0;
  for (let i = 0; i < pw.length; i++) {
    const prev = pw.charCodeAt(i - 1), cur = pw.charCodeAt(i);
    if (i > 0 && (cur === prev || cur === prev + 1 || cur === prev - 1)) continue;
    effective++;
  }
  const bits = Math.round(effective * Math.log2(pool || 1));
  const common = isCommonPassword(pw);
  let score = bits >= 80 ? 4 : bits >= 45 ? 3 : bits >= 32 ? 2 : bits >= 22 ? 1 : 0;
  if (common) score = Math.min(score, 0);
  const levels = [
    ["Very weak", "#FF6B5E", 12], ["Weak", "#FF8A5E", 32], ["Fair", "#FFC24B", 55],
    ["Strong", "#8BD450", 78], ["Excellent", "#5BD98C", 100]
  ];
  const [label, color, pct] = levels[score];
  return { score, bits, pct, color, label: common ? "Very weak (common password)" : label };
}

export const isWeak = (pw) => strength(pw).score <= 1;

/* ---------- Passkey (numeric 4, 6, or 8 digits, or strong alphanumeric) ---------- */
export const PIN_LENGTHS = [4, 6, 8];

export const BAD_PINS = new Set([
  "1234", "4321", "1212", "2580", "0852", "1122", "2000", "2024", "2025", "2026",
  "1357", "2468", "1004", "1314", "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
  "123456", "654321", "121212", "112233", "123123", "159753", "147258", "789456", "696969", "520520",
  "131452", "520131", "5201314", "135790", "246810", "085200", "100400",
  "12345678", "87654321", "11223344", "12341234", "00000000", "11111111"
]);

// Add birth years 1950–2010 and repeating pairs (AABB, ABAB, AA00)
for (let y = 1950; y <= 2010; y++) {
  BAD_PINS.add(String(y));
}
for (let a = 0; a <= 9; a++) {
  for (let b = 0; b <= 9; b++) {
    BAD_PINS.add(`${a}${a}${b}${b}`);
    BAD_PINS.add(`${a}${b}${a}${b}`);
    BAD_PINS.add(`${a}${a}${b}${b}${a}${a}`);
    BAD_PINS.add(`${a}${b}${a}${b}${a}${b}`);
  }
}

function isRepeatingPairs(p) {
  if (p.length === 4) {
    return (p[0] === p[1] && p[2] === p[3]) || (p[0] === p[2] && p[1] === p[3]);
  }
  if (p.length === 6) {
    return (
      (p[0] === p[1] && p[2] === p[3] && p[4] === p[5]) ||
      (p[0] === p[2] && p[2] === p[4] && p[1] === p[3] && p[3] === p[5]) ||
      (p.slice(0, 3) === p.slice(3, 6))
    );
  }
  if (p.length === 8) {
    return (
      (p[0] === p[1] && p[2] === p[3] && p[4] === p[5] && p[6] === p[7]) ||
      (p.slice(0, 4) === p.slice(4, 8))
    );
  }
  return false;
}

/**
 * Validates a Passkey:
 * - Standard numeric Passkey: 4, 6, or 8 digits (0–9), rejecting sequences, birth years, and repeating patterns.
 * - Optional "strong" alphanumeric Passkey (`length === "strong"` or alphanumeric >= 8 chars): at least 8 chars with letters & digits.
 */
export function checkPin(pin, length) {
  const p = String(pin ?? "");
  if (length === "strong" || (length === undefined && /[A-Za-z]/.test(p) && p.length >= 8)) {
    if (p.length < 8 || p.length > 64) return { ok: false, hint: "Strong Passkey must be 8 to 64 characters." };
    if (!/[A-Za-z]/.test(p) || !/\d/.test(p)) return { ok: false, hint: "Strong Passkey must include both letters and numbers." };
    if (isCommonPassword(p) || /^ (.)\1+$/.test(p)) return { ok: false, hint: "Too easy to guess — choose a stronger Passkey." };
    return { ok: true, hint: "" };
  }
  if (!/^\d*$/.test(p)) return { ok: false, hint: "Numbers only (0–9)." };
  const want = length || p.length;
  if (!PIN_LENGTHS.includes(want) || p.length !== want) {
    return { ok: false, hint: `Enter ${PIN_LENGTHS.includes(length) ? length : "4 or 6"} digits.` };
  }
  if (/^(\d)\1+$/.test(p)) return { ok: false, hint: "Too easy to guess — don’t repeat one digit." };
  const d = [...p].map(Number);
  const step = d.every((x, i) => i === 0 || x - d[i - 1] === 1) || d.every((x, i) => i === 0 || x - d[i - 1] === -1);
  const step2 = d.every((x, i) => i === 0 || x - d[i - 1] === 2) || d.every((x, i) => i === 0 || x - d[i - 1] === -2);
  if (step || step2 || BAD_PINS.has(p) || isRepeatingPairs(p)) {
    return { ok: false, hint: "Too easy to guess — avoid runs like 1234, birth years, or repeating pairs." };
  }
  return { ok: true, hint: "" };
}

/* ---------- Master Password: minimum 8 characters + special character ---------- */
export const MASTER_MIN = 8;
export const MASTER_MAX = 128;

/**
 * Validates Master / Account Password:
 * - At least 8 characters (up to 128)
 * - Contains letters and at least 1 special character (e.g. !, @, #, $)
 * - Not a common dictionary password and does not contain the Passkey
 */
export function checkMasterPassword(pw, pin = "") {
  const p = String(pw ?? "");
  const s = strength(p);
  const base = { ...s, ok: false, hint: "" };
  if (p.length < MASTER_MIN) return { ...base, hint: `Use at least ${MASTER_MIN} characters.` };
  if (p.length > MASTER_MAX) return { ...base, hint: `Keep it under ${MASTER_MAX} characters.` };
  if (/^\d+$/.test(p)) return { ...base, hint: "Numbers alone are too easy to guess — add letters and a special character." };
  if (!/[A-Za-z]/.test(p)) return { ...base, hint: "Include at least one letter." };
  if (!/[^A-Za-z0-9\s]/.test(p)) return { ...base, hint: "Include at least 1 special character (e.g. @, #, !, $)." };
  if (pin && p.replace(/\s/g, "").includes(String(pin))) return { ...base, hint: "It must not contain your Passkey." };
  if (isCommonPassword(p)) return { ...base, hint: "Too easy to guess — avoid common passwords." };
  return { ...base, ok: true };
}
