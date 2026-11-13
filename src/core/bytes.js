/** Small byte/encoding helpers shared by the core. No DOM access. */
export const enc = new TextEncoder();
export const dec = new TextDecoder();

export const rand = (n) => crypto.getRandomValues(new Uint8Array(n));

/** URL-safe base64 without padding. */
export function b64(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function ub64(str) {
  let s = String(str).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Unbiased random integer in [0, max). */
export function randInt(max) {
  if (!Number.isInteger(max) || max <= 0 || max > 0x100000000) throw new RangeError("bad max");
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  let x;
  do { crypto.getRandomValues(buf); x = buf[0]; } while (x >= limit);
  return x % max;
}
