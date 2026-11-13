/**
 * RFC 6238 TOTP (Time-Based One-Time Password) implementation using WebCrypto (`src/core/totp.js`).
 * Supports standard Google Authenticator / Microsoft Authenticator / 1Password / Bitwarden.
 *
 * B13 Enhancements:
 *   - Strict `base32Decode`: throws on invalid characters instead of silently ignoring them.
 *   - Constant-time code comparison (`sameBytes`).
 *   - Replay protection: tracks last used `timeStep` per secret so a code cannot be reused within the 90s window.
 *   - Attempt limiter: 5 failed tries locks verification for 60s.
 *   - One-time backup codes: generates 8 backup codes (`XXXX-XXXX`), hashes them with SHA-256 for storage inside
 *     sealed metadata (`meta.totpBackupHashes`), and consumes them single-use.
 *   - Local SVG QR code generator (ISO/IEC 18004 Byte Mode, Error Correction Level L, Versions 1–10) with zero
 *     external network requests (CSP-safe).
 */
import { enc, rand } from "./bytes.js";
import { sameBytes } from "./crypto.js";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const lastUsedStepBySecret = new Map(); // secretHash -> timeStep
const totpThrottleState = new Map(); // key -> { fails, lockedUntil }
const TOTP_MAX_FAILS = 5;
const TOTP_LOCK_MS = 60_000;

export function resetTotpReplayAndThrottleForTests() {
  lastUsedStepBySecret.clear();
  totpThrottleState.clear();
}

export function generateTotpSecret(length = 20) {
  const bytes = rand(length);
  let bits = 0;
  let value = 0;
  let output = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/**
 * Decodes a Base32 string into bytes. Throws on invalid Base32 characters (B13).
 */
export function base32Decode(str) {
  let bits = 0;
  let value = 0;
  const output = [];
  const raw = String(str ?? "").trim();
  if (!raw) throw new Error("Invalid base32 secret: empty input.");
  const clean = raw.toUpperCase().replace(/[\s=-]/g, "");
  if (!clean) throw new Error("Invalid base32 secret.");
  for (let i = 0; i < clean.length; i++) {
    const val = BASE32_ALPHABET.indexOf(clean[i]);
    if (val === -1) {
      throw new Error(`Invalid base32 character: "${clean[i]}"`);
    }
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

export async function generateTotp(secret, timeStep = Math.floor(Date.now() / 1000 / 30)) {
  const keyBytes = base32Decode(secret);
  if (!keyBytes.length) throw new Error("Invalid base32 secret.");
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setBigUint64(0, BigInt(timeStep));
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));
  const offset = sig[sig.length - 1] & 0x0f;
  const code =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  return String(code % 1_000_000).padStart(6, "0");
}

/**
 * Constant-time TOTP verification with replay protection and 5-try / 60s lockout (B13).
 */
export async function verifyTotpCode(secret, token, window = 1, { throttleKey = "default", checkReplay = true, lastAcceptedStep = null, onStepAccepted = null } = {}) {
  const now = Date.now();
  const thr = totpThrottleState.get(throttleKey) || { fails: 0, lockedUntil: 0 };
  if (thr.lockedUntil > now) {
    const retryAfter = Math.max(1, Math.ceil((thr.lockedUntil - now) / 1000));
    const err = new Error(`Too many wrong codes. Try again in ${retryAfter}s.`);
    err.code = "LOCKED_OUT";
    err.retryAfter = retryAfter;
    throw err;
  }

  const clean = String(token || "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(clean)) {
    const fails = thr.fails + 1;
    const lockedUntil = fails >= TOTP_MAX_FAILS ? now + TOTP_LOCK_MS : 0;
    totpThrottleState.set(throttleKey, { fails, lockedUntil });
    return false;
  }

  const tokenBytes = enc.encode(clean);
  const currentStep = Math.floor(now / 1000 / 30);
  const secretKey = String(secret || "").trim().toUpperCase();
  const recordedStep = lastAcceptedStep !== null && lastAcceptedStep !== undefined
    ? Number(lastAcceptedStep)
    : lastUsedStepBySecret.get(secretKey);

  let matchedStep = null;
  for (let offset = -window; offset <= window; offset++) {
    const step = currentStep + offset;
    try {
      const candidate = await generateTotp(secret, step);
      if (sameBytes(enc.encode(candidate), tokenBytes)) {
        matchedStep = step;
        break;
      }
    } catch {
      return false;
    }
  }

  if (matchedStep !== null) {
    if (checkReplay && Number.isFinite(recordedStep) && matchedStep <= recordedStep) {
      // Replay detected in the same or earlier time step!
      return false;
    }
    lastUsedStepBySecret.set(secretKey, matchedStep);
    totpThrottleState.delete(throttleKey);
    onStepAccepted?.(matchedStep);
    return true;
  }

  const fails = thr.fails + 1;
  const lockedUntil = fails >= TOTP_MAX_FAILS ? now + TOTP_LOCK_MS : 0;
  totpThrottleState.set(throttleKey, { fails, lockedUntil });
  return false;
}

/* ---------- 8 One-Time TOTP Backup Codes (B13) ---------- */
export function generateTotpBackupCodes(count = 8) {
  const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  const codes = [];
  for (let i = 0; i < count; i++) {
    const bytes = rand(8);
    let part1 = "", part2 = "";
    for (let j = 0; j < 4; j++) part1 += alphabet[bytes[j] % alphabet.length];
    for (let j = 4; j < 8; j++) part2 += alphabet[bytes[j] % alphabet.length];
    codes.push(`${part1}-${part2}`);
  }
  return codes;
}

export async function hashTotpBackupCode(code) {
  const clean = String(code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(`keyvex:totp-backup:${clean}`));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function verifyAndConsumeTotpBackupCode(code, hashedCodes = []) {
  const clean = String(code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (clean.length < 6 || !Array.isArray(hashedCodes) || !hashedCodes.length) {
    return { ok: false, remainingHashes: hashedCodes || [] };
  }
  const candidateHash = await hashTotpBackupCode(clean);
  const candidateBytes = enc.encode(candidateHash);
  let matchedIndex = -1;
  for (let i = 0; i < hashedCodes.length; i++) {
    const h = String(hashedCodes[i] || "");
    if (sameBytes(enc.encode(h), candidateBytes)) {
      matchedIndex = i;
    }
  }
  if (matchedIndex === -1) {
    return { ok: false, remainingHashes: [...hashedCodes] };
  }
  const remainingHashes = hashedCodes.filter((_, idx) => idx !== matchedIndex);
  return { ok: true, remainingHashes };
}

export function getTotpUri(email, secret, issuer = "KeyVEX") {
  const label = encodeURIComponent(issuer) + ":" + encodeURIComponent(email);
  const iss = encodeURIComponent(issuer);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${iss}&algorithm=SHA1&digits=6&period=30`;
}

/* ============================================================================
 * Local Zero-Dependency ISO/IEC 18004 QR Code SVG Generator (Error Level L)
 * Supports byte payloads up to 271 bytes (otpauth:// URIs are ~85–120 bytes).
 * ============================================================================ */
const QR_VERSIONS = [
  null,
  { total: 26, ecPerBlock: 7, blocks: [1, 19] },
  { total: 44, ecPerBlock: 10, blocks: [1, 34] },
  { total: 70, ecPerBlock: 15, blocks: [1, 55] },
  { total: 100, ecPerBlock: 20, blocks: [1, 80] },
  { total: 134, ecPerBlock: 26, blocks: [1, 108] },
  { total: 172, ecPerBlock: 18, blocks: [2, 68] },
  { total: 196, ecPerBlock: 20, blocks: [2, 78] },
  { total: 242, ecPerBlock: 24, blocks: [2, 97] },
  { total: 292, ecPerBlock: 30, blocks: [2, 116] },
  { total: 346, ecPerBlock: 18, blocks: [2, 68, 2, 69] }
];

const ALIGNMENT_POS = [
  [],
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50]
];

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGeneratorPoly(degree) {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    const factor = GF_EXP[i];
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], factor);
    }
    poly = next;
  }
  return poly;
}

function rsEncode(data, ecLen) {
  const gen = rsGeneratorPoly(ecLen);
  const rem = new Uint8Array(ecLen);
  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ rem[0];
    rem.copyWithin(0, 1);
    rem[ecLen - 1] = 0;
    for (let j = 0; j < ecLen; j++) {
      rem[j] ^= gfMul(gen[j + 1], factor);
    }
  }
  return rem;
}

export function generateQrSvg(text, { margin = 3 } = {}) {
  const bytes = enc.encode(String(text || ""));
  let ver = 1;
  while (ver <= 10) {
    const info = QR_VERSIONS[ver];
    const dataCap = info.total - info.ecPerBlock * (info.blocks.length === 2 ? info.blocks[0] : info.blocks[0] + info.blocks[2]);
    const headerBytes = ver <= 9 ? 2 : 3;
    if (bytes.length + headerBytes <= dataCap) break;
    ver++;
  }
  if (ver > 10) ver = 10;
  const vInfo = QR_VERSIONS[ver];
  const totalDataCw = vInfo.total - vInfo.ecPerBlock * (vInfo.blocks.length === 2 ? vInfo.blocks[0] : vInfo.blocks[0] + vInfo.blocks[2]);

  // Build bit stream: Byte mode (0100), char count (8 bits for v1-9, 16 for v10)
  const bits = [];
  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };
  pushBits(0b0100, 4);
  const payload = bytes.slice(0, totalDataCw - (ver <= 9 ? 2 : 3));
  pushBits(payload.length, ver <= 9 ? 8 : 16);
  for (const b of payload) pushBits(b, 8);
  const maxBits = totalDataCw * 8;
  pushBits(0, Math.min(4, maxBits - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);
  const dataCw = new Uint8Array(totalDataCw);
  for (let i = 0; i < bits.length / 8; i++) {
    let v = 0;
    for (let b = 0; b < 8; b++) v = (v << 1) | bits[i * 8 + b];
    dataCw[i] = v;
  }
  let padIdx = 0;
  for (let i = bits.length / 8; i < totalDataCw; i++) {
    dataCw[i] = padIdx++ % 2 === 0 ? 0xec : 0x11;
  }

  // Split into blocks and compute RS error correction
  const dataBlocks = [];
  const ecBlocks = [];
  let offset = 0;
  for (let b = 0; b < vInfo.blocks.length; b += 2) {
    const count = vInfo.blocks[b];
    const len = vInfo.blocks[b + 1];
    for (let i = 0; i < count; i++) {
      const blk = dataCw.slice(offset, offset + len);
      offset += len;
      dataBlocks.push(blk);
      ecBlocks.push(rsEncode(blk, vInfo.ecPerBlock));
    }
  }

  const finalCw = [];
  const maxDataLen = Math.max(...dataBlocks.map((b) => b.length));
  for (let i = 0; i < maxDataLen; i++) {
    for (const blk of dataBlocks) if (i < blk.length) finalCw.push(blk[i]);
  }
  for (let i = 0; i < vInfo.ecPerBlock; i++) {
    for (const blk of ecBlocks) finalCw.push(blk[i]);
  }

  const size = 17 + ver * 4;
  const grid = Array.from({ length: size }, () => new Uint8Array(size));
  const reserved = Array.from({ length: size }, () => new Uint8Array(size));

  const setMod = (r, c, dark) => {
    if (r < 0 || r >= size || c < 0 || c >= size) return;
    grid[r][c] = dark ? 1 : 0;
    reserved[r][c] = 1;
  };

  const placeFinder = (row, col) => {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const inOuter = r >= 0 && r <= 6 && c >= 0 && c <= 6;
        const onBorder = r === 0 || r === 6 || c === 0 || c === 6;
        const inInner = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        setMod(row + r, col + c, inOuter && (onBorder || inInner));
      }
    }
  };
  placeFinder(0, 0);
  placeFinder(0, size - 7);
  placeFinder(size - 7, 0);

  const aligns = ALIGNMENT_POS[ver];
  for (const r of aligns) {
    for (const c of aligns) {
      if ((r < 9 && c < 9) || (r < 9 && c > size - 10) || (r > size - 10 && c < 9)) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          setMod(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
        }
      }
    }
  }

  for (let i = 8; i < size - 8; i++) {
    if (!reserved[6][i]) setMod(6, i, i % 2 === 0);
    if (!reserved[i][6]) setMod(i, 6, i % 2 === 0);
  }
  setMod(size - 8, 8, 1);

  for (let i = 0; i < 9; i++) {
    if (!reserved[8][i]) reserved[8][i] = 1;
    if (!reserved[i][8]) reserved[i][8] = 1;
  }
  for (let i = 0; i < 8; i++) {
    if (!reserved[8][size - 1 - i]) reserved[8][size - 1 - i] = 1;
    if (!reserved[size - 1 - i][8]) reserved[size - 1 - i][8] = 1;
  }

  // Place data bits with mask 0 ((r + c) % 2 === 0)
  let bitIdx = 0;
  const totalBits = finalCw.length * 8;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++) {
      const r = upward ? size - 1 - vert : vert;
      for (let j = 0; j < 2; j++) {
        const c = right - j;
        if (reserved[r][c]) continue;
        const bit = bitIdx < totalBits ? ((finalCw[bitIdx >>> 3] >>> (7 - (bitIdx & 7))) & 1) : 0;
        bitIdx++;
        const masked = bit ^ ((r + c) % 2 === 0 ? 1 : 0);
        grid[r][c] = masked;
      }
    }
    upward = !upward;
  }

  // Format information for Level L (01) + Mask 0 (000) -> 0x77c4
  const fmtBits = 0x77c4;
  for (let i = 0; i < 15; i++) {
    const bit = (fmtBits >>> i) & 1;
    if (i < 6) grid[i][8] = bit;
    else if (i < 8) grid[i + 1][8] = bit;
    else grid[8][size - 15 + i] = bit;

    if (i < 8) grid[8][size - 1 - i] = bit;
    else if (i < 9) grid[7][8] = bit;
    else grid[14 - i][8] = bit;
  }

  const totalSize = size + margin * 2;
  let path = "";
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (grid[r][c]) {
        path += `M${c + margin},${r + margin}h1v1h-1z`;
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${totalSize} ${totalSize}" shape-rendering="crispEdges" role="img" aria-label="Authenticator QR Code"><rect width="${totalSize}" height="${totalSize}" rx="2" fill="#ffffff"/><path d="${path}" fill="#0b0710"/></svg>`;
}
