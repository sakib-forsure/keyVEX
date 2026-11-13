/**
 * Safe Performance Instrumentation for KeyVEX (`src/core/perf.js`).
 *
 * Uses standard `performance.mark()` and `performance.measure()` to record
 * latency across critical authentication, KDF, Firestore, local-cache, and UI paths.
 *
 * Security Invariant:
 *   Never accepts or records passwords, passkeys, tokens, recovery keys, emails,
 *   UIDs, or decrypted entry contents in mark/measure names or metadata.
 */
const ALLOWED_METRICS = new Set([
  "app_init",
  "session_restore",
  "token_refresh",
  "kdf_derivation",
  "firestore_meta_read",
  "firestore_entries_read",
  "firestore_write",
  "local_cache_read",
  "vault_decrypt",
  "vault_sync",
  "account_deletion",
  "first_vault_render"
]);

const samples = new Map(); // metricName -> number[] (durations in ms)
const MAX_SAMPLES = 5000;

function nowMs() {
  if (typeof performance !== "undefined" && typeof performance.now === "function") {
    return performance.now();
  }
  return Date.now();
}

export function startMeasure(metricName) {
  const safeName = ALLOWED_METRICS.has(metricName) ? metricName : "custom_op";
  const t0 = nowMs();
  const markStart = `kvx:${safeName}:start`;
  const markEnd = `kvx:${safeName}:end`;
  try {
    if (typeof performance !== "undefined" && typeof performance.mark === "function") {
      performance.mark(markStart);
    }
  } catch { /* ignore */ }

  let ended = false;
  return {
    end() {
      if (ended) return 0;
      ended = true;
      const duration = Math.max(0, nowMs() - t0);
      try {
        if (typeof performance !== "undefined" && typeof performance.mark === "function" && typeof performance.measure === "function") {
          performance.mark(markEnd);
          performance.measure(`kvx:${safeName}`, markStart, markEnd);
        }
      } catch { /* ignore */ }
      recordSample(safeName, duration);
      return duration;
    }
  };
}

export function recordSample(metricName, durationMs) {
  const safeName = ALLOWED_METRICS.has(metricName) ? metricName : "custom_op";
  if (!samples.has(safeName)) samples.set(safeName, []);
  const arr = samples.get(safeName);
  arr.push(Number(durationMs) || 0);
  if (arr.length > MAX_SAMPLES) arr.shift();
}

export async function measureAsync(metricName, fn) {
  const m = startMeasure(metricName);
  try {
    return await fn();
  } finally {
    m.end();
  }
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return Math.round(sorted[idx] * 100) / 100;
}

export function getPerfStats(metricName) {
  const arr = samples.get(metricName) || [];
  if (!arr.length) {
    return { count: 0, min: 0, max: 0, mean: 0, p50: 0, p95: 0, p99: 0, last: 0 };
  }
  const sorted = [...arr].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  return {
    count: sorted.length,
    min: Math.round(sorted[0] * 100) / 100,
    max: Math.round(sorted[sorted.length - 1] * 100) / 100,
    mean: Math.round((sum / sorted.length) * 100) / 100,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
    last: Math.round(arr[arr.length - 1] * 100) / 100
  };
}

export function getAllPerfStats() {
  const out = {};
  for (const name of ALLOWED_METRICS) {
    const st = getPerfStats(name);
    if (st.count > 0) out[name] = st;
  }
  return out;
}

export function resetPerfStats() {
  samples.clear();
  try {
    if (typeof performance !== "undefined" && typeof performance.clearMarks === "function") {
      performance.clearMarks();
      performance.clearMeasures?.();
    }
  } catch { /* ignore */ }
}
