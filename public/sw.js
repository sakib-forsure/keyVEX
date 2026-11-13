/* App-shell cache so the interface loads quickly. Account data is NEVER cached here: /api is always network-only. */
const CACHE = "keyvex-shell-v5";
const PRECACHE_URLS = ["/", "/index.html", "/offline.html", "/manifest.webmanifest", "/icon.svg", "/icon-192.png", "/icon-512.png", "/apple-touch-icon.png"];

const SENSITIVE_QUERY_KEYS = ["oobcode", "token", "resettoken", "mode", "code", "state"];

export function hasSensitiveAuthQuery(urlObj) {
  try {
    const u = urlObj instanceof URL ? urlObj : new URL(String(urlObj), "http://localhost");
    if (!u.search) return false;
    for (const [k] of u.searchParams.entries()) {
      if (SENSITIVE_QUERY_KEYS.includes(String(k).toLowerCase())) return true;
    }
    return false;
  } catch {
    return false;
  }
}

export function normalizeCacheKeyUrl(urlObj) {
  const u = urlObj instanceof URL ? new URL(urlObj.href) : new URL(String(urlObj), "http://localhost");
  u.search = "";
  u.hash = "";
  return u.toString();
}

if (typeof self !== "undefined" && typeof self.addEventListener === "function") {
  self.addEventListener("install", (e) => {
    self.skipWaiting?.();
    e.waitUntil(
      caches.open(CACHE).then(async (c) => {
        for (const u of PRECACHE_URLS) {
          try { await c.add(u); } catch { /* ignore individual missing asset in dev */ }
        }
      })
    );
  });

  self.addEventListener("activate", (e) => {
    e.waitUntil(
      caches.keys()
        .then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
        .then(async () => {
          // Purge any stale or query-string entries inside the active cache
          const c = await caches.open(CACHE);
          const reqs = await c.keys();
          for (const req of reqs) {
            const u = new URL(req.url);
            if (hasSensitiveAuthQuery(u)) {
              await c.delete(req);
            }
          }
          return self.clients?.claim?.();
        })
    );
  });

  self.addEventListener("message", (e) => {
    if (e.data?.type === "SKIP_WAITING") self.skipWaiting?.();
  });

  self.addEventListener("fetch", (e) => {
    const url = new URL(e.request.url);
    if (e.request.method !== "GET" || url.origin !== location.origin || url.pathname.startsWith("/api/")) return;

    // B16: NEVER cache URLs containing one-time OOB action codes, tokens, or auth modes!
    const sensitiveQuery = hasSensitiveAuthQuery(url);
    const isNav = e.request.mode === "navigate" || url.pathname === "/" || url.pathname === "/index.html";
    const isAsset = /\.(js|css|woff2?|svg|png|ico|webmanifest)$/i.test(url.pathname);
    const cleanCacheKey = normalizeCacheKeyUrl(url);

    e.respondWith(
      fetch(e.request)
        .then((res) => {
          if (res.ok && !sensitiveQuery) {
            const ctype = (res.headers.get("content-type") || "").toLowerCase();
            if (!isAsset || !ctype.includes("text/html")) {
              const copy = res.clone();
              caches.open(CACHE).then((c) => c.put(cleanCacheKey, copy)).catch(() => {});
            }
          }
          return res;
        })
        .catch(() =>
          caches.match(cleanCacheKey).then((hit) => {
            if (hit) return hit;
            if (isNav) {
              return caches.match("/index.html").then((idx) => idx || caches.match("/offline.html"));
            }
            return Response.error();
          })
        )
    );
  });
}
