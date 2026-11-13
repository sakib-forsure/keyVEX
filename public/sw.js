/*
 * KeyVEX service worker — makes the app shell open with NO network (desktop, Android, iPhone Home Screen).
 *
 *  - The build (scripts/build.mjs) stamps the two placeholders below with the real list of hashed
 *    JS / CSS / font files, so everything needed to boot is cached at install time, not on first use.
 *  - /assets/* (content-hashed, immutable)  → cache-first.
 *  - Navigations (/, /login, /vault, …)       → cached shell first when offline; online it is refreshed in the background.
 *  - /api/* and every cross-origin request (Firebase / Google) are NEVER touched: account data is never cached here.
 *    Offline vault data lives encrypted in IndexedDB, not in the Cache Storage.
 */
const BUILD = "__KEYVEX_BUILD__";
const CACHE = `keyvex-shell-${BUILD}`;
const PRECACHE_URLS = __KEYVEX_PRECACHE__;
const CORE_URLS = ["/", "/index.html", "/offline.html", "/manifest.webmanifest", "/icon.svg", "/favicon.svg", "/icon-192.png", "/icon-512.png", "/apple-touch-icon.png"];

const SENSITIVE_QUERY_KEYS = ["oobcode", "token", "resettoken", "mode", "code", "state", "apikey"];

function hasSensitiveAuthQuery(urlObj) {
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

function normalizeCacheKeyUrl(urlObj) {
  const u = urlObj instanceof URL ? new URL(urlObj.href) : new URL(String(urlObj), "http://localhost");
  u.search = "";
  u.hash = "";
  return u.toString();
}

/**
 * A Response with `redirected === true` must never be served for a navigation (browsers reject it with a network
 * error). Cloudflare redirects `/index.html` -> `/`, so every response is rebuilt without the redirect flag
 * before it is stored or returned.
 */
async function cleanResponse(res) {
  if (!res || !res.redirected) return res;
  const body = await res.clone().blob();
  return new Response(body, { status: res.status, statusText: res.statusText, headers: res.headers });
}

if (typeof self !== "undefined" && typeof self.addEventListener === "function") {
  const isHashedAsset = (url) => url.pathname.startsWith("/assets/");

  self.addEventListener("install", (e) => {
    e.waitUntil(
      caches.open(CACHE).then(async (c) => {
        const all = [...new Set([...CORE_URLS, ...PRECACHE_URLS])];
        await Promise.all(all.map(async (u) => {
          try {
            const res = await fetch(new Request(u, { cache: "reload" }));
            if (res.ok) await c.put(u, await cleanResponse(res));
          } catch { /* a single missing file (dev server) must not break install */ }
        }));
        // Keep the shell consistent: no half-installed worker if the entry point is missing in production.
        if (PRECACHE_URLS.length > 0 && !(await c.match("/index.html"))) throw new Error("shell not cached");
      }).then(() => self.skipWaiting?.())
    );
  });

  self.addEventListener("activate", (e) => {
    e.waitUntil(
      (async () => {
        const keys = await caches.keys();
        await Promise.all(keys.filter((k) => k.startsWith("keyvex-shell-") && k !== CACHE).map((k) => caches.delete(k)));
        const c = await caches.open(CACHE);
        for (const req of await c.keys()) {
          if (hasSensitiveAuthQuery(new URL(req.url))) await c.delete(req);
        }
        await self.clients?.claim?.();
      })()
    );
  });

  self.addEventListener("message", (e) => {
    if (e.data?.type === "SKIP_WAITING") self.skipWaiting?.();
  });

  async function cacheFirst(request, key) {
    const cache = await caches.open(CACHE);
    const hit = await cache.match(key);
    if (hit) return hit;
    const res = await fetch(request);
    if (res.ok) cache.put(key, res.clone()).catch(() => {});
    return res;
  }

  async function shellResponse(cache) {
    return (await cache.match("/index.html")) || (await cache.match("/")) || (await cache.match("/offline.html"));
  }

  async function navigate(e, url) {
    const cache = await caches.open(CACHE);
    const sensitive = hasSensitiveAuthQuery(url);
    const refresh = fetch(e.request)
      .then((res) => {
        // Only the real HTML shell is cached, and only for clean (non auth-action) URLs.
        if (res.ok && !sensitive && (res.headers.get("content-type") || "").includes("text/html")) {
          cleanResponse(res.clone()).then((clean) => cache.put("/index.html", clean)).catch(() => {});
        }
        return res;
      });

    // Online & fast: always prefer the fresh shell. Offline / slow: the cached shell opens the app instantly.
    const cached = await shellResponse(cache);
    if (!cached) return refresh.catch(() => Response.error());
    const timeout = new Promise((resolve) => setTimeout(() => resolve(null), 2500));
    try {
      const fresh = await Promise.race([refresh, timeout]);
      if (fresh && fresh.ok) return fresh;
    } catch { /* offline */ }
    refresh.catch(() => {});
    return cached;
  }

  self.addEventListener("fetch", (e) => {
    const url = new URL(e.request.url);
    if (e.request.method !== "GET" || url.origin !== location.origin || url.pathname.startsWith("/api/")) return;

    if (e.request.mode === "navigate") {
      e.respondWith(navigate(e, url));
      return;
    }

    if (isHashedAsset(url)) {
      e.respondWith(cacheFirst(e.request, normalizeCacheKeyUrl(url)).catch(() => Response.error()));
      return;
    }

    // Other same-origin statics (icons, manifest, sw-adjacent files): network first, cache fallback.
    const key = normalizeCacheKeyUrl(url);
    const sensitive = hasSensitiveAuthQuery(url);
    e.respondWith(
      fetch(e.request)
        .then((res) => {
          if (res.ok && !sensitive && !(res.headers.get("content-type") || "").includes("text/html")) {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(key, copy)).catch(() => {});
          }
          return res;
        })
        .catch(() => caches.match(key).then((hit) => hit || Response.error()))
    );
  });
}
