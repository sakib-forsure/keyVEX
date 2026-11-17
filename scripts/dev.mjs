/**
 * Unified Development Server Runner (`npm run dev` / `node scripts/dev.mjs`).
 *
 * Responsibilities:
 *   1. Starts the KeyVEX backend API server (`server/app.js`) on `API_PORT` (default `8787`).
 *   2. Starts the frontend dev server on `PORT` (default `5173`):
 *      - Uses `node_modules/.bin/vite` when installed.
 *      - Otherwise starts a built-in zero-dependency ESM development server that serves `index.html`,
 *        `/src/**` ES modules (transforming `.css` and `@fontsource-variable/*` imports into live `<style>`
 *        injectors), `/public/**` static assets, SPA fallback, and proxies `/api/*` to the backend server.
 *   3. Handles process signals (`SIGINT`, `SIGTERM`) cleanly and supports `--check` / `DEV_SMOKE_TEST=1`
 *      for automated verification in `npm test`.
 */
import http from "node:http";
import { existsSync, readFileSync, statSync } from "node:fs";
import { join, dirname, resolve, extname, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createApp } from "../server/app.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".json": "application/json; charset=utf-8",
  ".webmanifest": "application/manifest+json",
  ".ico": "image/x-icon"
};

function transformDevJsModule(code) {
  return code
    .replace(
      /^import\s+["']@fontsource-variable\/(manrope|inter)["'];?\s*$/gm,
      (_, fam) => {
        const fontFile = fam === "manrope" ? "manrope-latin-wght-normal.woff2" : "inter-latin-wght-normal.woff2";
        const familyName = fam === "manrope" ? "Manrope Variable" : "Inter Variable";
        const css = `@font-face{font-family:"${familyName}";font-style:normal;font-display:swap;font-weight:100 900;src:url("/src/styles/fonts/${fontFile}") format("woff2");}`;
        return `{ const s = document.createElement("style"); s.textContent = ${JSON.stringify(css)}; document.head.appendChild(s); }`;
      }
    )
    .replace(
      /^import\s+["'](\.\/styles\/[^"']+\.css)["'];?\s*$/gm,
      (_, relCss) => `import "${relCss}?import";`
    );
}

export async function startDevServers({
  apiPort = Number(process.env.API_PORT) || 8787,
  webPort = Number(process.env.PORT) || 5173,
  host = "127.0.0.1",
  preferBuiltinWeb = false
} = {}) {
  const apiApp = createApp({
    dbPath: process.env.KEYVEX_DB || ":memory:",
    production: false
  });

  await new Promise((resolveListen, rejectListen) => {
    apiApp.server.once("error", rejectListen);
    apiApp.server.listen(apiPort, host, resolveListen);
  });
  const boundApiPort = apiApp.server.address().port;

  let viteProc = null;
  let webServer = null;
  let boundWebPort = webPort;

  const viteBin = join(root, "node_modules", ".bin", "vite");
  if (!preferBuiltinWeb && existsSync(viteBin)) {
    viteProc = spawn(viteBin, ["--host", host, "--port", String(webPort)], {
      cwd: root,
      stdio: "inherit",
      env: { ...process.env, API_PORT: String(boundApiPort) }
    });
  } else {
    webServer = http.createServer((req, res) => {
      const reqUrl = new URL(req.url || "/", `http://${req.headers.host || host}`);
      const pathname = reqUrl.pathname;

      // Proxy /api/* to the backend server
      if (pathname.startsWith("/api/")) {
        const proxyReq = http.request(
          {
            hostname: host,
            port: boundApiPort,
            path: pathname + reqUrl.search,
            method: req.method,
            headers: req.headers
          },
          (proxyRes) => {
            res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
            proxyRes.pipe(res);
          }
        );
        proxyReq.on("error", () => {
          res.writeHead(502, { "Content-Type": "application/json; charset=utf-8" });
          res.end(JSON.stringify({ error: "BAD_GATEWAY", message: "Backend API proxy failed." }));
        });
        req.pipe(proxyReq);
        return;
      }

      // Serve CSS module imports (`*.css?import`) as JS style injectors
      if (pathname.endsWith(".css") && reqUrl.searchParams.has("import")) {
        const safeRel = normalize(decodeURIComponent(pathname)).replace(/^(\.\.(\/|\\|$))+/, "");
        const cssPath = join(root, safeRel);
        if (cssPath.startsWith(root + sep) && existsSync(cssPath)) {
          const cssText = readFileSync(cssPath, "utf8");
          const jsModule = `const s = document.createElement("style"); s.textContent = ${JSON.stringify(cssText)}; document.head.appendChild(s); export default s;\n`;
          res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store" });
          res.end(jsModule);
          return;
        }
      }

      // Serve /src/* or /public/* or root index.html
      let candidate = null;
      const safeRel = normalize(decodeURIComponent(pathname)).replace(/^(\.\.(\/|\\|$))+/, "");
      const rootCandidate = join(root, safeRel);
      const pubCandidate = join(root, "public", safeRel);

      if (pathname === "/" || pathname === "/index.html") {
        candidate = join(root, "index.html");
      } else if (pubCandidate.startsWith(join(root, "public") + sep) && existsSync(pubCandidate) && statSync(pubCandidate).isFile()) {
        candidate = pubCandidate;
      } else if (rootCandidate.startsWith(root + sep) && existsSync(rootCandidate) && statSync(rootCandidate).isFile()) {
        candidate = rootCandidate;
      } else if (!extname(pathname)) {
        candidate = join(root, "index.html");
      }

      if (!candidate || !existsSync(candidate)) {
        res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Not found");
        return;
      }

      const ext = extname(candidate).toLowerCase();
      const mime = MIME[ext] || "application/octet-stream";
      if (candidate === join(root, "src", "main.js") || (candidate.startsWith(join(root, "src") + sep) && ext === ".js")) {
        const transformed = transformDevJsModule(readFileSync(candidate, "utf8"));
        res.writeHead(200, { "Content-Type": mime, "Cache-Control": "no-store" });
        res.end(transformed);
        return;
      }

      res.writeHead(200, { "Content-Type": mime, "Cache-Control": "no-store" });
      res.end(readFileSync(candidate));
    });

    await new Promise((resolveWeb, rejectWeb) => {
      webServer.once("error", rejectWeb);
      webServer.listen(webPort, host, resolveWeb);
    });
    boundWebPort = webServer.address().port;
  }

  async function close() {
    if (viteProc && !viteProc.killed) {
      viteProc.kill("SIGTERM");
    }
    if (webServer) {
      await new Promise((r) => webServer.close(r));
    }
    await apiApp.close();
  }

  return {
    apiPort: boundApiPort,
    webPort: boundWebPort,
    apiUrl: `http://${host}:${boundApiPort}`,
    webUrl: `http://${host}:${boundWebPort}`,
    close
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const isCheck = process.argv.includes("--check") || process.env.DEV_SMOKE_TEST === "1";
  const dev = await startDevServers({
    apiPort: isCheck ? 0 : Number(process.env.API_PORT) || 8787,
    webPort: isCheck ? 0 : Number(process.env.PORT) || 5173,
    preferBuiltinWeb: isCheck
  });

  console.log(`[dev] KeyVEX API server listening at ${dev.apiUrl}`);
  console.log(`[dev] KeyVEX Web server listening at ${dev.webUrl}`);

  const shutdown = async () => {
    await dev.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  if (isCheck) {
    const rHtml = await fetch(`${dev.webUrl}/`);
    const rMain = await fetch(`${dev.webUrl}/src/main.js`);
    const rFav = await fetch(`${dev.webUrl}/favicon.svg`);
    const rApi = await fetch(`${dev.webUrl}/api/health`);
    if (!rHtml.ok || !rMain.ok || !rFav.ok || !rApi.ok) {
      await dev.close();
      throw new Error(`Dev server smoke check failed: html=${rHtml.status}, main=${rMain.status}, fav=${rFav.status}, api=${rApi.status}`);
    }
    await dev.close();
    console.log("[dev] Smoke check passed (HTML, ESM transform, favicon, and /api proxy verified).");
  }
}
