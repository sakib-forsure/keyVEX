/**
 * Production build script (`npm run build` / `scripts/build.mjs`).
 *
 * Responsibilities:
 *   1. Self-heals `src/data/brands.js` from `src/ui/brands-catalog.js` if an older `.gitignore` (`data/`) omitted it.
 *   2. Validates the full relative ES-module import graph across `src/` and `server/` AND all CSS/font/public assets.
 *   3. NEVER ships un-hashed `/assets/src/**` module files.
 *   4. Bundles the ES module graph into a single content-hashed JS chunk (`/assets/index-<hash>.js`),
 *      a single content-hashed, minified CSS bundle (`/assets/index-<hash>.css`), and content-hashed WOFF2 font files
 *      (`/assets/inter-latin-wght-normal-<hash>.woff2`, `/assets/manrope-latin-wght-normal-<hash>.woff2`) with a
 *      Vite-compatible manifest (`dist/.vite/manifest.json`) and unified CSP (`scripts/csp.mjs`).
 *   5. Verifies every asset referenced in `dist/index.html` and `dist/manifest.webmanifest` physically exists in `dist/`.
 */
import { existsSync, mkdirSync, rmSync, readFileSync, writeFileSync, copyFileSync, readdirSync, cpSync } from "node:fs";
import { join, dirname, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { META_CSP } from "./csp.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function ensureBrandsDataModule() {
  const dataDir = join(root, "src", "data");
  const brandsTarget = join(dataDir, "brands.js");
  const backupCatalog = join(root, "src", "ui", "brands-catalog.js");
  if (!existsSync(brandsTarget) && existsSync(backupCatalog)) {
    mkdirSync(dataDir, { recursive: true });
    copyFileSync(backupCatalog, brandsTarget);
  }
}

function loadBuildEnvLiteral() {
  const envObj = { PROD: true, MODE: "production" };
  const envFile = join(root, ".env");
  if (existsSync(envFile)) {
    const lines = readFileSync(envFile, "utf8").split(/\r?\n/);
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx > 0) {
        const key = trimmed.slice(0, eqIdx).trim();
        const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, "");
        if (key.startsWith("VITE_") && val) {
          envObj[key] = val;
        }
      }
    }
  }
  if (typeof process !== "undefined" && process.env) {
    for (const [k, v] of Object.entries(process.env)) {
      if (k.startsWith("VITE_") && v !== undefined && v !== "") {
        envObj[k] = v;
      }
    }
  }
  return JSON.stringify(envObj);
}

export function validateModuleImportGraph(dir) {
  ensureBrandsDataModule();
  const checkedFiles = [];
  const missingImports = [];
  const REL_IMPORT_RE = /(?:import|export)\s+(?:[^"']*?\s+from\s+)?["'](\.\.?\/[^"']+)["']/g;

  function walk(currentDir) {
    for (const entry of readdirSync(currentDir, { withFileTypes: true })) {
      const fullPath = join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === ".git" || entry.name === ".tmp-tests") continue;
        walk(fullPath);
      } else if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")) {
        checkedFiles.push(fullPath);
        const code = readFileSync(fullPath, "utf8");
        let match;
        REL_IMPORT_RE.lastIndex = 0;
        while ((match = REL_IMPORT_RE.exec(code)) !== null) {
          const spec = match[1];
          const resolvedPath = resolve(dirname(fullPath), spec);
          if (!existsSync(resolvedPath)) {
            missingImports.push({ importer: fullPath, specifier: spec, resolvedPath });
          }
        }
      }
    }
  }

  walk(dir);
  if (missingImports.length > 0) {
    const first = missingImports[0];
    throw new Error(
      `[build] Broken relative import in ${first.importer}: "${first.specifier}" -> missing file ${first.resolvedPath}`
    );
  }
  return { ok: true, checkedCount: checkedFiles.length };
}

export function verifyDistAssetsExist(distDir = join(root, "dist")) {
  const indexHtmlPath = join(distDir, "index.html");
  if (!existsSync(indexHtmlPath)) {
    throw new Error(`[build] Missing production entry: ${indexHtmlPath}`);
  }
  const html = readFileSync(indexHtmlPath, "utf8");
  const refRe = /(?:href|src)=["'](\/[^"']+)["']/g;
  let m;
  const verified = [];
  while ((m = refRe.exec(html)) !== null) {
    const refPath = m[1];
    const diskPath = join(distDir, refPath.replace(/^\//, ""));
    if (!existsSync(diskPath)) {
      throw new Error(`[build] dist/index.html references missing asset "${refPath}" (expected at ${diskPath})`);
    }
    verified.push(refPath);
  }

  const manifestPath = join(distDir, "manifest.webmanifest");
  if (existsSync(manifestPath)) {
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    for (const iconObj of manifest.icons || []) {
      const src = String(iconObj.src || "");
      if (src.startsWith("/")) {
        const diskIcon = join(distDir, src.replace(/^\//, ""));
        if (!existsSync(diskIcon)) {
          throw new Error(`[build] dist/manifest.webmanifest references missing icon "${src}"`);
        }
        verified.push(src);
      }
    }
  }
  return { ok: true, verified };
}

/**
 * Offline support: stamps `dist/sw.js` with every hashed asset (JS, CSS, fonts) so the whole app shell is cached at
 * install time, and writes `dist/.assetsignore` so build-only files are not uploaded to Cloudflare.
 */
export function finalizeServiceWorker(distDir = join(root, "dist")) {
  const swPath = join(distDir, "sw.js");
  if (!existsSync(swPath)) throw new Error("[build] dist/sw.js is missing");
  const assetsDir = join(distDir, "assets");
  const files = existsSync(assetsDir) ? readdirSync(assetsDir).sort() : [];
  const urls = files.map((f) => `/assets/${f}`);
  if (!urls.some((u) => u.endsWith(".js")) || !urls.some((u) => u.endsWith(".css"))) {
    throw new Error("[build] No hashed JS/CSS found in dist/assets to precache");
  }
  const buildId = contentHash(urls.join("|") + readFileSync(join(distDir, "index.html"), "utf8"), 10);
  let sw = readFileSync(swPath, "utf8");
  if (!sw.includes("__KEYVEX_PRECACHE__") || !sw.includes("__KEYVEX_BUILD__")) {
    throw new Error("[build] public/sw.js is missing its precache placeholders");
  }
  sw = sw.replace("__KEYVEX_PRECACHE__", JSON.stringify(urls)).replaceAll("__KEYVEX_BUILD__", buildId);
  writeFileSync(swPath, sw);
  writeFileSync(join(distDir, ".assetsignore"), ".vite\n.assetsignore\n");
  return { buildId, precached: urls.length };
}

function contentHash(bufOrStr, len = 10) {
  return createHash("sha256").update(bufOrStr).digest("base64url").replace(/[^A-Za-z0-9_-]/g, "A").slice(0, len);
}

/**
 * Topological ES module bundler that combines `src/main.js` and its dependencies into a single
 * self-contained ES module bundle so `dist/assets/` contains ONLY hashed chunks (never `/assets/src/**`).
 */
function bundleEsModules(entryPath) {
  const visited = new Set();
  const ordered = [];
  const envLiteral = loadBuildEnvLiteral();

  function visit(filePath) {
    const abs = resolve(filePath);
    if (visited.has(abs)) return;
    visited.add(abs);
    if (!existsSync(abs)) {
      throw new Error(`[build] Missing source module: ${abs}`);
    }
    const code = readFileSync(abs, "utf8");
    const importRe = /(?:import|export)\s+(?:[\s\S]*?\s+from\s+)?["'](\.\.?\/[^"']+)["']/g;
    let m;
    while ((m = importRe.exec(code)) !== null) {
      const spec = m[1];
      if (spec.endsWith(".css")) {
        const cssAbs = resolve(dirname(abs), spec);
        if (!existsSync(cssAbs)) {
          throw new Error(`[build] Missing stylesheet imported by ${abs}: ${spec}`);
        }
        continue;
      }
      visit(resolve(dirname(abs), spec));
    }
    ordered.push(abs);
  }

  visit(entryPath);

  const modIndex = new Map();
  ordered.forEach((f, idx) => modIndex.set(f, idx));

  const chunks = [];
  chunks.push(`// KeyVEX v1.0.0 Production Bundle\n`);

  for (const absPath of ordered) {
    const idx = modIndex.get(absPath);
    let src = readFileSync(absPath, "utf8");

    src = src
      .replace(/^import\s+["']@fontsource[^"']+["'];?\s*$/gm, "")
      .replace(/^import\s+["']\.\/styles\/[^"']+["'];?\s*$/gm, "")
      .replace(/import\.meta\.env\?\.PROD/g, "true")
      .replace(/import\.meta\.env\.PROD/g, "true")
      .replace(/import\.meta\.env\?\.MODE/g, '"production"')
      .replace(/import\.meta\.env/g, envLiteral);

    src = src.replace(
      /import\s+([\s\S]*?)\s+from\s+["'](\.\.?\/[^"']+)["'];?/g,
      (_, clause, spec) => {
        if (spec.endsWith(".css")) return "";
        const depAbs = resolve(dirname(absPath), spec);
        const depIdx = modIndex.get(depAbs);
        if (depIdx === undefined) return "";
        const trimmed = clause.trim();
        if (trimmed.startsWith("{")) {
          const inner = trimmed
            .slice(1, -1)
            .replace(/\s+as\s+/g, ": ")
            .trim();
          return `const { ${inner} } = __mod_${depIdx};`;
        }
        return `const ${trimmed} = __mod_${depIdx}.default ?? __mod_${depIdx};`;
      }
    );

    const exportedMap = new Map();

    src = src.replace(
      /export\s+\{([^}]+)\}\s+from\s+["'](\.\.?\/[^"']+)["'];?/g,
      (_, list, spec) => {
        const depAbs = resolve(dirname(absPath), spec);
        const depIdx = modIndex.get(depAbs);
        const lines = [];
        for (const item of list.split(",")) {
          const p = item.trim();
          if (!p) continue;
          const parts = p.split(/\s+as\s+/);
          const orig = parts[0].trim();
          const alias = (parts[1] || orig).trim();
          const localTmp = `__reexp_${idx}_${alias}`;
          lines.push(`const ${localTmp} = __mod_${depIdx}.${orig};`);
          exportedMap.set(alias, localTmp);
        }
        return lines.join("\n");
      }
    );

    src = src.replace(/export\s+\{([^}]+)\};?/g, (_, list) => {
      for (const item of list.split(",")) {
        const p = item.trim();
        if (!p) continue;
        const parts = p.split(/\s+as\s+/);
        const local = parts[0].trim();
        const exported = (parts[1] || local).trim();
        exportedMap.set(exported, local);
      }
      return "";
    });

    src = src.replace(/export\s+async\s+function\s+([A-Za-z0-9_$]+)/g, (_, name) => {
      exportedMap.set(name, name);
      return `async function ${name}`;
    });
    src = src.replace(/export\s+function\s+([A-Za-z0-9_$]+)/g, (_, name) => {
      exportedMap.set(name, name);
      return `function ${name}`;
    });
    src = src.replace(/export\s+class\s+([A-Za-z0-9_$]+)/g, (_, name) => {
      exportedMap.set(name, name);
      return `class ${name}`;
    });
    src = src.replace(/export\s+(const|let|var)\s+([A-Za-z0-9_$]+)/g, (_, kw, name) => {
      exportedMap.set(name, name);
      return `${kw} ${name}`;
    });
    src = src.replace(/export\s+default\s+/g, () => {
      exportedMap.set("default", "__default_exp");
      return "const __default_exp = ";
    });

    const exportProps = [...exportedMap.entries()]
      .map(([exp, loc]) => (exp === loc ? exp : `${exp}: ${loc}`))
      .join(", ");

    chunks.push(`const __mod_${idx} = (() => {\n${src}\nreturn { ${exportProps} };\n})();\n`);
  }

  return chunks.join("\n");
}

function minifyCss(css) {
  return css
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\s+/g, " ")
    .replace(/\s*([{}:;,])\s*/g, "$1")
    .trim();
}

export function runProductionBuild({ requireViteCli = false } = {}) {
  ensureBrandsDataModule();
  validateModuleImportGraph(join(root, "src"));
  validateModuleImportGraph(join(root, "server"));

  const viteBin = join(root, "node_modules", ".bin", "vite");
  if (requireViteCli && !existsSync(viteBin)) {
    throw new Error("FATAL: vite binary is missing in node_modules/.bin/vite. Run `npm install` before building.");
  }

  if (requireViteCli && existsSync(viteBin)) {
    const res = spawnSync(viteBin, ["build"], { cwd: root, stdio: "inherit" });
    if ((res.status ?? 0) !== 0) {
      throw new Error(`vite build exited with status ${res.status}`);
    }
    verifyDistAssetsExist(join(root, "dist"));
    finalizeServiceWorker(join(root, "dist"));
    return { bundler: "vite" };
  }

  const dist = join(root, "dist");
  const assetsDir = join(dist, "assets");
  rmSync(dist, { recursive: true, force: true });
  mkdirSync(assetsDir, { recursive: true });

  // 1. Copy public/ files (favicon.svg, icon.svg, PNG icons, manifest.webmanifest, sw.js, offline.html, _headers, _redirects)
  const pubDir = join(root, "public");
  cpSync(pubDir, dist, { recursive: true }); // includes icons/<theme>/ and manifest-<theme>.webmanifest

  // 2. Copy and content-hash WOFF2 fonts (Inter & Manrope) into dist/assets/
  const fontsDir = join(root, "src", "styles", "fonts");
  const fontAssets = [];
  let fontFaceCss = "";
  if (!existsSync(fontsDir)) {
    throw new Error(`[build] Missing required fonts directory: ${fontsDir}`);
  }
  for (const f of readdirSync(fontsDir)) {
    if (!f.endsWith(".woff2")) continue;
    const buf = readFileSync(join(fontsDir, f));
    const fHash = contentHash(buf, 10);
    const base = basename(f, ".woff2");
    const hashedFontName = `${base}-${fHash}.woff2`;
    writeFileSync(join(assetsDir, hashedFontName), buf);
    fontAssets.push(`assets/${hashedFontName}`);
    const family = f.startsWith("manrope") ? "Manrope Variable" : "Inter Variable";
    fontFaceCss += `@font-face{font-family:"${family}";font-style:normal;font-display:swap;font-weight:100 900;src:url("/assets/${hashedFontName}") format("woff2");}\n`;
  }

  // 3. Bundle & minify CSS in the exact order imported by src/main.js
  const cssFiles = ["tokens.css", "base.css", "glass.css", "screens.css", "components.css"];
  for (const f of cssFiles) {
    const p = join(root, "src", "styles", f);
    if (!existsSync(p)) {
      throw new Error(`[build] Missing required stylesheet: ${p}`);
    }
  }
  const rawCss = fontFaceCss + cssFiles.map((f) => readFileSync(join(root, "src", "styles", f), "utf8")).join("\n");
  const cssContent = minifyCss(rawCss);
  const cssHash = contentHash(cssContent, 10);
  const cssFileName = `index-${cssHash}.css`;
  writeFileSync(join(assetsDir, cssFileName), cssContent);

  // 4. Bundle ES modules into a single content-hashed chunk (NO dist/assets/src/** un-hashed modules!)
  const bundledJs = bundleEsModules(join(root, "src", "main.js"));
  const jsHash = contentHash(bundledJs, 10);
  const jsFileName = `index-${jsHash}.js`;
  writeFileSync(join(assetsDir, jsFileName), bundledJs);

  // 5. Write Vite-compatible manifest so SW / tooling can inspect built assets
  const viteDir = join(dist, ".vite");
  mkdirSync(viteDir, { recursive: true });
  const manifest = {
    "index.html": {
      file: `assets/${jsFileName}`,
      name: "index",
      src: "index.html",
      isEntry: true,
      css: [`assets/${cssFileName}`],
      assets: fontAssets
    }
  };
  writeFileSync(join(viteDir, "manifest.json"), JSON.stringify(manifest, null, 2));

  // 6. Transform index.html with unified META_CSP and hashed asset links
  let html = readFileSync(join(root, "index.html"), "utf8");
  html = html
    .replace('<meta name="referrer"', `<meta http-equiv="Content-Security-Policy" content="${META_CSP}" />\n  <meta name="referrer"`)
    .replace("</head>", `  <link rel="stylesheet" crossorigin href="/assets/${cssFileName}" />\n  <script type="module" crossorigin src="/assets/${jsFileName}"></script>\n</head>`)
    .replace(/\s*<script type="module" src="\/src\/main\.js"><\/script>/, "");
  writeFileSync(join(dist, "index.html"), html);

  // 7. Strictly verify every referenced asset in dist/index.html and dist/manifest.webmanifest exists
  verifyDistAssetsExist(dist);
  const swInfo = finalizeServiceWorker(dist);

  console.log(`[build] Service worker stamped: build ${swInfo.buildId}, ${swInfo.precached} asset(s) precached for offline use`);
  console.log(`[build] Built dist/index.html, dist/assets/${cssFileName}, dist/assets/${jsFileName}, and ${fontAssets.length} hashed font(s)`);
  return { bundler: "vite-compatible", cssFileName, jsFileName, fontAssets };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runProductionBuild();
}
