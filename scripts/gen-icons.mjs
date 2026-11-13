/**
 * Generates the per-theme installable-app assets into /public:
 *   public/icons/<theme>/icon.svg, icon-192.png, icon-512.png, icon-maskable-512.png, apple-touch-icon.png
 *   public/manifest-<theme>.webmanifest   (+ default manifest.webmanifest / icon.svg / favicon.svg = ocean)
 * Run:  node scripts/gen-icons.mjs      (needs Playwright's Chromium — only for a one-off PNG render)
 */
import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { LOGO_THEMES, logoSvg, themeBg } from "../src/ui/logo.js";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const PUB = new URL("../public/", import.meta.url).pathname;

const browser = await chromium.launch();
const page = await browser.newPage();
async function png(svg, size) {
  await page.setViewportSize({ width: size, height: size });
  await page.setContent(`<style>html,body{margin:0;background:transparent}svg{display:block;width:${size}px;height:${size}px}</style>${svg}`);
  return page.screenshot({ omitBackground: true, clip: { x: 0, y: 0, width: size, height: size } });
}

const base = JSON.parse(readFileSync(PUB + "manifest.webmanifest", "utf8"));
for (const theme of LOGO_THEMES) {
  const dir = `${PUB}icons/${theme}/`;
  mkdirSync(dir, { recursive: true });
  const round = logoSvg(theme, { id: "a" });
  writeFileSync(dir + "icon.svg", round);
  writeFileSync(dir + "icon-192.png", await png(round, 192));
  writeFileSync(dir + "icon-512.png", await png(round, 512));
  writeFileSync(dir + "icon-maskable-512.png", await png(logoSvg(theme, { id: "m", rounded: false, scale: 0.78 }), 512));
  writeFileSync(dir + "apple-touch-icon.png", await png(logoSvg(theme, { id: "t", rounded: false }), 180));
  const p = `/icons/${theme}/`;
  const manifest = {
    ...base,
    theme_color: themeBg(theme),
    background_color: themeBg(theme),
    icons: [
      { src: p + "icon.svg", sizes: "any", type: "image/svg+xml", purpose: "any" },
      { src: p + "icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
      { src: p + "icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
      { src: p + "icon-maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" }
    ]
  };
  writeFileSync(`${PUB}manifest-${theme}.webmanifest`, JSON.stringify(manifest, null, 2) + "\n");
  if (theme === "ocean") {
    // Defaults used before JS runs / by crawlers: the Ocean (default) colourway.
    writeFileSync(PUB + "manifest.webmanifest", JSON.stringify(manifest, null, 2) + "\n");
    writeFileSync(PUB + "icon.svg", round);
    writeFileSync(PUB + "favicon.svg", round);
    writeFileSync(PUB + "icon-192.png", readFileSync(dir + "icon-192.png"));
    writeFileSync(PUB + "icon-512.png", readFileSync(dir + "icon-512.png"));
    writeFileSync(PUB + "icon-maskable-512.png", readFileSync(dir + "icon-maskable-512.png"));
    writeFileSync(PUB + "apple-touch-icon.png", readFileSync(dir + "apple-touch-icon.png"));
  }
}
await browser.close();
console.log("icons generated for:", LOGO_THEMES.join(", "));
