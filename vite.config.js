import { defineConfig } from "vite";
import { META_CSP } from "./scripts/csp.mjs";

export { META_CSP };

const productionCsp = () => ({
  name: "keyvex-csp",
  apply: "build",
  transformIndexHtml: (html) =>
    html.replace(
      '<meta name="referrer"',
      `<meta http-equiv="Content-Security-Policy" content="${META_CSP}" />\n  <meta name="referrer"`
    )
});

export default defineConfig({
  plugins: [productionCsp()],
  server: { proxy: { "/api": { target: process.env.API_URL || "http://localhost:8787", changeOrigin: false } } },
  build: { target: "es2022", sourcemap: false, assetsInlineLimit: 0, manifest: true },
  test: { environment: "node", include: ["tests/**/*.test.js"], testTimeout: 30_000 }
});
