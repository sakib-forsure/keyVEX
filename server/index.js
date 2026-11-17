import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createApp } from "./app.js";

const here = dirname(fileURLToPath(import.meta.url));
const env = process.env;
const production = env.NODE_ENV === "production";
const port = Number(env.PORT || 5173);
const host = env.HOST || "0.0.0.0";

const app = createApp({
  dbPath: env.DATABASE_PATH || join(here, "..", "data", "keyvex.db"),
  staticDir: env.STATIC_DIR || join(here, "..", "dist"),
  production,
  requireNativeSqlite: production || env.REQUIRE_NATIVE_SQLITE === "true",
  multiInstance: env.MULTI_INSTANCE === "true",
  trustProxy: Number(env.TRUST_PROXY || 0),
  allowedOrigin: env.ALLOWED_ORIGIN || "",
  log: (level, err) => console.error(`[${level}]`, err?.code || err?.message || "Internal server error")
});

app.server.listen(port, host, () => console.log(`KeyVEX listening on http://${host}:${port} (${production ? "production" : "development"})`));

const stop = (sig) => { console.log(`${sig} received, shutting down…`); app.close().then(() => process.exit(0)); setTimeout(() => process.exit(1), 10_000).unref(); };
process.on("SIGTERM", () => stop("SIGTERM"));
process.on("SIGINT", () => stop("SIGINT"));
process.on("unhandledRejection", (e) => console.error("[unhandledRejection]", e?.code || e?.message || "Unhandled rejection"));
