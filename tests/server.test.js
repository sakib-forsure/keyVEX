import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startServer, PIN, MASTER } from "./helpers.js";
import { deriveCredentials } from "../src/core/crypto.js";

const post = (srv, path, body, headers = {}) =>
  fetch(srv.base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body)
  }).catch((err) => ({ status: 413, error: err }));

describe("HTTP API hardening", () => {
  let srv, dir;
  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), "keyvex-"));
    mkdirSync(join(dir, "assets"));
    writeFileSync(join(dir, "index.html"), "<!doctype html><title>KeyVEX</title>");
    writeFileSync(join(dir, "assets", "app-a1b2c3d4.js"), "1");
    writeFileSync(join(dir, "assets", "unhashed.js"), "1");
    writeFileSync(join(dir, "..", "keyvex-secret.txt"), "outside");
    srv = await startServer({ staticDir: dir, production: true });
  });
  afterEach(() => srv.close());

  it("sets strict security headers on every response", async () => {
    for (const path of ["/api/health", "/", "/nope.js"]) {
      const r = await fetch(srv.base + path);
      expect(r.headers.get("content-security-policy")).toContain("default-src 'self'");
      expect(r.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
      expect(r.headers.get("x-content-type-options")).toBe("nosniff");
      expect(r.headers.get("x-frame-options")).toBe("DENY");
      expect(r.headers.get("referrer-policy")).toBe("no-referrer");
      expect(r.headers.get("strict-transport-security")).toContain("max-age=");
    }
    expect((await fetch(srv.base + "/api/health")).headers.get("cache-control")).toBe("no-store");
  });

  it("serves the app with sensible caching (immutable ONLY for 8+ char hashed assets), falls back to index.html, 404s missing files", async () => {
    expect((await fetch(srv.base + "/")).headers.get("cache-control")).toBe("no-cache");
    expect((await fetch(srv.base + "/assets/app-a1b2c3d4.js")).headers.get("cache-control")).toContain("immutable");
    expect((await fetch(srv.base + "/assets/unhashed.js")).headers.get("cache-control")).toBe("no-cache");
    expect(await (await fetch(srv.base + "/some/route")).text()).toContain("KeyVEX");
    expect((await fetch(srv.base + "/missing.js")).status).toBe(404);
  });

  it("refuses path traversal", async () => {
    for (const p of ["/../keyvex-secret.txt", "/%2e%2e/keyvex-secret.txt", "/..%2fkeyvex-secret.txt", "/assets/../../keyvex-secret.txt"]) {
      const r = await fetch(srv.base + p);
      expect(await r.text()).not.toContain("outside");
    }
    const raw = await new Promise((ok) => { import("node:net").then(({ connect }) => { const s = connect(srv.server.address().port, "127.0.0.1", () => s.write("GET /../keyvex-secret.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); let d = ""; s.on("data", (c) => (d += c)); s.on("close", () => ok(d)); }); });
    expect(raw).not.toContain("outside");
  });

  it("requires JSON, caps body size, rejects malformed JSON", async () => {
    expect((await post(srv, "/api/login", "x=1", { "Content-Type": "text/plain" })).status).toBe(415);
    expect((await post(srv, "/api/login", "{nope")).status).toBe(400);
    expect((await post(srv, "/api/login", JSON.stringify({ pad: "x".repeat(3 * 1024 * 1024) }))).status).toBe(413);
  });

  it("validates every field strictly", async () => {
    const good = await deriveCredentials(PIN, MASTER);
    for (const body of [{}, { lookup: "short", auth: good.auth }, { lookup: good.lookup, auth: 5 }, { lookup: good.lookup + "!", auth: good.auth }]) {
      const r = await post(srv, "/api/login", body);
      expect(r.status).toBe(400);
    }
    expect((await post(srv, "/api/register", { lookup: good.lookup, auth: good.auth, meta: { format: 6 } })).status).toBe(400);
    expect((await post(srv, "/api/register", { lookup: good.lookup, auth: good.auth, meta: "x" })).status).toBe(400);
  });

  it("refuses cross-origin writes and unauthenticated access (checking auth before parsing body, B9e)", async () => {
    expect((await post(srv, "/api/login", {}, { Origin: "https://evil.example" })).status).toBe(403);
    for (const [m, p] of [["GET", "/api/vault"], ["POST", "/api/logout"], ["PUT", "/api/entries/abcdefgh"], ["DELETE", "/api/entries/abcdefgh"], ["POST", "/api/entries/batch"], ["POST", "/api/account/credentials"]]) {
      const r = await fetch(srv.base + p, { method: m, headers: { "Content-Type": "application/json", Authorization: "Bearer " + "A".repeat(43) }, body: m === "GET" || m === "DELETE" ? undefined : "{}" });
      expect(r.status).toBe(401);
    }
    // Unauthenticated malformed body returns 401 before body parsing
    const unauthBadJson = await fetch(srv.base + "/api/entries/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{not-json"
    });
    expect(unauthBadJson.status).toBe(401);
    expect((await fetch(srv.base + "/api/vault")).status).toBe(401);
    expect((await fetch(srv.base + "/api/nope")).status).toBe(401);
  });

  it("validates entry ids and sizes once signed in", async () => {
    const v = srv.newVault(); await v.register(PIN, MASTER);
    const api = v.api;
    await expect(api.putEntry({ id: "../etc", iv: "AAAA", data: "AAAA" })).rejects.toMatchObject({ status: 400 });
    await expect(api.putEntry({ id: "abcdefgh", iv: "AAAA", data: "A".repeat(200_000) })).rejects.toMatchObject({ status: 400 });
    await expect(api.putEntries([])).rejects.toMatchObject({ status: 400 });
    await expect(api.putEntries(Array.from({ length: 501 }, (_, i) => ({ id: "entry" + String(i).padStart(5, "0"), iv: "AAAA", data: "AAAA" })))).rejects.toMatchObject({ status: 400 });
    await expect(api.putEntry({ id: "abcdefgh", iv: "AAAA", data: "AAAA" })).resolves.toBeTruthy();
  });

  it("one account can never touch another account's entries", async () => {
    const a = srv.newVault(); await a.register(PIN, MASTER); const e = await a.save({ service: "Mine", password: "pw" });
    const b = srv.newVault(); await b.register("7392", "Green Tea Mountain 77?");
    await b.api.deleteEntry(e.id);                                  // 204 but only affects b's own (empty) set
    await b.api.putEntry({ id: e.id, iv: "AAAA", data: "AAAA" });    // creates b's own record with the same id
    a.lock(); await a.signIn(PIN, MASTER);
    expect(a.list()[0].service).toBe("Mine");
  });

  it("rate-limits registration per address", async () => {
    const results = [];
    for (let i = 0; i < 12; i++) {
      const c = await deriveCredentials("48291" + (i % 10), MASTER + i);
      results.push((await post(srv, "/api/register", { lookup: c.lookup, auth: c.auth, meta: {} })).status);
    }
    expect(results.slice(0, 10).every((s) => s === 400)).toBe(true);   // validated (and counted) …
    expect(results.slice(10)).toEqual([429, 429]);                      // … then limited
  });

  it("expired sessions are refused", async () => {
    const v = srv.newVault(); await v.register(PIN, MASTER);
    srv.db.prepare("UPDATE sessions SET expires_at = ?").run(Date.now() - 1000);
    await expect(v.api.fetchVault()).rejects.toMatchObject({ status: 401, code: "SESSION_EXPIRED" });
  });
});
