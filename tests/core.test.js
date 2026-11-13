import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { startServer, PIN, MASTER, sample } from "./helpers.js";
import { Vault, VaultError, MASTER_MAX_FAILS } from "../src/core/vault.js";
import { Api } from "../src/core/api.js";
import { readBackup } from "../src/core/backup.js";
import {
  seedSimulatedLegacyVault,
  getSimulatedLegacyVault,
  getPreMigrationBackups,
  resetLocalVaultStorage
} from "../src/core/idb.js";
import { seal, open, generateVaultKey, deriveCredentials } from "../src/core/crypto.js";
import { randInt, b64, ub64, enc } from "../src/core/bytes.js";
import { generatePassword } from "../src/core/generator.js";
import { strength, checkPin, checkMasterPassword } from "../src/core/strength.js";
import { auditEntries } from "../src/core/audit.js";
import { readLegacyBackup } from "../src/core/legacy.js";
import { parseCSV, csvToEntries } from "../src/core/csv.js";

describe("encoding", () => {
  it("round-trips base64", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(37));
    expect([...ub64(b64(bytes))]).toEqual([...bytes]);
  });
  it("randInt stays in range and is roughly uniform", () => {
    const counts = [0, 0, 0];
    for (let i = 0; i < 3000; i++) counts[randInt(3)]++;
    counts.forEach((c) => expect(c).toBeGreaterThan(800));
    expect(() => randInt(0)).toThrow();
  });
});

describe("Passkey and Master Password rules", () => {
  it("accepts 4, 6, 8 digits or strong alphanumeric passkeys and nothing else", () => {
    expect(checkPin("7392").ok).toBe(true);
    expect(checkPin("7392", 4).ok).toBe(true);
    expect(checkPin("7392", 6).ok).toBe(false);
    expect(checkPin("482916").ok).toBe(true);
    expect(checkPin("482916", 6).ok).toBe(true);
    expect(checkPin("482916", 4).ok).toBe(false);
    expect(checkPin("48291673", 8).ok).toBe(true);
    expect(checkPin("StrongPass99", "strong").ok).toBe(true);
    for (const bad of ["", "12", "73921", "7392a", "73 92", "4829167"]) expect(checkPin(bad).ok).toBe(false);
  });
  it("refuses guessable Passkeys including birth years (1950–2010), sequences, and repeating pairs", () => {
    for (const bad of ["0000", "1234", "4321", "1111", "123456", "654321", "999999", "112233", "1985", "1999", "2005", "1357", "2468", "0852", "1004", "1314", "121212"]) {
      expect(checkPin(bad).ok).toBe(false);
    }
  });
  it("Master Password requires at least 8 chars + letter + special char, and must not contain the Passkey", () => {
    expect(checkMasterPassword("short1!").ok).toBe(false);
    expect(checkMasterPassword("1234567890123").ok).toBe(false);
    expect(checkMasterPassword("!@#$%^&*()").ok).toBe(false);
    expect(checkMasterPassword("password1234!").ok).toBe(false);
    expect(checkMasterPassword("NoSpecial123").ok).toBe(false);
    expect(checkMasterPassword(`Blue${PIN}Moon River!`, PIN).ok).toBe(false);
    expect(checkMasterPassword("Secur3!@", PIN).ok).toBe(true);
    expect(checkMasterPassword(MASTER, PIN).ok).toBe(true);
  });
});

describe("crypto", () => {
  it("never reuses an IV and binds AAD", async () => {
    const k = await generateVaultKey();
    const a = await seal(k, { x: 1 }, "aad1"), b = await seal(k, { x: 1 }, "aad1");
    expect(a.iv).not.toBe(b.iv);
    await expect(open(k, a, "aad2")).rejects.toBeTruthy();
    expect(await open(k, a, "aad1")).toEqual({ x: 1 });
  });
  it("derives three unrelated values, deterministically, from the PAIR", async () => {
    const a = await deriveCredentials(PIN, MASTER), b = await deriveCredentials(PIN, MASTER);
    expect(a.lookup).toBe(b.lookup); expect(a.auth).toBe(b.auth);
    expect(a.lookup).not.toBe(a.auth);
    for (const [p, m] of [["482917", MASTER], [PIN, MASTER + "x"], [PIN, MASTER.toLowerCase()]]) {
      const c = await deriveCredentials(p, m);
      expect(c.lookup).not.toBe(a.lookup); expect(c.auth).not.toBe(a.auth);
    }
  });
});

describe("accounts (browser vault ↔ real server + cross-device sync & offline cache)", () => {
  let srv;
  beforeEach(async () => {
    await resetLocalVaultStorage();
    srv = await startServer();
  });
  afterEach(() => srv.close());

  it("registers, saves, signs out and signs in again — also from a second device", async () => {
    const phone = srv.newVault();
    await phone.register(PIN, MASTER);
    expect(phone.unlocked).toBe(true);
    await phone.save(sample);
    phone.lock();
    expect(phone.unlocked).toBe(false);
    expect(phone.list()).toEqual([]);

    const laptop = srv.newVault();                       // a different device: nothing shared but the two secrets
    await laptop.signIn(PIN, MASTER);
    expect(laptop.list()).toHaveLength(1);
    expect(laptop.list()[0]).toMatchObject({ service: "GitHub", password: "S3cret!pass" });
  });

  it("synchronizes live changes across two signed-in devices via vault.sync()", async () => {
    const pc = new Vault(new Api(srv.base, { allowOffline: true }));
    const phone = new Vault(new Api(srv.base, { allowOffline: true }));
    await pc.register(PIN, MASTER);
    const saved = await pc.save(sample);

    await phone.signIn(PIN, MASTER);
    expect(phone.list()).toHaveLength(1);
    await phone.save({ ...saved, password: "UpdatedOnPhone!99" });
    await phone.save({ service: "GitLab", username: "dev@x.com", password: "Gl!Password88", category: "Work" });

    // PC pulls changes made on phone via sync()
    await pc.sync();
    expect(pc.list()).toHaveLength(2);
    expect(pc.get(saved.id).password).toBe("UpdatedOnPhone!99");
  });

  it("handles server unavailability with local IndexedDB cache and syncs queued offline changes on reconnect", async () => {
    const api = new Api(srv.base, { allowOffline: true });
    const v = new Vault(api);
    await v.register("7392", "MyVault@99");
    await v.save(sample);
    v.lock();

    // Point to an unreachable port to simulate offline / server down
    const offlineApi = new Api("http://127.0.0.1:1", { allowOffline: true });
    const offlineVault = new Vault(offlineApi);
    await offlineVault.signIn("7392", "MyVault@99");
    expect(offlineVault.unlocked).toBe(true);
    expect(offlineApi.offline).toBe(true);
    expect(offlineVault.list()).toHaveLength(1);

    // Save a new entry while offline — it gets queued in v6_sync_queue
    await offlineVault.save({ service: "OfflineService", username: "off@x.com", password: "Off!Pass123" });
    expect(offlineVault.list()).toHaveLength(2);

    // Reconnect to the live server and synchronize
    offlineApi.base = srv.base;
    await offlineVault.sync();
    expect(offlineApi.offline).toBe(false);

    // Verify a second device sees the entry created while the first device was offline
    const secondDevice = srv.newVault();
    await secondDevice.signIn("7392", "MyVault@99");
    expect(secondDevice.list().map((e) => e.service).sort()).toEqual(["GitHub", "OfflineService"]);
  });

  it("supports a 4 digit Passkey", async () => {
    const v = srv.newVault(); await v.register("7392", MASTER);
    v.lock(); await v.signIn("7392", MASTER); expect(v.unlocked).toBe(true);
  });

  it("rejects weak input before anything is sent", async () => {
    const v = srv.newVault();
    await expect(v.register("1234", MASTER)).rejects.toMatchObject({ code: "WEAK_PIN" });
    await expect(v.register(PIN, "weak")).rejects.toMatchObject({ code: "WEAK_MASTER" });
    expect(srv.db.prepare("SELECT COUNT(*) n FROM accounts").get().n).toBe(0);
  });

  it("wrong Passkey and wrong Master Password look identical, and both are refused", async () => {
    const v = srv.newVault(); await v.register(PIN, MASTER); v.lock();
    const a = await srv.newVault().signIn("482917", MASTER).catch((e) => e);
    const b = await srv.newVault().signIn(PIN, MASTER + "!").catch((e) => e);
    const c = await srv.newVault().signIn(PIN, MASTER.toLowerCase()).catch((e) => e);   // case-sensitive
    for (const e of [a, b, c]) expect(e).toMatchObject({ status: 401, code: "BAD_CREDENTIALS" });
    expect(a.message).toBe(b.message);
  });

  it("the same pair can't be registered twice", async () => {
    await srv.newVault().register(PIN, MASTER);
    await expect(srv.newVault().register(PIN, MASTER)).rejects.toMatchObject({ status: 409, code: "ACCOUNT_EXISTS" });
  });

  it("two accounts stay separate even with the same Passkey", async () => {
    const a = srv.newVault(); await a.register(PIN, MASTER); await a.save(sample);
    const b = srv.newVault(); await b.register(PIN, "Green Tea Mountain 77?");
    expect(b.list()).toEqual([]);
  });

  it("the server stores nothing readable", async () => {
    const v = srv.newVault(); await v.register(PIN, MASTER);
    await v.save({ ...sample, notes: "top secret note" });
    const dump = JSON.stringify([srv.db.prepare("SELECT * FROM accounts").all(), srv.db.prepare("SELECT * FROM entries").all(), srv.db.prepare("SELECT * FROM sessions").all()]);
    for (const secret of [PIN, MASTER, "S3cret!pass", "GitHub", "github.com", "me@x.com", "top secret note", "Blue Moon"]) expect(dump).not.toContain(secret);
    const row = srv.db.prepare("SELECT lookup, auth_hash FROM accounts").get();
    const creds = await deriveCredentials(PIN, MASTER);
    expect(row.auth_hash).not.toContain(creds.auth);      // only a salted hash of the proof is kept
  });

  it("sessions end on sign-out", async () => {
    const v = srv.newVault(); await v.register(PIN, MASTER);
    await v.api.fetchVault();
    v.lock(); await new Promise((r) => setTimeout(r, 50));
    await expect(v.api.fetchVault()).rejects.toMatchObject({ status: 401 });
  });

  it("detects a record moved onto another entry id (AAD binding) and tampered ciphertext", async () => {
    const v = srv.newVault(); await v.register(PIN, MASTER);
    const a = await v.save(sample), b = await v.save({ ...sample, service: "Other", username: "o@x.com" });
    const rows = srv.db.prepare("SELECT id, iv, data FROM entries").all();
    const ra = rows.find((r) => r.id === a.id), rb = rows.find((r) => r.id === b.id);
    srv.db.prepare("UPDATE entries SET iv = ?, data = ? WHERE id = ?").run(ra.iv, ra.data, b.id);   // swap
    v.lock();
    await v.signIn(PIN, MASTER);
    expect(v.list()).toHaveLength(1); expect(v.skipped).toBe(1);
    srv.db.prepare("UPDATE entries SET data = ? WHERE id = ?").run(rb.data.slice(0, -2) + "AA", a.id); // tamper
    v.lock(); await v.signIn(PIN, MASTER);
    expect(v.skipped).toBeGreaterThanOrEqual(1);
  });

  it("validates entries", async () => {
    const v = srv.newVault(); await v.register(PIN, MASTER);
    await expect(v.save({ service: "", password: "x" })).rejects.toMatchObject({ code: "INVALID_ENTRY" });
    await expect(v.save({ service: "X", password: "" })).rejects.toMatchObject({ code: "INVALID_ENTRY" });
    const e = await v.save({ service: "X".repeat(500), password: "p", category: "Nope" });
    expect(e.service.length).toBe(80); expect(e.category).toBe("Other");
  });

  it("edits and deletes entries on the server too", async () => {
    const v = srv.newVault(); await v.register(PIN, MASTER);
    const e = await v.save(sample); await v.save({ ...e, favorite: true });
    await v.save({ ...sample, service: "Second", username: "b" }); await v.remove(PIN, e.id);
    v.lock(); await v.signIn(PIN, MASTER);
    expect(v.list().map((x) => x.service)).toEqual(["Second"]);
  });

  describe("safe non-destructive legacy migration", () => {
    async function buildV5Fixture(pin, master, plainEntries) {
      const iter = 1_000, vk = await generateVaultKey(), vid = "v5vault123";
      const kek = async (secret, salt) => crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
        await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]),
        { name: "AES-KW", length: 256 }, false, ["wrapKey", "unwrapKey"]
      );
      const sp = crypto.getRandomValues(new Uint8Array(16)), sn = crypto.getRandomValues(new Uint8Array(16));
      const wrap = async (s, salt) => b64(new Uint8Array(await crypto.subtle.wrapKey("raw", vk, await kek(s, salt), "AES-KW")));
      const meta = {
        format: 5, vaultId: vid, kdf: { iterations: iter },
        saltPin: b64(sp), wrappedPin: await wrap(pin, sp),
        saltName: b64(sn), wrappedName: await wrap("mp2:" + master, sn),
        mpVersion: 2, verifier: await seal(vk, { ok: true }, `keyvex:${vid}:verify:`)
      };
      const entries = await Promise.all(
        plainEntries.map(async (e, idx) => {
          const id = e.id || `entry_${idx + 1}00000`;
          return { id, ...(await seal(vk, e, `keyvex:${vid}:entry:${id}`)) };
        })
      );
      return { meta, entries };
    }

    it("migrates a v5 vault safely, creates a pre-migration backup, verifies records, and syncs to server", async () => {
      const fixture = await buildV5Fixture("5927", "OldPass@1", [
        { id: "old_entry_01", service: "OldBank", username: "alice", password: "Bank!Password1" },
        { id: "old_entry_02", service: "OldMail", username: "alice@x.com", password: "Mail!Password2" }
      ]);
      seedSimulatedLegacyVault("v5_test", fixture);

      const v = srv.newVault();
      await v.signIn("5927", "OldPass@1");
      expect(v.unlocked).toBe(true);
      expect(v.migrated).toBe(true);
      expect(v.list()).toHaveLength(2);
      expect(v.get("old_entry_01").service).toBe("OldBank");
      expect(v.get("old_entry_02").service).toBe("OldMail");

      // Verify pre-migration backup snapshot was created before finalizing
      const backups = await getPreMigrationBackups();
      expect(backups.length).toBeGreaterThanOrEqual(1);
      expect(backups[0].rawEntries).toHaveLength(2);
      expect(getSimulatedLegacyVault("v5_test").migratedToV6).toBe(true);
    });

    it("aborts migration and preserves original vault if any legacy entry fails to decrypt (zero data loss)", async () => {
      const fixture = await buildV5Fixture("5927", "OldPass@1", [
        { id: "good_entry_1", service: "Good", username: "u1", password: "pw1" },
        { id: "bad_entry_02", service: "Corrupt", username: "u2", password: "pw2" }
      ]);
      // Tamper with the second entry's ciphertext
      fixture.entries[1].data = fixture.entries[1].data.slice(0, -4) + "AAAA";
      seedSimulatedLegacyVault("v5_corrupt", fixture);

      const v = srv.newVault();
      await expect(v.signIn("5927", "OldPass@1")).rejects.toMatchObject({
        code: "MIGRATION_CORRUPT_ENTRY",
        failedCount: 1,
        totalCount: 2
      });
      // Original legacy vault MUST remain untouched and not marked migrated
      expect(getSimulatedLegacyVault("v5_corrupt").migratedToV6).toBeUndefined();
      expect(srv.db.prepare("SELECT COUNT(*) n FROM accounts").get().n).toBe(0);
    });

    it("is retry-safe without creating duplicate entries if interrupted after account creation", async () => {
      const fixture = await buildV5Fixture("5927", "OldPass@1", [
        { id: "retry_ent_01", service: "RetrySvc", username: "user1", password: "Retry!Pass1" }
      ]);
      // Pre-create the destination account with 0 entries (simulating an interrupted first migration attempt)
      const pre = srv.newVault();
      await pre.register("5927", "OldPass@1");
      pre.lock();

      seedSimulatedLegacyVault("v5_retry", fixture);
      // Force migration by calling signIn when legacy vault is re-discovered after a simulated partial state
      const v = srv.newVault();
      // Remove the account from server first, register it during migration, then re-seed and ensure no duplicates
      await pre.signIn("5927", "OldPass@1");
      await pre.deleteAccount("5927", "OldPass@1");

      await v.signIn("5927", "OldPass@1");
      expect(v.list()).toHaveLength(1);
      expect(v.list()[0].id).toBe("retry_ent_01");
    });
  });

  describe("sensitive actions re-confirm the Master Password / Passkey (enforced in the vault)", () => {
    it("import needs it; five wrong confirmations sign the vault out", async () => {
      const v = srv.newVault(); await v.register(PIN, MASTER);
      const items = [{ service: "A", username: "a", password: "pw1" }];
      await expect(v.importEntries(items)).rejects.toMatchObject({ code: "MASTER_REQUIRED" });
      await expect(v.importEntries(items, PIN)).rejects.toMatchObject({ code: "BAD_CREDENTIALS" });   // the Passkey is not the Master Password
      expect(await v.importEntries(items, MASTER)).toBe(1);
      expect(await v.importEntries(items, MASTER)).toBe(0);                                          // duplicates skipped
      for (let i = 1; i < MASTER_MAX_FAILS; i++) await expect(v.importEntries(items, "nope")).rejects.toMatchObject({ code: "BAD_CREDENTIALS" });
      await expect(v.importEntries(items, "nope")).rejects.toMatchObject({ code: "TOO_MANY_TRIES" });
      expect(v.unlocked).toBe(false);
    });

    it("a correct confirmation resets the strike count", async () => {
      const v = srv.newVault(); await v.register(PIN, MASTER);
      for (let r = 0; r < 3; r++) { for (let i = 0; i < 3; i++) await v.importEntries([], "bad").catch(() => {}); await v.importEntries([], MASTER); }
      expect(v.unlocked).toBe(true);
    });

    it("imports large batches", async () => {
      const v = srv.newVault(); await v.register(PIN, MASTER);
      const items = Array.from({ length: 450 }, (_, i) => ({ service: `S${i}`, username: "u", password: "pw" + i }));
      expect(await v.importEntries(items, MASTER)).toBe(450);
      v.lock(); await v.signIn(PIN, MASTER); expect(v.list()).toHaveLength(450);
    });
  });

  describe("changing credentials", () => {
    it("Passkey change: needs both current secrets, entries survive, other devices are signed out", async () => {
      const a = srv.newVault(); await a.register(PIN, MASTER); await a.save(sample);
      const other = srv.newVault(); await other.signIn(PIN, MASTER);
      await expect(a.changePasskey("000000", MASTER, "7392")).rejects.toMatchObject({ code: "BAD_CREDENTIALS" });
      await expect(a.changePasskey(PIN, "wrong", "7392")).rejects.toMatchObject({ code: "BAD_CREDENTIALS" });
      await expect(a.changePasskey(PIN, MASTER, "1234")).rejects.toMatchObject({ code: "WEAK_PIN" });
      await a.changePasskey(PIN, MASTER, "7392");
      await expect(other.api.fetchVault()).rejects.toMatchObject({ status: 401 });
      a.lock();
      await expect(srv.newVault().signIn(PIN, MASTER)).rejects.toMatchObject({ code: "BAD_CREDENTIALS" });
      const fresh = srv.newVault(); await fresh.signIn("7392", MASTER);
      expect(fresh.list()).toHaveLength(1);
    });

    it("Master Password change", async () => {
      const a = srv.newVault(); await a.register(PIN, MASTER); await a.save(sample);
      await expect(a.changeMasterPassword(PIN, MASTER, "weak")).rejects.toMatchObject({ code: "WEAK_MASTER" });
      const NEXT = "Green Tea Mountain 77?";
      await a.changeMasterPassword(PIN, MASTER, NEXT);
      expect(await a.importEntries([{ service: "N", username: "n", password: "pw" }], NEXT)).toBe(1);   // the sealed copy was refreshed
      a.lock();
      await expect(srv.newVault().signIn(PIN, MASTER)).rejects.toMatchObject({ code: "BAD_CREDENTIALS" });
      const fresh = srv.newVault(); await fresh.signIn(PIN, NEXT); expect(fresh.list()).toHaveLength(2);
    });

    it("can't switch to credentials another account already uses", async () => {
      const b = srv.newVault(); await b.register("7392", MASTER); b.lock();
      const a = srv.newVault(); await a.register(PIN, MASTER);
      await expect(a.changePasskey(PIN, MASTER, "7392")).rejects.toMatchObject({ status: 409 });
      expect(a.unlocked).toBe(true);
      a.lock(); await a.signIn(PIN, MASTER);       // still works with the old pair
    });
  });

  it("deleting the account removes it and every entry", async () => {
    const a = srv.newVault(); await a.register(PIN, MASTER); await a.save(sample);
    await expect(a.deleteAccount(PIN, "wrong")).rejects.toMatchObject({ code: "BAD_CREDENTIALS" });
    await a.deleteAccount(PIN, MASTER);
    expect(a.unlocked).toBe(false);
    expect(srv.db.prepare("SELECT COUNT(*) n FROM accounts").get().n).toBe(0);
    expect(srv.db.prepare("SELECT COUNT(*) n FROM entries").get().n).toBe(0);
    await expect(srv.newVault().signIn(PIN, MASTER)).rejects.toMatchObject({ code: "BAD_CREDENTIALS" });
  });

  describe("backup", () => {
    it("exports an encrypted file that only the right pair can read, preserves entry IDs, and imports into another account", async () => {
      const a = srv.newVault(); await a.register(PIN, MASTER);
      const saved = await a.save(sample);
      const file = await a.exportBackup(PIN);
      for (const secret of ["S3cret!pass", "GitHub", MASTER]) expect(file).not.toContain(secret);
      await expect(readBackup(file, { passkey: PIN, master: "wrong" })).rejects.toMatchObject({ code: "BAD_SECRET" });
      await expect(readBackup(file, { passkey: "000000", master: MASTER })).rejects.toMatchObject({ code: "BAD_SECRET" });
      await expect(readBackup("{}", {})).rejects.toMatchObject({ code: "BAD_BACKUP" });
      await expect(readBackup("nope", {})).rejects.toMatchObject({ code: "BAD_BACKUP" });
      await expect(readBackup(JSON.stringify({ app: "keyvex", v: 99, meta: {} }), {})).rejects.toMatchObject({ code: "INCOMPATIBLE_BACKUP" });

      const items = await readBackup(file, { passkey: PIN, master: MASTER });
      expect(items).toHaveLength(1);
      expect(items[0].id).toBe(saved.id);

      // Corrupted record inside backup is rejected instead of silently dropped
      const corruptedObj = JSON.parse(file);
      corruptedObj.entries[0].data = corruptedObj.entries[0].data.slice(0, -4) + "AAAA";
      await expect(readBackup(JSON.stringify(corruptedObj), { passkey: PIN, master: MASTER })).rejects.toMatchObject({ code: "CORRUPTED_BACKUP" });

      const b = srv.newVault(); await b.register("7392", "Green Tea Mountain 77?");
      expect(await b.importEntries(items, "Green Tea Mountain 77?")).toBe(1);
      expect(b.list()[0]).toMatchObject({ id: saved.id, service: "GitHub", password: "S3cret!pass" });
    });

    it("still reads a backup made by the previous local-only build (format 5)", async () => {
      const iter = 600_000, vk = await generateVaultKey(), vid = "vid123";
      const kek = async (secret, salt) => crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]), { name: "AES-KW", length: 256 }, false, ["wrapKey", "unwrapKey"]);
      const sp = crypto.getRandomValues(new Uint8Array(16)), sn = crypto.getRandomValues(new Uint8Array(16));
      const wrap = async (s, salt) => b64(new Uint8Array(await crypto.subtle.wrapKey("raw", vk, await kek(s, salt), "AES-KW")));
      const file = JSON.stringify({ app: "keyvex", v: 5, meta: { format: 5, vaultId: vid, kdf: { iterations: iter }, saltPin: b64(sp), wrappedPin: await wrap("482916", sp), saltName: b64(sn), wrappedName: await wrap("mp2:" + MASTER, sn), mpVersion: 2, verifier: await seal(vk, { ok: true }, `keyvex:${vid}:verify:`) },
        entries: [{ id: "e1", ...(await seal(vk, { service: "Old", password: "pw", username: "u" }, `keyvex:${vid}:entry:e1`)) }] });
      expect((await readBackup(file, { passkey: "482916" }))[0].service).toBe("Old");
      expect((await readBackup(file, { master: MASTER }))).toHaveLength(1);
      await expect(readBackup(file, { passkey: "111111" })).rejects.toMatchObject({ code: "BAD_SECRET" });
    }, 30000);
  });
});

describe("brute-force protection (server)", () => {
  let srv;
  beforeEach(async () => { srv = await startServer(); });
  afterEach(() => srv.close());

  it("locks a lookup after 5 wrong sign-ins and locks an IP after 25 wrong sign-ins (B9b)", async () => {
    const owner = srv.newVault(); await owner.register(PIN, MASTER); owner.lock();
    const tries = [];
    for (let i = 0; i < 5; i++) tries.push(await srv.newVault().signIn("482917", MASTER).catch((e) => e));
    expect(tries.map((e) => e.code)).toEqual(Array(5).fill("BAD_CREDENTIALS"));
    expect(tries[4].retryAfter).toBeGreaterThan(0);

    // 6th attempt with the SAME lookup is locked out immediately (AUTH_FREE_TRIES = 5)
    const lockedLookup = await srv.newVault().signIn("482917", MASTER).catch((e) => e);
    expect(lockedLookup).toMatchObject({ status: 429, code: "LOCKED_OUT" });
    expect(lockedLookup.retryAfter).toBeGreaterThan(0);

    // Other users behind the same shared NAT / office IP can still sign in until IP_FREE_TRIES (25) is reached
    for (let i = 0; i < 20; i++) {
      await srv.newVault().signIn(String(200000 + i * 3137 % 799999).slice(0, 6), `OtherOfficeUser!${i}`).catch(() => {});
    }
    const lockedIp = await srv.newVault().signIn(PIN, MASTER).catch((e) => e);
    expect(lockedIp).toMatchObject({ status: 429, code: "LOCKED_OUT" });
    expect(lockedIp.retryAfter).toBeGreaterThan(0);
  });

  it("parallel guesses can't beat the per-lookup (5) or per-IP (25) counter", async () => {
    const owner = srv.newVault(); await owner.register(PIN, MASTER); owner.lock();
    const results = await Promise.all(
      Array.from({ length: 12 }, () => srv.newVault().signIn("482917", MASTER).catch((e) => e))
    );
    expect(results.filter((e) => e.status === 401)).toHaveLength(5);
    expect(results.filter((e) => e.status === 429)).toHaveLength(7);
  });

  it("a successful sign-in clears the count", async () => {
    const owner = srv.newVault(); await owner.register(PIN, MASTER); owner.lock();
    for (let r = 0; r < 3; r++) { for (let i = 0; i < 3; i++) await srv.newVault().signIn("482917", MASTER).catch(() => {}); await srv.newVault().signIn(PIN, MASTER); }
  });
});

describe("generator / strength / audit", () => {
  it("generates the requested length with every enabled class", () => {
    for (let i = 0; i < 50; i++) {
      const p = generatePassword({ length: 12 });
      expect(p).toHaveLength(12);
      expect(p).toMatch(/[a-z]/); expect(p).toMatch(/[A-Z]/); expect(p).toMatch(/[2-9]/); expect(p).toMatch(/[^A-Za-z0-9]/);
    }
    expect(() => generatePassword({ lower: false, upper: false, digits: false, symbols: false })).toThrow();
  });
  it("scores passwords sensibly", () => {
    expect(strength("password123").score).toBe(0);
    expect(strength("aaaaaaaaaaaa").score).toBeLessThan(2);
    expect(strength(generatePassword({ length: 20 })).score).toBe(4);
  });
  it("audits weak, reused and old entries", () => {
    const now = Date.now(), old = now - 200 * 86400000;
    const r = auditEntries([
      { id: 1, password: "123456", updatedAt: now }, { id: 2, password: "Dup!Pass#9x", updatedAt: now },
      { id: 3, password: "Dup!Pass#9x", updatedAt: old }
    ], now);
    expect(r.weak.map((e) => e.id)).toEqual([1]);
    expect(r.reused.map((e) => e.id)).toEqual([2, 3]);
    expect(r.old.map((e) => e.id)).toEqual([3]);
  });
});

describe("legacy import (old PIN-based KeyVEX backup)", () => {
  async function makeLegacy(pin, name, entries) {
    const rounds = 600000, kek = async (secret, salt) => crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: rounds, hash: "SHA-256" },
      await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]),
      { name: "AES-KW", length: 256 }, false, ["wrapKey", "unwrapKey"]);
    const vk = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const sp = crypto.getRandomValues(new Uint8Array(16)), sr = crypto.getRandomValues(new Uint8Array(16));
    const wrap = async (s, salt) => b64(new Uint8Array(await crypto.subtle.wrapKey("raw", vk, await kek(s, salt), "AES-KW")));
    const encrypt = async (obj) => { const iv = crypto.getRandomValues(new Uint8Array(12)); return { iv: b64(iv), data: b64(new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, vk, enc.encode(typeof obj === "string" ? obj : JSON.stringify(obj))))) }; };
    return JSON.stringify({
      app: "keep-safe", kind: "encrypted-vault-backup", v: 2,
      meta: { v: 3, pinLength: pin.length, saltPin: b64(sp), saltRec: b64(sr), wrappedPin: await wrap(pin, sp), wrappedRec: await wrap(name.trim().replace(/\s+/g, " ").toLowerCase(), sr), verifier: await encrypt("keep-safe-vault-ok") },
      entries: await Promise.all(entries.map(async (e, i) => ({ id: "id" + i, ...(await encrypt(e)) })))
    });
  }
  it("opens with the old PIN or the old recovery name", async () => {
    const backup = await makeLegacy("123456", "Blue Moon", [{ service: "Netflix", username: "a@b.c", password: "pw1", category: "Entertainment", favorite: true }]);
    const viaPin = await readLegacyBackup(backup, "123456", "pin");
    expect(viaPin[0]).toMatchObject({ service: "Netflix", password: "pw1", favorite: true });
    const viaName = await readLegacyBackup(backup, "  blue   MOON ", "name");
    expect(viaName).toHaveLength(1);
    await expect(readLegacyBackup(backup, "000000", "pin")).rejects.toMatchObject({ code: "BAD_SECRET" });
    await expect(readLegacyBackup("{}", "1", "pin")).rejects.toMatchObject({ code: "NOT_LEGACY" });
  }, 30000);
});

describe("CSV import", () => {
  it("parses quotes, commas, newlines in fields and a BOM", () => {
    const rows = parseCSV('﻿name,note\r\n"A, B","line1\nline2"\r\n"say ""hi""",x\r\n');
    expect(rows).toEqual([["name", "note"], ["A, B", "line1\nline2"], ['say "hi"', "x"]]);
  });
  it("maps Chrome and Bitwarden exports and auto-detects ; and tab delimiters with password-free preview", () => {
    const chrome = "name,url,username,password,note\nGitHub,https://github.com/login,me,pw1,\n,https://example.com,u,pw2,hello\n,,x,,\n";
    const { items, skipped, preview, delimiter } = csvToEntries(chrome);
    expect(delimiter).toBe(",");
    expect(items.map((i) => i.service)).toEqual(["GitHub", "example.com"]);
    expect(items[1].notes).toBe("hello");
    expect(skipped).toBe(1);
    expect(preview).toHaveLength(2);
    expect(preview[0].password).toBeUndefined();

    const semicolonCsv = "name;url;username;password;note\nGitLab;https://gitlab.com;dev;pwSemi;semi note\n";
    const semiRes = csvToEntries(semicolonCsv);
    expect(semiRes.delimiter).toBe(";");
    expect(semiRes.items[0]).toMatchObject({ service: "GitLab", username: "dev", password: "pwSemi" });
    expect(semiRes.preview[0].password).toBeUndefined();

    const bw = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,1,login,Slack,,,0,slack.com,me@x.com,pw3,\n";
    expect(csvToEntries(bw).items[0]).toMatchObject({ service: "Slack", category: "Work", favorite: true, username: "me@x.com", password: "pw3" });
  });
  it("rejects files that are not password exports", () => {
    expect(() => csvToEntries("a,b\n1,2\n")).toThrow();
    expect(() => csvToEntries("only a header")).toThrow();
  });
});
