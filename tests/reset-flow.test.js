// @vitest-environment jsdom
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  setFirebaseTransport,
  firebaseSendPasswordResetEmail,
  firestoreDeleteVault
} from "../src/core/firebase.js";
import { resetPasswordScreen } from "../src/ui/screens/resetPassword.js";

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 3000) => {
  const t = Date.now();
  while (Date.now() - t < ms) {
    const v = fn();
    if (v) return v;
    await wait(15);
  }
  throw new Error("timeout: " + fn.toString());
};
const type = (el, v) => {
  el.value = v;
  el.dispatchEvent(new Event("input", { bubbles: true }));
};
const res = (status, body) => ({ ok: status >= 200 && status < 300, status, json: async () => body });

afterEach(() => setFirebaseTransport(null));

describe("in-app reset password page (/reset-password)", () => {
  let ctx;
  beforeEach(() => {
    document.body.replaceChildren();
    ctx = {
      go: vi.fn(),
      logoutAccount: vi.fn(async () => {}),
      vault: {
        verifyPasswordResetCode: vi.fn(async () => ({ ok: true, email: "ada@gmail.com" })),
        confirmPasswordResetWithOobCode: vi.fn(async () => ({ ok: true }))
      }
    };
  });

  it("shows New password + Confirm password for the email, saves, then returns to sign-in in the SAME tab", async () => {
    const open = vi.spyOn(window, "open");
    const root = resetPasswordScreen(ctx, { oobCode: "abc123" });
    document.body.append(root);
    await until(() => root.querySelector('input[name="reset-new-password"]'));
    expect(root.textContent).toContain("ada@gmail.com");
    expect(root.textContent).toContain("New Password");
    expect(root.textContent).toContain("Confirm Password");

    // mismatch is rejected before any network call
    type(root.querySelector('input[name="reset-new-password"]'), "Str0ng!Pass-99");
    type(root.querySelector('input[name="reset-new-password-confirm"]'), "different");
    root.querySelector("form").dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await until(() => root.querySelector(".notice.err"));
    expect(ctx.vault.confirmPasswordResetWithOobCode).not.toHaveBeenCalled();

    type(root.querySelector('input[name="reset-new-password-confirm"]'), "Str0ng!Pass-99");
    root.querySelector("form").dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await until(() => ctx.logoutAccount.mock.calls.length === 1);
    expect(ctx.vault.confirmPasswordResetWithOobCode).toHaveBeenCalledWith("abc123", "Str0ng!Pass-99");
    expect(ctx.logoutAccount.mock.calls[0][0]).toMatch(/sign in with your new password/i);
    expect(open).not.toHaveBeenCalled();
  });

  it("explains an invalid / expired / already used link and offers a way back", async () => {
    ctx.vault.verifyPasswordResetCode = vi.fn(async () => { throw Object.assign(new Error("x"), { code: "INVALID_OOB_CODE" }); });
    const root = resetPasswordScreen(ctx, { oobCode: "used" });
    document.body.append(root);
    await until(() => root.querySelector(".notice.err"));
    expect(root.querySelector('input[type="password"]')).toBeNull();
    [...root.querySelectorAll("button")].find((b) => b.textContent.includes("Back to sign in")).click();
    expect(ctx.go).toHaveBeenCalledWith("login", expect.anything());
  });

  it("a missing code never shows the form", () => {
    const root = resetPasswordScreen(ctx, {});
    expect(root.querySelector(".notice.err")).toBeTruthy();
    expect(ctx.vault.verifyPasswordResetCode).not.toHaveBeenCalled();
  });
});

describe("forgot password for an account that no longer exists", () => {
  it("returns a direct 'account does not exist' error", async () => {
    setFirebaseTransport(async () => res(400, { error: { message: "EMAIL_NOT_FOUND" } }));
    await expect(firebaseSendPasswordResetEmail("deleted@gmail.com")).rejects.toMatchObject({
      code: "EMAIL_NOT_FOUND",
      message: expect.stringMatching(/does not exist/i)
    });
  });
});

describe("account deletion removes every Firestore record", () => {
  function fakeFirestore(uid) {
    const docs = new Map();
    for (let i = 0; i < 3; i++) docs.set(`users/${uid}/entries/e${i}`, { fields: {} });
    for (let i = 0; i < 2; i++) docs.set(`users/${uid}/tombstones/t${i}`, { fields: {} });
    docs.set(`users/${uid}`, { fields: {} });
    const prefix = (p) => `users/${uid}/${p}/`;
    const transport = vi.fn(async (url, opts = {}) => {
      const path = decodeURIComponent(url.split("/documents")[1] || "");
      if (path === ":commit") {
        for (const w of JSON.parse(opts.body).writes) docs.delete(w.delete.split("/documents/")[1]);
        return res(200, {});
      }
      const [p] = path.split("?");
      if (opts.method === "DELETE") { docs.delete(p.replace(/^\//, "")); return res(200, {}); }
      const rel = p.replace(/^\//, "");
      for (const sub of ["entries", "tombstones"]) {
        if (rel === `users/${uid}/${sub}`) {
          const list = [...docs.keys()].filter((k) => k.startsWith(prefix(sub)))
            .map((k) => ({ name: `projects/p/databases/(default)/documents/${k}`, fields: { id: { stringValue: k.split("/").pop() } } }));
          return res(200, list.length ? { documents: list } : {});
        }
      }
      return docs.has(rel) ? res(200, docs.get(rel)) : res(404, {});
    });
    return { docs, transport };
  }

  it("deletes entries, tombstones and the profile, and verifies all are gone", async () => {
    const f = fakeFirestore("u1");
    setFirebaseTransport(f.transport);
    const out = await firestoreDeleteVault("u1", "tok");
    expect(out.verifiedEmpty).toBe(true);
    expect([...f.docs.keys()]).toEqual([]);
  });

  it("fails (so it is retried) instead of silently leaving tombstones behind", async () => {
    const f = fakeFirestore("u2");
    setFirebaseTransport(async (url, opts = {}) => {
      if (String(url).endsWith(":commit") && JSON.parse(opts.body).writes.some((w) => w.delete.includes("/tombstones/"))) {
        return res(500, { error: { message: "boom", status: "INTERNAL" } });
      }
      return f.transport(url, opts);
    });
    await expect(firestoreDeleteVault("u2", "tok")).rejects.toBeTruthy();
    expect([...f.docs.keys()].some((k) => k.includes("/tombstones/"))).toBe(true);
  });
});
