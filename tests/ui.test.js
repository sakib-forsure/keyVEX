// @vitest-environment jsdom
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { webcrypto } from "node:crypto";
import { startServer, PIN, MASTER } from "./helpers.js";
import { Api } from "../src/core/api.js";
import { resetLocalVaultStorage } from "../src/core/idb.js";

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 15000) => {
  const t = Date.now();
  while (Date.now() - t < ms) {
    const v = fn();
    if (v) return v;
    await wait(40);
  }
  throw new Error("timeout: " + fn.toString());
};
const type = (el, v) => {
  el.value = v;
  el.dispatchEvent(new Event("input", { bubbles: true }));
};
const submit = (form) => form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
const btn = (text) => [...document.querySelectorAll("button")].find((b) => b.textContent.includes(text));
const input = (name, root = document) => root.querySelector(`input[name="${name}"]`);

describe("UI smoke test (jsdom + 2-Layer Authentication & Vault)", () => {
  let ctx, srv, api;
  beforeAll(async () => {
    Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
    if (typeof window !== "undefined") {
      Object.defineProperty(window, "crypto", { value: webcrypto, configurable: true });
      window.scrollTo = () => {};
      window.matchMedia = window.matchMedia || (() => ({ matches: true, addEventListener() {} }));
    }
    await resetLocalVaultStorage();
    srv = await startServer();
    if (!document.querySelector("#app")) {
      const appEl = document.createElement("div"); appEl.setAttribute("id", "app");
      const layerEl = document.createElement("div"); layerEl.setAttribute("id", "layer");
      const toastEl = document.createElement("div"); toastEl.setAttribute("id", "toast");
      document.body.replaceChildren(appEl, layerEl, toastEl);
    } else {
      document.querySelector("#app").replaceChildren();
      document.querySelector("#layer")?.replaceChildren();
    }
    const { startApp } = await import("../src/ui/app.js");
    api = new Api(srv.base);
    ctx = startApp(api);
  });
  afterAll(async () => {
    ctx?.destroy?.();
    await srv.close();
  });

  it("opens on the Welcome / Sign-In screen with Continue with Google, Email, Password, Forgot password, and Create account", () => {
    expect(document.body.dataset.screen).toBe("login");
    expect(document.querySelector("h1 .name").textContent).toBe("KeyVEX");
    expect(document.querySelector("h1 .slogan").textContent).toBe("Keep your life safe");
    expect(btn("Continue with Google")).toBeTruthy();
    expect(input("email")).toBeTruthy();
    expect(input("master-password")).toBeTruthy();
    expect(btn("Forgot password?")).toBeTruthy();
    expect(btn("Create account")).toBeTruthy();
  });

  it("validates empty sign-in form cleanly", async () => {
    submit(document.querySelector("form"));
    await until(() => document.querySelector(".notice.err")?.textContent.includes("valid email"));
  });

  it("navigates to Create Account, registers a new Email user, sets Vault Passkey, and enters Vault directly (no Recovery Key modal)", async () => {
    btn("Create account").click();
    await until(() => document.body.dataset.screen === "register");
    expect(input("name")).toBeTruthy();
    expect(input("email")).toBeTruthy();
    expect(input("master-password")).toBeTruthy();
    expect(input("master-password-confirm")).toBeTruthy();

    type(input("name"), "Ada Lovelace");
    type(input("email"), "ada@gmail.com");
    type(input("master-password"), MASTER);
    type(input("master-password-confirm"), MASTER);
    submit(document.querySelector("form"));

    await until(() => document.body.dataset.screen === "passkey", 10000);
    expect(document.body.textContent).toContain("Set your Vault Passkey");

    type(input("passkey"), PIN);
    type(input("passkey-confirm"), PIN);
    submit(document.querySelector("form"));

    await until(() => document.body.dataset.screen === "vault", 10000);
    expect(document.querySelector(".empty h3").textContent).toBe("Your vault is empty");
  });

  it("locks vault back to Passkey screen and logs out back to Welcome screen", async () => {
    ctx.lockNow("Locked");
    await until(() => document.body.dataset.screen === "passkey");
    expect(ctx.vault.unlocked).toBe(false);
    expect(ctx.vault.accountSignedIn).toBe(true);

    await ctx.logoutAccount();
    await until(() => document.body.dataset.screen === "login");
    expect(ctx.vault.accountSignedIn).toBe(false);
  });
});

describe("theme", () => {
  it("recolours the browser-tab icon when the theme changes", async () => {
    const { applyTheme } = await import("../src/ui/settings.js");
    const icon = () => decodeURIComponent(document.querySelector('link[rel="icon"]').href.split(",")[1]);
    applyTheme("sunset");
    const a = icon();
    applyTheme("ocean");
    const b = icon();
    expect(a).toContain("#ffb347");
    expect(b).toContain("#5ee0d2");
    expect(b).not.toContain("#ffb347");
    expect(document.querySelectorAll('link[rel="icon"]').length).toBe(1);
  });
});
