import { h, $, clear } from "./dom.js";
import { Api } from "../core/api.js";
import { Vault } from "../core/vault.js";
import { startMeasure } from "../core/perf.js";
import { consumeGoogleOAuthRedirectCallback, closeActiveGooglePopup, unloadGoogleIdentityServices } from "../core/firebase.js";
import { closeAllSheets, closeTopSheet, hasOpenSheets, openSheet, setBusy } from "./components/sheet.js";
import { brand } from "./components/brand.js";
import { notice } from "./components/fields.js";
import { masterPasswordSetup } from "./components/masterfield.js";
import { toast, clearClipboardIfSecret } from "./components/feedback.js";
import { icon } from "./icons.js";
import { startNetworkStatus, maybeShowIosInstallHint } from "./components/netstatus.js";
import { maybeShowInstallBanner } from "./components/install.js";
import { errText, logAuthError } from "./errors.js";
import { startAutoLock } from "./autolock.js";
import { loginScreen } from "./screens/login.js";
import { registerScreen } from "./screens/register.js";
import { passkeyScreen } from "./screens/passkey.js";
import { vaultScreen } from "./screens/vault.js";

const SCREENS = {
  login: loginScreen,
  register: registerScreen,
  passkey: passkeyScreen,
  vault: vaultScreen
};

const SCREEN_PATHS = {
  login: "/login",
  register: "/register",
  passkey: "/passkey",
  vault: "/vault"
};

let activeCleanup = null;

function screenFromPathname(pathname = "/") {
  const clean = String(pathname || "/").replace(/\/+$/, "").toLowerCase() || "/";
  if (clean === "/register" || clean === "/signup") return "register";
  if (clean === "/passkey" || clean === "/unlock") return "passkey";
  if (clean === "/vault" || clean === "/dashboard") return "vault";
  if (clean === "/login" || clean === "/signin" || clean === "/reset-password") return "login";
  return null;
}

/**
 * Top-level UI Error Boundary Screen (`renderErrorBoundary`).
 * Ensures the app root is never left blank if a screen render or state transition throws.
 */
export function renderErrorBoundary(ctx, err, targetScreen = "login", targetProps = {}) {
  const correlationId = logAuthError(`render:${targetScreen}`, Object.assign(err || new Error("Render failed"), { code: err?.code || "UI_RENDER_FAILURE" }));
  return h("main", { class: "screen center auth", "data-error-boundary": "true" },
    brand({ size: "sm", slogan: false }),
    h("div", { class: "card glass auth-card" },
      h("h2", { class: "flow-title" }, "Something interrupted this view"),
      h("p", { class: "muted small flow-sub" }, "Your encrypted vault data is safe and untouched."),
      notice("err", errText(err)),
      h("small", { class: "muted", style: { fontFamily: "monospace" } }, `Diagnostic ID: ${correlationId}`),
      h("div", { class: "row-btns", style: { marginTop: "8px" } },
        h("button", {
          class: "btn primary",
          type: "button",
          onclick: () => ctx.go(targetScreen, targetProps)
        }, icon("refresh", 16), "Retry"),
        h("button", {
          class: "btn glass",
          type: "button",
          onclick: () => ctx.logoutAccount("Signed out safely.")
        }, icon("lock", 16), "Sign out")
      )
    )
  );
}

/**
 * PART 1 & F1: Parses ONLY `mode=resetPassword` (Firebase account password reset, unrelated to Passkey),
 * `passwordReset=1` (redirect back from Firebase hosted password-reset popup/page), and `mode=verifyEmail`.
 */
function parseEmailActionUrl() {
  try {
    if (typeof location === "undefined" || !location.search) return null;
    const params = new URLSearchParams(location.search);
    const mode = params.get("mode") || "";
    const oobCode = params.get("oobCode") || "";
    const passwordResetDone = params.get("passwordReset") === "1" || params.get("passwordReset") === "done";
    if (passwordResetDone && !oobCode) {
      return { mode: "passwordResetDone", oobCode: "" };
    }
    if (mode !== "resetPassword" && mode !== "verifyEmail") {
      if (mode || oobCode || location.search) {
        clearActionQueryParams();
      }
      return null;
    }
    return { mode, oobCode };
  } catch {
    return null;
  }
}

function clearActionQueryParams(targetPath = null) {
  try {
    if (typeof window !== "undefined" && window.history?.replaceState && typeof location !== "undefined") {
      const nextPath = targetPath || location.pathname || "/login";
      window.history.replaceState(window.history.state || { screen: "login" }, "", nextPath);
    }
  } catch { /* ignore */ }
}

/**
 * In-App Password Reset Modal (`showOobPasswordResetSheet`):
 *   - Triggered when the user clicks the password reset link in their email
 *     (`https://your-domain/?mode=resetPassword&oobCode=...`).
 *   - Renders New Account Password + Repeat Password (Confirm Password) right inside KeyVEX.
 *   - Confirms the new password with Firebase and redirects to `/login` with a confirmation notice.
 */
function showOobPasswordResetSheet(ctx, oobCode) {
  const master = masterPasswordSetup({
    label: "New Account Password",
    name: "oob-new-password",
    autofocus: true
  });
  const msg = h("div", { class: "flow-msg", "aria-live": "polite" });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Save New Password");

  const sheet = openSheet({
    title: "Reset your account password",
    content: h("form", {
      novalidate: true,
      class: "flow",
      onsubmit: async (e) => {
        e.preventDefault();
        msg.replaceChildren();
        const m = master.validate();
        if (!m.ok) {
          msg.replaceChildren(notice("err", m.hint));
          return;
        }
        setBusy(btn, true, "Saving new password…");
        try {
          await ctx.vault.confirmPasswordResetWithOobCode(oobCode, master.value);
          master.clear();
          setBusy(btn, false);
          sheet.close();
          await ctx.logoutAccount("Password updated! Please sign in with your new password.");
          toast("Password updated — please sign in");
        } catch (err) {
          setBusy(btn, false);
          logAuthError("confirmPasswordResetWithOobCode", err);
          msg.replaceChildren(notice("err", errText(err)));
        }
      }
    },
      notice("info", "Enter and confirm your new account password below. Once saved, you will be redirected to the sign-in screen."),
      master.root,
      msg,
      btn
    )
  });
  return sheet;
}

export function startApp(api = new Api()) {
  const initMeasure = startMeasure("app_init");

  if (typeof activeCleanup === "function") {
    try { activeCleanup(); } catch { /* ignore */ }
    activeCleanup = null;
  }

  if (consumeGoogleOAuthRedirectCallback()) {
    initMeasure.end();
    return null;
  }

  const vault = new Vault(api);
  const actionUrl = parseEmailActionUrl();
  let screenCleanup = null;
  let isFirstNavigation = true;
  let handlingPopState = false;

  const runScreenCleanup = () => {
    if (typeof screenCleanup === "function") {
      try { screenCleanup(); } catch { /* ignore */ }
      screenCleanup = null;
    }
  };

  const syncBrowserUrl = (screenName, replace = false) => {
    try {
      if (typeof window === "undefined" || !window.history?.pushState || typeof location === "undefined") return;
      const targetPath = SCREEN_PATHS[screenName] || "/login";
      const currentPath = location.pathname || "/";
      const stateObj = { screen: screenName, modalDepth: 0 };
      if (replace || isFirstNavigation || currentPath === targetPath) {
        window.history.replaceState(stateObj, "", targetPath);
      } else {
        window.history.pushState(stateObj, "", targetPath);
      }
      isFirstNavigation = false;
    } catch { /* ignore history errors in restricted environments */ }
  };

  const ctx = {
    vault,
    lastError: null,
    registerScreenCleanup(fn) {
      runScreenCleanup();
      screenCleanup = typeof fn === "function" ? fn : null;
    },
    go(name, props) {
      if (name === "vault" && !vault.unlocked) {
        name = vault.accountSignedIn ? "passkey" : "login";
      }
      if (name === "passkey" && !vault.accountSignedIn) {
        name = "login";
      }
      if (!SCREENS[name]) {
        name = "login";
      }
      if (name === "vault") {
        // B7: Ensure GIS script tag is unloaded when entering the unlocked vault
        unloadGoogleIdentityServices();
      }
      runScreenCleanup();
      closeAllSheets();
      const root = $("#app");
      try {
        const renderMeasure = name === "vault" ? startMeasure("first_vault_render") : null;
        const nextScreen = SCREENS[name](ctx, props);
        clear(root).append(nextScreen);
        document.body.dataset.screen = name;
        if (!handlingPopState) {
          syncBrowserUrl(name, Boolean(props?.replaceHistory));
        } else {
          syncBrowserUrl(name, true);
        }
        renderMeasure?.end();
        window.scrollTo(0, 0);
      } catch (err) {
        ctx.lastError = err;
        vault.lock();
        clear(root).append(renderErrorBoundary(ctx, err, name, props));
        document.body.dataset.screen = "error";
      }
    },
    lockNow(noticeMsg) {
      runScreenCleanup();
      closeAllSheets();
      clearClipboardIfSecret().catch(() => {});
      vault.lock();
      ctx.go(vault.accountSignedIn ? "passkey" : "login", { notice: noticeMsg });
    },
    async logoutAccount(noticeMsg = "You have been signed out.") {
      runScreenCleanup();
      closeAllSheets();
      clearClipboardIfSecret().catch(() => {});
      closeActiveGooglePopup();
      const signOutPromise = vault.signOutAccount();
      ctx.go("login", { notice: noticeMsg, replaceHistory: true });
      await signOutPromise;
    }
  };

  // Browser Back / Forward (`popstate`) handler for 1-step navigation & URL bar edits
  const onPopState = (e) => {
    // 1. If any modal sheet is open, pressing Back closes the topmost sheet first!
    if (hasOpenSheets()) {
      closeTopSheet();
      return;
    }

    const currentScreen = document.body?.dataset?.screen || "login";
    const requested = e?.state?.screen || screenFromPathname(typeof location !== "undefined" ? location.pathname : "/") || "login";

    handlingPopState = true;
    try {
      if (currentScreen === "vault" && requested !== "vault") {
        // 1 step back from Vault -> lock vault to Passkey screen
        vault.lock();
        ctx.go(vault.accountSignedIn ? "passkey" : "login");
        return;
      }
      if (currentScreen === "passkey" && (requested === "login" || requested === "register")) {
        // 1 step back from Passkey -> sign out session and return to Login / Register
        vault.signOutAccount().catch(() => {});
        ctx.go(requested);
        return;
      }
      if (requested === "register" && !vault.accountSignedIn) {
        ctx.go("register");
        return;
      }
      if (requested === "passkey" && vault.accountSignedIn) {
        if (vault.unlocked) vault.lock();
        ctx.go("passkey");
        return;
      }
      if (requested === "vault" && vault.unlocked) {
        ctx.go("vault");
        return;
      }
      ctx.go(vault.unlocked ? "vault" : (vault.accountSignedIn ? "passkey" : "login"));
    } finally {
      handlingPopState = false;
    }
  };

  if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
    window.addEventListener("popstate", onPopState);
  }

  api.onExpire = () => {
    if (vault.unlocked) ctx.lockNow("Your session ended. Please enter your Passkey again.");
  };

  // Background sync: whenever the connection returns (and every 60 s while changes are queued) the offline outbox
  // is pushed to Firebase automatically. Unlocked → full two-way sync; locked → push queued (encrypted) changes only.
  let syncRunning = false;
  const runBackgroundSync = async () => {
    if (syncRunning || !vault.accountSignedIn || (typeof navigator !== "undefined" && navigator.onLine === false)) return;
    syncRunning = true;
    try {
      if (vault.unlocked) {
        await vault.sync();
      } else {
        await vault.syncPending();
      }
      if (typeof window !== "undefined" && typeof window.dispatchEvent === "function" && typeof CustomEvent === "function") {
        window.dispatchEvent(new CustomEvent("keyvex:synced"));
      }
    } catch (err) {
      if (err?.code === "PASSKEY_CHANGED_REMOTELY") {
        ctx.lockNow(err.message);
      } else {
        logAuthError("autoSync", err);
      }
    } finally {
      syncRunning = false;
    }
  };

  const stopNetStatus = startNetworkStatus({
    getPending: () => vault.pendingOutboxCount,
    onOnline: () => { runBackgroundSync(); }
  });
  maybeShowIosInstallHint();
  const stopInstallBanner = maybeShowInstallBanner();
  // Also covers the case where the browser was already online but a previous attempt failed (e.g. flaky network)
  const bgSyncTimer = setInterval(() => {
    if (vault.pendingOutboxCount > 0) runBackgroundSync();
  }, 30_000);
  bgSyncTimer?.unref?.();
  // First sync attempt shortly after start-up: flushes anything queued during a previous offline session.
  setTimeout(() => { if (vault.pendingOutboxCount > 0) runBackgroundSync(); }, 4000);

  const stopAutoLock = startAutoLock(ctx);
  const unsubAuth = vault.onAuthStateChanged((acct) => {
    const currentScreen = document.body?.dataset?.screen;
    if (!acct && (currentScreen === "passkey" || (currentScreen === "vault" && !vault.unlocked))) {
      ctx.go("login", { notice: vault.lastSessionNotice || undefined, replaceHistory: true });
    }
  });

  activeCleanup = () => {
    runScreenCleanup();
    clearInterval(bgSyncTimer);
    stopNetStatus?.();
    stopInstallBanner?.();
    if (typeof window !== "undefined" && typeof window.removeEventListener === "function") {
      window.removeEventListener("popstate", onPopState);
    }
    stopAutoLock?.();
    unsubAuth?.();
  };
  ctx.destroy = activeCleanup;

  // Frame-1 instant routing: honor `/register` when signed out, or route to `passkey` / `login`
  const requestedFromUrl = typeof location !== "undefined" ? screenFromPathname(location.pathname) : null;
  const initialScreen = vault.accountSignedIn
    ? "passkey"
    : (requestedFromUrl === "register" ? "register" : "login");
  ctx.go(initialScreen, { replaceHistory: true });
  initMeasure.end();

  // Process Firebase OOB email action link (`verifyEmail`, `resetPassword`, or `passwordResetDone`)
  if (actionUrl) {
    clearActionQueryParams("/login");
    if (actionUrl.mode === "passwordResetDone") {
      ctx.logoutAccount("Password reset complete! Please sign in with your new password.").catch(() => {});
    } else if (actionUrl.mode === "resetPassword" && actionUrl.oobCode) {
      setTimeout(() => showOobPasswordResetSheet(ctx, actionUrl.oobCode), 0);
    } else if (actionUrl.mode === "verifyEmail" && actionUrl.oobCode) {
      vault.handleEmailActionLink(actionUrl).then((res) => {
        if (res?.mode === "verifyEmail" && res?.verified) {
          toast("Email address verified!");
          if (document.body.dataset.screen === "passkey") {
            ctx.go("passkey", { replaceHistory: true });
          }
        }
      }).catch(() => {});
    }
  }

  const initialPinLen = vault.account?.pinLength || null;
  vault.restoreAccountSession({
    onFastCachedSession(cachedAcct) {
      if (cachedAcct && !vault.unlocked) {
        if (document.body.dataset.screen === "login" || (cachedAcct.pinLength && cachedAcct.pinLength !== initialPinLen)) {
          ctx.go("passkey", { replaceHistory: true });
        }
      }
    }
  }).then((acct) => {
    if (acct && !vault.unlocked) {
      if (document.body.dataset.screen === "login" || (acct.pinLength && acct.pinLength !== initialPinLen)) {
        ctx.go("passkey", { replaceHistory: true });
      }
    } else if (!acct && document.body.dataset.screen !== "login" && document.body.dataset.screen !== "register") {
      ctx.go("login", { notice: vault.lastSessionNotice || undefined, replaceHistory: true });
    }
  }).catch((err) => {
    const cid = logAuthError("restoreAccountSession", err);
    ctx.lastError = err;
    if (document.body.dataset.screen !== "vault") {
      ctx.go("login", { notice: `${errText(err)} (Ref: ${cid})`, replaceHistory: true });
    }
  });

  return ctx;
}
