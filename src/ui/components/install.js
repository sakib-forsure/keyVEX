import { h } from "../dom.js";
import { openSheet } from "./sheet.js";
import { isIosDevice, isStandalone } from "./netstatus.js";

/**
 * "Add to Home Screen" / Install-app support (`install.js`).
 *
 *  - Android / desktop Chrome & Edge: the browser fires `beforeinstallprompt` once the app is installable
 *    (manifest + service worker). We keep that event, and offer our own "Install app" button (banner + Settings row)
 *    that calls `prompt()` — the native install dialog then appears. The browser's own menu entry keeps working too.
 *  - iPhone / iPad Safari has no install API: we show step-by-step instructions (Share → Add to Home Screen).
 *  - Other browsers (Firefox desktop, …): a short how-to sheet.
 *
 * The listeners are registered at import time (before the `load` event) so the early event is never missed.
 */
const DISMISS_KEY = "keyvex_install_banner_dismissed_at";
const DISMISS_MS = 7 * 24 * 60 * 60 * 1000;

let deferredPrompt = null;
let installed = false;
const listeners = new Set();

const notify = () => listeners.forEach((fn) => { try { fn(); } catch { /* ignore */ } });

if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredPrompt = e;
    notify();
  });
  window.addEventListener("appinstalled", () => {
    installed = true;
    deferredPrompt = null;
    document.querySelector?.(".install-banner")?.remove();
    notify();
  });
}

export function onInstallStateChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** True when the browser has handed us a native install prompt. */
export function canPromptInstall() {
  return Boolean(deferredPrompt) && !installed && !isStandalone();
}

/** True when the app already runs as an installed app (or was just installed). */
export function isInstalled() {
  return installed || isStandalone();
}

/** Shows the native install dialog. Resolves to "accepted" | "dismissed" | "unavailable". */
export async function promptInstall() {
  const evt = deferredPrompt;
  if (!evt) return "unavailable";
  deferredPrompt = null; // an install prompt can only be used once
  try {
    await evt.prompt();
    const choice = await evt.userChoice;
    if (choice?.outcome === "accepted") installed = true;
    notify();
    return choice?.outcome || "dismissed";
  } catch {
    notify();
    return "dismissed";
  }
}

function stepList(steps) {
  return h("ol", { class: "install-steps", style: { margin: "8px 0 0", paddingLeft: "20px", display: "grid", gap: "8px", lineHeight: "1.45" } },
    ...steps.map((s) => h("li", null, s)));
}

/** Instructions sheet for browsers without a programmatic install prompt. */
export function openInstallHelp() {
  let steps;
  let intro = "Install KeyVEX on your device so it opens like a normal app, works offline and keeps your vault on this device.";
  if (isIosDevice()) {
    steps = [
      "Open KeyVEX in Safari (not inside another app's browser).",
      "Tap the Share button (square with an arrow) at the bottom of the screen.",
      "Scroll down and tap “Add to Home Screen”, then tap “Add”.",
      "Open KeyVEX from your Home Screen and sign in once inside that app."
    ];
  } else if (/Android/i.test(navigator.userAgent || "")) {
    steps = [
      "Open the browser menu (⋮) in Chrome.",
      "Tap “Install app” or “Add to Home screen”.",
      "Confirm with “Install”. KeyVEX then appears with your other apps."
    ];
  } else {
    steps = [
      "In Chrome or Edge, click the install icon at the right end of the address bar (or open the ⋮ menu → “Install KeyVEX”).",
      "Confirm with “Install”. KeyVEX then opens in its own window."
    ];
  }
  return openSheet({
    title: "Install KeyVEX",
    content: h("div", { class: "flow" },
      h("p", { class: "muted" }, intro),
      stepList(steps)
    )
  });
}

/** Single entry point for UI buttons: native prompt when possible, instructions otherwise. */
export async function startInstallFlow() {
  if (canPromptInstall()) {
    const res = await promptInstall();
    if (res === "accepted") return res;
    return res;
  }
  openInstallHelp();
  return "help";
}

function dismissedRecently() {
  try {
    const at = Number(localStorage.getItem(DISMISS_KEY) || 0);
    return at > 0 && Date.now() - at < DISMISS_MS;
  } catch {
    return false;
  }
}

/** Bottom banner with an "Install app" button for Android / desktop (iOS has its own hint in netstatus.js). */
export function maybeShowInstallBanner() {
  if (typeof document === "undefined" || isIosDevice() || isInstalled()) return () => {};

  const render = () => {
    const existing = document.querySelector(".install-banner");
    if (!canPromptInstall() || dismissedRecently() || document.body?.classList.contains("is-offline")) {
      existing?.remove();
      return;
    }
    if (existing) return;
    const close = () => {
      try { localStorage.setItem(DISMISS_KEY, String(Date.now())); } catch { /* ignore */ }
      card.remove();
    };
    const card = h("div", { class: "install-banner ios-install-hint glass", role: "dialog", "aria-label": "Install KeyVEX" },
      h("div", { class: "ios-install-text" },
        h("strong", null, "Install KeyVEX"),
        h("span", null, "Add it to your Home screen for one-tap access and offline use.")
      ),
      h("button", { class: "btn glass slim", type: "button", onclick: close }, "Not now"),
      h("button", {
        class: "btn primary slim",
        type: "button",
        onclick: async () => { card.remove(); await promptInstall(); }
      }, "Install")
    );
    document.body.append(card);
  };

  const off = onInstallStateChange(render);
  render();
  return () => { off(); document.querySelector(".install-banner")?.remove(); };
}
