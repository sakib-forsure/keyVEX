import { h } from "../dom.js";

/**
 * Connectivity UI (`netstatus.js`):
 *   - `body.is-offline` class so screens/CSS can react (no visible "You're offline" banner any more).
 *   - Asks the browser to keep this site's storage (`navigator.storage.persist`) so the offline vault is not evicted.
 *   - On iPhone/iPad Safari (not yet installed) shows a one-time "Add to Home Screen" hint, because Safari may clear
 *     the website data of a normal tab after 7 days of non-use, while an installed Home Screen app keeps it.
 */
const IOS_HINT_KEY = "keyvex_ios_install_hint_dismissed";

export function isOffline() {
  return typeof navigator !== "undefined" && navigator.onLine === false;
}

export function isIosDevice() {
  if (typeof navigator === "undefined") return false;
  const ua = navigator.userAgent || "";
  const iPadOs = navigator.platform === "MacIntel" && (navigator.maxTouchPoints || 0) > 1;
  return /iPad|iPhone|iPod/.test(ua) || iPadOs;
}

export function isStandalone() {
  try {
    return Boolean(navigator.standalone) || (typeof matchMedia === "function" && matchMedia("(display-mode: standalone)").matches);
  } catch {
    return false;
  }
}

export async function requestPersistentStorage() {
  try {
    if (navigator.storage?.persist) {
      if (await navigator.storage.persisted?.()) return true;
      return await navigator.storage.persist();
    }
  } catch { /* best effort */ }
  return false;
}

/**
 * Tracks connectivity silently (no on-screen banner): toggles `body.is-offline` for CSS/other components and fires
 * `onOnline` when the connection returns so queued changes sync in the background. The offline vault keeps working.
 * @param {{ getPending?: () => number, onOnline?: () => void }} opts
 * @returns {() => void} cleanup
 */
export function startNetworkStatus({ onOnline } = {}) {
  if (typeof document === "undefined" || typeof window === "undefined" || typeof window.addEventListener !== "function" || !document.body) return () => {};

  const onOffEvt = () => document.body.classList.add("is-offline");
  const onOnEvt = () => {
    document.body.classList.remove("is-offline");
    try { onOnline?.(); } catch { /* ignore */ }
  };
  window.addEventListener("offline", onOffEvt);
  window.addEventListener("online", onOnEvt);
  if (isOffline()) onOffEvt();

  requestPersistentStorage();

  return () => {
    window.removeEventListener("offline", onOffEvt);
    window.removeEventListener("online", onOnEvt);
    document.body.classList.remove("is-offline");
  };
}

/** One-time iPhone/iPad hint: install to the Home Screen so Safari does not purge the offline vault. */
export function maybeShowIosInstallHint() {
  if (typeof document === "undefined" || !isIosDevice() || isStandalone()) return;
  try { if (localStorage.getItem(IOS_HINT_KEY)) return; } catch { /* storage blocked: show anyway */ }
  if (document.querySelector(".ios-install-hint")) return;

  const close = () => {
    try { localStorage.setItem(IOS_HINT_KEY, "1"); } catch { /* ignore */ }
    card.remove();
  };
  const card = h("div", { class: "ios-install-hint glass", role: "dialog", "aria-label": "Install KeyVEX" },
    h("div", { class: "ios-install-text" },
      h("strong", null, "Keep KeyVEX available offline"),
      h("span", null, "Tap Share, then “Add to Home Screen”. Installed apps keep your vault on this iPhone; Safari tabs can be cleared after 7 days.")
    ),
    h("button", { class: "btn glass slim", type: "button", onclick: close }, "Got it")
  );
  document.body.append(card);
}
