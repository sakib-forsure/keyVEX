import { h, $ } from "./dom.js";
import { getSettings } from "./settings.js";

const HIDDEN_LOCK_MS = 30_000;

/**
 * Locks after inactivity, when the tab/app is hidden (immediately if `lockOnHide` is enabled, or after 30 s),
 * and on `pagehide` (B27). Shows a visible countdown banner in the last 10 s of inactivity.
 * Returns a cleanup function.
 */
export function startAutoLock(ctx) {
  let last = Date.now(), hiddenAt = 0;

  let countdownEl = null;
  const hideCountdown = () => {
    if (countdownEl) {
      countdownEl.remove();
      countdownEl = null;
    }
  };
  const showCountdown = (secLeft) => {
    if (!countdownEl && typeof document !== "undefined") {
      countdownEl = h("div", {
        class: "autolock-countdown glass",
        role: "status",
        "aria-live": "polite",
        style: {
          position: "fixed",
          top: "12px",
          left: "50%",
          transform: "translateX(-50%)",
          zIndex: "80",
          padding: "8px 16px",
          borderRadius: "999px",
          fontSize: "13.5px",
          fontWeight: "650"
        }
      });
      document.body?.append(countdownEl);
    }
    if (countdownEl) {
      countdownEl.textContent = `Locking vault in ${secLeft}s due to inactivity…`;
    }
  };

  const bump = () => {
    last = Date.now();
    hideCountdown();
  };
  const events = ["pointerdown", "keydown", "touchstart", "wheel"];
  events.forEach((ev) => document.addEventListener(ev, bump, { passive: true }));

  const timer = setInterval(() => {
    const min = getSettings().autoLockMin;
    if (!ctx.vault.unlocked || !(min > 0)) {
      hideCountdown();
      return;
    }
    const elapsed = Date.now() - last;
    const limitMs = min * 60_000;
    const remainingMs = limitMs - elapsed;
    if (remainingMs <= 0) {
      hideCountdown();
      ctx.lockNow(`Signed out after ${min} min of inactivity.`);
    } else if (remainingMs <= 10_000) {
      showCountdown(Math.max(1, Math.ceil(remainingMs / 1000)));
    } else {
      hideCountdown();
    }
  }, 1_000);
  timer?.unref?.();

  const onVis = () => {
    if (document.hidden) {
      hiddenAt = Date.now();
      if (ctx.vault.unlocked && getSettings().lockOnHide) {
        hideCountdown();
        ctx.lockNow("Locked automatically when tab was hidden.");
      }
      return;
    }
    if (ctx.vault.unlocked && hiddenAt && Date.now() - hiddenAt > HIDDEN_LOCK_MS) {
      hideCountdown();
      ctx.lockNow("Signed out while the app was in the background.");
    }
    hiddenAt = 0;
    bump();
  };

  const onPageHide = () => {
    hideCountdown();
    if (ctx.vault.unlocked) {
      ctx.lockNow("Vault locked when leaving page.");
    }
  };

  document.addEventListener("visibilitychange", onVis);
  if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
    window.addEventListener("pagehide", onPageHide);
  }

  return () => {
    clearInterval(timer);
    hideCountdown();
    events.forEach((ev) => document.removeEventListener(ev, bump));
    document.removeEventListener("visibilitychange", onVis);
    if (typeof window !== "undefined" && typeof window.removeEventListener === "function") {
      window.removeEventListener("pagehide", onPageHide);
    }
  };
}
