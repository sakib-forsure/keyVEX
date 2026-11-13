import { h, $ } from "./dom.js";
import { getSettings } from "./settings.js";

const TICKET_WRITE_MS = 4_000;
const ACTIVE_KEY = "keyvex.lastActive";

/**
 * Auto-lock rules:
 *   - "Lock immediately when tab is hidden" ON  → the vault locks the moment the tab/app goes to the background
 *     (or the page is left / refreshed).
 *   - OFF (default) → ONLY the inactivity timer (1/5/15/30 min) locks the vault. Going to another tab, refreshing or
 *     closing and re-opening the page does not ask for the Passkey while the timer has not run out; the time spent in
 *     the background counts as inactivity, so it locks as soon as the timer is exceeded.
 * Shows a visible countdown banner in the last 10 s of inactivity. Returns a cleanup function.
 * `ctx.touchAutoLock(ts)` lets the app restore the last-activity time after a resume.
 */
export function startAutoLock(ctx) {
  let last = Date.now(), lastWrite = 0;
  ctx.touchAutoLock = (ts = Date.now()) => { last = ts; lastWrite = 0; };

  // Persist the last-activity time so a refresh / reopened tab can keep the session until the timer ends.
  const persistActivity = (force = false) => {
    if (!ctx.vault.unlocked) return;
    const now = Date.now();
    if (!force && now - lastWrite < TICKET_WRITE_MS) return;
    lastWrite = now;
    try { localStorage.setItem(ACTIVE_KEY, String(last)); } catch { /* storage blocked */ }
    ctx.vault.touchUnlockTicket?.(last)?.catch?.(() => {});
  };

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
    const { autoLockMin: min } = getSettings();
    if (!ctx.vault.unlocked || !(min > 0)) {
      hideCountdown();
      return;
    }
    persistActivity();
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
    if (!ctx.vault.unlocked) return;
    const { autoLockMin: min, lockOnHide } = getSettings();
    if (document.hidden) {
      if (lockOnHide) {
        hideCountdown();
        ctx.lockNow("Locked automatically when tab was hidden.");
      } else {
        persistActivity(true);
      }
      return;
    }
    // Back in the foreground: if the inactivity timer already ran out while away, lock now.
    // (Do NOT reset the timer here — only real interaction does.)
    if (min > 0 && Date.now() - last >= min * 60_000) {
      hideCountdown();
      ctx.lockNow(`Signed out after ${min} min of inactivity.`);
    }
  };

  const onPageHide = () => {
    hideCountdown();
    if (!ctx.vault.unlocked) return;
    if (getSettings().lockOnHide) {
      ctx.lockNow("Vault locked when leaving page.");
    } else {
      persistActivity(true); // keep the session: a refresh within the timer stays unlocked
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
