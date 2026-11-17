import "@fontsource-variable/manrope";
import "@fontsource-variable/inter";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/glass.css";
import "./styles/screens.css";
import "./styles/components.css";
import "./styles/themes.css";
import "./styles/liquid.css";
import { startApp } from "./ui/app.js";
import { applyTheme, watchSystemTheme } from "./ui/settings.js";
import { h } from "./ui/dom.js";

applyTheme();
watchSystemTheme();

// Liquid glass: light that glides after the pointer / finger (eased, so it flows like water) and ripples where you touch.
if (typeof document !== "undefined") {
  const REDUCED = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
  const track = new Map(); // element -> { tx, ty, x, y }
  let raf = 0;
  const tick = () => {
    raf = 0;
    let live = false;
    for (const [el, t] of track) {
      t.x += (t.tx - t.x) * 0.2; t.y += (t.ty - t.y) * 0.2;
      el.style.setProperty("--px", `${t.x.toFixed(1)}px`);
      el.style.setProperty("--py", `${t.y.toFixed(1)}px`);
      if (Math.abs(t.tx - t.x) > 0.4 || Math.abs(t.ty - t.y) > 0.4) live = true; else track.delete(el);
    }
    if (live || track.size) raf = requestAnimationFrame(tick);
  };
  const aim = (el, e, snap) => {
    const r = el.getBoundingClientRect();
    const x = e.clientX - r.left, y = e.clientY - r.top;
    let t = track.get(el);
    if (!t) { t = { tx: x, ty: y, x: snap ? x : (parseFloat(el.style.getPropertyValue("--px")) || x), y: snap ? y : (parseFloat(el.style.getPropertyValue("--py")) || y) }; track.set(el, t); }
    t.tx = x; t.ty = y;
    if (!raf) raf = requestAnimationFrame(tick);
  };
  let pressed = null;
  const glassOf = (e) => (e.target instanceof Element ? e.target.closest(".glass") : null);
  document.addEventListener("pointermove", (e) => {
    const el = pressed || glassOf(e);
    if (el) aim(el, e, false);
  }, { passive: true });

  const RIPPLE = ".btn, .dock-btn, .nav-item, .chip-toggle, .cat, .icon-btn, .round, .seg button, .swatch, .choice, .promo, .entry, .tile, .setting, .search-pill";
  const ripple = (host, e) => {
    const r = host.getBoundingClientRect();
    const x = e.clientX - r.left, y = e.clientY - r.top;
    const size = Math.max(Math.hypot(Math.max(x, r.width - x), Math.max(y, r.height - y)) * 2.1, 60);
    const wrap = document.createElement("span");
    wrap.className = "ripple-wrap"; wrap.setAttribute("aria-hidden", "true");
    const dot = document.createElement("span");
    dot.className = "ripple";
    dot.style.cssText = `--rx:${x}px;--ry:${y}px;--rs:${size}px`;
    wrap.append(dot); host.append(wrap);
    setTimeout(() => wrap.remove(), 1300);
  };

  document.addEventListener("pointerdown", (e) => {
    const t = e.target instanceof Element ? e.target : null;
    if (!t) return;
    const g = glassOf(e);
    if (g) { pressed = g; aim(g, e, true); g.classList.add("is-pressed"); }
    if (REDUCED || t.closest("input, textarea, select, [disabled]")) return;
    const host = t.closest(RIPPLE);
    if (host) ripple(host, e);
  }, { passive: true });
  const release = () => { if (pressed) { pressed.classList.remove("is-pressed"); pressed = null; } };
  document.addEventListener("pointerup", release, { passive: true });
  document.addEventListener("pointercancel", release, { passive: true });
}

startApp();

function showNewVersionBanner() {
  if (typeof document === "undefined" || document.querySelector(".sw-update-banner")) return;
  const banner = h("div", {
    class: "sw-update-banner glass",
    role: "status",
    "aria-live": "polite",
    style: {
      position: "fixed",
      bottom: "24px",
      left: "50%",
      transform: "translateX(-50%)",
      zIndex: "90",
      display: "flex",
      alignItems: "center",
      gap: "12px",
      padding: "10px 18px",
      borderRadius: "999px",
      fontWeight: "650",
      fontSize: "14px"
    }
  },
    h("span", null, "New version available"),
    h("button", {
      class: "btn primary slim",
      type: "button",
      onclick: () => location.reload()
    }, "New version — Reload")
  );
  document.body?.append(banner);
}

if (typeof navigator !== "undefined" && "serviceWorker" in navigator) {
  if (import.meta.env?.PROD) {
    let hadController = Boolean(navigator.serviceWorker.controller);
    navigator.serviceWorker.addEventListener?.("controllerchange", () => {
      if (hadController) {
        showNewVersionBanner();
      } else {
        hadController = true;
      }
    });

    addEventListener("load", () => {
      navigator.serviceWorker.register("/sw.js")
        .then((reg) => {
          reg.update().catch(() => {});
          reg.addEventListener("updatefound", () => {
            const installing = reg.installing;
            if (!installing) return;
            installing.addEventListener("statechange", () => {
              if (installing.state === "installed" && navigator.serviceWorker.controller) {
                installing.postMessage({ type: "SKIP_WAITING" });
              }
            });
          });
        })
        .catch(() => {});
    });
  } else {
    navigator.serviceWorker.getRegistrations().then((regs) => regs.forEach((r) => r.unregister())).catch(() => {});
  }
}
