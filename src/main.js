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

// Water ripple where you touch a button / card (cheap: one transformed, fading element; removed after 1.3s).
if (typeof document !== "undefined") {
  const REDUCED = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
  const RIPPLE = ".btn, .dock-btn, .nav-item, .chip-toggle, .cat, .icon-btn, .round, .seg button, .swatch, .choice, .promo, .tile, .setting";
  document.addEventListener("pointerdown", (e) => {
    const t = e.target instanceof Element ? e.target : null;
    if (!t || REDUCED || t.closest("input, textarea, select, [disabled]")) return;
    const host = t.closest(RIPPLE);
    if (!host) return;
    const r = host.getBoundingClientRect();
    const x = e.clientX - r.left, y = e.clientY - r.top;
    const size = Math.max(Math.hypot(Math.max(x, r.width - x), Math.max(y, r.height - y)) * 2.1, 60);
    const wrap = document.createElement("span");
    wrap.className = "ripple-wrap"; wrap.setAttribute("aria-hidden", "true");
    const dot = document.createElement("span");
    dot.className = "ripple";
    dot.style.cssText = `--rx:${x}px;--ry:${y}px;--rs:${size}px`;
    wrap.append(dot); host.append(wrap);
    setTimeout(() => wrap.remove(), 800);
  }, { passive: true });
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
