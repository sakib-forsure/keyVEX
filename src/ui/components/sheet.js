import { h, $, sleep, reducedMotion } from "../dom.js";
import { icon } from "../icons.js";

const stack = [];

export function hasOpenSheets() {
  return stack.length > 0;
}

export function closeTopSheet() {
  if (!stack.length) return false;
  stack[stack.length - 1].close({ fromPopState: true });
  return true;
}

/**
 * Bottom sheet (glass). Returns { el, body, close }.
 * Esc / backdrop / drag handle area / browser Back button closes the top sheet one step at a time.
 * B26: Focus trap includes `[tabindex]:not([tabindex="-1"])`.
 */
export function openSheet({ title, content, onClose, wide = false }) {
  const opener = document.activeElement;
  const body = h("div", { class: "sheet-body" }, content);
  const closeBtn = h("button", { class: "icon-btn", type: "button", "aria-label": "Close", onclick: () => api.close() }, icon("close", 18));
  const el = h("section", { class: "sheet" + (wide ? " wide" : ""), role: "dialog", "aria-modal": "true", "aria-label": title },
    h("div", { class: "grab" }),
    h("header", { class: "sheet-head" }, h("h2", null, title), closeBtn),
    body);
  const backdrop = h("div", { class: "backdrop", onclick: () => api.close() });
  const wrap = h("div", { class: "sheet-wrap" }, backdrop, el);
  const onKey = (e) => {
    if (stack[stack.length - 1] !== api) return;
    if (e.key === "Escape") api.close();
    if (e.key === "Tab") {
      const f = [...el.querySelectorAll('button,input,select,textarea,a[href],[tabindex]:not([tabindex="-1"])')].filter((n) => !n.disabled && !n.hidden && n.offsetParent !== null);
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  };
  let closing = false;
  const api = {
    el, body,
    async close() {
      if (closing) return; closing = true;
      wrap.classList.add("leaving");
      document.removeEventListener("keydown", onKey);
      await sleep(reducedMotion() ? 0 : 240);
      wrap.remove();
      const idx = stack.indexOf(api);
      if (idx !== -1) stack.splice(idx, 1);
      if (!stack.length) document.body.classList.remove("no-scroll");
      opener?.focus?.();
      onClose?.();
    }
  };
  stack.push(api);
  try {
    if (typeof window !== "undefined" && window.history?.pushState && typeof location !== "undefined") {
      const curState = window.history.state && typeof window.history.state === "object" ? window.history.state : {};
      window.history.pushState({ ...curState, modalDepth: stack.length }, "", (location.pathname || "/") + (location.search || ""));
    }
  } catch { /* ignore history errors in sandboxed/test contexts */ }
  document.body.classList.add("no-scroll");
  $("#layer").append(wrap);
  document.addEventListener("keydown", onKey);
  requestAnimationFrame(() => (el.querySelector("[autofocus],input,select,textarea") || closeBtn).focus({ preventScroll: true }));
  return api;
}

export function closeAllSheets() { [...stack].forEach((s) => s.close()); }

/** Promise-based confirmation. Resolves true only on the confirm button. */
export function confirmSheet({ title, text, yes = "Confirm", danger = false }) {
  return new Promise((resolve) => {
    let answered = false;
    const done = (v) => { answered = true; sheet.close(); resolve(v); };
    const sheet = openSheet({
      title,
      onClose: () => { if (!answered) resolve(false); },
      content: [
        h("p", { class: "muted" }, text),
        h("div", { class: "row-btns" },
          h("button", { class: "btn glass", type: "button", onclick: () => done(false) }, "Cancel"),
          h("button", { class: "btn " + (danger ? "danger" : "primary"), type: "button", onclick: () => done(true) }, yes))
      ]
    });
  });
}

export function setBusy(btn, busy, label = "Working…") {
  if (busy) { btn.dataset.label = btn.textContent; btn.replaceChildren(h("span", { class: "spin" }), label); btn.disabled = true; }
  else { if (btn.dataset.label) btn.textContent = btn.dataset.label; btn.disabled = false; }
}
