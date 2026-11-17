import { h, $ } from "../dom.js";
import { icon } from "../icons.js";

let timer;
export function toast(message) {
  const t = $("#toast");
  if (!t) return;
  t.replaceChildren(icon("check", 18), message);
  t.classList.add("show");
  clearTimeout(timer);
  timer = setTimeout(() => t.classList.remove("show"), 2600);
}

/**
 * Copies text, then wipes the clipboard after 25 s ONLY if the clipboard still equals `lastCopiedSecret`
 * (or on lock/sign-out via `clearClipboardIfSecret`), so it never wipes something else the user copied later (B14).
 */
let clipTimer = null;
let lastCopiedSecret = null;

export async function clearClipboardIfSecret() {
  clearTimeout(clipTimer);
  clipTimer = null;
  const expected = lastCopiedSecret;
  lastCopiedSecret = null;
  if (!expected || typeof navigator === "undefined" || !navigator.clipboard) return false;
  try {
    if (typeof navigator.clipboard.readText === "function") {
      const current = await navigator.clipboard.readText();
      if (current !== expected) return false;
      await navigator.clipboard.writeText("");
      return true;
    }
  } catch {
    /* When readText() is denied by browser permissions, skip blind overwrite per B14 */
  }
  return false;
}

export async function copySecret(text, message = "Copied", clearAfterMs = 25_000) {
  try { await navigator.clipboard.writeText(text); }
  catch {
    const ta = h("textarea", { style: { position: "fixed", opacity: "0" } });
    ta.value = text; document.body.append(ta); ta.select();
    try { document.execCommand("copy"); } catch { /* ignore */ }
    ta.remove();
  }
  toast(clearAfterMs ? `${message} · clears in ${Math.round(clearAfterMs / 1000)}s` : message);
  clearTimeout(clipTimer);
  if (clearAfterMs) {
    lastCopiedSecret = String(text);
    clipTimer = setTimeout(() => {
      clearClipboardIfSecret().catch(() => {});
    }, clearAfterMs);
  } else {
    lastCopiedSecret = null;
  }
}

export function getLastCopiedSecretForTest() {
  return lastCopiedSecret;
}

/** Flash a check mark on an icon button. */
export function flash(btn) {
  if (!btn || btn.dataset.flash) return;
  btn.dataset.flash = "1";
  const old = [...btn.childNodes];
  btn.replaceChildren(icon("check", 18)); btn.classList.add("ok");
  setTimeout(() => { btn.replaceChildren(...old); btn.classList.remove("ok"); delete btn.dataset.flash; }, 1100);
}

export function strengthMeter() {
  const fill = h("i");
  const label = h("span", { class: "meter-label" });
  const root = h("div", { class: "meter", "aria-live": "polite" }, h("div", { class: "meter-bar" }, fill), label);
  root.update = (s) => { fill.style.width = s.pct + "%"; fill.style.background = s.color; label.textContent = s.label; label.style.color = s.color; };
  return root;
}
