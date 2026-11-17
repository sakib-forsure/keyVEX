import { logoSvg, themeBg } from "./logo.js";

/** Non-sensitive UI preferences (never secrets). */
const KEY = "keyvex.settings";
/** The colour theme is also kept under its own key, so it survives even if the settings blob is ever lost/reset. */
const THEME_KEY = "keyvex.theme";
const DEFAULTS = { autoLockMin: 5, lockOnHide: false, theme: "system", sort: "recent", view: "grid" };
export const THEMES = ["system", "dark", "light"];

/** Saved preference: "system" (follow the device, default) | "dark" | "light". Retired gradient themes open as Dark. */
export const normalizeTheme = (t) => (t === "system" || t == null || t === "" ? "system" : t === "light" ? "light" : "dark");

/** The colourway actually painted: a fixed choice wins, "system" follows the device's light/dark setting live. */
export function resolveTheme(pref) {
  const p = normalizeTheme(pref);
  if (p !== "system") return p;
  try { return typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"; } catch { return "dark"; }
}

export function getSettings() {
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(KEY) || "{}") || {}; } catch { /* corrupt / blocked */ }
  let theme = saved.theme;
  try { theme = localStorage.getItem(THEME_KEY) || theme; } catch { /* storage blocked */ }
  return { ...DEFAULTS, ...saved, theme: normalizeTheme(theme) };
}
export function setSetting(name, value) {
  try { localStorage.setItem(KEY, JSON.stringify({ ...getSettings(), [name]: value })); } catch { /* storage blocked */ }
  if (name === "theme") { try { localStorage.setItem(THEME_KEY, String(value)); } catch { /* storage blocked */ } }
}

export { logoSvg };

/** Sets (or creates) a <link>/<meta> in <head> and returns it. */
function headEl(tag, selector, attrs) {
  let el = document.head.querySelector(selector);
  if (!el) { el = document.createElement(tag); document.head.append(el); }
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

/**
 * Applies the colour theme to <html> and re-brands everything that shows the logo to match.
 * `data-theme-pref` holds what the user picked (system | dark | light); `data-theme` the resolved colourway the CSS uses.
 * With "system" the page follows the device live (see watchSystemTheme).
 */
export function applyTheme(name = getSettings().theme) {
  const pref = normalizeTheme(name);
  const theme = resolveTheme(pref);
  const root = document.documentElement;
  const changed = root.dataset.theme !== theme;
  root.dataset.themePref = pref;
  root.dataset.theme = theme;
  if (changed) { root.classList.add("theme-fade"); clearTimeout(applyTheme._t); applyTheme._t = setTimeout(() => root.classList.remove("theme-fade"), 650); }
  try {
    const iconHref = "data:image/svg+xml," + encodeURIComponent(logoSvg(theme, { id: "tab" }));
    const tab = document.head.querySelector('link[rel="icon"]');
    if (!tab || tab.getAttribute("href") !== iconHref) {
      document.querySelectorAll('link[rel="icon"]').forEach((l) => l.remove());
      const link = document.createElement("link");
      link.rel = "icon"; link.type = "image/svg+xml"; link.href = iconHref;
      document.head.append(link);
    }
    headEl("link", 'link[rel="alternate icon"]', { rel: "alternate icon", href: `/icons/${theme}/icon.svg`, type: "image/svg+xml" });
    headEl("link", 'link[rel="apple-touch-icon"]', { rel: "apple-touch-icon", href: `/icons/${theme}/apple-touch-icon.png` });
    // Only touch the manifest link when the colourway really changed: re-writing an identical href makes desktop
    // Chrome / Edge re-evaluate installability and can swallow the "Install app" prompt.
    const man = document.head.querySelector('link[rel="manifest"]');
    const manHref = `/manifest-${theme}.webmanifest`;
    if (!man) headEl("link", 'link[rel="manifest"]', { rel: "manifest", href: manHref });
    else if (new URL(man.href, location.href).pathname !== manHref) man.setAttribute("href", manHref);
    headEl("meta", 'meta[name="theme-color"]', { name: "theme-color", content: themeBg(theme) });
  } catch { /* no document head (tests) */ }
}

let watching = false;
/** Re-applies the theme whenever the device switches light/dark — but only while the preference is "system". */
export function watchSystemTheme() {
  if (watching || typeof matchMedia !== "function") return;
  watching = true;
  try {
    const mq = matchMedia("(prefers-color-scheme: light)");
    const on = () => { if (getSettings().theme === "system") applyTheme("system"); };
    if (mq.addEventListener) mq.addEventListener("change", on); else mq.addListener?.(on);
    // phones can switch scheme while the tab sleeps (sunset auto-dark): re-check on wake
    document.addEventListener("visibilitychange", () => { if (!document.hidden) on(); });
  } catch { /* ignore */ }
}
