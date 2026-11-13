import { logoSvg, themeBg } from "./logo.js";

/** Non-sensitive UI preferences (never secrets). */
const KEY = "keyvex.settings";
/** The colour theme is also kept under its own key, so it survives even if the settings blob is ever lost/reset. */
const THEME_KEY = "keyvex.theme";
const DEFAULTS = { autoLockMin: 5, lockOnHide: false, theme: "ocean", sort: "recent", view: "grid" };
export const THEMES = ["ocean", "sunset", "violet", "light"];

export function getSettings() {
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem(KEY) || "{}") || {}; } catch { /* corrupt / blocked */ }
  let theme = saved.theme;
  try { theme = localStorage.getItem(THEME_KEY) || theme; } catch { /* storage blocked */ }
  return { ...DEFAULTS, ...saved, theme: THEMES.includes(theme) ? theme : DEFAULTS.theme };
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
 * Applies the saved colour theme to <html> and re-brands everything that shows the logo to match:
 * the browser-tab icon, the iPhone Home-Screen icon, and the web-app manifest — so "Install app"
 * installs the logo of the theme that is active at that moment.
 */
export function applyTheme(name = getSettings().theme) {
  const theme = THEMES.includes(name) ? name : "ocean";
  document.documentElement.dataset.theme = theme;
  try {
    document.querySelectorAll('link[rel="icon"]').forEach((l) => l.remove());
    const link = document.createElement("link");
    link.rel = "icon"; link.type = "image/svg+xml";
    link.href = "data:image/svg+xml," + encodeURIComponent(logoSvg(theme, { id: "tab" }));
    document.head.append(link);
    headEl("link", 'link[rel="alternate icon"]', { rel: "alternate icon", href: `/icons/${theme}/icon.svg`, type: "image/svg+xml" });
    headEl("link", 'link[rel="apple-touch-icon"]', { rel: "apple-touch-icon", href: `/icons/${theme}/apple-touch-icon.png` });
    headEl("link", 'link[rel="manifest"]', { rel: "manifest", href: `/manifest-${theme}.webmanifest` });
    headEl("meta", 'meta[name="theme-color"]', { name: "theme-color", content: themeBg(theme) });
  } catch { /* no document head (tests) */ }
}
