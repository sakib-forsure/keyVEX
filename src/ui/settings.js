/** Non-sensitive UI preferences (never secrets). */
const KEY = "keyvex.settings";
const DEFAULTS = { autoLockMin: 5, lockOnHide: false, theme: "ocean", sort: "recent", view: "grid" };
export const THEMES = ["ocean", "sunset", "violet", "light"];

export function getSettings() {
  try { return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(KEY) || "{}") }; } catch { return { ...DEFAULTS }; }
}
export function setSetting(name, value) {
  try { localStorage.setItem(KEY, JSON.stringify({ ...getSettings(), [name]: value })); } catch { /* storage blocked */ }
}

/** Logo colours per theme: [top, middle, bottom] of the gradient. Matches the on-page logo mark. */
const LOGO = {
  ocean: ["#5EE0D2", "#2A86F0", "#0A1E3D"],
  sunset: ["#FFB347", "#FF5A36", "#2A0A0C"],
  violet: ["#B266FF", "#8A2EFF", "#1D0A3F"],
  light: ["#FF9A4A", "#FF5233", "#3A0E0C"]
};

/** The browser-tab icon, drawn in the current theme's colours. */
export function logoSvg(name = "ocean") {
  const [a, b, c] = LOGO[name] || LOGO.ocean;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${a}"/><stop offset=".5" stop-color="${b}"/><stop offset="1" stop-color="${c}"/></linearGradient></defs><rect width="64" height="64" rx="16" fill="url(#g)"/><path d="M22 29v-6a10 10 0 0 1 20 0v6" fill="none" stroke="#fff" stroke-width="5" stroke-linecap="round"/><rect x="16" y="28" width="32" height="24" rx="8" fill="#fff"/><circle cx="32" cy="38" r="3.6" fill="${b}"/><rect x="30.4" y="40" width="3.2" height="7" rx="1.6" fill="${b}"/></svg>`;
}

/** Applies the saved colour theme to <html> and recolours the tab icon to match. */
export function applyTheme(name = getSettings().theme) {
  const theme = THEMES.includes(name) ? name : "ocean";
  document.documentElement.dataset.theme = theme;
  try {
    document.querySelectorAll('link[rel="icon"]').forEach((l) => l.remove());
    const link = document.createElement("link");
    link.rel = "icon"; link.type = "image/svg+xml";
    link.href = "data:image/svg+xml," + encodeURIComponent(logoSvg(theme));
    document.head.append(link);
  } catch { /* no document head (tests) */ }
}
