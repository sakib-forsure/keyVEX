/* Runs before first paint: applies the saved colour theme (System follows the device) + its logo, so a refresh never flashes another colour.
   Also catches the browser's install prompt early so the "Install app" button works on desktop even if the event fires before the app boots. */
(function () {
  try {
    var bg = { dark: "#020a26", light: "#cbe9fd" };
    var t = localStorage.getItem("keyvex.theme");
    if (!t) { try { t = (JSON.parse(localStorage.getItem("keyvex.settings") || "{}") || {}).theme; } catch (e) {} }
    var pref = (!t || t === "system") ? "system" : (t === "light" ? "light" : "dark"); // retired gradient themes fall back to Dark
    var dark = true;
    try { dark = !(window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches); } catch (e) {}
    t = pref === "system" ? (dark ? "dark" : "light") : pref;
    var d = document;
    d.documentElement.setAttribute("data-theme", t);
    d.documentElement.setAttribute("data-theme-pref", pref);
    function set(sel, attr, val) { var el = d.head.querySelector(sel); if (el) el.setAttribute(attr, val); }
    set('meta[name="theme-color"]', "content", bg[t]);
    set('link[rel="manifest"]', "href", "/manifest-" + t + ".webmanifest");
    set('link[rel="apple-touch-icon"]', "href", "/icons/" + t + "/apple-touch-icon.png");
    set('link[rel="icon"]', "href", "/icons/" + t + "/icon.svg");
    set('link[rel="alternate icon"]', "href", "/icons/" + t + "/icon.svg");
  } catch (e) { /* storage blocked: keep default */ }
  try {
    window.addEventListener("beforeinstallprompt", function (e) { e.preventDefault(); window.__kvBip = e; });
  } catch (e) {}
})();
