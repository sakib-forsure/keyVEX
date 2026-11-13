/* Runs before first paint: applies the saved colour theme + its logo so a refresh never flashes another colour. */
(function () {
  try {
    var themes = ["ocean", "sunset", "violet", "light"];
    var bg = { ocean: "#081428", sunset: "#1c0a0c", violet: "#0e081e", light: "#1a0b08" };
    var t = localStorage.getItem("keyvex.theme");
    if (!t) { try { t = (JSON.parse(localStorage.getItem("keyvex.settings") || "{}") || {}).theme; } catch (e) {} }
    if (themes.indexOf(t) < 0) t = "ocean";
    var d = document;
    d.documentElement.setAttribute("data-theme", t);
    function set(sel, attr, val) { var el = d.head.querySelector(sel); if (el) el.setAttribute(attr, val); }
    set('meta[name="theme-color"]', "content", bg[t]);
    set('link[rel="manifest"]', "href", "/manifest-" + t + ".webmanifest");
    set('link[rel="apple-touch-icon"]', "href", "/icons/" + t + "/apple-touch-icon.png");
    set('link[rel="icon"]', "href", "/icons/" + t + "/icon.svg");
    set('link[rel="alternate icon"]', "href", "/icons/" + t + "/icon.svg");
  } catch (e) { /* storage blocked: keep default */ }
})();
