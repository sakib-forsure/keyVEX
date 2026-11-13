import { h, svg } from "../dom.js";

const GLYPH = `<path d="M24 8.5 12 13.2v8.4c0 7.6 4.9 12.3 12 15.2 7.1-2.9 12-7.6 12-15.2v-8.4z" fill="rgba(255,255,255,.2)" stroke="#fff" stroke-width="2.2" stroke-linejoin="round"/>
<circle cx="24" cy="20.5" r="3.7" fill="#fff"/><path d="M24 24.2v7.3M24 28.4h3.2M24 31.5h2.2" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/>`;

/**
 * KeyVEX wordmark.
 *   size "xl" / "lg": stacked and centred — logo, big name, small slogan underneath (login screens).
 *   size "sm":       one row — logo + name (sidebar, mobile top bar).
 */
export function brand({ size = "lg", slogan = true, tag = "div" } = {}) {
  return h(tag, { class: `brand ${size}`, "aria-label": "KeyVEX" },
    h("span", { class: "logo-mark", "aria-hidden": "true" }, svg(GLYPH, { viewBox: "0 0 48 48" })),
    h("span", { class: "wordmark" },
      h("span", { class: "name" }, "Key", h("b", null, "VEX")),
      slogan && h("span", { class: "slogan" }, "Keep your life safe")));
}
