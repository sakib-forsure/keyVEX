import { h } from "../dom.js";
import { logoSvg } from "../logo.js";

let seq = 0;

/**
 * KeyVEX wordmark.
 *   size "xl" / "lg": stacked and centred — logo, big name, small slogan underneath (login screens).
 *   size "sm":       one row — logo + name (sidebar, mobile top bar).
 * The logo follows the active colour theme live (it is painted with the theme's CSS variables).
 */
export function brand({ size = "lg", slogan = true, tag = "div" } = {}) {
  const mark = h("span", { class: "logo-mark", "aria-hidden": "true", html: logoSvg("ocean", { id: `kvl${++seq}`, vars: true, xmlns: false }) });
  return h(tag, { class: `brand ${size}`, "aria-label": "KeyVEX" },
    mark,
    h("span", { class: "wordmark" },
      h("span", { class: "name" }, "Key", h("b", null, "VEX")),
      slogan && h("span", { class: "slogan" }, "Keep your life safe")));
}
