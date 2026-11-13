import { h, svg } from "../dom.js";
import { BRAND_SVG } from "../../data/brands.js";

/** Round service logo: offline brand glyph if we have one, otherwise a letter on a warm gradient. */
export function avatar(name, size = "md") {
  const key = String(name || "").trim().toLowerCase();
  const brand = BRAND_SVG[key];
  if (brand) {
    const el = h("div", { class: `avatar ${size}`, style: { background: brand.bg } });
    el.append(svg(brand.svg, { cls: "brand" }));
    return el;
  }
  let hash = 0;
  for (let i = 0; i < key.length; i++) hash = (hash * 31 + key.charCodeAt(i)) % 360;
  const hue = 8 + (hash % 40);
  return h("div", {
    class: `avatar ${size}`,
    style: { background: `linear-gradient(135deg,hsl(${hue},72%,46%),hsl(${(hue + 14) % 360},70%,30%))` }
  }, (name || "?").trim().charAt(0).toUpperCase() || "?");
}
