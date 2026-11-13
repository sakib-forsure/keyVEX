/** Tiny DOM builder. User data is only ever set via textContent/attributes — never innerHTML. */
const SVG_NS = "http://www.w3.org/2000/svg";

export function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") for (const [p, val] of Object.entries(v)) (p.startsWith("--") ? el.style.setProperty(p, val) : (el.style[p] = val)); // CSSOM: allowed by a strict CSP
    else if (k === "html") el.innerHTML = v;                       // TRUSTED static markup only (icons/art)
    else if (k.startsWith("on")) el.addEventListener(k.slice(2).toLowerCase(), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  append(el, kids);
  return el;
}

function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    el.append(k.nodeType ? k : document.createTextNode(String(k)));
  }
}

export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => [...r.querySelectorAll(s)];
export const clear = (el) => { while (el.firstChild) el.firstChild.remove(); return el; };

export function svg(inner, { size, cls, viewBox = "0 0 24 24" } = {}) {
  const el = document.createElementNS(SVG_NS, "svg");
  el.setAttribute("viewBox", viewBox);
  el.setAttribute("aria-hidden", "true");
  if (size) { el.setAttribute("width", size); el.setAttribute("height", size); }
  if (cls) el.setAttribute("class", cls);
  el.innerHTML = inner; // TRUSTED static markup
  return el;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
