import { h } from "../dom.js";
import { icon } from "../icons.js";

export function field({ label, hint, extra, ...attrs }) {
  const input = attrs.type === "textarea"
    ? h("textarea", { rows: 3, ...attrs, type: null })
    : h("input", { spellcheck: "false", autocapitalize: "off", ...attrs });
  const hintEl = hint ? h("small", { class: "hint" }, hint) : null;
  const root = h("label", { class: "field" }, h("span", { class: "label" }, label),
    h("span", { class: "control" }, input, extra), hintEl);
  return { root, input, hintEl };
}

export function passwordField({ label, hint, ...attrs }) {
  const eye = h("button", { class: "icon-btn", type: "button", "aria-label": "Show password" }, icon("eye", 18));
  const f = field({ label, hint, ...attrs, type: "password", extra: eye });
  eye.addEventListener("click", () => {
    const show = f.input.type === "password";
    f.input.type = show ? "text" : "password";
    if (attrs.inputmode) f.input.setAttribute("inputmode", attrs.inputmode);
    eye.replaceChildren(icon(show ? "eyeOff" : "eye", 18));
    eye.setAttribute("aria-label", show ? "Hide password" : "Show password");
  });
  return f;
}

export const notice = (kind, text) => h("div", { class: `notice ${kind}`, role: kind === "err" ? "alert" : "status", "aria-live": "polite" }, text);

/**
 * Passkey input:
 * - Numeric mode (`length = 4 | 6`): digits only, opens numeric keypad on mobile & desktop, blocks non-digit keys.
 */
export function pinField({ label, hint, length = 6, ...attrs }) {
  let modeLen = (length === 4 || length === 6 || length === 8 || length === "strong") ? length : 6;
  let maxLen = modeLen === "strong" ? 64 : Number(modeLen);
  const f = passwordField({
    label,
    hint,
    inputmode: modeLen === "strong" ? "text" : "numeric",
    pattern: modeLen === "strong" ? undefined : "[0-9]*",
    enterkeyhint: "done",
    maxlength: String(maxLen),
    autocomplete: "off",
    autocorrect: "off",
    ...attrs
  });

  f.input.inputMode = modeLen === "strong" ? "text" : "numeric";

  f.input.addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key && e.key.length === 1) {
      if (modeLen !== "strong" && !/^[0-9]$/.test(e.key)) {
        e.preventDefault();
        return;
      }
      const selLen = Math.abs((f.input.selectionEnd || 0) - (f.input.selectionStart || 0));
      if (f.input.value.length - selLen >= maxLen) {
        e.preventDefault();
      }
    }
  });

  f.input.addEventListener("beforeinput", (e) => {
    if (modeLen !== "strong" && e.data && /\D/.test(e.data)) {
      e.preventDefault();
    }
  });

  f.input.addEventListener("paste", (e) => {
    const raw = e.clipboardData?.getData("text") ?? "";
    if (raw) {
      e.preventDefault();
      const cleaned = modeLen === "strong" ? raw.trim() : raw.replace(/\D/g, "");
      const start = f.input.selectionStart ?? f.input.value.length;
      const end = f.input.selectionEnd ?? f.input.value.length;
      const combined = f.input.value.slice(0, start) + cleaned + f.input.value.slice(end);
      const next = (modeLen === "strong" ? combined : combined.replace(/\D/g, "")).slice(0, maxLen);
      f.input.value = next;
      f.input.dispatchEvent(new Event("input", { bubbles: true }));
    }
  });

  const enforce = () => {
    const clean = (modeLen === "strong" ? f.input.value : f.input.value.replace(/\D/g, "")).slice(0, maxLen);
    if (clean !== f.input.value) f.input.value = clean;
  };
  f.input.addEventListener("input", enforce);

  f.setLength = (nextLen, updatePlaceholder = true) => {
    modeLen = (nextLen === 4 || nextLen === 6 || nextLen === 8 || nextLen === "strong") ? nextLen : 6;
    maxLen = modeLen === "strong" ? 64 : Number(modeLen);
    f.input.maxLength = maxLen;
    f.input.setAttribute("maxlength", String(maxLen));
    f.input.inputMode = modeLen === "strong" ? "text" : "numeric";
    f.input.setAttribute("inputmode", modeLen === "strong" ? "text" : "numeric");
    if (updatePlaceholder) {
      f.input.placeholder = modeLen === "strong" ? "8+ chars (letters & numbers)" : `${maxLen} digits (0–9)`;
    }
    enforce();
  };
  f.getLength = () => modeLen;

  return f;
}

/**
 * Reusable Passkey length selector segmented control (`4 Digit` / `6 Digit` ONLY).
 */
export function pinLengthSelector({ initial = 6, onChange } = {}) {
  const options = [4, 6];
  let current = initial === 4 ? 4 : 6;
  const wrap = h("div", { class: "seg pin-len-seg", role: "radiogroup", "aria-label": "Passkey length" });
  const render = () => {
    wrap.replaceChildren(
      ...options.map((len) =>
        h("button", {
          type: "button",
          role: "radio",
          class: current === len ? "on" : "",
          "aria-checked": String(current === len),
          onclick: () => {
            if (current === len) return;
            current = len;
            render();
            onChange?.(len);
          }
        }, `${len} Digit`)
      )
    );
  };
  render();
  return {
    root: wrap,
    get value() { return current; },
    set value(len) {
      const next = Number(len) === 4 ? 4 : 6;
      if (next !== current) { current = next; render(); }
    }
  };
}
