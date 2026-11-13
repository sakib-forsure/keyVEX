import { h } from "../dom.js";
import { passwordField } from "./fields.js";
import { strengthMeter } from "./feedback.js";
import { strength, checkMasterPassword } from "../../core/strength.js";

/**
 * "Choose a Master Password": one field with a live strength meter, plus a repeat field.
 * validate() mirrors the rules the Vault enforces, so the user gets the reason before submitting.
 */
export function masterPasswordSetup({ getPin = () => "", label = "Master Password", name = "master-password", autofocus = true } = {}) {
  const pw = passwordField({ label, name, autocomplete: "new-password", maxlength: "128", autofocus, placeholder: "At least 8 characters (e.g. Pass@123)" });
  const again = passwordField({ label: `Repeat ${label}`, name: `${name}-confirm`, autocomplete: "new-password", maxlength: "128", placeholder: `Re-enter ${label}` });
  const meter = strengthMeter();
  const sync = () => meter.update(strength(pw.input.value));
  pw.input.addEventListener("input", sync);
  sync();

  return {
    root: h("div", { class: "master-set" }, pw.root, meter, again.root),
    input: pw.input,
    get value() { return pw.input.value; },
    validate() {
      const c = checkMasterPassword(pw.input.value, getPin());
      if (!c.ok) return { ok: false, hint: c.hint };
      if (pw.input.value !== again.input.value) return { ok: false, hint: "The two Passwords don’t match." };
      return { ok: true, hint: "" };
    },
    clear() { pw.input.value = ""; again.input.value = ""; sync(); }
  };
}
