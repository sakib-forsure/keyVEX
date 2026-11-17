import { h } from "../dom.js";
import { icon } from "../icons.js";
import { avatar } from "../components/avatar.js";
import { openSheet, confirmSheet, setBusy } from "../components/sheet.js";
import { pinField, notice } from "../components/fields.js";
import { copySecret, flash, toast, strengthMeter } from "../components/feedback.js";
import { errText, logAuthError } from "../errors.js";
import { strength } from "../../core/strength.js";
import { openEntryForm } from "./entryForm.js";

/** Only http(s) links are ever opened. */
export function safeUrl(site) {
  if (!site) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:/i.test(site) ? site : "https://" + site);
    return u.protocol === "https:" || u.protocol === "http:" ? u.href : null;
  } catch { return null; }
}

/**
 * PART 4 & B12: Deleting a saved password prompts for the user's current Passkey inside the confirmation sheet,
 * passes it to `vault.remove(passkey, id)`, and states "removed from all your devices" (B12).
 */
export function openDeleteEntrySheet(ctx, entry, onDeleted) {
  const { vault } = ctx;
  const acct = vault.account;
  const pinLen = acct?.pinLength || acct?.meta?.pinLength || 6;
  const pkField = pinField({
    label: "Enter your Passkey",
    name: "delete-entry-passkey",
    length: pinLen,
    autofocus: true,
    placeholder: pinLen === "strong" ? "Enter your Passkey" : `${pinLen} digits (0–9)`
  });
  const msg = h("div", { class: "flow-msg", "aria-live": "polite" });
  const delBtn = h("button", { class: "btn danger", type: "submit" }, "Delete");
  const cancelBtn = h("button", { class: "btn glass", type: "button", onclick: () => sheet.close() }, "Cancel");

  const form = h("form", {
    novalidate: true,
    class: "flow",
    onsubmit: async (ev) => {
      ev.preventDefault();
      msg.replaceChildren();
      const pk = pkField.input.value.trim();
      if (!pk) {
        msg.replaceChildren(notice("err", "Enter your Passkey to delete this password."));
        pkField.input.focus();
        return;
      }
      setBusy(delBtn, true, "Deleting…");
      try {
        await vault.remove(pk, entry.id);
        sheet.close();
        onDeleted?.();
        toast("Deleted");
      } catch (err) {
        logAuthError("deleteEntry", err);
        msg.replaceChildren(notice("err", errText(err)));
        pkField.input.value = "";
        pkField.input.focus();
      } finally {
        setBusy(delBtn, false);
      }
    }
  },
    h("p", { class: "muted" }, `“${entry.service}” will be removed from all your devices. This can’t be undone.`),
    pkField.root,
    msg,
    h("div", { class: "row-btns" }, cancelBtn, delBtn)
  );

  const sheet = openSheet({
    title: "Delete this password?",
    content: form
  });
  return sheet;
}

export function openDetail(ctx, id, onChange) {
  const { vault } = ctx;
  let e = vault.get(id);
  if (!e) return;
  let shown = false, rehide;

  const pw = h("div", { class: "v mono" }, "••••••••••••");
  const eye = h("button", { class: "icon-btn", type: "button", "aria-label": "Show password", onclick: () => setShown(!shown) }, icon("eye", 18));
  const setShown = (v) => {
    shown = v; pw.textContent = v ? e.password : "••••••••••••";
    eye.replaceChildren(icon(v ? "eyeOff" : "eye", 18)); eye.setAttribute("aria-label", v ? "Hide password" : "Show password");
    clearTimeout(rehide); if (v) rehide = setTimeout(() => setShown(false), 15_000);
  };
  const copyBtn = (label, text, msg, secret) => h("button", { class: "icon-btn", type: "button", "aria-label": label,
    onclick: (ev) => { if (!text) return toast("Nothing to copy"); flash(ev.currentTarget); copySecret(text, msg, secret ? 25_000 : 0); } }, icon("copy", 18));
  const kv = (label, value, ...actions) => h("div", { class: "kv glass" }, h("div", { class: "k" }, h("small", null, label), h("div", { class: "v" }, value || "—")), ...actions);

  const meter = strengthMeter(); meter.update(strength(e.password));
  const url = safeUrl(e.website);
  const star = h("button", { class: "icon-btn star-btn" + (e.favorite ? " on" : ""), type: "button", "aria-label": "Favorite", "aria-pressed": String(!!e.favorite),
    onclick: async (ev) => {
      e = await vault.save({ ...e, favorite: !e.favorite });
      ev.currentTarget.classList.toggle("on", e.favorite); ev.currentTarget.setAttribute("aria-pressed", String(e.favorite));
      ev.currentTarget.replaceChildren(icon(e.favorite ? "star" : "starOutline", 20)); onChange();
    } }, icon(e.favorite ? "star" : "starOutline", 20));

  const sheet = openSheet({
    title: e.service,
    onClose: () => clearTimeout(rehide),
    content: [
      h("div", { class: "detail-top" }, avatar(e.service, "lg"), h("div", { class: "grow" }, h("div", { class: "detail-name" }, e.service), h("div", { class: "muted small" }, e.category)), star),
      e.website && kv("Website", e.website, url && h("a", { class: "icon-btn", href: url, target: "_blank", rel: "noopener noreferrer", "aria-label": "Open website" }, icon("link", 18)), copyBtn("Copy website", e.website, "Website copied")),
      kv("Username or email", e.username, copyBtn("Copy username", e.username, "Username copied")),
      h("div", { class: "kv glass" }, h("div", { class: "k" }, h("small", null, "Password"), pw), eye, copyBtn("Copy password", e.password, "Password copied", true)),
      meter,
      e.notes && kv("Notes", e.notes),
      h("p", { class: "tiny muted" }, "Updated " + new Date(e.updatedAt || e.createdAt).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })),
      h("div", { class: "row-btns" },
        h("button", { class: "btn glass", type: "button", onclick: () => { sheet.close(); setTimeout(() => openEntryForm(ctx, e, null, onChange), 260); } }, icon("edit", 18), "Edit"),
        h("button", { class: "btn danger", type: "button", onclick: () => {
          openDeleteEntrySheet(ctx, e, () => {
            sheet.close();
            onChange();
          });
        } }, icon("trash", 18), "Delete"))
    ]
  });
}
