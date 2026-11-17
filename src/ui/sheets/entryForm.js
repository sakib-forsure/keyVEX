import { h, sleep } from "../dom.js";
import { icon } from "../icons.js";
import { avatar } from "../components/avatar.js";
import { field, passwordField, notice } from "../components/fields.js";
import { openSheet, setBusy } from "../components/sheet.js";
import { strengthMeter, toast } from "../components/feedback.js";
import { openGenerator } from "./generator.js";
import { SERVICES } from "../../data/brands.js";
import { strength } from "../../core/strength.js";

/** Step 1 of "add": choose a known service (logo + category prefilled) or a custom entry. */
export function openPicker(ctx, onChange) {
  const list = h("div", { class: "pick-list" });
  const q = h("input", { type: "search", placeholder: "Search services", "aria-label": "Search services", autofocus: true });
  const choose = (preset) => { sheet.close(); setTimeout(() => openEntryForm(ctx, null, preset, onChange), 260); };
  const render = () => {
    const term = q.value.trim().toLowerCase();
    const items = SERVICES.filter((s) => !term || s.name.toLowerCase().includes(term) || s.web.includes(term));
    list.replaceChildren(
      h("button", { class: "pick glass", type: "button", onclick: () => choose(q.value.trim() ? { name: q.value.trim(), web: "", cat: "Other" } : null) },
        h("div", { class: "avatar md plus" }, icon("plus", 20)), h("span", { class: "meta" }, h("span", { class: "name" }, q.value.trim() ? `Add “${q.value.trim()}”` : "Custom entry"), h("span", { class: "sub" }, "Any website or app"))),
      ...items.map((s) => h("button", { class: "pick glass", type: "button", onclick: () => choose({ name: s.name, web: s.web, cat: s.cat }) },
        avatar(s.name), h("span", { class: "meta" }, h("span", { class: "name" }, s.name), h("span", { class: "sub" }, s.web)))));
  };
  q.addEventListener("input", render);
  const sheet = openSheet({ title: "Add password", content: [h("div", { class: "search-pill glass" }, icon("search", 18), q), list] });
  render();
}

export function openEntryForm(ctx, entry, preset, onChange) {
  const { vault } = ctx;
  const cats = vault.categories;
  const state = { category: entry?.category || preset?.cat || "Social", favorite: !!entry?.favorite };

  const service = field({ label: "Service", name: "service", value: entry?.service || preset?.name || "", maxlength: 80, required: true, autocomplete: "off" });
  const website = field({ label: "Website", name: "website", value: entry?.website || preset?.web || "", maxlength: 200, autocomplete: "off", inputmode: "url" });
  const username = field({ label: "Username or email", name: "username", value: entry?.username || "", maxlength: 200, autocomplete: "off" });
  const password = passwordField({ label: "Password", name: "password", value: entry?.password || "", maxlength: 1024, required: true, autocomplete: "new-password" });
  const notes = field({ label: "Notes", type: "textarea", name: "notes", maxlength: 2000 });
  notes.input.value = entry?.notes || "";
  const meter = strengthMeter();
  const refreshMeter = () => meter.update(strength(password.input.value));
  password.input.addEventListener("input", refreshMeter); refreshMeter();

  const gen = h("button", { class: "btn glass slim", type: "button", onclick: () => openGenerator({ vault, onUse: (p) => { password.input.value = p; password.input.type = "text"; refreshMeter(); } }) }, icon("wand", 16), "Generate");
  const av = h("div", { class: "avatar-slot" }, avatar(service.input.value, "md"));
  service.input.addEventListener("input", () => av.replaceChildren(avatar(service.input.value, "md")));

  const chips = h("div", { class: "chips-wrap", role: "radiogroup", "aria-label": "Category" });
  const drawChips = () => chips.replaceChildren(...cats.map((c) => h("button", { type: "button", role: "radio", "aria-checked": String(state.category === c),
    class: "chip-toggle" + (state.category === c ? " on" : ""), onclick: () => { state.category = c; drawChips(); } }, c)));
  drawChips();

  const fav = h("label", { class: "switch" }, h("input", { type: "checkbox", checked: state.favorite || null, onchange: (e) => { state.favorite = e.target.checked; } }), h("span", { class: "track" }), "Mark as favorite");
  const msg = h("div");
  const save = h("button", { class: "btn primary", type: "submit" }, entry ? "Save changes" : "Save password");

  const form = h("form", { novalidate: true, onsubmit: async (ev) => {
    ev.preventDefault(); msg.replaceChildren();
    setBusy(save, true, "Encrypting…");
    try {
      await vault.save({ id: entry?.id, service: service.input.value, website: website.input.value, username: username.input.value,
        password: password.input.value, category: state.category, notes: notes.input.value, favorite: state.favorite });
      save.replaceChildren(icon("check", 20), "Saved"); save.classList.add("saved");
      await sleep(560); sheet.close(); onChange(); toast(entry ? "Changes saved" : "Password saved");
    } catch (err) { setBusy(save, false); msg.replaceChildren(notice("err", err.message || "Could not save.")); }
  } },
    h("div", { class: "service-row" }, av, h("div", { class: "grow" }, service.root)),
    website.root, username.root, password.root, h("div", { class: "form-tools" }, meter, gen),
    h("div", { class: "label" }, "Category"), chips, notes.root, fav, msg, save);

  const sheet = openSheet({ title: entry ? "Edit password" : "New password", content: form });
}
