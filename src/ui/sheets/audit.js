import { h } from "../dom.js";
import { avatar } from "../components/avatar.js";
import { openSheet } from "../components/sheet.js";
import { auditEntries } from "../../core/audit.js";
import { openDetail } from "./detail.js";

export function openSecurityCheck(ctx, onChange) {
  const entries = ctx.vault.list();
  const a = auditEntries(entries);
  const flagged = new Set([...a.weak, ...a.reused, ...a.old].map((e) => e.id));
  const score = entries.length ? Math.round(100 * (1 - flagged.size / entries.length)) : 100;

  const group = (title, items, reason) => items.length === 0 ? null : h("section", { class: "audit-group" },
    h("h3", null, `${title} · ${items.length}`),
    items.map((e) => h("button", { class: "pick glass", type: "button", onclick: () => { sheet.close(); setTimeout(() => openDetail(ctx, e.id, onChange), 260); } },
      avatar(e.service), h("span", { class: "meta" }, h("span", { class: "name" }, e.service), h("span", { class: "sub" }, reason)))));

  const sheet = openSheet({
    title: "Security check",
    content: [
      h("div", { class: "score glass" },
        h("div", { class: "ring", style: { "--p": score } }, h("strong", null, score + "%")),
        h("div", null, h("div", { class: "detail-name" }, entries.length ? (score === 100 ? "All clear" : "Needs attention") : "Nothing to check yet"),
          h("div", { class: "muted small" }, entries.length ? `${entries.length} saved · checked on this device only` : "Add a few passwords first."))),
      group("Weak passwords", a.weak, "Easy to guess — replace it"),
      group("Reused passwords", a.reused, "Same password used elsewhere"),
      group("Not changed in 6 months", a.old, "Consider updating it"),
      entries.length && flagged.size === 0 ? h("p", { class: "muted" }, "No weak, reused or old passwords found.") : null
    ]
  });
}
